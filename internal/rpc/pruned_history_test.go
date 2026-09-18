package rpc

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Snapshot-boot / missing-history honesty for getblockchaininfo + getblockhash.
//
// Live mainnet (2026-09-17T22:50Z): getblock on Core's real block hash misses
// at 1 / 500000 / 900000 / 940000 and HAVEs from 960000, while
// getblockchaininfo reports pruned=false with no pruneheight. getblockhash(1)
// still answers because the in-memory header chain / height index is dense —
// that is not the same as holding the body.
//
// Core (rpc/blockchain.cpp): pruned is true when the node does not hold the
// full chain; pruneheight is the first height with complete block data.
// getblockhash -8 is only for height < 0 or height > tip; an in-range height
// the node simply does not retain is -1 "Block not available (pruned data)"
// (same string Core's getblock uses for pruned bodies).
//
// pruneheight is the first height of the contiguous run to the tip
// (Core GetFirstBlock), NOT the first stored body. An interior hole
// raises that floor; advertising the first body over-claims complete
// data (nimrod 87ac1d8: pruneheight=952185 while 966302..967347 were
// unreadable). The retained-range audit scans from the first body so
// a hole above that floor is visible. getblockhash consults the body
// store, not a floor cutoff — an island below pruneheight still
// returns its hash, an interior hole returns -1.
//
// This commit reports the truth. It does not backfill genesis→floor.
//
// CONTROL: go test ./internal/storage/ ./internal/rpc/ -count=1 -timeout 120s -run 'TestHistoryFloor_|TestBodyFloor_|TestFirstBody_|TestRetainedBody_|TestPrunedHistory_'

const (
	prunedHistoryFloor = int32(10)
	prunedHistoryTip   = int32(20)
	prunedDataMsg      = "Block not available (pruned data)"
	oorMsg             = "Block height out of range"
)

func prunedHistoryHash(n int32) wire.Hash256 {
	var h wire.Hash256
	binary.BigEndian.PutUint32(h[:], uint32(n))
	return h
}

// seedIndexAndBodyHole writes genesis + Floor..Tip into chainDB (height
// index and bodies) and records the tip in chainstate. Heights 1..Floor-1
// are absent from both. Mirrors rustoshi/clearbit snapshot-boot index hole
// and is the CONTROL for getblockhash -1 vs -8 (chainMgr not wired, so the
// handler cannot walk in-memory headers).
func seedIndexAndBodyHole(t *testing.T, floor, tip int32) *storage.ChainDB {
	t.Helper()
	cdb := storage.NewChainDB(storage.NewMemDB())
	for _, n := range []int32{0} {
		h := prunedHistoryHash(n)
		if err := cdb.SetBlockHeight(n, h); err != nil {
			t.Fatalf("SetBlockHeight(%d): %v", n, err)
		}
		if err := cdb.StoreBlock(h, dummyPrunedHistoryBlock(n)); err != nil {
			t.Fatalf("StoreBlock(%d): %v", n, err)
		}
	}
	for n := floor; n <= tip; n++ {
		h := prunedHistoryHash(n)
		if err := cdb.SetBlockHeight(n, h); err != nil {
			t.Fatalf("SetBlockHeight(%d): %v", n, err)
		}
		if err := cdb.StoreBlock(h, dummyPrunedHistoryBlock(n)); err != nil {
			t.Fatalf("StoreBlock(%d): %v", n, err)
		}
	}
	if err := cdb.SetChainState(&storage.ChainState{
		BestHash:   prunedHistoryHash(tip),
		BestHeight: tip,
	}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	return cdb
}

func dummyPrunedHistoryBlock(n int32) *wire.MsgBlock {
	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  prunedHistoryHash(n - 1),
			MerkleRoot: prunedHistoryHash(n),
			Timestamp:  1231006505 + uint32(n),
			Bits:       0x207fffff,
			Nonce:      uint32(n),
		},
		Transactions: []*wire.MsgTx{{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
				SignatureScript:  []byte{byte(n)},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{
				Value:    50 * 100000000,
				PkScript: []byte{0x51},
			}},
		}},
	}
}

func indexHoleServer(t *testing.T, floor, tip int32) *Server {
	t.Helper()
	cdb := seedIndexAndBodyHole(t, floor, tip)
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(cdb),
	)
}

// connectedBodyHoleRig mines a dense header+body chain 1..tip, then deletes
// bodies below floor. Headers stay in memory (getblock-by-hash of a known
// header still reaches the body-missing path) while getblockhash of those
// heights consults the body store and returns -1. -prune is off.
type connectedBodyHoleRig struct {
	server *Server
	db     *storage.ChainDB
	cm     *consensus.ChainManager
	idx    *consensus.HeaderIndex
}

func newConnectedBodyHoleRig(t *testing.T, floor, tip int32) *connectedBodyHoleRig {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	if err := db.StoreBlock(params.GenesisHash, params.GenesisBlock); err != nil {
		t.Fatalf("StoreBlock genesis: %v", err)
	}
	if err := db.SetBlockHeight(0, params.GenesisHash); err != nil {
		t.Fatalf("SetBlockHeight genesis: %v", err)
	}
	utxo := consensus.NewUTXOSet(db)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
		UTXOSet:     utxo,
	})

	prev := idx.Genesis()
	for h := int32(1); h <= tip; h++ {
		blk := buildRegtestBlock(t, params, prev)
		node, err := idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader at height %d: %v", h, err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock at height %d: %v", h, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock at height %d: %v", h, err)
		}
		prev = node
	}

	_, gotTip := cm.BestBlock()
	if gotTip != tip {
		t.Fatalf("tip height = %d, want %d", gotTip, tip)
	}

	tipNode := cm.BestBlockNode()
	for h := int32(1); h < floor; h++ {
		anc := tipNode.GetAncestor(h)
		if anc == nil {
			t.Fatalf("no ancestor at height %d", h)
		}
		if err := db.DB().Delete(storage.MakeBlockDataKey(anc.Hash)); err != nil {
			t.Fatalf("delete body at %d: %v", h, err)
		}
		if db.HasBlock(anc.Hash) {
			t.Fatalf("body still present at height %d after delete", h)
		}
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
	)
	return &connectedBodyHoleRig{server: server, db: db, cm: cm, idx: idx}
}

func newCompleteChainRig(t *testing.T, tip int32) *connectedBodyHoleRig {
	t.Helper()
	// floor=1 drops nothing (loop is 1..floor-1).
	return newConnectedBodyHoleRig(t, 1, tip)
}

// newGappedRetentionRig is the live 87ac1d8 shape, scaled: unretained
// prefix, an island of bodies, a hole, then a contiguous suffix to the
// tip. 2026-09-18 mainnet: first body 952185, hole 966302..967347,
// suffix 967348..tip.
func newGappedRetentionRig(t *testing.T, firstBody, holeLo, holeHi, tip int32) *connectedBodyHoleRig {
	t.Helper()
	rig := newConnectedBodyHoleRig(t, firstBody, tip)
	rig.punchBodies(t, holeLo, holeHi)
	return rig
}

func (r *connectedBodyHoleRig) punchBodies(t *testing.T, lo, hi int32) {
	t.Helper()
	tipNode := r.cm.BestBlockNode()
	if tipNode == nil {
		t.Fatal("no tip")
	}
	for h := lo; h <= hi; h++ {
		anc := tipNode.GetAncestor(h)
		if anc == nil {
			t.Fatalf("no ancestor at height %d", h)
		}
		if err := r.db.DB().Delete(storage.MakeBlockDataKey(anc.Hash)); err != nil {
			t.Fatalf("delete body at %d: %v", h, err)
		}
		if r.db.HasBlockBody(anc.Hash) {
			t.Fatalf("body still present at height %d after delete", h)
		}
	}
}

func (r *connectedBodyHoleRig) hashAt(t *testing.T, height int32) string {
	t.Helper()
	tipNode := r.cm.BestBlockNode()
	if tipNode == nil {
		t.Fatal("no tip")
	}
	anc := tipNode.GetAncestor(height)
	if anc == nil {
		t.Fatalf("no ancestor at height %d", height)
	}
	return anc.Hash.String()
}

func (r *connectedBodyHoleRig) bodyViaGetblock(t *testing.T, height int32) bool {
	t.Helper()
	hexHash := r.hashAt(t, height)
	resp := testRPCRequest(t, r.server.handleRPC, "getblock", []interface{}{hexHash, float64(0)}, "", "")
	return resp.Error == nil
}

func rpcJSONMap(t *testing.T, server *Server, method string, params []interface{}) map[string]interface{} {
	t.Helper()
	resp := testRPCRequest(t, server.handleRPC, method, params, "", "")
	if resp.Error != nil {
		t.Fatalf("%s errored: %v", method, resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("%s result type %T, want map", method, resp.Result)
	}
	return m
}

func TestPrunedHistory_CompleteChainReportsPrunedFalse(t *testing.T) {
	rig := newCompleteChainRig(t, 10)
	m := rpcJSONMap(t, rig.server, "getblockchaininfo", []interface{}{})
	if pruned, _ := m["pruned"].(bool); pruned {
		t.Fatalf("complete chain must report pruned=false, got %v", m["pruned"])
	}
	if _, present := m["pruneheight"]; present {
		t.Fatalf("complete chain must omit pruneheight, got %v", m["pruneheight"])
	}
	if _, present := m["prune_target_size"]; present {
		t.Fatalf("do not invent prune_target_size: %v", m["prune_target_size"])
	}
}

func TestPrunedHistory_SnapshotHoleReportsPrunedAndPruneheight(t *testing.T) {
	rig := newConnectedBodyHoleRig(t, prunedHistoryFloor, prunedHistoryTip)
	m := rpcJSONMap(t, rig.server, "getblockchaininfo", []interface{}{})
	if pruned, _ := m["pruned"].(bool); !pruned {
		t.Fatalf("snapshot hole must report pruned=true, got pruned=%v json=%v", m["pruned"], m)
	}
	got, _ := m["pruneheight"].(float64)
	if int32(got) != prunedHistoryFloor {
		t.Fatalf("pruneheight = %v, want %d (first height with a body)", m["pruneheight"], prunedHistoryFloor)
	}
	if _, present := m["prune_target_size"]; present {
		t.Fatalf("do not invent prune_target_size when -prune is off: %v", m["prune_target_size"])
	}
	if auto, _ := m["automatic_pruning"].(bool); auto {
		t.Fatalf("do not invent automatic_pruning when -prune is off")
	}
	raw, _ := json.Marshal(m)
	if !strings.Contains(string(raw), `"pruned":true`) {
		t.Fatalf("wire missing pruned:true: %s", raw)
	}
}

func TestPrunedHistory_DenseIndexMissingBodiesReportsPrunedTrue(t *testing.T) {
	rig := newConnectedBodyHoleRig(t, prunedHistoryFloor, prunedHistoryTip)
	m := rpcJSONMap(t, rig.server, "getblockchaininfo", []interface{}{})
	if pruned, _ := m["pruned"].(bool); !pruned {
		t.Fatalf("dense headers + missing bodies must report pruned=true, got %v", m["pruned"])
	}
	got, _ := m["pruneheight"].(float64)
	if int32(got) != prunedHistoryFloor {
		t.Fatalf("pruneheight = %v, want %d", m["pruneheight"], prunedHistoryFloor)
	}
	// Headers are dense but the body is gone: getblockhash consults the
	// body store, not a floor cutoff, and must not hand out the index hash.
	resp := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(5)}, "", "")
	if resp.Error == nil {
		t.Fatal("getblockhash(5) must not return a hash for a body we do not hold")
	}
	if resp.Error.Code != RPCErrMisc || resp.Error.Message != prunedDataMsg {
		t.Fatalf("got %v, want -1 %q", resp.Error, prunedDataMsg)
	}
}

func TestPrunedHistory_GetBlockHashBelowFloorIsMinus1NotMinus8(t *testing.T) {
	server := indexHoleServer(t, prunedHistoryFloor, prunedHistoryTip)
	resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{float64(1)}, "", "")
	if resp.Error == nil {
		t.Fatal("getblockhash(1) must error (not retained)")
	}
	if resp.Error.Code != RPCErrMisc {
		t.Fatalf("not-retained must be -1 (RPC_MISC_ERROR), not %d; got %v", resp.Error.Code, resp.Error)
	}
	if resp.Error.Message != prunedDataMsg {
		t.Fatalf("message = %q, want %q", resp.Error.Message, prunedDataMsg)
	}
	if resp.Error.Message == oorMsg {
		t.Fatal("in-range missing height must not look like a bad parameter")
	}
}

func TestPrunedHistory_GetBlockHashMidHoleIsMinus1NotMinus8(t *testing.T) {
	server := indexHoleServer(t, prunedHistoryFloor, prunedHistoryTip)
	resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{float64(5)}, "", "")
	if resp.Error == nil {
		t.Fatal("getblockhash(5) must error (not retained)")
	}
	if resp.Error.Code != RPCErrMisc || resp.Error.Message != prunedDataMsg {
		t.Fatalf("got %v, want -1 %q", resp.Error, prunedDataMsg)
	}
}

func TestPrunedHistory_GetBlockHashAtFloorReturnsHash(t *testing.T) {
	server := indexHoleServer(t, prunedHistoryFloor, prunedHistoryTip)
	for _, h := range []int32{0, prunedHistoryFloor, prunedHistoryTip} {
		resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{float64(h)}, "", "")
		if resp.Error != nil {
			t.Fatalf("getblockhash(%d) errored: %v", h, resp.Error)
		}
		got, ok := resp.Result.(string)
		if !ok || len(got) != 64 {
			t.Fatalf("getblockhash(%d) result = %v (%T), want 64-char hex", h, resp.Result, resp.Result)
		}
		if got != prunedHistoryHash(h).String() {
			t.Fatalf("getblockhash(%d) = %s, want %s", h, got, prunedHistoryHash(h).String())
		}
	}
}

func TestPrunedHistory_GetBlockHashAboveTipIsStillMinus8(t *testing.T) {
	server := indexHoleServer(t, prunedHistoryFloor, prunedHistoryTip)
	for _, h := range []float64{21, 999999} {
		resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{h}, "", "")
		if resp.Error == nil {
			t.Fatalf("getblockhash(%v) must be out of range", h)
		}
		if resp.Error.Code != RPCErrInvalidParameter || resp.Error.Message != oorMsg {
			t.Fatalf("getblockhash(%v) = %v, want -8 %q", h, resp.Error, oorMsg)
		}
	}
}

func TestPrunedHistory_GetBlockHashNegativeIsStillMinus8(t *testing.T) {
	server := indexHoleServer(t, prunedHistoryFloor, prunedHistoryTip)
	resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{float64(-1)}, "", "")
	if resp.Error == nil {
		t.Fatal("getblockhash(-1) must be out of range")
	}
	if resp.Error.Code != RPCErrInvalidParameter || resp.Error.Message != oorMsg {
		t.Fatalf("got %v, want -8 %q", resp.Error, oorMsg)
	}
}

func TestPrunedHistory_GetBlockMissingBodyWithIndexIsPrunedData(t *testing.T) {
	rig := newConnectedBodyHoleRig(t, prunedHistoryFloor, prunedHistoryTip)
	// Probe getblock-by-hash independently of getblockhash: the height
	// index still resolves, the body store does not.
	hashHex := rig.hashAt(t, 5)
	resp := testRPCRequest(t, rig.server.handleRPC, "getblock", []interface{}{hashHex}, "", "")
	if resp.Error == nil {
		t.Fatal("getblock of a known-but-unretained body must error")
	}
	if resp.Error.Code != RPCErrMisc || resp.Error.Message != prunedDataMsg {
		t.Fatalf("got %v, want -1 %q (not -5 Block not found)", resp.Error, prunedDataMsg)
	}
}

func TestPrunedHistory_GetBlockAtFloorHasBody(t *testing.T) {
	rig := newConnectedBodyHoleRig(t, prunedHistoryFloor, prunedHistoryTip)
	hashResp := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(prunedHistoryFloor)}, "", "")
	if hashResp.Error != nil {
		t.Fatalf("getblockhash(%d): %v", prunedHistoryFloor, hashResp.Error)
	}
	hashHex, _ := hashResp.Result.(string)
	resp := testRPCRequest(t, rig.server.handleRPC, "getblock", []interface{}{hashHex, float64(0)}, "", "")
	if resp.Error != nil {
		t.Fatalf("getblock at floor: %v", resp.Error)
	}
	hexStr, ok := resp.Result.(string)
	if !ok || hexStr == "" {
		t.Fatalf("getblock at floor result = %v (%T), want hex", resp.Result, resp.Result)
	}
}

func TestPrunedHistory_InteriorHoleRaisesPruneheightToContiguousSuffix(t *testing.T) {
	// Binary-search first-body is 6; the contiguous run to the tip
	// starts at 14. pruneheight is the latter (Core GetFirstBlock).
	// 385e480 advertised the first stored body and over-claimed.
	rig := newGappedRetentionRig(t, 6, 11, 13, 20)
	m := rpcJSONMap(t, rig.server, "getblockchaininfo", []interface{}{})
	if pruned, _ := m["pruned"].(bool); !pruned {
		t.Fatalf("gapped retention must report pruned=true, got %v", m["pruned"])
	}
	got, _ := m["pruneheight"].(float64)
	if int32(got) != 14 {
		t.Fatalf("pruneheight = %v, want 14 (contiguous suffix, not first body 6)", m["pruneheight"])
	}
	if _, present := m["prune_target_size"]; present {
		t.Fatalf("do not invent prune_target_size when -prune is off: %v", m["prune_target_size"])
	}
}

func TestPrunedHistory_TwoSidedProbeAtPruneheight(t *testing.T) {
	rig := newGappedRetentionRig(t, 6, 11, 13, 20)
	m := rpcJSONMap(t, rig.server, "getblockchaininfo", []interface{}{})
	got, _ := m["pruneheight"].(float64)
	floor := int32(got)
	if floor != 14 {
		t.Fatalf("pruneheight = %v, want 14", m["pruneheight"])
	}
	if !rig.db.HasBlockBody(mustAncestorHash(t, rig, 10)) {
		t.Fatal("island body at 10 must still be on disk")
	}
	if rig.db.HasBlockBody(mustAncestorHash(t, rig, 11)) {
		t.Fatal("hole at 11 must have no body")
	}
	if rig.db.HasBlockBody(mustAncestorHash(t, rig, 13)) {
		t.Fatal("hole at 13 must have no body")
	}
	if !rig.db.HasBlockBody(mustAncestorHash(t, rig, 14)) {
		t.Fatal("suffix start 14 must have a body")
	}
	if !rig.bodyViaGetblock(t, floor) {
		t.Fatalf("getblock at pruneheight=%d must succeed", floor)
	}
	if !rig.bodyViaGetblock(t, floor+1) {
		t.Fatalf("getblock at pruneheight+1=%d must succeed", floor+1)
	}
	if !rig.bodyViaGetblock(t, 20) {
		t.Fatal("getblock at tip must succeed")
	}
	if rig.bodyViaGetblock(t, 11) {
		t.Fatal("getblock at hole 11 must be refused")
	}
	if rig.bodyViaGetblock(t, 13) {
		t.Fatal("getblock at hole 13 must be refused")
	}
	if rig.bodyViaGetblock(t, 5) {
		t.Fatal("getblock below first body must be refused")
	}
	// Island below pruneheight is still servable by hash — we hold the body.
	if !rig.bodyViaGetblock(t, 10) {
		t.Fatal("getblock of island 10 must succeed (body present, below pruneheight)")
	}
}

func TestPrunedHistory_GetBlockHashAtInteriorHoleIsMinus1NotIndexHash(t *testing.T) {
	rig := newGappedRetentionRig(t, 6, 11, 13, 20)
	// Height index / header walk still resolves 11.
	if _, ok := rig.server.hashAtHeight(11); !ok {
		t.Fatal("height 11 must still be in the index")
	}
	resp := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(11)}, "", "")
	if resp.Error == nil {
		t.Fatalf("getblockhash(11) must not hand out a hash for a body we do not hold, got %v", resp.Result)
	}
	if resp.Error.Code != RPCErrMisc || resp.Error.Message != prunedDataMsg {
		t.Fatalf("got %v, want -1 %q", resp.Error, prunedDataMsg)
	}
	atFloor := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(14)}, "", "")
	if atFloor.Error != nil {
		t.Fatalf("getblockhash(14) at contiguous floor: %v", atFloor.Error)
	}
	if _, ok := atFloor.Result.(string); !ok {
		t.Fatalf("getblockhash(14) type %T", atFloor.Result)
	}
}

func TestPrunedHistory_GetBlockHashOnIslandBelowHoleReturnsHash(t *testing.T) {
	rig := newGappedRetentionRig(t, 6, 11, 13, 20)
	// Floor cutoff over-claims: height 10 has a body, so a pruneheight
	// cutoff of 14 would refuse a hash we can actually serve.
	resp := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(10)}, "", "")
	if resp.Error != nil {
		t.Fatalf("getblockhash(10) island below pruneheight must return the hash, got %v", resp.Error)
	}
	got, ok := resp.Result.(string)
	if !ok || len(got) != 64 {
		t.Fatalf("getblockhash(10) = %v (%T), want 64-char hex", resp.Result, resp.Result)
	}
}

func TestPrunedHistory_GetBlockHashBelowFirstBodyOnDenseHeadersIsMinus1(t *testing.T) {
	rig := newConnectedBodyHoleRig(t, prunedHistoryFloor, prunedHistoryTip)
	resp := testRPCRequest(t, rig.server.handleRPC, "getblockhash", []interface{}{float64(5)}, "", "")
	if resp.Error == nil {
		t.Fatal("getblockhash(5) must not return a hash for a body we do not hold")
	}
	if resp.Error.Code != RPCErrMisc || resp.Error.Message != prunedDataMsg {
		t.Fatalf("got %v, want -1 %q", resp.Error, prunedDataMsg)
	}
}

func mustAncestorHash(t *testing.T, rig *connectedBodyHoleRig, height int32) wire.Hash256 {
	t.Helper()
	tipNode := rig.cm.BestBlockNode()
	if tipNode == nil {
		t.Fatal("no tip")
	}
	anc := tipNode.GetAncestor(height)
	if anc == nil {
		t.Fatalf("no ancestor at height %d", height)
	}
	return anc.Hash
}
