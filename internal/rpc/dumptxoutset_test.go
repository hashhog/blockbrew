package rpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// encodeBIP34HeightForTest mirrors the helper in
// internal/consensus/chainmanager_test.go (kept private there).
func encodeBIP34HeightForTest(height int32) []byte {
	if height == 0 {
		return []byte{0x00}
	}
	if height >= 1 && height <= 16 {
		return []byte{byte(script.OP_1 + height - 1)}
	}
	var data []byte
	switch {
	case height < 128:
		data = []byte{byte(height)}
	case height < 32768:
		data = []byte{byte(height), byte(height >> 8)}
	default:
		data = []byte{byte(height), byte(height >> 8), byte(height >> 16)}
		if data[len(data)-1]&0x80 != 0 {
			data = append(data, 0x00)
		}
	}
	return append([]byte{byte(len(data))}, data...)
}

// buildRegtestBlock mines a minimal regtest block on top of prevNode. The only
// transaction is the coinbase, which sends to OP_TRUE (mirrors the helper in
// chainmanager_test.go that's package-private over there).
func buildRegtestBlock(t *testing.T, params *consensus.ChainParams, prevNode *consensus.BlockNode) *wire.MsgBlock {
	t.Helper()

	height := prevNode.Height + 1
	heightScript := encodeBIP34HeightForTest(height)
	if len(heightScript) < 2 {
		heightScript = append(heightScript, 0x00)
	}

	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  heightScript,
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    consensus.CalcBlockSubsidy(height),
			PkScript: []byte{0x51}, // OP_TRUE
		}},
		LockTime: 0,
	}

	txs := []*wire.MsgTx{coinbase}
	hashes := []wire.Hash256{coinbase.TxHash()}
	merkleRoot := consensus.CalcMerkleRoot(hashes)

	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prevNode.Hash,
		MerkleRoot: merkleRoot,
		Timestamp:  prevNode.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}
	target := consensus.CompactToBig(header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		header.Nonce = i
		hash := header.BlockHash()
		if consensus.HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}

	return &wire.MsgBlock{Header: header, Transactions: txs}
}

// dumpTxOutSetTestRig wires up a regtest chain manager + RPC server against
// in-memory storage and returns a connected fleet useful for exercising the
// dumptxoutset rollback path.
type dumpTxOutSetTestRig struct {
	params *consensus.ChainParams
	idx    *consensus.HeaderIndex
	db     *storage.ChainDB
	utxo   *consensus.UTXOSet
	cm     *consensus.ChainManager
	server *Server
	tips   []*consensus.BlockNode // tips[i] = chain node at height i+1
}

func newDumpTxOutSetTestRig(t *testing.T, nBlocks int) *dumpTxOutSetTestRig {
	t.Helper()

	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	utxo := consensus.NewUTXOSet(db)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
		UTXOSet:     utxo,
	})

	tips := make([]*consensus.BlockNode, 0, nBlocks)
	prev := idx.Genesis()
	for i := 0; i < nBlocks; i++ {
		blk := buildRegtestBlock(t, params, prev)
		node, err := idx.AddHeader(blk.Header)
		if err != nil {
			t.Fatalf("AddHeader at height %d: %v", prev.Height+1, err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock at height %d: %v", prev.Height+1, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock at height %d: %v", prev.Height+1, err)
		}
		tips = append(tips, node)
		prev = node
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	return &dumpTxOutSetTestRig{
		params: params,
		idx:    idx,
		db:     db,
		utxo:   utxo,
		cm:     cm,
		server: server,
		tips:   tips,
	}
}

func (r *dumpTxOutSetTestRig) callDumpTxOutSet(t *testing.T, args []interface{}) (*DumpTxOutSetResult, *RPCError) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	result, rpcErr := r.server.handleDumpTxOutSet(raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	dr, ok := result.(*DumpTxOutSetResult)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	return dr, nil
}

// TestDumpTxOutSetLatestStillWorks ensures the existing default
// "latest" path is unaffected by the rollback wiring. (Honest-progress
// guardrail from the task brief.)
func TestDumpTxOutSetLatestStillWorks(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 5)
	tipHash, tipHeight := rig.cm.BestBlock()

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo.dat")

	dr, rpcErr := rig.callDumpTxOutSet(t, []interface{}{path})
	if rpcErr != nil {
		t.Fatalf("dumptxoutset(latest, default): %+v", rpcErr)
	}
	if dr.BaseHeight != tipHeight {
		t.Errorf("BaseHeight = %d, want %d", dr.BaseHeight, tipHeight)
	}
	if dr.BaseHash != tipHash.String() {
		t.Errorf("BaseHash = %s, want %s", dr.BaseHash, tipHash.String())
	}

	// Explicit "latest" should produce the same answer.
	dr2, rpcErr := rig.callDumpTxOutSet(t, []interface{}{filepath.Join(dir, "utxo2.dat"), "latest"})
	if rpcErr != nil {
		t.Fatalf("dumptxoutset(\"latest\"): %+v", rpcErr)
	}
	if dr2.BaseHeight != tipHeight || dr2.BaseHash != tipHash.String() {
		t.Errorf("explicit latest mismatch: got h=%d hash=%s, want h=%d hash=%s",
			dr2.BaseHeight, dr2.BaseHash, tipHeight, tipHash.String())
	}

	// Chain should still be at the original tip after a no-op latest dump.
	gotHash, gotHeight := rig.cm.BestBlock()
	if gotHash != tipHash || gotHeight != tipHeight {
		t.Errorf("chain moved during latest dump: got h=%d hash=%s, want h=%d hash=%s",
			gotHeight, gotHash.String(), tipHeight, tipHash.String())
	}

	// Snapshot file must read back as a valid SnapshotMetadata pointing at tip.
	verifySnapshotMetadata(t, path, rig.params.NetworkMagic, tipHash)
}

// TestDumpTxOutSetRollbackToHeight exercises the rollback path against a
// known height: it must restore the chain to the original tip afterwards
// and the dumped file must reference the rolled-back base block.
func TestDumpTxOutSetRollbackToHeight(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 5)
	originalTipHash, originalTipHeight := rig.cm.BestBlock()

	target := rig.tips[2] // height 3
	if target.Height != 3 {
		t.Fatalf("test scaffolding: want target height 3, got %d", target.Height)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo-rollback.dat")

	dr, rpcErr := rig.callDumpTxOutSet(t, []interface{}{
		path,
		"rollback",
		map[string]interface{}{"rollback": float64(target.Height)},
	})
	if rpcErr != nil {
		t.Fatalf("dumptxoutset rollback: %+v", rpcErr)
	}

	if dr.BaseHeight != target.Height {
		t.Errorf("BaseHeight = %d, want %d", dr.BaseHeight, target.Height)
	}
	if dr.BaseHash != target.Hash.String() {
		t.Errorf("BaseHash = %s, want %s", dr.BaseHash, target.Hash.String())
	}

	// Chain must be restored to original tip after the rollback dance.
	gotHash, gotHeight := rig.cm.BestBlock()
	if gotHeight != originalTipHeight || gotHash != originalTipHash {
		t.Fatalf("chain not restored: got h=%d hash=%s, want h=%d hash=%s",
			gotHeight, gotHash.String(), originalTipHeight, originalTipHash.String())
	}

	// Snapshot file must reference the rolled-back base block.
	verifySnapshotMetadata(t, path, rig.params.NetworkMagic, target.Hash)
}

// TestDumpTxOutSetRollbackByHash accepts a 64-char hex block hash through the
// `rollback` named option.
func TestDumpTxOutSetRollbackByHash(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 4)
	target := rig.tips[1] // height 2

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo-by-hash.dat")

	dr, rpcErr := rig.callDumpTxOutSet(t, []interface{}{
		path,
		"rollback",
		map[string]interface{}{"rollback": target.Hash.String()},
	})
	if rpcErr != nil {
		t.Fatalf("dumptxoutset rollback by hash: %+v", rpcErr)
	}
	if dr.BaseHash != target.Hash.String() {
		t.Errorf("BaseHash = %s, want %s", dr.BaseHash, target.Hash.String())
	}
}

// TestDumpTxOutSetRollbackContradictoryType matches Core's
// "Invalid snapshot type \"%s\" specified with rollback option" guard.
func TestDumpTxOutSetRollbackContradictoryType(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo-bad.dat")

	_, rpcErr := rig.callDumpTxOutSet(t, []interface{}{
		path,
		"latest",
		map[string]interface{}{"rollback": float64(2)},
	})
	if rpcErr == nil {
		t.Fatalf("expected RPC error for type=latest + rollback option")
	}
	if rpcErr.Code != RPCErrInvalidParams {
		t.Errorf("error code = %d, want %d", rpcErr.Code, RPCErrInvalidParams)
	}
}

// TestDumpTxOutSetInvalidType matches Core's
// "Invalid snapshot type ... Please specify \"rollback\" or \"latest\"".
func TestDumpTxOutSetInvalidType(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 2)

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo-invalid-type.dat")

	_, rpcErr := rig.callDumpTxOutSet(t, []interface{}{path, "bogus"})
	if rpcErr == nil {
		t.Fatalf("expected RPC error for type=bogus")
	}
	if rpcErr.Code != RPCErrInvalidParams {
		t.Errorf("error code = %d, want %d", rpcErr.Code, RPCErrInvalidParams)
	}
}

// TestDumpTxOutSetAtomicWrite asserts the canonical Core .incomplete + rename
// flow: a successful dump leaves <path> on disk and NO <path>.incomplete
// orphan. Refusing to overwrite an existing destination is also covered.
//
// Mirrors `bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset` which writes to
// `temppath = path + ".incomplete"`, fsyncs, and renames before returning.
func TestDumpTxOutSetAtomicWrite(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)

	dir := t.TempDir()
	path := filepath.Join(dir, "utxo-atomic.dat")

	if _, rpcErr := rig.callDumpTxOutSet(t, []interface{}{path}); rpcErr != nil {
		t.Fatalf("dumptxoutset(latest): %+v", rpcErr)
	}

	// <path> exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot path missing after successful dump: %v", err)
	}

	// <path>.incomplete must NOT exist after a successful dump.
	if _, err := os.Stat(snapshotTempPath(path)); err == nil {
		t.Fatalf("temp file %s still present after successful dump (expected to be renamed away)", snapshotTempPath(path))
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error for temp path: %v", err)
	}

	// Calling dumptxoutset against the same path must refuse — Core's
	// "<path> already exists" guard.
	_, rpcErr := rig.callDumpTxOutSet(t, []interface{}{path})
	if rpcErr == nil {
		t.Fatalf("expected error when dumping to an existing path")
	}
	if rpcErr.Code != RPCErrInvalidParams {
		t.Errorf("expected RPCErrInvalidParams for clobber attempt, got %d", rpcErr.Code)
	}
}

// TestDumpTxOutSetCleansTempOnError forces the snapshot writer down a failure
// path (a path under a non-existent directory) and asserts that no
// .incomplete file is left behind on the filesystem.
func TestDumpTxOutSetCleansTempOnError(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 2)

	dir := t.TempDir()
	// Path under a directory that doesn't exist — os.Create fails so no
	// temp file is ever created. We assert the cleanup path doesn't leave
	// orphans even when the temp file was never created.
	bad := filepath.Join(dir, "no-such-subdir", "utxo-fail.dat")

	_, rpcErr := rig.callDumpTxOutSet(t, []interface{}{bad})
	if rpcErr == nil {
		t.Fatalf("expected RPC error for unwritable path")
	}

	// Neither path should exist.
	if _, err := os.Stat(bad); err == nil {
		t.Fatalf("final path %s exists after a failed dump", bad)
	}
	if _, err := os.Stat(snapshotTempPath(bad)); err == nil {
		t.Fatalf("temp path %s exists after a failed dump", snapshotTempPath(bad))
	}
}

// verifySnapshotMetadata re-reads the snapshot file written by the RPC and
// asserts the magic + network magic + base block hash match expectations.
func verifySnapshotMetadata(t *testing.T, path string, wantMagic [4]byte, wantHash wire.Hash256) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open snapshot %s: %v", path, err)
	}
	defer f.Close()

	var meta consensus.SnapshotMetadata
	if err := meta.Deserialize(f); err != nil {
		t.Fatalf("deserialize snapshot metadata: %v", err)
	}
	if meta.Magic != consensus.SnapshotMagic {
		t.Errorf("snapshot magic = %x, want %x", meta.Magic, consensus.SnapshotMagic)
	}
	if meta.NetworkMagic != wantMagic {
		t.Errorf("network magic = %x, want %x", meta.NetworkMagic, wantMagic)
	}
	if meta.BlockHash != wantHash {
		t.Errorf("block hash = %s, want %s", meta.BlockHash.String(), wantHash.String())
	}
}
