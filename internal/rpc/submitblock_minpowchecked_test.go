package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// submitblock_minpowchecked_test.go — pins the min_pow_checked vouch on the
// RPC block-submission path.
//
// THE DEFECT. Bitcoin Core's min_pow_checked is a CALLER-supplied anti-DoS
// assertion, not a property of the header. AcceptBlockHeader refuses to create
// a new index entry without it:
//
//	if (!min_pow_checked) {
//	    return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK,
//	                         "too-little-chainwork");
//	}
//	                                (bitcoin-core validation.cpp:4229-4233)
//
// and every RPC entry point in Core hard-codes the vouch, because an
// authenticated RPC caller is not the header-flooding peer the gate exists to
// stop: submitblock passes /*min_pow_checked=*/true (rpc/mining.cpp:1095), as
// do generateblock (:157) and submitheader (:1138). net_processing is the real
// caller, and it vouches only after the headers-presync anti-DoS check.
//
// blockbrew's handleSubmitBlock / handleSubmitBlockBatch passed FALSE, so
// blockbrew's analogue of the gate — "reject unless the new tip's cumulative
// work already meets MinimumChainWork" (headerindex.go:474-479) — ran on the
// RPC path. On a normally-synced mainnet node the tip's work is astronomically
// past the threshold, so nothing was ever observed. On a chain that is
// legitimately BELOW the threshold it rejects every submitted block, and at an
// assumeUTXO snapshot base that is permanent: the base is a real early-chain
// block whose cumulative work can never grow, so the node positions at the base
// and then refuses its first child forever. Caught by the 2026-09-05 boundary
// campaign at mainnet block 6300 above base 6299 (cumulative work
// 0x189c189c189c, ~19 orders of magnitude below mainnet nMinimumChainWork):
// submitblock answered a bare "rejected" for a block Core accepts.
//
// The 2026-06-24 submitheader review caught this exact divergence and fixed it
// on the method under review (blockbrew 200b5ba) while noting the
// MinimumChainWork divergence was "regtest-untestable". It is testable — the
// threshold is a ChainParams field, so a regtest rig can simply carry a
// non-zero one, which is what makes these tests real rather than structural.

// lowWorkRigMinChainWork is far above anything a handful of regtest blocks can
// accumulate (regtest work per block is ~2), so every candidate in these tests
// is genuinely below the threshold — the same relation a real snapshot base at
// height 6299 has to mainnet's nMinimumChainWork.
var lowWorkRigMinChainWork = new(big.Int).Lsh(big.NewInt(1), 64)

// newLowWorkSubmitBlockRig mirrors newSubmitBlockRig but arms the
// MinimumChainWork threshold, so the min_pow_checked gate is live. The rig's
// own bootstrap vouches (AddHeader(..., true)), exactly as P2P header sync
// (p2p/sync.go:879,942) and the chain manager (chainmanager.go:2341,2426) do.
func newLowWorkSubmitBlockRig(t *testing.T, nBlocks int) *submitBlockTestRig {
	t.Helper()

	params := consensus.RegtestParams()
	params.MinimumChainWork = new(big.Int).Set(lowWorkRigMinChainWork)

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
		node, err := idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("rig bootstrap AddHeader at height %d: %v", prev.Height+1, err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("rig bootstrap StoreBlock at height %d: %v", prev.Height+1, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("rig bootstrap ConnectBlock at height %d: %v", prev.Height+1, err)
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

	return &submitBlockTestRig{
		params: params, idx: idx, db: db, utxo: utxo, cm: cm, server: server, tips: tips,
	}
}

// remineSibling returns a DISTINCT valid block with the same parent as blk, by
// shifting the timestamp one second and re-mining. buildRegtestBlock is
// deterministic per parent, so this is the only way to get two candidates off
// one tip — needed for the negative control, which must not collide with the
// block the RPC accepts.
func remineSibling(t *testing.T, params *consensus.ChainParams, blk *wire.MsgBlock) *wire.MsgBlock {
	t.Helper()

	hdr := blk.Header
	hdr.Timestamp++
	target := consensus.CompactToBig(hdr.Bits)
	found := false
	for i := uint32(0); i < 10_000_000; i++ {
		hdr.Nonce = i
		if consensus.HashToBig(hdr.BlockHash()).Cmp(target) <= 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("could not mine a sibling regtest header")
	}
	if hdr.BlockHash() == blk.Header.BlockHash() {
		t.Fatal("sibling is not distinct from the original")
	}
	return &wire.MsgBlock{Header: hdr, Transactions: blk.Transactions}
}

// TestSubmitBlockVouchesMinPowChecked is the regression: submitblock must
// accept a block extending a chain whose cumulative work is below
// MinimumChainWork, because Core's submitblock vouches
// (/*min_pow_checked=*/true, rpc/mining.cpp:1095).
//
// The negative control on the same rig proves the gate is armed and that only
// the CALLER's vouch changed: the unvouched convention still rejects with
// ErrTooLittleChainwork. Without the control this test would pass just as
// happily against a rig whose threshold was never reached.
func TestSubmitBlockVouchesMinPowChecked(t *testing.T) {
	rig := newLowWorkSubmitBlockRig(t, 3)
	tipNode := rig.tips[len(rig.tips)-1]

	candidate := buildRegtestBlock(t, rig.params, tipNode)
	control := remineSibling(t, rig.params, candidate)

	// Precondition: the chain really is below the threshold, so the gate has
	// something to bite on.
	if tipNode.TotalWork.Cmp(rig.params.MinimumChainWork) >= 0 {
		t.Fatalf("test bug: rig tip work %s already meets MinimumChainWork %s",
			tipNode.TotalWork.Text(16), rig.params.MinimumChainWork.Text(16))
	}

	// NEGATIVE CONTROL — the unvouched convention (p2p/sync.go:2686, an
	// unrequested block message) must still refuse this header.
	if _, err := rig.idx.AddHeader(control.Header, false); !errors.Is(err, consensus.ErrTooLittleChainwork) {
		t.Fatalf("control: AddHeader(minPowChecked=false) below MinimumChainWork: want ErrTooLittleChainwork, got %v", err)
	}
	// …and accept it once vouched, so the ONLY variable is the flag.
	if _, err := rig.idx.AddHeader(control.Header, true); err != nil {
		t.Fatalf("control: AddHeader(minPowChecked=true) below MinimumChainWork: want accept, got %v", err)
	}

	// THE REGRESSION — submitblock must vouch on the caller's behalf.
	res, rpcErr := rig.submitBlock(t, candidate)
	if rpcErr != nil {
		t.Fatalf("submitblock returned an RPC error: %+v", rpcErr)
	}
	if res != nil {
		t.Fatalf("submitblock rejected a valid block below MinimumChainWork with %q; "+
			"Core answers null here (min_pow_checked=true, rpc/mining.cpp:1095)", res)
	}

	tipHash, tipHeight := rig.cm.BestBlock()
	if tipHash != candidate.Header.BlockHash() || tipHeight != tipNode.Height+1 {
		t.Fatalf("tip did not advance to the submitted block: got %s@%d, want %s@%d",
			tipHash.String()[:16], tipHeight,
			candidate.Header.BlockHash().String()[:16], tipNode.Height+1)
	}
}

// TestSubmitBlockBatchVouchesMinPowChecked pins the same contract on
// submitblockbatch, which carried a copy of the unvouched call. Core has no
// batch RPC, so its per-block semantics must equal submitblock's.
func TestSubmitBlockBatchVouchesMinPowChecked(t *testing.T) {
	rig := newLowWorkSubmitBlockRig(t, 3)
	tipNode := rig.tips[len(rig.tips)-1]
	candidate := buildRegtestBlock(t, rig.params, tipNode)

	var w byteWriter
	if err := candidate.Serialize(&w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	raw, err := json.Marshal([]interface{}{[]string{hex.EncodeToString(w.bytes)}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	res, rpcErr := rig.server.handleSubmitBlockBatch(raw)
	if rpcErr != nil {
		t.Fatalf("submitblockbatch returned an RPC error: %+v", rpcErr)
	}
	results, ok := res.([]interface{})
	if !ok || len(results) != 1 {
		t.Fatalf("submitblockbatch returned %T %v, want a 1-element array", res, res)
	}
	if results[0] != nil {
		t.Fatalf("submitblockbatch rejected a valid block below MinimumChainWork with %q", results[0])
	}

	if tipHash, tipHeight := rig.cm.BestBlock(); tipHash != candidate.Header.BlockHash() ||
		tipHeight != tipNode.Height+1 {
		t.Fatalf("tip did not advance: got %s@%d", tipHash.String()[:16], tipHeight)
	}
}
