package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestFIX80_GetBlockHash_ChainDBFallback exercises the chainDB-fallback path
// of handleGetBlockHash for the configuration where no chain manager is
// wired up (early-startup or storage-only test rigs).  This is the
// pre-FIX-80 behaviour and remains the only path used when chainMgr is nil.
//
// Pre-FIX-80, height-out-of-range returned RPC error -5 ("Block not found"),
// which Bitcoin Core's rpc/blockchain.cpp:589-591 returns as -8
// ("Block height out of range").  FIX-80 aligns the error code.  The
// daily consensus-diff harness flagged the divergence on the live mainnet
// node — see consensus-diff-20260516T070038Z.md.
func TestFIX80_GetBlockHash_ChainDBFallback(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cdb := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(cdb),
	)

	// Seed chainDB with three known height->hash mappings, including
	// height 0 (analogous to a node that has the genesis mapping written
	// to disk).
	mappings := []struct {
		height int32
		hash   wire.Hash256
	}{
		{0, wire.Hash256{0xde, 0xad, 0xbe, 0xef}},
		{1, wire.Hash256{0xca, 0xfe, 0xba, 0xbe}},
		{900000, wire.Hash256{0x90, 0x00, 0x00, 0x00}},
	}
	for _, m := range mappings {
		if err := cdb.SetBlockHeight(m.height, m.hash); err != nil {
			t.Fatalf("SetBlockHeight(%d): %v", m.height, err)
		}
	}

	// Verify chainDB roundtrip for each mapping.  Note that, since
	// chainMgr is not wired here, the RPC handler takes the fallback
	// path on every call — exactly what we want to test.
	for _, m := range mappings {
		resp := testRPCRequest(t, server.handleRPC,
			"getblockhash", []interface{}{float64(m.height)}, "", "")
		if resp.Error != nil {
			t.Errorf("getblockhash(%d) errored: %v", m.height, resp.Error)
			continue
		}
		got, ok := resp.Result.(string)
		if !ok {
			t.Errorf("getblockhash(%d) result type = %T, want string", m.height, resp.Result)
			continue
		}
		want := m.hash.String()
		if got != want {
			t.Errorf("getblockhash(%d) = %s, want %s", m.height, got, want)
		}
	}

	// A height not in chainDB should now return "Block height out of range"
	// with RPC_INVALID_PARAMETER (-8), matching Core's behaviour.
	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(424242)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error for unknown height, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("error code = %d, want %d (RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
	if resp.Error.Message != "Block height out of range" {
		t.Errorf("error message = %q, want %q",
			resp.Error.Message, "Block height out of range")
	}
}

// TestFIX80_GetBlockHash_InMemoryActiveChain exercises the primary path of
// handleGetBlockHash: walking the in-memory active chain via
// chainMgr.BestBlockNode().GetAncestor(height).  This matches Bitcoin
// Core's rpc/blockchain.cpp::getblockhash which uses
// `chainman.ActiveChain()[nHeight]`.
//
// The bug FIX-80 closes: pre-fix, blockbrew read only chainDB, so a node
// that had not written height->hash mappings for historical heights (e.g.
// when started post-assume-valid IBD) would return "Block not found" for
// any height below the launched-from tip — even though the BlockNode
// chain in memory was complete from genesis to tip.
func TestFIX80_GetBlockHash_InMemoryActiveChain(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
	)

	// At freshly-initialised time the chain manager tip is genesis.
	// `getblockhash 0` should return the genesis hash via the in-memory
	// path — chainDB has no height->hash mapping yet.
	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(0)}, "", "")
	if resp.Error != nil {
		t.Fatalf("getblockhash(0): %v", resp.Error)
	}
	got, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("getblockhash(0) result type = %T, want string", resp.Result)
	}
	if got != params.GenesisHash.String() {
		t.Errorf("getblockhash(0) = %s, want genesis hash %s",
			got, params.GenesisHash.String())
	}

	// A height above the tip must return "Block height out of range"
	// with RPC_INVALID_PARAMETER (-8), matching Core.
	resp = testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(900000)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error for above-tip height, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("above-tip error code = %d, want %d (RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}

	// Negative height must also return "Block height out of range".
	resp = testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(-1)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error for negative height, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("negative-height error code = %d, want %d (RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// TestFIX80_GetBlockHash_InMemoryBeatsStaleChainDB verifies that when the
// in-memory active chain disagrees with chainDB at a given height, the
// in-memory chain wins.  This is the load-bearing invariant the live
// mainnet bug exposed: chainDB was missing historical entries that the
// in-memory chain definitely had (via header sync).  We invert the
// scenario for the test — chainDB has a *wrong* hash for height 0 — and
// assert the RPC still returns the correct (in-memory) genesis hash.
func TestFIX80_GetBlockHash_InMemoryBeatsStaleChainDB(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Plant a bogus height->hash mapping in chainDB.  If the handler
	// falls back to chainDB despite chainMgr being wired, this is the
	// hash it would return.
	bogus := wire.Hash256{0xba, 0xd0}
	if err := db.SetBlockHeight(0, bogus); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
	)

	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(0)}, "", "")
	if resp.Error != nil {
		t.Fatalf("getblockhash(0): %v", resp.Error)
	}
	got, _ := resp.Result.(string)
	if got != params.GenesisHash.String() {
		t.Errorf("in-memory path lost to chainDB: got %s, want genesis %s",
			got, params.GenesisHash.String())
	}
	if got == bogus.String() {
		t.Fatal("handler returned chainDB's bogus hash — in-memory path bypassed")
	}
}

// TestFIX80_GetBlockHash_NoBackingState verifies that with neither a
// chain manager nor a chainDB, the handler returns
// RPC_INVALID_PARAMETER ("Block height out of range") rather than
// the pre-FIX-80 RPC_INVALID_ADDRESS_OR_KEY (-5).
func TestFIX80_GetBlockHash_NoBackingState(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
	)

	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(100)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error with no backing state, got nil")
	}
	// With no chainMgr and no chainDB, height 100 is out of range
	// relative to a genesis-only chain.
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("error code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}
