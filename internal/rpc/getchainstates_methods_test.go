package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// getchainstates mirrors Bitcoin Core's RPCHelpForChainstate
// (bitcoin-core/src/rpc/blockchain.cpp::getchainstates). The shape contract:
//
//   - top-level: { headers: NUM, chainstates: ARR (active/most-work LAST) }
//   - each chainstate: blocks, bestblockhash, bits, target, difficulty,
//     verificationprogress, coins_db_cache_bytes, coins_tip_cache_bytes,
//     validated; snapshot_blockhash is OPTIONAL (only for a from-snapshot
//     chainstate).
//
// These tests pin the four shape fixes: coins_db_cache_bytes /
// coins_tip_cache_bytes are ALWAYS present (Core pushes them unconditionally),
// validated is true for blockbrew's single validated chainstate, and
// snapshot_blockhash is absent (no from-snapshot chainstate at runtime).

// callGetChainStates round-trips the handler result through JSON so the test
// asserts the on-the-wire shape (omitempty behaviour included), exactly what an
// RPC client sees.
func callGetChainStates(t *testing.T, server *Server) map[string]interface{} {
	t.Helper()
	result, rpcErr := server.handleGetChainStates()
	if rpcErr != nil {
		t.Fatalf("getchainstates: %+v", rpcErr)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m
}

// TestGetChainStatesShape builds a small regtest chain and asserts the full
// Core-parity shape of the single (active, validated) chainstate.
func TestGetChainStatesShape(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 5)
	tipHash, tipHeight := rig.cm.BestBlock()

	m := callGetChainStates(t, rig.server)

	// --- top-level: headers == best header height (5 connected blocks). ---
	headers, ok := m["headers"].(float64)
	if !ok {
		t.Fatalf("headers field missing/not a number: %v", m["headers"])
	}
	if int32(headers) != rig.idx.BestHeight() {
		t.Errorf("headers = %d, want %d", int32(headers), rig.idx.BestHeight())
	}

	// --- chainstates: exactly one element (single validated chainstate). ---
	csArr, ok := m["chainstates"].([]interface{})
	if !ok {
		t.Fatalf("chainstates field missing/not an array: %v", m["chainstates"])
	}
	if len(csArr) != 1 {
		t.Fatalf("chainstates len = %d, want 1", len(csArr))
	}
	cs, ok := csArr[0].(map[string]interface{})
	if !ok {
		t.Fatalf("chainstate[0] not an object: %T", csArr[0])
	}

	// --- blocks / bestblockhash track the active tip. ---
	if int32(cs["blocks"].(float64)) != tipHeight {
		t.Errorf("blocks = %v, want %d", cs["blocks"], tipHeight)
	}
	if cs["bestblockhash"] != tipHash.String() {
		t.Errorf("bestblockhash = %v, want %s", cs["bestblockhash"], tipHash.String())
	}

	// --- bits is the active tip's compact target, 8 hex chars. ---
	tipNode := rig.cm.BestBlockNode()
	wantBits := uint32ToBitsHex(tipNode.Header.Bits)
	if cs["bits"] != wantBits {
		t.Errorf("bits = %v, want %s", cs["bits"], wantBits)
	}

	// --- coins_db_cache_bytes / coins_tip_cache_bytes ALWAYS present.
	//     This is the core of fix (1): Core pushes both unconditionally; the
	//     pre-fix omitempty tags dropped them from JSON when zero. ---
	if _, present := cs["coins_db_cache_bytes"]; !present {
		t.Error("coins_db_cache_bytes absent from JSON (must always be emitted)")
	}
	if _, present := cs["coins_tip_cache_bytes"]; !present {
		t.Error("coins_tip_cache_bytes absent from JSON (must always be emitted)")
	}
	// coins_tip_cache_bytes reports the configured in-memory coins-cache budget.
	if got := int64(cs["coins_tip_cache_bytes"].(float64)); got != consensus.DefaultCacheMaxBytes {
		t.Errorf("coins_tip_cache_bytes = %d, want %d (UTXOSet default budget)",
			got, int64(consensus.DefaultCacheMaxBytes))
	}

	// --- validated true (fix (2)). ---
	if v, ok := cs["validated"].(bool); !ok || !v {
		t.Errorf("validated = %v, want true", cs["validated"])
	}

	// --- snapshot_blockhash OPTIONAL: absent for a non-snapshot chainstate
	//     (fix (3) — must be omitted, never emitted as empty/null). ---
	if _, present := cs["snapshot_blockhash"]; present {
		t.Errorf("snapshot_blockhash present for non-snapshot chainstate: %v",
			cs["snapshot_blockhash"])
	}
}

// TestGetChainStatesCoinsTipCacheBytesCustom verifies coins_tip_cache_bytes
// reflects a non-default UTXO cache budget — proving the field is sourced from
// the configured cache size rather than hard-coded.
func TestGetChainStatesCoinsTipCacheBytesCustom(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 2)

	const customBudget int64 = 123_456_789
	// Swap in a chain manager whose UTXOSet carries a custom cache budget. The
	// rig's UTXOSet shares the same chainDB, so the active tip is unchanged.
	customUTXO := consensus.NewUTXOSetWithMaxCache(rig.db, customBudget)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      rig.params,
		HeaderIndex: rig.idx,
		ChainDB:     rig.db,
		UTXOSet:     customUTXO,
	})
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(rig.params),
		WithChainManager(cm),
		WithHeaderIndex(rig.idx),
		WithChainDB(rig.db),
	)

	m := callGetChainStates(t, server)
	csArr := m["chainstates"].([]interface{})
	if len(csArr) != 1 {
		t.Fatalf("chainstates len = %d, want 1", len(csArr))
	}
	cs := csArr[0].(map[string]interface{})
	if got := int64(cs["coins_tip_cache_bytes"].(float64)); got != customBudget {
		t.Errorf("coins_tip_cache_bytes = %d, want %d (custom budget)", got, customBudget)
	}
}

// uint32ToBitsHex formats nBits the way the handler does (Core: "%08x").
func uint32ToBitsHex(bits uint32) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = hexdigits[bits&0xf]
		bits >>= 4
	}
	return string(out)
}
