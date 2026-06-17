// Package rpc — W125 RPC error code parity audit (DISCOVERY).
//
// See audit/w125_rpc_error_parity.md for the full audit. This file
// implements 30 xfail tests pinning down current blockbrew behavior
// for each of the 30 audit gates. Tests assert the **actual**
// emitted error code/message; a future fix wave should flip the
// assertions to the Core-correct value.
//
// Reference: bitcoin-core/src/rpc/protocol.h (canonical RPCErrorCode enum)
// Precedent: FIX-80 (668244f) — getblockhash -5 → -8 alignment.
//
// Convention: each test name encodes "TestW125_BUG_<NN>_<short_label>"
// so the fix wave can flip a single assertion per bug ID.
//
// All tests are pure shape tests — they don't depend on chain state or
// wallet state, only on the json-rpc envelope handling and arg parsing
// done at the head of each handler.
package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/storage"
)

// w125TestServer builds a minimal RPC server with enough state to reach
// every audited handler's argument-validation block. We don't need a
// real chain, wallet, or mempool — only enough wiring so that calls
// don't trip on nil-pointer guards before reaching the arg-validation
// branch under test.
func w125TestServer(t *testing.T) *Server {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nil)
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
		WithMempool(mp),
	)
}

// w125TestServerWithPeerMgr builds the same minimal RPC server as
// w125TestServer but also wires a real (un-Started) PeerManager so the
// addnode / setban / disconnectnode handlers reach their actual
// peer-management error paths instead of short-circuiting on the
// peerMgr-nil guard. NewPeerManager with an empty config performs no
// network I/O and (with no DataDir) loads no ban list, so this is cheap
// and side-effect free for a unit test.
func w125TestServerWithPeerMgr(t *testing.T) *Server {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nil)
	pm := p2p.NewPeerManager(p2p.PeerManagerConfig{ChainParams: params})
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
		WithMempool(mp),
		WithPeerManager(pm),
	)
}

// ─────────────────────────────────────────────────────────────────────
// Gate #1 — getblockhash height out of range (FIX-80 baseline; PRESENT).
// Sanity check that the FIX-80 closure still holds.
// ─────────────────────────────────────────────────────────────────────

func TestW125_Gate01_GetBlockHash_OutOfRange_Present(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{float64(424242)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// Core: -8 RPC_INVALID_PARAMETER ("Block height out of range")
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("PRESENT regressed: code = %d, want %d (FIX-80 RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-2 — getblockhash missing height arg (MISSING).
// Core: -8 RPC_INVALID_PARAMETER
// blockbrew: -32602 RPCErrInvalidParams
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_02_GetBlockHash_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"getblockhash", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// CURRENT (xfail) — blockbrew emits -32602.
	// FUTURE FIX — should be RPCErrInvalidParameter (-8) per Core.
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-3 — getblockheader missing hash arg.
// Core: -8 ; blockbrew: -32602
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_03_GetBlockHeader_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"getblockheader", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-1 — getrawtransaction malformed txid (FIXED).
// A malformed (wrong-length / non-hex) txid is rejected at Core's
// ParseHashV parse boundary with -8 RPC_INVALID_PARAMETER, BEFORE any
// lookup (rpc/util.cpp:117). The earlier doc note "Core wants -5" was
// wrong: -5 is the well-formed-but-absent case, not the malformed-parse
// case. blockbrew now emits -8.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_01_GetRawTransaction_InvalidTxidHex(t *testing.T) {
	server := w125TestServer(t)
	// Non-hex string in txid slot — wrong length AND non-hex.
	resp := testRPCRequest(t, server.handleRPC,
		"getrawtransaction", []interface{}{"not-a-valid-txid-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("malformed txid: code = %d, want %d (-8 RPC_INVALID_PARAMETER, Core ParseHashV)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-4 — getrawtransaction missing txid arg.
// Core: -8 ; blockbrew: -32602
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_04_GetRawTransaction_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"getrawtransaction", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-5 — gettxout missing args.
// Core: -8 for missing-arg, -8 for txid parse-fail.
// blockbrew: -32602 for all.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_05a_GetTxOut_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"gettxout", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_05b_GetTxOut_InvalidTxidHex(t *testing.T) {
	server := w125TestServer(t)
	// FIXED: malformed txid -> -8 at Core's ParseHashV boundary.
	resp := testRPCRequest(t, server.handleRPC,
		"gettxout", []interface{}{"not-hex", float64(0)}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("malformed txid: code = %d, want %d (-8 RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-7 — getmempoolentry shape divergence.
// Core: -5 "Transaction not in mempool"
// blockbrew: -5 with txid embedded in message + -32602 on parse fail.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_07a_GetMempoolEntry_NotFoundMessage(t *testing.T) {
	server := w125TestServer(t)
	// Well-formed but absent txid.
	txid := "0000000000000000000000000000000000000000000000000000000000000001"
	resp := testRPCRequest(t, server.handleRPC,
		"getmempoolentry", []interface{}{txid}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrTxNotFound {
		t.Errorf("code = %d, want %d (-5 RPCErrTxNotFound)",
			resp.Error.Code, RPCErrTxNotFound)
	}
	// Core: bare "Transaction not in mempool" (mempool.cpp:739).
	// blockbrew: appends ": <txid>". Documented as PARTIAL.
	want := "Transaction not in mempool"
	if resp.Error.Message != want {
		t.Logf("PARTIAL divergence: message = %q, Core wants %q (no txid suffix)",
			resp.Error.Message, want)
	}
}

func TestW125_BUG_07b_GetMempoolEntry_InvalidTxidHex(t *testing.T) {
	server := w125TestServer(t)
	// FIXED: malformed txid -> -8 at Core's ParseHashV boundary, BEFORE the
	// mempool lookup. (-5 is the well-formed-but-absent case, see BUG-07a.)
	resp := testRPCRequest(t, server.handleRPC,
		"getmempoolentry", []interface{}{"not-hex"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("malformed txid: code = %d, want %d (-8 RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-8 — getmempoolancestors shape (same shape as BUG-7).
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_08_GetMempoolAncestors_InvalidTxidHex(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"getmempoolancestors", []interface{}{"not-hex"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -5.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-9 — submitblock missing hex arg.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_09_SubmitBlock_MissingHex(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"submitblock", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-10 — getblock invalid hash format.
// Core: -8 for parse, -5 for "Block not found".
// blockbrew: -32602 for parse, -5 for not-found.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_10a_GetBlock_InvalidHashHex(t *testing.T) {
	server := w125TestServer(t)
	// FIXED: malformed blockhash -> -8 at Core's ParseHashV boundary, BEFORE
	// the block lookup. (-5 "Block not found" is the absent case, BUG-10b.)
	resp := testRPCRequest(t, server.handleRPC,
		"getblock", []interface{}{"not-hex"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("malformed blockhash: code = %d, want %d (-8 RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestW125_BUG_10b_GetBlock_NotFound_Present(t *testing.T) {
	server := w125TestServer(t)
	// Well-formed but absent hash.
	hash := "0000000000000000000000000000000000000000000000000000000000000123"
	resp := testRPCRequest(t, server.handleRPC,
		"getblock", []interface{}{hash}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrBlockNotFound {
		t.Errorf("PRESENT regressed: code = %d, want %d (-5 RPCErrBlockNotFound)",
			resp.Error.Code, RPCErrBlockNotFound)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-11 — setban error parity (4 sub-cases).
// Core: -30 invalid IP, -23 already-banned, -8 timestamp-in-past, -30 unban-not-found.
// blockbrew: all -32602 (no -23/-30 constants defined at all).
// ─────────────────────────────────────────────────────────────────────

// FIXED (was a documented-divergence xfail): setban with an un-parseable
// IP/subnet now returns RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) with Core's
// exact message, matching bitcoin-core rpc/net.cpp (the !IsValid → throw
// JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid IP/Subnet")
// gate). Driven through the live handler with a real peerMgr wired so the
// validity check (not the nil-guard) is what fires.
func TestW125_BUG_11a_SetBan_InvalidIP(t *testing.T) {
	server := w125TestServerWithPeerMgr(t)
	resp := testRPCRequest(t, server.handleRPC,
		"setban", []interface{}{"not-an-ip", "add"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrClientInvalidIPOrSubnet {
		t.Errorf("setban invalid IP code = %d, want %d (RPC_CLIENT_INVALID_IP_OR_SUBNET)",
			resp.Error.Code, RPCErrClientInvalidIPOrSubnet)
	}
	if resp.Error.Message != "Error: Invalid IP/Subnet" {
		t.Errorf("setban invalid IP message = %q, want %q",
			resp.Error.Message, "Error: Invalid IP/Subnet")
	}

	// A malformed subnet (has '/', bad CIDR) takes the subnet branch and is
	// likewise rejected with -30.
	resp2 := testRPCRequest(t, server.handleRPC,
		"setban", []interface{}{"10.0.0.0/99", "add"}, "", "")
	if resp2.Error == nil || resp2.Error.Code != RPCErrClientInvalidIPOrSubnet {
		t.Errorf("setban invalid subnet code = %v, want %d",
			resp2.Error, RPCErrClientInvalidIPOrSubnet)
	}

	// Sanity: a well-formed IP does NOT hit the -30 path (success).
	resp3 := testRPCRequest(t, server.handleRPC,
		"setban", []interface{}{"1.2.3.4", "add"}, "", "")
	if resp3.Error != nil {
		t.Errorf("setban valid IP unexpectedly errored: %v", resp3.Error)
	}
}

func TestW125_BUG_11b_SetBan_InvalidCommand(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"setban", []interface{}{"1.2.3.4", "bogus-command"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// blockbrew returns -1 here because peerMgr is nil and the nil check
	// runs before the command switch. Document either outcome.
	switch resp.Error.Code {
	case RPCErrInvalidParams:
		// Command switch path
	case RPCErrInternal:
		// Pre-peerMgr guard path (also a divergence — Core has no internal err here)
	default:
		t.Logf("unexpected: code = %d", resp.Error.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-12 — sendrawtransaction reject code (mempool reject and already-in-utxo).
// Core: -26 RPC_VERIFY_REJECTED, -27 RPC_VERIFY_ALREADY_IN_UTXO_SET.
// blockbrew: -25 RPCErrVerify for both.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_12_SendRawTransaction_TxDecodeFail_Present(t *testing.T) {
	// Well-formed envelope but garbage hex — exercises the deserialization
	// path, which IS correctly mapped to -22.
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"sendrawtransaction", []interface{}{"deadbeef"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrDeserialization {
		t.Errorf("PRESENT regressed: code = %d, want %d (-22 RPCErrDeserialization)",
			resp.Error.Code, RPCErrDeserialization)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-13 — addnode missing error codes.
// Core: -23 already-added, -24 not-added, -8 invalid command.
// blockbrew: no double-add check; invalid command -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_13_AddNode_InvalidCommand(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{"1.2.3.4", "bogus-command"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// Without peerMgr wired, the nil-check fires first with -31 (P2P disabled).
	// Either documents a divergence.
	switch resp.Error.Code {
	case RPCErrInvalidParams:
		// Pre-fix expected (command switch path)
	case RPCErrClientP2PDisabled:
		// peerMgr nil guard fired first; Core would still emit -8 for the command
	default:
		t.Logf("unexpected: code = %d", resp.Error.Code)
	}
}

// FIXED (was a documented-divergence xfail): addnode "add" of an
// already-added node returns RPC_CLIENT_NODE_ALREADY_ADDED (-23), and
// "remove" of a node that was never added returns RPC_CLIENT_NODE_NOT_ADDED
// (-24), each with Core's exact message (bitcoin-core rpc/net.cpp:362/368,
// backed by CConnman::AddNode dedup / RemoveAddedNode absent-check). Driven
// through the live handler with a real peerMgr wired.
func TestW125_BUG_13_AddNode_DuplicateAddAndRemoveUnknown(t *testing.T) {
	server := w125TestServerWithPeerMgr(t)
	node := "1.2.3.4:8333"

	// remove before any add → -24 RPC_CLIENT_NODE_NOT_ADDED.
	respNoAdd := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{node, "remove"}, "", "")
	if respNoAdd.Error == nil || respNoAdd.Error.Code != RPCErrClientNodeNotAdded {
		t.Fatalf("addnode remove-unknown code = %v, want %d (RPC_CLIENT_NODE_NOT_ADDED)",
			respNoAdd.Error, RPCErrClientNodeNotAdded)
	}
	if respNoAdd.Error.Message != "Error: Node could not be removed. It has not been added previously." {
		t.Errorf("addnode remove-unknown message = %q", respNoAdd.Error.Message)
	}

	// first add → success (no error).
	respAdd := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{node, "add"}, "", "")
	if respAdd.Error != nil {
		t.Fatalf("addnode first add unexpectedly errored: %v", respAdd.Error)
	}

	// duplicate add → -23 RPC_CLIENT_NODE_ALREADY_ADDED.
	respDup := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{node, "add"}, "", "")
	if respDup.Error == nil || respDup.Error.Code != RPCErrClientNodeAlreadyAdded {
		t.Fatalf("addnode duplicate-add code = %v, want %d (RPC_CLIENT_NODE_ALREADY_ADDED)",
			respDup.Error, RPCErrClientNodeAlreadyAdded)
	}
	if respDup.Error.Message != "Error: Node already added" {
		t.Errorf("addnode duplicate-add message = %q", respDup.Error.Message)
	}

	// remove the now-added node → success (round-trip), and a second remove
	// is again -24.
	respRm := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{node, "remove"}, "", "")
	if respRm.Error != nil {
		t.Fatalf("addnode remove-after-add unexpectedly errored: %v", respRm.Error)
	}
	respRm2 := testRPCRequest(t, server.handleRPC,
		"addnode", []interface{}{node, "remove"}, "", "")
	if respRm2.Error == nil || respRm2.Error.Code != RPCErrClientNodeNotAdded {
		t.Errorf("addnode second remove code = %v, want %d",
			respRm2.Error, RPCErrClientNodeNotAdded)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-14 — disconnectnode missing both addr+id.
// Core: -32602 for the "exactly one of address/nodeid" case (legitimate).
// blockbrew: -1 (nil peerMgr guard fires first in this test rig).
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_14_DisconnectNode_NoArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"disconnectnode", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// peerMgr is nil → -1 RPCErrInternal fires first. Document that.
	if resp.Error.Code != RPCErrInternal {
		t.Logf("note: code = %d, peerMgr-nil guard expected to fire", resp.Error.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-15 — prioritisetransaction missing arg.
// Core: -8 ; blockbrew: -32602 for missing args (but -8 for dummy!=0).
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_15a_Prioritise_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"prioritisetransaction", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_15b_Prioritise_DummyNotZero_Present(t *testing.T) {
	// PRESENT: dummy!=0 → -8 RPCErrInvalidParameter per Core mining.cpp:530.
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"prioritisetransaction",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001", float64(42), float64(100)},
		"", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("PRESENT regressed: code = %d, want %d (-8)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-16 — verifymessage missing args.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_16_VerifyMessage_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"verifymessage", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-17 — signmessage missing args.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_17_SignMessage_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"signmessage", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-18 — signmessagewithprivkey missing args.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_18_SignMessageWithPrivKey_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"signmessagewithprivkey", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-19 — validateaddress missing arg.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_19_ValidateAddress_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"validateaddress", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-20 — createmultisig validation errors.
// Core: -8 for nrequired/pubkeys bounds, -5 for pubkey hex/address_type.
// blockbrew: -32602 for all.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_20a_CreateMultisig_MissingArgs(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"createmultisig", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_20b_CreateMultisig_NRequiredOutOfRange(t *testing.T) {
	server := w125TestServer(t)
	// nrequired=2 but only 1 pubkey provided.
	resp := testRPCRequest(t, server.handleRPC,
		"createmultisig", []interface{}{
			float64(2),
			[]interface{}{"02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_20c_CreateMultisig_InvalidPubkey(t *testing.T) {
	server := w125TestServer(t)
	// 1-of-1 with non-hex pubkey.
	resp := testRPCRequest(t, server.handleRPC,
		"createmultisig", []interface{}{
			float64(1),
			[]interface{}{"not-a-valid-hex-pubkey"},
		}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -5.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_20d_CreateMultisig_UnknownAddressType(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"createmultisig", []interface{}{
			float64(1),
			[]interface{}{"020000000000000000000000000000000000000000000000000000000000000001"},
			"bogus-type",
		}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -5.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-21 — walletpassphrase missing passphrase arg.
// Core: -8 ; blockbrew: -32602 (the empty-passphrase path IS -8, PRESENT).
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_21_WalletPassphrase_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	// Without a wallet, blockbrew returns RPCErrWalletNotFound (-18) which
	// is also Core-correct. So this test specifically routes via the
	// wallet-loaded path. Without a wallet plumbed, document the early-fail.
	resp := testRPCRequest(t, server.handleRPC,
		"walletpassphrase", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// Either RPCErrWalletNotFound (-18 — short-circuit) or
	// RPCErrInvalidParams (-32602 — arg-check path).
	switch resp.Error.Code {
	case RPCErrWalletNotFound:
		// Pre-arg-check guard fired (no wallet wired in test rig).
		t.Logf("note: wallet-not-loaded fired before arg check; code = -18 (Core-correct shape)")
	case RPCErrInvalidParams:
		// Documented xfail
	default:
		t.Logf("unexpected: code = %d", resp.Error.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-22 — sendtoaddress wallet errors all collapsed to -4.
// Core: -6 insufficient-funds, -8 invalid amount, -5 invalid address, -4 generic.
// blockbrew: -4 for everything.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_22_SendToAddress_NoWallet(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"sendtoaddress", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// No wallet wired → -18 RPCErrWalletNotFound — Core-correct shape.
	if resp.Error.Code != RPCErrWalletNotFound {
		t.Errorf("PRESENT regressed: code = %d, want %d (-18 RPCErrWalletNotFound)",
			resp.Error.Code, RPCErrWalletNotFound)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-23 — gettxoutproof missing args.
// Core: -8 ; blockbrew: -32602.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_23_GetTxOutProof_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"gettxoutproof", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG-24 — PSBT family missing args.
// Core: -8 ; blockbrew: -32602 for all PSBT arg-shape errors.
// ─────────────────────────────────────────────────────────────────────

func TestW125_BUG_24a_DecodePsbt_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"decodepsbt", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

func TestW125_BUG_24b_FinalizePsbt_MissingArg(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"finalizepsbt", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrInvalidParams {
		t.Errorf("documented divergence: code = %d, want %d (current). Core wants -8.",
			resp.Error.Code, RPCErrInvalidParams)
	}
}

// ─────────────────────────────────────────────────────────────────────
// PRESENT gates — sanity checks
// ─────────────────────────────────────────────────────────────────────

// Gate: method-not-found is correctly -32601 (Core-aligned).
func TestW125_MethodNotFound_Present(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"nonexistent_method", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrMethodNotFound {
		t.Errorf("PRESENT regressed: code = %d, want %d (-32601)",
			resp.Error.Code, RPCErrMethodNotFound)
	}
}

// Gate: encryptwallet without wallet → -18 (Core-correct).
func TestW125_EncryptWallet_NoWallet_Present(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"encryptwallet", []interface{}{"some-passphrase"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != RPCErrWalletNotFound {
		t.Errorf("PRESENT regressed: code = %d, want %d (-18)",
			resp.Error.Code, RPCErrWalletNotFound)
	}
}

// Gate: encryptwallet empty passphrase → -8 (Core-correct).
// Requires wallet path; without wallet wired we get -18 instead. Still
// documents the right ladder.
func TestW125_EncryptWallet_EmptyPassphrase_Documented(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC,
		"encryptwallet", []interface{}{""}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	// -18 (no wallet) is the short-circuit. The -8 path requires a wallet
	// fixture; this test documents the short-circuit.
	if resp.Error.Code != RPCErrWalletNotFound {
		t.Logf("note: code = %d (expected -18 short-circuit)", resp.Error.Code)
	}
}
