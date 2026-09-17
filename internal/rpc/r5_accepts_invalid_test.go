// R5 accepts-invalid class: Core rejects these inputs; blockbrew must too.
//
// Probe source: tools/r5-probes.d/{mining-relay,rawtx-psbt,util}.jsonl
// (2026-09-17 live run: T1 40/46 T2 18/41). A node that accepts what Core
// rejects is a divergence an operator's script will act on.
package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Probe: getnetworkhashps type-error — params=["foo"], expect -3.
// Core: RPCArg::Type::NUM → UniValue type error (rpc/mining.cpp:119).
func TestR5_GetNetworkHashPS_TypeError(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "getnetworkhashps", []interface{}{"foo"}, "", "")
	if resp.Error == nil {
		t.Fatal("getnetworkhashps(\"foo\"): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Fatalf("getnetworkhashps(\"foo\"): code = %d, want %d (Core RPC_TYPE_ERROR)",
			resp.Error.Code, RPCErrTypeError)
	}
}

// Probe: getblocktemplate missing-segwit-rule — params=[{}], expect -8.
// Core: mining.cpp:854-857, "getblocktemplate must be called with the segwit rule set".
func TestR5_GetBlockTemplate_MissingSegwitRule(t *testing.T) {
	server := gbtRulesTestSetup(t, consensus.RegtestParams())
	resp := testRPCRequest(t, server.handleRPC, "getblocktemplate",
		[]interface{}{map[string]interface{}{}}, "", "")
	if resp.Error == nil {
		t.Fatal("getblocktemplate({}): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("getblocktemplate({}): code = %d, want %d (Core RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// Probe: combinerawtransaction unknown-input — prevout all-0xaa, expect -25.
// Core: rawtransaction.cpp:650-652, RPC_VERIFY_ERROR "Input not found or already spent".
func TestR5_CombineRawTransaction_UnknownInput(t *testing.T) {
	server := w125TestServer(t)
	const unknownHex = "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"
	resp := testRPCRequest(t, server.handleRPC, "combinerawtransaction",
		[]interface{}{[]string{unknownHex, unknownHex}}, "", "")
	if resp.Error == nil {
		t.Fatal("combinerawtransaction(unknown-input): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrVerify {
		t.Fatalf("combinerawtransaction(unknown-input): code = %d, want %d (Core RPC_VERIFY_ERROR)",
			resp.Error.Code, RPCErrVerify)
	}
}

// Probe: deriveaddresses missing-checksum — no #checksum, expect -5.
// Core: output_script.cpp:315 Parse(..., require_checksum=true) → RPC_INVALID_ADDRESS_OR_KEY.
func TestR5_DeriveAddresses_MissingChecksum(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "deriveaddresses",
		[]interface{}{"wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)"}, "", "")
	if resp.Error == nil {
		t.Fatal("deriveaddresses(missing-checksum): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("deriveaddresses(missing-checksum): code = %d, want %d (Core RPC_INVALID_ADDRESS_OR_KEY)",
			resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

// Probe: deriveaddresses range-on-unranged — checksummed wpkh + [0,2], expect -8.
// Core: output_script.cpp:320-322 "Range should not be specified for an un-ranged descriptor".
func TestR5_DeriveAddresses_RangeOnUnranged(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "deriveaddresses",
		[]interface{}{
			"wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#e72f49hy",
			[]int{0, 2},
		}, "", "")
	if resp.Error == nil {
		t.Fatal("deriveaddresses(range-on-unranged): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("deriveaddresses(range-on-unranged): code = %d, want %d (Core RPC_INVALID_PARAMETER)",
			resp.Error.Code, RPCErrInvalidParameter)
	}
}

// Probe: signmessagewithprivkey zero-privkey — WIF of the all-zero scalar, expect -5.
// Core: DecodeSecret → CKey::Check (secp256k1_ec_seckey_verify) fails for 0
// (signmessage.cpp:87-90, RPC_INVALID_ADDRESS_OR_KEY "Invalid private key").
// Must run on mainnet params: the probe WIF is version 0x80; regtest expects 0xef
// and would reject on the version check before the zero-scalar test.
func TestR5_ImportMempool_BadPath(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "importmempool",
		[]interface{}{"/nonexistent/r5-probe-no-such-file.dat"}, "", "")
	if resp.Error == nil {
		t.Fatal("importmempool(bad-path): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrMisc {
		t.Fatalf("importmempool(bad-path): code = %d, want %d (Core RPC_MISC_ERROR)",
			resp.Error.Code, RPCErrMisc)
	}
}

func TestR5_PruneBlockchain_HeightTypeError(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "pruneblockchain", []interface{}{"zz"}, "", "")
	if resp.Error == nil {
		t.Fatal("pruneblockchain(\"zz\"): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Fatalf("pruneblockchain(\"zz\"): code = %d, want %d (Core RPC_TYPE_ERROR)",
			resp.Error.Code, RPCErrTypeError)
	}
}

func TestR5_SignMessageWithPrivKey_ZeroPrivkey(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	resp := testRPCRequest(t, server.handleRPC, "signmessagewithprivkey",
		[]interface{}{"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU", "x"}, "", "")
	if resp.Error == nil {
		t.Fatal("signmessagewithprivkey(zero-privkey): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("signmessagewithprivkey(zero-privkey): code = %d, want %d (Core RPC_INVALID_ADDRESS_OR_KEY)",
			resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}
