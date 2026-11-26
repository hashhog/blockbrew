package rpc

// r3fix-blockbrew-areinputsstandard-solver: testmempoolaccept (the dry-run
// the R3 generating fuzzer measures) must run Core's
// ValidateInputsStandardness, like the real accept path. Night-1 row R106
// (mempool/verdict/nonstandard|accept, 288 cases) minimised to a spend of a
// bare OP_1 output with an empty scriptSig: Core v31.1 answers
// allowed=false, reject-reason "bad-txns-nonstandard-inputs"; blockbrew
// answered allowed=true.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// The minimised R106 case from the fuzzer report (seed 739943): one input
// spending <txid>:0 with an empty scriptSig, one P2WSH output of 97,999 sat.
const r3fixAISMinimisedHex = "0200000001919d1faae2ac80aea547c477a7bfa7556da5923c98e1a482b12eb1fefee98a280000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"

func r3fixAISServer(t *testing.T, prevScript []byte) (*Server, string) {
	t.Helper()
	raw, err := hex.DecodeString(r3fixAISMinimisedHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	view := consensus.NewInMemoryUTXOView()
	view.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{
		Amount:   100_000,
		PkScript: prevScript,
		Height:   10,
	})
	cfg := mempool.DefaultConfig()
	cfg.ChainState = &tmaFakeChainState{height: 200, mtp: 1_600_000_000}
	mp := mempool.New(cfg, view)
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp)), r3fixAISMinimisedHex
}

// TestR3fixAreInputsStandardSolverTestMempoolAcceptBareOP1 is R106's
// minimised case: Core refuses it with bad-txns-nonstandard-inputs.
func TestR3fixAreInputsStandardSolverTestMempoolAcceptBareOP1(t *testing.T) {
	srv, txHex := r3fixAISServer(t, []byte{0x51})
	r := runTMA(t, srv, txHex)
	if r.Allowed {
		t.Fatalf("allowed=true; Core v31.1: allowed=false, reject-reason bad-txns-nonstandard-inputs")
	}
	if r.RejectReason != "bad-txns-nonstandard-inputs" {
		t.Fatalf("reject-reason = %q, want %q", r.RejectReason, "bad-txns-nonstandard-inputs")
	}
	if want := "bad-txns-nonstandard-inputs, input 0 script unknown"; r.RejectDetails != want {
		t.Errorf("reject-details = %q, want %q", r.RejectDetails, want)
	}
}

// TestR3fixAreInputsStandardSolverTestMempoolAcceptP2WPKHControl: the same tx
// spending a P2WPKH output passes ValidateInputsStandardness and then fails
// the script check on its missing witness, as in Core, not as
// bad-txns-nonstandard-inputs.
func TestR3fixAreInputsStandardSolverTestMempoolAcceptP2WPKHControl(t *testing.T) {
	spk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x42}, 20)...)
	srv, txHex := r3fixAISServer(t, spk)
	r := runTMA(t, srv, txHex)
	if r.RejectReason == "bad-txns-nonstandard-inputs" {
		t.Fatalf("P2WPKH prevout refused as nonstandard input (%q); Core's Solver says WITNESS_V0_KEYHASH", r.RejectDetails)
	}
	if r.Allowed {
		t.Fatalf("allowed=true with an empty witness on a P2WPKH spend; the script check must refuse it")
	}
}

// p2shOpTrueTestScript is P2SH(OP_TRUE), a coin fixtures can spend without a
// signature that Core's ValidateInputsStandardness still accepts (Solver
// SCRIPTHASH). Fixtures used to fund from a bare OP_1 output, which Core
// refuses as a nonstandard input.
func p2shOpTrueTestScript() []byte {
	h := crypto.Hash160([]byte{0x51})
	return append(append([]byte{0xa9, 0x14}, h[:]...), 0x87)
}

// p2shOpTrueTestScriptSig spends p2shOpTrueTestScript: it pushes the
// redeemScript OP_TRUE.
var p2shOpTrueTestScriptSig = []byte{0x01, 0x51}
