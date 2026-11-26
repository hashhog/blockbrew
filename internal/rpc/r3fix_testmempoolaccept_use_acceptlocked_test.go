package rpc

// r3fix-blockbrew-testmempoolaccept-use-acceptlocked: the single-transaction
// testmempoolaccept dry run ran its own copy of PreChecks and skipped four
// rules that acceptLocked (sendrawtransaction) and Core's test_accept apply:
//
//	G5  IsStandardTx's scriptSig loop  scriptsig-size / scriptsig-not-pushonly
//	    (Core policy/policy.cpp:117-133)
//	G6  IsWitnessStandard              bad-witness-nonstandard
//	    (Core validation.cpp:908-909)
//	G7  BIP68 sequence locks           non-BIP68-final
//	    (Core validation.cpp:894-895)
//	G8  SingleTRUCChecks               TRUC-violation
//	    (Core policy/truc_policy.cpp:200-202, validation.cpp:960)
//
// Each test feeds the R3 fuzzer's minimised case for its group (seed 739943,
// night 1, 2026-11-23) byte for byte, plus a hostile case the dry run used to
// report allowed, plus a control of the same shape that Core accepts, so the
// refusal is shown to come from the rule and not from the fixture.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// r3tmaServer is a regtest mempool (segwit, taproot and CSV active) over
// view, with the tip at height and a fixed median-time-past.
func r3tmaServer(view *consensus.InMemoryUTXOView, height int32) *Server {
	cfg := mempool.DefaultConfig()
	cfg.ChainParams = consensus.RegtestParams()
	cfg.ChainState = &tmaFakeChainState{height: height, mtp: 1_600_000_000}
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mempool.New(cfg, view)))
}

func r3tmaDecode(t *testing.T, txHex string) *wire.MsgTx {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimSpace(txHex))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("deserialize tx: %v", err)
	}
	return &tx
}

// r3tmaP2TRFromControl rebuilds the P2TR scriptPubKey a single-leaf
// script-path spend commits to, from the spend's own witness (script and
// control block), and checks the rebuilt key's parity against the control
// block so the fixture is the coin the fuzzer funded.
func r3tmaP2TRFromControl(t *testing.T, witness [][]byte) []byte {
	t.Helper()
	if len(witness) < 2 {
		t.Fatalf("setup: script-path witness has %d items", len(witness))
	}
	control := witness[len(witness)-1]
	leafScript := witness[len(witness)-2]
	if len(control) != 33 {
		t.Fatalf("setup: control block is %d bytes, want 33 (single leaf)", len(control))
	}
	internal := control[1:33]
	leaf := script.TapLeaf(control[0]&0xfe, leafScript)
	tweak := script.TapTweak(internal, leaf[:])
	outKey, parity := crypto.ComputeTaprootOutputKey(internal, tweak)
	if outKey == nil {
		t.Fatalf("setup: taproot tweak failed")
	}
	if parity != control[0]&1 {
		t.Fatalf("setup: rebuilt output key parity %d, control block says %d", parity, control[0]&1)
	}
	return append([]byte{0x51, 0x20}, outKey...)
}

func r3tmaP2WSH(witnessScript []byte) []byte {
	h := sha256.Sum256(witnessScript)
	return append([]byte{0x00, 0x20}, h[:]...)
}

func r3tmaP2SH(redeemScript []byte) []byte {
	h := crypto.Hash160(redeemScript)
	return append(append([]byte{0xa9, 0x14}, h[:]...), 0x87)
}

func r3tmaWantReject(t *testing.T, r *TestMempoolAcceptResult, reason string) {
	t.Helper()
	if r.Allowed {
		t.Fatalf("allowed=true, want reject-reason %q (Core v31.1)", reason)
	}
	if r.RejectReason != reason {
		t.Fatalf("reject-reason = %q (details %q), want Core v31.1's %q", r.RejectReason, r.RejectDetails, reason)
	}
}

func r3tmaWantAllowed(t *testing.T, r *TestMempoolAcceptResult) {
	t.Helper()
	if !r.Allowed {
		t.Fatalf("control refused: reject-reason %q (details %q)", r.RejectReason, r.RejectDetails)
	}
}

// r3tmaOneOut is a single standard 90,000-sat P2WPKH output (10,000 sat fee
// from a 100,000-sat coin).
func r3tmaOneOut() []*wire.TxOut {
	return []*wire.TxOut{{Value: 90_000, PkScript: tmaP2WPKHScript(0x70)}}
}

// G5: IsStandardTx's scriptSig loop.
func TestR3Fix_TMA_ScriptSigStandardness(t *testing.T) {
	// Minimised case "bare script=[] sig=[MIN] v=2 lt=['height', 0]
	// seq=0xfffffffe": the locktime (2311) is the next block's height, so the
	// tx is also non-final. Core stops at IsStandardTx first
	// (scriptsig-not-pushonly); the dry run fell through to "non-final".
	t.Run("minimised_nonstandard_vs_final", func(t *testing.T) {
		const minimised = "02000000019f9463c4d5b583bdc23222735b2f3bd96f7e46bbc4ccdef5af1048f094e945790000000001a3feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326007090000"
		tx := r3tmaDecode(t, minimised)
		if tx.LockTime != 2311 {
			t.Fatalf("setup: locktime %d, want 2311", tx.LockTime)
		}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{Amount: 100_000, PkScript: []byte{}, Height: 10})
		r := runTMA(t, r3tmaServer(view, 2310), minimised)
		r3tmaWantReject(t, r, "scriptsig-not-pushonly")
	})

	// Hostile: a fee-paying spend of a bare (empty) scriptPubKey whose
	// scriptSig is OP_1 OP_NOP. Script-valid, so the dry run reported it
	// allowed; Core refuses it as non-push-only before looking at inputs.
	t.Run("not_pushonly_was_allowed", func(t *testing.T) {
		op := wire.OutPoint{Hash: wire.Hash256{0x51, 0x01}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: []byte{}, Height: 10})
		tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{PreviousOutPoint: op, SignatureScript: []byte{0x51, 0x61}, Sequence: 0xffffffff}}, TxOut: r3tmaOneOut()}
		r := runTMA(t, r3tmaServer(view, 200), txToHex(t, tx))
		r3tmaWantReject(t, r, "scriptsig-not-pushonly")
		if r.RejectDetails != "scriptsig-not-pushonly" {
			t.Fatalf("reject-details = %q, want Core's %q", r.RejectDetails, "scriptsig-not-pushonly")
		}
	})

	// Hostile: a push-only scriptSig of 2,092 bytes (> 1,650) satisfying
	// OP_2DROP OP_2DROP OP_1. Core: scriptsig-size.
	t.Run("scriptsig_size", func(t *testing.T) {
		var sig []byte
		for i := 0; i < 4; i++ {
			sig = append(sig, 0x4d, 0x08, 0x02) // OP_PUSHDATA2 520
			sig = append(sig, bytes.Repeat([]byte{byte(i + 1)}, 520)...)
		}
		if len(sig) <= mempool.MaxStandardScriptSigSize {
			t.Fatalf("setup: scriptSig %d bytes", len(sig))
		}
		op := wire.OutPoint{Hash: wire.Hash256{0x51, 0x02}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: []byte{0x6d, 0x6d, 0x51}, Height: 10})
		tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{PreviousOutPoint: op, SignatureScript: sig, Sequence: 0xffffffff}}, TxOut: r3tmaOneOut()}
		r := runTMA(t, r3tmaServer(view, 200), txToHex(t, tx))
		r3tmaWantReject(t, r, "scriptsig-size")
		if r.RejectDetails != "scriptsig-size" {
			t.Fatalf("reject-details = %q, want Core's %q", r.RejectDetails, "scriptsig-size")
		}
	})

	// Control: a push-only scriptSig (P2SH OP_TRUE) is allowed.
	t.Run("control_pushonly_allowed", func(t *testing.T) {
		redeem := []byte{0x51}
		op := wire.OutPoint{Hash: wire.Hash256{0x51, 0x03}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: r3tmaP2SH(redeem), Height: 10})
		tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{PreviousOutPoint: op, SignatureScript: []byte{0x01, 0x51}, Sequence: 0xffffffff}}, TxOut: r3tmaOneOut()}
		r3tmaWantAllowed(t, runTMA(t, r3tmaServer(view, 200), txToHex(t, tx)))
	})
}

// G6: IsWitnessStandard.
func TestR3Fix_TMA_WitnessStandardness(t *testing.T) {
	// Minimised case "tapscript script=[] annex=": the last witness item is
	// empty, so the control block is empty. Core: bad-witness-nonstandard
	// (policy.cpp, "Empty control block is invalid"); the dry run ran the
	// script and reported TAPROOT_WRONG_CONTROL_SIZE.
	t.Run("minimised_empty_control_block", func(t *testing.T) {
		const minimised = "02000000000101015e6337b75d81758df32ce22b7d11abc6906b9e37d58adbc65e8acfe4b09ba10000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260030021c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980000000000"
		tx := r3tmaDecode(t, minimised)
		w := tx.TxIn[0].Witness
		if len(w) != 3 || len(w[2]) != 0 {
			t.Fatalf("setup: witness %x, want 3 items ending in an empty one", w)
		}
		// The coin is a P2TR output; the key is never reached.
		spk := append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x11}, 32)...)
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{Amount: 100_000, PkScript: spk, Height: 10})
		r := runTMA(t, r3tmaServer(view, 200), minimised)
		r3tmaWantReject(t, r, "bad-witness-nonstandard")
		if r.RejectDetails != "bad-witness-nonstandard" {
			t.Fatalf("reject-details = %q, want Core's %q", r.RejectDetails, "bad-witness-nonstandard")
		}
	})

	p2wshSpend := func(t *testing.T, itemLen int, seed byte) *TestMempoolAcceptResult {
		ws := []byte{0x75, 0x51} // OP_DROP OP_1
		op := wire.OutPoint{Hash: wire.Hash256{0x66, seed}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: r3tmaP2WSH(ws), Height: 10})
		tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			Witness:          [][]byte{bytes.Repeat([]byte{0x01}, itemLen), ws},
			Sequence:         0xffffffff,
		}}, TxOut: r3tmaOneOut()}
		return runTMA(t, r3tmaServer(view, 200), txToHex(t, tx))
	}

	// Hostile: a script-valid P2WSH spend with an 81-byte stack item
	// (MAX_STANDARD_P2WSH_STACK_ITEM_SIZE is 80). The dry run said allowed.
	t.Run("p2wsh_item_81_bytes_was_allowed", func(t *testing.T) {
		r3tmaWantReject(t, p2wshSpend(t, 81, 1), "bad-witness-nonstandard")
	})

	// Control: the same spend with an 80-byte item is standard.
	t.Run("control_p2wsh_item_80_bytes_allowed", func(t *testing.T) {
		r3tmaWantAllowed(t, p2wshSpend(t, 80, 2))
	})
}

// G7: BIP68 sequence locks.
func TestR3Fix_TMA_SequenceLocks(t *testing.T) {
	// Minimised case R111 "tapscript script=[IF 1 ENDIF] wit=['01'] v=2
	// seq=0x7fffffff": a time-based relative lock of 0xffff*512 s that a coin
	// confirmed at the tip cannot meet. Script-valid, so the dry run said
	// allowed; Core: non-BIP68-final.
	t.Run("minimised_time_lock_was_allowed", func(t *testing.T) {
		const minimised = "02000000000101aed31d95118c1ff98693fb9c5f1da735e1c508ce5c27726c3d48325c71b4a11d0000000000ffffff7f01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600301010363516821c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
		tx := r3tmaDecode(t, minimised)
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{
			Amount: 100_000, PkScript: r3tmaP2TRFromControl(t, tx.TxIn[0].Witness), Height: 200,
		})
		r := runTMA(t, r3tmaServer(view, 200), minimised)
		r3tmaWantReject(t, r, "non-BIP68-final")
		if r.RejectDetails != "non-BIP68-final" {
			t.Fatalf("reject-details = %q, want Core's %q", r.RejectDetails, "non-BIP68-final")
		}
	})

	heightLocked := func(t *testing.T, coinHeight int32, seed byte) *TestMempoolAcceptResult {
		ws := []byte{0x51}
		op := wire.OutPoint{Hash: wire.Hash256{0x68, seed}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: r3tmaP2WSH(ws), Height: coinHeight})
		tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			Witness:          [][]byte{ws},
			Sequence:         5, // relative lock: 5 blocks
		}}, TxOut: r3tmaOneOut()}
		return runTMA(t, r3tmaServer(view, 200), txToHex(t, tx))
	}

	// Hostile: a 5-block relative lock on a coin confirmed at the tip (200);
	// the next block (201) is too early. Core: non-BIP68-final.
	t.Run("height_lock_not_met", func(t *testing.T) {
		r3tmaWantReject(t, heightLocked(t, 200, 1), "non-BIP68-final")
	})

	// Control: the same lock on a coin confirmed at height 10 is met.
	t.Run("control_height_lock_met_allowed", func(t *testing.T) {
		r3tmaWantAllowed(t, heightLocked(t, 10, 2))
	})
}

// G8: SingleTRUCChecks.
func TestR3Fix_TMA_TRUC(t *testing.T) {
	// Minimised case: a v3 tapscript CHECKSIGADD chain of 39,755 bytes
	// (vsize > TRUC_MAX_VSIZE 10,000). Core refuses it TRUC-violation before
	// the scripts; the dry run ran the scripts and reported
	// SCHNORR_SIG_HASHTYPE. Full hex from the night-1 run's
	// rows["mempool/reason/other:truc-violation|script-policy/SCHNORR_SIG_HASHTYPE"].tx.
	t.Run("minimised_v3_too_big", func(t *testing.T) {
		raw, err := os.ReadFile("testdata/r3fix_testmempoolaccept_truc_minimised.hex")
		if err != nil {
			t.Fatalf("read testdata: %v", err)
		}
		tx := r3tmaDecode(t, string(raw))
		if tx.Version != 3 {
			t.Fatalf("setup: version %d, want 3", tx.Version)
		}
		if vsize := (consensus.CalcTxWeight(tx) + 3) / 4; vsize <= mempool.TRUCMaxVSize {
			t.Fatalf("setup: vsize %d, want > %d", vsize, mempool.TRUCMaxVSize)
		}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{
			Amount: 100_000, PkScript: r3tmaP2TRFromControl(t, tx.TxIn[0].Witness), Height: 10,
		})
		r := runTMA(t, r3tmaServer(view, 200), strings.TrimSpace(string(raw)))
		r3tmaWantReject(t, r, "TRUC-violation")
		if !strings.HasPrefix(r.RejectDetails, "TRUC-violation, ") {
			t.Fatalf("reject-details = %q, want Core's \"TRUC-violation, <reason>\" form", r.RejectDetails)
		}
	})

	v3ManyOutputs := func(t *testing.T, nOut int, seed byte) (*TestMempoolAcceptResult, int64) {
		ws := []byte{0x51}
		op := wire.OutPoint{Hash: wire.Hash256{0x83, seed}, Index: 0}
		view := consensus.NewInMemoryUTXOView()
		view.AddUTXO(op, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: r3tmaP2WSH(ws), Height: 10})
		tx := &wire.MsgTx{Version: 3, TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			Witness:          [][]byte{ws},
			Sequence:         0xffffffff,
		}}}
		for i := 0; i < nOut; i++ {
			tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 1_000, PkScript: tmaP2WPKHScript(byte(i))})
		}
		vsize := (consensus.CalcTxWeight(tx) + 3) / 4
		return runTMA(t, r3tmaServer(view, 200), txToHex(t, tx)), vsize
	}

	// Hostile: a script-valid v3 tx of 330 outputs (vsize > 10,000). The dry
	// run said allowed.
	t.Run("v3_over_10000_vbytes_was_allowed", func(t *testing.T) {
		r, vsize := v3ManyOutputs(t, 330, 1)
		if vsize <= mempool.TRUCMaxVSize {
			t.Fatalf("setup: vsize %d, want > %d", vsize, mempool.TRUCMaxVSize)
		}
		r3tmaWantReject(t, r, "TRUC-violation")
	})

	// Control: the same tx with 300 outputs fits TRUC_MAX_VSIZE.
	t.Run("control_v3_under_10000_vbytes_allowed", func(t *testing.T) {
		r, vsize := v3ManyOutputs(t, 300, 2)
		if vsize > mempool.TRUCMaxVSize {
			t.Fatalf("setup: vsize %d, want <= %d", vsize, mempool.TRUCMaxVSize)
		}
		r3tmaWantAllowed(t, r)
	})
}
