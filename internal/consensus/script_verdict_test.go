package consensus

// Script failures through the block-connect verdict path
// (receipts/blockbrew-gate6-2026-10-04.md deferred item; QUEUES blockbrew 0).
//
// Each case plants a coin whose scriptPubKey (or the spending scriptSig)
// reaches one script-engine failure site, connects a block spending it at the
// active tip, and requires a consensus VERDICT that names the Core ScriptError
// it mirrors. The verdict is what keeps a crafted block from halting the node:
// a script failure without a Core code is classified as a system fault.

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// coreCoded is satisfied by a script-engine error that names its Core
// ScriptError_t (script/script_error.h).
type coreCoded interface {
	error
	ScriptError() string
}

// newScriptVerdictRig is the gate-6 rig, optionally with the production
// script path (ParallelScripts: the persistent CCheckQueue-style pool).
func newScriptVerdictRig(t *testing.T, queue bool) *gate6Rig {
	t.Helper()
	r := newGate6Rig(t, 0)
	if queue {
		cm := NewChainManager(ChainManagerConfig{Params: r.params, HeaderIndex: r.idx, ChainDB: r.chainDB,
			UTXOSet: r.utxo, ParallelScripts: true, Par: 3})
		cm.SetIBD(false)
		r.cm = cm
	}
	return r
}

func TestScriptFailureVerdict_ConnectBlock(t *testing.T) {
	cases := []struct {
		name     string
		pk, sig  []byte
		wantCore string
	}{
		{"push_direct_truncated", []byte{0x51}, []byte{0x05, 0x01}, "SCRIPT_ERR_BAD_OPCODE"},
		{"pushdata1_no_length", []byte{0x51}, []byte{0x4c}, "SCRIPT_ERR_BAD_OPCODE"},
		{"pushdata1_short_data", []byte{0x51}, []byte{0x4c, 0x05, 0x01}, "SCRIPT_ERR_BAD_OPCODE"},
		{"pushdata2_short_data", []byte{0x51}, []byte{0x4d, 0x05, 0x00, 0x01}, "SCRIPT_ERR_BAD_OPCODE"},
		{"pushdata4_short_data", []byte{0x51}, []byte{0x4e, 0x05, 0, 0, 0, 0x01}, "SCRIPT_ERR_BAD_OPCODE"},
		{"opcode_0xff_executed", []byte{0xff}, nil, "SCRIPT_ERR_BAD_OPCODE"},
		{"op_reserved_executed", []byte{0x50}, nil, "SCRIPT_ERR_BAD_OPCODE"},
		{"scriptnum_overflow", []byte{0x05, 1, 2, 3, 4, 5, 0x8b}, nil, "SCRIPT_ERR_UNKNOWN_ERROR"},
		{"op_return", []byte{0x6a}, nil, "SCRIPT_ERR_OP_RETURN"},
		{"eval_false", []byte{0x00}, nil, "SCRIPT_ERR_EVAL_FALSE"},
	}
	for _, mode := range []string{"serial", "queue"} {
		for i, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				r := newScriptVerdictRig(t, mode == "queue")
				bad := r.plant(byte(0x40+i), 50_000, c.pk)
				ok := r.plant(byte(0x80+i), 50_000, nil)
				tx := spendTx(bad, 40_000, 1)
				tx.TxIn[0].SignatureScript = c.sig
				b := r.block(r.tip, []*wire.MsgTx{spendTx(ok, 40_000, 2), tx})
				err := r.cm.ConnectBlock(b)
				if err == nil {
					t.Fatal("block with a failing script connected")
				}
				if _, verdict := AsBlockInvalid(err); !verdict {
					t.Fatalf("script failure is not a verdict: %v (%T)", err, err)
				}
				if IsSystemFault(err) || IsAborted() {
					t.Fatalf("script failure became a system fault / latched AbortNode: %v", err)
				}
				var ce coreCoded
				if !errors.As(err, &ce) {
					t.Fatalf("verdict carries an unclassified script error %q: no Core ScriptError code", err)
				}
				if got := ce.ScriptError(); got != c.wantCore {
					t.Fatalf("%q classified as %s, want %s", err, got, c.wantCore)
				}
				if r.tipHash() == b.Header.BlockHash() {
					t.Fatal("tip moved to the invalid block")
				}
				// The queue reports "tx N input M: script failed: ..."; the
				// serial path does not. Proves which path was exercised.
				if viaQueue := strings.Contains(err.Error(), "input 0: script failed"); viaQueue != (mode == "queue") {
					t.Fatalf("%s mode took the wrong script path: %v", mode, err)
				}
			})
		}
	}
}

// Control (the other direction): a block whose scripts all pass still
// connects, with the same rig and shape as the failing cases.
func TestScriptFailureVerdict_Control_ValidBlockConnects(t *testing.T) {
	for _, mode := range []string{"serial", "queue"} {
		t.Run(mode, func(t *testing.T) { validBlockConnects(t, newScriptVerdictRig(t, mode == "queue")) })
	}
}

func validBlockConnects(t *testing.T, r *gate6Rig) {
	a := r.plant(1, 50_000, nil)
	b := r.plant(2, 50_000, []byte{0x01, 0x07, 0x57, 0x87}) // <7> OP_7 OP_EQUAL
	tx := spendTx(b, 40_000, 2)
	tx.TxIn[0].SignatureScript = nil
	blk := r.block(r.tip, []*wire.MsgTx{spendTx(a, 40_000, 1), tx})
	if err := r.cm.ConnectBlock(blk); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}
	if r.tipHash() != blk.Header.BlockHash() || IsAborted() {
		t.Fatal("valid block did not become the tip")
	}
}
