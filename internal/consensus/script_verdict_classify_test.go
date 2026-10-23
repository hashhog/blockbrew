package consensus

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Every script ErrorCode goes through scriptVerdict and lands in exactly one
// class: a Core code is a BLOCK_CONSENSUS verdict with no AbortNode; the
// internal code is a system fault that latches AbortNode. Neither is ever nil
// (a script failure can never become an accept).
func TestScriptVerdict_EveryErrorCodeIsClassified(t *testing.T) {
	h := wire.Hash256{7}
	verdicts, faults := 0, 0
	for c := script.ErrorCode(1); c < script.NumErrorCodes; c++ {
		t.Run(c.String(), func(t *testing.T) {
			ResetAbortForTesting()
			defer ResetAbortForTesting()
			err := scriptVerdict(h, fmt.Errorf("tx 1 input 0: script failed: %w", &script.Error{Code: c}))
			if err == nil {
				t.Fatal("a script failure classified as success")
			}
			_, verdict := AsBlockInvalid(err)
			fault := IsSystemFault(err)
			if verdict == fault {
				t.Fatalf("unclassified: verdict=%v systemFault=%v (%v)", verdict, fault, err)
			}
			if c.IsConsensus() {
				if !verdict || IsAborted() {
					t.Fatalf("Core code %s: want a verdict without AbortNode, got %v (aborted=%v)", c, err, IsAborted())
				}
				verdicts++
				return
			}
			if !fault || !IsAborted() || !errors.Is(err, ErrUnclassifiedScriptFailure) {
				t.Fatalf("internal code %s: want a latched system fault, got %v (aborted=%v)", c, err, IsAborted())
			}
			faults++
		})
	}
	// Core's ScriptError_t has 54 codes after SCRIPT_ERR_OK; blockbrew adds
	// one internal code.
	if verdicts != 54 || faults != 1 {
		t.Fatalf("verdict codes=%d (want 54), system-fault codes=%d (want 1)", verdicts, faults)
	}
}

// An error that is not a script.Error at all is not a verdict either: the
// classifier is an allow-list, so it becomes a latched system fault.
func TestScriptVerdict_UntypedErrorIsSystemFault(t *testing.T) {
	ResetAbortForTesting()
	defer ResetAbortForTesting()
	err := scriptVerdict(wire.Hash256{8}, errors.New("something the engine never returns"))
	if _, verdict := AsBlockInvalid(err); verdict || !IsSystemFault(err) || !IsAborted() {
		t.Fatalf("untyped error: got %v (aborted=%v), want a latched system fault", err, IsAborted())
	}
}

// The non-verdict classes that existed before keep their handling: a missing
// prevout stays a plain error with no AbortNode (the P2P loop's marker-lag
// probe handles it), a typed system fault passes through, and once the node
// is aborted even a Core-coded failure is not a verdict.
func TestScriptVerdict_ExistingNonVerdictsUnchanged(t *testing.T) {
	ResetAbortForTesting()
	defer ResetAbortForTesting()
	h := wire.Hash256{9}
	missing := fmt.Errorf("%w for tx 1 input 0", ErrScriptPrevoutMissing)
	if err := scriptVerdict(h, missing); err != missing || IsAborted() {
		t.Fatalf("missing prevout: got %v (aborted=%v)", err, IsAborted())
	}
	sf := SystemFault("read coin", ErrCoinsDBRead)
	if err := scriptVerdict(h, sf); err != sf {
		t.Fatalf("system fault: got %v", err)
	}
	AbortNode(errors.New("test latch"))
	err := scriptVerdict(h, script.ErrEvalFalse)
	if _, verdict := AsBlockInvalid(err); verdict || !IsSystemFault(err) {
		t.Fatalf("after AbortNode a script failure must not be a verdict: %v", err)
	}
}

// The check queue's own invariant failure (a job no block can produce) is a
// system fault, while a real script failure from the same queue is a verdict.
func TestScriptVerdict_CheckQueueInvariantIsSystemFault(t *testing.T) {
	ResetAbortForTesting()
	defer ResetAbortForTesting()
	q := NewScriptCheckQueue(2)
	defer q.Stop()
	tx := &wire.MsgTx{Version: 1, TxIn: []*wire.TxIn{{Sequence: 0xFFFFFFFF}}, TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}}}
	res := q.Run([]ScriptCheckJob{{Tx: tx, TxIdx: 1, InputIdx: 0, PrevOut: nil}})
	if res.OK {
		t.Fatal("invalid job passed")
	}
	err := scriptVerdict(wire.Hash256{10}, res.FirstFailErr)
	if _, verdict := AsBlockInvalid(err); verdict || !IsSystemFault(err) || !IsAborted() {
		t.Fatalf("queue invariant: got %v (aborted=%v), want a latched system fault", err, IsAborted())
	}

	ResetAbortForTesting()
	res = q.Run([]ScriptCheckJob{{Tx: tx, TxIdx: 1, InputIdx: 0,
		PrevOut: &UTXOEntry{Amount: 1, PkScript: []byte{0x00}}, PrevOuts: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00}}}}})
	err = scriptVerdict(wire.Hash256{11}, res.FirstFailErr)
	if _, verdict := AsBlockInvalid(err); !verdict || IsAborted() {
		t.Fatalf("script failure from the queue: got %v (aborted=%v), want a verdict", err, IsAborted())
	}
}
