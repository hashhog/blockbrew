package script

import (
	"bytes"
	"errors"
	"testing"
)

// newBareEngine builds an Engine suitable for calling executeScript directly,
// mirroring Core's EvalScript entry point (no tx / sighash needed for these
// stack-size cases).
func newBareEngine() *Engine {
	return &Engine{
		stack:      NewStack(),
		altStack:   NewStack(),
		condStack:  make([]bool, 0),
		sigVersion: SigVersionBase,
	}
}

// Core interpreter.cpp:1222 runs `if (stack.size() + altstack.size() >
// MAX_STACK_SIZE)` at the END of EVERY loop iteration, including pure push
// opcodes. 1001 OP_1 pushes must therefore be REJECTED with a stack-size
// error; blockbrew previously skipped the check on the push path and ACCEPTED.
func TestMaxStackSizePushesOverLimit(t *testing.T) {
	script := bytes.Repeat([]byte{OP_1}, 1001)
	e := newBareEngine()
	err := e.executeScript(script)
	if !errors.Is(err, ErrStackOverflow) {
		t.Fatalf("1001 pushes: expected ErrStackOverflow, got %v", err)
	}
}

// The legitimate 1000-element boundary must NOT regress: exactly 1000 pushes
// is OK in Core (1000 is not > MAX_STACK_SIZE).
func TestMaxStackSizePushesAtLimit(t *testing.T) {
	script := bytes.Repeat([]byte{OP_1}, 1000)
	e := newBareEngine()
	if err := e.executeScript(script); err != nil {
		t.Fatalf("1000 pushes: expected success, got %v", err)
	}
	if got := e.stack.Size(); got != 1000 {
		t.Fatalf("1000 pushes: expected stack size 1000, got %d", got)
	}
}

// Draining back to size 1 after exceeding the limit must still REJECT: Core
// already fails at the 1001st push, before the OP_DROP runs.
func TestMaxStackSizePushThenDrain(t *testing.T) {
	script := bytes.Repeat([]byte{OP_1}, 1001)
	script = append(script, bytes.Repeat([]byte{OP_DROP}, 1000)...)
	e := newBareEngine()
	err := e.executeScript(script)
	if !errors.Is(err, ErrStackOverflow) {
		t.Fatalf("1001 pushes then drain: expected ErrStackOverflow, got %v", err)
	}
}
