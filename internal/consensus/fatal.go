package consensus

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
)

// Gate 6 (docs/RELEASE-CHECKLIST.md): OOM, disk-full, I/O and DB failures lead
// to retry or halt, never to a reject or an accept.
//
// This file is blockbrew's analogue of Bitcoin Core's AbortNode / FatalError
// (validation.cpp:2136, node/abort.cpp). Core's contract:
//
//   - a failed coins-DB read aborts the node (CCoinsViewErrorCatcher,
//     coins.cpp:415-427), it is never read as "coin absent";
//   - a failed block/undo/chainstate write or flush is FatalError -> AbortNode
//     (validation.cpp:2779-2836, blockstorage.cpp:986-1007): the block is never
//     marked invalid, the peer is never punished, nothing more is connected and
//     the node shuts down;
//   - the in-memory coins cache is cleared only AFTER BatchWrite succeeds.
//
// blockbrew keeps ONE process-wide latch. It is set at the source — the place
// that saw the system fault — and every consumer that could otherwise turn the
// fault into a decision checks it: the chain manager's mutation entry points
// (connect, reorg, adopt, disconnect), the verdict classifier (blockVerdict),
// every UTXO flush (so a torn in-memory view never reaches disk, including the
// graceful-shutdown flush), submitblock (RPC_VERIFY_ERROR), the mempool, and
// the P2P connect loop. cmd/blockbrew watches Aborted() and shuts the process
// down with exit status 1 WITHOUT flushing the chainstate, so systemd restarts
// it on the last durable atomic batch.

// ErrNodeAborted is returned by every entry point that refuses work because the
// fatal latch is set. It is a system condition, never a verdict.
var ErrNodeAborted = errors.New("node is shutting down after a fatal error")

// ErrCoinsDBRead marks a failed read of the coins database (I/O error, closed
// DB, undecodable record). Core: CCoinsViewErrorCatcher -> AbortNode.
var ErrCoinsDBRead = errors.New("coins database read failed")

// ErrChainstateWrite marks a failed write of the chainstate (block body/index
// rows, undo, UTXO delta, tip pointer). Core: FatalError("Failed to write ...").
var ErrChainstateWrite = errors.New("chainstate write failed")

// ErrPanicDuringConnect marks a Go panic raised while a block was being
// connected. The in-memory view is torn at that point; Core's equivalent is a
// crash.
var ErrPanicDuringConnect = errors.New("panic during block connection")

// SystemFaultError wraps a local system failure (I/O, disk full, closed DB,
// panic) observed while validating or connecting a block. It is NEVER a
// consensus verdict: callers must not mark the block failed, must not punish
// the peer, and must not answer a BIP-22 reject token for it.
type SystemFaultError struct {
	Op  string // what was being done ("read coin", "write block batch", ...)
	Err error
}

func (e *SystemFaultError) Error() string {
	return fmt.Sprintf("system fault (%s): %v", e.Op, e.Err)
}

func (e *SystemFaultError) Unwrap() error { return e.Err }

// SystemFault wraps err as a SystemFaultError for operation op.
func SystemFault(op string, err error) error {
	if err == nil {
		return nil
	}
	return &SystemFaultError{Op: op, Err: err}
}

// IsSystemFault reports whether err is (or wraps) a local system failure or a
// refusal caused by the fatal latch. Such errors are never verdicts.
func IsSystemFault(err error) bool {
	if err == nil {
		return false
	}
	var sf *SystemFaultError
	return errors.As(err, &sf) || errors.Is(err, ErrNodeAborted)
}

var (
	abortedFlag atomic.Bool
	abortMu     sync.Mutex
	abortReason error
	abortedCh   = make(chan struct{})
)

// AbortNode latches the process-wide fatal state. The first reason wins; later
// calls are logged and otherwise ignored. Safe for concurrent use.
//
// After this returns, no chain mutation is accepted, no UTXO state is written,
// submitblock and the mempool refuse, and cmd/blockbrew shuts the process down
// with a non-zero exit status, skipping the chainstate flush.
func AbortNode(reason error) {
	if reason == nil {
		reason = errors.New("unspecified fatal error")
	}
	abortMu.Lock()
	if abortedFlag.Load() {
		abortMu.Unlock()
		log.Printf("[FATAL] additional fatal error after AbortNode (ignored): %v", reason)
		return
	}
	abortReason = reason
	abortedFlag.Store(true)
	close(abortedCh)
	abortMu.Unlock()
	log.Printf("[FATAL] AbortNode: %v — no further blocks will be connected, the "+
		"chainstate will NOT be flushed on shutdown, and the process will exit non-zero "+
		"so it restarts on the last durable atomic batch", reason)
}

// IsAborted reports whether AbortNode has been called.
func IsAborted() bool { return abortedFlag.Load() }

// AbortReason returns the reason passed to the first AbortNode call, or nil.
func AbortReason() error {
	abortMu.Lock()
	defer abortMu.Unlock()
	return abortReason
}

// Aborted returns a channel that is closed when AbortNode is first called.
func Aborted() <-chan struct{} {
	abortMu.Lock()
	defer abortMu.Unlock()
	return abortedCh
}

// abortedErr returns ErrNodeAborted wrapped with the latched reason.
func abortedErr() error {
	if r := AbortReason(); r != nil {
		return fmt.Errorf("%w: %v", ErrNodeAborted, r)
	}
	return ErrNodeAborted
}

// ResetAbortForTesting clears the fatal latch. Tests only: production code must
// never un-latch — the only way out of an AbortNode is a process restart.
func ResetAbortForTesting() {
	abortMu.Lock()
	defer abortMu.Unlock()
	abortedFlag.Store(false)
	abortReason = nil
	abortedCh = make(chan struct{})
}

// latchOnPanic is deferred by every chain-mutating entry point. If the function
// is unwinding from a panic, it latches AbortNode BEFORE the panic reaches any
// outer recover (p2p connect loop, submitblock handler), then re-panics.
//
// Without it a recovered panic mid-connect let the node keep running on a
// half-applied UTXO view, and the graceful-shutdown flush then persisted that
// half block; on reboot the marker-lag repair found the block's own coinbase
// on disk and adopted it as fully valid without ever running its scripts
// (audit F3/C2). Core has no recover here at all: a fatal error halts.
func latchOnPanic() {
	if r := recover(); r != nil {
		AbortNode(SystemFault("chain mutation", fmt.Errorf("%w: %v", ErrPanicDuringConnect, r)))
		panic(r)
	}
}
