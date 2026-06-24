package consensus

import "sync"

// TipNotifier is the wake-on-tip-advance primitive shared by the wait-family
// RPCs (waitfornewblock / waitforblock / waitforblockheight).
//
// Bitcoin Core registers a WaitTipChanged condition variable (kernel
// KernelNotifications::blockTip) that is signalled on every active-chain tip
// update. The wait-family RPCs (rpc/blockchain.cpp) block on it with a deadline,
// re-checking their predicate (new tip / hash match / height >=) after each
// wake and returning the current tip {hash, height} on match OR timeout.
// TipNotifier is blockbrew's analogue.
//
// Design (mirrors the proven ouroboros TipNotifier pilot):
//
//   - The waiter's predicate is always evaluated against the AUTHORITATIVE chain
//     tip (cm.BestBlock()), never against state carried inside this object. The
//     notifier only provides a prompt wake-up; correctness does not depend on a
//     notify ever firing for a specific tip value. This makes the primitive
//     robust to coalesced / missed notifications (e.g. two blocks connected
//     back-to-back, or a reorg's disconnect+connect halves, before a waiter
//     wakes): the waiter re-reads the real tip after every wake and after the
//     timeout, exactly like Core.
//
//   - A monotonically increasing generation counter lets a waiter detect a tip
//     change that happened BETWEEN its predicate check and its Wait call (the
//     classic lost-wakeup race). A waiter captures the generation, checks its
//     predicate against the authoritative tip, then awaits a generation bump —
//     so a Notify that races in after the check but before the wait is not lost.
//
//   - The wake mechanism is a sync.Cond. Notify bumps the generation under the
//     lock and Broadcasts, releasing every current waiter. A timeout is layered
//     on top with a per-wait watchdog goroutine that Broadcasts when the
//     deadline elapses (sync.Cond has no native timed wait), and the waiter
//     distinguishes timeout from tip-change by re-checking the generation.
type TipNotifier struct {
	mu         sync.Mutex
	cond       *sync.Cond
	generation uint64
}

// NewTipNotifier returns a ready-to-use TipNotifier.
func NewTipNotifier() *TipNotifier {
	tn := &TipNotifier{}
	tn.cond = sync.NewCond(&tn.mu)
	return tn
}

// Generation returns the current tip-change generation. A waiter snapshots this
// BEFORE checking its predicate so a Notify that races in between the check and
// the Wait is observed (no lost wakeup).
func (tn *TipNotifier) Generation() uint64 {
	tn.mu.Lock()
	g := tn.generation
	tn.mu.Unlock()
	return g
}

// Notify signals that the active-chain tip advanced. It bumps the generation
// counter and wakes every goroutine currently in Wait so each re-evaluates its
// predicate against the authoritative tip. Safe to call from any connect /
// disconnect / reorg chokepoint, from any goroutine.
//
// A nil receiver is a no-op so chokepoints can call it unconditionally even
// when no notifier was wired (degraded boot / unit tests).
func (tn *TipNotifier) Notify() {
	if tn == nil {
		return
	}
	tn.mu.Lock()
	tn.generation++
	tn.cond.Broadcast()
	tn.mu.Unlock()
}

// Wait blocks until the generation advances past lastGeneration (a tip change
// occurred) or, if a deadline channel is supplied, until that channel fires.
//
// lastGeneration is the generation the caller snapshotted via Generation()
// BEFORE it last checked its predicate. If the generation has already moved
// past it (a Notify raced in), Wait returns immediately — closing the
// lost-wakeup window.
//
// timedOut is a channel that, when it becomes readable/closed, signals the
// caller's deadline has elapsed; pass nil for an unbounded wait. Wait returns
// true if it observed a generation bump, false if it returned because the
// deadline fired. Either way the caller MUST re-read the authoritative tip and
// re-evaluate its predicate (Core re-checks on both wake and timeout).
func (tn *TipNotifier) Wait(lastGeneration uint64, timedOut <-chan struct{}) (changed bool) {
	tn.mu.Lock()
	defer tn.mu.Unlock()

	// Fast path: a Notify already raced in since the caller's snapshot.
	if tn.generation != lastGeneration {
		return true
	}

	if timedOut == nil {
		// Unbounded wait: block until the generation moves.
		for tn.generation == lastGeneration {
			tn.cond.Wait()
		}
		return true
	}

	// Bounded wait. sync.Cond has no timed Wait, so spawn a one-shot watchdog
	// that Broadcasts when the deadline channel fires; the loop then observes
	// the deadline flag (set under the lock) and returns. The generation is
	// re-checked on every wake so a real tip change still returns changed=true
	// even if it lands in the same wake as the timeout.
	expired := false
	done := make(chan struct{})
	go func() {
		select {
		case <-timedOut:
			tn.mu.Lock()
			expired = true
			tn.cond.Broadcast()
			tn.mu.Unlock()
		case <-done:
		}
	}()
	// Ensure the watchdog goroutine exits when we leave (so a never-firing
	// deadline channel does not leak a goroutine after a tip change wakes us).
	defer close(done)

	for tn.generation == lastGeneration && !expired {
		tn.cond.Wait()
	}
	return tn.generation != lastGeneration
}
