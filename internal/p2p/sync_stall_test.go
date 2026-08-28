package p2p

import (
	"testing"
	"time"
)

// TestStallShouldRearm pins #73 layer C — the stall handler starving its own
// retry. Live timeline (mainnet 964241, 2026-08-27): once the stall backoff
// reached 16s+ while stall passes arrived every 5-15s, EVERY pass re-armed
// NextRetryAt=now+backoff before it could expire, so requestBlocks' backoff
// gate never opened and the block was never requested again — for 12+
// minutes, permanently. A Pending request with an armed, unexpired backoff
// must be left alone.
func TestStallShouldRearm(t *testing.T) {
	now := time.Now()

	armed := &blockRequest{State: BlockDownloadPending, NextRetryAt: now.Add(30 * time.Second)}
	if stallShouldRearm(armed, now) {
		t.Fatal("Pending request with an armed, unexpired backoff must NOT be re-armed (#73 starvation)")
	}

	expired := &blockRequest{State: BlockDownloadPending, NextRetryAt: now.Add(-time.Second)}
	if !stallShouldRearm(expired, now) {
		t.Fatal("expired backoff must allow re-arming")
	}

	fresh := &blockRequest{State: BlockDownloadPending}
	if !stallShouldRearm(fresh, now) {
		t.Fatal("zero-value NextRetryAt must allow arming")
	}

	// A non-Pending (e.g. InFlight) request is a genuine transition — the
	// stall handler may always reset those.
	inflight := &blockRequest{State: BlockDownloadInFlight, NextRetryAt: now.Add(30 * time.Second)}
	if !stallShouldRearm(inflight, now) {
		t.Fatal("InFlight requests must remain resettable")
	}
}

// TestStallStarvationScenario replays the wedge arithmetic: stall passes at a
// 10s cadence against a 60s backoff. With re-arm-on-every-pass (the old
// behavior, simulated), the retry gate NEVER opens across 100 passes; with
// stallShouldRearm gating, the backoff expires and the gate opens.
func TestStallStarvationScenario(t *testing.T) {
	start := time.Now()
	req := &blockRequest{State: BlockDownloadPending}

	// Old behavior: every pass re-arms unconditionally.
	req.NextRetryAt = start.Add(60 * time.Second)
	opened := false
	for i := 1; i <= 100; i++ {
		now := start.Add(time.Duration(i) * 10 * time.Second)
		if !now.Before(req.NextRetryAt) {
			opened = true
			break
		}
		req.NextRetryAt = now.Add(60 * time.Second) // unconditional re-arm
	}
	if opened {
		t.Fatal("simulation broken: unconditional re-arm should starve forever")
	}

	// New behavior: re-arm only when stallShouldRearm allows.
	req.NextRetryAt = start.Add(60 * time.Second)
	opened = false
	for i := 1; i <= 100; i++ {
		now := start.Add(time.Duration(i) * 10 * time.Second)
		if !now.Before(req.NextRetryAt) {
			opened = true
			break
		}
		if stallShouldRearm(req, now) {
			req.NextRetryAt = now.Add(60 * time.Second)
		}
	}
	if !opened {
		t.Fatal("with stallShouldRearm gating, the backoff must eventually expire and the retry gate open")
	}
}

// #75 (2026-08-28): the stall handler must distinguish a request that was TRIED
// AND FAILED from one that was NEVER ISSUED.
//
// Live evidence: blockbrew sat at height 964413 with state=Pending, inflight=0,
// peer=false, retries=0 — nothing outstanding, nothing attempted — and served
// out an escalating backoff for 5m43s, logging "backoff already armed — waiting
// it out" until a peer sent the block unsolicited. Several such blocks in a row
// produced a 4-5 block lag while every other node stayed at the tip.
//
// The escalating penalty must be reserved for attempts that actually happened;
// otherwise the node punishes itself for work it never did.
func TestStallRecoveryPlan_NeverIssuedDoesNotEscalate(t *testing.T) {
	req := &blockRequest{
		State:       BlockDownloadPending,
		Peer:        nil,
		RetryCount:  0,
		StallResets: 4, // a high prior count must NOT be charged to a fresh attempt
	}
	backoff, escalate := stallRecoveryPlan(req, false)
	if escalate {
		t.Error("a never-issued request (no peer, no retries, not in flight) has no " +
			"failed attempt to penalise — it must not escalate")
	}
	if backoff != stallBackoff(0) {
		t.Errorf("backoff = %v, want the BASE %v: a request that was never dispatched "+
			"must be retried promptly, not made to serve the accumulated penalty",
			backoff, stallBackoff(0))
	}
	if backoff >= stallBackoff(4) {
		t.Errorf("backoff %v is not shorter than the escalated %v — the fix would have "+
			"no effect on the observed 5m43s stall", backoff, stallBackoff(4))
	}
}

// The other direction: a request that WAS dispatched keeps the escalating
// penalty. Without this, a peer that cannot serve us would be re-asked in a hot
// loop — the failure mode the backoff exists to prevent.
func TestStallRecoveryPlan_TriedAndFailedStillEscalates(t *testing.T) {
	// Dispatched and retried.
	retried := &blockRequest{State: BlockDownloadPending, RetryCount: 2, StallResets: 3}
	if backoff, escalate := stallRecoveryPlan(retried, false); !escalate ||
		backoff != stallBackoff(3) {
		t.Errorf("a retried request must keep the escalating penalty: got backoff=%v escalate=%v",
			backoff, escalate)
	}
	// Assigned to a peer (dispatch in progress).
	assigned := &blockRequest{State: BlockDownloadPending, Peer: &Peer{}, StallResets: 1}
	if _, escalate := stallRecoveryPlan(assigned, false); !escalate {
		t.Error("a request already assigned to a peer counts as attempted")
	}
	// Still in flight.
	inflight := &blockRequest{State: BlockDownloadPending, StallResets: 1}
	if _, escalate := stallRecoveryPlan(inflight, true); !escalate {
		t.Error("a request still in flight counts as attempted")
	}
}
