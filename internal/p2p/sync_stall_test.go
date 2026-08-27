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
