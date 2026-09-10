package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
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

// TestStallRecoveryPlan_DispatchedThenResetStillEscalates is the 09-09
// control. Live log at height 966196: state=Pending, inflight=0, peer=false,
// retries=0 — the same shape as #75's never-issued case — except getdata HAD
// been sent (RequestAt is stamped on dispatch and is not cleared). Both reset
// sites used to nil Peer and zero RetryCount, so stallRecoveryPlan took the
// never-issued branch on every subsequent pass and StallResets froze for
// 13 minutes. A dispatched-then-reset request must escalate.
//
// Revert control: restore
//
//	neverIssued := req.RetryCount == 0 && req.Peer == nil && !inFlight
//
// in stallRecoveryPlan (drop the RequestAt conjunct) and this test fails.
func TestStallRecoveryPlan_DispatchedThenResetStillEscalates(t *testing.T) {
	req := &blockRequest{
		State:       BlockDownloadPending,
		Peer:        nil,
		RetryCount:  0, // live logs: retries=0 the whole stall
		StallResets: 1,
		RequestAt:   time.Now().Add(-time.Minute),
	}
	backoff, escalate := stallRecoveryPlan(req, false)
	if !escalate {
		t.Fatal("a request that was dispatched (RequestAt set) is not never-issued " +
			"after the stall reset; must take the escalation branch")
	}
	if backoff != stallBackoff(1) {
		t.Errorf("backoff=%v, want stallBackoff(StallResets)=%v", backoff, stallBackoff(1))
	}
}

// TestApplyPendingStallRecovery_EscalatesAcrossResets drives the production
// stall-handler helper over repeated passes — the path that was unreachable
// when the helper zeroed RetryCount. StallResets must grow on every pass of
// a previously dispatched request; RetryCount must survive.
func TestApplyPendingStallRecovery_EscalatesAcrossResets(t *testing.T) {
	now := time.Now()
	req := &blockRequest{
		State:      BlockDownloadPending,
		Peer:       &Peer{},
		RetryCount: 2,
		RequestAt:  now.Add(-time.Minute),
	}

	for i := 0; i < 6; i++ {
		_, escalate := applyPendingStallRecovery(req, now, false)
		if !escalate {
			t.Fatalf("pass %d: dispatched request must escalate; stallRecoveryPlan "+
				"took the never-issued branch (RetryCount=%d peer=%v RequestAt zero=%v)",
				i, req.RetryCount, req.Peer != nil, req.RequestAt.IsZero())
		}
		if req.RetryCount != 2 {
			t.Fatalf("pass %d: RetryCount=%d, want 2 — zeroing it is why the "+
				"escalation branch was unreachable", i, req.RetryCount)
		}
		if req.Peer != nil {
			t.Fatalf("pass %d: peer restriction must be cleared", i)
		}
		now = now.Add(10 * time.Second)
	}
	if req.StallResets != 6 {
		t.Fatalf("StallResets=%d, want 6 — the escalation branch did not run on every pass",
			req.StallResets)
	}
}

// TestApplyPendingStallRecovery_NeverIssuedDoesNotEscalate keeps the #75
// pin on the production helper, not just stallRecoveryPlan: a request that
// was never dispatched must not accrue StallResets.
func TestApplyPendingStallRecovery_NeverIssuedDoesNotEscalate(t *testing.T) {
	req := &blockRequest{State: BlockDownloadPending, StallResets: 4}
	_, escalate := applyPendingStallRecovery(req, time.Now(), false)
	if escalate {
		t.Fatal("#75: a never-issued request must not escalate")
	}
	if req.StallResets != 4 {
		t.Fatalf("StallResets=%d, want 4 (must not increment on never-issued)", req.StallResets)
	}
}

func TestReleasePeerSlot_PreservesRetryCount(t *testing.T) {
	req := &blockRequest{
		State:      BlockDownloadInFlight,
		Peer:       &Peer{},
		RetryCount: 3,
		RequestAt:  time.Now(),
	}
	releasePeerSlot(req)
	if req.State != BlockDownloadPending {
		t.Fatalf("state=%d, want Pending", req.State)
	}
	if req.Peer != nil {
		t.Fatal("peer must be cleared so a live peer can be assigned")
	}
	if req.RetryCount != 3 {
		t.Fatalf("RetryCount=%d, want 3: zeroing it is why stallRecoveryPlan never escalated (09-09 966196)",
			req.RetryCount)
	}
	if _, escalate := stallRecoveryPlan(req, false); !escalate {
		t.Fatal("after releasePeerSlot, a previously issued request must still escalate")
	}
}

// TestStartBlockDownload_EvictionPreservesRetryCountAndEscalates reaches
// the production eviction site (sync.go StartBlockDownload) that used to
// assign RetryCount=0. Re-adding that assignment fails this test.
func TestStartBlockDownload_EvictionPreservesRetryCountAndEscalates(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	dead := createMockPeer("dead:8333", 0)
	dead.state = PeerStateDisconnected
	req := &blockRequest{
		Height:      966196,
		State:       BlockDownloadInFlight,
		Peer:        dead,
		RetryCount:  2,
		StallResets: 3,
		RequestAt:   time.Now().Add(-time.Minute),
	}
	sm.blockQueue = []*blockRequest{req}
	sm.inflight[req.Hash] = req

	sm.StartBlockDownload()

	if req.RetryCount != 2 {
		t.Fatalf("RetryCount=%d, want 2: StartBlockDownload eviction zeroed it, so stallRecoveryPlan never escalates",
			req.RetryCount)
	}
	if req.Peer != nil {
		t.Fatal("dead peer must be cleared")
	}
	if req.State != BlockDownloadPending {
		t.Fatalf("state=%d, want Pending", req.State)
	}
	if _, ok := sm.inflight[req.Hash]; ok {
		t.Fatal("in-flight slot must be released")
	}
	if _, escalate := stallRecoveryPlan(req, false); !escalate {
		t.Fatal("after StartBlockDownload eviction, a tried request must still escalate")
	}
}

// TestCheckStaleRequests_DeadPeerPreservesRetryCountAndEscalates reaches
// the other production reset that used to assign RetryCount=0 (the W13
// inflight sweep). Same control as the StartBlockDownload pin.
func TestCheckStaleRequests_DeadPeerPreservesRetryCountAndEscalates(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	dead := createMockPeer("dead:8333", 0)
	dead.state = PeerStateDisconnected
	var hash wire.Hash256
	hash[0] = 1
	req := &blockRequest{
		Hash:        hash,
		Height:      966196,
		State:       BlockDownloadInFlight,
		Peer:        dead,
		RetryCount:  2,
		StallResets: 1,
		RequestAt:   time.Now().Add(-time.Minute),
	}
	sm.inflight[hash] = req

	sm.checkStaleRequests()

	if req.RetryCount != 2 {
		t.Fatalf("RetryCount=%d, want 2 (zeroing it is the 09-09 unreachable-escalation bug)",
			req.RetryCount)
	}
	if req.State != BlockDownloadPending {
		t.Fatalf("state=%d, want Pending", req.State)
	}
	if req.Peer != nil {
		t.Fatal("dead peer must be cleared")
	}
	if _, ok := sm.inflight[hash]; ok {
		t.Fatal("in-flight slot must be released")
	}
	if _, escalate := stallRecoveryPlan(req, false); !escalate {
		t.Fatal("after dead-peer eviction, a previously issued request must still escalate")
	}
}
