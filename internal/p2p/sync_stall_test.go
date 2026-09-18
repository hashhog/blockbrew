package p2p

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"
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

// advancingChainConnector is a mock whose ConnectBlock advances the tip so
// connectPendingBlocks' IBD-DESYNC guard does not rewind nextHeight.
type advancingChainConnector struct {
	mockChainConnector
	mu         sync.Mutex
	connects   int
	lastHeight int32
}

func (a *advancingChainConnector) ConnectBlock(b *wire.MsgBlock) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connects++
	a.tipHeight++
	if b != nil {
		a.tipHash = b.Header.BlockHash()
	}
	a.lastHeight = a.tipHeight
	return nil
}

func (a *advancingChainConnector) BestBlock() (wire.Hash256, int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tipHash, a.tipHeight
}

func (a *advancingChainConnector) connectCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connects
}

func stallTestBlock(height int32) *wire.MsgBlock {
	hdr := createTestBlockHeader(wire.Hash256{}, uint32(100+height), uint32(height))
	return &wire.MsgBlock{
		Header: hdr,
		Transactions: []*wire.MsgTx{{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
				SignatureScript:  []byte{0x01, byte(height)},
				Sequence:         0xFFFFFFFF,
			}},
			TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x51}}},
		}},
	}
}

// TestApplyStallRecovery_DoesNotResetValidatedToPending is control (2) for
// the 2026-09-17 mainnet crawl. Live log: state=3 (Validated) → "stuck in
// state 3, resetting to pending". A Validated HOL has already been
// downloaded AND sanity-checked; the stall detector must drive connect, not
// throw the work away. Fails on d30f4bb: applyStallRecovery copies the
// `else if req.State != Pending` branch that assigned Pending.
func TestApplyStallRecovery_DoesNotResetValidatedToPending(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	req := &blockRequest{
		Height:     967280,
		State:      BlockDownloadValidated,
		RetryCount: 1,
	}
	sm.blockQueue = []*blockRequest{req}
	sm.nextHeight = 967280

	sm.applyStallRecovery(req, time.Now())

	if req.State != BlockDownloadValidated {
		t.Fatalf("applyStallRecovery reset Validated → state=%d (want Validated=%d); "+
			"a downloaded+validated block must not be thrown back to the download queue",
			req.State, BlockDownloadValidated)
	}
	if req.Peer != nil {
		t.Fatal("Validated recovery must not assign a download peer")
	}
}

func TestApplyStallRecovery_DoesNotResetReceivedToPending(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	req := &blockRequest{Height: 967280, State: BlockDownloadReceived}
	sm.applyStallRecovery(req, time.Now())
	if req.State != BlockDownloadReceived {
		t.Fatalf("applyStallRecovery reset Received → state=%d (want Received=%d)",
			req.State, BlockDownloadReceived)
	}
}

func TestApplyStallRecovery_StillResetsInFlight(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	peer := createMockPeer("1.2.3.4:8333", 0)
	req := &blockRequest{
		Height:     967280,
		State:      BlockDownloadInFlight,
		Peer:       peer,
		RequestAt:  time.Now().Add(-BaseStallTimeout - time.Second),
		RetryCount: 0,
	}
	sm.inflight[req.Hash] = req
	sm.applyStallRecovery(req, time.Now())
	if req.State != BlockDownloadPending {
		t.Fatalf("InFlight is a stuck DOWNLOAD; state=%d, want Pending", req.State)
	}
	if req.Peer != peer {
		t.Fatal("timed-out InFlight must keep Peer so requestBlocks skips the mute peer")
	}
	if req.RetryCount != 1 {
		t.Fatalf("RetryCount=%d, want 1: mute timeout must count as a failed attempt", req.RetryCount)
	}
	if !req.NextRetryAt.IsZero() {
		t.Fatal("timed-out InFlight must retry immediately, not arm a stall backoff")
	}
	if _, ok := sm.inflight[req.Hash]; ok {
		t.Fatal("InFlight reset must drop the inflight slot")
	}
}

// TestStallRecovery_ValidatedHeadConnectsWithoutRedownload is control (1).
// A queue whose HOL is Validated, with the body already in hand, must end
// Connected without any re-download (no InFlight, no peer, ConnectBlock
// called once). Lost-wakeup shape: the body is on the request, not in
// connectionChan — the stall detector has to nudge the connect path.
// Fails on d30f4bb: recovery assigns Pending and never injects, so the
// connectionWorker never sees the block.
func TestStallRecovery_ValidatedHeadConnectsWithoutRedownload(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	adv := &advancingChainConnector{mockChainConnector: mockChainConnector{tipHeight: 0, tipTimestamp: 1}}
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		ChainManager:   adv,
		DownloadWindow: 8,
	})
	sm.Start()
	defer func() {
		done := make(chan struct{})
		go func() {
			sm.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Stop did not complete within 3s")
		}
	}()

	block := stallTestBlock(1)
	req := &blockRequest{
		Hash:          block.Header.BlockHash(),
		Height:        1,
		State:         BlockDownloadValidated,
		pipelineBlock: block,
	}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{req}
	sm.nextHeight = 1
	sm.applyStallRecovery(req, time.Now())
	stateAfterRecovery := req.State
	sm.mu.Unlock()

	if stateAfterRecovery == BlockDownloadPending || stateAfterRecovery == BlockDownloadInFlight {
		t.Fatalf("stall recovery put Validated HOL into download state %d; "+
			"must leave it in the local pipeline (Validated) and nudge connect",
			stateAfterRecovery)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sm.mu.Lock()
		st := req.State
		sm.mu.Unlock()
		if st == BlockDownloadConnected {
			if adv.connectCount() != 1 {
				t.Fatalf("ConnectBlock called %d times, want 1 (no re-download, no double connect)",
					adv.connectCount())
			}
			if req.Peer != nil {
				t.Fatal("Connected HOL was assigned a download peer — that is a re-download")
			}
			return
		}
		if st == BlockDownloadPending || st == BlockDownloadInFlight {
			t.Fatalf("HOL fell into download state %d while waiting to connect — re-download", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sm.mu.Lock()
	st := req.State
	sm.mu.Unlock()
	t.Fatalf("Validated HOL did not connect: state=%d connects=%d (want Connected, 1 connect, no re-download)",
		st, adv.connectCount())
}

// TestApplyNearbyStallReset_PreservesValidatedAndReceived: the 16-height
// window that runs on every stall pass used to assign Pending to every
// non-Pending/non-Connected neighbour, wiping already-validated blocks
// ahead of the HOL. That is why catch-up went one block at a time.
func TestApplyNearbyStallReset_PreservesValidatedAndReceived(t *testing.T) {
	var h1, h2, h3, h4 wire.Hash256
	h1[0], h2[0], h3[0], h4[0] = 1, 2, 3, 4
	validated := &blockRequest{Hash: h1, Height: 967281, State: BlockDownloadValidated}
	received := &blockRequest{Hash: h2, Height: 967282, State: BlockDownloadReceived}
	inflight := &blockRequest{Hash: h3, Height: 967283, State: BlockDownloadInFlight, Peer: &Peer{}}
	pending := &blockRequest{Hash: h4, Height: 967284, State: BlockDownloadPending}
	inflightMap := map[wire.Hash256]*blockRequest{h3: inflight}
	queue := []*blockRequest{validated, received, inflight, pending}

	applyNearbyStallReset(queue, 967280, inflightMap)

	if validated.State != BlockDownloadValidated {
		t.Fatalf("window reset Validated neighbour to %d", validated.State)
	}
	if received.State != BlockDownloadReceived {
		t.Fatalf("window reset Received neighbour to %d", received.State)
	}
	if inflight.State != BlockDownloadPending {
		t.Fatalf("window must still release a stuck InFlight neighbour, state=%d", inflight.State)
	}
	if inflight.Peer != nil {
		t.Fatal("InFlight neighbour peer must be cleared")
	}
	if _, ok := inflightMap[h3]; ok {
		t.Fatal("InFlight neighbour must leave the inflight map")
	}
	if pending.State != BlockDownloadPending {
		t.Fatalf("Pending neighbour mutated to %d", pending.State)
	}
}

// drainGetData pulls queued getdata hashes off a mock peer without blocking.
func drainGetData(p *Peer) []wire.Hash256 {
	var out []wire.Hash256
	for {
		select {
		case msg := <-p.sendQueue:
			if gd, ok := msg.(*MsgGetData); ok {
				for _, inv := range gd.InvList {
					out = append(out, inv.Hash)
				}
			}
		default:
			return out
		}
	}
}

func mineRegtestHeader(h *wire.BlockHeader) {
	target := consensus.CompactToBig(h.Bits)
	for i := uint32(0); i < 1_000_000; i++ {
		h.Nonce = i
		if consensus.HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return
		}
	}
	panic("regtest header did not meet target")
}

// nearMaxWeightBlock builds a CheckBlockSanity-valid regtest block whose
// weight is ≥ 3.9M WU (the live 967495 block was 3,993,841). Padding is
// OP_RETURN-filler outputs so sigops stay well under the block cap.
func nearMaxWeightBlock(t *testing.T, prev wire.Hash256, timestamp uint32) *wire.MsgBlock {
	t.Helper()
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x01, 0x01},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 50e8, PkScript: []byte{0x51}}},
	}
	pad := bytes.Repeat([]byte{0x6a}, 10000)
	padding := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
	}
	// 97 × 10 KiB scripts ≈ 3.88M WU plus header/coinbase; add until we
	// clear 3.9M without crossing MaxBlockWeight.
	for i := 0; i < 97; i++ {
		padding.TxOut = append(padding.TxOut, &wire.TxOut{Value: 0, PkScript: pad})
	}
	block := &wire.MsgBlock{Transactions: []*wire.MsgTx{coinbase, padding}}
	for {
		w := consensus.CalcBlockWeight(block)
		if w >= 3_900_000 && w <= consensus.MaxBlockWeight {
			break
		}
		if w > consensus.MaxBlockWeight {
			if len(padding.TxOut) == 0 {
				t.Fatalf("cannot fit near-max weight block (weight=%d)", w)
			}
			padding.TxOut = padding.TxOut[:len(padding.TxOut)-1]
			continue
		}
		padding.TxOut = append(padding.TxOut, &wire.TxOut{Value: 0, PkScript: pad})
	}
	hashes := []wire.Hash256{coinbase.TxHash(), padding.TxHash()}
	block.Header = wire.BlockHeader{
		Version:    1,
		PrevBlock:  prev,
		MerkleRoot: consensus.CalcMerkleRoot(hashes),
		Timestamp:  timestamp,
		Bits:       0x207fffff,
	}
	mineRegtestHeader(&block.Header)
	w := consensus.CalcBlockWeight(block)
	if w < 3_900_000 || w > consensus.MaxBlockWeight {
		t.Fatalf("near-max block weight %d not in [3900000, %d]", w, consensus.MaxBlockWeight)
	}
	return block
}

// TestApplyStallRecovery_DoesNotAbortYoungInFlight is the unit pin for the
// 967495 abort: once nextHeight has been stuck >30s, every stall tick reset
// InFlight → Pending (backoff 2s…60s) even when getdata had just gone out.
// A near-max block cannot finish in that 10s window. A request still inside
// getStallTimeout must be left to complete.
func TestApplyStallRecovery_DoesNotAbortYoungInFlight(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	peer := createMockPeer("mute.example:8333", 1)
	var hash wire.Hash256
	hash[0] = 0x49
	req := &blockRequest{
		Hash:      hash,
		Height:    967495,
		State:     BlockDownloadInFlight,
		Peer:      peer,
		RequestAt: time.Now(),
	}
	sm.inflight[hash] = req
	sm.blockQueue = []*blockRequest{req}

	sm.applyStallRecovery(req, time.Now())

	if req.State != BlockDownloadInFlight {
		t.Fatalf("young InFlight was reset to state=%d (want InFlight=%d); "+
			"aborting a download that just started is the 967495 stall "+
			"(state=1 → pending + backoff, retries=0, never rotated)",
			req.State, BlockDownloadInFlight)
	}
	if req.Peer != peer {
		t.Fatal("young InFlight must keep its download peer")
	}
	if _, ok := sm.inflight[hash]; !ok {
		t.Fatal("young InFlight must stay in the inflight map")
	}
	if req.RetryCount != 0 {
		t.Fatalf("RetryCount=%d, want 0: a live download is not a failed attempt", req.RetryCount)
	}
}

// TestMuteMidBodyNearMaxBlockRotatesAndConnects is the 2026-09-18 control.
// Live at height 967495 (weight 3,993,841, 99.8% of max): header accepted,
// then `stall detected … state=0, inflight=0, peer=false, retries=0` for
// minutes, briefly `state=1, inflight=1, peer=true` immediately followed by
// `stuck in state 1, resetting to pending (backoff 1m0s)`. A peer that goes
// mute mid-body must be timed out, the request must rotate to another
// connected peer, and that peer's body must connect. A test that serves a
// small block promptly cannot reproduce the abort-during-download.
func TestMuteMidBodyNearMaxBlockRotatesAndConnects(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	genesis := idx.Genesis()
	block := nearMaxWeightBlock(t, genesis.Hash, genesis.Header.Timestamp+600)
	node, err := idx.AddHeader(block.Header, true)
	if err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	adv := &advancingChainConnector{mockChainConnector: mockChainConnector{tipHeight: 0, tipTimestamp: 1}}
	pm := &PeerManager{}
	mute := createMockPeer("mute.example:8333", node.Height)
	good := createMockPeer("good.example:8333", node.Height)
	pm.InsertConnectedPeer(mute)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		ChainManager:   adv,
		DownloadWindow: 8,
	})
	sm.Start()
	defer func() {
		done := make(chan struct{})
		go func() {
			sm.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop did not complete within 5s")
		}
	}()

	req := &blockRequest{
		Hash:   node.Hash,
		Height: node.Height,
		State:  BlockDownloadPending,
	}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{req}
	sm.nextHeight = node.Height
	sm.mu.Unlock()

	sm.requestBlocks()

	gotMute := drainGetData(mute)
	if len(gotMute) != 1 || gotMute[0] != node.Hash {
		t.Fatalf("mute peer getdata = %v, want [%s]", gotMute, node.Hash)
	}
	sm.mu.Lock()
	if req.State != BlockDownloadInFlight || req.Peer != mute {
		sm.mu.Unlock()
		t.Fatalf("after requestBlocks: state=%d peer=%v, want InFlight on mute", req.State, req.Peer != nil)
	}
	sm.mu.Unlock()

	// Stall detector fires because nextHeight has not advanced (the live
	// stallDuration was already minutes). The download itself is young —
	// mute has gone quiet mid-body, but the per-request window has not
	// expired. Aborting here is the bug.
	sm.mu.Lock()
	sm.applyStallRecovery(req, time.Now())
	youngState, youngPeer := req.State, req.Peer
	sm.mu.Unlock()
	if youngState != BlockDownloadInFlight {
		t.Fatalf("young near-max InFlight reset to state=%d; stall detector must not abort a download still inside getStallTimeout",
			youngState)
	}
	if youngPeer != mute {
		t.Fatal("young InFlight peer was cleared — that is an abort")
	}

	// Mute never delivers. The per-request window expires.
	sm.mu.Lock()
	req.RequestAt = time.Now().Add(-BaseStallTimeout - time.Second)
	sm.applyStallRecovery(req, time.Now())
	staleState := req.State
	staleRetries := req.RetryCount
	stalePeer := req.Peer
	staleRetryAt := req.NextRetryAt
	sm.mu.Unlock()
	if staleState != BlockDownloadPending {
		t.Fatalf("timed-out InFlight state=%d, want Pending so another peer can be asked", staleState)
	}
	if staleRetries < 1 {
		t.Fatalf("RetryCount=%d after mute timeout, want ≥1 so requestBlocks rotates (live log: retries=0 the whole stall)",
			staleRetries)
	}
	if stalePeer != mute {
		t.Fatal("timed-out InFlight must keep Peer so requestBlocks skips the mute peer")
	}
	if !staleRetryAt.IsZero() && time.Until(staleRetryAt) > time.Second {
		t.Fatalf("NextRetryAt is %s in the future — a mute timeout must rotate immediately, not serve a 60s self-penalty",
			time.Until(staleRetryAt).Round(time.Millisecond))
	}

	pm.InsertConnectedPeer(good)
	sm.requestBlocks()

	if extra := drainGetData(mute); len(extra) != 0 {
		t.Fatalf("mute peer was asked again after timeout (%v) — must rotate away", extra)
	}
	gotGood := drainGetData(good)
	if len(gotGood) != 1 || gotGood[0] != node.Hash {
		t.Fatalf("good peer getdata = %v, want [%s] (did not rotate)", gotGood, node.Hash)
	}

	sm.HandleBlock(good, &MsgBlock{Block: block})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sm.mu.Lock()
		st := req.State
		sm.mu.Unlock()
		if st == BlockDownloadConnected {
			if adv.connectCount() != 1 {
				t.Fatalf("ConnectBlock called %d times, want 1", adv.connectCount())
			}
			_, tip := adv.BestBlock()
			if tip != node.Height {
				t.Fatalf("tip height %d, want %d", tip, node.Height)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	sm.mu.Lock()
	st := req.State
	sm.mu.Unlock()
	t.Fatalf("rotated near-max block did not connect: state=%d connects=%d (want Connected, tip=%d)",
		st, adv.connectCount(), node.Height)
}

// liveNearMaxSerializedBytes is block 967495's size (the first near-max stall).
// nearMaxWeightBlock pads with OP_RETURN so it is denser than a 7k-tx mainnet
// body; the timeout must cover the real wire size, not just the test fixture.
const liveNearMaxSerializedBytes = 1_539_532

// TestNearMaxBodyAtRealisticRateCompletesWithoutStall is the 2026-09-18 soak
// control. Seven consecutive ≥3.9 M-weight blocks arrived; rotation worked
// (retries 1..7, peer=true) but each body took long enough to hit
// getStallTimeout, so the node sat at a 2-block lag while six other impls
// on the same box stayed at tip. If the fetch time of a ≥3.9 M-weight body
// at a realistic rate is anywhere near getStallTimeout, the timeout is the
// bug. The body must connect without a "stall detected" line.
func TestNearMaxBodyAtRealisticRateCompletesWithoutStall(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	genesis := idx.Genesis()
	block := nearMaxWeightBlock(t, genesis.Hash, genesis.Header.Timestamp+600)
	node, err := idx.AddHeader(block.Header, true)
	if err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	var ser bytes.Buffer
	if err := block.Serialize(&ser); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	size := ser.Len()
	if size < 900_000 {
		t.Fatalf("near-max body serialized to %d bytes; want ≥900KiB", size)
	}
	wireBytes := size
	if wireBytes < liveNearMaxSerializedBytes {
		wireBytes = liveNearMaxSerializedBytes
	}
	fetch := time.Duration(wireBytes) * time.Second / minLiveBlockThroughput
	if fetch < 35*time.Second {
		t.Fatalf("fixture fetch %s is too short to exercise the soak (live p90 38.1s)", fetch)
	}

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	log.SetOutput(&lockedLogWriter{mu: &logMu, w: &logBuf})
	defer log.SetOutput(os.Stderr)

	adv := &advancingChainConnector{mockChainConnector: mockChainConnector{tipHeight: 0, tipTimestamp: 1}}
	pm := &PeerManager{}
	peer := createMockPeer("slow.example:8333", node.Height)
	pm.InsertConnectedPeer(peer)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		ChainManager:   adv,
		DownloadWindow: 8,
	})
	sm.Start()
	defer func() {
		done := make(chan struct{})
		go func() {
			sm.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop did not complete within 5s")
		}
	}()

	timeout := sm.getStallTimeout(peer)
	t.Logf("near-max body serialized=%d wireBytes=%d rate=%d B/s fetch=%s getStallTimeout=%s BaseStallTimeout=%s",
		size, wireBytes, minLiveBlockThroughput, fetch, timeout, BaseStallTimeout)
	if fetch >= timeout {
		t.Fatalf("time-to-complete %s for a %d-byte ≥3.9M-weight body at %d B/s is not inside getStallTimeout %s — the timeout is the bug, not the peer (live p90 38.1s / worst 56.0s vs old 30s)",
			fetch, wireBytes, minLiveBlockThroughput, timeout)
	}

	req := &blockRequest{
		Hash:   node.Hash,
		Height: node.Height,
		State:  BlockDownloadPending,
	}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{req}
	sm.nextHeight = node.Height
	sm.mu.Unlock()

	sm.requestBlocks()
	got := drainGetData(peer)
	if len(got) != 1 || got[0] != node.Hash {
		t.Fatalf("getdata = %v, want [%s]", got, node.Hash)
	}

	// Body is still arriving: RequestAt is `fetch` ago, matching a 1.54 MB
	// transfer at 32 KiB/s. checkStaleRequests and the stall ticker both
	// fire in that window on mainnet (1s and 10s ticks).
	now := time.Now()
	sm.mu.Lock()
	req.RequestAt = now.Add(-fetch)
	if req.State != BlockDownloadInFlight {
		sm.mu.Unlock()
		t.Fatalf("after requestBlocks: state=%d, want InFlight", req.State)
	}
	sm.mu.Unlock()

	sm.checkStaleRequests()

	sm.mu.Lock()
	if req.State != BlockDownloadInFlight {
		st, retries := req.State, req.RetryCount
		sm.mu.Unlock()
		t.Fatalf("checkStaleRequests aborted a realistic-rate near-max fetch: state=%d retries=%d after %s (timeout %s)",
			st, retries, fetch, timeout)
	}
	lastH, _ := sm.checkForStall(now, node.Height, now.Add(-fetch))
	stateAfterStall := req.State
	sm.mu.Unlock()
	if stateAfterStall != BlockDownloadInFlight {
		t.Fatalf("stall detector aborted a live near-max download: state=%d after fetch %s", stateAfterStall, fetch)
	}
	if lastH != node.Height {
		t.Fatalf("stall cursor height %d, want %d", lastH, node.Height)
	}

	// After a prior timeout, stallDuration is already > BaseStallTimeout
	// while the replacement getdata is still young. That produced the soak
	// residual: 48 "stall detected" lines in 39 min, all peer=true.
	sm.mu.Lock()
	req.RequestAt = now
	sm.checkForStall(now, node.Height, now.Add(-BaseStallTimeout-time.Second))
	if req.State != BlockDownloadInFlight {
		st := req.State
		sm.mu.Unlock()
		t.Fatalf("young InFlight during a long nextHeight stall was reset to state=%d", st)
	}
	sm.mu.Unlock()

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if strings.Contains(logs, "stall detected") {
		t.Fatalf("stall line during a realistic-rate near-max fetch (timeout %s, fetch %s):\n%s", timeout, fetch, logs)
	}

	sm.HandleBlock(peer, &MsgBlock{Block: block})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sm.mu.Lock()
		st := req.State
		sm.mu.Unlock()
		if st == BlockDownloadConnected {
			if adv.connectCount() != 1 {
				t.Fatalf("ConnectBlock called %d times, want 1", adv.connectCount())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	sm.mu.Lock()
	st := req.State
	sm.mu.Unlock()
	t.Fatalf("near-max body did not connect: state=%d connects=%d", st, adv.connectCount())
}

type lockedLogWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedLogWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
