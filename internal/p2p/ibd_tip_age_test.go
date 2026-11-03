package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Core leaves initial block download only through
// ChainstateManager::UpdateIBDStatus (validation.cpp), which latches
// m_cached_is_ibd=false iff CChain::IsTipRecent (chain.h) holds:
//
//	tip->nChainWork >= MinimumChainWork() &&
//	tip->Time() >= Now<NodeSeconds>() - max_tip_age   // DEFAULT_MAX_TIP_AGE 24h
//
// There is no regtest exception and no "block tip caught up to the best
// header" exit. Core v31.1 on regtest with a chain whose tip carries a 2023
// timestamp therefore reports getblockchaininfo.initialblockdownload=true
// (core-regtest rows chain/…, seed_invalidated_submit/…,
// warden_invalidated_submit/…:initialblockdownload).

// TestIBDTipAge_RegtestOldTipCaughtUpToHeadersStaysInIBD is the failing case:
// a regtest node whose block tip equals its best header but whose tip
// timestamp is far older than MaxTipAge must stay in IBD.
func TestIBDTipAge_RegtestOldTipCaughtUpToHeadersStaysInIBD(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Block tip at the header index's best height (genesis, 0): nothing
	// left to download. Timestamp 2023-11-14, years older than 24h.
	if idx.BestHeight() != 0 {
		t.Fatalf("fresh header index best height = %d, want 0", idx.BestHeight())
	}
	mock := &mockChainConnector{tipHeight: 0, tipTimestamp: 1700000000}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})

	sm.updateIBDStatus()
	if !sm.IsIBDActive() {
		t.Fatal("regtest tip 1700000000 (older than MaxTipAge) caught up to headers: " +
			"IsIBDActive()=false, want true (Core IsTipRecent has no regtest exit)")
	}

	// RefreshIBDStatus (the submitblock path) must not latch it either.
	sm.RefreshIBDStatus()
	if !sm.IsIBDActive() {
		t.Fatal("RefreshIBDStatus latched IBD false for an old regtest tip")
	}
}

// TestIBDTipAge_RegtestRecentTipLeavesIBD guards the other side: a regtest tip
// within MaxTipAge still latches IBD to false, as Core does.
func TestIBDTipAge_RegtestRecentTipLeavesIBD(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	recent := uint32(time.Now().Add(-MaxTipAge + time.Hour).Unix())
	mock := &mockChainConnector{tipHeight: 0, tipTimestamp: recent}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})

	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("regtest tip 23h old: IsIBDActive()=true, want false")
	}
}

// TestIBDTipAge_OldTipThenRecentTipLatchesOnce: an old tip keeps IBD on; once a
// recent tip connects the latch flips and an older tip never re-enters IBD
// (Core's m_cached_is_ibd is sticky).
func TestIBDTipAge_OldTipThenRecentTipLatchesOnce(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	mock := &mockChainConnector{tipHeight: 0, tipTimestamp: 1700000000}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})

	sm.updateIBDStatus()
	if !sm.IsIBDActive() {
		t.Fatal("old tip: IsIBDActive()=false, want true")
	}

	mock.tipHeight = 1
	mock.tipTimestamp = uint32(time.Now().Unix())
	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("recent tip: IsIBDActive()=true, want false")
	}

	mock.tipTimestamp = 1700000000
	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("latch broken: IBD re-entered after leaving it")
	}
}
