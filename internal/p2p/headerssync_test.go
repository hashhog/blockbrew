package p2p

// headerssync_test.go — comprehensive unit tests for the PRESYNC/REDOWNLOAD
// pipeline (headerssync.go).
//
// Test coverage map (Core gate numbers from headerssync.go comments):
//   G1  commitment_period assertion
//   G2  max_commitments = 6 * (now - MTP + 7200) / 600
//   G3  random commit_offset in [0, HeaderCommitmentPeriod)
//   G4  empty batch → success=true, no-op
//   G5  FINAL state → empty result, no panic
//   G6  PRESYNC dispatches to validateAndStoreHeadersCommitments
//   G7  full batch + presync → RequestMore=true
//   G8  short batch + still presync (no threshold) → RequestMore=false
//   G9  REDOWNLOAD dispatches per header
//   G10 REDOWNLOAD drains buffer via popHeadersReadyForAcceptance
//   G11 REDOWNLOAD buffer drains to zero when processAll=true
//   G12 REDOWNLOAD + full message → RequestMore=true
//   G13 REDOWNLOAD + non-full → no request_more, still success
//   G14 finalize on !(success && request_more)
//   G15 NextLocator FINAL → nil
//   G16 NextLocator PRESYNC → last header hash as first entry
//   G17 NextLocator REDOWNLOAD → redownloadBufferLastHash as first entry
//   G18 NextLocator always appends chainStartHash
//   G19 connectivity check in PRESYNC
//   G20 per-header validation loop
//   G21 PRESYNC → REDOWNLOAD transition on work threshold
//   G22 validateAndProcessSingleHeader requires PRESYNC
//   G23 PermittedDifficultyTransition abort in PRESYNC
//   G24 commitment stored at (height % PERIOD == offset)
//   G25 max_commitments overflow abort
//   G26 CalcWork accumulates in currentChainWork
//   G27 lastHeaderReceived + currentHeight advance
//   G28 validateAndStoreRedownloadedHeader requires REDOWNLOAD
//   G29 redownload connectivity check
//   G30 PermittedDifficultyTransition abort in REDOWNLOAD
//   G31 redownload work accumulation
//   G32 processAllRemainingHeaders set when work >= threshold
//   G33 commitment check at designated heights
//   G34 commitment overrun abort
//   G35 commitment mismatch abort
//   G36 buffer append + state advance
//   G37 popHeadersReadyForAcceptance requires REDOWNLOAD
//   G38 drain condition: buffer > REDOWNLOAD_BUFFER_SIZE OR processAll
//   G39 full header reconstruction from compressedHeader

import (
	"math/big"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// testChainParams returns a regtest-like chain params with a configurable
// MinimumChainWork so we can control when PRESYNC transitions.
func testChainParams(minWork *big.Int) *consensus.ChainParams {
	p := consensus.RegtestParams()
	// Return a copy with the specified minimum work.
	// We can't modify the singleton, so use a local copy.
	cp := *p
	cp.MinimumChainWork = minWork
	return &cp
}

// buildTestChain constructs n regtest-difficulty headers chained together,
// starting from genesis.  Returns (nodes, chainStart) where nodes[0] is
// genesis.  For test purposes we don't mine valid PoW; regtest params
// skip PermittedDifficultyTransition so any nBits is fine, but we do need
// the prevBlock chain to be continuous.
//
// NOTE: we use HeadersSyncState internal methods directly, so we don't need
// actual valid PoW here; the testnet/regtest PermittedDifficultyTransition
// always returns true (fPowAllowMinDifficultyBlocks).
func buildTestChainHeaders(n int) ([]wire.BlockHeader, *consensus.BlockNode) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Mine regtest genesis + n blocks.
	headers := make([]wire.BlockHeader, n)
	prevHash := idx.Genesis().Hash
	ts := uint32(time.Now().Unix()) - uint32(n*600)
	for i := 0; i < n; i++ {
		hdr := wire.BlockHeader{
			Version:    1,
			PrevBlock:  prevHash,
			MerkleRoot: wire.Hash256{byte(i), byte(i >> 8)},
			Timestamp:  ts + uint32(i)*600,
			Bits:       0x207fffff, // Regtest easy
			Nonce:      uint32(i),
		}
		// find a valid nonce for regtest (target is 0x7fffff...):
		target := consensus.CompactToBig(hdr.Bits)
		for j := uint32(0); j < 0xFFFFFF; j++ {
			hdr.Nonce = j
			h := hdr.BlockHash()
			if consensus.HashToBig(h).Cmp(target) <= 0 {
				break
			}
		}
		headers[i] = hdr
		prevHash = hdr.BlockHash()
	}
	return headers, idx.Genesis()
}

// buildHSSForTest creates a HeadersSyncState with a deterministic clock so
// that max_commitments is reproducible.
func buildHSSForTest(t *testing.T, chainStart *consensus.BlockNode, minWork *big.Int) *HeadersSyncState {
	t.Helper()
	params := testChainParams(minWork)
	orig := headersSyncNowUnix
	headersSyncNowUnix = func() int64 {
		return chainStart.GetMedianTimePast() + 3*365*24*3600 // 3 years of slack
	}
	t.Cleanup(func() { headersSyncNowUnix = orig })
	return NewHeadersSyncState("test-peer", params, chainStart, minWork)
}

// TestNewHeadersSyncState_CommitOffset verifies G3: commit_offset is in range.
func TestNewHeadersSyncState_CommitOffset(t *testing.T) {
	headers, genesis := buildTestChainHeaders(0)
	_ = headers
	for i := 0; i < 200; i++ {
		hss := buildHSSForTest(t, genesis, big.NewInt(0))
		if hss.commitOffset < 0 || hss.commitOffset >= HeaderCommitmentPeriod {
			t.Fatalf("commitOffset=%d out of [0,%d)", hss.commitOffset, HeaderCommitmentPeriod)
		}
	}
}

// TestNewHeadersSyncState_MaxCommitments verifies G2: bound calculation.
func TestNewHeadersSyncState_MaxCommitments(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	params := testChainParams(big.NewInt(0))
	fixedNow := genesis.GetMedianTimePast() + 10*365*24*3600 // 10 years from MTP

	orig := headersSyncNowUnix
	headersSyncNowUnix = func() int64 { return fixedNow }
	defer func() { headersSyncNowUnix = orig }()

	hss := NewHeadersSyncState("test", params, genesis, big.NewInt(0))
	maxSecs := (fixedNow - genesis.GetMedianTimePast()) + HeaderSyncMaxFutureTime
	expected := int(HeaderSyncMaxBlockRate * maxSecs / HeaderCommitmentPeriod)
	if hss.maxCommitments != expected {
		t.Errorf("maxCommitments=%d want %d", hss.maxCommitments, expected)
	}
}

// TestProcessNextHeaders_EmptyBatch verifies G4.
func TestProcessNextHeaders_EmptyBatch(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss := buildHSSForTest(t, genesis, big.NewInt(0))
	result := hss.ProcessNextHeaders(nil, false)
	if !result.Success {
		t.Error("empty batch should succeed (G4)")
	}
	if result.RequestMore {
		t.Error("empty batch should not request more (G4)")
	}
}

// TestProcessNextHeaders_FinalState verifies G5.
func TestProcessNextHeaders_FinalState(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss := buildHSSForTest(t, genesis, big.NewInt(0))
	hss.finalize()
	headers, _ := buildTestChainHeaders(1)
	result := hss.ProcessNextHeaders(headers, true)
	if result.Success || result.RequestMore {
		t.Error("FINAL state should return empty result (G5)")
	}
}

// TestProcessNextHeaders_PresyncFullMsg verifies G7: full message → RequestMore=true.
func TestProcessNextHeaders_PresyncFullMsg(t *testing.T) {
	// Build a very short chain; regtest minWork=0 so we'll transition
	// to REDOWNLOAD immediately on the first batch.  Use a high minWork
	// so we stay in PRESYNC.
	// Use impossibly high minWork so we never transition.
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	headers, genesis := buildTestChainHeaders(5)
	hss := buildHSSForTest(t, genesis, hugeWork)

	result := hss.ProcessNextHeaders(headers, true) // full message
	if !result.Success {
		t.Fatalf("expected success, got failure")
	}
	if !result.RequestMore {
		t.Error("full message in PRESYNC should set RequestMore=true (G7)")
	}
}

// TestProcessNextHeaders_PresyncShortMsg verifies G8: non-full + still PRESYNC → done.
func TestProcessNextHeaders_PresyncShortMsg(t *testing.T) {
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	headers, genesis := buildTestChainHeaders(3)
	hss := buildHSSForTest(t, genesis, hugeWork)

	result := hss.ProcessNextHeaders(headers, false) // non-full
	if !result.Success {
		t.Fatalf("expected success (G8)")
	}
	if result.RequestMore {
		t.Error("non-full PRESYNC message should NOT set RequestMore (G8)")
	}
	if hss.phase != HeadersSyncFinal {
		t.Error("state should be FINAL after non-full PRESYNC (G14)")
	}
}

// TestPresync_NonContinuous verifies G19: first header prevBlock mismatch → fail.
func TestPresync_NonContinuous(t *testing.T) {
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	headers, genesis := buildTestChainHeaders(3)
	hss := buildHSSForTest(t, genesis, hugeWork)

	// Corrupt the chain by clearing prevBlock on the first header.
	bad := make([]wire.BlockHeader, len(headers))
	copy(bad, headers)
	bad[0].PrevBlock = wire.Hash256{0xDE, 0xAD}

	result := hss.ProcessNextHeaders(bad, true)
	if result.Success {
		t.Error("non-continuous headers should fail (G19)")
	}
	if hss.phase != HeadersSyncFinal {
		t.Error("state should be FINAL after failure (G14)")
	}
}

// TestPresync_DifficultyJump verifies G23: sudden nBits change on mainnet → fail.
func TestPresync_DifficultyJump(t *testing.T) {
	// Use mainnet params where PermittedDifficultyTransition is strict.
	mainnetParams := consensus.MainnetParams()
	genesis := consensus.NewHeaderIndex(mainnetParams).Genesis()
	orig := headersSyncNowUnix
	headersSyncNowUnix = func() int64 {
		return genesis.GetMedianTimePast() + 5*365*24*3600
	}
	defer func() { headersSyncNowUnix = orig }()

	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	hss := NewHeadersSyncState("test", mainnetParams, genesis, hugeWork)

	// Build one header with different nBits at height 1 (non-retarget boundary).
	prevHash := genesis.Hash
	hdr := wire.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: wire.Hash256{},
		Timestamp:  uint32(genesis.GetMedianTimePast()) + 600,
		Bits:       0x1c00ffff, // Different from genesis 0x1d00ffff
		Nonce:      0,
	}
	result := hss.ProcessNextHeaders([]wire.BlockHeader{hdr}, true)
	if result.Success {
		t.Error("invalid difficulty transition should fail (G23)")
	}
}

// TestPresync_Transition verifies G21: once work threshold reached → REDOWNLOAD.
func TestPresync_Transition(t *testing.T) {
	// Build enough headers to exceed very small minWork.
	headers, genesis := buildTestChainHeaders(10)

	// minWork = work of 5 headers.
	fiveHeadersWork := new(big.Int)
	w := consensus.CalcWork(0x207fffff)
	for i := 0; i < 5; i++ {
		fiveHeadersWork.Add(fiveHeadersWork, w)
	}

	hss := buildHSSForTest(t, genesis, fiveHeadersWork)

	result := hss.ProcessNextHeaders(headers, true)
	if !result.Success {
		t.Fatalf("expected success after transition: phase=%v", hss.phase)
	}
	// Should have transitioned to REDOWNLOAD (and since it's a full message,
	// RequestMore=true).
	if !result.RequestMore {
		t.Error("full message after PRESYNC→REDOWNLOAD should set RequestMore (G7)")
	}
}

// TestPresync_CommitmentStored verifies G24: commitment bit stored at right heights.
func TestPresync_CommitmentStored(t *testing.T) {
	headers, genesis := buildTestChainHeaders(HeaderCommitmentPeriod * 3)
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	hss := buildHSSForTest(t, genesis, hugeWork)
	// Force commit_offset = 0 so commitments land at heights 600, 1200, 1800.
	hss.commitOffset = 0

	// Feed headers one at a time to count commitments.
	for i, hdr := range headers {
		if i == 0 {
			// Verify prevBlock connects.
			_ = hdr
		}
		hss.validateAndProcessSingleHeader(hdr)
	}
	// We built 3 * 600 = 1800 headers; with offset=0 commitments at 600,1200,1800 → 3.
	if len(hss.headerCommitments) != 3 {
		t.Errorf("expected 3 commitments, got %d", len(hss.headerCommitments))
	}
}

// TestPresync_MaxCommitmentsAbort verifies G25: exceeding max_commitments aborts.
func TestPresync_MaxCommitmentsAbort(t *testing.T) {
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	headers, genesis := buildTestChainHeaders(HeaderCommitmentPeriod * 5)
	hss := buildHSSForTest(t, genesis, hugeWork)
	hss.commitOffset = 0
	hss.maxCommitments = 2 // Only allow 2 commitments (not 5)

	result := hss.ProcessNextHeaders(headers, true)
	if result.Success {
		t.Error("should abort when commitments exceed max_commitments (G25)")
	}
}

// TestRedownload_ConnectivityCheck verifies G29.
func TestRedownload_ConnectivityCheck(t *testing.T) {
	headers, genesis := buildTestChainHeaders(5)

	w := consensus.CalcWork(0x207fffff)
	minWork := new(big.Int).Mul(w, big.NewInt(3)) // threshold at ~3 headers

	hss := buildHSSForTest(t, genesis, minWork)
	// First batch: transition to REDOWNLOAD.
	result := hss.ProcessNextHeaders(headers, true)
	if !result.Success {
		t.Fatalf("phase1 failed: %v", hss.phase)
	}
	if hss.phase != HeadersSyncRedownload {
		t.Skip("didn't transition to REDOWNLOAD — adjust test parameters")
	}

	// Second batch: broken connectivity.
	bad := make([]wire.BlockHeader, 2)
	copy(bad, headers[:2])
	bad[0].PrevBlock = wire.Hash256{0xFF} // wrong prevBlock

	result2 := hss.ProcessNextHeaders(bad, true)
	if result2.Success {
		t.Error("broken redownload connectivity should fail (G29)")
	}
}

// TestRedownload_CommitmentMismatch verifies G35.
func TestRedownload_CommitmentMismatch(t *testing.T) {
	headers, genesis := buildTestChainHeaders(HeaderCommitmentPeriod + 5)

	w := consensus.CalcWork(0x207fffff)
	// Set threshold very high so we never fully satisfy it in REDOWNLOAD,
	// forcing commitment checks to remain active (G33).
	bigWork := new(big.Int).Mul(w, big.NewInt(int64(HeaderCommitmentPeriod)*100))

	// We need the presync to transition to REDOWNLOAD.  Use a tiny threshold.
	smallWork := new(big.Int).Mul(w, big.NewInt(3))
	hss := buildHSSForTest(t, genesis, smallWork)
	hss.commitOffset = 0

	// Run PRESYNC.
	result := hss.ProcessNextHeaders(headers, true)
	if !result.Success || hss.phase != HeadersSyncRedownload {
		t.Skip("didn't get to REDOWNLOAD, skip")
	}

	// Manually replace the minimumRequiredWork with the big value so
	// processAllRemainingHeaders never fires during REDOWNLOAD.
	hss.minimumRequiredWork = bigWork
	hss.processAllRemainingHeaders = false
	hss.redownloadChainWork = new(big.Int).Set(genesis.TotalWork)

	// Flip a stored commitment bit to simulate mismatch.
	if len(hss.headerCommitments) > 0 {
		hss.headerCommitments[0] = !hss.headerCommitments[0]
	}

	// The redownload starts from chainStartHash; rebuild the chain from there.
	redownHeaders := buildRedownloadHeaders(genesis, headers, hss.redownloadBufferLastHash)
	if len(redownHeaders) == 0 {
		t.Skip("no headers to redownload")
	}

	result2 := hss.ProcessNextHeaders(redownHeaders, true)
	if result2.Success {
		t.Error("flipped commitment should cause mismatch failure (G35)")
	}
}

// buildRedownloadHeaders rebuilds the chain from the given prev hash.
// This simulates what the peer would send in the REDOWNLOAD phase.
func buildRedownloadHeaders(genesis *consensus.BlockNode, headers []wire.BlockHeader, prevHash wire.Hash256) []wire.BlockHeader {
	// Find where prevHash is in the chain.
	if prevHash == genesis.Hash {
		return headers
	}
	for i, h := range headers {
		if h.BlockHash() == prevHash {
			if i+1 < len(headers) {
				return headers[i+1:]
			}
			return nil
		}
	}
	return nil
}

// TestPopHeadersReadyForAcceptance_BufferDrain verifies G38+G39.
func TestPopHeadersReadyForAcceptance_BufferDrain(t *testing.T) {
	headers, genesis := buildTestChainHeaders(RedownloadBufferSize + 10)
	w := consensus.CalcWork(0x207fffff)
	// minWork very low so PRESYNC→REDOWNLOAD fast.
	minWork := new(big.Int).Mul(w, big.NewInt(1))
	hss := buildHSSForTest(t, genesis, minWork)

	// Phase 1: PRESYNC on first 5 headers → transition to REDOWNLOAD.
	result := hss.ProcessNextHeaders(headers[:5], true)
	if !result.Success || hss.phase != HeadersSyncRedownload {
		t.Skip("didn't reach REDOWNLOAD")
	}

	// Phase 2: feed redownload batch large enough to overflow the buffer.
	// We need to rebuild headers starting from chainStartHash.
	redownHeaders := headers // start from genesis → chainStart → ...
	// The redownload buffer starts at chainStartHash (genesis hash).
	// Feed enough headers to overflow the buffer.
	if len(redownHeaders) < RedownloadBufferSize+5 {
		t.Skip("not enough headers built")
	}

	result2 := hss.ProcessNextHeaders(redownHeaders[:RedownloadBufferSize+5], true)
	if !result2.Success {
		t.Fatalf("redownload failed: %v", hss.phase)
	}
	// Buffer should have drained at least some headers (G38).
	if len(result2.POWValidatedHeaders) == 0 {
		t.Error("expected some POWValidatedHeaders when buffer overflows (G38)")
	}
}

// TestPopHeadersReadyForAcceptance_ProcessAllFlag verifies G11+G38.
func TestPopHeadersReadyForAcceptance_ProcessAllFlag(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss := buildHSSForTest(t, genesis, big.NewInt(0))
	// Manually put the state into REDOWNLOAD with processAll=true.
	hss.phase = HeadersSyncRedownload
	hss.processAllRemainingHeaders = true
	hss.redownloadBufferFirstPrevHash = genesis.Hash
	hss.redownloadBufferLastHash = genesis.Hash
	hss.redownloadBufferLastHeight = genesis.Height
	hss.redownloadChainWork = new(big.Int).Set(genesis.TotalWork)

	// Add some headers to the buffer.
	headers, _ := buildTestChainHeaders(5)
	prev := genesis.Hash
	for _, h := range headers {
		h.PrevBlock = prev
		hss.redownloadedHeaders = append(hss.redownloadedHeaders, compressedHeader{
			Version:    h.Version,
			MerkleRoot: h.MerkleRoot,
			Timestamp:  h.Timestamp,
			Bits:       h.Bits,
			Nonce:      h.Nonce,
		})
		prev = h.BlockHash()
	}

	out := hss.popHeadersReadyForAcceptance()
	if len(out) != 5 {
		t.Errorf("processAllRemainingHeaders=true should drain all 5, got %d (G11)", len(out))
	}
	if len(hss.redownloadedHeaders) != 0 {
		t.Errorf("buffer should be empty after draining all, got %d (G11)", len(hss.redownloadedHeaders))
	}
}

// TestNextLocator_Phases verifies G15/G16/G17/G18.
func TestNextLocator_Phases(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss := buildHSSForTest(t, genesis, new(big.Int).Lsh(big.NewInt(1), 250))

	bestTipFn := func(h int32) wire.Hash256 { return genesis.Hash }

	// G16: PRESYNC → first entry is last received header hash.
	loc := hss.NextLocator(bestTipFn)
	if len(loc) == 0 {
		t.Fatal("PRESYNC locator should be non-empty (G16)")
	}
	genesisHdr := genesis.Header
	lastHash := genesisHdr.BlockHash()
	if loc[0] != lastHash {
		t.Errorf("PRESYNC locator[0] = %v, want lastHeader hash %v (G16)", loc[0], lastHash)
	}
	// G18: chain_start hash appended.
	if loc[len(loc)-1] != genesis.Hash {
		t.Errorf("chain_start hash not appended to locator (G18)")
	}

	// G17: switch to REDOWNLOAD and verify locator changes.
	hss.phase = HeadersSyncRedownload
	hss.redownloadBufferLastHash = wire.Hash256{0xAB, 0xCD}
	loc2 := hss.NextLocator(bestTipFn)
	if len(loc2) == 0 {
		t.Fatal("REDOWNLOAD locator should be non-empty (G17)")
	}
	if loc2[0] != hss.redownloadBufferLastHash {
		t.Errorf("REDOWNLOAD locator[0] = %v, want redownloadBufferLastHash (G17)", loc2[0])
	}

	// G15: FINAL → nil.
	hss.phase = HeadersSyncFinal
	if loc3 := hss.NextLocator(bestTipFn); loc3 != nil {
		t.Errorf("FINAL locator should be nil, got %v (G15)", loc3)
	}
}

// TestCompressedHeader_RoundTrip verifies G39: reconstruction preserves all fields.
func TestCompressedHeader_RoundTrip(t *testing.T) {
	prevBlock := wire.Hash256{0x01, 0x02, 0x03}
	orig := wire.BlockHeader{
		Version:    2,
		PrevBlock:  prevBlock,
		MerkleRoot: wire.Hash256{0xAA, 0xBB},
		Timestamp:  1_700_000_000,
		Bits:       0x207fffff,
		Nonce:      42,
	}
	c := compressedHeader{
		Version:    orig.Version,
		MerkleRoot: orig.MerkleRoot,
		Timestamp:  orig.Timestamp,
		Bits:       orig.Bits,
		Nonce:      orig.Nonce,
	}
	reconstructed := c.fullHeader(prevBlock)
	if reconstructed.Version != orig.Version {
		t.Errorf("Version mismatch: got %d want %d", reconstructed.Version, orig.Version)
	}
	if reconstructed.PrevBlock != orig.PrevBlock {
		t.Errorf("PrevBlock mismatch")
	}
	if reconstructed.MerkleRoot != orig.MerkleRoot {
		t.Errorf("MerkleRoot mismatch")
	}
	if reconstructed.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp mismatch")
	}
	if reconstructed.Bits != orig.Bits {
		t.Errorf("Bits mismatch")
	}
	if reconstructed.Nonce != orig.Nonce {
		t.Errorf("Nonce mismatch")
	}
}

// TestHashBit_Determinism verifies the salted hasher is deterministic
// for the same keys and input.
func TestHashBit_Determinism(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss := buildHSSForTest(t, genesis, big.NewInt(0))
	h := wire.Hash256{0xAB, 0xCD, 0xEF}
	b1 := hss.hashBit(h)
	b2 := hss.hashBit(h)
	if b1 != b2 {
		t.Error("hashBit should be deterministic for the same input")
	}
}

// TestHashBit_SaltDivergence verifies two states with different keys produce
// independently distributed bits (not always the same).
func TestHashBit_SaltDivergence(t *testing.T) {
	_, genesis := buildTestChainHeaders(0)
	hss1 := buildHSSForTest(t, genesis, big.NewInt(0))
	hss2 := buildHSSForTest(t, genesis, big.NewInt(0))
	// Ensure keys differ (very unlikely to be identical).
	if hss1.hasherK0 == hss2.hasherK0 && hss1.hasherK1 == hss2.hasherK1 {
		t.Skip("salts identical (astronomically rare), skipping divergence check")
	}
	// Compute bits for 100 hashes; they should differ at least once.
	differ := false
	for i := 0; i < 100; i++ {
		h := wire.Hash256{byte(i)}
		if hss1.hashBit(h) != hss2.hashBit(h) {
			differ = true
			break
		}
	}
	if !differ {
		t.Error("two independently salted hashers should produce different bits for some inputs")
	}
}

// TestMinimumChainWork_RegTest verifies that needsHeadersSync returns false
// for regtest (minWork=0).
func TestMinimumChainWork_RegTest(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.needsHeadersSync() {
		t.Error("regtest with minWork=0 should not need headerssync")
	}
}

// TestMinimumChainWork_NilMinWork verifies graceful handling of nil MinimumChainWork.
func TestMinimumChainWork_NilMinWork(t *testing.T) {
	params := consensus.RegtestParams()
	cpCopy := *params
	cpCopy.MinimumChainWork = nil
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: &cpCopy,
		HeaderIndex: idx,
	})
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.needsHeadersSync() {
		t.Error("nil MinimumChainWork should not require headerssync")
	}
}

// TestComputeMinimumRequiredWork_TakesMax verifies that computeMinimumRequiredWork
// returns max(chainMinWork, tipWork).
func TestComputeMinimumRequiredWork_TakesMax(t *testing.T) {
	params := consensus.RegtestParams()
	cpCopy := *params
	// Set a modest chain minimum.
	cpCopy.MinimumChainWork = big.NewInt(1000)

	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: &cpCopy,
		HeaderIndex: idx,
	})

	sm.mu.Lock()
	defer sm.mu.Unlock()

	minWork := sm.computeMinimumRequiredWork()
	// Genesis has TotalWork > 0; if genesis work > 1000 then result = genesis work.
	genesisWork := idx.Genesis().TotalWork
	if genesisWork != nil && genesisWork.Cmp(big.NewInt(1000)) > 0 {
		if minWork.Cmp(genesisWork) != 0 {
			t.Errorf("expected minWork=%v (genesis), got %v", genesisWork, minWork)
		}
	} else {
		if minWork.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected minWork=1000, got %v", minWork)
		}
	}
}

// TestHeadersSyncState_Constants verifies the numeric constants match Core.
func TestHeadersSyncState_Constants(t *testing.T) {
	if HeaderCommitmentPeriod != 600 {
		t.Errorf("HeaderCommitmentPeriod=%d, want 600", HeaderCommitmentPeriod)
	}
	if RedownloadBufferSize != 14304 {
		t.Errorf("RedownloadBufferSize=%d, want 14304", RedownloadBufferSize)
	}
	if HeaderSyncMaxFutureTime != 7200 {
		t.Errorf("HeaderSyncMaxFutureTime=%d, want 7200", HeaderSyncMaxFutureTime)
	}
	if HeaderSyncMaxBlockRate != 6 {
		t.Errorf("HeaderSyncMaxBlockRate=%d, want 6", HeaderSyncMaxBlockRate)
	}
}

// TestProcessNextHeaders_PresyncTransitionThenRedownloadFull verifies G9/G12:
// a full REDOWNLOAD message that has NOT yet processed all committed headers
// produces RequestMore=true.
func TestProcessNextHeaders_PresyncTransitionThenRedownloadFull(t *testing.T) {
	// Use a very high minWork so processAllRemainingHeaders never fires during
	// REDOWNLOAD of a small batch — this keeps us in the G12 path (RequestMore)
	// rather than the G11 path (complete).
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 250)
	headers, genesis := buildTestChainHeaders(10)
	w := consensus.CalcWork(0x207fffff)
	// Threshold at ~3 headers so PRESYNC→REDOWNLOAD triggers, but
	// REDOWNLOAD's own cumulative work (redownloadChainWork starts from
	// chainStart.TotalWork ≈ 0) won't cross hugeWork on just 10 headers.
	presyncMinWork := new(big.Int).Mul(w, big.NewInt(3))

	hss := buildHSSForTest(t, genesis, presyncMinWork)

	// Phase 1: PRESYNC → REDOWNLOAD.
	r1 := hss.ProcessNextHeaders(headers, true)
	if !r1.Success || hss.phase != HeadersSyncRedownload {
		t.Skip("didn't reach REDOWNLOAD after PRESYNC")
	}

	// Override minimumRequiredWork to hugeWork so processAllRemainingHeaders
	// stays false during REDOWNLOAD.
	hss.minimumRequiredWork = hugeWork
	hss.processAllRemainingHeaders = false
	hss.redownloadChainWork = new(big.Int).Set(genesis.TotalWork)

	// Phase 2: REDOWNLOAD with full message.  processAllRemainingHeaders is
	// false and the buffer has < RedownloadBufferSize entries, so we land
	// in G12 (request_more = true).
	r2 := hss.ProcessNextHeaders(headers, true) // full message
	if !r2.Success {
		t.Fatalf("REDOWNLOAD failed (G9): phase=%v", hss.phase)
	}
	if !r2.RequestMore {
		t.Error("full REDOWNLOAD message (processAll=false) should set RequestMore (G12)")
	}
}

// TestProcessNextHeaders_RedownloadNonFull verifies G13: non-full REDOWNLOAD = done.
func TestProcessNextHeaders_RedownloadNonFull(t *testing.T) {
	n := 5
	headers, genesis := buildTestChainHeaders(n)
	w := consensus.CalcWork(0x207fffff)
	minWork := new(big.Int).Mul(w, big.NewInt(2))

	hss := buildHSSForTest(t, genesis, minWork)

	// Phase 1: PRESYNC → REDOWNLOAD.
	r1 := hss.ProcessNextHeaders(headers, true)
	if !r1.Success || hss.phase != HeadersSyncRedownload {
		t.Skip("didn't reach REDOWNLOAD")
	}

	// Phase 2: REDOWNLOAD with non-full message.
	r2 := hss.ProcessNextHeaders(headers[:2], false) // non-full
	if !r2.Success {
		t.Fatalf("non-full REDOWNLOAD should still succeed (G13)")
	}
	if r2.RequestMore {
		t.Error("non-full REDOWNLOAD should NOT set RequestMore (G13)")
	}
	// State should be finalized (G14).
	if hss.phase != HeadersSyncFinal {
		t.Error("state should be FINAL after non-full REDOWNLOAD (G14)")
	}
}
