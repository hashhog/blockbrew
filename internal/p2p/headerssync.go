package p2p

// headerssync.go — Bitcoin Core headerssync.cpp PRESYNC/REDOWNLOAD pipeline port.
//
// Reference: bitcoin-core/src/headerssync.cpp + headerssync.h
// Core constants (headerssync-params.py output, reproduced in headerssync.cpp comments):
//
//	HEADER_COMMITMENT_PERIOD = 600   // store 1 bit per 600 headers
//	REDOWNLOAD_BUFFER_SIZE   = 14304 // keep this many headers in buffer during REDOWNLOAD
//	MAX_FUTURE_BLOCK_TIME    = 7200  // 2h, matches consensus.MaxTimeAdjustment
//
// The two-phase algorithm:
//   - PRESYNC : validate PoW + PermittedDifficultyTransition on each header; store one
//     salted-hash commitment bit every HEADER_COMMITMENT_PERIOD headers; abort if chain
//     is too long (MTP-bounded); switch to REDOWNLOAD once cumulative work ≥ threshold.
//   - REDOWNLOAD: re-download the same chain from the peer; verify each header against its
//     stored commitment; buffer REDOWNLOAD_BUFFER_SIZE headers; release headers to the
//     caller once the buffer overflows or m_process_all_remaining_headers is set.
//
// Porting notes:
//   - Core uses bitdeque<> for m_header_commitments (1 bit/entry).  We use []bool for
//     clarity; the extra memory is negligible (sub-MB even for a 1M-block chain at 1/600).
//   - Core's SaltedUint256Hasher uses SipHash-2-4 with a random 128-bit key, giving a
//     single uint64 output. We use the same siphash24Keys function already in this package
//     (unexported, in minisketch.go).  The result is taken mod 2 for the 1-bit commitment.
//   - Core's m_max_commitments uses NodeClock::now(). We use time.Now() and supply a
//     clock hook (headersNowUnix) so tests can inject deterministic time.

import (
	"fmt"
	"log"
	"math/big"
	"math/rand/v2"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// headerssync constants, matching Bitcoin Core src/headerssync.cpp.
const (
	// HeaderCommitmentPeriod is the interval between stored commitment bits.
	// Core: HEADER_COMMITMENT_PERIOD = 600 (headerssync.cpp comment).
	HeaderCommitmentPeriod = 600

	// RedownloadBufferSize is the number of headers buffered during REDOWNLOAD
	// before we start releasing them to the caller for full validation.
	// Core: REDOWNLOAD_BUFFER_SIZE = 14304 (headerssync.cpp comment).
	RedownloadBufferSize = 14304

	// HeaderSyncMaxFutureTime is the forward-time slack for the MTP-bounded
	// max-commitments calculation.  Mirrors MAX_FUTURE_BLOCK_TIME = 7200s in
	// Bitcoin Core (headerssync.cpp:44) and consensus.MaxTimeAdjustment.
	HeaderSyncMaxFutureTime = 7200 // seconds

	// HeaderSyncMaxBlockRate is the maximum block rate (blocks/s) used to bound
	// how many commitments an honest peer could have.  Core uses 6 (headerssync.cpp:35).
	HeaderSyncMaxBlockRate = 6
)

// headersSyncNowUnix is the clock hook for max_commitments calculation.
// Tests may override this to inject a deterministic time.
var headersSyncNowUnix = func() int64 { return time.Now().Unix() }

// HeadersSyncPhase represents the phase of the two-download-headers pipeline.
type HeadersSyncPhase int

const (
	// HeadersSyncPresync is the first phase: validate PoW, store commitment bits.
	HeadersSyncPresync HeadersSyncPhase = iota
	// HeadersSyncRedownload is the second phase: verify commitments, buffer headers.
	HeadersSyncRedownload
	// HeadersSyncFinal means this state has been finalized and should not be reused.
	HeadersSyncFinal
)

// compressedHeader stores a block header without hashPrevBlock to save memory.
// Bitcoin Core: struct CompressedHeader (headerssync.h:21-53).
type compressedHeader struct {
	Version    int32
	MerkleRoot wire.Hash256
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
}

// fullHeader reconstructs the wire.BlockHeader given the previous block hash.
func (c compressedHeader) fullHeader(prevBlock wire.Hash256) wire.BlockHeader {
	return wire.BlockHeader{
		Version:    c.Version,
		PrevBlock:  prevBlock,
		MerkleRoot: c.MerkleRoot,
		Timestamp:  c.Timestamp,
		Bits:       c.Bits,
		Nonce:      c.Nonce,
	}
}

// HeadersSyncState implements the Bitcoin Core headerssync PRESYNC/REDOWNLOAD
// DoS-resistant header download pipeline per Bitcoin Core src/headerssync.cpp.
//
// One instance is created per peer at the start of headers synchronisation with
// that peer.  It is owned by SyncManager and protected by sm.mu.
type HeadersSyncState struct {
	// id is the peer address string, used only for log messages.
	id string

	// chainParams holds consensus params needed for PermittedDifficultyTransition.
	chainParams *consensus.ChainParams

	// chainStartHeight / chainStartHash are the block we forked from.
	// Correspond to m_chain_start in Core.
	chainStartHeight int32
	chainStartHash   wire.Hash256
	chainStartBits   uint32
	chainStartWork   *big.Int // nChainWork of chain_start

	// minimumRequiredWork is the cumulative work threshold; only chains that
	// reach this are accepted.  Corresponds to m_minimum_required_work in Core.
	minimumRequiredWork *big.Int

	// currentChainWork is the work accumulated so far in PRESYNC.
	// Corresponds to m_current_chain_work in Core.
	currentChainWork *big.Int

	// commitOffset is the random offset within [0, HeaderCommitmentPeriod)
	// that determines which heights get a commitment bit.
	// Corresponds to m_commit_offset in Core (headerssync.h:185).
	commitOffset int

	// hasherK0, hasherK1 are the SipHash-2-4 key halves for the salted hasher.
	// Correspond to m_hasher (SaltedUint256Hasher) in Core.
	hasherK0, hasherK1 uint64

	// headerCommitments stores the 1-bit commitments collected during PRESYNC
	// and verified during REDOWNLOAD.
	// Core: bitdeque<> m_header_commitments (headerssync.h:235).
	headerCommitments []bool

	// maxCommitments is the MTP-bounded upper limit on commitment count.
	// Core: uint64_t m_max_commitments (headerssync.h:242).
	maxCommitments int

	// lastHeaderReceived is the last header seen in PRESYNC (starts as genesis/chain_start).
	// Core: CBlockHeader m_last_header_received (headerssync.h:245).
	lastHeaderReceived wire.BlockHeader

	// currentHeight is the height of lastHeaderReceived.
	// Core: int64_t m_current_height (headerssync.h:248).
	currentHeight int32

	// redownloadedHeaders is the lookahead buffer during REDOWNLOAD.
	// Core: std::deque<CompressedHeader> m_redownloaded_headers (headerssync.h:253).
	redownloadedHeaders []compressedHeader

	// redownloadBufferLastHeight is the height of the last entry in the buffer.
	// Core: int64_t m_redownload_buffer_last_height (headerssync.h:256).
	redownloadBufferLastHeight int32

	// redownloadBufferLastHash is the hash of the last entry in the buffer
	// (since compressedHeader doesn't store prevHash, we track it here).
	// Core: uint256 m_redownload_buffer_last_hash (headerssync.h:261).
	redownloadBufferLastHash wire.Hash256

	// redownloadBufferFirstPrevHash is the hashPrevBlock for the first entry in
	// redownloadedHeaders; needed to reconstruct the full header.
	// Core: uint256 m_redownload_buffer_first_prev_hash (headerssync.h:268).
	redownloadBufferFirstPrevHash wire.Hash256

	// redownloadChainWork is the cumulative work of the redownloaded chain.
	// Core: arith_uint256 m_redownload_chain_work (headerssync.h:271).
	redownloadChainWork *big.Int

	// processAllRemainingHeaders is set once cumulative redownload work
	// reaches minimumRequiredWork; after this point all buffered headers are
	// released and commitment checks are skipped.
	// Core: bool m_process_all_remaining_headers (headerssync.h:277).
	processAllRemainingHeaders bool

	// phase tracks whether we're in PRESYNC, REDOWNLOAD, or FINAL.
	phase HeadersSyncPhase
}

// HeadersSyncResult is the return value from ProcessNextHeaders.
// Mirrors Bitcoin Core's HeadersSyncState::ProcessingResult.
type HeadersSyncResult struct {
	// POWValidatedHeaders contains headers that can now be fully validated
	// and stored (returned during REDOWNLOAD when the buffer drains).
	POWValidatedHeaders []wire.BlockHeader
	// Success is false when a protocol error was detected (chain discontinuity,
	// commitment mismatch, difficulty anomaly).
	Success bool
	// RequestMore is true when the caller should send another GETHEADERS.
	RequestMore bool
}

// NewHeadersSyncState creates a HeadersSyncState for a peer.
//
// Parameters (mirrors Bitcoin Core HeadersSyncState constructor, headerssync.cpp:17):
//   - peerID: peer address string (for logging)
//   - chainParams: network consensus parameters
//   - chainStart: the BlockNode the peer's chain forks from (our best known shared tip)
//   - minimumRequiredWork: work threshold the peer's chain must meet
//
// Gates implemented (matching Core):
//   G1  commitment_period > 0 assertion
//   G2  max_commitments = 6 * (now - chain_start.MTP + MAX_FUTURE_BLOCK_TIME) / PERIOD
//   G3  random commit_offset = rand(commitment_period)
func NewHeadersSyncState(
	peerID string,
	chainParams *consensus.ChainParams,
	chainStart *consensus.BlockNode,
	minimumRequiredWork *big.Int,
) *HeadersSyncState {
	// G1: commitment_period must be non-zero.
	if HeaderCommitmentPeriod == 0 {
		panic("headerssync: HeaderCommitmentPeriod must be non-zero")
	}

	// G2: max_commitments — MTP-bounded upper limit on chain length.
	// Core: max_seconds_since_start = (now - chain_start.MTP) + MAX_FUTURE_BLOCK_TIME
	//       m_max_commitments = 6 * max_seconds / commitment_period
	// (headerssync.cpp:41-43)
	chainStartMTP := chainStart.GetMedianTimePast()
	now := headersSyncNowUnix()
	maxSecondsSinceStart := (now - chainStartMTP) + HeaderSyncMaxFutureTime
	if maxSecondsSinceStart < 0 {
		maxSecondsSinceStart = 0
	}
	maxCommitments := int(HeaderSyncMaxBlockRate * maxSecondsSinceStart / HeaderCommitmentPeriod)

	// G3: random commit_offset ∈ [0, HeaderCommitmentPeriod).
	commitOffset := rand.IntN(HeaderCommitmentPeriod)

	// Salted hasher: two random uint64 keys for SipHash-2-4.
	k0 := rand.Uint64()
	k1 := rand.Uint64()

	chainStartHdr := chainStart.Header
	chainStartHash := chainStart.Hash

	s := &HeadersSyncState{
		id:                  peerID,
		chainParams:         chainParams,
		chainStartHeight:    chainStart.Height,
		chainStartHash:      chainStartHash,
		chainStartBits:      chainStartHdr.Bits,
		chainStartWork:      new(big.Int).Set(chainStart.TotalWork),
		minimumRequiredWork: new(big.Int).Set(minimumRequiredWork),
		currentChainWork:    new(big.Int).Set(chainStart.TotalWork),
		commitOffset:        commitOffset,
		hasherK0:            k0,
		hasherK1:            k1,
		maxCommitments:      maxCommitments,
		lastHeaderReceived:  chainStartHdr,
		currentHeight:       chainStart.Height,
		redownloadChainWork: new(big.Int).Set(chainStart.TotalWork),
		phase:               HeadersSyncPresync,
	}

	log.Printf("headerssync: started with peer=%s height=%d max_commitments=%d min_work=%s",
		peerID, s.currentHeight, maxCommitments, minimumRequiredWork.Text(16))
	return s
}

// Phase returns the current phase.
func (s *HeadersSyncState) Phase() HeadersSyncPhase { return s.phase }

// PresyncHeight returns the height reached during PRESYNC.
func (s *HeadersSyncState) PresyncHeight() int32 { return s.currentHeight }

// finalize frees memory and marks this state as no longer usable.
// Core: HeadersSyncState::Finalize() (headerssync.cpp:51-63).
func (s *HeadersSyncState) finalize() {
	s.headerCommitments = nil
	s.redownloadedHeaders = nil
	s.phase = HeadersSyncFinal
}

// ProcessNextHeaders processes a batch of headers from a peer.
//
// received: headers received from the peer (caller has verified continuity
//   and basic PoW against the nBits in each header, but has NOT verified that
//   nBits is correct per consensus rules — that check happens here).
// fullMessage: true if the batch was MaxHeadersPerRequest (2000) headers,
//   implying the peer may have more.
//
// Returns a HeadersSyncResult:
//   - Success=false: disconnect/ban the peer.
//   - RequestMore=true: send another GETHEADERS.
//   - POWValidatedHeaders: headers ready for full validation.
//
// Core: HeadersSyncState::ProcessNextHeaders (headerssync.cpp:68-137).
//
// Gates:
//   G4  early-return on empty batch
//   G5  early-return if already FINAL
//   G6  PRESYNC path: call ValidateAndStoreHeadersCommitments
//   G7  PRESYNC success + (full_msg OR transitioned-to-REDOWNLOAD) → request_more=true
//   G8  PRESYNC success + non-full + still PRESYNC → chain too short, abort
//   G9  REDOWNLOAD path: call ValidateAndStoreRedownloadedHeader per header
//   G10 REDOWNLOAD success: drain buffer via PopHeadersReadyForAcceptance
//   G11 REDOWNLOAD success + m_process_all_remaining_headers + buffer empty → done
//   G12 REDOWNLOAD success + full_msg → request_more=true
//   G13 REDOWNLOAD success + non-full → peer won't serve full chain again, abort
//   G14 finalize on !(success && request_more)
func (s *HeadersSyncState) ProcessNextHeaders(received []wire.BlockHeader, fullMessage bool) HeadersSyncResult {
	var ret HeadersSyncResult

	// G4: empty batch — caller contract violation, but be safe.
	if len(received) == 0 {
		ret.Success = true // not a peer error, just a no-op
		return ret
	}

	// G5: already finalized.
	if s.phase == HeadersSyncFinal {
		return ret
	}

	if s.phase == HeadersSyncPresync {
		// G6: PRESYNC path.
		ret.Success = s.validateAndStoreHeadersCommitments(received)
		if ret.Success {
			// G7: request more if full message OR we just transitioned to REDOWNLOAD.
			if fullMessage || s.phase == HeadersSyncRedownload {
				ret.RequestMore = true
			} else {
				// G8: non-full + still PRESYNC → peer's chain ended below threshold.
				log.Printf("headerssync: aborted with peer=%s: incomplete message at height=%d (presync)",
					s.id, s.currentHeight)
			}
		}
	} else if s.phase == HeadersSyncRedownload {
		// G9: REDOWNLOAD path.
		ret.Success = true
		for i := range received {
			if !s.validateAndStoreRedownloadedHeader(received[i]) {
				ret.Success = false
				break
			}
		}

		if ret.Success {
			// G10: drain buffer.
			ret.POWValidatedHeaders = s.popHeadersReadyForAcceptance()

			if len(s.redownloadedHeaders) == 0 && s.processAllRemainingHeaders {
				// G11: all committed headers released; REDOWNLOAD complete.
				log.Printf("headerssync: complete with peer=%s: released all at height=%d (redownload)",
					s.id, s.redownloadBufferLastHeight)
			} else if fullMessage {
				// G12: more headers available.
				ret.RequestMore = true
			} else {
				// G13: peer stopped serving early — accept what we have but no more.
				log.Printf("headerssync: aborted with peer=%s: incomplete message at height=%d (redownload)",
					s.id, s.redownloadBufferLastHeight)
			}
		}
	}

	// G14: finalize unless we succeeded and need more.
	if !(ret.Success && ret.RequestMore) {
		s.finalize()
	}
	return ret
}

// NextLocator returns the GETHEADERS locator to send at the current phase.
// Core: HeadersSyncState::NextHeadersRequestLocator (headerssync.cpp:296-317).
//
// Gates:
//   G15 return empty locator if FINAL
//   G16 PRESYNC: start from last received header
//   G17 REDOWNLOAD: start from redownload_buffer_last_hash
//   G18 always append chain_start locator entries
func (s *HeadersSyncState) NextLocator(bestTip func(height int32) wire.Hash256) []wire.Hash256 {
	// G15
	if s.phase == HeadersSyncFinal {
		return nil
	}

	var locator []wire.Hash256

	if s.phase == HeadersSyncPresync {
		// G16: during PRESYNC resume from the last header we received.
		lastHash := s.lastHeaderReceived.BlockHash()
		locator = append(locator, lastHash)
	} else {
		// G17: during REDOWNLOAD resume from last buffered hash.
		locator = append(locator, s.redownloadBufferLastHash)
	}

	// G18: append chain_start locator (exponential step-back from chain_start).
	// We keep it simple: include chain_start hash. The peer will use the first
	// matching entry. This mirrors Core's LocatorEntries(&m_chain_start) call.
	locator = append(locator, s.chainStartHash)

	return locator
}

// validateAndStoreHeadersCommitments validates the batch in PRESYNC mode,
// storing commitment bits and transitioning to REDOWNLOAD when work is sufficient.
// Core: HeadersSyncState::ValidateAndStoreHeadersCommitments (headerssync.cpp:139-175).
//
// Gates:
//   G19 batch[0].hashPrevBlock must connect to last received header
//   G20 iterate: ValidateAndProcessSingleHeader per header
//   G21 after loop: if cumulative work >= threshold → transition to REDOWNLOAD
func (s *HeadersSyncState) validateAndStoreHeadersCommitments(headers []wire.BlockHeader) bool {
	if s.phase != HeadersSyncPresync {
		return false
	}

	// G19: connectivity check — first header must build on the last one we saw.
	lastHash := s.lastHeaderReceived.BlockHash()
	if headers[0].PrevBlock != lastHash {
		log.Printf("headerssync: aborted with peer=%s: non-continuous at height=%d (presync)",
			s.id, s.currentHeight)
		return false
	}

	// G20: process each header.
	for i := range headers {
		if !s.validateAndProcessSingleHeader(headers[i]) {
			return false
		}
	}

	// G21: check if we've accumulated enough work to switch to REDOWNLOAD.
	if s.currentChainWork.Cmp(s.minimumRequiredWork) >= 0 {
		s.redownloadedHeaders = nil
		s.redownloadBufferLastHeight = s.chainStartHeight
		s.redownloadBufferFirstPrevHash = s.chainStartHash
		s.redownloadBufferLastHash = s.chainStartHash
		s.redownloadChainWork = new(big.Int).Set(s.chainStartWork)
		s.phase = HeadersSyncRedownload
		log.Printf("headerssync: transition with peer=%s: sufficient work at height=%d, redownloading from height=%d",
			s.id, s.currentHeight, s.redownloadBufferLastHeight)
	}
	return true
}

// validateAndProcessSingleHeader validates one header in PRESYNC mode,
// stores a commitment bit if applicable, and updates state.
// Core: HeadersSyncState::ValidateAndProcessSingleHeader (headerssync.cpp:177-213).
//
// Gates:
//   G22 must be in PRESYNC
//   G23 PermittedDifficultyTransition: abort if difficulty jumped illegally
//   G24 commitment gate: (height % PERIOD) == commit_offset → store 1 bit
//   G25 max_commitments overflow guard: abort if too many commitments
//   G26 accumulate GetBlockProof(header) into currentChainWork
//   G27 update lastHeaderReceived and currentHeight
func (s *HeadersSyncState) validateAndProcessSingleHeader(hdr wire.BlockHeader) bool {
	// G22
	if s.phase != HeadersSyncPresync {
		return false
	}

	nextHeight := s.currentHeight + 1

	// G23: PermittedDifficultyTransition guard.
	// Core: pow.cpp:89-136, mirrors PermittedDifficultyTransition call at
	// headerssync.cpp:189-191.
	if !consensus.PermittedDifficultyTransition(s.chainParams, nextHeight,
		s.lastHeaderReceived.Bits, hdr.Bits) {
		log.Printf("headerssync: aborted with peer=%s: invalid difficulty at height=%d (presync)",
			s.id, nextHeight)
		return false
	}

	// G24: store commitment bit at designated heights.
	if int(nextHeight)%HeaderCommitmentPeriod == s.commitOffset {
		hash := hdr.BlockHash()
		bit := s.hashBit(hash)
		s.headerCommitments = append(s.headerCommitments, bit)

		// G25: abort if this peer's chain is impossibly long.
		if len(s.headerCommitments) > s.maxCommitments {
			log.Printf("headerssync: aborted with peer=%s: exceeded max_commitments=%d at height=%d (presync)",
				s.id, s.maxCommitments, nextHeight)
			return false
		}
	}

	// G26: accumulate chain work.
	blockWork := consensus.CalcWork(hdr.Bits)
	s.currentChainWork.Add(s.currentChainWork, blockWork)

	// G27: advance state.
	s.lastHeaderReceived = hdr
	s.currentHeight = nextHeight
	return true
}

// validateAndStoreRedownloadedHeader processes one header in REDOWNLOAD mode,
// verifying its commitment (if applicable) and adding it to the lookahead buffer.
// Core: HeadersSyncState::ValidateAndStoreRedownloadedHeader (headerssync.cpp:215-278).
//
// Gates:
//   G28 must be in REDOWNLOAD
//   G29 hashPrevBlock must connect to redownload_buffer_last_hash
//   G30 PermittedDifficultyTransition check against previous buffered/start nBits
//   G31 accumulate GetBlockProof into redownloadChainWork
//   G32 if redownloadChainWork >= minimumRequiredWork → set processAllRemainingHeaders
//   G33 commitment check: at designated heights, compare stored bit vs hash bit
//   G34 commitment overrun: abort if we've used all stored commitments before reaching target
//   G35 commitment mismatch: abort if bit doesn't match
//   G36 store compressedHeader in buffer, advance state
func (s *HeadersSyncState) validateAndStoreRedownloadedHeader(hdr wire.BlockHeader) bool {
	// G28
	if s.phase != HeadersSyncRedownload {
		return false
	}

	nextHeight := s.redownloadBufferLastHeight + 1

	// G29: connectivity check.
	if hdr.PrevBlock != s.redownloadBufferLastHash {
		log.Printf("headerssync: aborted with peer=%s: non-continuous at height=%d (redownload)",
			s.id, nextHeight)
		return false
	}

	// G30: difficulty transition check.
	var previousBits uint32
	if len(s.redownloadedHeaders) > 0 {
		previousBits = s.redownloadedHeaders[len(s.redownloadedHeaders)-1].Bits
	} else {
		previousBits = s.chainStartBits
	}
	if !consensus.PermittedDifficultyTransition(s.chainParams, nextHeight,
		previousBits, hdr.Bits) {
		log.Printf("headerssync: aborted with peer=%s: invalid difficulty at height=%d (redownload)",
			s.id, nextHeight)
		return false
	}

	// G31: accumulate chain work.
	blockWork := consensus.CalcWork(hdr.Bits)
	s.redownloadChainWork.Add(s.redownloadChainWork, blockWork)

	// G32: check if we've now seen enough work to release all remaining headers.
	if s.redownloadChainWork.Cmp(s.minimumRequiredWork) >= 0 {
		s.processAllRemainingHeaders = true
	}

	// G33–G35: commitment verification (skipped once processAllRemainingHeaders
	// is set — the peer may have extended the chain between PRESYNC and REDOWNLOAD).
	if !s.processAllRemainingHeaders && int(nextHeight)%HeaderCommitmentPeriod == s.commitOffset {
		// G34: overrun guard.
		if len(s.headerCommitments) == 0 {
			log.Printf("headerssync: aborted with peer=%s: commitment overrun at height=%d (redownload)",
				s.id, nextHeight)
			return false
		}
		hash := hdr.BlockHash()
		got := s.hashBit(hash)
		want := s.headerCommitments[0]
		s.headerCommitments = s.headerCommitments[1:]
		// G35: mismatch → peer fed us a different chain.
		if got != want {
			log.Printf("headerssync: aborted with peer=%s: commitment mismatch at height=%d (redownload)",
				s.id, nextHeight)
			return false
		}
	}

	// G36: store header, advance state.
	s.redownloadedHeaders = append(s.redownloadedHeaders, compressedHeader{
		Version:    hdr.Version,
		MerkleRoot: hdr.MerkleRoot,
		Timestamp:  hdr.Timestamp,
		Bits:       hdr.Bits,
		Nonce:      hdr.Nonce,
	})
	s.redownloadBufferLastHeight = nextHeight
	s.redownloadBufferLastHash = hdr.BlockHash()
	return true
}

// popHeadersReadyForAcceptance drains the lookahead buffer, returning all
// headers that are "sufficiently committed": the buffer has grown past
// RedownloadBufferSize OR processAllRemainingHeaders is set.
// Core: HeadersSyncState::PopHeadersReadyForAcceptance (headerssync.cpp:280-294).
//
// Gates:
//   G37 must be in REDOWNLOAD
//   G38 drain while (buffer > REDOWNLOAD_BUFFER_SIZE) OR (processAll && buffer non-empty)
//   G39 reconstruct full header from compressedHeader + running prevHash
func (s *HeadersSyncState) popHeadersReadyForAcceptance() []wire.BlockHeader {
	// G37
	if s.phase != HeadersSyncRedownload {
		return nil
	}

	var out []wire.BlockHeader
	prevHash := s.redownloadBufferFirstPrevHash

	// G38
	for len(s.redownloadedHeaders) > RedownloadBufferSize ||
		(len(s.redownloadedHeaders) > 0 && s.processAllRemainingHeaders) {
		// G39: reconstruct full header.
		full := s.redownloadedHeaders[0].fullHeader(prevHash)
		s.redownloadedHeaders = s.redownloadedHeaders[1:]
		prevHash = full.BlockHash()
		out = append(out, full)
	}
	// Update first-prev-hash so subsequent calls continue from the right point.
	s.redownloadBufferFirstPrevHash = prevHash
	return out
}

// hashBit returns the 1-bit salted hash of a block hash used for commitments.
// Core: m_hasher(hash) & 1 (SaltedUint256Hasher in util/hasher.h applied to uint256).
// We use SipHash-2-4 on the raw 32-byte hash, then take bit 0 of the result.
func (s *HeadersSyncState) hashBit(h wire.Hash256) bool {
	v := hsSipHash24(s.hasherK0, s.hasherK1, h[:])
	return (v & 1) != 0
}

// hsSipHash24 is SipHash-2-4 with explicit keys, inlined here to avoid a
// cross-package dependency on crypto.siphash24Keys (unexported).
// Reference: Jean-Philippe Aumasson and Daniel J. Bernstein, "SipHash: a fast
// short-input PRF", INDOCRYPT 2012.
func hsSipHash24(k0, k1 uint64, msg []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	blocks := len(msg) / 8
	for i := 0; i < blocks; i++ {
		m := uint64(msg[i*8]) |
			uint64(msg[i*8+1])<<8 |
			uint64(msg[i*8+2])<<16 |
			uint64(msg[i*8+3])<<24 |
			uint64(msg[i*8+4])<<32 |
			uint64(msg[i*8+5])<<40 |
			uint64(msg[i*8+6])<<48 |
			uint64(msg[i*8+7])<<56
		v3 ^= m
		v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
		v0 ^= m
	}

	var last uint64
	remaining := msg[blocks*8:]
	for i := len(remaining) - 1; i >= 0; i-- {
		last <<= 8
		last |= uint64(remaining[i])
	}
	last |= uint64(len(msg)%256) << 56

	v3 ^= last
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
	v0 ^= last

	v2 ^= 0xff
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = hsSipRound(v0, v1, v2, v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func hsSipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)
	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)
	return v0, v1, v2, v3
}

// DescribePhase returns a human-readable phase name for logging.
func (s *HeadersSyncState) DescribePhase() string {
	switch s.phase {
	case HeadersSyncPresync:
		return "PRESYNC"
	case HeadersSyncRedownload:
		return "REDOWNLOAD"
	case HeadersSyncFinal:
		return "FINAL"
	default:
		return fmt.Sprintf("unknown(%d)", s.phase)
	}
}
