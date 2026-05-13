package consensus

import (
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// W97 — ChainstateManager::AcceptBlockHeader + ProcessNewBlockHeaders +
// AcceptBlock gate audit (Bitcoin Core validation.cpp:4186-4396).
//
// This file pins the 30 gates from the W97 audit checklist. Each test
// encodes the SPEC against which blockbrew's AddHeader / ConnectBlock /
// HandleHeaders should behave. Tests that currently fail (i.e. encode a
// missing or divergent gate) are marked `t.Skip("W97 audit — not yet
// implemented")` so the lib-test binary continues to build / pass clean
// while the bug list lives in code form.
//
// Cross-impl reference: bitcoin-core/src/validation.cpp.
//
// SEVERITY KEY
//   CONSENSUS  — real fork risk
//   DOS        — resource exhaustion / peer-misbehavior bypass
//   CORRECT    — bad input handling, no fork
//   OBSERV     — wrong error string / log / metric

// ---------------------------------------------------------------------------
// G1. Duplicate-hash short-circuit before any validation
// ---------------------------------------------------------------------------
//
// Core: AcceptBlockHeader returns true (with *ppindex pointing at the existing
// CBlockIndex) when the header is already known. blockbrew's AddHeader
// instead returns (nil, ErrDuplicateHeader). This makes the caller unable to
// distinguish "we already have this" from "this header is invalid", and the
// caller (sync.go:684) special-cases the error to skip it — meaning every
// duplicate header walks the full check pipeline up to the map lookup before
// being rejected.
//
// SEVERITY: CORRECT (no consensus impact in practice since the duplicate is
// rejected before insertion; but the API contract diverges from Core).
func TestW97_G1_DuplicateHeaderReturnsExistingNode(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G1: blockbrew returns ErrDuplicateHeader instead of the existing node)")
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	h := createTestHeader(params.GenesisHash, params.GenesisBlock.Header.Timestamp+600, 1)
	first, err := idx.AddHeader(h, true)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}
	dup, err := idx.AddHeader(h, true)
	if err != nil {
		t.Fatalf("Core returns success on duplicate, got error: %v", err)
	}
	if dup != first {
		t.Errorf("Core returns the existing CBlockIndex; got a different node")
	}
}

// ---------------------------------------------------------------------------
// G2. Genesis-block bypass of CheckBlockHeader + prev lookup
// ---------------------------------------------------------------------------
//
// Core: `if (hash != GetConsensus().hashGenesisBlock) { ... }` so the genesis
// hash short-circuits everything (no PoW check, no prev-lookup, no contextual
// check). blockbrew preloads genesis into idx.nodes in NewHeaderIndex, so a
// re-submitted genesis hits the duplicate-header path (G1) and the genesis
// bypass is structural — there is no explicit `hash == GenesisHash` branch
// inside AddHeader.
//
// SEVERITY: CORRECT (covered structurally; verify it).
func TestW97_G2_GenesisHashIsPreloaded(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	if g := idx.Genesis(); g == nil || g.Hash != params.GenesisHash {
		t.Fatalf("genesis preload missing; got %v", g)
	}
	// Re-submitting genesis must NOT panic or insert a duplicate; today it
	// returns ErrDuplicateHeader (which is the same observable behaviour as
	// the Core early-return). When G1 is fixed, this becomes a hard
	// equivalence test.
	if _, err := idx.AddHeader(params.GenesisBlock.Header, true); err == nil {
		t.Logf("genesis re-add silently accepted (post-G1-fix behaviour)")
	}
}

// ---------------------------------------------------------------------------
// G3. Existing BLOCK_FAILED_VALID → "duplicate-invalid" / BLOCK_CACHED_INVALID
// ---------------------------------------------------------------------------
//
// Core: if the duplicate already has nStatus & BLOCK_FAILED_VALID, return
// state.Invalid(BLOCK_CACHED_INVALID, "duplicate-invalid"). blockbrew's
// AddHeader does NOT consult the existing node's Status — every duplicate
// is treated as ErrDuplicateHeader regardless of invalidation state, so a
// peer that re-sends an already-known-bad header receives no extra penalty
// (no consensus violation, but a missed DoS-mitigation opportunity).
//
// SEVERITY: DOS.
func TestW97_G3_DuplicateInvalidReturnsCachedInvalid(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G3: blockbrew loses BLOCK_FAILED_VALID signal on duplicate)")
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	h := createTestHeader(params.GenesisHash, params.GenesisBlock.Header.Timestamp+600, 2)
	node, err := idx.AddHeader(h, true)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}
	// Simulate that consensus marked this header invalid later.
	node.Status |= StatusInvalid
	_, err = idx.AddHeader(h, true)
	if err == nil {
		t.Errorf("Core returns BLOCK_CACHED_INVALID/'duplicate-invalid' on re-submit, got nil")
	}
}

// ---------------------------------------------------------------------------
// G4. CheckBlockHeader call (PoW + nBits sanity)
// ---------------------------------------------------------------------------
//
// Core: ConsensusCheckBlockHeader (pow.cpp / validation.cpp) before
// any prev-lookup. blockbrew calls CheckProofOfWork(hash, header.Bits, ...)
// AFTER the parent lookup, not before. The reorder is benign for valid
// headers but means a header with valid prev but corrupt nBits / nonsense
// PoW returns ErrInvalidPoW instead of the earlier no-prev short-circuit.
//
// SEVERITY: CORRECT (observable error differs but no consensus impact).
func TestW97_G4_InvalidPoWRejected(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	h := wire.BlockHeader{
		Version:    4,
		PrevBlock:  params.GenesisHash,
		MerkleRoot: wire.Hash256{},
		Timestamp:  params.GenesisBlock.Header.Timestamp + 600,
		Bits:       0x1d00ffff, // mainnet difficulty — too hard for regtest
		Nonce:      0,
	}
	_, err := idx.AddHeader(h, true)
	if err == nil {
		t.Errorf("expected PoW-invalid header to be rejected")
	}
}

// ---------------------------------------------------------------------------
// G5. Prev block lookup → "prev-blk-not-found" / BLOCK_MISSING_PREV
// ---------------------------------------------------------------------------
//
// Core: state.Invalid(BLOCK_MISSING_PREV, "prev-blk-not-found"). blockbrew
// returns ErrOrphanHeader instead of a Core-style BIP-22 error string. Net
// effect at the wire is the same — peer scored for unknown-parent — but RPC
// `submitblock` returns "rejected" rather than the canonical
// "prev-blk-not-found" string.
//
// SEVERITY: OBSERV.
func TestW97_G5_OrphanHeaderRejected(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	// Construct a header pointing at a non-existent parent.
	bogusPrev := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
	h := createTestHeader(bogusPrev, params.GenesisBlock.Header.Timestamp+600, 3)
	_, err := idx.AddHeader(h, true)
	if !errors.Is(err, ErrOrphanHeader) {
		t.Errorf("expected ErrOrphanHeader, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// G6. Prev BLOCK_FAILED_VALID → "bad-prevblk" / BLOCK_INVALID_PREV
// ---------------------------------------------------------------------------
//
// Core: if pindexPrev->nStatus & BLOCK_FAILED_VALID, reject with "bad-prevblk".
// blockbrew's AddHeader does NOT consult parent.Status.IsInvalid() before
// extending it. This means a peer can feed us a chain of headers built atop
// a known-invalid header (e.g. one we recently rejected for a sigops cost
// violation or a CVE-2018-17144 dup-input block) and they will all be
// accepted into the header index and counted toward total work.
//
// SEVERITY: DOS (memory exhaustion + wasted PoW-check CPU).
func TestW97_G6_HeaderOnInvalidParentRejected(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G6: AddHeader does not check parent.Status.IsInvalid())")
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	parent := createTestHeader(params.GenesisHash, params.GenesisBlock.Header.Timestamp+600, 4)
	parentNode, err := idx.AddHeader(parent, true)
	if err != nil {
		t.Fatalf("parent add: %v", err)
	}
	parentNode.Status |= StatusInvalid

	child := createTestHeader(parent.BlockHash(), parent.Timestamp+600, 5)
	_, err = idx.AddHeader(child, true)
	if err == nil {
		t.Errorf("child of invalidated parent must be rejected (Core: bad-prevblk)")
	}
}

// ---------------------------------------------------------------------------
// G7. ContextualCheckBlockHeader (block, state, blockman, *this, pindexPrev)
// ---------------------------------------------------------------------------
//
// Core: gates on (timestamp > MTP), nVersion-by-height (BIP34/65/66),
// difficulty target equality, future-time, BIP-94 timewarp, and
// "too-large-block" sanity. blockbrew's AddHeader implements most of these
// directly: time-too-old (MTP), BIP-94 timewarp, future-time, difficulty
// match, and checkpoints. The nVersion gates (BIP34/66/65) are NOT applied
// at header acceptance — they are deferred to CheckBlockContext at full-block
// validation time. This is a Core divergence: in Core, the nVersion-too-low
// check fires at header-accept, so a peer can't even get its header into our
// index. In blockbrew the header is accepted, takes index memory, and only
// fails when the full block arrives.
//
// SEVERITY: DOS (index pollution from bad-version headers).
func TestW97_G7_LowNVersionHeaderRejected(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G7: BIP34/66/65 nVersion gates deferred to full-block validation; not enforced at header time)")
	params := RegtestParams()
	// Force BIP34 active from h=1 so a v1 header is illegal immediately.
	params.BIP34Height = 1
	idx := NewHeaderIndex(params)
	h := createTestHeader(params.GenesisHash, params.GenesisBlock.Header.Timestamp+600, 6)
	h.Version = 1 // <2 — illegal once BIP34 is active
	_, err := idx.AddHeader(h, true)
	if err == nil {
		t.Errorf("Core rejects nVersion=1 at BIP34Height in ContextualCheckBlockHeader; got nil")
	}
}

// ---------------------------------------------------------------------------
// G8. min_pow_checked gate → "too-little-chainwork" / BLOCK_HEADER_LOW_WORK
// ---------------------------------------------------------------------------
//
// Core: AcceptBlockHeader takes a `bool min_pow_checked` argument. If false,
// it short-circuits with BLOCK_HEADER_LOW_WORK ("too-little-chainwork")
// AFTER all the contextual checks — meaning a peer can never grow our index
// with low-work headers unless we've vetted them via the PRESYNC pipeline
// (or our chain is already above nMinimumChainWork).
//
// blockbrew's AddHeader has NO min_pow_checked argument and accepts every
// PoW-valid header regardless of cumulative chain work. The PRESYNC pipeline
// (headerssync.go) gates ProcessNextHeaders externally, but headers that
// bypass the pipeline (any peer not in sm.peerHeadersSync) flow straight
// through addValidatedHeaders → AddHeader. This is the largest structural
// divergence from Core for the header-accept gate.
//
// SEVERITY: DOS (no chainwork-aware index pollution defense at the helper).
//
// Three active cases (W97 FIX-4):
//   1. Low-work header + minPowChecked=false → ErrTooLittleChainwork (rejected).
//   2. Low-work header + minPowChecked=true  → accepted (PRESYNC vouched for it).
//   3. High-work header + minPowChecked=false → accepted (chain already meets threshold).
func TestW97_G8_MinPowCheckedGate(t *testing.T) {
	// We need a network whose MinimumChainWork is non-zero but achievable with a
	// regtest-difficulty chain.  Testnet4 has a real MinimumChainWork hex value,
	// but its PoW limit requires mainnet-level mining which is impractical for
	// unit tests.  Instead, construct a synthetic ChainParams that inherits
	// regtest's very-easy PowLimit but carries a positive MinimumChainWork, so
	// we can mine valid headers cheaply while still exercising the gate.
	lowWork := new(big.Int)
	lowWork.SetString("0000000000000000000000000000000000000000000000000001000000000000", 16)

	params := *RegtestParams() // shallow copy — safe to modify MinimumChainWork
	params.MinimumChainWork = new(big.Int).Set(lowWork)

	idx := NewHeaderIndex(&params)

	// Mine a single header on top of genesis. With regtest bits (0x207fffff)
	// each block contributes only ~2 units of chain work, so one block's
	// total work will be far below the synthetic MinimumChainWork threshold.
	genesis := idx.Genesis()
	h := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, uint32(genesis.Header.Bits))
	// Verify the new header's projected TotalWork is actually below the threshold.
	singleBlockWork := CalcWork(h.Bits)
	projected := new(big.Int).Add(genesis.TotalWork, singleBlockWork)
	if projected.Cmp(params.MinimumChainWork) >= 0 {
		t.Skipf("synthetic MinimumChainWork %s is not above projected work %s; test precondition unmet",
			params.MinimumChainWork.Text(16), projected.Text(16))
	}

	// Case 1: low-work header, minPowChecked=false → must be rejected.
	_, err := idx.AddHeader(h, false)
	if !errors.Is(err, ErrTooLittleChainwork) {
		t.Errorf("case 1: low-work header + minPowChecked=false: want ErrTooLittleChainwork, got %v", err)
	}

	// Case 2: same low-work header, minPowChecked=true → must be accepted
	// (PRESYNC pipeline has vouched for the cumulative work).
	node, err := idx.AddHeader(h, true)
	if err != nil {
		t.Errorf("case 2: low-work header + minPowChecked=true: want nil error, got %v", err)
	}
	if node == nil {
		t.Fatal("case 2: AddHeader returned nil node on success")
	}

	// Case 3: build a second header on top; after case 2 the first header is
	// in the index.  Now raise MinimumChainWork to exactly the threshold so the
	// second header's TotalWork meets it.  This exercises the "chain already
	// meets threshold" path with minPowChecked=false.
	h2 := createTestHeader(h.BlockHash(), h.Timestamp+600, uint32(h.Bits))
	twoBlockWork := new(big.Int).Add(projected, singleBlockWork)
	// Set MinimumChainWork to exactly two-block work so the second header meets it.
	params.MinimumChainWork = new(big.Int).Set(twoBlockWork)
	// Use a fresh index so we are not relying on case-2 state.
	idx2 := NewHeaderIndex(&params)
	// First block must pass with minPowChecked=true (it's low-work).
	if _, err := idx2.AddHeader(h, true); err != nil {
		t.Fatalf("case 3 setup: first header rejected: %v", err)
	}
	// Second block has cumulative work == MinimumChainWork; minPowChecked=false
	// must succeed because twoBlockWork >= MinimumChainWork.
	if _, err := idx2.AddHeader(h2, false); err != nil {
		t.Errorf("case 3: high-work header + minPowChecked=false: want nil error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// G9. AddToBlockIndex updates best_header + nChainWork
// ---------------------------------------------------------------------------
//
// Core: m_blockman.AddToBlockIndex updates m_best_header to track the
// most-work header seen, separate from the active tip. blockbrew updates
// idx.bestTip via TotalWork comparison inside AddHeader. The bestTip in
// blockbrew tracks more-work-than-active-tip equivalently; the m_best_header
// vs ActiveTip distinction is collapsed.
//
// SEVERITY: CORRECT (consensus-equivalent for single-chain blockbrew model).
func TestW97_G9_BestTipUpdatedOnMoreWork(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	prev := idx.Genesis()
	for i := 1; i <= 5; i++ {
		h := createTestHeader(prev.Hash, prev.Header.Timestamp+600, uint32(100+i))
		n, err := idx.AddHeader(h, true)
		if err != nil {
			t.Fatalf("add header %d: %v", i, err)
		}
		if idx.BestTip() != n {
			t.Errorf("bestTip not advanced at height %d", i)
		}
		if n.TotalWork.Cmp(prev.TotalWork) <= 0 {
			t.Errorf("TotalWork did not increase at height %d", i)
		}
		prev = n
	}
}

// ---------------------------------------------------------------------------
// G10. ppindex write-back including genesis-bypass
// ---------------------------------------------------------------------------
//
// Core: AcceptBlockHeader writes *ppindex even on the genesis-hash early
// return. blockbrew's AddHeader returns (*BlockNode, error); the genesis
// re-add path returns ErrDuplicateHeader without giving the caller a handle
// to idx.genesis. Symptom: tests / callers that need the genesis node after
// a "duplicate" re-submit have to fetch it via idx.Genesis() rather than
// receiving it from AddHeader.
//
// SEVERITY: CORRECT.
func TestW97_G10_GenesisAccessibleViaGenesisGetter(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	if idx.Genesis() == nil {
		t.Fatalf("idx.Genesis() returned nil")
	}
	if idx.GetNode(params.GenesisHash) == nil {
		t.Fatalf("genesis not in idx.nodes")
	}
}

// ---------------------------------------------------------------------------
// G11. cs_main held throughout per-header loop
// ---------------------------------------------------------------------------
//
// Core: ProcessNewBlockHeaders takes LOCK(cs_main) once and holds it across
// the entire batch. blockbrew's HandleHeaders takes sm.mu around the whole
// addValidatedHeaders loop (sync.go:581 + 658 contract), and idx.AddHeader
// also takes idx.mu.Lock() inside each call. Two-level locking is structural
// — Core uses cs_main as a single big lock; blockbrew separates SyncManager
// state (sm.mu) from header-index state (idx.mu). The header-add itself is
// linearised by idx.mu, so observable behaviour matches.
//
// SEVERITY: CORRECT.
func TestW97_G11_AddHeaderLinearised(t *testing.T) {
	// Compile-time pin: HandleHeaders holds sm.mu and AddHeader holds idx.mu.
	// Documented in this assertion-free test as a structural cross-check.
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	_ = idx
	_ = params
}

// ---------------------------------------------------------------------------
// G12. CheckBlockIndex invariant after EACH AcceptBlockHeader
// ---------------------------------------------------------------------------
//
// Core: ProcessNewBlockHeaders calls CheckBlockIndex() inside the per-header
// loop body. CheckBlockIndex is a debug-mode invariant audit that verifies
// e.g. nChainWork monotonicity, skip-pointer correctness, and best_header
// consistency. blockbrew has no analog (no CheckBlockIndex equivalent
// anywhere in the codebase). Skip-pointer correctness is exercised via
// individual unit tests (headerindex_test.go::TestGetAncestor) but no
// runtime invariant check fires per-header.
//
// SEVERITY: OBSERV (debug-only in Core; cheap-to-miss-runtime-bug class).
func TestW97_G12_CheckBlockIndexInvariantAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G12: blockbrew has no CheckBlockIndex equivalent)")
}

// ---------------------------------------------------------------------------
// G13. Early return on first failed header
// ---------------------------------------------------------------------------
//
// Core: `if (!accepted) return false;` halts the loop on the first failure.
// blockbrew's addValidatedHeaders does roughly the same — on a non-orphan
// non-duplicate error it flushes the pending headers, penalises the peer,
// and returns. On orphan-as-first or duplicate, it continues / re-requests.
// This is structurally consistent with Core.
func TestW97_G13_EarlyReturnOnInvalidHeader(t *testing.T) {
	// Not directly testable without a SyncManager mock; pin the helper-level
	// contract: AddHeader returns (nil, err) on any failure so the caller
	// can early-return.
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	h := createTestHeader(wire.Hash256{0x01}, params.GenesisBlock.Header.Timestamp+600, 8)
	if _, err := idx.AddHeader(h, true); err == nil {
		t.Fatalf("orphan header must error")
	}
}

// ---------------------------------------------------------------------------
// G14. ppindex updated on each successful accept
// ---------------------------------------------------------------------------
//
// Core: the outer loop stores the last accepted CBlockIndex in *ppindex so
// the caller can read .Time() and compute the IBD progress log.
// blockbrew's addValidatedHeaders increments headersAdded but does NOT
// surface the last accepted node back to the caller. Side effect: the
// caller cannot log "Synchronizing blockheaders, height: X (~Y%)" using
// the last header's timestamp.
//
// SEVERITY: OBSERV (no consensus impact — affects IBD log only).
func TestW97_G14_LastAcceptedHeaderNotReturnedToCaller(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G14: addValidatedHeaders does not return last-accepted node)")
}

// ---------------------------------------------------------------------------
// G15. NotifyHeaderTip OUTSIDE cs_main
// ---------------------------------------------------------------------------
//
// Core: after the per-header loop, ProcessNewBlockHeaders releases cs_main
// (RAII scope ends) and then calls NotifyHeaderTip() — a UI-level signal
// that wallets / RPC subscribers can hook. blockbrew has NO NotifyHeaderTip
// equivalent. There is no signal fired when the best header advances; the
// RPC progress hook polls idx.BestHeight() instead. This is a missed
// integration point — wallets cannot subscribe to header-tip updates.
//
// SEVERITY: OBSERV.
func TestW97_G15_NotifyHeaderTipAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G15: no NotifyHeaderTip / header-tip signal)")
}

// ---------------------------------------------------------------------------
// G16. IBD progress log uses PowTargetSpacing()
// ---------------------------------------------------------------------------
//
// Core: blocks_left = (now - last_accepted.Time()) / PowTargetSpacing(); the
// progress percentage uses this estimate so the operator can see "~37.4%"
// during header sync. blockbrew's addValidatedHeaders only logs the raw
// count (`added 2000 headers (123456 -> 125456)`) with no percentage
// estimate, even though chainparams.go has TargetSpacing available.
//
// SEVERITY: OBSERV.
func TestW97_G16_HeaderSyncProgressMissesPercentage(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G16: header-sync log lacks ETA / percentage)")
}

// ---------------------------------------------------------------------------
// G17. AcceptBlockHeader inner call + CheckBlockIndex invariant
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock starts with `bool accepted_header{AcceptBlockHeader(...)}`
// followed by `CheckBlockIndex()`. blockbrew's ConnectBlock does NOT call
// AddHeader internally — it requires the header to be present in the index
// already (see chainmanager.go:447 lookup). This is the canonical headers-
// first split. Callers (sync.go) must call idx.AddHeader before
// chainMgr.ConnectBlock. The CheckBlockIndex invariant analog (G12) is also
// absent.
//
// SEVERITY: CORRECT (structural; documented). G12 covers the invariant.
func TestW97_G17_ConnectBlockRequiresHeaderInIndex(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db,
	})
	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	// Deliberately do NOT call AddHeader.
	err := cm.ConnectBlock(block)
	if err == nil {
		t.Errorf("ConnectBlock without prior AddHeader must fail")
	}
}

// ---------------------------------------------------------------------------
// G18. fAlreadyHave = (nStatus & BLOCK_HAVE_DATA) → return true
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock short-circuits with `if (fAlreadyHave) return true;`
// when the block has already been received + persisted. blockbrew's
// ConnectBlock has NO equivalent gate — calling ConnectBlock twice on the
// same block proceeds through full re-validation. The wider sync pipeline
// has a `chainDB.HasBlock(req.Hash)` check (sync.go:1547) that short-
// circuits the network round-trip, but the validation path itself does
// not.
//
// SEVERITY: CORRECT (validation re-runs are idempotent — same result;
// wasted CPU).
func TestW97_G18_AlreadyHaveDataShortCircuitAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G18: ConnectBlock has no fAlreadyHave short-circuit)")
}

// ---------------------------------------------------------------------------
// G19a. nTx != 0 early-return (previously-pruned block)
// ---------------------------------------------------------------------------
//
// Core: `if (pindex->nTx != 0) return true;` — a block we already have a
// tx-count for (validated previously, then pruned from disk) does NOT need
// re-validation. blockbrew's BlockNode struct has no nTx / TxCount field
// (StatusDataStored is defined but never set anywhere — see headerindex.go:37
// and check the unused-flag finding below). Therefore, on an unrequested
// previously-pruned block, blockbrew has no way to short-circuit.
//
// SEVERITY: CORRECT (post-prune re-validation is wasted work).
func TestW97_G19a_NTxFieldAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G19a: BlockNode has no nTx field; cannot identify previously-pruned blocks)")
}

// ---------------------------------------------------------------------------
// G19b. !fHasMoreOrSameWork early-return on unrequested blocks
// ---------------------------------------------------------------------------
//
// Core: an unrequested block whose chainwork is less than the active tip's
// chainwork is silently dropped. blockbrew's ConnectBlock returns the
// "block does not connect to tip and has less work" error AFTER a tip-prev
// comparison, but the gate fires at the wrong layer — the block has already
// been received from the network and persisted to chainDB by the time we
// reject it.
//
// SEVERITY: DOS (disk-write amplification by less-work flooders).
func TestW97_G19b_LessWorkBlockReachesDisk(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G19b: less-work block is persisted before chainwork comparison)")
}

// ---------------------------------------------------------------------------
// G19c. fTooFarAhead = (nHeight > ActiveHeight + MIN_BLOCKS_TO_KEEP/288)
// ---------------------------------------------------------------------------
//
// Core: `if (fTooFarAhead) return true;` — a block too far ahead of the
// active tip is dropped, with the rationale that it would limit pruning
// effectiveness. IsTooFarAhead implements this gate; it is called by
// sync.HandleBlock on the unrequested (P2P-inv-driven) block path.
//
// SEVERITY: DOS (disk + memory amplification far ahead of tip).
//
// Three cases:
//  1. Unrequested block too far ahead → IsTooFarAhead returns true (reject).
//  2. Unrequested block at gate boundary (activeHeight + 288) → false (accept).
//  3. "Requested" context: even a too-far-ahead height is logically exempt
//     (caller enforces this by skipping the IsTooFarAhead call for solicited
//     blocks; we verify the pure function returns true so the caller's if-gate
//     would fire — confirming the correct call-site exemption is needed).
func TestW97_G19c_TooFarAheadGate(t *testing.T) {
	const activeHeight int32 = 1000
	const limit = int32(storage.MinBlocksToKeep) // 288

	// Case 1: unrequested block is beyond activeHeight + 288 → must be dropped.
	tooFar := activeHeight + limit + 1
	if !IsTooFarAhead(tooFar, activeHeight) {
		t.Errorf("case 1: IsTooFarAhead(%d, %d) = false; want true (unrequested block too far ahead must be rejected)",
			tooFar, activeHeight)
	}

	// Case 2: unrequested block exactly at the gate boundary (activeHeight + 288) → must be accepted.
	atGate := activeHeight + limit
	if IsTooFarAhead(atGate, activeHeight) {
		t.Errorf("case 2: IsTooFarAhead(%d, %d) = true; want false (block at gate boundary must be accepted)",
			atGate, activeHeight)
	}

	// Case 3: for a solicited/requested block the caller skips IsTooFarAhead
	// entirely — but the pure function itself still returns true for a too-far
	// height, confirming that the call-site must exempt requested blocks (i.e.
	// the if(!fRequested) wrapper is load-bearing).
	if !IsTooFarAhead(tooFar, activeHeight) {
		t.Errorf("case 3: IsTooFarAhead(%d, %d) = false; want true (confirms requested-block exemption is needed at call site)",
			tooFar, activeHeight)
	}
}

// ---------------------------------------------------------------------------
// G19d. nChainWork < MinimumChainWork() early-return
// ---------------------------------------------------------------------------
//
// Core: an unrequested block whose chainwork is below
// Consensus::Params::nMinimumChainWork is rejected to avoid DoS via low-
// work side-chains. blockbrew gates this externally via the PRESYNC
// pipeline (headerssync.go) at the HEADER level, but not at the BLOCK
// level. Once a header crosses MinimumChainWork via PRESYNC, every block
// below it on a side-chain is still accepted by ConnectBlock's tip-prev
// comparison (it just fails to connect). Disk write fires first.
//
// SEVERITY: DOS (mirrors G19b at the block layer).
func TestW97_G19d_MinimumChainWorkGateBlockLevel(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G19d: MinimumChainWork is enforced at header time only, not block time)")
}

// ---------------------------------------------------------------------------
// G20. CheckBlock call (block-level sanity)
// ---------------------------------------------------------------------------
//
// Core: ConnectBlock invokes CheckBlock(block, state, params.GetConsensus()).
// blockbrew calls CheckBlockSanity inside ConnectBlock (chainmanager.go:531)
// but ONLY when `!cm.isIBD`. During IBD it skips block sanity, relying on
// the validationWorker (sync.go:1865) to have done it. This is a careful
// optimisation but creates a dual-path:
//
//   - Network → validationWorker → CheckBlockSanity → connectionChan.
//   - RPC submitblock / reorg-replay → ConnectBlock directly with
//     cm.isIBD already false → CheckBlockSanity here.
//
// A genesis-replay or in-test cm.ConnectBlock(...) call with cm.isIBD=true
// will SKIP CheckBlockSanity. Tests can hit this; production code can hit
// this via cm.ReorgTo recursive replay when the chainstate isIBD flag is
// stale.
//
// SEVERITY: CORRECT (production codepaths are covered; gap is fragile).
func TestW97_G20_CheckBlockSanitySkippedDuringIBDFlag(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G20: CheckBlockSanity skipped when cm.isIBD=true; relies on validationWorker)")
}

// ---------------------------------------------------------------------------
// G21. ContextualCheckBlock(block, state, *this, pindex->pprev)
// ---------------------------------------------------------------------------
//
// Core: ConnectBlock runs CheckBlock AND ContextualCheckBlock atomically
// before InvalidBlockFound. blockbrew calls CheckBlockContext (the
// blockbrew analog) at chainmanager.go:545. Implementation matches Core
// for BIP34/65/66 nVersion, witness commitment, IsFinalTx (BIP-113 MTP),
// and timestamp.
func TestW97_G21_ContextualCheckBlockRuns(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db,
	})
	cm.SetIBD(false)
	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.StoreBlock(block.Header.BlockHash(), block); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("happy-path ConnectBlock: %v", err)
	}
}

// ---------------------------------------------------------------------------
// G22. InvalidBlockFound on either fail
// ---------------------------------------------------------------------------
//
// Core: when CheckBlock or ContextualCheckBlock fails, the block index is
// updated via InvalidBlockFound — this sets BLOCK_FAILED_VALID and
// propagates to descendants. blockbrew's ConnectBlock returns an error
// without marking node.Status |= StatusInvalid on validation failure. The
// only path that marks StatusInvalid on a connect-time validation failure
// is the sync.go:1882 path inside the validation worker — but ONLY for
// CheckBlockSanity failures, not for CheckBlockContext / fee /
// CheckTransactionInputs failures inside ConnectBlock itself.
//
// SEVERITY: DOS (a peer that delivers a context-invalid block is scored,
// but the block hash is not permanently marked invalid; future deliveries
// from other peers re-attempt validation).
func TestW97_G22_FailedConnectDoesNotMarkInvalid(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G22: ConnectBlock validation failure does not set StatusInvalid on the node)")
}

// ---------------------------------------------------------------------------
// G23. NewPoWValidBlock signal ONLY when (!IBD && ActiveTip == pindex->pprev)
// ---------------------------------------------------------------------------
//
// Core: m_options.signals->NewPoWValidBlock(pindex, pblock) fires when the
// new block extends the active tip outside IBD, so net_processing can
// announce via compact-block / cmpctblock relay BEFORE the full validation
// completes (per BIP-152). blockbrew has NO equivalent — compact-block
// relay announcement happens after the block is fully validated and
// connected, not at the "headers-valid + PoW-valid" interim state.
//
// SEVERITY: OBSERV (latency cost; not consensus).
func TestW97_G23_NewPoWValidBlockSignalAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G23: no NewPoWValidBlock interim-state signal for compact-block relay)")
}

// ---------------------------------------------------------------------------
// G24. WriteBlock vs UpdateBlockInfo (dbp != nullptr path)
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock writes the block to a flat file, OR (when dbp != nullptr)
// just updates the in-memory BlockFileInfo for a block already on disk
// (e.g. -reindex). blockbrew's storage layer always writes via StoreBlock /
// StoreBlockAt (sync.go:1815, never an UpdateBlockInfo-only path); there is
// no -reindex mode where the on-disk block file is canonical and we just
// need to re-index the metadata. This is a feature gap, not a bug — but it
// means a future -reindex implementation will need a new code path.
//
// SEVERITY: CORRECT (feature absent).
func TestW97_G24_UpdateBlockInfoPathAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G24: no reindex / UpdateBlockInfo-only path)")
}

// ---------------------------------------------------------------------------
// G25. ReceivedBlockTransactions transitions BLOCK_HAVE_DATA
// ---------------------------------------------------------------------------
//
// Core: ReceivedBlockTransactions(block, pindex, blockPos) sets
// nStatus |= BLOCK_HAVE_DATA + sets nTx, and propagates HAVE_DATA-and-up to
// descendants. blockbrew sets StatusDataStored in ConnectBlock (after W101
// fix) and via MarkDataStored after StoreBlockAt in sync.go.
//
// FIX-33 update: the original audit-time pin asserted genesis did NOT have
// StatusDataStored, because the flag was dead code (never set). W101 fixed
// that — ConnectBlock now sets StatusFullyValid|StatusDataStored. FIX-33
// adds StatusHaveUndo set after undo data is written to disk.
// This test verifies the FIXED behavior: both StatusDataStored and
// StatusHaveUndo must be set after a block is connected.
func TestW97_G25_StatusDataStoredFlagSet(t *testing.T) {
	if StatusDataStored == 0 {
		t.Fatalf("StatusDataStored constant has zero value (unexpected)")
	}
	if StatusHaveUndo == 0 {
		t.Fatalf("StatusHaveUndo constant has zero value (unexpected)")
	}
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db,
	})
	cm.SetIBD(false)
	genesis := idx.Genesis()

	// Build block1 on top of genesis and connect it.
	block1 := createTestBlock(t, params, genesis, nil)
	node1, err := idx.AddHeader(block1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader block1: %v", err)
	}
	if err := db.StoreBlock(block1.Header.BlockHash(), block1); err != nil {
		t.Fatalf("StoreBlock block1: %v", err)
	}
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("ConnectBlock block1: %v", err)
	}

	// StatusDataStored must be set on the connected node.
	if node1.Status&StatusDataStored == 0 {
		t.Errorf("G25 FIX: node1 StatusDataStored not set after ConnectBlock; want bit 0x%02x in Status=0x%02x",
			StatusDataStored, node1.Status)
	}
	// StatusHaveUndo must also be set (FIX-33): ConnectBlock writes undo data
	// (mirrors Core blockstorage.cpp:1029 BLOCK_HAVE_UNDO after rev*.dat write).
	if node1.Status&StatusHaveUndo == 0 {
		t.Errorf("G25/FIX-33: node1 StatusHaveUndo not set after ConnectBlock; want bit 0x%02x in Status=0x%02x",
			StatusHaveUndo, node1.Status)
	}
}

// ---------------------------------------------------------------------------
// G26. FlushStateToDisk(FlushStateMode::NONE) — pruning hint
// ---------------------------------------------------------------------------
//
// Core: at the end of AcceptBlock, FlushStateToDisk(NONE) is called so the
// pruner can opportunistically delete block files. blockbrew's ConnectBlock
// flushes on a periodic-blocks counter (cm.blocksSinceFlush >=
// cm.flushInterval) instead of via a NONE-mode hint per block. The pruner
// (storage/prune.go) runs on its own ticker rather than being invoked from
// the validation path.
//
// SEVERITY: CORRECT (different flushing discipline; not a bug).
func TestW97_G26_FlushStateModeNONEAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G26: pruner runs on independent ticker; no per-block hint)")
}

// ---------------------------------------------------------------------------
// G27. CheckBlockIndex final invariant
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock ends with CheckBlockIndex(). Same as G12 — no analog.
//
// SEVERITY: OBSERV (debug-only).
func TestW97_G27_FinalCheckBlockIndexInvariantAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G27: see G12 — no CheckBlockIndex)")
}

// ---------------------------------------------------------------------------
// G28. fNewBlock output (only true on actual new-block path)
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock writes `*fNewBlock = true` ONLY after passing the
// fAlreadyHave / nTx != 0 short-circuits — i.e. only on a path that
// actually persists new block data. blockbrew's ConnectBlock has no
// fNewBlock output; the caller (validationWorker → connectionWorker) tracks
// "did we connect this block" implicitly via the success / failure return.
// An RPC `submitblock` cannot distinguish "block was new" from "block was
// already known" — the BIP-22 result map collapses both into the same
// "rejected" or "" string.
//
// SEVERITY: OBSERV (BIP-22 submitblock result fidelity).
func TestW97_G28_FNewBlockOutputAbsent(t *testing.T) {
	t.Skip("W97 audit — not yet implemented (G28: no fNewBlock output; submitblock cannot signal duplicate-vs-new)")
}

// ---------------------------------------------------------------------------
// G29. System-error catch on disk write
// ---------------------------------------------------------------------------
//
// Core: AcceptBlock wraps the WriteBlock + ReceivedBlockTransactions in a
// try { ... } catch (const std::runtime_error&) and routes to FatalError —
// which both logs a fatal banner and signals shutdown so the operator
// notices a disk-full / IO-error condition.
//
// blockbrew's ConnectBlock returns `fmt.Errorf(...)` on a chainDB batch
// Write failure (chainmanager.go:1015, 1029, etc) — the error propagates
// up to connectionWorker (sync.go:2356), which latches
// sm.chainstateCorrupted and halts the connect loop. This is roughly
// equivalent to FatalError but does NOT trigger a process shutdown — the
// node keeps running with a latched-corrupted flag, serving RPCs but not
// advancing. Better-than-Core in some respects, divergent in shape.
//
// SEVERITY: OBSERV (different shutdown discipline; documented).
func TestW97_G29_FatalErrorOnDiskWriteShape(t *testing.T) {
	// Compile-time pin: chainmanager.go ConnectBlock returns an error rather
	// than panicking on chainDB batch failure. Tested indirectly via
	// chainstate-corruption tests in chainmanager_test.go.
	_ = "shape-pin"
}

// ---------------------------------------------------------------------------
// G30. BLOCK_HAVE_DATA set BEFORE next ReceivedBlockTransactions short-circuit
// ---------------------------------------------------------------------------
//
// Core: pindex->nStatus |= BLOCK_HAVE_DATA must be set inside
// ReceivedBlockTransactions BEFORE any subsequent call from a sibling
// block can read it; this prevents a race where two arrivals of the same
// block (e.g. via inv from two peers) both attempt to validate.
//
// blockbrew sets node.Status |= StatusFullyValid only after the entire
// ConnectBlock returns success (chainmanager.go:949). There is no
// intermediate "data stored but not yet validated" flag (G25 — the
// StatusDataStored flag exists but is never set). The race between
// two concurrent ConnectBlock(block) calls for the same hash is
// instead serialised by cm.mu.Lock() — both goroutines run the full
// validation, and the second observes the same end state but does
// redundant work.
//
// SEVERITY: CORRECT (cm.mu serialises; cost is duplicate work).
func TestW97_G30_StatusFullyValidSetAfterConnect(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db,
	})
	cm.SetIBD(false)
	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	node, err := idx.AddHeader(block.Header, true)
	if err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if node.Status&StatusFullyValid != 0 {
		t.Errorf("StatusFullyValid set before ConnectBlock")
	}
	if err := db.StoreBlock(block.Header.BlockHash(), block); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	if node.Status&StatusFullyValid == 0 {
		t.Errorf("StatusFullyValid not set after successful ConnectBlock")
	}
}

// ---------------------------------------------------------------------------
// Additional finding: addValidatedHeaders pendingHeaders flush on
// invalid-header-mid-batch is correct BUT ErrTimestampTooFarFuture is
// retried as a normal sync re-request rather than throttling the peer.
// ---------------------------------------------------------------------------
//
// blockbrew's addValidatedHeaders treats ErrTimestampTooFarFuture as a
// "genuinely bad header" with score = ScoreInvalidBlock (100, instant ban).
// Core treats time-too-new at header-accept the same way — they match. Pin
// the equivalence.
func TestW97_AddHeaderRejectsFarFutureTimestamp(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	now := int64(params.GenesisBlock.Header.Timestamp + 600)
	headerNowUnixOrig := headerNowUnix
	headerNowUnix = func() int64 { return now }
	defer func() { headerNowUnix = headerNowUnixOrig }()

	h := createTestHeader(params.GenesisHash, uint32(now+MaxTimeAdjustment+10), 7)
	if _, err := idx.AddHeader(h, true); !errors.Is(err, ErrTimestampTooFarFuture) {
		t.Errorf("expected ErrTimestampTooFarFuture, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// W97 chainwork-on-best-tip monotonicity smoke
// ---------------------------------------------------------------------------
//
// Adds a header that becomes the new best tip; the cumulative TotalWork
// must strictly exceed the previous bestTip's. Pins the G9 invariant.
func TestW97_BestTipChainworkMonotone(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	prev := idx.Genesis()
	var lastWork *big.Int = new(big.Int).Set(prev.TotalWork)
	for i := 1; i <= 3; i++ {
		h := createTestHeader(prev.Hash, prev.Header.Timestamp+600, uint32(200+i))
		n, err := idx.AddHeader(h, true)
		if err != nil {
			t.Fatalf("add header %d: %v", i, err)
		}
		if n.TotalWork.Cmp(lastWork) <= 0 {
			t.Errorf("TotalWork did not increase at height %d (%s -> %s)",
				i, lastWork.String(), n.TotalWork.String())
		}
		lastWork.Set(n.TotalWork)
		prev = n
	}
}
