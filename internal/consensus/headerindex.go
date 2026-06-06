package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Header validation errors.
var (
	ErrOrphanHeader          = errors.New("header has unknown parent")
	ErrDuplicateHeader       = errors.New("header already exists")
	ErrInvalidPoW            = errors.New("header has invalid proof of work")
	ErrTimestampTooEarly     = errors.New("header timestamp is before median time past")
	ErrTimestampTooFarFuture = errors.New("header timestamp is more than 2 hours in the future")
	ErrTimeWarpAttack        = errors.New("block timestamp violates BIP-94 timewarp rule at difficulty adjustment boundary")
	ErrBadDifficulty         = errors.New("header has incorrect difficulty bits")
	ErrCheckpointMismatch    = errors.New("header does not match checkpoint")
	ErrForkBeforeCheckpoint  = errors.New("fork before last checkpoint is not allowed")
	// ErrTooLittleChainwork is returned by AddHeader when minPowChecked is false
	// and the header's cumulative chain work does not meet the network's
	// MinimumChainWork threshold.  Mirrors Bitcoin Core validation.cpp:4229:
	//   if (!min_pow_checked)
	//       return state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
	ErrTooLittleChainwork = errors.New("too-little-chainwork")
)

// headerNowUnix returns the current wall-clock time in seconds since epoch.
// It is a package variable so tests can substitute a deterministic clock when
// exercising the future-time gate in AddHeader.
var headerNowUnix = func() int64 { return time.Now().Unix() }

// BlockStatus tracks the validation state of a block.
type BlockStatus uint32

const (
	StatusHeaderValid  BlockStatus = 1 << 0 // Header passed PoW and basic checks
	StatusDataStored   BlockStatus = 1 << 1 // Full block data is stored (mirrors Core's BLOCK_HAVE_DATA)
	StatusFullyValid   BlockStatus = 1 << 2 // Block passed full validation
	StatusInvalid      BlockStatus = 1 << 3 // Block is known invalid (explicitly marked via invalidateblock)
	StatusInvalidChild BlockStatus = 1 << 4 // Block is invalid because ancestor is invalid
	StatusHaveUndo     BlockStatus = 1 << 5 // Undo data is stored on disk (mirrors Core's BLOCK_HAVE_UNDO)
)

// IsInvalid returns true if this block is marked as invalid (either directly or via ancestor).
func (s BlockStatus) IsInvalid() bool {
	return s&(StatusInvalid|StatusInvalidChild) != 0
}

// BlockNode represents a block header in the header chain.
type BlockNode struct {
	Hash       wire.Hash256
	Header     wire.BlockHeader
	Height     int32
	Parent     *BlockNode
	Skip       *BlockNode   // Skip-list pointer for O(log N) ancestor lookup (Bitcoin Core's pskip)
	TotalWork  *big.Int     // Cumulative chain work up to this block
	Status     BlockStatus  // Validation state
	Children   []*BlockNode // Potential forks
	SequenceID int32        // Sequence ID for precious block ordering (lower = more precious)
}

// invertLowestOne clears the lowest set bit of n. Helper for getSkipHeight.
// Mirror of Bitcoin Core's InvertLowestOne in src/chain.cpp.
func invertLowestOne(n int32) int32 { return n & (n - 1) }

// getSkipHeight returns the height that a BlockNode at `height` should skip to.
// Chosen so that at most ~log2(N) hops are needed to walk back N blocks.
// Mirror of Bitcoin Core's GetSkipHeight in src/chain.cpp.
func getSkipHeight(height int32) int32 {
	if height < 2 {
		return 0
	}
	if height&1 != 0 {
		return invertLowestOne(invertLowestOne(height-1)) + 1
	}
	return invertLowestOne(height)
}

// buildSkip populates the Skip pointer based on this node's Parent.
// Must be called after Parent is set and before the node is returned.
// Mirror of Bitcoin Core's CBlockIndex::BuildSkip.
func (n *BlockNode) buildSkip() {
	if n.Parent != nil {
		n.Skip = n.Parent.GetAncestor(getSkipHeight(n.Height))
	}
}

// GetAncestorHashAtHeight returns the hash of this node's ancestor at the given
// height, and a boolean indicating whether the ancestor was found.  Used by
// CheckForkConflictsWithCheckpoint without exposing the full BlockNode.
func (n *BlockNode) GetAncestorHashAtHeight(height int32) (wire.Hash256, bool) {
	anc := n.GetAncestor(height)
	if anc == nil {
		return wire.Hash256{}, false
	}
	return anc.Hash, true
}

// GetAncestor returns the ancestor of a node at a given height.
// Returns nil if the height is invalid or this node doesn't have an ancestor at that height.
//
// Uses skip-list pointers (BlockNode.Skip) for O(log N) lookup when available,
// falling back to parent walks otherwise. Mirror of Bitcoin Core's
// CBlockIndex::GetAncestor in src/chain.cpp.
func (n *BlockNode) GetAncestor(height int32) *BlockNode {
	if height < 0 || height > n.Height {
		return nil
	}

	walk := n
	heightWalk := n.Height
	for heightWalk > height {
		heightSkip := getSkipHeight(heightWalk)
		heightSkipPrev := getSkipHeight(heightWalk - 1)
		if walk.Skip != nil &&
			(heightSkip == height ||
				(heightSkip > height && !(heightSkipPrev < heightSkip-2 &&
					heightSkipPrev >= height))) {
			// Follow the skip pointer — one big jump instead of many parent steps.
			walk = walk.Skip
			heightWalk = heightSkip
		} else {
			if walk.Parent == nil {
				return nil
			}
			walk = walk.Parent
			heightWalk--
		}
	}
	return walk
}

// BuildLocator builds a block locator starting from this node.
// The locator includes hashes at exponentially increasing intervals:
// tip, tip-1, tip-2, ..., tip-10, then doubling steps: tip-12, tip-16, tip-24, ...
// Always ends with the genesis hash (height 0).
func (n *BlockNode) BuildLocator() []wire.Hash256 {
	step := int32(1)
	locator := make([]wire.Hash256, 0, 32)
	node := n

	for node != nil {
		locator = append(locator, node.Hash)

		// Calculate next height
		height := node.Height - step
		if height < 0 {
			break
		}

		// After first 10 entries, start doubling the step
		if len(locator) > 10 {
			step *= 2
		}

		node = node.GetAncestor(height)
	}

	// Always include genesis (height 0) if not already there
	if len(locator) == 0 || n.GetAncestor(0) == nil {
		return locator
	}

	genesis := n.GetAncestor(0)
	if locator[len(locator)-1] != genesis.Hash {
		locator = append(locator, genesis.Hash)
	}

	return locator
}

// GetMedianTimePast returns the median timestamp of the previous 11 blocks.
// For blocks with height < 11, uses all available ancestors.
func (n *BlockNode) GetMedianTimePast() int64 {
	// Collect timestamps from this block and its ancestors
	timestamps := make([]uint32, 0, MedianTimeSpan)
	node := n
	for i := 0; i < MedianTimeSpan && node != nil; i++ {
		timestamps = append(timestamps, node.Header.Timestamp)
		node = node.Parent
	}

	// Sort timestamps
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// Return the median
	return int64(timestamps[len(timestamps)/2])
}

// CalcWork calculates the proof-of-work for a block given its bits.
// work = 2^256 / (target + 1)
// This gives more work to blocks with lower targets (harder blocks).
func CalcWork(bits uint32) *big.Int {
	target := CompactToBig(bits)
	if target.Sign() <= 0 {
		return big.NewInt(0)
	}

	// work = 2^256 / (target + 1)
	// We use 2^256 - 1 as our "2^256" since 2^256 doesn't fit in a uint256
	// and then add 1 to compensate
	oneLsh256 := new(big.Int).Lsh(big.NewInt(1), 256)
	targetPlusOne := new(big.Int).Add(target, big.NewInt(1))
	return new(big.Int).Div(oneLsh256, targetPlusOne)
}

// FindFork finds the common ancestor of two chain tips.
// Returns nil if the chains don't share a common ancestor.
func FindFork(a, b *BlockNode) *BlockNode {
	if a == nil || b == nil {
		return nil
	}

	// Bring both nodes to the same height
	for a.Height > b.Height {
		a = a.Parent
	}
	for b.Height > a.Height {
		b = b.Parent
	}

	// Walk up until we find the common ancestor
	for a != b {
		if a == nil || b == nil {
			return nil
		}
		a = a.Parent
		b = b.Parent
	}

	return a
}

// HeaderIndex maintains the tree of block headers.
type HeaderIndex struct {
	mu             sync.RWMutex
	nodes          map[wire.Hash256]*BlockNode // All known block nodes
	bestTip        *BlockNode                  // Tip of the best (most work) chain
	genesis        *BlockNode                  // The genesis block node
	params         *ChainParams                // Chain parameters
	checkpointData *CheckpointData             // Checkpoint verification data

	// Precious block tracking
	preciousBlock    *BlockNode // The block designated as precious (ephemeral)
	lastPreciousWork *big.Int   // Chainwork when last precious call was made
	blockSequenceID  int32      // Sequence counter for precious block tie-breaking

	// Lock-free best height cache for RPC reads (updated atomically when best tip changes).
	// This avoids RLock contention with header validation during rapid header sync in IBD.
	cachedBestHeight atomic.Int32
}

// Ensure HeaderIndex implements BlockProvider
var _ BlockProvider = (*HeaderIndex)(nil)

// GetHeaderByHeight returns the block node at a given height on the best chain.
// Returns nil if the height is invalid or beyond the current tip.
func (idx *HeaderIndex) GetHeaderByHeight(height int32) *BlockNode {
	if height < 0 || idx.bestTip == nil || height > idx.bestTip.Height {
		return nil
	}
	return idx.bestTip.GetAncestor(height)
}

// GetPrevHeader returns the parent of a block node.
func (idx *HeaderIndex) GetPrevHeader(node *BlockNode) *BlockNode {
	if node == nil {
		return nil
	}
	return node.Parent
}

// NewHeaderIndex creates a new header index with the genesis block.
func NewHeaderIndex(params *ChainParams) *HeaderIndex {
	idx := &HeaderIndex{
		nodes:          make(map[wire.Hash256]*BlockNode),
		params:         params,
		checkpointData: GetCheckpointsForNetwork(params.Name),
	}

	// Add genesis block
	genesisNode := &BlockNode{
		Hash:      params.GenesisHash,
		Header:    params.GenesisBlock.Header,
		Height:    0,
		Parent:    nil,
		TotalWork: CalcWork(params.GenesisBlock.Header.Bits),
		Status:    StatusHeaderValid | StatusFullyValid | StatusDataStored,
		Children:  nil,
	}

	idx.nodes[genesisNode.Hash] = genesisNode
	idx.genesis = genesisNode
	idx.bestTip = genesisNode
	idx.cachedBestHeight.Store(0)

	return idx
}

// GetCheckpointData returns the checkpoint data for this header index.
func (idx *HeaderIndex) GetCheckpointData() *CheckpointData {
	return idx.checkpointData
}

// GetLastCheckpoint returns the highest checkpoint for this network.
func (idx *HeaderIndex) GetLastCheckpoint() *Checkpoint {
	if idx.checkpointData == nil {
		return nil
	}
	return idx.checkpointData.GetLastCheckpoint()
}

// isOnBestChain checks if a block node is on the current best chain.
func (idx *HeaderIndex) isOnBestChain(node *BlockNode) bool {
	if node == nil || idx.bestTip == nil {
		return false
	}
	// A node is on the best chain if its ancestor at that height equals the node
	ancestor := idx.bestTip.GetAncestor(node.Height)
	return ancestor != nil && ancestor.Hash == node.Hash
}

// wouldCreateFork returns true if adding a header at the given height with the given parent
// would create a fork from the best chain. A fork is created if the best chain already
// has a block at this height that isn't the new header's parent's child.
func (idx *HeaderIndex) wouldCreateFork(parent *BlockNode, newHeight int32) bool {
	if idx.bestTip == nil {
		return false
	}

	// If new height is beyond the best tip, it's extending the chain, not forking
	if newHeight > idx.bestTip.Height {
		return false
	}

	// Check if the parent is on the best chain
	parentOnBestChain := idx.isOnBestChain(parent)
	if !parentOnBestChain {
		// Parent is not on best chain, so this is definitely a fork
		return true
	}

	// Parent is on best chain. Check if there's already a block at newHeight on best chain.
	// If the best chain has a block at this height, we're creating a sibling (fork).
	existingAtHeight := idx.bestTip.GetAncestor(newHeight)
	if existingAtHeight != nil {
		// There's already a block at this height on the best chain
		// Adding another one is a fork
		return true
	}

	return false
}

// mustParseHash parses a hex hash string, panicking on error.
func mustParseHash(s string) wire.Hash256 {
	h, err := wire.NewHash256FromHex(s)
	if err != nil {
		panic("invalid checkpoint hash: " + s)
	}
	return h
}

// AddHeader adds a validated header to the index. Returns the new BlockNode.
//
// minPowChecked must be true when the caller has already verified that the
// header sits on a chain whose cumulative work meets or exceeds the network's
// MinimumChainWork threshold (e.g. after the PRESYNC/REDOWNLOAD pipeline, or
// for locally-generated blocks).  When false, AddHeader enforces the
// MinimumChainWork gate itself: if the new header's cumulative work would
// remain below MinimumChainWork the call is rejected with ErrTooLittleChainwork.
//
// This mirrors Bitcoin Core validation.cpp AcceptBlockHeader (line 4229):
//
//	if (!min_pow_checked) {
//	    return state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
//	}
//
// Callers:
//   - PRESYNC/REDOWNLOAD pipeline (addValidatedHeaders): pass true.
//   - P2P unsolicited blocks (HandleBlock): pass false.
//   - submitblock RPC: pass false.
//   - Local miner / import path: pass true (blocks are locally generated or
//     already trusted).
func (idx *HeaderIndex) AddHeader(header wire.BlockHeader, minPowChecked bool) (*BlockNode, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Compute block hash
	hash := header.BlockHash()

	// Check if already exists
	if _, exists := idx.nodes[hash]; exists {
		return nil, ErrDuplicateHeader
	}

	// Check parent exists
	parent, exists := idx.nodes[header.PrevBlock]
	if !exists {
		return nil, ErrOrphanHeader
	}

	// Calculate new height
	height := parent.Height + 1

	// Verify proof-of-work
	if err := CheckProofOfWork(hash, header.Bits, idx.params.PowLimit); err != nil {
		return nil, ErrInvalidPoW
	}

	// Header-contextual gates (difficulty / time-too-old / BIP-94 timewarp /
	// time-too-new), in Bitcoin Core's ContextualCheckBlockHeader order. The
	// production path injects the LIVE values it has always used — the parent's
	// median-time-past and the wall clock (headerNowUnix) — and DISABLES the
	// header-level version gate (checkVersion=false) so block-version
	// enforcement stays exactly where blockbrew has always enforced it, in
	// CheckBlockContext at block-connect time. Behavior here is byte-identical
	// to the inlined checks this replaces; ContextualCheckBlockHeader is the
	// single source of truth the header differential drives with injected
	// MTP / current-time / expected-bits.
	if err := idx.ContextualCheckBlockHeader(
		header, parent, height,
		parent.GetMedianTimePast(), headerNowUnix(), nil, false,
	); err != nil {
		return nil, err
	}

	// Checkpoint verification: verify hash matches if at a checkpoint height
	if err := VerifyCheckpoint(idx.checkpointData, height, hash); err != nil {
		return nil, err
	}

	// Checkpoint fork rejection (W15 root-cause fix):
	// Previously we rejected any header whose parent was off-best-chain when the
	// candidate height was <= last checkpoint, which fired for every honest peer
	// during IBD catch-up and, coupled with a +100 misbehavior penalty, drained
	// the outbound peer pool (W8/W12/W13/W14 cascade, ref:
	// wave14-2026-04-14/BLOCKBREW-DURABILITY.md).  Replace with a conservative
	// Core-like check: reject only on an ACTUAL conflict — the candidate's
	// ancestor chain has a hash at a known-checkpoint height that differs from
	// the known checkpoint hash.  VerifyCheckpoint() already handles the
	// exact-height case for the candidate itself.
	if err := CheckForkConflictsWithCheckpoint(idx.checkpointData, parent, height); err != nil {
		return nil, err
	}

	// Calculate total work
	work := CalcWork(header.Bits)
	totalWork := new(big.Int).Add(parent.TotalWork, work)

	// G8. min_pow_checked gate (Bitcoin Core validation.cpp:4229).
	// When the caller has NOT vouched for the cumulative work (e.g. a peer
	// that bypassed the PRESYNC pipeline), verify that the new chain tip's
	// total work meets the network's MinimumChainWork threshold.  This
	// prevents low-work header flooding from peers that skip PRESYNC — they
	// cannot grow the index with headers that don't contribute enough PoW.
	// Regtest and other networks with MinimumChainWork == 0 are unaffected.
	if !minPowChecked {
		minWork := idx.params.MinimumChainWork
		if minWork != nil && minWork.Sign() > 0 && totalWork.Cmp(minWork) < 0 {
			return nil, ErrTooLittleChainwork
		}
	}

	// Create new node
	node := &BlockNode{
		Hash:      hash,
		Header:    header,
		Height:    height,
		Parent:    parent,
		TotalWork: totalWork,
		Status:    StatusHeaderValid,
		Children:  nil,
	}
	node.buildSkip()

	// Add to parent's children
	parent.Children = append(parent.Children, node)

	// Add to index
	idx.nodes[hash] = node

	// Update best tip if this chain has more work
	if totalWork.Cmp(idx.bestTip.TotalWork) > 0 {
		idx.bestTip = node
		// Update atomic cache so RPC reads don't need to take RLock
		idx.cachedBestHeight.Store(node.Height)
	}

	return node, nil
}

// ContextualCheckBlockHeader runs the header-contextual consensus gates Bitcoin
// Core applies in ContextualCheckBlockHeader (validation.cpp:4080-4124), in
// Core's exact order, over an EXPLICIT (header, parent, height) tuple with the
// time-sensitive inputs INJECTED rather than read from live state. It is the
// single source of truth for these gates: the production header path (AddHeader)
// calls it with the parent's median-time-past + the wall clock, and the
// header-level differential calls it with corpus-supplied values, so a
// divergence is one real consensus bug, not a parallel re-implementation.
//
// Inputs (Core ref in parentheses):
//   - mtp          — median-time-past of the parent's 11 ancestors. In production
//     this is parent.GetMedianTimePast(); the differential injects
//     it directly (validation.cpp:4092 "time-too-old").
//   - currentTime  — the wall-clock "adjusted time" the time-too-new gate compares
//     against (validation.cpp:4108). Production passes
//     headerNowUnix(); the differential injects it. A value of 0 is
//     a sentinel that DISABLES the time-too-new gate (used by the
//     differential's determinism control), matching the fact that
//     Core's check is the only wall-clock-dependent gate.
//   - expectedBitsOverride — when non-nil, the mandated nBits is taken from here
//     instead of recomputed via GetNextWorkRequired. Used by the
//     differential to ISOLATE a non-difficulty gate (e.g. the
//     timewarp floor) at a retarget boundary where reconstructing
//     the full 2016-block retarget context is not the gate under
//     test. Production always passes nil (real recompute).
//   - checkVersion — when true, also enforce the BIP34/66/65 mandatory-version
//     gate (validation.cpp:4112, "bad-version"). Production passes
//     FALSE so block-version enforcement stays in CheckBlockContext
//     exactly where blockbrew has always applied it (default-
//     preserving); the differential passes TRUE for full Core-parity
//     header validation.
//
// PoW (the high-hash gate, validation.cpp CheckBlockHeader/CheckProofOfWork) is
// NOT done here — AddHeader runs it before calling this, and the differential
// runs CheckProofOfWork directly — matching Core's split between CheckBlockHeader
// and ContextualCheckBlockHeader.
func (idx *HeaderIndex) ContextualCheckBlockHeader(
	header wire.BlockHeader, parent *BlockNode, height int32,
	mtp int64, currentTime int64, expectedBitsOverride *uint32, checkVersion bool,
) error {
	// (1) bad-diffbits — FIRST contextual gate (validation.cpp:4088). The
	// expected nBits comes from blockbrew's REAL GetNextWorkRequired over the
	// parent context (regtest no-retarget -> parent.bits; mainnet off-boundary
	// -> parent.bits; retarget boundary -> full recompute) unless an explicit
	// override isolates a later gate.
	var expectedBits uint32
	if expectedBitsOverride != nil {
		expectedBits = *expectedBitsOverride
	} else {
		expectedBits = GetNextWorkRequired(idx.params, height, int64(header.Timestamp), parent, idx)
	}
	if header.Bits != expectedBits {
		return ErrBadDifficulty
	}

	// (2) time-too-old (validation.cpp:4092-4093): timestamp must be STRICTLY
	// greater than the median-time-past (equal is rejected).
	if int64(header.Timestamp) <= mtp {
		return ErrTimestampTooEarly
	}

	// (3) BIP-94 timewarp (validation.cpp:4097-4104, "time-timewarp-attack"):
	// when enforced (testnet4 / regtest with EnforceBIP94) at every difficulty
	// adjustment boundary (height % 2016 == 0), the new block's timestamp must
	// not be more than MaxTimewarp (600s) behind the immediately preceding
	// block's timestamp.
	if idx.params.EnforceBIP94 && height%int32(idx.params.DifficultyAdjInterval) == 0 {
		if int64(header.Timestamp) < int64(parent.Header.Timestamp)-MaxTimewarp {
			return ErrTimeWarpAttack
		}
	}

	// (4) time-too-new (validation.cpp:4108): reject headers whose timestamp is
	// more than MaxTimeAdjustment (7200s) ahead of the adjusted wall-clock time.
	// currentTime==0 is the differential's sentinel disabling this single wall-
	// clock-dependent gate (production never passes 0).
	if currentTime != 0 && int64(header.Timestamp) > currentTime+MaxTimeAdjustment {
		return ErrTimestampTooFarFuture
	}

	// (5) bad-version (validation.cpp:4112) — only when requested (see doc). The
	// production header path leaves this to CheckBlockContext at block-connect.
	if checkVersion {
		if err := CheckBlockHeaderVersion(header.Version, height, idx.params); err != nil {
			return err
		}
	}

	return nil
}

// validateDifficulty checks that the header has the correct difficulty target.
//
// Mirrors Bitcoin Core's ContextualCheckBlockHeader (validation.cpp): compute
// expected nBits via GetNextWorkRequired and require an exact match.
// No tolerance is applied — compact encoding is deterministic and Core uses
// a direct equality check.
func (idx *HeaderIndex) validateDifficulty(header wire.BlockHeader, parent *BlockNode, height int32) error {
	// Compute the expected nBits for this block.
	expectedBits := GetNextWorkRequired(idx.params, height, int64(header.Timestamp), parent, idx)

	if header.Bits != expectedBits {
		return ErrBadDifficulty
	}
	return nil
}

// GetNode returns the BlockNode for a hash, or nil if unknown.
func (idx *HeaderIndex) GetNode(hash wire.Hash256) *BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.nodes[hash]
}

// MarkDataStored sets StatusDataStored on the node identified by hash.
// Called by the sync pipeline after StoreBlockAt succeeds, and by ConnectBlock
// on the genesis block path. Mirrors Bitcoin Core's ReceivedBlockTransactions
// which sets BLOCK_HAVE_DATA when block body data lands on disk.
// No-op if the hash is not in the index.
func (idx *HeaderIndex) MarkDataStored(hash wire.Hash256) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if node, ok := idx.nodes[hash]; ok {
		node.Status |= StatusDataStored
	}
}

// MarkUndoStored sets StatusHaveUndo on the node identified by hash.
// Called by ConnectBlock after undo data is written to disk (all paths:
// genesis, reorg-batch, regular-batch, and IBD between-flush). Mirrors
// Bitcoin Core's blockstorage.cpp:1029 where block.nStatus |= BLOCK_HAVE_UNDO
// is set after writing the CBlockUndo to rev*.dat.
// No-op if the hash is not in the index.
func (idx *HeaderIndex) MarkUndoStored(hash wire.Hash256) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if node, ok := idx.nodes[hash]; ok {
		node.Status |= StatusHaveUndo
	}
}

// BestTip returns the tip of the best (most proof-of-work) chain.
func (idx *HeaderIndex) BestTip() *BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.bestTip
}

// BestHeight returns the height of the best chain tip.
// Uses atomic cache so it never blocks on the write lock held by header validation.
func (idx *HeaderIndex) BestHeight() int32 {
	return idx.cachedBestHeight.Load()
}

// Genesis returns the genesis block node.
func (idx *HeaderIndex) Genesis() *BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.genesis
}

// PersistedHeaderSource supplies persisted headers (by hash) so the in-memory
// header index can be rehydrated on startup. Satisfied by *storage.ChainDB.
type PersistedHeaderSource interface {
	GetBlockHeader(hash wire.Hash256) (*wire.BlockHeader, error)
}

// HydrateFromDB rebuilds the in-memory header index from headers already
// persisted in the chain DB, walking the chain BACKWARD from the saved best
// block (bestHash) by following each header's PrevBlock pointer until it reaches
// genesis (or a header already in the index), then adding the collected headers
// in ascending order.
//
// Without this, a restart begins with only genesis in the index, so
// ChainManager.loadChainState cannot resolve the saved best-block and marks the
// node pendingRecovery — it then re-downloads ~every header from peers before it
// can restore the tip and resume block download (the "deferring recovery until
// headers are re-synced" path, a ~15-minute penalty on every restart, observed
// acutely on the 2026-06-06 blockbrew snapshot restore). After hydration the
// saved tip is present in the index, so loadChainState restores it immediately
// and block download resumes from the real tip. Mirrors how Bitcoin Core loads
// the block index from disk at startup rather than re-fetching it.
//
// We follow header-by-hash (PrevBlock) rather than the height->hash index
// precisely because a snapshot-bootstrapped chaindata has a GAP in the height
// index below the snapshot base (only blocks connected since the snapshot have a
// height->hash entry), whereas header sync re-downloads and persists the full
// header chain from genesis. If the on-disk chain cannot be walked all the way
// back to a header already in the index (a missing header, or a walk longer than
// maxHeight), hydration loads NOTHING and returns (0, nil): a partial chain that
// does not connect to the index would only orphan, so we degrade gracefully to
// network header sync. maxHeight (the saved chainstate height) bounds the walk.
//
// Each header is re-validated through AddHeader (PoW + contextual checks) — cheap
// and CPU-local relative to a network re-download, and it doubles as an
// integrity check. Returns the number of headers loaded; a header that fails
// revalidation (corruption / param mismatch) returns the error so the caller can
// log it non-fatally.
func (idx *HeaderIndex) HydrateFromDB(src PersistedHeaderSource, bestHash wire.Hash256, maxHeight int32) (int, error) {
	genesisHash := idx.Genesis().Hash
	if bestHash == genesisHash || idx.HasHeader(bestHash) {
		return 0, nil // nothing above what the index already holds
	}

	// Walk best -> ... -> genesis, collecting headers (best-first).
	chain := make([]*wire.BlockHeader, 0, maxHeight+1)
	h := bestHash
	for {
		if h == genesisHash || idx.HasHeader(h) {
			break // the collected chain connects to a header already in the index
		}
		if int32(len(chain)) > maxHeight+1 {
			// Longer than the saved height allows — corrupt/cyclic header store.
			// Bail; network header sync will rebuild from scratch.
			return 0, nil
		}
		hdr, err := src.GetBlockHeader(h)
		if err != nil {
			// Missing header: the on-disk chain doesn't reach the index, so any
			// partial add would orphan. Degrade to network header sync.
			return 0, nil
		}
		chain = append(chain, hdr)
		h = hdr.PrevBlock
	}

	// Add in ascending order (chain is best-first, so iterate in reverse).
	loaded := 0
	for i := len(chain) - 1; i >= 0; i-- {
		if _, err := idx.AddHeader(*chain[i], true); err != nil {
			if errors.Is(err, ErrDuplicateHeader) {
				continue
			}
			return loaded, fmt.Errorf("hydrate header (%s): %w",
				chain[i].BlockHash().String()[:16], err)
		}
		loaded++
	}
	return loaded, nil
}

// HasHeader checks if a header with the given hash exists.
func (idx *HeaderIndex) HasHeader(hash wire.Hash256) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	_, exists := idx.nodes[hash]
	return exists
}

// NodeCount returns the total number of headers in the index.
func (idx *HeaderIndex) NodeCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.nodes)
}

// LocatorHashes returns block hashes for the given locator positions.
// Used to respond to getheaders requests.
func (idx *HeaderIndex) LocatorHashes(locators []wire.Hash256, stopHash wire.Hash256, maxHeaders int) []wire.Hash256 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Find the starting point from the locators
	var startNode *BlockNode
	for _, hash := range locators {
		if node, ok := idx.nodes[hash]; ok {
			// Verify this is on the best chain
			ancestor := idx.bestTip.GetAncestor(node.Height)
			if ancestor != nil && ancestor.Hash == node.Hash {
				startNode = node
				break
			}
		}
	}

	// If no locator matched, start from genesis
	if startNode == nil {
		startNode = idx.genesis
	}

	// Collect headers starting from the block after startNode
	headers := make([]wire.Hash256, 0, maxHeaders)
	for node := startNode; node != nil && len(headers) < maxHeaders; {
		// Move to the next block on the best chain
		nextHeight := node.Height + 1
		if nextHeight > idx.bestTip.Height {
			break
		}
		nextNode := idx.bestTip.GetAncestor(nextHeight)
		if nextNode == nil {
			break
		}

		// Skip the starting node itself (we return blocks AFTER the locator)
		if node != startNode {
			headers = append(headers, node.Hash)
		}

		// Stop if we hit the stop hash
		if !stopHash.IsZero() && node.Hash == stopHash {
			break
		}

		node = nextNode
	}

	// Add the remaining nodes up to maxHeaders
	node := startNode
	for len(headers) < maxHeaders {
		nextHeight := node.Height + 1
		if nextHeight > idx.bestTip.Height {
			break
		}
		nextNode := idx.bestTip.GetAncestor(nextHeight)
		if nextNode == nil {
			break
		}
		headers = append(headers, nextNode.Hash)

		if !stopHash.IsZero() && nextNode.Hash == stopHash {
			break
		}
		node = nextNode
	}

	return headers
}

// GetHeadersAfter returns headers starting after the given hash, up to maxHeaders.
func (idx *HeaderIndex) GetHeadersAfter(startHash wire.Hash256, maxHeaders int) []wire.BlockHeader {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	startNode := idx.nodes[startHash]
	if startNode == nil {
		return nil
	}

	headers := make([]wire.BlockHeader, 0, maxHeaders)

	// Walk up from the best tip to find headers after startNode
	for height := startNode.Height + 1; height <= idx.bestTip.Height && len(headers) < maxHeaders; height++ {
		node := idx.bestTip.GetAncestor(height)
		if node != nil {
			headers = append(headers, node.Header)
		}
	}

	return headers
}

// SetPreciousBlock marks a block as "precious" for chain selection.
// When two chains have equal work, the precious block's chain is preferred.
// This is ephemeral - lost on restart. New calls override previous.
func (idx *HeaderIndex) SetPreciousBlock(node *BlockNode) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// If chain has been extended since last precious call, reset the sequence counter
	if idx.lastPreciousWork == nil || idx.bestTip.TotalWork.Cmp(idx.lastPreciousWork) > 0 {
		idx.blockSequenceID = -1
	}
	idx.lastPreciousWork = new(big.Int).Set(idx.bestTip.TotalWork)

	// Give this block a negative sequence ID (lower = more precious)
	node.SequenceID = idx.blockSequenceID
	if idx.blockSequenceID > -2147483647 { // Avoid overflow
		idx.blockSequenceID--
	}

	idx.preciousBlock = node
}

// RecalculateBestTip recalculates the best chain tip, excluding invalid blocks.
// This is called after marking blocks as invalid or reconsidering them.
func (idx *HeaderIndex) RecalculateBestTip() {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.recalculateBestTipLocked()
}

// recalculateBestTipLocked performs the actual best tip calculation (caller must hold lock).
//
// Mirrors Bitcoin Core's FindMostWorkChain (validation.cpp:3114):
//   - G1: skip candidates where StatusDataStored is absent on the candidate node itself.
//   - G3: walk the ancestor chain from the candidate back toward the active tip;
//     skip any candidate whose ancestor chain has a node with StatusDataStored absent.
//   - G5: when chain work and SequenceID are equal, use block hash as a deterministic
//     tiebreak so map-iteration order cannot influence chain selection.
func (idx *HeaderIndex) recalculateBestTipLocked() {
	var bestCandidate *BlockNode

	for _, node := range idx.nodes {
		// Skip invalid blocks (FAILED_MASK filter — G2, already correct).
		if node.Status.IsInvalid() {
			continue
		}

		// G1: skip candidates that have no block body data stored.
		if node.Status&StatusDataStored == 0 {
			continue
		}

		// G3: walk the ancestor chain to verify BLOCK_HAVE_DATA on every link.
		// Stop when we reach the genesis node (nil Parent) — genesis always has data.
		// If any ancestor is missing data, skip this candidate.
		missingAncestorData := false
		for anc := node.Parent; anc != nil; anc = anc.Parent {
			if anc.Status&StatusDataStored == 0 {
				missingAncestorData = true
				break
			}
		}
		if missingAncestorData {
			continue
		}

		// Compare against current best candidate.
		if bestCandidate == nil {
			bestCandidate = node
			continue
		}

		switch node.TotalWork.Cmp(bestCandidate.TotalWork) {
		case 1: // node has strictly more work — new best
			bestCandidate = node
		case 0: // equal work — apply tiebreaks for determinism (G5)
			// Primary tiebreak: lower SequenceID wins (precious block preference,
			// same as Core's nSequenceId ordering).
			if node.SequenceID < bestCandidate.SequenceID {
				bestCandidate = node
				break
			}
			if node.SequenceID > bestCandidate.SequenceID {
				break
			}
			// Secondary tiebreak: compare block hashes lexicographically so
			// the winner is deterministic regardless of Go map iteration order.
			// Core uses pointer address; using hash is equally arbitrary but
			// stable across restarts.
			for i := 0; i < len(node.Hash); i++ {
				if node.Hash[i] < bestCandidate.Hash[i] {
					bestCandidate = node
					break
				}
				if node.Hash[i] > bestCandidate.Hash[i] {
					break
				}
			}
		}
	}

	if bestCandidate != nil {
		idx.bestTip = bestCandidate
		// Update atomic cache so RPC reads don't need to take RLock
		idx.cachedBestHeight.Store(bestCandidate.Height)
	}
}

// ClearPreciousBlock removes the precious block designation.
func (idx *HeaderIndex) ClearPreciousBlock() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.preciousBlock = nil
}

// GetAllTips returns all chain tips (leaf nodes) in the header index.
// This is useful for implementing getchaintips RPC.
func (idx *HeaderIndex) GetAllTips() []*BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	tips := make([]*BlockNode, 0)

	// Find all nodes that have no valid children on any chain
	for _, node := range idx.nodes {
		hasValidChild := false
		for _, child := range node.Children {
			if !child.Status.IsInvalid() {
				hasValidChild = true
				break
			}
		}
		if !hasValidChild {
			tips = append(tips, node)
		}
	}

	return tips
}
