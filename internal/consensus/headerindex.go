package consensus

import (
	"errors"
	"math/big"
	"sort"
	"sync"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Header validation errors.
var (
	ErrOrphanHeader         = errors.New("header has unknown parent")
	ErrDuplicateHeader      = errors.New("header already exists")
	ErrInvalidPoW           = errors.New("header has invalid proof of work")
	ErrTimestampTooEarly    = errors.New("header timestamp is before median time past")
	ErrBadDifficulty        = errors.New("header has incorrect difficulty bits")
	ErrCheckpointMismatch   = errors.New("header does not match checkpoint")
	ErrForkBeforeCheckpoint = errors.New("fork before last checkpoint is not allowed")
)

// BlockStatus tracks the validation state of a block.
type BlockStatus uint32

const (
	StatusHeaderValid BlockStatus = 1 << 0 // Header passed PoW and basic checks
	StatusDataStored  BlockStatus = 1 << 1 // Full block data is stored
	StatusFullyValid  BlockStatus = 1 << 2 // Block passed full validation
	StatusInvalid     BlockStatus = 1 << 3 // Block is known invalid (explicitly marked via invalidateblock)
	StatusInvalidChild BlockStatus = 1 << 4 // Block is invalid because ancestor is invalid
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
	TotalWork  *big.Int      // Cumulative chain work up to this block
	Status     BlockStatus   // Validation state
	Children   []*BlockNode  // Potential forks
	SequenceID int32         // Sequence ID for precious block ordering (lower = more precious)
}

// GetAncestor returns the ancestor of a node at a given height.
// Returns nil if the height is invalid or this node doesn't have an ancestor at that height.
func (n *BlockNode) GetAncestor(height int32) *BlockNode {
	if height < 0 || height > n.Height {
		return nil
	}
	if height == n.Height {
		return n
	}

	// Walk up the chain until we reach the target height
	node := n
	for node != nil && node.Height > height {
		node = node.Parent
	}
	return node
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
	mu              sync.RWMutex
	nodes           map[wire.Hash256]*BlockNode // All known block nodes
	bestTip         *BlockNode                  // Tip of the best (most work) chain
	genesis         *BlockNode                  // The genesis block node
	params          *ChainParams                // Chain parameters
	checkpointData  *CheckpointData             // Checkpoint verification data

	// Precious block tracking
	preciousBlock       *BlockNode // The block designated as precious (ephemeral)
	lastPreciousWork    *big.Int   // Chainwork when last precious call was made
	blockSequenceID     int32      // Sequence counter for precious block tie-breaking
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
		Status:    StatusHeaderValid | StatusFullyValid,
		Children:  nil,
	}

	idx.nodes[genesisNode.Hash] = genesisNode
	idx.genesis = genesisNode
	idx.bestTip = genesisNode

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
func (idx *HeaderIndex) AddHeader(header wire.BlockHeader) (*BlockNode, error) {
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

	// Check timestamp > median time past
	mtp := parent.GetMedianTimePast()
	if int64(header.Timestamp) <= mtp {
		return nil, ErrTimestampTooEarly
	}

	// Validate difficulty at adjustment boundaries
	if err := idx.validateDifficulty(header, parent, height); err != nil {
		return nil, err
	}

	// Checkpoint verification: verify hash matches if at a checkpoint height
	if err := VerifyCheckpoint(idx.checkpointData, height, hash); err != nil {
		return nil, err
	}

	// Checkpoint fork rejection: reject headers that would fork before the last checkpoint.
	// A header creates a fork if there's already a different block at this height on the best chain.
	isFork := idx.wouldCreateFork(parent, height)
	if err := CheckForkBeforeLastCheckpoint(idx.checkpointData, height, isFork); err != nil {
		return nil, err
	}

	// Calculate total work
	work := CalcWork(header.Bits)
	totalWork := new(big.Int).Add(parent.TotalWork, work)

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

	// Add to parent's children
	parent.Children = append(parent.Children, node)

	// Add to index
	idx.nodes[hash] = node

	// Update best tip if this chain has more work
	if totalWork.Cmp(idx.bestTip.TotalWork) > 0 {
		idx.bestTip = node
	}

	return node, nil
}

// validateDifficulty checks that the header has the correct difficulty target.
func (idx *HeaderIndex) validateDifficulty(header wire.BlockHeader, parent *BlockNode, height int32) error {
	// Use GetNextWorkRequired to calculate the expected difficulty
	expectedBits := GetNextWorkRequired(idx.params, height, int64(header.Timestamp), parent, idx)

	// For regtest with no-retargeting, just check against expected
	if idx.params.PowNoRetargeting {
		if header.Bits != expectedBits {
			return ErrBadDifficulty
		}
		return nil
	}

	// For testnet, min-difficulty blocks are allowed when > 20 min gap
	if idx.params.MinDiffReductionTime {
		if IsMinDifficultyBlock(idx.params, int64(header.Timestamp), int64(parent.Header.Timestamp)) {
			// Block can use either min difficulty or the expected difficulty
			if header.Bits == idx.params.PowLimitBits {
				return nil
			}
		}
	}

	// Compare expected vs actual bits
	if header.Bits == expectedBits {
		return nil
	}

	// Allow small rounding differences by comparing the actual targets
	expectedTarget := CompactToBig(expectedBits)
	actualTarget := CompactToBig(header.Bits)

	// Targets must match (or be very close due to compact encoding rounding)
	diff := new(big.Int).Sub(actualTarget, expectedTarget)
	diff.Abs(diff)
	tolerance := new(big.Int).Div(expectedTarget, big.NewInt(1000))
	if diff.Cmp(tolerance) > 0 {
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

// BestTip returns the tip of the best (most proof-of-work) chain.
func (idx *HeaderIndex) BestTip() *BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.bestTip
}

// BestHeight returns the height of the best chain tip.
func (idx *HeaderIndex) BestHeight() int32 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.bestTip.Height
}

// Genesis returns the genesis block node.
func (idx *HeaderIndex) Genesis() *BlockNode {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.genesis
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
func (idx *HeaderIndex) recalculateBestTipLocked() {
	var bestCandidate *BlockNode

	// Find all chain tips (nodes with no children or only invalid children)
	for _, node := range idx.nodes {
		// Skip invalid blocks
		if node.Status.IsInvalid() {
			continue
		}

		// Check if this could be a tip (better than current best candidate)
		if bestCandidate == nil {
			bestCandidate = node
			continue
		}

		// Compare using work and sequence ID
		switch node.TotalWork.Cmp(bestCandidate.TotalWork) {
		case 1: // node has more work
			bestCandidate = node
		case 0: // equal work - use sequence ID (precious block preference)
			if node.SequenceID < bestCandidate.SequenceID {
				bestCandidate = node
			}
		}
	}

	if bestCandidate != nil {
		idx.bestTip = bestCandidate
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
