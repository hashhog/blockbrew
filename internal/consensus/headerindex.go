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
	ErrOrphanHeader       = errors.New("header has unknown parent")
	ErrDuplicateHeader    = errors.New("header already exists")
	ErrInvalidPoW         = errors.New("header has invalid proof of work")
	ErrTimestampTooEarly  = errors.New("header timestamp is before median time past")
	ErrBadDifficulty      = errors.New("header has incorrect difficulty bits")
	ErrCheckpointMismatch = errors.New("header does not match checkpoint")
)

// BlockStatus tracks the validation state of a block.
type BlockStatus uint32

const (
	StatusHeaderValid BlockStatus = 1 << 0 // Header passed PoW and basic checks
	StatusDataStored  BlockStatus = 1 << 1 // Full block data is stored
	StatusFullyValid  BlockStatus = 1 << 2 // Block passed full validation
	StatusInvalid     BlockStatus = 1 << 3 // Block is known invalid
)

// BlockNode represents a block header in the header chain.
type BlockNode struct {
	Hash      wire.Hash256
	Header    wire.BlockHeader
	Height    int32
	Parent    *BlockNode
	TotalWork *big.Int      // Cumulative chain work up to this block
	Status    BlockStatus   // Validation state
	Children  []*BlockNode  // Potential forks
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

// Checkpoint represents a known-good block hash at a specific height.
type Checkpoint struct {
	Height int32
	Hash   wire.Hash256
}

// HeaderIndex maintains the tree of block headers.
type HeaderIndex struct {
	mu           sync.RWMutex
	nodes        map[wire.Hash256]*BlockNode // All known block nodes
	bestTip      *BlockNode                  // Tip of the best (most work) chain
	genesis      *BlockNode                  // The genesis block node
	params       *ChainParams                // Chain parameters
	checkpoints  map[int32]wire.Hash256      // Height -> expected hash
}

// NewHeaderIndex creates a new header index with the genesis block.
func NewHeaderIndex(params *ChainParams) *HeaderIndex {
	idx := &HeaderIndex{
		nodes:       make(map[wire.Hash256]*BlockNode),
		params:      params,
		checkpoints: make(map[int32]wire.Hash256),
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

	// Add mainnet checkpoints
	idx.loadCheckpoints()

	return idx
}

// loadCheckpoints adds known-good block hashes for checkpoint verification.
func (idx *HeaderIndex) loadCheckpoints() {
	if idx.params.Name != "mainnet" {
		return
	}

	checkpoints := []Checkpoint{
		{11111, mustParseHash("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
		{33333, mustParseHash("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
		{74000, mustParseHash("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
		{105000, mustParseHash("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
		{134444, mustParseHash("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
		{168000, mustParseHash("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
		{193000, mustParseHash("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
		{210000, mustParseHash("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
		{250000, mustParseHash("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		{295000, mustParseHash("00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
	}

	for _, cp := range checkpoints {
		idx.checkpoints[cp.Height] = cp.Hash
	}
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

	// Check against checkpoints
	if expectedHash, ok := idx.checkpoints[height]; ok {
		if hash != expectedHash {
			return nil, ErrCheckpointMismatch
		}
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
	// Check for testnet min difficulty rule
	if idx.params.MinDiffReductionTime {
		if IsMinDifficultyBlock(idx.params, int64(header.Timestamp), int64(parent.Header.Timestamp)) {
			// On testnet, if block is > 20 minutes after prev, difficulty can be PowLimitBits
			if header.Bits == idx.params.PowLimitBits {
				return nil
			}
		}
	}

	// At difficulty adjustment boundaries (every 2016 blocks)
	if height%int32(idx.params.DifficultyAdjInterval) == 0 {
		return idx.validateDifficultyAdjustment(header, parent, height)
	}

	// Non-adjustment block should have same difficulty as parent
	// (except for testnet min difficulty which was checked above)
	if !idx.params.MinDiffReductionTime && header.Bits != parent.Header.Bits {
		return ErrBadDifficulty
	}

	return nil
}

// validateDifficultyAdjustment validates the difficulty at a 2016 block boundary.
func (idx *HeaderIndex) validateDifficultyAdjustment(header wire.BlockHeader, parent *BlockNode, height int32) error {
	// Find the first block in this difficulty period
	blocksBack := int32(idx.params.DifficultyAdjInterval) - 1
	firstNode := parent
	for i := int32(0); i < blocksBack && firstNode.Parent != nil; i++ {
		firstNode = firstNode.Parent
	}

	// Calculate expected difficulty
	expectedBits := CalcNextRequiredDifficulty(
		idx.params,
		parent.Header.Bits,
		int64(firstNode.Header.Timestamp),
		int64(parent.Header.Timestamp),
	)

	// Allow small rounding differences by comparing the actual targets
	expectedTarget := CompactToBig(expectedBits)
	actualTarget := CompactToBig(header.Bits)

	// Targets must match (or be very close due to compact encoding rounding)
	if actualTarget.Cmp(expectedTarget) != 0 {
		// Check if they're within 0.1% of each other (compact encoding can round)
		diff := new(big.Int).Sub(actualTarget, expectedTarget)
		diff.Abs(diff)
		tolerance := new(big.Int).Div(expectedTarget, big.NewInt(1000))
		if diff.Cmp(tolerance) > 0 {
			return ErrBadDifficulty
		}
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
