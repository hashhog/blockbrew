package consensus

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// createTestHeader creates a test block header with valid PoW for regtest.
// Uses brute force to find a valid nonce (regtest is very easy).
func createTestHeader(prevHash wire.Hash256, timestamp uint32, baseNonce uint32) wire.BlockHeader {
	header := wire.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: wire.Hash256{},
		Timestamp:  timestamp,
		Bits:       0x207fffff, // Easy regtest difficulty
		Nonce:      baseNonce,
	}

	// Find a valid nonce (regtest target is very high, so this is fast)
	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 1000000; i++ {
		header.Nonce = baseNonce + i
		hash := header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			return header
		}
	}

	// Fallback - shouldn't happen with regtest difficulty
	return header
}

func TestNewHeaderIndex(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Should have genesis
	if idx.genesis == nil {
		t.Fatal("genesis should not be nil")
	}

	if idx.BestHeight() != 0 {
		t.Errorf("best height = %d, want 0", idx.BestHeight())
	}

	if idx.BestTip().Hash != params.GenesisHash {
		t.Errorf("best tip hash = %s, want %s", idx.BestTip().Hash.String(), params.GenesisHash.String())
	}

	if idx.NodeCount() != 1 {
		t.Errorf("node count = %d, want 1", idx.NodeCount())
	}
}

func TestAddHeaderChain(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build a chain of 10 headers
	prevNode := idx.genesis
	for i := 1; i <= 10; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600, // 10 minutes later
			uint32(i),
		)

		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}

		if node.Height != int32(i) {
			t.Errorf("header %d height = %d, want %d", i, node.Height, i)
		}

		if node.Parent != prevNode {
			t.Errorf("header %d parent mismatch", i)
		}

		prevNode = node
	}

	// Verify best tip
	if idx.BestHeight() != 10 {
		t.Errorf("best height = %d, want 10", idx.BestHeight())
	}

	// Verify total work is increasing
	if idx.BestTip().TotalWork.Cmp(big.NewInt(0)) <= 0 {
		t.Error("total work should be > 0")
	}

	// Verify node count
	if idx.NodeCount() != 11 { // genesis + 10
		t.Errorf("node count = %d, want 11", idx.NodeCount())
	}
}

func TestAddDuplicateHeader(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create first header
	header := createTestHeader(
		params.GenesisHash,
		params.GenesisBlock.Header.Timestamp+600,
		1,
	)

	_, err := idx.AddHeader(header, true)
	if err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Try to add again
	_, err = idx.AddHeader(header, true)
	if err != ErrDuplicateHeader {
		t.Errorf("expected ErrDuplicateHeader, got %v", err)
	}
}

func TestAddOrphanHeader(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create header with unknown parent
	var unknownParent wire.Hash256
	unknownParent[0] = 0x12
	unknownParent[1] = 0x34

	header := createTestHeader(
		unknownParent,
		params.GenesisBlock.Header.Timestamp+600,
		1,
	)

	_, err := idx.AddHeader(header, true)
	if err != ErrOrphanHeader {
		t.Errorf("expected ErrOrphanHeader, got %v", err)
	}
}

func TestAddHeaderTimestampTooEarly(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create header with timestamp before MTP
	// MTP of genesis is just the genesis timestamp
	header := createTestHeader(
		params.GenesisHash,
		params.GenesisBlock.Header.Timestamp-1, // Before genesis
		1,
	)

	_, err := idx.AddHeader(header, true)
	if err != ErrTimestampTooEarly {
		t.Errorf("expected ErrTimestampTooEarly, got %v", err)
	}
}

func TestBlockLocator(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build a chain of 100 headers
	prevNode := idx.genesis
	for i := 1; i <= 100; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		prevNode = node
	}

	// Build locator from tip
	locator := idx.BestTip().BuildLocator()

	// Should have: 100, 99, 98, ..., 90 (first 11), then exponential
	// After 10 entries, step doubles each time
	if len(locator) == 0 {
		t.Fatal("locator should not be empty")
	}

	// First hash should be the tip
	if locator[0] != idx.BestTip().Hash {
		t.Error("first locator hash should be tip")
	}

	// Last hash should be genesis
	if locator[len(locator)-1] != idx.genesis.Hash {
		t.Error("last locator hash should be genesis")
	}

	// Verify exponential spacing after first 10
	// Heights should be: 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90
	// Then: 88 (step=2), 84 (step=4), 76 (step=8), 60 (step=16), 28 (step=32), 0 (genesis)
	// Total: 11 + 6 = 17 entries (approximately)
	if len(locator) < 10 {
		t.Errorf("locator should have at least 10 entries, got %d", len(locator))
	}

	// Verify all locator hashes exist in the index
	for i, hash := range locator {
		if idx.GetNode(hash) == nil {
			t.Errorf("locator[%d] hash %s not found in index", i, hash.String())
		}
	}
}

func TestGetAncestor(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build chain of 20 headers
	nodes := make([]*BlockNode, 21)
	nodes[0] = idx.genesis

	prevNode := idx.genesis
	for i := 1; i <= 20; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		nodes[i] = node
		prevNode = node
	}

	tip := idx.BestTip()

	// Test various ancestor lookups
	tests := []struct {
		targetHeight int32
		expected     *BlockNode
	}{
		{20, nodes[20]}, // Self
		{10, nodes[10]}, // Middle
		{0, nodes[0]},   // Genesis
		{-1, nil},       // Invalid (negative)
		{21, nil},       // Invalid (too high)
	}

	for _, tt := range tests {
		ancestor := tip.GetAncestor(tt.targetHeight)
		if ancestor != tt.expected {
			if tt.expected == nil {
				t.Errorf("GetAncestor(%d) = %v, want nil", tt.targetHeight, ancestor)
			} else {
				t.Errorf("GetAncestor(%d) = height %d, want %d",
					tt.targetHeight, ancestor.Height, tt.expected.Height)
			}
		}
	}
}

// TestGetAncestorSkipList validates the O(log N) skip-list GetAncestor against a
// naive parent-walk reference, at every height of a 2048-long chain. Guards the
// skip-pointer rewrite against off-by-one errors.
func TestGetAncestorSkipList(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	const chainLen = 2048
	prev := idx.genesis
	for i := 1; i <= chainLen; i++ {
		header := createTestHeader(prev.Hash, prev.Header.Timestamp+600, uint32(i))
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("AddHeader(%d): %v", i, err)
		}
		if node.Skip != nil && node.Skip.Height != getSkipHeight(node.Height) {
			t.Fatalf("node %d: Skip height %d, want %d",
				i, node.Skip.Height, getSkipHeight(node.Height))
		}
		prev = node
	}

	naive := func(n *BlockNode, h int32) *BlockNode {
		for n != nil && n.Height > h {
			n = n.Parent
		}
		return n
	}

	tip := idx.BestTip()
	for h := int32(0); h <= chainLen; h++ {
		got := tip.GetAncestor(h)
		want := naive(tip, h)
		if got != want {
			t.Fatalf("GetAncestor(%d): skip-list result diverges from naive walk", h)
		}
	}
}

func TestGetSkipHeight(t *testing.T) {
	// Values produced by running Bitcoin Core's GetSkipHeight formula directly.
	// Odd heights skip by only 2 under this scheme — the wins come from even
	// heights with low-order 2^k structure (6→4, 1000→992, etc.).
	cases := []struct{ in, want int32 }{
		{0, 0}, {1, 0}, {2, 0}, {3, 1}, {4, 0}, {5, 1}, {6, 4}, {7, 1},
		{8, 0}, {16, 0}, {17, 1}, {32, 0}, {1000, 992}, {1024, 0},
	}
	for _, c := range cases {
		if got := getSkipHeight(c.in); got != c.want {
			t.Errorf("getSkipHeight(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestMedianTimePast(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create a chain with known timestamps
	// Genesis timestamp is 1296688602
	timestamps := []uint32{
		1296688602, // Genesis (height 0)
		1296688800, // +198 (height 1)
		1296689000, // +200 (height 2)
		1296689100, // +100 (height 3)
		1296689200, // +100 (height 4)
		1296689300, // +100 (height 5)
		1296689400, // +100 (height 6)
		1296689500, // +100 (height 7)
		1296689600, // +100 (height 8)
		1296689700, // +100 (height 9)
		1296689800, // +100 (height 10)
		1296689900, // +100 (height 11)
	}

	prevNode := idx.genesis
	for i := 1; i < len(timestamps); i++ {
		header := createTestHeader(
			prevNode.Hash,
			timestamps[i],
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		prevNode = node
	}

	// At height 11, MTP should be median of timestamps[1..11] (11 blocks)
	// Sorted: 1296688800, 1296689000, 1296689100, 1296689200, 1296689300,
	//         1296689400, 1296689500, 1296689600, 1296689700, 1296689800, 1296689900
	// Median (index 5): 1296689400
	mtp := idx.BestTip().GetMedianTimePast()
	expected := int64(1296689400)
	if mtp != expected {
		t.Errorf("MTP = %d, want %d", mtp, expected)
	}
}

func TestFindFork(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build main chain: genesis -> 1 -> 2 -> 3 -> 4 -> 5
	prevNode := idx.genesis
	mainChain := make([]*BlockNode, 6)
	mainChain[0] = idx.genesis

	for i := 1; i <= 5; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		mainChain[i] = node
		prevNode = node
	}

	// Create fork at height 3: 3 -> 4' -> 5'
	forkNode := mainChain[2] // Fork from height 2
	forkChain := make([]*BlockNode, 3)

	for i := 0; i < 3; i++ {
		header := createTestHeader(
			forkNode.Hash,
			forkNode.Header.Timestamp+600,
			uint32(100+i), // Different nonce for different hash
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add fork header %d: %v", i, err)
		}
		forkChain[i] = node
		forkNode = node
	}

	// Find fork between main chain tip and fork chain tip
	fork := FindFork(mainChain[5], forkChain[2])
	if fork != mainChain[2] {
		t.Errorf("fork point height = %d, want 2", fork.Height)
	}

	// Find fork between same chain (should return the lower one)
	fork = FindFork(mainChain[5], mainChain[3])
	if fork != mainChain[3] {
		t.Errorf("same chain fork = %d, want 3", fork.Height)
	}

	// Find fork with nil
	fork = FindFork(nil, mainChain[3])
	if fork != nil {
		t.Error("fork with nil should be nil")
	}
}

func TestCalcWork(t *testing.T) {
	tests := []struct {
		name string
		bits uint32
	}{
		{"genesis difficulty", 0x1d00ffff},
		{"regtest difficulty", 0x207fffff},
		{"high difficulty", 0x170bdd6f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			work := CalcWork(tt.bits)

			// Work should be positive
			if work.Sign() <= 0 {
				t.Errorf("work should be positive, got %s", work.String())
			}

			// Higher difficulty (lower target) should give more work
			target := CompactToBig(tt.bits)
			if target.Sign() > 0 {
				// Sanity check: work * (target+1) should be close to 2^256
				expected := new(big.Int).Lsh(big.NewInt(1), 256)
				calculated := new(big.Int).Mul(work, new(big.Int).Add(target, big.NewInt(1)))

				// Should be within rounding error
				diff := new(big.Int).Sub(expected, calculated)
				if diff.Sign() < 0 {
					diff.Neg(diff)
				}
				if diff.Cmp(target) > 0 {
					t.Errorf("work calculation seems off: %s * (%s + 1) = %s, want ~%s",
						work.String(), target.String(), calculated.String(), expected.String())
				}
			}
		})
	}

	// Compare work values: higher difficulty = more work
	easyWork := CalcWork(0x207fffff)  // Regtest (easy)
	hardWork := CalcWork(0x1d00ffff)  // Genesis (harder)
	harderWork := CalcWork(0x170bdd6f) // High difficulty

	if easyWork.Cmp(hardWork) >= 0 {
		t.Error("easy difficulty should have less work than genesis difficulty")
	}
	if hardWork.Cmp(harderWork) >= 0 {
		t.Error("genesis difficulty should have less work than high difficulty")
	}
}

func TestTotalWorkAccumulation(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build a chain and verify work accumulates
	prevNode := idx.genesis
	prevWork := prevNode.TotalWork

	for i := 1; i <= 5; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}

		// Total work should increase
		if node.TotalWork.Cmp(prevWork) <= 0 {
			t.Errorf("header %d total work did not increase", i)
		}

		// Total work should equal parent work + this block's work
		blockWork := CalcWork(header.Bits)
		expectedWork := new(big.Int).Add(prevNode.TotalWork, blockWork)
		if node.TotalWork.Cmp(expectedWork) != 0 {
			t.Errorf("header %d total work = %s, want %s",
				i, node.TotalWork.String(), expectedWork.String())
		}

		prevNode = node
		prevWork = node.TotalWork
	}
}

func TestBestChainSelection(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build initial chain: genesis -> 1 -> 2
	prevNode := idx.genesis
	for i := 1; i <= 2; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		prevNode = node
	}

	// Best tip should be at height 2
	if idx.BestHeight() != 2 {
		t.Errorf("best height = %d, want 2", idx.BestHeight())
	}

	// Create a longer fork from genesis: genesis -> A -> B -> C
	forkNode := idx.genesis
	for i := 0; i < 3; i++ {
		header := createTestHeader(
			forkNode.Hash,
			forkNode.Header.Timestamp+600,
			uint32(200+i), // Different nonce
		)
		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add fork header %d: %v", i, err)
		}
		forkNode = node
	}

	// Best tip should now be the longer fork (height 3)
	if idx.BestHeight() != 3 {
		t.Errorf("best height = %d, want 3 (longer fork)", idx.BestHeight())
	}

	if idx.BestTip() != forkNode {
		t.Error("best tip should be the fork chain tip")
	}
}

func TestHasHeader(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Genesis should exist
	if !idx.HasHeader(params.GenesisHash) {
		t.Error("genesis should exist")
	}

	// Random hash should not exist
	var randomHash wire.Hash256
	randomHash[0] = 0xAB
	randomHash[1] = 0xCD
	if idx.HasHeader(randomHash) {
		t.Error("random hash should not exist")
	}

	// Add a header and check
	header := createTestHeader(
		params.GenesisHash,
		params.GenesisBlock.Header.Timestamp+600,
		1,
	)
	node, _ := idx.AddHeader(header, true)

	if !idx.HasHeader(node.Hash) {
		t.Error("newly added header should exist")
	}
}

func TestGetNode(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Get genesis
	genesisNode := idx.GetNode(params.GenesisHash)
	if genesisNode == nil {
		t.Fatal("genesis node should not be nil")
	}
	if genesisNode.Height != 0 {
		t.Errorf("genesis height = %d, want 0", genesisNode.Height)
	}

	// Get non-existent
	var randomHash wire.Hash256
	randomHash[0] = 0xFF
	if idx.GetNode(randomHash) != nil {
		t.Error("random hash should return nil")
	}
}

func TestBlockNodeChildren(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Genesis should have no children initially
	if len(idx.genesis.Children) != 0 {
		t.Errorf("genesis should have 0 children, got %d", len(idx.genesis.Children))
	}

	// Add a child
	header := createTestHeader(
		params.GenesisHash,
		params.GenesisBlock.Header.Timestamp+600,
		1,
	)
	child, _ := idx.AddHeader(header, true)

	// Genesis should now have one child
	if len(idx.genesis.Children) != 1 {
		t.Errorf("genesis should have 1 child, got %d", len(idx.genesis.Children))
	}

	if idx.genesis.Children[0] != child {
		t.Error("genesis child mismatch")
	}

	// Add another child (fork)
	header2 := createTestHeader(
		params.GenesisHash,
		params.GenesisBlock.Header.Timestamp+700,
		2, // Different nonce
	)
	child2, _ := idx.AddHeader(header2, true)

	// Genesis should have two children
	if len(idx.genesis.Children) != 2 {
		t.Errorf("genesis should have 2 children, got %d", len(idx.genesis.Children))
	}

	// Both children should be in the list
	foundChild1, foundChild2 := false, false
	for _, c := range idx.genesis.Children {
		if c == child {
			foundChild1 = true
		}
		if c == child2 {
			foundChild2 = true
		}
	}
	if !foundChild1 || !foundChild2 {
		t.Error("not all children found in genesis.Children")
	}
}

// TestBestHeightCache verifies that BestHeight uses atomic cache and returns correct values.
func TestBestHeightCache(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Genesis starts at height 0
	if idx.BestHeight() != 0 {
		t.Errorf("initial best height = %d, want 0", idx.BestHeight())
	}

	// Verify cache is initialized
	if idx.cachedBestHeight.Load() != 0 {
		t.Errorf("initial cache value = %d, want 0", idx.cachedBestHeight.Load())
	}

	// Add headers and verify cache is updated
	prevNode := idx.genesis
	for i := 1; i <= 5; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)

		node, err := idx.AddHeader(header, true)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}

		// Verify BestHeight returns correct value
		if idx.BestHeight() != int32(i) {
			t.Errorf("after adding header %d, best height = %d, want %d", i, idx.BestHeight(), i)
		}

		// Verify cache is updated
		if idx.cachedBestHeight.Load() != int32(i) {
			t.Errorf("after adding header %d, cached height = %d, want %d", i, idx.cachedBestHeight.Load(), i)
		}

		prevNode = node
	}

	// Verify BestHeight and cache are consistent with BestTip
	bestHeight := idx.BestHeight()
	bestTip := idx.BestTip()
	if bestHeight != bestTip.Height {
		t.Errorf("BestHeight(%d) != BestTip.Height(%d)", bestHeight, bestTip.Height)
	}
}

// TestAddHeaderRejectsFarFutureTimestamp verifies the BIP-130/Core
// `ContextualCheckBlockHeader` future-time check at the header-acceptance
// gate.  Without this check an adversarial peer can grow the in-memory
// header index with far-future headers that only fail at block validation.
//
// We pin the wall-clock to a value above the regtest genesis timestamp,
// then attempt to add a header timestamped MaxTimeAdjustment+1 seconds in
// the future.  AddHeader must return ErrTimestampTooFarFuture and must NOT
// add the node to the index.
func TestAddHeaderRejectsFarFutureTimestamp(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Pin "now" to a deterministic value clearly past the regtest genesis
	// (1296688602) so the future-window math is unambiguous.
	pinnedNow := int64(2_000_000_000) // 2033-05-18 UTC, well after regtest genesis
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	// Header timestamp 7201 seconds ahead of pinnedNow == one second past the
	// 2-hour future-time window.  Must be rejected.
	farFutureTS := uint32(pinnedNow + MaxTimeAdjustment + 1)
	header := createTestHeader(params.GenesisHash, farFutureTS, 1)

	_, err := idx.AddHeader(header, true)
	if err != ErrTimestampTooFarFuture {
		t.Fatalf("AddHeader(far-future) err = %v, want ErrTimestampTooFarFuture", err)
	}

	// Header must not have been admitted to the index.
	if idx.NodeCount() != 1 {
		t.Errorf("NodeCount = %d after rejected far-future header, want 1 (genesis only)",
			idx.NodeCount())
	}
	if idx.BestHeight() != 0 {
		t.Errorf("BestHeight = %d after rejected far-future header, want 0", idx.BestHeight())
	}
}

// TestAddHeaderAcceptsTimestampAtFutureBoundary verifies the future-time
// check is inclusive of `now + MaxTimeAdjustment` (matching Core's
// `nTime <= nAdjustedTime + MAX_FUTURE_BLOCK_TIME`) and admits headers at
// the exact boundary.  This guards against an off-by-one that would reject
// honest peers whose clock is ~7200s ahead.
func TestAddHeaderAcceptsTimestampAtFutureBoundary(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	// Boundary timestamp: pinnedNow + MaxTimeAdjustment exactly.
	boundaryTS := uint32(pinnedNow + MaxTimeAdjustment)
	header := createTestHeader(params.GenesisHash, boundaryTS, 1)

	node, err := idx.AddHeader(header, true)
	if err != nil {
		t.Fatalf("AddHeader(boundary) err = %v, want nil", err)
	}
	if node == nil || node.Height != 1 {
		t.Fatalf("AddHeader(boundary) node = %+v, want height 1", node)
	}
}

// buildBIP94Chain builds a chain of n blocks (heights 1..n) suitable for
// testing the BIP-94 timewarp gate.  The first n-1 blocks have small,
// monotonically increasing timestamps so that the MTP at block n-1 is low.
// The last block (n) has a much larger timestamp; this is used as the "prev"
// when testing whether a boundary block is accepted or rejected.
//
// The trick: to isolate the BIP-94 gate from the MTP gate we need a chain
// where MTP << prevBlock.Timestamp.  We achieve this by making blocks 1..10
// advance their timestamps by only 1 second each, then giving block 11 a big
// jump.  The MTP at block 11 is then approximately genesis+5 (median of 11
// values in a slowly-increasing series), while block 11's own timestamp is far
// above that.
//
// Returns the HeaderIndex and the tip BlockNode (height n).
func buildBIP94Chain(t *testing.T, params *ChainParams, n int, pinnedNow int64) (*HeaderIndex, *BlockNode) {
	t.Helper()
	idx := NewHeaderIndex(params)

	// Blocks 1..(n-1): slow-walk timestamps so MTP stays low.
	genTS := int64(params.GenesisBlock.Header.Timestamp)
	prevNode := idx.genesis
	for i := 1; i < n; i++ {
		ts := uint32(genTS + int64(i)) // +1s per block
		hdr := createTestHeader(prevNode.Hash, ts, uint32(i))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("buildBIP94Chain height %d: AddHeader err = %v", i, err)
		}
		prevNode = node
	}

	// Block n: big timestamp jump so block n's timestamp is well above MTP.
	bigTS := uint32(pinnedNow - 20_000)
	hdrN := createTestHeader(prevNode.Hash, bigTS, uint32(n))
	nodeN, err := idx.AddHeader(hdrN, true)
	if err != nil {
		t.Fatalf("buildBIP94Chain height %d (big-jump): AddHeader err = %v", n, err)
	}
	return idx, nodeN
}

// TestBIP94TimewarpRejected verifies that AddHeader rejects a block at a
// difficulty adjustment boundary whose timestamp is more than MaxTimewarp (600s)
// behind the previous block's timestamp (validation.cpp:4097-4104,
// "time-timewarp-attack").
//
// Strategy: use DifficultyAdjInterval=12, build heights 1..11 with slow-
// walking timestamps + a big jump on h11, then test h12 (the boundary).
// At h11 the MTP is approximately genesis+5 (well below bigTS), so a
// candidate timestamp of bigTS - MaxTimewarp - 1 passes the MTP gate but
// fails the BIP-94 gate.
func TestBIP94TimewarpRejected(t *testing.T) {
	params := *RegtestParams()
	params.EnforceBIP94 = true
	params.DifficultyAdjInterval = 12 // boundary at height 12
	params.TargetTimespan = 12 * 10 * 60
	params.TargetSpacing = 10 * 60

	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx, node11 := buildBIP94Chain(t, &params, 11, pinnedNow)

	// Height 12 is the first adjustment boundary.
	// timestamp = node11.Timestamp - MaxTimewarp - 1 → ErrTimeWarpAttack.
	tooEarlyTS := uint32(int64(node11.Header.Timestamp) - MaxTimewarp - 1)

	// Sanity: tooEarlyTS must be above MTP at node11 (otherwise MTP fires first).
	mtp11 := node11.GetMedianTimePast()
	if int64(tooEarlyTS) <= mtp11 {
		t.Skipf("tooEarlyTS %d <= MTP %d; test precondition not met — bigTS too small?",
			tooEarlyTS, mtp11)
	}

	h12bad := createTestHeader(node11.Hash, tooEarlyTS, 1)
	_, err := idx.AddHeader(h12bad, true)
	if err != ErrTimeWarpAttack {
		t.Fatalf("height 12 (timewarp attack): AddHeader err = %v, want ErrTimeWarpAttack", err)
	}

	// Index must not have grown beyond genesis + h1..h11.
	if idx.NodeCount() != 12 {
		t.Errorf("NodeCount = %d after rejected timewarp header, want 12", idx.NodeCount())
	}
}

// TestBIP94TimewarpBoundaryAccepted verifies that a block at the adjustment
// boundary with timestamp exactly equal to prevBlock.Timestamp - MaxTimewarp
// is accepted (the check is strict less-than, so the boundary value is valid).
// Core: block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP
func TestBIP94TimewarpBoundaryAccepted(t *testing.T) {
	params := *RegtestParams()
	params.EnforceBIP94 = true
	params.DifficultyAdjInterval = 12
	params.TargetTimespan = 12 * 10 * 60
	params.TargetSpacing = 10 * 60

	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx, node11 := buildBIP94Chain(t, &params, 11, pinnedNow)

	// Exactly at the boundary: prevTS - MaxTimewarp.
	// Core rejects strictly less than, so this exact value is valid.
	boundaryTS := uint32(int64(node11.Header.Timestamp) - MaxTimewarp)

	mtp11 := node11.GetMedianTimePast()
	if int64(boundaryTS) <= mtp11 {
		t.Skipf("boundaryTS %d <= MTP %d; test precondition not met", boundaryTS, mtp11)
	}

	h12 := createTestHeader(node11.Hash, boundaryTS, 1)
	node12, err := idx.AddHeader(h12, true)
	if err != nil {
		t.Fatalf("height 12 (timewarp boundary exact): AddHeader err = %v, want nil", err)
	}
	if node12 == nil || node12.Height != 12 {
		t.Fatalf("height 12 (timewarp boundary exact): node = %+v, want height 12", node12)
	}
}

// TestBIP94TimewarpNotAppliedOnMainnet verifies that the timewarp check is
// skipped for networks without EnforceBIP94 (e.g., mainnet).
func TestBIP94TimewarpNotAppliedOnMainnet(t *testing.T) {
	params := *RegtestParams()
	params.EnforceBIP94 = false
	params.DifficultyAdjInterval = 12
	params.TargetTimespan = 12 * 10 * 60
	params.TargetSpacing = 10 * 60

	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx, node11 := buildBIP94Chain(t, &params, 11, pinnedNow)

	// Timestamp that would fail BIP-94 (< prevTS - MaxTimewarp - 1)
	// but must pass without EnforceBIP94.
	tooEarlyTS := uint32(int64(node11.Header.Timestamp) - MaxTimewarp - 1)

	mtp11 := node11.GetMedianTimePast()
	if int64(tooEarlyTS) <= mtp11 {
		t.Skipf("tooEarlyTS %d <= MTP %d; test precondition not met", tooEarlyTS, mtp11)
	}

	h12 := createTestHeader(node11.Hash, tooEarlyTS, 1)
	_, err := idx.AddHeader(h12, true)
	if err != nil {
		t.Fatalf("height 12 (no BIP94 enforcement): AddHeader err = %v, want nil", err)
	}
}

// TestBIP94TimewarpNotAppliedAtNonAdjustmentHeight verifies that the timewarp
// check fires only at adjustment boundaries, not at intermediate heights.
func TestBIP94TimewarpNotAppliedAtNonAdjustmentHeight(t *testing.T) {
	// DifficultyAdjInterval = 12 so boundary is at height 12.
	// Heights 1..11 are not boundaries — even a large backwards jump is OK.
	params := *RegtestParams()
	params.EnforceBIP94 = true
	params.DifficultyAdjInterval = 12
	params.TargetTimespan = 12 * 10 * 60
	params.TargetSpacing = 10 * 60

	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	// Build heights 1..10 slowly, then attempt height 11 (non-boundary) with
	// a timestamp far behind the previous block but above the chain MTP.
	idx, node10 := buildBIP94Chain(t, &params, 10, pinnedNow)

	// node10 has a big-jump timestamp (pinnedNow - 20_000).
	// Height 11 is NOT a boundary (11 % 12 != 0), so a far-back timestamp
	// should be accepted (subject only to MTP).
	tooEarlyTS := uint32(int64(node10.Header.Timestamp) - MaxTimewarp - 1)

	mtp10 := node10.GetMedianTimePast()
	if int64(tooEarlyTS) <= mtp10 {
		t.Skipf("tooEarlyTS %d <= MTP %d; test precondition not met", tooEarlyTS, mtp10)
	}

	h11 := createTestHeader(node10.Hash, tooEarlyTS, 1)
	_, err := idx.AddHeader(h11, true)
	if err != nil {
		t.Fatalf("height 11 (non-boundary with BIP94): AddHeader err = %v, want nil", err)
	}
}

// TestGetMedianTimePastN1 verifies GetMedianTimePast for a chain of exactly 1
// block (the genesis itself): MTP == genesis timestamp.
func TestGetMedianTimePastN1(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	mtp := idx.genesis.GetMedianTimePast()
	if mtp != int64(params.GenesisBlock.Header.Timestamp) {
		t.Errorf("N=1 MTP = %d, want %d", mtp, params.GenesisBlock.Header.Timestamp)
	}
}

// TestGetMedianTimePastN5 verifies GetMedianTimePast for a chain of 5 blocks.
// With 5 timestamps sorted, the median is at index 2.
func TestGetMedianTimePastN5(t *testing.T) {
	params := RegtestParams()
	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx := NewHeaderIndex(params)

	// Build 5 blocks with monotonically increasing timestamps.
	timestamps := []uint32{
		params.GenesisBlock.Header.Timestamp, // height 0
		uint32(pinnedNow - 40_000),           // height 1
		uint32(pinnedNow - 30_000),           // height 2
		uint32(pinnedNow - 20_000),           // height 3
		uint32(pinnedNow - 10_000),           // height 4
		uint32(pinnedNow - 5_000),            // height 5
	}

	prevNode := idx.genesis
	for i := 1; i < len(timestamps); i++ {
		hdr := createTestHeader(prevNode.Hash, timestamps[i], uint32(i))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("height %d: AddHeader err = %v", i, err)
		}
		prevNode = node
	}

	// At height 5, MTP = GetMedianTimePast() of node at height 5.
	// Collects timestamps from heights 5,4,3,2,1 (5 values since 5 < 11).
	// Sorted ascending, median = index 5/2 = index 2.
	ts := timestamps[1:] // heights 1..5, most-recent-first in collection
	_ = ts               // collected in descending order then sorted
	// Sorted: ts[4]<ts[3]<ts[2]<ts[1]<ts[0]  (all ascending already)
	// After sort: [pinnedNow-40k, pinnedNow-30k, pinnedNow-20k, pinnedNow-10k, pinnedNow-5k]
	// Median at [5/2] = [2] = pinnedNow-20k
	expected := int64(pinnedNow - 20_000)
	got := prevNode.GetMedianTimePast()
	if got != expected {
		t.Errorf("N=5 MTP = %d, want %d", got, expected)
	}
}

// TestGetMedianTimePastN10 verifies the 10-block case (just below the 11-block cap).
func TestGetMedianTimePastN10(t *testing.T) {
	params := RegtestParams()
	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx := NewHeaderIndex(params)

	// Build 10 additional blocks (heights 1..10).
	prevNode := idx.genesis
	for i := 1; i <= 10; i++ {
		ts := uint32(pinnedNow - int64(11-i)*10_000)
		hdr := createTestHeader(prevNode.Hash, ts, uint32(i))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("height %d: AddHeader err = %v", i, err)
		}
		prevNode = node
	}

	// At height 10, MTP collects from heights 10..0 (11 entries including
	// genesis, since 10 < MedianTimeSpan).
	// Values: genesis (1296688602), h1 (pinnedNow-100k), h2 (pinnedNow-90k),
	//         ..., h10 (pinnedNow-10k).
	// After sort: [genesis, pinnedNow-100k, -90k, -80k, -70k, -60k,
	//              -50k, -40k, -30k, -20k, -10k] (11 values, genesis is tiny).
	// Median at [11/2] = [5] = the 6th value = pinnedNow-60k
	expected := int64(pinnedNow - 60_000)
	got := prevNode.GetMedianTimePast()
	if got != expected {
		t.Errorf("N=10 MTP = %d, want %d", got, expected)
	}
}

// TestGetMedianTimePastN12 verifies that GetMedianTimePast caps at 11 entries
// even when more than 11 ancestors exist.  A chain of 12 blocks should use
// only the most-recent 11 timestamps.
func TestGetMedianTimePastN12(t *testing.T) {
	params := RegtestParams()
	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx := NewHeaderIndex(params)

	// Build 12 blocks.  Heights 1..12; timestamps ascending.
	prevNode := idx.genesis
	for i := 1; i <= 12; i++ {
		ts := uint32(pinnedNow - int64(13-i)*10_000)
		hdr := createTestHeader(prevNode.Hash, ts, uint32(i))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("height %d: AddHeader err = %v", i, err)
		}
		prevNode = node
	}

	// At height 12, MTP collects from heights 12..2 (11 entries, capped).
	// Heights 2..12 timestamps: pinnedNow-110k, -100k, ..., -10k
	// (heights 2 through 12 inclusive, values -110k to -10k in steps of 10k)
	// After sort: same order.  Median at [11/2] = [5] = pinnedNow-60k
	expected := int64(pinnedNow - 60_000)
	got := prevNode.GetMedianTimePast()
	if got != expected {
		t.Errorf("N=12 MTP (capped at 11) = %d, want %d", got, expected)
	}
}

// TestMTPTimeOldBoundaryStrict verifies that the MTP check is strict (<=),
// not non-strict.  A block with timestamp == MTP must be rejected; a block
// with timestamp == MTP+1 must be accepted.
func TestMTPTimeOldBoundaryStrict(t *testing.T) {
	params := RegtestParams()
	pinnedNow := int64(2_000_000_000)
	prevNow := headerNowUnix
	headerNowUnix = func() int64 { return pinnedNow }
	defer func() { headerNowUnix = prevNow }()

	idx := NewHeaderIndex(params)

	// Build 11 blocks with known timestamps so we can predict MTP exactly.
	timestamps := [12]uint32{
		params.GenesisBlock.Header.Timestamp, // height 0 — genesis
	}
	for i := 1; i <= 11; i++ {
		timestamps[i] = uint32(pinnedNow - int64(12-i)*1_000)
	}
	prevNode := idx.genesis
	for i := 1; i <= 11; i++ {
		hdr := createTestHeader(prevNode.Hash, timestamps[i], uint32(i))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("height %d: AddHeader err = %v", i, err)
		}
		prevNode = node
	}

	// MTP at height 11: collects timestamps[1..11] (11 values), sorted ascending,
	// median at index 5.
	mtp := prevNode.GetMedianTimePast()

	// Reject: timestamp == MTP (strict <=).
	badHdr := createTestHeader(prevNode.Hash, uint32(mtp), 1)
	_, err := idx.AddHeader(badHdr, true)
	if err != ErrTimestampTooEarly {
		t.Fatalf("timestamp == MTP: AddHeader err = %v, want ErrTimestampTooEarly", err)
	}

	// Accept: timestamp == MTP + 1.
	goodHdr := createTestHeader(prevNode.Hash, uint32(mtp)+1, 2)
	node12, err := idx.AddHeader(goodHdr, true)
	if err != nil {
		t.Fatalf("timestamp == MTP+1: AddHeader err = %v, want nil", err)
	}
	if node12 == nil || node12.Height != 12 {
		t.Fatalf("timestamp == MTP+1: node = %+v, want height 12", node12)
	}
}
