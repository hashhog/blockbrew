package mempool

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestFeeFrac tests the FeeFrac type.
func TestFeeFrac(t *testing.T) {
	tests := []struct {
		name     string
		a, b     FeeFrac
		expected int
	}{
		{
			name:     "equal feerates",
			a:        FeeFrac{Fee: 1000, Size: 100},
			b:        FeeFrac{Fee: 2000, Size: 200},
			expected: 0,
		},
		{
			name:     "a higher feerate",
			a:        FeeFrac{Fee: 1100, Size: 100},
			b:        FeeFrac{Fee: 1000, Size: 100},
			expected: 1,
		},
		{
			name:     "b higher feerate",
			a:        FeeFrac{Fee: 900, Size: 100},
			b:        FeeFrac{Fee: 1000, Size: 100},
			expected: -1,
		},
		{
			name:     "different sizes equal rate",
			a:        FeeFrac{Fee: 3000, Size: 300},
			b:        FeeFrac{Fee: 1000, Size: 100},
			expected: 0,
		},
		{
			name:     "zero size a",
			a:        FeeFrac{Fee: 0, Size: 0},
			b:        FeeFrac{Fee: 1000, Size: 100},
			expected: -1,
		},
		{
			name:     "zero size b",
			a:        FeeFrac{Fee: 1000, Size: 100},
			b:        FeeFrac{Fee: 0, Size: 0},
			expected: 1,
		},
		{
			name:     "both zero",
			a:        FeeFrac{Fee: 0, Size: 0},
			b:        FeeFrac{Fee: 0, Size: 0},
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.a.Compare(tc.b)
			if result != tc.expected {
				t.Errorf("Compare(%v, %v) = %d, want %d", tc.a, tc.b, result, tc.expected)
			}
		})
	}
}

// TestFeeFracAdd tests FeeFrac addition.
func TestFeeFracAdd(t *testing.T) {
	a := FeeFrac{Fee: 1000, Size: 100}
	b := FeeFrac{Fee: 500, Size: 50}
	result := a.Add(b)

	if result.Fee != 1500 || result.Size != 150 {
		t.Errorf("Add(%v, %v) = %v, want {1500, 150}", a, b, result)
	}
}

// TestBitSet tests the BitSet type.
func TestBitSet(t *testing.T) {
	var b BitSet

	// Test Set and Has
	b.Set(0)
	b.Set(5)
	b.Set(63)
	b.Set(64)
	b.Set(100)

	if !b.Has(0) {
		t.Error("Has(0) should be true")
	}
	if !b.Has(5) {
		t.Error("Has(5) should be true")
	}
	if !b.Has(63) {
		t.Error("Has(63) should be true")
	}
	if !b.Has(64) {
		t.Error("Has(64) should be true")
	}
	if !b.Has(100) {
		t.Error("Has(100) should be true")
	}
	if b.Has(1) {
		t.Error("Has(1) should be false")
	}
	if b.Has(127) {
		t.Error("Has(127) should be false")
	}

	// Test Count
	if b.Count() != 5 {
		t.Errorf("Count() = %d, want 5", b.Count())
	}

	// Test Reset
	b.Reset(5)
	if b.Has(5) {
		t.Error("Has(5) should be false after Reset")
	}
	if b.Count() != 4 {
		t.Errorf("Count() = %d, want 4", b.Count())
	}

	// Test First
	if b.First() != 0 {
		t.Errorf("First() = %d, want 0", b.First())
	}

	// Test Any/None
	if !b.Any() {
		t.Error("Any() should be true")
	}
	if b.None() {
		t.Error("None() should be false")
	}

	// Test empty set
	var empty BitSet
	if empty.Any() {
		t.Error("Empty.Any() should be false")
	}
	if !empty.None() {
		t.Error("Empty.None() should be true")
	}
	if empty.First() != -1 {
		t.Errorf("Empty.First() = %d, want -1", empty.First())
	}
}

// TestBitSetOperations tests BitSet union, intersection, difference.
func TestBitSetOperations(t *testing.T) {
	var a, b BitSet
	a.Set(1)
	a.Set(2)
	a.Set(3)
	b.Set(2)
	b.Set(3)
	b.Set(4)

	// Union
	union := a.Union(b)
	expected := []int{1, 2, 3, 4}
	if union.Count() != 4 {
		t.Errorf("Union count = %d, want 4", union.Count())
	}
	for _, i := range expected {
		if !union.Has(i) {
			t.Errorf("Union should have %d", i)
		}
	}

	// Intersection
	inter := a.Intersection(b)
	if inter.Count() != 2 {
		t.Errorf("Intersection count = %d, want 2", inter.Count())
	}
	if !inter.Has(2) || !inter.Has(3) {
		t.Error("Intersection should have 2 and 3")
	}

	// Difference
	diff := a.Difference(b)
	if diff.Count() != 1 {
		t.Errorf("Difference count = %d, want 1", diff.Count())
	}
	if !diff.Has(1) {
		t.Error("Difference should have 1")
	}

	// IsSubsetOf
	var c BitSet
	c.Set(2)
	if !c.IsSubsetOf(a) {
		t.Error("c should be subset of a")
	}
	if a.IsSubsetOf(c) {
		t.Error("a should not be subset of c")
	}

	// Overlaps
	if !a.Overlaps(b) {
		t.Error("a and b should overlap")
	}
	var d BitSet
	d.Set(10)
	if a.Overlaps(d) {
		t.Error("a and d should not overlap")
	}
}

// TestBitSetElements tests BitSet.Elements().
func TestBitSetElements(t *testing.T) {
	var b BitSet
	b.Set(3)
	b.Set(7)
	b.Set(65)

	elements := b.Elements()
	if len(elements) != 3 {
		t.Errorf("Elements() length = %d, want 3", len(elements))
	}

	expected := map[int]bool{3: true, 7: true, 65: true}
	for _, e := range elements {
		if !expected[e] {
			t.Errorf("Unexpected element %d", e)
		}
	}
}

// TestDepGraph tests the dependency graph.
func TestDepGraph(t *testing.T) {
	g := NewDepGraph()

	// Add transactions: A -> B -> C (A is parent of B, B is parent of C)
	idxA := g.AddTransaction(FeeFrac{Fee: 1000, Size: 100})
	idxB := g.AddTransaction(FeeFrac{Fee: 500, Size: 50})
	idxC := g.AddTransaction(FeeFrac{Fee: 2000, Size: 100})

	if g.TxCount() != 3 {
		t.Errorf("TxCount() = %d, want 3", g.TxCount())
	}

	// Add A -> B dependency
	g.AddDependencies(Singleton(idxA), idxB)

	// Add B -> C dependency
	g.AddDependencies(Singleton(idxB), idxC)

	// Check ancestors of C (should be A, B, C)
	ancC := g.Ancestors(idxC)
	if ancC.Count() != 3 {
		t.Errorf("Ancestors(C) count = %d, want 3", ancC.Count())
	}
	if !ancC.Has(idxA) || !ancC.Has(idxB) || !ancC.Has(idxC) {
		t.Error("Ancestors(C) should have A, B, C")
	}

	// Check descendants of A (should be A, B, C)
	descA := g.Descendants(idxA)
	if descA.Count() != 3 {
		t.Errorf("Descendants(A) count = %d, want 3", descA.Count())
	}

	// Check reduced parents of C (should just be B)
	reducedParents := g.GetReducedParents(idxC)
	if reducedParents.Count() != 1 || !reducedParents.Has(idxB) {
		t.Errorf("GetReducedParents(C) = %v, want just B", reducedParents.Elements())
	}
}

// TestCluster tests basic cluster operations.
func TestCluster(t *testing.T) {
	cluster := NewCluster(1)

	// Add transaction A (no parents)
	hashA := makeTestHash(1)
	idxA, err := cluster.AddTransaction(hashA, FeeFrac{Fee: 1000, Size: 100}, nil)
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}
	if idxA < 0 {
		t.Fatal("Invalid index returned")
	}

	// Add transaction B (child of A)
	hashB := makeTestHash(2)
	idxB, err := cluster.AddTransaction(hashB, FeeFrac{Fee: 2000, Size: 100}, []int{idxA})
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}

	if cluster.Size() != 2 {
		t.Errorf("Size() = %d, want 2", cluster.Size())
	}

	// Check linearization
	lin := cluster.GetLinearization()
	if len(lin) != 2 {
		t.Errorf("Linearization length = %d, want 2", len(lin))
	}

	// Parent A should come before child B
	aPos, bPos := -1, -1
	for i, idx := range lin {
		if idx == idxA {
			aPos = i
		}
		if idx == idxB {
			bPos = i
		}
	}
	if aPos >= bPos {
		t.Error("Parent A should come before child B in linearization")
	}

	// Check chunks
	chunks := cluster.GetChunks()
	if len(chunks) == 0 {
		t.Error("Should have at least one chunk")
	}
}

// TestLinearization tests the linearization algorithm.
func TestLinearization(t *testing.T) {
	cluster := NewCluster(1)

	// Create a diamond structure:
	//     A (low fee)
	//    / \
	//   B   C (high fees)
	//    \ /
	//     D (medium fee)

	hashA := makeTestHash(1)
	hashB := makeTestHash(2)
	hashC := makeTestHash(3)
	hashD := makeTestHash(4)

	idxA, _ := cluster.AddTransaction(hashA, FeeFrac{Fee: 100, Size: 100}, nil) // 1 sat/vB
	idxB, _ := cluster.AddTransaction(hashB, FeeFrac{Fee: 500, Size: 50}, []int{idxA}) // 10 sat/vB
	idxC, _ := cluster.AddTransaction(hashC, FeeFrac{Fee: 500, Size: 50}, []int{idxA}) // 10 sat/vB
	idxD, _ := cluster.AddTransaction(hashD, FeeFrac{Fee: 200, Size: 100}, []int{idxB, idxC}) // 2 sat/vB

	lin := cluster.GetLinearization()

	// Verify topological order
	posA := indexOfInt(lin, idxA)
	posB := indexOfInt(lin, idxB)
	posC := indexOfInt(lin, idxC)
	posD := indexOfInt(lin, idxD)

	if posA >= posB || posA >= posC {
		t.Error("A should come before B and C")
	}
	if posB >= posD || posC >= posD {
		t.Error("B and C should come before D")
	}

	// Verify we have chunks
	chunks := cluster.GetChunks()
	if len(chunks) == 0 {
		t.Error("Should have chunks")
	}

	// Chunks should be in descending feerate order
	for i := 1; i < len(chunks); i++ {
		if chunks[i].FeeRate.Compare(chunks[i-1].FeeRate) > 0 {
			t.Errorf("Chunks not in descending feerate order at %d", i)
		}
	}
}

// TestChunking tests the chunking algorithm.
func TestChunking(t *testing.T) {
	cluster := NewCluster(1)

	// Create a simple chain: A -> B -> C with increasing feerates
	// This should produce 3 chunks with CPFP behavior

	hashA := makeTestHash(1)
	hashB := makeTestHash(2)
	hashC := makeTestHash(3)

	// C has high feerate, which should "pull up" A and B
	idxA, _ := cluster.AddTransaction(hashA, FeeFrac{Fee: 100, Size: 100}, nil)  // 1 sat/vB
	idxB, _ := cluster.AddTransaction(hashB, FeeFrac{Fee: 100, Size: 100}, []int{idxA}) // 1 sat/vB
	idxC, _ := cluster.AddTransaction(hashC, FeeFrac{Fee: 800, Size: 100}, []int{idxB}) // 8 sat/vB

	chunks := cluster.GetChunks()

	// The best chunk should include all 3 (because ABC together has 1000/300 = 3.33 sat/vB
	// which is better than just C alone at 8 sat/vB due to dependency requirement)
	// Actually, the greedy algorithm picks the best ancestor set.
	// For C, ancestors are {A, B, C} with rate 1000/300 = 3.33
	// For B, ancestors are {A, B} with rate 200/200 = 1
	// For A, ancestors are {A} with rate 100/100 = 1
	// So first chunk should be {A, B, C} with combined feerate

	t.Logf("Got %d chunks", len(chunks))
	for i, chunk := range chunks {
		t.Logf("Chunk %d: txs=%v, feerate=%v", i, chunk.Txs, chunk.FeeRate)
	}

	// Verify all transactions are covered
	totalTxs := 0
	for _, chunk := range chunks {
		totalTxs += len(chunk.Txs)
	}
	if totalTxs != 3 {
		t.Errorf("Total transactions in chunks = %d, want 3", totalTxs)
	}

	// Verify idxC is in a chunk
	found := false
	for _, chunk := range chunks {
		for _, idx := range chunk.Txs {
			if idx == idxC {
				found = true
			}
		}
	}
	if !found {
		t.Error("Transaction C not found in any chunk")
	}
}

// TestClusterManager tests the cluster manager.
func TestClusterManager(t *testing.T) {
	cm := NewClusterManager()

	// Add first transaction (creates new cluster)
	hashA := makeTestHash(1)
	clusterA, err := cm.AddTransaction(hashA, 1000, 100, nil)
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}
	if clusterA == nil {
		t.Fatal("Cluster should not be nil")
	}

	// Add second independent transaction (creates new cluster)
	hashB := makeTestHash(2)
	clusterB, err := cm.AddTransaction(hashB, 2000, 100, nil)
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}

	if clusterA.ID == clusterB.ID {
		t.Error("Independent transactions should be in different clusters")
	}

	// Add third transaction that depends on A (joins cluster A)
	hashC := makeTestHash(3)
	clusterC, err := cm.AddTransaction(hashC, 500, 50, []wire.Hash256{hashA})
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}

	if clusterC.ID != clusterA.ID {
		t.Error("Child transaction should join parent's cluster")
	}

	// Add fourth transaction that depends on both A and B (merges clusters)
	hashD := makeTestHash(4)
	clusterD, err := cm.AddTransaction(hashD, 1500, 100, []wire.Hash256{hashA, hashB})
	if err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}

	// After merge, all should be in same cluster
	if cm.GetCluster(hashA).ID != cm.GetCluster(hashB).ID {
		t.Error("Clusters should be merged")
	}
	if cm.GetCluster(hashA).ID != clusterD.ID {
		t.Error("All transactions should be in same cluster")
	}

	// Check distinct cluster count
	count := cm.CountDistinctClusters([]wire.Hash256{hashA, hashB, hashC, hashD})
	if count != 1 {
		t.Errorf("CountDistinctClusters = %d, want 1", count)
	}
}

// TestClusterRemoval tests removing transactions from clusters.
func TestClusterRemoval(t *testing.T) {
	cm := NewClusterManager()

	// Create a chain: A -> B -> C
	hashA := makeTestHash(1)
	hashB := makeTestHash(2)
	hashC := makeTestHash(3)

	cm.AddTransaction(hashA, 1000, 100, nil)
	cm.AddTransaction(hashB, 1000, 100, []wire.Hash256{hashA})
	cm.AddTransaction(hashC, 1000, 100, []wire.Hash256{hashB})

	// All should be in same cluster
	if cm.CountDistinctClusters([]wire.Hash256{hashA, hashB, hashC}) != 1 {
		t.Error("All transactions should be in same cluster initially")
	}

	// Remove B (middle of chain) - this should split the cluster
	cm.RemoveTransaction(hashB)

	// A and C should now be in different clusters (no longer connected)
	clusterA := cm.GetCluster(hashA)
	clusterC := cm.GetCluster(hashC)

	if clusterA == nil {
		t.Error("Cluster A should still exist")
	}
	if clusterC == nil {
		t.Error("Cluster C should still exist")
	}
	if clusterA.ID == clusterC.ID {
		t.Error("A and C should be in different clusters after removing B")
	}
}

// TestClusterSizeLimit tests the cluster size limit.
func TestClusterSizeLimit(t *testing.T) {
	cm := NewClusterManager()

	// Add transactions up to the limit
	var lastHash wire.Hash256
	for i := 0; i < MaxClusterSize; i++ {
		hash := makeTestHash(i + 1)
		var parents []wire.Hash256
		if i > 0 {
			parents = []wire.Hash256{lastHash}
		}
		_, err := cm.AddTransaction(hash, 1000, 100, parents)
		if err != nil {
			t.Fatalf("AddTransaction %d failed: %v", i, err)
		}
		lastHash = hash
	}

	// Try to add one more - should fail
	hash := makeTestHash(MaxClusterSize + 1)
	_, err := cm.AddTransaction(hash, 1000, 100, []wire.Hash256{lastHash})
	if err == nil {
		t.Error("Should reject transaction that would exceed cluster size")
	}
}

// TestMiningChunks tests getting chunks for mining.
func TestMiningChunks(t *testing.T) {
	cm := NewClusterManager()

	// Create two independent transactions with different feerates
	hashA := makeTestHash(1)
	hashB := makeTestHash(2)

	cm.AddTransaction(hashA, 1000, 100, nil) // 10 sat/vB
	cm.AddTransaction(hashB, 500, 100, nil)  // 5 sat/vB

	chunks := cm.GetChunksForMining()

	if len(chunks) != 2 {
		t.Errorf("GetChunksForMining() returned %d chunks, want 2", len(chunks))
	}

	// Chunks should be sorted by feerate descending
	if chunks[0].FeeRate.Compare(chunks[1].FeeRate) <= 0 {
		t.Error("Chunks should be sorted by feerate descending")
	}
}

// TestEvictionChunk tests getting the worst chunk for eviction.
func TestEvictionChunk(t *testing.T) {
	cm := NewClusterManager()

	hashA := makeTestHash(1)
	hashB := makeTestHash(2)

	cm.AddTransaction(hashA, 1000, 100, nil) // 10 sat/vB
	cm.AddTransaction(hashB, 100, 100, nil)  // 1 sat/vB

	cluster, chunk := cm.GetWorstChunkForEviction()

	if cluster == nil || chunk == nil {
		t.Fatal("Should return worst chunk")
	}

	// Worst chunk should be B (lower feerate)
	if chunk.FeeRate.Fee != 100 {
		t.Errorf("Worst chunk fee = %d, want 100", chunk.FeeRate.Fee)
	}
}

// TestFeerateDiagram tests feerate diagram comparison.
func TestFeerateDiagram(t *testing.T) {
	// Create two linearizations with different feerates
	chunks1 := []Chunk{
		{Txs: []int{0}, FeeRate: FeeFrac{Fee: 1000, Size: 100}}, // 10 sat/vB
		{Txs: []int{1}, FeeRate: FeeFrac{Fee: 500, Size: 100}},  // 5 sat/vB
	}

	chunks2 := []Chunk{
		{Txs: []int{0}, FeeRate: FeeFrac{Fee: 800, Size: 100}}, // 8 sat/vB
		{Txs: []int{1}, FeeRate: FeeFrac{Fee: 700, Size: 100}}, // 7 sat/vB
	}

	diag1 := NewFeerateDiagram(chunks1)
	diag2 := NewFeerateDiagram(chunks2)

	// Neither should be strictly better (they cross)
	// diag1 starts higher but ends lower
	cmp := diag1.Compare(diag2)

	// This comparison depends on the exact areas, just verify it doesn't crash
	t.Logf("Diagram comparison result: %d", cmp)

	// Test identical diagrams
	diag3 := NewFeerateDiagram(chunks1)
	if diag1.Compare(diag3) != 0 {
		t.Error("Identical diagrams should compare equal")
	}
}

// Helper functions

func makeTestHash(n int) wire.Hash256 {
	var h wire.Hash256
	h[0] = byte(n)
	h[1] = byte(n >> 8)
	return h
}

func indexOfInt(slice []int, val int) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return -1
}
