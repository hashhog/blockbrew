package mempool

import "testing"

// TestChunkMergesParentWithAllCPFPChildren pins Core's cluster-mempool
// linearization (cluster_linearize.h): the best chunk is the highest-feerate
// topologically closed subset, which can be a union of several ancestor sets.
// A low-fee parent with several high-fee children must form ONE chunk.
// Before the fix every candidate was a single transaction's ancestor set, so
// the chunk stopped at parent+one child.
func TestChunkMergesParentWithAllCPFPChildren(t *testing.T) {
	cluster := NewCluster(1)
	p, _ := cluster.AddTransaction(makeTestHash(1), FeeFrac{Fee: 100, Size: 1000}, nil)
	var kids []int
	for i := 0; i < 3; i++ {
		k, _ := cluster.AddTransaction(makeTestHash(10+i), FeeFrac{Fee: 5000, Size: 100}, []int{p})
		kids = append(kids, k)
	}
	chunks := cluster.GetChunks()
	if len(chunks) != 1 {
		for i, c := range chunks {
			t.Logf("chunk %d: txs=%v rate=%v", i, c.Txs, c.FeeRate)
		}
		t.Fatalf("got %d chunks, want 1 (parent + 3 children)", len(chunks))
	}
	if len(chunks[0].Txs) != 4 {
		t.Fatalf("chunk has %d txs, want 4", len(chunks[0].Txs))
	}
}

// TestChunkFeeratesNonIncreasing guards the invariant the union search must
// keep: chunk feerates never increase along the linearization, and every tx
// is placed after its parent.
func TestChunkFeeratesNonIncreasing(t *testing.T) {
	cluster := NewCluster(1)
	a, _ := cluster.AddTransaction(makeTestHash(1), FeeFrac{Fee: 100, Size: 1000}, nil)
	b, _ := cluster.AddTransaction(makeTestHash(2), FeeFrac{Fee: 4000, Size: 100}, []int{a})
	c, _ := cluster.AddTransaction(makeTestHash(3), FeeFrac{Fee: 9000, Size: 100}, []int{a})
	d, _ := cluster.AddTransaction(makeTestHash(4), FeeFrac{Fee: 10, Size: 500}, []int{b})
	chunks := cluster.GetChunks()
	pos := map[int]int{}
	n := 0
	for ci, ch := range chunks {
		if ci > 0 && ch.FeeRate.Compare(chunks[ci-1].FeeRate) > 0 {
			t.Errorf("chunk %d feerate %v exceeds chunk %d feerate %v", ci, ch.FeeRate, ci-1, chunks[ci-1].FeeRate)
		}
		for _, i := range ch.Txs {
			pos[i] = n
			n++
		}
	}
	if n != 4 {
		t.Fatalf("placed %d txs, want 4", n)
	}
	for child, parent := range map[int]int{b: a, c: a, d: b} {
		if pos[parent] > pos[child] {
			t.Errorf("tx %d placed before its parent %d", child, parent)
		}
	}
}
