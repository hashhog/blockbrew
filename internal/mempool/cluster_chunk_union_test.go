package mempool

import (
	"math/rand"
	"testing"
	"time"
)

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

// bruteBestClosed returns the highest aggregate feerate over every non-empty
// subset of `rem` that is topologically closed within `rem` (every in-`rem`
// ancestor of a member is a member). n is at most 16 here, so 2^n is cheap.
func bruteBestClosed(t *testing.T, g *DepGraph, rem BitSet) FeeFrac {
	t.Helper()
	elems := rem.Elements()
	var best FeeFrac
	have := false
	for mask := 1; mask < 1<<len(elems); mask++ {
		var s BitSet
		for k, e := range elems {
			if mask&(1<<k) != 0 {
				s.Set(e)
			}
		}
		closed := true
		s.ForEach(func(i int) {
			if !g.Ancestors(i).Intersection(rem).IsSubsetOf(s) {
				closed = false
			}
		})
		if !closed {
			continue
		}
		r := g.AggregateFeeFrac(s)
		if !have || r.Compare(best) > 0 {
			best, have = r, true
		}
	}
	return best
}

// checkChunksOptimal asserts Core's chunk property (cluster_linearize.h):
// each chunk is topologically closed within what remains and has the highest
// feerate of any closed subset of what remains; chunk feerates never rise.
func checkChunksOptimal(t *testing.T, c *Cluster) {
	t.Helper()
	g := c.DepGraph
	rem := g.Positions()
	chunks := c.GetChunks()
	for ci, ch := range chunks {
		var s BitSet
		for _, i := range ch.Txs {
			s.Set(i)
		}
		s.ForEach(func(i int) {
			if !g.Ancestors(i).Intersection(rem).IsSubsetOf(s) {
				t.Errorf("chunk %d is not closed: tx %d is missing an ancestor", ci, i)
			}
		})
		want := bruteBestClosed(t, g, rem)
		if ch.FeeRate.Compare(want) != 0 {
			t.Errorf("chunk %d: txs=%v fee/size %d/%d, best closed subset of the remainder is %d/%d",
				ci, ch.Txs, ch.FeeRate.Fee, ch.FeeRate.Size, want.Fee, want.Size)
		}
		// Core keeps equal-feerate pieces apart (ChunkLinearization merges
		// only on a strictly higher feerate), so a chunk must not contain a
		// smaller non-empty closed subset of the remainder at its feerate.
		elems := s.Elements()
		for mask := 1; mask < 1<<len(elems)-1; mask++ {
			var sub BitSet
			for k, e := range elems {
				if mask&(1<<k) != 0 {
					sub.Set(e)
				}
			}
			closed := true
			sub.ForEach(func(i int) {
				if !g.Ancestors(i).Intersection(rem).IsSubsetOf(sub) {
					closed = false
				}
			})
			if closed && g.AggregateFeeFrac(sub).Compare(ch.FeeRate) >= 0 {
				t.Errorf("chunk %d txs=%v is not minimal: closed subset %v has the same feerate",
					ci, ch.Txs, sub.Elements())
				break
			}
		}
		if ci > 0 && ch.FeeRate.Compare(chunks[ci-1].FeeRate) > 0 {
			t.Errorf("chunk %d feerate %d/%d exceeds chunk %d feerate %d/%d",
				ci, ch.FeeRate.Fee, ch.FeeRate.Size, ci-1, chunks[ci-1].FeeRate.Fee, chunks[ci-1].FeeRate.Size)
		}
		rem = rem.Difference(s)
	}
	if rem.Any() {
		t.Errorf("chunks left txs %v unplaced", rem.Elements())
	}
}

// TestChunkIsBestClosedSubsetWardenCluster is the cluster from the review of
// blockbrew#50: growing a seed by the one ancestor set that most raises the
// feerate, never dropping a tx, returns all 12 txs at 109/170, while the closed
// subset {0,1,2,3,4,5,8,9} is 74/114 (strictly higher). Core's first chunk is
// the latter; the leftover {6,7,10,11} (35/56) is a separate, worse chunk.
func TestChunkIsBestClosedSubsetWardenCluster(t *testing.T) {
	fees := []int64{5, 4, 7, 15, 1, 17, 6, 3, 13, 12, 12, 14}
	sizes := []int32{24, 14, 22, 15, 16, 9, 13, 11, 12, 2, 16, 16}
	parents := [][]int{nil, {0}, nil, {2}, {1, 3}, {4}, {0, 1, 4}, nil, {4}, {0, 3, 4}, {1, 3, 7, 9}, {5, 6, 10}}
	c := NewCluster(1)
	for i := range fees {
		idx, err := c.AddTransaction(makeTestHash(100+i), FeeFrac{Fee: fees[i], Size: sizes[i]}, parents[i])
		if err != nil || idx != i {
			t.Fatalf("add tx %d: idx=%d err=%v", i, idx, err)
		}
	}
	chunks := c.GetChunks()
	for i, ch := range chunks {
		t.Logf("chunk %d: txs=%v fee/size %d/%d", i, ch.Txs, ch.FeeRate.Fee, ch.FeeRate.Size)
	}
	if got := chunks[0].FeeRate; got.Fee != 74 || got.Size != 114 {
		t.Errorf("first chunk fee/size %d/%d, want 74/114 ({0,1,2,3,4,5,8,9})", got.Fee, got.Size)
	}
	// Eviction reads the worst chunk: it must be the 35/56 tail {6,7,10,11},
	// not one 12-tx blob that hides it.
	if got := c.WorstChunkFeeRate(); got.Fee != 35 || got.Size != 56 {
		t.Errorf("worst chunk fee/size %d/%d, want 35/56 ({6,7,10,11})", got.Fee, got.Size)
	}
	checkChunksOptimal(t, c)
}

// TestChunkSplitsEqualFeerateGroups: a parent at 1000/10 with two 0/10
// children, each with two 15/10 children. After the parent, the two 3-tx
// groups both have feerate 30/30 and are independent; Core emits them as two
// chunks, so eviction drops 3 txs, not 6, and each tx reports a 30/30 chunk.
func TestChunkSplitsEqualFeerateGroups(t *testing.T) {
	c := NewCluster(1)
	add := func(h int, fee int64, parents []int) int {
		idx, err := c.AddTransaction(makeTestHash(h), FeeFrac{Fee: fee, Size: 10}, parents)
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		return idx
	}
	p := add(1, 1000, nil)
	a := add(2, 0, []int{p})
	b := add(3, 0, []int{p})
	add(4, 15, []int{a})
	add(5, 15, []int{a})
	add(6, 15, []int{b})
	add(7, 15, []int{b})
	chunks := c.GetChunks()
	for i, ch := range chunks {
		t.Logf("chunk %d: txs=%v fee/size %d/%d", i, ch.Txs, ch.FeeRate.Fee, ch.FeeRate.Size)
	}
	if len(chunks) != 3 {
		t.Errorf("got %d chunks, want 3 ([p], then two 30/30 groups)", len(chunks))
	}
	checkChunksOptimal(t, c)
}

// TestChunkIsBestClosedSubsetRandom checks the same property against every
// closed subset on random clusters (fixed seed, n <= 12, dense parents),
// including negative modified fees (prioritisetransaction can lower them).
func TestChunkIsBestClosedSubsetRandom(t *testing.T) {
	configs := []struct {
		name               string
		parentOneIn        int
		feeLo, feeHi, size int
	}{
		{"dense", 2, -10, 30, 30},
		// Sparse parents and tiny values make equal-feerate groups common,
		// which exercises the minimal-chunk split.
		{"ties", 4, 0, 5, 3},
	}
	for _, cfg := range configs {
		rng := rand.New(rand.NewSource(50))
		for iter := 0; iter < 2000; iter++ {
			n := 1 + rng.Intn(12)
			c := NewCluster(1)
			for i := 0; i < n; i++ {
				var ps []int
				for j := 0; j < i; j++ {
					if rng.Intn(cfg.parentOneIn) == 0 {
						ps = append(ps, j)
					}
				}
				fr := FeeFrac{Fee: int64(cfg.feeLo + rng.Intn(cfg.feeHi-cfg.feeLo)), Size: int32(1 + rng.Intn(cfg.size))}
				if _, err := c.AddTransaction(makeTestHash(1000*iter+i), fr, ps); err != nil {
					t.Fatalf("add: %v", err)
				}
			}
			checkChunksOptimal(t, c)
			if t.Failed() {
				t.Fatalf("%s: iteration %d (n=%d) failed", cfg.name, iter, n)
			}
		}
	}
}

// TestChunkHugeModifiedFeesStayClosed: prioritisetransaction can push a
// modified fee far past any real fee. The closure search multiplies fees by
// sizes; where those products could leave int64 it must still finish and
// return closed chunks that place every tx (wrapped min-cut capacities made
// it spin forever).
func TestChunkHugeModifiedFeesStayClosed(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 300; iter++ {
		n := 2 + rng.Intn(8)
		c := NewCluster(1)
		for i := 0; i < n; i++ {
			var ps []int
			for j := 0; j < i; j++ {
				if rng.Intn(3) == 0 {
					ps = append(ps, j)
				}
			}
			fr := FeeFrac{Fee: rng.Int63n(1<<46) - (1 << 45), Size: int32(1 + rng.Intn(400000))}
			if _, err := c.AddTransaction(makeTestHash(1000*iter+i), fr, ps); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		done := make(chan []Chunk, 1)
		go func() { done <- c.GetChunks() }()
		var chunks []Chunk
		select {
		case chunks = <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d (n=%d): GetChunks did not finish in 10s", iter, n)
		}
		g := c.DepGraph
		rem := g.Positions()
		for ci, ch := range chunks {
			var set BitSet
			for _, i := range ch.Txs {
				set.Set(i)
			}
			if set.None() {
				t.Fatalf("iteration %d: chunk %d is empty", iter, ci)
			}
			set.ForEach(func(i int) {
				if !g.Ancestors(i).Intersection(rem).IsSubsetOf(set) {
					t.Fatalf("iteration %d: chunk %d txs=%v is not closed (tx %d)", iter, ci, ch.Txs, i)
				}
			})
			rem = rem.Difference(set)
		}
		if rem.Any() {
			t.Fatalf("iteration %d: txs %v never placed", iter, rem.Elements())
		}
	}
}
