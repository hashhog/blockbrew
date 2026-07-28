package mempool

import (
	"fmt"
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// mergeClusters must be deterministic and must preserve every dependency edge.
//
// It used to take all of its ordering from Go map iteration, which is
// randomised per range statement. A moved transaction was linked only to
// ancestors ALREADY in the target cluster, so whenever a child was moved
// before its parent the edge was silently dropped. A cluster missing internal
// edges linearises differently, which changes eviction and the
// too-large-cluster decision on the RBF path — nondeterministically, and
// therefore differently on different nodes of a fleet that is supposed to
// agree byte-for-byte.
// ---------------------------------------------------------------------------

func hashN(n byte) wire.Hash256 {
	var h wire.Hash256
	h[0] = n
	h[31] = 0xC1
	return h
}

// clusterFingerprint renders the cluster containing txHash as a canonical,
// order-independent string: every transaction with its ancestor set, both
// sorted by txid. Two runs that built the same graph produce the same string;
// a run that dropped an edge produces a different one.
func clusterFingerprint(cm *ClusterManager, txHash wire.Hash256) string {
	cid, ok := cm.txToCluster[txHash]
	if !ok {
		return "<no cluster>"
	}
	c := cm.clusters[cid]

	idxToHash := make(map[int]wire.Hash256, len(c.Transactions))
	hashes := make([]wire.Hash256, 0, len(c.Transactions))
	for h, i := range c.Transactions {
		idxToHash[i] = h
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(a, b int) bool { return hashes[a][0] < hashes[b][0] })

	out := ""
	for _, h := range hashes {
		idx := c.Transactions[h]
		anc := c.DepGraph.Ancestors(idx)
		anc.Reset(idx)
		var ancNames []int
		anc.ForEach(func(a int) {
			if ah, ok := idxToHash[a]; ok {
				ancNames = append(ancNames, int(ah[0]))
			}
		})
		sort.Ints(ancNames)
		out += fmt.Sprintf("%d<-%v;", h[0], ancNames)
	}
	return out
}

// buildMergeScenario creates two independent clusters, the second of which is a
// parent->child->grandchild CHAIN (so intra-source edges exist and merge order
// matters), then admits a transaction that depends on a member of each —
// forcing mergeClusters to fold the chain into the other cluster.
//
// Returns the manager and the joining transaction's hash.
func buildMergeScenario(t *testing.T) (*ClusterManager, wire.Hash256) {
	t.Helper()
	cm := NewClusterManager()

	const fee, size, adj = int64(1000), int32(250), int64(1000)

	// Cluster A: two independent roots, so it is the larger cluster and
	// becomes the merge target.
	a1, a2 := hashN(1), hashN(2)
	if _, err := cm.AddTransaction(a1, fee, size, adj, nil); err != nil {
		t.Fatalf("add a1: %v", err)
	}
	if _, err := cm.AddTransaction(a2, fee, size, adj, nil); err != nil {
		t.Fatalf("add a2: %v", err)
	}
	// Join them so cluster A has size 3 and is strictly the largest.
	aJoin := hashN(3)
	if _, err := cm.AddTransaction(aJoin, fee, size, adj, []wire.Hash256{a1, a2}); err != nil {
		t.Fatalf("add aJoin: %v", err)
	}

	// Cluster B: a strict chain b1 -> b2 -> b3. These edges are exactly what
	// the buggy merge could drop.
	b1, b2, b3 := hashN(10), hashN(11), hashN(12)
	if _, err := cm.AddTransaction(b1, fee, size, adj, nil); err != nil {
		t.Fatalf("add b1: %v", err)
	}
	if _, err := cm.AddTransaction(b2, fee, size, adj, []wire.Hash256{b1}); err != nil {
		t.Fatalf("add b2: %v", err)
	}
	if _, err := cm.AddTransaction(b3, fee, size, adj, []wire.Hash256{b2}); err != nil {
		t.Fatalf("add b3: %v", err)
	}

	// The joiner depends on one tx from each cluster -> triggers the merge.
	joiner := hashN(20)
	if _, err := cm.AddTransaction(joiner, fee, size, adj, []wire.Hash256{aJoin, b3}); err != nil {
		t.Fatalf("add joiner: %v", err)
	}
	return cm, joiner
}

// TestMergeClustersIsDeterministic runs the identical admission sequence many
// times. Go randomises map iteration per run, so a merge that reads its
// ordering from a map produces varying graphs across iterations.
func TestMergeClustersIsDeterministic(t *testing.T) {
	const runs = 200

	first := ""
	seen := map[string]int{}
	for i := 0; i < runs; i++ {
		cm, joiner := buildMergeScenario(t)
		fp := clusterFingerprint(cm, joiner)
		seen[fp]++
		if i == 0 {
			first = fp
		}
	}

	if len(seen) != 1 {
		var shapes []string
		for s, n := range seen {
			shapes = append(shapes, fmt.Sprintf("\n  (%dx) %s", n, s))
		}
		sort.Strings(shapes)
		t.Fatalf("NONDETERMINISTIC MERGE: %d distinct cluster shapes across %d "+
			"identical admission sequences. mergeClusters must not take its "+
			"ordering from Go map iteration — a dropped dependency edge changes "+
			"linearisation, and therefore eviction and the too-large-cluster "+
			"decision, differently on different nodes.%s",
			len(seen), runs, shapes)
	}
	t.Logf("stable across %d runs: %s", runs, first)
}

// TestMergeClustersPreservesAllEdges pins the actual graph, not just its
// stability: a merge that consistently dropped the same edge would be
// deterministic AND wrong, so determinism alone is not sufficient.
//
// Expected ancestry after the merge (by first hash byte):
//
//	1,2,10 : roots
//	3      : 1,2
//	11     : 10
//	12     : 10,11
//	20     : 1,2,3,10,11,12
func TestMergeClustersPreservesAllEdges(t *testing.T) {
	cm, joiner := buildMergeScenario(t)
	got := clusterFingerprint(cm, joiner)
	want := "1<-[];2<-[];3<-[1 2];10<-[];11<-[10];12<-[10 11];20<-[1 2 3 10 11 12];"
	if got != want {
		t.Errorf("MERGE DROPPED OR ALTERED EDGES\n got: %s\nwant: %s\n\n"+
			"The b1->b2->b3 chain must survive being folded into the target "+
			"cluster. Linking a moved transaction only to ancestors already "+
			"present loses the edge whenever a child moves before its parent.",
			got, want)
	}
}
