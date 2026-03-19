package mempool

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestClusterRemovalDebug(t *testing.T) {
	cm := NewClusterManager()

	// Create a chain: A -> B -> C
	hashA := makeTestHash2(1)
	hashB := makeTestHash2(2)
	hashC := makeTestHash2(3)

	cm.AddTransaction(hashA, 1000, 100, nil)
	t.Logf("After adding A: cluster=%v", cm.txToCluster)

	cm.AddTransaction(hashB, 1000, 100, []wire.Hash256{hashA})
	t.Logf("After adding B: cluster=%v", cm.txToCluster)

	cm.AddTransaction(hashC, 1000, 100, []wire.Hash256{hashB})
	t.Logf("After adding C: cluster=%v", cm.txToCluster)

	// Check initial cluster
	clusterA := cm.GetCluster(hashA)
	t.Logf("Cluster A has %d transactions", clusterA.Size())
	t.Logf("DepGraph positions: %v", clusterA.DepGraph.Positions().Elements())
	
	idxA := clusterA.Transactions[hashA]
	idxB := clusterA.Transactions[hashB]
	idxC := clusterA.Transactions[hashC]
	t.Logf("Indices: A=%d, B=%d, C=%d", idxA, idxB, idxC)
	t.Logf("Ancestors(A): %v", clusterA.DepGraph.Ancestors(idxA).Elements())
	t.Logf("Ancestors(B): %v", clusterA.DepGraph.Ancestors(idxB).Elements())
	t.Logf("Ancestors(C): %v", clusterA.DepGraph.Ancestors(idxC).Elements())
	t.Logf("IsConnected: %v", clusterA.DepGraph.IsConnected(clusterA.DepGraph.Positions()))

	// Remove B (middle of chain)
	cm.RemoveTransaction(hashB)
	t.Logf("After removing B: cluster map=%v", cm.txToCluster)

	// Check what remains
	clusterAfter := cm.GetCluster(hashA)
	if clusterAfter != nil {
		t.Logf("Cluster containing A: ID=%d, size=%d", clusterAfter.ID, clusterAfter.Size())
		t.Logf("Cluster transactions: %v", clusterAfter.Transactions)
		t.Logf("DepGraph positions: %v", clusterAfter.DepGraph.Positions().Elements())
		
		for txh, idx := range clusterAfter.Transactions {
			t.Logf("  tx %x: idx=%d, ancestors=%v, descendants=%v", 
				txh[:4], idx, 
				clusterAfter.DepGraph.Ancestors(idx).Elements(),
				clusterAfter.DepGraph.Descendants(idx).Elements())
		}
		t.Logf("IsConnected: %v", clusterAfter.DepGraph.IsConnected(clusterAfter.DepGraph.Positions()))
	}

	clusterC2 := cm.GetCluster(hashC)
	if clusterC2 != nil {
		t.Logf("Cluster containing C: ID=%d, size=%d", clusterC2.ID, clusterC2.Size())
	} else {
		t.Logf("C is not in any cluster!")
	}
}

func makeTestHash2(n int) wire.Hash256 {
	var h wire.Hash256
	h[0] = byte(n)
	h[1] = byte(n >> 8)
	return h
}
