package mempool

// Package RBF Rule 5 counts clusters, as the single-transaction path does.
//
// Core reference (bitcoin-core/src/validation.cpp PackageRBFChecks):
//   the direct conflicts of both members are merged and handed to
//   GetEntriesForConflicts (policy/rbf.cpp), which refuses only when
//   GetUniqueClusterCount(direct conflicts) > MAX_REPLACEMENT_CANDIDATES,
//   with reason "package RBF failed: too many potential replacements" and
//   debug "rejecting replacement <child>; too many conflicting clusters
//   (%u > %d)". The number of evicted transactions is not limited.
//
// The bug these tests pin: packageRBFChecksLocked refused when the eviction
// set held more than 100 transactions, so a 1p1c package sweeping five
// 21-transaction clusters was refused although the same sweep is accepted
// on the single-transaction path (TestClusterRBF_FiveClustersOf21AreOneReplacement).

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestPackageRBFEvicts105TxsFromFiveClusters: P sweeps the five funding coins
// of five 21-transaction clusters paying 1,000 sat (too little to replace
// 105,000 sat alone), C spends P paying 200,000. The package evicts 105
// transactions from 5 clusters; Core accepts it.
func TestPackageRBFEvicts105TxsFromFiveClusters(t *testing.T) {
	mp, ops := clusterRBFMempool(5)
	for _, op := range ops {
		addCluster(t, mp, op, 20, 1_000)
	}
	if got := mp.Count(); got != 105 {
		t.Fatalf("fixture: pool holds %d txs, want 105", got)
	}
	if got := mp.CountDistinctClusters(mp.GetAllTxHashes()); got != 5 {
		t.Fatalf("fixture: pool holds %d clusters, want 5", got)
	}

	total := int64(len(ops)) * clusterRBFFunding
	p := sweepTx(ops, total, 1_000)
	c := spendableTx(wire.OutPoint{Hash: p.TxHash(), Index: 0}, p.TxOut[0].Value-200_000, 1)

	// Precondition: P alone does not pay for the replacement, so this is a
	// package RBF and not two single-transaction acceptances.
	if conflicts, err := mp.TestReplacement(p); !conflicts || !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("fixture: P alone = (%v, %v), want an insufficient-fee replacement", conflicts, err)
	}

	res, err := mp.AcceptPackage([]*wire.MsgTx{p, c})
	if err != nil {
		t.Fatalf("package evicting 105 txs from 5 clusters refused: %v", err)
	}
	if got := mp.Count(); got != 2 || !mp.HasTransaction(p.TxHash()) || !mp.HasTransaction(c.TxHash()) {
		t.Fatalf("after package RBF pool holds %d txs (P %v, C %v), want only P and C",
			got, mp.HasTransaction(p.TxHash()), mp.HasTransaction(c.TxHash()))
	}
	if len(res.ReplacedTxs) != 105 {
		t.Errorf("ReplacedTxs has %d entries, want 105", len(res.ReplacedTxs))
	}
}

// TestPackageRBFConflictsSpanning101ClustersRefused: the direct conflicts of
// the two members together span 101 single-transaction clusters — P conflicts
// with 51, C with the other 50 — so neither member alone exceeds the limit.
// Core refuses with its reason and debug string and leaves the pool alone.
func TestPackageRBFConflictsSpanning101ClustersRefused(t *testing.T) {
	const n = MaxRBFReplacedTxs + 1
	mp, ops := clusterRBFMempool(n)
	for _, op := range ops {
		if err := mp.AddTransaction(spendableTx(op, clusterRBFFunding-1_000, 1)); err != nil {
			t.Fatalf("fixture tx rejected: %v", err)
		}
	}
	pOps, cOps := ops[:51], ops[51:]
	p := sweepTx(pOps, int64(len(pOps))*clusterRBFFunding, 1_000)
	cIns := append([]wire.OutPoint{{Hash: p.TxHash(), Index: 0}}, cOps...)
	c := sweepTx(cIns, p.TxOut[0].Value+int64(len(cOps))*clusterRBFFunding, 10_000_000)

	_, err := mp.AcceptPackage([]*wire.MsgTx{p, c})
	if !errors.Is(err, ErrPackageRBF) {
		t.Fatalf("got %v, want ErrPackageRBF", err)
	}
	want := fmt.Sprintf("package RBF failed: too many potential replacements, rejecting replacement %s; too many conflicting clusters (101 > 100)",
		c.TxHash())
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if got := mp.Count(); got != n || mp.HasTransaction(p.TxHash()) || mp.HasTransaction(c.TxHash()) {
		t.Fatalf("refused package changed the pool: %d txs, want the %d originals", got, n)
	}
}

// TestPackageRBFConflictsSpanning100ClustersAccepted is the boundary, with
// the child carrying half the conflicts: P conflicts with 50 clusters, C with
// 50 more. Core's ">" lets exactly MAX_REPLACEMENT_CANDIDATES through, and
// C's own conflicts must not end the package before it is retried with P.
func TestPackageRBFConflictsSpanning100ClustersAccepted(t *testing.T) {
	const n = MaxRBFReplacedTxs
	mp, ops := clusterRBFMempool(n)
	for _, op := range ops {
		if err := mp.AddTransaction(spendableTx(op, clusterRBFFunding-1_000, 1)); err != nil {
			t.Fatalf("fixture tx rejected: %v", err)
		}
	}
	pOps, cOps := ops[:50], ops[50:]
	p := sweepTx(pOps, int64(len(pOps))*clusterRBFFunding, 1_000)
	cIns := append([]wire.OutPoint{{Hash: p.TxHash(), Index: 0}}, cOps...)
	c := sweepTx(cIns, p.TxOut[0].Value+int64(len(cOps))*clusterRBFFunding, 10_000_000)

	if _, err := mp.AcceptPackage([]*wire.MsgTx{p, c}); err != nil {
		t.Fatalf("package conflicting with 100 clusters refused: %v", err)
	}
	if got := mp.Count(); got != 2 || !mp.HasTransaction(p.TxHash()) || !mp.HasTransaction(c.TxHash()) {
		t.Fatalf("pool holds %d txs, want only P and C", got)
	}
}
