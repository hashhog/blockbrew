package mempool

// Core 31 cluster RBF: Rule 5 counts the clusters the replacement conflicts
// with directly, not the transactions it evicts, and every replacement
// refusal carries Core's reject reason and debug message.
//
// Core reference:
//   policy/rbf.cpp  GetEntriesForConflicts — GetUniqueClusterCount(direct
//                   conflicts) > MAX_REPLACEMENT_CANDIDATES (100) →
//                   "rejecting replacement %s; too many conflicting clusters (%u > %d)"
//   policy/rbf.cpp  PaysForRBF — "rejecting replacement %s, less fees than
//                   conflicting txs; %s < %s" (FormatMoney amounts)
//   validation.cpp  ReplacementChecks — reasons "too many potential
//                   replacements", "insufficient fee", "replacement-failed"
//
// The fixtures are the ones the Core regtest harness runs (tools/core-regtest
// harness/scenarios/rbf.py): five 21-transaction clusters swept by one
// replacement, and a 1-in-40-out replacement that pays enough but worsens
// the feerate diagram.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

const clusterRBFFunding = 5_000_000_000

// clusterRBFMempool returns a full-RBF mempool and n confirmed anyone-can-spend
// P2SH(OP_TRUE) outpoints of clusterRBFFunding sats each.
func clusterRBFMempool(n int) (*Mempool, []wire.OutPoint) {
	utxoSet := newTestUTXOSet()
	ops := make([]wire.OutPoint, n)
	for i := range ops {
		var h wire.Hash256
		h[0], h[1], h[2] = 0xC1, byte(i>>8), byte(i)
		ops[i] = wire.OutPoint{Hash: h, Index: 0}
		utxoSet.AddUTXO(ops[i], &consensus.UTXOEntry{
			Amount:   clusterRBFFunding,
			PkScript: p2shAnyoneCanSpendScript(),
			Height:   1,
		})
	}
	mp := New(Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, utxoSet)
	mp.SetChainHeight(800_000)
	return mp, ops
}

// sweepTx spends every outpoint in ins into one output, paying fee.
func sweepTx(ins []wire.OutPoint, inValue, fee int64) *wire.MsgTx {
	tx := spendableTxMulti(ins, inValue-fee, 1)
	for _, in := range tx.TxIn {
		in.Sequence = 0xfffffffd
	}
	return tx
}

// addCluster puts a root spending funding into `children` outputs plus one
// child per output into the pool: one cluster of children+1 transactions.
// Each transaction pays fee. Returns the cluster's total fee.
func addCluster(t *testing.T, mp *Mempool, funding wire.OutPoint, children int, fee int64) int64 {
	t.Helper()
	each := (clusterRBFFunding - fee) / int64(children)
	root := spendableTx(funding, each, children)
	root.TxOut[0].Value += clusterRBFFunding - fee - each*int64(children)
	if err := mp.AddTransaction(root); err != nil {
		t.Fatalf("cluster root rejected: %v", err)
	}
	for i, out := range root.TxOut {
		child := spendableTx(wire.OutPoint{Hash: root.TxHash(), Index: uint32(i)}, out.Value-fee, 1)
		if err := mp.AddTransaction(child); err != nil {
			t.Fatalf("cluster child %d rejected: %v", i, err)
		}
	}
	return fee * int64(children+1)
}

// TestClusterRBF_FiveClustersOf21AreOneReplacement is the harness's
// rbf/clusters scenario. The sweep conflicts with five clusters and evicts
// 105 transactions; Core 31 counts five clusters and accepts. Counting
// evictions (BIP125 rule 5) refused it with "would evict 105 transactions".
func TestClusterRBF_FiveClustersOf21AreOneReplacement(t *testing.T) {
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

	sweep := sweepTx(ops, int64(len(ops))*clusterRBFFunding, 200_000)
	if conflicts, err := mp.TestReplacement(sweep); !conflicts || err != nil {
		t.Fatalf("TestReplacement = (%v, %v), want (true, nil)", conflicts, err)
	}
	if err := mp.AddTransaction(sweep); err != nil {
		t.Fatalf("five-cluster replacement rejected: %v", err)
	}
	if got := mp.Count(); got != 1 || !mp.HasTransaction(sweep.TxHash()) {
		t.Fatalf("after replacement pool holds %d txs (sweep present %v), want only the sweep",
			got, mp.HasTransaction(sweep.TxHash()))
	}
}

// TestClusterRBF_FeesStillCoverEveryEvictedTx: counting clusters for Rule 5
// must not shrink Rule 3. The five clusters hold 105 transactions paying
// 105_000 sats; a sweep paying 100_000 is refused for its fee, with Core's
// message.
func TestClusterRBF_FeesStillCoverEveryEvictedTx(t *testing.T) {
	mp, ops := clusterRBFMempool(5)
	var total int64
	for _, op := range ops {
		total += addCluster(t, mp, op, 20, 1_000)
	}
	sweep := sweepTx(ops, int64(len(ops))*clusterRBFFunding, 100_000)
	err := mp.AddTransaction(sweep)
	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("underpaying sweep: got %v, want ErrRBFInsufficientFee", err)
	}
	want := fmt.Sprintf("insufficient fee, rejecting replacement %s, less fees than conflicting txs; %s < %s",
		sweep.TxHash(), "0.001", "0.00105")
	if total != 105_000 || err.Error() != want {
		t.Fatalf("got %q (conflict fees %d), want %q", err.Error(), total, want)
	}
	if got := mp.Count(); got != 105 {
		t.Fatalf("refused replacement changed the pool: %d txs, want 105", got)
	}
}

// TestClusterRBF_101ConflictingClustersRefused: 101 single-transaction
// clusters exceed MAX_REPLACEMENT_CANDIDATES. Core's reason and message.
func TestClusterRBF_101ConflictingClustersRefused(t *testing.T) {
	mp, ops := clusterRBFMempool(MaxRBFReplacedTxs + 1)
	for _, op := range ops {
		if err := mp.AddTransaction(spendableTx(op, clusterRBFFunding-1_000, 1)); err != nil {
			t.Fatalf("fixture tx rejected: %v", err)
		}
	}
	sweep := sweepTx(ops, int64(len(ops))*clusterRBFFunding, 10_000_000)
	err := mp.AddTransaction(sweep)
	if !errors.Is(err, ErrRBFTooManyConflicts) {
		t.Fatalf("got %v, want ErrRBFTooManyConflicts", err)
	}
	want := fmt.Sprintf("too many potential replacements, rejecting replacement %s; too many conflicting clusters (101 > 100)",
		sweep.TxHash())
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if got := mp.Count(); got != MaxRBFReplacedTxs+1 {
		t.Fatalf("refused replacement changed the pool: %d txs, want %d", got, MaxRBFReplacedTxs+1)
	}
}

// TestClusterRBF_100ConflictingClustersAccepted is the boundary: Core's ">"
// lets exactly MAX_REPLACEMENT_CANDIDATES clusters through.
func TestClusterRBF_100ConflictingClustersAccepted(t *testing.T) {
	mp, ops := clusterRBFMempool(MaxRBFReplacedTxs)
	for _, op := range ops {
		if err := mp.AddTransaction(spendableTx(op, clusterRBFFunding-1_000, 1)); err != nil {
			t.Fatalf("fixture tx rejected: %v", err)
		}
	}
	sweep := sweepTx(ops, int64(len(ops))*clusterRBFFunding, 10_000_000)
	if err := mp.AddTransaction(sweep); err != nil {
		t.Fatalf("100-cluster replacement rejected: %v", err)
	}
	if got := mp.Count(); got != 1 {
		t.Fatalf("pool holds %d txs, want 1", got)
	}
}

// TestClusterRBF_DiagramRefusalIsReplacementFailed is the harness's
// rbf/diagram scenario: a 1-in-1-out spend paying 5_000 replaced by a
// 1-in-40-out spend paying 5_200. PaysForRBF passes, the diagram gets worse,
// and Core refuses with reason "replacement-failed".
func TestClusterRBF_DiagramRefusalIsReplacementFailed(t *testing.T) {
	mp, ops := clusterRBFMempool(1)
	original := spendableTx(ops[0], clusterRBFFunding-5_000, 1)
	original.TxIn[0].Sequence = 0xfffffffd
	if err := mp.AddTransaction(original); err != nil {
		t.Fatalf("original rejected: %v", err)
	}
	const outputs = 40
	spendable := int64(clusterRBFFunding - 5_200)
	wide := spendableTx(ops[0], spendable/outputs, outputs)
	wide.TxOut[0].Value += spendable - spendable/outputs*outputs
	wide.TxIn[0].Sequence = 0xfffffffd

	err := mp.AddTransaction(wide)
	if !errors.Is(err, ErrRBFFeerateDiagram) {
		t.Fatalf("got %v, want ErrRBFFeerateDiagram", err)
	}
	const want = "replacement-failed, insufficient feerate: does not improve feerate diagram"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if _, terr := mp.TestReplacement(wide); terr == nil || terr.Error() != want {
		t.Fatalf("TestReplacement: got %v, want %q", terr, want)
	}
	if !mp.HasTransaction(original.TxHash()) || mp.Count() != 1 {
		t.Fatalf("refused replacement changed the pool")
	}
}

// chainOf puts a chain of n one-output transactions spending funding into the
// pool, each paying fee, and returns the tip's txid and output value.
func chainOf(t *testing.T, mp *Mempool, funding wire.OutPoint, n int, fee int64) (wire.Hash256, int64) {
	t.Helper()
	prev, value := funding, int64(clusterRBFFunding)
	var tip wire.Hash256
	for i := 0; i < n; i++ {
		value -= fee
		tx := spendableTx(prev, value, 1)
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("chain tx %d rejected: %v", i, err)
		}
		tip = tx.TxHash()
		prev = wire.OutPoint{Hash: tip, Index: 0}
	}
	return tip, value
}

// mergingReplacement builds two clusters, each a chain of n transactions
// whose tip has one child, and a replacement spending both tips' outputs:
// it conflicts with both children and its surviving parents (the chains)
// sit in two clusters, which the replacement merges.
func mergingReplacement(t *testing.T, n int) (*Mempool, *wire.MsgTx) {
	t.Helper()
	mp, ops := clusterRBFMempool(2)
	var ins []wire.OutPoint
	var total int64
	for _, op := range ops {
		tip, value := chainOf(t, mp, op, n, 1_000)
		in := wire.OutPoint{Hash: tip, Index: 0}
		if err := mp.AddTransaction(spendableTx(in, value-1_000, 1)); err != nil {
			t.Fatalf("child rejected: %v", err)
		}
		ins = append(ins, in)
		total += value
	}
	return mp, sweepTx(ins, total, 1_000_000)
}

// TestClusterRBF_ReplacementMergingTwoClusters: the replacement joins both
// chains' clusters. It must be counted once, in the merged cluster, and is
// accepted.
func TestClusterRBF_ReplacementMergingTwoClusters(t *testing.T) {
	mp, r := mergingReplacement(t, 3)
	if err := mp.AddTransaction(r); err != nil {
		t.Fatalf("merging replacement rejected: %v", err)
	}
	if got := mp.Count(); got != 7 {
		t.Fatalf("pool holds %d txs, want 7 (two 3-chains + replacement)", got)
	}
	if got := mp.CountDistinctClusters(mp.GetAllTxHashes()); got != 1 {
		t.Fatalf("pool holds %d clusters, want 1 (merged)", got)
	}
}

// TestClusterRBF_MergedClusterOverCountLimit: two 40-transaction chains
// merged by the replacement make an 81-transaction cluster. Core's
// CheckMemPoolPolicyLimits refuses it "too-large-cluster" before the
// diagram, and the conflicts stay.
func TestClusterRBF_MergedClusterOverCountLimit(t *testing.T) {
	mp, r := mergingReplacement(t, 40)
	before := mp.Count()
	if _, err := mp.TestReplacement(r); !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("TestReplacement: got %v, want ErrClusterTooLarge", err)
	}
	if err := mp.AddTransaction(r); !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("AddTransaction: got %v, want ErrClusterTooLarge", err)
	}
	if got := mp.Count(); got != before {
		t.Fatalf("refused replacement changed the pool: %d txs, want %d", got, before)
	}
}

// TestClusterRBF_SurvivorCutOffByEvictionNotCounted: the limit counts only the
// component the replacement re-anchors to, not every survivor of a joined
// cluster. Cluster A is P1 and a 35-transaction side chain, joined by J,
// which spends P1 and the side chain's tip. Cluster B is a 29-transaction
// chain plus one child. The replacement spends P1's output and B's tip, so it
// evicts J and the child. With J gone the side chain is its own cluster; the
// replacement's cluster is P1 + B's chain + itself = 31 transactions, under
// MaxClusterCount, and Core accepts. Counting every survivor of A (36) plus
// B's chain (29) plus the replacement made 66 and refused it
// "too-large-cluster" before the diagram.
func TestClusterRBF_SurvivorCutOffByEvictionNotCounted(t *testing.T) {
	mp, ops := clusterRBFMempool(3)

	p1 := spendableTx(ops[0], clusterRBFFunding-1_000, 1)
	if err := mp.AddTransaction(p1); err != nil {
		t.Fatalf("P1 rejected: %v", err)
	}
	p1Out := wire.OutPoint{Hash: p1.TxHash(), Index: 0}
	sideTip, sideValue := chainOf(t, mp, ops[1], 35, 1_000)
	joiner := sweepTx([]wire.OutPoint{p1Out, {Hash: sideTip, Index: 0}},
		clusterRBFFunding-1_000+sideValue, 1_000)
	if err := mp.AddTransaction(joiner); err != nil {
		t.Fatalf("joiner rejected: %v", err)
	}

	bTip, bValue := chainOf(t, mp, ops[2], 29, 1_000)
	bOut := wire.OutPoint{Hash: bTip, Index: 0}
	if err := mp.AddTransaction(spendableTx(bOut, bValue-1_000, 1)); err != nil {
		t.Fatalf("B child rejected: %v", err)
	}
	if got := mp.Count(); got != 67 {
		t.Fatalf("fixture: pool holds %d txs, want 67", got)
	}

	r := sweepTx([]wire.OutPoint{p1Out, bOut}, clusterRBFFunding-1_000+bValue, 500_000)
	removals := mp.replacementRemovalSetLocked(map[wire.Hash256]bool{joiner.TxHash(): true, mp.outpoints[bOut]: true})
	count, _ := mp.clusters.ProspectiveCluster(mp.clusterAdjWeightLocked(r), mp.mempoolParentsLocked(r), removals)
	if count != 31 {
		t.Fatalf("fixture: ProspectiveCluster count %d, want 31", count)
	}

	if conflicts, err := mp.TestReplacement(r); !conflicts || err != nil {
		t.Fatalf("TestReplacement = (%v, %v), want (true, nil)", conflicts, err)
	}
	if err := mp.AddTransaction(r); err != nil {
		t.Fatalf("replacement rejected: %v", err)
	}
	if got := mp.Count(); got != 66 || mp.HasTransaction(joiner.TxHash()) {
		t.Fatalf("pool holds %d txs (joiner present %v), want 66 without the joiner",
			got, mp.HasTransaction(joiner.TxHash()))
	}
	if got := mp.CountDistinctClusters(mp.GetAllTxHashes()); got != 2 {
		t.Fatalf("pool holds %d clusters, want 2 (side chain; P1+B+replacement)", got)
	}
}
