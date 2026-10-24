package mempool

// submitpackage / AcceptPackage CPFP acceptance, Core parity.
//
// Core reference (bitcoin-core/src/validation.cpp):
//   AcceptPackage (l.1622): every member not already in the mempool is first
//     tried on its own (AcceptSubPackage({tx})). A member that is valid alone
//     ENTERS THE MEMPOOL there and its fee is never counted again. Only a
//     member that failed for its feerate (TX_RECONSIDERABLE) or for missing
//     inputs (its parent is a deferred member) is retried as a package; any
//     other failure ends the package ("transaction failed").
//   AcceptMultipleTransactionsInternal (l.1432): the retried subpackage's
//     feerate is Σ fee / Σ vsize over exactly those members, checked with
//     CheckFeeRate (l.1507).
//
// The bug these tests pin: blockbrew's first pass deferred the low-fee parent
// and the child (missing inputs) WITHOUT adding their fee or vsize, so the
// package feerate was 0/0 = 0 and every CPFP package was refused with
// "package feerate 0.00 sat/vB < minimum". In the other direction, a member
// already in the mempool had its fee counted towards the package, so a child
// paying 1 sat rode in on its confirmed-to-mempool parent's fee.

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

const cpfpFunding = 1_000_000

// cpfpPair builds parent (spends in, pays parentFee) and child (spends parent
// output 0, pays childFee). Both are 85-vbyte anyone-can-spend P2SH spends.
func cpfpPair(in wire.OutPoint, amount, parentFee, childFee int64) (*wire.MsgTx, *wire.MsgTx) {
	parent := spendableTx(in, amount-parentFee, 1)
	child := spendableTx(wire.OutPoint{Hash: parent.TxHash(), Index: 0}, amount-parentFee-childFee, 1)
	return parent, child
}

// badScript replaces input 0's scriptSig with a push of a redeem script that
// does not hash to the P2SH(OP_TRUE) commitment, so script validation fails.
func badScript(tx *wire.MsgTx) *wire.MsgTx {
	tx.TxIn[0].SignatureScript = []byte{0x01, 0x52} // push OP_2: wrong redeem script
	return tx
}

func sameWtxids(got, want []wire.Hash256) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestPackageCPFPLowFeeParentPaidForByChild is the item's failing case: a
// 1-sat parent (below the 1 sat/vB min relay feerate on its own) plus a child
// paying 20,000 sat. Core accepts both with effective feerate
// 20001/170 = 117.65 sat/vB and effective-includes = [parent, child].
func TestPackageCPFPLowFeeParentPaidForByChild(t *testing.T) {
	mp, op := spendableMempool(0xc1, cpfpFunding)
	parent, child := cpfpPair(op, cpfpFunding, 1, 20_000)

	// Precondition: the parent is not relayable alone, else this is not CPFP.
	alone, aloneOp := spendableMempool(0xc1, cpfpFunding)
	_ = aloneOp
	if err := alone.AddTransaction(parent); !errors.Is(err, ErrInsufficientFee) {
		t.Fatalf("fixture: parent alone should fail min relay fee, got %v", err)
	}

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err != nil {
		t.Fatalf("CPFP package refused: %v", err)
	}
	if !mp.HasTransaction(parent.TxHash()) || !mp.HasTransaction(child.TxHash()) {
		t.Fatalf("CPFP package members not in mempool: parent=%v child=%v",
			mp.HasTransaction(parent.TxHash()), mp.HasTransaction(child.TxHash()))
	}
	want := []wire.Hash256{parent.WTxHash(), child.WTxHash()}
	for _, tx := range []*wire.MsgTx{parent, child} {
		r := res.TxResults[tx.WTxHash()]
		if r == nil || !r.Accepted {
			t.Fatalf("result for %s: %+v, want Accepted", tx.TxHash(), r)
		}
		if !sameWtxids(r.EffectiveIncludes, want) {
			t.Errorf("effective-includes for %s = %v, want %v", tx.TxHash(), r.EffectiveIncludes, want)
		}
	}
	if got, want := res.PackageFeerate, 20_001.0/170.0; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("package feerate = %v sat/vB, want %v", got, want)
	}
}

// TestPackageCPFPChildTooCheapForBoth is the negative control for the fix: a
// package whose AGGREGATE feerate (101 sat / 170 vB = 0.59 sat/vB) is still
// below min relay must be refused, and must leave the mempool untouched. A
// fix that skipped the package feerate gate instead of computing it would
// admit this.
func TestPackageCPFPChildTooCheapForBoth(t *testing.T) {
	mp, op := spendableMempool(0xc2, cpfpFunding)
	parent, child := cpfpPair(op, cpfpFunding, 1, 100)

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err == nil {
		t.Fatal("package below min relay feerate was accepted")
	}
	if !errors.Is(err, ErrPackageInsufficientFee) {
		t.Errorf("err = %v, want ErrPackageInsufficientFee", err)
	}
	if mp.Count() != 0 {
		t.Errorf("mempool has %d txs after a refused package, want 0", mp.Count())
	}
	if r := res.TxResults[child.WTxHash()]; r == nil || r.Accepted || r.Error == nil {
		t.Errorf("child result = %+v, want a fee failure", r)
	}
}

// TestPackageInMempoolParentFeeNotCountedTwice: Core de-duplicates a member
// that is already in the mempool and evaluates only the new ones, so an
// in-mempool parent's fee cannot pay for a 1-sat child (validation.cpp:1664
// comment: "don't double-count ... fees for fee-related policy").
func TestPackageInMempoolParentFeeNotCountedTwice(t *testing.T) {
	mp, op := spendableMempool(0xc3, cpfpFunding)
	parent, child := cpfpPair(op, cpfpFunding, 5_000, 1)
	if err := mp.AddTransaction(parent); err != nil {
		t.Fatalf("fixture: parent should be accepted alone: %v", err)
	}

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err == nil {
		t.Fatal("1-sat child accepted on its in-mempool parent's fee")
	}
	if mp.HasTransaction(child.TxHash()) {
		t.Error("1-sat child is in the mempool")
	}
	if r := res.TxResults[parent.WTxHash()]; r == nil || !r.AlreadyInMempool {
		t.Errorf("parent result = %+v, want AlreadyInMempool", r)
	}
}

// TestPackageValidParentStaysWhenChildFails: a parent that pays its own way is
// accepted on its own (Core AcceptPackage individual pass submits it), so a
// child that then fails does not take the parent down with it.
func TestPackageValidParentStaysWhenChildFails(t *testing.T) {
	mp, op := spendableMempool(0xc4, cpfpFunding)
	parent := spendableTx(op, cpfpFunding-1_000, 1)
	var missing wire.Hash256
	missing[0] = 0x22
	child := spendableTxMulti([]wire.OutPoint{
		{Hash: parent.TxHash(), Index: 0},
		{Hash: missing, Index: 1},
	}, cpfpFunding-2_000, 1)

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err == nil {
		t.Fatal("package with a missing input succeeded")
	}
	if !mp.HasTransaction(parent.TxHash()) {
		t.Error("individually valid parent was not kept in the mempool")
	}
	if mp.HasTransaction(child.TxHash()) {
		t.Error("child with a missing input is in the mempool")
	}
	if r := res.TxResults[child.WTxHash()]; r == nil || !errors.Is(r.Error, ErrMissingInputs) {
		t.Errorf("child result = %+v, want ErrMissingInputs", r)
	}
	if r := res.TxResults[parent.WTxHash()]; r == nil || !r.Accepted ||
		!sameWtxids(r.EffectiveIncludes, []wire.Hash256{parent.WTxHash()}) {
		t.Errorf("parent result = %+v, want Accepted with effective-includes [parent]", r)
	}
}

// TestPackageBadScriptChildCannotRideCPFP: the invalid-becomes-valid guard. A
// high-fee child with a failing script must not get a low-fee parent in, and
// must not get in itself, however much it pays.
func TestPackageBadScriptChildCannotRideCPFP(t *testing.T) {
	mp, op := spendableMempool(0xc5, cpfpFunding)
	parent, child := cpfpPair(op, cpfpFunding, 1, 20_000)
	badScript(child)

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err == nil {
		t.Fatal("package with an invalid-script child was accepted")
	}
	if mp.Count() != 0 {
		t.Errorf("mempool has %d txs, want 0", mp.Count())
	}
	if r := res.TxResults[child.WTxHash()]; r == nil || !errors.Is(r.Error, ErrScriptValidation) {
		t.Errorf("child result = %+v, want ErrScriptValidation", r)
	}
}

// TestPackageBadScriptChildKeepsSelfPayingParent: Core accepts the parent
// alone, then refuses the child for its script; the parent stays.
func TestPackageBadScriptChildKeepsSelfPayingParent(t *testing.T) {
	mp, op := spendableMempool(0xc6, cpfpFunding)
	parent, child := cpfpPair(op, cpfpFunding, 1_000, 1_000)
	badScript(child)

	if _, err := mp.AcceptPackage([]*wire.MsgTx{parent, child}); err == nil {
		t.Fatal("package with an invalid-script child reported success")
	}
	if !mp.HasTransaction(parent.TxHash()) {
		t.Error("self-paying parent was not kept")
	}
	if mp.HasTransaction(child.TxHash()) {
		t.Error("invalid-script child is in the mempool")
	}
}

// TestPackageBadScriptParentAdmitsNothing: a parent whose script fails is a
// non-reconsiderable failure; Core quits early and the child (missing inputs)
// is never admitted, even though it pays enough for both.
func TestPackageBadScriptParentAdmitsNothing(t *testing.T) {
	for _, parentFee := range []int64{1, 1_000} {
		mp, op := spendableMempool(0xc7, cpfpFunding)
		parent, child := cpfpPair(op, cpfpFunding, parentFee, 20_000)
		badScript(parent)
		// Child commits to the bad parent's txid.
		child.TxIn[0].PreviousOutPoint.Hash = parent.TxHash()

		if _, err := mp.AcceptPackage([]*wire.MsgTx{parent, child}); err == nil {
			t.Fatalf("parentFee=%d: package with an invalid-script parent was accepted", parentFee)
		}
		if mp.Count() != 0 {
			t.Errorf("parentFee=%d: mempool has %d txs, want 0", parentFee, mp.Count())
		}
	}
}

// Package RBF (Core PackageRBFChecks, validation.cpp). Fixture: O spends the
// funding coin paying 1,000 sat, D spends O paying 1,000 sat; P double-spends
// the funding coin paying too little to replace O+D alone, C spends P.

func rbfFixture(t *testing.T, seed byte) (mp *Mempool, op wire.OutPoint, o, d *wire.MsgTx) {
	t.Helper()
	mp, op = spendableMempool(seed, cpfpFunding)
	o = spendableTx(op, cpfpFunding-1_000, 2) // two outputs so it differs from P
	o.TxOut[0].Value = cpfpFunding - 1_000 - 10_000
	o.TxOut[1].Value = 10_000
	d = spendableTx(wire.OutPoint{Hash: o.TxHash(), Index: 0}, o.TxOut[0].Value-1_000, 1)
	for _, tx := range []*wire.MsgTx{o, d} {
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	return mp, op, o, d
}

// TestPackageRBFReplacesConflictsWithCPFP: P (500 sat) cannot replace O+D
// (2,000 sat) alone; with C (10,000 sat) the package pays for the
// replacement, is its own chunk and improves the diagram. Core accepts it and
// reports O and D as replaced.
func TestPackageRBFReplacesConflictsWithCPFP(t *testing.T) {
	mp, op, o, d := rbfFixture(t, 0xe1)
	p, c := cpfpPair(op, cpfpFunding, 500, 10_000)

	res, err := mp.AcceptPackage([]*wire.MsgTx{p, c})
	if err != nil {
		t.Fatalf("package RBF refused: %v", err)
	}
	if !mp.HasTransaction(p.TxHash()) || !mp.HasTransaction(c.TxHash()) {
		t.Fatal("package members not in mempool")
	}
	if mp.HasTransaction(o.TxHash()) || mp.HasTransaction(d.TxHash()) {
		t.Fatal("replaced transactions still in mempool")
	}
	replaced := map[wire.Hash256]bool{}
	for _, h := range res.ReplacedTxs {
		replaced[h] = true
	}
	if len(replaced) != 2 || !replaced[o.TxHash()] || !replaced[d.TxHash()] {
		t.Errorf("ReplacedTxs = %v, want O and D", res.ReplacedTxs)
	}
}

// TestPackageRBFMustPayForConflicts: negative control. P+C pay 1,500 sat <
// O+D's 2,000: Core refuses with "insufficient anti-DoS fees" and O, D stay.
func TestPackageRBFMustPayForConflicts(t *testing.T) {
	mp, op, o, d := rbfFixture(t, 0xe2)
	p, c := cpfpPair(op, cpfpFunding, 500, 1_000)

	_, err := mp.AcceptPackage([]*wire.MsgTx{p, c})
	if err == nil {
		t.Fatal("underpaying package RBF accepted")
	}
	if !mp.HasTransaction(o.TxHash()) || !mp.HasTransaction(d.TxHash()) {
		t.Error("conflicts were evicted by a refused package")
	}
	if mp.HasTransaction(p.TxHash()) || mp.HasTransaction(c.TxHash()) {
		t.Error("refused package members are in the mempool")
	}
	if want := "package RBF failed: insufficient anti-DoS fees"; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("err = %q, want prefix %q", err, want)
	}
}

// TestPackageRBFPackageMustBeItsOwnChunk: negative control. P pays 1,900 sat
// (22.35 sat/vB, still short of O+D alone), C only 200: the package pays for
// the replacement but its feerate (12.35 sat/vB) is below the parent's, so the
// child is only paying anti-DoS fees. Core refuses.
func TestPackageRBFPackageMustBeItsOwnChunk(t *testing.T) {
	mp, op, o, _ := rbfFixture(t, 0xe3)
	p, c := cpfpPair(op, cpfpFunding, 1_900, 200)

	_, err := mp.AcceptPackage([]*wire.MsgTx{p, c})
	if err == nil {
		t.Fatal("package whose feerate is below its parent's replaced the conflicts")
	}
	if !mp.HasTransaction(o.TxHash()) {
		t.Error("conflict was evicted by a refused package")
	}
	if want := "package RBF failed: package feerate is less than or equal to parent feerate"; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("err = %q, want prefix %q", err, want)
	}
}

// TestPackageRBFOnlyOneParentOneChild: negative control. A conflicting
// subpackage of three is not a package RBF Core considers.
func TestPackageRBFOnlyOneParentOneChild(t *testing.T) {
	mp, op, o, _ := rbfFixture(t, 0xe4)
	p1 := spendableTx(op, cpfpFunding-500, 1)
	// A second parent, funded from its own confirmed coin (a package RBF
	// member may not have mempool parents).
	var h2 wire.Hash256
	h2[0] = 0xe5
	op2 := wire.OutPoint{Hash: h2, Index: 0}
	mp.utxoSet.(*testUTXOSet).AddUTXO(op2, &consensus.UTXOEntry{Amount: cpfpFunding, PkScript: p2shAnyoneCanSpendScript(), Height: 1})
	p2 := spendableTx(op2, cpfpFunding-1, 1) // 1 sat: deferred too
	c := spendableTxMulti([]wire.OutPoint{
		{Hash: p1.TxHash(), Index: 0},
		{Hash: p2.TxHash(), Index: 0},
	}, 2*cpfpFunding-501-50_000, 1)

	_, err := mp.AcceptPackage([]*wire.MsgTx{p1, p2, c})
	if err == nil {
		t.Fatal("three-transaction package RBF accepted")
	}
	if !mp.HasTransaction(o.TxHash()) {
		t.Error("conflict was evicted by a refused package")
	}
	if want := "package RBF failed: package must be 1-parent-1-child"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
}

// TestPackageReportsSigopAdjustedVSize: Core's package results and package
// feerate use GetVirtualTransactionSize(weight, sigop cost, 20), not the
// serialized vsize. A child with 30 bare 1-of-1 multisig outputs (20 legacy
// sigops each, cost 2,400) has a sigop-adjusted vsize of 2,400*20/4 = 12,000
// vB, far above its serialized size.
func TestPackageReportsSigopAdjustedVSize(t *testing.T) {
	mp, op := spendableMempool(0xf1, cpfpFunding)
	parent := spendableTx(op, cpfpFunding-1, 1)
	pub := make([]byte, 33)
	pub[0] = 0x02
	pub[32] = 0x01
	multisig := append(append([]byte{0x51, 0x21}, pub...), 0x51, 0xae) // OP_1 <pub> OP_1 OP_CHECKMULTISIG
	child := spendableTx(wire.OutPoint{Hash: parent.TxHash(), Index: 0}, 1_000, 31)
	for i := 1; i < 31; i++ {
		child.TxOut[i].PkScript = multisig
	}
	childFee := int64(50_000)
	child.TxOut[0].Value = cpfpFunding - 1 - childFee - 30*1_000

	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err != nil {
		t.Fatalf("package refused: %v", err)
	}
	const wantChild = 2_400 * 20 / 4
	if raw := (consensus.CalcTxWeight(child) + 3) / 4; raw >= wantChild {
		t.Fatalf("fixture: serialized vsize %d is not below the sigop-adjusted %d", raw, wantChild)
	}
	if got := res.TxResults[child.WTxHash()].VSize; got != wantChild {
		t.Errorf("child vsize = %d, want sigop-adjusted %d", got, wantChild)
	}
	if got := res.TxResults[parent.WTxHash()].VSize; got != 85 {
		t.Errorf("parent vsize = %d, want 85", got)
	}
	if want := float64(1+childFee) / float64(85+wantChild); res.PackageFeerate != want {
		t.Errorf("package feerate = %v, want %v (sigop-adjusted)", res.PackageFeerate, want)
	}
}

// TRUC (version 3) packages. Core runs PackageTRUCChecks over every member of
// the subpackage before any member is submitted and before any conflict is
// evicted (validation.cpp:1479-1486, ahead of FinalizeSubpackage). blockbrew
// ran it member by member AFTER adding the previous member, so the just-added
// in-package parent was counted twice (as a mempool parent and as an
// in-package parent) and every 1-parent-1-child TRUC package was refused with
// "too many ancestors" — after the package RBF eviction had already run.

// trucPair is cpfpPair with the parent at version 3 and the child at
// childVersion.
func trucPair(in wire.OutPoint, amount, parentFee, childFee int64, childVersion int32) (*wire.MsgTx, *wire.MsgTx) {
	parent := spendableTx(in, amount-parentFee, 1)
	parent.Version = TRUCVersion
	child := spendableTx(wire.OutPoint{Hash: parent.TxHash(), Index: 0}, amount-parentFee-childFee, 1)
	child.Version = childVersion
	return parent, child
}

// TestPackageTRUCCPFPAccepted: a 1-sat version-3 parent and a 20,000-sat
// version-3 child (85 vB, under TRUC_CHILD_MAX_VSIZE) have two ancestors
// counting the child itself, which is the TRUC limit. Core accepts both.
func TestPackageTRUCCPFPAccepted(t *testing.T) {
	mp, op := spendableMempool(0xd1, cpfpFunding)
	parent, child := trucPair(op, cpfpFunding, 1, 20_000, TRUCVersion)

	if _, err := mp.AcceptPackage([]*wire.MsgTx{parent, child}); err != nil {
		t.Fatalf("TRUC CPFP package refused: %v", err)
	}
	if !mp.HasTransaction(parent.TxHash()) || !mp.HasTransaction(child.TxHash()) {
		t.Fatalf("TRUC package members not in mempool: parent=%v child=%v",
			mp.HasTransaction(parent.TxHash()), mp.HasTransaction(child.TxHash()))
	}
}

// TestPackageTRUCRBFReplacesConflicts is the version-3 shape of
// TestPackageRBFReplacesConflictsWithCPFP: Core accepts it and replaces O, D.
func TestPackageTRUCRBFReplacesConflicts(t *testing.T) {
	mp, op, o, d := rbfFixture(t, 0xd2)
	p, c := trucPair(op, cpfpFunding, 500, 10_000, TRUCVersion)

	if _, err := mp.AcceptPackage([]*wire.MsgTx{p, c}); err != nil {
		t.Fatalf("TRUC package RBF refused: %v", err)
	}
	if !mp.HasTransaction(p.TxHash()) || !mp.HasTransaction(c.TxHash()) {
		t.Fatal("package members not in mempool")
	}
	if mp.HasTransaction(o.TxHash()) || mp.HasTransaction(d.TxHash()) {
		t.Fatal("replaced transactions still in mempool")
	}
}

// TestPackageTRUCViolationKeepsConflicts: a package that pays for the
// replacement of O+D but breaks a TRUC rule (a version-2 child spending a
// version-3 parent) is refused, and refusing it must not have evicted O or D:
// Core judges TRUC before anything is removed.
func TestPackageTRUCViolationKeepsConflicts(t *testing.T) {
	mp, op, o, d := rbfFixture(t, 0xd3)
	p, c := trucPair(op, cpfpFunding, 500, 10_000, 2)

	if _, err := mp.AcceptPackage([]*wire.MsgTx{p, c}); err == nil {
		t.Fatal("version-2 child of a version-3 parent was accepted")
	}
	if mp.HasTransaction(p.TxHash()) || mp.HasTransaction(c.TxHash()) {
		t.Error("refused package left a member in the mempool")
	}
	if !mp.HasTransaction(o.TxHash()) || !mp.HasTransaction(d.TxHash()) {
		t.Errorf("refused package evicted its conflicts: O=%v D=%v",
			mp.HasTransaction(o.TxHash()), mp.HasTransaction(d.TxHash()))
	}
}
