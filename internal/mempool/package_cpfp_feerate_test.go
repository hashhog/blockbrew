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
	"testing"

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
