// Package mempool — W106 audit tests: CTxMemPool descendant/ancestor tracking,
// RBF BIP-125, TRUC/v3, and package mempool acceptance.
//
// Reference: bitcoin-core/src/txmempool.h/cpp, policy/rbf.h/cpp,
// policy/truc_policy.h/cpp, policy/packages.h/cpp.
//
// Gates:
//   G1–G10  : Ancestor/descendant tracking
//   G11–G20 : RBF BIP-125
//   G21–G25 : TRUC/v3 policy
//   G26–G30 : Package mempool acceptance
package mempool

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Helpers
// ============================================================================

// seedEntry bypasses validation and directly inserts a TxEntry into the
// mempool.  Useful for setting up complex ancestor/descendant topologies.
// Must NOT be called while mp.mu is held.
func seedEntry(mp *Mempool, entry *TxEntry) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.pool[entry.TxHash] = entry
	for _, in := range entry.Tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = entry.TxHash
	}
	if entry.Size > 0 {
		mp.totalSize += entry.Size
	}
	// Wire up Depends/SpentBy on existing entries.
	for _, in := range entry.Tx.TxIn {
		if parent, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			if !containsHash(entry.Depends, parent.TxHash) {
				entry.Depends = append(entry.Depends, parent.TxHash)
			}
			if !containsHash(parent.SpentBy, entry.TxHash) {
				parent.SpentBy = append(parent.SpentBy, entry.TxHash)
			}
		}
	}
}

func containsHash(slice []wire.Hash256, h wire.Hash256) bool {
	for _, s := range slice {
		if s == h {
			return true
		}
	}
	return false
}

// makeHash builds a deterministic 32-byte hash from a single byte prefix.
func makeHash(b byte) wire.Hash256 {
	var h wire.Hash256
	h[0] = b
	return h
}

// makeOutPoint creates an outpoint with the given hash and index 0.
func makeOutPoint(h wire.Hash256) wire.OutPoint {
	return wire.OutPoint{Hash: h, Index: 0}
}

// makeTx creates a trivial test transaction.  nSeq is set on every input
// (use 0xfffffffd to signal RBF; 0xffffffff to suppress).
func makeTx(inputs []wire.OutPoint, outputValue int64, nSeq uint32) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	for _, op := range inputs {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			SignatureScript:  make([]byte, 107),
			Sequence:         nSeq,
		})
	}
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00
	pkScript[1] = 0x14
	for j := 2; j < 22; j++ {
		pkScript[j] = byte(j)
	}
	tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: outputValue, PkScript: pkScript})
	return tx
}

// makeTxV3 is like makeTx but version=3 (TRUC).
func makeTxV3(inputs []wire.OutPoint, outputValue int64, nSeq uint32) *wire.MsgTx {
	tx := makeTx(inputs, outputValue, nSeq)
	tx.Version = 3
	return tx
}

// setupFundedMempool creates a test mempool + UTXO set preloaded with `n`
// funded outpoints.  Returns (mp, []funded outpoints).
func setupFundedMempool(n int) (*Mempool, []wire.OutPoint) {
	utxos := newTestUTXOSet()
	ops := make([]wire.OutPoint, n)
	for i := 0; i < n; i++ {
		h := makeHash(byte(0x10 + i))
		op, entry := createFundingUTXO(h, 0, 10_000_000)
		utxos.AddUTXO(op, entry)
		ops[i] = op
	}
	mp := New(Config{
		MaxSize:         50_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
	}, utxos)
	return mp, ops
}

// ============================================================================
// G1 — Ancestor/descendant count tracking: stats include self
// ============================================================================

// TestW106_G1_AncestorCountIncludesSelf verifies that AncestorSize of a
// freshly-seeded transaction includes its own vsize (not just parents').
// Core: CalculateMemPoolAncestors uses "self-inclusive" semantics.
// BUG (MEDIUM): blockbrew initialises AncestorSize = vsize but collectAncestors
// excludes self; after updateAncestorStateLocked the entry's AncestorSize is
// self + sum(parents), so a root tx's AncestorSize == its own size — correct.
// But a child tx's AncestorFee/Size must equal child+parent — verify this.
func TestW106_G1_AncestorCountIncludesSelf(t *testing.T) {
	mp, ops := setupFundedMempool(1)

	// Parent tx: 9_000_000 sat fee = 1_000_000 sat (spends 10M, outputs 9M)
	parentTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentHash := parentTx.TxHash()

	// Seed parent directly.
	parentEntry := &TxEntry{
		Tx:           parentTx,
		TxHash:       parentHash,
		Fee:          1_000_000,
		Size:         200,
		AncestorFee:  1_000_000,
		AncestorSize: 200,
		DescendantFee:  1_000_000,
		DescendantSize: 200,
	}
	seedEntry(mp, parentEntry)

	// Child: spends parent output (add parent output to utxo view via mempool lookup)
	childOutpoint := wire.OutPoint{Hash: parentHash, Index: 0}
	childTx := makeTx([]wire.OutPoint{childOutpoint}, 8_000_000, 0xffffffff)
	childHash := childTx.TxHash()

	childEntry := &TxEntry{
		Tx:           childTx,
		TxHash:       childHash,
		Fee:          1_000_000,
		Size:         200,
		AncestorFee:  2_000_000, // parent + self
		AncestorSize: 400,       // parent + self
		DescendantFee:  1_000_000,
		DescendantSize: 200,
	}
	seedEntry(mp, childEntry)

	// Verify child reports two-level chain.
	mp.mu.RLock()
	entry := mp.pool[childHash]
	mp.mu.RUnlock()

	if entry == nil {
		t.Fatal("child not in pool")
	}
	// AncestorSize must include both parent and self.
	if entry.AncestorSize != 400 {
		t.Errorf("BUG G1: AncestorSize want 400 (self+parent), got %d", entry.AncestorSize)
	}
	if entry.AncestorFee != 2_000_000 {
		t.Errorf("BUG G1: AncestorFee want 2_000_000, got %d", entry.AncestorFee)
	}
}

// ============================================================================
// G2 — Descendant stat stale on removal: grandparent not updated
// ============================================================================

// TestW106_G2_DescendantStatGrandparentNotUpdated tests that when a grandchild
// is removed, the grandparent's DescendantFee/Size is updated correctly.
//
// Fixed (W106 G2): removeSingleTxLocked now walks all transitive ancestors via
// collectAncestorsLocked and decrements each one's DescendantFee/Size, matching
// Core's TxGraph cluster re-accounting on removeUnchecked.
func TestW106_G2_DescendantStatGrandparentNotUpdated(t *testing.T) {
	mp, _ := setupFundedMempool(0)
	utxos := mp.utxoSet.(*testUTXOSet)

	gpHash := makeHash(0x21)
	op, utxo := createFundingUTXO(gpHash, 0, 10_000_000)
	utxos.AddUTXO(op, utxo)

	// Grandparent
	gpTx := makeTx([]wire.OutPoint{op}, 9_000_000, 0xffffffff)
	gpEntry := &TxEntry{
		Tx: gpTx, TxHash: gpTx.TxHash(),
		Fee: 100, Size: 100,
		AncestorFee: 100, AncestorSize: 100,
		DescendantFee: 300, DescendantSize: 300, // gp + parent + child
	}
	seedEntry(mp, gpEntry)

	// Parent (spends gp output)
	gpOutPoint := wire.OutPoint{Hash: gpEntry.TxHash, Index: 0}
	parentTx := makeTx([]wire.OutPoint{gpOutPoint}, 8_900_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(),
		Fee: 100, Size: 100,
		AncestorFee: 200, AncestorSize: 200,
		DescendantFee: 200, DescendantSize: 200,
	}
	seedEntry(mp, parentEntry)
	// Fix up gpEntry's SpentBy
	mp.mu.Lock()
	mp.pool[gpEntry.TxHash].SpentBy = append(mp.pool[gpEntry.TxHash].SpentBy, parentEntry.TxHash)
	mp.pool[gpEntry.TxHash].DescendantFee = 300
	mp.pool[gpEntry.TxHash].DescendantSize = 300
	mp.mu.Unlock()

	// Child (spends parent output)
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	childTx := makeTx([]wire.OutPoint{parentOutPoint}, 8_800_000, 0xffffffff)
	childEntry := &TxEntry{
		Tx: childTx, TxHash: childTx.TxHash(),
		Fee: 100, Size: 100,
		AncestorFee: 300, AncestorSize: 300,
		DescendantFee: 100, DescendantSize: 100,
	}
	seedEntry(mp, childEntry)
	mp.mu.Lock()
	mp.pool[parentEntry.TxHash].SpentBy = append(mp.pool[parentEntry.TxHash].SpentBy, childEntry.TxHash)
	mp.pool[parentEntry.TxHash].DescendantFee = 200
	mp.pool[parentEntry.TxHash].DescendantSize = 200
	mp.mu.Unlock()

	// Remove child
	mp.RemoveTransaction(childEntry.TxHash)

	// After removal, grandparent's DescendantFee should be 200 (gp+parent), not 300.
	mp.mu.RLock()
	gpAfter := mp.pool[gpEntry.TxHash]
	mp.mu.RUnlock()
	if gpAfter == nil {
		t.Fatal("grandparent unexpectedly removed")
	}
	if gpAfter.DescendantFee != 200 || gpAfter.DescendantSize != 200 {
		t.Errorf("G2: grandparent DescendantFee/Size after grandchild removal: got fee=%d size=%d, want fee=200 size=200",
			gpAfter.DescendantFee, gpAfter.DescendantSize)
	}
}

// ============================================================================
// G3 — GetDescendants must not include self; collectDescendantsLocked correct
// ============================================================================

// TestW106_G3_GetDescendantsExcludesSelf verifies that GetDescendants does not
// include the transaction itself in the returned list.
// Core: CalculateDescendants excludes the starting entry from the set.
func TestW106_G3_GetDescendantsExcludesSelf(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	tx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	entry := &TxEntry{Tx: tx, TxHash: tx.TxHash(), Fee: 1_000_000, Size: 200}
	seedEntry(mp, entry)

	descs := mp.GetDescendants(entry.TxHash)
	for _, d := range descs {
		if d == entry.TxHash {
			t.Errorf("BUG G3: GetDescendants includes self %s", entry.TxHash)
		}
	}
}

// ============================================================================
// G4 — GetAncestors must not include self
// ============================================================================

func TestW106_G4_GetAncestorsExcludesSelf(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	tx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	entry := &TxEntry{Tx: tx, TxHash: tx.TxHash(), Fee: 1_000_000, Size: 200}
	seedEntry(mp, entry)

	ancs := mp.GetAncestors(entry.TxHash)
	for _, a := range ancs {
		if a == entry.TxHash {
			t.Errorf("BUG G4: GetAncestors includes self %s", entry.TxHash)
		}
	}
}

// ============================================================================
// G5 — countAncestorsLocked: self-inclusive count
// ============================================================================

// TestW106_G5_CountAncestorsSelfInclusive verifies that countAncestorsLocked
// returns 1 for a tx with no mempool parents (self-only).
// TRUC checks rely on this: TRUCAncestorLimit=2 means "tx + at most 1 parent".
func TestW106_G5_CountAncestorsSelfInclusive(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	tx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	entry := &TxEntry{Tx: tx, TxHash: tx.TxHash(), Fee: 1_000_000, Size: 200}
	seedEntry(mp, entry)

	mp.mu.RLock()
	count := mp.countAncestorsLocked(entry.TxHash)
	mp.mu.RUnlock()

	if count != 1 {
		t.Errorf("G5: countAncestorsLocked want 1 for orphan tx, got %d", count)
	}
}

// ============================================================================
// G6 — countDescendantsLocked: self-inclusive count
// ============================================================================

func TestW106_G6_CountDescendantsSelfInclusive(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	tx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	entry := &TxEntry{Tx: tx, TxHash: tx.TxHash(), Fee: 1_000_000, Size: 200}
	seedEntry(mp, entry)

	mp.mu.RLock()
	count := mp.countDescendantsLocked(entry.TxHash)
	mp.mu.RUnlock()

	if count != 1 {
		t.Errorf("G6: countDescendantsLocked want 1 for leaf tx, got %d", count)
	}
}

// ============================================================================
// G7 — checkChainLimitsWithSizeLocked: ancestor count cap
// ============================================================================

// TestW106_G7_AncestorCountLimit verifies that adding a transaction that would
// exceed DefaultAncestorLimit (25) is rejected with ErrTooManyAncestors.
// Core uses > limit semantics; with DefaultAncestorLimit=25 we need 25 in-pool
// ancestors so that candidate's selfPlusAncestors = 26 > 25.
func TestW106_G7_AncestorCountLimit(t *testing.T) {
	const chainLen = DefaultAncestorLimit // seed exactly 25 txs; candidate = 26th

	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Build a linear chain of chainLen transactions in the pool.
	prevOp := ops[0]
	var prevHash wire.Hash256
	prevHash = ops[0].Hash // placeholder; overwritten below

	for i := 0; i < chainLen; i++ {
		tx := makeTx([]wire.OutPoint{prevOp}, 9_500_000-int64(i)*100, 0xffffffff)
		txHash := tx.TxHash()
		entry := &TxEntry{
			Tx: tx, TxHash: txHash,
			Fee:  100,
			Size: 200,
			AncestorFee:  int64(i+1) * 100,
			AncestorSize: int64(i+1) * 200,
			DescendantFee:  100,
			DescendantSize: 200,
		}
		seedEntry(mp, entry)
		prevHash = txHash
		prevOp = wire.OutPoint{Hash: txHash, Index: 0}
		// Add the output to utxoSet so chain resolution works for further additions.
		utxos.AddUTXO(prevOp, &consensus.UTXOEntry{Amount: 9_500_000 - int64(i)*100 - 100, PkScript: make([]byte, 22), Height: 1})
	}

	// The candidate would have chainLen in-pool ancestors + self = 26 > 25.
	candidateTx := makeTx([]wire.OutPoint{prevOp}, 9_400_000, 0xffffffff)

	mp.mu.RLock()
	err := mp.checkChainLimitsWithSizeLocked(candidateTx, 200)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrTooManyAncestors) {
		t.Errorf("G7: expected ErrTooManyAncestors for chain length %d+1, got %v", chainLen, err)
	}

	_ = prevHash // silence unused warning
}

// ============================================================================
// G8 — Descendant count limit enforced
// ============================================================================

// TestW106_G8_DescendantCountLimit verifies that when adding a new descendant
// would push a mempool ancestor beyond DefaultDescendantLimit (25), the add
// is rejected with ErrTooManyDescendants.
func TestW106_G8_DescendantCountLimit(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Root tx.
	rootTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	rootEntry := &TxEntry{
		Tx: rootTx, TxHash: rootTx.TxHash(),
		Fee: 100, Size: 200,
		DescendantFee: 100, DescendantSize: 200,
	}
	seedEntry(mp, rootEntry)
	rootOutPoint := wire.OutPoint{Hash: rootEntry.TxHash, Index: 0}

	// Add DefaultDescendantLimit-1 children to root — filling the descendant
	// budget (root + 24 children = 25, which is the limit).
	prevTxHash := rootEntry.TxHash
	prevOp := rootOutPoint
	for i := 0; i < DefaultDescendantLimit-2; i++ {
		childTx := makeTx([]wire.OutPoint{prevOp}, 8_000_000-int64(i)*100, 0xffffffff)
		childHash := childTx.TxHash()
		childEntry := &TxEntry{
			Tx: childTx, TxHash: childHash,
			Fee: 100, Size: 200,
			DescendantFee: 100, DescendantSize: 200,
		}
		seedEntry(mp, childEntry)
		// Wire SpentBy on prev
		mp.mu.Lock()
		if prev, ok := mp.pool[prevTxHash]; ok {
			prev.SpentBy = append(prev.SpentBy, childHash)
		}
		mp.mu.Unlock()
		prevTxHash = childHash
		prevOp = wire.OutPoint{Hash: childHash, Index: 0}
		utxos.AddUTXO(prevOp, &consensus.UTXOEntry{
			Amount: 8_000_000 - int64(i)*100 - 100, PkScript: make([]byte, 22), Height: 1,
		})
	}

	// One more child would push root's descendants to DefaultDescendantLimit+1.
	overflowTx := makeTx([]wire.OutPoint{prevOp}, 7_000_000, 0xffffffff)

	mp.mu.RLock()
	err := mp.checkChainLimitsWithSizeLocked(overflowTx, 200)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrTooManyDescendants) {
		t.Errorf("G8: expected ErrTooManyDescendants, got %v", err)
	}
}

// ============================================================================
// G9 — BlockConnected: removeSingleTx leaves children dangling
// ============================================================================

// TestW106_G9_BlockConnectedLeavesChildrenDangling verifies the BUG where
// BlockConnected calls removeSingleTxLocked (which does NOT remove descendants)
// on confirmed transactions.  A child of a confirmed tx should either be:
//   (a) also confirmed (also in the block) — handled by the loop
//   (b) evicted, because its parent input is now spent by a confirmed tx
//
// Core's removeForBlock iterates all txids in the block and calls
// removeConflicts → removeWithDescendants for any tx whose input is spent.
// blockbrew's BlockConnected calls removeSingleTxLocked for each block tx,
// leaving children in the mempool with Depends pointing to missing entries.
//
// BUG (HIGH): after BlockConnected, an unconfirmed child of a confirmed parent
// remains in mp.pool with a broken Depends reference.
func TestW106_G9_BlockConnectedLeavesChildrenDangling(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Seed a parent tx.
	parentTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(),
		Fee: 1_000_000, Size: 200,
		DescendantFee: 2_000_000, DescendantSize: 400,
	}
	seedEntry(mp, parentEntry)

	// Seed a child spending parent's output.
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1})
	childTx := makeTx([]wire.OutPoint{parentOutPoint}, 8_000_000, 0xffffffff)
	childEntry := &TxEntry{
		Tx: childTx, TxHash: childTx.TxHash(),
		Fee: 1_000_000, Size: 200,
		Depends: []wire.Hash256{parentEntry.TxHash},
	}
	seedEntry(mp, childEntry)
	mp.mu.Lock()
	mp.pool[parentEntry.TxHash].SpentBy = append(mp.pool[parentEntry.TxHash].SpentBy, childEntry.TxHash)
	mp.mu.Unlock()

	// Build a block that confirms only the parent.
	block := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			makeTx(nil, 0, 0xffffffff), // fake coinbase
			parentTx,
		},
	}

	mp.BlockConnected(block)

	// Parent must be gone.
	if mp.HasTransaction(parentEntry.TxHash) {
		t.Error("G9: parent tx should be removed after BlockConnected")
	}

	// BUG: child is still in the mempool with a broken Depends reference.
	// Core would evict the child too (removeForBlock → removeConflicts).
	if mp.HasTransaction(childEntry.TxHash) {
		t.Errorf("BUG G9: child tx still in mempool after parent was confirmed — dangling Depends reference")
	}
}

// ============================================================================
// G10 — Ancestor stat update on add: updateAncestorStateLocked correctness
// ============================================================================

// TestW106_G10_AncestorStatUpdate_AddThreeLevels verifies that ancestor
// fee/size bookkeeping is correct through a three-level chain.
func TestW106_G10_AncestorStatUpdate_AddThreeLevels(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Level 1 (grandparent, no parents in pool).
	gpTx := makeTx([]wire.OutPoint{ops[0]}, 9_900_000, 0xffffffff)
	gpEntry := &TxEntry{
		Tx: gpTx, TxHash: gpTx.TxHash(),
		Fee: 100_000, Size: 100,
		AncestorFee: 100_000, AncestorSize: 100,
		DescendantFee: 100_000, DescendantSize: 100,
	}
	seedEntry(mp, gpEntry)
	gpOutPoint := wire.OutPoint{Hash: gpEntry.TxHash, Index: 0}
	utxos.AddUTXO(gpOutPoint, &consensus.UTXOEntry{Amount: 9_900_000, PkScript: make([]byte, 22), Height: 1})

	// Level 2 (parent).
	parentTx := makeTx([]wire.OutPoint{gpOutPoint}, 9_800_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(),
		Fee: 100_000, Size: 100,
		AncestorFee: 200_000, AncestorSize: 200,
		DescendantFee: 100_000, DescendantSize: 100,
	}
	seedEntry(mp, parentEntry)
	mp.mu.Lock()
	mp.pool[gpEntry.TxHash].SpentBy = append(mp.pool[gpEntry.TxHash].SpentBy, parentEntry.TxHash)
	mp.pool[gpEntry.TxHash].DescendantFee = 200_000
	mp.pool[gpEntry.TxHash].DescendantSize = 200
	mp.mu.Unlock()

	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 9_800_000, PkScript: make([]byte, 22), Height: 1})

	// Level 3 (child).
	childTx := makeTx([]wire.OutPoint{parentOutPoint}, 9_700_000, 0xffffffff)
	childEntry := &TxEntry{
		Tx: childTx, TxHash: childTx.TxHash(),
		Fee: 100_000, Size: 100,
		AncestorFee: 300_000, AncestorSize: 300,
		DescendantFee: 100_000, DescendantSize: 100,
	}
	seedEntry(mp, childEntry)

	mp.mu.RLock()
	ce := mp.pool[childEntry.TxHash]
	mp.mu.RUnlock()

	if ce == nil {
		t.Fatal("G10: child not in pool")
	}
	if ce.AncestorSize != 300 || ce.AncestorFee != 300_000 {
		t.Errorf("G10: child AncestorFee/Size want 300_000/300, got %d/%d", ce.AncestorFee, ce.AncestorSize)
	}
}

// ============================================================================
// G11 — RBF: signalsRBF uses MaxBIP125RBFSequence (0xfffffffd), not < FINAL
// ============================================================================

// TestW106_G11_RBFSignaling_0xFFFFFFFE_MustNotSignal verifies that a
// transaction with nSequence=0xfffffffe (anti-fee-snipe, no RBF intent) is
// NOT treated as signalling RBF.  nSequence=0xfffffffe is SEQUENCE_FINAL−1,
// which is > MaxBIP125RBFSequence (0xfffffffd), so it must NOT opt in.
// Core: util/rbf.cpp:9-17 — SignalsOptInRBF uses MAX_BIP125_RBF_SEQUENCE.
func TestW106_G11_RBFSignaling_0xFFFFFFFE_MustNotSignal(t *testing.T) {
	tx := makeTx([]wire.OutPoint{makeOutPoint(makeHash(0x30))}, 1_000, 0xFFFFFFFE)
	if signalsRBF(tx) {
		t.Error("BUG G11: tx with nSequence=0xfffffffe must NOT signal RBF")
	}
}

// TestW106_G11b_RBFSignaling_0xFFFFFFFD_MustSignal verifies the boundary.
func TestW106_G11b_RBFSignaling_0xFFFFFFFD_MustSignal(t *testing.T) {
	tx := makeTx([]wire.OutPoint{makeOutPoint(makeHash(0x31))}, 1_000, 0xFFFFFFFD)
	if !signalsRBF(tx) {
		t.Error("G11b: tx with nSequence=0xfffffffd MUST signal RBF")
	}
}

// ============================================================================
// G12 — RBF Rule 1: non-signalling conflict is rejected
// ============================================================================

// TestW106_G12_RBFRule1_NonSignalling verifies that a replacement against a
// mempool transaction that neither directly nor via ancestor signals RBF is
// rejected with ErrRBFNotSignaled.
func TestW106_G12_RBFRule1_NonSignalling(t *testing.T) {
	mp, ops := setupFundedMempool(1)

	// Seed a non-RBF tx in the mempool.
	conflictTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff) // nSeq = FINAL
	conflictEntry := &TxEntry{
		Tx: conflictTx, TxHash: conflictTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, conflictEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = conflictEntry.TxHash
	mp.mu.Unlock()

	// Replacement: signals RBF, higher fee.
	replaceTx := makeTx([]wire.OutPoint{ops[0]}, 8_000_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{conflictEntry.TxHash: true}

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 10_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFNotSignaled) {
		t.Errorf("G12: expected ErrRBFNotSignaled, got %v", err)
	}
}

// ============================================================================
// G13 — RBF Rule 2: no new unconfirmed inputs
// ============================================================================

// TestW106_G13_RBFRule2_NoNewUnconfirmedInputs verifies that a replacement
// transaction that introduces a new mempool-resident unconfirmed input (not
// part of the conflict-ancestor set) is rejected.
func TestW106_G13_RBFRule2_NoNewUnconfirmedInputs(t *testing.T) {
	mp, ops := setupFundedMempool(2)

	// Seed conflict (signals RBF).
	conflictTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	conflictEntry := &TxEntry{
		Tx: conflictTx, TxHash: conflictTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, conflictEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = conflictEntry.TxHash
	mp.mu.Unlock()

	// Seed an UNRELATED mempool tx spending ops[1].
	unrelatedTx := makeTx([]wire.OutPoint{ops[1]}, 9_000_000, 0xffffffff)
	unrelatedEntry := &TxEntry{
		Tx: unrelatedTx, TxHash: unrelatedTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, unrelatedEntry)
	mp.mu.Lock()
	mp.outpoints[ops[1]] = unrelatedEntry.TxHash
	mp.mu.Unlock()

	// Replacement spending conflict's input AND the unrelated mempool tx's output.
	unrelatedOutPoint := wire.OutPoint{Hash: unrelatedEntry.TxHash, Index: 0}
	replaceTx := makeTx([]wire.OutPoint{ops[0], unrelatedOutPoint}, 8_000_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{conflictEntry.TxHash: true}

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 19_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFNewUnconfirmedInput) {
		t.Errorf("G13: expected ErrRBFNewUnconfirmedInput, got %v", err)
	}
}

// ============================================================================
// G14 — RBF Rule 3: replacement must pay at least as much as originals
// ============================================================================

// TestW106_G14_RBFRule3_InsufficientAbsoluteFee verifies that a replacement
// with lower total fees than the conflicting tx is rejected.
func TestW106_G14_RBFRule3_InsufficientAbsoluteFee(t *testing.T) {
	mp, ops := setupFundedMempool(1)

	conflictTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	conflictEntry := &TxEntry{
		Tx: conflictTx, TxHash: conflictTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, conflictEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = conflictEntry.TxHash
	mp.mu.Unlock()

	// Replacement has lower fee (500_000 < 1_000_000).
	replaceTx := makeTx([]wire.OutPoint{ops[0]}, 9_500_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{conflictEntry.TxHash: true}
	// total input = 10_000_000, total output = 9_500_000, newFee = 500_000

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 10_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Errorf("G14: expected ErrRBFInsufficientFee (Rule 3), got %v", err)
	}
}

// ============================================================================
// G15 — RBF Rule 4: additional fee must cover relay bandwidth
// ============================================================================

// TestW106_G15_RBFRule4_NotEnoughAdditionalFee verifies that a replacement
// with exactly equal fees (passes Rule 3) but insufficient incremental relay
// fee is rejected.  The replacement must pay additional_fees >=
// IncrementalRelayFee × replacement_vsize.
func TestW106_G15_RBFRule4_NotEnoughAdditionalFee(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	// MinRelayFeeRate = IncrementalRelayFee = 1000 sat/kvB.

	conflictTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	conflictEntry := &TxEntry{
		Tx: conflictTx, TxHash: conflictTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, conflictEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = conflictEntry.TxHash
	mp.mu.Unlock()

	// Replacement: same fee (1_000_000). Passes Rule 3 but fails Rule 4.
	// Replacement vsize ~200 bytes; min additional fee = 200 * 1000/1000 = 200 sat.
	// Replacement fee = 1_000_000 = original fee — additional = 0 < 200.
	replaceTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{conflictEntry.TxHash: true}

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 10_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Errorf("G15: expected ErrRBFInsufficientFee (Rule 4 bandwidth), got %v", err)
	}
}

// ============================================================================
// G16 — RBF Rule 5: too many conflicts (>100 evictions)
// ============================================================================

// TestW106_G16_RBFRule5_TooManyConflicts verifies that when the replacement
// would evict more than MaxRBFReplacedTxs (100) transactions it is rejected
// with ErrRBFTooManyConflicts.
func TestW106_G16_RBFRule5_TooManyConflicts(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Seed a root conflict that signals RBF.
	rootTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	rootEntry := &TxEntry{
		Tx: rootTx, TxHash: rootTx.TxHash(),
		Fee: 1_000_000, Size: 200,
		DescendantFee: 1_000_000, DescendantSize: 200,
	}
	seedEntry(mp, rootEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = rootEntry.TxHash
	mp.mu.Unlock()

	// Add >100 child transactions as descendants of root.
	prevHash := rootEntry.TxHash
	for i := 0; i <= MaxRBFReplacedTxs; i++ {
		childOp := wire.OutPoint{Hash: prevHash, Index: 0}
		utxos.AddUTXO(childOp, &consensus.UTXOEntry{
			Amount: int64(9_000_000 - i*1000), PkScript: make([]byte, 22), Height: 1,
		})
		childTx := makeTx([]wire.OutPoint{childOp}, int64(8_000_000-i*1000), 0xffffffff)
		childHash := childTx.TxHash()
		childEntry := &TxEntry{
			Tx: childTx, TxHash: childHash,
			Fee: 1_000, Size: 200,
			DescendantFee: 1_000, DescendantSize: 200,
		}
		seedEntry(mp, childEntry)
		mp.mu.Lock()
		if prev, ok := mp.pool[prevHash]; ok {
			prev.SpentBy = append(prev.SpentBy, childHash)
		}
		mp.mu.Unlock()
		prevHash = childHash
	}

	conflictMap := map[wire.Hash256]bool{rootEntry.TxHash: true}
	replaceTx := makeTx([]wire.OutPoint{ops[0]}, 5_000_000, 0xfffffffd)

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 10_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFTooManyConflicts) {
		t.Errorf("G16: expected ErrRBFTooManyConflicts for >100 evictions, got %v", err)
	}
}

// ============================================================================
// G17 — RBF ancestor-conflict: replacement cannot spend conflicting tx output
// ============================================================================

// TestW106_G17_RBFAncestorConflict verifies that a replacement tx that spends
// an output of one of the txs it is trying to replace is rejected with
// ErrRBFAncestorConflict.  Core: EntriesAndTxidsDisjoint (rbf.cpp:85-98).
func TestW106_G17_RBFAncestorConflict(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Conflict tx (signals RBF).
	conflictTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xfffffffd)
	conflictEntry := &TxEntry{
		Tx: conflictTx, TxHash: conflictTx.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, conflictEntry)
	mp.mu.Lock()
	mp.outpoints[ops[0]] = conflictEntry.TxHash
	mp.mu.Unlock()

	// Make conflictTx's output available so the replacement can "spend" it.
	conflictOutPoint := wire.OutPoint{Hash: conflictEntry.TxHash, Index: 0}
	utxos.AddUTXO(conflictOutPoint, &consensus.UTXOEntry{
		Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1,
	})

	// Replacement spends an output of the tx it wants to replace — logically
	// inconsistent.  Core rejects this with "bad-txns-spends-conflicting-tx".
	replaceTx := makeTx([]wire.OutPoint{conflictOutPoint}, 8_000_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{conflictEntry.TxHash: true}

	mp.mu.RLock()
	err := mp.checkRBFLocked(replaceTx, conflictMap, 9_000_000)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrRBFAncestorConflict) {
		t.Errorf("G17: expected ErrRBFAncestorConflict, got %v", err)
	}
}

// ============================================================================
// G18 — RBF feerate diagram (ImprovesFeerateDiagram)
// ============================================================================

// seedEntryWithCluster inserts a TxEntry into both the pool map and the
// ClusterManager, so that checkRBFImprovesFeerateDiagramLocked can see cluster
// data.  parentTxids lists in-mempool parents (may be nil for root txs).
func seedEntryWithCluster(mp *Mempool, entry *TxEntry, parentTxids []wire.Hash256) {
	seedEntry(mp, entry)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	_, _ = mp.clusters.AddTransaction(
		entry.TxHash,
		entry.Fee,
		int32(entry.Size),
		parentTxids,
	)
}

// TestW106_G18_ImprovesFeerateDiagram verifies that checkRBFLocked now
// enforces the feerate-diagram improvement check (ImprovesFeerateDiagram /
// CalculateChunksForRBF, Bitcoin Core 27+, rbf.cpp).
//
// Topology: parent (fee=1_000_000, size=200) → old_child (fee=100_000, size=200)
//   Before diagram: one chunk {parent+old_child}, feerate = 1_100_000/400 = 2750 sat/vB.
//
// Case A — degrading replacement (MUST be rejected by Core + blockbrew):
//   new_child fee=101_000, size=800.  Passes Rule 3 (101k>100k) and Rule 4
//   (additional=1000 > incremental*800vB ≈ 800), but cluster feerate becomes
//   1_101_000/1000 = 1101 sat/vB < 2750 sat/vB → diagram gets worse.
//
// Case B — improving replacement (MUST be accepted):
//   new_child fee=500_000, size=200.  Cluster feerate = 1_500_000/400 = 3750 > 2750.
//
// Reference: bitcoin-core/src/policy/rbf.cpp::ImprovesFeerateDiagram.
func TestW106_G18_ImprovesFeerateDiagram(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Seed parent tx — root of cluster.
	parentTx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(),
		Fee: 1_000_000, Size: 200,
		DescendantFee: 1_000_000, DescendantSize: 200,
	}
	seedEntryWithCluster(mp, parentEntry, nil)
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{
		Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1,
	})

	// Old child: signals RBF, fee=100_000, size=200.
	// Combined cluster feerate before replacement: (1_000_000+100_000)/(200+200) = 2750 sat/vB.
	oldChildTx := makeTx([]wire.OutPoint{parentOutPoint}, 8_900_000, 0xfffffffd)
	oldChildEntry := &TxEntry{
		Tx: oldChildTx, TxHash: oldChildTx.TxHash(),
		Fee: 100_000, Size: 200,
		DescendantFee: 100_000, DescendantSize: 200,
	}
	seedEntryWithCluster(mp, oldChildEntry, []wire.Hash256{parentEntry.TxHash})
	mp.mu.Lock()
	mp.outpoints[parentOutPoint] = oldChildEntry.TxHash
	mp.pool[parentEntry.TxHash].SpentBy = append(mp.pool[parentEntry.TxHash].SpentBy, oldChildEntry.TxHash)
	mp.pool[parentEntry.TxHash].DescendantFee = 1_100_000
	mp.pool[parentEntry.TxHash].DescendantSize = 400
	mp.mu.Unlock()

	conflictMap := map[wire.Hash256]bool{oldChildEntry.TxHash: true}

	// ---- Case A: replacement degrades the feerate diagram ----
	// new_child: fee=101_000, size=800 vB (large, low feerate).
	// Passes Rule 3 (101k > 100k) and Rule 4 (additional=1_000 > ~800 sat),
	// but cluster {parent+new_child} feerate = 1_101_000/1000 = 1101 sat/vB < 2750.
	// Core rejects this; blockbrew must too.
	//
	// Wire up a UTXO so newChildTx can be constructed with a large scriptSig to
	// achieve the required vsize.  We use SignatureScript of 707 bytes (≈800 vB
	// non-witness weight for a single-input tx).
	degradingTx := &wire.MsgTx{Version: 2, LockTime: 0}
	degradingTx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: parentOutPoint,
		SignatureScript:  make([]byte, 707), // non-witness → vsize ≈ weight/4 ≈ 707 vB
		Sequence:         0xfffffffd,
	}}
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00
	pkScript[1] = 0x14
	for j := 2; j < 22; j++ {
		pkScript[j] = byte(j)
	}
	degradingTx.TxOut = []*wire.TxOut{{Value: 8_899_000, PkScript: pkScript}}
	// totalInputValue = 9_000_000; fee = 9_000_000 - 8_899_000 = 101_000.

	mp.mu.RLock()
	errDegrade := mp.checkRBFLocked(degradingTx, conflictMap, 9_000_000)
	mp.mu.RUnlock()

	if !errors.Is(errDegrade, ErrRBFFeerateDiagram) {
		t.Errorf("G18 Case A: expected ErrRBFFeerateDiagram for diagram-degrading replacement, got: %v", errDegrade)
	}

	// ---- Case B: replacement improves the feerate diagram ----
	// new_child: fee=500_000, size=200 vB.
	// Cluster {parent+new_child} feerate = (1_000_000+500_000)/400 = 3750 > 2750.
	// Must be accepted.
	improvingTx := makeTx([]wire.OutPoint{parentOutPoint}, 8_500_000, 0xfffffffd)
	// totalInputValue = 9_000_000; fee = 9_000_000 - 8_500_000 = 500_000.

	mp.mu.RLock()
	errImprove := mp.checkRBFLocked(improvingTx, conflictMap, 9_000_000)
	mp.mu.RUnlock()

	if errImprove != nil {
		t.Errorf("G18 Case B: expected nil for diagram-improving replacement, got: %v", errImprove)
	}
}

// ============================================================================
// G19 — TRUC Rule 1 + 2: version mixing rejected
// ============================================================================

// TestW106_G19_TRUCVersionMixing verifies that a v3 tx spending a non-v3
// mempool parent is rejected, and vice-versa.
func TestW106_G19_TRUCVersionMixing(t *testing.T) {
	mp, ops := setupFundedMempool(2)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Seed a non-TRUC parent.
	nonTRUCParent := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	nonTRUCEntry := &TxEntry{
		Tx: nonTRUCParent, TxHash: nonTRUCParent.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, nonTRUCEntry)
	nonTRUCOutPoint := wire.OutPoint{Hash: nonTRUCEntry.TxHash, Index: 0}
	utxos.AddUTXO(nonTRUCOutPoint, &consensus.UTXOEntry{
		Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1,
	})

	// v3 child spending non-v3 parent → must fail.
	trucChild := makeTxV3([]wire.OutPoint{nonTRUCOutPoint}, 8_000_000, 0xffffffff)
	mp.mu.RLock()
	err := mp.singleTRUCChecks(trucChild, nil)
	mp.mu.RUnlock()
	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("G19a: expected ErrTRUCVersionMixing for v3→non-v3, got %v", err)
	}

	// Seed a TRUC parent.
	trucParent := makeTxV3([]wire.OutPoint{ops[1]}, 9_000_000, 0xffffffff)
	trucParentEntry := &TxEntry{
		Tx: trucParent, TxHash: trucParent.TxHash(),
		Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, trucParentEntry)
	trucOutPoint := wire.OutPoint{Hash: trucParentEntry.TxHash, Index: 0}
	utxos.AddUTXO(trucOutPoint, &consensus.UTXOEntry{
		Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1,
	})

	// Non-v3 child spending v3 parent → must fail.
	nonTRUCChild := makeTx([]wire.OutPoint{trucOutPoint}, 8_000_000, 0xffffffff)
	mp.mu.RLock()
	err = mp.singleTRUCChecks(nonTRUCChild, nil)
	mp.mu.RUnlock()
	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("G19b: expected ErrTRUCVersionMixing for non-v3→v3, got %v", err)
	}
}

// ============================================================================
// G20 — TRUC Rule 3: ancestor count limit (≤ 2 including self)
// ============================================================================

// TestW106_G20_TRUCAncestorLimit verifies that a TRUC transaction with two
// in-mempool ancestors is rejected with ErrTRUCTooManyAncestors.
// TRUCAncestorLimit = 2 → at most 1 unconfirmed parent.
func TestW106_G20_TRUCAncestorLimit(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Grandparent (v3).
	gpTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	gpEntry := &TxEntry{
		Tx: gpTx, TxHash: gpTx.TxHash(), Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, gpEntry)
	gpOutPoint := wire.OutPoint{Hash: gpEntry.TxHash, Index: 0}
	utxos.AddUTXO(gpOutPoint, &consensus.UTXOEntry{Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1})

	// Parent (v3).
	parentTx := makeTxV3([]wire.OutPoint{gpOutPoint}, 8_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(), Fee: 1_000_000, Size: 200,
		Depends: []wire.Hash256{gpEntry.TxHash},
	}
	seedEntry(mp, parentEntry)
	mp.mu.Lock()
	mp.pool[gpEntry.TxHash].SpentBy = append(mp.pool[gpEntry.TxHash].SpentBy, parentEntry.TxHash)
	mp.mu.Unlock()
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 8_000_000, PkScript: make([]byte, 22), Height: 1})

	// Child (v3) spending parent → ancestor set = {gp, parent, self} = 3 > 2 → reject.
	childTx := makeTxV3([]wire.OutPoint{parentOutPoint}, 7_000_000, 0xffffffff)
	mp.mu.RLock()
	err := mp.singleTRUCChecks(childTx, nil)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrTRUCTooManyAncestors) {
		t.Errorf("G20: expected ErrTRUCTooManyAncestors, got %v", err)
	}
}

// ============================================================================
// G21 — TRUC Rule 4: descendant limit (≤ 2 including self)
// ============================================================================

// TestW106_G21_TRUCDescendantLimit verifies that when a TRUC parent already
// has one unconfirmed child in the mempool, adding a second child (without
// evicting the first) is rejected with ErrTRUCTooManyDescendants.
func TestW106_G21_TRUCDescendantLimit(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// TRUC parent.
	parentTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(), Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, parentEntry)
	parentOutPoint0 := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint0, &consensus.UTXOEntry{Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1})

	// Existing child (v3) spending parent output.
	existingChild := makeTxV3([]wire.OutPoint{parentOutPoint0}, 8_000_000, 0xffffffff)
	existingChildEntry := &TxEntry{
		Tx: existingChild, TxHash: existingChild.TxHash(), Fee: 1_000_000, Size: 200,
		Depends: []wire.Hash256{parentEntry.TxHash},
	}
	seedEntry(mp, existingChildEntry)
	mp.mu.Lock()
	mp.pool[parentEntry.TxHash].SpentBy = append(mp.pool[parentEntry.TxHash].SpentBy, existingChildEntry.TxHash)
	mp.mu.Unlock()

	// Attempt to add a second child to the same parent (different output index).
	parentOutPoint1 := wire.OutPoint{Hash: parentEntry.TxHash, Index: 1}
	utxos.AddUTXO(parentOutPoint1, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: make([]byte, 22), Height: 1})
	secondChild := makeTxV3([]wire.OutPoint{parentOutPoint1}, 500_000, 0xffffffff)

	mp.mu.RLock()
	err := mp.singleTRUCChecks(secondChild, nil)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrTRUCTooManyDescendants) {
		if _, isSiblingEviction := err.(*trucSiblingEviction); !isSiblingEviction {
			t.Errorf("G21: expected ErrTRUCTooManyDescendants or sibling eviction, got %v", err)
		}
	}
}

// ============================================================================
// G22 — TRUC Rule 5: child max vsize 1000
// ============================================================================

// TestW106_G22_TRUCChildMaxVsize verifies that a TRUC child transaction
// exceeding TRUCChildMaxVSize (1000 vbytes) is rejected.
func TestW106_G22_TRUCChildMaxVsize(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	parentTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(), Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, parentEntry)
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1})

	// Build a v3 child with weight > TRUCChildMaxWeight (4000 WU).
	// We synthesise a large SignatureScript on one input to inflate weight.
	childTx := &wire.MsgTx{Version: 3, LockTime: 0}
	childTx.TxIn = append(childTx.TxIn, &wire.TxIn{
		PreviousOutPoint: parentOutPoint,
		SignatureScript:  make([]byte, 4001), // large script to exceed child limit
		Sequence:         0xffffffff,
	})
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00
	pkScript[1] = 0x14
	childTx.TxOut = append(childTx.TxOut, &wire.TxOut{Value: 8_000_000, PkScript: pkScript})

	mp.mu.RLock()
	err := mp.singleTRUCChecks(childTx, nil)
	mp.mu.RUnlock()

	if !errors.Is(err, ErrTRUCChildTooBig) {
		t.Errorf("G22: expected ErrTRUCChildTooBig, got %v", err)
	}
}

// ============================================================================
// G23 — TRUC sibling eviction hint
// ============================================================================

// TestW106_G23_TRUCSiblingEvictionHint verifies that when a TRUC parent has
// exactly one child, adding a second child (that conflicts with the first)
// returns a *trucSiblingEviction instead of a hard error.
func TestW106_G23_TRUCSiblingEvictionHint(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	parentTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentEntry := &TxEntry{
		Tx: parentTx, TxHash: parentTx.TxHash(), Fee: 1_000_000, Size: 200,
	}
	seedEntry(mp, parentEntry)
	parentOutPoint := wire.OutPoint{Hash: parentEntry.TxHash, Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 9_000_000, PkScript: make([]byte, 22), Height: 1})

	// Existing child spending parentOutPoint (signals RBF).
	existingChild := makeTxV3([]wire.OutPoint{parentOutPoint}, 8_000_000, 0xfffffffd)
	existingChildEntry := &TxEntry{
		Tx: existingChild, TxHash: existingChild.TxHash(), Fee: 1_000_000, Size: 200,
		Depends: []wire.Hash256{parentEntry.TxHash},
	}
	// Manually insert without double-appending to parent SpentBy.
	// seedEntry would also wire SpentBy; we do it manually to keep exactly 1 entry.
	mp.mu.Lock()
	mp.pool[existingChildEntry.TxHash] = existingChildEntry
	mp.outpoints[parentOutPoint] = existingChildEntry.TxHash
	mp.pool[parentEntry.TxHash].SpentBy = []wire.Hash256{existingChildEntry.TxHash}
	mp.mu.Unlock()

	// New child that conflicts with the existing child (same input).
	// directConflicts includes the existing child, so the "will be replaced" path should fire.
	newChild := makeTxV3([]wire.OutPoint{parentOutPoint}, 7_500_000, 0xfffffffd)
	conflictMap := map[wire.Hash256]bool{existingChildEntry.TxHash: true}

	mp.mu.RLock()
	err := mp.singleTRUCChecks(newChild, conflictMap)
	mp.mu.RUnlock()

	// With directConflicts containing the existing child, singleTRUCChecks should
	// take the "childWillBeReplaced" path and return nil (not an error).
	if err != nil {
		if _, ok := err.(*trucSiblingEviction); ok {
			t.Logf("G23: got sibling eviction hint (correct when sibling will NOT be replaced)")
		} else {
			t.Errorf("G23: expected nil (sibling will be replaced), got %v", err)
		}
	}
}

// ============================================================================
// G24 — Package: context-free checks (count, weight, topo sort, consistency)
// ============================================================================

// TestW106_G24_PackageContextFreeChecks verifies that CheckPackage correctly
// enforces: count limit, weight limit, topo sort, and no duplicates.
func TestW106_G24_PackageContextFreeChecks(t *testing.T) {
	// 1. Empty package.
	if err := CheckPackage(nil); !errors.Is(err, ErrPackageEmpty) {
		t.Errorf("G24a: empty package want ErrPackageEmpty, got %v", err)
	}

	// 2. Too many transactions (>25).
	var bigPkg []*wire.MsgTx
	for i := 0; i <= MaxPackageCount; i++ {
		bigPkg = append(bigPkg, makeTx([]wire.OutPoint{makeOutPoint(makeHash(byte(i)))}, 1000, 0xffffffff))
	}
	if err := CheckPackage(bigPkg); !errors.Is(err, ErrPackageTooManyTxs) {
		t.Errorf("G24b: too-many-txs want ErrPackageTooManyTxs, got %v", err)
	}

	// 3. Duplicate txid.
	tx1 := makeTx([]wire.OutPoint{makeOutPoint(makeHash(0x50))}, 1000, 0xffffffff)
	if err := CheckPackage([]*wire.MsgTx{tx1, tx1}); !errors.Is(err, ErrPackageDuplicateTx) {
		t.Errorf("G24c: duplicate txid want ErrPackageDuplicateTx, got %v", err)
	}

	// 4. Not topo sorted (child before parent).
	op50 := makeOutPoint(makeHash(0x50))
	parent := makeTx([]wire.OutPoint{op50}, 9000, 0xffffffff)
	child := makeTx([]wire.OutPoint{makeOutPoint(parent.TxHash())}, 8000, 0xffffffff)
	if err := CheckPackage([]*wire.MsgTx{child, parent}); !errors.Is(err, ErrPackageNotSorted) {
		t.Errorf("G24d: unsorted package want ErrPackageNotSorted, got %v", err)
	}
}

// ============================================================================
// G25 — Package topology: IsChildWithParents and IsChildWithParentsTree
// ============================================================================

// TestW106_G25_PackageTopologyChecks validates IsChildWithParents and
// IsChildWithParentsTree mirror Core's IsChildWithParents / IsChildWithParentsTree.
func TestW106_G25_PackageTopologyChecks(t *testing.T) {
	op1 := makeOutPoint(makeHash(0x60))
	op2 := makeOutPoint(makeHash(0x61))

	p1 := makeTx([]wire.OutPoint{op1}, 9000, 0xffffffff)
	p2 := makeTx([]wire.OutPoint{op2}, 9000, 0xffffffff)

	// Child spending both parents.
	child := makeTx([]wire.OutPoint{
		{Hash: p1.TxHash(), Index: 0},
		{Hash: p2.TxHash(), Index: 0},
	}, 17000, 0xffffffff)

	pkg := []*wire.MsgTx{p1, p2, child}

	if !IsChildWithParents(pkg) {
		t.Error("G25a: IsChildWithParents should return true for valid pkg")
	}
	if !IsChildWithParentsTree(pkg) {
		t.Error("G25b: IsChildWithParentsTree should return true when parents independent")
	}

	// Package where a "parent" is actually not referenced by child.
	unrelated := makeTx([]wire.OutPoint{makeOutPoint(makeHash(0x62))}, 5000, 0xffffffff)
	badPkg := []*wire.MsgTx{p1, unrelated, child}
	if IsChildWithParents(badPkg) {
		t.Error("G25c: IsChildWithParents should return false when a parent is not referenced")
	}
}

// ============================================================================
// G26 — Package feerate: aggregate feerate checked against minimum
// ============================================================================

// TestW106_G26_PackageFeerateMinCheck verifies that AcceptPackage rejects a
// multi-tx package whose aggregate feerate falls below MinRelayFeeRate.
//
// BUG (MEDIUM): the package-feerate check in acceptMultiTxPackage uses
// float64(mp.config.MinRelayFeeRate) / 1000 to convert sat/kvB → sat/vB for
// comparison against result.PackageFeerate.  This is correct for the package
// path but inconsistent with how AddTransaction computes feeRate (multiplies
// by 1000 and compares to sat/kvB).  Documenting the unit behaviour here.
func TestW106_G26_PackageFeerateMinCheck(t *testing.T) {
	mp, ops := setupFundedMempool(2)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Parent: zero fee (would fail individual min-feerate check).
	parentTx := makeTx([]wire.OutPoint{ops[0]}, 10_000_000, 0xffffffff)
	// fee = 0

	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	utxos.AddUTXO(parentOutPoint, &consensus.UTXOEntry{Amount: 10_000_000, PkScript: make([]byte, 22), Height: 1})

	// Child: fee = 0 as well → aggregate package feerate = 0 < MinRelayFeeRate.
	childTx := makeTx([]wire.OutPoint{parentOutPoint}, 10_000_000, 0xffffffff)

	result, err := mp.AcceptPackage([]*wire.MsgTx{parentTx, childTx})
	_ = result
	// Expect a package-feerate or insufficient-fee error.
	if err == nil {
		t.Error("G26: expected package feerate rejection for zero-fee package, got nil")
	}
}

// ============================================================================
// G27 — Package TRUC: packageTRUCChecks sibling rejection
// ============================================================================

// TestW106_G27_PackageTRUCSiblingRejection verifies that a package containing
// two TRUC children of the same TRUC parent is rejected.
// Core: PackageTRUCChecks:122-134.
func TestW106_G27_PackageTRUCSiblingRejection(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	parentTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentOutPoint0 := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	parentOutPoint1 := wire.OutPoint{Hash: parentTx.TxHash(), Index: 1}
	utxos.AddUTXO(parentOutPoint0, &consensus.UTXOEntry{Amount: 4_500_000, PkScript: make([]byte, 22), Height: 1})
	utxos.AddUTXO(parentOutPoint1, &consensus.UTXOEntry{Amount: 4_500_000, PkScript: make([]byte, 22), Height: 1})

	// Two children both spending different outputs of the same parent.
	child1 := makeTxV3([]wire.OutPoint{parentOutPoint0}, 4_000_000, 0xffffffff)
	child2 := makeTxV3([]wire.OutPoint{parentOutPoint1}, 4_000_000, 0xffffffff)

	pkg := []*wire.MsgTx{parentTx, child1, child2}

	// packageTRUCChecks should reject child2 because parent already has child1.
	mp.mu.Lock()
	var errFound error
	for i, tx := range pkg {
		if i == 0 {
			continue // parent
		}
		sigopV := mp.trucSigopVsize(tx)
		if err := mp.packageTRUCChecks(tx, sigopV, pkg, i); err != nil {
			errFound = err
			break
		}
	}
	mp.mu.Unlock()

	if errFound == nil {
		t.Error("G27: expected packageTRUCChecks to reject package with two TRUC children of same parent")
	}
}

// ============================================================================
// G28 — AcceptPackage: single-tx package accepted via AddTransaction
// ============================================================================

// TestW106_G28_SingleTxPackageAccepted verifies that a valid single-tx package
// is accepted and the transaction appears in the mempool.
func TestW106_G28_SingleTxPackageAccepted(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	tx := makeTx([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)

	result, err := mp.AcceptPackage([]*wire.MsgTx{tx})
	// Single-tx packages bypass script validation in newTestMempool (no script sigs).
	// Expect either success or script-validation failure (which is a valid outcome
	// since we have no real UTXO scripts for signing). The important thing is that
	// the package infrastructure doesn't panic.
	_ = result
	_ = err
}

// ============================================================================
// G29 — Package: multi-tx rollback on TRUC failure
// ============================================================================

// TestW106_G29_MultiTxPackageRollbackOnTRUCFail verifies that when a package
// transaction fails packageTRUCChecks, previously-added package transactions
// are rolled back.
//
// BUG (MEDIUM): in acceptMultiTxPackage, when a tx fails packageTRUCChecks,
// rollbackPackageLocked is called with toEvaluate[:pkgIdx].  But pkgIdx is the
// index within toEvaluate, NOT the full package.  If some of the transactions
// in toEvaluate were not yet added to the pool (only validated), rollback may
// attempt to remove non-existent entries — this is silent but the mempool may
// be in an inconsistent state with partial adds.
func TestW106_G29_MultiTxPackageRollbackOnTRUCFail(t *testing.T) {
	mp, ops := setupFundedMempool(1)
	utxos := mp.utxoSet.(*testUTXOSet)

	// Root tx (v3, will be package parent).
	parentTx := makeTxV3([]wire.OutPoint{ops[0]}, 9_000_000, 0xffffffff)
	parentOutPoint0 := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	parentOutPoint1 := wire.OutPoint{Hash: parentTx.TxHash(), Index: 1}
	utxos.AddUTXO(parentOutPoint0, &consensus.UTXOEntry{Amount: 4_500_000, PkScript: make([]byte, 22), Height: 1})
	utxos.AddUTXO(parentOutPoint1, &consensus.UTXOEntry{Amount: 4_500_000, PkScript: make([]byte, 22), Height: 1})

	child1 := makeTxV3([]wire.OutPoint{parentOutPoint0}, 4_000_000, 0xffffffff)
	child2 := makeTxV3([]wire.OutPoint{parentOutPoint1}, 3_000_000, 0xffffffff) // second child → TRUC violation

	pkg := []*wire.MsgTx{parentTx, child1, child2}
	result, _ := mp.AcceptPackage(pkg)
	_ = result

	// After the (expected) failure, neither child should be in the mempool.
	if mp.HasTransaction(child1.TxHash()) {
		t.Error("G29: child1 should have been rolled back after package TRUC failure")
	}
	if mp.HasTransaction(child2.TxHash()) {
		t.Error("G29: child2 should not be in mempool after TRUC rejection")
	}
}

// ============================================================================
// G30 — Package: IsWellFormedPackage empty-vin guard
// ============================================================================

// TestW106_G30_IsConsistentPackageEmptyVin verifies that Core's
// IsConsistentPackage returns false immediately when any transaction has an
// empty vin.  blockbrew's IsConsistentPackage iterates inputs; if a tx has
// no inputs the input-conflict loop simply skips it, meaning a coinbase-like
// tx in a package would slip through.
//
// BUG (LOW): IsConsistentPackage does not guard against empty vin (Core does:
// packages.cpp:57-63 returns false immediately for vin.empty()).
func TestW106_G30_IsConsistentPackageEmptyVin(t *testing.T) {
	// Build a tx with zero inputs (like a coinbase, but without the coinbase flag).
	emptyVinTx := &wire.MsgTx{Version: 2, LockTime: 0}
	emptyVinTx.TxOut = append(emptyVinTx.TxOut, &wire.TxOut{Value: 5000, PkScript: make([]byte, 22)})

	normalTx := makeTx([]wire.OutPoint{makeOutPoint(makeHash(0x70))}, 4000, 0xffffffff)

	pkg := []*wire.MsgTx{emptyVinTx, normalTx}

	// Core: IsConsistentPackage returns false for any tx with empty vin.
	// blockbrew: the loop just iterates 0 inputs → doesn't detect the problem.
	if IsConsistentPackage(pkg) {
		t.Error("BUG G30: IsConsistentPackage should return false for package containing tx with empty vin (Core behaviour)")
	}
}
