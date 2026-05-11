// Package mempool — BIP-431 TRUC (Topologically Restricted Until Confirmation)
// policy enforcement.
//
// A transaction with version=3 is treated as TRUC (also called v3). TRUC rules
// restrict the mempool topology so that RBF (Replace-By-Fee) guarantees are
// stronger: each TRUC transaction may have at most one unconfirmed parent and
// may only be a parent of one unconfirmed child.
//
// Reference: bitcoin-core/src/policy/truc_policy.h + truc_policy.cpp
// BIP-431: https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki
package mempool

import (
	"fmt"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TRUC (v3) policy constants.
// Mirrors Bitcoin Core truc_policy.h.
const (
	// TRUCVersion is the transaction version that enables TRUC policy (v3).
	// Core: static constexpr decltype(CTransaction::version) TRUC_VERSION{3};
	TRUCVersion int32 = 3

	// TRUCAncestorLimit is the maximum number of transactions including a TRUC
	// tx and all its in-mempool ancestors (including itself). Value = 2 means
	// at most 1 unconfirmed parent.
	// Core: TRUC_ANCESTOR_LIMIT = 2
	TRUCAncestorLimit = 2

	// TRUCDescendantLimit is the maximum number of transactions including a
	// TRUC tx and all its in-mempool descendants (including itself). Value = 2
	// means at most 1 unconfirmed child.
	// Core: TRUC_DESCENDANT_LIMIT = 2
	TRUCDescendantLimit = 2

	// TRUCMaxVSize is the maximum sigop-adjusted virtual size (vbytes) of any
	// TRUC transaction.
	// Core: TRUC_MAX_VSIZE = 10_000
	TRUCMaxVSize int64 = 10_000

	// TRUCMaxWeight = TRUCMaxVSize × WITNESS_SCALE_FACTOR (= 4).
	// Core: TRUC_MAX_WEIGHT = TRUC_MAX_VSIZE * WITNESS_SCALE_FACTOR
	TRUCMaxWeight int64 = TRUCMaxVSize * consensus.WitnessScaleFactor

	// TRUCChildMaxVSize is the maximum sigop-adjusted virtual size (vbytes) of
	// a TRUC transaction that spends an unconfirmed TRUC parent.
	// Core: TRUC_CHILD_MAX_VSIZE = 1_000
	TRUCChildMaxVSize int64 = 1_000

	// TRUCChildMaxWeight = TRUCChildMaxVSize × WITNESS_SCALE_FACTOR.
	// Core: TRUC_CHILD_MAX_WEIGHT = TRUC_CHILD_MAX_VSIZE * WITNESS_SCALE_FACTOR
	TRUCChildMaxWeight int64 = TRUCChildMaxVSize * consensus.WitnessScaleFactor
)

// TRUC-specific sentinel errors.
var (
	// ErrTRUCVersionMixing is returned when a TRUC tx has non-TRUC in-mempool
	// ancestors, or a non-TRUC tx has TRUC in-mempool ancestors.
	// Core: SingleTRUCChecks, truc_policy.cpp:178-190.
	ErrTRUCVersionMixing = fmt.Errorf("version=3 and non-version=3 transactions cannot be mixed in the same mempool ancestor chain")

	// ErrTRUCTooManyAncestors is returned when a TRUC tx would exceed
	// TRUC_ANCESTOR_LIMIT (2) in-mempool ancestors.
	// Core: SingleTRUCChecks, truc_policy.cpp:207-210.
	ErrTRUCTooManyAncestors = fmt.Errorf("version=3 tx would have too many ancestors (limit: 2)")

	// ErrTRUCTooManyDescendants is returned when adding a TRUC tx would push a
	// parent's in-mempool descendant count above TRUC_DESCENDANT_LIMIT (2).
	// Core: SingleTRUCChecks, truc_policy.cpp:243-257.
	ErrTRUCTooManyDescendants = fmt.Errorf("version=3 parent would exceed descendant count limit (limit: 2)")

	// ErrTRUCTooBig is returned when a TRUC tx's sigop-adjusted vsize exceeds
	// TRUC_MAX_VSIZE (10_000 vbytes).
	// Core: SingleTRUCChecks, truc_policy.cpp:200-204.
	ErrTRUCTooBig = fmt.Errorf("version=3 tx exceeds maximum virtual size (10000 vbytes)")

	// ErrTRUCChildTooBig is returned when a TRUC child tx's sigop-adjusted
	// vsize exceeds TRUC_CHILD_MAX_VSIZE (1_000 vbytes).
	// Core: SingleTRUCChecks, truc_policy.cpp:223-227.
	ErrTRUCChildTooBig = fmt.Errorf("version=3 child tx exceeds maximum virtual size for TRUC child (1000 vbytes)")

	// ErrTRUCPackageTooManyAncestors is the package-context variant of ancestor
	// limit violation. Core: PackageTRUCChecks, truc_policy.cpp:76-85.
	ErrTRUCPackageTooManyAncestors = fmt.Errorf("version=3 tx in package would have too many ancestors")

	// ErrTRUCPackageTooManyDescendants is the package-context variant of
	// descendant limit violation (sibling in same package).
	// Core: PackageTRUCChecks, truc_policy.cpp:130-133.
	ErrTRUCPackageTooManyDescendants = fmt.Errorf("version=3 parent would exceed descendant count limit in package")

	// ErrTRUCPackageChildHasChild is returned when a TRUC child already has a
	// descendant in the same package (chain exceeds depth 2).
	// Core: PackageTRUCChecks, truc_policy.cpp:136-139.
	ErrTRUCPackageChildHasChild = fmt.Errorf("version=3 tx in package would have too many ancestors (chain too deep)")
)

// trucSiblingEviction is returned by singleTRUCChecks when a sibling can be
// evicted instead of rejecting the incoming transaction. The field sibling
// holds the existing child that should be considered for RBF-style eviction.
type trucSiblingEviction struct {
	msg     string
	sibling wire.Hash256
}

func (e *trucSiblingEviction) Error() string { return e.msg }

// IsTRUCSiblingEviction reports whether err is a sibling-eviction hint from
// singleTRUCChecks.
func IsTRUCSiblingEviction(err error) (wire.Hash256, bool) {
	if se, ok := err.(*trucSiblingEviction); ok {
		return se.sibling, true
	}
	return wire.Hash256{}, false
}

// trucVsize computes the sigop-adjusted virtual size for TRUC policy checks.
//
// TRUC caps (10_000 for root, 1_000 for child) are defined in terms of
// sigop-adjusted vsize, not raw vsize. This matches Bitcoin Core's
// GetVirtualTransactionSize call in SingleTRUCChecks (truc_policy.cpp:200,
// truc_policy.cpp:223), which uses bytes_per_sigop=DEFAULT_BYTES_PER_SIGOP.
//
// W76 finding: blockbrew's vsize variable at AddTransaction line 516 is the
// raw ceiling-division (weight+3)/4 without sigop adjustment. TRUC gates must
// use this function instead of the raw vsize.
//
// Must be called with mp.mu held (uses mp.lookupOutputLocked).
func (mp *Mempool) trucSigopVsize(tx *wire.MsgTx) int64 {
	weight := consensus.CalcTxWeight(tx)
	view := &mempoolUTXOView{mp: mp}
	sigOpCost := consensus.GetTransactionSigOpCost(tx, view)
	return consensus.GetVirtualTransactionSize(weight, sigOpCost, consensus.DefaultBytesPerSigOp)
}

// singleTRUCChecks enforces the BIP-431 TRUC rules for a single transaction
// being submitted to the mempool (not as part of a package).
//
// Must be called with mp.mu held.
//
// Implements Core's SingleTRUCChecks (truc_policy.cpp:171-261):
//
//   Rule 1: Non-TRUC tx must not have TRUC unconfirmed ancestors.
//   Rule 2: TRUC tx must not have non-TRUC unconfirmed ancestors.
//   Rule 3: TRUC tx ancestor set (including itself) ≤ TRUC_ANCESTOR_LIMIT (2).
//   Rule 4: TRUC tx descendant set of any parent ≤ TRUC_DESCENDANT_LIMIT (2).
//   Rule 5: TRUC tx with any unconfirmed ancestor must have sigop-vsize ≤
//            TRUC_CHILD_MAX_VSIZE (1_000).
//   Rule 6: Any TRUC tx must have sigop-vsize ≤ TRUC_MAX_VSIZE (10_000).
//
// Additionally implements the sibling-eviction hint (Core truc_policy.cpp:249-257):
// if the parent already has exactly one child in the mempool and that child
// would be the only violation, we return an *trucSiblingEviction so the
// caller can attempt to evict it under RBF rules instead of hard-rejecting.
//
// Returns nil if all checks pass. Returns *trucSiblingEviction when sibling
// eviction is applicable, or a plain error for hard violations.
func (mp *Mempool) singleTRUCChecks(tx *wire.MsgTx, directConflicts map[wire.Hash256]bool) error {
	// Collect in-mempool parents.
	var mempoolParents []*TxEntry
	for _, in := range tx.TxIn {
		if entry, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			// Deduplicate (a tx may spend multiple outputs of the same parent).
			found := false
			for _, p := range mempoolParents {
				if p.TxHash == entry.TxHash {
					found = true
					break
				}
			}
			if !found {
				mempoolParents = append(mempoolParents, entry)
			}
		}
	}

	// Rule 1 + 2: TRUC/non-TRUC inheritance check.
	// Core: truc_policy.cpp:178-190.
	for _, parent := range mempoolParents {
		parentIsTRUC := parent.Tx.Version == TRUCVersion
		txIsTRUC := tx.Version == TRUCVersion
		if txIsTRUC && !parentIsTRUC {
			return fmt.Errorf("%w: tx %s cannot spend from non-version=3 tx %s",
				ErrTRUCVersionMixing, formatHash(tx.TxHash()), formatHash(parent.TxHash))
		}
		if !txIsTRUC && parentIsTRUC {
			return fmt.Errorf("%w: non-version=3 tx %s cannot spend from version=3 tx %s",
				ErrTRUCVersionMixing, formatHash(tx.TxHash()), formatHash(parent.TxHash))
		}
	}

	// Remaining rules only apply to TRUC transactions.
	if tx.Version != TRUCVersion {
		return nil
	}

	// Rule 6: TRUC tx must have sigop-adjusted vsize ≤ TRUC_MAX_VSIZE (10_000).
	// Core: truc_policy.cpp:200-204.
	sigopVsize := mp.trucSigopVsize(tx)
	if sigopVsize > TRUCMaxVSize {
		return fmt.Errorf("%w: got %d vbytes", ErrTRUCTooBig, sigopVsize)
	}

	// Rule 3: TRUC ancestor set (including itself) ≤ TRUC_ANCESTOR_LIMIT (2).
	// With TRUC_ANCESTOR_LIMIT=2 this means: at most 1 unconfirmed parent.
	// Core: truc_policy.cpp:207-210.
	if len(mempoolParents)+1 > TRUCAncestorLimit {
		return fmt.Errorf("%w: %d parents, limit is %d total (including self)",
			ErrTRUCTooManyAncestors, len(mempoolParents), TRUCAncestorLimit)
	}

	// Remaining checks require at least one unconfirmed parent.
	if len(mempoolParents) == 0 {
		return nil
	}

	parent := mempoolParents[0]

	// Verify that the parent itself has no unconfirmed ancestors (would exceed
	// the ancestor limit of 2 for the child).
	// Core: truc_policy.cpp:214-219 — pool.GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT.
	parentAncCount := mp.countAncestorsLocked(parent.TxHash)
	if parentAncCount+1 > TRUCAncestorLimit {
		return fmt.Errorf("%w: parent %s has %d in-mempool ancestors",
			ErrTRUCTooManyAncestors, formatHash(parent.TxHash), parentAncCount)
	}

	// Rule 5: TRUC child vsize ≤ TRUC_CHILD_MAX_VSIZE (1_000 vbytes).
	// Core: truc_policy.cpp:223-227.
	if sigopVsize > TRUCChildMaxVSize {
		return fmt.Errorf("%w: got %d vbytes, limit is %d",
			ErrTRUCChildTooBig, sigopVsize, TRUCChildMaxVSize)
	}

	// Rule 4: parent's in-mempool descendant count (including parent) + 1
	// (for the incoming child) must not exceed TRUC_DESCENDANT_LIMIT (2).
	// Core: truc_policy.cpp:243-257.
	//
	// GetDescendantCount(parent_entry) is the count including the parent itself.
	// After adding the incoming tx the parent would have count+1 descendants.
	parentDescCount := mp.countDescendantsLocked(parent.TxHash)

	if parentDescCount+1 > TRUCDescendantLimit {
		// Sibling eviction: if the parent has exactly 1 existing child and that
		// child will be replaced by the incoming tx (via RBF), the descendant
		// count limit is not actually violated. Core: truc_policy.cpp:240-243,
		// "Don't double-count a transaction that is going to be replaced."
		if parentDescCount == 2 {
			childHash := mp.findSingleChildLocked(parent.TxHash)
			if childHash != (wire.Hash256{}) {
				childWillBeReplaced := directConflicts != nil && directConflicts[childHash]
				if childWillBeReplaced {
					// The child will be evicted; effective descendant count after
					// replacement is 2 (parent + incoming), which satisfies the limit.
					// Fall through to success.
					return nil
				}
				// Child is not being replaced. Consider sibling eviction hint
				// (Core: truc_policy.cpp:249-257): if the sibling has no
				// additional descendants (clean 1-child tree), return a hint.
				siblingDescCount := mp.countDescendantsLocked(childHash)
				siblingAncCount := mp.countAncestorsLocked(childHash)
				if siblingDescCount == 1 && siblingAncCount == 2 {
					return &trucSiblingEviction{
						msg:     fmt.Sprintf("version=3 parent %s would exceed descendant limit; consider evicting sibling %s", formatHash(parent.TxHash), formatHash(childHash)),
						sibling: childHash,
					}
				}
			}
		}
		return fmt.Errorf("%w: parent %s has %d descendants (including self)",
			ErrTRUCTooManyDescendants, formatHash(parent.TxHash), parentDescCount)
	}

	return nil
}

// packageTRUCChecks enforces TRUC rules for a transaction submitted inside a
// package, mirroring Core's PackageTRUCChecks (truc_policy.cpp:57-169).
//
// For each transaction in the package the function checks:
//   - Non-TRUC transactions must have no TRUC parents (mempool or package).
//   - TRUC transactions must have only TRUC parents.
//   - A TRUC child (has a parent) must have sigop-vsize ≤ TRUC_CHILD_MAX_VSIZE.
//   - The TRUC ancestor set (package + mempool) must not exceed TRUC_ANCESTOR_LIMIT.
//   - A TRUC parent must not have other children in the package or in the mempool.
//   - A TRUC child must not itself have children in the package.
//
// Must be called with mp.mu held.
// pkgTxs is the topologically-sorted package, pkgIdx is the 0-based index of
// tx within pkgTxs.
func (mp *Mempool) packageTRUCChecks(tx *wire.MsgTx, sigopVsize int64, pkgTxs []*wire.MsgTx, pkgIdx int) error {
	// Find in-package parents of tx (package must be topo-sorted, so parents
	// appear before children). Core: FindInPackageParents (truc_policy.cpp:18-37).
	inPkgParentIndices := findInPackageParents(pkgTxs, pkgIdx)

	// Collect mempool parents.
	var mempoolParents []*TxEntry
	for _, in := range tx.TxIn {
		if entry, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			found := false
			for _, p := range mempoolParents {
				if p.TxHash == entry.TxHash {
					found = true
					break
				}
			}
			if !found {
				mempoolParents = append(mempoolParents, entry)
			}
		}
	}

	if tx.Version == TRUCVersion {
		// TRUC tx: verify size ≤ TRUC_MAX_VSIZE (already checked in single-tx
		// path when available, but package path must check independently).
		// Core: PackageTRUCChecks:71-73.
		if sigopVsize > TRUCMaxVSize {
			return fmt.Errorf("version=3 tx %s is too big: %d > %d virtual bytes",
				formatHash(tx.TxHash()), sigopVsize, TRUCMaxVSize)
		}

		// Ancestor count: mempool parents + in-package parents + self ≤ 2.
		// Core: PackageTRUCChecks:76-79.
		if len(mempoolParents)+len(inPkgParentIndices)+1 > TRUCAncestorLimit {
			return fmt.Errorf("%w: tx %s", ErrTRUCPackageTooManyAncestors, formatHash(tx.TxHash()))
		}

		// If there is a mempool parent, check its ancestor count doesn't push
		// the total over the limit. Core: PackageTRUCChecks:81-85.
		if len(mempoolParents) > 0 {
			parentAncCount := mp.countAncestorsLocked(mempoolParents[0].TxHash)
			if parentAncCount+len(inPkgParentIndices)+1 > TRUCAncestorLimit {
				return fmt.Errorf("%w: tx %s (mempool parent has %d ancestors)",
					ErrTRUCPackageTooManyAncestors, formatHash(tx.TxHash()), parentAncCount)
			}
		}

		hasParent := len(mempoolParents)+len(inPkgParentIndices) > 0
		if hasParent {
			// Rule 5 in package context: child vsize ≤ TRUC_CHILD_MAX_VSIZE.
			// Core: PackageTRUCChecks:90-95.
			if sigopVsize > TRUCChildMaxVSize {
				return fmt.Errorf("version=3 child tx %s is too big: %d > %d virtual bytes",
					formatHash(tx.TxHash()), sigopVsize, TRUCChildMaxVSize)
			}

			// Determine the parent txid for sibling checks.
			var parentTxHash wire.Hash256
			var parentIsTRUC bool
			if len(mempoolParents) > 0 {
				parentTxHash = mempoolParents[0].TxHash
				parentIsTRUC = mempoolParents[0].Tx.Version == TRUCVersion
			} else {
				parentTx := pkgTxs[inPkgParentIndices[0]]
				parentTxHash = parentTx.TxHash()
				parentIsTRUC = parentTx.Version == TRUCVersion
			}

			// Rule 2 in package context: TRUC child must have TRUC parent.
			// Core: PackageTRUCChecks:115-119.
			if !parentIsTRUC {
				return fmt.Errorf("version=3 tx %s cannot spend from non-version=3 tx %s",
					formatHash(tx.TxHash()), formatHash(parentTxHash))
			}

			// No sibling allowed: no other tx in the package may spend an
			// output of the same parent. Core: PackageTRUCChecks:122-134.
			for i, pkgTx := range pkgTxs {
				if i == pkgIdx {
					continue
				}
				for _, in := range pkgTx.TxIn {
					if in.PreviousOutPoint.Hash == parentTxHash {
						return fmt.Errorf("%w: parent %s already has another child in the package",
							ErrTRUCPackageTooManyDescendants, formatHash(parentTxHash))
					}
					// This tx cannot have a child in the package.
					// Core: PackageTRUCChecks:136-139.
					if in.PreviousOutPoint.Hash == tx.TxHash() {
						return fmt.Errorf("%w: tx %s has a child in the package",
							ErrTRUCPackageChildHasChild, formatHash(pkgTx.TxHash()))
					}
				}
			}

			// If the mempool parent already has a descendant in the mempool,
			// the incoming child would exceed the descendant limit.
			// Core: PackageTRUCChecks:144-147.
			if len(mempoolParents) > 0 {
				parentDescCount := mp.countDescendantsLocked(parentTxHash)
				if parentDescCount > 1 {
					return fmt.Errorf("%w: mempool parent %s already has %d descendants",
						ErrTRUCPackageTooManyDescendants, formatHash(parentTxHash), parentDescCount)
				}
			}
		}
	} else {
		// Non-TRUC transaction: must have no TRUC parents, in mempool or package.
		// Core: PackageTRUCChecks:149-167.
		for _, p := range mempoolParents {
			if p.Tx.Version == TRUCVersion {
				return fmt.Errorf("non-version=3 tx %s cannot spend from version=3 tx %s",
					formatHash(tx.TxHash()), formatHash(p.TxHash))
			}
		}
		for _, idx := range inPkgParentIndices {
			if pkgTxs[idx].Version == TRUCVersion {
				return fmt.Errorf("non-version=3 tx %s cannot spend from version=3 tx %s",
					formatHash(tx.TxHash()), formatHash(pkgTxs[idx].TxHash()))
			}
		}
	}

	return nil
}

// findInPackageParents returns the indices (within pkgTxs) of transactions that
// are direct parents of pkgTxs[txIdx]. The package must be topologically sorted.
// Core: FindInPackageParents (truc_policy.cpp:18-37).
func findInPackageParents(pkgTxs []*wire.MsgTx, txIdx int) []int {
	tx := pkgTxs[txIdx]
	// Build set of outpoint hashes referenced by tx's inputs.
	possible := make(map[wire.Hash256]bool, len(tx.TxIn))
	for _, in := range tx.TxIn {
		possible[in.PreviousOutPoint.Hash] = true
	}

	var parents []int
	for i := 0; i < txIdx; i++ {
		h := pkgTxs[i].TxHash()
		if possible[h] {
			parents = append(parents, i)
		}
	}
	return parents
}

// countAncestorsLocked returns the number of in-mempool ancestors of txHash,
// including txHash itself.
// Must be called with mp.mu held.
func (mp *Mempool) countAncestorsLocked(txHash wire.Hash256) int {
	visited := make(map[wire.Hash256]bool)
	var walk func(h wire.Hash256)
	walk = func(h wire.Hash256) {
		if visited[h] {
			return
		}
		visited[h] = true
		entry, ok := mp.pool[h]
		if !ok {
			return
		}
		for _, dep := range entry.Depends {
			walk(dep)
		}
	}
	walk(txHash)
	return len(visited)
}

// countDescendantsLocked returns the number of in-mempool descendants of txHash,
// including txHash itself.
// Must be called with mp.mu held.
func (mp *Mempool) countDescendantsLocked(txHash wire.Hash256) int {
	visited := make(map[wire.Hash256]bool)
	var walk func(h wire.Hash256)
	walk = func(h wire.Hash256) {
		if visited[h] {
			return
		}
		visited[h] = true
		entry, ok := mp.pool[h]
		if !ok {
			return
		}
		for _, child := range entry.SpentBy {
			walk(child)
		}
	}
	walk(txHash)
	return len(visited)
}

// findSingleChildLocked returns the txHash of the single in-mempool child of
// parentHash, or the zero hash if there is not exactly one child.
// Must be called with mp.mu held.
func (mp *Mempool) findSingleChildLocked(parentHash wire.Hash256) wire.Hash256 {
	entry, ok := mp.pool[parentHash]
	if !ok {
		return wire.Hash256{}
	}
	if len(entry.SpentBy) != 1 {
		return wire.Hash256{}
	}
	return entry.SpentBy[0]
}

// formatHash returns the first 16 hex characters of a hash for error messages.
// (Matches the convention used in other blockbrew error strings.)
func formatHash(h wire.Hash256) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 16)
	for i := 0; i < 8; i++ {
		b[2*i] = hex[h[i]>>4]
		b[2*i+1] = hex[h[i]&0xf]
	}
	return string(b) + "..."
}
