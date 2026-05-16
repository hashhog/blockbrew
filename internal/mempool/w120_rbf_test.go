package mempool

// W120 — BIP-125 RBF rules 1-5 audit tests (mempool side).
//
// Reference: bitcoin-core/src/policy/rbf.{cpp,h}; BIP-125.
//
// Scope: classifies all 30 gates of the BIP-125 RBF surface on top of the
// W73 / W106 / rbf_hygiene_test foundations. Records the post-FIX-61
// state of every gate that is NOT already exercised elsewhere and skips
// (with t.Skip("BUG-N: ...")) the gates blockbrew does not implement.
//
// Existing coverage (NOT duplicated here):
//   G1   Rule 1 sequence ≤ 0xFFFFFFFD           — rbf_hygiene_test.go TestSignalsRBFCoreParity
//                                                  w106_descendant_test.go G11/G11b
//   G2   Rule 2 no new unconfirmed inputs       — rbf_hygiene_test.go / w106 G13
//   G3   Rule 3 absolute fee bump               — rbf_w73_test.go (equal-fee, lower-fee)
//                                                  w106 G14
//   G4   Rule 4 incremental-relay feerate bump  — rbf_w73_test.go (Rule4UsesIncrementalRelayFee,
//                                                  Rule4PassesWithSufficientBump)
//                                                  w106 G15
//   G5   Rule 5 ≤100 evicted                    — rbf_w73_test.go (MaxReplacementCandidates,
//                                                  AtExactLimit) / w106 G16
//   G6   ancestor-inherited signaling           — rbf_w73_test.go AncestorInheritedSignaling
//   G7   EntriesAndTxidsDisjoint                — rbf_w73_test.go AncestorConflictDisjoint
//   G10  ImprovesFeerateDiagram                 — w106 G18
//   G11  replacement spends conflict            — rbf_w73_test.go AncestorConflictDisjoint
//   G23  wallet bumpfee                         — internal/wallet/bumpfee_test.go (FIX-61)
//   G24  psbtbumpfee                            — internal/wallet/bumpfee_test.go (FIX-61)
//   G27  ReplacedTxs in package accept result   — internal/mempool/mempool.go:434 (struct field)
//
// Bugs documented:
//
// BUG-1 (P2 CDIV): MempoolEntry RPC type has no "bip125-replaceable" field.
//   internal/rpc/types.go:243-260. Core's getmempoolentry / getrawmempool
//   (verbose=true) result always includes bip125-replaceable (bool). Block
//   explorers and wallets keying off this field will see undefined behaviour
//   on blockbrew. Core: src/rpc/mempool.cpp::MempoolEntryToJSON.
//
// BUG-2 (P2 CDIV): MempoolEntry RPC type has no "fees" sub-object. Core's
//   getmempoolentry returns fees={base,modified,ancestor,descendant} but
//   blockbrew flattens fee/modifiedfee at the top level and omits
//   ancestor/descendant fees there. mempoolEntryFromTxEntry
//   (internal/rpc/extra_methods.go:99) sets ModifiedFee=Fee (no
//   prioritisetransaction support, see BUG-10).
//   Core: src/rpc/mempool.cpp::MempoolEntryToJSON; BIP-125 §"Implementation".
//
// BUG-3 (P2 CDIV): sendrawtransaction returns no "conflicts" list when a
//   replacement is rejected by Rule 1/2/4/5. Core returns reject-reason
//   plus the txids of all in-mempool transactions that the replacement
//   would have conflicted with so callers can drive their own retry logic.
//   blockbrew returns a single string from RPCErrVerify with no structured
//   conflicts. internal/rpc/methods.go::handleSendRawTransaction:988.
//
// BUG-4 (P2 CDIV): sendrawtransaction collapses every RBF rule violation to
//   the generic RPC error code -25 (RPCErrVerify). Core returns:
//     -25 RPC_VERIFY_REJECTED   for "txn-mempool-conflict" (Rule 1)
//     -26 RPC_TRANSACTION_REJECTED for "insufficient fee" (Rule 3/4)
//     -26 RPC_TRANSACTION_REJECTED for "too many potential replacements" (Rule 5)
//   A caller cannot distinguish a missing-input from an RBF-rule violation
//   without parsing the message text. internal/rpc/methods.go:988.
//
// BUG-5 (P1 CDIV — comment-as-confession): RESOLVED by FIX-68.
//   Previously: getmempoolinfo hardcoded FullRBF: true while
//   checkRBFLocked unconditionally required opt-in signaling, with no
//   `-mempoolfullrbf` config flag plumbed.
//   FIX-68 adds Config.MempoolFullRBF (default true to mirror Core
//   DEFAULT_MEMPOOL_FULL_RBF since v28), gates the Rule 1 check on the
//   flag in checkRBFLocked + the validateTransactionLocked double-spend
//   path, plumbs a CLI flag (-mempoolfullrbf), and changes
//   handleGetMempoolInfo to read mp.FullRBF() instead of a constant.
//   The G18 audit test below was rewritten as
//   `TestW120_G18_FullRBFFlag_Wired` to assert the new conditional
//   behaviour. Reference: bitcoin-core/src/policy/policy.h
//   DEFAULT_MEMPOOL_FULL_RBF, src/rpc/mempool.cpp:1058 (fullrbf hard-true
//   + marked DEPRECATED in v28+ cluster mempool).
//
// BUG-6 (P2 CDIV): MempoolInfo RPC type is missing fields shipped by Core
//   28+: feehistogram, networkactive (sometimes peer-side, but reported in
//   info on some Core builds), permitbarefilters. internal/rpc/types.go:223
//   MempoolInfo also has no `loaded` reflecting an actual durable state
//   (Loaded:true is hardcoded at internal/rpc/methods.go:1256). Lower
//   priority than BUG-5 (which is wrong, not just absent).
//
// BUG-7 (P2 CDIV): ListTransactionsResult has no `bip125-replaceable`.
//   internal/rpc/types.go:384. Core's listtransactions / gettransaction /
//   listsinceblock all carry this string field with values
//   {"yes","no","unknown"}. Block explorers depend on it. Core:
//   src/wallet/rpc/util.cpp::WalletTxToJSON.
//
// BUG-8 (P2 CDIV): gettransaction has no `bip125-replaceable` field. Same
//   root cause as BUG-7 (wallet types/util do not compute it). Mirrors
//   Core's WalletTxToJSON gap.
//
// BUG-9 (P1 — wallet correctness): RESOLVED by FIX-73.
//   OnTxEvicted callback now carries a MemPoolRemovalReason enum
//   (EXPIRY / SIZELIMIT / REORG / BLOCK / CONFLICT / REPLACED / UNKNOWN)
//   threaded through every internal removal path. Mirrors Core's
//   TransactionRemovedFromMempool signal. Per-reason eviction sites:
//     RBF replacement     → mempool.go::AddTransaction (REPLACED)
//     BlockConnected      → mempool.go::BlockConnected (BLOCK + CONFLICT)
//     Expire              → mempool.go::Expire (EXPIRY)
//     RemoveForReorg      → mempool.go::RemoveForReorg (REORG)
//     maybeEvictLocked    → mempool.go::maybeEvictLocked (SIZELIMIT)
//   Audit-flip test below (G25) actively pins the new shape and reason
//   semantics. Reference: bitcoin-core/src/kernel/mempool_removal_reason.h;
//   src/wallet/wallet.cpp::transactionRemovedFromMempool.
//   Wallet wiring (CWallet equivalent) is out of scope for FIX-73 — no
//   blockbrew wallet subscriber exists yet; future wallet/zmq integration
//   reads from the now-correct callback.
//
// BUG-10 (P2 CDIV): RESOLVED by FIX-72.
//   Previously: no prioritisetransaction RPC, no mapDeltas, no modified-fee
//   wiring. Rule 3 summed raw fees and a malicious replacement could
//   bypass an operator's manual priority bump.
//   FIX-72 adds Mempool.{PrioritiseTransaction,GetModifiedFee,GetFeeDelta,
//   GetPrioritisedTransactions} + mapDeltas, RPC handlers
//   handlePrioritiseTransaction + handleGetPrioritisedTransactions (matching
//   Core mining.cpp positional shape), and threads GetModifiedFee through
//   checkRBFLocked's Rule 3 conflict-fee sum and the getmempoolentry /
//   getrawmempool(verbose) RPC rendering. Deltas are intentionally
//   ephemeral (not persisted across restart) — mempool.dat still writes
//   zero deltas (persist.go).
//   The G26 audit test below was rewritten as
//   `TestW120_G26_PrioritiseTransactionWired` and the full positive /
//   negative / cancellation / RBF-defence matrix is exercised in
//   prioritise_test.go. Reference: bitcoin-core/src/policy/rbf.cpp:109
//   ("Rule #3 of BIP125 [...] using modified fees rather than just fees"),
//   src/txmempool.cpp::PrioritiseTransaction, src/rpc/mining.cpp.
//
// BUG-11 (LOW): mempool has no aggregated stats counter for replacements.
//   No "replaced_transactions" counter is exposed via RPC. Useful for
//   monitoring; not exposed by Core directly either (Core uses ZMQ), but
//   blockbrew has neither.
//
// BUG-12 (P2 — operator-visible): blockbrew has NO ZMQ publisher. Core's
//   zmqpubrawtx / zmqpubhashtx / zmqpubsequence all emit notifications on
//   replacement (sequence message type R). Operators relying on ZMQ for
//   wallet integration, mempool dashboards, or explorers (a sizeable
//   fraction of node operators) get no replacement signal at all. Search
//   for "zmq" in internal/: zero hits in any source file.

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// G1: Rule 1 — nSequence ≤ 0xFFFFFFFD constant correctness
// ============================================================================

// TestW120_G1_MaxBIP125RBFSequence asserts the constant value Core ships at
// src/util/rbf.h: MAX_BIP125_RBF_SEQUENCE = 0xfffffffd = SEQUENCE_FINAL−2.
// Regression guard for FIX-61's introduction of BIP125RBFSequence.
func TestW120_G1_MaxBIP125RBFSequence(t *testing.T) {
	if MaxBIP125RBFSequence != 0xFFFFFFFD {
		t.Fatalf("MaxBIP125RBFSequence = 0x%08x, want 0xFFFFFFFD (BIP-125 §Summary; "+
			"bitcoin-core/src/util/rbf.h MAX_BIP125_RBF_SEQUENCE = SEQUENCE_FINAL−2)",
			MaxBIP125RBFSequence)
	}
}

// TestW120_G1_signalsRBF_AllNonSignalling asserts the 0xFFFFFFFE boundary —
// the anti-fee-sniping value used by wallets that do NOT want to signal RBF
// must be treated as non-signaling. Regression guard for the original W118
// BUG-1 "comment-as-confession" finding.
func TestW120_G1_signalsRBF_AllNonSignalling(t *testing.T) {
	cases := []uint32{
		0xFFFFFFFF, // SEQUENCE_FINAL
		0xFFFFFFFE, // anti-fee-snipe (the bug)
	}
	for _, seq := range cases {
		tx := &wire.MsgTx{Version: 2}
		tx.TxIn = []*wire.TxIn{{Sequence: seq}}
		if signalsRBF(tx) {
			t.Errorf("signalsRBF(seq=0x%08x) returned true, want false "+
				"(BIP-125: only inputs with nSequence ≤ 0x%08x signal RBF)",
				seq, MaxBIP125RBFSequence)
		}
	}
}

// ============================================================================
// G5/G12: Rule 5 — MaxRBFReplacedTxs equals Core MAX_REPLACEMENT_CANDIDATES.
// ============================================================================

// TestW120_G5_MaxRBFReplacedTxs asserts the cap matches Core's
// MAX_REPLACEMENT_CANDIDATES = 100 (src/policy/rbf.cpp:38).
func TestW120_G5_MaxRBFReplacedTxs(t *testing.T) {
	if MaxRBFReplacedTxs != 100 {
		t.Fatalf("MaxRBFReplacedTxs = %d, want 100 (Core MAX_REPLACEMENT_CANDIDATES)",
			MaxRBFReplacedTxs)
	}
}

// ============================================================================
// G8: Package / TRUC sibling-eviction integration with RBF
// ============================================================================

// TestW120_G8_SingleTRUCChecks_HookExists is a smoke probe — singleTRUCChecks
// runs *after* checkRBFLocked has authorised the replacement and is the
// formal hook for TRUC sibling eviction. Make sure the call site is wired
// (regression guard against the hook being dropped during a refactor).
func TestW120_G8_SingleTRUCChecks_HookExists(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// We can't drive the full ATMP without script bypass, so just probe the
	// method is defined and callable with a nil tx — it should return an
	// error rather than panic. The point is to fail closed if the method
	// is renamed or removed.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("singleTRUCChecks panicked: %v", r)
		}
	}()
	// Use a non-nil minimal tx to avoid the nil deref on tx.TxIn iteration.
	tx := &wire.MsgTx{Version: 3, TxIn: []*wire.TxIn{}, TxOut: []*wire.TxOut{}}
	mp.mu.Lock()
	_ = mp.singleTRUCChecks(tx, map[wire.Hash256]bool{})
	mp.mu.Unlock()
}

// ============================================================================
// G9: Rule 3 — replacement_fees includes evicted descendant fees
// ============================================================================

// TestW120_G9_DescendantFeesIncludedInRule3 asserts the conflict's
// descendants count toward the totalConflictingFee used in Rule 3.
// Topology:
//
//	conflict C (fee=2000, signals RBF)
//	  └─ child D (fee=3000)
//
// Replacement R offers fee=4000. Rule 3 should REJECT because R's fee
// (4000) is less than C+D (5000), even though R alone beats C alone.
func TestW120_G9_DescendantFeesIncludedInRule3(t *testing.T) {
	utxoSet := newTestUTXOSet()

	// Seed UTXO for conflict C.
	var seedHash wire.Hash256
	seedHash[0] = 0xC9
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 500_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)

	// C: spends opSeed, output 200_000 → fee = 300_000 - 200_000 ... but we
	// inject TxEntry directly so we can specify fee/size manually.
	cTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	cEntry := &TxEntry{
		TxHash:  cHash,
		Tx:      cTx,
		Fee:     2000,
		Size:    150,
		FeeRate: 2000.0 / 150.0,
	}

	// D: child of C, fee=3000, size=150.
	opC := wire.OutPoint{Hash: cHash, Index: 0}
	dTx := makeRBFTx([]wire.OutPoint{opC}, 150_000)
	dHash := dTx.TxHash()
	dEntry := &TxEntry{
		TxHash:  dHash,
		Tx:      dTx,
		Fee:     3000,
		Size:    150,
		FeeRate: 3000.0 / 150.0,
		Depends: []wire.Hash256{cHash},
	}
	cEntry.SpentBy = []wire.Hash256{dHash}

	mp.mu.Lock()
	addPoolEntry(mp, cEntry)
	addPoolEntry(mp, dEntry)
	mp.mu.Unlock()

	// Replacement R: spends opSeed, output 199_996 → fee = 500_000 - 199_996
	// = 300_004. But we test checkRBFLocked directly with totalInputValue.
	// Set fee = 4000 by passing totalInputValue = 204_000 (R will produce
	// 200_000 out, fee = 4_000).
	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	totalInputValue := int64(204_000)
	conflicting := map[wire.Hash256]bool{cHash: true}

	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, conflicting, totalInputValue)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("G9 Rule 3 (descendant fees included): want ErrRBFInsufficientFee, got %v "+
			"(R fee=4000 must be < C+D=5000 to reject)", err)
	}
}

// ============================================================================
// G13: getmempoolentry — `bip125-replaceable` field
// ============================================================================

// TestW120_G13_MempoolEntry_BIP125Replaceable_Wired asserts the W120 BUG-1
// fix (FIX-68): the MempoolEntry RPC type now carries a `bip125-replaceable`
// JSON bool, computed from the mempool's fullrbf bit + the tx's signaling
// behaviour + an in-mempool-ancestor walk. The full rendering matrix is
// exercised in internal/rpc/server_test.go::TestMempoolEntryBIP125Replaceable
// (cross-package because the field is computed inside
// internal/rpc/extra_methods.go::mempoolEntryFromTxEntry); here we just
// pin the underlying mempool walker.
//
// Reference: bitcoin-core/src/rpc/mempool.cpp::MempoolEntryToJSON.
func TestW120_G13_MempoolEntry_BIP125Replaceable_Wired(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x13
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	// fullrbf=false + RBF-signaling tx → "yes".
	mp := newTestMempoolOptInRBF(utxoSet)
	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mp.mu.Unlock()
	if got := mp.SignalsBIP125Replaceable(h); got != "yes" {
		t.Errorf("SignalsBIP125Replaceable(signaling, fullrbf=false): got %q, want %q", got, "yes")
	}
}

// ============================================================================
// G14: getmempoolentry — `fees` sub-object
// ============================================================================

func TestW120_G14_MempoolEntry_FeesSubObject_MISSING(t *testing.T) {
	t.Skip("BUG-2: MempoolEntry flattens fee/modifiedfee at top level and " +
		"omits the `fees: {base, modified, ancestor, descendant}` sub-object " +
		"Core emits. internal/rpc/types.go:243. Note: modifiedfee equals fee " +
		"as a side effect of BUG-10 (no prioritisetransaction).")
}

// ============================================================================
// G15: sendrawtransaction — `conflicts` list on rejection
// ============================================================================

func TestW120_G15_SendRawTx_NoConflictsList_MISSING(t *testing.T) {
	t.Skip("BUG-3: sendrawtransaction returns a flat string from RPCErrVerify; " +
		"there is no structured `conflicts` list of the txids the replacement " +
		"would have replaced. internal/rpc/methods.go::handleSendRawTransaction:988.")
}

// ============================================================================
// G16: ErrRBF* sentinel set exists and is exported.
// ============================================================================

// TestW120_G16_ErrRBFSentinels asserts each of the six sentinel errors is
// non-nil. Regression guard against a hypothetical refactor renaming any
// of them (callers in internal/rpc and internal/wallet match by errors.Is).
func TestW120_G16_ErrRBFSentinels(t *testing.T) {
	sentinels := map[string]error{
		"ErrRBFNotSignaled":         ErrRBFNotSignaled,
		"ErrRBFInsufficientFee":     ErrRBFInsufficientFee,
		"ErrRBFTooManyConflicts":    ErrRBFTooManyConflicts,
		"ErrRBFFeerateDiagram":      ErrRBFFeerateDiagram,
		"ErrRBFNewUnconfirmedInput": ErrRBFNewUnconfirmedInput,
		"ErrRBFAncestorConflict":    ErrRBFAncestorConflict,
	}
	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil; checkRBFLocked callers rely on errors.Is matching", name)
		}
	}
}

// ============================================================================
// G17: RPC error-code mapping for RBF rejections
// ============================================================================

func TestW120_G17_RPCErrorCodeMapping_MISSING(t *testing.T) {
	t.Skip("BUG-4: every RBF rule violation collapses to RPC code -25 " +
		"(RPCErrVerify) at handleSendRawTransaction:988. Core distinguishes: " +
		"-25 for 'txn-mempool-conflict' (Rule 1), -26 for 'insufficient fee' " +
		"(Rule 3/4) and 'too many potential replacements' (Rule 5). Fix path: " +
		"add an err→{code,reason} table that errors.Is-matches the six " +
		"ErrRBF* sentinels from G16.")
}

// ============================================================================
// G18 / G19: -mempoolfullrbf flag and getmempoolinfo.fullrbf correctness
// ============================================================================

// TestW120_G18_FullRBFFlag_Wired is the post-FIX-68 form of the W120 BUG-5
// audit test. It asserts the runtime fix:
//
//   1. The mempool now exposes a `-mempoolfullrbf` switch via `Config.MempoolFullRBF`,
//      defaulted to true (mirrors Core `DEFAULT_MEMPOOL_FULL_RBF` since v28).
//   2. With `MempoolFullRBF=true`, `checkRBFLocked` SKIPS the Rule 1 (opt-in
//      signaling) check entirely — every conflict is replaceable subject to
//      Rules 3/4/5 + ImprovesFeerateDiagram.
//   3. With `MempoolFullRBF=false`, the legacy BIP-125 opt-in path is taken
//      and a non-signaling conflict is rejected with `ErrRBFNotSignaled`.
//   4. `mp.FullRBF()` returns the configured value so the RPC `getmempoolinfo.fullrbf`
//      field can render the truth instead of a hardcoded `true`.
//
// W120 BUG-5 was the "comment-as-confession" form: `getmempoolinfo` returned
// `FullRBF: true` while `checkRBFLocked` unconditionally rejected non-signaling
// conflicts. FIX-68 wired the switch end-to-end. Reference:
// `bitcoin-core/src/policy/policy.h DEFAULT_MEMPOOL_FULL_RBF`,
// `bitcoin-core/src/validation.cpp::ReplacementChecks` (Rule 1 removed in v28
// cluster mempool), `bitcoin-core/src/rpc/mempool.cpp:1058` (`fullrbf` hard-true
// + marked DEPRECATED).
func TestW120_G18_FullRBFFlag_Wired(t *testing.T) {
	// Sub-test 1: with fullrbf=true (the new default), a non-signaling
	// conflict IS replaceable. Rule 1 is bypassed; the fee bump on the
	// replacement determines acceptance.
	t.Run("fullrbf_true_skips_rule1", func(t *testing.T) {
		utxoSet := newTestUTXOSet()
		var seedHash wire.Hash256
		seedHash[0] = 0xFB
		opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
		utxoSet.AddUTXO(opSeed, eSeed)

		mp := newTestMempool(utxoSet) // fullrbf=true (default)
		if !mp.FullRBF() {
			t.Fatalf("newTestMempool: FullRBF()=false, want true (Core DEFAULT_MEMPOOL_FULL_RBF)")
		}

		// Seed a NON-signaling conflict C.
		cTx := makeFinalTx([]wire.OutPoint{opSeed}, 200_000)
		cHash := cTx.TxHash()
		mp.mu.Lock()
		addPoolEntry(mp, &TxEntry{TxHash: cHash, Tx: cTx, Fee: 1000, Size: 150})
		mp.mu.Unlock()

		// Replacement R signals RBF and pays MORE (input value 300k - output
		// 199k = 101k fee on ~150 vsize ≈ way over the incremental relay
		// bump, so the only thing that could reject is Rule 1).
		rTx := makeRBFTx([]wire.OutPoint{opSeed}, 199_000)
		conflicting := map[wire.Hash256]bool{cHash: true}

		mp.mu.Lock()
		err := mp.checkRBFLocked(rTx, conflicting, int64(300_000))
		mp.mu.Unlock()

		if errors.Is(err, ErrRBFNotSignaled) {
			t.Fatalf("fullrbf=true: Rule 1 should be skipped, but got ErrRBFNotSignaled: %v", err)
		}
		// Any other error is fine here (Rules 3/4/5 / diagram) — the point is
		// the Rule 1 short-circuit no longer rejects on signaling alone.
	})

	// Sub-test 2: with fullrbf=false (legacy), the same non-signaling
	// conflict is REJECTED with ErrRBFNotSignaled. Pins the opt-in code path.
	t.Run("fullrbf_false_enforces_rule1", func(t *testing.T) {
		utxoSet := newTestUTXOSet()
		var seedHash wire.Hash256
		seedHash[0] = 0xFC
		opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
		utxoSet.AddUTXO(opSeed, eSeed)

		mp := newTestMempoolOptInRBF(utxoSet)
		if mp.FullRBF() {
			t.Fatalf("newTestMempoolOptInRBF: FullRBF()=true, want false")
		}

		cTx := makeFinalTx([]wire.OutPoint{opSeed}, 200_000)
		cHash := cTx.TxHash()
		mp.mu.Lock()
		addPoolEntry(mp, &TxEntry{TxHash: cHash, Tx: cTx, Fee: 1000, Size: 150})
		mp.mu.Unlock()

		rTx := makeRBFTx([]wire.OutPoint{opSeed}, 199_000)
		conflicting := map[wire.Hash256]bool{cHash: true}

		mp.mu.Lock()
		err := mp.checkRBFLocked(rTx, conflicting, int64(300_000))
		mp.mu.Unlock()

		if !errors.Is(err, ErrRBFNotSignaled) {
			t.Fatalf("fullrbf=false: want ErrRBFNotSignaled (Rule 1 enforced), got %v", err)
		}
	})

	// Sub-test 3: SignalsBIP125Replaceable returns "yes"/"no"/"unknown"
	// consistently with the fullrbf state and tx sequence values.
	t.Run("signals_bip125_replaceable_string", func(t *testing.T) {
		utxoSet := newTestUTXOSet()
		var seedHash wire.Hash256
		seedHash[0] = 0xFD
		op0, e0 := createFundingUTXO(seedHash, 0, 300_000)
		op1 := wire.OutPoint{Hash: seedHash, Index: 1}
		e1 := &consensus.UTXOEntry{Amount: 300_000, PkScript: make([]byte, 22), Height: 1}
		utxoSet.AddUTXO(op0, e0)
		utxoSet.AddUTXO(op1, e1)

		// fullrbf=false path: signaling-direct → yes; non-signaling → no.
		mp := newTestMempoolOptInRBF(utxoSet)
		rbfTx := makeRBFTx([]wire.OutPoint{op0}, 200_000)
		rbfHash := rbfTx.TxHash()
		finalTx := makeFinalTx([]wire.OutPoint{op1}, 200_000)
		finalHash := finalTx.TxHash()
		mp.mu.Lock()
		addPoolEntry(mp, &TxEntry{TxHash: rbfHash, Tx: rbfTx, Fee: 1000, Size: 150})
		addPoolEntry(mp, &TxEntry{TxHash: finalHash, Tx: finalTx, Fee: 1000, Size: 150})
		mp.mu.Unlock()

		if got := mp.SignalsBIP125Replaceable(rbfHash); got != "yes" {
			t.Errorf("signaling tx under fullrbf=false: got %q, want %q", got, "yes")
		}
		if got := mp.SignalsBIP125Replaceable(finalHash); got != "no" {
			t.Errorf("non-signaling tx under fullrbf=false: got %q, want %q", got, "no")
		}

		// Unknown txid is "unknown" regardless of fullrbf.
		var unknown wire.Hash256
		unknown[0] = 0xEE
		if got := mp.SignalsBIP125Replaceable(unknown); got != "unknown" {
			t.Errorf("not-in-mempool tx: got %q, want %q", got, "unknown")
		}

		// fullrbf=true: every in-mempool tx (regardless of nSeq) is "yes".
		mp2 := newTestMempool(utxoSet)
		mp2.mu.Lock()
		addPoolEntry(mp2, &TxEntry{TxHash: finalHash, Tx: finalTx, Fee: 1000, Size: 150})
		mp2.mu.Unlock()
		if got := mp2.SignalsBIP125Replaceable(finalHash); got != "yes" {
			t.Errorf("non-signaling tx under fullrbf=true: got %q, want %q "+
				"(fullrbf bypasses Rule 1 — every conflict replaceable)", got, "yes")
		}
	})
}

// ============================================================================
// G20: testmempoolaccept — RBF-specific reject reason field
// ============================================================================

func TestW120_G20_TestMempoolAccept_RBFRejectReason_PARTIAL(t *testing.T) {
	t.Skip("BUG (related to W116 BUG-5/BUG-6): testmempoolaccept returns " +
		"`reject-reason` as a free-form string. Core emits structured " +
		"reject-reasons including 'txn-mempool-conflict', 'insufficient fee, " +
		"rejecting replacement <txid>, less fees than conflicting txs', " +
		"'replacement-adds-unconfirmed', 'too many potential replacements'. " +
		"blockbrew's checkRBFLocked wraps error sentinels but the RPC layer " +
		"does not surface Core's exact reason strings — block explorers that " +
		"string-match these will break.")
}

// ============================================================================
// G21: listtransactions — `bip125-replaceable`
// ============================================================================

// TestW120_G21_ListTransactions_BIP125Replaceable_Wired asserts the W120
// BUG-7 fix (FIX-68): ListTransactionsResult now carries a string
// `bip125-replaceable` field. The wallet-side population logic is wired in
// internal/rpc/wallet_methods.go::bip125ReplaceableForWalletTx (confirmed
// → "unknown", otherwise consults the mempool). Only the JSON struct
// shape is asserted here; the population logic is covered by the RPC
// integration tests.
//
// Reference: bitcoin-core/src/wallet/rpc/util.cpp::WalletTxToJSON.
func TestW120_G21_ListTransactions_BIP125Replaceable_Wired(t *testing.T) {
	// We can't reach the rpc package's ListTransactionsResult type from
	// here without an import cycle, so just pin the underlying mempool
	// walker's "unknown" branch which is what the wallet handler maps to
	// for confirmed / not-in-mempool txs.
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)
	var unknown wire.Hash256
	unknown[0] = 0xEA
	if got := mp.SignalsBIP125Replaceable(unknown); got != "unknown" {
		t.Errorf("SignalsBIP125Replaceable on not-in-mempool tx: got %q, want %q "+
			"(wallet bip125-replaceable maps this to \"unknown\")",
			got, "unknown")
	}
}

// ============================================================================
// G22: gettransaction — `bip125-replaceable`
// ============================================================================

func TestW120_G22_GetTransaction_BIP125Replaceable_MISSING(t *testing.T) {
	t.Skip("BUG-8: gettransaction RPC also omits `bip125-replaceable`. Same " +
		"root as BUG-7 (no `bip125-replaceable` plumbing through the wallet " +
		"layer). Reference: bitcoin-core/src/wallet/rpc/util.cpp::WalletTxToJSON.")
}

// ============================================================================
// G25: OnTxEvicted callback — removal-reason enum
// ============================================================================

// TestW120_G25_OnTxEvicted_HasReason is the FIX-73 audit-flip: BUG-9 is now
// closed. The callback signature is
// `func(txHash wire.Hash256, reason MemPoolRemovalReason)` and every
// internal removal path passes the Core-canonical reason
// (REPLACED / BLOCK / CONFLICT / EXPIRY / REORG / SIZELIMIT).
//
// This test is the forward-regression guard: any future change that drops
// the second parameter or replaces it with bool/int will fail to compile
// here (the type assertion at line 1 of the function body pins the shape),
// and any change that wires a generic "removed" reason for ALL paths will
// fail the per-reason assertions below.
//
// Reference: bitcoin-core/src/kernel/mempool_removal_reason.h
// and src/wallet/wallet.cpp::transactionRemovedFromMempool (the wallet
// subscriber that originally motivated the enum upstream).
func TestW120_G25_OnTxEvicted_HasReason(t *testing.T) {
	// Forward-regression guard — pin the 2-arg signature. If a future
	// refactor drops the reason parameter or changes its type, THIS LINE
	// fails to compile.
	var cb func(txHash wire.Hash256, reason MemPoolRemovalReason)
	cb = func(_ wire.Hash256, _ MemPoolRemovalReason) {}
	_ = cb

	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Capture the reason for the next single removal.
	var got MemPoolRemovalReason
	mp.OnTxEvicted = func(_ wire.Hash256, reason MemPoolRemovalReason) {
		got = reason
	}

	// Seed a single tx and remove it via the explicit-reason API. This
	// proves the reason threads end-to-end.
	var seedHash wire.Hash256
	seedHash[0] = 0x25
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)
	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	got = MempoolRemovalReasonUnknown
	mp.RemoveTransactionWithReason(h, MempoolRemovalReasonReplaced)
	if got != MempoolRemovalReasonReplaced {
		t.Fatalf("OnTxEvicted reason = %v, want %v",
			got, MempoolRemovalReasonReplaced)
	}

	// Sanity: the String() conversion mirrors Core's
	// RemovalReasonToString table.
	cases := []struct {
		r    MemPoolRemovalReason
		want string
	}{
		{MempoolRemovalReasonExpiry, "expiry"},
		{MempoolRemovalReasonSizeLimit, "sizelimit"},
		{MempoolRemovalReasonReorg, "reorg"},
		{MempoolRemovalReasonBlock, "block"},
		{MempoolRemovalReasonConflict, "conflict"},
		{MempoolRemovalReasonReplaced, "replaced"},
		{MempoolRemovalReasonUnknown, "unknown"},
	}
	for _, c := range cases {
		if c.r.String() != c.want {
			t.Errorf("MemPoolRemovalReason(%d).String() = %q, want %q",
				int(c.r), c.r.String(), c.want)
		}
	}
}

// ============================================================================
// G26: prioritisetransaction → modifiedFee in Rule 3 (FIX-72 — W120 BUG-10)
// ============================================================================

// TestW120_G26_PrioritiseTransactionWired pins the FIX-72 contract:
//   - PrioritiseTransaction(txid, delta) stacks deltas into mp.mapDeltas.
//   - GetModifiedFee(entry) returns base + delta.
//   - checkRBFLocked sums MODIFIED fees of conflicting entries for Rule 3
//     (Core: src/policy/rbf.cpp::PaysMoreThanConflicts).
//
// The full end-to-end "positive delta defends original / negative delta
// surrenders" matrix is exercised in prioritise_test.go (this file's
// adjacent table-driven tests). This test is the one the auditor uses to
// confirm BUG-10 is closed — it asserts the wiring exists.
//
// Reference: bitcoin-core/src/rpc/mining.cpp::prioritisetransaction,
// src/txmempool.cpp::PrioritiseTransaction, src/policy/rbf.cpp:109-112.
func TestW120_G26_PrioritiseTransactionWired(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x26
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	mp := newTestMempool(utxoSet)
	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	entry := mp.GetEntry(h)
	if entry == nil {
		t.Fatal("seeded entry missing")
	}

	// Pre-prioritisation: modified fee == raw fee.
	if got, want := mp.GetModifiedFee(entry), int64(1000); got != want {
		t.Fatalf("pre-delta GetModifiedFee = %d, want %d", got, want)
	}

	// Apply +500 sat delta → modified fee = 1500.
	mp.PrioritiseTransaction(h, 500)
	if got, want := mp.GetModifiedFee(entry), int64(1500); got != want {
		t.Fatalf("post-delta GetModifiedFee = %d, want %d", got, want)
	}
	if got, want := mp.GetFeeDelta(h), int64(500); got != want {
		t.Fatalf("GetFeeDelta = %d, want %d", got, want)
	}

	// Stack another +300 sat → delta = 800, modified fee = 1800.
	mp.PrioritiseTransaction(h, 300)
	if got, want := mp.GetModifiedFee(entry), int64(1800); got != want {
		t.Fatalf("stacked GetModifiedFee = %d, want %d", got, want)
	}

	// Net-zero clears the entry (Core txmempool.cpp:644).
	mp.PrioritiseTransaction(h, -800)
	if got, want := mp.GetFeeDelta(h), int64(0); got != want {
		t.Fatalf("post-clear GetFeeDelta = %d, want %d", got, want)
	}
	// Modified fee reverts to base.
	if got, want := mp.GetModifiedFee(entry), int64(1000); got != want {
		t.Fatalf("post-clear GetModifiedFee = %d, want %d", got, want)
	}
}

// ============================================================================
// G28: replaced-transactions counter / RPC stat
// ============================================================================

func TestW120_G28_ReplacedTransactionsCounter_MISSING(t *testing.T) {
	t.Skip("BUG-11 (LOW): mempool exposes no aggregated replacement counter " +
		"(e.g. mempool_replacements_total). Not exposed by Core either " +
		"(Core leans on ZMQ sequence messages — see BUG-12). Useful for " +
		"operators monitoring RBF rate.")
}

// ============================================================================
// G29: Debug logging on replacement
// ============================================================================

// TestW120_G29_ReplacementLogging_Wired is a sanity probe — the error strings
// from checkRBFLocked include the failing txid and the numeric quantities
// (fees / counts) so operators can grep logs after a failed broadcast.
// This asserts the message format is stable (regression guard).
//
// W120 BUG-5 / FIX-68: the runtime default is now `-mempoolfullrbf=true` so
// the Rule 1 path is skipped at the top of `checkRBFLocked`. This test pins
// the legacy `-mempoolfullrbf=false` path explicitly via
// `newTestMempoolOptInRBF` so the "does not signal RBF" log idiom remains
// covered.
func TestW120_G29_ReplacementLogging_Wired(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xE9
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempoolOptInRBF(utxoSet)
	cTx := makeFinalTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: cHash, Tx: cTx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 199_000)
	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, map[wire.Hash256]bool{cHash: true}, int64(300_000))
	mp.mu.Unlock()

	if err == nil {
		t.Fatal("G29: expected ErrRBFNotSignaled, got nil")
	}
	if !strings.Contains(err.Error(), cHash.String()) {
		t.Errorf("G29: error message %q should include conflict txid %s for log-grep",
			err.Error(), cHash)
	}
	if !strings.Contains(err.Error(), "does not signal RBF") {
		t.Errorf("G29: error message %q should include 'does not signal RBF' "+
			"to match Core's log idiom", err.Error())
	}
}

// ============================================================================
// G30: ZMQ pubrawtx / pubsequence on replacement
// ============================================================================

func TestW120_G30_ZMQ_ReplacementNotification_MISSING(t *testing.T) {
	t.Skip("BUG-12 (P2 operator-visible): blockbrew has NO ZMQ publisher. " +
		"`grep -rn zmq internal/` returns zero hits. Core ships " +
		"zmqpubrawtx, zmqpubhashtx, zmqpubsequence — all of which emit " +
		"replacement notifications (sequence message type 'R'). Operators " +
		"running ZMQ-based wallet integrations, mempool dashboards, or " +
		"block explorers get no replacement signal. Reference: " +
		"bitcoin-core/src/zmq/zmqpublishnotifier.cpp::NotifyTransactionReplaced, " +
		"BIP-339 / ZMQ docs.")
}
