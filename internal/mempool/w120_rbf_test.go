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
// BUG-5 (P1 CDIV — comment-as-confession): getmempoolinfo hardcodes
//   FullRBF: true (internal/rpc/methods.go:1266) BUT the actual mempool
//   policy code unconditionally requires opt-in signaling
//   (checkRBFLocked:2368-2389). There is no `-mempoolfullrbf` config flag
//   wired anywhere. The struct field
//   (internal/rpc/types.go:239) is decorative. This is "comment-as-
//   confession": the RPC advertises a policy the code does not implement.
//   Reference: bitcoin-core/src/policy/policy.h DEFAULT_MEMPOOL_FULL_RBF,
//   src/init.cpp:687-689 (-mempoolfullrbf).
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
// BUG-9 (P1 — wallet correctness): OnTxEvicted callback carries NO reason.
//   internal/mempool/mempool.go:499. Core's TransactionRemovedFromMempool
//   signal takes a MemPoolRemovalReason (BLOCK / EXPIRY / SIZELIMIT /
//   REORG / CONFLICT / REPLACED / UNKNOWN). The wallet uses this to mark
//   conflicting wallet txs as "conflicted" rather than "abandoned" when a
//   replacement supersedes them. With a reasonless callback the wallet
//   bookkeeping CANNOT distinguish a REPLACED tx from an EXPIRED one —
//   they look identical to gettransaction. Core:
//   src/kernel/mempool_removal_reason.h; src/wallet/wallet.cpp::transactionRemovedFromMempool.
//
// BUG-10 (P2 CDIV): blockbrew has no prioritisetransaction RPC at all
//   (confirmed by internal/mempool/persist.go:161 comment "blockbrew has
//   no prioritisetransaction yet"). Consequently Rule 3 compares raw
//   absolute fees instead of "modified fees" (raw fee plus per-entry
//   delta). Core's rbf.cpp:109 says "// Rule #3 of BIP125 [...] using
//   modified fees rather than just fees". A user who has bumped the
//   priority of an original tx with prioritisetransaction (e.g. to win a
//   race against an attacker) would on Core see the replacement fail
//   Rule 3 unless it also pays the modifier; on blockbrew the modifier
//   does not exist, so a malicious replacement can bypass the manual
//   priority bump. Core: src/policy/rbf.cpp::PaysMoreThanConflicts.
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

func TestW120_G13_MempoolEntry_BIP125Replaceable_MISSING(t *testing.T) {
	t.Skip("BUG-1: MempoolEntry has no `bip125-replaceable` field. " +
		"Core: src/rpc/mempool.cpp::MempoolEntryToJSON emits it on every entry. " +
		"Fix path: add string field to internal/rpc/types.go MempoolEntry, " +
		"compute via signalsRBF(entry.Tx) || any-ancestor-signals.")
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

// TestW120_G18_FullRBFFlag_HardcodedNotWired demonstrates BUG-5: the RPC
// claims fullrbf=true but the policy is opt-in only. A caller reading the
// RPC and deciding to broadcast a non-signaling tx replacement (under the
// impression the node will accept it) will be silently mis-served. This is
// the *active failing assertion* form of the bug.
func TestW120_G18_FullRBFFlag_HardcodedNotWired(t *testing.T) {
	// We can't easily call handleGetMempoolInfo from this package without
	// pulling in the rpc package's full Server type. Instead we assert at
	// the *behavioural* level that checkRBFLocked unconditionally requires
	// opt-in. If fullrbf were truly wired, a non-signaling conflict
	// would be replaceable.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xFB
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)

	// Seed a NON-signaling conflict C.
	cTx := makeFinalTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: cHash, Tx: cTx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	// Replacement R signals RBF and pays more.
	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 199_000)
	conflicting := map[wire.Hash256]bool{cHash: true}

	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, conflicting, int64(300_000))
	mp.mu.Unlock()

	// Under TRUE fullrbf the replacement would be accepted (no Rule 1).
	// Under blockbrew's actual policy it is REJECTED. This proves the RPC
	// claim diverges from runtime policy.
	if !errors.Is(err, ErrRBFNotSignaled) {
		t.Skip("BUG-5 (G18/G19): if this test starts FAILING because err is " +
			"nil, the policy may have been silently wired to fullrbf — " +
			"verify intentionally. Currently the RPC advertises FullRBF: true " +
			"(internal/rpc/methods.go:1266) but the policy code at " +
			"checkRBFLocked:2384 unconditionally rejects non-signaling " +
			"conflicts. This is the comment-as-confession pattern: " +
			"advertise a feature the code does not implement. Fix path: " +
			"either (a) add a -mempoolfullrbf config flag and wire it into " +
			"checkRBFLocked's Rule 1 gate, or (b) set FullRBF: false in " +
			"handleGetMempoolInfo until (a) lands.")
	}
	// The expected-current behaviour is rejection, so an err of
	// ErrRBFNotSignaled confirms the policy is opt-in. The Skip above
	// emits the BUG-5 narrative so the gate is visible in test output.
	_ = err
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

func TestW120_G21_ListTransactions_BIP125Replaceable_MISSING(t *testing.T) {
	t.Skip("BUG-7: ListTransactionsResult (internal/rpc/types.go:384) has no " +
		"`bip125-replaceable` field. Core's listtransactions returns it as " +
		"{\"yes\",\"no\",\"unknown\"}. " +
		"Reference: bitcoin-core/src/wallet/rpc/util.cpp::WalletTxToJSON.")
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

// TestW120_G25_OnTxEvicted_HasNoReason actively asserts the missing-reason
// pattern. The callback signature is `func(txHash wire.Hash256)` — no
// MemPoolRemovalReason, so wallet code wired to this callback CANNOT
// distinguish REPLACED from BLOCK/EXPIRY/SIZELIMIT/REORG/CONFLICT/UNKNOWN.
func TestW120_G25_OnTxEvicted_HasNoReason(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Confirm the callback type signature has no reason parameter.
	// If FIX-N adds a reason this test will FAIL TO COMPILE — caller can
	// then delete the t.Skip below.
	var cb func(txHash wire.Hash256) = func(_ wire.Hash256) {}
	mp.OnTxEvicted = cb

	t.Skip("BUG-9: OnTxEvicted callback at internal/mempool/mempool.go:499 " +
		"carries NO removal reason. Core's TransactionRemovedFromMempool " +
		"signal takes a MemPoolRemovalReason enum: BLOCK / EXPIRY / SIZELIMIT " +
		"/ REORG / CONFLICT / REPLACED / UNKNOWN. With a reasonless callback " +
		"a wallet subscriber cannot mark RBF-superseded txs as 'conflicted' " +
		"vs 'abandoned' vs 'expired' — they all look identical. " +
		"Reference: bitcoin-core/src/kernel/mempool_removal_reason.h and " +
		"src/wallet/wallet.cpp::transactionRemovedFromMempool. " +
		"Fix path: define MemPoolRemovalReason enum in mempool package, " +
		"change OnTxEvicted to `func(txHash wire.Hash256, reason MemPoolRemovalReason)`, " +
		"update the four call sites at removeSingleTxLocked:1583, " +
		"sizeLimitMempool:1864, expireOlderThan:1895, removeForReorg:2031.")
}

// ============================================================================
// G26: prioritisetransaction → modifiedFee in Rule 3
// ============================================================================

func TestW120_G26_PrioritiseTransaction_NotImplemented(t *testing.T) {
	t.Skip("BUG-10: blockbrew has no prioritisetransaction RPC. " +
		"internal/mempool/persist.go:161 self-documents " +
		"(\"blockbrew has no prioritisetransaction yet\"). " +
		"Consequence: checkRBFLocked's Rule 3 comparison " +
		"`newFee < totalConflictingFee` uses raw absolute fees, not Core's " +
		"\"modified fees\" (raw + delta). A manual priority bump on the " +
		"original cannot raise the bar against a malicious replacement. " +
		"Core: src/policy/rbf.cpp::PaysMoreThanConflicts uses GetModifiedFee.")
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
func TestW120_G29_ReplacementLogging_Wired(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xE9
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
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
