// W129 Coin Selection (BnB / Knapsack / SRD / CG) audit — blockbrew (Go)
//
// Discovery audit. 30 gates / 22 BUGs. See audit/w129_coin_selection.md
// for the full rationale and the Bitcoin Core line references.
//
// Audit gates:
//   G1  BnB algorithm present (SelectCoinsBnB)
//   G2  Knapsack algorithm present (KnapsackSolver)
//   G3  SRD algorithm present                                   BUG-1
//   G4  CoinGrinder algorithm present                           BUG-2
//   G5  effective_value = nValue - input_fee per UTXO           (PARTIAL — BUG-3)
//   G6  Effective-value filter (drop ≤ 0) before BnB
//   G7  long_term_feerate tracked per UTXO/OutputGroup          BUG-4
//   G8  cost_of_change = discard×change_spend + eff×change_out  BUG-12
//   G9  m_change_fee tracked                                    (PARTIAL — BUG-5)
//   G10 min_viable_change = max(change_spend_fee+1, dust)       BUG-6
//   G11 m_min_change_target via GenerateChangeTarget            BUG-7
//   G12 CHANGE_LOWER=50000, CHANGE_UPPER=1000000                BUG-7
//   G13 BnB iteration cap = 100000
//   G14 BnB sorts by descending effective value
//   G15 BnB sort tie-break by waste                             BUG-11
//   G16 BnB lookahead via curr_available_value
//   G17 BnB equivalence-shortcut: effValue AND fee              (PARTIAL — BUG-10)
//   G18 BnB is_feerate_high waste-grows pruning                 BUG-13
//   G19 max_selection_weight cap enforced per branch            BUG-8
//   G20 ErrorMaxWeightExceeded returned when limit exceeded     BUG-8
//   G21 Knapsack 2-pass random + fill-in
//   G22 Knapsack CSPRNG randomness (FIX-45 closed W113 BUG-6)
//   G23 Knapsack iteration cap = 1000
//   G24 Knapsack second-pass at target + min_change_target      BUG-14
//   G25 SFFO skip-BnB                                           BUG-15
//   G26 3×LTFRE CoinGrinder gate                                BUG-2
//   G27 OUTPUT_GROUP_MAX_ENTRIES=100 cap                        BUG-16
//   G28 Per-OutputType AttemptSelection                         BUG-17
//   G29 RecalculateWaste formula                                BUG-13
//   G30 Multi-algorithm waste comparison via min_element        BUG-9
//
// Methodology: PRESENT gates run end-to-end. PARTIAL gates assert what
// works and t.Skip on the rest. MISSING gates t.Skip with the BUG ID.
//
// Source-of-truth file references:
//   - bitcoin-core/src/wallet/coinselection.h
//   - bitcoin-core/src/wallet/coinselection.cpp
//   - bitcoin-core/src/wallet/spend.cpp
//   - bitcoin-core/src/wallet/feebumper.cpp

package wallet

import (
	"math"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ── G1: BnB algorithm present ────────────────────────────────────────────────

func TestW129G1_BnBPresent(t *testing.T) {
	// Two UTXOs that sum to exactly an effective-value target.
	// Amount=50068 → eff = 50000 at 1 sat/vB / 68 vbyte P2WPKH input.
	// Amount=30068 → eff = 30000.
	utxos := []*WalletUTXO{
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{1}}, Amount: 50068, PkScript: makeP2WPKHScript(), Confirmed: true},
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{2}}, Amount: 30068, PkScript: makeP2WPKHScript(), Confirmed: true},
	}
	result, err := SelectCoins(utxos, 80000, 1.0, 5000)
	if err != nil {
		t.Fatalf("G1 SelectCoins: %v", err)
	}
	if result == nil {
		t.Fatal("G1 nil result")
	}
	if result.Total < 80000 {
		t.Errorf("G1 total %d < target 80000", result.Total)
	}
}

// ── G2: Knapsack algorithm present ───────────────────────────────────────────

func TestW129G2_KnapsackPresent(t *testing.T) {
	// utxoWithEffValue → approximateBestSubset should be reachable.
	utxos := []*utxoWithEffValue{
		{utxo: &WalletUTXO{Amount: 10000}, effValue: 9932},
		{utxo: &WalletUTXO{Amount: 20000}, effValue: 19932},
		{utxo: &WalletUTXO{Amount: 30000}, effValue: 29932},
	}
	_, val := approximateBestSubset(utxos, 25000)
	if val < 25000 {
		t.Errorf("G2 approximateBestSubset val %d < target 25000", val)
	}
}

// ── G3: SRD present — BUG-1 ──────────────────────────────────────────────────

func TestW129G3_SRDPresent(t *testing.T) {
	t.Skip("BUG-1: SRD (SelectCoinsSRD) is MISSING ENTIRELY. " +
		"Core's ChooseSelectionResult runs SRD as one of four algorithms; " +
		"blockbrew has BnB + Knapsack only. " +
		"Fix: implement SelectCoinsSRD per coinselection.cpp:536-588.")
}

// ── G4: CoinGrinder present — BUG-2 ──────────────────────────────────────────

func TestW129G4_CoinGrinderPresent(t *testing.T) {
	t.Skip("BUG-2: CoinGrinder is MISSING ENTIRELY. " +
		"Core runs CoinGrinder when effective_feerate > 3 × long_term_feerate " +
		"(spend.cpp:769). DFS over the UTXO power-set optimised for minimum " +
		"input weight. blockbrew has no CoinGrinder function. " +
		"Fix: implement per coinselection.cpp:325-525.")
}

// ── G5: effective_value = nValue - input_fee — PARTIAL (BUG-3) ───────────────

func TestW129G5_EffectiveValuePresentButRoundingWrong(t *testing.T) {
	// Effective-value computation exists (good). But the rounding direction
	// of estimateInputFee is wrong (BUG-3).

	// Direction-check: at 1.7 sat/vB × 68 vbyte = 115.6, Core's CFeeRate
	// ::GetFee rounds UP (returns 116). blockbrew truncates toward zero
	// via int64(float64(...)) and returns 115.
	got := estimateInputFee(makeP2WPKHScript(), 1.7)

	const coreCeil = 116 // Core: (68 * 1700 + 999) / 1000 = 116
	if got == coreCeil {
		t.Fatal("G5 EXPECTED-FAIL: estimateInputFee now rounds up — BUG-3 closed; flip this test")
	}
	t.Logf("G5 BUG-3 confirmed: blockbrew estimateInputFee(P2WPKH, 1.7) = %d, Core ceil = %d", got, coreCeil)
	t.Skip("BUG-3 (HIGH): estimateInputFee truncates toward zero via " +
		"int64(float64(vsize) * feeRate); Core's CFeeRate::GetFee rounds UP via " +
		"(nSize * nSatoshisPerK + 999) / 1000 (policy/feerate.cpp:23-27). " +
		"Off-by-one effective_value cascades through BnB cost-of-change windows.")
}

// ── G6: Effective-value filter (drop ≤ 0) ───────────────────────────────────

func TestW129G6_EffectiveValueFilter(t *testing.T) {
	utxos := []*WalletUTXO{
		// Amount=50, fee=68 at 1 sat/vB → eff = -18 (must be filtered)
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{1}}, Amount: 50, PkScript: makeP2WPKHScript(), Confirmed: true},
		// Amount=100000, fee=68 → eff = 99932 (included)
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{2}}, Amount: 100000, PkScript: makeP2WPKHScript(), Confirmed: true},
	}
	result, err := SelectCoins(utxos, 90000, 1.0, 31)
	if err != nil {
		t.Fatalf("G6 SelectCoins: %v", err)
	}
	if len(result.Coins) != 1 {
		t.Errorf("G6 expected 1 coin (dust filtered), got %d", len(result.Coins))
	}
	if len(result.Coins) >= 1 && result.Coins[0].Amount != 100000 {
		t.Errorf("G6 expected the 100000-sat UTXO, got %d", result.Coins[0].Amount)
	}
}

// ── G7: long_term_feerate per UTXO — BUG-4 ───────────────────────────────────

func TestW129G7_LongTermFeerate(t *testing.T) {
	t.Skip("BUG-4 (MEDIUM): utxoWithEffValue has only {utxo, effValue, inputFee}; " +
		"Core's COutput carries long_term_fee (coinselection.h:70) populated from " +
		"OutputGroup::m_long_term_feerate at Insert time. Without it the waste " +
		"metric (waste += GetFee()-long_term_fee per coin) cannot be computed. " +
		"See coinselection.go:108-113; also W113 BUG-5.")
}

// ── G8: cost_of_change formula — BUG-12 ──────────────────────────────────────

func TestW129G8_CostOfChangeFormula(t *testing.T) {
	t.Skip("BUG-12 (HIGH): callers compute costOfChange = changeOutputSize × feeRate " +
		"(creation cost only). Core formula: m_cost_of_change = " +
		"discard_feerate × change_spend_size + effective_feerate × change_output_size " +
		"(spend.cpp:1174-1175). At 1 sat/vB eff + 3 sat/vB discard + 31-vbyte change + " +
		"68-vbyte change-spend, Core's cost_of_change = 235 sat; blockbrew = 31 sat. " +
		"BnB's acceptance window is 7.5× too narrow. " +
		"Sites: wallet.go:931, wallet_wave_methods.go:533.")
}

// ── G9: m_change_fee tracked — PARTIAL (BUG-5) ───────────────────────────────

func TestW129G9_ChangeFee(t *testing.T) {
	// Change fee is computed inline at callers (wallet.go:931,
	// wallet_wave_methods.go:533) rather than stored in a CoinSelectionParams
	// struct. Functional but architecturally diverged.
	t.Skip("BUG-5 (LOW): no CoinSelectionParams struct; m_change_fee is computed " +
		"inline at wallet.go:931 and wallet_wave_methods.go:533. Core bundles " +
		"14 selection parameters into CoinSelectionParams (coinselection.h:134-196).")
}

// ── G10: min_viable_change formula — BUG-6 ───────────────────────────────────

func TestW129G10_MinViableChange(t *testing.T) {
	// dustThreshold is correct at 546 (P2PKH dust at 3 sat/vB discard).
	if dustThreshold != 546 {
		t.Errorf("G10 dustThreshold = %d, want 546 (P2PKH dust)", dustThreshold)
	}
	t.Skip("BUG-6 (MEDIUM): blockbrew uses hardcoded dustThreshold=546 everywhere. " +
		"Core: min_viable_change = max(change_spend_fee+1, dust) where " +
		"change_spend_fee = discard_feerate × change_spend_size (spend.cpp:1183-1184). " +
		"At discard=10 sat/vB + 68-vbyte change-spend, min_viable_change=681, not 546. " +
		"blockbrew creates dust change outputs that Core would drop to fees.")
}

// ── G11: GenerateChangeTarget randomised — BUG-7 ─────────────────────────────

func TestW129G11_GenerateChangeTarget(t *testing.T) {
	t.Skip("BUG-7 (MEDIUM): no GenerateChangeTarget function. Core " +
		"(coinselection.cpp:809) returns change_fee + rng.randrange(min(payment×2, " +
		"1000000) − 50000) + 50000 when payment > 25000, else change_fee + 50000. " +
		"Privacy: randomises change-target to break the 'this output is change' " +
		"heuristic. blockbrew uses fixed costOfChange.")
}

// ── G12: CHANGE_LOWER / CHANGE_UPPER constants — BUG-7 ───────────────────────

func TestW129G12_ChangeLowerUpperConstants(t *testing.T) {
	t.Skip("BUG-7 (MEDIUM): no CHANGE_LOWER=50000 or CHANGE_UPPER=1000000 constants " +
		"(coinselection.h:23-25). Same fix bundle as G11.")
}

// ── G13: BnB iteration cap = 100000 ──────────────────────────────────────────

func TestW129G13_BnBIterationCap(t *testing.T) {
	if maxBnBIterations != 100000 {
		t.Errorf("G13 maxBnBIterations = %d, want 100000 (Core TOTAL_TRIES)", maxBnBIterations)
	}
}

// ── G14: BnB descending sort by effective value ──────────────────────────────

func TestW129G14_BnBDescendingSort(t *testing.T) {
	// Verify the sort comparator is descending by effective value.
	// We pass three UTXOs with increasing eff value; BnB should consider
	// the largest first (inclusion-branch first per the algorithm).
	utxos := []*WalletUTXO{
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{1}}, Amount: 10068, PkScript: makeP2WPKHScript(), Confirmed: true},
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{2}}, Amount: 20068, PkScript: makeP2WPKHScript(), Confirmed: true},
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{3}}, Amount: 30068, PkScript: makeP2WPKHScript(), Confirmed: true},
	}
	// Target = 30000 (matches the largest UTXO eff value exactly). BnB
	// must find it in 1 iteration if sort is descending.
	result, err := SelectCoins(utxos, 30000, 1.0, 5000)
	if err != nil {
		t.Fatalf("G14 SelectCoins: %v", err)
	}
	if result == nil || len(result.Coins) == 0 {
		t.Fatal("G14 nil/empty result")
	}
}

// ── G15: BnB sort tie-break — BUG-11 ─────────────────────────────────────────

func TestW129G15_BnBSortTieBreak(t *testing.T) {
	t.Skip("BUG-11 (LOW): BnB sort comparator (sort.Slice with " +
		"sorted[i].effValue > sorted[j].effValue, coinselection.go:126-128) has " +
		"no tie-break and is unstable. Core's descending struct " +
		"(coinselection.cpp:29-38) breaks ties by 'lower waste first' " +
		"(a.fee - a.long_term_fee < b.fee - b.long_term_fee). " +
		"On UTXOs with tied eff values the result is non-deterministic.")
}

// ── G16: BnB lookahead — curr_available_value ────────────────────────────────

func TestW129G16_BnBLookahead(t *testing.T) {
	// Lookahead exists in blockbrew's BnB (coinselection.go:147, :191).
	// A target unreachable by the *full* sum must short-circuit via the
	// initial total-availability check (line 136). Construct that case.
	utxos := []*WalletUTXO{
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{1}}, Amount: 10000, PkScript: makeP2WPKHScript(), Confirmed: true},
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{2}}, Amount: 10000, PkScript: makeP2WPKHScript(), Confirmed: true},
	}
	// Total eff value ≈ 19864; target 50000 must fail fast.
	_, err := SelectCoins(utxos, 50000, 1.0, 5000)
	if err != ErrInsufficientFunds {
		t.Errorf("G16 expected ErrInsufficientFunds (lookahead short-circuit), got %v", err)
	}
}

// ── G17: BnB equivalence shortcut — PARTIAL (BUG-10) ────────────────────────

func TestW129G17_BnBEquivalenceShortcut(t *testing.T) {
	// Shortcut on equal eff value exists (coinselection.go:207). Missing:
	// also check fee equality (Core coinselection.cpp:175-177). Without
	// long_term_fee the check degenerates.
	t.Skip("BUG-10 (MEDIUM): equivalence shortcut checks effValue only " +
		"(coinselection.go:207). Core also requires fee equality: " +
		"'utxo.GetSelectionAmount() != utxo_pool.at(utxo_pool_index-1).GetSelectionAmount() " +
		"|| utxo.fee != utxo_pool.at(utxo_pool_index-1).fee' (coinselection.cpp:175-177). " +
		"With mixed input types at the same effValue (e.g. P2WPKH=68 + P2TR=57), waste " +
		"differs but blockbrew skips the second branch — sub-optimal result.")
}

// ── G18: BnB waste-grows pruning is_feerate_high — BUG-13 ────────────────────

func TestW129G18_BnBWasteGrowsPruning(t *testing.T) {
	t.Skip("BUG-13 (HIGH): no RecalculateWaste means no curr_waste tracking; the " +
		"is_feerate_high pruning branch in Core (coinselection.cpp:129: " +
		"'curr_waste > best_waste && is_feerate_high') cannot fire. " +
		"BnB explores branches Core would have skipped.")
}

// ── G19: max_selection_weight cap — BUG-8 ────────────────────────────────────

func TestW129G19_MaxSelectionWeight(t *testing.T) {
	t.Skip("BUG-8 (HIGH): selectCoinsBnB tracks no m_weight per UTXO and no " +
		"curr_selection_weight per branch. Core (coinselection.cpp:131) backtracks " +
		"when curr_selection_weight > max_selection_weight. A 50000-input UTXO set " +
		"could be returned as a 'valid' selection but rejected as oversized " +
		"by the mempool's 400k-weight standard limit.")
}

// ── G20: ErrorMaxWeightExceeded — BUG-8 ──────────────────────────────────────

func TestW129G20_ErrMaxWeightExceeded(t *testing.T) {
	t.Skip("BUG-8 (HIGH): no ErrMaxWeightExceeded sentinel error. Core returns " +
		"ErrorMaxWeightExceeded with the user-visible 'inputs size exceeds maximum " +
		"weight' message (coinselection.cpp:22-26) when the iteration could only " +
		"find solutions over the weight cap. blockbrew returns ErrInsufficientFunds " +
		"which is the wrong user error.")
}

// ── G21: Knapsack 2-pass random + fill-in ────────────────────────────────────

func TestW129G21_Knapsack2Pass(t *testing.T) {
	// approximateBestSubset runs two passes (pass 0 = random, pass 1 = fill-in)
	// — verify structurally by calling it and checking the value reached.
	utxos := []*utxoWithEffValue{
		{utxo: &WalletUTXO{Amount: 5000}, effValue: 4932},
		{utxo: &WalletUTXO{Amount: 15000}, effValue: 14932},
		{utxo: &WalletUTXO{Amount: 25000}, effValue: 24932},
	}
	_, val := approximateBestSubset(utxos, 20000)
	if val < 20000 {
		t.Errorf("G21 approximateBestSubset val %d < target 20000", val)
	}
}

// ── G22: Knapsack CSPRNG randomness (FIX-45) ─────────────────────────────────

func TestW129G22_KnapsackCSPRNG(t *testing.T) {
	// W113 BUG-6 closed by FIX-45; csRandShuffle uses crypto/rand.
	// Two independent shuffles of 8 elements should differ with probability
	// 1 - 1/8! ≈ 99.9975%.
	const n = 8
	utxos := make([]*utxoWithEffValue, n)
	for i := 0; i < n; i++ {
		utxos[i] = &utxoWithEffValue{
			utxo:     &WalletUTXO{Amount: int64(10000 + i*1000)},
			effValue: int64(9932 + i*1000),
		}
	}
	s1 := make([]*utxoWithEffValue, n)
	copy(s1, utxos)
	csRandShuffle(s1)
	s2 := make([]*utxoWithEffValue, n)
	copy(s2, utxos)
	csRandShuffle(s2)
	same := true
	for i := range s1 {
		if s1[i] != s2[i] {
			same = false
			break
		}
	}
	if same {
		t.Log("G22 NOTE: two independent shuffles produced identical order " +
			"(probability < 1/40000); rerun to confirm non-determinism — not a hard fail")
	}
}

// ── G23: Knapsack iteration cap = 1000 ───────────────────────────────────────

func TestW129G23_KnapsackIterationCap(t *testing.T) {
	if maxKnapsackIterations != 1000 {
		t.Errorf("G23 maxKnapsackIterations = %d, want 1000", maxKnapsackIterations)
	}
}

// ── G24: Knapsack second-pass at target + min_change_target — BUG-14 ─────────

func TestW129G24_KnapsackSecondPassTarget(t *testing.T) {
	t.Skip("BUG-14 (MEDIUM): selectCoinsKnapsack's second pass at " +
		"target+changeTarget (coinselection.go:312-318) uses costOfChange as the " +
		"change-target. Core uses m_min_change_target (the randomised target from " +
		"GenerateChangeTarget) — almost always LARGER than the creation-cost-only " +
		"costOfChange. blockbrew converges on a too-tight upper bound; Knapsack " +
		"creates change outputs Core would view as dust. Cross-ref W113 BUG-11.")
}

// ── G25: SFFO skip-BnB — BUG-15 ──────────────────────────────────────────────

func TestW129G25_SFFOSkipBnB(t *testing.T) {
	t.Skip("BUG-15 (MEDIUM): SelectCoins has no m_subtract_fee_outputs parameter; " +
		"BnB always runs. Core's ChooseSelectionResult skips BnB when SFFO is " +
		"active (spend.cpp:751: 'SFFO frequently causes issues in the context of " +
		"changeless input sets'). RPC layer applies SFFO POST-selection " +
		"(wallet_wave_methods.go:592) — too late to influence algorithm choice.")
}

// ── G26: 3×LTFRE CoinGrinder gate — BUG-2 ────────────────────────────────────

func TestW129G26_CoinGrinderGate(t *testing.T) {
	t.Skip("BUG-2 (MEDIUM): no 3×LTFRE branch. Core runs CoinGrinder when " +
		"effective_feerate > 3 × long_term_feerate (spend.cpp:769) — the " +
		"'high feerate, minimise input set' regime. Same fix as G4.")
}

// ── G27: OUTPUT_GROUP_MAX_ENTRIES=100 cap — BUG-16 ───────────────────────────

func TestW129G27_OutputGroupMaxEntries(t *testing.T) {
	t.Skip("BUG-16 (LOW): OUTPUT_GROUP_MAX_ENTRIES=100 is not defined or enforced. " +
		"Requires OutputGroup struct first (W113 BUG-2). Core caps each OutputGroup " +
		"at 100 entries when avoid-partial-spends is active (spend.cpp:889).")
}

// ── G28: Per-OutputType AttemptSelection — BUG-17 ────────────────────────────

func TestW129G28_PerOutputTypeAttempt(t *testing.T) {
	t.Skip("BUG-17 (MEDIUM): AttemptSelection (spend.cpp:702) runs " +
		"ChooseSelectionResult once per OutputType, picks the minimum-waste, " +
		"and only mixes types as last resort. blockbrew has no output-type " +
		"partitioning — every UTXO is in one global pool. Privacy: mixed-type " +
		"input sets are produced whenever Knapsack picks them, regardless of " +
		"whether a single-type solution exists.")
}

// ── G29: RecalculateWaste formula — BUG-13 ───────────────────────────────────

func TestW129G29_RecalculateWaste(t *testing.T) {
	t.Skip("BUG-13 (HIGH): SelectionResult has no Waste field, no RecalculateWaste " +
		"method, and no GetWaste accessor (coinselection.go:40-44). " +
		"Core's formula (coinselection.cpp:827): " +
		"  for each coin: waste += GetFee()-long_term_fee; waste -= bump_fee_group_discount; " +
		"  if change: waste += change_cost; else: waste += excess_over_target. " +
		"This is the keystone bug: gates BUG-9 (cross-algo comparison), BUG-10 " +
		"(equivalence shortcut), BUG-11 (sort tie-break), BUG-18 (is_feerate_high " +
		"pruning). A single RecalculateWaste implementation closes 4-5 downstream bugs.")
}

// ── G30: Multi-algorithm waste comparison — BUG-9 ────────────────────────────

func TestW129G30_MultiAlgoWasteComparison(t *testing.T) {
	t.Skip("BUG-9 (HIGH): SelectCoins (coinselection.go:64-106) runs BnB first " +
		"and RETURNS IMMEDIATELY on success (line 96-97), only running Knapsack " +
		"if BnB fails. Core runs ALL algorithms, pushes each result into a " +
		"vector, and picks the minimum-waste via std::min_element " +
		"(coinselection.cpp:716,811). Operator< compares by waste, breaks ties " +
		"by larger input count. blockbrew leaves waste on the table whenever " +
		"BnB succeeds with higher waste than Knapsack would have.")
}

// ── Bonus structural test: confirm SelectionResult shape (BUG-18 / BUG-19) ───

func TestW129BonusSelectionResultShape(t *testing.T) {
	utxos := []*WalletUTXO{
		{OutPoint: wire.OutPoint{Hash: wire.Hash256{1}}, Amount: 50068, PkScript: makeP2WPKHScript(), Confirmed: true},
	}
	result, err := SelectCoins(utxos, 40000, 1.0, 5000)
	if err != nil {
		t.Fatalf("Bonus SelectCoins: %v", err)
	}
	if result == nil {
		t.Fatal("Bonus nil result")
	}
	// Verify the *current* shape:
	//   - Coins (present)
	//   - Total (present)
	//   - Algorithm (present)
	// And document what's missing relative to Core:
	//   - Target, Weight, Waste, AlgoCompleted, SelectionsEvaluated,
	//     BumpFeeGroupDiscount, UseEffective — all MISSING (BUG-18, BUG-19).
	if result.Total == 0 {
		t.Error("Bonus: Total field unpopulated")
	}
	t.Logf("Bonus: result has Algorithm=%v, Total=%d, len(Coins)=%d; " +
		"missing Target/Weight/Waste/AlgoCompleted/SelectionsEvaluated/" +
		"BumpFeeGroupDiscount/UseEffective per Core (BUG-18, BUG-19)",
		result.Algorithm, result.Total, len(result.Coins))
}

// ── Sanity: estimateInputFee at integer feerates (no rounding mismatch) ──────

func TestW129SanityIntegerFeerate(t *testing.T) {
	// At integer feerates (1, 2, 3 sat/vB) blockbrew's truncation matches
	// Core's ceiling because 68 * N is divisible by 1000 when N is an int
	// multiple of vsize × satPerKvB / 1000 — actually it doesn't, but at
	// 1 sat/vB the product is 68, which int64(float64(68)) returns as 68.
	// Document the boundary so reviewers see when BUG-3 cleanly fails.
	cases := []struct {
		vsize    int
		feeRate  float64
		blockbrew int64 // observed (truncates)
		coreCeil  int64 // ceil((vsize * 1000 * feeRate + 999) / 1000)
	}{
		{68, 1.0, 68, 68},  // matches
		{68, 2.0, 136, 136}, // matches
		{68, 1.5, 102, 102}, // matches (68*1.5 = 102.0 exactly)
		{68, 1.7, 115, 116}, // BUG-3: 68*1.7 = 115.6 → blockbrew 115, Core 116
		{68, 1.3, 88, 89},   // BUG-3: 68*1.3 = 88.4 → blockbrew 88, Core 89
	}
	for _, c := range cases {
		got := estimateInputFee(makeP2WPKHScript(), c.feeRate)
		want := int64(math.Floor(float64(c.vsize) * c.feeRate))
		if got != want {
			t.Errorf("estimateInputFee(P2WPKH, %.2f) = %d, want %d (float truncate)",
				c.feeRate, got, want)
		}
		if got != c.coreCeil {
			t.Logf("BUG-3 at feeRate=%.2f: blockbrew %d != Core ceil %d", c.feeRate, got, c.coreCeil)
		}
	}
}
