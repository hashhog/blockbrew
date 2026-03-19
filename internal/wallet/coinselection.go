// Package wallet implements key management and transaction signing.
package wallet

import (
	"math/rand"
	"sort"
)

// CoinSelectionAlgorithm identifies which algorithm was used.
type CoinSelectionAlgorithm int

const (
	AlgoBnB      CoinSelectionAlgorithm = iota // Branch and Bound
	AlgoKnapsack                               // Knapsack (stochastic approximation)
)

// SelectionResult contains the result of a coin selection algorithm.
type SelectionResult struct {
	Coins     []*WalletUTXO          // Selected UTXOs
	Total     int64                  // Total amount of selected UTXOs
	Algorithm CoinSelectionAlgorithm // Algorithm used
}

// BnB constants
const (
	// maxBnBIterations is the maximum number of iterations for BnB algorithm.
	// Bitcoin Core uses 100,000.
	maxBnBIterations = 100000

	// maxKnapsackIterations is the number of random passes for knapsack.
	maxKnapsackIterations = 1000

	// dustThreshold is the minimum output value to avoid creating dust.
	dustThreshold = int64(546)
)

// SelectCoins selects UTXOs to fund a transaction.
// It tries BnB first for an exact match, then falls back to Knapsack.
// target is the amount to send (not including fees).
// feeRate is in sat/vbyte.
// costOfChange is the fee cost for adding a change output.
func SelectCoins(utxos []*WalletUTXO, target int64, feeRate float64, costOfChange int64) (*SelectionResult, error) {
	if len(utxos) == 0 {
		return nil, ErrInsufficientFunds
	}

	// Filter to confirmed UTXOs only and calculate effective values
	var available []*utxoWithEffValue
	var totalAvailable int64
	for _, u := range utxos {
		if !u.Confirmed {
			continue
		}
		// Estimate input fee based on UTXO type
		inputFee := estimateInputFee(u.PkScript, feeRate)
		effValue := u.Amount - inputFee
		if effValue > 0 {
			available = append(available, &utxoWithEffValue{
				utxo:     u,
				effValue: effValue,
				inputFee: inputFee,
			})
			totalAvailable += effValue
		}
	}

	if totalAvailable < target {
		return nil, ErrInsufficientFunds
	}

	// Try Branch and Bound first (prefers changeless transactions)
	result := selectCoinsBnB(available, target, costOfChange)
	if result != nil {
		return result, nil
	}

	// Fall back to Knapsack
	result = selectCoinsKnapsack(available, target, costOfChange)
	if result != nil {
		return result, nil
	}

	return nil, ErrInsufficientFunds
}

// utxoWithEffValue wraps a UTXO with its effective value (after input fee).
type utxoWithEffValue struct {
	utxo     *WalletUTXO
	effValue int64 // amount - input_fee
	inputFee int64
}

// selectCoinsBnB implements the Branch and Bound coin selection algorithm.
// It searches for a selection that is exactly equal to target or within costOfChange of it.
// This avoids creating a change output.
func selectCoinsBnB(utxos []*utxoWithEffValue, target int64, costOfChange int64) *SelectionResult {
	if len(utxos) == 0 {
		return nil
	}

	// Sort by descending effective value
	sorted := make([]*utxoWithEffValue, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].effValue > sorted[j].effValue
	})

	// Calculate total available
	var totalAvailable int64
	for _, u := range sorted {
		totalAvailable += u.effValue
	}

	if totalAvailable < target {
		return nil
	}

	// Best solution found
	var bestSelection []int
	bestWaste := int64(1<<62 - 1) // Max int64-ish

	// Current selection state
	currSelection := make([]int, 0)
	currValue := int64(0)
	currAvailable := totalAvailable

	// DFS with backtracking
	for tries := 0; tries < maxBnBIterations; tries++ {
		// Compute current UTXO index (next to consider)
		utxoIdx := 0
		if len(currSelection) > 0 {
			utxoIdx = currSelection[len(currSelection)-1] + 1
		}

		// Check if we need to backtrack
		backtrack := false

		if currValue+currAvailable < target {
			// Cannot possibly reach target
			backtrack = true
		} else if currValue > target+costOfChange {
			// Overshoot - too much change
			backtrack = true
		} else if currValue >= target {
			// Found a valid solution!
			waste := currValue - target
			if waste < bestWaste {
				bestWaste = waste
				bestSelection = make([]int, len(currSelection))
				copy(bestSelection, currSelection)
			}
			// Backtrack to find potentially better solutions
			backtrack = true
		} else if utxoIdx >= len(sorted) {
			// Exhausted UTXOs
			backtrack = true
		}

		if backtrack {
			// Pop the last selection and try skipping it
			if len(currSelection) == 0 {
				// Searched everything
				break
			}

			// Restore available amount for skipped UTXOs
			lastIdx := currSelection[len(currSelection)-1]
			for i := utxoIdx - 1; i >= lastIdx; i-- {
				currAvailable += sorted[i].effValue
			}

			// Remove the last selected UTXO
			currValue -= sorted[lastIdx].effValue
			currSelection = currSelection[:len(currSelection)-1]

			// Move to skip this UTXO (will be handled in next iteration)
			// We need to continue from lastIdx+1
			if len(currSelection) > 0 {
				utxoIdx = lastIdx + 1
			} else {
				utxoIdx = lastIdx + 1
			}

			// Skip equivalent UTXOs (same effective value)
			for utxoIdx < len(sorted) && sorted[utxoIdx].effValue == sorted[lastIdx].effValue {
				currAvailable -= sorted[utxoIdx].effValue
				utxoIdx++
			}

			if utxoIdx >= len(sorted) {
				continue
			}

			// Include the next UTXO
			currSelection = append(currSelection, utxoIdx)
			currValue += sorted[utxoIdx].effValue
			currAvailable -= sorted[utxoIdx].effValue
		} else {
			// Include current UTXO and continue
			currSelection = append(currSelection, utxoIdx)
			currValue += sorted[utxoIdx].effValue
			currAvailable -= sorted[utxoIdx].effValue
		}
	}

	if len(bestSelection) == 0 {
		return nil
	}

	// Build result
	result := &SelectionResult{
		Coins:     make([]*WalletUTXO, len(bestSelection)),
		Algorithm: AlgoBnB,
	}

	for i, idx := range bestSelection {
		result.Coins[i] = sorted[idx].utxo
		result.Total += sorted[idx].utxo.Amount
	}

	return result
}

// selectCoinsKnapsack implements the Knapsack coin selection algorithm.
// It uses randomized stochastic approximation to find a subset close to target.
func selectCoinsKnapsack(utxos []*utxoWithEffValue, target int64, changeTarget int64) *SelectionResult {
	if len(utxos) == 0 {
		return nil
	}

	// Separate into applicable (< target + change) and larger
	var applicable []*utxoWithEffValue
	var lowestLarger *utxoWithEffValue
	var totalLower int64

	// Shuffle first for randomness
	shuffled := make([]*utxoWithEffValue, len(utxos))
	copy(shuffled, utxos)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	for _, u := range shuffled {
		if u.effValue == target {
			// Exact match!
			return &SelectionResult{
				Coins:     []*WalletUTXO{u.utxo},
				Total:     u.utxo.Amount,
				Algorithm: AlgoKnapsack,
			}
		} else if u.effValue < target+changeTarget {
			applicable = append(applicable, u)
			totalLower += u.effValue
		} else if lowestLarger == nil || u.effValue < lowestLarger.effValue {
			lowestLarger = u
		}
	}

	// Check if total of smaller coins equals target exactly
	if totalLower == target {
		result := &SelectionResult{
			Algorithm: AlgoKnapsack,
		}
		for _, u := range applicable {
			result.Coins = append(result.Coins, u.utxo)
			result.Total += u.utxo.Amount
		}
		return result
	}

	// If smaller coins are insufficient, use the larger one
	if totalLower < target {
		if lowestLarger == nil {
			return nil
		}
		return &SelectionResult{
			Coins:     []*WalletUTXO{lowestLarger.utxo},
			Total:     lowestLarger.utxo.Amount,
			Algorithm: AlgoKnapsack,
		}
	}

	// Sort applicable by descending value for the approximation
	sort.Slice(applicable, func(i, j int) bool {
		return applicable[i].effValue > applicable[j].effValue
	})

	// Approximate best subset using stochastic algorithm
	bestSelection, bestValue := approximateBestSubset(applicable, target)

	// Try again with target + changeTarget
	if bestValue != target && totalLower >= target+changeTarget {
		sel2, val2 := approximateBestSubset(applicable, target+changeTarget)
		if val2 >= target+changeTarget && (bestValue < target || val2 < bestValue) {
			bestSelection = sel2
			bestValue = val2
		}
	}

	// Compare with lowestLarger
	if lowestLarger != nil {
		if bestValue < target || lowestLarger.effValue <= bestValue {
			return &SelectionResult{
				Coins:     []*WalletUTXO{lowestLarger.utxo},
				Total:     lowestLarger.utxo.Amount,
				Algorithm: AlgoKnapsack,
			}
		}
	}

	// Build result from best selection
	if len(bestSelection) == 0 || bestValue < target {
		if lowestLarger != nil {
			return &SelectionResult{
				Coins:     []*WalletUTXO{lowestLarger.utxo},
				Total:     lowestLarger.utxo.Amount,
				Algorithm: AlgoKnapsack,
			}
		}
		return nil
	}

	result := &SelectionResult{
		Algorithm: AlgoKnapsack,
	}
	for _, idx := range bestSelection {
		result.Coins = append(result.Coins, applicable[idx].utxo)
		result.Total += applicable[idx].utxo.Amount
	}

	return result
}

// approximateBestSubset uses random selection passes to find a good subset.
// Returns indices into the utxos slice and the effective value sum.
func approximateBestSubset(utxos []*utxoWithEffValue, target int64) ([]int, int64) {
	n := len(utxos)
	if n == 0 {
		return nil, 0
	}

	// Best solution: worst case is all UTXOs
	bestIncluded := make([]bool, n)
	for i := range bestIncluded {
		bestIncluded[i] = true
	}
	var bestValue int64
	for _, u := range utxos {
		bestValue += u.effValue
	}

	included := make([]bool, n)

	for rep := 0; rep < maxKnapsackIterations && bestValue != target; rep++ {
		// Reset included
		for i := range included {
			included[i] = false
		}
		var total int64
		reachedTarget := false

		// Two passes: first random, second fill in remaining
		for pass := 0; pass < 2 && !reachedTarget; pass++ {
			for i := 0; i < n; i++ {
				// First pass: randomly include/exclude
				// Second pass: include anything not already included
				if (pass == 0 && rand.Intn(2) == 1) || (pass == 1 && !included[i]) {
					total += utxos[i].effValue
					included[i] = true

					if total >= target {
						reachedTarget = true
						// If this is better than best, save it
						if total < bestValue {
							bestValue = total
							copy(bestIncluded, included)
						}
						// Remove this last addition and continue
						total -= utxos[i].effValue
						included[i] = false
					}
				}
			}
		}
	}

	// Convert bestIncluded to indices
	var result []int
	for i, inc := range bestIncluded {
		if inc {
			result = append(result, i)
		}
	}

	return result, bestValue
}

// estimateInputFee estimates the fee for spending a UTXO based on script type.
func estimateInputFee(pkScript []byte, feeRate float64) int64 {
	vsize := estimateInputVSize(pkScript)
	return int64(float64(vsize) * feeRate)
}

// estimateInputVSize estimates the virtual size of an input based on script type.
func estimateInputVSize(pkScript []byte) int {
	if len(pkScript) == 0 {
		return 68 // Default to P2WPKH
	}

	// P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
	if len(pkScript) == 25 && pkScript[0] == 0x76 && pkScript[1] == 0xa9 {
		// Legacy input: ~148 bytes
		return 148
	}

	// P2SH: OP_HASH160 <20> OP_EQUAL
	if len(pkScript) == 23 && pkScript[0] == 0xa9 {
		// Could be P2SH-P2WPKH: ~91 vbytes
		return 91
	}

	// P2WPKH: OP_0 <20>
	if len(pkScript) == 22 && pkScript[0] == 0x00 && pkScript[1] == 0x14 {
		// Native segwit: ~68 vbytes
		return 68
	}

	// P2WSH: OP_0 <32>
	if len(pkScript) == 34 && pkScript[0] == 0x00 && pkScript[1] == 0x20 {
		// Witness script: ~108 vbytes (depends on script)
		return 108
	}

	// P2TR: OP_1 <32>
	if len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20 {
		// Taproot key-path: ~57 vbytes
		return 57
	}

	// Default to P2WPKH
	return 68
}

// estimateOutputVSize estimates the virtual size of an output based on script type.
func estimateOutputVSize(pkScript []byte) int {
	if len(pkScript) == 0 {
		return 31 // Default to P2WPKH
	}

	// P2PKH
	if len(pkScript) == 25 {
		return 34
	}

	// P2SH
	if len(pkScript) == 23 {
		return 32
	}

	// P2WPKH
	if len(pkScript) == 22 {
		return 31
	}

	// P2WSH / P2TR
	if len(pkScript) == 34 {
		return 43
	}

	return 31
}

// EstimateTxVSize estimates the virtual size of a transaction.
func EstimateTxVSize(numInputs int, inputScripts [][]byte, numOutputs int, outputScripts [][]byte) int {
	// Base size (version + locktime + input/output counts)
	baseSize := 10

	// Add input sizes
	for i := 0; i < numInputs; i++ {
		if i < len(inputScripts) {
			baseSize += estimateInputVSize(inputScripts[i])
		} else {
			baseSize += 68 // default P2WPKH
		}
	}

	// Add output sizes
	for i := 0; i < numOutputs; i++ {
		if i < len(outputScripts) {
			baseSize += estimateOutputVSize(outputScripts[i])
		} else {
			baseSize += 31 // default P2WPKH
		}
	}

	return baseSize
}

// EstimateChangeOutputFee estimates the fee for adding a change output.
func EstimateChangeOutputFee(changeScript []byte, feeRate float64) int64 {
	vsize := estimateOutputVSize(changeScript)
	return int64(float64(vsize) * feeRate)
}
