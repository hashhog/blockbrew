package consensus

import (
	"errors"
	"log"
	"math/big"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ErrDifficultyTooLow is returned when a block's proof of work doesn't meet the target.
var ErrDifficultyTooLow = errors.New("block hash does not meet target difficulty")

// ErrNegativeTarget is returned when the compact target decodes to a negative value.
var ErrNegativeTarget = errors.New("negative target")

// ErrTargetTooHigh is returned when the target exceeds the pow limit or overflows.
var ErrTargetTooHigh = errors.New("target exceeds pow limit")

// ErrBadDifficultyTransition is returned when a non-retarget block changes nBits,
// or when a retarget block's nBits falls outside the 4× permitted range.
var ErrBadDifficultyTransition = errors.New("difficulty transition not permitted")

// CompactToBig converts a Bitcoin compact target representation to a big.Int.
// Compact format: the first byte is the exponent (number of bytes), the next
// 3 bytes are the mantissa.
// target = mantissa * 2^(8*(exponent-3))
//
// The compact format uses sign-magnitude representation. If the high bit of
// the mantissa is set, the result is negative. Bitcoin never uses negative
// targets, so this is mainly for completeness.
func CompactToBig(compact uint32) *big.Int {
	n, _, _ := compactToBigFull(compact)
	return n
}

// compactToBigFull converts a compact target and also returns the negative and
// overflow flags. This mirrors Bitcoin Core's arith_uint256::SetCompact.
//
// Overflow is true when the encoded value cannot be represented in 256 bits:
//   - exponent > 34, OR
//   - exponent == 34 and mantissa > 0xff, OR
//   - exponent == 33 and mantissa > 0xffff
//
// These conditions correspond exactly to Core arith_uint256.cpp:190-192.
func compactToBigFull(compact uint32) (n *big.Int, isNegative, isOverflow bool) {
	exponent := compact >> 24
	mantissa := compact & 0x007fffff

	// Negative flag: bit 23 of the original compact word.
	isNegative = (mantissa != 0) && (compact&0x00800000 != 0)

	// Overflow flag: mirrors Core's SetCompact overflow check.
	isOverflow = mantissa != 0 && (exponent > 34 ||
		(mantissa > 0xff && exponent > 33) ||
		(mantissa > 0xffff && exponent > 32))

	var target *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		target = big.NewInt(int64(mantissa))
	} else {
		target = big.NewInt(int64(mantissa))
		target.Lsh(target, 8*(uint(exponent)-3))
	}

	if isNegative {
		target.Neg(target)
	}

	return target, isNegative, isOverflow
}

// BigToCompact converts a big.Int target to compact representation.
// This reverses the CompactToBig operation.
func BigToCompact(n *big.Int) uint32 {
	// Handle zero
	if n.Sign() == 0 {
		return 0
	}

	// Work with absolute value
	isNegative := n.Sign() < 0
	absN := new(big.Int).Abs(n)

	// Get the byte representation
	bytes := absN.Bytes()
	exponent := uint32(len(bytes))

	// Build the mantissa from the most significant bytes
	var mantissa uint32
	if exponent <= 3 {
		// Pad with zeros on the right
		mantissa = uint32(absN.Uint64()) << (8 * (3 - exponent))
	} else {
		// Use the top 3 bytes
		mantissa = uint32(bytes[0])<<16 | uint32(bytes[1])<<8 | uint32(bytes[2])
	}

	// If the high bit is set in the mantissa, we need to shift right to avoid
	// it being interpreted as a negative number
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	// Combine exponent and mantissa
	compact := (exponent << 24) | mantissa

	// Set negative bit if needed
	if isNegative {
		compact |= 0x00800000
	}

	return compact
}

// CalcNextRequiredDifficulty calculates the required difficulty for a new block.
// prevBits: the difficulty target of the last block
// firstTimestamp: the timestamp of the first block in the current difficulty period
// lastTimestamp: the timestamp of the last block in the current difficulty period
//
// The algorithm:
// 1. actualTimespan = lastTimestamp - firstTimestamp
// 2. Clamp actualTimespan to [TargetTimespan/4, TargetTimespan*4]
// 3. newTarget = oldTarget * actualTimespan / TargetTimespan
// 4. If newTarget > powLimit, set to powLimit
// 5. Return BigToCompact(newTarget)
func CalcNextRequiredDifficulty(params *ChainParams, prevBits uint32, firstTimestamp, lastTimestamp int64) uint32 {
	// Calculate actual timespan
	actualTimespan := lastTimestamp - firstTimestamp

	// Clamp the timespan to prevent extreme difficulty changes
	// Minimum: TargetTimespan/4 (302,400 seconds = ~3.5 days)
	// Maximum: TargetTimespan*4 (4,838,400 seconds = ~8 weeks)
	minTimespan := params.TargetTimespan / 4
	maxTimespan := params.TargetTimespan * 4

	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	}
	if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	// Calculate new target: newTarget = oldTarget * actualTimespan / TargetTimespan
	oldTarget := CompactToBig(prevBits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(actualTimespan))
	newTarget.Div(newTarget, big.NewInt(params.TargetTimespan))

	// Ensure new target doesn't exceed pow limit
	if newTarget.Cmp(params.PowLimit) > 0 {
		newTarget.Set(params.PowLimit)
	}

	return BigToCompact(newTarget)
}

// CalcBlockSubsidy returns the subsidy for a block at the given height using
// the MAINNET halving interval (210,000). The subsidy halves every
// SubsidyHalvingInterval blocks; after 64 halvings, the subsidy is zero.
//
// This is the historical (network-agnostic) entrypoint, preserved byte-for-byte
// for every existing caller. For per-network correctness (regtest halves every
// 150 blocks, kernel/chainparams.cpp:535) use CalcBlockSubsidyForInterval,
// which mirrors Bitcoin Core's GetBlockSubsidy(nHeight, consensusParams)
// reading consensusParams.nSubsidyHalvingInterval (validation.cpp:1839-1841).
func CalcBlockSubsidy(height int32) int64 {
	return CalcBlockSubsidyForInterval(height, SubsidyHalvingInterval)
}

// CalcBlockSubsidyForInterval returns the block subsidy at the given height for
// an arbitrary halving interval, the network-aware form of CalcBlockSubsidy.
// Faithful port of Bitcoin Core validation.cpp:1839-1851
// GetBlockSubsidy(nHeight, consensusParams):
//
//	int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
//	if (halvings >= 64) return 0;
//	CAmount nSubsidy = 50 * COIN;
//	nSubsidy >>= halvings;
//
// Default-preserving: passing SubsidyHalvingInterval (210,000) is identical to
// the original CalcBlockSubsidy. A zero/negative interval is guarded to the
// mainnet interval so a malformed params value cannot divide-by-zero.
func CalcBlockSubsidyForInterval(height int32, halvingInterval int32) int64 {
	if halvingInterval <= 0 {
		halvingInterval = SubsidyHalvingInterval
	}
	halvings := height / halvingInterval
	if halvings >= 64 {
		return 0
	}
	subsidy := InitialSubsidy
	subsidy >>= uint(halvings)
	return subsidy
}

// HashToBig converts a Hash256 to a big.Int for comparison with the target.
// The hash bytes are interpreted as a little-endian 256-bit number.
func HashToBig(hash wire.Hash256) *big.Int {
	// The hash is stored in internal order (little-endian when viewed as a number)
	// We need to reverse it for big.Int which expects big-endian
	var reversed [32]byte
	for i := 0; i < 32; i++ {
		reversed[i] = hash[31-i]
	}
	return new(big.Int).SetBytes(reversed[:])
}

// CheckProofOfWork verifies that the block hash meets the target difficulty.
// The hash must be less than or equal to the target derived from bits.
// Returns nil if the proof of work is valid, an error otherwise.
//
// Mirrors Bitcoin Core's CheckProofOfWorkImpl / DeriveTarget (pow.cpp):
//   - negative compact → reject
//   - overflow compact → reject (exponent encodes > 256 bits)
//   - target == 0 → reject
//   - target > powLimit → reject
//   - hash > target → reject
func CheckProofOfWork(hash wire.Hash256, bits uint32, powLimit *big.Int) error {
	target, isNegative, isOverflow := compactToBigFull(bits)

	// Check for negative target (sign bit set in compact mantissa).
	if isNegative {
		return ErrNegativeTarget
	}

	// Check for overflow (compact exponent encodes more than 256 bits).
	// Core: DeriveTarget returns {} when fOverflow is true (pow.cpp:154-156).
	if isOverflow {
		return ErrTargetTooHigh
	}

	// Zero target is invalid.
	if target.Sign() == 0 {
		return ErrNegativeTarget
	}

	// Check that target doesn't exceed the pow limit
	if target.Cmp(powLimit) > 0 {
		return ErrTargetTooHigh
	}

	// Convert hash to big.Int and compare
	hashNum := HashToBig(hash)
	if hashNum.Cmp(target) > 0 {
		log.Printf("PoW FAIL: hash=%064x target=%064x bits=%08x", hashNum, target, bits)
		return ErrDifficultyTooLow
	}

	return nil
}

// IsMinDifficultyBlock checks if a block should use minimum difficulty.
// On testnet, if a block's timestamp is more than 2*TargetSpacing (20 minutes)
// after the previous block, the difficulty resets to PowLimitBits.
// This is the MinDiffReductionTime rule (BIP 94 for testnet4).
func IsMinDifficultyBlock(params *ChainParams, blockTimestamp, prevBlockTimestamp int64) bool {
	if !params.MinDiffReductionTime {
		return false
	}
	return blockTimestamp > prevBlockTimestamp+2*params.TargetSpacing
}

// BlockProvider is an interface for looking up block header data needed for
// difficulty calculations. This allows the difficulty code to work with both
// the full HeaderIndex and simpler test implementations.
type BlockProvider interface {
	// GetHeaderByHeight returns the header at a given height, or nil if not found.
	GetHeaderByHeight(height int32) *BlockNode
	// GetPrevHeader returns the parent of a block, or nil for genesis.
	GetPrevHeader(node *BlockNode) *BlockNode
}

// GetNextWorkRequired calculates the required difficulty for a new block.
// This is the main entry point that handles all network-specific rules:
//   - Normal mainnet retarget (every 2016 blocks)
//   - Testnet min-difficulty exception (> 20 min gap)
//   - Testnet walk-back (find last non-min-difficulty block)
//   - BIP94 testnet4 (use first block of period for retarget base)
//   - Regtest no-retarget (always return genesis difficulty)
//
// Parameters:
//   - params: chain parameters
//   - height: height of the new block being validated
//   - newBlockTimestamp: timestamp of the new block
//   - lastNode: the parent block node
//   - provider: interface to look up ancestor blocks
func GetNextWorkRequired(params *ChainParams, height int32, newBlockTimestamp int64, lastNode *BlockNode, provider BlockProvider) uint32 {
	// Genesis block uses PowLimitBits
	if lastNode == nil {
		return params.PowLimitBits
	}

	// Regtest: never adjust difficulty
	if params.PowNoRetargeting {
		return lastNode.Header.Bits
	}

	// Check if this is a difficulty adjustment boundary
	if height%int32(params.DifficultyAdjInterval) != 0 {
		// Not at a retarget boundary
		if params.MinDiffReductionTime {
			// Testnet special rule: if block is > 20 min after previous,
			// allow minimum difficulty
			if newBlockTimestamp > int64(lastNode.Header.Timestamp)+2*params.TargetSpacing {
				return params.PowLimitBits
			}
			// Otherwise, walk back to find the last non-min-difficulty block
			return getTestnetNonMinDiffBits(params, lastNode, provider)
		}
		// Mainnet: use same difficulty as last block
		return lastNode.Header.Bits
	}

	// At a difficulty adjustment boundary (every 2016 blocks)
	return CalculateNextWorkRequired(params, height, lastNode)
}

// getTestnetNonMinDiffBits walks back through the chain to find the last block
// that wasn't at minimum difficulty. This implements the testnet walk-back rule.
func getTestnetNonMinDiffBits(params *ChainParams, lastNode *BlockNode, provider BlockProvider) uint32 {
	node := lastNode
	for node != nil &&
		node.Height%int32(params.DifficultyAdjInterval) != 0 &&
		node.Header.Bits == params.PowLimitBits {
		node = provider.GetPrevHeader(node)
	}
	if node == nil {
		return params.PowLimitBits
	}
	return node.Header.Bits
}

// CalculateNextWorkRequired calculates the new difficulty at a retarget boundary.
// Implements both standard and BIP94 (testnet4) retarget logic.
//
// The period-first block is resolved by walking lastNode's OWN parent ancestry,
// matching Bitcoin Core pow.cpp:44:
//
//	pindexFirst = pindexLast->GetAncestor(nHeightFirst)
//
// This is branch-correct for fork headers: a fork tip uses its own lineage for
// the retarget, not whatever the active (best) chain has at that height.
func CalculateNextWorkRequired(params *ChainParams, height int32, lastNode *BlockNode) uint32 {
	// Find the first block of the difficulty period by walking lastNode's ancestry.
	// Core pow.cpp:42-44: nHeightFirst = pindexLast->nHeight - (DifficultyAdjustmentInterval-1)
	//                      pindexFirst  = pindexLast->GetAncestor(nHeightFirst)
	firstHeight := height - int32(params.DifficultyAdjInterval)
	firstNode := lastNode.GetAncestor(firstHeight)
	if firstNode == nil {
		return lastNode.Header.Bits
	}

	// Calculate actual timespan for the period
	actualTimespan := int64(lastNode.Header.Timestamp) - int64(firstNode.Header.Timestamp)

	// Clamp to [TargetTimespan/4, TargetTimespan*4]
	minTimespan := params.TargetTimespan / 4
	maxTimespan := params.TargetTimespan * 4
	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	}
	if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	// BIP94 (testnet4): use the first block's difficulty as the base.
	// This prevents miners from manipulating difficulty by using the
	// min-difficulty exception repeatedly.
	var baseBits uint32
	if params.EnforceBIP94 {
		baseBits = firstNode.Header.Bits
	} else {
		baseBits = lastNode.Header.Bits
	}

	// Calculate new target: newTarget = oldTarget * actualTimespan / TargetTimespan
	oldTarget := CompactToBig(baseBits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(actualTimespan))
	newTarget.Div(newTarget, big.NewInt(params.TargetTimespan))

	// Ensure new target doesn't exceed pow limit
	if newTarget.Cmp(params.PowLimit) > 0 {
		newTarget.Set(params.PowLimit)
	}

	return BigToCompact(newTarget)
}

// PermittedDifficultyTransition reports whether the difficulty transition from
// old_nbits to new_nbits at the given height is valid.
//
// Mirrors Bitcoin Core's PermittedDifficultyTransition (pow.cpp:89-136):
//   - On networks where min-difficulty blocks are allowed (testnet/regtest),
//     always returns true.
//   - At retarget boundaries (height % 2016 == 0): new_nbits must be within
//     the [÷4, ×4] factor of old_nbits. Comparison uses a compact round-trip
//     (BigToCompact(GetCompact-decoded-value)) to match Core exactly.
//   - At all other heights: new_nbits must equal old_nbits exactly.
//
// Note: this is a defence-in-depth guard for headers-first sync. It is called
// in addition to (not instead of) GetNextWorkRequired, which already computes
// the correct expected bits.
func PermittedDifficultyTransition(params *ChainParams, height int32, oldNBits, newNBits uint32) bool {
	// Networks allowing min-difficulty blocks skip this check.
	// Core: if (params.fPowAllowMinDifficultyBlocks) return true; (pow.cpp:91)
	if params.MinDiffReductionTime {
		return true
	}

	powLimit := params.PowLimit

	if height%int32(params.DifficultyAdjInterval) == 0 {
		// Retarget boundary: verify new_nbits is within ×4 / ÷4 of old_nbits.
		smallestTimespan := params.TargetTimespan / 4
		largestTimespan := params.TargetTimespan * 4

		observedNew := CompactToBig(newNBits)

		// Calculate the largest (easiest) permitted difficulty value:
		// largest_target = old_target * (4 * TargetTimespan) / TargetTimespan
		largestTarget := CompactToBig(oldNBits)
		largestTarget.Mul(largestTarget, big.NewInt(largestTimespan))
		largestTarget.Div(largestTarget, big.NewInt(params.TargetTimespan))
		if largestTarget.Cmp(powLimit) > 0 {
			largestTarget.Set(powLimit)
		}
		// Round-trip through compact encoding, as Core does (pow.cpp:113-114).
		maximumNew := CompactToBig(BigToCompact(largestTarget))
		if maximumNew.Cmp(observedNew) < 0 {
			return false
		}

		// Calculate the smallest (hardest) permitted difficulty value:
		// smallest_target = old_target * (TargetTimespan/4) / TargetTimespan
		smallestTarget := CompactToBig(oldNBits)
		smallestTarget.Mul(smallestTarget, big.NewInt(smallestTimespan))
		smallestTarget.Div(smallestTarget, big.NewInt(params.TargetTimespan))
		if smallestTarget.Cmp(powLimit) > 0 {
			smallestTarget.Set(powLimit)
		}
		// Round-trip through compact encoding (pow.cpp:130-131).
		minimumNew := CompactToBig(BigToCompact(smallestTarget))
		if minimumNew.Cmp(observedNew) > 0 {
			return false
		}
	} else {
		// Non-retarget height: nBits must be unchanged.
		// Core: else if (old_nbits != new_nbits) { return false; } (pow.cpp:132-133)
		if oldNBits != newNBits {
			return false
		}
	}
	return true
}
