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

// ErrTargetTooHigh is returned when the target exceeds the pow limit.
var ErrTargetTooHigh = errors.New("target exceeds pow limit")

// CompactToBig converts a Bitcoin compact target representation to a big.Int.
// Compact format: the first byte is the exponent (number of bytes), the next
// 3 bytes are the mantissa.
// target = mantissa * 2^(8*(exponent-3))
//
// The compact format uses sign-magnitude representation. If the high bit of
// the mantissa is set, the result is negative. Bitcoin never uses negative
// targets, so this is mainly for completeness.
func CompactToBig(compact uint32) *big.Int {
	// Extract the mantissa and exponent
	exponent := compact >> 24
	mantissa := compact & 0x007fffff

	var target *big.Int
	if exponent <= 3 {
		// For small exponents, we need to right-shift the mantissa
		mantissa >>= 8 * (3 - exponent)
		target = big.NewInt(int64(mantissa))
	} else {
		// For larger exponents, we shift left
		target = big.NewInt(int64(mantissa))
		target.Lsh(target, 8*(uint(exponent)-3))
	}

	// Handle negative bit (bit 23 of mantissa means negative)
	if compact&0x00800000 != 0 {
		target.Neg(target)
	}

	return target
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

// CalcBlockSubsidy returns the subsidy for a block at the given height.
// The subsidy halves every SubsidyHalvingInterval blocks (210,000 on mainnet).
// After 64 halvings, the subsidy is zero.
func CalcBlockSubsidy(height int32) int64 {
	halvings := height / SubsidyHalvingInterval
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
func CheckProofOfWork(hash wire.Hash256, bits uint32, powLimit *big.Int) error {
	target := CompactToBig(bits)

	// Check for negative target
	if target.Sign() <= 0 {
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
	return CalculateNextWorkRequired(params, height, lastNode, provider)
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
func CalculateNextWorkRequired(params *ChainParams, height int32, lastNode *BlockNode, provider BlockProvider) uint32 {
	// Find the first block of the difficulty period
	firstHeight := height - int32(params.DifficultyAdjInterval)
	firstNode := provider.GetHeaderByHeight(firstHeight)
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
