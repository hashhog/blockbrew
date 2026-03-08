package consensus

import (
	"github.com/hashhog/blockbrew/internal/wire"
)

// CalcMerkleRoot computes the Merkle root of a list of transaction hashes.
// Bitcoin's Merkle tree duplicates the last element if the count is odd.
func CalcMerkleRoot(hashes []wire.Hash256) wire.Hash256 {
	if len(hashes) == 0 {
		return wire.Hash256{}
	}

	// Make a copy to avoid modifying the input
	level := make([]wire.Hash256, len(hashes))
	copy(level, hashes)

	for len(level) > 1 {
		// If odd number of elements, duplicate the last one
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1])
		}

		// Compute the next level
		nextLevel := make([]wire.Hash256, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			nextLevel[i/2] = hashPair(level[i], level[i+1])
		}
		level = nextLevel
	}

	return level[0]
}

// hashPair computes DoubleSHA256(left || right).
func hashPair(left, right wire.Hash256) wire.Hash256 {
	var combined [64]byte
	copy(combined[:32], left[:])
	copy(combined[32:], right[:])
	return wire.DoubleHashB(combined[:])
}

// CalcWitnessMerkleRoot computes the witness Merkle root (BIP141).
// The first hash (coinbase wtxid) is replaced with all zeros.
func CalcWitnessMerkleRoot(wtxids []wire.Hash256) wire.Hash256 {
	if len(wtxids) == 0 {
		return wire.Hash256{}
	}

	// Make a copy with the first element (coinbase wtxid) set to all zeros
	hashes := make([]wire.Hash256, len(wtxids))
	copy(hashes, wtxids)
	hashes[0] = wire.Hash256{} // Coinbase wtxid is replaced with 32 zero bytes

	return CalcMerkleRoot(hashes)
}

// CalcWitnessCommitment computes the witness commitment for a block.
// commitment = DoubleSHA256(witnessMerkleRoot || witnessReservedValue)
// The witnessReservedValue is the coinbase's witness item (typically 32 zero bytes).
func CalcWitnessCommitment(wtxids []wire.Hash256, witnessReservedValue []byte) wire.Hash256 {
	witnessMerkleRoot := CalcWitnessMerkleRoot(wtxids)

	// Compute: DoubleSHA256(witnessMerkleRoot || witnessReservedValue)
	data := make([]byte, 32+len(witnessReservedValue))
	copy(data[:32], witnessMerkleRoot[:])
	copy(data[32:], witnessReservedValue)

	return wire.DoubleHashB(data)
}
