package consensus

import (
	"github.com/hashhog/blockbrew/internal/wire"
)

// CalcMerkleRoot computes the Merkle root of a list of transaction hashes.
// Bitcoin's Merkle tree duplicates the last element if the count is odd.
//
// Note: This wrapper does NOT detect CVE-2012-2459 (merkle-tree malleability
// from duplicate adjacent hashes). For block validation, use
// CalcMerkleRootMutation, which returns a `mutated` flag so the caller can
// distinguish a malicious mutation (transient — must NOT mark the block
// permanently invalid) from a real merkle-root mismatch (real — mark
// permanently invalid). See Bitcoin Core consensus/merkle.cpp:46-63 +
// validation.cpp:3837-3862.
func CalcMerkleRoot(hashes []wire.Hash256) wire.Hash256 {
	root, _ := CalcMerkleRootMutation(hashes)
	return root
}

// CalcMerkleRootMutation computes the Merkle root and reports whether any
// adjacent pair of hashes at any level is identical, the signature of
// CVE-2012-2459: an attacker can construct a "mutated" transaction list
// (e.g. [1,2,3,4,5,6,5,6]) that produces the same merkle root as the
// legitimate list ([1,2,3,4,5,6]) but has a different transaction count.
//
// Treat `mutated == true` as a transient block error: the block must be
// rejected, but it must NOT be permanently marked invalid, because the
// legitimate (un-mutated) form has the same block hash and is still valid.
//
// Mirrors Bitcoin Core's `ComputeMerkleRoot(std::vector<uint256> hashes,
// bool* mutated)` (consensus/merkle.cpp:46-63).
func CalcMerkleRootMutation(hashes []wire.Hash256) (wire.Hash256, bool) {
	if len(hashes) == 0 {
		return wire.Hash256{}, false
	}

	// Make a copy to avoid modifying the input
	level := make([]wire.Hash256, len(hashes))
	copy(level, hashes)

	mutated := false

	for len(level) > 1 {
		// Detect CVE-2012-2459: if any two adjacent hashes (before the odd-
		// duplicate step) are equal, mark the tree as mutated. This catches
		// both naturally duplicated adjacent leaves and the attacker's
		// trailing duplication. Core checks ALL levels, not just leaves.
		for pos := 0; pos+1 < len(level); pos += 2 {
			if level[pos] == level[pos+1] {
				mutated = true
			}
		}

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

	return level[0], mutated
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
