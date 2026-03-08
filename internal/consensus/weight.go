package consensus

import (
	"bytes"

	"github.com/hashhog/blockbrew/internal/wire"
)

// CalcTxWeight computes the weight of a transaction.
// Weight = (non-witness bytes * 3) + total_bytes
// This is equivalent to: base_size * (WitnessScaleFactor - 1) + total_size
func CalcTxWeight(tx *wire.MsgTx) int64 {
	// Calculate base size (without witness)
	var baseBuf bytes.Buffer
	tx.SerializeNoWitness(&baseBuf)
	baseSize := int64(baseBuf.Len())

	// Calculate total size (with witness if present)
	var totalBuf bytes.Buffer
	tx.Serialize(&totalBuf)
	totalSize := int64(totalBuf.Len())

	// Weight = (non_witness_bytes * 3) + total_bytes
	// Which is: (baseSize * 3) + totalSize
	// Note: The witness bytes are counted once in totalSize,
	// while non-witness bytes are counted 4 times total (3 + 1)
	return baseSize*(WitnessScaleFactor-1) + totalSize
}

// CalcBlockWeight computes the weight of a block.
// Weight = header weight + sum of transaction weights
// Header weight = 80 bytes * WitnessScaleFactor = 320 WU
func CalcBlockWeight(block *wire.MsgBlock) int64 {
	// Header is always 80 bytes, counts as non-witness data
	weight := int64(MaxBlockHeaderPayload * WitnessScaleFactor)

	// Add weight of all transactions
	for _, tx := range block.Transactions {
		weight += CalcTxWeight(tx)
	}

	return weight
}

// CalcTxVirtualSize computes the virtual size (vsize) of a transaction.
// VirtualSize = Weight / WitnessScaleFactor (rounded up)
func CalcTxVirtualSize(tx *wire.MsgTx) int64 {
	weight := CalcTxWeight(tx)
	// Round up: (weight + 3) / 4
	return (weight + WitnessScaleFactor - 1) / WitnessScaleFactor
}

// CalcTxSerializeSize returns the serialized size of a transaction with witness.
func CalcTxSerializeSize(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	tx.Serialize(&buf)
	return int64(buf.Len())
}

// CalcTxSerializeSizeNoWitness returns the serialized size without witness.
func CalcTxSerializeSizeNoWitness(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	return int64(buf.Len())
}
