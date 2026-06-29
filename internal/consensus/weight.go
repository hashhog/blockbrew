package consensus

import (
	"bytes"

	"github.com/hashhog/blockbrew/internal/wire"
)

// compactSizeLen returns the byte length of a CompactSize-encoded integer.
// This mirrors Bitcoin Core's GetSizeOfCompactSize().
func compactSizeLen(n uint64) int64 {
	switch {
	case n < 0xFD:
		return 1
	case n <= 0xFFFF:
		return 3 // 0xFD + 2 bytes
	case n <= 0xFFFFFFFF:
		return 5 // 0xFE + 4 bytes
	default:
		return 9 // 0xFF + 8 bytes
	}
}

// CalcTxWeight computes the weight of a transaction.
// Weight = stripped_size × (WITNESS_SCALE_FACTOR−1) + total_size
//        = stripped_size × 3 + total_size
//
// This is identical to Bitcoin Core's GetTransactionWeight (consensus/validation.h:132−134).
// Stripped serialization excludes the segwit marker (0x00), flag (0x01), and
// all per-input witness stacks.
func CalcTxWeight(tx *wire.MsgTx) int64 {
	// Calculate base size (without witness)
	var baseBuf bytes.Buffer
	tx.SerializeNoWitness(&baseBuf)
	baseSize := int64(baseBuf.Len())

	// Calculate total size (with witness if present)
	var totalBuf bytes.Buffer
	tx.Serialize(&totalBuf)
	totalSize := int64(totalBuf.Len())

	// Weight = stripped × 3 + total
	// (equivalent to stripped × 4 + witness_only_bytes)
	return baseSize*(WitnessScaleFactor-1) + totalSize
}

// CalcBlockWeight computes the weight of a block.
//
// Mirrors Bitcoin Core GetBlockWeight (consensus/validation.h:136−138):
//   weight = GetSerializeSize(TX_NO_WITNESS(block)) × 3
//            + GetSerializeSize(TX_WITH_WITNESS(block))
//
// The stripped block serialization is:
//   header (80) + compact_size(tx_count) + stripped_txs
// The full block serialization is:
//   header (80) + compact_size(tx_count) + full_txs
//
// Both serializations share the same header and tx-count varint, so the
// varint contributes varint_len × 4 WU to the block weight.  Earlier
// implementations omitted this term.
func CalcBlockWeight(block *wire.MsgBlock) int64 {
	nTx := uint64(len(block.Transactions))

	// Header is always 80 bytes; counts as non-witness data only.
	// Contribution: 80 × (4−1) + 80 = 80 × 4 = 320 WU.
	headerWU := int64(MaxBlockHeaderPayload * WitnessScaleFactor)

	// Tx-count varint: present identically in both stripped and full
	// serializations, so it contributes varint_len × 4 WU.
	varIntWU := compactSizeLen(nTx) * WitnessScaleFactor

	// Sum over all transactions.
	var txWU int64
	for _, tx := range block.Transactions {
		txWU += CalcTxWeight(tx)
	}

	return headerWU + varIntWU + txWU
}

// CalcTxInputWeight computes the weight of a single transaction input,
// including its witness stack contribution.
//
// Mirrors Bitcoin Core GetTransactionInputWeight (consensus/validation.h:140−143):
//   weight = stripped(txin) × 3 + total(txin) + serialize(witness.stack)
//
// The witness stack size is added explicitly because in the segwit wire
// format witness items and txins are serialized in separate passes; the
// per-input stripped/total sizes do not include the witness.
func CalcTxInputWeight(txin *wire.TxIn) int64 {
	// Stripped txin: prevout (36) + script_len varint + scriptSig + sequence (4)
	scriptLen := int64(len(txin.SignatureScript))
	strippedLen := 36 + compactSizeLen(uint64(scriptLen)) + scriptLen + 4

	// Total txin is the same as stripped (witness is NOT inlined in the txin).
	totalLen := strippedLen

	// Witness stack bytes: compact_size(items) + sum of compact_size(len)+item for each item.
	var witnessLen int64
	witnessLen += compactSizeLen(uint64(len(txin.Witness)))
	for _, item := range txin.Witness {
		l := int64(len(item))
		witnessLen += compactSizeLen(uint64(l)) + l
	}

	return strippedLen*(WitnessScaleFactor-1) + totalLen + witnessLen
}

// GetSigOpsAdjustedWeight returns max(weight, sigOpCost × bytesPerSigOp).
//
// Mirrors Bitcoin Core GetSigOpsAdjustedWeight (policy/policy.cpp:390−393):
//   return std::max(weight, sigop_cost * bytes_per_sigop);
//
// When bytesPerSigOp is 0 the sigop adjustment is disabled and the raw
// weight is returned unchanged (avoids division-by-zero in callers).
func GetSigOpsAdjustedWeight(weight, sigOpCost int64, bytesPerSigOp int) int64 {
	if bytesPerSigOp == 0 || sigOpCost == 0 {
		return weight
	}
	adj := sigOpCost * int64(bytesPerSigOp)
	if adj > weight {
		return adj
	}
	return weight
}

// GetVirtualTransactionSize computes the virtual size (vbytes) of a transaction
// given its weight and optional sigop cost.
//
// Mirrors Bitcoin Core GetVirtualTransactionSize (policy/policy.cpp:395−397):
//   return (GetSigOpsAdjustedWeight(nWeight, nSigOpCost, bytes_per_sigop)
//           + WITNESS_SCALE_FACTOR − 1) / WITNESS_SCALE_FACTOR;
//
// This is a ceiling division: vsize = ceil(adjusted_weight / 4).
// Pass sigOpCost=0 or bytesPerSigOp=0 to skip the sigop adjustment.
func GetVirtualTransactionSize(weight, sigOpCost int64, bytesPerSigOp int) int64 {
	adj := GetSigOpsAdjustedWeight(weight, sigOpCost, bytesPerSigOp)
	return (adj + WitnessScaleFactor - 1) / WitnessScaleFactor
}

// CalcTxVirtualSize computes the virtual size (vsize) of a transaction.
// VirtualSize = ceil(Weight / 4)  — no sigop adjustment.
// Use GetVirtualTransactionSize with a non-zero bytesPerSigOp for the
// sigop-adjusted variant (needed in mempool fee calculations).
func CalcTxVirtualSize(tx *wire.MsgTx) int64 {
	weight := CalcTxWeight(tx)
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

// CalcStrippedBlockWeight computes the "stripped" block weight:
// GetSerializeSize(TX_NO_WITNESS(block)) × WITNESS_SCALE_FACTOR (4).
//
// This is the context-free size check that Bitcoin Core applies in CheckBlock
// (validation.cpp:3947) BEFORE witness data is validated:
//
//	GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
//
// By excluding witness data, this check can be applied context-free without
// being vulnerable to witness-padding attacks: an attacker can pad witness
// data on a valid block (the block hash does not commit to witness) to inflate
// the full block weight beyond MAX_BLOCK_WEIGHT. If the witness-inclusive check
// ran first, the block hash would be permanently marked invalid — preventing
// the legitimate block (same hash, correct witness) from ever being accepted.
// The full witness-inclusive weight check is deferred to CheckBlockContext, after
// CheckWitnessMalleation has verified the witness commitment (so any excessive
// witness is the block's own, not an attacker's padding). See Core's
// ContextualCheckBlock comment (validation.cpp:4173-4178).
func CalcStrippedBlockWeight(block *wire.MsgBlock) int64 {
	nTx := uint64(len(block.Transactions))

	// Header (80 bytes) is non-witness data; it contributes 80 × 4 = 320 WU.
	headerWU := int64(MaxBlockHeaderPayload * WitnessScaleFactor)

	// Tx-count varint is the same in stripped and full serializations.
	varIntWU := compactSizeLen(nTx) * WitnessScaleFactor

	// Sum stripped (no-witness) tx sizes, each scaled by WitnessScaleFactor.
	var txWU int64
	for _, tx := range block.Transactions {
		var buf bytes.Buffer
		tx.SerializeNoWitness(&buf)
		txWU += int64(buf.Len()) * WitnessScaleFactor
	}

	return headerWU + varIntWU + txWU
}
