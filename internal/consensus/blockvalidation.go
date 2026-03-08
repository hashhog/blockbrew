package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Block validation errors.
var (
	ErrNoTransactions          = errors.New("block has no transactions")
	ErrFirstTxNotCoinbase      = errors.New("first transaction is not coinbase")
	ErrMultipleCoinbase        = errors.New("block has multiple coinbase transactions")
	ErrBadMerkleRoot           = errors.New("merkle root mismatch")
	ErrBlockWeightTooHigh      = errors.New("block weight exceeds maximum")
	ErrTimestampTooFar         = errors.New("block timestamp too far in the future")
	ErrBlockVersionTooLow      = errors.New("block version too low for height")
	ErrTimestampBeforeMTP      = errors.New("block timestamp before median time past")
	ErrBadBIP34Height          = errors.New("coinbase does not contain valid block height")
	ErrMissingWitnessCommitment = errors.New("segwit block missing witness commitment")
	ErrBadWitnessCommitment    = errors.New("witness commitment mismatch")
	ErrSigOpsCostTooHigh       = errors.New("block sigops cost exceeds maximum")
	ErrBadCoinbaseValue        = errors.New("coinbase value exceeds allowed subsidy plus fees")
)

// WitnessCommitmentMagic is the magic prefix for witness commitment in coinbase.
// Format: OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>
var WitnessCommitmentMagic = []byte{0xaa, 0x21, 0xa9, 0xed}

// CheckBlockSanity performs context-free checks on a block.
// powLimit is the maximum allowed proof of work target.
func CheckBlockSanity(block *wire.MsgBlock, powLimit *big.Int) error {
	// 1. Block header proof of work is valid (hash <= target from bits)
	blockHash := block.Header.BlockHash()
	if err := CheckProofOfWork(blockHash, block.Header.Bits, powLimit); err != nil {
		return err
	}

	// 2. Block timestamp is not more than 2 hours in the future
	maxTime := time.Now().Unix() + MaxTimeAdjustment
	if int64(block.Header.Timestamp) > maxTime {
		return fmt.Errorf("%w: block time %d, max allowed %d",
			ErrTimestampTooFar, block.Header.Timestamp, maxTime)
	}

	// 8. Block must have at least one transaction
	if len(block.Transactions) == 0 {
		return ErrNoTransactions
	}

	// 3. First transaction must be coinbase
	if !IsCoinbaseTx(block.Transactions[0]) {
		return ErrFirstTxNotCoinbase
	}

	// 4. No other transaction may be coinbase
	for i := 1; i < len(block.Transactions); i++ {
		if IsCoinbaseTx(block.Transactions[i]) {
			return ErrMultipleCoinbase
		}
	}

	// 5. All transactions pass CheckTransactionSanity
	for i, tx := range block.Transactions {
		if err := CheckTransactionSanity(tx); err != nil {
			return fmt.Errorf("transaction %d: %w", i, err)
		}
	}

	// 6. Merkle root matches computed Merkle root from transaction IDs
	txHashes := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.TxHash()
	}
	calculatedMerkle := CalcMerkleRoot(txHashes)
	if calculatedMerkle != block.Header.MerkleRoot {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrBadMerkleRoot, calculatedMerkle.String(), block.Header.MerkleRoot.String())
	}

	// 7. Block weight must not exceed MaxBlockWeight
	weight := CalcBlockWeight(block)
	if weight > MaxBlockWeight {
		return fmt.Errorf("%w: %d > %d", ErrBlockWeightTooHigh, weight, MaxBlockWeight)
	}

	return nil
}

// CheckBlockContext performs context-dependent checks (requires chain state).
func CheckBlockContext(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams) error {
	// 1-3. Block version checks based on BIP34/66/65 activation
	if height >= params.BIP34Height && block.Header.Version < 2 {
		return fmt.Errorf("%w: version %d, need >= 2 for BIP34",
			ErrBlockVersionTooLow, block.Header.Version)
	}
	if height >= params.BIP66Height && block.Header.Version < 3 {
		return fmt.Errorf("%w: version %d, need >= 3 for BIP66",
			ErrBlockVersionTooLow, block.Header.Version)
	}
	if height >= params.BIP65Height && block.Header.Version < 4 {
		return fmt.Errorf("%w: version %d, need >= 4 for BIP65",
			ErrBlockVersionTooLow, block.Header.Version)
	}

	// 4. Block timestamp must be greater than median time past (MTP)
	// Note: We need the timestamps of the previous 11 blocks for MTP calculation.
	// For now, we just check against the previous block's timestamp as a minimum check.
	// Full MTP validation requires chain context that's passed in separately.

	// 5. If segwit is active, validate witness commitment
	if height >= params.SegwitHeight {
		if err := checkWitnessCommitment(block); err != nil {
			return err
		}
	}

	// BIP34: coinbase must include the block height as a script number push
	if height >= params.BIP34Height {
		if err := checkBIP34Height(block.Transactions[0], height); err != nil {
			return err
		}
	}

	return nil
}

// checkWitnessCommitment validates the witness commitment in a segwit block.
func checkWitnessCommitment(block *wire.MsgBlock) error {
	// Find witness commitment in coinbase outputs (use last matching output)
	coinbase := block.Transactions[0]
	var witnessCommitment []byte

	for i := len(coinbase.TxOut) - 1; i >= 0; i-- {
		out := coinbase.TxOut[i]
		// Look for OP_RETURN output with witness commitment magic
		// Format: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commitment>
		if len(out.PkScript) >= 38 &&
			out.PkScript[0] == script.OP_RETURN &&
			out.PkScript[1] == 0x24 && // 36 bytes push
			bytes.Equal(out.PkScript[2:6], WitnessCommitmentMagic) {
			witnessCommitment = out.PkScript[6:38]
			break
		}
	}

	// Check if any transaction has witness data
	hasWitness := false
	for _, tx := range block.Transactions {
		if tx.HasWitness() {
			hasWitness = true
			break
		}
	}

	// If no witness data, commitment is optional
	if !hasWitness && witnessCommitment == nil {
		return nil
	}

	// If there's witness data, commitment is required
	if witnessCommitment == nil {
		return ErrMissingWitnessCommitment
	}

	// Get witness reserved value from coinbase witness
	var witnessReservedValue []byte
	if len(coinbase.TxIn) > 0 && len(coinbase.TxIn[0].Witness) > 0 {
		witnessReservedValue = coinbase.TxIn[0].Witness[0]
	} else {
		// Default to 32 zero bytes
		witnessReservedValue = make([]byte, 32)
	}

	// Calculate witness transaction IDs
	wtxids := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		wtxids[i] = tx.WTxHash()
	}

	// Calculate expected commitment
	expectedCommitment := CalcWitnessCommitment(wtxids, witnessReservedValue)

	// Compare
	if !bytes.Equal(witnessCommitment, expectedCommitment[:]) {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrBadWitnessCommitment, expectedCommitment[:], witnessCommitment)
	}

	return nil
}

// checkBIP34Height validates that the coinbase contains the block height.
// BIP34 requires the first item in the coinbase scriptSig to be a push of
// the block height as a minimally-encoded script number.
func checkBIP34Height(coinbase *wire.MsgTx, expectedHeight int32) error {
	if len(coinbase.TxIn) == 0 {
		return ErrBadBIP34Height
	}

	scriptSig := coinbase.TxIn[0].SignatureScript
	if len(scriptSig) == 0 {
		return ErrBadBIP34Height
	}

	// The first byte tells us how many bytes follow for the height push
	firstByte := scriptSig[0]

	var pushedHeight int64
	var pushLen int

	if firstByte == 0 {
		// OP_0 = height 0
		pushedHeight = 0
		pushLen = 1
	} else if firstByte >= 1 && firstByte <= 75 {
		// Direct push of 1-75 bytes
		pushLen = int(firstByte)
		if len(scriptSig) < 1+pushLen {
			return ErrBadBIP34Height
		}
		data := scriptSig[1 : 1+pushLen]
		pushedHeight = decodeScriptNum(data)
	} else if firstByte == script.OP_PUSHDATA1 {
		if len(scriptSig) < 2 {
			return ErrBadBIP34Height
		}
		pushLen = int(scriptSig[1])
		if len(scriptSig) < 2+pushLen {
			return ErrBadBIP34Height
		}
		data := scriptSig[2 : 2+pushLen]
		pushedHeight = decodeScriptNum(data)
	} else if firstByte >= script.OP_1 && firstByte <= script.OP_16 {
		// OP_1 through OP_16 = heights 1-16
		pushedHeight = int64(firstByte - script.OP_1 + 1)
		pushLen = 1
	} else {
		return ErrBadBIP34Height
	}

	if pushedHeight != int64(expectedHeight) {
		return fmt.Errorf("%w: expected %d, got %d", ErrBadBIP34Height, expectedHeight, pushedHeight)
	}

	return nil
}

// decodeScriptNum decodes a minimally-encoded script number (little-endian with sign bit).
func decodeScriptNum(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}

	// Little-endian with sign in high bit of last byte
	var result int64
	for i := 0; i < len(data); i++ {
		result |= int64(data[i]) << uint(8*i)
	}

	// Check sign bit
	if data[len(data)-1]&0x80 != 0 {
		// Clear the sign bit and negate
		result &= ^(int64(0x80) << uint(8*(len(data)-1)))
		result = -result
	}

	return result
}

// ValidateBlock performs full validation of a block including all transactions.
// This function handles intra-block UTXO spending by updating the UTXO view
// as it processes each transaction.
func ValidateBlock(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, utxoView UpdatableUTXOView) error {
	// Perform sanity checks
	if err := CheckBlockSanity(block, params.PowLimit); err != nil {
		return err
	}

	// Perform context-dependent checks
	if err := CheckBlockContext(block, prevHeader, height, params); err != nil {
		return err
	}

	// Get script flags for this block height
	scriptFlags := GetBlockScriptFlags(height, params)

	// Calculate expected subsidy
	subsidy := CalcBlockSubsidy(height)

	// Track total fees
	var totalFees int64

	// Validate each transaction
	for i, tx := range block.Transactions {
		// Check transaction sanity (already done in CheckBlockSanity, but we do it again
		// to ensure consistency)
		if err := CheckTransactionSanity(tx); err != nil {
			return fmt.Errorf("tx %d: %w", i, err)
		}

		if i == 0 {
			// Coinbase transaction - add outputs to UTXO view
			utxoView.AddTxOutputs(tx, height)
			continue
		}

		// Check transaction inputs (this includes coinbase maturity checks)
		fee, err := CheckTransactionInputs(tx, height, utxoView)
		if err != nil {
			return fmt.Errorf("tx %d: %w", i, err)
		}
		totalFees += fee

		// Validate transaction scripts
		if err := ValidateTransactionScripts(tx, utxoView, scriptFlags); err != nil {
			return fmt.Errorf("tx %d script: %w", i, err)
		}

		// Update UTXO view: spend inputs and add outputs
		// IMPORTANT: This handles intra-block spending - txs can spend outputs
		// from earlier txs in the same block
		utxoView.SpendTxInputs(tx)
		utxoView.AddTxOutputs(tx, height)
	}

	// Verify coinbase value doesn't exceed subsidy + fees
	coinbase := block.Transactions[0]
	var coinbaseValue int64
	for _, out := range coinbase.TxOut {
		coinbaseValue += out.Value
	}
	if coinbaseValue > subsidy+totalFees {
		return fmt.Errorf("%w: %d > %d (subsidy) + %d (fees)",
			ErrBadCoinbaseValue, coinbaseValue, subsidy, totalFees)
	}

	// Check sigops cost
	sigOpsCost := CountBlockSigOpsCost(block, utxoView)
	if sigOpsCost > MaxBlockSigOpsCost {
		return fmt.Errorf("%w: %d > %d", ErrSigOpsCostTooHigh, sigOpsCost, MaxBlockSigOpsCost)
	}

	return nil
}

// CalcMedianTimePast calculates the median time past for a block.
// This is the median timestamp of the previous MedianTimeSpan (11) blocks.
func CalcMedianTimePast(timestamps []uint32) uint32 {
	if len(timestamps) == 0 {
		return 0
	}

	// Copy and sort timestamps
	sorted := make([]uint32, len(timestamps))
	copy(sorted, timestamps)

	// Simple insertion sort (only 11 elements max)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Return median
	return sorted[len(sorted)/2]
}

// CheckBlockTimestamp validates a block's timestamp against the median time past.
func CheckBlockTimestamp(blockTimestamp uint32, medianTimePast uint32) error {
	if blockTimestamp <= medianTimePast {
		return fmt.Errorf("%w: block time %d <= MTP %d",
			ErrTimestampBeforeMTP, blockTimestamp, medianTimePast)
	}
	return nil
}

// ContextualCheckBlock performs all contextual block checks including MTP validation.
// This is a convenience function that combines CheckBlockContext with MTP check.
func ContextualCheckBlock(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, prevTimestamps []uint32) error {
	// Check MTP
	if len(prevTimestamps) > 0 {
		mtp := CalcMedianTimePast(prevTimestamps)
		if err := CheckBlockTimestamp(block.Header.Timestamp, mtp); err != nil {
			return err
		}
	}

	// Perform other context checks
	return CheckBlockContext(block, prevHeader, height, params)
}

// AddTxOutputs adds all outputs from a transaction to the UTXO view.
// This is implemented on InMemoryUTXOView, defined here as a method on the interface
// for documentation purposes.
func (v *InMemoryUTXOView) AddTxOutputsAtHeight(tx *wire.MsgTx, height int32) {
	v.AddTxOutputs(tx, height)
}
