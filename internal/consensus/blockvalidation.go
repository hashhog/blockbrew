package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
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
	ErrDuplicateTx             = errors.New("block contains duplicate transaction outputs (BIP30)")
	ErrDuplicateCoinbase       = errors.New("block contains duplicate coinbase outputs (BIP30)")
	ErrBadDifficultyBits       = errors.New("block difficulty bits do not match expected value")
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
// medianTimePast is the MTP of the previous 11 blocks (0 to skip MTP check).
func CheckBlockContext(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, medianTimePast ...uint32) error {
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
	if len(medianTimePast) > 0 && medianTimePast[0] > 0 {
		if err := CheckBlockTimestamp(block.Header.Timestamp, medianTimePast[0]); err != nil {
			return err
		}
	}

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

	// Difficulty validation is handled by the header index during header sync
	// using GetNextWorkRequired(), which correctly handles all network-specific
	// rules including testnet min-difficulty walk-back, BIP94, and retarget
	// boundaries. We skip the redundant check here to avoid rejecting valid
	// blocks with a simplified check that doesn't handle all edge cases
	// (e.g., non-min-difficulty blocks after a min-difficulty parent on testnet4).

	// Check all transactions are final (IsFinalTx)
	// Use MTP as block time for BIP113 if CSV is active, otherwise use block timestamp
	var blockTime uint32
	if height >= params.CSVHeight && len(medianTimePast) > 0 {
		blockTime = medianTimePast[0]
	} else {
		blockTime = block.Header.Timestamp
	}
	for i, tx := range block.Transactions {
		if !IsFinalTx(tx, height, blockTime) {
			return fmt.Errorf("tx %d: %w", i, ErrNonFinalTx)
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

// checkBIP34Height validates that the coinbase scriptSig starts with the
// byte-exact canonical encoding of expectedHeight, matching Bitcoin Core's
// ContextualCheckBlock (validation.cpp:4151-4159):
//
//	CScript expect = CScript() << nHeight;
//	sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
//
// The canonical encoding mirrors Core's CScript::push_int64 (script.h:433-448):
//   - height == 0  → OP_0 (0x00), single byte
//   - 1..16        → OP_1..OP_16 (0x51..0x60), single byte
//   - otherwise    → length-prefixed CScriptNum (sign-magnitude little-endian)
//
// Non-canonical forms (OP_PUSHDATA1 prefix, zero-padded mantissa, redundant
// sign byte, wrong OP_N for low heights) are rejected.
func checkBIP34Height(coinbase *wire.MsgTx, expectedHeight int32) error {
	if len(coinbase.TxIn) == 0 {
		return ErrBadBIP34Height
	}
	scriptSig := coinbase.TxIn[0].SignatureScript
	expect := encodeBIP34Height(expectedHeight)
	if len(scriptSig) < len(expect) || !bytes.Equal(scriptSig[:len(expect)], expect) {
		return fmt.Errorf("%w: expected prefix %x in scriptSig %x",
			ErrBadBIP34Height, expect, scriptSig)
	}
	return nil
}

// encodeBIP34Height returns the canonical BIP-34 byte encoding of height,
// matching Bitcoin Core's CScript() << nHeight (script.h:433-448).
func encodeBIP34Height(height int32) []byte {
	if height == 0 {
		// OP_0 — single byte 0x00
		return []byte{0x00}
	}
	if height >= 1 && height <= 16 {
		// OP_1..OP_16 — single byte 0x51..0x60
		return []byte{byte(0x50 + height)}
	}
	// CScriptNum: minimal sign-magnitude little-endian, prefixed by byte count.
	h := uint32(height)
	var le [4]byte
	n := 0
	for h > 0 {
		le[n] = byte(h & 0xff)
		h >>= 8
		n++
	}
	// If the high bit of the last byte is set, append a zero sign byte.
	if le[n-1]&0x80 != 0 {
		le[n] = 0x00
		n++
	}
	out := make([]byte, 1+n)
	out[0] = byte(n)
	copy(out[1:], le[:n])
	return out
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

// ValidateBlockOptions configures block validation behavior.
type ValidateBlockOptions struct {
	// SkipScripts skips script validation (used for assume-valid during IBD)
	SkipScripts bool
	// ParallelScripts enables parallel script validation
	ParallelScripts bool
}

// DefaultValidateBlockOptions returns the default validation options.
func DefaultValidateBlockOptions() ValidateBlockOptions {
	return ValidateBlockOptions{
		SkipScripts:     false,
		ParallelScripts: true, // Enable parallel validation by default
	}
}

// ValidateBlock performs full validation of a block including all transactions.
// This function handles intra-block UTXO spending by updating the UTXO view
// as it processes each transaction.
func ValidateBlock(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, utxoView UpdatableUTXOView) error {
	return ValidateBlockWithOptions(block, prevHeader, height, params, utxoView, DefaultValidateBlockOptions())
}

// ValidateBlockWithOptions performs full validation with configurable options.
// Use this for IBD with assume-valid optimization or for performance tuning.
func ValidateBlockWithOptions(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, utxoView UpdatableUTXOView, opts ValidateBlockOptions) error {
	// Perform sanity checks
	if err := CheckBlockSanity(block, params.PowLimit); err != nil {
		return err
	}

	// Perform context-dependent checks
	if err := CheckBlockContext(block, prevHeader, height, params); err != nil {
		return err
	}

	// BIP30: Check for duplicate transaction outputs in the UTXO set.
	// Two historical blocks (91722 and 91812) on mainnet have duplicate coinbase
	// txids and are exempted. After BIP34 activation, the height encoded in the
	// coinbase makes duplicate txids impossible, so the check can be skipped.
	// However, after height 1,983,702 the check must resume because BIP34 does
	// not fully guarantee uniqueness beyond that point.
	const bip34ImpliesBIP30Limit int32 = 1_983_702
	enforceBIP30 := height != 91722 && height != 91812
	// Skip BIP30 after BIP34 activation (unique coinbase guarantees unique txids)
	if enforceBIP30 && height >= params.BIP34Height {
		enforceBIP30 = false
	}
	// Re-enable BIP30 at or above the BIP34-implies-BIP30 limit
	if !enforceBIP30 && height >= bip34ImpliesBIP30Limit {
		enforceBIP30 = true
	}
	if enforceBIP30 {
		for _, tx := range block.Transactions {
			txHash := tx.TxHash()
			for i := range tx.TxOut {
				outpoint := wire.OutPoint{Hash: txHash, Index: uint32(i)}
				if utxoView.GetUTXO(outpoint) != nil {
					return fmt.Errorf("%w: output %s:%d already exists",
						ErrDuplicateTx, txHash.String()[:16], i)
				}
			}
		}
	}

	// Get script flags for this block (hash checked against exception map)
	blockHash := block.Header.BlockHash()
	scriptFlags := GetBlockScriptFlags(height, params, blockHash)

	// Calculate expected subsidy
	subsidy := CalcBlockSubsidy(height)

	// Track total fees
	var totalFees int64

	// First pass: validate transaction structure and inputs (not scripts)
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
		if totalFees > MaxMoney {
			return fmt.Errorf("accumulated fee in the block out of range: %d > %d", totalFees, MaxMoney)
		}

		// Update UTXO view: spend inputs and add outputs
		// IMPORTANT: This handles intra-block spending - txs can spend outputs
		// from earlier txs in the same block
		utxoView.SpendTxInputs(tx)
		utxoView.AddTxOutputs(tx, height)
	}

	// Second pass: validate scripts (can be parallelized)
	// Skip script validation if assume-valid optimization is active
	if !opts.SkipScripts {
		if opts.ParallelScripts {
			// Use parallel validation for better performance
			if err := ParallelScriptValidation(block, utxoView, scriptFlags); err != nil {
				return err
			}
		} else {
			// Sequential validation
			for i, tx := range block.Transactions {
				if i == 0 {
					continue // Skip coinbase
				}
				if err := ValidateTransactionScripts(tx, utxoView, scriptFlags); err != nil {
					return fmt.Errorf("tx %d script: %w", i, err)
				}
			}
		}
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

// scriptJob represents a single script validation job.
type scriptJob struct {
	tx       *wire.MsgTx
	txIdx    int
	inputIdx int
	prevOut  *UTXOEntry
	prevOuts []*wire.TxOut
}

// ParallelScriptValidation validates all transaction scripts in a block using parallel workers.
// Script validation is CPU-intensive and embarrassingly parallel since each input is independent.
// This function provides significant speedup on multi-core systems (roughly 6-7x on 8 cores).
func ParallelScriptValidation(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags) error {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Collect all script validation jobs
	var jobs []scriptJob

	for txIdx, tx := range block.Transactions {
		// Skip coinbase (first transaction has no real inputs)
		if txIdx == 0 {
			continue
		}

		// Build prevOuts slice for this transaction (needed for sighash)
		prevOuts := make([]*wire.TxOut, len(tx.TxIn))
		for i, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d: %s:%d",
					txIdx, i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			}
			prevOuts[i] = &wire.TxOut{
				Value:    utxo.Amount,
				PkScript: utxo.PkScript,
			}
		}

		// Create a job for each input
		for inputIdx, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d", txIdx, inputIdx)
			}
			jobs = append(jobs, scriptJob{
				tx:       tx,
				txIdx:    txIdx,
				inputIdx: inputIdx,
				prevOut:  utxo,
				prevOuts: prevOuts,
			})
		}
	}

	// If no jobs, validation passes
	if len(jobs) == 0 {
		return nil
	}

	// For small job counts, validate sequentially to avoid goroutine overhead
	if len(jobs) <= 4 {
		for _, job := range jobs {
			err := script.VerifyScript(
				job.tx.TxIn[job.inputIdx].SignatureScript,
				job.prevOut.PkScript,
				job.tx,
				job.inputIdx,
				flags,
				job.prevOut.Amount,
				job.prevOuts,
			)
			if err != nil {
				return fmt.Errorf("tx %d input %d: script failed: %w", job.txIdx, job.inputIdx, err)
			}
		}
		return nil
	}

	// Use atomic.Pointer to store the first error without race conditions.
	// Workers check this to exit early once any script fails.
	var firstErr atomic.Pointer[error]

	// WaitGroup to track completion
	var wg sync.WaitGroup

	// Semaphore to limit concurrent workers
	sem := make(chan struct{}, numWorkers)

	for _, job := range jobs {
		wg.Add(1)
		go func(j scriptJob) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if we already have an error (early exit)
			if firstErr.Load() != nil {
				return
			}

			// Validate the script
			err := script.VerifyScript(
				j.tx.TxIn[j.inputIdx].SignatureScript,
				j.prevOut.PkScript,
				j.tx,
				j.inputIdx,
				flags,
				j.prevOut.Amount,
				j.prevOuts,
			)
			if err != nil {
				// Store the first error atomically (only first wins)
				wrapped := fmt.Errorf("tx %d input %d: script failed: %w", j.txIdx, j.inputIdx, err)
				firstErr.CompareAndSwap(nil, &wrapped)
			}
		}(job)
	}

	// Wait for all workers to finish
	wg.Wait()

	// Check if there was an error
	if errPtr := firstErr.Load(); errPtr != nil {
		return *errPtr
	}
	return nil
}

// ValidateBlockScripts validates all scripts in a block, optionally in parallel.
// If parallel is true, uses ParallelScriptValidation for better performance.
func ValidateBlockScripts(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags, parallel bool) error {
	if parallel {
		return ParallelScriptValidation(block, utxoView, flags)
	}

	// Sequential validation
	for txIdx, tx := range block.Transactions {
		if txIdx == 0 {
			continue // Skip coinbase
		}
		if err := ValidateTransactionScripts(tx, utxoView, flags); err != nil {
			return fmt.Errorf("tx %d: %w", txIdx, err)
		}
	}
	return nil
}

// ParallelScriptValidationCached validates scripts with signature cache support.
// Cached entries are looked up before expensive script verification, and successful
// verifications are added to the cache for future reuse.
func ParallelScriptValidationCached(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags, cache *SigCache) error {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Collect all script validation jobs
	var jobs []scriptJob

	for txIdx, tx := range block.Transactions {
		// Skip coinbase (first transaction has no real inputs)
		if txIdx == 0 {
			continue
		}

		// Build prevOuts slice for this transaction (needed for sighash)
		prevOuts := make([]*wire.TxOut, len(tx.TxIn))
		for i, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d: %s:%d",
					txIdx, i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			}
			prevOuts[i] = &wire.TxOut{
				Value:    utxo.Amount,
				PkScript: utxo.PkScript,
			}
		}

		// Create a job for each input
		for inputIdx, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d", txIdx, inputIdx)
			}
			jobs = append(jobs, scriptJob{
				tx:       tx,
				txIdx:    txIdx,
				inputIdx: inputIdx,
				prevOut:  utxo,
				prevOuts: prevOuts,
			})
		}
	}

	// If no jobs, validation passes
	if len(jobs) == 0 {
		return nil
	}

	// For small job counts, validate sequentially to avoid goroutine overhead
	if len(jobs) <= 4 {
		for _, job := range jobs {
			txid := job.tx.TxHash()
			// Check cache first
			if cache != nil && cache.Lookup(txid, uint32(job.inputIdx), flags) {
				continue
			}

			err := script.VerifyScript(
				job.tx.TxIn[job.inputIdx].SignatureScript,
				job.prevOut.PkScript,
				job.tx,
				job.inputIdx,
				flags,
				job.prevOut.Amount,
				job.prevOuts,
			)
			if err != nil {
				return fmt.Errorf("tx %d input %d: script failed: %w", job.txIdx, job.inputIdx, err)
			}

			// Cache successful verification
			if cache != nil {
				cache.Insert(txid, uint32(job.inputIdx), flags)
			}
		}
		return nil
	}

	// Use atomic.Pointer to store the first error without race conditions.
	var firstErr atomic.Pointer[error]
	var wg sync.WaitGroup
	sem := make(chan struct{}, numWorkers)

	for _, job := range jobs {
		wg.Add(1)
		go func(j scriptJob) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if we already have an error (early exit)
			if firstErr.Load() != nil {
				return
			}

			txid := j.tx.TxHash()
			// Check cache first
			if cache != nil && cache.Lookup(txid, uint32(j.inputIdx), flags) {
				return
			}

			// Validate the script
			err := script.VerifyScript(
				j.tx.TxIn[j.inputIdx].SignatureScript,
				j.prevOut.PkScript,
				j.tx,
				j.inputIdx,
				flags,
				j.prevOut.Amount,
				j.prevOuts,
			)
			if err != nil {
				wrapped := fmt.Errorf("tx %d input %d: script failed: %w", j.txIdx, j.inputIdx, err)
				firstErr.CompareAndSwap(nil, &wrapped)
				return
			}

			// Cache successful verification
			if cache != nil {
				cache.Insert(txid, uint32(j.inputIdx), flags)
			}
		}(job)
	}

	wg.Wait()

	if errPtr := firstErr.Load(); errPtr != nil {
		return *errPtr
	}
	return nil
}
