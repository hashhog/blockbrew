package consensus

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Transaction validation errors.
var (
	ErrNoInputs              = errors.New("transaction has no inputs")
	ErrNoOutputs             = errors.New("transaction has no outputs")
	ErrOversizedTx           = errors.New("transaction exceeds maximum weight")
	ErrNegativeOutput        = errors.New("transaction output value is negative")
	ErrOutputTooLarge        = errors.New("transaction output value exceeds max money")
	ErrTotalOutputTooLarge   = errors.New("total transaction output exceeds max money")
	ErrDuplicateInput        = errors.New("transaction contains duplicate inputs")
	ErrCoinbaseScriptSize    = errors.New("coinbase script size out of range")
	ErrNullInput             = errors.New("non-coinbase transaction has null input")
	ErrOutputScriptTooLarge  = errors.New("output script exceeds maximum size")
	ErrMissingInput          = errors.New("transaction input references missing UTXO")
	ErrImmatureCoinbase      = errors.New("coinbase output is immature")
	ErrInputTooLarge         = errors.New("transaction input value exceeds max money")
	ErrTotalInputTooLarge    = errors.New("total transaction input exceeds max money")
	ErrInsufficientFunds     = errors.New("transaction inputs less than outputs")
	ErrNonFinalTx            = errors.New("transaction is not final")
	ErrSequenceLockNotMet    = errors.New("sequence lock requirements not met")
)

// UTXOView provides access to unspent transaction outputs.
type UTXOView interface {
	// GetUTXO returns the UTXO for an outpoint, or nil if not found / already spent.
	GetUTXO(outpoint wire.OutPoint) *UTXOEntry
}

// UTXOEntry represents an unspent transaction output.
type UTXOEntry struct {
	Amount     int64
	PkScript   []byte
	Height     int32 // Height of the block that created this UTXO
	IsCoinbase bool
}

// IsCoinbaseTx returns true if the transaction is a coinbase transaction.
// A coinbase transaction has exactly one input with a null previous outpoint
// (all zeros hash and index 0xFFFFFFFF).
func IsCoinbaseTx(tx *wire.MsgTx) bool {
	if len(tx.TxIn) != 1 {
		return false
	}
	prevOut := tx.TxIn[0].PreviousOutPoint
	return prevOut.Hash.IsZero() && prevOut.Index == 0xFFFFFFFF
}

// CheckTransactionSanity performs context-free checks on a transaction.
func CheckTransactionSanity(tx *wire.MsgTx) error {
	// 1. Transaction must have at least one input and one output
	if len(tx.TxIn) == 0 {
		return ErrNoInputs
	}
	if len(tx.TxOut) == 0 {
		return ErrNoOutputs
	}

	// 2. Transaction serialized size must not exceed MaxBlockWeight
	weight := CalcTxWeight(tx)
	if weight > MaxBlockWeight {
		return ErrOversizedTx
	}

	// 3. Each output value must be non-negative and not exceed MaxMoney
	var totalOutput int64
	for _, out := range tx.TxOut {
		if out.Value < 0 {
			return ErrNegativeOutput
		}
		if out.Value > MaxMoney {
			return ErrOutputTooLarge
		}
		totalOutput += out.Value
		// 4. Sum of all output values must not exceed MaxMoney
		if totalOutput > MaxMoney {
			return ErrTotalOutputTooLarge
		}
	}

	// 5. No duplicate inputs (same outpoint referenced twice)
	seen := make(map[wire.OutPoint]struct{})
	for _, in := range tx.TxIn {
		if _, exists := seen[in.PreviousOutPoint]; exists {
			return ErrDuplicateInput
		}
		seen[in.PreviousOutPoint] = struct{}{}
	}

	// 6. Coinbase-specific checks
	if IsCoinbaseTx(tx) {
		// Coinbase scriptSig length must be between 2 and 100 bytes
		scriptLen := len(tx.TxIn[0].SignatureScript)
		if scriptLen < 2 || scriptLen > 100 {
			return ErrCoinbaseScriptSize
		}
	} else {
		// 7. Non-coinbase transactions: no input may reference a null outpoint
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint.Hash.IsZero() && in.PreviousOutPoint.Index == 0xFFFFFFFF {
				return ErrNullInput
			}
		}
	}

	// 8. Output scripts must not exceed MaxScriptSize
	for _, out := range tx.TxOut {
		if len(out.PkScript) > MaxScriptSize {
			return ErrOutputScriptTooLarge
		}
	}

	return nil
}

// CheckTransactionInputs performs context-dependent checks using the UTXO set.
// Returns the transaction fee (inputs - outputs) if successful.
func CheckTransactionInputs(tx *wire.MsgTx, txHeight int32, utxoView UTXOView) (int64, error) {
	// Coinbase transactions have no inputs to validate against UTXO set
	if IsCoinbaseTx(tx) {
		return 0, nil
	}

	var totalInput int64
	for _, in := range tx.TxIn {
		// 1. All inputs must reference existing UTXOs
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			return 0, fmt.Errorf("%w: %s:%d", ErrMissingInput,
				in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		}

		// 2. Coinbase UTXOs must have at least CoinbaseMaturity confirmations
		if utxo.IsCoinbase {
			// Number of confirmations = current height - utxo height
			confirmations := txHeight - utxo.Height
			if confirmations < CoinbaseMaturity {
				return 0, fmt.Errorf("%w: %d confirmations, need %d",
					ErrImmatureCoinbase, confirmations, CoinbaseMaturity)
			}
		}

		// 3. Each input amount must be non-negative and not exceed MaxMoney
		if utxo.Amount < 0 {
			return 0, ErrInputTooLarge
		}
		if utxo.Amount > MaxMoney {
			return 0, ErrInputTooLarge
		}

		totalInput += utxo.Amount

		// 4. Sum of input amounts must not exceed MaxMoney
		if totalInput > MaxMoney {
			return 0, ErrTotalInputTooLarge
		}
	}

	// Calculate total output
	var totalOutput int64
	for _, out := range tx.TxOut {
		totalOutput += out.Value
	}

	// 5. Sum of inputs must be >= sum of outputs
	if totalInput < totalOutput {
		return 0, fmt.Errorf("%w: inputs=%d, outputs=%d",
			ErrInsufficientFunds, totalInput, totalOutput)
	}

	// Return the fee (inputs - outputs)
	return totalInput - totalOutput, nil
}

// UpdatableUTXOView extends UTXOView with modification capabilities.
// This is used for intra-block UTXO tracking during block validation.
type UpdatableUTXOView interface {
	UTXOView
	// AddUTXO adds a UTXO to the view.
	AddUTXO(outpoint wire.OutPoint, entry *UTXOEntry)
	// SpendUTXO removes a UTXO from the view.
	SpendUTXO(outpoint wire.OutPoint)
	// AddTxOutputs adds all outputs from a transaction to the UTXO view.
	AddTxOutputs(tx *wire.MsgTx, height int32)
	// SpendTxInputs removes all inputs of a transaction from the UTXO view.
	SpendTxInputs(tx *wire.MsgTx)
}

// InMemoryUTXOView is a simple in-memory UTXO view for testing and block validation.
type InMemoryUTXOView struct {
	utxos map[wire.OutPoint]*UTXOEntry
}

// NewInMemoryUTXOView creates a new in-memory UTXO view.
func NewInMemoryUTXOView() *InMemoryUTXOView {
	return &InMemoryUTXOView{
		utxos: make(map[wire.OutPoint]*UTXOEntry),
	}
}

// GetUTXO returns the UTXO for an outpoint, or nil if not found.
func (v *InMemoryUTXOView) GetUTXO(outpoint wire.OutPoint) *UTXOEntry {
	return v.utxos[outpoint]
}

// AddUTXO adds a UTXO to the view.
func (v *InMemoryUTXOView) AddUTXO(outpoint wire.OutPoint, entry *UTXOEntry) {
	v.utxos[outpoint] = entry
}

// SpendUTXO removes a UTXO from the view.
func (v *InMemoryUTXOView) SpendUTXO(outpoint wire.OutPoint) {
	delete(v.utxos, outpoint)
}

// IsUnspendable returns true if a script is provably unspendable.
// A script is unspendable if it starts with OP_RETURN (0x6a) or is empty.
func IsUnspendable(pkScript []byte) bool {
	if len(pkScript) == 0 {
		return true
	}
	return pkScript[0] == 0x6a // OP_RETURN
}

// AddTxOutputs adds all outputs from a transaction to the UTXO view.
// Outputs that are provably unspendable (OP_RETURN or empty script) are
// skipped to avoid polluting the UTXO set.
func (v *InMemoryUTXOView) AddTxOutputs(tx *wire.MsgTx, height int32) {
	txHash := tx.TxHash()
	isCoinbase := IsCoinbaseTx(tx)

	for i, out := range tx.TxOut {
		// Skip provably unspendable outputs (OP_RETURN or empty script)
		if IsUnspendable(out.PkScript) {
			continue
		}
		outpoint := wire.OutPoint{
			Hash:  txHash,
			Index: uint32(i),
		}
		v.AddUTXO(outpoint, &UTXOEntry{
			Amount:     out.Value,
			PkScript:   bytes.Clone(out.PkScript),
			Height:     height,
			IsCoinbase: isCoinbase,
		})
	}
}

// IsFinalTx checks if a transaction is final at a given height and time.
// A transaction is final if its locktime is satisfied or all inputs have
// sequence 0xFFFFFFFF. This matches Bitcoin Core's IsFinalTx().
func IsFinalTx(tx *wire.MsgTx, blockHeight int32, blockTime uint32) bool {
	// A locktime of 0 means the transaction is always final.
	if tx.LockTime == 0 {
		return true
	}

	// Determine if locktime is a block height or timestamp.
	var lockTimeLimit int64
	if tx.LockTime < LockTimeThreshold {
		lockTimeLimit = int64(blockHeight)
	} else {
		lockTimeLimit = int64(blockTime)
	}

	if int64(tx.LockTime) < lockTimeLimit {
		return true
	}

	// If all inputs are finalized (sequence == 0xFFFFFFFF), tx is final
	// regardless of locktime.
	for _, in := range tx.TxIn {
		if in.Sequence != 0xFFFFFFFF {
			return false
		}
	}
	return true
}

// SequenceLock represents the minimum block height and time at which a
// transaction can be included in a block (BIP68).
type SequenceLock struct {
	MinHeight int32  // Minimum block height (-1 if no height lock)
	MinTime   int64  // Minimum median time past (-1 if no time lock)
}

// CalculateSequenceLocks computes the sequence locks for a transaction.
// For each input with a relative lock (BIP68), it calculates the minimum
// block height or median time past required.
// prevHeights contains the height of the block that includes each input's UTXO.
// blockHeight is the height of the block being validated.
func CalculateSequenceLocks(tx *wire.MsgTx, prevHeights []int32, medianTimePast int64, blockHeight int32) *SequenceLock {
	lock := &SequenceLock{
		MinHeight: -1,
		MinTime:   -1,
	}

	// BIP68 only applies to version >= 2 transactions.
	if tx.Version < 2 {
		return lock
	}

	for i, in := range tx.TxIn {
		// Skip coinbase inputs
		if in.PreviousOutPoint.Hash.IsZero() && in.PreviousOutPoint.Index == 0xFFFFFFFF {
			continue
		}

		seq := in.Sequence

		// If the disable flag is set, skip this input.
		if seq&SequenceLockTimeDisabledFlag != 0 {
			continue
		}

		if seq&SequenceLockTimeTypeFlag != 0 {
			// Time-based relative lock
			// The locked time is in units of 512 seconds (granularity of 9 bits)
			lockedTime := (int64(seq&SequenceLockTimeMask) << SequenceLockTimeGranularity) - 1
			// Add to the MTP of the block that included the input UTXO
			// We need the MTP at prevHeights[i]-1, but we approximate with
			// medianTimePast which is the MTP of the current block's parent
			minTime := lockedTime + medianTimePast
			if minTime > lock.MinTime {
				lock.MinTime = minTime
			}
		} else {
			// Height-based relative lock
			minHeight := prevHeights[i] + int32(seq&SequenceLockTimeMask) - 1
			if minHeight > lock.MinHeight {
				lock.MinHeight = minHeight
			}
		}
	}

	return lock
}

// EvaluateSequenceLocks checks if a transaction's sequence locks are satisfied.
func EvaluateSequenceLocks(lock *SequenceLock, blockHeight int32, medianTimePast int64) bool {
	if lock.MinHeight >= blockHeight {
		return false
	}
	if lock.MinTime >= medianTimePast {
		return false
	}
	return true
}

// SpendTxInputs removes all inputs of a transaction from the UTXO view.
func (v *InMemoryUTXOView) SpendTxInputs(tx *wire.MsgTx) {
	if IsCoinbaseTx(tx) {
		return // Coinbase has no real inputs to spend
	}
	for _, in := range tx.TxIn {
		v.SpendUTXO(in.PreviousOutPoint)
	}
}
