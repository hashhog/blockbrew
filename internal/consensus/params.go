package consensus

// Consensus constants for Bitcoin.
const (
	// MaxBlockSize is the maximum size of a legacy block in bytes.
	MaxBlockSize = 1_000_000

	// MaxBlockWeight is the maximum weight of a block (BIP141).
	MaxBlockWeight = 4_000_000

	// WitnessScaleFactor is the ratio of non-witness to witness bytes.
	WitnessScaleFactor = 4

	// MaxBlockSigOpsCost is the maximum sigops cost allowed in a block.
	MaxBlockSigOpsCost = 80_000

	// CoinbaseMaturity is the number of blocks before coinbase outputs are spendable.
	CoinbaseMaturity = 100

	// MaxMoney is the maximum number of satoshis (21 million BTC).
	MaxMoney int64 = 21_000_000 * 100_000_000

	// SatoshiPerBitcoin is the number of satoshis in one bitcoin.
	SatoshiPerBitcoin int64 = 100_000_000

	// SubsidyHalvingInterval is the number of blocks between subsidy halvings.
	SubsidyHalvingInterval = 210_000

	// InitialSubsidy is the initial block subsidy in satoshis (50 BTC).
	InitialSubsidy int64 = 50 * SatoshiPerBitcoin

	// DifficultyAdjustmentInterval is the number of blocks between difficulty adjustments.
	DifficultyAdjustmentInterval = 2016

	// TargetTimespan is the desired timespan for DifficultyAdjustmentInterval blocks (2 weeks).
	TargetTimespan int64 = 14 * 24 * 60 * 60 // 1,209,600 seconds

	// TargetSpacing is the desired time between blocks (10 minutes).
	TargetSpacing int64 = 10 * 60 // 600 seconds

	// MaxTimeAdjustment is the maximum time a block timestamp can be ahead of the median.
	MaxTimeAdjustment = 2 * 60 * 60 // 7200 seconds (2 hours into the future)

	// MedianTimeSpan is the number of blocks used for median time calculation.
	MedianTimeSpan = 11

	// MaxScriptSize is the maximum size of a script in bytes.
	MaxScriptSize = 10_000

	// MaxScriptElementSize is the maximum size of a push in a script.
	MaxScriptElementSize = 520

	// MaxPubKeysPerMultisig is the maximum number of public keys in a multisig.
	MaxPubKeysPerMultisig = 20

	// MaxOpsPerScript is the maximum number of opcodes in a script.
	MaxOpsPerScript = 201

	// LockTimeThreshold is the threshold for interpreting lock time as a timestamp vs block height.
	LockTimeThreshold uint32 = 500_000_000

	// SequenceLockTimeDisabledFlag indicates sequence lock is disabled.
	SequenceLockTimeDisabledFlag uint32 = 1 << 31

	// SequenceLockTimeMask is the mask for the relative lock time value.
	SequenceLockTimeMask uint32 = 0x0000ffff

	// SequenceLockTimeTypeFlag indicates time-based (vs height-based) relative lock.
	SequenceLockTimeTypeFlag uint32 = 1 << 22

	// SequenceLockTimeGranularity is the granularity of time-based relative locks (512 seconds).
	SequenceLockTimeGranularity = 9

	// MaxBlockHeaderPayload is the maximum block header payload (80 bytes).
	MaxBlockHeaderPayload = 80

	// MaxTransactionWeight is the maximum transaction weight (400,000 WU).
	MaxTransactionWeight = MaxBlockWeight / 10

	// MinTransactionSize is the minimum transaction size (60 bytes for a non-witness tx).
	MinTransactionSize = 60

	// MaxStandardTxWeight is the max weight of a "standard" transaction (400,000 WU).
	MaxStandardTxWeight = 400_000

	// MaxStandardTxSigOpsCost is the maximum sigops cost for a standard (relay/mine)
	// transaction. Transactions exceeding this are rejected as non-standard.
	// Core: policy/policy.h:44  MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5.
	MaxStandardTxSigOpsCost int64 = MaxBlockSigOpsCost / 5 // = 16_000

	// MaxP2SHSigOpsPerInput is the maximum number of sigops a P2SH redeemScript
	// may contain for a single input to be considered standard.
	// Core: policy/policy.h:42  MAX_P2SH_SIGOPS = 15.
	MaxP2SHSigOpsPerInput = 15

	// MaxTxLegacySigOps is the maximum number of non-witness (legacy) sigops
	// allowed across an entire standard transaction (BIP-54 gate).
	// Core: policy/policy.h:46  MAX_TX_LEGACY_SIGOPS = 2_500.
	MaxTxLegacySigOps = 2_500

	// DustRelayFeeRate is the fee rate below which outputs are considered dust (3000 sat/kvB).
	DustRelayFeeRate int64 = 3000

	// MinRelayTxFee is the minimum relay fee rate in satoshis per kvB.
	MinRelayTxFee int64 = 1000
)

// BIP9 deployment bit positions.
const (
	DeploymentCSV     = 0
	DeploymentSegwit  = 1
	DeploymentTaproot = 2
)
