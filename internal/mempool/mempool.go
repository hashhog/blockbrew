// Package mempool implements the transaction memory pool.
package mempool

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// rollingFeeHalflife is the halflife for the rolling minimum fee rate decay.
// Core: txmempool.h:212 — ROLLING_FEE_HALFLIFE = 60 * 60 * 12 (12 hours).
const rollingFeeHalflife = float64(12 * 60 * 60) // 12 hours in seconds

// DefaultMempoolExpiryHours is the number of hours after which mempool
// transactions are expired. Core: kernel/mempool_options.h:23 —
// DEFAULT_MEMPOOL_EXPIRY_HOURS = 336 (14 days).
const DefaultMempoolExpiryHours = 336

// OrphanTxExpireTime is the maximum age of an orphan transaction before it
// is evicted from the orphan pool.  Matches Bitcoin Core's
// ORPHAN_TX_EXPIRE_TIME in net_processing.cpp / txorphanage.cpp:
//
//	static constexpr auto ORPHAN_TX_EXPIRE_TIME{20min};
//
// Core calls LimitOrphans (which eventually evicts old entries) after every
// AddTx; blockbrew drives ExpireOrphans on a periodic timer instead.
const OrphanTxExpireTime = 20 * time.Minute

// Mempool errors.
var (
	ErrAlreadyInMempool   = errors.New("transaction already in mempool")
	ErrCoinbaseNotAllowed = errors.New("coinbase transactions not allowed in mempool")
	ErrTxTooLarge         = errors.New("transaction exceeds maximum standard weight")
	ErrTxTooSmall         = errors.New("transaction non-witness size below minimum (65 bytes)")
	ErrTxVersion          = errors.New("transaction version out of standard range [1,3]")
	ErrScriptSigTooLarge  = errors.New("scriptsig exceeds maximum standard size (1650 bytes)")
	ErrScriptSigNotPushOnly = errors.New("scriptsig is not push-only")
	ErrDataCarrierTooLarge  = errors.New("total OP_RETURN payload exceeds datacarrier limit")
	ErrDoubleSpend        = errors.New("input already spent by mempool transaction")
	ErrMissingInputs      = errors.New("transaction references missing inputs")
	ErrNegativeFee        = errors.New("transaction fee is negative")
	ErrInsufficientFee    = errors.New("fee rate below minimum relay fee")
	ErrDustOutput         = errors.New("output is dust")
	ErrScriptValidation   = errors.New("script validation failed")
	// IsWitnessStandard gate 1: P2A input with non-empty witness.
	// Core: policy.cpp:283-285, reason "bad-witness-nonstandard".
	ErrWitnessStuffing = errors.New("witness stuffing: P2A input must have empty witness")

	// IsWitnessStandard gate 2: P2SH scriptSig failed to evaluate or produced
	// an empty stack (cannot extract redeemScript).
	ErrWitnessNonstandardP2SHRedeem = errors.New("bad-witness-nonstandard: P2SH scriptSig eval failed or empty stack")

	// IsWitnessStandard gate 3: non-witness prevScript paired with a witness.
	ErrWitnessNonstandardNonWitness = errors.New("bad-witness-nonstandard: witness on non-witness program")

	// IsWitnessStandard gate 4a: P2WSH witness script exceeds 3600 bytes.
	ErrWitnessNonstandardP2WSHScriptSize = errors.New("bad-witness-nonstandard: P2WSH script exceeds 3600 bytes")

	// IsWitnessStandard gate 4b: P2WSH stack depth (excluding script) exceeds 100.
	ErrWitnessNonstandardP2WSHStackDepth = errors.New("bad-witness-nonstandard: P2WSH stack depth exceeds 100 items")

	// IsWitnessStandard gate 4c: P2WSH stack item (excluding script) exceeds 80 bytes.
	ErrWitnessNonstandardP2WSHStackItemSize = errors.New("bad-witness-nonstandard: P2WSH stack item exceeds 80 bytes")

	// IsWitnessStandard gate 5a: taproot annex present (nonstandard).
	ErrWitnessNonstandardTaprootAnnex = errors.New("bad-witness-nonstandard: taproot annex present")

	// IsWitnessStandard gate 5b: taproot script-path empty control block.
	ErrWitnessNonstandardTaprootEmptyControl = errors.New("bad-witness-nonstandard: taproot empty control block")

	// IsWitnessStandard gate 5c: tapscript (leaf 0xc0) stack item exceeds 80 bytes.
	ErrWitnessNonstandardTapscriptStackItemSize = errors.New("bad-witness-nonstandard: tapscript stack item exceeds 80 bytes")

	// IsWitnessStandard gate 5d: taproot spend with empty witness stack.
	ErrWitnessNonstandardTaprootEmptyStack = errors.New("bad-witness-nonstandard: taproot spend with empty witness stack")
	ErrMempoolFull        = errors.New("mempool is full")
	ErrOrphanPoolFull     = errors.New("orphan pool is full")
	ErrRBFNotSignaled     = errors.New("conflicting transaction does not signal RBF")
	ErrRBFInsufficientFee = errors.New("replacement fee too low")
	ErrRBFTooManyConflicts = errors.New("replacement would evict too many transactions")

	// ErrRBFFeerateDiagram is returned when the replacement does not strictly
	// improve the mempool feerate diagram.
	// Mirrors Bitcoin Core rbf.cpp::ImprovesFeerateDiagram (Core 27+,
	// cluster-mempool).
	ErrRBFFeerateDiagram = errors.New("insufficient feerate: does not improve feerate diagram")

	// BIP-68 sequence-lock failure (mempool accept).
	ErrSequenceLockNotMet = errors.New("non-final transaction (BIP-68 sequence locks not met)")

	// IsFinalTx failure (BIP-113 nLockTime gate, mempool accept).
	ErrNonFinalTx = errors.New("non-final transaction (nLockTime not satisfied at tip+1)")

	// Coinbase maturity failure (mempool accept).
	ErrImmatureCoinbaseSpend = errors.New("immature coinbase spend: output does not have enough confirmations")

	// Output script is not a known standard type (Core: "scriptpubkey").
	ErrNonStandardOutput = errors.New("nonstandard output script")

	// ErrTxSigOpsCostTooHigh is returned when GetTransactionSigOpCost exceeds
	// MAX_STANDARD_TX_SIGOPS_COST (16000). Core: validation.cpp:941,
	// reason "bad-txns-too-many-sigops".
	ErrTxSigOpsCostTooHigh = errors.New("transaction sigops cost exceeds maximum standard limit (16000)")

	// ErrP2SHSigOpsTooMany is returned when a single P2SH input's redeemScript
	// contains more than MAX_P2SH_SIGOPS (15) sigops. Core: policy.cpp:255,
	// reason "bad-txns-nonstandard-inputs".
	ErrP2SHSigOpsTooMany = errors.New("P2SH redeemscript sigops exceed per-input limit (15)")

	// ErrTxLegacySigOpsTooMany is returned when the total number of non-witness
	// (legacy) sigops across all inputs exceeds MAX_TX_LEGACY_SIGOPS (2500).
	// Core: policy.cpp:188 (CheckSigopsBIP54), reason "bad-txns-nonstandard-inputs".
	ErrTxLegacySigOpsTooMany = errors.New("non-witness sigops exceed BIP54 limit (2500)")

	// Ancestor/descendant chain limits (Core DEFAULT_ANCESTOR_LIMIT/DEFAULT_DESCENDANT_LIMIT).
	ErrTooManyAncestors   = errors.New("too many unconfirmed ancestors")
	ErrTooManyDescendants = errors.New("too many descendants for an unconfirmed parent")

	// Ancestor/descendant size limits in kvB
	// (Core DEFAULT_ANCESTOR_SIZE_LIMIT_KVB / DEFAULT_DESCENDANT_SIZE_LIMIT_KVB, both 101).
	ErrAncestorSizeTooLarge   = errors.New("exceeds ancestor size limit")
	ErrDescendantSizeTooLarge = errors.New("exceeds descendant size limit")

	// BIP-125 Rule 2 (MempoolFullRBF disabled): replacement must not introduce
	// new unconfirmed inputs that were not already in the original conflicting
	// transactions or their in-mempool ancestors.
	ErrRBFNewUnconfirmedInput = errors.New("replacement adds new unconfirmed input not in conflicts' ancestor set")

	// ErrRBFAncestorConflict is returned when the replacement transaction's
	// in-mempool ancestors overlap with the set of direct conflicts — i.e., the
	// replacement spends an output of a transaction it is trying to replace.
	// Mirrors Bitcoin Core rbf.cpp::EntriesAndTxidsDisjoint (rbf.cpp:85-98),
	// called from validation.cpp:1356 with error "bad-txns-spends-conflicting-tx".
	ErrRBFAncestorConflict = errors.New("replacement spends conflicting transaction")

	// Package validation errors.
	ErrPackageEmpty            = errors.New("package is empty")
	ErrPackageTooManyTxs       = errors.New("package exceeds maximum transaction count")
	ErrPackageTooLarge         = errors.New("package exceeds maximum weight")
	ErrPackageDuplicateTx      = errors.New("package contains duplicate transactions")
	ErrPackageNotSorted        = errors.New("package is not topologically sorted")
	ErrPackageConflict         = errors.New("package contains conflicting transactions")
	ErrPackageNotChildWithParents = errors.New("package topology must be child-with-unconfirmed-parents")
	ErrPackageInsufficientFee  = errors.New("package feerate below minimum relay fee")

	// W96 ATMP gates (mirrors Bitcoin Core MemPoolAccept).

	// ErrSameTxidDifferentWitness fires when a transaction sharing the txid of
	// an in-mempool tx but with a different witness (different wtxid) is
	// submitted. Mirrors Core validation.cpp:828 — TX_CONFLICT,
	// "txn-same-nonwitness-data-in-mempool". Distinguishing this from the
	// vanilla wtxid-duplicate case lets p2p code suppress retransmission of a
	// known witness-mutated variant.
	ErrSameTxidDifferentWitness = errors.New("txn-same-nonwitness-data-in-mempool")

	// ErrTxnAlreadyKnown fires when a submitted tx's inputs are missing from
	// the UTXO view yet its own outputs are already cached in the UTXO set —
	// the wallet/peer is replaying a tx whose effects we already committed.
	// Mirrors Core validation.cpp:862 — TX_CONFLICT, "txn-already-known".
	// Distinguishes this case from a true orphan (missing parents), so the
	// caller does NOT add the tx to the orphan pool.
	ErrTxnAlreadyKnown = errors.New("txn-already-known")

	// ErrEphemeralDustNonZeroFee fires when a tx with a dust output is
	// submitted with non-zero fee. Mirrors Core PreCheckEphemeralTx
	// (policy/ephemeral_policy.cpp:23-30) — "tx with dust output must be
	// 0-fee". Ephemeral anchors must be CPFP-mined, so giving them
	// stand-alone mining incentive is a relay DoS vector.
	ErrEphemeralDustNonZeroFee = errors.New("dust: tx with dust output must be 0-fee")

	// ErrTxConsensus is returned when ConsensusScriptChecks (the second
	// CheckInputScripts pass run with the current tip's MANDATORY/consensus
	// block flags) fails AFTER PolicyScriptChecks (STANDARD flags) succeeded.
	// This indicates a real consensus divergence (or a bug in our STANDARD
	// flag handling). Mirrors Core validation.cpp:1184 — LogError
	// "BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block
	// but not STANDARD flags". Returning a distinct error keeps the
	// TX_NOT_STANDARD/TX_CONSENSUS split visible to callers.
	ErrTxConsensus = errors.New("consensus-script-fail: STANDARD pass but block-flags reject")
)

// RBF constants (BIP125).
const (
	// MaxRBFReplacedTxs is the maximum number of transactions that can be
	// replaced by a single RBF replacement (including descendants).
	MaxRBFReplacedTxs = 100

	// SequenceFinal is the maximum sequence number (disables RBF signaling).
	SequenceFinal = 0xFFFFFFFF

	// MaxBIP125RBFSequence is the largest nSequence value that opts a
	// transaction in to BIP-125 replaceability. Mirrors Bitcoin Core's
	// `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd` (`src/util/rbf.h:12`,
	// SEQUENCE_FINAL−2). A tx signals RBF iff at least one input has
	// nSequence <= MaxBIP125RBFSequence.
	//
	// Note: this is intentionally tighter than the historical "any
	// nSequence < SEQUENCE_FINAL signals" reading. Wallets that set
	// nSequence = 0xfffffffe (anti-fee-snipe locktime, no RBF intent)
	// must NOT be marked replaceable.
	MaxBIP125RBFSequence uint32 = 0xFFFFFFFD
)

// Standard transaction policy constants (mirrors policy/policy.h).
const (
	// TxMinStandardVersion is the minimum standard transaction version.
	// Mirrors Bitcoin Core's TX_MIN_STANDARD_VERSION = 1.
	TxMinStandardVersion = 1

	// TxMaxStandardVersion is the maximum standard transaction version.
	// Mirrors Bitcoin Core's TX_MAX_STANDARD_VERSION = 3.
	TxMaxStandardVersion = 3

	// MaxStandardScriptSigSize is the maximum size in bytes of a standard
	// scriptSig. Mirrors Bitcoin Core's MAX_STANDARD_SCRIPTSIG_SIZE = 1650.
	MaxStandardScriptSigSize = 1650

	// MinStandardTxNonWitnessSize is the minimum non-witness serialized size
	// for a standard transaction, to mitigate CVE-2017-12842 (64-byte
	// transaction merkle-branch confusion). Mirrors Bitcoin Core's
	// MIN_STANDARD_TX_NONWITNESS_SIZE = 65 (policy.h:40, validation.cpp:813).
	MinStandardTxNonWitnessSize = 65

	// MaxOpReturnRelay is the maximum cumulative OP_RETURN (nulldata) payload
	// bytes allowed per transaction. Mirrors Bitcoin Core's
	// MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR
	// = 400_000 / 4 = 100_000 bytes (policy.h:84).
	MaxOpReturnRelay = 100_000
)

// Package relay constants (BIP331 / Bitcoin Core policy).
const (
	// MaxPackageCount is the maximum number of transactions in a package.
	MaxPackageCount = 25

	// MaxPackageWeight is the maximum total weight of a package in weight units.
	// This matches the default ancestor size limit (~101 kvB).
	MaxPackageWeight = 404_000
)

// Ancestor/descendant/cluster chain limits matching Bitcoin Core
// (src/policy/policy.h, src/kernel/mempool_limits.h).
const (
	// DefaultAncestorLimit is the maximum number of in-mempool ancestors a tx
	// may have (including itself). Matches Core DEFAULT_ANCESTOR_LIMIT=25
	// (src/policy/policy.h:76).
	DefaultAncestorLimit = 25

	// DefaultDescendantLimit is the maximum number of in-mempool descendants
	// a tx may have (including itself). Matches Core DEFAULT_DESCENDANT_LIMIT=25
	// (src/policy/policy.h:78).
	DefaultDescendantLimit = 25

	// DefaultAncestorSizeLimitKvB caps the total virtual size (kvB) of a
	// transaction's in-mempool ancestor set, including itself. Matches
	// Core's historical DEFAULT_ANCESTOR_SIZE_LIMIT_KVB = 101. A short chain of
	// large transactions may respect the count cap and still violate this.
	DefaultAncestorSizeLimitKvB = 101

	// DefaultDescendantSizeLimitKvB caps the total virtual size (kvB) of
	// any in-mempool ancestor's descendant set, including itself. Matches
	// Core's historical DEFAULT_DESCENDANT_SIZE_LIMIT_KVB = 101.
	DefaultDescendantSizeLimitKvB = 101

	// DefaultClusterSizeLimitKvB is the maximum total virtual size (kvB) of a
	// cluster. Matches Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101
	// (src/policy/policy.h:74). The cluster count limit is MaxClusterSize=64
	// (cluster.go, matching Core DEFAULT_CLUSTER_LIMIT=64, policy.h:72).
	DefaultClusterSizeLimitKvB = 101

	// ExtraDescendantTxSizeLimit is the maximum vsize (vbytes) of an extra
	// descendant that qualifies for the CPFP carve-out exemption. A single
	// transaction with exactly one in-mempool ancestor and vsize ≤ this value
	// may enter the mempool even when the descendant count or size limit is
	// otherwise exceeded. Matches Core EXTRA_DESCENDANT_TX_SIZE_LIMIT=10000
	// (src/policy/policy.h:90).
	//
	// NOTE: Core 27+ dropped the per-tx ancestor/descendant limits in favour
	// of cluster-based limits (DEFAULT_CLUSTER_LIMIT / DEFAULT_CLUSTER_SIZE_LIMIT_KVB).
	// The carve-out is therefore deprecated in cluster-mempool mode but the
	// constant is preserved for documentation and future -limitancestorcount
	// command-line compatibility.
	ExtraDescendantTxSizeLimit = 10_000

	// vbytesPerKvB is the byte/vbyte conversion factor used by the kvB-
	// denominated mempool limits. 1 kvB = 1000 vB.
	vbytesPerKvB = 1000
)

// ChainState is the read-only view of the active chain that the mempool needs
// for context-sensitive checks (BIP-68 sequence-locks, lock-time evaluation).
//
// All methods must be safe for concurrent callers. The implementation in
// production is the chain manager; tests provide fakes.
type ChainState interface {
	// TipHeight returns the current best chain tip height.
	TipHeight() int32

	// TipMTP returns the median time past at the chain tip (the timestamp used
	// to evaluate BIP-68 time-based sequence locks for transactions that would
	// be included in the next block).
	TipMTP() int64

	// MTPAtHeight returns the median time past of the block at the given
	// height in the active chain. Returns 0 when the height is unknown
	// (caller treats this as "no time-based lock satisfied").
	MTPAtHeight(height int32) int64
}

// Config configures the mempool.
type Config struct {
	MaxSize             int64 // Maximum mempool size in bytes (default: 300 MB)
	MinRelayFeeRate     int64 // Minimum fee rate in sat/kvB (default: 1000)
	IncrementalRelayFee int64 // Incremental relay fee in sat/kvB (default: 1000)
	MaxOrphanTxs        int   // Maximum orphan transactions (default: 100)
	ChainParams         *consensus.ChainParams

	// ChainState is optional. When provided, mempool accept enforces BIP-68
	// sequence-locks against the chain tip's MTP. When nil (legacy/test
	// callers), the BIP-68 check is skipped.
	ChainState ChainState

	// AncestorLimit overrides DefaultAncestorLimit when > 0.
	// Set to math.MaxInt to disable the ancestor count check (NoLimits mode).
	// Matches Core -limitancestorcount (src/node/mempool_args.cpp:39).
	AncestorLimit int

	// DescendantLimit overrides DefaultDescendantLimit when > 0.
	// Set to math.MaxInt to disable the descendant count check.
	// Matches Core -limitdescendantcount (src/node/mempool_args.cpp:41).
	DescendantLimit int

	// AncestorSizeLimitKvB overrides DefaultAncestorSizeLimitKvB when > 0.
	// Set to math.MaxInt to disable the ancestor size check.
	AncestorSizeLimitKvB int

	// DescendantSizeLimitKvB overrides DefaultDescendantSizeLimitKvB when > 0.
	// Set to math.MaxInt to disable the descendant size check.
	DescendantSizeLimitKvB int
}

// DefaultConfig returns a mempool config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxSize:             300_000_000, // 300 MB
		MinRelayFeeRate:     1000,        // 1 sat/vB
		IncrementalRelayFee: 1000,        // 1 sat/vB
		MaxOrphanTxs:        100,
		ChainParams:         consensus.MainnetParams(),
	}
}

// NoLimitsConfig returns a Config with all chain-length limits disabled.
// Equivalent to Bitcoin Core's CTxMemPool::Limits::NoLimits()
// (src/kernel/mempool_limits.h:31). Intended for test-only use — production
// mempools MUST use default or tighter limits.
func NoLimitsConfig() Config {
	cfg := DefaultConfig()
	cfg.AncestorLimit = math.MaxInt
	cfg.DescendantLimit = math.MaxInt
	cfg.AncestorSizeLimitKvB = math.MaxInt
	cfg.DescendantSizeLimitKvB = math.MaxInt
	return cfg
}

// TxEntry represents a transaction in the mempool.
type TxEntry struct {
	Tx             *wire.MsgTx
	TxHash         wire.Hash256
	Fee            int64         // Transaction fee in satoshis
	Size           int64         // Transaction virtual size (weight / 4)
	FeeRate        float64       // Fee rate in sat/vB
	Time           time.Time     // When the transaction was added
	Height         int32         // Chain height when added
	Depends        []wire.Hash256 // Transactions this depends on (parent txids in mempool)
	SpentBy        []wire.Hash256 // Transactions that spend this transaction's outputs
	AncestorFee    int64         // Total fee of this tx + all ancestors
	AncestorSize   int64         // Total size of this tx + all ancestors
	DescendantFee  int64         // Total fee of this tx + all descendants
	DescendantSize int64         // Total size of this tx + all descendants
	// SpendsCoinbase is true if any input of this tx spends a coinbase output
	// from the UTXO set (not a mempool parent). Set in AcceptToMemoryPool /
	// AddTransaction's input loop. Mirrors Core's CTxMemPoolEntry::spendsCoinbase
	// (kernel/mempool_entry.h:101). Used by reorg handlers (Core
	// removeForReorg, validation.cpp:1191-1232) to re-scan transactions whose
	// coinbase parents may now be immature after a chain rewind.
	SpendsCoinbase bool
}

// AncestorFeeRate returns the ancestor fee rate (sat/vB).
func (e *TxEntry) AncestorFeeRate() float64 {
	if e.AncestorSize == 0 {
		return 0
	}
	return float64(e.AncestorFee) / float64(e.AncestorSize)
}

// DescendantFeeRate returns the descendant fee rate (sat/vB).
func (e *TxEntry) DescendantFeeRate() float64 {
	if e.DescendantSize == 0 {
		return 0
	}
	return float64(e.DescendantFee) / float64(e.DescendantSize)
}

// orphanEntry represents an orphan transaction awaiting its parents.
type orphanEntry struct {
	tx         *wire.MsgTx
	txHash     wire.Hash256
	addedTime  time.Time
	missingOut []wire.OutPoint // Missing parent outpoints
}

// PackageResult holds the result of a package acceptance attempt.
type PackageResult struct {
	// PackageFeerate is the aggregate feerate of the package (sat/vB).
	PackageFeerate float64

	// PackageError is a package-level error, if any.
	PackageError error

	// TxResults contains per-transaction results.
	TxResults map[wire.Hash256]*TxAcceptResult

	// ReplacedTxs lists txids that were replaced via package RBF.
	ReplacedTxs []wire.Hash256
}

// TxAcceptResult holds the result for a single transaction in a package.
type TxAcceptResult struct {
	// TxID is the transaction ID.
	TxID wire.Hash256

	// WTxID is the witness transaction ID.
	WTxID wire.Hash256

	// Accepted indicates whether the transaction was accepted.
	Accepted bool

	// AlreadyInMempool indicates the transaction was already in the mempool.
	AlreadyInMempool bool

	// Fee is the transaction fee in satoshis (if accepted).
	Fee int64

	// VSize is the virtual size in vbytes (if accepted).
	VSize int64

	// Error is the rejection reason (if not accepted).
	Error error

	// EffectiveFeerate is the feerate used for this transaction (sat/vB).
	// For package transactions, this is the package aggregate feerate.
	EffectiveFeerate float64

	// EffectiveIncludes lists wtxids included in the effective feerate calculation.
	EffectiveIncludes []wire.Hash256
}

// Mempool holds unconfirmed transactions.
type Mempool struct {
	mu          sync.RWMutex
	config      Config
	pool        map[wire.Hash256]*TxEntry     // txid -> TxEntry
	outpoints   map[wire.OutPoint]wire.Hash256 // spent outpoint -> spending txid
	orphans     map[wire.Hash256]*orphanEntry  // Orphan transactions (missing inputs)
	totalSize   int64                          // Total virtual size of all mempool txs
	utxoSet     consensus.UTXOView
	chainHeight int32
	clusters    *ClusterManager               // Cluster-based mempool structure

	// Rolling minimum fee state (mirrors Core txmempool.cpp).
	// rollingMinimumFeeRate is the current floor in sat/kvB as a float64;
	// it is bumped when chunks are evicted (trackPackageRemovedLocked) and
	// decays toward zero between blocks (GetMinFeeRate / getMinFeeRateLocked).
	// blockSinceLastRollingFeeBump is true after each block is connected,
	// which arms the decay timer.  lastRollingFeeUpdate is the Unix timestamp
	// of the last decay computation.
	// Core: txmempool.h:207-212, txmempool.cpp:829-859.
	rollingMinimumFeeRate    float64 // sat/kvB
	blockSinceLastRollingFeeBump bool
	lastRollingFeeUpdate     int64   // Unix seconds
}

// New creates a new mempool.
func New(config Config, utxoSet consensus.UTXOView) *Mempool {
	// Apply defaults if not set
	if config.MaxSize == 0 {
		config.MaxSize = 300_000_000
	}
	if config.MinRelayFeeRate == 0 {
		config.MinRelayFeeRate = 1000
	}
	if config.IncrementalRelayFee == 0 {
		config.IncrementalRelayFee = 1000
	}
	if config.MaxOrphanTxs == 0 {
		config.MaxOrphanTxs = 100
	}
	if config.ChainParams == nil {
		config.ChainParams = consensus.MainnetParams()
	}

	return &Mempool{
		config:               config,
		pool:                 make(map[wire.Hash256]*TxEntry),
		outpoints:            make(map[wire.OutPoint]wire.Hash256),
		orphans:              make(map[wire.Hash256]*orphanEntry),
		utxoSet:              utxoSet,
		clusters:             NewClusterManager(),
		lastRollingFeeUpdate: time.Now().Unix(),
	}
}

// SetChainHeight updates the chain height (called when blocks are connected/disconnected).
func (mp *Mempool) SetChainHeight(height int32) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.chainHeight = height
}

// ChainHeight returns the current chain height.
func (mp *Mempool) ChainHeight() int32 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.chainHeight
}

// AcceptToMemoryPool validates and adds a transaction to the mempool.
// This is the canonical entry point matching Bitcoin Core's naming convention.
// Performs all policy checks including BIP125 RBF, fee-rate validation,
// script verification, and cluster mempool limits.
// Returns nil if accepted, error with reason if rejected.
func (mp *Mempool) AcceptToMemoryPool(tx *wire.MsgTx) error {
	return mp.AddTransaction(tx)
}

// AddTransaction validates and adds a transaction to the mempool.
// Returns nil if accepted, error with reason if rejected.
//
// Pipeline mirrors Bitcoin Core MemPoolAccept::PreChecks → ReplacementChecks
// → PolicyScriptChecks → ConsensusScriptChecks (validation.cpp:782-1190).
// The ordering of gates is deliberately consensus-faithful: cheap context-free
// checks first (sanity, coinbase, IsStandardTx, MIN_STANDARD_TX_NONWITNESS_SIZE,
// IsFinalTx), then sigops + chain-context (BIP-68 + CheckTxInputs), then
// expensive script verification last.
func (mp *Mempool) AddTransaction(tx *wire.MsgTx) error {
	txHash := tx.TxHash()
	wtxid := tx.WTxHash()

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// 1. Wtxid-aware duplicate detection (W96, mirrors Core validation.cpp:823-830).
	// Core makes two distinct exists() probes — first against the wtxid, then
	// against the txid — so that a witness-mutated variant of an already-known
	// tx is distinguishable from a vanilla duplicate. Both are TX_CONFLICT,
	// but the p2p layer caches them differently: "txn-already-in-mempool" can
	// be cleared on reorg, "txn-same-nonwitness-data-in-mempool" must remain
	// suppressed (the wire bytes are different but the consensus state is
	// already committed).
	if existing, ok := mp.pool[txHash]; ok {
		if existing.Tx.WTxHash() == wtxid {
			// Exact (wtxid) duplicate.
			return fmt.Errorf("%w: %s", ErrAlreadyInMempool, txHash)
		}
		// Same txid, different wtxid — witness-mutated variant.
		return fmt.Errorf("%w: %s", ErrSameTxidDifferentWitness, txHash)
	}

	// 2. Basic sanity checks
	if err := consensus.CheckTransactionSanity(tx); err != nil {
		return fmt.Errorf("transaction sanity check failed: %w", err)
	}

	// 3. Reject coinbase transactions
	if consensus.IsCoinbaseTx(tx) {
		return ErrCoinbaseNotAllowed
	}

	// 3a. Transaction version range check (Core IsStandardTx line 102,
	// policy.h TX_MIN_STANDARD_VERSION=1 / TX_MAX_STANDARD_VERSION=3).
	// Rejects version 0 and any version > 3 as non-standard.
	if tx.Version < TxMinStandardVersion || tx.Version > TxMaxStandardVersion {
		return fmt.Errorf("%w: got %d, want [%d, %d]",
			ErrTxVersion, tx.Version, TxMinStandardVersion, TxMaxStandardVersion)
	}

	// 4. Check transaction weight (max standard tx weight: 400,000 WU)
	weight := consensus.CalcTxWeight(tx)
	if weight > consensus.MaxStandardTxWeight {
		return fmt.Errorf("%w: weight %d exceeds maximum %d", ErrTxTooLarge, weight, consensus.MaxStandardTxWeight)
	}

	// 4a. Minimum non-witness size check (Core validation.cpp:813,
	// MIN_STANDARD_TX_NONWITNESS_SIZE = 65). Mitigates CVE-2017-12842
	// (64-byte tx merkle-branch confusion attack).
	{
		var nwBuf bytes.Buffer
		_ = tx.SerializeNoWitness(&nwBuf)
		if nwBuf.Len() < MinStandardTxNonWitnessSize {
			return fmt.Errorf("%w: got %d bytes", ErrTxTooSmall, nwBuf.Len())
		}
	}

	// 5. Calculate virtual size
	vsize := (weight + 3) / 4 // Round up

	// 5a. Per-input scriptSig policy (Core IsStandardTx input loop,
	// policy/policy.cpp:117-135):
	//   - scriptSig size must not exceed MAX_STANDARD_SCRIPTSIG_SIZE (1650 bytes).
	//   - scriptSig must be push-only (IsPushOnly).
	// Both mitigate CPU-exhaustion DoS from large/non-push scriptSigs.
	for i, in := range tx.TxIn {
		if len(in.SignatureScript) > MaxStandardScriptSigSize {
			return fmt.Errorf("%w: input %d scriptSig %d bytes > %d",
				ErrScriptSigTooLarge, i, len(in.SignatureScript), MaxStandardScriptSigSize)
		}
		if len(in.SignatureScript) > 0 && !script.IsPushOnly(in.SignatureScript) {
			return fmt.Errorf("%w: input %d", ErrScriptSigNotPushOnly, i)
		}
	}

	// 5b. Check output script standardness (Core IsStandardTx vout loop,
	// policy/policy.cpp:140).  Each output must be a known standard type:
	//   P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A, or well-formed nulldata
	//   (OP_RETURN + IsPushOnly remainder per consensus.IsNullData).
	// A script that starts with OP_RETURN but has a truncated or non-push
	// trailing byte (e.g. 6a09deadbeef) is classified NONSTANDARD and
	// rejected here — the W56 fix to isNullData now shares this logic via
	// consensus.IsNullData so both the mempool gate and decodescript agree.
	// Also enforce MAX_OP_RETURN_RELAY (100_000 bytes) cumulative budget
	// across all OP_RETURN outputs in the transaction (Core policy.cpp:147).
	{
		var datacarrierBytesUsed int
		for i, out := range tx.TxOut {
			if !isStandardOutputScript(out.PkScript) {
				return fmt.Errorf("%w: output %d script is nonstandard", ErrNonStandardOutput, i)
			}
			// Track OP_RETURN (nulldata) bytes for datacarrier budget.
			if consensus.IsNullData(out.PkScript) {
				datacarrierBytesUsed += len(out.PkScript)
				if datacarrierBytesUsed > MaxOpReturnRelay {
					return fmt.Errorf("%w: %d bytes > %d",
						ErrDataCarrierTooLarge, datacarrierBytesUsed, MaxOpReturnRelay)
				}
			}
		}
	}

	// 5c. IsFinalTx (BIP-113): reject non-final transactions at mempool admit.
	// Mempool holds txs for the *next* block, so check against tipHeight+1
	// and the current chain MTP (MEDIAN_TIME_PAST of the last 11 blocks).
	// Mirrors Bitcoin Core MemPoolAccept::PreChecks → CheckFinalTxAtTip
	// (validation.cpp:819).
	if mp.config.ChainState != nil {
		cs := mp.config.ChainState
		nextHeight := cs.TipHeight() + 1
		mtp := uint32(cs.TipMTP())
		if !consensus.IsFinalTx(tx, nextHeight, mtp) {
			return ErrNonFinalTx
		}
	}

	// 5d. Sigops policy gates.
	//
	// Gate 1 — per-tx sigops cost (BIP141 weighted, MAX_STANDARD_TX_SIGOPS_COST=16000).
	// Mirrors Bitcoin Core MemPoolAccept::PreChecks:
	//   nSigOpsCost = GetTransactionSigOpCost(tx, m_view, …)
	//   if nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST → reject "bad-txns-too-many-sigops"
	// Core: validation.cpp:908-943.
	//
	// We build a thin UTXOView over mp.lookupOutputLocked so P2SH redeem-script
	// and witness sigops are counted accurately (requires prevout scriptPubKey).
	{
		mempoolView := &mempoolUTXOView{mp: mp}
		txSigOpsCost := consensus.GetTransactionSigOpCost(tx, mempoolView)
		if txSigOpsCost > consensus.MaxStandardTxSigOpsCost {
			return fmt.Errorf("%w: cost %d > %d",
				ErrTxSigOpsCostTooHigh, txSigOpsCost, consensus.MaxStandardTxSigOpsCost)
		}
	}

	// Gate 2 — per-P2SH-input redeemScript sigop limit (MAX_P2SH_SIGOPS=15).
	// For every input spending a P2SH output the redeemScript (last push in
	// scriptSig) must have ≤ 15 sigops (accurate counting). This prevents
	// relay of txns with pathological P2SH redeemScripts.
	// Core: policy.cpp:254-258, ValidateInputsStandardness.
	{
		mempoolView := &mempoolUTXOView{mp: mp}
		for i, in := range tx.TxIn {
			utxo := mempoolView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				continue
			}
			if !script.IsP2SH(utxo.PkScript) {
				continue
			}
			// Count sigops in the redeemScript extracted from scriptSig.
			sigops := consensus.CountScriptSigOps(in.SignatureScript)
			if sigops > consensus.MaxP2SHSigOpsPerInput {
				return fmt.Errorf("%w: input %d has %d sigops > %d",
					ErrP2SHSigOpsTooMany, i, sigops, consensus.MaxP2SHSigOpsPerInput)
			}
		}
	}

	// Gate 3 — total non-witness (legacy) sigops across all inputs (BIP54,
	// MAX_TX_LEGACY_SIGOPS=2500). Counts: scriptSig sigops (accurate) +
	// prevout scriptPubKey sigops (P2SH-accurate). Witness sigops excluded.
	// Core: policy.cpp:170-193 (CheckSigopsBIP54), called from
	// ValidateInputsStandardness at policy.cpp:221.
	{
		mempoolView := &mempoolUTXOView{mp: mp}
		var legacySigops int
		overLimit := false
		for _, in := range tx.TxIn {
			// scriptSig sigops (accurate).
			legacySigops += consensus.CountSigOpsAccurate(in.SignatureScript)
			// prevout scriptPubKey sigops (P2SH-accurate).
			utxo := mempoolView.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				legacySigops += consensus.CountScriptPubKeySigOps(utxo.PkScript, in.SignatureScript)
			}
			if legacySigops > consensus.MaxTxLegacySigOps {
				overLimit = true
				break
			}
		}
		if overLimit {
			return fmt.Errorf("%w: %d > %d",
				ErrTxLegacySigOpsTooMany, legacySigops, consensus.MaxTxLegacySigOps)
		}
	}

	// 6. Check for double spends (with RBF support) and gather input values
	var totalInputValue int64
	var missingInputs []wire.OutPoint
	var conflictingTxs map[wire.Hash256]bool // Transactions to replace via RBF
	// W96: fSpendsCoinbase — record whether ANY input spends a confirmed
	// coinbase output. Carried into the TxEntry so reorg handlers
	// (removeForReorg) can re-verify maturity when the chain shortens.
	// Mirrors Core CTxMemPoolEntry::spendsCoinbase + PreChecks loop at
	// validation.cpp:912-919.
	var spendsCoinbase bool

	for _, in := range tx.TxIn {
		// Check mempool double-spend
		if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			if conflictingTxs == nil {
				conflictingTxs = make(map[wire.Hash256]bool)
			}
			conflictingTxs[existingTxHash] = true
		}

		// Look up the UTXO (check mempool outputs first, then UTXO set)
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			missingInputs = append(missingInputs, in.PreviousOutPoint)
		} else {
			// Coinbase maturity (Gap B3): a confirmed coinbase output must
			// have at least CoinbaseMaturity (100) confirmations before it
			// can be spent in the mempool.
			// Mirrors Bitcoin Core MemPoolAccept::PreChecks / CheckTxInputs
			// (consensus/tx_verify.cpp).
			if utxo.IsCoinbase {
				spendsCoinbase = true
				if mp.config.ChainState != nil {
					tipHeight := mp.config.ChainState.TipHeight()
					age := tipHeight - utxo.Height
					if age < consensus.CoinbaseMaturity {
						return fmt.Errorf("%w: age %d < %d required",
							ErrImmatureCoinbaseSpend, age, consensus.CoinbaseMaturity)
					}
				}
			}
			// W96: per-input MoneyRange check (Core CheckTxInputs at
			// tx_verify.cpp:179-184, called from PreChecks at
			// validation.cpp:892). Defence-in-depth: prevout amounts
			// pulled from UTXO storage must be in [0, MAX_MONEY].
			if utxo.Amount < 0 || utxo.Amount > consensus.MaxMoney {
				return fmt.Errorf("bad-txns-inputvalues-outofrange: input %s value %d",
					in.PreviousOutPoint.Hash, utxo.Amount)
			}
			totalInputValue += utxo.Amount
			// W96: accumulated MoneyRange (Core tx_verify.cpp:185-189).
			// A pathological set of barely-in-range inputs can still sum
			// past MAX_MONEY (overflow attack class CVE-2010-5139 territory).
			if totalInputValue < 0 || totalInputValue > consensus.MaxMoney {
				return fmt.Errorf("bad-txns-inputvalues-outofrange: accumulated %d",
					totalInputValue)
			}
		}
	}

	// If there are conflicting transactions, check RBF rules
	if len(conflictingTxs) > 0 && len(missingInputs) == 0 {
		rbfErr := mp.checkRBFLocked(tx, conflictingTxs, totalInputValue)
		if rbfErr != nil {
			return rbfErr
		}
	} else if len(conflictingTxs) > 0 {
		// Can't do RBF with missing inputs
		for txHash := range conflictingTxs {
			return fmt.Errorf("%w: input already spent by mempool tx %s",
				ErrDoubleSpend, txHash)
		}
	}

	// W96: tx-already-known distinction (Core validation.cpp:858-866).
	// When inputs are missing, scan our own UTXO set for outpoints of THIS
	// tx — if any of the tx's outputs are already present, the caller has
	// replayed a tx we already accepted (its parents were spent on commit).
	// This is TX_CONFLICT, not TX_MISSING_INPUTS, and we must NOT enrol it
	// in the orphan pool (it would just churn there until expiry).
	if len(missingInputs) > 0 && mp.utxoSet != nil {
		for outIdx := range tx.TxOut {
			op := wire.OutPoint{Hash: txHash, Index: uint32(outIdx)}
			if existing := mp.utxoSet.GetUTXO(op); existing != nil {
				return fmt.Errorf("%w: tx %s already committed (output %d in UTXO set)",
					ErrTxnAlreadyKnown, txHash, outIdx)
			}
		}
	}

	// If we have missing inputs, treat as orphan
	if len(missingInputs) > 0 {
		mp.addOrphanLocked(txHash, tx, missingInputs)
		return fmt.Errorf("%w: added as orphan with %d missing inputs", ErrMissingInputs, len(missingInputs))
	}

	// 7. Calculate fee
	var totalOutputValue int64
	for _, out := range tx.TxOut {
		totalOutputValue += out.Value
	}
	fee := totalInputValue - totalOutputValue
	if fee < 0 {
		return ErrNegativeFee
	}

	// 8. Check minimum fee rate (dynamic, accounts for mempool fullness)
	feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
	minFeeRate := mp.getMinFeeRateLocked()
	if int64(feeRate) < minFeeRate {
		return fmt.Errorf("%w: %.1f sat/kvB below minimum %d sat/kvB",
			ErrInsufficientFee, feeRate, minFeeRate)
	}

	// 9. PreCheckEphemeralTx + dust outputs (W96, BIP-431 ephemeral anchors).
	//
	// Core (policy/ephemeral_policy.cpp:23) carves out a narrow exception to
	// the dust rule: a transaction that pays ZERO FEE may have dust outputs,
	// on the understanding that it can only be mined via CPFP (a higher-fee
	// child that consumes the dust). Any non-zero fee + dust output
	// combination is rejected with "tx with dust output must be 0-fee".
	//
	// We wrap BOTH error paths through ErrDustOutput so existing callers
	// (errors.Is(err, ErrDustOutput)) still work, while the W96 sentinel
	// ErrEphemeralDustNonZeroFee is reachable as the wrapped cause for
	// callers that want the fee==0 distinction.
	for i, out := range tx.TxOut {
		if !mp.isDust(out) {
			continue
		}
		if fee == 0 {
			// Ephemeral anchor / 0-fee CPFP carrier: dust is permitted.
			// Continue scanning — other outputs may still need checking
			// (e.g. AnchorDust cap on P2A handled inside isDust).
			continue
		}
		// Non-zero-fee tx with dust output. Wrap both sentinels so
		// callers asserting either ErrDustOutput (legacy) or
		// ErrEphemeralDustNonZeroFee (W96) succeed.
		return fmt.Errorf("%w (%w): output %d value %d",
			ErrDustOutput, ErrEphemeralDustNonZeroFee, i, out.Value)
	}

	// 9e. IsWitnessStandard (Core policy.cpp:265-352, validation.cpp:904).
	// Called only when the tx carries witness data, before script evaluation,
	// so rejections return descriptive sentinel errors unwrappable with errors.Is.
	if tx.HasWitness() {
		witnessLookup := func(op wire.OutPoint) *consensus.UTXOEntry {
			return mp.lookupOutputLocked(op)
		}
		if err := isWitnessStandard(tx, witnessLookup); err != nil {
			return err
		}
	}

	// 10b. BIP-68 sequence-lock check (Bitcoin Core
	//      validation.cpp::CheckSequenceLocksAtTip in PreChecks).
	//      Locks are evaluated against the *next* block (tip height + 1)
	//      and the chain tip's MTP. Skipped when no ChainState is wired.
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		return err
	}

	// 10c. Ancestor/descendant count + size limits (Core
	//      DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT = 25 and
	//      DEFAULT_{ANCESTOR,DESCENDANT}_SIZE_LIMIT_KVB = 101). Reject
	//      before mutating cluster/pool state so a rejection is
	//      side-effect free.
	if err := mp.checkChainLimitsWithSizeLocked(tx, vsize); err != nil {
		return err
	}

	// 10d. BIP-431 TRUC (version=3) policy checks. Runs before script
	//      validation (expensive) to give fast policy rejections.
	//      Must run after outpoint/input resolution (step 6) so we know
	//      in-mempool parents. Uses sigop-adjusted vsize per
	//      truc_policy.h TRUC_MAX_VSIZE / TRUC_CHILD_MAX_VSIZE.
	//      Core: SingleTRUCChecks (truc_policy.cpp:171-261), called from
	//      MemPoolAccept::PreChecks (validation.cpp) before CheckInputScripts.
	if err := mp.singleTRUCChecks(tx, conflictingTxs); err != nil {
		// Sibling eviction: caller could attempt RBF eviction of the sibling,
		// but in the single-tx path we conservatively reject. The caller of
		// AcceptPackage may handle sibling eviction in the package path.
		return err
	}

	// 10. Validate scripts — two-pass STANDARD vs CONSENSUS split (W96).
	//
	// PolicyScriptChecks runs with STANDARD_SCRIPT_VERIFY_FLAGS (which is a
	// strict superset of consensus block flags: adds NULLFAIL, STRICTENC,
	// WITNESS_PUBKEYTYPE). A failure here means the tx is non-standard.
	// Core: validation.cpp:1135-1156, mapped to TX_NOT_STANDARD.
	//
	// ConsensusScriptChecks then re-runs CheckInputScripts with the current
	// tip's MANDATORY/consensus block flags. Because STANDARD ⊇ CONSENSUS,
	// a STANDARD-pass result MUST also be a CONSENSUS-pass. If the second
	// pass fails, that is either a bug in our STANDARD flag handling or a
	// genuine consensus divergence — both are LogError "BUG! PLEASE REPORT"
	// territory (Core validation.cpp:1184) and must be surfaced as a
	// distinct error code (TX_CONSENSUS), NOT collapsed into TX_NOT_STANDARD.
	//
	// W96 fix: previously the mempool ran a single pass at STANDARD flags
	// only, so a true consensus reject would be reported as ErrScriptValidation
	// (interpreted by callers as policy-only). Now both passes run, and the
	// CONSENSUS reject path returns ErrTxConsensus, which p2p / RPC layers
	// can route to a louder warning channel.
	policyFlags := mp.getStandardScriptFlags()
	if err := mp.validateScriptsLocked(tx, policyFlags); err != nil {
		return fmt.Errorf("%w: %v", ErrScriptValidation, err)
	}
	consensusFlags := mp.getConsensusScriptFlags()
	if consensusFlags != policyFlags {
		if err := mp.validateScriptsLocked(tx, consensusFlags); err != nil {
			// This is a "BUG! PLEASE REPORT" scenario — we just passed the
			// strict superset of these flags. Returning ErrTxConsensus
			// (wrapped) keeps the policy / consensus distinction visible.
			return fmt.Errorf("%w: tx %s rejected at MANDATORY flags after STANDARD pass: %v",
				ErrTxConsensus, txHash, err)
		}
	}

	// 11. Create entry and add to mempool
	entry := &TxEntry{
		Tx:             tx,
		TxHash:         txHash,
		Fee:            fee,
		Size:           vsize,
		FeeRate:        float64(fee) / float64(vsize),
		Time:           time.Now(),
		Height:         mp.chainHeight,
		AncestorFee:    fee,
		AncestorSize:   vsize,
		DescendantFee:  fee,
		DescendantSize: vsize,
		SpendsCoinbase: spendsCoinbase, // W96, see PreChecks loop above.
	}

	// Track dependencies (parent transactions in mempool)
	for _, in := range tx.TxIn {
		if parentEntry, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			entry.Depends = append(entry.Depends, parentEntry.TxHash)
			parentEntry.SpentBy = append(parentEntry.SpentBy, txHash)
		}
	}

	// Update ancestor/descendant tracking
	mp.updateAncestorStateLocked(entry)
	mp.updateDescendantStateLocked(entry)

	// Execute RBF replacements if any
	if len(conflictingTxs) > 0 {
		for conflictHash := range conflictingTxs {
			mp.removeWithDescendantsLocked(conflictHash)
		}
	}

	// Add to pool
	mp.pool[txHash] = entry
	for _, in := range tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txHash
	}
	mp.totalSize += vsize

	// Add to cluster manager
	parentTxids := entry.Depends
	_, clusterErr := mp.clusters.AddTransaction(txHash, fee, int32(vsize), parentTxids)
	if clusterErr != nil {
		// Cluster too large - remove the transaction we just added
		mp.removeSingleTxLocked(txHash)
		return clusterErr
	}

	// 12. Evict if mempool too large
	mp.maybeEvictLocked()

	// 13. Check if this resolves any orphans
	mp.processOrphansLocked(txHash)

	return nil
}

// lookupOutputLocked looks up a UTXO from mempool or UTXO set.
// Must be called with mu held.
//
// W96 slice-alias hardening: when the UTXO is sourced from a mempool tx's
// output, copy the PkScript bytes into a fresh slice rather than aliasing
// entry.Tx.TxOut[idx].PkScript. Callers (sigops counting, witness
// standardness, signature evaluators with script interning) may mutate or
// embed the returned PkScript in caches; sharing the backing array
// silently corrupts the source transaction. Same defect class as
// W82/W92/W93 PkScript aliasing in connect/disconnect paths.
func (mp *Mempool) lookupOutputLocked(outpoint wire.OutPoint) *consensus.UTXOEntry {
	// First check if a mempool transaction creates this output
	if entry, ok := mp.pool[outpoint.Hash]; ok {
		if int(outpoint.Index) < len(entry.Tx.TxOut) {
			out := entry.Tx.TxOut[outpoint.Index]
			pk := make([]byte, len(out.PkScript))
			copy(pk, out.PkScript)
			return &consensus.UTXOEntry{
				Amount:   out.Value,
				PkScript: pk,
				Height:   entry.Height,
				// Coinbase txs are rejected at PreChecks step 3, so a
				// mempool-output cannot be a coinbase. Leaving IsCoinbase
				// at its zero value (false) is correct.
			}
		}
	}
	// Fall back to the UTXO set
	if mp.utxoSet != nil {
		return mp.utxoSet.GetUTXO(outpoint)
	}
	return nil
}

// GetUTXO implements consensus.UTXOView, allowing mempool to be used as a UTXO source.
func (mp *Mempool) GetUTXO(outpoint wire.OutPoint) *consensus.UTXOEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.lookupOutputLocked(outpoint)
}

// mempoolUTXOView is a thin consensus.UTXOView adapter that calls
// mp.lookupOutputLocked without acquiring mp.mu. It is only valid to use
// while mp.mu is already held (e.g. inside AddTransaction).
type mempoolUTXOView struct {
	mp *Mempool
}

// GetUTXO implements consensus.UTXOView without acquiring mp.mu.
// Must only be called while the caller holds mp.mu.
func (v *mempoolUTXOView) GetUTXO(outpoint wire.OutPoint) *consensus.UTXOEntry {
	return v.mp.lookupOutputLocked(outpoint)
}

// AnchorDust is the maximum value allowed for P2A outputs (in satoshis).
// P2A outputs are exempt from the normal dust threshold but capped at this value.
const AnchorDust int64 = 240

// isDust checks if an output is dust (uneconomical to spend).
// Mirrors Bitcoin Core's GetDustThreshold / IsDust (policy/policy.cpp):
// provably unspendable outputs (OP_RETURN / empty) have a dust threshold of 0
// and are therefore never dust — they carry no future spending cost.
func (mp *Mempool) isDust(txOut *wire.TxOut) bool {
	// Provably unspendable outputs (OP_RETURN or empty) are never dust.
	// Core's GetDustThreshold returns 0 for IsUnspendable(), so IsDust is false.
	if consensus.IsUnspendable(txOut.PkScript) {
		return false
	}

	// P2A (Pay-to-Anchor) outputs are exempt from normal dust rules.
	// They are meant for fee bumping via CPFP and can have value 0.
	// However, for standardness we cap them at AnchorDust satoshis.
	if consensus.IsPayToAnchor(txOut.PkScript) {
		return txOut.Value > AnchorDust // P2A is only standard if value <= AnchorDust
	}

	// Dust is defined as an output whose spending cost exceeds its value.
	// Spending cost depends on the script type.
	spendingSize := int64(148) // Conservative default (P2PKH spending size)

	if consensus.IsP2WPKH(txOut.PkScript) {
		spendingSize = 68 // Witness v0 keyhash spending size
	} else if consensus.IsP2WSH(txOut.PkScript) {
		spendingSize = 68 // Conservative estimate
	} else if consensus.IsP2TR(txOut.PkScript) {
		spendingSize = 58 // Taproot key path spending size
	}

	dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000
	return txOut.Value < dustThreshold
}

// isStandardOutputScript returns true if pkScript is a known-standard output
// type that blockbrew's mempool policy accepts.  Mirrors Bitcoin Core's
// IsStandard (policy/policy.cpp:80) output classification:
//
//   - P2PKH, P2SH, P2WPKH, P2WSH, P2TR — always standard
//   - P2A (pay-to-anchor) — standard
//   - Nulldata: OP_RETURN followed by IsPushOnly bytes (consensus.IsNullData) —
//     standard.  Starts-with-OP_RETURN but malformed (truncated push) → false.
//   - Unknown witness programs — accepted as future-soft-fork outputs (Core
//     TxoutType::WITNESS_UNKNOWN branch in IsStandard).
//   - Everything else — nonstandard.
func isStandardOutputScript(pkScript []byte) bool {
	switch {
	case consensus.IsP2PKH(pkScript),
		consensus.IsP2SH(pkScript),
		consensus.IsP2WPKH(pkScript),
		consensus.IsP2WSH(pkScript),
		consensus.IsP2TR(pkScript),
		consensus.IsPayToAnchor(pkScript):
		return true
	case consensus.IsNullData(pkScript):
		// Well-formed OP_RETURN with IsPushOnly remainder.
		return true
	case len(pkScript) > 0 && pkScript[0] == 0x6a:
		// Starts with OP_RETURN but is NOT well-formed nulldata (e.g. truncated
		// push bytes).  Core classifies this NONSTANDARD via its Solver check.
		return false
	default:
		// Unknown witness programs are accepted (forward-compat with soft forks).
		// A witness program is: OP_N (0x00|0x51..0x60) <2..40 byte push>.
		if isUnknownWitnessProgram(pkScript) {
			return true
		}
		// All other script forms are nonstandard.
		return false
	}
}

// isUnknownWitnessProgram returns true for segwit v2+ witness programs that
// Core accepts as WITNESS_UNKNOWN (forward-compat for future soft forks).
// Format: OP_N <push of 2..40 bytes> where N is 0x00 (v0), 0x51..0x60 (v1–v16).
// v0 (P2WPKH/P2WSH) and v1 (P2TR) are handled above; only v2–v16 land here.
func isUnknownWitnessProgram(pkScript []byte) bool {
	if len(pkScript) < 4 || len(pkScript) > 42 {
		return false
	}
	// First byte must be a witness version opcode.
	ver := pkScript[0]
	if ver != 0x00 && (ver < 0x51 || ver > 0x60) {
		return false
	}
	// Second byte is the push length; must push 2..40 bytes.
	pushLen := int(pkScript[1])
	if pushLen < 2 || pushLen > 40 {
		return false
	}
	return len(pkScript) == 2+pushLen
}

// getStandardScriptFlags returns script validation flags for mempool validation.
// Uses GetStandardScriptFlags which adds policy-only flags (NULLFAIL,
// WITNESS_PUBKEYTYPE, STRICTENC) on top of the consensus flags.
func (mp *Mempool) getStandardScriptFlags() script.ScriptFlags {
	// Mempool uses current chain tip flags — no exception hash needed
	// (exceptions are only for historical blocks during IBD).
	var zeroHash wire.Hash256
	return consensus.GetStandardScriptFlags(mp.chainHeight, mp.config.ChainParams, zeroHash)
}

// getConsensusScriptFlags returns the script verification flags that would
// apply if this transaction were mined into the NEXT block at the current
// chain tip. These are the MANDATORY consensus flags only — no policy-only
// additions (no NULLFAIL / STRICTENC / WITNESS_PUBKEYTYPE).
//
// W96: used by ConsensusScriptChecks (the second of the PolicyScriptChecks /
// ConsensusScriptChecks pair). Mirrors Core's
// GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), ...) called from
// validation.cpp:1181. When the consensus and standard flag sets coincide
// (no policy bits enabled at this height) the caller skips the second pass.
func (mp *Mempool) getConsensusScriptFlags() script.ScriptFlags {
	var zeroHash wire.Hash256
	return consensus.GetBlockScriptFlags(mp.chainHeight, mp.config.ChainParams, zeroHash)
}

// validateScriptsLocked validates transaction scripts.
// Must be called with mu held (at least for reading).
func (mp *Mempool) validateScriptsLocked(tx *wire.MsgTx, flags script.ScriptFlags) error {
	// Build prevOuts slice for the transaction
	prevOuts := make([]*wire.TxOut, len(tx.TxIn))
	for i, in := range tx.TxIn {
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			return consensus.ErrMissingInput
		}
		prevOuts[i] = &wire.TxOut{
			Value:    utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	// Validate each input
	for i, in := range tx.TxIn {
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			return consensus.ErrMissingInput
		}

		err := script.VerifyScript(
			in.SignatureScript,
			utxo.PkScript,
			tx,
			i,
			flags,
			utxo.Amount,
			prevOuts,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// updateAncestorStateLocked updates ancestor fee/size for a new entry.
// Must be called with mu held.
func (mp *Mempool) updateAncestorStateLocked(entry *TxEntry) {
	// Collect all ancestors
	visited := make(map[wire.Hash256]bool)
	ancestors := mp.collectAncestorsLocked(entry.TxHash, visited)

	for _, ancestorHash := range ancestors {
		if ancestor, ok := mp.pool[ancestorHash]; ok {
			entry.AncestorFee += ancestor.Fee
			entry.AncestorSize += ancestor.Size
		}
	}
}

// updateDescendantStateLocked updates descendant fees for ancestors when adding a new tx.
// Must be called with mu held.
func (mp *Mempool) updateDescendantStateLocked(entry *TxEntry) {
	// Update all ancestors' descendant counts
	visited := make(map[wire.Hash256]bool)
	ancestors := mp.collectAncestorsLocked(entry.TxHash, visited)

	for _, ancestorHash := range ancestors {
		if ancestor, ok := mp.pool[ancestorHash]; ok {
			ancestor.DescendantFee += entry.Fee
			ancestor.DescendantSize += entry.Size
		}
	}
}

// collectAncestorsLocked collects all ancestor transaction hashes.
// Must be called with mu held.
func (mp *Mempool) collectAncestorsLocked(txHash wire.Hash256, visited map[wire.Hash256]bool) []wire.Hash256 {
	if visited[txHash] {
		return nil
	}
	visited[txHash] = true

	entry, ok := mp.pool[txHash]
	if !ok {
		return nil
	}

	var result []wire.Hash256
	for _, parentHash := range entry.Depends {
		result = append(result, parentHash)
		result = append(result, mp.collectAncestorsLocked(parentHash, visited)...)
	}
	return result
}

// collectDescendantsLocked collects all descendant transaction hashes.
// Must be called with mu held.
func (mp *Mempool) collectDescendantsLocked(txHash wire.Hash256, visited map[wire.Hash256]bool) []wire.Hash256 {
	if visited[txHash] {
		return nil
	}
	visited[txHash] = true

	entry, ok := mp.pool[txHash]
	if !ok {
		return nil
	}

	var result []wire.Hash256
	for _, childHash := range entry.SpentBy {
		result = append(result, childHash)
		result = append(result, mp.collectDescendantsLocked(childHash, visited)...)
	}
	return result
}

// checkSequenceLocksLocked enforces BIP-68 (sequence locks) at mempool accept.
//
// Mirrors src/validation.cpp::CheckSequenceLocksAtTip: the lock is evaluated
// against the *next* block (tip height + 1) and the chain tip's MTP — i.e.,
// the values the transaction would see if mined into the next block. The
// per-input height is the height of the block that confirmed the spent UTXO
// (mempool parents are conservatively treated as confirming at tip+1, which
// matches Core's "use the next block height for not-yet-confirmed inputs").
//
// Skipped when no ChainState is wired (legacy and test callers).
// Must be called with mu held.
func (mp *Mempool) checkSequenceLocksLocked(tx *wire.MsgTx) error {
	if mp.config.ChainState == nil {
		return nil
	}
	// BIP-68 only applies to v2+ transactions; spare the work otherwise.
	if tx.Version < 2 {
		return nil
	}
	cs := mp.config.ChainState
	tipHeight := cs.TipHeight()
	if mp.config.ChainParams != nil && tipHeight < mp.config.ChainParams.CSVHeight {
		// CSV not yet active.
		return nil
	}
	nextHeight := tipHeight + 1

	prevHeights := make([]int32, len(tx.TxIn))
	for i, in := range tx.TxIn {
		// Mempool parent: would be in the same block as this tx, so use
		// nextHeight (Core uses tip+1 for unconfirmed parents).
		if _, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			prevHeights[i] = nextHeight
			continue
		}
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			// Caller already checked missing inputs; treat as "not yet
			// confirmed" so we don't crash.
			prevHeights[i] = nextHeight
			continue
		}
		prevHeights[i] = utxo.Height
	}

	getMTP := func(h int32) int64 {
		if h < 0 {
			return 0
		}
		return cs.MTPAtHeight(h)
	}
	lock := consensus.CalculateSequenceLocks(tx, prevHeights, getMTP)
	if !consensus.EvaluateSequenceLocks(lock, nextHeight, cs.TipMTP()) {
		return ErrSequenceLockNotMet
	}
	return nil
}

// checkChainLimitsLocked enforces ancestor/descendant count + size limits
// when adding a new transaction. Mirrors Bitcoin Core's
// CalculateMemPoolAncestors failure path
// (DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT, both 25;
// DEFAULT_ANCESTOR_SIZE_LIMIT_KVB / DEFAULT_DESCENDANT_SIZE_LIMIT_KVB,
// both 101 kvB = 101_000 vB).
//
// Counts and sizes include the transaction itself (Core's
// "ancestor count = 1 + parent count" / "descendant count = 1 + child count"
// semantics). The candidate's vsize is supplied via candidateVSize; when
// the caller does not yet know it (legacy callers) it may pass 0 and the
// size cap will be evaluated against ancestors only — count caps still
// apply. Must be called with mu held.
func (mp *Mempool) checkChainLimitsLocked(tx *wire.MsgTx) error {
	return mp.checkChainLimitsWithSizeLocked(tx, 0)
}

func (mp *Mempool) checkChainLimitsWithSizeLocked(tx *wire.MsgTx, candidateVSize int64) error {
	// Resolve effective limits: Config fields override defaults when > 0.
	// math.MaxInt in a Config field disables that check entirely (NoLimits mode).
	ancestorLimit := DefaultAncestorLimit
	if mp.config.AncestorLimit > 0 {
		ancestorLimit = mp.config.AncestorLimit
	}
	descendantLimit := DefaultDescendantLimit
	if mp.config.DescendantLimit > 0 {
		descendantLimit = mp.config.DescendantLimit
	}
	ancestorSizeKvB := DefaultAncestorSizeLimitKvB
	if mp.config.AncestorSizeLimitKvB > 0 {
		ancestorSizeKvB = mp.config.AncestorSizeLimitKvB
	}
	descendantSizeKvB := DefaultDescendantSizeLimitKvB
	if mp.config.DescendantSizeLimitKvB > 0 {
		descendantSizeKvB = mp.config.DescendantSizeLimitKvB
	}

	// Ancestor limit: candidate + union of ancestor-sets of its mempool parents.
	// Build the union by visiting each parent, then expanding via Depends.
	ancestorSet := make(map[wire.Hash256]bool)
	var addAncestors func(hash wire.Hash256)
	addAncestors = func(hash wire.Hash256) {
		if ancestorSet[hash] {
			return
		}
		entry, ok := mp.pool[hash]
		if !ok {
			return
		}
		ancestorSet[hash] = true
		for _, parent := range entry.Depends {
			addAncestors(parent)
		}
	}
	for _, in := range tx.TxIn {
		addAncestors(in.PreviousOutPoint.Hash)
	}
	// |ancestorSet| is the number of distinct in-mempool ancestors. +1 for self.
	// Matches Core CalculateMemPoolAncestors self-counts-as-ancestor convention.
	selfPlusAncestors := len(ancestorSet) + 1
	if selfPlusAncestors > ancestorLimit {
		return fmt.Errorf("%w: %d > %d", ErrTooManyAncestors,
			selfPlusAncestors, ancestorLimit)
	}

	// Ancestor SIZE limit (Core DEFAULT_ANCESTOR_SIZE_LIMIT_KVB, 101 kvB):
	// sum of vsizes of all ancestors plus the candidate.
	// Use math.MaxInt64 sentinel when the KvB limit is math.MaxInt (NoLimits mode)
	// to avoid int64 overflow from int64(math.MaxInt)*1000.
	var maxAncestorBytes int64
	if ancestorSizeKvB >= math.MaxInt/vbytesPerKvB {
		maxAncestorBytes = math.MaxInt64
	} else {
		maxAncestorBytes = int64(ancestorSizeKvB) * vbytesPerKvB
	}
	var ancestorBytes int64
	for ancHash := range ancestorSet {
		if entry, ok := mp.pool[ancHash]; ok {
			ancestorBytes += entry.Size
		}
	}
	totalAncestorBytes := ancestorBytes + candidateVSize
	if maxAncestorBytes < math.MaxInt64 && totalAncestorBytes > maxAncestorBytes {
		return fmt.Errorf("%w: %d vB > %d vB",
			ErrAncestorSizeTooLarge, totalAncestorBytes, maxAncestorBytes)
	}

	// Descendant limit: for each in-mempool ancestor of the candidate, adding
	// the candidate would push that ancestor's descendant-set by one. Core
	// counts descendants-including-self; the candidate is a new descendant.
	// Matches Core CalculateMemPoolDescendants recursive walk.
	var maxDescendantBytes int64
	if descendantSizeKvB >= math.MaxInt/vbytesPerKvB {
		maxDescendantBytes = math.MaxInt64
	} else {
		maxDescendantBytes = int64(descendantSizeKvB) * vbytesPerKvB
	}
	for ancHash := range ancestorSet {
		descVisited := make(map[wire.Hash256]bool)
		descs := mp.collectDescendantsLocked(ancHash, descVisited)
		// descs excludes ancHash itself. After adding candidate, the count
		// including self becomes len(descs) + 1 (self) + 1 (new candidate).
		selfPlusDescs := len(descs) + 2
		if selfPlusDescs > descendantLimit {
			return fmt.Errorf("%w: ancestor %s would have %d descendants > %d",
				ErrTooManyDescendants, ancHash, selfPlusDescs,
				descendantLimit)
		}

		// Descendant SIZE limit: ancestor.Size + sum(descendant vsizes) + candidate.
		if maxDescendantBytes < math.MaxInt64 {
			var descBytes int64
			if anc, ok := mp.pool[ancHash]; ok {
				descBytes = anc.Size
			}
			for _, dHash := range descs {
				if d, ok := mp.pool[dHash]; ok {
					descBytes += d.Size
				}
			}
			descBytes += candidateVSize
			if descBytes > maxDescendantBytes {
				return fmt.Errorf("%w: ancestor %s would have descendant size %d vB > %d vB",
					ErrDescendantSizeTooLarge, ancHash, descBytes, maxDescendantBytes)
			}
		}
	}
	return nil
}

// RemoveTransaction removes a transaction and all its descendants from the mempool.
func (mp *Mempool) RemoveTransaction(txHash wire.Hash256) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.removeWithDescendantsLocked(txHash)
}

// removeWithDescendantsLocked removes a transaction and all descendants.
// Must be called with mu held.
func (mp *Mempool) removeWithDescendantsLocked(txHash wire.Hash256) {
	visited := make(map[wire.Hash256]bool)
	descendants := mp.collectDescendantsLocked(txHash, visited)

	// Remove descendants first (children before parents for proper cleanup)
	// Reverse order to remove children first
	for i := len(descendants) - 1; i >= 0; i-- {
		mp.removeSingleTxLocked(descendants[i])
	}

	// Remove the transaction itself
	mp.removeSingleTxLocked(txHash)
}

// removeSingleTxLocked removes a single transaction without touching descendants.
// Must be called with mu held.
func (mp *Mempool) removeSingleTxLocked(txHash wire.Hash256) {
	entry, ok := mp.pool[txHash]
	if !ok {
		return
	}

	// Remove from outpoints map
	for _, in := range entry.Tx.TxIn {
		delete(mp.outpoints, in.PreviousOutPoint)
	}

	// Update parent's SpentBy lists
	for _, parentHash := range entry.Depends {
		if parent, ok := mp.pool[parentHash]; ok {
			parent.SpentBy = removeHash(parent.SpentBy, txHash)
			// Update parent's descendant tracking
			parent.DescendantFee -= entry.Fee
			parent.DescendantSize -= entry.Size
		}
	}

	// Update total size
	mp.totalSize -= entry.Size

	// Remove from cluster manager
	mp.clusters.RemoveTransaction(txHash)

	// Remove from pool
	delete(mp.pool, txHash)
}

// removeHash removes a hash from a slice.
func removeHash(slice []wire.Hash256, hash wire.Hash256) []wire.Hash256 {
	result := make([]wire.Hash256, 0, len(slice))
	for _, h := range slice {
		if h != hash {
			result = append(result, h)
		}
	}
	return result
}

// GetTransaction returns a transaction from the mempool, or nil if not found.
func (mp *Mempool) GetTransaction(txHash wire.Hash256) *wire.MsgTx {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if entry, ok := mp.pool[txHash]; ok {
		return entry.Tx
	}
	return nil
}

// GetEntry returns a transaction entry from the mempool, or nil if not found.
func (mp *Mempool) GetEntry(txHash wire.Hash256) *TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.pool[txHash]
}

// GetAncestors returns the ancestor transaction hashes for the given transaction.
// The returned list does not include txHash itself.
func (mp *Mempool) GetAncestors(txHash wire.Hash256) []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if _, ok := mp.pool[txHash]; !ok {
		return nil
	}
	visited := make(map[wire.Hash256]bool)
	return mp.collectAncestorsLocked(txHash, visited)
}

// GetDescendants returns the descendant transaction hashes for the given transaction.
// The returned list does not include txHash itself.
func (mp *Mempool) GetDescendants(txHash wire.Hash256) []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if _, ok := mp.pool[txHash]; !ok {
		return nil
	}
	visited := make(map[wire.Hash256]bool)
	return mp.collectDescendantsLocked(txHash, visited)
}

// HasTransaction returns true if the transaction is in the mempool.
func (mp *Mempool) HasTransaction(txHash wire.Hash256) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	_, ok := mp.pool[txHash]
	return ok
}

// GetTxByWTxid returns the mempool transaction with the given witness txid,
// or nil if no such transaction is in the mempool. Used by BIP-331 package
// relay to satisfy "getpkgtxns" requests.
//
// Implementation note: the mempool indexes by txid, not wtxid, so this is a
// linear scan. BIP-331 caps a single getpkgtxns at 25 wtxids, so the worst
// case is 25 * |mempool| comparisons, which is acceptable for the package
// relay use case (peer-driven, rate-limited).
func (mp *Mempool) GetTxByWTxid(wtxid wire.Hash256) *wire.MsgTx {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	for _, entry := range mp.pool {
		if entry.Tx.WTxHash() == wtxid {
			return entry.Tx
		}
	}
	return nil
}

// Count returns the number of transactions in the mempool.
func (mp *Mempool) Count() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.pool)
}

// TotalSize returns the total virtual size of mempool transactions in bytes.
func (mp *Mempool) TotalSize() int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.totalSize
}

// GetAllTxHashes returns all transaction hashes in the mempool.
func (mp *Mempool) GetAllTxHashes() []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	hashes := make([]wire.Hash256, 0, len(mp.pool))
	for hash := range mp.pool {
		hashes = append(hashes, hash)
	}
	return hashes
}

// GetAllTransactions returns all transactions in the mempool.
// Used by compact block reconstruction.
func (mp *Mempool) GetAllTransactions() []*wire.MsgTx {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txs := make([]*wire.MsgTx, 0, len(mp.pool))
	for _, entry := range mp.pool {
		txs = append(txs, entry.Tx)
	}
	return txs
}

// GetSortedByFeeRate returns transactions sorted by fee rate (highest first).
// Used by block template construction.
func (mp *Mempool) GetSortedByFeeRate() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FeeRate > entries[j].FeeRate
	})

	return entries
}

// GetSortedByAncestorFeeRate returns transactions sorted by ancestor fee rate (highest first).
// This is the correct metric for CPFP-aware mining.
// Deprecated: Use GetChunksForMining for cluster-based optimal ordering.
func (mp *Mempool) GetSortedByAncestorFeeRate() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].AncestorFeeRate() > entries[j].AncestorFeeRate()
	})

	return entries
}

// GetChunksForMining returns all transaction chunks sorted by feerate (highest first).
// This provides optimal ordering for block template construction using cluster mempool.
// Chunks respect transaction dependencies - including a chunk means including all its transactions.
func (mp *Mempool) GetChunksForMining() []MiningChunk {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetChunksForMining()
}

// GetTransactionsForMining returns transactions in optimal mining order.
// Uses cluster linearization for globally optimal transaction ordering.
func (mp *Mempool) GetTransactionsForMining() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	chunks := mp.clusters.GetChunksForMining()
	var result []*TxEntry

	for _, mchunk := range chunks {
		// Get txids for this chunk from the cluster
		idxToHash := make(map[int]wire.Hash256)
		for txHash, idx := range mchunk.Cluster.Transactions {
			idxToHash[idx] = txHash
		}

		for _, idx := range mchunk.Chunk.Txs {
			if txHash, ok := idxToHash[idx]; ok {
				if entry, ok := mp.pool[txHash]; ok {
					result = append(result, entry)
				}
			}
		}
	}

	return result
}

// GetCluster returns the cluster containing the specified transaction.
func (mp *Mempool) GetCluster(txHash wire.Hash256) *Cluster {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetCluster(txHash)
}

// GetAllClusters returns all transaction clusters in the mempool.
func (mp *Mempool) GetAllClusters() []*Cluster {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetAllClusters()
}

// CountDistinctClusters counts how many distinct clusters contain the given transactions.
// Used for RBF validation with cluster mempool.
func (mp *Mempool) CountDistinctClusters(txids []wire.Hash256) int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.CountDistinctClusters(txids)
}

// CheckSpend checks if an outpoint is already spent by a mempool transaction.
// Returns the spending transaction hash, or nil if not spent.
func (mp *Mempool) CheckSpend(outpoint wire.OutPoint) *wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if txHash, ok := mp.outpoints[outpoint]; ok {
		return &txHash
	}
	return nil
}

// trackPackageRemovedLocked updates the rolling minimum fee rate when a chunk
// is evicted from the mempool.  The rate is set to the removed chunk's feerate
// (in sat/kvB) if that is higher than the current floor.  Also clears
// blockSinceLastRollingFeeBump so subsequent calls to getMinFeeRateLocked
// do not decay the rate immediately.
//
// Core: txmempool.cpp:853-859 (CTxMemPool::trackPackageRemoved).
// Must be called with mu held.
func (mp *Mempool) trackPackageRemovedLocked(feeRateSatKvB float64) {
	if feeRateSatKvB > mp.rollingMinimumFeeRate {
		mp.rollingMinimumFeeRate = feeRateSatKvB
		mp.blockSinceLastRollingFeeBump = false
	}
}

// maybeEvictLocked evicts transactions if the mempool is too large.
// Uses cluster-based eviction: removes the lowest-feerate chunk from the worst
// cluster.  After each eviction the rolling minimum fee rate is bumped via
// trackPackageRemovedLocked so that subsequent adds must pay incremental relay
// fee above the evicted chunk's rate.
// Core: txmempool.cpp:861-911 (CTxMemPool::TrimToSize).
// Must be called with mu held.
func (mp *Mempool) maybeEvictLocked() {
	for mp.totalSize > mp.config.MaxSize && len(mp.pool) > 0 {
		// Use cluster-based eviction: find the worst chunk across all clusters
		worstCluster, worstChunk := mp.clusters.GetWorstChunkForEviction()

		if worstCluster == nil || worstChunk == nil {
			// Fallback to old behavior if no clusters
			var worst *TxEntry
			worstRate := math.MaxFloat64

			for _, entry := range mp.pool {
				rate := entry.DescendantFeeRate()
				if rate < worstRate {
					worstRate = rate
					worst = entry
				}
			}

			if worst == nil {
				break
			}

			// Bump rolling minimum: feerate of removed tx + incremental relay fee.
			// Core: txmempool.cpp:876-878.
			removedRateKvB := worst.DescendantFeeRate() * 1000
			mp.trackPackageRemovedLocked(removedRateKvB + float64(mp.config.IncrementalRelayFee))

			mp.removeWithDescendantsLocked(worst.TxHash)
			continue
		}

		// Compute the feerate for the worst chunk (total fee / total vsize * 1000).
		var chunkFee int64
		var chunkSize int64
		idxToHash := make(map[int]wire.Hash256)
		for txHash, idx := range worstCluster.Transactions {
			idxToHash[idx] = txHash
		}
		for _, idx := range worstChunk.Txs {
			if txHash, ok := idxToHash[idx]; ok {
				if entry, ok := mp.pool[txHash]; ok {
					chunkFee += entry.Fee
					chunkSize += entry.Size
				}
			}
		}

		// Bump rolling minimum: chunk feerate + incremental relay fee.
		// Core: txmempool.cpp:870-878 (removed += incremental_relay_feerate;
		// trackPackageRemoved(removed)).
		if chunkSize > 0 {
			chunkRateKvB := float64(chunkFee) / float64(chunkSize) * 1000
			mp.trackPackageRemovedLocked(chunkRateKvB + float64(mp.config.IncrementalRelayFee))
		}

		// Remove all transactions in the worst chunk
		for _, idx := range worstChunk.Txs {
			if txHash, ok := idxToHash[idx]; ok {
				mp.removeWithDescendantsLocked(txHash)
			}
		}
	}
}

// Orphan pool management

// addOrphanLocked adds a transaction to the orphan pool.
// Must be called with mu held.
func (mp *Mempool) addOrphanLocked(txHash wire.Hash256, tx *wire.MsgTx, missingOuts []wire.OutPoint) {
	// Check if already in orphan pool
	if _, ok := mp.orphans[txHash]; ok {
		return
	}

	// Evict random orphan if pool is full
	if len(mp.orphans) >= mp.config.MaxOrphanTxs {
		mp.evictRandomOrphanLocked()
	}

	mp.orphans[txHash] = &orphanEntry{
		tx:         tx,
		txHash:     txHash,
		addedTime:  time.Now(),
		missingOut: missingOuts,
	}
}

// evictRandomOrphanLocked removes a random orphan from the pool.
// Must be called with mu held.
func (mp *Mempool) evictRandomOrphanLocked() {
	if len(mp.orphans) == 0 {
		return
	}

	// First try to evict expired orphans (older than OrphanTxExpireTime)
	expiry := time.Now().Add(-OrphanTxExpireTime)
	for hash, orphan := range mp.orphans {
		if orphan.addedTime.Before(expiry) {
			delete(mp.orphans, hash)
			return
		}
	}

	// No expired orphans, pick a random one
	idx := rand.Intn(len(mp.orphans))
	i := 0
	for hash := range mp.orphans {
		if i == idx {
			delete(mp.orphans, hash)
			return
		}
		i++
	}
}

// processOrphansLocked checks if any orphans can now be promoted to the mempool.
// Must be called with mu held.
func (mp *Mempool) processOrphansLocked(newTxHash wire.Hash256) {
	entry, ok := mp.pool[newTxHash]
	if !ok {
		return
	}

	// Find orphans that depend on outputs of the new transaction
	var toProcess []*orphanEntry
	for _, orphan := range mp.orphans {
		for i, missing := range orphan.missingOut {
			if missing.Hash == newTxHash && int(missing.Index) < len(entry.Tx.TxOut) {
				// This missing output is now available
				orphan.missingOut = append(orphan.missingOut[:i], orphan.missingOut[i+1:]...)
				break
			}
		}
		if len(orphan.missingOut) == 0 {
			toProcess = append(toProcess, orphan)
		}
	}

	// Promote orphans that have all inputs now
	for _, orphan := range toProcess {
		delete(mp.orphans, orphan.txHash)

		// Unlock and relock to avoid deadlock during recursive AddTransaction
		mp.mu.Unlock()
		_ = mp.AddTransaction(orphan.tx) // Ignore errors, orphan might still be invalid
		mp.mu.Lock()
	}
}

// ExpireOrphans removes orphans that have been in the pool longer than
// OrphanTxExpireTime.  Matches Bitcoin Core's ORPHAN_TX_EXPIRE_TIME (20
// minutes).  Called periodically by the main loop — see the orphanExpireTicker
// goroutine in cmd/blockbrew/main.go.
func (mp *Mempool) ExpireOrphans() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	expiry := time.Now().Add(-OrphanTxExpireTime)
	for hash, orphan := range mp.orphans {
		if orphan.addedTime.Before(expiry) {
			delete(mp.orphans, hash)
		}
	}
}

// OrphanCount returns the number of orphan transactions.
func (mp *Mempool) OrphanCount() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.orphans)
}

// Block connection/disconnection

// BlockConnected removes transactions that were included in a new block.
// Also arms the rolling-fee decay timer (blockSinceLastRollingFeeBump = true)
// so GetMinFeeRate will decay the rate back toward zero over the next 12 hours.
// Core: txmempool.cpp:405-431 (removeForBlock sets lastRollingFeeUpdate +
// blockSinceLastRollingFeeBump = true).
func (mp *Mempool) BlockConnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Increment chain height
	mp.chainHeight++

	// Remove confirmed transactions
	for _, tx := range block.Transactions {
		txHash := tx.TxHash()
		mp.removeSingleTxLocked(txHash)

		// Also remove conflicting transactions (double spends)
		for _, in := range tx.TxIn {
			if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
				mp.removeWithDescendantsLocked(spendingTx)
			}
		}
	}

	// Arm the rolling-fee decay timer.  Core resets lastRollingFeeUpdate to
	// GetTime() here; we do the same so the 10-second cooldown in
	// getMinFeeRateLocked is measured from the block arrival time, not from
	// the last call to GetMinFeeRate.
	mp.lastRollingFeeUpdate = time.Now().Unix()
	mp.blockSinceLastRollingFeeBump = true
}

// BlockDisconnected re-adds transactions from a disconnected block
// (if they are still valid).
func (mp *Mempool) BlockDisconnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	mp.chainHeight--
	mp.mu.Unlock()

	// Re-add transactions from the disconnected block (skip coinbase)
	for i, tx := range block.Transactions {
		if i == 0 {
			continue // Skip coinbase
		}
		_ = mp.AddTransaction(tx) // Ignore errors
	}
}

// Expire removes transactions that were added before cutoff, along with all of
// their in-mempool descendants.  Returns the number of transactions removed.
// Callers typically pass (time.Now() - DefaultMempoolExpiryHours * time.Hour).
//
// Core: txmempool.cpp:811-827 (CTxMemPool::Expire).
func (mp *Mempool) Expire(cutoff time.Time) int {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Collect all entries added before cutoff.
	var toExpire []wire.Hash256
	for txHash, entry := range mp.pool {
		if entry.Time.Before(cutoff) {
			toExpire = append(toExpire, txHash)
		}
	}

	// For each expired tx, also collect its in-mempool descendants so they
	// are removed together.  Core uses CalculateDescendants here.
	visited := make(map[wire.Hash256]bool)
	stage := make([]wire.Hash256, 0)
	for _, txHash := range toExpire {
		if !visited[txHash] {
			descs := mp.collectDescendantsLocked(txHash, visited)
			stage = append(stage, descs...)
			stage = append(stage, txHash)
			visited[txHash] = true
		}
	}

	// Remove collected transactions.
	for _, txHash := range stage {
		mp.removeSingleTxLocked(txHash)
	}
	return len(stage)
}

// RemoveForReorg evicts mempool transactions that are no longer valid after a
// chain reorganisation.  A transaction becomes invalid when:
//
//  (a) It is non-final at the new chain tip (nLockTime / BIP-68 sequence locks
//      no longer satisfied at the new tip height + median-time-past).
//  (b) It directly spends a coinbase output that has become immature again
//      (fewer than CoinbaseMaturity = 100 confirmations at the new tip).
//
// All descendants of an invalid transaction are also removed.
//
// This mirrors Core's CTxMemPool::removeForReorg (txmempool.cpp:360-386).
// The function is a no-op when ChainState is not wired; in that case the
// caller is responsible for validity.
func (mp *Mempool) RemoveForReorg() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if mp.config.ChainState == nil {
		return 0
	}

	tipHeight := mp.config.ChainState.TipHeight()
	tipMTP := uint32(mp.config.ChainState.TipMTP())

	var invalid []wire.Hash256
	for txHash, entry := range mp.pool {
		if mp.txInvalidAtTip(entry.Tx, tipHeight, tipMTP) {
			invalid = append(invalid, txHash)
		}
	}

	visited := make(map[wire.Hash256]bool)
	stage := make([]wire.Hash256, 0)
	for _, txHash := range invalid {
		if !visited[txHash] {
			descs := mp.collectDescendantsLocked(txHash, visited)
			stage = append(stage, descs...)
			stage = append(stage, txHash)
			visited[txHash] = true
		}
	}

	for _, txHash := range stage {
		mp.removeSingleTxLocked(txHash)
	}
	return len(stage)
}

// txInvalidAtTip reports whether tx must be evicted after a reorg to the
// current chain tip.
//
// Two conditions checked (Core: txmempool.cpp:360-386, check_final_and_mature
// callback passed to removeForReorg):
//  1. Non-final: IsFinalTx fails at (tipHeight+1, tipMTP).
//     Core uses the *next* block's height/time to match the mempool-accept gate.
//  2. Immature coinbase spend: any input that spends a coinbase output with
//     fewer than CoinbaseMaturity (100) confirmations at the new tip.
//
// Must be called with mp.mu held.
func (mp *Mempool) txInvalidAtTip(tx *wire.MsgTx, tipHeight int32, tipMTP uint32) bool {
	// Gate 1 — non-final tx.
	// Core evaluates at nBlockHeight = active_chain.Height()+1 and
	// nBlockTime = active_chain.Tip()->GetMedianTimePast().
	if !consensus.IsFinalTx(tx, tipHeight+1, tipMTP) {
		return true
	}

	// Gate 2 — immature coinbase spend.
	// A confirmed coinbase output at height H has (tipHeight - H + 1)
	// confirmations.  It is spendable when that value >= CoinbaseMaturity.
	if mp.utxoSet != nil {
		for _, in := range tx.TxIn {
			utxo := mp.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil && utxo.IsCoinbase {
				confirmations := tipHeight - utxo.Height + 1
				if confirmations < consensus.CoinbaseMaturity {
					return true
				}
			}
		}
	}

	return false
}

// Fee estimation

// EstimateFee returns the estimated fee rate (sat/vB) for confirmation within targetBlocks.
// Uses a simple heuristic based on current mempool state.
func (mp *Mempool) EstimateFee(targetBlocks int) float64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if len(mp.pool) == 0 {
		// Empty mempool, return minimum fee rate
		return float64(mp.config.MinRelayFeeRate) / 1000
	}

	// Sort by fee rate
	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FeeRate > entries[j].FeeRate
	})

	// Estimate how many transactions can fit in targetBlocks blocks
	// Assume ~4MB of transactions per block (4,000,000 WU / 4 = 1,000,000 vB)
	targetVSize := int64(targetBlocks) * 1_000_000

	var cumSize int64
	for _, entry := range entries {
		cumSize += entry.Size
		if cumSize >= targetVSize {
			return entry.FeeRate
		}
	}

	// All mempool fits, return minimum fee rate
	return float64(mp.config.MinRelayFeeRate) / 1000
}

// Utility functions

// CalcMinFee calculates the minimum fee for a transaction of given vsize.
func (mp *Mempool) CalcMinFee(vsize int64) int64 {
	return (vsize * mp.config.MinRelayFeeRate + 999) / 1000 // Round up
}

// GetMinFeeRate returns the current dynamic minimum fee rate in sat/kvB.
// This accounts for mempool fullness - when the mempool is full, the minimum
// fee rate increases to the lowest-feerate transaction plus the incremental relay fee.
// This value should be broadcast to peers via feefilter (BIP133).
func (mp *Mempool) GetMinFeeRate() int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.getMinFeeRateLocked()
}

// getMinFeeRateLocked returns the current dynamic minimum fee rate in sat/kvB.
// It implements the Core rolling-fee halflife decay:
//
//  1. If no block has been connected since the last eviction
//     (blockSinceLastRollingFeeBump is false), or the rolling rate is zero,
//     return the stored rate without decay.
//  2. Otherwise, if more than 10 seconds have elapsed since the last update,
//     decay the rate by pow(2, elapsed/halflife) where halflife is:
//     - 12 h (base) when mempool is >= sizelimit/2,
//     - 6 h (halved) when mempool is between sizelimit/4 and sizelimit/2,
//     - 3 h (quartered) when mempool is < sizelimit/4.
//  3. If the decayed rate falls below incremental_relay_feerate/2, zero it.
//  4. Return max(decayed_rate, incremental_relay_feerate), but always at
//     least config.MinRelayFeeRate.
//
// Core: txmempool.cpp:829-851 (CTxMemPool::GetMinFee).
// Must be called with mp.mu held.
func (mp *Mempool) getMinFeeRateLocked() int64 {
	incrementalKvB := float64(mp.config.IncrementalRelayFee)

	// No decay while blockSinceLastRollingFeeBump is false (just evicted).
	if !mp.blockSinceLastRollingFeeBump || mp.rollingMinimumFeeRate == 0 {
		rolling := int64(math.Round(mp.rollingMinimumFeeRate))
		return max64(rolling, mp.config.MinRelayFeeRate)
	}

	now := time.Now().Unix()
	if now > mp.lastRollingFeeUpdate+10 {
		// Choose halflife based on current mempool fullness.
		// Core: txmempool.cpp:836-840.
		halflife := rollingFeeHalflife
		sizelimit := mp.config.MaxSize
		if mp.totalSize*4 < sizelimit { // < sizelimit/4
			halflife /= 4
		} else if mp.totalSize*2 < sizelimit { // < sizelimit/2
			halflife /= 2
		}

		elapsed := float64(now - mp.lastRollingFeeUpdate)
		mp.rollingMinimumFeeRate = mp.rollingMinimumFeeRate / math.Pow(2.0, elapsed/halflife)
		mp.lastRollingFeeUpdate = now

		// Zero out when decayed below incremental_relay_feerate/2.
		// Core: txmempool.cpp:845-848.
		if mp.rollingMinimumFeeRate < incrementalKvB/2 {
			mp.rollingMinimumFeeRate = 0
			return mp.config.MinRelayFeeRate
		}
	}

	// Return max(rollingMinimumFeeRate, incremental_relay_feerate), but at
	// least MinRelayFeeRate.  Core: txmempool.cpp:850.
	rolling := int64(math.Round(mp.rollingMinimumFeeRate))
	incremental := int64(math.Round(incrementalKvB))
	result := rolling
	if incremental > result {
		result = incremental
	}
	if mp.config.MinRelayFeeRate > result {
		result = mp.config.MinRelayFeeRate
	}
	return result
}

// max64 returns the larger of a and b.
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// GetMinFee returns the minimum fee required for a transaction of given vsize.
// This uses the dynamic minimum fee rate (accounting for mempool fullness).
func (mp *Mempool) GetMinFee(vsize int64) int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	minRate := mp.getMinFeeRateLocked()
	// Convert from sat/kvB to satoshis for this transaction size
	return (minRate * vsize + 999) / 1000 // Round up
}

// GetRawMempool returns a map of txid -> fee rate for all mempool transactions.
func (mp *Mempool) GetRawMempool() map[wire.Hash256]float64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	result := make(map[wire.Hash256]float64, len(mp.pool))
	for hash, entry := range mp.pool {
		result[hash] = entry.FeeRate
	}
	return result
}

// Clear removes all transactions from the mempool.
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.pool = make(map[wire.Hash256]*TxEntry)
	mp.outpoints = make(map[wire.OutPoint]wire.Hash256)
	mp.orphans = make(map[wire.Hash256]*orphanEntry)
	mp.totalSize = 0
	mp.clusters.Clear()
}

// checkRBFLocked validates whether a replacement transaction satisfies BIP125 rules.
// Must be called with mu held.
//
// Gates enforced (mirroring Bitcoin Core):
//   1. Conflicting tx (or any of its in-mempool ancestors) signals RBF.
//      Core: IsRBFOptIn → SignalsOptInRBF + ancestor walk (rbf.cpp:24-50,
//      util/rbf.cpp:9-17).
//   2. Replacement must not introduce new unconfirmed inputs.
//      Core: checkRBFNoNewUnconfirmedInputsLocked (validation.cpp, BIP-125 Rule 2).
//   3. Replacement's in-mempool ancestors must not overlap with direct conflicts
//      (replacement cannot spend an output of the tx it replaces).
//      Core: EntriesAndTxidsDisjoint (rbf.cpp:85-98, validation.cpp:1356).
//   4. Rule #5: total evicted transactions ≤ MAX_REPLACEMENT_CANDIDATES (100).
//      Core: GetEntriesForConflicts (rbf.cpp:64-75).
//   5. Rule #3: replacement_fees >= original_fees (rbf.cpp:109-112).
//   6. Rule #4: additional_fees >= incremental_relay_fee × replacement_vsize
//      (rbf.cpp:114-123). Uses IncrementalRelayFee (not MinRelayFeeRate).
func (mp *Mempool) checkRBFLocked(newTx *wire.MsgTx, conflicting map[wire.Hash256]bool, totalInputValue int64) error {
	// Gate 1 + Gate 2: BIP-125 Rule 1 — each conflicting tx must signal
	// opt-in RBF. A conflicting tx is considered opt-in if:
	//   (a) it directly signals (any input nSequence <= 0xfffffffd), OR
	//   (b) any of its in-mempool ancestors signals.
	// Mirrors Bitcoin Core IsRBFOptIn (rbf.cpp:24-50) which checks the tx
	// itself first, then walks mempool ancestors via CalculateMemPoolAncestors.
	for txHash := range conflicting {
		entry, ok := mp.pool[txHash]
		if !ok {
			continue
		}
		if !signalsRBF(entry.Tx) {
			// Check if any in-mempool ancestor signals RBF (inherited opt-in).
			// Core rbf.cpp:39-48.
			ancestorSignals := false
			visited := make(map[wire.Hash256]bool)
			for _, ancHash := range mp.collectAncestorsLocked(txHash, visited) {
				if ancEntry, ok := mp.pool[ancHash]; ok && signalsRBF(ancEntry.Tx) {
					ancestorSignals = true
					break
				}
			}
			if !ancestorSignals {
				return fmt.Errorf("%w: tx %s does not signal RBF (neither directly nor via ancestor)",
					ErrRBFNotSignaled, txHash)
			}
		}
	}

	// Gate 3: BIP-125 Rule 2 — replacement must not introduce new unconfirmed
	// inputs that were not already in the conflicting txs' ancestor set.
	// Core: checkRBFNoNewUnconfirmedInputsLocked (validation.cpp).
	if err := mp.checkRBFNoNewUnconfirmedInputsLocked(newTx, conflicting); err != nil {
		return err
	}

	// Gate 4: EntriesAndTxidsDisjoint — the replacement's in-mempool ancestors
	// must not overlap with the direct conflicts. A replacement that spends an
	// output of a tx it is trying to replace is logically inconsistent.
	// Core: rbf.cpp:85-98, called from validation.cpp:1356.
	{
		visited := make(map[wire.Hash256]bool)
		for _, in := range newTx.TxIn {
			parentHash := in.PreviousOutPoint.Hash
			if _, inMempool := mp.pool[parentHash]; !inMempool {
				continue
			}
			// Walk ancestors of the replacement tx.
			for _, ancHash := range mp.collectAncestorsLocked(parentHash, visited) {
				if conflicting[ancHash] {
					return fmt.Errorf("%w: %s spends conflicting transaction %s",
						ErrRBFAncestorConflict, newTx.TxHash(), ancHash)
				}
			}
			// Also check the direct parent itself.
			if conflicting[parentHash] {
				return fmt.Errorf("%w: %s spends conflicting transaction %s",
					ErrRBFAncestorConflict, newTx.TxHash(), parentHash)
			}
		}
	}

	// Collect all transactions that would be evicted (conflicts + their descendants).
	var totalConflictingFee int64
	var totalEvicted int

	for txHash := range conflicting {
		entry, ok := mp.pool[txHash]
		if !ok {
			continue
		}
		totalConflictingFee += entry.Fee
		totalEvicted++

		// Include descendants in fee sum and eviction count.
		visited := make(map[wire.Hash256]bool)
		descendants := mp.collectDescendantsLocked(txHash, visited)
		for _, descHash := range descendants {
			if descEntry, ok := mp.pool[descHash]; ok {
				totalConflictingFee += descEntry.Fee
				totalEvicted++
			}
		}
	}

	// Gate 5: BIP-125 Rule #5 — total evicted transactions must not exceed
	// MAX_REPLACEMENT_CANDIDATES (100). Mirrors GetEntriesForConflicts
	// (rbf.cpp:64-75). Core counts unique clusters; blockbrew counts individual
	// txs (equivalent for non-cluster-mempool deployments).
	if totalEvicted > MaxRBFReplacedTxs {
		return fmt.Errorf("%w: would evict %d transactions (max %d)",
			ErrRBFTooManyConflicts, totalEvicted, MaxRBFReplacedTxs)
	}

	// Calculate new transaction fee.
	var totalOutputValue int64
	for _, out := range newTx.TxOut {
		totalOutputValue += out.Value
	}
	newFee := totalInputValue - totalOutputValue

	// Gate 6a: BIP-125 Rule #3 — replacement_fees >= original_fees.
	// Core: rbf.cpp:109-112. Note: equal fees must PASS Rule 3 (the fee bump
	// to cover relay is enforced by Rule 4 below). Pre-fix blockbrew used
	// `<=` which incorrectly rejected equal-fee replacements.
	if newFee < totalConflictingFee {
		return fmt.Errorf("%w: rejecting replacement, less fees than conflicting txs; %d < %d",
			ErrRBFInsufficientFee, newFee, totalConflictingFee)
	}

	// Gate 6b: BIP-125 Rule #4 — additional_fees >= incremental_relay_fee × vsize.
	// Core: rbf.cpp:114-123. Uses IncrementalRelayFee (separate from
	// MinRelayFeeRate). Pre-fix blockbrew used MinRelayFeeRate here.
	weight := consensus.CalcTxWeight(newTx)
	newVSize := (weight + 3) / 4
	minFeeBump := (newVSize * mp.config.IncrementalRelayFee + 999) / 1000
	if newFee-totalConflictingFee < minFeeBump {
		return fmt.Errorf("%w: rejecting replacement, not enough additional fees to relay; %d < %d",
			ErrRBFInsufficientFee, newFee-totalConflictingFee, minFeeBump)
	}

	// Gate 7: ImprovesFeerateDiagram — the replacement must strictly improve
	// the mempool feerate diagram at every chunk boundary.
	// Core: rbf.cpp::ImprovesFeerateDiagram (Core 27+, cluster-mempool).
	// Build the full evicted set (conflicts + all descendants) to pass to the
	// diagram checker.
	evictedFull := make(map[wire.Hash256]bool, totalEvicted)
	for txHash := range conflicting {
		evictedFull[txHash] = true
		visited := make(map[wire.Hash256]bool)
		for _, descHash := range mp.collectDescendantsLocked(txHash, visited) {
			evictedFull[descHash] = true
		}
	}
	if err := mp.checkRBFImprovesFeerateDiagramLocked(newTx, evictedFull, newFee, int64(newVSize)); err != nil {
		return err
	}

	return nil
}

// signalsRBF returns true if the transaction signals BIP125 replaceability.
//
// A transaction opts in to RBF iff at least one input has
// nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd, SEQUENCE_FINAL−2).
// Mirrors `bitcoin-core/src/util/rbf.cpp::SignalsOptInRBF`.
//
// Crucially this is NOT `< SEQUENCE_FINAL`: nSequence == 0xfffffffe
// (the anti-fee-snipe value used by many wallets that have no RBF
// intent) must be treated as non-signaling.
func signalsRBF(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		if in.Sequence <= MaxBIP125RBFSequence {
			return true
		}
	}
	return false
}

// checkRBFNoNewUnconfirmedInputsLocked enforces BIP-125 Rule 2: every
// mempool-resident parent of the replacement transaction must either be
// one of the directly-conflicting txs, or a mempool ancestor of one of
// those conflicts. Confirmed (UTXO-set) inputs are always allowed. Must
// be called with mu held.
func (mp *Mempool) checkRBFNoNewUnconfirmedInputsLocked(
	newTx *wire.MsgTx,
	conflicting map[wire.Hash256]bool,
) error {
	// Build the closure: { conflict txids } ∪ { ancestors of each conflict }.
	allowed := make(map[wire.Hash256]bool, len(conflicting)*4)
	for cHash := range conflicting {
		allowed[cHash] = true
		visited := make(map[wire.Hash256]bool)
		for _, anc := range mp.collectAncestorsLocked(cHash, visited) {
			allowed[anc] = true
		}
	}

	// Any input whose previous-output hash is in the mempool but NOT in
	// the allowed closure is a "new unconfirmed input". Inputs that
	// reference confirmed UTXOs (i.e., outpoints not in mp.pool) are fine.
	for _, in := range newTx.TxIn {
		parentHash := in.PreviousOutPoint.Hash
		if _, inMempool := mp.pool[parentHash]; !inMempool {
			continue
		}
		if !allowed[parentHash] {
			return fmt.Errorf("%w: input %s:%d references unconfirmed parent %s "+
				"that is not a conflict or conflict-ancestor",
				ErrRBFNewUnconfirmedInput,
				parentHash, in.PreviousOutPoint.Index, parentHash)
		}
	}
	return nil
}

// checkRBFImprovesFeerateDiagramLocked checks that the replacement transaction
// strictly improves the mempool feerate diagram, mirroring Bitcoin Core's
// ImprovesFeerateDiagram / CalculateChunksForRBF (rbf.cpp, Core 27+).
//
// Algorithmic choice: "simulated cluster replacement"
//   - We build a *temporary* in-memory DepGraph for each affected cluster
//     (those containing a direct conflict or a descendant of a conflict).
//   - The "before" diagram is the FeerateDiagram produced by the existing
//     cluster chunks.
//   - The "after" diagram is produced by removing all evicted transactions
//     (conflicts + their descendants) and adding the replacement with its
//     computed fee/vsize, inheriting the in-cluster parents it retains.
//   - We require after.Compare(before) == 1, i.e. strictly better.
//
// This is equivalent to Core's CalculateChunksForRBF which does the same
// simulation via CTxMemPool::ChangeSet::AddedTxInfo / removed set.
//
// Must be called with mp.mu held (read or write).
func (mp *Mempool) checkRBFImprovesFeerateDiagramLocked(
	newTx *wire.MsgTx,
	evicted map[wire.Hash256]bool, // conflicts + all their descendants
	newFee int64,
	newVSize int64,
) error {
	// Collect the distinct set of clusters that are affected.
	affectedClusters := make(map[uint64]*Cluster)
	for txHash := range evicted {
		if c := mp.clusters.GetCluster(txHash); c != nil {
			affectedClusters[c.ID] = c
		}
	}

	// If no clusters are tracked (e.g. empty or single-tx mempool with no
	// cluster manager data), skip the diagram check — we cannot compute it.
	if len(affectedClusters) == 0 {
		return nil
	}

	// For each affected cluster, build before/after diagrams and compare.
	//
	// We concatenate all chunks across affected clusters into one combined
	// before/after diagram. This is conservative: the combined diagram is
	// dominated iff every individual cluster's diagram is dominated, because
	// chunks are already sorted in descending feerate order.
	var beforeChunks, afterChunks []Chunk

	for _, cluster := range affectedClusters {
		// --- BEFORE: current cluster chunks ---
		for _, ch := range cluster.GetChunks() {
			beforeChunks = append(beforeChunks, ch)
		}

		// --- AFTER: simulate removal of evicted txs + insertion of newTx ---
		//
		// Build a fresh DepGraph containing only the surviving transactions in
		// this cluster, then add newTx (if any of its inputs are in this cluster).

		// Step 1: identify surviving txs (cluster txs minus evicted).
		type simTx struct {
			txHash  wire.Hash256
			fee     int64
			size    int32
			origIdx int // index in cluster.DepGraph
		}
		var survivors []simTx
		for txHash, idx := range cluster.Transactions {
			if !evicted[txHash] {
				fr := cluster.DepGraph.FeeRate(idx)
				survivors = append(survivors, simTx{
					txHash:  txHash,
					fee:     fr.Fee,
					size:    fr.Size,
					origIdx: idx,
				})
			}
		}

		// Step 2: Check if newTx has any in-cluster parents (that survive).
		// A parent is in this cluster if one of newTx's inputs spends a tx in
		// the cluster that was NOT evicted.
		survivorSet := make(map[wire.Hash256]bool, len(survivors))
		for _, s := range survivors {
			survivorSet[s.txHash] = true
		}
		newTxParentsInCluster := false
		for _, in := range newTx.TxIn {
			if survivorSet[in.PreviousOutPoint.Hash] {
				newTxParentsInCluster = true
				break
			}
		}

		// If newTx has no parents in this cluster AND there are survivors, the
		// new tx will form its own new cluster later. We still need the after
		// diagram for survivors in this cluster to be at least as good as before.
		// newTx's contribution is added only to the cluster it actually joins.
		//
		// Determine whether newTx "joins" this cluster:
		// It joins if it has at least one parent (surviving) in this cluster,
		// OR if this is the sole affected cluster and newTx has no mempool parents
		// at all (i.e. it's a standalone replacement of a root tx).
		newTxJoinsCluster := newTxParentsInCluster
		if !newTxJoinsCluster && len(affectedClusters) == 1 {
			// Check if newTx has any surviving mempool parent at all.
			hasAnyMempoolParent := false
			for _, in := range newTx.TxIn {
				if _, inPool := mp.pool[in.PreviousOutPoint.Hash]; inPool {
					if !evicted[in.PreviousOutPoint.Hash] {
						hasAnyMempoolParent = true
						break
					}
				}
			}
			if !hasAnyMempoolParent {
				// newTx is a root in the cluster (replaces the root conflict).
				newTxJoinsCluster = true
			}
		}

		// Step 3: Build a simulated DepGraph for the after-state.
		simGraph := NewDepGraph()
		simIdxMap := make(map[wire.Hash256]int, len(survivors)+1) // txHash -> simIdx

		// Add survivors in topological order (parents before children).
		// We use the original topological order from the cluster's linearization.
		origLinear := cluster.GetLinearization() // already in topological order
		for _, origIdx := range origLinear {
			// Find txHash for this origIdx.
			var txHash wire.Hash256
			found := false
			for h, idx := range cluster.Transactions {
				if idx == origIdx {
					txHash = h
					found = true
					break
				}
			}
			if !found || !survivorSet[txHash] {
				continue
			}
			fr := cluster.DepGraph.FeeRate(origIdx)
			simIdx := simGraph.AddTransaction(fr)
			simIdxMap[txHash] = simIdx

			// Add dependencies to parents that are already in simGraph.
			var parentSet BitSet
			for _, in := range mp.pool[txHash].Tx.TxIn {
				if pSimIdx, ok := simIdxMap[in.PreviousOutPoint.Hash]; ok {
					parentSet.Set(pSimIdx)
				}
			}
			if parentSet.Any() {
				simGraph.AddDependencies(parentSet, simIdx)
			}
		}

		// Add newTx if it joins this cluster.
		if newTxJoinsCluster {
			newSimIdx := simGraph.AddTransaction(FeeFrac{Fee: newFee, Size: int32(newVSize)})
			if newSimIdx >= 0 {
				var parentSet BitSet
				for _, in := range newTx.TxIn {
					if pSimIdx, ok := simIdxMap[in.PreviousOutPoint.Hash]; ok {
						parentSet.Set(pSimIdx)
					}
				}
				if parentSet.Any() {
					simGraph.AddDependencies(parentSet, newSimIdx)
				}
			}
		}

		// Step 4: Compute after-chunks from the simulated DepGraph using the
		// same greedy linearisation algorithm as Cluster.recomputeLinearization.
		simCluster := &Cluster{
			ID:           cluster.ID,
			Transactions: make(map[wire.Hash256]int),
			DepGraph:     simGraph,
			dirty:        true,
		}
		for txHash, simIdx := range simIdxMap {
			simCluster.Transactions[txHash] = simIdx
		}
		for _, ch := range simCluster.GetChunks() {
			afterChunks = append(afterChunks, ch)
		}
	}

	// Sort both chunk slices in descending feerate order so the combined
	// feerate diagram is well-formed (monotonically non-increasing feerate).
	sortChunksDesc(beforeChunks)
	sortChunksDesc(afterChunks)

	before := NewFeerateDiagram(beforeChunks)
	after := NewFeerateDiagram(afterChunks)

	if after.Compare(before) != 1 {
		return ErrRBFFeerateDiagram
	}
	return nil
}

// sortChunksDesc sorts chunks in descending feerate order (highest feerate first).
func sortChunksDesc(chunks []Chunk) {
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].FeeRate.Compare(chunks[j].FeeRate) > 0
	})
}

// Ensure Mempool implements consensus.UTXOView
var _ consensus.UTXOView = (*Mempool)(nil)

// TxSerializeSize returns the serialized size of a transaction without witness.
func txSerializeSize(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	_ = tx.SerializeNoWitness(&buf)
	return int64(buf.Len())
}

// ============================================================================
// Package Validation
// ============================================================================

// IsTopoSortedPackage checks if the package is topologically sorted
// (parents appear before children).
func IsTopoSortedPackage(txns []*wire.MsgTx) bool {
	// Build a set of txids that appear later in the package
	laterTxids := make(map[wire.Hash256]bool)
	for i := len(txns) - 1; i >= 0; i-- {
		txid := txns[i].TxHash()
		// Check that no input spends a transaction that appears later
		for _, in := range txns[i].TxIn {
			if laterTxids[in.PreviousOutPoint.Hash] {
				return false
			}
		}
		laterTxids[txid] = true
	}
	return true
}

// IsConsistentPackage checks that no transactions in the package conflict
// (no duplicate txids, no inputs spending the same prevout).
func IsConsistentPackage(txns []*wire.MsgTx) bool {
	txids := make(map[wire.Hash256]bool)
	spentOutpoints := make(map[wire.OutPoint]bool)

	for _, tx := range txns {
		txid := tx.TxHash()

		// Check for duplicate txids
		if txids[txid] {
			return false
		}
		txids[txid] = true

		// Check for conflicting inputs
		for _, in := range tx.TxIn {
			if spentOutpoints[in.PreviousOutPoint] {
				return false
			}
			spentOutpoints[in.PreviousOutPoint] = true
		}
	}
	return true
}

// IsChildWithParents checks if the package is a valid child-with-unconfirmed-parents
// topology: all transactions except the last (child) must be direct parents of the child.
func IsChildWithParents(txns []*wire.MsgTx) bool {
	if len(txns) < 2 {
		return false
	}

	// The last transaction is the child
	child := txns[len(txns)-1]

	// Collect all txids the child references as inputs
	childInputTxids := make(map[wire.Hash256]bool)
	for _, in := range child.TxIn {
		childInputTxids[in.PreviousOutPoint.Hash] = true
	}

	// All parent transactions must be referenced by the child
	for i := 0; i < len(txns)-1; i++ {
		parentTxid := txns[i].TxHash()
		if !childInputTxids[parentTxid] {
			return false
		}
	}

	return true
}

// IsChildWithParentsTree is a stricter check: child-with-parents where
// parents don't depend on each other (tree structure, no inter-parent deps).
func IsChildWithParentsTree(txns []*wire.MsgTx) bool {
	if !IsChildWithParents(txns) {
		return false
	}

	// Check that no parent spends another parent's output
	parentTxids := make(map[wire.Hash256]bool)
	for i := 0; i < len(txns)-1; i++ {
		parentTxids[txns[i].TxHash()] = true
	}

	for i := 0; i < len(txns)-1; i++ {
		for _, in := range txns[i].TxIn {
			if parentTxids[in.PreviousOutPoint.Hash] {
				return false
			}
		}
	}

	return true
}

// CheckPackage performs context-free package validation.
func CheckPackage(txns []*wire.MsgTx) error {
	if len(txns) == 0 {
		return ErrPackageEmpty
	}

	if len(txns) > MaxPackageCount {
		return ErrPackageTooManyTxs
	}

	// Check total weight (only for multi-tx packages)
	if len(txns) > 1 {
		var totalWeight int64
		for _, tx := range txns {
			totalWeight += consensus.CalcTxWeight(tx)
		}
		if totalWeight > MaxPackageWeight {
			return ErrPackageTooLarge
		}
	}

	// Check for duplicates (via txid set)
	txids := make(map[wire.Hash256]bool)
	for _, tx := range txns {
		txid := tx.TxHash()
		if txids[txid] {
			return ErrPackageDuplicateTx
		}
		txids[txid] = true
	}

	// Check topological sorting
	if !IsTopoSortedPackage(txns) {
		return ErrPackageNotSorted
	}

	// Check for internal conflicts
	if !IsConsistentPackage(txns) {
		return ErrPackageConflict
	}

	return nil
}

// AcceptPackage validates and accepts a package of related transactions.
// The package must be in child-with-unconfirmed-parents topology.
// Returns detailed results for each transaction.
func (mp *Mempool) AcceptPackage(txns []*wire.MsgTx) (*PackageResult, error) {
	result := &PackageResult{
		TxResults: make(map[wire.Hash256]*TxAcceptResult),
	}

	// Context-free validation
	if err := CheckPackage(txns); err != nil {
		result.PackageError = err
		return result, err
	}

	// For multi-tx packages, verify child-with-parents topology
	if len(txns) > 1 && !IsChildWithParentsTree(txns) {
		result.PackageError = ErrPackageNotChildWithParents
		return result, ErrPackageNotChildWithParents
	}

	// Single-tx package is trivially valid topology
	if len(txns) == 1 {
		return mp.acceptSingleTxPackage(txns[0], result)
	}

	return mp.acceptMultiTxPackage(txns, result)
}

// acceptSingleTxPackage handles a single-transaction "package".
func (mp *Mempool) acceptSingleTxPackage(tx *wire.MsgTx, result *PackageResult) (*PackageResult, error) {
	txid := tx.TxHash()
	wtxid := tx.WTxHash()

	txResult := &TxAcceptResult{
		TxID:  txid,
		WTxID: wtxid,
	}
	result.TxResults[wtxid] = txResult

	// Check if already in mempool
	if mp.HasTransaction(txid) {
		txResult.AlreadyInMempool = true
		txResult.Accepted = true
		entry := mp.GetEntry(txid)
		if entry != nil {
			txResult.Fee = entry.Fee
			txResult.VSize = entry.Size
			txResult.EffectiveFeerate = entry.FeeRate
		}
		txResult.EffectiveIncludes = []wire.Hash256{wtxid}
		return result, nil
	}

	// Try to add the transaction
	if err := mp.AddTransaction(tx); err != nil {
		txResult.Error = err
		result.PackageError = err
		return result, err
	}

	// Transaction accepted
	txResult.Accepted = true
	entry := mp.GetEntry(txid)
	if entry != nil {
		txResult.Fee = entry.Fee
		txResult.VSize = entry.Size
		txResult.EffectiveFeerate = entry.FeeRate
		result.PackageFeerate = entry.FeeRate
	}
	txResult.EffectiveIncludes = []wire.Hash256{wtxid}

	return result, nil
}

// acceptMultiTxPackage handles multi-transaction package acceptance.
func (mp *Mempool) acceptMultiTxPackage(txns []*wire.MsgTx, result *PackageResult) (*PackageResult, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Track transactions that need package evaluation
	var toEvaluate []*wire.MsgTx
	var totalFee int64
	var totalVSize int64
	var allWtxids []wire.Hash256

	// First pass: try each transaction individually
	for _, tx := range txns {
		txid := tx.TxHash()
		wtxid := tx.WTxHash()

		txResult := &TxAcceptResult{
			TxID:  txid,
			WTxID: wtxid,
		}
		result.TxResults[wtxid] = txResult

		// Already in mempool?
		if entry, ok := mp.pool[txid]; ok {
			txResult.AlreadyInMempool = true
			txResult.Accepted = true
			txResult.Fee = entry.Fee
			txResult.VSize = entry.Size
			txResult.EffectiveFeerate = entry.FeeRate
			txResult.EffectiveIncludes = []wire.Hash256{wtxid}
			totalFee += entry.Fee
			totalVSize += entry.Size
			allWtxids = append(allWtxids, wtxid)
			continue
		}

		// Try to validate individually (without actually adding yet)
		fee, vsize, err := mp.validateTransactionLocked(tx, false)
		if err != nil {
			// Check if this is a retryable error (missing inputs or fee issues)
			if isRetryablePackageError(err) {
				// Defer to package evaluation
				toEvaluate = append(toEvaluate, tx)
				allWtxids = append(allWtxids, wtxid)
				continue
			}
			// Non-retryable error - fail the package
			txResult.Error = err
			result.PackageError = fmt.Errorf("transaction %s failed: %w", txid, err)
			return result, result.PackageError
		}

		// Transaction would be valid individually
		txResult.Fee = fee
		txResult.VSize = vsize
		txResult.EffectiveFeerate = float64(fee) / float64(vsize)
		totalFee += fee
		totalVSize += vsize
		allWtxids = append(allWtxids, wtxid)
		toEvaluate = append(toEvaluate, tx)
	}

	// Calculate package feerate
	if totalVSize > 0 {
		result.PackageFeerate = float64(totalFee) / float64(totalVSize)
	}

	// Check package feerate against minimum
	minFeeRate := float64(mp.config.MinRelayFeeRate) / 1000 // Convert to sat/vB
	if result.PackageFeerate < minFeeRate {
		result.PackageError = fmt.Errorf("%w: package feerate %.2f sat/vB < minimum %.2f sat/vB",
			ErrPackageInsufficientFee, result.PackageFeerate, minFeeRate)
		return result, result.PackageError
	}

	// Now validate and add all transactions that need package evaluation
	// We need to add them in order, making parent outputs available for children
	for _, tx := range toEvaluate {
		txid := tx.TxHash()
		wtxid := tx.WTxHash()
		txResult := result.TxResults[wtxid]

		// Skip if already processed
		if txResult.Accepted || txResult.AlreadyInMempool {
			continue
		}

		// Validate with package context (parent outputs now available)
		fee, vsize, err := mp.validateTransactionLocked(tx, true)
		if err != nil {
			txResult.Error = err
			result.PackageError = fmt.Errorf("transaction %s failed validation: %w", txid, err)
			// Rollback: remove any transactions we added
			mp.rollbackPackageLocked(toEvaluate[:indexOf(toEvaluate, tx)])
			return result, result.PackageError
		}

		// BIP-431 PackageTRUCChecks: enforce TRUC topology rules with the full
		// package context. Core: PackageTRUCChecks (truc_policy.cpp:57-169).
		pkgIdx := indexOf(toEvaluate, tx)
		sigopVsize := mp.trucSigopVsize(tx)
		if err := mp.packageTRUCChecks(tx, sigopVsize, toEvaluate, pkgIdx); err != nil {
			txResult.Error = err
			result.PackageError = fmt.Errorf("transaction %s failed TRUC package check: %w", txid, err)
			mp.rollbackPackageLocked(toEvaluate[:pkgIdx])
			return result, result.PackageError
		}

		// Add to mempool
		if err := mp.addTransactionLocked(tx, fee, vsize); err != nil {
			txResult.Error = err
			result.PackageError = fmt.Errorf("failed to add %s: %w", txid, err)
			mp.rollbackPackageLocked(toEvaluate[:indexOf(toEvaluate, tx)])
			return result, result.PackageError
		}

		txResult.Accepted = true
		txResult.Fee = fee
		txResult.VSize = vsize
		txResult.EffectiveFeerate = result.PackageFeerate
		txResult.EffectiveIncludes = allWtxids
	}

	// Update effective feerate for all transactions in the package
	for _, wtxid := range allWtxids {
		if txResult, ok := result.TxResults[wtxid]; ok {
			txResult.EffectiveFeerate = result.PackageFeerate
			txResult.EffectiveIncludes = allWtxids
		}
	}

	// Evict if needed
	mp.maybeEvictLocked()

	return result, nil
}

// validateTransactionLocked validates a transaction without adding it.
// If packageMode is true, allows looking up parent outputs from earlier package txs.
// Returns fee and vsize on success.
// Must be called with mu held.
func (mp *Mempool) validateTransactionLocked(tx *wire.MsgTx, packageMode bool) (int64, int64, error) {
	txHash := tx.TxHash()

	// Reject if already in mempool
	if _, ok := mp.pool[txHash]; ok {
		return 0, 0, ErrAlreadyInMempool
	}

	// Basic sanity checks
	if err := consensus.CheckTransactionSanity(tx); err != nil {
		return 0, 0, fmt.Errorf("sanity check failed: %w", err)
	}

	// Reject coinbase
	if consensus.IsCoinbaseTx(tx) {
		return 0, 0, ErrCoinbaseNotAllowed
	}

	// Check weight
	weight := consensus.CalcTxWeight(tx)
	if weight > consensus.MaxStandardTxWeight {
		return 0, 0, ErrTxTooLarge
	}
	vsize := (weight + 3) / 4

	// Gather inputs and check for conflicts
	var totalInputValue int64
	var missingInputs []wire.OutPoint

	for _, in := range tx.TxIn {
		// Check for double-spend in mempool
		if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			existingEntry := mp.pool[existingTxHash]
			if existingEntry != nil && !signalsRBF(existingEntry.Tx) {
				return 0, 0, ErrRBFNotSignaled
			}
		}

		// Look up the UTXO
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			missingInputs = append(missingInputs, in.PreviousOutPoint)
		} else {
			totalInputValue += utxo.Amount
		}
	}

	if len(missingInputs) > 0 {
		return 0, 0, fmt.Errorf("%w: %d missing inputs", ErrMissingInputs, len(missingInputs))
	}

	// Calculate fee
	var totalOutputValue int64
	for _, out := range tx.TxOut {
		totalOutputValue += out.Value
	}
	fee := totalInputValue - totalOutputValue
	if fee < 0 {
		return 0, 0, ErrNegativeFee
	}

	// Note: In package mode, we don't check individual feerate here
	// because the package aggregate feerate is used instead.
	if !packageMode {
		feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
		if int64(feeRate) < mp.config.MinRelayFeeRate {
			return 0, 0, fmt.Errorf("%w: %.1f sat/kvB below minimum %d sat/kvB",
				ErrInsufficientFee, feeRate, mp.config.MinRelayFeeRate)
		}
	}

	// Check dust
	for i, out := range tx.TxOut {
		if mp.isDust(out) {
			return 0, 0, fmt.Errorf("%w: output %d value %d", ErrDustOutput, i, out.Value)
		}
	}

	// Validate scripts
	flags := mp.getStandardScriptFlags()
	if err := mp.validateScriptsLocked(tx, flags); err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrScriptValidation, err)
	}

	// BIP-68 sequence-lock check (mirrors AddTransaction).
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		return 0, 0, err
	}

	// Ancestor/descendant chain limits (count + size).
	if err := mp.checkChainLimitsWithSizeLocked(tx, vsize); err != nil {
		return 0, 0, err
	}

	// BIP-431 TRUC checks (single-tx path, no package context).
	// Core: SingleTRUCChecks (truc_policy.cpp:171-261).
	if err := mp.singleTRUCChecks(tx, nil); err != nil {
		return 0, 0, err
	}

	return fee, vsize, nil
}

// addTransactionLocked adds a validated transaction to the mempool.
// Must be called with mu held.
func (mp *Mempool) addTransactionLocked(tx *wire.MsgTx, fee, vsize int64) error {
	txHash := tx.TxHash()

	entry := &TxEntry{
		Tx:             tx,
		TxHash:         txHash,
		Fee:            fee,
		Size:           vsize,
		FeeRate:        float64(fee) / float64(vsize),
		Time:           time.Now(),
		Height:         mp.chainHeight,
		AncestorFee:    fee,
		AncestorSize:   vsize,
		DescendantFee:  fee,
		DescendantSize: vsize,
	}

	// Track dependencies
	for _, in := range tx.TxIn {
		if parentEntry, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			entry.Depends = append(entry.Depends, parentEntry.TxHash)
			parentEntry.SpentBy = append(parentEntry.SpentBy, txHash)
		}
	}

	// Update ancestor/descendant tracking
	mp.updateAncestorStateLocked(entry)
	mp.updateDescendantStateLocked(entry)

	// Add to pool
	mp.pool[txHash] = entry
	for _, in := range tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txHash
	}
	mp.totalSize += vsize

	return nil
}

// rollbackPackageLocked removes transactions that were added as part of a failed package.
// Must be called with mu held.
func (mp *Mempool) rollbackPackageLocked(txns []*wire.MsgTx) {
	// Remove in reverse order (children before parents)
	for i := len(txns) - 1; i >= 0; i-- {
		txHash := txns[i].TxHash()
		mp.removeSingleTxLocked(txHash)
	}
}

// isRetryablePackageError returns true if the error might be resolved
// by evaluating the transaction as part of a package.
func isRetryablePackageError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Missing inputs might be satisfied by earlier package transactions
	if errors.Is(err, ErrMissingInputs) {
		return true
	}
	if containsSubstr(errStr, "missing") {
		return true
	}
	// Insufficient fee might be covered by aggregate package feerate
	if errors.Is(err, ErrInsufficientFee) {
		return true
	}
	if containsSubstr(errStr, "fee") {
		return true
	}
	return false
}

// containsSubstr checks if s contains substr.
func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// indexOf returns the index of tx in txns, or -1 if not found.
func indexOf(txns []*wire.MsgTx, tx *wire.MsgTx) int {
	for i, t := range txns {
		if t == tx {
			return i
		}
	}
	return -1
}
