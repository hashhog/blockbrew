// Package mining implements block template creation and proof-of-work mining.
package mining

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Block template weight / sigops constants — mirror Bitcoin Core's policy/policy.h.
//
// DefaultBlockReservedWeight: space permanently reserved for the block header,
// tx-count varint, and coinbase tx (Core DEFAULT_BLOCK_RESERVED_WEIGHT = 8000).
// Core miner.cpp:114 — nBlockWeight starts at this value.
//
// MinimumBlockReservedWeight: lowest value accepted by ClampOptions
// (Core MINIMUM_BLOCK_RESERVED_WEIGHT = 2000).
const (
	DefaultBlockReservedWeight  = 8_000
	MinimumBlockReservedWeight  = 2_000
	blockFullEnoughWeightDelta  = 4_000 // Core miner.cpp:285 BLOCK_FULL_ENOUGH_WEIGHT_DELTA
	maxConsecutiveFailures      = 1_000 // Core miner.cpp:284 MAX_CONSECUTIVE_FAILURES
)

// coinbaseMaxSequenceNonfinal is the nSequence value used for the coinbase
// input. It equals CTxIn::MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) from Core
// primitives/transaction.h:82, making the coinbase's nLockTime enforceable.
// Using 0xFFFFFFFF (SEQUENCE_FINAL) would bypass the locktime check entirely.
// Core miner.cpp:171.
const coinbaseMaxSequenceNonfinal uint32 = 0xFFFFFFFE

// BlockTemplate is a fully constructed block ready for mining (finding a valid nonce).
type BlockTemplate struct {
	Block             *wire.MsgBlock
	Height            int32
	Fees              int64  // Total fees from included transactions
	SigOpsCost        int64  // Total sigops cost
	CoinbaseValue     int64  // Subsidy + fees
	WitnessCommitment []byte // Witness commitment hash
	// TxSigOpsCost is the per-tx sigops cost for each non-coinbase transaction,
	// in the same order as Block.Transactions[1:]. Mirrors Bitcoin Core's
	// CBlockTemplate::vTxSigOpsCost (see node/miner.cpp). Used by getblocktemplate
	// to populate the per-tx `sigops` field.
	TxSigOpsCost []int64
	// MinTime is the minimum timestamp valid for the next block, per
	// GetMinimumTime (Core node/miner.cpp:36-47). Always MTP+1; at difficulty
	// adjustment boundaries also bounded below by prevBlock.time − MAX_TIMEWARP
	// (BIP-94 timewarp rule). Used by getblocktemplate's "mintime" field.
	// Bug fixed: was set to template.Block.Header.Timestamp (current time)
	// instead of the consensus minimum.
	MinTime int64
}

// TemplateConfig configures block template generation.
type TemplateConfig struct {
	MinerAddress  []byte  // ScriptPubKey to pay the block reward to
	ExtraNonce    []byte  // Extra nonce data in coinbase (for pool mining)
	MaxWeight     int64   // Maximum block weight (default: MaxBlockWeight)
	MaxSigOpsCost int64   // Maximum sigops cost (default: MaxBlockSigOpsCost)
	MinTxFeeRate  float64 // Minimum fee rate to include (sat/vB)
}

// TemplateGenerator generates block templates from the mempool.
type TemplateGenerator struct {
	chainParams   *consensus.ChainParams
	chainMgr      ChainStateProvider
	mp            MempoolProvider
	headerIndex   HeaderIndexProvider
	utxoSrc       UTXOViewProvider        // Optional; nil falls back to output-only sigops estimate.
	blockProvider consensus.BlockProvider // Optional; used by GetNextWorkRequired for testnet4 min-diff.
}

// ChainStateProvider provides chain state for template generation.
type ChainStateProvider interface {
	BestBlock() (wire.Hash256, int32)
	TipNode() *consensus.BlockNode
}

// MempoolProvider provides mempool access for template generation.
type MempoolProvider interface {
	GetSortedByAncestorFeeRate() []*mempool.TxEntry
}

// HeaderIndexProvider provides header index access for template generation.
type HeaderIndexProvider interface {
	GetNode(hash wire.Hash256) *consensus.BlockNode
	AddHeader(header wire.BlockHeader) (*consensus.BlockNode, error)
}

// UTXOViewProvider returns the current UTXO view. Used by the template
// generator so per-tx sigops accounting can include P2SH redeem-script and
// witness sigops (which require resolving the prevout's scriptPubKey).
type UTXOViewProvider interface {
	UTXOSet() consensus.UpdatableUTXOView
}

// NewTemplateGenerator creates a new block template generator.
func NewTemplateGenerator(
	params *consensus.ChainParams,
	cm ChainStateProvider,
	mp MempoolProvider,
	idx HeaderIndexProvider,
) *TemplateGenerator {
	tg := &TemplateGenerator{
		chainParams: params,
		chainMgr:    cm,
		mp:          mp,
		headerIndex: idx,
	}
	// If the chain-state provider also exposes a UTXO view (the production
	// ChainManager does), wire it up automatically so callers don't have to
	// thread it separately.
	if up, ok := cm.(UTXOViewProvider); ok {
		tg.utxoSrc = up
	}
	// If the header index also implements BlockProvider (production HeaderIndex
	// does), wire it up so GetNextWorkRequired can walk back for testnet4
	// min-difficulty blocks. Core miner.cpp:219 / pow.cpp.
	if bp, ok := idx.(consensus.BlockProvider); ok {
		tg.blockProvider = bp
	}
	return tg
}

// SetBlockProvider overrides the BlockProvider used for difficulty calculation.
// Primarily used by tests that construct a minimal mock index.
func (tg *TemplateGenerator) SetBlockProvider(bp consensus.BlockProvider) {
	tg.blockProvider = bp
}

// SetUTXOSource overrides the UTXO source used for per-tx sigops accounting.
// Primarily used by tests; production code wires it up via NewTemplateGenerator.
func (tg *TemplateGenerator) SetUTXOSource(p UTXOViewProvider) {
	tg.utxoSrc = p
}

// GenerateTemplate creates a new block template.
func (tg *TemplateGenerator) GenerateTemplate(config TemplateConfig) (*BlockTemplate, error) {
	// 1. Get the current chain tip
	tipHash, tipHeight := tg.chainMgr.BestBlock()
	tipNode := tg.headerIndex.GetNode(tipHash)
	newHeight := tipHeight + 1

	// 3. Build the block header — timestamp first so GetNextWorkRequired can
	// apply the testnet4 20-minute min-difficulty rule (Core miner.cpp:147,219).
	header := wire.BlockHeader{
		Version:   0x20000000, // BIP9 version bits signaling
		PrevBlock: tipHash,
		Timestamp: uint32(time.Now().Unix()),
		Bits:      0, // set below after timestamp is finalised
		Nonce:     0, // Miner will iterate this
	}

	// Ensure timestamp is strictly after MTP (BIP-113 / Core miner.cpp:148).
	mtp := tipNode.GetMedianTimePast()
	if int64(header.Timestamp) <= mtp {
		header.Timestamp = uint32(mtp + 1)
	}

	// 2. Calculate difficulty using the full GetNextWorkRequired so that the
	// testnet4 20-minute min-difficulty exception (fPowAllowMinDifficultyBlocks)
	// is handled correctly. Core UpdateTime (miner.cpp:60-62) re-runs nBits
	// calculation after the timestamp is finalised for exactly this reason.
	// Bug fixed: previously used CalcNextRequiredDifficulty only at retarget
	// boundaries, missing the testnet4 min-diff rule entirely.
	// Core reference: miner.cpp:219-220, pow.cpp:GetNextWorkRequired.
	var newBits uint32
	if tg.blockProvider != nil {
		newBits = consensus.GetNextWorkRequired(
			tg.chainParams,
			newHeight,
			int64(header.Timestamp),
			tipNode,
			tg.blockProvider,
		)
	} else {
		// Fallback (tests without a full BlockProvider): use simple interval check.
		if newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
			blocksBack := int32(tg.chainParams.DifficultyAdjInterval) - 1
			firstNode := tipNode.GetAncestor(tipHeight - blocksBack)
			newBits = consensus.CalcNextRequiredDifficulty(
				tg.chainParams,
				tipNode.Header.Bits,
				int64(firstNode.Header.Timestamp),
				int64(tipNode.Header.Timestamp),
			)
		} else {
			newBits = tipNode.Header.Bits
		}
	}
	header.Bits = newBits

	// 4. Select transactions from the mempool
	maxWeight := config.MaxWeight
	if maxWeight == 0 {
		maxWeight = consensus.MaxBlockWeight
	}
	maxSigOps := config.MaxSigOpsCost
	if maxSigOps == 0 {
		maxSigOps = consensus.MaxBlockSigOpsCost
	}

	// Reserve DefaultBlockReservedWeight WU for the fixed block overhead:
	// 80-byte header (320 WU) + tx-count varint + coinbase tx.
	// Core miner.cpp:114: nBlockWeight = *Assert(m_options.block_reserved_weight)
	// where block_reserved_weight defaults to DEFAULT_BLOCK_RESERVED_WEIGHT=8000.
	// Bug fixed: was 4000 (half of Core's reserved budget), allowing templates
	// that were 4000 WU too heavy and could fail block-weight validation.
	coinbaseReserve := int64(DefaultBlockReservedWeight)
	availableWeight := maxWeight - coinbaseReserve

	// Resolve a UTXO view if the chain state exposes one. This lets us count
	// P2SH redeem-script and segwit/taproot witness sigops accurately, matching
	// Bitcoin Core's GetTransactionSigOpCost. If no view is available we fall
	// back to a conservative output-script-only estimate.
	var utxoView consensus.UTXOView
	if tg.utxoSrc != nil {
		utxoView = tg.utxoSrc.UTXOSet()
	}

	selectedTxs, txSigOpsCost, totalFees, totalSigOps := selectTransactions(
		tg.mp, availableWeight, maxSigOps, newHeight, uint32(mtp), config.MinTxFeeRate, utxoView)

	// 5. Calculate the subsidy
	subsidy := consensus.CalcBlockSubsidy(newHeight)
	coinbaseValue := subsidy + totalFees

	// 6. Build the witness commitment (if segwit is active)
	var witnessCommitment []byte
	if tg.chainParams.SegwitHeight <= newHeight {
		wtxids := make([]wire.Hash256, 0, len(selectedTxs)+1)
		wtxids = append(wtxids, wire.Hash256{}) // Coinbase wtxid is all zeros
		for _, tx := range selectedTxs {
			wtxids = append(wtxids, tx.WTxHash())
		}
		witnessReserved := make([]byte, 32) // 32 zero bytes
		commitment := consensus.CalcWitnessCommitment(wtxids, witnessReserved)
		witnessCommitment = commitment[:]
	}

	// 7. Create the coinbase transaction
	coinbaseTx := CreateCoinbaseTx(newHeight, config.MinerAddress, config.ExtraNonce,
		subsidy, totalFees, witnessCommitment)

	// 8. Assemble the block
	allTxs := make([]*wire.MsgTx, 0, len(selectedTxs)+1)
	allTxs = append(allTxs, coinbaseTx)
	allTxs = append(allTxs, selectedTxs...)

	// 9. Compute the Merkle root
	txHashes := make([]wire.Hash256, len(allTxs))
	for i, tx := range allTxs {
		txHashes[i] = tx.TxHash()
	}
	header.MerkleRoot = consensus.CalcMerkleRoot(txHashes)

	// Compute MinTime per GetMinimumTime (Core node/miner.cpp:36-47):
	// always MTP+1; at retarget boundaries also bounded by
	// prevBlock.time − MAX_TIMEWARP (BIP-94 timewarp rule).
	minTime := mtp + 1
	if tg.chainParams.EnforceBIP94 &&
		newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
		timeWarpMin := int64(tipNode.Header.Timestamp) - consensus.MaxTimewarp
		if timeWarpMin > minTime {
			minTime = timeWarpMin
		}
	}

	return &BlockTemplate{
		Block: &wire.MsgBlock{
			Header:       header,
			Transactions: allTxs,
		},
		Height:            newHeight,
		Fees:              totalFees,
		SigOpsCost:        totalSigOps,
		CoinbaseValue:     coinbaseValue,
		WitnessCommitment: witnessCommitment,
		TxSigOpsCost:      txSigOpsCost,
		MinTime:           minTime,
	}, nil
}

// selectTransactions selects transactions from the mempool using the
// ancestor fee rate algorithm (CPFP-aware). Returns the selected txs, a
// parallel slice of per-tx sigops cost (sigops cost units, already scaled),
// total fees, and total sigops cost.
//
// blockHeight and lockTimeCutoff are the height and MTP of the block being
// built; they are forwarded to IsFinalTx to reject non-final transactions.
// Core reference: TestChunkTransactions (miner.cpp:252-260).
//
// If utxoView is non-nil, sigops counting matches Bitcoin Core's
// GetTransactionSigOpCost: legacy (vin+vout) scaled by 4 + P2SH redeem-script
// sigops scaled by 4 + witness sigops (unscaled). If utxoView is nil, falls
// back to the conservative output-script estimate so callers without a UTXO
// view (e.g. early-init regtest tests) still get budget enforcement and
// non-zero per-tx reporting.
func selectTransactions(mp MempoolProvider, maxWeight, maxSigOps int64, blockHeight int32, lockTimeCutoff uint32, minFeeRate float64, utxoView consensus.UTXOView) ([]*wire.MsgTx, []int64, int64, int64) {
	entries := mp.GetSortedByAncestorFeeRate()

	var selected []*wire.MsgTx
	var sigOpsCosts []int64
	var totalFees int64
	var totalSigOps int64
	var totalWeight int64
	included := make(map[wire.Hash256]bool)

	// Consecutive-failure early-exit mirrors Core addChunks() heuristic:
	// Core miner.cpp:284-316 — give up after MAX_CONSECUTIVE_FAILURES skips
	// when the block is already close to full (within BLOCK_FULL_ENOUGH_WEIGHT_DELTA).
	consecutiveFailed := 0

	for _, entry := range entries {
		if entry.FeeRate < minFeeRate {
			continue
		}

		txWeight := consensus.CalcTxWeight(entry.Tx)

		// Weight limit: use >= to match Core's TestChunkBlockLimits.
		// Core miner.cpp:241: if (nBlockWeight + chunk.size >= nBlockMaxWeight)
		// Bug fixed: was > (strictly greater), allowing exactly-at-limit blocks.
		if totalWeight+txWeight >= maxWeight {
			consecutiveFailed++
			if consecutiveFailed > maxConsecutiveFailures &&
				totalWeight+blockFullEnoughWeightDelta > maxWeight {
				break
			}
			continue
		}

		txSigOps := computeTxSigOpsCost(entry.Tx, utxoView)

		// Sigops limit: use >= to match Core's TestChunkBlockLimits.
		// Core miner.cpp:244: if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST)
		// Bug fixed: was > (strictly greater), allowing exactly-at-limit blocks.
		if totalSigOps+txSigOps >= maxSigOps {
			consecutiveFailed++
			if consecutiveFailed > maxConsecutiveFailures &&
				totalWeight+blockFullEnoughWeightDelta > maxWeight {
				break
			}
			continue
		}

		// IsFinalTx check: reject non-final transactions.
		// Core miner.cpp:252-260 TestChunkTransactions: each tx must pass
		// IsFinalTx(tx, nHeight, m_lock_time_cutoff) where m_lock_time_cutoff
		// = pindexPrev->GetMedianTimePast() (BIP-113).
		// Bug fixed: IsFinalTx was never called during template building.
		if !consensus.IsFinalTx(entry.Tx, blockHeight, lockTimeCutoff) {
			consecutiveFailed++
			if consecutiveFailed > maxConsecutiveFailures &&
				totalWeight+blockFullEnoughWeightDelta > maxWeight {
				break
			}
			continue
		}

		// Ensure all parent transactions are included
		allParentsIncluded := true
		for _, dep := range entry.Depends {
			if !included[dep] {
				allParentsIncluded = false
				break
			}
		}
		if !allParentsIncluded {
			consecutiveFailed++
			if consecutiveFailed > maxConsecutiveFailures &&
				totalWeight+blockFullEnoughWeightDelta > maxWeight {
				break
			}
			continue // Skip — parent not yet selected
		}

		consecutiveFailed = 0
		selected = append(selected, entry.Tx)
		sigOpsCosts = append(sigOpsCosts, txSigOps)
		included[entry.TxHash] = true
		totalFees += entry.Fee
		totalWeight += txWeight
		totalSigOps += txSigOps
	}

	return selected, sigOpsCosts, totalFees, totalSigOps
}

// computeTxSigOpsCost returns the BIP141 sigops cost for a transaction.
// Mirrors Bitcoin Core's GetTransactionSigOpCost (consensus/tx_verify.cpp):
// legacy (scriptSig + scriptPubKey) scaled by WITNESS_SCALE_FACTOR, plus P2SH
// redeem-script sigops (also scaled), plus witness sigops (unscaled).
//
// When utxoView is nil, only legacy sigops are counted (P2SH and witness
// sigops require resolving the prevout's scriptPubKey). This is a conservative
// over- or under-estimate depending on script type, but it keeps behavior
// sensible in tests / pre-UTXO-init paths.
func computeTxSigOpsCost(tx *wire.MsgTx, utxoView consensus.UTXOView) int64 {
	if consensus.IsCoinbaseTx(tx) {
		return 0
	}

	// Legacy sigops: count CHECKSIG/CHECKMULTISIG opcodes in scriptSig of every
	// input AND scriptPubKey of every output, then scale by 4. Matches
	// GetLegacySigOpCount in Core which uses GetSigOpCount(fAccurate=false):
	// CHECKMULTISIG always counts as 20 regardless of preceding push opcode.
	legacy := 0
	for _, in := range tx.TxIn {
		legacy += consensus.CountSigOpsInaccurate(in.SignatureScript)
	}
	for _, out := range tx.TxOut {
		legacy += consensus.CountSigOpsInaccurate(out.PkScript)
	}
	cost := int64(legacy) * int64(consensus.WitnessScaleFactor)

	if utxoView != nil {
		cost += int64(consensus.CountP2SHSigOps(tx, utxoView)) // already scaled
		cost += int64(consensus.CountWitnessSigOps(tx, utxoView))
	}

	return cost
}

// CreateCoinbaseTx creates the coinbase transaction for a block.
func CreateCoinbaseTx(height int32, minerScript []byte, extraNonce []byte, subsidy int64, fees int64, witnessCommitment []byte) *wire.MsgTx {
	// Build the coinbase scriptSig:
	// BIP34: push the block height as a script number
	heightScript := serializeBlockHeight(height)

	// Add extra nonce space (default 8 bytes of zeros, or use provided extraNonce)
	scriptSig := heightScript
	if len(extraNonce) > 0 {
		scriptSig = append(scriptSig, extraNonce...)
	} else {
		scriptSig = append(scriptSig, make([]byte, 8)...)
	}

	// nLockTime = height - 1 per Core miner.cpp:196 — makes the coinbase
	// enforceable only after the block at height-1. Combined with
	// nSequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) which opts the input into
	// locktime enforcement (Core miner.cpp:171). Using 0xFFFFFFFF would signal
	// SEQUENCE_FINAL which bypasses the locktime check entirely.
	// Bug fixed: was nLockTime=0 and nSequence=0xFFFFFFFF.
	lockTime := uint32(0)
	if height > 0 {
		lockTime = uint32(height - 1)
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{}, // All zeros for coinbase
				Index: 0xFFFFFFFF,
			},
			SignatureScript: scriptSig,
			Sequence:        coinbaseMaxSequenceNonfinal, // 0xFFFFFFFE = MAX_SEQUENCE_NONFINAL
		}},
		TxOut: []*wire.TxOut{{
			Value:    subsidy + fees,
			PkScript: minerScript,
		}},
		LockTime: lockTime, // nHeight - 1 per Core miner.cpp:196
	}

	// Add witness commitment output (BIP141)
	if witnessCommitment != nil {
		commitScript := make([]byte, 0, 38)
		commitScript = append(commitScript, 0x6a)                   // OP_RETURN
		commitScript = append(commitScript, 0x24)                   // Push 36 bytes
		commitScript = append(commitScript, 0xaa, 0x21, 0xa9, 0xed) // Witness magic
		commitScript = append(commitScript, witnessCommitment...)
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    0,
			PkScript: commitScript,
		})
		// Add witness reserved value (32 zero bytes) to coinbase witness
		tx.TxIn[0].Witness = [][]byte{make([]byte, 32)}
	}

	return tx
}

// serializeBlockHeight encodes a block height as a minimal CScript push.
// This implements BIP34 height encoding in the coinbase.
func serializeBlockHeight(height int32) []byte {
	// Heights 0-16 can use OP_0 through OP_16
	if height == 0 {
		return []byte{0x00} // OP_0
	}
	if height >= 1 && height <= 16 {
		return []byte{byte(0x50 + height)} // OP_1 through OP_16
	}

	// Serialize as a script number push
	heightBytes := scriptNumSerialize(int64(height))
	result := make([]byte, 0, len(heightBytes)+1)
	result = append(result, byte(len(heightBytes)))
	result = append(result, heightBytes...)
	return result
}

// scriptNumSerialize encodes an integer as a minimally-encoded Bitcoin script number.
// The encoding is little-endian with a sign bit in the highest bit of the last byte.
func scriptNumSerialize(n int64) []byte {
	if n == 0 {
		return nil
	}

	negative := n < 0
	if negative {
		n = -n
	}

	// Encode as little-endian
	var result []byte
	for n > 0 {
		result = append(result, byte(n&0xff))
		n >>= 8
	}

	// If the high bit is set, we need an extra byte for the sign
	if result[len(result)-1]&0x80 != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative {
		result[len(result)-1] |= 0x80
	}

	return result
}

// DefaultMaxTries is the default number of nonce attempts for block mining.
const DefaultMaxTries = 1000000

// BlockMiner handles instant block generation for regtest mode.
type BlockMiner struct {
	templateGen *TemplateGenerator
	chainMgr    BlockConnector
	chainDB     BlockStorage
	headerIndex HeaderIndexProvider
	chainParams *consensus.ChainParams
}

// BlockConnector is the interface for connecting mined blocks to the chain.
type BlockConnector interface {
	ConnectBlock(block *wire.MsgBlock) error
	BestBlock() (wire.Hash256, int32)
}

// BlockStorage is the interface for storing mined blocks.
type BlockStorage interface {
	StoreBlock(hash wire.Hash256, block *wire.MsgBlock) error
}

// NewBlockMiner creates a new block miner for instant mining.
func NewBlockMiner(
	tg *TemplateGenerator,
	cm BlockConnector,
	db BlockStorage,
	idx HeaderIndexProvider,
	params *consensus.ChainParams,
) *BlockMiner {
	return &BlockMiner{
		templateGen: tg,
		chainMgr:    cm,
		chainDB:     db,
		headerIndex: idx,
		chainParams: params,
	}
}

// GenerateBlocks mines nblocks blocks instantly, paying the coinbase to the given script.
// Returns the hashes of the generated blocks.
func (m *BlockMiner) GenerateBlocks(nblocks int, coinbaseScript []byte, maxTries int) ([]wire.Hash256, error) {
	if maxTries == 0 {
		maxTries = DefaultMaxTries
	}

	hashes := make([]wire.Hash256, 0, nblocks)

	for i := 0; i < nblocks; i++ {
		hash, err := m.GenerateBlock(coinbaseScript, nil, maxTries)
		if err != nil {
			return hashes, err
		}
		hashes = append(hashes, hash)
	}

	return hashes, nil
}

// GenerateBlock mines a single block with the given coinbase script and optional transactions.
// If txs is nil, transactions are selected from the mempool.
// Returns the hash of the generated block.
func (m *BlockMiner) GenerateBlock(coinbaseScript []byte, txs []*wire.MsgTx, maxTries int) (wire.Hash256, error) {
	if maxTries == 0 {
		maxTries = DefaultMaxTries
	}

	// Generate block template
	config := TemplateConfig{
		MinerAddress: coinbaseScript,
	}

	template, err := m.templateGen.GenerateTemplate(config)
	if err != nil {
		return wire.Hash256{}, err
	}

	block := template.Block

	// If specific transactions are provided, use them instead of mempool txs
	if txs != nil {
		// Keep only the coinbase transaction
		coinbase := block.Transactions[0]

		// Rebuild transaction list with coinbase + provided txs
		block.Transactions = make([]*wire.MsgTx, 0, len(txs)+1)
		block.Transactions = append(block.Transactions, coinbase)
		block.Transactions = append(block.Transactions, txs...)

		// Recalculate the merkle root
		txHashes := make([]wire.Hash256, len(block.Transactions))
		for i, tx := range block.Transactions {
			txHashes[i] = tx.TxHash()
		}
		block.Header.MerkleRoot = consensus.CalcMerkleRoot(txHashes)

		// Recalculate witness commitment if segwit is active
		if m.chainParams.SegwitHeight <= template.Height {
			wtxids := make([]wire.Hash256, len(block.Transactions))
			wtxids[0] = wire.Hash256{} // Coinbase wtxid is all zeros
			for i := 1; i < len(block.Transactions); i++ {
				wtxids[i] = block.Transactions[i].WTxHash()
			}
			witnessReserved := make([]byte, 32)
			commitment := consensus.CalcWitnessCommitment(wtxids, witnessReserved)

			// Update coinbase witness commitment output
			UpdateCoinbaseWitnessCommitment(coinbase, commitment[:])
		}
	}

	// Mine the block by iterating nonces
	hash, err := m.mineBlock(block, maxTries)
	if err != nil {
		return wire.Hash256{}, err
	}

	// Store and connect the block
	if m.chainDB != nil {
		if err := m.chainDB.StoreBlock(hash, block); err != nil {
			return wire.Hash256{}, err
		}
	}

	// Add the block header to the header index so ConnectBlock can find it
	if m.headerIndex != nil {
		if _, err := m.headerIndex.AddHeader(block.Header); err != nil {
			return wire.Hash256{}, fmt.Errorf("failed to add header to index: %w", err)
		}
	}

	if m.chainMgr != nil {
		if err := m.chainMgr.ConnectBlock(block); err != nil {
			return wire.Hash256{}, err
		}
	}

	return hash, nil
}

// mineBlock iterates nonces until a valid proof-of-work is found.
func (m *BlockMiner) mineBlock(block *wire.MsgBlock, maxTries int) (wire.Hash256, error) {
	target := consensus.CompactToBig(block.Header.Bits)

	for nonce := uint32(0); nonce < uint32(maxTries); nonce++ {
		block.Header.Nonce = nonce
		hash := block.Header.BlockHash()

		hashNum := consensus.HashToBig(hash)
		if hashNum.Cmp(target) <= 0 {
			return hash, nil
		}
	}

	return wire.Hash256{}, ErrMaxTriesExceeded
}

// UpdateCoinbaseWitnessCommitment updates the witness commitment in the coinbase transaction.
func UpdateCoinbaseWitnessCommitment(coinbase *wire.MsgTx, commitment []byte) {
	// Find the witness commitment output (OP_RETURN with 0xaa21a9ed magic)
	for i, out := range coinbase.TxOut {
		if len(out.PkScript) >= 38 &&
			out.PkScript[0] == 0x6a && // OP_RETURN
			out.PkScript[1] == 0x24 && // Push 36 bytes
			out.PkScript[2] == 0xaa &&
			out.PkScript[3] == 0x21 &&
			out.PkScript[4] == 0xa9 &&
			out.PkScript[5] == 0xed {
			// Update the commitment
			copy(coinbase.TxOut[i].PkScript[6:], commitment)
			return
		}
	}
}

// ErrMaxTriesExceeded is returned when mining fails to find a valid nonce.
var ErrMaxTriesExceeded = errors.New("maximum nonce tries exceeded")
