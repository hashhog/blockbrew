// Package mining implements block template creation and proof-of-work mining.
package mining

import (
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// BlockTemplate is a fully constructed block ready for mining (finding a valid nonce).
type BlockTemplate struct {
	Block             *wire.MsgBlock
	Height            int32
	Fees              int64  // Total fees from included transactions
	SigOpsCost        int64  // Total sigops cost
	CoinbaseValue     int64  // Subsidy + fees
	WitnessCommitment []byte // Witness commitment hash
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
	chainParams *consensus.ChainParams
	chainMgr    ChainStateProvider
	mp          MempoolProvider
	headerIndex HeaderIndexProvider
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
}

// NewTemplateGenerator creates a new block template generator.
func NewTemplateGenerator(
	params *consensus.ChainParams,
	cm ChainStateProvider,
	mp MempoolProvider,
	idx HeaderIndexProvider,
) *TemplateGenerator {
	return &TemplateGenerator{
		chainParams: params,
		chainMgr:    cm,
		mp:          mp,
		headerIndex: idx,
	}
}

// GenerateTemplate creates a new block template.
func (tg *TemplateGenerator) GenerateTemplate(config TemplateConfig) (*BlockTemplate, error) {
	// 1. Get the current chain tip
	tipHash, tipHeight := tg.chainMgr.BestBlock()
	tipNode := tg.headerIndex.GetNode(tipHash)
	newHeight := tipHeight + 1

	// 2. Calculate difficulty for the new block
	var newBits uint32
	if newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
		// Need to recalculate difficulty
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

	// 3. Build the block header
	header := wire.BlockHeader{
		Version:   0x20000000, // BIP9 version bits signaling
		PrevBlock: tipHash,
		Timestamp: uint32(time.Now().Unix()),
		Bits:      newBits,
		Nonce:     0, // Miner will iterate this
	}

	// Ensure timestamp is after MTP
	mtp := tipNode.GetMedianTimePast()
	if int64(header.Timestamp) <= mtp {
		header.Timestamp = uint32(mtp + 1)
	}

	// 4. Select transactions from the mempool
	maxWeight := config.MaxWeight
	if maxWeight == 0 {
		maxWeight = consensus.MaxBlockWeight
	}
	maxSigOps := config.MaxSigOpsCost
	if maxSigOps == 0 {
		maxSigOps = consensus.MaxBlockSigOpsCost
	}

	// Reserve weight for the coinbase transaction (~4000 WU is conservative)
	coinbaseReserve := int64(4000)
	availableWeight := maxWeight - coinbaseReserve

	selectedTxs, totalFees, totalSigOps := selectTransactions(
		tg.mp, availableWeight, maxSigOps, config.MinTxFeeRate)

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
	}, nil
}

// selectTransactions selects transactions from the mempool using the
// ancestor fee rate algorithm (CPFP-aware).
func selectTransactions(mp MempoolProvider, maxWeight, maxSigOps int64, minFeeRate float64) ([]*wire.MsgTx, int64, int64) {
	entries := mp.GetSortedByAncestorFeeRate()

	var selected []*wire.MsgTx
	var totalFees int64
	var totalSigOps int64
	var totalWeight int64
	included := make(map[wire.Hash256]bool)

	for _, entry := range entries {
		if entry.FeeRate < minFeeRate {
			continue
		}

		txWeight := consensus.CalcTxWeight(entry.Tx)

		// Check weight limit
		if totalWeight+txWeight > maxWeight {
			continue // Try next (smaller) transaction
		}

		// Estimate sigops cost for this transaction
		// We count sigops in outputs (scaled by 4)
		txSigOps := int64(0)
		for _, out := range entry.Tx.TxOut {
			txSigOps += int64(consensus.CountSigOps(out.PkScript)) * consensus.WitnessScaleFactor
		}

		// Check sigops limit
		if totalSigOps+txSigOps > maxSigOps {
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
			continue // Skip — parent not yet selected
		}

		selected = append(selected, entry.Tx)
		included[entry.TxHash] = true
		totalFees += entry.Fee
		totalWeight += txWeight
		totalSigOps += txSigOps
	}

	return selected, totalFees, totalSigOps
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

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{}, // All zeros for coinbase
				Index: 0xFFFFFFFF,
			},
			SignatureScript: scriptSig,
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    subsidy + fees,
			PkScript: minerScript,
		}},
		LockTime: 0,
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
