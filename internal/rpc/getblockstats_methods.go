package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// numGetBlockStatsPercentiles is the number of feerate percentiles computed by
// getblockstats (10th, 25th, 50th, 75th, 90th). Mirrors Core's
// NUM_GETBLOCKSTATS_PERCENTILES (rpc/blockchain.cpp).
const numGetBlockStatsPercentiles = 5

// perUTXOOverhead is Core's PER_UTXO_OVERHEAD constant used by getblockstats to
// estimate the on-disk size delta of the UTXO set per output:
//
//	sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool)
//	  = (uint256(32) + uint32(4)) + uint32(4) + bool(1) = 41
//
// Verified against bitcoin-core/test/functional/data/rpc_getblockstats.json:
// height 101 has one spendable P2PKH output (script 25 bytes) →
// utxo_size_inc_actual = 75 = GetSerializeSize(out)=34 + 41.
// Reference: bitcoin-core/src/rpc/blockchain.cpp:1953-1954.
const perUTXOOverhead = 41

// witnessScaleFactor is Core's WITNESS_SCALE_FACTOR (= 4); feerate is expressed
// in satoshis per virtual byte where vsize = weight / 4.
const witnessScaleFactor = 4

// maxBlockSerializedSize is Core's MAX_BLOCK_SERIALIZED_SIZE, used purely as the
// sentinel initial value for mintxsize (rendered as 0 when no non-coinbase tx
// is present). Reference: bitcoin-core/src/consensus/consensus.h.
const maxBlockSerializedSize = 4_000_000

// blockStatsResult holds every getblockstats statistic. Fields use pointers so
// that the JSON marshalling can emit only the subset requested by the `stats`
// argument (omitempty drops nil pointers), exactly like Core's per-stat pushKV
// loop in the non-do_all branch. When no stats filter is given every field is
// populated.
//
// Field JSON names + result shape mirror Bitcoin Core's getblockstats
// (bitcoin-core/src/rpc/blockchain.cpp:1956-2214) verbatim.
type blockStatsResult struct {
	AvgFee             *int64   `json:"avgfee,omitempty"`
	AvgFeeRate         *int64   `json:"avgfeerate,omitempty"`
	AvgTxSize          *int64   `json:"avgtxsize,omitempty"`
	BlockHash          *string  `json:"blockhash,omitempty"`
	FeeRatePercentiles *[]int64 `json:"feerate_percentiles,omitempty"`
	Height             *int32   `json:"height,omitempty"`
	Ins                *int64   `json:"ins,omitempty"`
	MaxFee             *int64   `json:"maxfee,omitempty"`
	MaxFeeRate         *int64   `json:"maxfeerate,omitempty"`
	MaxTxSize          *int64   `json:"maxtxsize,omitempty"`
	MedianFee          *int64   `json:"medianfee,omitempty"`
	MedianTime         *int64   `json:"mediantime,omitempty"`
	MedianTxSize       *int64   `json:"mediantxsize,omitempty"`
	MinFee             *int64   `json:"minfee,omitempty"`
	MinFeeRate         *int64   `json:"minfeerate,omitempty"`
	MinTxSize          *int64   `json:"mintxsize,omitempty"`
	Outs               *int64   `json:"outs,omitempty"`
	Subsidy            *int64   `json:"subsidy,omitempty"`
	SwTotalSize        *int64   `json:"swtotal_size,omitempty"`
	SwTotalWeight      *int64   `json:"swtotal_weight,omitempty"`
	SwTxs              *int64   `json:"swtxs,omitempty"`
	Time               *int64   `json:"time,omitempty"`
	TotalOut           *int64   `json:"total_out,omitempty"`
	TotalSize          *int64   `json:"total_size,omitempty"`
	TotalWeight        *int64   `json:"total_weight,omitempty"`
	TotalFee           *int64   `json:"totalfee,omitempty"`
	Txs                *int64   `json:"txs,omitempty"`
	UTXOIncrease       *int64   `json:"utxo_increase,omitempty"`
	UTXOSizeInc        *int64   `json:"utxo_size_inc,omitempty"`
	UTXOIncreaseActual *int64   `json:"utxo_increase_actual,omitempty"`
	UTXOSizeIncActual  *int64   `json:"utxo_size_inc_actual,omitempty"`
}

// handleGetBlockStats implements the getblockstats RPC.
//
//	getblockstats hash_or_height ( stats )
//
// Faithful port of bitcoin-core/src/rpc/blockchain.cpp::getblockstats
// (RPCHelpMan + lambda). Computes per-block statistics — fees, feerates,
// sizes, weights and UTXO-set deltas — for the target block. All amounts are
// in satoshis; feerates are satoshis per virtual byte (vsize = weight / 4).
//
// First arg resolves EITHER as a block height (JSON number / numeric string) OR
// a block hash (hex string), matching Core's ParseHashOrHeight. The optional
// second arg is an array of stat names; when present the response contains only
// those keys (an unknown name is an error, as in Core). Omitted/empty = all.
//
// Fee math (per non-coinbase tx): fee = sum(prevout values) - sum(output
// values). Input prevout values come from the block's undo data (one TxUndo per
// non-coinbase tx; SpentCoin.TxOut.Value is the spent output's value). The
// coinbase is excluded from every fee/feerate statistic but still counts toward
// txs / outs / utxo_size_inc, exactly as Core does.
func (s *Server) handleGetBlockStats(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil || s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}
	if s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Block store not available"}
	}

	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}
	if len(args) < 1 || args[0] == nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hash_or_height parameter"}
	}

	// --- 1. Resolve the target block (Core's ParseHashOrHeight). ---
	node, rpcErr := s.parseHashOrHeight(args[0])
	if rpcErr != nil {
		return nil, rpcErr
	}

	// --- 2. Parse the optional stats filter. ---
	// An absent/null second arg selects every statistic (do_all). Otherwise
	// the response is restricted to the named stats; an unknown name is an
	// error after computation (Core: "Invalid selected statistic").
	var selected map[string]bool
	if len(args) >= 2 && args[1] != nil {
		arr, ok := args[1].([]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "stats must be an array"}
		}
		selected = make(map[string]bool, len(arr))
		for _, v := range arr {
			name, ok := v.(string)
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "stats entries must be strings"}
			}
			selected[name] = true
		}
	}

	// --- 3. Load the block body + undo data. ---
	block, err := s.chainDB.GetBlock(node.Hash)
	if err != nil || block == nil {
		// Header known but body absent: pruned (if pruning on) vs never had it.
		// Mirrors Core's GetBlockChecked, which surfaces the pruned case.
		if s.pruner != nil && s.pruner.IsEnabled() && s.chainMgr.IsInMainChain(node.Hash) {
			return nil, &RPCError{Code: RPCErrMisc, Message: "Block not available (pruned data)"}
		}
		return nil, &RPCError{Code: RPCErrMisc, Message: "Block not found on disk"}
	}

	// Undo data carries the spent-prevout values needed for fee stats. Genesis
	// has no spends; a block with only a coinbase has an empty undo. If undo is
	// missing for a block that DOES have non-coinbase txs we cannot compute
	// fees correctly — fail loudly rather than report wrong fees (Core's
	// GetUndoChecked throws on a missing/corrupt undo).
	var blockUndo *storage.BlockUndo
	if u, uerr := s.chainDB.ReadBlockUndo(node.Hash); uerr == nil {
		blockUndo = u
	}

	// --- 4. Compute every statistic. ---
	stats, cerr := computeBlockStats(block, blockUndo, node, s.chainParams.SubsidyHalvingInterval)
	if cerr != nil {
		return nil, cerr
	}

	// --- 5. Apply the stats filter (Core's non-do_all branch). ---
	if selected != nil {
		return filterBlockStats(stats, selected)
	}
	return stats, nil
}

// parseHashOrHeight resolves the getblockstats first argument to a BlockNode.
// It mirrors Bitcoin Core's ParseHashOrHeight (rpc/blockchain.cpp:126):
//
//   - numeric (JSON number, or a string that parses as an integer): a block
//     height into the active chain. Negative or above-tip heights are
//     RPC_INVALID_PARAMETER (-8).
//   - otherwise: a block hash. Unknown hash is RPC_INVALID_ADDRESS_OR_KEY (-5).
//
// Bitcoin Core's RPC frontend treats a numeric height arg as `getInt<int>`
// whether it arrives as a JSON number or a numeric string, so we accept both.
func (s *Server) parseHashOrHeight(param interface{}) (*consensus.BlockNode, *RPCError) {
	// Numeric height: JSON number, or a string of digits (Core's frontend
	// coerces numeric strings to the NUM arg type).
	if height, ok := asBlockHeight(param); ok {
		tip := s.chainMgr.BestBlockNode()
		if tip == nil {
			return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
		}
		if height < 0 {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Target block height %d is negative", height),
			}
		}
		if height > tip.Height {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Target block height %d after current tip %d", height, tip.Height),
			}
		}
		anc := tip.GetAncestor(height)
		if anc == nil {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Block height out of range"}
		}
		return anc, nil
	}

	// Otherwise a block hash.
	hashStr, ok := param.(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "hash_or_height must be a height or block hash"}
	}
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash format"}
	}
	node := s.headerIndex.GetNode(hash)
	if node == nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Block not found"}
	}
	return node, nil
}

// asBlockHeight returns (height, true) when v represents a block height: a JSON
// number, or a string consisting solely of an optional sign followed by digits.
// A non-numeric string (e.g. a hex hash) returns (0, false) so the caller falls
// through to hash resolution.
func asBlockHeight(v interface{}) (int32, bool) {
	switch t := v.(type) {
	case float64:
		return int32(int64(t)), true
	case string:
		if t == "" {
			return 0, false
		}
		neg := false
		s := t
		if s[0] == '+' || s[0] == '-' {
			neg = s[0] == '-'
			s = s[1:]
		}
		if s == "" {
			return 0, false
		}
		var n int64
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int64(c-'0')
		}
		if neg {
			n = -n
		}
		return int32(n), true
	default:
		return 0, false
	}
}

// computeBlockStats produces the full getblockstats result for a block. It is a
// direct, allocation-conservative port of the per-tx loop in
// bitcoin-core/src/rpc/blockchain.cpp:2074-2198. It always computes every
// statistic; the caller may then subset the result.
//
// halvingInterval is the network's nSubsidyHalvingInterval, used for the
// subsidy stat (Core: GetBlockSubsidy(pindex.nHeight, consensus params)).
func computeBlockStats(block *wire.MsgBlock, blockUndo *storage.BlockUndo, node *consensus.BlockNode, halvingInterval int32) (*blockStatsResult, *RPCError) {
	var (
		maxFee            int64
		maxFeeRate        int64
		minFee            = int64(consensus.MaxMoney)
		minFeeRate        = int64(consensus.MaxMoney)
		totalOut          int64
		totalFee          int64
		inputs            int64
		maxTxSize         int64
		minTxSize         = int64(maxBlockSerializedSize)
		outputs           int64
		swTotalSize       int64
		swTotalWt         int64
		swTxs             int64
		totalSize         int64
		totalWeight       int64
		utxos             int64 // spendable outputs created (utxo_increase_actual numerator)
		utxoSizeInc       int64
		utxoSizeIncActual int64

		feeArray     []int64
		feerateArray []feerateScore
		txsizeArray  []int64
	)

	isGenesis := node.Height == 0
	undoIdx := 0 // index into blockUndo.TxUndos (advances per non-coinbase tx)

	for _, tx := range block.Transactions {
		isCoinbase := consensus.IsCoinbaseTx(tx)
		outputs += int64(len(tx.TxOut))

		var txTotalOut int64
		for _, out := range tx.TxOut {
			txTotalOut += out.Value

			outSize := txOutSerializeSize(out) + perUTXOOverhead
			utxoSizeInc += outSize

			// Genesis (and BIP30-repeat coinbases, n/a on these networks) do
			// not change the UTXO-set counts and are excluded from the actual
			// counters. Core: rpc/blockchain.cpp:2088.
			if isGenesis {
				continue
			}
			// Unspendable outputs never enter the UTXO set.
			if isUnspendableScript(out.PkScript) {
				continue
			}
			utxos++
			utxoSizeIncActual += outSize
		}

		if isCoinbase {
			continue
		}

		inputs += int64(len(tx.TxIn)) // coinbase's fake input not counted
		totalOut += txTotalOut        // coinbase reward not counted

		// Sizes / weight (always computed; matches Core's do_all path).
		txSize := txTotalSerializeSize(tx)
		txsizeArray = append(txsizeArray, txSize)
		if txSize > maxTxSize {
			maxTxSize = txSize
		}
		if txSize < minTxSize {
			minTxSize = txSize
		}
		totalSize += txSize

		weight := txWeight(tx)
		totalWeight += weight

		if tx.HasWitness() {
			swTxs++
			swTotalSize += txSize
			swTotalWt += weight
		}

		// Fee math from undo data. One TxUndo per non-coinbase tx, in order.
		if blockUndo == nil || undoIdx >= len(blockUndo.TxUndos) {
			// Non-coinbase tx with no matching undo entry: prevout values are
			// unavailable, so we cannot compute a correct fee. Refuse rather
			// than report a wrong fee (wrong fee stats are worse than none).
			return nil, &RPCError{
				Code:    RPCErrMisc,
				Message: "Undo data unavailable for block (cannot compute fees)",
			}
		}
		txUndo := blockUndo.TxUndos[undoIdx]
		undoIdx++

		var txTotalIn int64
		for i := range txUndo.SpentCoins {
			prevOut := txUndo.SpentCoins[i].TxOut
			txTotalIn += prevOut.Value
			prevoutSize := txOutSerializeSize(&prevOut) + perUTXOOverhead
			utxoSizeInc -= prevoutSize
			utxoSizeIncActual -= prevoutSize
		}

		txFee := txTotalIn - txTotalOut
		feeArray = append(feeArray, txFee)
		if txFee > maxFee {
			maxFee = txFee
		}
		if txFee < minFee {
			minFee = txFee
		}
		totalFee += txFee

		// Feerate is satoshis per virtual byte: fee * 4 / weight.
		var feerate int64
		if weight != 0 {
			feerate = (txFee * witnessScaleFactor) / weight
		}
		feerateArray = append(feerateArray, feerateScore{rate: feerate, weight: weight})
		if feerate > maxFeeRate {
			maxFeeRate = feerate
		}
		if feerate < minFeeRate {
			minFeeRate = feerate
		}
	}

	feeratePercentiles := calculatePercentilesByWeight(feerateArray, totalWeight)

	nTx := int64(len(block.Transactions))
	nNonCoinbase := nTx - 1
	if nNonCoinbase < 0 {
		nNonCoinbase = 0
	}

	avgFee := int64(0)
	avgTxSize := int64(0)
	if nNonCoinbase > 0 {
		avgFee = totalFee / nNonCoinbase
		avgTxSize = totalSize / nNonCoinbase
	}
	avgFeeRate := int64(0)
	if totalWeight != 0 {
		avgFeeRate = (totalFee * witnessScaleFactor) / totalWeight
	}

	if minFee == int64(consensus.MaxMoney) {
		minFee = 0
	}
	if minFeeRate == int64(consensus.MaxMoney) {
		minFeeRate = 0
	}
	if minTxSize == int64(maxBlockSerializedSize) {
		minTxSize = 0
	}

	subsidy := consensus.CalcBlockSubsidyForInterval(node.Height, halvingInterval)

	blockHash := node.Hash.String()
	height := node.Height
	medianFee := calculateTruncatedMedian(feeArray)
	medianTime := node.GetMedianTimePast()
	medianTxSize := calculateTruncatedMedian(txsizeArray)
	blockTime := int64(node.Header.Timestamp)
	utxoIncrease := outputs - inputs
	utxoIncreaseActual := utxos - inputs

	return &blockStatsResult{
		AvgFee:             &avgFee,
		AvgFeeRate:         &avgFeeRate,
		AvgTxSize:          &avgTxSize,
		BlockHash:          &blockHash,
		FeeRatePercentiles: &feeratePercentiles,
		Height:             &height,
		Ins:                &inputs,
		MaxFee:             &maxFee,
		MaxFeeRate:         &maxFeeRate,
		MaxTxSize:          &maxTxSize,
		MedianFee:          &medianFee,
		MedianTime:         &medianTime,
		MedianTxSize:       &medianTxSize,
		MinFee:             &minFee,
		MinFeeRate:         &minFeeRate,
		MinTxSize:          &minTxSize,
		Outs:               &outputs,
		Subsidy:            &subsidy,
		SwTotalSize:        &swTotalSize,
		SwTotalWeight:      &swTotalWt,
		SwTxs:              &swTxs,
		Time:               &blockTime,
		TotalOut:           &totalOut,
		TotalSize:          &totalSize,
		TotalWeight:        &totalWeight,
		TotalFee:           &totalFee,
		Txs:                &nTx,
		UTXOIncrease:       &utxoIncrease,
		UTXOSizeInc:        &utxoSizeInc,
		UTXOIncreaseActual: &utxoIncreaseActual,
		UTXOSizeIncActual:  &utxoSizeIncActual,
	}, nil
}

// feerateScore pairs a tx feerate (sat/vB) with its weight, for weight-ranked
// percentile selection. Mirrors Core's std::pair<CAmount,int64_t>.
type feerateScore struct {
	rate   int64
	weight int64
}

// calculatePercentilesByWeight returns the [10th,25th,50th,75th,90th] feerate
// percentiles selected by cumulative WEIGHT (not by count). Faithful port of
// bitcoin-core/src/rpc/blockchain.cpp::CalculatePercentilesByWeight: scores are
// sorted by feerate ascending; a percentile boundary at total_weight*p is
// crossed by accumulating each element's weight; remaining percentiles are
// filled with the largest feerate. An empty score set yields all zeros.
func calculatePercentilesByWeight(scores []feerateScore, totalWeight int64) []int64 {
	result := make([]int64, numGetBlockStatsPercentiles)
	if len(scores) == 0 {
		return result
	}

	sort.Slice(scores, func(i, j int) bool {
		if scores[i].rate != scores[j].rate {
			return scores[i].rate < scores[j].rate
		}
		return scores[i].weight < scores[j].weight
	})

	weights := [numGetBlockStatsPercentiles]float64{
		float64(totalWeight) / 10.0,
		float64(totalWeight) / 4.0,
		float64(totalWeight) / 2.0,
		(float64(totalWeight) * 3.0) / 4.0,
		(float64(totalWeight) * 9.0) / 10.0,
	}

	nextIdx := 0
	var cumulative int64
	for _, el := range scores {
		cumulative += el.weight
		for nextIdx < numGetBlockStatsPercentiles && float64(cumulative) >= weights[nextIdx] {
			result[nextIdx] = el.rate
			nextIdx++
		}
	}
	for i := nextIdx; i < numGetBlockStatsPercentiles; i++ {
		result[i] = scores[len(scores)-1].rate
	}
	return result
}

// calculateTruncatedMedian returns the truncated median of an int64 slice.
// Faithful port of bitcoin-core/src/rpc/blockchain.cpp::CalculateTruncatedMedian:
// empty → 0; even count → integer mean of the two central elements (truncated);
// odd count → the central element. The input is sorted in place.
func calculateTruncatedMedian(scores []int64) int64 {
	n := len(scores)
	if n == 0 {
		return 0
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i] < scores[j] })
	if n%2 == 0 {
		return (scores[n/2-1] + scores[n/2]) / 2
	}
	return scores[n/2]
}

// txOutSerializeSize returns GetSerializeSize(out): the byte length of the
// consensus serialization of a CTxOut (8-byte value + compactsize(scriptlen) +
// script). Computed by serializing into a counting buffer, the same idiom
// handleGetBlock uses for stripped-size.
func txOutSerializeSize(out *wire.TxOut) int64 {
	var buf bytes.Buffer
	_ = out.Serialize(&buf)
	return int64(buf.Len())
}

// txTotalSerializeSize returns ComputeTotalSize(tx): the full witness
// serialization byte length (BIP144). Core: GetSerializeSize(TX_WITH_WITNESS).
func txTotalSerializeSize(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	_ = tx.Serialize(&buf)
	return int64(buf.Len())
}

// txWeight returns GetTransactionWeight(tx) = stripped_size*3 + total_size
// (BIP141). Matches handleGetBlock's per-block weight idiom applied per-tx.
func txWeight(tx *wire.MsgTx) int64 {
	var total bytes.Buffer
	_ = tx.Serialize(&total)
	var stripped bytes.Buffer
	_ = tx.SerializeNoWitness(&stripped)
	return int64(3*stripped.Len() + total.Len())
}

// isUnspendableScript mirrors CScript::IsUnspendable: a script is unspendable if
// it starts with OP_RETURN (0x6a) or exceeds MAX_SCRIPT_SIZE (10000) bytes.
// Reference: bitcoin-core/src/script/script.h:563.
func isUnspendableScript(pkScript []byte) bool {
	const opReturn = 0x6a
	const maxScriptSize = 10000
	if len(pkScript) > 0 && pkScript[0] == opReturn {
		return true
	}
	if len(pkScript) > maxScriptSize {
		return true
	}
	return false
}

// filterBlockStats returns only the requested statistics as a JSON object,
// mirroring Core's non-do_all branch: an unknown stat name is an error
// (RPC_INVALID_PARAMETER, "Invalid selected statistic 'name'").
func filterBlockStats(stats *blockStatsResult, selected map[string]bool) (interface{}, *RPCError) {
	all := blockStatsToMap(stats)
	out := make(map[string]interface{}, len(selected))
	for name := range selected {
		v, ok := all[name]
		if !ok {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Invalid selected statistic '%s'", name),
			}
		}
		out[name] = v
	}
	return out, nil
}

// blockStatsToMap flattens a fully-populated blockStatsResult into a name→value
// map keyed by Core stat names, for the stats-subset path.
func blockStatsToMap(s *blockStatsResult) map[string]interface{} {
	return map[string]interface{}{
		"avgfee":               *s.AvgFee,
		"avgfeerate":           *s.AvgFeeRate,
		"avgtxsize":            *s.AvgTxSize,
		"blockhash":            *s.BlockHash,
		"feerate_percentiles":  *s.FeeRatePercentiles,
		"height":               *s.Height,
		"ins":                  *s.Ins,
		"maxfee":               *s.MaxFee,
		"maxfeerate":           *s.MaxFeeRate,
		"maxtxsize":            *s.MaxTxSize,
		"medianfee":            *s.MedianFee,
		"mediantime":           *s.MedianTime,
		"mediantxsize":         *s.MedianTxSize,
		"minfee":               *s.MinFee,
		"minfeerate":           *s.MinFeeRate,
		"mintxsize":            *s.MinTxSize,
		"outs":                 *s.Outs,
		"subsidy":              *s.Subsidy,
		"swtotal_size":         *s.SwTotalSize,
		"swtotal_weight":       *s.SwTotalWeight,
		"swtxs":                *s.SwTxs,
		"time":                 *s.Time,
		"total_out":            *s.TotalOut,
		"total_size":           *s.TotalSize,
		"total_weight":         *s.TotalWeight,
		"totalfee":             *s.TotalFee,
		"txs":                  *s.Txs,
		"utxo_increase":        *s.UTXOIncrease,
		"utxo_size_inc":        *s.UTXOSizeInc,
		"utxo_increase_actual": *s.UTXOIncreaseActual,
		"utxo_size_inc_actual": *s.UTXOSizeIncActual,
	}
}
