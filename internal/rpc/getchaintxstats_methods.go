package rpc

import (
	"encoding/json"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ChainTxStatsResult is the getchaintxstats response object.
//
// Mirrors Bitcoin Core's getchaintxstats result shape exactly
// (bitcoin-core/src/rpc/blockchain.cpp:1818-1835). Fields are emitted in
// Core's pushKV order:
//
//	time, txcount?, window_final_block_hash, window_final_block_height,
//	window_block_count, window_interval?, window_tx_count?, txrate?
//
// The four `?` fields are optional. They are pointers so that they marshal
// to JSON only when present, replicating Core's conditional pushKV:
//   - txcount: dropped when the cumulative tx count is unknown (e.g. assumeutxo).
//   - window_interval / window_tx_count / txrate: dropped per Core's nested
//     conditions (window_block_count == 0 drops all three; missing start/end
//     tx counts drop window_tx_count + txrate; window_interval <= 0 drops
//     txrate).
type ChainTxStatsResult struct {
	Time                   int64    `json:"time"`
	TxCount                *uint64  `json:"txcount,omitempty"`
	WindowFinalBlockHash   string   `json:"window_final_block_hash"`
	WindowFinalBlockHeight int32    `json:"window_final_block_height"`
	WindowBlockCount       int      `json:"window_block_count"`
	WindowInterval         *int64   `json:"window_interval,omitempty"`
	WindowTxCount          *uint64  `json:"window_tx_count,omitempty"`
	TxRate                 *float64 `json:"txrate,omitempty"`
}

// handleGetChainTxStats implements the getchaintxstats RPC.
//
// Computes transaction-count statistics over a window of blocks ending at a
// chosen block (default: the active chain tip). Read-only chain stats — not
// consensus. Faithful port of bitcoin-core/src/rpc/blockchain.cpp:1840-1896.
//
//	getchaintxstats ( nblocks "blockhash" )
//
// Both args optional. nblocks defaults to "one month" of blocks
// (30*24*60*60 / nPowTargetSpacing); on a short chain the default clamps to
// max(0, min(default, height-1)). blockhash defaults to the active tip.
//
// Semantics that are easy to get wrong, copied verbatim from Core:
//   - "time" is the FINAL block's RAW header nTime, not its median-time-past.
//   - "window_interval" uses MEDIAN-TIME-PAST (11-block window) of the final
//     block minus the MTP of the start block (pindex - nblocks), NOT raw times.
//   - "txcount" is the cumulative number of txs from genesis up to pindex
//     (Core's m_chain_tx_count).
//   - "window_tx_count" = txcount(pindex) - txcount(pindex - nblocks).
//   - "txrate" = window_tx_count / window_interval (only when interval > 0).
func (s *Server) handleGetChainTxStats(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil || s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Parse positional args. Both are optional; an absent/null arg falls back
	// to the Core defaults below.
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}

	nblocksGiven := len(args) >= 1 && args[0] != nil
	blockhashGiven := len(args) >= 2 && args[1] != nil

	// --- 1. Resolve pindex (the final block in the window). ---
	var pindex *consensus.BlockNode
	if !blockhashGiven {
		pindex = s.chainMgr.BestBlockNode()
		if pindex == nil {
			return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
		}
	} else {
		hashStr, ok := args[1].(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "blockhash must be a string"}
		}
		hash, err := wire.NewHash256FromHex(hashStr)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash format"}
		}
		pindex = s.headerIndex.GetNode(hash)
		if pindex == nil {
			// Core: RPC_INVALID_ADDRESS_OR_KEY (-5).
			return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Block not found"}
		}
		if !s.chainMgr.IsInMainChain(hash) {
			// Core: RPC_INVALID_PARAMETER (-8).
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Block is not in main chain"}
		}
	}

	// --- 2. Resolve blockcount (window size). ---
	// Default: 1 month of blocks = 30*24*60*60 / nPowTargetSpacing.
	blockcount := int(30 * 24 * 60 * 60 / s.chainParams.TargetSpacing)

	if !nblocksGiven {
		// Core: std::max(0, std::min(blockcount, pindex->nHeight - 1)).
		hm1 := int(pindex.Height) - 1
		if blockcount > hm1 {
			blockcount = hm1
		}
		if blockcount < 0 {
			blockcount = 0
		}
	} else {
		nblocksF, ok := args[0].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "nblocks must be a number"}
		}
		blockcount = int(nblocksF)
		// Core: blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight).
		if blockcount < 0 || (blockcount > 0 && blockcount >= int(pindex.Height)) {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Invalid block count: should be between 0 and the block's height - 1",
			}
		}
	}

	// --- 3. Window start block and MTP interval. ---
	pastBlock := pindex.GetAncestor(pindex.Height - int32(blockcount))
	if pastBlock == nil {
		// Should be unreachable given the bounds above; mirror Core's
		// CHECK_NONFATAL by failing loudly rather than silently mis-reporting.
		return nil, &RPCError{Code: RPCErrInternal, Message: "Window start block not found"}
	}
	nTimeDiff := pindex.GetMedianTimePast() - pastBlock.GetMedianTimePast()

	// --- 4. Assemble the result in Core's field order. ---
	res := &ChainTxStatsResult{
		Time:                   int64(pindex.Header.Timestamp), // RAW header nTime, not MTP.
		WindowFinalBlockHash:   pindex.Hash.String(),
		WindowFinalBlockHeight: pindex.Height,
		WindowBlockCount:       blockcount,
	}

	// Cumulative tx count up to pindex (Core's m_chain_tx_count). Optional:
	// dropped when unknown (e.g. an assumeutxo background-sync gap).
	endCount, endKnown := s.chainTxCount(pindex)
	if endKnown {
		ec := endCount
		res.TxCount = &ec
	}

	if blockcount > 0 {
		interval := nTimeDiff
		res.WindowInterval = &interval

		startCount, startKnown := s.chainTxCount(pastBlock)
		if endKnown && startKnown {
			windowTx := endCount - startCount
			res.WindowTxCount = &windowTx
			if nTimeDiff > 0 {
				rate := float64(windowTx) / float64(nTimeDiff)
				res.TxRate = &rate
			}
		}
	}

	return res, nil
}

// chainTxCount returns the cumulative number of transactions from genesis up
// to and including the given main-chain block (Bitcoin Core's
// CBlockIndex::m_chain_tx_count), plus a bool reporting whether the value is
// known.
//
// blockbrew does not stamp a running tx counter at block-connect (the
// consensus path stays untouched), so this is computed lazily and persisted
// into the "Q" cumulative-tx-count-by-height map (ChainDB.GetChainTxCount /
// PutChainTxCount). On a cache miss it walks back to the nearest stored
// height (or genesis), then walks forward summing per-block tx counts read
// from the block store, persisting each height so subsequent calls are O(1).
//
// Returns (0, false) when the block bodies needed to compute the count are
// not available locally (e.g. headers-only or assumeutxo gap), which makes
// the handler drop the optional txcount/window_tx_count/txrate fields exactly
// as Core does when m_chain_tx_count is unset.
func (s *Server) chainTxCount(node *consensus.BlockNode) (uint64, bool) {
	if node == nil {
		return 0, false
	}
	if s.chainDB == nil {
		return 0, false
	}
	target := node.Height
	if target < 0 {
		return 0, false
	}

	// Fast path: already persisted.
	if v, ok, err := s.chainDB.GetChainTxCount(target); err == nil && ok {
		return v, true
	}

	// Find the highest stored ancestor height < target to resume from, so we
	// don't re-walk the whole chain on every cold call. Probe a bounded number
	// of recent heights; if none is stored, fall back to a full walk from
	// genesis.
	var base uint64
	startH := int32(0) // first height we must (re)compute, inclusive
	const probeBack = 4320
	lowProbe := target - probeBack
	if lowProbe < 0 {
		lowProbe = 0
	}
	for h := target - 1; h >= lowProbe; h-- {
		if v, ok, err := s.chainDB.GetChainTxCount(h); err == nil && ok {
			base = v
			startH = h + 1
			break
		}
	}

	count := base
	for h := startH; h <= target; h++ {
		anc := node.GetAncestor(h)
		if anc == nil {
			return 0, false
		}
		block, err := s.chainDB.GetBlock(anc.Hash)
		if err != nil || block == nil {
			// Block body not available locally → count is unknown.
			return 0, false
		}
		count += uint64(len(block.Transactions))
		// Self-heal: persist as we go so future calls are O(1). Best-effort;
		// a write failure does not change the returned value.
		_ = s.chainDB.PutChainTxCount(h, count)
	}

	return count, true
}
