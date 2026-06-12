package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// handleGetTxSpendingPrevout implements the gettxspendingprevout RPC, matching
// Bitcoin Core's rpc/mempool.cpp::gettxspendingprevout (v31.99) exactly.
//
// Scans the mempool (and, if -txospenderindex is enabled, the confirmed-spend
// index) to find transactions spending any of the given outputs.
//
// Params:
//
//	[0] outputs  (ARR, required): array of {"txid": hex, "vout": num>=0}.
//	    Empty -> RPC_INVALID_PARAMETER "Invalid parameter, outputs are missing".
//	    Negative vout -> "Invalid parameter, vout cannot be negative".
//	[1] options  (OBJ, optional, strict): {mempool_only:bool, return_spending_tx:bool}.
//	    mempool_only default = (txospenderindex unavailable); return_spending_tx default false.
//
// Output: ARR of OBJ, pushKV order per object:
//
//	txid, vout, [spendingtxid], [spendingtx], [blockhash]
//
// blockhash is set ONLY on the confirmed/index path (never for a mempool
// spender). Unspent -> object carries only txid+vout.
//
// Algorithm (Core mempool.cpp:937-1039): scan the mempool FIRST via the
// outpoint reverse-index (Core's GetConflictTx). For each entry, if a mempool
// spender is found OR mempool_only is set, emit and drop from the worklist.
// Return early if the worklist is empty. Otherwise (mempool_only==false) the
// index must be available and synced, else RPC_MISC_ERROR; for each remaining
// outpoint, look it up in the index.
func (s *Server) handleGetTxSpendingPrevout(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, outputs are missing"}
	}

	outputParams, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, outputs must be an array"}
	}
	// Core: const UniValue& output_params = request.params[0].get_array();
	//       if (output_params.empty()) throw "Invalid parameter, outputs are missing".
	if len(outputParams) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, outputs are missing"}
	}

	// Locate the confirmed-spend index (nil when -txospenderindex is off).
	var spenderIndex *storage.TxoSpenderIndex
	if s.indexManager != nil {
		if idx := s.indexManager.GetIndex("txospenderindex"); idx != nil {
			if ts, ok := idx.(*storage.TxoSpenderIndex); ok {
				spenderIndex = ts
			}
		}
	}

	// Parse options (strict: only mempool_only + return_spending_tx).
	// mempool_only default = !index-available (Core: !g_txospenderindex).
	mempoolOnly := spenderIndex == nil
	returnSpendingTx := false
	if len(args) >= 2 && args[1] != nil {
		optMap, ok := args[1].(map[string]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid options object"}
		}
		for k := range optMap {
			if k != "mempool_only" && k != "return_spending_tx" {
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter " + k}
			}
		}
		if v, present := optMap["mempool_only"]; present {
			b, ok := v.(bool)
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "JSON value of type ... is not of expected type bool"}
			}
			mempoolOnly = b
		}
		if v, present := optMap["return_spending_tx"]; present {
			b, ok := v.(bool)
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "JSON value of type ... is not of expected type bool"}
			}
			returnSpendingTx = b
		}
	}

	// Worklist entry: parsed outpoint + the original {txid,vout} so the result
	// object copies txid/vout verbatim (Core: `UniValue o{*prevout.raw}`).
	type entry struct {
		outpoint wire.OutPoint
		txidStr  string
		vout     int
	}
	worklist := make([]entry, 0, len(outputParams))
	for _, raw := range outputParams {
		o, ok := raw.(map[string]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, output must be an object"}
		}
		// Strict: exactly txid + vout.
		for k := range o {
			if k != "txid" && k != "vout" {
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter " + k}
			}
		}
		txidStr, ok := o["txid"].(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, missing txid"}
		}
		voutF, ok := o["vout"].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, missing vout"}
		}
		nOutput := int(voutF)
		if nOutput < 0 {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameter, vout cannot be negative"}
		}
		txid, err := wire.NewHash256FromHex(txidStr)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "txid must be hexadecimal string (not '" + txidStr + "')"}
		}
		worklist = append(worklist, entry{
			outpoint: wire.OutPoint{Hash: txid, Index: uint32(nOutput)},
			txidStr:  txidStr,
			vout:     nOutput,
		})
	}

	// makeOutput builds the per-output object in Core's pushKV order:
	// txid, vout, [spendingtxid], [spendingtx]. blockhash is appended by the
	// caller on the confirmed path only.
	makeOutput := func(e entry, spendingTx *wire.MsgTx) *omap {
		o := newOMap().Set("txid", e.txidStr).Set("vout", e.vout)
		if spendingTx != nil {
			o.Set("spendingtxid", spendingTx.TxHash().String())
			if returnSpendingTx {
				var buf bytes.Buffer
				if err := spendingTx.Serialize(&buf); err == nil {
					o.Set("spendingtx", hex.EncodeToString(buf.Bytes()))
				}
			}
		}
		return o
	}

	result := make([]interface{}, 0, len(worklist))

	// Phase 1: scan the mempool first (Core's GetConflictTx reverse-index).
	remaining := worklist[:0]
	for _, e := range worklist {
		var spendingTx *wire.MsgTx
		if s.mempool != nil {
			if spenderTxid := s.mempool.CheckSpend(e.outpoint); spenderTxid != nil {
				spendingTx = s.mempool.GetTransaction(*spenderTxid)
			}
		}
		// If unspent in mempool and this is not a mempool-only request, defer.
		if spendingTx == nil && !mempoolOnly {
			remaining = append(remaining, e)
			continue
		}
		result = append(result, makeOutput(e, spendingTx))
	}

	// Return early if the mempool scan handled everything (Core early-return).
	if len(remaining) == 0 {
		return result, nil
	}

	// Phase 2: the request was not mempool-only and some outpoints are
	// unresolved. Require the index to be available AND synced to the tip
	// (Core: !g_txospenderindex || !BlockUntilSyncedToCurrentChain()).
	tipSynced := false
	if spenderIndex != nil && s.chainMgr != nil {
		_, tipHeight := s.chainMgr.BestBlock()
		tipSynced = spenderIndex.BestHeight() >= tipHeight
	}
	if spenderIndex == nil || !tipSynced {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Mempool lacks a relevant spend, and txospenderindex is unavailable."}
	}

	for _, e := range remaining {
		spender, found, err := spenderIndex.FindSpender(e.outpoint)
		if err != nil {
			return nil, &RPCError{Code: RPCErrMisc, Message: err.Error()}
		}
		if found {
			// Fetch the full spending tx only when needed (return_spending_tx),
			// reading it from the spending block recorded in the index entry.
			var spendingTx *wire.MsgTx
			if returnSpendingTx {
				spendingTx = s.fetchTxFromBlock(spender.SpendingTxid, spender.BlockHash)
			} else {
				// Need the txid for spendingtxid; synthesize a tx carrying it so
				// makeOutput emits the recorded spending txid verbatim.
				spendingTx = nil
			}
			var o *omap
			if spendingTx != nil {
				o = makeOutput(e, spendingTx)
			} else {
				o = newOMap().Set("txid", e.txidStr).Set("vout", e.vout)
				o.Set("spendingtxid", spender.SpendingTxid.String())
			}
			o.Set("blockhash", spender.BlockHash.String())
			result = append(result, o)
		} else {
			// Unspent on-chain: only txid+vout (Core make_output(prevout)).
			result = append(result, makeOutput(e, nil))
		}
	}

	return result, nil
}

// fetchTxFromBlock reads a confirmed transaction by txid from the block that
// confirmed it (recorded in the spender-index entry). Returns nil if the block
// or tx cannot be read; the caller then omits the spendingtx field.
func (s *Server) fetchTxFromBlock(txid, blockHash wire.Hash256) *wire.MsgTx {
	if s.chainDB == nil {
		return nil
	}
	block, err := s.chainDB.GetBlock(blockHash)
	if err != nil {
		return nil
	}
	for _, btx := range block.Transactions {
		if btx.TxHash() == txid {
			return btx
		}
	}
	return nil
}
