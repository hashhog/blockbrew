// scanblocks_methods.go — RPC handler for scanblocks
//
// Reference: Bitcoin Core src/rpc/blockchain.cpp::scanblocks
// (action start/status/abort).
//
//	scanblocks "action" ( [scanobjects] start_height stop_height "filtertype" options )
//
// scanblocks drives the BIP-157 basic block filter index to find blocks whose
// GCS filter MATCHES any of the given scanobjects' scriptPubKeys, returning
//
//	{ from_height, to_height, relevant_blocks:[blockhash...], completed }
//
// It is the index-side counterpart to scantxoutset (which walks the UTXO set):
// scanblocks walks compact block filters, so it can locate the block a script
// was funded/spent in even after the coin is gone.
//
// blockbrew runs the scan synchronously inside the RPC call, so there is never
// a background scan in progress:
//   - action=status -> null (Core: "no scan in progress")
//   - action=abort  -> false (Core: "reserve was possible -> nothing running")
//   - action=start  -> does the real work
//
// CENTRAL CAVEAT: block filters have FALSE POSITIVES (rate ~1/M, M=784931), so
// relevant_blocks may contain EXTRA blocks. The contract is that a block
// actually containing a matched script MUST appear, never that the list is
// exact.
//
// Error codes mirror Core:
//   - unknown filtertype -> RPC_INVALID_ADDRESS_OR_KEY (-5) "Unknown filtertype"
//   - index disabled     -> RPC_MISC_ERROR (-1) "Index is not enabled for filtertype <name>"
//   - bad start/stop hgt -> RPC_MISC_ERROR (-1) "Invalid start_height"/"Invalid stop_height"
package rpc

import (
	"encoding/json"
	"fmt"
)

// scanBlocksResult is the result of scanblocks "start".
//
// Field order mirrors Bitcoin Core's pushKV order in
// src/rpc/blockchain.cpp::scanblocks (from_height, to_height, relevant_blocks,
// completed) so the JSON shape is comparable.
type scanBlocksResult struct {
	FromHeight     int32    `json:"from_height"`
	ToHeight       int32    `json:"to_height"`
	RelevantBlocks []string `json:"relevant_blocks"`
	Completed      bool     `json:"completed"`
}

func (s *Server) handleScanBlocks(params json.RawMessage) (interface{}, *RPCError) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing action parameter"}
	}

	var action string
	if err := json.Unmarshal(args[0], &action); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid action parameter"}
	}

	switch action {
	case "status":
		// No background scan ever runs (this scan is synchronous), so there is
		// never anything in progress. Core returns null in that case.
		return nil, nil
	case "abort":
		// Nothing to abort; report no-scan-was-running.
		return false, nil
	case "start":
		return s.scanBlocksStart(args)
	default:
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: fmt.Sprintf("Invalid action '%s'", action),
		}
	}
}

func (s *Server) scanBlocksStart(args []json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// (1) scanobjects required for "start" (Core get_array on params[1]).
	if len(args) < 2 {
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: "scanobjects argument is required for the start action",
		}
	}

	// (2) filtertype validation (Core 2603-2606). Default "basic". This is
	// checked BEFORE the index-enabled gate so an unknown filtertype yields -5
	// even when the index is off, matching getblockfilter's order.
	filterType := "basic"
	if len(args) >= 5 {
		// args[4] may be JSON null (positional placeholder); only override when
		// it deserializes to a non-empty string.
		var ft string
		if err := json.Unmarshal(args[4], &ft); err == nil && ft != "" {
			filterType = ft
		}
	}
	if filterType != "basic" {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Unknown filtertype"}
	}

	// (3) Index-enabled gate (Core 2611-2614: GetBlockFilterIndex==null ->
	// RPC_MISC_ERROR "Index is not enabled for filtertype <name>"). Reuse the
	// same accessor getblockfilter / the REST handler use.
	bfi, errMsg := s.getBlockFilterIndex()
	if bfi == nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: errMsg}
	}

	// (4) Build the needle scripts from the scanobjects (Core 2643-2651).
	// Reuse parseScanObject — the same descriptor parser scantxoutset uses, so
	// addr()/raw()/pkh()/wpkh()/tr() parity is shared with that RPC.
	var scanObjects []json.RawMessage
	if err := json.Unmarshal(args[1], &scanObjects); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "scanobjects must be an array"}
	}
	needles := make([][]byte, 0, len(scanObjects))
	for _, raw := range scanObjects {
		spk, _, rerr := s.parseScanObject(raw)
		if rerr != nil {
			return nil, rerr
		}
		needles = append(needles, spk)
	}

	// (5) Height range (Core 2620-2641). NOTE Core uses RPC_MISC_ERROR (-1)
	// for bad heights here, NOT -8 like scantxoutset. Default start=genesis(0),
	// default stop=tip.
	_, tipHeight := s.chainMgr.BestBlock()
	tipNode := s.chainMgr.BestBlockNode()

	start := int32(0)
	if len(args) >= 3 {
		var sh int64
		if err := json.Unmarshal(args[2], &sh); err == nil {
			start = int32(sh)
		}
	}
	if start < 0 || start > tipHeight {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Invalid start_height"}
	}

	stop := tipHeight
	if len(args) >= 4 {
		var st int64
		if err := json.Unmarshal(args[3], &st); err == nil {
			// A JSON null placeholder leaves stop at the tip default; only a
			// numeric value overrides. (json.Unmarshal of "null" into int64
			// errors, so the default is preserved in that case.)
			stop = int32(st)
		}
	}
	if stop < start || stop > tipHeight {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Invalid stop_height"}
	}

	// blockHashAtHeight resolves the display-hex hash of the block at `height`
	// on the active chain. Mirrors scantxoutset's helper: prefer the in-memory
	// header index (tip->GetAncestor), fall back to the chain DB.
	blockHashAtHeight := func(height int32) string {
		if tipNode != nil {
			if anc := tipNode.GetAncestor(height); anc != nil {
				return anc.Hash.String()
			}
		}
		if s.chainDB != nil {
			if h, err := s.chainDB.GetBlockHashByHeight(height); err == nil {
				return h.String()
			}
		}
		return ""
	}

	// (6) Scan loop (Core 2664-2706). Walk [start, stop], match the filter at
	// each height against the needle scripts, and collect the block hashes of
	// matching blocks. With no scanobjects the loop matches nothing (Core: an
	// empty needle set never matches), so relevant_blocks comes back empty.
	relevant := make([]string, 0)
	if len(needles) > 0 {
		for h := start; h <= stop; h++ {
			matched, err := bfi.MatchFilter(h, needles)
			if err != nil {
				// A height in range lacks a filter row: the index is lagging
				// the chain. Surface a clear error rather than silently
				// returning a misleadingly incomplete relevant_blocks list.
				return nil, &RPCError{
					Code:    RPCErrMisc,
					Message: "Filter not found. Block filters are still in the process of being indexed.",
				}
			}
			if !matched {
				continue
			}
			bh := blockHashAtHeight(h)
			if bh == "" {
				return nil, &RPCError{
					Code:    RPCErrInternal,
					Message: fmt.Sprintf("could not resolve block hash at height %d", h),
				}
			}
			relevant = append(relevant, bh)
		}
	}

	// (7) Return (Core 2708-2711). The synchronous scan is never aborted, so
	// `completed` is always true.
	return &scanBlocksResult{
		FromHeight:     start,
		ToHeight:       stop,
		RelevantBlocks: relevant,
		Completed:      true,
	}, nil
}
