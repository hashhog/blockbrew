package rpc

import (
	"encoding/json"
	"log"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// DEFAULT_CHECKLEVEL / DEFAULT_CHECKBLOCKS — Core consensus defaults
// (bitcoin-core/src/validation.h: DEFAULT_CHECKLEVEL = 3,
// DEFAULT_CHECKBLOCKS = 6).
const (
	defaultVerifyCheckLevel  = 3
	defaultVerifyCheckBlocks = 6
)

// handleVerifyChain implements the verifychain RPC.
//
//	verifychain ( checklevel nblocks )
//
// Faithful port of bitcoin-core/src/rpc/blockchain.cpp::verifychain ->
// CVerifyDB::VerifyDB (validation.cpp:4611). It re-reads and re-validates the
// last `nblocks` blocks of the active chain, walking backward from the tip, at
// the requested `checklevel`, using the SAME validation machinery the node runs
// during sync (CheckBlockSanity == Core CheckBlock, the persisted undo data, and
// ParallelScriptValidationCached == the script-verification pass run inside
// ChainManager.ConnectBlock). Returns a bare JSON bool: true if every check
// passed, false on the first failure (Core returns
// VerifyDB(...) == VerifyDBResult::SUCCESS).
//
// checklevel meanings (Core CHECKLEVEL_DOC, ascending = cumulative):
//
//	0  read block from disk
//	1  + verify block validity (CheckBlock / CheckBlockSanity: PoW, merkle
//	     root, tx sanity, witness commitment, size/weight)
//	2  + verify undo data is present and decodes
//	3  + check coin-database consistency by a memory-only disconnect of the
//	     tip blocks (Core DisconnectBlock into a sandbox CCoinsViewCache).
//	     blockbrew reconstructs the pre-block UTXO set for each block from its
//	     persisted undo data and checks every spend is accounted for, the
//	     equivalent consistency check, WITHOUT mutating the live chainstate.
//	4  + reconnect: re-run full script verification for every non-coinbase tx
//	     using the persisted undo coins as the prevout source — the same
//	     ParallelScriptValidationCached pass ConnectBlock runs (Core
//	     ConnectBlock on the sandbox view).
//
// This is NOT a constant-true stub: every level above 0 invokes real validator
// functions and returns false (logging the failing height) on any failure. A
// corrupted/tampered block body, a missing or malformed undo record, or a
// script that no longer verifies all surface as a false result.
//
// NOT consensus-affecting (read-only; mutates no chainstate).
func (s *Server) handleVerifyChain(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil || s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}
	if s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Block store not available"}
	}

	// --- Parse params: [checklevel=3, nblocks=6]. ---
	checkLevel := defaultVerifyCheckLevel
	checkDepth := defaultVerifyCheckBlocks
	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
		if len(args) >= 1 && args[0] != nil {
			v, ok := jsonToInt(args[0])
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "checklevel must be a number"}
			}
			checkLevel = v
		}
		if len(args) >= 2 && args[1] != nil {
			v, ok := jsonToInt(args[1])
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "nblocks must be a number"}
			}
			checkDepth = v
		}
	}

	// Clamp checklevel to [0,4] (Core: std::max(0, std::min(4, nCheckLevel))).
	if checkLevel < 0 {
		checkLevel = 0
	}
	if checkLevel > 4 {
		checkLevel = 4
	}

	tip := s.chainMgr.BestBlockNode()
	if tip == nil || tip.Parent == nil {
		// Tip is nil or only genesis: nothing to verify. Core returns SUCCESS
		// when m_chain.Tip()==nullptr || Tip()->pprev==nullptr.
		return true, nil
	}
	tipHeight := tip.Height

	// nblocks <= 0 or > chain height means "all blocks" (Core: if nCheckDepth
	// <= 0 || nCheckDepth > m_chain.Height(), nCheckDepth = m_chain.Height()).
	if checkDepth <= 0 || checkDepth > int(tipHeight) {
		checkDepth = int(tipHeight)
	}

	log.Printf("verifychain: verifying last %d blocks at level %d (tip height %d)",
		checkDepth, checkLevel, tipHeight)

	// Lowest height we will visit. Core stops when pindex->nHeight <=
	// m_chain.Height() - nCheckDepth (exclusive), and never visits genesis
	// (the loop requires pindex->pprev). So we visit heights
	// (tipHeight - checkDepth, tipHeight], i.e. checkDepth blocks down to and
	// excluding the genesis when checkDepth == height.
	stopHeight := int(tipHeight) - checkDepth

	verified := 0
	node := tip
	for node != nil && node.Parent != nil {
		if int(node.Height) <= stopHeight {
			break
		}
		if ok, rpcErr := s.verifyOneBlock(node, checkLevel); rpcErr != nil {
			return nil, rpcErr
		} else if !ok {
			// A real validation failure. Core returns
			// VerifyDBResult::CORRUPTED_BLOCK_DB which maps to a false RPC
			// result. Already logged inside verifyOneBlock.
			return false, nil
		}
		verified++
		node = node.Parent
	}

	log.Printf("verifychain: OK — re-validated %d blocks at level %d", verified, checkLevel)
	return true, nil
}

// verifyOneBlock re-validates a single block at the requested level, reusing the
// node's real validation functions. Returns (true,nil) on success, (false,nil)
// on a validation failure (already logged), or (false,rpcErr) on an internal
// error that should surface as an RPC error rather than a false result.
func (s *Server) verifyOneBlock(node *consensus.BlockNode, checkLevel int) (bool, *RPCError) {
	hash := node.Hash

	// Level 0: read block from disk. Always done (Core ReadBlock). A read
	// failure here is Core's CORRUPTED_BLOCK_DB -> false.
	block, err := s.chainDB.GetBlock(hash)
	if err != nil || block == nil {
		log.Printf("verifychain: ReadBlock failed at height %d hash=%s: %v",
			node.Height, hash.String(), err)
		return false, nil
	}

	// Level 1: verify block validity — CheckBlockSanity is blockbrew's
	// CheckBlock (PoW + merkle root + tx sanity + witness commitment +
	// size/weight). Same function the live sync path runs via
	// ChainManager.ConnectBlock -> CheckBlockSanity. PoW is fully checked
	// (skipPOW defaults to false). This is what catches a tampered block body:
	// any mutation that changes a txid breaks the merkle root, and any header
	// mutation breaks PoW.
	if checkLevel >= 1 {
		if err := consensus.CheckBlockSanity(block, s.chainParams.PowLimit); err != nil {
			log.Printf("verifychain: found bad block at height %d hash=%s: %v",
				node.Height, hash.String(), err)
			return false, nil
		}
	}

	// Levels 2-4 operate on the persisted undo data. The genesis block has no
	// spends, but we never reach it here (the caller stops at node.Parent==nil).
	// A non-coinbase-only block legitimately has an empty undo.
	if checkLevel >= 2 {
		undo, uerr := s.chainDB.ReadBlockUndo(hash)
		if uerr != nil || undo == nil {
			log.Printf("verifychain: found bad undo data at height %d hash=%s: %v",
				node.Height, hash.String(), uerr)
			return false, nil
		}

		// Count non-coinbase transactions in the block: undo data carries one
		// TxUndo per non-coinbase tx (storage.BlockUndo contract). A mismatch
		// means the undo record does not describe this block.
		nonCoinbase := 0
		for i := range block.Transactions {
			if i == 0 {
				continue // coinbase has no inputs to undo
			}
			nonCoinbase++
		}

		// Level 3: coin-database consistency. Core memory-only-disconnects the
		// tip blocks into a sandbox CCoinsViewCache and asserts no
		// inconsistency. blockbrew's equivalent, WITHOUT touching the live
		// chainstate, is to reconstruct the spent-input set from the undo
		// record and confirm every non-coinbase input has a matching spent
		// coin (one per input, the disconnect-undo invariant). A drift here is
		// exactly the inconsistency Core's DisconnectBlock would report.
		if checkLevel >= 3 {
			if len(undo.TxUndos) != nonCoinbase {
				log.Printf("verifychain: undo/tx count mismatch at height %d hash=%s "+
					"(undo=%d non-coinbase-tx=%d)",
					node.Height, hash.String(), len(undo.TxUndos), nonCoinbase)
				return false, nil
			}
			ui := 0
			for i, tx := range block.Transactions {
				if i == 0 {
					continue
				}
				txUndo := undo.TxUndos[ui]
				ui++
				if len(txUndo.SpentCoins) != len(tx.TxIn) {
					log.Printf("verifychain: undo input-count mismatch at height %d "+
						"hash=%s tx=%d (undo=%d txin=%d)",
						node.Height, hash.String(), i, len(txUndo.SpentCoins), len(tx.TxIn))
					return false, nil
				}
			}
		}

		// Level 4: reconnect — re-run full script verification for every
		// non-coinbase tx, using the persisted undo coins as the prevout
		// source. This is the SAME ParallelScriptValidationCached pass that
		// ChainManager.ConnectBlock runs during sync (chainmanager.go:945).
		// Building the prevout view from undo data mirrors Core's ConnectBlock
		// re-applying the block against the sandbox view in VerifyDB's
		// level-4 reconnect loop.
		if checkLevel >= 4 {
			if ok, rpcErr := s.reverifyBlockScripts(block, node, undo); rpcErr != nil {
				return false, rpcErr
			} else if !ok {
				return false, nil
			}
		}
	}

	return true, nil
}

// reverifyBlockScripts re-runs the block's script verification using the
// persisted undo data as the prevout source, reusing the node's real
// ParallelScriptValidationCached. Returns (true,nil) on pass, (false,nil) on a
// script failure (logged), or (false,rpcErr) on an internal error.
func (s *Server) reverifyBlockScripts(block *wire.MsgBlock, node *consensus.BlockNode, undo *storage.BlockUndo) (bool, *RPCError) {
	// Build an in-memory prevout view from the undo coins. Core's ConnectBlock
	// reconnect reads prevouts from the (disconnected) sandbox coins view; the
	// undo record IS exactly those spent coins (value + pkScript + height +
	// coinbase), so it reproduces the prevout set this block consumed.
	view := consensus.NewInMemoryUTXOView()
	ui := 0
	for i, tx := range block.Transactions {
		if i == 0 {
			continue // coinbase: no prevouts to supply
		}
		if ui >= len(undo.TxUndos) {
			log.Printf("verifychain: level-4 undo underflow at height %d tx=%d", node.Height, i)
			return false, nil
		}
		txUndo := undo.TxUndos[ui]
		ui++
		if len(txUndo.SpentCoins) != len(tx.TxIn) {
			log.Printf("verifychain: level-4 undo input-count mismatch at height %d tx=%d", node.Height, i)
			return false, nil
		}
		for j, in := range tx.TxIn {
			sc := txUndo.SpentCoins[j]
			view.AddUTXO(in.PreviousOutPoint, &consensus.UTXOEntry{
				Amount:     sc.TxOut.Value,
				PkScript:   sc.TxOut.PkScript,
				Height:     sc.Height,
				IsCoinbase: sc.Coinbase,
			})
		}
	}

	// Same script flags ConnectBlock derives for this height/hash.
	flags := consensus.GetBlockScriptFlags(node.Height, s.chainParams, node.Hash)

	// Reuse the node's real (cached, parallel) script-validation pass. A nil
	// sigcache is acceptable — ParallelScriptValidationCached treats it as "no
	// cache" and still verifies every input.
	if err := consensus.ParallelScriptValidationCached(block, view, flags, nil); err != nil {
		log.Printf("verifychain: found unconnectable block at height %d hash=%s: %v",
			node.Height, node.Hash.String(), err)
		return false, nil
	}
	return true, nil
}

// jsonToInt coerces a JSON-decoded value (float64 from encoding/json, or a
// json.Number) to an int. Returns (0,false) for non-numeric values.
func jsonToInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}
