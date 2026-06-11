// wave47b_methods.go — RPC ports from wave-47b P2:
//   gettxoutsetinfo, getnetworkhashps, gettxoutproof, verifytxoutproof, getrpcinfo
//
// Reference: Bitcoin Core src/rpc/blockchain.cpp + src/rpc/mining.cpp
// Ouroboros reference: src/ouroboros/rpc.py
package rpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// gettxoutsetinfo
// ============================================================================

// handleGetTxOutSetInfo implements `gettxoutsetinfo ( "hash_type" hash_or_height
// use_index )` for the base chainstate at the tip (no coinstatsindex).
//
// Reference: bitcoin-core/src/rpc/blockchain.cpp::gettxoutsetinfo +
// src/kernel/coinstats.cpp::ComputeUTXOStats. We walk the entire UTXO set
// (flush-then-cursor, via consensus.ComputeUTXOSetInfo) and report
// height/bestblock/txouts/total_amount + the requested set hash.
//
// hash_type defaults to "hash_serialized_3" (Core's legacy SHA256d digest over
// the coin cursor) and also accepts "muhash" (MuHash3072) and "none". The
// hash_or_height argument requires coinstatsindex, which blockbrew does not run
// here; per Core, hash_serialized_3 with a specific block is rejected with
// RPC_INVALID_PARAMETER (-8). An unrecognized hash_type is likewise -8.
func (s *Server) handleGetTxOutSetInfo(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Parse positional args: [hash_type, hash_or_height, use_index].
	var args []json.RawMessage
	if len(params) > 0 {
		_ = json.Unmarshal(params, &args)
	}

	hashType := "hash_serialized_3"
	if len(args) >= 1 {
		var ht string
		if err := json.Unmarshal(args[0], &ht); err == nil && ht != "" {
			hashType = ht
		}
	}

	// ParseHashType: validate the hash_type up front (Core blockchain.cpp:967).
	switch hashType {
	case "hash_serialized_3", "muhash", "none":
	default:
		return nil, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("'%s' is not a valid hash_type", hashType),
		}
	}

	// hash_or_height present (non-null) => coinstatsindex territory. blockbrew's
	// base chainstate only knows the tip; a specific block can only be served
	// from the coinstatsindex, mirroring Core's gettxoutsetinfo dispatch
	// (blockchain.cpp:1086-1092).
	specificBlock := false
	if len(args) >= 2 {
		var raw interface{}
		if err := json.Unmarshal(args[1], &raw); err == nil && raw != nil {
			specificBlock = true
		}
	}
	if specificBlock {
		// Is the coinstatsindex registered?
		var csi *storage.CoinStatsIndex
		if s.indexManager != nil {
			if idx := s.indexManager.GetIndex("coinstatsindex"); idx != nil {
				csi, _ = idx.(*storage.CoinStatsIndex)
			}
		}
		if csi == nil {
			// Without the index, ANY specific-block query is rejected with
			// "Querying specific block heights requires coinstatsindex"
			// (blockchain.cpp:1086), before the hash_serialized_3-specific
			// guard is reached. RPC_INVALID_PARAMETER (-8).
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Querying specific block heights requires coinstatsindex",
			}
		}
		// hash_serialized_3 cannot be served for a specific block even with the
		// index — only the order-independent muhash (and none) are maintained
		// per height (blockchain.cpp:992 + 1089-1092). RPC_INVALID_PARAMETER (-8).
		if hashType == "hash_serialized_3" {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "hash_serialized_3 hash type cannot be queried for a specific block",
			}
		}

		// Resolve args[1] to a main-chain height H. It is either an integer
		// height or a 32-byte block hash (display order, big-endian hex).
		height, rerr := s.resolveHashOrHeight(args[1])
		if rerr != nil {
			return nil, rerr
		}

		stats, err := csi.GetStats(height)
		if err != nil {
			// Above the index best / not indexed / out of range.
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Can't read the UTXO set statistics for block at height %d", height),
			}
		}

		// Build the index-served response. Per Core (blockchain.cpp:1034-1035)
		// the index path omits `transactions` and `disk_size` and adds
		// total_unspendable_amount + block_info; we emit the subset the class
		// actually tracks (height, bestblock, txouts, bogosize, total_amount,
		// and the muhash digest).
		// Core order (index path, blockchain.cpp:1115): height, bestblock,
		// txouts, bogosize, [muhash], total_amount — muhash before total_amount.
		ret := newOMap().
			Set("height", height).
			Set("bestblock", stats.BlockHash.String()).
			Set("txouts", stats.UTXOCount).
			Set("bogosize", stats.BogoSize)
		if hashType == "muhash" {
			ret.Set("muhash", stats.HashSerialized.String())
		}
		ret.Set("total_amount", btcAmount(stats.TotalAmount))
		return ret, nil
	}

	tipHash, tipHeight := s.chainMgr.BestBlock()

	utxoSet := s.chainMgr.UTXOSet()
	us, ok := utxoSet.(*consensus.UTXOSet)
	if !ok || us == nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Unable to read UTXO set"}
	}

	info, err := consensus.ComputeUTXOSetInfo(us)
	if err != nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Unable to read UTXO set"}
	}

	// disk_size: Core fills this from CCoinsViewDB::EstimateSize(), the LevelDB
	// estimated on-disk byte count of the coins database. That value is storage-
	// engine-specific and non-deterministic (it depends on flush/compaction
	// state) — on a freshly-mined regtest chain whose coins are still in the
	// in-memory cache (unflushed) Core's EstimateSize() returns 0. blockbrew's
	// from-scratch UTXO store has no comparable LevelDB-estimate and cannot
	// reproduce Core's number byte-for-byte, so (matching the cross-impl
	// convention — rustoshi server.rs:10384, clearbit rpc.zig:16349 both emit 0)
	// we report disk_size as 0 rather than a non-portable proxy (it was bogosize,
	// which spuriously diverged from Core's 0).
	diskSize := uint64(0)

	// Emit in Core's gettxoutsetinfo pushKV order (blockchain.cpp:1115):
	// height, bestblock, txouts, bogosize, [hash_serialized_3|muhash],
	// total_amount, transactions, disk_size — the hash digest is pushed BEFORE
	// total_amount, NOT last. Go map order (alphabetical) diverges, so use omap.
	ret := newOMap().
		Set("height", tipHeight).
		Set("bestblock", tipHash.String()).
		Set("txouts", info.TxOuts).
		Set("bogosize", info.BogoSize)
	switch hashType {
	case "hash_serialized_3":
		ret.Set("hash_serialized_3", info.HashSerialized3.String())
	case "muhash":
		ret.Set("muhash", info.MuHash.String())
	}
	ret.Set("total_amount", btcAmount(info.TotalAmount)).
		Set("transactions", info.Transactions).
		Set("disk_size", diskSize)
	return ret, nil
}

// resolveHashOrHeight maps the gettxoutsetinfo hash_or_height argument to a
// main-chain block height. The argument is either:
//   - a JSON integer height, validated against [0, tipHeight]; or
//   - a JSON string block hash (display order, big-endian hex), resolved to its
//     height via the header index (must be a known block).
//
// Mirrors Bitcoin Core's ParseHashOrHeight (rpc/blockchain.cpp). Errors use
// RPC_INVALID_PARAMETER (-8), matching Core's height/hash validation arm.
func (s *Server) resolveHashOrHeight(arg json.RawMessage) (int32, *RPCError) {
	_, tipHeight := s.chainMgr.BestBlock()

	// Try integer height first.
	var h int64
	if err := json.Unmarshal(arg, &h); err == nil {
		if h < 0 || h > int64(tipHeight) {
			return 0, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Target block height %d after current tip %d", h, tipHeight),
			}
		}
		return int32(h), nil
	}

	// Otherwise a block-hash string (display order).
	var hs string
	if err := json.Unmarshal(arg, &hs); err != nil {
		return 0, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: "hash_or_height must be a block height (int) or block hash (hex string)",
		}
	}
	b, err := hex.DecodeString(hs)
	if err != nil || len(b) != 32 {
		return 0, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("blockhash must be of length 64 (not %d)", len(hs)),
		}
	}
	// Display order (big-endian) -> internal little-endian.
	var hash wire.Hash256
	copy(hash[:], b)
	reverseBytes(hash[:])

	if s.headerIndex == nil {
		return 0, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}
	node := s.headerIndex.GetNode(hash)
	if node == nil {
		return 0, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Block not found"}
	}
	if node.Height < 0 || node.Height > tipHeight {
		return 0, &RPCError{Code: RPCErrInvalidParameter, Message: "Block is not in the main chain"}
	}
	// Confirm the block is on the active chain at that height (not a stale fork).
	if s.chainDB != nil {
		mainHash, herr := s.chainDB.GetBlockHashByHeight(node.Height)
		if herr == nil && mainHash != hash {
			return 0, &RPCError{Code: RPCErrInvalidParameter, Message: "Block is not in the main chain"}
		}
	}
	return node.Height, nil
}

// ============================================================================
// getnetworkhashps
// ============================================================================

func (s *Server) handleGetNetworkHashPS(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Parse optional [nblocks, height].
	var args []interface{}
	_ = json.Unmarshal(params, &args)
	nblocksI := int64(120)
	heightI := int64(-1)
	if len(args) >= 1 {
		if v, ok := args[0].(float64); ok {
			nblocksI = int64(v)
		}
	}
	if len(args) >= 2 {
		if v, ok := args[1].(float64); ok {
			heightI = int64(v)
		}
	}

	_, bestHeight := s.chainMgr.BestBlock()
	tipH := int32(bestHeight)
	if heightI >= 0 && int32(heightI) <= bestHeight {
		tipH = int32(heightI)
	}

	nblocks := nblocksI
	if nblocks <= 0 {
		nblocks = int64(tipH % 2016)
		if nblocks == 0 {
			nblocks = 1
		}
	}
	if int32(nblocks) > tipH {
		nblocks = int64(tipH)
	}
	if nblocks == 0 {
		return 0.0, nil
	}

	// Look up headers at tipH and tipH-nblocks.
	tipNode := s.headerIndex.GetHeaderByHeight(tipH)
	startNode := s.headerIndex.GetHeaderByHeight(tipH - int32(nblocks))
	if tipNode == nil || startNode == nil {
		return 0.0, nil
	}

	timeDiff := int64(tipNode.Header.Timestamp) - int64(startNode.Header.Timestamp)
	if timeDiff <= 0 {
		return 0.0, nil
	}

	// Chainwork diff as float64.
	var workDiff *big.Int
	if tipNode.TotalWork != nil && startNode.TotalWork != nil {
		workDiff = new(big.Int).Sub(tipNode.TotalWork, startNode.TotalWork)
	} else {
		return 0.0, nil
	}
	if workDiff.Sign() <= 0 {
		return 0.0, nil
	}

	wf, _ := new(big.Float).SetInt(workDiff).Float64()
	return wf / float64(timeDiff), nil
}

// ============================================================================
// gettxoutproof
// ============================================================================

func (s *Server) handleGetTxOutProof(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil || s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Expected [txids, (blockhash)]"}
	}

	txidsRaw, ok := args[0].([]interface{})
	if !ok || len(txidsRaw) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "txids must be a non-empty array"}
	}

	targetSet := make(map[wire.Hash256]struct{})
	for _, raw := range txidsRaw {
		s2, ok2 := raw.(string)
		if !ok2 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "txid must be a string"}
		}
		b, err := hex.DecodeString(s2)
		if err != nil || len(b) != 32 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid txid: %s", s2)}
		}
		// Display order is big-endian; internal Hash256 is little-endian.
		var h wire.Hash256
		copy(h[:], b)
		reverseBytes(h[:])
		targetSet[h] = struct{}{}
	}

	var block *wire.MsgBlock
	if len(args) >= 2 {
		bh, ok2 := args[1].(string)
		if !ok2 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "blockhash must be a string"}
		}
		b, err := hex.DecodeString(bh)
		if err != nil || len(b) != 32 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash"}
		}
		var hash wire.Hash256
		copy(hash[:], b)
		reverseBytes(hash[:])
		blk, err2 := s.chainDB.GetBlock(hash)
		if err2 != nil || blk == nil {
			return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
		}
		block = blk
	} else {
		// Search the last 100 blocks for any that contain the target txids.
		_, tipHeight := s.chainMgr.BestBlock()
		for h := tipHeight; h >= tipHeight-100 && h >= 0; h-- {
			hash, err := s.chainDB.GetBlockHashByHeight(h)
			if err != nil {
				continue
			}
			blk, err := s.chainDB.GetBlock(hash)
			if err != nil || blk == nil {
				continue
			}
			for _, tx := range blk.Transactions {
				txid := tx.TxHash()
				if _, ok2 := targetSet[txid]; ok2 {
					block = blk
					break
				}
			}
			if block != nil {
				break
			}
		}
		if block == nil {
			return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Transaction not found in recent blocks"}
		}
	}

	// Collect all txids and verify targets are present.
	allTxIDs := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		allTxIDs[i] = tx.TxHash()
	}
	for t := range targetSet {
		found := false
		for _, id := range allTxIDs {
			if id == t {
				found = true
				break
			}
		}
		if !found {
			display := t
			reverseBytes(display[:])
			return nil, &RPCError{Code: RPCErrInvalidParams,
				Message: fmt.Sprintf("Transaction %s not found in block", hex.EncodeToString(display[:]))}
		}
	}

	matches := make([]bool, len(allTxIDs))
	for i, id := range allTxIDs {
		_, matches[i] = targetSet[id]
	}

	// Serialize 80-byte header.
	var headerBuf bytes.Buffer
	if err := block.Header.Serialize(&headerBuf); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize header"}
	}
	headerBytes := headerBuf.Bytes()[:80]

	proofBytes := buildPartialMerkleTree(headerBytes, allTxIDs, matches)
	return hex.EncodeToString(proofBytes), nil
}

// ============================================================================
// verifytxoutproof
// ============================================================================

func (s *Server) handleVerifyTxOutProof(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Expected [proof_hex]"}
	}
	proofHex, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "proof must be a string"}
	}
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hex"}
	}
	if len(proofBytes) < 84 {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Proof too short"}
	}

	headerBytes := proofBytes[:80]
	blockHash := dsha256Block(headerBytes)

	// Confirm block is in our chain.
	var bhash wire.Hash256
	copy(bhash[:], blockHash[:])
	if _, err2 := s.chainDB.GetBlock(bhash); errors.Is(err2, errors.New("not found")) || err2 != nil {
		// Try header index as fallback.
		if s.headerIndex == nil || s.headerIndex.GetNode(bhash) == nil {
			return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not in chain"}
		}
	}

	// The merkle root in the header (LE bytes 36..68).
	merkleRootInHeader := headerBytes[36:68]

	matched, computedRoot, parseErr := parsePartialMerkleTree(proofBytes[80:])
	if parseErr != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: parseErr.Error()}
	}
	if !bytes.Equal(computedRoot, merkleRootInHeader) {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Merkle root mismatch"}
	}

	// Return txids in display order (reversed).
	result := make([]string, len(matched))
	for i, m := range matched {
		display := make([]byte, 32)
		copy(display, m[:])
		reverseBytes(display)
		result[i] = hex.EncodeToString(display)
	}
	return result, nil
}

// ============================================================================
// getrpcinfo
// ============================================================================

func (s *Server) handleGetRPCInfo(_ json.RawMessage) (interface{}, *RPCError) {
	return map[string]interface{}{
		"active_commands": []interface{}{},
		"logpath":         "",
	}, nil
}

// ============================================================================
// Partial Merkle tree helpers (CMerkleBlock wire format)
// Mirrors Bitcoin Core src/merkleblock.cpp
// ============================================================================

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func dsha256Block(data []byte) [32]byte {
	h1 := sha256.Sum256(data)
	return sha256.Sum256(h1[:])
}

func dsha256Pair(a, b [32]byte) [32]byte {
	var combined [64]byte
	copy(combined[:32], a[:])
	copy(combined[32:], b[:])
	return dsha256Block(combined[:])
}

func treeWidth(nTx, height int) int {
	return (nTx + (1 << height) - 1) >> height
}

func calcTreeHash(txids []wire.Hash256, nTx, height, pos int) [32]byte {
	if height == 0 {
		if pos < nTx {
			return txids[pos]
		}
		return [32]byte{}
	}
	left := calcTreeHash(txids, nTx, height-1, pos*2)
	rightPos := pos*2 + 1
	var right [32]byte
	if rightPos < treeWidth(nTx, height-1) {
		right = calcTreeHash(txids, nTx, height-1, rightPos)
	} else {
		right = left
	}
	return dsha256Pair(left, right)
}

func encodeVarInt(n int) []byte {
	switch {
	case n < 0xFD:
		return []byte{byte(n)}
	case n <= 0xFFFF:
		b := make([]byte, 3)
		b[0] = 0xFD
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xFFFFFFFF:
		b := make([]byte, 5)
		b[0] = 0xFE
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xFF
		binary.LittleEndian.PutUint64(b[1:], uint64(n))
		return b
	}
}

func buildPartialMerkleTree(headerBytes []byte, txids []wire.Hash256, matches []bool) []byte {
	n := len(txids)
	height := 0
	for (1 << height) < n {
		height++
	}

	var hashes [][32]byte
	var bits []bool

	var traverse func(h, pos int)
	traverse = func(h, pos int) {
		start := pos << h
		end := (pos + 1) << h
		if end > n {
			end = n
		}
		parentMatch := false
		for i := start; i < end; i++ {
			if matches[i] {
				parentMatch = true
				break
			}
		}
		bits = append(bits, parentMatch)
		if h == 0 || !parentMatch {
			if h == 0 {
				if pos < n {
					hashes = append(hashes, txids[pos])
				} else {
					hashes = append(hashes, [32]byte{})
				}
			} else {
				h32 := calcTreeHash(txids, n, h, pos)
				hashes = append(hashes, h32)
			}
		} else {
			traverse(h-1, pos*2)
			if pos*2+1 < treeWidth(n, h-1) {
				traverse(h-1, pos*2+1)
			}
		}
	}
	traverse(height, 0)

	var result []byte
	result = append(result, headerBytes[:80]...)
	nBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nBytes, uint32(n))
	result = append(result, nBytes...)
	result = append(result, encodeVarInt(len(hashes))...)
	for _, h := range hashes {
		result = append(result, h[:]...)
	}
	flagCount := (len(bits) + 7) / 8
	result = append(result, encodeVarInt(flagCount)...)
	flagBytes := make([]byte, flagCount)
	for i, b := range bits {
		if b {
			flagBytes[i/8] |= 1 << (i % 8)
		}
	}
	result = append(result, flagBytes...)
	return result
}

func readVarIntBB(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("unexpected end reading varint")
	}
	switch data[offset] {
	case 0xFD:
		if offset+3 > len(data) {
			return 0, 0, fmt.Errorf("short 2-byte varint")
		}
		return int(binary.LittleEndian.Uint16(data[offset+1:])), offset + 3, nil
	case 0xFE:
		if offset+5 > len(data) {
			return 0, 0, fmt.Errorf("short 4-byte varint")
		}
		return int(binary.LittleEndian.Uint32(data[offset+1:])), offset + 5, nil
	case 0xFF:
		if offset+9 > len(data) {
			return 0, 0, fmt.Errorf("short 8-byte varint")
		}
		return int(binary.LittleEndian.Uint64(data[offset+1:])), offset + 9, nil
	default:
		return int(data[offset]), offset + 1, nil
	}
}

func parsePartialMerkleTree(data []byte) ([]wire.Hash256, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("proof payload too short")
	}
	nTx := int(binary.LittleEndian.Uint32(data[:4]))
	offset := 4

	nHashes, off, err := readVarIntBB(data, offset)
	if err != nil {
		return nil, nil, err
	}
	offset = off

	hashes := make([][32]byte, nHashes)
	for i := 0; i < nHashes; i++ {
		if offset+32 > len(data) {
			return nil, nil, fmt.Errorf("proof truncated in hashes")
		}
		copy(hashes[i][:], data[offset:offset+32])
		offset += 32
	}

	nFlagBytes, off2, err := readVarIntBB(data, offset)
	if err != nil {
		return nil, nil, err
	}
	offset = off2
	if offset+nFlagBytes > len(data) {
		return nil, nil, fmt.Errorf("proof truncated in flags")
	}
	flagBytesRaw := data[offset : offset+nFlagBytes]
	allBits := make([]bool, nFlagBytes*8)
	for i, b := range flagBytesRaw {
		for bit := 0; bit < 8; bit++ {
			allBits[i*8+bit] = (b & (1 << bit)) != 0
		}
	}

	height := 0
	for (1 << height) < nTx {
		height++
	}

	hashIdx := 0
	bitIdx := 0
	var matched []wire.Hash256

	var consume func(h, pos int) ([32]byte, error)
	consume = func(h, pos int) ([32]byte, error) {
		if bitIdx >= len(allBits) {
			return [32]byte{}, fmt.Errorf("bits exhausted")
		}
		parentMatch := allBits[bitIdx]
		bitIdx++

		if h == 0 {
			var cur [32]byte
			if hashIdx < len(hashes) {
				cur = hashes[hashIdx]
			}
			hashIdx++
			if parentMatch {
				matched = append(matched, cur)
			}
			return cur, nil
		}

		if !parentMatch {
			var cur [32]byte
			if hashIdx < len(hashes) {
				cur = hashes[hashIdx]
			}
			hashIdx++
			return cur, nil
		}

		left, err := consume(h-1, pos*2)
		if err != nil {
			return [32]byte{}, err
		}
		rightPos := pos*2 + 1
		var right [32]byte
		if rightPos < treeWidth(nTx, h-1) {
			right, err = consume(h-1, rightPos)
			if err != nil {
				return [32]byte{}, err
			}
		} else {
			right = left
		}
		return dsha256Pair(left, right), nil
	}

	computed, err2 := consume(height, 0)
	if err2 != nil {
		return nil, nil, err2
	}
	return matched, computed[:], nil
}
