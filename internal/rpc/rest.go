package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// REST API constants matching Bitcoin Core's REST interface.
const (
	// Maximum number of headers to return in a single request.
	maxRESTHeadersResults = 2000

	// Maximum number of outpoints to query in getutxos.
	maxGetUTXOsOutpoints = 15
)

// RESTFormat represents the response format for REST endpoints.
type RESTFormat int

const (
	RESTFormatJSON RESTFormat = iota
	RESTFormatHex
	RESTFormatBin
)

// parseRESTFormat extracts the format and base parameter from a path component like "hash.json".
func parseRESTFormat(param string) (string, RESTFormat, error) {
	// Find the last dot for format extension
	pos := strings.LastIndex(param, ".")
	if pos == -1 {
		return "", 0, fmt.Errorf("missing format extension (expected .json, .hex, or .bin)")
	}

	base := param[:pos]
	ext := param[pos+1:]

	switch ext {
	case "json":
		return base, RESTFormatJSON, nil
	case "hex":
		return base, RESTFormatHex, nil
	case "bin":
		return base, RESTFormatBin, nil
	default:
		return "", 0, fmt.Errorf("invalid format extension: %s (expected .json, .hex, or .bin)", ext)
	}
}

// restError writes an error response for REST endpoints.
func restError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// restResponse writes a successful response in the appropriate format.
func restResponse(w http.ResponseWriter, format RESTFormat, data []byte, jsonObj interface{}) {
	switch format {
	case RESTFormatJSON:
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jsonObj); err != nil {
			restError(w, http.StatusInternalServerError, "failed to encode JSON response")
		}
	case RESTFormatHex:
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(hex.EncodeToString(data)))
		w.Write([]byte("\n"))
	case RESTFormatBin:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	}
}

// RegisterRESTHandlers registers the REST API handlers on the given mux.
func (s *Server) RegisterRESTHandlers(mux *http.ServeMux) {
	// Block endpoints
	mux.HandleFunc("/rest/block/", s.handleRESTBlock)
	mux.HandleFunc("/rest/block/notxdetails/", s.handleRESTBlockNoTxDetails)

	// Transaction endpoint
	mux.HandleFunc("/rest/tx/", s.handleRESTTx)

	// Headers endpoint
	mux.HandleFunc("/rest/headers/", s.handleRESTHeaders)

	// Block hash by height endpoint
	mux.HandleFunc("/rest/blockhashbyheight/", s.handleRESTBlockHashByHeight)

	// Chain info endpoint
	mux.HandleFunc("/rest/chaininfo.json", s.handleRESTChainInfo)

	// Mempool endpoints
	mux.HandleFunc("/rest/mempool/info.json", s.handleRESTMempoolInfo)
	mux.HandleFunc("/rest/mempool/contents.json", s.handleRESTMempoolContents)

	// UTXO query endpoint
	mux.HandleFunc("/rest/getutxos/", s.handleRESTGetUTXOs)
}

// handleRESTBlock handles GET /rest/block/<hash>.<format>
func (s *Server) handleRESTBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract hash and format from path
	path := strings.TrimPrefix(r.URL.Path, "/rest/block/")

	// Check if this is actually the notxdetails endpoint
	if strings.HasPrefix(path, "notxdetails/") {
		s.handleRESTBlockNoTxDetails(w, r)
		return
	}

	hashStr, format, err := parseRESTFormat(path)
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Parse the hash
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		restError(w, http.StatusBadRequest, "invalid hash: "+hashStr)
		return
	}

	// Get block from database
	if s.chainDB == nil {
		restError(w, http.StatusNotFound, "block not found")
		return
	}

	block, err := s.chainDB.GetBlock(hash)
	if err != nil {
		restError(w, http.StatusNotFound, hashStr+" not found")
		return
	}

	// Serialize block for binary/hex formats
	var buf bytes.Buffer
	if err := block.Serialize(&buf); err != nil {
		restError(w, http.StatusInternalServerError, "failed to serialize block")
		return
	}

	// For JSON format, build the detailed response
	if format == RESTFormatJSON {
		blockResult := s.buildRESTBlockResult(block, hash, true)
		restResponse(w, format, nil, blockResult)
		return
	}

	restResponse(w, format, buf.Bytes(), nil)
}

// handleRESTBlockNoTxDetails handles GET /rest/block/notxdetails/<hash>.<format>
func (s *Server) handleRESTBlockNoTxDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract hash and format from path
	path := strings.TrimPrefix(r.URL.Path, "/rest/block/notxdetails/")
	hashStr, format, err := parseRESTFormat(path)
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Parse the hash
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		restError(w, http.StatusBadRequest, "invalid hash: "+hashStr)
		return
	}

	// Get block from database
	if s.chainDB == nil {
		restError(w, http.StatusNotFound, "block not found")
		return
	}

	block, err := s.chainDB.GetBlock(hash)
	if err != nil {
		restError(w, http.StatusNotFound, hashStr+" not found")
		return
	}

	// Serialize block for binary/hex formats
	var buf bytes.Buffer
	if err := block.Serialize(&buf); err != nil {
		restError(w, http.StatusInternalServerError, "failed to serialize block")
		return
	}

	// For JSON format, build the response without full transaction details
	if format == RESTFormatJSON {
		blockResult := s.buildRESTBlockResult(block, hash, false)
		restResponse(w, format, nil, blockResult)
		return
	}

	restResponse(w, format, buf.Bytes(), nil)
}

// handleRESTTx handles GET /rest/tx/<txid>.<format>
func (s *Server) handleRESTTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract txid and format from path
	path := strings.TrimPrefix(r.URL.Path, "/rest/tx/")
	txidStr, format, err := parseRESTFormat(path)
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Parse the txid
	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		restError(w, http.StatusBadRequest, "invalid txid: "+txidStr)
		return
	}

	// Try to find the transaction
	var tx *wire.MsgTx
	var blockHash wire.Hash256
	var hasBlockHash bool

	// Check mempool first
	if s.mempool != nil {
		if mempoolTx := s.mempool.GetTransaction(txid); mempoolTx != nil {
			tx = mempoolTx
		}
	}

	// Check txindex if not in mempool and txindex is enabled
	if tx == nil && s.config.TxIndex && s.chainDB != nil {
		if txEntry, err := s.chainDB.GetTxIndex(txid); err == nil {
			blockHash = txEntry.BlockHash
			hasBlockHash = true
			// Get the block to find the transaction
			if block, err := s.chainDB.GetBlock(blockHash); err == nil {
				for _, blockTx := range block.Transactions {
					if blockTx.TxHash() == txid {
						tx = blockTx
						break
					}
				}
			}
		}
	}

	if tx == nil {
		restError(w, http.StatusNotFound, txidStr+" not found")
		return
	}

	// Serialize transaction for binary/hex formats
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		restError(w, http.StatusInternalServerError, "failed to serialize transaction")
		return
	}

	// For JSON format, build the detailed response
	if format == RESTFormatJSON {
		txResult := buildTxResult(tx, false)
		if hasBlockHash {
			txResult.BlockHash = blockHash.String()
		}
		restResponse(w, format, nil, txResult)
		return
	}

	restResponse(w, format, buf.Bytes(), nil)
}

// handleRESTHeaders handles GET /rest/headers/<count>/<hash>.<format>
func (s *Server) handleRESTHeaders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract count and hash from path
	path := strings.TrimPrefix(r.URL.Path, "/rest/headers/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		restError(w, http.StatusBadRequest, "invalid URI format. Expected /rest/headers/<count>/<hash>.<ext>")
		return
	}

	// Parse count
	count, err := strconv.Atoi(parts[0])
	if err != nil || count < 1 || count > maxRESTHeadersResults {
		restError(w, http.StatusBadRequest, fmt.Sprintf("header count is invalid or out of range (1-%d)", maxRESTHeadersResults))
		return
	}

	// Parse hash and format
	hashStr, format, err := parseRESTFormat(parts[1])
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		restError(w, http.StatusBadRequest, "invalid hash: "+hashStr)
		return
	}

	// Get headers starting from the given hash
	if s.headerIndex == nil {
		restError(w, http.StatusNotFound, "header index not available")
		return
	}

	node := s.headerIndex.GetNode(hash)
	if node == nil {
		restError(w, http.StatusNotFound, hashStr+" not found")
		return
	}

	// Collect headers
	var headers []*wire.BlockHeader
	currentNode := node
	for len(headers) < count && currentNode != nil {
		headers = append(headers, &currentNode.Header)
		// Move to next block in main chain
		if len(currentNode.Children) > 0 {
			// Find child in main chain
			var nextNode *BlockNode
			for _, child := range currentNode.Children {
				if s.chainMgr != nil && s.chainMgr.IsInMainChain(child.Hash) {
					nextNode = child
					break
				}
			}
			currentNode = nextNode
		} else {
			currentNode = nil
		}
	}

	// Serialize headers for binary/hex formats
	var buf bytes.Buffer
	for _, header := range headers {
		if err := header.Serialize(&buf); err != nil {
			restError(w, http.StatusInternalServerError, "failed to serialize header")
			return
		}
	}

	// For JSON format, build the response
	if format == RESTFormatJSON {
		var headerResults []BlockHeaderResult
		for i, header := range headers {
			result := s.buildBlockHeaderResult(header, node.Height+int32(i))
			headerResults = append(headerResults, result)
		}
		restResponse(w, format, nil, headerResults)
		return
	}

	restResponse(w, format, buf.Bytes(), nil)
}

// handleRESTBlockHashByHeight handles GET /rest/blockhashbyheight/<height>.<format>
func (s *Server) handleRESTBlockHashByHeight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract height and format from path
	path := strings.TrimPrefix(r.URL.Path, "/rest/blockhashbyheight/")
	heightStr, format, err := parseRESTFormat(path)
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Parse height
	height, err := strconv.ParseInt(heightStr, 10, 32)
	if err != nil || height < 0 {
		restError(w, http.StatusBadRequest, "invalid height: "+heightStr)
		return
	}

	// Get block hash at height
	if s.chainDB == nil {
		restError(w, http.StatusNotFound, "block height out of range")
		return
	}

	hash, err := s.chainDB.GetBlockHashByHeight(int32(height))
	if err != nil {
		restError(w, http.StatusNotFound, "block height out of range")
		return
	}

	// For JSON format
	if format == RESTFormatJSON {
		restResponse(w, format, nil, map[string]string{"blockhash": hash.String()})
		return
	}

	// For hex format, return the display hex (reversed)
	if format == RESTFormatHex {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(hash.String()))
		w.Write([]byte("\n"))
		return
	}

	// For binary format, return raw bytes
	restResponse(w, format, hash[:], nil)
}

// handleRESTChainInfo handles GET /rest/chaininfo.json
func (s *Server) handleRESTChainInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Reuse the existing RPC handler
	result, rpcErr := s.handleGetBlockchainInfo()
	if rpcErr != nil {
		restError(w, http.StatusInternalServerError, rpcErr.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRESTMempoolInfo handles GET /rest/mempool/info.json
func (s *Server) handleRESTMempoolInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Reuse the existing RPC handler
	result, rpcErr := s.handleGetMempoolInfo()
	if rpcErr != nil {
		restError(w, http.StatusInternalServerError, rpcErr.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRESTMempoolContents handles GET /rest/mempool/contents.json
func (s *Server) handleRESTMempoolContents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Reuse the existing RPC handler with verbose=true
	params, _ := json.Marshal([]interface{}{true})
	result, rpcErr := s.handleGetRawMempool(params)
	if rpcErr != nil {
		restError(w, http.StatusInternalServerError, rpcErr.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRESTGetUTXOs handles GET /rest/getutxos/<checkmempool>/<txid>-<n>/...<format>
func (s *Server) handleRESTGetUTXOs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract path components
	path := strings.TrimPrefix(r.URL.Path, "/rest/getutxos/")
	if path == "" {
		restError(w, http.StatusBadRequest, "empty request")
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		restError(w, http.StatusBadRequest, "empty request")
		return
	}

	// Check if first part is "checkmempool"
	checkMempool := false
	startIdx := 0
	if parts[0] == "checkmempool" {
		checkMempool = true
		startIdx = 1
	}

	if startIdx >= len(parts) {
		restError(w, http.StatusBadRequest, "empty request")
		return
	}

	// Last part contains format extension
	lastIdx := len(parts) - 1
	lastPart, format, err := parseRESTFormat(parts[lastIdx])
	if err != nil {
		restError(w, http.StatusBadRequest, err.Error())
		return
	}
	parts[lastIdx] = lastPart

	// Parse outpoints
	var outpoints []wire.OutPoint
	for i := startIdx; i <= lastIdx; i++ {
		if parts[i] == "" {
			continue
		}
		outpoint, err := parseOutpoint(parts[i])
		if err != nil {
			restError(w, http.StatusBadRequest, "parse error")
			return
		}
		outpoints = append(outpoints, outpoint)
	}

	if len(outpoints) == 0 {
		restError(w, http.StatusBadRequest, "empty request")
		return
	}

	if len(outpoints) > maxGetUTXOsOutpoints {
		restError(w, http.StatusBadRequest, fmt.Sprintf("error: max outpoints exceeded (max: %d, tried: %d)", maxGetUTXOsOutpoints, len(outpoints)))
		return
	}

	// Query UTXOs
	result := s.queryUTXOs(outpoints, checkMempool)

	// For JSON format
	if format == RESTFormatJSON {
		restResponse(w, format, nil, result)
		return
	}

	// For binary/hex format, serialize the response
	var buf bytes.Buffer

	// Write chain height (4 bytes LE)
	writeUint32LE(&buf, uint32(result.ChainHeight))

	// Write chain tip hash (32 bytes)
	hash, _ := wire.NewHash256FromHex(result.ChainTipHash)
	buf.Write(hash[:])

	// Write bitmap
	bitmap := bitmapFromString(result.Bitmap)
	buf.Write(bitmap)

	// Write UTXOs
	for _, utxo := range result.UTXOs {
		// Height (4 bytes LE)
		writeUint32LE(&buf, uint32(utxo.Height))
		// Value as satoshis (8 bytes LE)
		valueSats := int64(utxo.Value * 100_000_000)
		writeInt64LE(&buf, valueSats)
		// Script
		scriptBytes, _ := hex.DecodeString(utxo.ScriptPubKey.Hex)
		writeVarBytes(&buf, scriptBytes)
	}

	restResponse(w, format, buf.Bytes(), nil)
}

// parseOutpoint parses an outpoint string like "txid-n".
func parseOutpoint(s string) (wire.OutPoint, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return wire.OutPoint{}, fmt.Errorf("invalid outpoint format")
	}

	txid, err := wire.NewHash256FromHex(parts[0])
	if err != nil {
		return wire.OutPoint{}, fmt.Errorf("invalid txid")
	}

	index, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return wire.OutPoint{}, fmt.Errorf("invalid output index")
	}

	return wire.OutPoint{Hash: txid, Index: uint32(index)}, nil
}

// GetUTXOsResult is the result of the getutxos REST endpoint.
type GetUTXOsResult struct {
	ChainHeight  int32              `json:"chainHeight"`
	ChainTipHash string             `json:"chaintipHash"`
	Bitmap       string             `json:"bitmap"`
	UTXOs        []RESTUTXOInfo     `json:"utxos"`
}

// RESTUTXOInfo represents a UTXO in the REST response.
type RESTUTXOInfo struct {
	Height       int32        `json:"height"`
	Value        float64      `json:"value"`
	ScriptPubKey ScriptPubKey `json:"scriptPubKey"`
}

// queryUTXOs queries the UTXO set for the given outpoints.
func (s *Server) queryUTXOs(outpoints []wire.OutPoint, checkMempool bool) *GetUTXOsResult {
	result := &GetUTXOsResult{
		UTXOs: []RESTUTXOInfo{},
	}

	// Get current chain state
	if s.chainMgr != nil {
		tipHash, tipHeight := s.chainMgr.BestBlock()
		result.ChainHeight = tipHeight
		result.ChainTipHash = tipHash.String()
	}

	// Build bitmap and collect UTXOs
	var bitmapStr strings.Builder
	utxoView := s.chainMgr.UTXOSet()

	for _, outpoint := range outpoints {
		var found bool

		// Check if spent in mempool
		if checkMempool && s.mempool != nil && s.mempool.CheckSpend(outpoint) != nil {
			bitmapStr.WriteString("0")
			continue
		}

		// Check UTXO set
		if utxoView != nil {
			entry := utxoView.GetUTXO(outpoint)
			if entry != nil {
				found = true
				result.UTXOs = append(result.UTXOs, RESTUTXOInfo{
					Height: entry.Height,
					Value:  float64(entry.Amount) / 100_000_000,
					ScriptPubKey: ScriptPubKey{
						Asm:  disassembleScript(entry.PkScript),
						Hex:  hex.EncodeToString(entry.PkScript),
						Type: detectScriptType(entry.PkScript),
					},
				})
			}
		}

		// Check mempool for unconfirmed outputs
		if !found && checkMempool && s.mempool != nil {
			mempoolEntry := s.mempool.GetUTXO(outpoint)
			if mempoolEntry != nil {
				found = true
				result.UTXOs = append(result.UTXOs, RESTUTXOInfo{
					Height: 0, // Mempool
					Value:  float64(mempoolEntry.Amount) / 100_000_000,
					ScriptPubKey: ScriptPubKey{
						Asm:  disassembleScript(mempoolEntry.PkScript),
						Hex:  hex.EncodeToString(mempoolEntry.PkScript),
						Type: detectScriptType(mempoolEntry.PkScript),
					},
				})
			}
		}

		if found {
			bitmapStr.WriteString("1")
		} else {
			bitmapStr.WriteString("0")
		}
	}

	result.Bitmap = bitmapStr.String()
	return result
}

// bitmapFromString converts a bitmap string like "101" to a byte slice.
func bitmapFromString(s string) []byte {
	bitmap := make([]byte, (len(s)+7)/8)
	for i, c := range s {
		if c == '1' {
			bitmap[i/8] |= 1 << (i % 8)
		}
	}
	return bitmap
}

// buildRESTBlockResult builds a BlockResult for REST response.
func (s *Server) buildRESTBlockResult(block *wire.MsgBlock, hash wire.Hash256, includeTxDetails bool) *BlockResult {
	// Get block metadata from header index
	var height int32
	var confirmations int32 = -1
	var prevHash, nextHash string
	var chainWork string

	if s.headerIndex != nil {
		node := s.headerIndex.GetNode(hash)
		if node != nil {
			height = node.Height
			if s.chainMgr != nil {
				_, tipHeight := s.chainMgr.BestBlock()
				if s.chainMgr.IsInMainChain(hash) {
					confirmations = tipHeight - height + 1
				}
			}
			if node.Parent != nil {
				prevHash = node.Parent.Hash.String()
			}
			// Find next block in main chain
			for _, child := range node.Children {
				if s.chainMgr != nil && s.chainMgr.IsInMainChain(child.Hash) {
					nextHash = child.Hash.String()
					break
				}
			}
			chainWork = fmt.Sprintf("%064x", node.TotalWork)
		}
	}

	// Calculate block size and weight
	var buf bytes.Buffer
	block.Serialize(&buf)
	size := buf.Len()
	weight := calcBlockWeight(block)

	// Calculate difficulty
	difficulty := calcDifficulty(block.Header.Bits)

	// Build transaction list
	var txList []interface{}
	for i, tx := range block.Transactions {
		if includeTxDetails {
			txResult := buildTxResult(tx, i == 0)
			txResult.BlockHash = hash.String()
			txResult.Confirmations = confirmations
			txResult.BlockTime = block.Header.Timestamp
			txResult.Time = block.Header.Timestamp
			txList = append(txList, txResult)
		} else {
			txList = append(txList, tx.TxHash().String())
		}
	}

	// Compute stripped size for REST response
	restStrippedSize := 80
	for _, tx := range block.Transactions {
		var noWitBuf bytes.Buffer
		tx.SerializeNoWitness(&noWitBuf)
		restStrippedSize += noWitBuf.Len()
	}

	// Build coinbase_tx metadata (Core 27+) for REST response.
	var restCoinbaseTx interface{}
	if len(block.Transactions) > 0 {
		cb := block.Transactions[0]
		if len(cb.TxIn) > 0 {
			vin0 := cb.TxIn[0]
			cbMap := map[string]interface{}{
				"version":  cb.Version,
				"locktime": cb.LockTime,
				"sequence": vin0.Sequence,
				"coinbase": hex.EncodeToString(vin0.SignatureScript),
			}
			if len(vin0.Witness) > 0 {
				cbMap["witness"] = hex.EncodeToString(vin0.Witness[0])
			}
			restCoinbaseTx = cbMap
		}
	}

	return &BlockResult{
		Hash:          hash.String(),
		Confirmations: confirmations,
		Size:          size,
		StrippedSize:  restStrippedSize,
		Weight:        weight,
		Height:        height,
		Version:       block.Header.Version,
		VersionHex:    fmt.Sprintf("%08x", block.Header.Version),
		MerkleRoot:    block.Header.MerkleRoot.String(),
		Tx:            txList,
		Time:          block.Header.Timestamp,
		Nonce:         block.Header.Nonce,
		Bits:          fmt.Sprintf("%08x", block.Header.Bits),
		Target:        fmt.Sprintf("%064x", consensus.CompactToBig(block.Header.Bits)),
		Difficulty:    difficulty,
		ChainWork:     chainWork,
		NTx:           len(block.Transactions),
		PreviousHash:  prevHash,
		NextHash:      nextHash,
		CoinbaseTx:    restCoinbaseTx,
	}
}

// buildBlockHeaderResult builds a BlockHeaderResult for the REST response.
func (s *Server) buildBlockHeaderResult(header *wire.BlockHeader, height int32) BlockHeaderResult {
	hash := header.BlockHash()

	var confirmations int32 = -1
	var prevHash, nextHash string
	var chainWork string

	if s.chainMgr != nil {
		_, tipHeight := s.chainMgr.BestBlock()
		if s.chainMgr.IsInMainChain(hash) {
			confirmations = tipHeight - height + 1
		}
	}

	if s.headerIndex != nil {
		node := s.headerIndex.GetNode(hash)
		if node != nil {
			if node.Parent != nil {
				prevHash = node.Parent.Hash.String()
			}
			for _, child := range node.Children {
				if s.chainMgr != nil && s.chainMgr.IsInMainChain(child.Hash) {
					nextHash = child.Hash.String()
					break
				}
			}
			chainWork = fmt.Sprintf("%064x", node.TotalWork)
		}
	}

	if !header.PrevBlock.IsZero() {
		prevHash = header.PrevBlock.String()
	}

	return BlockHeaderResult{
		Hash:          hash.String(),
		Confirmations: confirmations,
		Height:        height,
		Version:       header.Version,
		VersionHex:    fmt.Sprintf("%08x", header.Version),
		MerkleRoot:    header.MerkleRoot.String(),
		Time:          header.Timestamp,
		Nonce:         header.Nonce,
		Bits:          fmt.Sprintf("%08x", header.Bits),
		Difficulty:    calcDifficulty(header.Bits),
		ChainWork:     chainWork,
		PreviousHash:  prevHash,
		NextHash:      nextHash,
	}
}

// Helper functions for binary serialization
func writeUint32LE(buf *bytes.Buffer, v uint32) {
	buf.WriteByte(byte(v))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 24))
}

func writeInt64LE(buf *bytes.Buffer, v int64) {
	buf.WriteByte(byte(v))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 56))
}

func writeVarBytes(buf *bytes.Buffer, b []byte) {
	// Write compact size
	l := len(b)
	if l < 0xFD {
		buf.WriteByte(byte(l))
	} else if l <= 0xFFFF {
		buf.WriteByte(0xFD)
		buf.WriteByte(byte(l))
		buf.WriteByte(byte(l >> 8))
	} else if l <= 0xFFFFFFFF {
		buf.WriteByte(0xFE)
		writeUint32LE(buf, uint32(l))
	}
	buf.Write(b)
}

// BlockNode represents a node in the header chain (imported from consensus).
// This is a type alias for the consensus.BlockNode type.
type BlockNode = consensus.BlockNode

// calcDifficulty calculates the difficulty from the compact target (bits).
func calcDifficulty(bits uint32) float64 {
	genesisTarget := consensus.CompactToBig(0x1d00ffff) // Genesis difficulty
	currentTarget := consensus.CompactToBig(bits)
	if currentTarget.Sign() <= 0 {
		return 0
	}
	diff := new(big.Float).SetInt(genesisTarget)
	diff.Quo(diff, new(big.Float).SetInt(currentTarget))
	difficulty, _ := diff.Float64()
	return difficulty
}

// detectScriptType identifies the type of a scriptPubKey.
func detectScriptType(script []byte) string {
	if consensus.IsP2PKH(script) {
		return "pubkeyhash"
	} else if consensus.IsP2SH(script) {
		return "scripthash"
	} else if consensus.IsP2WPKH(script) {
		return "witness_v0_keyhash"
	} else if consensus.IsP2WSH(script) {
		return "witness_v0_scripthash"
	} else if consensus.IsP2TR(script) {
		return "witness_v1_taproot"
	} else if len(script) > 0 && script[0] == 0x6a {
		return "nulldata"
	}
	return "nonstandard"
}
