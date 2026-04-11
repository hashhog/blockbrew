package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// testRPCRequest sends a JSON-RPC request to the server and returns the response.
func testRPCRequest(t *testing.T, handler http.HandlerFunc, method string, params interface{}, username, password string) *RPCResponse {
	t.Helper()

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	req := RPCRequest{
		JSONRPC: "1.0",
		ID:      "test",
		Method:  method,
		Params:  paramsJSON,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	if username != "" || password != "" {
		httpReq.SetBasicAuth(username, password)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httpReq)

	var resp RPCResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return &resp
}

func TestMethodNotAllowed(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	server.handleRPC(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestBasicAuthRejection(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
		Username:   "admin",
		Password:   "secret",
	})

	// Request without auth
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()

	server.handleRPC(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}

	// Request with wrong credentials
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.SetBasicAuth("admin", "wrong")
	rr = httptest.NewRecorder()

	server.handleRPC(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestBasicAuthSuccess(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)

	server := NewServer(
		RPCConfig{
			ListenAddr: "127.0.0.1:0",
			Username:   "admin",
			Password:   "secret",
		},
		WithChainParams(params),
		WithHeaderIndex(idx),
	)

	resp := testRPCRequest(t, server.handleRPC, "getblockcount", []interface{}{}, "admin", "secret")

	if resp.Error != nil {
		// We expect an error about chain manager not being ready, not an auth error
		if resp.Error.Code == RPCErrMethodNotFound {
			t.Errorf("unexpected method not found error")
		}
	}
}

func TestParseError(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{invalid json`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.handleRPC(rr, req)

	var resp RPCResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error response")
	}
	if resp.Error.Code != RPCErrParseError {
		t.Errorf("expected error code %d, got %d", RPCErrParseError, resp.Error.Code)
	}
}

func TestMethodNotFound(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	resp := testRPCRequest(t, server.handleRPC, "nonexistentmethod", []interface{}{}, "", "")

	if resp.Error == nil {
		t.Error("expected error response")
	}
	if resp.Error.Code != RPCErrMethodNotFound {
		t.Errorf("expected error code %d, got %d", RPCErrMethodNotFound, resp.Error.Code)
	}
}

func TestGetBlockchainInfo(t *testing.T) {
	// Set up a minimal chain state
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)

	// Create a mock chain manager config
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	resp := testRPCRequest(t, server.handleRPC, "getblockchaininfo", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Parse the result
	result, ok := resp.Result.(*BlockchainInfo)
	if !ok {
		// Result might be a map, convert it
		resultMap, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatalf("unexpected result type: %T", resp.Result)
		}
		// Check expected fields exist
		if _, ok := resultMap["chain"]; !ok {
			t.Error("expected 'chain' field in response")
		}
		if _, ok := resultMap["blocks"]; !ok {
			t.Error("expected 'blocks' field in response")
		}
		if _, ok := resultMap["headers"]; !ok {
			t.Error("expected 'headers' field in response")
		}
		if _, ok := resultMap["bestblockhash"]; !ok {
			t.Error("expected 'bestblockhash' field in response")
		}
		return
	}

	if result.Chain != "main" {
		t.Errorf("expected chain 'main', got %s", result.Chain)
	}
}

func TestGetBlockCount(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	resp := testRPCRequest(t, server.handleRPC, "getblockcount", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Result should be 0 (genesis only)
	height, ok := resp.Result.(float64)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}
	if height != 0 {
		t.Errorf("expected height 0, got %v", height)
	}
}

func TestGetBestBlockHash(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	resp := testRPCRequest(t, server.handleRPC, "getbestblockhash", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	hash, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	// Should be genesis hash
	expectedHash := params.GenesisHash.String()
	if hash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, hash)
	}
}

func TestGetMempoolInfo(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	resp := testRPCRequest(t, server.handleRPC, "getmempoolinfo", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	if loaded, ok := result["loaded"].(bool); !ok || !loaded {
		t.Error("expected mempool to be loaded")
	}

	if size, ok := result["size"].(float64); !ok || size != 0 {
		t.Errorf("expected empty mempool, got size %v", size)
	}
}

func TestGetRawMempool(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Non-verbose
	resp := testRPCRequest(t, server.handleRPC, "getrawmempool", []interface{}{false}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.([]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	if len(result) != 0 {
		t.Errorf("expected empty mempool, got %d transactions", len(result))
	}
}

func TestSubmitPackageRPC(t *testing.T) {
	// Create a mempool for testing
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Test with empty package - should fail
	resp := testRPCRequest(t, server.handleRPC, "submitpackage", []interface{}{[]interface{}{}}, "", "")
	if resp.Error == nil {
		t.Error("expected error for empty package")
	}

	// Test with invalid hex - should fail
	resp = testRPCRequest(t, server.handleRPC, "submitpackage", []interface{}{[]interface{}{"not_hex"}}, "", "")
	if resp.Error == nil {
		t.Error("expected error for invalid hex")
	}

	// Test with missing array parameter
	resp = testRPCRequest(t, server.handleRPC, "submitpackage", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Error("expected error for missing parameter")
	}

	// Test with a simple valid raw transaction hex (P2WPKH spend)
	// This will fail validation because we don't have UTXOs, but tests the parsing path
	validTxHex := "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a010000001600140000000000000000000000000000000000000000ffffffff"
	resp = testRPCRequest(t, server.handleRPC, "submitpackage", []interface{}{[]interface{}{validTxHex}}, "", "")
	// Should return a result (even if it's an error in the package_msg)
	// because parsing succeeded
	if resp.Error == nil {
		// Check that we got a package result
		result, ok := resp.Result.(map[string]interface{})
		if ok {
			if packageMsg, ok := result["package_msg"].(string); ok {
				t.Logf("Package message: %s", packageMsg)
			}
		}
	}
}

func TestGetConnectionCount(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "getconnectioncount", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	count, ok := resp.Result.(float64)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	if count != 0 {
		t.Errorf("expected 0 connections, got %v", count)
	}
}

func TestGetNetworkInfo(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "getnetworkinfo", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	if version, ok := result["protocolversion"].(float64); !ok || version != 70016 {
		t.Errorf("expected protocol version 70016, got %v", version)
	}

	if subver, ok := result["subversion"].(string); !ok || subver == "" {
		t.Error("expected non-empty subversion")
	}
}

func TestGetPeerInfo(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "getpeerinfo", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.([]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	// No peers connected initially
	if len(result) != 0 {
		t.Errorf("expected 0 peers, got %d", len(result))
	}
}

func TestUptime(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	// Wait a tiny bit
	time.Sleep(10 * time.Millisecond)

	resp := testRPCRequest(t, server.handleRPC, "uptime", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	uptime, ok := resp.Result.(float64)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	if uptime < 0 {
		t.Errorf("expected positive uptime, got %v", uptime)
	}
}

func TestEstimateSmartFee(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	resp := testRPCRequest(t, server.handleRPC, "estimatesmartfee", []interface{}{6}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	// Should have blocks field
	if blocks, ok := result["blocks"].(float64); !ok || blocks != 6 {
		t.Errorf("expected blocks 6, got %v", blocks)
	}
}

func TestDecodeRawTransaction(t *testing.T) {
	// Create a simple transaction
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{},
				Index: 0xFFFFFFFF,
			},
			SignatureScript: []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    5000000000,
			PkScript: []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
		}},
		LockTime: 0,
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("failed to serialize tx: %v", err)
	}
	txHex := hex.EncodeToString(buf.Bytes())

	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "decoderawtransaction", []interface{}{txHex}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	// Verify some fields
	if version, ok := result["version"].(float64); !ok || version != 2 {
		t.Errorf("expected version 2, got %v", version)
	}

	if locktime, ok := result["locktime"].(float64); !ok || locktime != 0 {
		t.Errorf("expected locktime 0, got %v", locktime)
	}

	vin, ok := result["vin"].([]interface{})
	if !ok || len(vin) != 1 {
		t.Error("expected 1 input")
	}

	vout, ok := result["vout"].([]interface{})
	if !ok || len(vout) != 1 {
		t.Error("expected 1 output")
	}
}

func TestDecodeRawTransactionInvalidHex(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "decoderawtransaction", []interface{}{"invalid"}, "", "")

	if resp.Error == nil {
		t.Error("expected error for invalid hex")
	}
	if resp.Error.Code != RPCErrDeserialization {
		t.Errorf("expected error code %d, got %d", RPCErrDeserialization, resp.Error.Code)
	}
}

func TestGetDifficulty(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	resp := testRPCRequest(t, server.handleRPC, "getdifficulty", []interface{}{}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	difficulty, ok := resp.Result.(float64)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}

	// Genesis block should have difficulty 1
	if difficulty != 1.0 {
		t.Errorf("expected difficulty 1, got %v", difficulty)
	}
}

func TestInvalidParams(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
	)

	// getblockhash with missing height
	resp := testRPCRequest(t, server.handleRPC, "getblockhash", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected invalid params error for getblockhash without height")
	}

	// getblock with invalid hash
	resp = testRPCRequest(t, server.handleRPC, "getblock", []interface{}{"invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected invalid params error for getblock with invalid hash")
	}
}

func TestServerStartStop(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	if err := server.Stop(); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}
}

func TestContentType(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	reqBody, _ := json.Marshal(RPCRequest{
		JSONRPC: "1.0",
		ID:      "test",
		Method:  "getconnectioncount",
		Params:  json.RawMessage("[]"),
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.handleRPC(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestNullID(t *testing.T) {
	server := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
	})

	// Send request with null ID
	reqBody := []byte(`{"jsonrpc":"1.0","id":null,"method":"getconnectioncount","params":[]}`)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.handleRPC(rr, req)

	var resp RPCResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// ID should be null in response
	if resp.ID != nil {
		t.Errorf("expected null ID, got %v", resp.ID)
	}
}

func TestGetRawTransactionFromMempool(t *testing.T) {
	// Create a simple transaction. Use OP_1 (0x51) as the output script
	// (anyone-can-spend) so script validation passes with an empty scriptSig.
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{0x01, 0x02, 0x03},
				Index: 0,
			},
			SignatureScript: []byte{},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000000,
			PkScript: []byte{0x51}, // OP_1 (anyone-can-spend)
		}},
		LockTime: 0,
	}

	txid := tx.TxHash()

	// Provide a UTXO set with OP_1 output and excess value for fees.
	utxoView := consensus.NewInMemoryUTXOView()
	utxoView.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{
		Amount:   tx.TxOut[0].Value + 100000, // excess = fees
		PkScript: []byte{0x51},               // OP_1 (anyone-can-spend)
		Height:   1,
	})
	mp := mempool.New(mempool.DefaultConfig(), utxoView)
	if err := mp.AddTransaction(tx); err != nil {
		t.Fatalf("AddTransaction failed: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Test non-verbose mode
	resp := testRPCRequest(t, server.handleRPC, "getrawtransaction", []interface{}{txid.String(), false}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	hexStr, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected string result, got %T", resp.Result)
	}

	// Should be valid hex
	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Errorf("expected valid hex string, got error: %v", err)
	}

	// Test verbose mode
	resp = testRPCRequest(t, server.handleRPC, "getrawtransaction", []interface{}{txid.String(), true}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result for verbose mode, got %T", resp.Result)
	}

	if result["txid"] != txid.String() {
		t.Errorf("expected txid %s, got %v", txid.String(), result["txid"])
	}

	// Mempool tx should not have blockhash
	if _, ok := result["blockhash"]; ok && result["blockhash"] != "" {
		t.Error("expected no blockhash for mempool transaction")
	}
}

func TestGetRawTransactionNotFound(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: false},
		WithMempool(mp),
	)

	// Request non-existent transaction without txindex
	resp := testRPCRequest(t, server.handleRPC, "getrawtransaction",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001", false}, "", "")

	if resp.Error == nil {
		t.Fatal("expected error for non-existent transaction")
	}

	if resp.Error.Code != RPCErrTxNotFound {
		t.Errorf("expected error code %d, got %d", RPCErrTxNotFound, resp.Error.Code)
	}

	// Error message should mention txindex
	if !bytes.Contains([]byte(resp.Error.Message), []byte("txindex")) {
		t.Errorf("expected error message to mention txindex, got: %s", resp.Error.Message)
	}
}

func TestGetRawTransactionFromBlockhash(t *testing.T) {
	// Create a block with a coinbase transaction
	coinbaseTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{},
				Index: 0xFFFFFFFF,
			},
			SignatureScript: []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    5000000000,
			PkScript: []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
		}},
		LockTime: 0,
	}

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: wire.Hash256{},
			Timestamp:  1231006505,
			Bits:       0x1d00ffff,
			Nonce:      2083236893,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}

	blockHash := block.Header.BlockHash()
	txid := coinbaseTx.TxHash()

	// Create chain state with block stored
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Store the block
	if err := chainDB.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("failed to store block: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(chainDB),
	)

	// Request transaction with blockhash
	resp := testRPCRequest(t, server.handleRPC, "getrawtransaction",
		[]interface{}{txid.String(), true, blockHash.String()}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}

	if result["txid"] != txid.String() {
		t.Errorf("expected txid %s, got %v", txid.String(), result["txid"])
	}

	// Should have blockhash
	if result["blockhash"] != blockHash.String() {
		t.Errorf("expected blockhash %s, got %v", blockHash.String(), result["blockhash"])
	}

	// Should have coinbase field in vin
	vin, ok := result["vin"].([]interface{})
	if !ok || len(vin) != 1 {
		t.Fatal("expected 1 input")
	}
	vinEntry, ok := vin[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected vin entry to be a map")
	}
	if _, ok := vinEntry["coinbase"]; !ok {
		t.Error("expected coinbase field for coinbase transaction")
	}
}

func TestGetRawTransactionFromTxIndex(t *testing.T) {
	// Create a transaction
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{0x01, 0x02, 0x03},
				Index: 0,
			},
			SignatureScript: []byte{0x00},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000000,
			PkScript: []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
		}},
		LockTime: 0,
	}

	// Create a block containing the transaction
	coinbaseTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{},
				Index: 0xFFFFFFFF,
			},
			SignatureScript: []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    5000000000,
			PkScript: []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
		}},
		LockTime: 0,
	}

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: wire.Hash256{},
			Timestamp:  1231006505,
			Bits:       0x1d00ffff,
			Nonce:      2083236893,
		},
		Transactions: []*wire.MsgTx{coinbaseTx, tx},
	}

	blockHash := block.Header.BlockHash()
	txid := tx.TxHash()

	// Set up storage
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Store block and txindex
	if err := chainDB.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("failed to store block: %v", err)
	}
	if err := chainDB.WriteTxIndex(txid, blockHash); err != nil {
		t.Fatalf("failed to write txindex: %v", err)
	}

	// Create chain manager
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(chainDB),
		WithChainManager(chainMgr),
	)

	// Request transaction without blockhash - should find via txindex
	resp := testRPCRequest(t, server.handleRPC, "getrawtransaction",
		[]interface{}{txid.String(), true}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}

	if result["txid"] != txid.String() {
		t.Errorf("expected txid %s, got %v", txid.String(), result["txid"])
	}

	// Should have blockhash
	if result["blockhash"] != blockHash.String() {
		t.Errorf("expected blockhash %s, got %v", blockHash.String(), result["blockhash"])
	}

	// Non-verbose mode should also work
	resp = testRPCRequest(t, server.handleRPC, "getrawtransaction",
		[]interface{}{txid.String(), false}, "", "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	hexStr, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected string result, got %T", resp.Result)
	}

	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Errorf("expected valid hex string, got error: %v", err)
	}
}

func TestGetRawTransactionInvalidParams(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	// Missing txid
	resp := testRPCRequest(t, server.handleRPC, "getrawtransaction", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected invalid params error for missing txid")
	}

	// Invalid txid format
	resp = testRPCRequest(t, server.handleRPC, "getrawtransaction", []interface{}{"invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected invalid params error for invalid txid")
	}

	// Invalid blockhash format
	resp = testRPCRequest(t, server.handleRPC, "getrawtransaction",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001", false, "invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected invalid params error for invalid blockhash")
	}
}

// ============================================================================
// Chain Management RPC Tests
// ============================================================================

func TestInvalidateBlockRPC(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	// Missing blockhash parameter
	resp := testRPCRequest(t, server.handleRPC, "invalidateblock", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for missing blockhash")
	}

	// Invalid blockhash format
	resp = testRPCRequest(t, server.handleRPC, "invalidateblock", []interface{}{"invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for invalid blockhash format")
	}

	// Block not found
	resp = testRPCRequest(t, server.handleRPC, "invalidateblock",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrBlockNotFound {
		t.Errorf("expected block not found error, got %v", resp.Error)
	}

	// Valid request (genesis - should fail because genesis cannot be invalidated)
	resp = testRPCRequest(t, server.handleRPC, "invalidateblock",
		[]interface{}{params.GenesisHash.String()}, "", "")
	if resp.Error == nil {
		t.Error("expected error when invalidating genesis")
	}
}

func TestReconsiderBlockRPC(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	// Missing blockhash parameter
	resp := testRPCRequest(t, server.handleRPC, "reconsiderblock", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for missing blockhash")
	}

	// Invalid blockhash format
	resp = testRPCRequest(t, server.handleRPC, "reconsiderblock", []interface{}{"invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for invalid blockhash format")
	}

	// Block not found
	resp = testRPCRequest(t, server.handleRPC, "reconsiderblock",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrBlockNotFound {
		t.Errorf("expected block not found error, got %v", resp.Error)
	}

	// Valid request (genesis - should succeed, though no-op)
	resp = testRPCRequest(t, server.handleRPC, "reconsiderblock",
		[]interface{}{params.GenesisHash.String()}, "", "")
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

func TestPreciousBlockRPC(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	// Missing blockhash parameter
	resp := testRPCRequest(t, server.handleRPC, "preciousblock", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for missing blockhash")
	}

	// Invalid blockhash format
	resp = testRPCRequest(t, server.handleRPC, "preciousblock", []interface{}{"invalid"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParams {
		t.Error("expected error for invalid blockhash format")
	}

	// Block not found
	resp = testRPCRequest(t, server.handleRPC, "preciousblock",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrBlockNotFound {
		t.Errorf("expected block not found error, got %v", resp.Error)
	}

	// Valid request (genesis - should succeed)
	resp = testRPCRequest(t, server.handleRPC, "preciousblock",
		[]interface{}{params.GenesisHash.String()}, "", "")
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

// TestGetDeploymentInfoRegtest verifies that getdeploymentinfo returns a non-empty
// deployments map on regtest and that segwit and taproot are present and active
// (both are active from genesis height 0 on regtest).
func TestGetDeploymentInfoRegtest(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	// No params — should default to chain tip (genesis on an empty chain).
	resp := testRPCRequest(t, server.handleRPC, "getdeploymentinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}

	// Top-level fields.
	if _, ok := resultMap["hash"]; !ok {
		t.Error("expected 'hash' field in result")
	}
	if _, ok := resultMap["height"]; !ok {
		t.Error("expected 'height' field in result")
	}

	deploymentsRaw, ok := resultMap["deployments"]
	if !ok {
		t.Fatal("expected 'deployments' field in result")
	}
	deployments, ok := deploymentsRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("expected deployments to be a map, got %T", deploymentsRaw)
	}
	if len(deployments) == 0 {
		t.Fatal("expected non-empty deployments map")
	}

	// segwit must be present and active on regtest (SegwitHeight == 0).
	segwitRaw, ok := deployments["segwit"]
	if !ok {
		t.Fatal("expected 'segwit' deployment")
	}
	segwit, ok := segwitRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("segwit entry has unexpected type %T", segwitRaw)
	}
	if segwit["type"] != "buried" {
		t.Errorf("expected segwit type 'buried', got %v", segwit["type"])
	}
	if active, ok := segwit["active"].(bool); !ok || !active {
		t.Errorf("expected segwit to be active on regtest, got %v", segwit["active"])
	}

	// taproot must be present and active on regtest (TaprootHeight == 0).
	taprootRaw, ok := deployments["taproot"]
	if !ok {
		t.Fatal("expected 'taproot' deployment")
	}
	taproot, ok := taprootRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("taproot entry has unexpected type %T", taprootRaw)
	}
	if taproot["type"] != "buried" {
		t.Errorf("expected taproot type 'buried', got %v", taproot["type"])
	}
	if active, ok := taproot["active"].(bool); !ok || !active {
		t.Errorf("expected taproot to be active on regtest, got %v", taproot["active"])
	}
}

// TestGetDeploymentInfoByHash verifies that getdeploymentinfo accepts an explicit
// block hash parameter and returns the correct result for that block.
func TestGetDeploymentInfoByHash(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	// Query by genesis hash — should succeed.
	resp := testRPCRequest(t, server.handleRPC, "getdeploymentinfo",
		[]interface{}{params.GenesisHash.String()}, "", "")
	if resp.Error != nil {
		t.Fatalf("unexpected error querying genesis: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result for genesis")
	}

	// Query with an unknown hash — should return block-not-found error.
	resp = testRPCRequest(t, server.handleRPC, "getdeploymentinfo",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrBlockNotFound {
		t.Errorf("expected block-not-found error, got %v", resp.Error)
	}
}

// TestGetDeploymentInfoBIP9Testdummy verifies that the testdummy BIP9 deployment
// (always-active on regtest) is returned as a bip9 deployment that is active.
func TestGetDeploymentInfoBIP9Testdummy(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)

	resp := testRPCRequest(t, server.handleRPC, "getdeploymentinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	deployments, ok := resultMap["deployments"].(map[string]interface{})
	if !ok {
		t.Fatal("expected deployments map")
	}

	// testdummy has StartTime == AlwaysActive on regtest, so it should be active.
	tdRaw, ok := deployments["testdummy"]
	if !ok {
		t.Fatal("expected 'testdummy' deployment")
	}
	td, ok := tdRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("testdummy entry has unexpected type %T", tdRaw)
	}
	if td["type"] != "bip9" {
		t.Errorf("expected testdummy type 'bip9', got %v", td["type"])
	}
	if active, ok := td["active"].(bool); !ok || !active {
		t.Errorf("expected testdummy to be active on regtest, got %v", td["active"])
	}
	if td["bip9"] == nil {
		t.Error("expected bip9 sub-object for testdummy")
	}
}
