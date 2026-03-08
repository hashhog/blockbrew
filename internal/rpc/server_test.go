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
