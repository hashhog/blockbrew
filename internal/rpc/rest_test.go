package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// testRESTRequest sends a REST request to the server and returns the response.
func testRESTRequest(t *testing.T, handler http.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRESTParseFormat(t *testing.T) {
	tests := []struct {
		input       string
		wantBase    string
		wantFormat  RESTFormat
		wantErr     bool
	}{
		{"abc.json", "abc", RESTFormatJSON, false},
		{"abc.hex", "abc", RESTFormatHex, false},
		{"abc.bin", "abc", RESTFormatBin, false},
		{"abc", "", 0, true},           // Missing extension
		{"abc.txt", "", 0, true},       // Invalid extension
		{"abc.def.json", "abc.def", RESTFormatJSON, false}, // Multiple dots
	}

	for _, tt := range tests {
		base, format, err := parseRESTFormat(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseRESTFormat(%q): expected error, got none", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRESTFormat(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if base != tt.wantBase {
			t.Errorf("parseRESTFormat(%q): base = %q, want %q", tt.input, base, tt.wantBase)
		}
		if format != tt.wantFormat {
			t.Errorf("parseRESTFormat(%q): format = %v, want %v", tt.input, format, tt.wantFormat)
		}
	}
}

func TestRESTChainInfo(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	rr := testRESTRequest(t, server.handleRESTChainInfo, http.MethodGet, "/rest/chaininfo.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := result["chain"]; !ok {
		t.Error("expected 'chain' field in response")
	}
	if _, ok := result["blocks"]; !ok {
		t.Error("expected 'blocks' field in response")
	}
}

func TestRESTMempoolInfo(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithMempool(mp),
	)

	rr := testRESTRequest(t, server.handleRESTMempoolInfo, http.MethodGet, "/rest/mempool/info.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if loaded, ok := result["loaded"].(bool); !ok || !loaded {
		t.Error("expected mempool to be loaded")
	}
}

func TestRESTMempoolContents(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithMempool(mp),
	)

	rr := testRESTRequest(t, server.handleRESTMempoolContents, http.MethodGet, "/rest/mempool/contents.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Empty mempool should return empty object
	if len(result) != 0 {
		t.Errorf("expected empty mempool, got %d entries", len(result))
	}
}

func TestRESTBlockHashByHeight(t *testing.T) {
	params := consensus.MainnetParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Store genesis block hash at height 0
	if err := chainDB.SetBlockHeight(0, params.GenesisHash); err != nil {
		t.Fatalf("failed to set block height: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	// Test JSON format
	rr := testRESTRequest(t, server.handleRESTBlockHashByHeight, http.MethodGet, "/rest/blockhashbyheight/0.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["blockhash"] != params.GenesisHash.String() {
		t.Errorf("expected hash %s, got %s", params.GenesisHash.String(), result["blockhash"])
	}

	// Test hex format
	rr = testRESTRequest(t, server.handleRESTBlockHashByHeight, http.MethodGet, "/rest/blockhashbyheight/0.hex")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	hexBody := rr.Body.String()
	// Trim newline
	hexBody = hexBody[:len(hexBody)-1]
	if hexBody != params.GenesisHash.String() {
		t.Errorf("expected hex hash %s, got %s", params.GenesisHash.String(), hexBody)
	}

	// Test invalid height
	rr = testRESTRequest(t, server.handleRESTBlockHashByHeight, http.MethodGet, "/rest/blockhashbyheight/999.json")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}

	// Test invalid height format
	rr = testRESTRequest(t, server.handleRESTBlockHashByHeight, http.MethodGet, "/rest/blockhashbyheight/abc.json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}
}

func TestRESTBlock(t *testing.T) {
	// Create a simple block
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

	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Store the block
	if err := chainDB.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("failed to store block: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(chainDB),
	)

	// Test JSON format
	rr := testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/"+blockHash.String()+".json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["hash"] != blockHash.String() {
		t.Errorf("expected hash %s, got %v", blockHash.String(), result["hash"])
	}

	// Test hex format
	rr = testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/"+blockHash.String()+".hex")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	hexBody := rr.Body.String()
	// Trim newline
	hexBody = hexBody[:len(hexBody)-1]
	_, err := hex.DecodeString(hexBody)
	if err != nil {
		t.Errorf("expected valid hex, got error: %v", err)
	}

	// Test binary format
	rr = testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/"+blockHash.String()+".bin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %s", ct)
	}

	// Test block not found
	rr = testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/0000000000000000000000000000000000000000000000000000000000000001.json")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}

	// Test invalid hash
	rr = testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/invalid.json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	// Test missing format
	rr = testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/"+blockHash.String())
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}
}

func TestRESTBlockNoTxDetails(t *testing.T) {
	// Create a simple block with multiple transactions
	coinbaseTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
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

	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())

	if err := chainDB.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("failed to store block: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainDB(chainDB),
	)

	// Test notxdetails endpoint
	rr := testRESTRequest(t, server.handleRESTBlock, http.MethodGet, "/rest/block/notxdetails/"+blockHash.String()+".json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should have txids as strings, not full tx objects
	txList, ok := result["tx"].([]interface{})
	if !ok {
		t.Fatal("expected tx field to be an array")
	}
	if len(txList) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(txList))
	}
	// First tx should be a string (txid), not an object
	if _, ok := txList[0].(string); !ok {
		t.Errorf("expected tx to be a string (txid), got %T", txList[0])
	}
}

func TestRESTTx(t *testing.T) {
	// Create a transaction and add to mempool
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01, 0x02, 0x03}, Index: 0},
			SignatureScript:  []byte{0x00},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000000,
			PkScript: []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
		}},
		LockTime: 0,
	}

	txid := tx.TxHash()

	mp := mempool.New(mempool.DefaultConfig(), nil)
	mp.AddTransaction(tx)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithMempool(mp),
	)

	// Test JSON format
	rr := testRESTRequest(t, server.handleRESTTx, http.MethodGet, "/rest/tx/"+txid.String()+".json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["txid"] != txid.String() {
		t.Errorf("expected txid %s, got %v", txid.String(), result["txid"])
	}

	// Test hex format
	rr = testRESTRequest(t, server.handleRESTTx, http.MethodGet, "/rest/tx/"+txid.String()+".hex")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	hexBody := rr.Body.String()
	hexBody = hexBody[:len(hexBody)-1] // trim newline
	_, err := hex.DecodeString(hexBody)
	if err != nil {
		t.Errorf("expected valid hex, got error: %v", err)
	}

	// Test tx not found
	rr = testRESTRequest(t, server.handleRESTTx, http.MethodGet, "/rest/tx/0000000000000000000000000000000000000000000000000000000000000001.json")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}
}

func TestRESTHeaders(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
	)

	genesisHash := params.GenesisHash.String()

	// Test JSON format - get 1 header starting from genesis
	rr := testRESTRequest(t, server.handleRESTHeaders, http.MethodGet, "/rest/headers/1/"+genesisHash+".json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result []map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 header, got %d", len(result))
	}

	if result[0]["hash"] != genesisHash {
		t.Errorf("expected hash %s, got %v", genesisHash, result[0]["hash"])
	}

	// Test binary format - each header is 80 bytes
	rr = testRESTRequest(t, server.handleRESTHeaders, http.MethodGet, "/rest/headers/1/"+genesisHash+".bin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if rr.Body.Len() != 80 {
		t.Errorf("expected 80 bytes, got %d", rr.Body.Len())
	}

	// Test invalid count
	rr = testRESTRequest(t, server.handleRESTHeaders, http.MethodGet, "/rest/headers/0/"+genesisHash+".json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	// Test count out of range
	rr = testRESTRequest(t, server.handleRESTHeaders, http.MethodGet, "/rest/headers/3000/"+genesisHash+".json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	// Test invalid hash
	rr = testRESTRequest(t, server.handleRESTHeaders, http.MethodGet, "/rest/headers/1/0000000000000000000000000000000000000000000000000000000000000001.json")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}
}

func TestRESTGetUTXOs(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
		WithMempool(mp),
	)

	// Test with a non-existent outpoint
	txid := "0000000000000000000000000000000000000000000000000000000000000001"
	rr := testRESTRequest(t, server.handleRESTGetUTXOs, http.MethodGet, "/rest/getutxos/"+txid+"-0.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should have bitmap with "0" (not found)
	if bitmap, ok := result["bitmap"].(string); !ok || bitmap != "0" {
		t.Errorf("expected bitmap '0', got %v", result["bitmap"])
	}

	// Test with checkmempool
	rr = testRESTRequest(t, server.handleRESTGetUTXOs, http.MethodGet, "/rest/getutxos/checkmempool/"+txid+"-0.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Test too many outpoints
	var manyOutpoints bytes.Buffer
	for i := 0; i < 20; i++ {
		if i > 0 {
			manyOutpoints.WriteString("/")
		}
		manyOutpoints.WriteString(txid)
		manyOutpoints.WriteString("-")
		manyOutpoints.WriteString(string(rune('0' + i%10)))
	}
	rr = testRESTRequest(t, server.handleRESTGetUTXOs, http.MethodGet, "/rest/getutxos/"+manyOutpoints.String()+".json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for too many outpoints, got %d", rr.Code)
	}

	// Test empty request
	rr = testRESTRequest(t, server.handleRESTGetUTXOs, http.MethodGet, "/rest/getutxos/.json")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for empty request, got %d", rr.Code)
	}
}

func TestRESTMethodNotAllowed(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true})

	// All REST endpoints should reject non-GET requests
	endpoints := []struct {
		handler http.HandlerFunc
		path    string
	}{
		{server.handleRESTChainInfo, "/rest/chaininfo.json"},
		{server.handleRESTMempoolInfo, "/rest/mempool/info.json"},
		{server.handleRESTMempoolContents, "/rest/mempool/contents.json"},
	}

	for _, ep := range endpoints {
		rr := testRESTRequest(t, ep.handler, http.MethodPost, ep.path)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected status 405, got %d", ep.path, rr.Code)
		}
	}
}

func TestRESTServerIntegration(t *testing.T) {
	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	cmConfig := consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	}
	chainMgr := consensus.NewChainManager(cmConfig)
	mp := mempool.New(mempool.DefaultConfig(), nil)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", RESTEnabled: true},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(chainMgr),
		WithMempool(mp),
	)

	// Create a test mux and register handlers
	mux := http.NewServeMux()
	server.RegisterRESTHandlers(mux)

	// Test that REST endpoints are registered
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// Test chaininfo endpoint
	resp, err := http.Get(testServer.URL + "/rest/chaininfo.json")
	if err != nil {
		t.Fatalf("failed to get chaininfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Test mempool info endpoint
	resp, err = http.Get(testServer.URL + "/rest/mempool/info.json")
	if err != nil {
		t.Fatalf("failed to get mempool info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestBitmapFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"0", []byte{0x00}},
		{"1", []byte{0x01}},
		{"10", []byte{0x01}},
		{"01", []byte{0x02}},
		{"11", []byte{0x03}},
		{"10101010", []byte{0x55}},
		{"11111111", []byte{0xFF}},
		{"100000000", []byte{0x01, 0x01}}, // 9 bits
	}

	for _, tt := range tests {
		result := bitmapFromString(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("bitmapFromString(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseOutpoint(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"0000000000000000000000000000000000000000000000000000000000000001-0", false},
		{"0000000000000000000000000000000000000000000000000000000000000001-123", false},
		{"invalid", true},
		{"abc-def", true}, // Invalid txid and index
		{"0000000000000000000000000000000000000000000000000000000000000001", true}, // Missing index
	}

	for _, tt := range tests {
		_, err := parseOutpoint(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("parseOutpoint(%q): expected error, got none", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parseOutpoint(%q): unexpected error: %v", tt.input, err)
		}
	}
}
