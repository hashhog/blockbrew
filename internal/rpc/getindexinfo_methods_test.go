package rpc

// getindexinfo RPC — Core-parity contract test.
//
// Mirrors Bitcoin Core rpc/node.cpp::getindexinfo (363-410) +
// SummaryToJSON (351-361) + index/base.cpp::GetSummary (472-484). The shape
// contract:
//
//   - top-level: a DYNAMIC JSON OBJECT keyed BY INDEX NAME (the Core
//     GetName() string — "txindex", "basic block filter index", etc).
//   - each value: EXACTLY {synced: bool, best_block_height: int}, in that
//     order. Core NEVER emits best_hash / best_block_hash / a nested name.
//   - only ENABLED/running indexes appear.
//   - optional positional index_name arg filters to one index; a name that
//     matches NO running index yields {} (an EMPTY object, NOT an error) —
//     this is the load-bearing Core-parity assertion.
//   - a non-string index_name yields Core's RPC_TYPE_ERROR (-3), NOT
//     -32602 (RPCTypeCheck path in rpc/util.cpp). Pinned by
//     TestGetIndexInfo_NonStringTypeError below.
//
// The handler (extra_methods.go::handleGetIndexInfo) is already Core-correct;
// this test pins that shape against regressions. It deliberately drives the
// real handler end-to-end through handleRPC (the same path getorphantxs's
// teeth-test uses), decoding the on-the-wire JSON so field names/types/order
// are asserted as a client sees them.
//
// References: bitcoin-core/src/rpc/node.cpp (getindexinfo, SummaryToJSON);
// bitcoin-core/src/index/base.cpp (BaseIndex::GetSummary);
// bitcoin-core/src/index/blockfilterindex.cpp:78 (GetName ==
// "basic block filter index").

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
)

// assertIndexValueShape decodes one getindexinfo value object and asserts it
// carries EXACTLY {synced(bool), best_block_height(number)} — no best_hash,
// no best_block_hash, no name — and that best_block_height equals wantHeight
// (a JSON number, never a hex string).
func assertIndexValueShape(t *testing.T, key string, raw interface{}, wantHeight float64) {
	t.Helper()

	val, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("%q value is %T, want object", key, raw)
	}

	// EXACTLY two keys.
	if len(val) != 2 {
		t.Errorf("%q value has %d keys (%v), want exactly 2 {synced, best_block_height}",
			key, len(val), val)
	}

	// synced must be present and a bool.
	synced, present := val["synced"]
	if !present {
		t.Errorf("%q value missing `synced`: %v", key, val)
	} else if _, ok := synced.(bool); !ok {
		t.Errorf("%q synced is %T, want bool", key, synced)
	}

	// best_block_height must be present and a JSON number (NOT a hex string).
	bbh, present := val["best_block_height"]
	if !present {
		t.Errorf("%q value missing `best_block_height`: %v", key, val)
	} else {
		h, ok := bbh.(float64)
		if !ok {
			t.Errorf("%q best_block_height is %T, want number (Core emits an integer, never a hex string)", key, bbh)
		} else if h != wantHeight {
			t.Errorf("%q best_block_height = %v, want %v", key, h, wantHeight)
		}
	}

	// Core NEVER emits any of these inside the value object.
	for _, forbidden := range []string{"best_hash", "best_block_hash", "name"} {
		if _, present := val[forbidden]; present {
			t.Errorf("%q value must NOT contain %q (Core never emits it): %v", key, forbidden, val)
		}
	}
}

// callGetIndexInfo drives the handler end-to-end through handleRPC and returns
// the decoded top-level result as a map (the on-the-wire JSON object shape).
func callGetIndexInfo(t *testing.T, server *Server, params interface{}) (map[string]interface{}, *RPCError) {
	t.Helper()
	resp := testRPCRequest(t, server.handleRPC, "getindexinfo", params, "", "")
	if resp.Error != nil {
		return nil, resp.Error
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("getindexinfo result is %T, want JSON object", resp.Result)
	}
	return m, nil
}

// TestGetIndexInfo_Shape pins the full Core-parity shape: the dynamic
// name-keyed object, the EXACT {synced, best_block_height} value shape, the
// renamed blockfilterindex key, the unknown-name -> {} non-error case, and the
// non-string-arg error path.
func TestGetIndexInfo_Shape(t *testing.T) {
	// --- Case 1: no arg, TxIndex=true. ---------------------------------------
	// nil chainMgr -> tipHeight 0; per spec the entry must still appear keyed
	// "txindex" with best_block_height: 0. This keeps the test self-contained
	// (no heavy ChainManager / chain build) while still exercising the txindex
	// summary path.
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: true})

	m, rpcErr := callGetIndexInfo(t, server, []interface{}{})
	if rpcErr != nil {
		t.Fatalf("no-arg call returned error: %+v", rpcErr)
	}
	txVal, present := m["txindex"]
	if !present {
		t.Fatalf("no-arg result missing `txindex` key (TxIndex=true): %v", m)
	}
	assertIndexValueShape(t, "txindex", txVal, 0)

	// --- Case 2: filter match ["txindex"] -> exactly the txindex entry. ------
	m, rpcErr = callGetIndexInfo(t, server, []interface{}{"txindex"})
	if rpcErr != nil {
		t.Fatalf("filter-match call returned error: %+v", rpcErr)
	}
	if len(m) != 1 {
		t.Errorf("filter [\"txindex\"] result has %d entries, want exactly 1: %v", len(m), m)
	}
	if _, present := m["txindex"]; !present {
		t.Errorf("filter [\"txindex\"] result missing `txindex`: %v", m)
	}

	// --- Case 3: filter unknown ["does_not_exist"] -> EMPTY object {}, NOT an
	//     RPC error. This is the key Core-parity assertion (SummaryToJSON drops
	//     a non-matching name; the handler returns {} with Error == nil). ------
	resp := testRPCRequest(t, server.handleRPC, "getindexinfo", []interface{}{"does_not_exist"}, "", "")
	if resp.Error != nil {
		t.Fatalf("unknown index_name must NOT error (Core returns {}); got %+v", resp.Error)
	}
	unknown, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("unknown index_name result is %T, want empty object", resp.Result)
	}
	if len(unknown) != 0 {
		t.Errorf("unknown index_name result = %v, want empty object {}", unknown)
	}

	// --- (non-string index_name error code is pinned by
	//     TestGetIndexInfo_NonStringTypeError below.) ---------------------------

	// --- Field-order assertion: re-marshal the txindex value and confirm
	//     `synced` precedes `best_block_height` byte-for-byte. indexSummary is
	//     a struct (not a map) so encoding/json preserves declaration order. ---
	server2 := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: true})
	rawResult, handlerErr := server2.handleGetIndexInfo(json.RawMessage(`[]`))
	if handlerErr != nil {
		t.Fatalf("handleGetIndexInfo direct call errored: %+v", handlerErr)
	}
	resMap, ok := rawResult.(map[string]interface{})
	if !ok {
		t.Fatalf("handler result is %T, want map", rawResult)
	}
	valBytes, err := json.Marshal(resMap["txindex"])
	if err != nil {
		t.Fatalf("marshal txindex value: %v", err)
	}
	s := string(valBytes)
	si := strings.Index(s, "synced")
	bi := strings.Index(s, "best_block_height")
	if si < 0 || bi < 0 {
		t.Fatalf("txindex value missing expected keys on the wire: %s", s)
	}
	if si > bi {
		t.Errorf("field order wrong: %q — `synced` must precede `best_block_height`", s)
	}
}

// TestGetIndexInfo_BlockFilterIndexKey pins case 4: a storage index registered
// under the INTERNAL name "blockfilterindex" must surface under Core's
// GetName() string "basic block filter index" (NOT the internal name), with
// the identical {synced, best_block_height} value shape.
func TestGetIndexInfo_BlockFilterIndexKey(t *testing.T) {
	db := storage.NewMemDB()
	defer db.Close()
	cdb := storage.NewChainDB(db)

	mgr := storage.NewIndexManager(cdb)
	idx := storage.NewBlockFilterIndex(db)
	if err := mgr.RegisterIndex(idx); err != nil {
		t.Fatalf("RegisterIndex: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"}, // TxIndex defaults false
		WithIndexManager(mgr),
	)

	m, rpcErr := callGetIndexInfo(t, server, []interface{}{})
	if rpcErr != nil {
		t.Fatalf("no-arg call returned error: %+v", rpcErr)
	}

	// Must be keyed by Core's GetName() string, NOT the internal name.
	const coreName = "basic block filter index"
	if _, present := m["blockfilterindex"]; present {
		t.Errorf("result keyed by INTERNAL name \"blockfilterindex\"; Core uses %q: %v", coreName, m)
	}
	val, present := m[coreName]
	if !present {
		t.Fatalf("result missing Core key %q: %v", coreName, m)
	}

	// A freshly-registered index sits at bestHeight -1, which GetSummary clamps
	// to 0 (Core's else-arm) — so best_block_height must be 0, a number.
	assertIndexValueShape(t, coreName, val, 0)

	// TxIndex is disabled here, so "txindex" must NOT appear (Core only lists
	// running indexes).
	if _, present := m["txindex"]; present {
		t.Errorf("txindex present with TxIndex=false: %v", m)
	}
}

// TestGetIndexInfo_DisabledEmpty pins case 6: with no index enabled (TxIndex
// false, no IndexManager), the no-arg call returns an EMPTY object {} — never
// null, never an error.
func TestGetIndexInfo_DisabledEmpty(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})

	resp := testRPCRequest(t, server.handleRPC, "getindexinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("disabled-state call returned error: %+v", resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("disabled-state result is %T, want empty object", resp.Result)
	}
	if len(m) != 0 {
		t.Errorf("disabled-state result = %v, want empty object {}", m)
	}
}

// TestGetIndexInfo_NonStringTypeError pins the wrong-type arg path: a non-string
// index_name must yield Core's RPC_TYPE_ERROR (-3), NOT RPCErrInvalidParams
// (-32602). Core dispatches the typed `index_name` arg through RPCTypeCheck
// (rpc/util.cpp), which throws RPC_TYPE_ERROR for a mismatched type.
func TestGetIndexInfo_NonStringTypeError(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: true})

	// arg 0 is a number, not a string.
	resp := testRPCRequest(t, server.handleRPC, "getindexinfo", []interface{}{123}, "", "")
	if resp.Error == nil {
		t.Fatalf("non-string index_name must error; got result %+v", resp.Result)
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Errorf("non-string index_name: error code = %d, want %d (RPCErrTypeError, Core RPC_TYPE_ERROR)",
			resp.Error.Code, RPCErrTypeError)
	}
}
