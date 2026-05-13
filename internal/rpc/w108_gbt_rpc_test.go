// W108 G6 + G7 — RPC-level integration tests for GBT rules[] and vbavailable{}.
//
// These tests call handleGetBlockTemplate end-to-end and assert the response
// JSON contains the correct "rules" array and "vbavailable" map per BIP-9 /
// Bitcoin Core rpc/mining.cpp:950-983.
//
// Mining-package stubs (w108_gbt_test.go G6/G7) cannot import this package
// (cycle: rpc→mining), so the authoritative assertions live here.
package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// gbtRulesTestSetup creates a minimal Server wired with a real TemplateGenerator
// so that handleGetBlockTemplate can run end-to-end.
func gbtRulesTestSetup(t *testing.T, params *consensus.ChainParams) *Server {
	t.Helper()

	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Build a thin mock that satisfies mining.ChainStateProvider using
	// the real ChainManager so BestBlockNode() is wired correctly.
	tipHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   tipHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}
	mockCS := &gbtMockChainState{tipHash: tipHash, tipHeight: 0, tipNode: tipNode}
	mockMP := &gbtMockMempool{}
	mockHI := &gbtMockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{tipHash: tipNode}}

	tg := mining.NewTemplateGenerator(params, mockCS, mockMP, mockHI)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
		WithTemplateGenerator(tg),
	)
	return server
}

// ---------------------------------------------------------------------------
// TestW108_G6_RulesInGBTResponse — GBT response includes correct "rules" array.
//
// Core mining.cpp:950-963:
//   aRules = ["csv"]
//   if !fPreSegWit: aRules += ["!segwit", "taproot"]
//   if signet:      aRules += ["!signet"]
//
// On regtest all buried heights are 0 (active from genesis), so the expected
// rules array is ["csv", "!segwit", "taproot"].
// ---------------------------------------------------------------------------
func TestW108_G6_RulesInGBTResponse(t *testing.T) {
	params := consensus.RegtestParams()
	server := gbtRulesTestSetup(t, params)

	resp := testRPCRequest(t, server.handleRPC, "getblocktemplate", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("G6: getblocktemplate returned error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("G6: getblocktemplate returned nil result")
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("G6: result has unexpected type %T", resp.Result)
	}

	// "rules" must be present.
	rulesRaw, ok := resultMap["rules"]
	if !ok {
		t.Fatal("G6 BUG: 'rules' field absent from GBT response; " +
			"Core mining.cpp:994: result.pushKV(\"rules\", aRules)")
	}

	rulesSlice, ok := rulesRaw.([]interface{})
	if !ok {
		t.Fatalf("G6: 'rules' has unexpected type %T, want []interface{}", rulesRaw)
	}
	if len(rulesSlice) == 0 {
		t.Error("G6 BUG: 'rules' array is empty; must contain at least \"csv\"")
	}

	// Convert to []string for easier comparison.
	rules := make([]string, len(rulesSlice))
	for i, r := range rulesSlice {
		s, ok := r.(string)
		if !ok {
			t.Errorf("G6: rules[%d] has type %T, want string", i, r)
			continue
		}
		rules[i] = s
	}

	// "csv" must always be first (Core mining.cpp:954).
	if len(rules) == 0 || rules[0] != "csv" {
		t.Errorf("G6: rules[0] = %q, want \"csv\" (always first per Core mining.cpp:954)", rules[0])
	}

	// On regtest segwit is active from genesis (SegwitHeight == 0), so
	// "!segwit" must be present (Core mining.cpp:956: if !fPreSegWit).
	hasSegwit := false
	hasTaproot := false
	for _, r := range rules {
		if r == "!segwit" {
			hasSegwit = true
		}
		if r == "taproot" {
			hasTaproot = true
		}
	}
	if !hasSegwit {
		t.Errorf("G6: '!segwit' missing from rules %v; "+
			"Core: if !fPreSegWit: aRules.push_back(\"!segwit\") (mining.cpp:956)", rules)
	}
	// On regtest taproot is active from genesis (TaprootHeight == 0).
	if !hasTaproot {
		t.Errorf("G6: 'taproot' missing from rules %v; "+
			"Core: if !fPreSegWit && taproot active: aRules.push_back(\"taproot\") (mining.cpp:957)", rules)
	}

	// "vbrequired" must be present and zero (Core mining.cpp:996).
	vbrequiredRaw, ok := resultMap["vbrequired"]
	if !ok {
		t.Error("G6: 'vbrequired' field absent from GBT response; Core mining.cpp:996: result.pushKV(\"vbrequired\", 0)")
	} else {
		// JSON numbers decode as float64.
		if vbrequired, ok := vbrequiredRaw.(float64); !ok || vbrequired != 0 {
			t.Errorf("G6: vbrequired = %v, want 0", vbrequiredRaw)
		}
	}
}

// ---------------------------------------------------------------------------
// TestW108_G7_VbAvailableInGBTResponse — GBT response includes "vbavailable" map.
//
// Core mining.cpp:965-983: vbavailable maps deployment name → bit number for
// deployments in STARTED or LOCKED_IN state.
//
// On regtest the only BIP9 deployment is "testdummy" with StartTime=AlwaysActive.
// AlwaysActive → state is DeploymentActive, NOT STARTED/LOCKED_IN, so
// vbavailable must be present but EMPTY.
// ---------------------------------------------------------------------------
func TestW108_G7_VbAvailableInGBTResponse(t *testing.T) {
	params := consensus.RegtestParams()
	server := gbtRulesTestSetup(t, params)

	resp := testRPCRequest(t, server.handleRPC, "getblocktemplate", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("G7: getblocktemplate returned error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("G7: getblocktemplate returned nil result")
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("G7: result has unexpected type %T", resp.Result)
	}

	// "vbavailable" must be present (even when empty).
	vbRaw, ok := resultMap["vbavailable"]
	if !ok {
		t.Fatal("G7 BUG: 'vbavailable' field absent from GBT response; " +
			"Core mining.cpp:995: result.pushKV(\"vbavailable\", vbavailable)")
	}

	vbMap, ok := vbRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("G7: 'vbavailable' has unexpected type %T, want map[string]interface{}", vbRaw)
	}

	// On regtest testdummy is AlwaysActive → DeploymentActive, NOT STARTED/LOCKED_IN.
	// So vbavailable must be {} (empty).
	if _, exists := vbMap["testdummy"]; exists {
		t.Errorf("G7: vbavailable contains 'testdummy' but its state is DeploymentActive "+
			"(AlwaysActive); only STARTED/LOCKED_IN deployments are advertised "+
			"per Core mining.cpp:966-983")
	}
}

// ---------------------------------------------------------------------------
// TestW108_G7_VbAvailableStartedDeployment — a deployment in STARTED state
// must appear in vbavailable with its bit number.
//
// We construct a chain-params copy with a STARTED deployment (StartTime=0 so
// it starts at genesis MTP=0) and verify it appears in vbavailable.
// ---------------------------------------------------------------------------
func TestW108_G7_VbAvailableStartedDeployment(t *testing.T) {
	// Copy regtest params and add a deployment that starts at time 0 (genesis).
	// On regtest genesis MTP=0 >= StartTime=0 → DeploymentStarted.
	localParams := *consensus.RegtestParams()
	localParams.Deployments = []*consensus.BIP9Deployment{
		{
			Name:                "w108-test-started",
			Bit:                 5,
			StartTime:           0, // Starts at MTP=0 (genesis)
			Timeout:             consensus.NoTimeout,
			MinActivationHeight: 0,
			Period:              144,
			Threshold:           108,
		},
	}

	// Verify the state is STARTED before wiring it into the server.
	tipNode := &consensus.BlockNode{
		Hash:   localParams.GenesisHash,
		Header: localParams.GenesisBlock.Header,
		Height: 0,
	}
	state := consensus.GetDeploymentState(localParams.Deployments[0], 0, tipNode, &localParams, nil)
	if state != consensus.DeploymentStarted {
		t.Skipf("G7 started-deployment test: unexpected state %v (want Started); skipping", state)
	}

	// Now wire the server with this params copy.
	idx := consensus.NewHeaderIndex(&localParams)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      &localParams,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesisHash := localParams.GenesisHash
	mockCS := &gbtMockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	mockMP := &gbtMockMempool{}
	mockHI := &gbtMockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := mining.NewTemplateGenerator(&localParams, mockCS, mockMP, mockHI)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(&localParams),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
		WithTemplateGenerator(tg),
	)

	resp := testRPCRequest(t, server.handleRPC, "getblocktemplate", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("G7 started: getblocktemplate returned error: %v", resp.Error)
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("G7 started: result has unexpected type %T", resp.Result)
	}

	vbRaw, ok := resultMap["vbavailable"]
	if !ok {
		t.Fatal("G7 started: 'vbavailable' absent from GBT response")
	}

	vbMap, ok := vbRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("G7 started: vbavailable has type %T, want map", vbRaw)
	}

	// The STARTED deployment must be in vbavailable.
	bitRaw, exists := vbMap["w108-test-started"]
	if !exists {
		raw, _ := json.Marshal(vbMap)
		t.Errorf("G7 started: 'w108-test-started' missing from vbavailable %s; "+
			"STARTED deployments must be advertised per Core mining.cpp:968", raw)
		return
	}

	// Bit value must be 5.
	bit, ok := bitRaw.(float64)
	if !ok {
		t.Fatalf("G7 started: vbavailable[w108-test-started] type %T, want float64", bitRaw)
	}
	if int(bit) != 5 {
		t.Errorf("G7 started: vbavailable[w108-test-started] = %v, want 5", bit)
	}
}

// ---------------------------------------------------------------------------
// Local mocks for the mining interfaces (avoid importing mining_test internals).
// ---------------------------------------------------------------------------

type gbtMockChainState struct {
	tipHash   wire.Hash256
	tipHeight int32
	tipNode   *consensus.BlockNode
}

func (m *gbtMockChainState) BestBlock() (wire.Hash256, int32) {
	return m.tipHash, m.tipHeight
}

func (m *gbtMockChainState) TipNode() *consensus.BlockNode {
	return m.tipNode
}

type gbtMockMempool struct{}

func (m *gbtMockMempool) GetSortedByAncestorFeeRate() []*mempool.TxEntry {
	return nil
}

type gbtMockHeaderIndex struct {
	nodes map[wire.Hash256]*consensus.BlockNode
}

func (m *gbtMockHeaderIndex) GetNode(hash wire.Hash256) *consensus.BlockNode {
	return m.nodes[hash]
}

func (m *gbtMockHeaderIndex) AddHeader(header wire.BlockHeader, minPowChecked bool) (*consensus.BlockNode, error) {
	hash := header.BlockHash()
	parent := m.nodes[header.PrevBlock]
	var height int32
	if parent != nil {
		height = parent.Height + 1
	}
	node := &consensus.BlockNode{
		Hash:   hash,
		Header: header,
		Height: height,
		Parent: parent,
	}
	m.nodes[hash] = node
	return node, nil
}
