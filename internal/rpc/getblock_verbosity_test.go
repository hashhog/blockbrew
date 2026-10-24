package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// getblockVerbosityRig connects 101 coinbase-only blocks, then a block 102
// whose second tx spends block 1's (mature) OP_TRUE coinbase, so undo data
// exists for a non-coinbase input.
func getblockVerbosityRig(t *testing.T) (*Server, string) {
	t.Helper()
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)

	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	if err := db.StoreBlock(params.GenesisHash, params.GenesisBlock); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBlockHeight(0, params.GenesisHash); err != nil {
		t.Fatal(err)
	}
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: consensus.NewUTXOSet(db),
	})
	cm.SetIBD(false)

	connect := func(b *wire.MsgBlock) *consensus.BlockNode {
		node, err := idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := db.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock: %v", err)
		}
		return node
	}

	prev := idx.Genesis()
	var cb1 wire.Hash256
	for h := int32(1); h <= 101; h++ {
		b := buildRegtestBlock(t, params, prev)
		if h == 1 {
			cb1 = b.Transactions[0].TxHash()
		}
		prev = connect(b)
	}
	spend := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: cb1, Index: 0},
			Sequence:         0xFFFFFFFD,
		}},
		TxOut: []*wire.TxOut{{Value: consensus.CalcBlockSubsidy(1) - 1000, PkScript: []byte{0x51}}},
	}
	b := buildRegtestBlockWithTxs(t, params, prev, []*wire.MsgTx{spend})
	connect(b)

	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params), WithHeaderIndex(idx), WithChainManager(cm), WithChainDB(db))
	return server, b.Header.BlockHash().String()
}

func getblockCall(t *testing.T, s *Server, params ...interface{}) *RPCResponse {
	t.Helper()
	return testRPCRequest(t, s.handleRPC, "getblock", params, "", "")
}

func vin0Of(t *testing.T, res interface{}, txIndex int) map[string]interface{} {
	t.Helper()
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want object", res)
	}
	txs, _ := m["tx"].([]interface{})
	tx, _ := txs[txIndex].(map[string]interface{})
	vins, _ := tx["vin"].([]interface{})
	v, _ := vins[0].(map[string]interface{})
	if v == nil {
		t.Fatalf("no vin[0] in tx %d: %v", txIndex, tx)
	}
	return v
}

// Core ParseVerbosity(allow_bool=true): JSON false is verbosity 0 (hex).
func TestGetBlockBoolFalseReturnsHex(t *testing.T) {
	s, h := getblockVerbosityRig(t)
	for _, v := range []interface{}{false, float64(0)} {
		resp := getblockCall(t, s, h, v)
		if resp.Error != nil {
			t.Fatalf("verbosity %v: %v", v, resp.Error)
		}
		if _, ok := resp.Result.(string); !ok {
			t.Fatalf("verbosity %v: result %T, want hex string", v, resp.Result)
		}
	}
	resp := getblockCall(t, s, h, true)
	if _, ok := resp.Result.(string); ok || resp.Error != nil {
		t.Fatalf("verbosity true must be the verbosity-1 object, got %T err=%v", resp.Result, resp.Error)
	}
}

func TestGetBlockVerbosity3AddsPrevout(t *testing.T) {
	s, h := getblockVerbosityRig(t)

	v2 := vin0Of(t, getblockCall(t, s, h, float64(2)).Result, 1)
	if _, has := v2["prevout"]; has {
		t.Fatalf("verbosity 2 must not carry prevout: %v", v2)
	}

	for _, n := range []float64{3, 9} { // Core: anything above 2 is SHOW_DETAILS_AND_PREVOUT
		resp := getblockCall(t, s, h, n)
		if resp.Error != nil {
			t.Fatalf("verbosity %v: %v", n, resp.Error)
		}
		v3 := vin0Of(t, resp.Result, 1)
		p, ok := v3["prevout"].(map[string]interface{})
		if !ok {
			t.Fatalf("verbosity %v: vin[0] has no prevout: %v", n, v3)
		}
		if p["generated"] != true || p["height"] != float64(1) {
			t.Fatalf("prevout generated/height = %v/%v, want true/1", p["generated"], p["height"])
		}
		if _, ok := p["scriptPubKey"].(map[string]interface{}); !ok {
			t.Fatalf("prevout.scriptPubKey missing: %v", p)
		}
		if _, ok := p["value"]; !ok {
			t.Fatalf("prevout.value missing: %v", p)
		}
		// The coinbase has no prevout.
		if _, has := vin0Of(t, resp.Result, 0)["prevout"]; has {
			t.Fatal("coinbase vin must not carry prevout")
		}
	}
}
