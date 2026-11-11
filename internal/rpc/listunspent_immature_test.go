package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// listunspent and immature coinbase outputs (Core parity).
//
// Core (src/wallet/rpc/coins.cpp listunspent -> src/wallet/spend.cpp:357
// AvailableCoins) skips a coinbase output while
// CWallet::IsTxImmatureCoinBase is true, i.e. while it has fewer than
// COINBASE_MATURITY+1 = 101 confirmations (src/wallet/wallet.cpp
// GetTxBlocksToMaturity), unless query_options.include_immature_coinbase is
// true. That option is type-checked as a bool (RPCTypeCheckObj ->
// RPC_TYPE_ERROR, -3). Every coin listunspent returns reports
// "spendable": true (coins.cpp, "Any coins we list are always spendable").
//
// Fixture, mirroring the regtest wallet scenario: chain tip at height 101,
// wallet coinbases at heights 1..101 (one mature, 100 immature) and one
// ordinary payment confirmed in block 101.

const immatureTestTip = 101

// immatureTestChain connects `tip` coinbase-only regtest blocks (paying
// OP_TRUE, not the wallet) so the chain manager reports that tip height.
func immatureTestChain(t *testing.T, tip int32) (*consensus.ChainParams, *consensus.ChainManager) {
	t.Helper()
	base := *consensus.RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: consensus.NewUTXOSet(db),
	})
	cm.SetIBD(false)

	prev := idx.Genesis()
	for h := int32(1); h <= tip; h++ {
		var heightScript []byte
		if h <= 16 {
			heightScript = []byte{byte(0x50 + h), 0x00}
		} else {
			heightScript = []byte{0x01, byte(h)} // h < 128 here
		}
		coinbase := &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
				SignatureScript:  heightScript,
				Sequence:         0xFFFFFFFF,
			}},
			TxOut: []*wire.TxOut{{Value: consensus.CalcBlockSubsidy(h), PkScript: []byte{0x51}}},
		}
		header := wire.BlockHeader{
			Version:    4,
			PrevBlock:  prev.Hash,
			MerkleRoot: consensus.CalcMerkleRoot([]wire.Hash256{coinbase.TxHash()}),
			Timestamp:  prev.Header.Timestamp + 600,
			Bits:       params.PowLimitBits,
		}
		target := consensus.CompactToBig(header.Bits)
		for header.Nonce = 0; consensus.HashToBig(header.BlockHash()).Cmp(target) > 0; header.Nonce++ {
		}
		block := &wire.MsgBlock{Header: header, Transactions: []*wire.MsgTx{coinbase}}
		if _, err := idx.AddHeader(block.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(block); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(block.Header.BlockHash())
	}
	if _, got := cm.BestBlock(); got != tip {
		t.Fatalf("precondition: tip height = %d, want %d", got, tip)
	}
	return params, cm
}

func immatureTestServer(t *testing.T) *Server {
	t.Helper()
	params, cm := immatureTestChain(t, immatureTestTip)
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, params)
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithWalletManager(mgr),
	)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"w"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	w, err := mgr.GetWallet("w")
	if err != nil {
		t.Fatalf("GetWallet: %v", err)
	}
	addr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	decoded, err := address.DecodeAddress(addr, address.Regtest)
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	spk := decoded.ScriptPubKey()
	for h := int32(1); h <= immatureTestTip; h++ {
		w.AddUTXO(&wallet.WalletUTXO{
			OutPoint:   wire.OutPoint{Hash: wire.Hash256{0xcb, byte(h)}, Index: 0},
			Amount:     50_0000_0000,
			PkScript:   spk,
			Address:    addr,
			Height:     h,
			IsCoinbase: true,
			Confirmed:  true,
		})
	}
	// One ordinary (non-coinbase) payment in the tip block: 1 confirmation.
	w.AddUTXO(&wallet.WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0xaa}, Index: 1},
		Amount:    1_0000_0000,
		PkScript:  spk,
		Address:   addr,
		Height:    immatureTestTip,
		Confirmed: true,
	})
	return s
}

func immatureListUnspent(t *testing.T, s *Server, params []interface{}) []map[string]interface{} {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, "listunspent", params, "", "")
	if resp.Error != nil {
		t.Fatalf("listunspent %v: %+v", params, resp.Error)
	}
	raw, ok := resp.Result.([]interface{})
	if !ok {
		t.Fatalf("listunspent result type = %T, want array", resp.Result)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]interface{})
		if !ok {
			t.Fatalf("listunspent entry type = %T, want object", e)
		}
		out = append(out, m)
	}
	return out
}

// coinbaseConfs returns the confirmations of the listed 50 BTC (coinbase)
// entries, and how many entries had spendable != true.
func coinbaseConfs(entries []map[string]interface{}) (confs map[int]bool, notSpendable int) {
	confs = map[int]bool{}
	for _, e := range entries {
		if e["spendable"] != true {
			notSpendable++
		}
		if amt, _ := e["amount"].(float64); amt == 50 {
			c, _ := e["confirmations"].(float64)
			confs[int(c)] = true
		}
	}
	return confs, notSpendable
}

func TestListUnspentImmature_DefaultSkipsImmatureCoinbase(t *testing.T) {
	s := immatureTestServer(t)
	entries := immatureListUnspent(t, s, []interface{}{})
	confs, notSpendable := coinbaseConfs(entries)
	if len(entries) != 2 {
		t.Errorf("listunspent count = %d, want 2 (the one mature coinbase + the payment; Core omits the 100 immature coinbases)", len(entries))
	}
	if len(confs) != 1 || !confs[101] {
		t.Errorf("coinbases listed at %d distinct confirmation counts, want 1 (only the 101-conf coinbase)", len(confs))
	}
	if notSpendable != 0 {
		t.Errorf("%d entries have spendable != true; Core reports spendable:true for every listed coin", notSpendable)
	}
}

func TestListUnspentImmature_IncludeImmatureCoinbaseTrue(t *testing.T) {
	s := immatureTestServer(t)
	entries := immatureListUnspent(t, s, []interface{}{1, 9999999, nil, true,
		map[string]interface{}{"include_immature_coinbase": true}})
	confs, notSpendable := coinbaseConfs(entries)
	if len(entries) != immatureTestTip+1 {
		t.Errorf("listunspent count = %d, want %d (101 coinbases + the payment)", len(entries), immatureTestTip+1)
	}
	if len(confs) != immatureTestTip {
		t.Errorf("distinct coinbase confirmations = %d, want %d", len(confs), immatureTestTip)
	}
	if notSpendable != 0 {
		t.Errorf("%d entries have spendable != true; Core reports spendable:true for every listed coin, immature included", notSpendable)
	}
	for _, e := range entries {
		if e["safe"] != true || e["solvable"] != true {
			t.Errorf("entry %v:%v safe=%v solvable=%v, want true/true", e["txid"], e["vout"], e["safe"], e["solvable"])
			break
		}
	}
}

func TestListUnspentImmature_IncludeImmatureCoinbaseFalseIsDefault(t *testing.T) {
	s := immatureTestServer(t)
	entries := immatureListUnspent(t, s, []interface{}{1, 9999999, nil, true,
		map[string]interface{}{"include_immature_coinbase": false}})
	if len(entries) != 2 {
		t.Errorf("listunspent(include_immature_coinbase=false) count = %d, want 2", len(entries))
	}
}

func TestListUnspentImmature_NonBoolOptionIsTypeError(t *testing.T) {
	s := immatureTestServer(t)
	for _, bad := range []interface{}{"yes", 1} {
		resp := testRPCRequest(t, s.handleRPC, "listunspent", []interface{}{1, 9999999, nil, true,
			map[string]interface{}{"include_immature_coinbase": bad}}, "", "")
		if resp.Error == nil {
			t.Errorf("include_immature_coinbase=%#v: expected RPC_TYPE_ERROR (-3), call succeeded", bad)
			continue
		}
		if resp.Error.Code != RPCErrTypeError {
			t.Errorf("include_immature_coinbase=%#v: code = %d, want %d (RPC_TYPE_ERROR)", bad, resp.Error.Code, RPCErrTypeError)
		}
	}
	// query_options itself must be an object (Core: params[4].get_obj()).
	resp := testRPCRequest(t, s.handleRPC, "listunspent", []interface{}{1, 9999999, nil, true, "notanobject"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrTypeError {
		t.Errorf("query_options=\"notanobject\": got %+v, want RPC_TYPE_ERROR (-3)", resp.Error)
	}
}

// An explicit null passes Core's RPCTypeCheckObj (nulls allowed) but the key
// exists, so get_bool() throws UniValue::type_error, which rpc/server.cpp:512
// reports as RPC_TYPE_ERROR (-3) with the plain type_error text.
func TestListUnspentImmature_NullOptionIsTypeError(t *testing.T) {
	s := immatureTestServer(t)
	resp := testRPCRequest(t, s.handleRPC, "listunspent", []interface{}{1, 9999999, nil, true,
		map[string]interface{}{"include_immature_coinbase": nil}}, "", "")
	if resp.Error == nil {
		t.Fatalf("include_immature_coinbase=null: call succeeded, want RPC_TYPE_ERROR (-3)")
	}
	if resp.Error.Code != RPCErrTypeError || resp.Error.Message != "JSON value of type null is not of expected type bool" {
		t.Errorf("include_immature_coinbase=null: got %d %q, want %d %q", resp.Error.Code, resp.Error.Message,
			RPCErrTypeError, "JSON value of type null is not of expected type bool")
	}
}

// Control: minconf=101 selects exactly the one coinbase that is mature under
// either rule, so this passes before and after the fix.
func TestListUnspentImmature_MinconfControl(t *testing.T) {
	s := immatureTestServer(t)
	entries := immatureListUnspent(t, s, []interface{}{101})
	if len(entries) != 1 {
		t.Fatalf("listunspent(minconf=101) count = %d, want 1", len(entries))
	}
	if c, _ := entries[0]["confirmations"].(float64); c != 101 {
		t.Errorf("confirmations = %v, want 101", entries[0]["confirmations"])
	}
	if entries[0]["spendable"] != true {
		t.Errorf("mature coinbase spendable = %v, want true", entries[0]["spendable"])
	}
}
