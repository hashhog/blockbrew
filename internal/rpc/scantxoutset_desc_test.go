package rpc

// scantxoutset unspents[].desc is Core's InferDescriptor of the coin's own
// scriptPubKey (addr(...)#csum), not the scan object string the caller sent
// (rpc/blockchain.cpp scantxoutset).

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

const (
	scanDescP2SHSpk  = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"
	scanDescP2SHAddr = "2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN"
	scanDescP2SHDesc = "addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8"
)

func scanDescUnspentDesc(t *testing.T, scanObject string) string {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	utxo := consensus.NewUTXOSetWithMaxCache(db, 0)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
	})
	cm.SetIBD(false)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params), WithChainManager(cm), WithHeaderIndex(idx), WithChainDB(db))

	b1 := buildRegtestBlock(t, params, idx.Genesis())
	if _, err := idx.AddHeader(b1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("connect: %v", err)
	}
	spk, _ := hex.DecodeString(scanDescP2SHSpk)
	utxo.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x5d, 0x01}, Index: 0},
		&consensus.UTXOEntry{Amount: 50_000, PkScript: spk, Height: 1})
	if err := utxo.Flush(); err != nil {
		t.Fatal(err)
	}

	arg, _ := json.Marshal([]interface{}{"start", []string{scanObject}})
	res, rerr := server.handleScanTxOutSet(arg)
	if rerr != nil {
		t.Fatalf("scantxoutset: %+v", rerr)
	}
	r := res.(*scanTxOutSetResult)
	if len(r.Unspents) != 1 {
		t.Fatalf("want 1 unspent, got %d", len(r.Unspents))
	}
	return r.Unspents[0].Desc
}

func TestScanTxOutSetDescFromRawScanObjectIsInferredAddr(t *testing.T) {
	if got := scanDescUnspentDesc(t, "raw("+scanDescP2SHSpk+")"); got != scanDescP2SHDesc {
		t.Fatalf("desc = %q, want %q", got, scanDescP2SHDesc)
	}
}

func TestScanTxOutSetDescFromAddrScanObjectKeepsChecksum(t *testing.T) {
	if got := scanDescUnspentDesc(t, "addr("+scanDescP2SHAddr+")"); got != scanDescP2SHDesc {
		t.Fatalf("desc = %q, want %q", got, scanDescP2SHDesc)
	}
}
