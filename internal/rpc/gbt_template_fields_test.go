package rpc

// getblocktemplate per-transaction fields and default_witness_commitment
// against Core rpc/mining.cpp:897-935 and :1028-1031:
//   - "fee" is tx_fees[i], the entry's fee in satoshis;
//   - "depends" lists the 1-based template index of every input's prevout
//     txid already placed in the block (the coinbase is index 0);
//   - "default_witness_commitment" is the coinbase commitment OUTPUT SCRIPT
//     (OP_RETURN 0x24 aa21a9ed <32-byte commitment>), not the bare hash.

import (
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

type gbtFieldsMockMempool struct{ entries []*mempool.TxEntry }

func (m *gbtFieldsMockMempool) GetSortedByAncestorFeeRate() []*mempool.TxEntry {
	return m.entries
}

func gbtFieldsTx(prev wire.OutPoint, value int64, seed byte) *wire.MsgTx {
	pk := []byte{0x00, 0x14}
	for i := 0; i < 20; i++ {
		pk = append(pk, seed)
	}
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prev,
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: value, PkScript: pk}},
	}
}

func gbtFieldsEntry(tx *wire.MsgTx, fee int64, parents ...*mempool.TxEntry) *mempool.TxEntry {
	vsize := int64(consensus.CalcTxWeight(tx)+3) / 4
	e := &mempool.TxEntry{
		Tx: tx, TxHash: tx.TxHash(), Fee: fee, Size: vsize,
		FeeRate: float64(fee) / float64(vsize), AncestorFee: fee, AncestorSize: vsize,
	}
	for _, p := range parents {
		e.Depends = append(e.Depends, p.TxHash)
		e.AncestorFee += p.AncestorFee
		e.AncestorSize += p.AncestorSize
	}
	return e
}

func gbtFieldsServer(t *testing.T, entries []*mempool.TxEntry) *Server {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: db})
	tipNode := &consensus.BlockNode{Hash: params.GenesisHash, Header: params.GenesisBlock.Header, Height: 0}
	tg := mining.NewTemplateGenerator(params,
		&gbtMockChainState{tipHash: params.GenesisHash, tipHeight: 0, tipNode: tipNode},
		&gbtFieldsMockMempool{entries: entries},
		&gbtMockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{params.GenesisHash: tipNode}})
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params), WithChainManager(cm), WithHeaderIndex(idx),
		WithChainDB(db), WithTemplateGenerator(tg))
}

func gbtFieldsCall(t *testing.T, s *Server) map[string]interface{} {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, "getblocktemplate", gbtSegwitRequest(), "", "")
	if resp.Error != nil {
		t.Fatalf("getblocktemplate: %v", resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result has type %T", resp.Result)
	}
	return m
}

// A parent and a child that spends it, plus an unrelated tx. Core reports
// each entry's fee and the child's depends [1].
func TestGBT_TransactionsCarryFeeAndDepends(t *testing.T) {
	parent := gbtFieldsEntry(gbtFieldsTx(wire.OutPoint{Hash: wire.Hash256{0xa0}}, 100_000, 0xa1), 220)
	child := gbtFieldsEntry(gbtFieldsTx(wire.OutPoint{Hash: parent.TxHash, Index: 0}, 50_000, 0xb1), 200_000, parent)
	other := gbtFieldsEntry(gbtFieldsTx(wire.OutPoint{Hash: wire.Hash256{0xc0}}, 100_000, 0xc1), 1_500)

	res := gbtFieldsCall(t, gbtFieldsServer(t, []*mempool.TxEntry{child, parent, other}))
	txs, ok := res["transactions"].([]interface{})
	if !ok || len(txs) != 3 {
		t.Fatalf("transactions = %v, want 3 entries", res["transactions"])
	}
	want := []struct {
		txid    wire.Hash256
		fee     int64
		depends []int
	}{
		{parent.TxHash, 220, nil},
		{child.TxHash, 200_000, []int{1}},
		{other.TxHash, 1_500, nil},
	}
	for i, w := range want {
		e := txs[i].(map[string]interface{})
		if e["txid"] != w.txid.String() {
			t.Errorf("transactions[%d].txid = %v, want %s", i, e["txid"], w.txid)
			continue
		}
		if fee, _ := e["fee"].(float64); int64(fee) != w.fee {
			t.Errorf("transactions[%d].fee = %v, want %d", i, e["fee"], w.fee)
		}
		deps, _ := e["depends"].([]interface{})
		if len(deps) != len(w.depends) {
			t.Errorf("transactions[%d].depends = %v, want %v", i, e["depends"], w.depends)
			continue
		}
		for j := range deps {
			if d, _ := deps[j].(float64); int(d) != w.depends[j] {
				t.Errorf("transactions[%d].depends[%d] = %v, want %d", i, j, deps[j], w.depends[j])
			}
		}
	}
}

// default_witness_commitment must be the script the miner places verbatim
// in the coinbase, and it must equal the commitment output of the template's
// own coinbase.
func TestGBT_DefaultWitnessCommitmentIsScript(t *testing.T) {
	tx := gbtFieldsEntry(gbtFieldsTx(wire.OutPoint{Hash: wire.Hash256{0xa0}}, 100_000, 0xa1), 1_000)
	res := gbtFieldsCall(t, gbtFieldsServer(t, []*mempool.TxEntry{tx}))
	got, _ := res["default_witness_commitment"].(string)
	raw, err := hex.DecodeString(got)
	if err != nil || len(raw) != 38 || hex.EncodeToString(raw[:6]) != "6a24aa21a9ed" {
		t.Fatalf("default_witness_commitment = %q, want 6a24aa21a9ed + 32 bytes (38-byte script)", got)
	}

	// The script must commit to the template's transactions: recompute it.
	wtxids := []wire.Hash256{{}, tx.Tx.WTxHash()}
	commitment := consensus.CalcWitnessCommitment(wtxids, make([]byte, 32))
	if hex.EncodeToString(raw[6:]) != hex.EncodeToString(commitment[:]) {
		t.Errorf("commitment bytes = %x, want %x", raw[6:], commitment[:])
	}
}
