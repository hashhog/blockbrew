package rpc

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core 31's entryToJSON (bitcoin-core/src/rpc/mempool.cpp) emits
// `chunkweight` (after ancestorsize) and `fees.chunk`: the fee and
// sigops-adjusted weight of the tx's chunk in its cluster linearization.
// The tests read the JSON the RPC would send, so they compile on a tree that
// lacks the fields and fail on the missing keys.

type chunkJSON struct {
	chunkWeight int64
	chunkFee    float64
	modified    float64
	weight      int64
}

func entryChunkJSON(t *testing.T, s *Server, h wire.Hash256) chunkJSON {
	t.Helper()
	raw, err := json.Marshal(s.mempoolEntryFromTxEntry(s.mempool.GetEntry(h)))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		ChunkWeight *int64 `json:"chunkweight"`
		Weight      int64  `json:"weight"`
		Fees        struct {
			Chunk    *float64 `json:"chunk"`
			Modified float64  `json:"modified"`
		} `json:"fees"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.ChunkWeight == nil {
		t.Fatalf("%s: chunkweight missing from %s", h, raw)
	}
	if m.Fees.Chunk == nil {
		t.Fatalf("%s: fees.chunk missing from %s", h, raw)
	}
	return chunkJSON{*m.ChunkWeight, *m.Fees.Chunk, m.Fees.Modified, m.Weight}
}

func TestMempoolEntryChunkFieldsSingleTx(t *testing.T) {
	// A tx with no relatives is its own chunk.
	funding := wire.OutPoint{Hash: wire.Hash256{0x77, 0x01}, Index: 0}
	utxo := consensus.NewInMemoryUTXOView()
	utxo.AddUTXO(funding, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: opTrueP2WSH(), Height: 1})
	mp := mempool.New(mempool.DefaultConfig(), utxo)
	solo := spendOpTrue([]wire.OutPoint{funding}, 1, 990_000)
	if err := mp.AddTransaction(solo); err != nil {
		t.Fatal(err)
	}
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))
	got := entryChunkJSON(t, server, solo.TxHash())
	if want := consensus.CalcTxWeight(solo); got.chunkWeight != want {
		t.Errorf("chunkweight = %d, want %d", got.chunkWeight, want)
	}
	if math.Abs(got.chunkFee-got.modified) > 1e-12 || math.Abs(got.chunkFee-0.0001) > 1e-12 {
		t.Errorf("fees.chunk = %v, want modified fee %v (0.0001)", got.chunkFee, got.modified)
	}
}

// Every tx of a family sits in some chunk; the chunks partition the cluster,
// so the distinct chunks' weights and fees sum to the family totals, and
// each chunk's weight/fee is at least its own tx's.
func TestMempoolEntryChunkFieldsPartitionCluster(t *testing.T) {
	f := newMempoolFamily(t)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))
	txs := []*wire.MsgTx{f.p, f.c1, f.c2, f.g}
	var totW int64
	var totFee float64
	type key struct {
		w int64
		f float64
	}
	seen := map[key]int{}
	count := map[key]int{}
	for _, tx := range txs {
		g := entryChunkJSON(t, server, tx.TxHash())
		totW += g.weight
		totFee += g.modified
		if g.chunkWeight < g.weight || g.chunkFee+1e-12 < g.modified {
			t.Errorf("%s chunk (%d, %v) smaller than the tx itself (%d, %v)", tx.TxHash(), g.chunkWeight, g.chunkFee, g.weight, g.modified)
		}
		k := key{g.chunkWeight, g.chunkFee}
		seen[k]++
		count[k] = 1
	}
	var sumW int64
	var sumFee float64
	for k := range count {
		sumW += k.w
		sumFee += k.f
	}
	// Chunks with identical (weight, fee) would collapse here; the fixture
	// fees differ, so a mismatch means the chunks do not partition the pool.
	if sumW != totW || math.Abs(sumFee-totFee) > 1e-9 {
		t.Errorf("chunks sum to weight %d fee %v, want %d / %v", sumW, sumFee, totW, totFee)
	}
}
