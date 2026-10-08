package rpc

// BB-1 (receipts/arch-concurrency-liveness-audit-2026-10-07.md): dumptxoutset
// flushed the coin cache three times through UTXOSet.ScanUTXOs (WriteSnapshot's
// count + write passes, then ComputeHashSerialized), each under the UTXO-set
// mutex only. ConnectBlock mutates the cache input by input while holding cm.mu
// but not u.mu, so a dump could persist half a block under a coins marker that
// still names the previous block — and the boot marker-lag repair would then
// adopt it. Core flushes and opens the dump cursor under cs_main
// (rpc/blockchain.cpp PrepareUTXOSnapshot: LOCK(cs_main); ForceFlushStateToDisk;
// CreateCoinsCursor), which excludes ConnectBlock.
//
// Same deterministic seam as TestScanTxOutSetDoesNotFlushMidConnectBlock
// (parkReadDB parks ConnectBlock's read of its second input).

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

func TestDumpTxOutSetDoesNotFlushMidConnectBlock(t *testing.T) {
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)

	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	pdb := &parkReadDB{DB: storage.NewMemDB()}
	db := storage.NewChainDB(pdb)
	utxo := consensus.NewUTXOSetWithMaxCache(db, 0) // cold coins: every input is a DB read
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
	})
	cm.SetIBD(false)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params), WithChainManager(cm), WithHeaderIndex(idx), WithChainDB(db))

	connect := func(b *wire.MsgBlock) error {
		if _, err := idx.AddHeader(b.Header, true); err != nil && err != consensus.ErrDuplicateHeader {
			t.Fatalf("AddHeader: %v", err)
		}
		return cm.ConnectBlock(b)
	}
	b1 := buildRegtestBlock(t, params, idx.Genesis())
	if err := connect(b1); err != nil {
		t.Fatalf("connect b1: %v", err)
	}
	n1 := idx.GetNode(b1.Header.BlockHash())

	// X: spendable (OP_TRUE). Z: unspendable (OP_0) so b2 fails scripts.
	x := wire.OutPoint{Hash: wire.Hash256{0x5c, 0xa1}, Index: 0}
	z := wire.OutPoint{Hash: wire.Hash256{0x5c, 0xa2}, Index: 0}
	utxo.AddUTXO(x, &consensus.UTXOEntry{Amount: 50_000, PkScript: []byte{0x51}, Height: 1})
	utxo.AddUTXO(z, &consensus.UTXOEntry{Amount: 50_000, PkScript: []byte{0x00}, Height: 1})
	if err := utxo.Flush(); err != nil {
		t.Fatal(err)
	}

	spend := func(op wire.OutPoint, tag byte) *wire.MsgTx {
		return &wire.MsgTx{Version: 1,
			TxIn:  []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xFFFFFFFF}},
			TxOut: []*wire.TxOut{{Value: 40_000, PkScript: []byte{0x51, tag}}}}
	}
	tx1 := spend(x, 1)
	b2 := buildRegtestBlockWithTxs(t, params, n1, []*wire.MsgTx{tx1, spend(z, 2)})
	if _, err := idx.AddHeader(b2.Header, true); err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}

	dumpPath := filepath.Join(t.TempDir(), "utxo.dat")
	pdb.arm(storage.MakeUTXOKey(z))
	connErr := make(chan error, 1)
	go func() { connErr <- cm.ConnectBlock(b2) }()
	select {
	case <-pdb.readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("ConnectBlock never reached its second input")
	}

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		if _, rerr := server.handleDumpTxOutSet(json.RawMessage(`["` + dumpPath + `", "latest"]`)); rerr != nil {
			t.Errorf("dumptxoutset: %+v", rerr)
		}
	}()

	tornMidConnect := false
	select {
	case <-scanDone:
		// The scan finished while ConnectBlock(b2) was parked mid-first-pass.
		x1 := wire.OutPoint{Hash: tx1.TxHash(), Index: 0}
		raw, _ := db.DB().Get(storage.CoinsTipKey)
		cs, _ := storage.DeserializeChainState(raw)
		if !utxo.HasUTXODurable(x) || utxo.HasUTXODurable(x1) {
			tornMidConnect = true
			t.Errorf("TORN FLUSH mid-ConnectBlock: durable coins marker names h=%d, but b2's spend of X is durable=%v and b2's output is durable=%v",
				cs.BestHeight, !utxo.HasUTXODurable(x), utxo.HasUTXODurable(x1))
		}
	case <-time.After(2 * time.Second):
		// Blocked on the chain lock, as in Core.
	}

	close(pdb.release)
	select {
	case err := <-connErr:
		if err == nil {
			t.Fatal("b2 (spends an OP_0 coin) connected")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ConnectBlock never returned")
	}
	select {
	case <-scanDone:
	case <-time.After(10 * time.Second):
		t.Fatal("dumptxoutset never returned after the block finished")
	}

	if !tornMidConnect {
		x1 := wire.OutPoint{Hash: tx1.TxHash(), Index: 0}
		if !utxo.HasUTXODurable(x) || !utxo.HasUTXODurable(z) || utxo.HasUTXODurable(x1) {
			t.Errorf("durable set after rejected b2: X=%v Z=%v b2-output=%v, want true/true/false",
				utxo.HasUTXODurable(x), utxo.HasUTXODurable(z), utxo.HasUTXODurable(x1))
		}
	}
}
