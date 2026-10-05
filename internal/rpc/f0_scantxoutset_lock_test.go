package rpc

// scantxoutset flushed the coin cache WITHOUT the chain lock (UTXOSet.ScanUTXOs
// takes only u.mu). ConnectBlock mutates the cache in place, input by input,
// while holding cm.mu but dropping u.mu between calls, so that flush could land
// in the middle of a block: the block's first spends and creations become
// durable under a coins marker that still names the PREVIOUS block. If that
// block then fails validation (rolled back in memory only) or the process dies
// before the next flush, the durable set holds a torn, partly-applied — possibly
// invalid — block. Core flushes for scantxoutset under cs_main
// (rpc/blockchain.cpp scantxoutset: LOCK(cs_main); ForceFlushStateToDisk();
// Cursor(); tip), which excludes ConnectBlock.
//
// Deterministic interleaving: a storage.DB wrapper parks ConnectBlock's read of
// its SECOND input (after the first input's spend is applied) while the RPC runs.

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

type parkReadDB struct {
	storage.DB
	mu       sync.Mutex
	key      []byte
	readDone chan struct{}
	release  chan struct{}
}

func (p *parkReadDB) arm(key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = append([]byte(nil), key...)
	p.readDone = make(chan struct{})
	p.release = make(chan struct{})
}

func (p *parkReadDB) Get(key []byte) ([]byte, error) {
	data, err := p.DB.Get(key)
	p.mu.Lock()
	hit := p.key != nil && bytes.Equal(key, p.key)
	var done, rel chan struct{}
	if hit {
		p.key = nil
		done, rel = p.readDone, p.release
	}
	p.mu.Unlock()
	if hit {
		close(done)
		<-rel
	}
	return data, err
}

// NewSnapshot forwards the inner store's snapshot support (production Pebble
// and MemDB both have it; embedding the interface would hide it).
func (p *parkReadDB) NewSnapshot() storage.Snapshot {
	return p.DB.(storage.Snapshotter).NewSnapshot()
}

func buildRegtestBlockWithTxs(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode, txs []*wire.MsgTx) *wire.MsgBlock {
	t.Helper()
	b := buildRegtestBlock(t, params, prev)
	b.Transactions = append(b.Transactions, txs...)
	hashes := make([]wire.Hash256, len(b.Transactions))
	for i, tx := range b.Transactions {
		hashes[i] = tx.TxHash()
	}
	b.Header.MerkleRoot = consensus.CalcMerkleRoot(hashes)
	target := consensus.CompactToBig(b.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		b.Header.Nonce = i
		if consensus.HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return b
}

func TestScanTxOutSetDoesNotFlushMidConnectBlock(t *testing.T) {
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
		if _, rerr := server.handleScanTxOutSet(json.RawMessage(`["start", ["raw(51)"]]`)); rerr != nil {
			t.Errorf("scantxoutset: %+v", rerr)
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
		t.Fatal("scantxoutset never returned after the block finished")
	}

	if !tornMidConnect {
		x1 := wire.OutPoint{Hash: tx1.TxHash(), Index: 0}
		if !utxo.HasUTXODurable(x) || !utxo.HasUTXODurable(z) || utxo.HasUTXODurable(x1) {
			t.Errorf("durable set after rejected b2: X=%v Z=%v b2-output=%v, want true/true/false",
				utxo.HasUTXODurable(x), utxo.HasUTXODurable(z), utxo.HasUTXODurable(x1))
		}
	}
}
