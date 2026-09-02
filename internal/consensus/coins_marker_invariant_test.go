package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// THE INVARIANT PINNED BY THIS FILE
//
// The durable coins marker (storage.CoinsTipKey — Core's DB_BEST_BLOCK) must
// never name a height LOWER than what the persisted coin set actually
// reflects, and must never name a block the set does not reflect.
//
// A marker that is too HIGH is silent corruption: recovery skips work that was
// never done. A marker that is too LOW is ALSO corruption here, because the
// next boot re-applies blocks the set already contains — and a coinbase-only
// block among them has no inputs to trip over, so it is re-applied in full and
// its coinbase output is re-added even when a later block already spent it.
// That is the live 2026-08-15 signature (166,180,925 -> 166,180,926).
//
// Core cannot reach either state: Chainstate::LoadChainTip takes the tip FROM
// coins_cache.GetBestBlock() (bitcoin-core/src/validation.cpp:4546) and the
// only forward roll is ReplayBlocks (validation.cpp:4773), which runs strictly
// inside the window recorded by an interrupted flush.

// markerProbeChain builds a mainnet-shaped chain (BIP-34 provably active, so
// BIP-30 short-circuits and cannot mask a resurrection). Block `victimH` is
// coinbase-only; block `total` spends its coinbase. It then simulates the
// crash: the coins are durable through `total` but the chain-tip POINTER is
// left at genesis.
//
// Returns the DB, the victim outpoint, the pre-crash set hash + coin count,
// and the height->hash rows so a test can tear and restore them.
func markerProbeChain(t *testing.T, victimH, total int) (*storage.ChainDB, wire.OutPoint, wire.Hash256, uint64, map[int]wire.Hash256) {
	t.Helper()
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base

	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	rows := map[int]wire.Hash256{}
	prev := idx.Genesis()
	var victim wire.OutPoint
	connect := func(b *wire.MsgBlock, h int) {
		t.Helper()
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		rows[h] = b.Header.BlockHash()
		prev = idx.GetNode(b.Header.BlockHash())
	}
	for h := 1; h < total; h++ {
		b := createTestBlock(t, params, prev, nil)
		connect(b, h)
		if h == victimH {
			victim = wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0}
		}
	}
	spend := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: victim, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	}
	connect(createTestBlock(t, params, prev, []*wire.MsgTx{spend}), total)

	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if utxoSet.HasUTXODurable(victim) {
		t.Fatalf("precondition: victim must be spent on disk")
	}
	wantHash, wantCoins, err := ComputeHashSerialized(utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	// The crash: coins durable through `total`, tip pointer at genesis.
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: idx.Genesis().Hash, BestHeight: 0}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	return chainDB, victim, wantHash, wantCoins, rows
}

// markerProbeReboot models a cold boot over an existing datadir: a fresh header
// index, a fresh UTXO view, a fresh ChainManager, then crash recovery.
func markerProbeReboot(t *testing.T, chainDB *storage.ChainDB) (*ChainManager, *UTXOSet) {
	t.Helper()
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	idx := NewHeaderIndex(params)
	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)
	if _, err := cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	return cm, u
}

// TestBoot_SeedsAppliedTipFromDurableCoinsMarker pins finding #3, the root
// enabler: the in-memory applied tip must be seeded from the on-disk coins
// marker at construction, the way Core's Chainstate::LoadChainTip takes the tip
// from coins_cache.GetBestBlock() (validation.cpp:4546). Until the view knows
// what disk already reflects, every later flush republishes whatever the first
// thing to touch the marker happened to write.
func TestBoot_SeedsAppliedTipFromDurableCoinsMarker(t *testing.T) {
	const victimH, total = 20, 121
	chainDB, _, _, _, _ := markerProbeChain(t, victimH, total)

	want, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip: %v", err)
	}
	if want.BestHeight != int32(total) {
		t.Fatalf("precondition: durable marker = %d, want %d", want.BestHeight, total)
	}

	params := RegtestParams()
	idx := NewHeaderIndex(params)
	u := NewUTXOSet(chainDB)
	_ = NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: u,
	})

	gotHash, gotHeight, set := u.AppliedTip()
	if !set {
		t.Fatalf("the fresh UTXO view has NO applied tip, but the coins marker on disk "+
			"says the persisted set reflects %s@%d — the view will publish whatever the "+
			"first mutation writes, below the coins it describes",
			want.BestHash.String()[:16], want.BestHeight)
	}
	if gotHeight != want.BestHeight || gotHash != want.BestHash {
		t.Errorf("applied tip seeded to %s@%d, want the durable marker %s@%d",
			gotHash.String()[:16], gotHeight, want.BestHash.String()[:16], want.BestHeight)
	}
}

// TestRecovery_MarkerNeverRegressesOnHaltedReplay pins finding #1 (promoted
// from the reviewer's TestProbeA_MarkerRegressesOnHaltedRecovery).
//
// Recovery halts partway — a torn height row stops the replay at height 10 —
// while the on-disk coin set is durable through 121. The post-replay flush must
// NOT publish the marker down to the halt height.
func TestRecovery_MarkerNeverRegressesOnHaltedReplay(t *testing.T) {
	const victimH, total, halt = 20, 121, 10
	chainDB, victim, _, _, _ := markerProbeChain(t, victimH, total)

	before, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip pre: %v", err)
	}
	t.Logf("PRE-BOOT  coins marker = %d (on-disk set reflects height %d)", before.BestHeight, total)

	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(halt))); err != nil {
		t.Fatalf("tear row: %v", err)
	}
	cm, u := markerProbeReboot(t, chainDB)
	_, h := cm.BestBlock()
	after, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip post: %v", err)
	}
	t.Logf("POST-BOOT tip=%d  coins marker = %d  victimOnDisk=%v", h, after.BestHeight, u.HasUTXODurable(victim))
	if after.BestHeight < before.BestHeight {
		t.Errorf("MARKER REGRESSED %d -> %d while the on-disk set still reflects height %d",
			before.BestHeight, after.BestHeight, total)
	}
}

// TestRecovery_NoResurrectionOnSecondBootAfterHaltedReplay pins the CONSEQUENCE
// of finding #1 (promoted from the reviewer's
// TestProbeB_ResurrectionOnSecondBoot).
//
// Boot 1 halts below the marker. If it published the marker down to its halt
// height, boot 2 re-connects blocks the set already reflects — and the
// coinbase-only block among them re-adds a coinbase that block 121 already
// spent. The assertion is on the SET, not on a log line: the victim outpoint
// must still be absent from disk and the coin count unchanged.
func TestRecovery_NoResurrectionOnSecondBootAfterHaltedReplay(t *testing.T) {
	const victimH, total, halt1, halt2 = 20, 121, 10, 30
	chainDB, victim, wantHash, wantCoins, rows := markerProbeChain(t, victimH, total)

	// Boot 1: torn height row at halt1.
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(halt1))); err != nil {
		t.Fatalf("tear row1: %v", err)
	}
	cm1, u1 := markerProbeReboot(t, chainDB)
	_, h1 := cm1.BestBlock()
	m1, _ := chainDB.GetCoinsTip()
	t.Logf("BOOT1 tip=%d marker=%d victimOnDisk=%v", h1, m1.BestHeight, u1.HasUTXODurable(victim))

	// Operator/self-heal restores the torn row (or it was a transient read).
	if err := chainDB.SetBlockHeight(int32(halt1), rows[halt1]); err != nil {
		t.Fatalf("restore row1: %v", err)
	}
	// A second torn row above the victim, below the spender.
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(halt2))); err != nil {
		t.Fatalf("tear row2: %v", err)
	}

	cm2, u2 := markerProbeReboot(t, chainDB)
	_, h2 := cm2.BestBlock()
	if err := u2.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	gotHash, gotCoins, err := ComputeHashSerialized(u2)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	t.Logf("BOOT2 tip=%d victimOnDisk=%v coins %d -> %d", h2, u2.HasUTXODurable(victim), wantCoins, gotCoins)
	if u2.HasUTXODurable(victim) {
		t.Errorf("RESURRECTED: %v is unspent on disk again (coins %d -> %d, hash %s -> %s)",
			victim, wantCoins, gotCoins, wantHash.String()[:16], gotHash.String()[:16])
	}
	if gotCoins != wantCoins || gotHash != wantHash {
		t.Errorf("coin set changed across recovery: %d/%s -> %d/%s",
			wantCoins, wantHash.String()[:16], gotCoins, gotHash.String()[:16])
	}
}

// TestAdvanceAppliedTip_RefusesToLower pins the mechanism finding #1 turns on:
// the forward paths may only ever RAISE the marker.
func TestAdvanceAppliedTip_RefusesToLower(t *testing.T) {
	u := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	high := wire.Hash256{0xaa}
	low := wire.Hash256{0xbb}

	u.SetAppliedTip(high, 121)
	if u.AdvanceAppliedTip(low, 9) {
		t.Errorf("AdvanceAppliedTip lowered the marker 121 -> 9")
	}
	gotHash, gotHeight, _ := u.AppliedTip()
	if gotHeight != 121 || gotHash != high {
		t.Errorf("marker moved to %s@%d after a refused advance; want %s@121",
			gotHash.String()[:16], gotHeight, high.String()[:16])
	}
	if !u.AdvanceAppliedTip(low, 122) {
		t.Errorf("AdvanceAppliedTip refused a genuine raise 121 -> 122")
	}
}

// TestAdoptFlushedBlock_RefusesInvalidBlock pins finding #6.
//
// A standalone DisconnectBlock (the invalidateblock RPC) drops the chain-tip
// pointer below a block whose coins are still on disk without flushing the undo
// into that write, so recovery legitimately meets a coins marker that covers a
// deliberately-disconnected block. Walking the tip back over it — and stamping
// it StatusFullyValid on the way — would silently un-invalidate it. Core
// excludes invalid nodes from chain selection outright.
func TestAdoptFlushedBlock_RefusesInvalidBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	prev := idx.Genesis()
	var blocks []*wire.MsgBlock
	for h := 1; h <= 5; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		blocks = append(blocks, b)
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// invalidateblock-shaped state: the tip pointer is back at 4 while the
	// coins marker still covers 5, and block 5 is marked invalid.
	top := blocks[4]
	topNode := idx.GetNode(top.Header.BlockHash())
	parent := topNode.Parent
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: parent.Hash, BestHeight: parent.Height}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	cm2 := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: NewUTXOSet(chainDB),
	})
	cm2.SetIBD(false)
	if _, h := cm2.BestBlock(); h != parent.Height {
		t.Fatalf("precondition: rebooted tip = %d, want %d", h, parent.Height)
	}
	// invalidateblock clears the validity bit and sets the invalid one; do the
	// same so the re-stamp assertion below is meaningful.
	topNode.Status &^= StatusFullyValid
	topNode.Status |= StatusInvalid

	err := cm2.AdoptFlushedBlock(top)
	if err == nil {
		t.Errorf("AdoptFlushedBlock ADOPTED a block the header index marks invalid "+
			"(%s@%d) — the coins marker says the set reflects it, but it says nothing "+
			"about whether the block is wanted on the active chain",
			topNode.Hash.String()[:16], topNode.Height)
	}
	if _, h := cm2.BestBlock(); h != parent.Height {
		t.Errorf("tip advanced to %d over an invalid block; want it left at %d", h, parent.Height)
	}
	if topNode.Status&StatusFullyValid != 0 {
		t.Errorf("the invalid block was re-stamped StatusFullyValid by the adopt path")
	}
}
