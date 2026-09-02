package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── The defect these tests pin ──────────────────────────────────────────────
//
// RecoverFromPersistedBlocks used to decide "is this block already applied?"
// from the ERROR ConnectBlock returned: it connected first and only routed a
// block to the adoption path when the connect failed with "references missing
// UTXO". A coinbase-only block (nTx=1) has no inputs, so it can never produce
// that error — ConnectBlock always succeeded and re-applied the block, and
// AddUTXO put its coinbase output back even when a later block had already
// spent it. The tip and the block hash stayed correct; only the UTXO SET was
// wrong, and BIP-30 does not catch it (BIP-34 active, below the 1,983,702
// re-enforcement limit).
//
// Live signature, 2026-08-15 genesis rig: chain state at 958,000 with coins on
// disk already at 958,794; of the 794 replayed blocks exactly three did not log
// "ADOPTED already-applied" — 958187, 958693, 958762, all nTx=1 — and 958187's
// coinbase f29f7086…bea0:0 (3.125 BTC, spent long before 958,794 and absent
// from Core's C(958794)) came back. 166,180,925 -> 166,180,926; set hash
// 29692050…7af0 -> 24ec9202…7a5a.
//
// The fix is Core's: the coin database carries its own best-block marker
// written in the same batch as the coins (txdb.cpp:158-159), the chainstate
// boots at that marker (validation.cpp:4546 LoadChainTip) and only blocks
// ABOVE it are ever rolled forward (validation.cpp:4773 ReplayBlocks).
//
// EVERY assertion below is about the SET, not the tip: a tip-height check
// passes on the buggy code, which is exactly what made this silent.

// crashedChain builds a chain of `total` blocks on top of genesis where block 1
// is coinbase-only and block `total` spends block 1's coinbase (mature at
// CoinbaseMaturity = 100 confirmations), commits it all durably, and then
// rewinds ONLY the persisted chain-tip pointer to genesis — the marker-lag
// state a crash between a coin flush and a tip flush leaves behind.
//
// It returns the DB, the spent coinbase outpoint, and the correct pre-crash
// set (hash + coin count) to compare against after recovery.
func crashedChain(t *testing.T, params *ChainParams, total int) (*storage.ChainDB, wire.OutPoint, wire.Hash256, uint64) {
	t.Helper()
	if total <= CoinbaseMaturity {
		t.Fatalf("total=%d must exceed CoinbaseMaturity=%d for the spend to be legal", total, CoinbaseMaturity)
	}

	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	connect := func(b *wire.MsgBlock) {
		t.Helper()
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock: %v", err)
		}
	}

	// Block 1: coinbase-only. This is the block the buggy recovery re-applies.
	prev := idx.Genesis()
	b1 := createTestBlock(t, params, prev, nil)
	connect(b1)
	prev = idx.GetNode(b1.Header.BlockHash())
	victim := wire.OutPoint{Hash: b1.Transactions[0].TxHash(), Index: 0}

	// Filler, also coinbase-only.
	for h := 2; h < total; h++ {
		b := createTestBlock(t, params, prev, nil)
		connect(b)
		prev = idx.GetNode(b.Header.BlockHash())
	}

	// Final block spends block 1's coinbase.
	spend := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: victim, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	}
	connect(createTestBlock(t, params, prev, []*wire.MsgTx{spend}))

	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if utxoSet.HasUTXODurable(victim) {
		t.Fatalf("precondition: %v must be spent on disk before the simulated crash", victim)
	}
	wantHash, wantCoins, err := ComputeHashSerialized(utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}

	// The crash: coins are durable through `total`, the tip pointer is not.
	if err := chainDB.SetChainState(&storage.ChainState{
		BestHash: idx.Genesis().Hash, BestHeight: 0,
	}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	return chainDB, victim, wantHash, wantCoins
}

// reboot builds a fresh ChainManager over an existing DB (empty caches, empty
// header index) and runs crash recovery, exactly as a restart would.
func reboot(t *testing.T, params *ChainParams, chainDB *storage.ChainDB) (*ChainManager, *UTXOSet) {
	t.Helper()
	idx := NewHeaderIndex(params)
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)
	if _, err := cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	return cm, utxoSet
}

func assertSetUnchanged(t *testing.T, utxoSet *UTXOSet, victim wire.OutPoint, wantHash wire.Hash256, wantCoins uint64) {
	t.Helper()
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if utxoSet.HasUTXODurable(victim) {
		t.Errorf("recovery RESURRECTED a spent coinbase: %v is unspent on disk again. "+
			"Its block is coinbase-only, so ConnectBlock could not fail with "+
			"\"references missing UTXO\" and the block was re-applied.", victim)
	}
	gotHash, gotCoins, err := ComputeHashSerialized(utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	if gotCoins != wantCoins || gotHash != wantHash {
		t.Errorf("UTXO set changed across recovery: coins %d -> %d, hash %s -> %s "+
			"(recovery must reproduce the pre-crash set exactly)",
			wantCoins, gotCoins, wantHash.String(), gotHash.String())
	}
}

// TestRecoveryDoesNotResurrectSpentCoinbase is the pin.
//
// Block 1 is coinbase-only and sits above the persisted chain-tip pointer; its
// coinbase is spent by block 101, also above the pointer. Both are already in
// the persisted UTXO set. Recovery must reproduce that set exactly.
//
// Pre-fix this fails on the FIRST assertion — block 1 is re-applied, its
// coinbase is back on disk, and the set hash no longer matches. (Pre-fix the
// re-application also makes block 2 trip BIP-30 against its own already-present
// coinbase output, which halts the replay and makes the phantom permanent; the
// tip check below is deliberately last, because a tip-only test is what let the
// live incident through.)
func TestRecoveryDoesNotResurrectSpentCoinbase(t *testing.T) {
	params := RegtestParams()
	const total = CoinbaseMaturity + 1

	chainDB, victim, wantHash, wantCoins := crashedChain(t, params, total)
	cm, utxoSet := reboot(t, params, chainDB)

	assertSetUnchanged(t, utxoSet, victim, wantHash, wantCoins)

	if _, h := cm.BestBlock(); h != int32(total) {
		t.Errorf("recovered tip height = %d, want %d", h, total)
	}
}

// TestRecoveryDoesNotResurrectSpentCoinbaseWhenReplayHalts is the same defect in
// its MAINNET shape.
//
// Here BIP-34 is unambiguously active, so BIP-30 short-circuits and never sees
// the re-applied outputs — exactly the live 2026-08-15 configuration. The replay
// instead stops at a block whose body is missing (a torn write above the flushed
// marker), which is the supported early-exit in the loop. Recovery then flushes
// and commits its chain-tip pointer, so anything the replay conjured up to that
// point becomes durable under a correct-looking tip.
//
// The block that would have re-spent the resurrected coinbase is on the far side
// of the halt. That is the point: the buggy code's correctness depended on a
// LATER block cleaning up after it.
func TestRecoveryDoesNotResurrectSpentCoinbaseWhenReplayHalts(t *testing.T) {
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash // BIP-34 provably active => BIP-30 short-circuits
	params := &base
	const total = CoinbaseMaturity + 1
	const halt = 40 // between the coinbase-only block 1 and its spender at `total`

	chainDB, victim, wantHash, wantCoins := crashedChain(t, params, total)

	// Tear the height row at `halt`, so the forward walk stops there.
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(halt)); err != nil {
		t.Fatalf("Delete height row: %v", err)
	}

	_, utxoSet := reboot(t, params, chainDB)
	assertSetUnchanged(t, utxoSet, victim, wantHash, wantCoins)
}

// TestCoinsMarkerRidesTheCoinFlush pins the mechanism the fix rests on: the
// on-disk coins marker is written by the coin flush itself, so it always
// describes the set that is actually on disk. Core: CCoinsViewDB::BatchWrite
// puts DB_BEST_BLOCK in the same CDBBatch as the coins (txdb.cpp:158-159).
func TestCoinsMarkerRidesTheCoinFlush(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	if _, err := chainDB.GetCoinsTip(); err == nil {
		t.Fatalf("a fresh datadir must report NO coins marker (absence != height 0)")
	}

	prev := idx.Genesis()
	var hashes []wire.Hash256
	for h := 1; h <= 3; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock: %v", err)
		}
		hashes = append(hashes, b.Header.BlockHash())
		prev = idx.GetNode(b.Header.BlockHash())
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	marker, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip after flush: %v", err)
	}
	if marker.BestHeight != 3 || marker.BestHash != hashes[2] {
		t.Fatalf("coins marker = %s@%d, want %s@3", marker.BestHash.String()[:16], marker.BestHeight, hashes[2].String()[:16])
	}

	// A disconnect must bring the marker DOWN with the tip, or recovery would
	// later adopt a block whose effects have been undone.
	if err := cm.DisconnectBlock(hashes[2]); err != nil {
		t.Fatalf("DisconnectBlock: %v", err)
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush after disconnect: %v", err)
	}
	marker, err = chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip after disconnect: %v", err)
	}
	if marker.BestHeight != 2 || marker.BestHash != hashes[1] {
		t.Fatalf("coins marker after disconnect = %s@%d, want %s@2",
			marker.BestHash.String()[:16], marker.BestHeight, hashes[1].String()[:16])
	}
}
