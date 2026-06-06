package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestTipConnectFlushesUTXOAtomically is a regression test for the
// chainstate-corruption wedge fixed on 2026-06-06.
//
// Bug: at tip (isIBD=false) the forward-connect path advanced the persisted
// ChainState tip pointer on EVERY block (writeChainState = !isIBD ||
// shouldFlush) but flushed the UTXO set only every flushInterval (2000)
// blocks (the old `if shouldFlush` guard around FlushBatch). So at tip the
// on-disk tip pointer ran up to ~2000 blocks AHEAD of the on-disk UTXO set.
// An unclean exit (OOM/SIGKILL — no final flushUTXOs) then left the persisted
// tip pointing past coins that only existed in the in-memory cache. On the
// next start the consistency probe reported OK and the very next block failed
// "transaction input references missing UTXO", wedging the node with the
// recurring [CHAINSTATE-CORRUPTION] banner (blockbrew mainnet h=952343 on
// 2026-06-06; 950146 / 950155 / 950304 / 952342 before it).
//
// Invariant under test: after a successful ConnectBlock at tip, every coin
// the block created must be DURABLE in the chainDB — not merely staged in the
// in-memory UTXO cache. We model the crash by constructing a SECOND,
// cache-empty UTXOSet over the SAME chainDB and asserting it can still see the
// freshly-created coinbase coin. Pre-fix this read returns nil (the coin was
// only in the cache that the crash threw away); post-fix it returns the coin.
//
// Mirrors Bitcoin Core's invariant that CoinsTip's best-block is flushed
// atomically with the coins and never trails the active tip on disk
// (validation.cpp FlushStateToDisk).
func TestTipConnectFlushesUTXOAtomically(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     chainDB,
		UTXOSet:     utxoSet,
	})

	// At tip — the regime where the bug lived. During IBD the tip pointer
	// only advances on a flush block (writeChainState == shouldFlush), so the
	// persisted tip never outruns the persisted UTXO set; the corruption is
	// specific to the post-IBD, tip-following path.
	cm.SetIBD(false)

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock at tip: %v", err)
	}

	coinbase := block.Transactions[0]
	op := wire.OutPoint{Hash: coinbase.TxHash(), Index: 0}

	// Sanity: the live (cache-backed) set sees the coin it just created.
	if utxoSet.GetUTXO(op) == nil {
		t.Fatalf("live UTXO set lost the coinbase coin %s:0 immediately after ConnectBlock",
			coinbase.TxHash().String()[:16])
	}

	// Model an unclean crash: a brand-new UTXOSet over the SAME chainDB has an
	// empty cache, so it can only return coins that were durably flushed.
	crashRecovered := NewUTXOSet(chainDB)
	if got := crashRecovered.GetUTXO(op); got == nil {
		t.Fatalf("DURABILITY REGRESSION: coinbase coin %s:0 was NOT persisted to "+
			"chainDB after an at-tip ConnectBlock — a crash here would leave the "+
			"persisted tip ahead of the UTXO set and wedge with the missing-UTXO "+
			"[CHAINSTATE-CORRUPTION] banner", coinbase.TxHash().String()[:16])
	}

	// And the persisted tip must agree with the height whose coins we just
	// proved durable: tip and UTXO are mutually consistent on disk.
	cs, err := chainDB.GetChainState()
	if err != nil {
		t.Fatalf("GetChainState: %v", err)
	}
	wantHash := block.Header.BlockHash()
	if cs.BestHash != wantHash {
		t.Errorf("persisted ChainState tip hash = %s, want %s",
			cs.BestHash.String()[:16], wantHash.String()[:16])
	}
	if cs.BestHeight != genesis.Height+1 {
		t.Errorf("persisted ChainState tip height = %d, want %d",
			cs.BestHeight, genesis.Height+1)
	}
}
