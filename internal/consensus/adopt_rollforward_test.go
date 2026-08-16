package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestAdoptRollsForwardPartiallyAppliedBlock is the regression test for the
// silent chainstate corruption shipped in v0.1.0-rc1 (commit e7d0afe).
//
// Bug: AdoptAppliedBlock repaired "marker lag" (a crash between a block's UTXO
// writes landing and its tip pointer landing) by probing for evidence that the
// block had been applied and then ONLY ADVANCING THE TIP. It never re-applied
// the block's mutations. That is correct only if the prior session committed
// the block COMPLETELY — but the whole reason the tip pointer is missing is
// that the prior session was interrupted, so a PARTIAL commit is precisely the
// expected case. Adoption then froze the partial state under a tip claiming the
// block was done, permanently.
//
// It failed silently: the chain looked healthy, the block hashes were right,
// and only the UTXO SET was wrong. Caught in the wild on 2026-08-15, when the
// genesis rig adopted its way to C(958794) and reported 166,180,926 coins
// against the pinned 166,180,925 — exactly one un-applied spend — with a
// correct best-block hash
// (receipts/T2-capture-blockbrew-20260815T125623Z.md).
//
// Fix: durable-only evidence probe + TOLERANT ROLL-FORWARD — re-apply every
// mutation (idempotent spends, deterministic overwrite adds), committed
// atomically with the tip. Core analogue: validation.cpp::RollforwardBlock.
//
// This test models the partial commit directly: it makes a block's coinbase
// output durable (so the evidence probe fires) while leaving one of the block's
// SPENDS un-applied on disk, then asserts adoption actually performs that spend
// instead of freezing it.
func TestAdoptRollsForwardPartiallyAppliedBlock(t *testing.T) {
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
	cm.SetIBD(false)

	// Block 1: plain coinbase. Connect it normally so we have a spendable coin.
	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block1.Header, true); err != nil {
		t.Fatalf("AddHeader block1: %v", err)
	}
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("ConnectBlock block1: %v", err)
	}
	cb1 := block1.Transactions[0].TxHash()
	spendMe := wire.OutPoint{Hash: cb1, Index: 0}
	if !utxoSet.HasUTXODurable(spendMe) {
		t.Fatalf("precondition: block1 coinbase should be durable after connect")
	}

	// Block 2 spends block1's coinbase. Build it but do NOT connect it — we are
	// simulating a session that got partway through applying it and died.
	node1 := idx.GetNode(block1.Header.BlockHash())
	spendTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: spendMe, Sequence: 0xFFFFFFFF},
		},
		TxOut: []*wire.TxOut{
			{Value: 1000, PkScript: []byte{0x51}},
		},
	}
	block2 := createTestBlock(t, params, node1, []*wire.MsgTx{spendTx})
	if _, err := idx.AddHeader(block2.Header, true); err != nil {
		t.Fatalf("AddHeader block2: %v", err)
	}

	// ---- Model the PARTIAL commit -------------------------------------------
	// The prior session created block2's coinbase output (durable) but its
	// spend of block1's coinbase never made it to disk. This is exactly the
	// torn state adoption is supposed to repair.
	cb2 := block2.Transactions[0].TxHash()
	partialBatch := chainDB.NewBatch()
	partialBatch.Put(
		storage.MakeUTXOKey(wire.OutPoint{Hash: cb2, Index: 0}),
		SerializeUTXOEntry(&UTXOEntry{
			Amount:     block2.Transactions[0].TxOut[0].Value,
			PkScript:   block2.Transactions[0].TxOut[0].PkScript,
			Height:     node1.Height + 1,
			IsCoinbase: true,
		}))
	if err := partialBatch.Write(); err != nil {
		t.Fatalf("staging partial commit: %v", err)
	}
	// The spent coin is still on disk — the un-applied mutation.
	if !utxoSet.HasUTXODurable(spendMe) {
		t.Fatalf("precondition: the un-applied spend's coin should still be durable")
	}

	// ---- Adopt --------------------------------------------------------------
	if err := cm.AdoptAppliedBlock(block2); err != nil {
		t.Fatalf("AdoptAppliedBlock: %v", err)
	}

	// Tip advanced.
	if got := cm.TipNode().Height; got != node1.Height+1 {
		t.Fatalf("tip height = %d, want %d", got, node1.Height+1)
	}

	// THE ASSERTION THE OLD CODE FAILED: the un-applied spend must now be
	// applied and DURABLE. Pre-fix this coin survives forever and the UTXO set
	// carries one coin too many — the live C(958794) +1 signature.
	if utxoSet.HasUTXODurable(spendMe) {
		t.Errorf("adoption left an un-applied spend on disk: %v is still unspent "+
			"(this is the shipped-rc1 corruption: tip advanced, mutations skipped)", spendMe)
	}
}

// TestAdoptRefusesWithoutDurableEvidence pins the fail-closed direction: a
// block with no durable trace must NOT be adopted, so genuine corruption or a
// genuinely un-applied block keeps the ordinary loud reject path.
func TestAdoptRefusesWithoutDurableEvidence(t *testing.T) {
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
	cm.SetIBD(false)

	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// Never applied, nothing durable.
	if err := cm.AdoptAppliedBlock(block1); err != ErrNoAdoptionEvidence {
		t.Fatalf("AdoptAppliedBlock = %v, want ErrNoAdoptionEvidence", err)
	}
	if cm.TipNode().Height != genesis.Height {
		t.Fatalf("tip moved on a refused adoption: %d", cm.TipNode().Height)
	}
}

// TestAdoptIgnoresCacheOnlyResidue pins the probe's durability requirement.
// The original probe read through GetUTXO, which consults the in-memory cache
// — so it could "prove" a block was applied using residue from the CURRENT
// session's own failed attempt. Evidence must come from disk alone.
func TestAdoptIgnoresCacheOnlyResidue(t *testing.T) {
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
	cm.SetIBD(false)

	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// Plant the block's coinbase output in the CACHE only — never flushed.
	cb := block1.Transactions[0].TxHash()
	utxoSet.AddUTXO(wire.OutPoint{Hash: cb, Index: 0}, &UTXOEntry{
		Amount:     block1.Transactions[0].TxOut[0].Value,
		PkScript:   block1.Transactions[0].TxOut[0].PkScript,
		Height:     genesis.Height + 1,
		IsCoinbase: true,
	})

	// Cache-visible, disk-invisible.
	if utxoSet.GetUTXO(wire.OutPoint{Hash: cb, Index: 0}) == nil {
		t.Fatalf("precondition: entry should be visible through the cache")
	}
	if utxoSet.HasUTXODurable(wire.OutPoint{Hash: cb, Index: 0}) {
		t.Fatalf("precondition: entry must NOT be durable")
	}

	if err := cm.AdoptAppliedBlock(block1); err != ErrNoAdoptionEvidence {
		t.Fatalf("AdoptAppliedBlock = %v, want ErrNoAdoptionEvidence "+
			"(cache residue is not evidence)", err)
	}
}
