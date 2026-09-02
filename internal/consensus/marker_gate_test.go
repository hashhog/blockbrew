package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// THE INVARIANTS PINNED BY THIS FILE (round 3)
//
// Round 2 made the durable coins marker (storage.CoinsTipKey — Core's
// DB_BEST_BLOCK) an invariant rather than a hint. Three holes remained, each
// of the same shape: a guard that cannot fire in the state it exists for.
//
//	(a) The raise-only guard was conditional on UTXOSet.appliedSet, which
//	    seedAppliedTipFromMarker leaves FALSE on every boot where the marker
//	    is refused — so failing closed switched the guard off.
//	(b) The marker gate was wired into the P2P connect loop only; submitblock,
//	    submitblock batch, generatetoaddress and the miner connected blind.
//	(c) AdoptIfAlreadyFlushed proved "already applied" from the persisted
//	    height->hash row, and a MISSING height row is exactly what halts
//	    recovery below the marker in the first place.
//
// Every assertion below is on the SET (is a spent coinbase back?) or on the
// MARKER (did the on-disk marker regress?). A tip height stays correct-looking
// in all three failures, so it is never the thing asserted.

// markerProbeHalted models the state a HALTED recovery leaves behind: the
// chain-state pointer sits at `tip`, BELOW the coins marker, while the
// persisted coin set is durable through the marker. The header index is
// hydrated from the persisted bodies up to `hydrateTo`, which lets a test
// choose which of AdoptIfAlreadyFlushed's two proofs is even available:
// hydrating only to `tip` leaves the marker's own node out of the index, so
// the ancestry proof cannot fire and the height-map proof is on its own.
//
// It deliberately does NOT call RecoverFromPersistedBlocks: the whole premise
// of findings (b) and (c) is a boot walk that did not reach the marker.
func markerProbeHalted(
	t *testing.T,
	chainDB *storage.ChainDB,
	rows map[int]wire.Hash256,
	tip, hydrateTo int,
) (*ChainManager, *UTXOSet, *HeaderIndex, *ChainParams) {
	t.Helper()
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base

	idx := NewHeaderIndex(params)
	for h := 1; h <= hydrateTo; h++ {
		hash, ok := rows[h]
		if !ok {
			t.Fatalf("markerProbeHalted: no height row recorded for %d", h)
		}
		b, err := chainDB.GetBlock(hash)
		if err != nil || b == nil {
			t.Fatalf("markerProbeHalted: GetBlock h=%d: %v", h, err)
		}
		if _, err := idx.AddHeader(b.Header, true); err != nil && err != ErrDuplicateHeader {
			t.Fatalf("markerProbeHalted: AddHeader h=%d: %v", h, err)
		}
	}
	if err := chainDB.SetChainState(&storage.ChainState{
		BestHash: rows[tip], BestHeight: int32(tip),
	}); err != nil {
		t.Fatalf("markerProbeHalted: SetChainState: %v", err)
	}

	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)
	if _, h := cm.BestBlock(); h != int32(tip) {
		t.Fatalf("markerProbeHalted: tip resolved to %d, want %d", h, tip)
	}
	return cm, u, idx, params
}

// ---------------------------------------------------------------------------
// (a) A guard that switches itself off in its own failure case is not a guard.
// ---------------------------------------------------------------------------

// TestFailClosedMarker_DoesNotDisableTheRaiseOnlyGuard pins finding (a).
//
// ASSERTION: THE ON-DISK MARKER. With an interrupted-flush record present
// (storage.CoinsFlushKey — Core's DB_HEAD_BLOCKS, txdb.cpp:128-129) the marker
// is refused for adoption, so seedAppliedTipFromMarker cannot name the block
// the set reflects and UTXOSet.appliedSet stays false. AdvanceAppliedTip's
// raise-only test was `u.appliedSet && height <= u.appliedHeight`, which does
// not fire at all when appliedSet is false: recovery then re-connected from the
// chain pointer, halted at a hole in the height map, and the post-replay flush
// published the marker DOWN to the halt height — over a set durable through 121.
// A marker below its own coins is what makes the NEXT boot re-apply, and a
// coinbase-only block among those re-applies puts back a coin already spent.
//
// The fix does not need to name the block to keep the guard: it installs a
// raise-only FLOOR from the same on-disk evidence (durableCoinsFloor) and
// refuses to publish at or below it. Core reaches the same place by repairing
// the window instead — ReplayBlocks (validation.cpp:4773) rolls forward to
// hashHeads[0] before LoadChainTip (validation.cpp:4546) may read the marker,
// so Core never publishes a best block below the recorded window either.
//
// NOTE ON SCOPE: this boot still RE-APPLIES the blocks it walks, and the set
// it leaves behind is corrupt — that is the separately documented, deliberately
// unfixed GAP-BB-FLUSH-RACE (see flush_race_gap_test.go, probe 7D). This test
// asserts nothing about the set. It asserts only that the marker does not lie
// about it.
func TestFailClosedMarker_DoesNotDisableTheRaiseOnlyGuard(t *testing.T) {
	const victimH, total, holeH = 20, 121, 50
	chainDB, _, _, _, _ := markerProbeChain(t, victimH, total)

	before, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip pre: %v", err)
	}
	if before.BestHeight != int32(total) {
		t.Fatalf("precondition: durable marker = %d, want %d", before.BestHeight, total)
	}

	// The fail-closed trigger: an interrupted multi-batch coin flush.
	rec := append((&storage.ChainState{}).Serialize(), (&storage.ChainState{}).Serialize()...)
	if err := chainDB.DB().Put(storage.CoinsFlushKey, rec); err != nil {
		t.Fatalf("Put(CoinsFlushKey): %v", err)
	}
	// An ordinary, independent halt cause: a hole in the persisted height map.
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(holeH))); err != nil {
		t.Fatalf("delete height row: %v", err)
	}

	// Boot, but hold the assertions BEFORE recovery runs: the state under test
	// is what the view knows the moment the marker has been refused.
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	idx := NewHeaderIndex(params)
	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)

	// Preconditions: the marker really is refused, and the view really does
	// not know which block the set reflects. Without both of these the test
	// would be exercising the trusted-marker path and prove nothing.
	if _, _, ok := cm.DurableCoinsTip(); ok {
		t.Fatalf("precondition: the marker must be REFUSED while an interrupted " +
			"flush is recorded")
	}
	if _, _, set := u.AppliedTip(); set {
		t.Fatalf("precondition: a refused marker must not seed a NAMED applied tip")
	}

	floor, haveFloor := u.AppliedFloor()
	if !haveFloor || floor < before.BestHeight {
		t.Errorf("the view holds no usable floor (floor=%d set=%v) after refusing a marker "+
			"that says the persisted set reflects height %d — the raise-only guard has "+
			"nothing left to stand on and every forward path may publish below the set",
			floor, haveFloor, before.BestHeight)
	}

	if _, err := cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	after, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip post: %v", err)
	}
	_, tipH := cm.BestBlock()
	t.Logf("POST-BOOT tip=%d marker %d -> %d floor=%d", tipH, before.BestHeight, after.BestHeight, floor)
	if after.BestHeight < before.BestHeight {
		t.Errorf("THE COINS MARKER REGRESSED %d -> %d while the persisted set still "+
			"reflects height %d. Failing closed on an interrupted flush disabled the "+
			"very monotonicity guard it was supposed to protect",
			before.BestHeight, after.BestHeight, total)
	}
}

// TestAdvanceAppliedTip_FloorRefusesWithoutANamedTip is the mechanism behind
// the pin above, at unit scale: the floor must refuse a lowering even though no
// block has ever been named, and must still let a genuine raise through.
func TestAdvanceAppliedTip_FloorRefusesWithoutANamedTip(t *testing.T) {
	u := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	if !u.RaiseAppliedFloor(121) {
		t.Fatalf("RaiseAppliedFloor(121) reported no move on a fresh view")
	}
	if _, _, set := u.AppliedTip(); set {
		t.Fatalf("a floor must not fabricate a NAMED applied tip")
	}
	if u.AdvanceAppliedTip(wire.Hash256{0xbb}, 9) {
		t.Errorf("AdvanceAppliedTip published 9 over a view whose floor says the " +
			"persisted set may already reflect 121")
	}
	if _, _, set := u.AppliedTip(); set {
		t.Errorf("a refused advance still marked the view as having a published marker")
	}
	if !u.AdvanceAppliedTip(wire.Hash256{0xcc}, 122) {
		t.Errorf("the floor refused a genuine raise 121 -> 122")
	}
	// CORRECTED 2026-09-02 (see marker_floor_test.go). This assertion used to
	// read "SetAppliedTip RESETS the floor to the restated height", which is
	// the defect, not the invariant: it hands a DisconnectBlock the power to
	// switch the bound off in the one state the bound exists for. A
	// restatement lowers the IN-MEMORY applied tip, because the undo really
	// did remove those coins from the view. It changes nothing on disk, so the
	// bound on what the PERSISTED set may already reflect must stand.
	u.SetAppliedTip(wire.Hash256{0xdd}, 100)
	if _, h, set := u.AppliedTip(); !set || h != 100 {
		t.Errorf("SetAppliedTip left the applied tip at %d (set=%v); the restatement of "+
			"the in-memory view must go through", h, set)
	}
	if f, ok := u.AppliedFloor(); !ok || f != 121 {
		t.Errorf("SetAppliedTip moved the floor to %d (set=%v): a disconnect removes coins "+
			"from the VIEW, not from DISK, so the bound on what the persisted set may "+
			"already reflect must still be 121", f, ok)
	}
	// And the flush must not publish that restated marker either: 100 claims
	// less than the persisted set may already hold.
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if st, err := u.db.GetCoinsTip(); err != nil && err != storage.ErrNotFound {
		t.Fatalf("GetCoinsTip: %v", err)
	} else if st != nil {
		t.Errorf("a flush published the coins marker at height %d over a view whose floor "+
			"says the persisted set may already reflect 121", st.BestHeight)
	}
}

// ---------------------------------------------------------------------------
// (b) Every block-connecting caller must go through the same gate.
// ---------------------------------------------------------------------------

// TestSubmitBlock_GoesThroughTheMarkerGate pins finding (b).
//
// ASSERTION: THE SET. Recovery halted at height 19 while the persisted coin set
// is durable through 121. Block 20 is coinbase-only and block 121 spent its
// coinbase. A submitblock delivering block 20 extends the active tip, so
// ProcessSubmittedBlock took its happy path straight into ConnectBlock — which
// re-applied the block and re-added a coinbase that block 121 already spent.
// Nothing errors: a block with no inputs has nothing to trip over, and BIP-30
// is short-circuited because BIP-34 is provably active here.
//
// The header index is hydrated only to the halted tip, so the coins marker's
// own node is absent and AdoptIfAlreadyFlushed's ancestry proof cannot fire.
// This test therefore isolates the WIRING: the height-map proof was always
// available at height 20, and the gate simply was not on this path.
func TestSubmitBlock_GoesThroughTheMarkerGate(t *testing.T) {
	const victimH, total, haltAt = 20, 121, 19
	chainDB, victim, wantHash, wantCoins, rows := markerProbeChain(t, victimH, total)

	cm, u, idx, _ := markerProbeHalted(t, chainDB, rows, haltAt, haltAt)
	if idx.GetNode(rows[total]) != nil {
		t.Fatalf("precondition: the marker's node must be ABSENT from the header index " +
			"so the ancestry proof cannot mask a missing gate")
	}
	if u.HasUTXODurable(victim) {
		t.Fatalf("precondition: the victim coinbase must be spent on disk")
	}

	// submitblock's own preamble: the body is stored and the header indexed
	// before the block is handed to the chain manager.
	block, err := chainDB.GetBlock(rows[victimH])
	if err != nil || block == nil {
		t.Fatalf("GetBlock(%d): %v", victimH, err)
	}
	if len(block.Transactions) != 1 {
		t.Fatalf("precondition: block %d must be coinbase-only (got %d txs) — a block "+
			"with inputs would trip 'references missing UTXO' and be caught anyway",
			victimH, len(block.Transactions))
	}
	if _, err := idx.AddHeader(block.Header, true); err != nil && err != ErrDuplicateHeader {
		t.Fatalf("AddHeader: %v", err)
	}

	if err := cm.ProcessSubmittedBlock(block); err != nil {
		t.Fatalf("ProcessSubmittedBlock(%d): %v", victimH, err)
	}
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	gotHash, gotCoins, err := ComputeHashSerialized(u)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	_, tipH := cm.BestBlock()
	t.Logf("tip=%d victimOnDisk=%v coins %d -> %d", tipH, u.HasUTXODurable(victim), wantCoins, gotCoins)
	if u.HasUTXODurable(victim) {
		t.Errorf("RESURRECTED via submitblock: %v is unspent on disk again. The marker "+
			"gate was wired into the P2P connect loop only; ProcessSubmittedBlock "+
			"re-applied a block the persisted set already reflected", victim)
	}
	if gotCoins != wantCoins || gotHash != wantHash {
		t.Errorf("the coin set changed across a submitblock of an already-applied block: "+
			"%d/%s -> %d/%s", wantCoins, wantHash.String()[:16], gotCoins, gotHash.String()[:16])
	}
}

// ---------------------------------------------------------------------------
// (c) The gate's proof must work in the state that creates the need for it.
// ---------------------------------------------------------------------------

// TestMarkerGate_ProvesCoverageWhenTheHeightRowIsMissing pins finding (c).
//
// ASSERTION: THE SET. AdoptIfAlreadyFlushed proved "already applied" from
// chainDB.GetBlockHashByHeight(node.Height) and returned false when that row
// was absent — but an absent height row is precisely what makes
// RecoverFromPersistedBlocks halt below the marker (its replay loop breaks on
// the first GetBlockHashByHeight failure). The one proof the gate had could not
// fire in the one state the gate exists for, so the block was re-applied and
// the coinbase block 121 had already spent came back.
//
// The evidence that replaces it is the header index's prev-hash chain: the
// marker NAMES a block, the set reflects that block's mutations, and those are
// applied on top of every ancestor's — so an ancestor of the marker block at
// this height is covered by construction. That ancestry is cryptographic and,
// unlike a height table, cannot be rewritten by a later reorg. Core answers the
// same question the same way (CBlockIndex::GetAncestor, src/chain.cpp).
//
// The height row at 20 is deleted here, so the height-map proof is unavailable
// and only the ancestry proof can carry the test.
func TestMarkerGate_ProvesCoverageWhenTheHeightRowIsMissing(t *testing.T) {
	const victimH, total, haltAt = 20, 121, 19
	chainDB, victim, wantHash, wantCoins, rows := markerProbeChain(t, victimH, total)

	// The halt cause AND the proof-killer, one and the same row.
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(victimH))); err != nil {
		t.Fatalf("delete height row %d: %v", victimH, err)
	}

	cm, u, idx, _ := markerProbeHalted(t, chainDB, rows, haltAt, total)
	if _, err := chainDB.GetBlockHashByHeight(int32(victimH)); err == nil {
		t.Fatalf("precondition: the height row at %d must be missing", victimH)
	}
	if idx.GetNode(rows[total]) == nil {
		t.Fatalf("precondition: the marker's node must be PRESENT in the header index " +
			"for the ancestry proof to be available at all")
	}
	if _, mh, ok := cm.DurableCoinsTip(); !ok || mh != int32(total) {
		t.Fatalf("precondition: the coins marker must still be trusted at %d (got %d, ok=%v)",
			total, mh, ok)
	}
	if u.HasUTXODurable(victim) {
		t.Fatalf("precondition: the victim coinbase must be spent on disk")
	}

	block, err := chainDB.GetBlock(rows[victimH])
	if err != nil || block == nil {
		t.Fatalf("GetBlock(%d): %v", victimH, err)
	}
	if _, err := idx.AddHeader(block.Header, true); err != nil && err != ErrDuplicateHeader {
		t.Fatalf("AddHeader: %v", err)
	}

	adopted, err := cm.AdoptIfAlreadyFlushed(block)
	if err != nil {
		t.Fatalf("AdoptIfAlreadyFlushed: %v", err)
	}
	if !adopted {
		t.Errorf("the gate refused block %d, which the coins marker at %d provably covers, "+
			"because its height row is missing — the one condition that put the tip below "+
			"the marker to begin with", victimH, total)
	}

	// Whatever the gate decided, the caller connects on a refusal. Model that,
	// then assert on the SET: a gate that cannot fire is indistinguishable from
	// no gate at all, and this is what "no gate" costs.
	if !adopted {
		if err := cm.ConnectBlock(block); err != nil {
			t.Fatalf("ConnectBlock fallback: %v", err)
		}
	}
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	gotHash, gotCoins, err := ComputeHashSerialized(u)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	t.Logf("adopted=%v victimOnDisk=%v coins %d -> %d", adopted, u.HasUTXODurable(victim), wantCoins, gotCoins)
	if u.HasUTXODurable(victim) {
		t.Errorf("RESURRECTED: %v is unspent on disk again (coins %d -> %d, hash %s -> %s)",
			victim, wantCoins, gotCoins, wantHash.String()[:16], gotHash.String()[:16])
	}
	if gotCoins != wantCoins || gotHash != wantHash {
		t.Errorf("the coin set changed: %d/%s -> %d/%s",
			wantCoins, wantHash.String()[:16], gotCoins, gotHash.String()[:16])
	}
}

// TestMarkerGate_RefusesWhenTheViewHasBeenRestatedBelowTheBlock guards the
// permissive direction of the two changes above, and it is why the gate tests
// the in-memory view rather than the disk marker alone. DisconnectBlock and
// ReorgTo's rollback restate the view DOWNWARD without flushing, so between
// such a restatement and the next flush the on-disk marker is stale-HIGH: it
// still names a block whose coins the view has already undone. Now that every
// connect path runs through the gate, adopting there would skip work that was
// genuinely never done — the silent-corruption direction.
func TestMarkerGate_RefusesWhenTheViewHasBeenRestatedBelowTheBlock(t *testing.T) {
	const victimH, total, haltAt = 20, 121, 19
	chainDB, _, _, _, rows := markerProbeChain(t, victimH, total)
	cm, u, idx, _ := markerProbeHalted(t, chainDB, rows, haltAt, total)

	block, err := chainDB.GetBlock(rows[victimH])
	if err != nil || block == nil {
		t.Fatalf("GetBlock(%d): %v", victimH, err)
	}
	if _, err := idx.AddHeader(block.Header, true); err != nil && err != ErrDuplicateHeader {
		t.Fatalf("AddHeader: %v", err)
	}
	// Sanity: with the view still at the marker, the gate DOES fire.
	if adopted, err := cm.AdoptIfAlreadyFlushed(block); err != nil || !adopted {
		t.Fatalf("precondition: the gate must fire while the view is at the marker "+
			"(adopted=%v err=%v)", adopted, err)
	}

	// Now model the post-disconnect view on a FRESH boot of the same datadir:
	// the view is restated below the marker and not yet flushed.
	_ = u
	cm2, u2, idx2, _ := markerProbeHalted(t, chainDB, rows, haltAt, total)
	blk, err := chainDB.GetBlock(rows[victimH])
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	if _, err := idx2.AddHeader(blk.Header, true); err != nil && err != ErrDuplicateHeader {
		t.Fatalf("AddHeader: %v", err)
	}
	u2.SetAppliedTip(rows[10], 10)
	adopted, err := cm2.AdoptIfAlreadyFlushed(blk)
	if err != nil {
		t.Fatalf("AdoptIfAlreadyFlushed: %v", err)
	}
	if adopted {
		t.Errorf("the gate adopted block %d on a marker at %d that the view has already "+
			"superseded (view restated to 10). The block's mutations are NOT in the view "+
			"and skipping them is the silent-corruption direction", victimH, total)
	}
}
