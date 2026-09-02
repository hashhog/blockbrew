package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// THE INVARIANT PINNED BY THIS FILE (round 4)
//
// Round 3 installed a raise-only FLOOR so that failing closed on an
// interrupted flush no longer switched off the coins marker's monotonicity
// guard. It then let SetAppliedTip RESET that floor to the restated height,
// on the reasoning that DisconnectBlock and ReorgTo's rollback genuinely
// remove coins and so must not be blocked by a stale-high bound.
//
// That reasoning conflates two different quantities:
//
//   - the APPLIED TIP names the block the IN-MEMORY view reflects. A
//     disconnect legitimately lowers it: the undo removed those coins from
//     the view.
//   - the FLOOR bounds what the PERSISTED set on disk may already reflect.
//     Removing coins from the in-memory view changes nothing on disk. The
//     floor may therefore fall only when a flush has actually made the lower
//     state durable — never at the moment of a disconnect.
//
// Resetting on restatement re-opened the exact regression the floor exists
// for, in the exact state it exists for (TestDisconnectAfterFailClosedBoot_*
// below). Both directions are pinned here: the floor must not fall on a
// disconnect, and it must not be frozen either — a completed flush that
// publishes a marker at or above it subsumes it, or the marker would be
// stranded ABOVE the view and the next boot would skip blocks whose coins
// have genuinely been undone.
//
// Core does not need any of this because it REPAIRS the recorded window
// before LoadChainTip is ever allowed to read the marker: DB_HEAD_BLOCKS is
// written before the first batch and erased with DB_BEST_BLOCK in the last
// (txdb.cpp:127-129, :157-159), and ReplayBlocks rolls forward to
// hashHeads[0] before Chainstate::LoadChainTip takes the tip from
// coins_cache.GetBestBlock() (validation.cpp:4546). blockbrew bounds instead
// of repairing, so the bound has to survive exactly the operations that do
// not touch disk.

// floorProbeBoot opens a fresh ChainManager over an existing datadir with the
// chain-state pointer forced to `tip`. The header index is left unhydrated:
// these probes are about what the view knows the moment the marker is
// refused, not about the recovery walk.
func floorProbeBoot(t *testing.T, chainDB *storage.ChainDB, rows map[int]wire.Hash256, tip int) (*ChainManager, *UTXOSet) {
	t.Helper()
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: rows[tip], BestHeight: int32(tip)}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: NewHeaderIndex(params), ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)
	return cm, u
}

// floorProbeBootNatural boots WITHOUT rewriting the chain-state pointer, so
// recovery performs its real walk and halts at the hole — the state that
// actually republishes the marker.
func floorProbeBootNatural(t *testing.T, chainDB *storage.ChainDB) (*ChainManager, *UTXOSet) {
	t.Helper()
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: NewHeaderIndex(params), ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)
	return cm, u
}

// recordInterruptedFlush writes the interrupted-flush window (Core's
// DB_HEAD_BLOCKS, txdb.cpp:127-129) that makes the boot fail closed, with REAL
// heights at both ends.
func recordInterruptedFlush(t *testing.T, chainDB *storage.ChainDB, rows map[int]wire.Hash256, from, to int) {
	t.Helper()
	rec := append(
		(&storage.ChainState{BestHash: rows[from], BestHeight: int32(from)}).Serialize(),
		(&storage.ChainState{BestHash: rows[to], BestHeight: int32(to)}).Serialize()...)
	if err := chainDB.DB().Put(storage.CoinsFlushKey, rec); err != nil {
		t.Fatalf("Put(CoinsFlushKey): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Direction 1: the floor must NOT fall at the moment of a disconnect.
// ---------------------------------------------------------------------------

// TestDisconnectAfterFailClosedBoot_MarkerMustNotRegress is the acceptance
// criterion for this round. It is the reviewer's REV-3 probe, promoted.
//
// ASSERTION: THE ON-DISK MARKER. After a fail-closed boot (a real interrupted
// flush window 100->121 recorded, plus an ordinary hole in the height map at
// 50) recovery halts at tip 49 with the floor correctly installed at 121. One
// cm.DisconnectBlock — reachable in production straight from the
// invalidateblock RPC (internal/rpc/methods.go ChainManager.InvalidateBlock ->
// DisconnectBlock) and from VerifyChainstate — restated the view to 48 AND
// reset the floor to 48, and the next flush published a marker of 48 over a
// set the recorded window says may reflect up to 121. The next boot then
// re-applies 49..121 and a coinbase-only block among them puts back a coin a
// later block already spent.
//
// The tip is never the thing asserted: 48 is a perfectly correct tip here.
// Only the marker lies.
func TestDisconnectAfterFailClosedBoot_MarkerMustNotRegress(t *testing.T) {
	const victimH, total, holeH = 20, 121, 50
	chainDB, _, _, _, rows := markerProbeChain(t, victimH, total)

	recordInterruptedFlush(t, chainDB, rows, 100, total)
	if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(holeH))); err != nil {
		t.Fatalf("delete height row: %v", err)
	}

	cm, u := floorProbeBootNatural(t, chainDB)
	if _, _, ok := cm.DurableCoinsTip(); ok {
		t.Fatalf("precondition: the marker must be REFUSED while an interrupted flush " +
			"is recorded")
	}
	if _, err := cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	floorBefore, haveFloor := u.AppliedFloor()
	_, haltHeight := cm.BestBlock()
	if !haveFloor || floorBefore < int32(total) {
		t.Fatalf("precondition: the fail-closed boot must install a floor of %d, got %d (set=%v)",
			total, floorBefore, haveFloor)
	}
	before, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip pre: %v", err)
	}

	tipHash, _ := cm.BestBlock()
	if err := cm.DisconnectBlock(tipHash); err != nil {
		t.Fatalf("DisconnectBlock: %v", err)
	}
	floorAfter, _ := u.AppliedFloor()
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	after, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip post: %v", err)
	}
	_, viewHeight := cm.BestBlock()
	t.Logf("halt=%d floor %d -> %d, view=%d, marker %d -> %d",
		haltHeight, floorBefore, floorAfter, viewHeight, before.BestHeight, after.BestHeight)

	if floorAfter < floorBefore {
		t.Errorf("A DISCONNECT LOWERED THE FLOOR %d -> %d. The undo removed coins from "+
			"the in-memory VIEW; not one byte of the persisted set changed, and the "+
			"recorded flush window still says it may reflect up to %d",
			floorBefore, floorAfter, total)
	}
	if after.BestHeight < before.BestHeight {
		t.Errorf("THE COINS MARKER REGRESSED %d -> %d after a single DisconnectBlock on a "+
			"fail-closed boot. The persisted set may reflect up to %d, so the next boot "+
			"re-applies that span and resurrects a spent coinbase",
			before.BestHeight, after.BestHeight, total)
	}
	if after.BestHeight < int32(total) {
		t.Errorf("the published marker %d is BELOW the recorded flush window high end %d — "+
			"it claims less than the set may already hold", after.BestHeight, total)
	}
}

// ---------------------------------------------------------------------------
// The window-derived half of durableCoinsFloor, finally exercised.
// ---------------------------------------------------------------------------

// TestWindowOnlyFloor_GuardsWithNoMarkerAtAll is the reviewer's REV-1 probe,
// promoted. The round-3 pin
// (TestFailClosedMarker_DoesNotDisableTheRaiseOnlyGuard) writes its
// interrupted-flush record as two ZERO-value ChainStates, so both window ends
// contribute height 0 and its floor of 121 comes entirely from the
// GetCoinsTip() branch of durableCoinsFloor. The window-derived half — the
// half that matters precisely when the marker itself is absent — was never
// exercised by the committed suite.
//
// Here CoinsTipKey is DELETED outright, so the marker reads absent in the
// strictest sense and the floor can only come from the recorded window.
func TestWindowOnlyFloor_GuardsWithNoMarkerAtAll(t *testing.T) {
	const victimH, total = 20, 121
	chainDB, _, _, _, rows := markerProbeChain(t, victimH, total)

	recordInterruptedFlush(t, chainDB, rows, 100, total)
	if err := chainDB.DB().Delete(storage.CoinsTipKey); err != nil {
		t.Fatalf("Delete(CoinsTipKey): %v", err)
	}

	cm, u := floorProbeBoot(t, chainDB, rows, 49)
	if _, _, ok := cm.DurableCoinsTip(); ok {
		t.Fatalf("precondition: the marker must be refused")
	}
	if _, _, set := u.AppliedTip(); set {
		t.Fatalf("precondition: no NAMED applied tip may be seeded")
	}

	floor, have := u.AppliedFloor()
	t.Logf("window-only floor = %d (set=%v)", floor, have)
	if !have || floor < int32(total) {
		t.Errorf("WINDOW-ONLY FLOOR MISSING: floor=%d set=%v. There is no marker on disk "+
			"at all; the recorded flush window is the only evidence, and it says the "+
			"persisted set may reflect up to %d", floor, have, total)
	}
	for _, h := range []int32{1, 49, 100, 120, int32(total)} {
		if u.AdvanceAppliedTip(wire.Hash256{byte(h)}, h) {
			t.Errorf("MARKER MAY REGRESS: AdvanceAppliedTip published %d over a set the "+
				"window says may already reflect %d", h, total)
		}
	}
	if !u.AdvanceAppliedTip(rows[total], int32(total)+1) {
		t.Errorf("the floor blocked a genuine raise to %d — forward progress is wedged",
			total+1)
	}
}

// ---------------------------------------------------------------------------
// Direction 2: the floor must not be FROZEN either.
// ---------------------------------------------------------------------------

// TestFloorSubsumedByFlush_LegitimateDisconnectStillPublishesItsMarker pins the
// other direction, so a future author cannot "close" the hole above by simply
// never lowering the floor.
//
// ASSERTION: THE ON-DISK MARKER. The node boots fail-closed with a floor of
// 121, then makes genuine forward progress: it connects 122 and 123 and
// flushes, which publishes a marker of 123 — at which point the floor's weaker
// bound is subsumed by the marker and must be dropped. A later legitimate
// reorg peels 123, 122 and 121 back off and flushes; those coin removals are
// now durable, so the marker MUST follow the view down to 120.
//
// A floor frozen at 121 refuses to publish 120, the on-disk marker stays at
// 123, and the next boot adopts three blocks whose coins have been undone —
// the same corruption as the hole above, reached from the other side. That is
// the failure this test exists to prevent, and it is exactly the concern that
// motivated the reset this round removed.
func TestFloorSubsumedByFlush_LegitimateDisconnectStillPublishesItsMarker(t *testing.T) {
	const victimH, total = 20, 121
	chainDB, victim, _, _, rows := markerProbeChain(t, victimH, total)
	recordInterruptedFlush(t, chainDB, rows, 100, total)

	// Boot fail-closed with the chain-state pointer at the real tip and the
	// header index hydrated, so nothing is re-applied and the node is simply
	// live at 121 with a floor it cannot yet publish under.
	base := *RegtestParams()
	base.BIP34Hash = base.GenesisHash
	params := &base
	idx := NewHeaderIndex(params)
	for h := 1; h <= total; h++ {
		b, err := chainDB.GetBlock(rows[h])
		if err != nil || b == nil {
			t.Fatalf("GetBlock h=%d: %v", h, err)
		}
		if _, err := idx.AddHeader(b.Header, true); err != nil && err != ErrDuplicateHeader {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: rows[total], BestHeight: int32(total)}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	u := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: u,
	})
	cm.SetIBD(false)
	if f, ok := u.AppliedFloor(); !ok || f != int32(total) {
		t.Fatalf("precondition: the fail-closed boot must install a floor of %d, got %d (set=%v)",
			total, f, ok)
	}

	// Genuine forward progress ABOVE the floor: 122 and 123.
	prev := idx.GetNode(rows[total])
	if prev == nil {
		t.Fatalf("precondition: tip node %d missing from the index", total)
	}
	var extra []wire.Hash256
	for h := total + 1; h <= total+2; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		hash := b.Header.BlockHash()
		extra = append(extra, hash)
		prev = idx.GetNode(hash)
	}
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush after forward progress: %v", err)
	}
	published, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip after forward progress: %v", err)
	}
	if published.BestHeight != int32(total+2) {
		t.Fatalf("precondition: genuine progress above the floor must publish %d, got %d",
			total+2, published.BestHeight)
	}
	if f, ok := u.AppliedFloor(); ok && f > int32(total+2) {
		t.Fatalf("precondition: the floor should be subsumed or below the marker, got %d", f)
	}

	// A legitimate reorg peels 123, 122 and 121 back off.
	for i := len(extra) - 1; i >= 0; i-- {
		if err := cm.DisconnectBlock(extra[i]); err != nil {
			t.Fatalf("DisconnectBlock %d: %v", total+1+i, err)
		}
	}
	if err := cm.DisconnectBlock(rows[total]); err != nil {
		t.Fatalf("DisconnectBlock %d: %v", total, err)
	}
	_, viewHeight := cm.BestBlock()
	if viewHeight != int32(total-1) {
		t.Fatalf("precondition: the view should sit at %d after three disconnects, got %d",
			total-1, viewHeight)
	}
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush after the disconnects: %v", err)
	}

	after, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip post: %v", err)
	}
	floorAfter, floorSet := u.AppliedFloor()
	t.Logf("view=%d marker=%d floor=%d (set=%v)", viewHeight, after.BestHeight, floorAfter, floorSet)
	if after.BestHeight != viewHeight {
		t.Errorf("THE COINS MARKER IS STRANDED AT %d while the view — and, after that "+
			"flush, the persisted set — is at %d. A floor that can never fall refuses "+
			"the true marker after a legitimate reorg, and the next boot adopts blocks "+
			"whose coins have been undone", after.BestHeight, viewHeight)
	}
	// ASSERTION ON THE SET, alongside the marker: block 121 spent the
	// height-20 coinbase, and that block has now been disconnected and the
	// undo flushed, so the coin must be durably BACK. This is what makes the
	// lower marker correct rather than merely permitted — the persisted set
	// really is at 120.
	if !u.HasUTXODurable(victim) {
		t.Errorf("the disconnect of block %d was flushed, but its spend of the height-%d "+
			"coinbase is still durable: the persisted set does not match the marker "+
			"the flush published", total, victimH)
	}
}
