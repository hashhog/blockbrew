package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// PruneManual is the pruneblockchain RPC's file sweep (Core
// FindFilesToPruneManual + GetPruneRange). These tests drive it directly.

// manualPrune calls Pruner.PruneManual through an interface, so this file
// also compiles on the parent commit, where the method does not exist and
// pruneblockchain could not delete anything.
func manualPrune(t *testing.T, p *Pruner, height, tip int32) (PruneStats, error) {
	t.Helper()
	m, ok := interface{}(p).(interface {
		PruneManual(int32, int32) (PruneStats, error)
	})
	if !ok {
		t.Fatalf("Pruner has no PruneManual: a manual prune to height %d cannot delete anything", height)
	}
	return m.PruneManual(height, tip)
}

// manualPruneStore writes blocks at heights first..last into 1 KiB block
// files (about four blocks per file) and wires height -> hash.
func manualPruneStore(t *testing.T, first, last int) (*BlockStore, *ChainDB, string) {
	t.Helper()
	dir := t.TempDir()
	db := NewMemDB()
	t.Cleanup(func() { db.Close() })
	bs, err := NewBlockStore(dir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	t.Cleanup(func() { bs.Close() })
	bs.mu.Lock()
	bs.maxFileSize = 1024
	bs.mu.Unlock()
	cdb := NewChainDB(db)
	cdb.SetBlockStore(bs)
	payload := bytes.Repeat([]byte{0xCD}, 200)
	for h := first; h <= last; h++ {
		hash := wire.DoubleHashB([]byte{byte(h), byte(h >> 8), 0xA5})
		if _, err := bs.WriteAndIndexBlock(hash, payload, uint32(h), uint64(h)); err != nil {
			t.Fatalf("WriteAndIndexBlock(%d): %v", h, err)
		}
		if err := cdb.SetBlockHeight(int32(h), hash); err != nil {
			t.Fatalf("SetBlockHeight(%d): %v", h, err)
		}
		if err := cdb.WriteBlockUndo(hash, &BlockUndo{}); err != nil {
			t.Fatalf("WriteBlockUndo(%d): %v", h, err)
		}
	}
	if bs.MaxBlockfileNum() < 4 {
		t.Fatalf("precondition: want >= 4 block files, got %d", bs.MaxBlockfileNum())
	}
	return bs, cdb, dir
}

// TestPruneManualPrunesFilesAtOrBelowHeight: every file whose highest block
// is <= the requested height goes (files, metadata, block index rows); every
// file holding a block above it stays. Usage plays no part, so it works with
// a manual (-prune=1) pruner whose automatic pass never runs.
func TestPruneManualPrunesFilesAtOrBelowHeight(t *testing.T) {
	bs, cdb, dir := manualPruneStore(t, 0, 40)
	before := bs.FileInfoSnapshot()
	fileOf := map[int32]int32{}
	for h := int32(0); h <= 40; h++ {
		hash, _ := cdb.GetBlockHashByHeight(h)
		pos, err := bs.GetBlockPos(hash)
		if err != nil {
			t.Fatalf("GetBlockPos(%d): %v", h, err)
		}
		fileOf[h] = pos.FileNum
	}
	p := NewPruner(PruneConfig{Manual: true}, bs, cdb)

	// Tip far above, so only the requested height limits the sweep.
	const pruneTo = 17
	stats, err := manualPrune(t, p, pruneTo, 1000)
	if err != nil {
		t.Fatalf("PruneManual: %v", err)
	}
	wantPruned := 0
	for i, fi := range before {
		if fi.Size == 0 || int32(i) == bs.CurrentFile() {
			continue
		}
		path := filepath.Join(dir, fmtBlockFile(int32(i)))
		_, statErr := os.Stat(path)
		if fi.HeightLast <= pruneTo {
			wantPruned++
			if !os.IsNotExist(statErr) {
				t.Errorf("file %d (heights %d..%d) still on disk after pruning to %d",
					i, fi.HeightFirst, fi.HeightLast, pruneTo)
			}
			if got := bs.GetFileInfo(int32(i)); got.Size != 0 {
				t.Errorf("file %d metadata not reset (Size=%d)", i, got.Size)
			}
		} else if statErr != nil {
			t.Errorf("file %d (heights %d..%d) holds blocks above %d but was removed: %v",
				i, fi.HeightFirst, fi.HeightLast, pruneTo, statErr)
		}
	}
	if wantPruned == 0 {
		t.Fatal("precondition: no file lies wholly at or below the prune height")
	}
	if stats.FilesPruned != wantPruned {
		t.Errorf("FilesPruned = %d, want %d", stats.FilesPruned, wantPruned)
	}
	for h := int32(0); h <= 40; h++ {
		hash, _ := cdb.GetBlockHashByHeight(h)
		fi := before[fileOf[h]]
		want := fi.HeightLast > pruneTo || fileOf[h] == bs.CurrentFile()
		if bs.HasBlock(hash) != want {
			t.Errorf("height %d (file %d, heights %d..%d): block index present=%v, want %v",
				h, fileOf[h], fi.HeightFirst, fi.HeightLast, !want, want)
		}
		assertUndoKept(t, cdb, h, hash, want)
	}
	if !p.HavePruned() || p.PruneHeight() == 0 {
		t.Errorf("after a manual prune: HavePruned=%v PruneHeight=%d", p.HavePruned(), p.PruneHeight())
	}
	if p.PruneHeight() > pruneTo+1 {
		t.Errorf("PruneHeight = %d, above the requested height %d + 1", p.PruneHeight(), pruneTo)
	}
}

// TestPruneManualKeepsMinBlocksToKeep: a request at the tip is clamped to
// tip - 288, as Core's GetPruneRange does, so the last 288 blocks survive.
func TestPruneManualKeepsMinBlocksToKeep(t *testing.T) {
	bs, cdb, dir := manualPruneStore(t, 0, 40)
	before := bs.FileInfoSnapshot()
	p := NewPruner(PruneConfig{Manual: true}, bs, cdb)
	tip := int32(MinBlocksToKeep + 20) // last prunable height = 20

	if _, err := manualPrune(t, p, tip, tip); err != nil {
		t.Fatalf("PruneManual: %v", err)
	}
	for i, fi := range before {
		if fi.Size == 0 || int32(i) == bs.CurrentFile() {
			continue
		}
		_, statErr := os.Stat(filepath.Join(dir, fmtBlockFile(int32(i))))
		if fi.HeightLast > 20 && statErr != nil {
			t.Errorf("file %d (heights %d..%d) is within %d of tip %d but was pruned",
				i, fi.HeightFirst, fi.HeightLast, MinBlocksToKeep, tip)
		}
		if fi.HeightLast <= 20 && !os.IsNotExist(statErr) {
			t.Errorf("file %d (heights %d..%d) is below tip-%d but was kept",
				i, fi.HeightFirst, fi.HeightLast, MinBlocksToKeep)
		}
	}
}

// TestPruneManualZeroHeightIsNoOp: Core only prunes for a height > 0, and
// a disabled pruner never deletes.
func TestPruneManualZeroHeightIsNoOp(t *testing.T) {
	bs, cdb, _ := manualPruneStore(t, 0, 40)
	p := NewPruner(PruneConfig{Manual: true}, bs, cdb)
	if stats, err := manualPrune(t, p, 0, 1000); err != nil || stats.FilesPruned != 0 {
		t.Errorf("PruneManual(0) = %+v, %v; want nothing pruned", stats, err)
	}
	off := NewPruner(PruneConfig{}, bs, cdb)
	if stats, err := manualPrune(t, off, 30, 1000); err != nil || stats.FilesPruned != 0 {
		t.Errorf("disabled PruneManual = %+v, %v; want nothing pruned", stats, err)
	}
	if p.HavePruned() || off.HavePruned() {
		t.Error("HavePruned=true after a no-op")
	}
}

// assertUndoKept checks the block's undo record is on disk exactly when its
// block file was kept. Core keeps undo in the rev file, which is deleted
// with the block file; blockbrew keeps it in Pebble, so pruning must delete
// it there.
func assertUndoKept(t *testing.T, cdb *ChainDB, h int32, hash wire.Hash256, kept bool) {
	t.Helper()
	_, err := cdb.ReadBlockUndo(hash)
	if kept && err != nil {
		t.Errorf("height %d: block file kept but its undo record is gone: %v", h, err)
	}
	if !kept && err == nil {
		t.Errorf("height %d: block file pruned but its undo record is still on disk", h)
	}
}

// TestAutoPruneDeletesUndoRecords: the automatic pass frees the undo of the
// blocks in the files it prunes, as Core's rev files go with blk files.
func TestAutoPruneDeletesUndoRecords(t *testing.T) {
	bs, cdb, _ := manualPruneStore(t, 0, 40)
	fileOf := map[int32]int32{}
	for h := int32(0); h <= 40; h++ {
		hash, _ := cdb.GetBlockHashByHeight(h)
		pos, err := bs.GetBlockPos(hash)
		if err != nil {
			t.Fatalf("GetBlockPos(%d): %v", h, err)
		}
		fileOf[h] = pos.FileNum
	}
	p := NewPruner(PruneConfig{TargetBytes: 1}, bs, cdb)
	stats, err := p.MaybePrune(1000)
	if err != nil {
		t.Fatalf("MaybePrune: %v", err)
	}
	if stats.FilesPruned == 0 {
		t.Fatal("precondition: the automatic pass pruned nothing")
	}
	for h := int32(0); h <= 40; h++ {
		hash, _ := cdb.GetBlockHashByHeight(h)
		assertUndoKept(t, cdb, h, hash, bs.HasBlock(hash))
	}
}
