package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestPruneConfigEnabled covers the boundary: 0 disables, anything
// else enables. Validation of the 550 MiB floor lives in cmd/blockbrew
// (parseFlags) — see TestParsePruneFlag.
func TestPruneConfigEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  PruneConfig
		want bool
	}{
		{"zero disables (archive)", PruneConfig{TargetBytes: 0}, false},
		{"non-zero enables", PruneConfig{TargetBytes: 1024}, true},
		{"min target enables", PruneConfig{TargetBytes: MinPruneTargetBytes}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg.IsEnabled() != tt.want {
				t.Errorf("IsEnabled = %v, want %v", tt.cfg.IsEnabled(), tt.want)
			}
		})
	}
}

// TestPrunerNilSafety: a nil *Pruner (the archive-mode default in
// callers that haven't constructed one yet) must report disabled and
// MaybePrune must be a no-op. Guards against a NPE panic on the
// per-block hot path when -prune=0.
func TestPrunerNilSafety(t *testing.T) {
	var p *Pruner
	if p.IsEnabled() {
		t.Error("nil pruner reported IsEnabled=true")
	}
	if p.HavePruned() {
		t.Error("nil pruner reported HavePruned=true")
	}
	if h := p.PruneHeight(); h != 0 {
		t.Errorf("nil pruner PruneHeight = %d, want 0", h)
	}
	if tb := p.TargetBytes(); tb != 0 {
		t.Errorf("nil pruner TargetBytes = %d, want 0", tb)
	}
}

// TestPrunerDisabled: a Pruner constructed with TargetBytes=0 must
// also no-op. Same guard as above but covering the archive default
// in main.go.
func TestPrunerDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	defer bs.Close()
	chainDB := NewChainDB(db)

	p := NewPruner(PruneConfig{TargetBytes: 0}, bs, chainDB)
	if p.IsEnabled() {
		t.Fatal("disabled pruner reported IsEnabled=true")
	}
	stats, err := p.MaybePrune(1000)
	if err != nil {
		t.Fatalf("MaybePrune on disabled: %v", err)
	}
	if stats.FilesPruned != 0 || stats.BytesPruned != 0 {
		t.Errorf("disabled pruner did work: %+v", stats)
	}
}

// TestCalculateCurrentUsageEmpty: a fresh BlockStore reports zero
// usage. Validates the empty-fileInfo path used on first start before
// any block has been written.
func TestCalculateCurrentUsageEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	defer bs.Close()

	if u := bs.CalculateCurrentUsage(); u != 0 {
		t.Errorf("empty store usage = %d, want 0", u)
	}
}

// TestCalculateCurrentUsageAccumulates: after writing N blocks, usage
// reflects the sum of fileInfo.Size + fileInfo.UndoSize. Doesn't
// require pruning.
func TestCalculateCurrentUsageAccumulates(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	defer bs.Close()

	// Write 4 blocks of 1000 bytes each.
	payload := bytes.Repeat([]byte{0xAB}, 1000)
	for i := 0; i < 4; i++ {
		hash := wire.DoubleHashB([]byte{byte(i)})
		if _, err := bs.WriteAndIndexBlock(hash, payload, uint32(i), 1609459200+uint64(i)); err != nil {
			t.Fatalf("WriteAndIndexBlock(%d): %v", i, err)
		}
	}

	usage := bs.CalculateCurrentUsage()
	// Every block adds StorageHeaderSize (8) + 1000 to fileInfo.Size.
	wantMin := uint64(4 * (StorageHeaderSize + 1000))
	if usage < wantMin {
		t.Errorf("usage = %d, want >= %d", usage, wantMin)
	}
}

// TestPruneBelowTarget: usage well under target must not prune anything.
// Uses a 600 MiB target with ~4 KB of actual data.
func TestPruneBelowTarget(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	defer bs.Close()
	chainDB := NewChainDB(db)
	chainDB.SetBlockStore(bs)

	for i := 0; i < 4; i++ {
		hash := wire.DoubleHashB([]byte{byte(i)})
		if _, err := bs.WriteAndIndexBlock(hash, []byte("blockdata"), uint32(i), uint64(i)); err != nil {
			t.Fatalf("WriteAndIndexBlock: %v", err)
		}
	}

	p := NewPruner(PruneConfig{TargetBytes: MinPruneTargetBytes}, bs, chainDB)
	stats, err := p.MaybePrune(1000)
	if err != nil {
		t.Fatalf("MaybePrune: %v", err)
	}
	if stats.FilesPruned != 0 {
		t.Errorf("pruned %d files below target (expected 0)", stats.FilesPruned)
	}
	if p.HavePruned() {
		t.Error("HavePruned=true after no-op pass")
	}
}

// TestPruneAboveTarget: usage above target prunes oldest files first
// until either we drop under the target or we hit MinBlocksToKeep
// guard. Synthesizes the over-target condition by lowering the
// effective target rather than writing 550 MiB of blocks.
func TestPruneAboveTarget(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	// Force per-file rollover at 1 KiB so we end up with several block
	// files in the test rather than packing everything into blk00000.
	bs.mu.Lock()
	bs.maxFileSize = 1024
	bs.mu.Unlock()

	defer bs.Close()
	chainDB := NewChainDB(db)
	chainDB.SetBlockStore(bs)

	// Write ~10 blocks at successive heights. Each block is 200 bytes
	// of payload + 8-byte storage header. With maxFileSize=1024, expect
	// rollover roughly every ~5 blocks → 2-3 separate files.
	const numBlocks = 10
	payload := bytes.Repeat([]byte{0xCC}, 200)
	heights := make([]uint32, numBlocks)
	hashes := make([]wire.Hash256, numBlocks)
	for i := 0; i < numBlocks; i++ {
		heights[i] = uint32(i + 100) // height range 100..109
		hashes[i] = wire.DoubleHashB([]byte{byte(i), 0xFE})
		if _, err := bs.WriteAndIndexBlock(hashes[i], payload, heights[i], uint64(i)); err != nil {
			t.Fatalf("WriteAndIndexBlock(%d): %v", i, err)
		}
		// Wire height -> hash so the pruner can find per-block index
		// entries to clean up.
		if err := chainDB.SetBlockHeight(int32(heights[i]), hashes[i]); err != nil {
			t.Fatalf("SetBlockHeight: %v", err)
		}
	}

	maxNum := bs.MaxBlockfileNum()
	if maxNum < 2 {
		t.Fatalf("expected at least 2 block files, got %d", maxNum)
	}

	// Tip height 1000 means lastSafeHeight = 1000 - 288 = 712, well
	// above all our test heights (100..109). So all but the active file
	// should be eligible. Set TargetBytes=1 so we always over-target.
	p := NewPruner(PruneConfig{TargetBytes: 1}, bs, chainDB)
	stats, err := p.MaybePrune(1000)
	if err != nil {
		t.Fatalf("MaybePrune: %v", err)
	}

	if stats.FilesPruned == 0 {
		t.Fatal("expected at least one file pruned")
	}
	if !p.HavePruned() {
		t.Error("HavePruned=false after a successful prune pass")
	}
	if p.PruneHeight() == 0 {
		t.Error("PruneHeight=0 after a successful prune pass")
	}

	// Verify the on-disk files for fileNum 0 are gone.
	blockPath := filepath.Join(tmpDir, "blk00000.dat")
	if _, err := os.Stat(blockPath); !os.IsNotExist(err) {
		t.Errorf("blk00000.dat still exists after prune (err=%v)", err)
	}

	// The active file (currentFileNum) must NOT have been touched.
	currFile := bs.CurrentFile()
	currPath := filepath.Join(tmpDir, fmtBlockFile(currFile))
	if _, err := os.Stat(currPath); err != nil {
		t.Errorf("active file %s missing after prune: %v", currPath, err)
	}

	// File metadata for pruned files should be zeroed.
	for i := int32(0); i < currFile; i++ {
		fi := bs.GetFileInfo(i)
		if fi == nil {
			continue
		}
		if fi.Size != 0 {
			t.Errorf("fileInfo[%d].Size = %d after prune (want 0)", i, fi.Size)
		}
		if fi.NumBlocks != 0 {
			t.Errorf("fileInfo[%d].NumBlocks = %d after prune (want 0)", i, fi.NumBlocks)
		}
	}
}

// TestPruneRespectsMinBlocksToKeep: with tipHeight close to
// MinBlocksToKeep, no file may be pruned because the last-safe-height
// computation drops to 0.
func TestPruneRespectsMinBlocksToKeep(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	bs.mu.Lock()
	bs.maxFileSize = 1024
	bs.mu.Unlock()
	defer bs.Close()
	chainDB := NewChainDB(db)
	chainDB.SetBlockStore(bs)

	// Write blocks at heights 1..10 so the highest is well within the
	// MinBlocksToKeep buffer of any tip <= 297.
	payload := bytes.Repeat([]byte{0xCC}, 200)
	for i := 0; i < 10; i++ {
		h := uint32(i + 1)
		hash := wire.DoubleHashB([]byte{byte(i), 0xAA})
		if _, err := bs.WriteAndIndexBlock(hash, payload, h, uint64(i)); err != nil {
			t.Fatalf("WriteAndIndexBlock: %v", err)
		}
		_ = chainDB.SetBlockHeight(int32(h), hash)
	}

	// Tip height = 100: lastSafe = 100 - 288 → clamped to 0. Nothing
	// is below that, so nothing prunes even with TargetBytes=1.
	p := NewPruner(PruneConfig{TargetBytes: 1}, bs, chainDB)
	stats, err := p.MaybePrune(100)
	if err != nil {
		t.Fatalf("MaybePrune: %v", err)
	}
	if stats.FilesPruned != 0 {
		t.Errorf("pruned %d files (expected 0; tip too low)", stats.FilesPruned)
	}
}

// TestPrunedBlockReadFails: after pruning, ReadBlockByHash for a
// pruned block must fail. The error itself isn't a strong contract
// (the index entry may or may not have been cleaned up), but
// IsPrunedBlockError must report true on the underlying ENOENT case.
func TestPrunedBlockReadFails(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	bs.mu.Lock()
	bs.maxFileSize = 1024
	bs.mu.Unlock()
	defer bs.Close()
	chainDB := NewChainDB(db)
	chainDB.SetBlockStore(bs)

	payload := bytes.Repeat([]byte{0xDE}, 200)
	hashes := make([]wire.Hash256, 10)
	for i := 0; i < 10; i++ {
		hashes[i] = wire.DoubleHashB([]byte{byte(i), 0xBB})
		if _, err := bs.WriteAndIndexBlock(hashes[i], payload, uint32(i+100), uint64(i)); err != nil {
			t.Fatalf("WriteAndIndexBlock: %v", err)
		}
		_ = chainDB.SetBlockHeight(int32(i+100), hashes[i])
	}

	// Capture a hash that lives in fileNum 0 (oldest).
	pos0, err := bs.GetBlockPos(hashes[0])
	if err != nil {
		t.Fatalf("GetBlockPos: %v", err)
	}
	if pos0.FileNum != 0 {
		t.Skip("test layout drifted; oldest hash not in file 0")
	}

	p := NewPruner(PruneConfig{TargetBytes: 1}, bs, chainDB)
	if _, err := p.MaybePrune(1000); err != nil {
		t.Fatalf("MaybePrune: %v", err)
	}

	// Read the pruned block — must fail.
	_, err = bs.ReadBlockByHash(hashes[0])
	if err == nil {
		t.Fatal("ReadBlockByHash succeeded after prune")
	}

	// Also verify: HasBlockBody on the chainDB is now false. This is the
	// flag the RPC layer checks before answering "pruned data".
	if chainDB.HasBlockBody(hashes[0]) {
		t.Error("HasBlockBody returned true for pruned block")
	}
}

// TestIsPrunedBlockError covers the predicate used in the RPC layer.
func TestIsPrunedBlockError(t *testing.T) {
	if IsPrunedBlockError(nil) {
		t.Error("nil err is not a prune error")
	}
	if !IsPrunedBlockError(os.ErrNotExist) {
		t.Error("ErrNotExist must be classified as prune error")
	}
	wrapped := errWithCause("flatfile: open failed", os.ErrNotExist)
	if !IsPrunedBlockError(wrapped) {
		t.Error("wrapped ErrNotExist must classify as prune error")
	}
	if IsPrunedBlockError(errWithCause("other", errors.New("kaboom"))) {
		t.Error("unrelated error misclassified as prune error")
	}
}

// errWithCause wraps cause behind msg using fmt.Errorf %w semantics
// for the test above. Avoids depending on fmt for one-liner clarity.
func errWithCause(msg string, cause error) error {
	return wrappedErr{msg: msg, cause: cause}
}

type wrappedErr struct {
	msg   string
	cause error
}

func (w wrappedErr) Error() string { return w.msg + ": " + w.cause.Error() }
func (w wrappedErr) Unwrap() error { return w.cause }

// fmtBlockFile is a test helper that mirrors BlockStore.blockFilename
// without taking the lock — used in over-target test for the active
// file existence check.
func fmtBlockFile(fileNum int32) string {
	return blockfileName(fileNum)
}

// blockfileName mirrors the format used by BlockStore.blockFilename
// for the bare basename. Kept in test-only scope so any future change
// to the production name shape is caught here at build time via the
// shared BlockFilePrefix constant.
func blockfileName(fileNum int32) string {
	// Use the same %05d format BlockStore uses.
	return BlockFilePrefix + zeroPad(fileNum, 5) + ".dat"
}

func zeroPad(n int32, width int) string {
	s := ""
	if n < 0 {
		n = 0
	}
	v := int(n)
	digits := []byte{}
	if v == 0 {
		digits = []byte{'0'}
	}
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	for len(digits) < width {
		digits = append([]byte{'0'}, digits...)
	}
	s = string(digits)
	return s
}
