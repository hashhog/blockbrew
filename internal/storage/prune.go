package storage

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Pruning constants matching Bitcoin Core (validation.h).
const (
	// MinBlocksToKeep is the lower bound on the gap between the chain tip
	// and the highest block that may be pruned. Must match Bitcoin Core's
	// MIN_BLOCKS_TO_KEEP=288 — anything lower would trip net_processing's
	// MAX_BLOCKTXN_DEPTH static_assert and break BIP152 cmpct-block depth
	// reasoning across the fleet.
	MinBlocksToKeep = 288

	// MinPruneTargetMiB is the minimum -prune target in MiB. Bitcoin Core
	// uses 550 MiB (init.cpp: MIN_DISK_SPACE_FOR_BLOCK_FILES). Going below
	// this risks pruning data the node may need to serve over P2P inside
	// the next compact-block window.
	MinPruneTargetMiB = 550

	// MinPruneTargetBytes is MinPruneTargetMiB expressed in bytes.
	MinPruneTargetBytes = uint64(MinPruneTargetMiB) * 1024 * 1024
)

// PruneStats summarizes the result of a prune pass.
type PruneStats struct {
	// FilesPruned is the number of blk/rev pairs unlinked.
	FilesPruned int
	// BytesPruned is the total bytes freed from blk*.dat and rev*.dat.
	BytesPruned uint64
	// CurrentUsage is total disk usage of remaining flatfile data after
	// the prune pass.
	CurrentUsage uint64
	// PruneHeight is the lowest height with block data still on disk
	// after this pass. Zero means no data was pruned (or the chain has
	// not yet been pruned).
	PruneHeight int32
	// LastSafeHeight is the highest height that *could* have been pruned
	// during this pass (tip - MinBlocksToKeep).
	LastSafeHeight int32
}

// PruneConfig controls the auto-prune loop. Zero TargetBytes disables
// pruning entirely (the default for archive nodes).
type PruneConfig struct {
	// TargetBytes is the target maximum size of the on-disk blk*.dat +
	// rev*.dat directory. When CalculateCurrentUsage exceeds this plus
	// a buffer, the oldest pruneable files are unlinked. 0 = pruning
	// disabled (archive mode, the default).
	TargetBytes uint64
}

// IsEnabled reports whether auto-pruning is configured.
func (c PruneConfig) IsEnabled() bool {
	return c.TargetBytes > 0
}

// Pruner coordinates auto-prune passes for a BlockStore. It is safe to
// call MaybePrune concurrently with normal block-write traffic; the
// underlying BlockStore guards the per-file metadata with its own mutex
// and the pruner additionally serializes its own passes so two prune
// goroutines cannot race.
type Pruner struct {
	cfg        PruneConfig
	bs         *BlockStore
	chainDB    *ChainDB
	mu         sync.Mutex // serializes prune passes
	pruneHeight atomic.Int32 // lowest height with data; 0 if not yet pruned
	havePruned atomic.Bool  // true once at least one prune pass actually freed files
}

// NewPruner creates a Pruner. bs and chainDB must both be non-nil for
// auto-prune to do useful work; if either is nil the Pruner reports
// IsEnabled()=false from the config but MaybePrune is a no-op.
func NewPruner(cfg PruneConfig, bs *BlockStore, chainDB *ChainDB) *Pruner {
	return &Pruner{cfg: cfg, bs: bs, chainDB: chainDB}
}

// IsEnabled reports whether the pruner will actually do work.
func (p *Pruner) IsEnabled() bool {
	if p == nil {
		return false
	}
	return p.cfg.IsEnabled() && p.bs != nil
}

// HavePruned reports whether at least one prune pass has freed files
// since the process started. Used by RPC getblockchaininfo to decide
// whether to expose pruneheight.
func (p *Pruner) HavePruned() bool {
	if p == nil {
		return false
	}
	return p.havePruned.Load()
}

// PruneHeight returns the lowest height with block data still on disk.
// Zero means no prune has happened yet this process lifetime.
func (p *Pruner) PruneHeight() int32 {
	if p == nil {
		return 0
	}
	return p.pruneHeight.Load()
}

// TargetBytes returns the configured -prune target in bytes.
func (p *Pruner) TargetBytes() uint64 {
	if p == nil {
		return 0
	}
	return p.cfg.TargetBytes
}

// CalculateCurrentUsage sums Size + UndoSize across all known block
// files. Mirrors BlockManager::CalculateCurrentUsage in Bitcoin Core
// (node/blockstorage.cpp). Returns 0 if the store has no files yet.
func (bs *BlockStore) CalculateCurrentUsage() uint64 {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	var total uint64
	for _, fi := range bs.fileInfo {
		total += uint64(fi.Size) + uint64(fi.UndoSize)
	}
	return total
}

// MaxBlockfileNum returns the highest known fileNum + 1 (for iteration).
func (bs *BlockStore) MaxBlockfileNum() int32 {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return int32(len(bs.fileInfo))
}

// FileInfoSnapshot returns a copy of all known BlockFileInfo records,
// safe to inspect outside the BlockStore lock. Used by the pruner.
func (bs *BlockStore) FileInfoSnapshot() []BlockFileInfo {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]BlockFileInfo, len(bs.fileInfo))
	copy(out, bs.fileInfo)
	return out
}

// PruneOneBlockFile resets the BlockFileInfo for the given fileNum to
// zero (matching Core's m_blockfile_info.at(fileNumber) = CBlockFileInfo{})
// and persists the change. This does NOT touch the on-disk file or the
// per-block position index — those are handled by UnlinkPrunedFile and
// the caller's index-cleanup pass respectively.
func (bs *BlockStore) PruneOneBlockFile(fileNum int32) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if fileNum < 0 || int32(len(bs.fileInfo)) <= fileNum {
		return ErrInvalidPos
	}
	// Refuse to prune the currently-being-written file. Core does not
	// hit this case because the caller's range loop stops at MaxBlockfileNum
	// (which is the count, not the active fileNum), but the symmetry in
	// blockbrew is loose — guard explicitly.
	if fileNum == bs.currentFileNum {
		return errors.New("flatfile: refusing to prune currently active file")
	}
	bs.fileInfo[fileNum] = BlockFileInfo{}
	return bs.saveState()
}

// UnlinkPrunedFile removes the blk?????.dat and rev?????.dat files for
// fileNum. Returns the number of bytes freed (sum of the two file
// sizes before removal). Missing files are not an error — Core uses
// std::error_code on fs::remove and ignores ENOENT.
func (bs *BlockStore) UnlinkPrunedFile(fileNum int32) (uint64, error) {
	if fileNum < 0 {
		return 0, ErrInvalidPos
	}
	bs.mu.RLock()
	blockPath := bs.blockFilename(fileNum)
	undoPath := bs.undoFilename(fileNum)
	bs.mu.RUnlock()

	var freed uint64
	if info, err := os.Stat(blockPath); err == nil {
		freed += uint64(info.Size())
	}
	if info, err := os.Stat(undoPath); err == nil {
		freed += uint64(info.Size())
	}

	// os.Remove returns *PathError wrapping ENOENT for missing files;
	// match Core's behavior of treating that as success.
	if err := os.Remove(blockPath); err != nil && !os.IsNotExist(err) {
		return freed, fmt.Errorf("flatfile: unlink %s: %w", blockPath, err)
	}
	if err := os.Remove(undoPath); err != nil && !os.IsNotExist(err) {
		return freed, fmt.Errorf("flatfile: unlink %s: %w", undoPath, err)
	}
	return freed, nil
}

// MaybePrune runs one prune pass if (a) pruning is configured and
// (b) the current usage exceeds the target. tipHeight is the active
// chain tip; prune respects MinBlocksToKeep below that.
//
// Mirrors BlockManager::FindFilesToPrune (node/blockstorage.cpp). The
// algorithm:
//
//  1. If usage + buffer < target, do nothing.
//  2. Compute lastSafeHeight = max(0, tipHeight - MinBlocksToKeep).
//  3. Walk fileInfo in fileNum order (oldest first); for each non-empty
//     file whose HeightLast <= lastSafeHeight, prune it (zero metadata,
//     unlink files, drop the per-block position index entries) until
//     usage drops back under target or we run out of safe files.
//
// Returns PruneStats summarizing what happened (zero-valued fields are
// fine if nothing was eligible). Errors abort the pass and are returned
// directly.
func (p *Pruner) MaybePrune(tipHeight int32) (PruneStats, error) {
	var stats PruneStats
	if !p.IsEnabled() || p.chainDB == nil {
		return stats, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	currentUsage := p.bs.CalculateCurrentUsage()
	stats.CurrentUsage = currentUsage

	// Allocation buffer: leave headroom for one block file + one undo file
	// before the next prune pass. Core uses BLOCKFILE_CHUNK_SIZE +
	// UNDOFILE_CHUNK_SIZE; we approximate with one full block file
	// (MaxBlockFileSize, 128 MiB) since blockbrew preallocates in 16 MiB
	// chunks up to that cap. This is the same shape Core uses, just with
	// a slightly more conservative undo budget folded into the block
	// allocation (we don't preallocate undo files separately).
	buffer := uint64(MaxBlockFileSize)

	if currentUsage+buffer < p.cfg.TargetBytes {
		// Below target — refresh the prune-height accounting (the
		// lowest-height-with-data may have advanced via a previous
		// prune pass) and return.
		stats.PruneHeight = p.pruneHeight.Load()
		stats.LastSafeHeight = lastSafeHeight(tipHeight)
		return stats, nil
	}

	// Compute the highest safe-to-prune height. Anything strictly
	// greater than this must be retained (matches Core's
	// last_block_can_prune semantics for the simple no-historical-state
	// case; blockbrew has no snapshot/historical chainstate so we use
	// the simpler tip-MinBlocksToKeep formula).
	lastSafe := lastSafeHeight(tipHeight)
	stats.LastSafeHeight = lastSafe

	files := p.bs.FileInfoSnapshot()
	maxNum := p.bs.MaxBlockfileNum()
	currentFile := p.bs.CurrentFile()

	// Track the lowest height with data still on disk after the pass.
	// We seed with the current pruneHeight; a successful prune of a
	// file whose HeightFirst was the current minimum advances this.
	newPruneHeight := p.pruneHeight.Load()

	for fileNum := int32(0); fileNum < maxNum; fileNum++ {
		if currentUsage+buffer < p.cfg.TargetBytes {
			break // back under target
		}
		fi := files[fileNum]
		if fi.Size == 0 {
			continue // already pruned or empty
		}
		// Never touch the active file. The check inside PruneOneBlockFile
		// catches this too, but skipping early avoids the spurious
		// "refusing to prune" log on every pass.
		if fileNum == currentFile {
			continue
		}
		// Don't prune files whose contents extend above the safe height.
		// Core also enforces a lower bound (HeightFirst < min_block_to_prune)
		// for snapshot/historical chainstates; we don't have those, so
		// the lower bound is implicitly 0.
		if int32(fi.HeightLast) > lastSafe {
			continue
		}

		bytesFreed := uint64(fi.Size) + uint64(fi.UndoSize)

		// Drop per-block position index entries for the blocks that lived
		// in this file. Walk heights HeightFirst..HeightLast inclusive;
		// look up the canonical hash via chainDB.GetBlockHashByHeight and
		// delete the block-pos and undo-pos rows. Best-effort: missing
		// height rows (reorged sidechains, etc.) are skipped silently.
		for h := int32(fi.HeightFirst); h <= int32(fi.HeightLast); h++ {
			hash, err := p.chainDB.GetBlockHashByHeight(h)
			if err != nil {
				continue
			}
			_ = p.bs.DeleteBlockIndex(hash)
			_ = p.bs.DeleteUndoIndex(hash)
		}

		// Reset metadata in-memory and persist.
		if err := p.bs.PruneOneBlockFile(fileNum); err != nil {
			return stats, fmt.Errorf("flatfile: PruneOneBlockFile(%d): %w", fileNum, err)
		}

		// Unlink the on-disk files.
		freed, err := p.bs.UnlinkPrunedFile(fileNum)
		if err != nil {
			return stats, fmt.Errorf("flatfile: UnlinkPrunedFile(%d): %w", fileNum, err)
		}
		// Use the larger of (metadata size, fs size) — fs size accounts for
		// the preallocated tail that the metadata Size doesn't track.
		if freed > bytesFreed {
			bytesFreed = freed
		}

		if currentUsage > bytesFreed {
			currentUsage -= bytesFreed
		} else {
			currentUsage = 0
		}
		stats.FilesPruned++
		stats.BytesPruned += bytesFreed

		// Advance the prune-height watermark.
		if newPruneHeight == 0 || int32(fi.HeightLast)+1 > newPruneHeight {
			newPruneHeight = int32(fi.HeightLast) + 1
		}
	}

	stats.CurrentUsage = currentUsage

	if stats.FilesPruned > 0 {
		p.havePruned.Store(true)
		p.pruneHeight.Store(newPruneHeight)
		log.Printf("prune: removed %d blk/rev pairs (%d MiB freed); usage=%d MiB target=%d MiB pruneheight=%d",
			stats.FilesPruned,
			stats.BytesPruned>>20,
			currentUsage>>20,
			p.cfg.TargetBytes>>20,
			newPruneHeight,
		)
	}
	stats.PruneHeight = newPruneHeight
	return stats, nil
}

// lastSafeHeight returns max(0, tipHeight - MinBlocksToKeep). The
// MinBlocksToKeep buffer is the same one Core enforces — anything at or
// below this height is older than the cmpct-block depth and safe to drop.
func lastSafeHeight(tipHeight int32) int32 {
	if tipHeight <= MinBlocksToKeep {
		return 0
	}
	return tipHeight - MinBlocksToKeep
}

// IsPrunedBlockError returns true if err looks like the file-system
// signal that the underlying blk*.dat was pruned out from under a
// reader (fs.ErrNotExist on the blk file open in ReadBlock). Used by
// the RPC layer to translate ChainDB errors into Core's
// "block not available (pruned data)" response.
func IsPrunedBlockError(err error) bool {
	if err == nil {
		return false
	}
	// ReadBlock wraps the os.Open error with a "flatfile: open failed"
	// prefix; unwrap to inspect the underlying syscall error.
	return errors.Is(err, os.ErrNotExist)
}

// HasBlockBody reports whether the block body for hash is currently on
// disk. False either because the block was never seen, or because it
// was pruned. Mirrors Core's BLOCK_HAVE_DATA flag.
func (c *ChainDB) HasBlockBody(hash wire.Hash256) bool {
	if c.blockStore == nil {
		// Legacy path: no flatfile, but the block may still live under
		// the "B" prefix (tests/benchmarks).
		key := MakeBlockDataKey(hash)
		has, _ := c.db.Has(key)
		return has
	}
	if !c.blockStore.HasBlock(hash) {
		// Index entry missing — either never stored or already cleaned
		// up by a prior prune pass.
		return false
	}
	pos, err := c.blockStore.GetBlockPos(hash)
	if err != nil {
		return false
	}
	// Index entry present but the underlying file may have been
	// unlinked. Check that the file actually exists.
	c.blockStore.mu.RLock()
	path := c.blockStore.blockFilename(pos.FileNum)
	c.blockStore.mu.RUnlock()
	_, err = os.Stat(path)
	return err == nil
}
