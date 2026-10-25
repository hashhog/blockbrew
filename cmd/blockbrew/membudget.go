package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/storage"
)

// Memory budget under a cgroup memory limit.
//
// -dbcache is split 80% UTXO cache (Go heap) / 20% Pebble block cache (C heap,
// Pebble's manual allocator calls calloc). Neither half knew about the cgroup
// memory.max the node runs under, and the Go soft limit was a fixed 12 GiB.
// Mainnet runs -dbcache=8192 under MemoryMax=10G with no swap: 6.4 GiB of coins
// cache plus a 1.6 GiB block cache plus memtables is already ~8.5 GiB before
// GC headroom or allocator overhead, so the kernel killed the process long
// before the Go runtime would have collected (2026-10-19 OOM-kill, during a
// gettxoutsetinfo walk racing block 972203).
//
// planMemoryBudget sizes both caches and the Go soft limit so the whole
// process fits the cap. The constants are measured, not guessed:
//   - Pebble's C heap is ~2x its block cache: glibc keeps freed cache blocks
//     in its arenas (live node: 3.1 GB of malloc'd memory for a 1.6 GiB cache;
//     offline repro: ~500 MB held for a 256 MiB cache, ~450 MB with
//     MALLOC_ARENA_MAX=2).
//   - The coins cache costs ~2x its accounted bytes on the Go heap
//     (estimateEntrySize: cache + dirty + fresh maps), and the Go limit needs
//     the same again as GC headroom, so the UTXO share gets a quarter of it.

const (
	// pebbleCHeapFactor is Pebble's malloc'd memory per byte of block cache.
	pebbleCHeapFactor = 2
	// utxoShareOfGoLimit is the inverse fraction of the Go limit the UTXO
	// cache may account for.
	utxoShareOfGoLimit = 4
	// cgroupFSRootEnv relocates /proc and /sys/fs/cgroup for the cgroup probe
	// (containers that mount them elsewhere; tests).
	cgroupFSRootEnv = "BLOCKBREW_CGROUP_FS_ROOT"
)

// pebbleMemtableBudget is the most memtable memory Pebble holds (C heap).
func pebbleMemtableBudget() int64 {
	return int64(storage.DefaultPebbleDBConfig().MemTableSize) * storage.MemTableStopWritesThreshold
}

// memoryBudget is the cache split and Go soft limit for one process.
type memoryBudget struct {
	utxoCacheBytes        int64
	pebbleBlockCacheBytes int64
	// goMemLimit is the Go runtime soft limit; 0 means no cap was found and
	// the caller keeps its default.
	goMemLimit int64
	// capBytes is the cgroup memory.max the plan fits (0: none).
	capBytes int64
	// effectiveDBCacheMiB is the -dbcache the split was computed from; it is
	// below the requested value when the cap forced a clamp.
	effectiveDBCacheMiB int
	clamped             bool
}

// planMemoryBudget returns the cache split for -dbcache=dbcacheMiB, shrunk if
// needed so the process fits capBytes (the cgroup memory.max; <= 0 = none).
func planMemoryBudget(dbcacheMiB int, capBytes int64) memoryBudget {
	utxo, pebble := computeCacheSplit(dbcacheMiB)
	b := memoryBudget{utxoCacheBytes: utxo, pebbleBlockCacheBytes: pebble, effectiveDBCacheMiB: dbcacheMiB}
	if capBytes <= 0 {
		return b
	}
	b.capBytes = capBytes
	memtables := pebbleMemtableBudget()
	// Threads, cgo libraries, kernel-side socket buffers: not Go, not Pebble.
	reserve := capBytes / 16
	goLimit := func(pebbleCache int64) int64 {
		return capBytes - pebbleCHeapFactor*pebbleCache - memtables - reserve
	}
	if utxoShareOfGoLimit*utxo > goLimit(pebble) {
		// With the 80/20 split (utxo = 4p): 4*utxo <= cap - 2p - mt - r
		// gives 16p + 2p <= cap - mt - r, and dbcache = 5p.
		avail := capBytes - memtables - reserve
		mib := int(avail * 5 / (utxoShareOfGoLimit*4 + pebbleCHeapFactor) / (1 << 20))
		if mib < 4 {
			mib = 4
		}
		if mib < dbcacheMiB {
			utxo, pebble = computeCacheSplit(mib)
			b.utxoCacheBytes, b.pebbleBlockCacheBytes = utxo, pebble
			b.effectiveDBCacheMiB = mib
			b.clamped = true
		}
	}
	b.goMemLimit = goLimit(pebble)
	if floor := capBytes / 4; b.goMemLimit < floor {
		b.goMemLimit = floor
	}
	return b
}

// cgroupMemoryMax returns the tightest cgroup v2 memory.max on the path from
// this process's cgroup up to the hierarchy root, or 0 if none is set.
// fsRoot prefixes /proc and /sys/fs/cgroup ("" = the real ones).
func cgroupMemoryMax(fsRoot string) int64 {
	f, err := os.Open(filepath.Join(fsRoot, "/proc/self/cgroup"))
	if err != nil {
		return 0
	}
	defer f.Close()
	var rel string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// cgroup v2 unified hierarchy: "0::/user.slice/.../x.service".
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			rel = p
			break
		}
	}
	if rel == "" {
		return 0
	}
	base := filepath.Join(fsRoot, "/sys/fs/cgroup")
	var tightest int64
	for dir := filepath.Clean("/" + rel); ; dir = filepath.Dir(dir) {
		raw, err := os.ReadFile(filepath.Join(base, dir, "memory.max"))
		if err == nil {
			if v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && v > 0 {
				if tightest == 0 || v < tightest {
					tightest = v
				}
			}
		}
		if dir == "/" {
			break
		}
	}
	return tightest
}
