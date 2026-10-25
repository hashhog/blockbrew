package main

import (
	"os"
	"path/filepath"
	"testing"
)

const gib = int64(1 << 30)

// fits reports whether a plan's caches and Go limit fit its cap under the
// budget model (Pebble C heap = 2x block cache + memtables).
func fits(b memoryBudget) bool {
	cHeap := pebbleCHeapFactor*b.pebbleBlockCacheBytes + pebbleMemtableBudget()
	return b.goMemLimit+cHeap <= b.capBytes &&
		utxoShareOfGoLimit*b.utxoCacheBytes <= b.goMemLimit
}

func TestPlanMemoryBudgetNoCapKeepsSplit(t *testing.T) {
	b := planMemoryBudget(8192, 0)
	u, p := computeCacheSplit(8192)
	if b.utxoCacheBytes != u || b.pebbleBlockCacheBytes != p || b.clamped || b.goMemLimit != 0 {
		t.Fatalf("no cap must leave the split alone: %+v", b)
	}
}

// The mainnet unit: -dbcache=8192 under MemoryMax=10G.
func TestPlanMemoryBudgetMainnetUnitFits(t *testing.T) {
	b := planMemoryBudget(8192, 10*gib)
	if !b.clamped || b.effectiveDBCacheMiB >= 8192 {
		t.Fatalf("-dbcache=8192 cannot fit 10 GiB, expected a clamp: %+v", b)
	}
	if !fits(b) {
		t.Fatalf("plan does not fit its cap: %+v", b)
	}
	// Not needlessly small: 16 MiB more -dbcache would no longer fit.
	if fits(unclamped(b.effectiveDBCacheMiB+16, b.capBytes)) {
		t.Errorf("clamp to %d MiB is below what fits", b.effectiveDBCacheMiB)
	}
}

// unclamped is the plan for -dbcache=mib under capBytes without shrinking.
func unclamped(mib int, capBytes int64) memoryBudget {
	u, p := computeCacheSplit(mib)
	return memoryBudget{utxoCacheBytes: u, pebbleBlockCacheBytes: p, capBytes: capBytes,
		goMemLimit: capBytes - pebbleCHeapFactor*p - pebbleMemtableBudget() - capBytes/16}
}

func TestPlanMemoryBudgetSmallCacheUnderCapNotClamped(t *testing.T) {
	b := planMemoryBudget(450, 10*gib)
	u, p := computeCacheSplit(450)
	if b.clamped || b.utxoCacheBytes != u || b.pebbleBlockCacheBytes != p {
		t.Fatalf("a cache that fits must not be clamped: %+v", b)
	}
	if !fits(b) || b.goMemLimit <= 0 {
		t.Fatalf("Go limit must still be derived from the cap: %+v", b)
	}
}

func TestPlanMemoryBudgetTinyCapFloors(t *testing.T) {
	b := planMemoryBudget(8192, 256<<20)
	if b.effectiveDBCacheMiB < 4 {
		t.Fatalf("dbcache below the 4 MiB floor: %+v", b)
	}
	if b.goMemLimit < b.capBytes/4 {
		t.Fatalf("Go limit below its floor: %+v", b)
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupMemoryMaxTightestAncestorWins(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/self/cgroup"), "0::/a.slice/b.slice/node.service\n")
	cg := filepath.Join(root, "sys/fs/cgroup")
	writeFile(t, filepath.Join(cg, "a.slice/memory.max"), "8589934592\n")
	writeFile(t, filepath.Join(cg, "a.slice/b.slice/memory.max"), "max\n")
	writeFile(t, filepath.Join(cg, "a.slice/b.slice/node.service/memory.max"), "10737418240\n")
	if got := cgroupMemoryMax(root); got != 8*gib {
		t.Fatalf("got %d, want the 8 GiB ancestor limit", got)
	}
}

func TestCgroupMemoryMaxNoLimit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/self/cgroup"), "0::/x.service\n")
	writeFile(t, filepath.Join(root, "sys/fs/cgroup/x.service/memory.max"), "max\n")
	if got := cgroupMemoryMax(root); got != 0 {
		t.Fatalf("got %d, want 0 for memory.max=max", got)
	}
	// cgroup v1 only (no "0::" line) and a missing /proc: no limit known.
	v1 := t.TempDir()
	writeFile(t, filepath.Join(v1, "proc/self/cgroup"), "4:memory:/x\n")
	if got := cgroupMemoryMax(v1); got != 0 {
		t.Fatalf("v1-only: got %d, want 0", got)
	}
	if got := cgroupMemoryMax(filepath.Join(t.TempDir(), "nonexistent")); got != 0 {
		t.Fatalf("missing /proc: got %d, want 0", got)
	}
}
