package main

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCgroupMemoryMaxBoundsNodeCaches starts the real binary under a cgroup
// memory.max and checks that what it configures fits that cap.
//
// Mainnet runs -dbcache=8192 under MemoryMax=10G (no swap). The node split
// that into a 6.4 GiB coins cache and a 1.6 GiB Pebble block cache and kept a
// 12 GiB Go soft limit, so it could grow past the cap without the GC ever
// tightening, and the kernel OOM-killed it (2026-10-19, NRestarts=1).
//
// The fit rule: the coins cache costs ~2x its accounted bytes on the Go heap,
// Pebble's block cache ~2x its size in C heap, plus Pebble's memtables. The
// Go soft limit must leave room for Pebble's C heap.
func TestCgroupMemoryMaxBoundsNodeCaches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess memory-budget test in -short mode")
	}
	binary, err := buildTestBinary(t)
	if err != nil {
		t.Fatalf("build test binary: %v", err)
	}
	const mib = int64(1 << 20)
	const memtablesMiB = 4 * 128 // MemTableStopWritesThreshold x MemTableSize

	t.Run("capped_10GiB", func(t *testing.T) {
		capBytes := int64(10 << 30)
		out := startNodeUntilDBOpen(t, binary, fakeCgroupRoot(t, strconv.FormatInt(capBytes, 10)), 8192)
		utxo, pebble := parseCacheSplit(t, out)
		need := 2*utxo + 2*pebble + memtablesMiB
		if need*mib > capBytes {
			t.Errorf("caches need ~%d MiB (2x utxo_cache=%d + 2x pebble_block_cache=%d + %d memtables) but memory.max is %d MiB\n%s",
				need, utxo, pebble, memtablesMiB, capBytes/mib, out)
		}
		m := regexp.MustCompile(`Go soft limit (\d+) MiB`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no Go soft limit derived from memory.max in startup log\n%s", out)
		}
		goLimit, _ := strconv.ParseInt(m[1], 10, 64)
		if (goLimit+2*pebble+memtablesMiB)*mib > capBytes {
			t.Errorf("Go soft limit %d MiB + Pebble C heap ~%d MiB exceeds memory.max %d MiB",
				goLimit, 2*pebble+memtablesMiB, capBytes/mib)
		}
		if !strings.Contains(out, "WARNING: -dbcache=8192 MiB does not fit") {
			t.Errorf("clamping -dbcache must be announced\n%s", out)
		}
	})

	// Control: no limit anywhere up the hierarchy leaves -dbcache untouched.
	t.Run("no_limit_control", func(t *testing.T) {
		out := startNodeUntilDBOpen(t, binary, fakeCgroupRoot(t, "max"), 8192)
		utxo, pebble := parseCacheSplit(t, out)
		if utxo != 6553 || pebble != 1638 {
			t.Errorf("without a cgroup limit -dbcache=8192 must split 6553/1638 MiB, got %d/%d\n%s", utxo, pebble, out)
		}
		if strings.Contains(out, "does not fit") {
			t.Errorf("clamped without a limit\n%s", out)
		}
	})
}

// fakeCgroupRoot lays out /proc/self/cgroup and a two-level cgroup v2 tree
// whose leaf has memory.max = leafMax and whose parent is unlimited.
func fakeCgroupRoot(t *testing.T, leafMax string) string {
	t.Helper()
	root := t.TempDir()
	leaf := filepath.Join(root, "sys/fs/cgroup/app.slice/node.service")
	for _, d := range []string{filepath.Join(root, "proc/self"), leaf} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "proc/self/cgroup"):                   "0::/app.slice/node.service\n",
		filepath.Join(root, "sys/fs/cgroup/app.slice/memory.max"): "max\n",
		filepath.Join(leaf, "memory.max"):                         leafMax + "\n",
	}
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startNodeUntilDBOpen runs a regtest node until it logs "Database opened",
// then kills it, returning everything it logged up to that line.
func startNodeUntilDBOpen(t *testing.T, binary, cgroupRoot string, dbcache int) string {
	t.Helper()
	cmd := exec.Command(binary,
		"-network=regtest", "-datadir="+t.TempDir(), "-nodnsseed",
		"-listen="+freeLoopbackPort(t), "-rpcbind="+freeLoopbackPort(t),
		"-dbcache="+strconv.Itoa(dbcache))
	cmd.Env = append(os.Environ(), "BLOCKBREW_CGROUP_FS_ROOT="+cgroupRoot, "GOMEMLIMIT=")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			b.WriteString(sc.Text() + "\n")
			if strings.Contains(sc.Text(), "Database opened") {
				break
			}
		}
		done <- b.String()
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("node did not open its database within 60s")
		return ""
	}
}

func parseCacheSplit(t *testing.T, out string) (utxoMiB, pebbleMiB int64) {
	t.Helper()
	m := regexp.MustCompile(`utxo_cache=(\d+) MiB, pebble_block_cache=(\d+) MiB`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no cache split in startup log\n%s", out)
	}
	utxoMiB, _ = strconv.ParseInt(m[1], 10, 64)
	pebbleMiB, _ = strconv.ParseInt(m[2], 10, 64)
	return
}
