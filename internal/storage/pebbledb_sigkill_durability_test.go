package storage

// SIGKILL durability battery for the Pebble chainstate layer.
//
// Background: receipts/GEN-BREW-pebble-corruption-sigkill.md recorded a mainnet
// blockbrew whose pebble chaindata became unopenable after repeated SIGKILLs —
// "file NNNNNN (type 2) unknown to the objstorage provider: file does not exist"
// across L3/L4/L5 (the MANIFEST referenced sstables absent on disk). The leading
// (unproven) hypothesis was that blockbrew's reduced-durability config
// (Put/Delete use pebble.NoSync, WAL synced per-1MB) let a SIGKILL during a
// FLUSH/COMPACTION leave the manifest referencing sstables whose bytes were not
// yet durable.
//
// The node-level regtest crash harness (test-suite/test_crash_recovery.py) can
// NOT reproduce this: 110 tiny regtest blocks stay entirely inside the 128MB
// memtable + WAL, so no sstable is ever written and no flush/compaction runs.
//
// This test hammers the exact suspect pipeline directly against the production
// storage layer:
//   - a live child process opens a Pebble DB with production durability
//     semantics (NoSync data writes like PebbleDB.Put, periodic pebble.Sync
//     checkpoint batches like the chainstate flush batch) and writes continuously
//     so many real memtable flushes and L0->L1+ compactions are in flight;
//   - the parent SIGKILLs the child at a randomized moment (biased to land
//     during flush/compaction);
//   - the parent reopens the DB and asserts (a) pebble.Open SUCCEEDS with no
//     missing-sstable / manifest corruption, and (b) every key committed in a
//     durable Sync checkpoint batch is present and correct (no holes, no loss of
//     acknowledged-durable data). Tail keys written only via NoSync after the
//     last checkpoint MAY be lost — that is acceptable reduced durability, not
//     corruption.
//
// Run: go test ./internal/storage/ -run TestPebbleSigkillDurability -v
// The child arm is entered via BB_SIGKILL_CHILD in the same test binary.

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
)

const (
	sigkillChildEnv   = "BB_SIGKILL_CHILD"
	sigkillDirEnv     = "BB_SIGKILL_DIR"
	sigkillValSize    = 4096 // 4KB value -> a small memtable fills after a few hundred keys
	sigkillCkptEvery  = 250  // durable Sync checkpoint batch every N data keys
	sigkillMetaKeyPfx = "__ckpt__"
)

// stressOpts mirrors pebbledb.go's production Options (ZstdCompression, bloom(10),
// WALBytesPerSync=1MB, MemTableStopWritesThreshold=4, MaxConcurrentCompactions=4,
// L0 thresholds) but with a SMALL memtable + low L0 threshold so flushes and
// compactions happen constantly on a bounded dataset. The flush/compaction/
// manifest crash-consistency machinery under test is independent of memtable
// size; shrinking it just multiplies the number of crash windows per MB written.
func stressOpts() *pebble.Options {
	levelOpts := make([]pebble.LevelOptions, 7)
	for i := range levelOpts {
		levelOpts[i] = pebble.LevelOptions{
			Compression:    pebble.ZstdCompression,
			TargetFileSize: 2 * 1024 * 1024,
			FilterPolicy:   bloom.FilterPolicy(10),
		}
	}
	return &pebble.Options{
		MemTableSize:                1 * 1024 * 1024, // 1MB -> frequent flushes
		MemTableStopWritesThreshold: 4,
		Levels:                      levelOpts,
		MaxOpenFiles:                2000,
		WALBytesPerSync:             1024 * 1024, // production: sync WAL per 1MB
		L0CompactionThreshold:       2,           // compact aggressively -> many compactions
		L0StopWritesThreshold:       12,
		MaxConcurrentCompactions:    func() int { return 4 },
	}
}

func dataKey(i int) []byte  { return []byte(fmt.Sprintf("data-%012d", i)) }
func metaKey() []byte       { return []byte(sigkillMetaKeyPfx) }
func encodeCkpt(n int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(n))
	return b
}
func decodeCkpt(b []byte) int { return int(binary.LittleEndian.Uint64(b)) }

// deterministic value for key i so the parent can verify content, not just presence.
func valFor(i int) []byte {
	v := make([]byte, sigkillValSize)
	for j := range v {
		v[j] = byte((i + j) & 0xff)
	}
	return v
}

// runSigkillChild is the writer arm. It writes forever until SIGKILL'd:
//   - each data key via db.Set(..., pebble.NoSync)   (exactly PebbleDB.Put)
//   - every sigkillCkptEvery keys, a pebble.Sync batch that (re)writes the
//     checkpoint meta key = highest index whose durability is being acknowledged.
//     The Sync batch fsyncs the WAL, so after crash the meta key AND all data
//     keys <= it MUST survive. This models the chainstate Sync batch that
//     atomically advances the durable tip in chainmanager.go.
func runSigkillChild() {
	dir := os.Getenv(sigkillDirEnv)
	db, err := pebble.Open(dir, stressOpts())
	if err != nil {
		fmt.Fprintf(os.Stderr, "child open: %v\n", err)
		os.Exit(3)
	}
	// RESUME from the last durable checkpoint (models a node resuming IBD after a
	// crash). This makes the persisted checkpoint strictly grow across restarts,
	// so the parent's monotonic + no-hole invariants are meaningful over an
	// accumulating dataset rather than a per-run restart at 0.
	i := 0
	if mv, mcloser, merr := db.Get(metaKey()); merr == nil {
		i = decodeCkpt(mv) + 1
		mcloser.Close()
	}
	for {
		if err := db.Set(dataKey(i), valFor(i), pebble.NoSync); err != nil {
			fmt.Fprintf(os.Stderr, "child set: %v\n", err)
			os.Exit(4)
		}
		i++
		if i%sigkillCkptEvery == 0 {
			// Durable checkpoint: acknowledge that data keys [0, i-1] are committed.
			b := db.NewBatch()
			_ = b.Set(metaKey(), encodeCkpt(i-1), nil)
			if err := b.Commit(pebble.Sync); err != nil {
				fmt.Fprintf(os.Stderr, "child ckpt commit: %v\n", err)
				os.Exit(5)
			}
			_ = b.Close()
		}
	}
}

// verifyAfterCrash reopens the DB (this is the missing-sstable / manifest-
// corruption gate) and verifies all durably-checkpointed data survived intact.
func verifyAfterCrash(t *testing.T, dir string, iter int) (ckpt int, reopened bool) {
	t.Helper()
	// (a) Does pebble reopen? A missing-sstable / manifest corruption surfaces
	// here as an Open error ("file ... unknown to the objstorage provider").
	db, err := pebble.Open(dir, stressOpts())
	if err != nil {
		t.Errorf("iter %d: pebble.Open FAILED after SIGKILL (CORRUPTION): %v", iter, err)
		return -1, false
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("iter %d: Close after reopen: %v", iter, cerr)
		}
	}()

	// (b) Read the durable checkpoint.
	mv, mcloser, merr := db.Get(metaKey())
	if merr == pebble.ErrNotFound {
		// Crash before the very first checkpoint: nothing acknowledged durable.
		return -1, true
	}
	if merr != nil {
		t.Errorf("iter %d: get checkpoint meta: %v", iter, merr)
		return -1, true
	}
	c := decodeCkpt(mv)
	mcloser.Close()

	// (c) Every data key [0, c] committed under a Sync batch MUST be present and
	// byte-correct. A hole or a wrong value = durability/consistency failure.
	for i := 0; i <= c; i++ {
		v, closer, err := db.Get(dataKey(i))
		if err != nil {
			t.Errorf("iter %d: durable key %d MISSING after crash (ckpt=%d): %v", iter, i, c, err)
			return c, true
		}
		want := valFor(i)
		if len(v) != len(want) || string(v) != string(want) {
			closer.Close()
			t.Errorf("iter %d: durable key %d CORRUPT value after crash", iter, i)
			return c, true
		}
		closer.Close()
	}
	return c, true
}

func TestPebbleSigkillDurability(t *testing.T) {
	// Child arm: run the writer and block until the parent SIGKILLs us.
	if os.Getenv(sigkillChildEnv) == "1" {
		runSigkillChild()
		return // unreachable
	}

	if testing.Short() {
		t.Skip("skipping SIGKILL durability battery in -short")
	}

	// Number of crash iterations; each reuses the SAME datadir so, like the
	// mainnet incident, corruption can ACCUMULATE across repeated SIGKILLs
	// (the receipt's key observation: 1 tolerated missing sstable -> 6+ fatal).
	iters := 12
	if s := os.Getenv("BB_SIGKILL_ITERS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			iters = n
		}
	}

	dir := t.TempDir()
	// A spread of kill delays so SIGKILL lands in different phases: early
	// (first memtable filling, pre-flush), mid (steady flush+compaction), and
	// later (multiple L0->L1 compactions in flight).
	delays := []time.Duration{
		120 * time.Millisecond,
		300 * time.Millisecond,
		600 * time.Millisecond,
		900 * time.Millisecond,
		1400 * time.Millisecond,
	}

	prevCkpt := -1
	for iter := 0; iter < iters; iter++ {
		delay := delays[iter%len(delays)]

		cmd := exec.Command(os.Args[0], "-test.run", "TestPebbleSigkillDurability")
		cmd.Env = append(os.Environ(),
			sigkillChildEnv+"=1",
			sigkillDirEnv+"="+dir,
		)
		// New process group so SIGKILL to -pid can't escape; capture child stderr.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		var childErr []byte
		stderrR, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			t.Fatalf("iter %d: start child: %v", iter, err)
		}
		go func() { childErr, _ = readAll(stderrR) }()

		time.Sleep(delay)
		// Hard crash — no Close, no flush, mid-flight flushes/compactions.
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("iter %d: SIGKILL child: %v", iter, err)
		}
		state, _ := cmd.Process.Wait()
		// Confirm it actually died to a signal (not a clean/early exit that would
		// invalidate the "killed mid-write" premise).
		if ws, ok := state.Sys().(syscall.WaitStatus); ok {
			if !ws.Signaled() {
				// Child exited on its own — surface its stderr; likely an open/write error.
				t.Fatalf("iter %d: child exited code=%d not via signal; stderr=%s",
					iter, ws.ExitStatus(), string(childErr))
			}
		}

		ckpt, reopened := verifyAfterCrash(t, dir, iter)
		if !reopened {
			// Corruption: stop, we cannot continue on a dead DB. Preserve the dir.
			keep := filepath.Join(os.TempDir(), fmt.Sprintf("bb-sigkill-corrupt-%d", os.Getpid()))
			_ = os.Rename(dir, keep)
			t.Fatalf("iter %d: DB unopenable after SIGKILL; datadir preserved at %s", iter, keep)
		}
		// Durable checkpoint must be monotonic non-decreasing across restarts
		// (a reopen that lost acknowledged-durable data would regress it).
		if ckpt >= 0 && ckpt < prevCkpt {
			t.Errorf("iter %d: durable checkpoint REGRESSED %d -> %d after crash (durable data lost)",
				iter, prevCkpt, ckpt)
		}
		if ckpt > prevCkpt {
			prevCkpt = ckpt
		}
		t.Logf("iter %d: delay=%v reopened OK, durable_ckpt=%d (highest_durable_key=%d)",
			iter, delay, ckpt, ckpt)
	}
	t.Logf("SURVIVED %d SIGKILL cycles on one datadir; final durable checkpoint key=%d", iters, prevCkpt)
}

// readAll is a tiny io.ReadAll to avoid importing io just for the child-stderr read.
func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}
