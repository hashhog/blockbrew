package storage

// Close under a running compaction (gate 5, 2026-10-02): pebble.DB.Close waits
// for every in-flight compaction and flush, and on mainnet's I/O-saturated disk
// that wait took 30 s and then >51 s, past the daemon's 80 s shutdown deadline.
//
// slowSSTFS reproduces the saturated disk for sstable writes only, so a
// compaction takes seconds while the WAL and MANIFEST stay fast.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/vfs"
)

type slowSSTFS struct {
	vfs.FS
	delay  time.Duration
	writes atomic.Int64
}

func (fs *slowSSTFS) Create(name string) (vfs.File, error) {
	f, err := fs.FS.Create(name)
	if err != nil || !strings.HasSuffix(name, ".sst") {
		return f, err
	}
	return &slowSSTFile{File: f, fs: fs}, nil
}

type slowSSTFile struct {
	vfs.File
	fs *slowSSTFS
}

func (f *slowSSTFile) Write(b []byte) (int, error) {
	f.fs.writes.Add(1)
	time.Sleep(f.fs.delay)
	return f.File.Write(b)
}

const (
	closeTestValSize = 4096
	closeTestKeys    = 12000 // ~49 MB of values
)

func closeTestKey(i int) []byte {
	k := make([]byte, 12)
	copy(k, "ck")
	// Spread keys so compactions overlap many files.
	binary.BigEndian.PutUint64(k[2:], uint64(i)*2654435761%1_000_003)
	binary.BigEndian.PutUint16(k[10:], uint16(i))
	return k
}

func closeTestVal(i int) []byte {
	v := make([]byte, closeTestValSize)
	binary.BigEndian.PutUint64(v, uint64(i))
	for j := 8; j < len(v); j++ {
		v[j] = byte(i*31 + j) // compressible but not trivially so
	}
	return v
}

// openCloseTestDB opens a PebbleDB whose sstable writes are slow, with a small
// memtable so data reaches L0 quickly and compactions start.
func openCloseTestDB(t testing.TB, dir string, delay time.Duration) (*PebbleDB, *slowSSTFS) {
	slow := &slowSSTFS{FS: vfs.Default, delay: delay}
	cfg := DefaultPebbleDBConfig()
	cfg.BlockCacheSize = 8 << 20
	cfg.MemTableSize = 4 << 20
	cfg.fs = slow
	cfg.l0CompactionThreshold = 2
	db, err := NewPebbleDBWithConfig(dir, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db, slow
}

// fillUntilCompacting writes closeTestKeys keys in synced batches (the
// chainstate flush's durability), the last 1000 with NoSync Put (undo data's
// durability), and returns once a compaction is running.
func fillUntilCompacting(t testing.TB, db *PebbleDB) {
	const perBatch = 250
	syncedEnd := closeTestKeys - 1000
	for i := 0; i < syncedEnd; i += perBatch {
		b := db.NewBatch()
		for j := i; j < i+perBatch && j < syncedEnd; j++ {
			b.Put(closeTestKey(j), closeTestVal(j))
		}
		if err := b.Write(); err != nil {
			t.Fatalf("batch: %v", err)
		}
	}
	for j := syncedEnd; j < closeTestKeys; j++ {
		if err := db.Put(closeTestKey(j), closeTestVal(j)); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	deadline := time.Now().Add(60 * time.Second)
	for db.db.Metrics().Compact.NumInProgress == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no compaction started")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func verifyCloseTestDB(t testing.TB, dir string) {
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	defer db.Close()
	for i := 0; i < closeTestKeys; i++ {
		v, err := db.Get(closeTestKey(i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if v == nil {
			t.Fatalf("key %d lost after close", i)
		}
		if binary.BigEndian.Uint64(v) != uint64(i) || len(v) != closeTestValSize {
			t.Fatalf("key %d has the wrong value", i)
		}
	}
}

// TestCloseDoesNotWaitForRunningCompaction: Close returns within a bound while
// a compaction is running on a slow disk, the compaction really was cut short,
// and every key (synced and NoSync) is there on reopen.
//
// Negative control: with Close's abandon step removed it waits for the
// compaction (tens of seconds at this disk speed) and the test fails.
func TestCloseDoesNotWaitForRunningCompaction(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~50 MB")
	}
	dir := t.TempDir()
	db, slow := openCloseTestDB(t, dir, 40*time.Millisecond)
	fillUntilCompacting(t, db)
	// Let the compaction get going on the slow disk.
	time.Sleep(300 * time.Millisecond)
	inProgress := db.db.Metrics().Compact.NumInProgress
	writesBefore := slow.writes.Load()

	start := time.Now()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	took := time.Since(start)
	t.Logf("compactions in progress at close=%d, Close took %s, sstable ops refused=%d, slow writes before close=%d",
		inProgress, took, db.fs.refused.Load(), writesBefore)

	const bound = 2 * time.Second
	if took > bound {
		t.Fatalf("Close took %s with a compaction running; want < %s", took, bound)
	}
	if db.fs.refused.Load() == 0 {
		t.Fatalf("no sstable write was refused: the compaction was not cut short, so this run did not test the abandon path")
	}
	verifyCloseTestDB(t, dir)
}

// Child arm for TestKillDuringCloseKeepsDBConsistent.
const closeKillChildEnv = "BB_CLOSE_KILL_CHILD"

func TestCloseKillChild(t *testing.T) {
	dir := os.Getenv(closeKillChildEnv)
	if dir == "" {
		t.Skip("child arm only")
	}
	db, _ := openCloseTestDB(t, dir, 20*time.Millisecond)
	fillUntilCompacting(t, db)
	time.Sleep(200 * time.Millisecond)
	db.closeStage = func(stage string) {
		fmt.Println(stage)
		os.Stdout.Sync()
	}
	_ = db.Close()
	fmt.Println("CLOSED")
	os.Stdout.Sync()
	time.Sleep(time.Hour) // the parent kills us
}

// TestKillDuringCloseKeepsDBConsistent SIGKILLs a process at random points
// inside Close (WAL sync, abandoning compactions, pebble's own close) and
// checks that the DB reopens with every key present.
func TestKillDuringCloseKeepsDBConsistent(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes writing ~50 MB each")
	}
	iters := 8
	if s := os.Getenv("BB_CLOSE_KILL_ITERS"); s != "" {
		iters, _ = strconv.Atoi(s)
	}
	rng := rand.New(rand.NewSource(4242))
	for it := 0; it < iters; it++ {
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run", "^TestCloseKillChild$", "-test.v")
		cmd.Env = append(os.Environ(), closeKillChildEnv+"="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		lines := make(chan string, 16)
		go func() {
			buf := make([]byte, 4096)
			var acc string
			for {
				n, err := out.Read(buf)
				acc += string(buf[:n])
				for {
					i := strings.IndexByte(acc, '\n')
					if i < 0 {
						break
					}
					lines <- acc[:i]
					acc = acc[i+1:]
				}
				if err != nil {
					close(lines)
					return
				}
			}
		}()
		waitFor := func(want string) bool {
			timeout := time.After(120 * time.Second)
			for {
				select {
				case l, ok := <-lines:
					if !ok {
						return false
					}
					if strings.TrimSpace(l) == want {
						return true
					}
				case <-timeout:
					return false
				}
			}
		}
		// Even iterations kill around the WAL sync, odd ones inside
		// pebble's own close while abandoned compactions unwind.
		stage := "begin"
		if it%2 == 1 {
			stage = "abandoned"
		}
		if !waitFor(stage) {
			_ = cmd.Process.Kill()
			t.Fatalf("iter %d: child never reached close stage %q", it, stage)
		}
		delay := time.Duration(rng.Intn(5000)) * time.Microsecond
		time.Sleep(delay)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()
		closed := false
		for l := range lines {
			if strings.TrimSpace(l) == "CLOSED" {
				closed = true
			}
		}
		t.Logf("iter %d: SIGKILL %s after close stage %q (Close had finished: %v)", it, delay, stage, closed)
		verifyCloseTestDB(t, dir)
	}
}

// The reopen in verifyCloseTestDB uses production options; make sure a DB
// closed the normal way (no compaction running) still round-trips and that
// abandon mode never touches the WAL or MANIFEST.
func TestCloseIdleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := db.Put(closeTestKey(i), closeTestVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := db.fs.refused.Load(); n != 0 {
		t.Fatalf("idle close refused %d sstable ops", n)
	}
	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	for i := 0; i < 100; i++ {
		v, _ := db2.Get(closeTestKey(i))
		if v == nil {
			t.Fatalf("NoSync key %d lost across a clean close", i)
		}
	}
}

// flushchainstate's Flush must not hang when Close abandons the flush it is
// waiting for: an abandoned flush never signals completion (its memtable
// stays in the WAL), so a plain pebble Flush would wait forever.
func TestFlushReturnsWhenCloseAbandonsIt(t *testing.T) {
	dir := t.TempDir()
	db, _ := openCloseTestDB(t, dir, 50*time.Millisecond)
	for i := 0; i < 900; i++ { // ~3.7 MB, under one memtable: no flush yet
		if err := db.Put(closeTestKey(i), closeTestVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	flushed := make(chan error, 1)
	go func() { flushed <- db.Flush() }()
	time.Sleep(300 * time.Millisecond) // the flush is now writing its sstable
	select {
	case err := <-flushed:
		t.Fatalf("flush finished before Close (err=%v): the disk is not slow enough for this test to mean anything", err)
	default:
	}
	start := time.Now()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-flushed:
		t.Logf("Flush returned %v; Close took %s", err, time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("Flush still waiting 5s after Close abandoned it")
	}
	if db.fs.refused.Load() == 0 {
		t.Fatal("the flush was not abandoned: this run did not test the abandon path")
	}
	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	for i := 0; i < 900; i++ {
		if v, _ := db2.Get(closeTestKey(i)); v == nil {
			t.Fatalf("key %d of the abandoned flush lost", i)
		}
	}
}

// TestAbandonedCompactionIsNotRescheduled: between abandon mode switching on
// and pebble's own Close marking the DB closed, a compaction that fails on the
// abandoned filesystem must not be replaced by a fresh one. pebble re-picks
// compaction work after every failure, so without the disarm (compactSlots ->
// 0) it starts compaction after compaction, each failing at its first sstable
// create, for as long as that window lasts. The window is normally a few
// milliseconds; the test holds it open for 500 ms so the difference is
// measurable.
//
// (A failed FLUSH is retried the same way and is not gated by
// MaxConcurrentCompactions; that loop is logged here but not asserted. It ends
// when pebble's Close marks the DB closed, and it costs CPU, not I/O.)
//
// Negative control: with the compactSlots.Store(0) line removed, the
// compaction count climbs during the hold and the test fails.
func TestAbandonedCompactionIsNotRescheduled(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~50 MB")
	}
	dir := t.TempDir()
	db, _ := openCloseTestDB(t, dir, 40*time.Millisecond)
	fillUntilCompacting(t, db)
	time.Sleep(300 * time.Millisecond)
	var c0, c1, f0, f1 int64
	var inProgress int
	db.closeStage = func(stage string) {
		if stage != "abandoned" {
			return
		}
		time.Sleep(50 * time.Millisecond) // running jobs hit the abandoned FS
		m0 := db.db.Metrics()
		time.Sleep(500 * time.Millisecond)
		m1 := db.db.Metrics()
		c0, c1 = m0.Compact.Count, m1.Compact.Count
		f0, f1 = m0.Flush.Count, m1.Flush.Count
		inProgress = int(m1.Compact.NumInProgress)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("during the 500ms hold: compactions %d->%d (in progress at end %d), flush attempts %d->%d, sstable ops refused total %d",
		c0, c1, inProgress, f0, f1, db.fs.refused.Load())
	if c1 > c0 || inProgress > 0 {
		t.Fatalf("compactions kept starting after abandon (%d->%d, %d in progress): failed compactions are being rescheduled", c0, c1, inProgress)
	}
	verifyCloseTestDB(t, dir)
}
