package storage

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/vfs"
)

// syncLog captures the standard logger for one test.
type syncLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLog(t *testing.T) *syncLog {
	t.Helper()
	l := &syncLog{}
	prev := log.Writer()
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(prev) })
	return l
}

// assertInOrder fails unless every want appears in out, in order.
func assertInOrder(t *testing.T, out string, wants ...string) {
	t.Helper()
	pos := 0
	for _, w := range wants {
		i := strings.Index(out[pos:], w)
		if i < 0 {
			t.Fatalf("log is missing %q (in order) after offset %d:\n%s", w, pos, out)
		}
		pos += i + len(w)
	}
}

// Mainnet 2026-10-04: a close ran past the shutdown budget and the log said
// only "closing DB" -> "did not finish within 20s", because Close logged its
// steps only once it returned. Every step must now say when it starts and when
// it ends.
func TestCloseLogsEveryStepStartAndEnd(t *testing.T) {
	out := captureLog(t)
	db, err := NewPebbleDB(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	// A NoSync write after the last synced batch: the WAL sync is needed.
	if err := db.Put([]byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	assertInOrder(t, out.String(),
		"storage: close: begin; flushes running=",
		" block cache=",
		"storage: close: write gate (wait for in-flight reads/writes): started",
		"storage: close: write gate (wait for in-flight reads/writes): done in",
		"storage: close: WAL sync decision: needed (1 unsynced write(s)",
		"storage: close: WAL sync: started",
		"storage: close: WAL sync: done in",
		"storage: close: abandon background work: started",
		"storage: close: abandon background work: done in",
		"compaction slots 0, sstable writes refused;",
		"storage: close: pebble.Close: started",
		"storage: close: pebble.Close: done in",
		"err=<nil>; flushes running=0 compactions running=0",
		"since close: fsyncs=",
		"pebble close",
		"storage: close: block cache free: started",
		"storage: close: block cache free: done in",
	)
	if got := db.CloseStatus(); got != "storage: close finished" {
		t.Fatalf("CloseStatus after Close = %q", got)
	}
}

func TestCloseLogsASkippedWALSync(t *testing.T) {
	out := captureLog(t)
	db, err := NewPebbleDB(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	b := db.NewBatch()
	b.Put([]byte("k"), []byte("v"))
	if err := b.Write(); err != nil { // synced
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	assertInOrder(t, s, "WAL sync decision: skipped", "abandon background work: started", "pebble.Close: done in")
	if strings.Contains(s, "WAL sync: started") {
		t.Fatalf("a synced WAL was synced again:\n%s", s)
	}
}

// A close that does not return must say where it is waiting, repeatedly, while
// it waits. An operation still inside the DB holds the write gate, so Close
// waits in its first step.
func TestCloseProgressNamesTheStepItIsStuckIn(t *testing.T) {
	out := captureLog(t)
	prev := closeProgressInterval
	closeProgressInterval = 30 * time.Millisecond
	t.Cleanup(func() { closeProgressInterval = prev })

	db, err := NewPebbleDB(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.CloseStatus(); !strings.HasPrefix(got, "storage: close not started;") {
		t.Fatalf("CloseStatus before Close = %q", got)
	}
	if err := db.enter(); err != nil { // an in-flight operation
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- db.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "(still running)") {
		if time.Now().After(deadline) {
			t.Fatalf("no progress line while Close was stuck:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := db.CloseStatus()
	if !strings.Contains(st, `in step "write gate (wait for in-flight reads/writes)"`) {
		t.Fatalf("CloseStatus does not name the stuck step: %q", st)
	}
	if runtime.GOOS == "linux" && (!strings.Contains(st, " process swap=") || !strings.Contains(st, " major faults=")) {
		t.Fatalf("CloseStatus does not report process swap / major faults since close: %q", st)
	}
	if !strings.Contains(out.String(), `in step "write gate (wait for in-flight reads/writes)"`) ||
		!strings.Contains(out.String(), "(still running)") {
		t.Fatalf("progress log does not name the stuck step:\n%s", out.String())
	}
	select {
	case err := <-done:
		t.Fatalf("Close returned (%v) while an operation was in flight", err)
	default:
	}

	db.liveMu.RUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The progress reporter stops with Close.
	n := strings.Count(out.String(), "(still running)")
	time.Sleep(100 * time.Millisecond)
	if m := strings.Count(out.String(), "(still running)"); m != n {
		t.Fatalf("progress reporter kept logging after Close returned (%d -> %d)", n, m)
	}
}

// The background-work counters must agree with pebble's own metrics.
func TestCloseStatusSeesARunningCompaction(t *testing.T) {
	dir := t.TempDir()
	db, _ := openCloseTestDB(t, dir, 20*time.Millisecond)
	fillUntilCompacting(t, db)
	st := db.CloseStatus()
	if strings.Contains(st, "compactions running=0") {
		t.Fatalf("pebble reports %d compaction(s) in progress but CloseStatus says none: %q",
			db.db.Metrics().Compact.NumInProgress, st)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// After Close every begin has been matched by an end.
	if f, c := db.bg.flushes.Load(), db.bg.compactions.Load(); f != 0 || c != 0 {
		t.Fatalf("after Close: flushes=%d compactions=%d, want 0 0", f, c)
	}
}

// blockingWALFS makes fsyncs of WAL files block while armed (the previous
// root cause: Close's WAL sync waiting behind other fsyncs on a saturated
// disk).
type blockingWALFS struct {
	vfs.FS
	mu      sync.Mutex
	release chan struct{}
}

func (fs *blockingWALFS) arm() chan struct{} {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.release = make(chan struct{})
	return fs.release
}

func (fs *blockingWALFS) gate() {
	fs.mu.Lock()
	ch := fs.release
	fs.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (fs *blockingWALFS) wrap(name string, f vfs.File, err error) (vfs.File, error) {
	if err != nil || !strings.HasSuffix(name, ".log") {
		return f, err
	}
	return &blockingWALFile{File: f, fs: fs}, nil
}

func (fs *blockingWALFS) Create(name string) (vfs.File, error) {
	f, err := fs.FS.Create(name)
	return fs.wrap(name, f, err)
}

func (fs *blockingWALFS) ReuseForWrite(o, n string) (vfs.File, error) {
	f, err := fs.FS.ReuseForWrite(o, n)
	return fs.wrap(n, f, err)
}

type blockingWALFile struct {
	vfs.File
	fs *blockingWALFS
}

func (f *blockingWALFile) Sync() error { f.fs.gate(); return f.File.Sync() }

func (f *blockingWALFile) SyncData() error { f.fs.gate(); return f.File.SyncData() }

func (f *blockingWALFile) SyncTo(n int64) (bool, error) { f.fs.gate(); return f.File.SyncTo(n) }

// A WAL fsync that does not return shows up, by file name, in the in-flight
// filesystem ops that CloseStatus reports.
func TestCloseStatusShowsAnInFlightWALFsync(t *testing.T) {
	bfs := &blockingWALFS{FS: vfs.Default}
	cfg := DefaultPebbleDBConfig()
	cfg.BlockCacheSize = 8 << 20
	cfg.MemTableSize = 4 << 20
	cfg.fs = bfs
	db, err := NewPebbleDBWithConfig(filepath.Join(t.TempDir(), "db"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	release := bfs.arm()
	done := make(chan error, 1)
	go func() {
		b := db.NewBatch()
		b.Put([]byte("k"), []byte("v"))
		done <- b.Write() // synced: waits in the WAL fsync
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := db.CloseStatus()
		if strings.Contains(st, ".log ") && strings.Contains(st, "sync") {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("a blocked WAL fsync is not reported: %q", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := db.fs.ops.inFlight(8); got != "none" {
		t.Fatalf("in-flight ops after Close: %s", got)
	}
}

// The block-cache figure must reflect a populated cache: the close cost
// observed on the 3 h scratch clone was pebble.Close evicting it block by
// block, so a constant 0 here would hide exactly that.
func TestCloseStatusReportsAPopulatedBlockCache(t *testing.T) {
	db, err := NewPebbleDB(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b := db.NewBatch()
	for i := 0; i < 2000; i++ {
		b.Put(closeTestKey(i), closeTestVal(i))
	}
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if err := db.db.Flush(); err != nil { // into sstables, so reads go through the block cache
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := db.Get(closeTestKey(i)); err != nil {
			t.Fatal(err)
		}
	}
	m := db.cache.Metrics()
	if m.Count == 0 {
		t.Fatal("test setup: block cache still empty after reading 2000 flushed keys")
	}
	st := db.CloseStatus()
	want := fmt.Sprintf(" block cache=%d blocks/", m.Count)
	if !strings.Contains(st, want) {
		t.Fatalf("CloseStatus %q does not report the cache's %d blocks", st, m.Count)
	}
}

// procSwapAndMajflt must actually parse /proc on Linux (a silent ok=false
// would drop the paging evidence from every close line).
func TestProcSwapAndMajfltReadsProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux /proc only")
	}
	swap, majflt, ok := procSwapAndMajflt()
	if !ok {
		t.Fatal("procSwapAndMajflt: not ok on linux")
	}
	if swap < 0 || majflt < 0 {
		t.Fatalf("swap=%d majflt=%d", swap, majflt)
	}
	// Cross-check majflt against /proc/self/stat read independently.
	st, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(st[strings.LastIndexByte(string(st), ')')+1:]))
	later, err := strconv.ParseInt(f[9], 10, 64)
	if err != nil || later < majflt {
		t.Fatalf("majflt %d disagrees with a later /proc/self/stat field 12 %q (err %v)", majflt, f[9], err)
	}
}
