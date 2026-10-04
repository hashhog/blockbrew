package storage

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// Close observability.
//
// On mainnet 2026-10-04 11:14Z (3369394) Close ran past the 20 s shutdown
// budget and the process exited with nothing logged about WHERE it waited: the
// per-step summary line is only printed when Close returns. Everything here is
// there so the next slow close says which step it is in and what Pebble's
// background work and the filesystem are doing, while it is still waiting.
//
// It is all read without pebble's DB.mu (pebble.Close holds DB.mu for most of
// its run, so DB.Metrics would block behind the very thing being observed):
// counters maintained from pebble's EventListener and from the FS wrapper, plus
// the step Close is currently in. None of it changes what Close does.

// bgWork counts pebble background work from its EventListener. FlushBegin is
// always paired with FlushEnd and CompactionBegin with CompactionEnd, error or
// not (pebble v1.1.5 compaction.go flush1 / compact1).
type bgWork struct {
	flushes       atomic.Int32
	compactions   atomic.Int32
	stallSince    atomic.Int64 // unix nanos; 0 = no write stall
	stallReason   atomic.Pointer[string]
	tablesDeleted atomic.Int64
}

func (w *bgWork) listener(onErr func(error)) *pebble.EventListener {
	return &pebble.EventListener{
		BackgroundError: onErr,
		FlushBegin:      func(pebble.FlushInfo) { w.flushes.Add(1) },
		FlushEnd:        func(pebble.FlushInfo) { w.flushes.Add(-1) },
		CompactionBegin: func(pebble.CompactionInfo) { w.compactions.Add(1) },
		CompactionEnd:   func(pebble.CompactionInfo) { w.compactions.Add(-1) },
		WriteStallBegin: func(info pebble.WriteStallBeginInfo) {
			r := info.Reason
			w.stallReason.Store(&r)
			w.stallSince.Store(time.Now().UnixNano())
		},
		WriteStallEnd: func() { w.stallSince.Store(0) },
		TableDeleted:  func(pebble.TableDeleteInfo) { w.tablesDeleted.Add(1) },
	}
}

// fsOpTracker records the filesystem calls that can block for a long time on a
// saturated disk (fsyncs, removes, renames, sstable creation) while they are in
// flight, plus running totals. Writes and reads are not tracked: they are too
// frequent and they are not where a close has been seen to wait.
type fsOpTracker struct {
	mu     sync.Mutex
	nextID uint64
	ops    map[uint64]fsOp

	syncs   atomic.Int64
	removes atomic.Int64
}

type fsOp struct {
	kind  string
	name  string
	start time.Time
}

func (t *fsOpTracker) begin(kind, name string) uint64 {
	t.mu.Lock()
	if t.ops == nil {
		t.ops = make(map[uint64]fsOp)
	}
	t.nextID++
	id := t.nextID
	t.ops[id] = fsOp{kind: kind, name: name, start: time.Now()}
	t.mu.Unlock()
	return id
}

func (t *fsOpTracker) end(id uint64) {
	t.mu.Lock()
	delete(t.ops, id)
	t.mu.Unlock()
}

// inFlight describes the tracked calls still running, oldest first.
func (t *fsOpTracker) inFlight(max int) string {
	t.mu.Lock()
	ops := make([]fsOp, 0, len(t.ops))
	for _, op := range t.ops {
		ops = append(ops, op)
	}
	t.mu.Unlock()
	if len(ops) == 0 {
		return "none"
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].start.Before(ops[j].start) })
	var b strings.Builder
	for i, op := range ops {
		if i == max {
			fmt.Fprintf(&b, " (+%d more)", len(ops)-max)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %s %s", op.kind, shortName(op.name), time.Since(op.start).Round(time.Millisecond))
	}
	return b.String()
}

func shortName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// trackedFile reports the fsyncs of a non-sstable file (WAL, MANIFEST, OPTIONS,
// markers, directories) to the tracker. Everything else passes through.
type trackedFile struct {
	vfs.File
	name string
	t    *fsOpTracker
}

func (f *trackedFile) Sync() error {
	defer f.t.end(f.t.begin("fsync", f.name))
	f.t.syncs.Add(1)
	return f.File.Sync()
}

func (f *trackedFile) SyncData() error {
	defer f.t.end(f.t.begin("fdatasync", f.name))
	f.t.syncs.Add(1)
	return f.File.SyncData()
}

func (f *trackedFile) SyncTo(length int64) (bool, error) {
	defer f.t.end(f.t.begin("syncto", f.name))
	f.t.syncs.Add(1)
	return f.File.SyncTo(length)
}

// closeTrace is the step Close is in. Each step is logged when it starts and
// when it ends, with its own elapsed time and the time since Close began.
type closeTrace struct {
	start time.Time
	cur   atomic.Pointer[closeStep]
	done  atomic.Bool
}

type closeStep struct {
	name  string
	start time.Time
}

func (c *closeTrace) begin(name string) {
	c.cur.Store(&closeStep{name: name, start: time.Now()})
	log.Printf("storage: close: %s: started (close +%s)", name, time.Since(c.start).Round(time.Millisecond))
}

func (c *closeTrace) end(note string) {
	s := c.cur.Load()
	if s == nil {
		return
	}
	if note != "" {
		note = "; " + note
	}
	log.Printf("storage: close: %s: done in %s (close +%s)%s", s.name,
		time.Since(s.start).Round(time.Millisecond), time.Since(c.start).Round(time.Millisecond), note)
}

// closeProgressInterval is how often a close that has not returned logs where
// it is. A var so tests can shorten it.
var closeProgressInterval = 5 * time.Second

// backgroundState is a one-line view of pebble's background work and the
// filesystem, readable while pebble.Close holds DB.mu.
func (p *PebbleDB) backgroundState() string {
	stall := "no"
	if since := p.bgWork().stallSince.Load(); since != 0 {
		reason := ""
		if r := p.bgWork().stallReason.Load(); r != nil {
			reason = " (" + *r + ")"
		}
		stall = fmt.Sprintf("for %s%s", time.Since(time.Unix(0, since)).Round(time.Millisecond), reason)
	}
	var refused int64
	if p.fs != nil {
		refused = p.fs.refused.Load()
	}
	s := fmt.Sprintf("flushes running=%d compactions running=%d write stall=%s sstable ops refused=%d",
		p.bgWork().flushes.Load(), p.bgWork().compactions.Load(), stall, refused)
	if p.cache != nil {
		// pebble.Close evicts every cached block of every table one by one
		// (tableCache.close -> removeDB -> Cache.EvictFile, C.free per block):
		// on a scratch tip clone after 3 h uptime that was ~14 s of a 16.75 s
		// close. The count drains while that runs. Cache.Metrics takes only
		// the cache's shard locks, not DB.mu.
		m := p.cache.Metrics()
		s += fmt.Sprintf(" block cache=%d blocks/%d MiB", m.Count, m.Size>>20)
	}
	if base := p.closeBase.Load(); base != nil {
		s += fmt.Sprintf(" since close: fsyncs=%d removes=%d tables deleted=%d",
			p.fs.ops.syncs.Load()-base.syncs, p.fs.ops.removes.Load()-base.removes,
			p.bgWork().tablesDeleted.Load()-base.tablesDeleted)
	}
	if p.fs != nil {
		s += "; in-flight fs ops: " + p.fs.ops.inFlight(8)
	}
	return s
}

// closeBaseline holds the counters as they were when Close began.
type closeBaseline struct {
	syncs, removes, tablesDeleted int64
}

// CloseStatus describes where a Close that has not returned is waiting. The
// daemon logs it when its close budget expires, before exiting without the
// close.
func (p *PebbleDB) CloseStatus() string {
	tr := p.closeTrace.Load()
	if tr == nil {
		return "storage: close not started; " + p.backgroundState()
	}
	if tr.done.Load() {
		return "storage: close finished"
	}
	step := "?"
	stepFor := time.Duration(0)
	if s := tr.cur.Load(); s != nil {
		step, stepFor = s.name, time.Since(s.start)
	}
	return fmt.Sprintf("storage: close: in step %q for %s (close +%s); %s", step,
		stepFor.Round(time.Millisecond), time.Since(tr.start).Round(time.Millisecond), p.backgroundState())
}

// reportProgress logs CloseStatus every closeProgressInterval until stop is
// closed.
func (p *PebbleDB) reportProgress(stop <-chan struct{}) {
	t := time.NewTicker(closeProgressInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			log.Printf("%s (still running)", p.CloseStatus())
		}
	}
}
