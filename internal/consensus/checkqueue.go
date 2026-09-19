package consensus

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// scriptCheckBatchSize is Core's CCheckQueue nBatchSize (checkqueue.h).
// Workers pull at most this many checks per grab so in-flight buffers stay
// bounded by batch × (extra workers + master), not by the job count.
const scriptCheckBatchSize = 128

// ResolveScriptCheckWorkers maps Bitcoin Core's -par to the number of extra
// worker goroutines (the connecting thread is the master and always joins).
//
// Core: node/chainstatemanager_args.cpp:53-60
//
//	par=0  → auto: NumCPU()-1 extra workers (master + extras == every core)
//	par=1  → serial: 0 extra workers
//	par=n>1 → n-1 extra workers
//	par=-n → NumCPU()-n-1 extra workers (leave |n| cores free)
//
// We do not apply Core's MAX_SCRIPTCHECK_THREADS=15 cap: the point of this
// change on a 32-core box is to use the cores. Extra workers still cannot
// go negative.
func ResolveScriptCheckWorkers(par int) int {
	cores := runtime.NumCPU()
	if cores < 1 {
		cores = 1
	}
	scriptThreads := par
	if scriptThreads <= 0 {
		scriptThreads += cores
	}
	extra := scriptThreads - 1
	if extra < 0 {
		extra = 0
	}
	return extra
}

// ScriptCheckJob is one input's script check. Core: CScriptCheck (validation.h).
// Workers write only the unexported err field of the job they claimed; the
// caller's slice is borrowed, never copied, so more workers cannot grow the
// buffer.
type ScriptCheckJob struct {
	Tx       *wire.MsgTx
	TxIdx    int
	InputIdx int
	PrevOut  *UTXOEntry
	PrevOuts []*wire.TxOut
	Flags    script.ScriptFlags
	Cache    *SigCache
	err      error
}

// BatchResult is the queue's verdict after every claimed job has finished.
// FirstFailIndex/FirstFailErr are the lowest-index failure so 1 worker and N
// report the same reason — a race-winner reason would be a chain-split bug
// under -par.
type BatchResult struct {
	OK             bool
	FirstFailIndex int
	FirstFailErr   error
}

// ScriptCheckQueue is a persistent CCheckQueue-style pool. Extra worker
// goroutines park between batches; the master (ConnectBlock thread) joins as
// worker N+1. One Run at a time (controlMu), matching Core's m_control_mutex.
type ScriptCheckQueue struct {
	mu           sync.Mutex
	controlMu    sync.Mutex
	workCond     *sync.Cond
	doneCond     *sync.Cond
	stopWg       sync.WaitGroup
	stopOnce     sync.Once
	extraWorkers int
	stop         bool
	generation   uint64
	workersDone  int
	jobs         []ScriptCheckJob
	next         atomic.Uint64
	inFlight     atomic.Int64
	maxInFlight  atomic.Int64
}

// NewScriptCheckQueue starts extraWorkers parked goroutines. extraWorkers=0
// is serial: the master thread runs every job (Core -par=1).
func NewScriptCheckQueue(extraWorkers int) *ScriptCheckQueue {
	if extraWorkers < 0 {
		extraWorkers = 0
	}
	q := &ScriptCheckQueue{extraWorkers: extraWorkers}
	q.workCond = sync.NewCond(&q.mu)
	q.doneCond = sync.NewCond(&q.mu)
	if extraWorkers > 0 {
		q.stopWg.Add(extraWorkers)
		for i := 0; i < extraWorkers; i++ {
			go q.workerLoop()
		}
	}
	return q
}

// ExtraWorkers is the number of additional goroutines (not counting the master).
func (q *ScriptCheckQueue) ExtraWorkers() int { return q.extraWorkers }

// HasThreads reports whether extra workers exist. Core: CCheckQueue::HasThreads.
func (q *ScriptCheckQueue) HasThreads() bool { return q.extraWorkers > 0 }

// MaxInFlight is the peak number of checks held by workers+master in one Run.
func (q *ScriptCheckQueue) MaxInFlight() int64 { return q.maxInFlight.Load() }

// jobSliceIs reports whether the queue is still borrowing jobs' backing array.
func (q *ScriptCheckQueue) jobSliceIs(jobs []ScriptCheckJob) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) != len(jobs) {
		return false
	}
	if len(jobs) == 0 {
		return true
	}
	return &q.jobs[0] == &jobs[0]
}

// Stop parks-and-joins the extra workers. Idempotent. Do not Run afterwards.
func (q *ScriptCheckQueue) Stop() {
	q.stopOnce.Do(func() {
		q.controlMu.Lock()
		defer q.controlMu.Unlock()
		q.mu.Lock()
		q.stop = true
		q.workCond.Broadcast()
		q.mu.Unlock()
		q.stopWg.Wait()
	})
}

// Run submits jobs and waits for every check. The calling goroutine joins as
// the master worker. The jobs slice is borrowed for the duration of the call.
func (q *ScriptCheckQueue) Run(jobs []ScriptCheckJob) BatchResult {
	q.controlMu.Lock()
	defer q.controlMu.Unlock()

	q.inFlight.Store(0)
	q.maxInFlight.Store(0)
	q.next.Store(0)
	for i := range jobs {
		jobs[i].err = nil
	}

	q.mu.Lock()
	q.jobs = jobs
	extra := q.extraWorkers
	if q.stop {
		extra = 0
	}
	if extra > 0 {
		q.workersDone = 0
		q.generation++
		q.workCond.Broadcast()
	}
	q.mu.Unlock()

	if len(jobs) == 0 {
		return BatchResult{OK: true, FirstFailIndex: -1}
	}

	q.processJobs(jobs)

	if extra > 0 {
		q.mu.Lock()
		for q.workersDone < extra && !q.stop {
			q.doneCond.Wait()
		}
		q.mu.Unlock()
	}

	for i := range jobs {
		if jobs[i].err != nil {
			return BatchResult{
				OK:             false,
				FirstFailIndex: i,
				FirstFailErr: fmt.Errorf("tx %d input %d: script failed: %w",
					jobs[i].TxIdx, jobs[i].InputIdx, jobs[i].err),
			}
		}
	}
	return BatchResult{OK: true, FirstFailIndex: -1}
}

func (q *ScriptCheckQueue) workerLoop() {
	defer q.stopWg.Done()
	var lastGen uint64
	for {
		q.mu.Lock()
		for !q.stop && q.generation == lastGen {
			q.workCond.Wait()
		}
		if q.stop {
			q.mu.Unlock()
			return
		}
		lastGen = q.generation
		jobs := q.jobs
		q.mu.Unlock()

		q.processJobs(jobs)

		q.mu.Lock()
		q.workersDone++
		if q.workersDone == q.extraWorkers {
			q.doneCond.Signal()
		}
		q.mu.Unlock()
	}
}

func (q *ScriptCheckQueue) processJobs(jobs []ScriptCheckJob) {
	n := uint64(len(jobs))
	if n == 0 {
		return
	}
	extra := uint64(q.extraWorkers)
	for {
		start := q.next.Load()
		if start >= n {
			return
		}
		remaining := n - start
		// Core checkqueue.h:121
		//   nNow = max(1, min(nBatchSize, queue.size() / (nTotal + nIdle + 1)))
		// nTotal = extra workers + master; nIdle is not tracked, so extra+2
		// matches the +1 in Core's denominator plus the master.
		denom := extra + 2
		nNow := remaining / denom
		if nNow < 1 {
			nNow = 1
		}
		if nNow > scriptCheckBatchSize {
			nNow = scriptCheckBatchSize
		}
		if nNow > remaining {
			nNow = remaining
		}
		got := q.next.Add(nNow)
		batchStart := got - nNow
		if batchStart >= n {
			return
		}
		batchEnd := got
		if batchEnd > n {
			batchEnd = n
		}
		inflight := int64(batchEnd - batchStart)
		cur := q.inFlight.Add(inflight)
		for {
			max := q.maxInFlight.Load()
			if cur <= max || q.maxInFlight.CompareAndSwap(max, cur) {
				break
			}
		}
		for i := batchStart; i < batchEnd; i++ {
			q.runOne(&jobs[i])
		}
		q.inFlight.Add(-inflight)
	}
}

func (q *ScriptCheckQueue) runOne(job *ScriptCheckJob) {
	if job.PrevOut == nil || job.Tx == nil || job.InputIdx < 0 || job.InputIdx >= len(job.Tx.TxIn) {
		job.err = fmt.Errorf("invalid script check")
		return
	}
	if job.Cache != nil {
		wtxhash := job.Tx.WTxHash()
		if job.Cache.Lookup(wtxhash, uint32(job.InputIdx), job.Flags, job.PrevOut.Amount, job.PrevOut.PkScript) {
			return
		}
	}
	err := script.VerifyScript(
		job.Tx.TxIn[job.InputIdx].SignatureScript,
		job.PrevOut.PkScript,
		job.Tx,
		job.InputIdx,
		job.Flags,
		job.PrevOut.Amount,
		job.PrevOuts,
	)
	if err != nil {
		job.err = err
		return
	}
	if job.Cache != nil {
		wtxhash := job.Tx.WTxHash()
		job.Cache.Insert(wtxhash, uint32(job.InputIdx), job.Flags, job.PrevOut.Amount, job.PrevOut.PkScript)
	}
}

// CollectScriptChecks builds one ScriptCheckJob per non-coinbase input.
// Missing prevouts fail before any worker runs — that is a missing-input
// consensus reject, not a script-eval race.
func CollectScriptChecks(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags, cache *SigCache) ([]ScriptCheckJob, error) {
	var jobs []ScriptCheckJob
	for txIdx, tx := range block.Transactions {
		if txIdx == 0 {
			continue
		}
		prevOuts := make([]*wire.TxOut, len(tx.TxIn))
		for i, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return nil, fmt.Errorf("missing UTXO for tx %d input %d: %s:%d",
					txIdx, i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			}
			prevOuts[i] = &wire.TxOut{
				Value:    utxo.Amount,
				PkScript: utxo.PkScript,
			}
		}
		for inputIdx, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return nil, fmt.Errorf("missing UTXO for tx %d input %d", txIdx, inputIdx)
			}
			jobs = append(jobs, ScriptCheckJob{
				Tx:       tx,
				TxIdx:    txIdx,
				InputIdx: inputIdx,
				PrevOut:  utxo,
				PrevOuts: prevOuts,
				Flags:    flags,
				Cache:    cache,
			})
		}
	}
	return jobs, nil
}
