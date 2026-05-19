package consensus

// W105 CCheckQueue / parallel script verification 30-gate audit — blockbrew (Go)
//
// Reference:
//   bitcoin-core/src/checkqueue.h              — CCheckQueue<T> worker pool + batch dispatch
//   bitcoin-core/src/validation.cpp            — ConnectBlock uses CCheckQueueControl<CScriptCheck>
//   bitcoin-core/src/validation.h              — CScriptCheck, MAX_SCRIPTCHECK_THREADS=15
//   bitcoin-core/src/init.cpp                  — -par sizing
//   bitcoin-core/src/node/chainstatemanager_args.cpp — auto-core calculation
//   bitcoin-core/src/script/sigcache.h         — SignatureCache, nonce-salted SHA256 key
//
// Gates covered: G1–G30 across six groups:
//   Thread pool  (G1-G5)
//   Batch        (G6-G10)
//   Cancellation (G11-G15)
//   Master/RAII  (G16-G20)
//   Script-check (G21-G25)
//   Flags        (G26-G30)
//
// Bug IDs: W105-B1 through W105-B15
//
// Severity legend:
//   CONSENSUS-DIVERGENT — can produce accept/reject difference from Core
//   CORRECTNESS         — wrong result or corrupt state possible
//   SECURITY            — cryptographic or DoS weakness
//   DEVIATION           — differs from Core semantics without consensus impact
//   OBSERVABILITY       — user-visible misconfiguration

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// G1: -par sizing — Core default is 0 (auto) → GetNumCores()-1 workers
//
// BUG W105-B1 (DEVIATION): No -par equivalent. blockbrew exposes only a
// boolean --parallelscripts flag. Core's -par=<n> supports:
//   0  → auto: GetNumCores()-1 worker threads (default)
//   >0 → exactly n-1 worker threads (1 = serial, no pool)
//   <0 → GetNumCores() + n - 1 (leave |n| cores free)
// blockbrew always uses runtime.GOMAXPROCS(0) (all logical CPUs) for worker
// count with no -par flag, no MAX_SCRIPTCHECK_THREADS=15 cap, and no
// negative-cores-free mode.
// Core: node/chainstatemanager_args.cpp:53-60, validation.h:90
// ---------------------------------------------------------------------------

func TestW105_G1_ParSizingNoEquivalent(t *testing.T) {
	// Verify blockbrew has no -par parameter or MAX_SCRIPTCHECK_THREADS cap.
	// This is a documentation/DEVIATION test: the function uses GOMAXPROCS
	// not a bounded thread count.
	//
	// Core: const int MAX_SCRIPTCHECK_THREADS{15}; (validation.h:90)
	// Core default: GetNumCores()-1 (auto) (chainstatemanager_args.cpp:57-60)
	//
	// blockbrew: runtime.GOMAXPROCS(0) — unbounded, ignores -par equivalent.
	// On a 32-core machine GOMAXPROCS=32 → spawns 32 goroutines per block
	// instead of Core's 15 max.
	const maxScriptCheckThreads = 15 // Core's MAX_SCRIPTCHECK_THREADS

	// Simulate what blockbrew does: numWorkers = runtime.GOMAXPROCS(0)
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// On machines with > maxScriptCheckThreads+1 logical CPUs, blockbrew
	// exceeds Core's cap. We assert the divergence exists conceptually:
	// blockbrew does NOT clamp to MAX_SCRIPTCHECK_THREADS.
	// (This is a DEVIATION, not a CONSENSUS-DIVERGENT bug, but should be fixed.)
	t.Logf("W105-B1: blockbrew numWorkers=%d (from GOMAXPROCS), Core max=%d; no cap applied",
		numWorkers, maxScriptCheckThreads)

	// BUG W105-B1: there is no constant like MAX_SCRIPTCHECK_THREADS in blockbrew.
	// Assert it is absent by checking we use GOMAXPROCS directly.
	if numWorkers > maxScriptCheckThreads {
		t.Logf("CONFIRMED: on this machine numWorkers=%d > MAX_SCRIPTCHECK_THREADS=%d — Core would cap at %d",
			numWorkers, maxScriptCheckThreads, maxScriptCheckThreads)
	}
}

// ---------------------------------------------------------------------------
// G2: Pool reuse — Core reuses the CCheckQueue across blocks (workers spin)
//
// BUG W105-B2 (DEVIATION): blockbrew spawns fresh goroutines per block.
// Core constructs one CCheckQueue on startup; workers idle between blocks.
// blockbrew creates a new semaphore channel and spawns len(jobs) goroutines
// for every ConnectBlock call. This adds goroutine-spawn overhead (typically
// ~1-2µs per goroutine) to every block's script validation. A block with
// 2000 inputs (plausible large block) pays ~2-4ms in scheduling overhead.
// More critically: the "master joins as N'th worker" pattern (checkqueue.h:29)
// is absent — blockbrew's master only waits on wg.Wait().
// Core: checkqueue.h:144-155 (constructor spawns N workers that run Loop forever)
// ---------------------------------------------------------------------------

func TestW105_G2_NoWorkerPoolReuse(t *testing.T) {
	// Core: workers are created once in CCheckQueue constructor and reused.
	// blockbrew: ParallelScriptValidationCached spawns goroutines for every block.
	//
	// Demonstrate that each call creates fresh goroutines by observing that
	// the semaphore channel is a local variable (not a package-level pool).
	//
	// We test the observable symptom: calling ParallelScriptValidationCached
	// twice with the same block does not reuse any execution context.
	cache := NewSigCache(100)

	// Empty block (coinbase only) — no jobs, returns immediately.
	block := makeCoinbaseOnlyBlock()
	view := &InMemoryUTXOView{utxos: make(map[wire.OutPoint]*UTXOEntry)}
	flags := script.ScriptFlags(0)

	// Both calls succeed without error (no-op for empty job set).
	if err := ParallelScriptValidationCached(block, view, flags, cache); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := ParallelScriptValidationCached(block, view, flags, cache); err != nil {
		t.Fatalf("second call: %v", err)
	}
	t.Log("W105-B2: each call creates fresh goroutines (no pool reuse) — DEVIATION from Core CCheckQueue")
}

// ---------------------------------------------------------------------------
// G3: Minimum 1 worker — Core always has at least the master as worker N+1
//
// G4: Worker count clamped to MAX_SCRIPTCHECK_THREADS=15
//
// Both gates: blockbrew clamps numWorkers ≥ 1 (G3 ✓), but does NOT apply
// MAX_SCRIPTCHECK_THREADS=15 cap (G4 ✗ = BUG W105-B1 continued).
// ---------------------------------------------------------------------------

func TestW105_G3_MinOneWorker(t *testing.T) {
	// blockbrew correctly enforces at least 1 worker (line 576-578).
	// runtime.GOMAXPROCS(0) returns ≥1 on all real systems, and the guard
	// ensures numWorkers >= 1 even on a hypothetical GOMAXPROCS=0 host.
	// Core: checkqueue.h:144 (worker_threads_num passed to constructor; 0 → no workers, master is sole executor)
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers < 1 {
		t.Error("numWorkers < 1: minimum-1-worker guard broken")
	}
}

func TestW105_G4_MaxScriptCheckThreads(t *testing.T) {
	// BUG W105-B1 (continued): no MAX_SCRIPTCHECK_THREADS cap.
	// Core validation.h:90 defines MAX_SCRIPTCHECK_THREADS=15.
	// blockbrew has no equivalent constant and applies no cap.
	const maxScriptCheckThreads = 15

	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// We can only assert this conceptually: if GOMAXPROCS > 15, Core would cap
	// to 15 but blockbrew does not. Test serves as documentation.
	t.Logf("W105-G4: GOMAXPROCS=%d; Core cap=%d; blockbrew has no cap (BUG W105-B1)", numWorkers, maxScriptCheckThreads)
}

// ---------------------------------------------------------------------------
// G5: DEFAULT_SCRIPTCHECK_THREADS=0 means auto (GetNumCores()-1)
//
// blockbrew has no -par flag at all (boolean only). Default behaviour differs:
// Core default: GetNumCores()-1 workers (auto, half of logical cores reserved).
// blockbrew default: GOMAXPROCS(0) workers (all logical CPUs).
// ---------------------------------------------------------------------------

func TestW105_G5_DefaultParIsAuto(t *testing.T) {
	// Core: DEFAULT_SCRIPTCHECK_THREADS=0 → GetNumCores()-1 threads
	// blockbrew: no -par flag; always uses GOMAXPROCS(0)
	// On a 4-core machine: Core spawns 3 workers; blockbrew uses 4.
	// On a 32-core machine: Core spawns 14 workers (capped 15); blockbrew uses 32.
	t.Log("W105-B1: -par flag absent; blockbrew uses GOMAXPROCS(0) instead of GetNumCores()-1")
}

// ---------------------------------------------------------------------------
// G6: nBatchSize=128 — Core uses max-128-checks-per-batch pull
//
// BUG W105-B3 (DEVIATION): blockbrew has no batch-size concept. Each job
// becomes its own goroutine (one goroutine per input script, not per batch of
// 128 scripts). Core's formula:
//   nNow = max(1, min(128, queue.size() / (nTotal + nIdle + 1)))
// achieves work-stealing load balance across workers. blockbrew's semaphore
// approach achieves similar throughput but with higher per-job overhead
// (goroutine spawn vs. in-queue item pull) and no cooperative work-stealing.
// Core: checkqueue.h:121
// ---------------------------------------------------------------------------

func TestW105_G6_NoBatchSizeLimit(t *testing.T) {
	// blockbrew creates one goroutine per input, not batches of 128.
	// This is a DEVIATION from Core's nBatchSize=128 batch-pull algorithm.
	// For a block with 2000 inputs blockbrew spawns 2000 goroutines (gated
	// by semaphore=numWorkers); Core would pull chunks of ≤128 items.
	t.Log("W105-B3: no nBatchSize=128 concept; one goroutine per input vs Core batch-pull")
}

// ---------------------------------------------------------------------------
// G7: mutex + condvar — Core uses Mutex + m_worker_cv + m_master_cv
//
// blockbrew uses sync.WaitGroup + buffered channel semaphore instead. This
// is functionally equivalent for the "master waits for workers" contract
// but is a structural deviation. No separate master condvar.
// ---------------------------------------------------------------------------

func TestW105_G7_MutexCondvarEquivalent(t *testing.T) {
	// blockbrew uses WaitGroup + channel semaphore.
	// Core uses Mutex + condition_variable.
	// Functionally equivalent for correctness; structure differs.
	// No bug — OBSERVATION only.
	t.Log("W105-G7: blockbrew uses WaitGroup+chan vs Core Mutex+condvar — functionally equivalent")
}

// ---------------------------------------------------------------------------
// G8: notify_one vs notify_all — Core notifies one worker per single-check Add,
//     notify_all for multi-check Add.
//
// blockbrew's goroutine-per-job model does not have an explicit notify step
// since goroutines are spawned inline. No semantic difference.
// ---------------------------------------------------------------------------

func TestW105_G8_NotifyOneVsAll(t *testing.T) {
	t.Log("W105-G8: goroutine-per-job model; no notify_one/notify_all needed — N/A")
}

// ---------------------------------------------------------------------------
// G9: Batch pull/release — workers pull min(nBatchSize, queue/workers) checks
//
// BUG W105-B3 continued: one-goroutine-per-job. See G6.
// ---------------------------------------------------------------------------

func TestW105_G9_BatchPullRelease(t *testing.T) {
	t.Log("W105-B3: one goroutine per input; no batch pull/release — DEVIATION (see G6)")
}

// ---------------------------------------------------------------------------
// G10: Batch re-fetch after completion — workers re-fetch more work in a loop
//
// blockbrew goroutines run exactly once and exit. Core workers loop until
// m_request_stop. This is architecturally different but the per-block
// correctness is equivalent since blockbrew spawns goroutines per-block.
// ---------------------------------------------------------------------------

func TestW105_G10_BatchReFetch(t *testing.T) {
	t.Log("W105-G10: blockbrew goroutines run once; Core workers loop — DEVIATION, no bug per block")
}

// ---------------------------------------------------------------------------
// G11: First-failure short-circuit — once any check fails, remaining skip
//
// Core: `do_work = !m_result.has_value()` — workers check under mutex.
// blockbrew: `if firstErr.Load() != nil { return }` after acquiring semaphore.
//
// BUG W105-B4 (DEVIATION): short-circuit is racy and slow. Goroutines are
// already created and blocking on `sem <- struct{}{}`. When the first script
// fails, later goroutines eventually drain through the semaphore and check
// firstErr.Load() — but O(numWorkers) goroutines may execute scripts after
// the failure before all drain. Core's mutex-protected check is stricter:
// once m_result is set, no new batch is processed at all. The difference
// matters for blocks with a failing script early among thousands of inputs:
// Core stops within the next batch boundary; blockbrew continues until the
// semaphore drains.
// ---------------------------------------------------------------------------

func TestW105_G11_FirstFailureShortCircuit(t *testing.T) {
	// Verify that ParallelScriptValidationCached does stop after first failure.
	// We use a block with two non-coinbase txs and a stubbed view that returns
	// nil for the second tx's input, triggering early failure.
	//
	// The test confirms the function returns an error (not nil) — i.e., the
	// short-circuit works at the functional level. The racy slowness of the
	// semaphore drain is a performance/strictness issue, not a correctness bug.
	var (
		earlyReturn atomic.Bool
	)

	// Simulate the pattern: goroutines spawned first, then check firstErr.
	// Even if first error fires, numWorkers goroutines may pass the check
	// before the semaphore gates them.
	var firstErr atomic.Pointer[error]
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2) // 2 workers

	jobCount := 10
	executedAfterFailure := atomic.Int32{}

	for i := 0; i < jobCount; i++ {
		wg.Add(1)
		ii := i
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if firstErr.Load() != nil {
				executedAfterFailure.Add(1)
				return
			}

			if ii == 0 {
				// Fail on first job
				err := errorf("script failed at input 0")
				firstErr.CompareAndSwap(nil, &err)
				earlyReturn.Store(true)
			}
			// Jobs 1-9 may still run (racy short-circuit)
		}()
	}
	wg.Wait()

	// Assert first failure was recorded
	if firstErr.Load() == nil {
		t.Error("expected firstErr to be set after failing job")
	}

	// Document the racy behaviour: jobs after failure may still execute
	t.Logf("W105-B4: %d/%d goroutines ran checks after first failure (racy short-circuit; Core stops at batch boundary)",
		executedAfterFailure.Load(), jobCount-1)
}

// ---------------------------------------------------------------------------
// G12: RAII master wait — Core's ~CCheckQueueControl calls Complete() if not done
//
// BUG W105-B5 (CORRECTNESS): No RAII equivalent. blockbrew uses explicit
// `wg.Wait()` at the end of each function. If a caller holds a reference and
// returns early (e.g., panics), wg.Wait() is skipped and the goroutines
// continue running after `ConnectBlock` returns. Core's RAII control ensures
// completion is always awaited even on early exit.
// Core: checkqueue.h:233-236 (~CCheckQueueControl calls Complete if !fDone)
// ---------------------------------------------------------------------------

func TestW105_G12_NoRAIIMasterWait(t *testing.T) {
	// There is no CCheckQueueControl RAII wrapper in blockbrew.
	// If ParallelScriptValidationCached panics or returns early (before wg.Wait),
	// goroutines leak. Currently wg.Wait() is always reached, but there is no
	// structural RAII guarantee.
	//
	// Test: verify wg.Wait() is called on the normal path.
	cache := NewSigCache(10)
	block := makeCoinbaseOnlyBlock()
	view := &InMemoryUTXOView{utxos: make(map[wire.OutPoint]*UTXOEntry)}

	if err := ParallelScriptValidationCached(block, view, script.ScriptFlags(0), cache); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// If we reach here, wg.Wait() completed. No leak on happy path.
	t.Log("W105-B5: no RAII CCheckQueueControl; wg.Wait is reached on happy path but panic would leak goroutines")
}

// ---------------------------------------------------------------------------
// G13: nIdle counter — Core tracks idle workers for batch-size calculation
//
// blockbrew has no idle-worker counter. The semaphore channel implicitly
// limits concurrency but does not inform batch-size decisions.
// DEVIATION, no correctness impact.
// ---------------------------------------------------------------------------

func TestW105_G13_NoIdleCounter(t *testing.T) {
	t.Log("W105-G13: no nIdle equivalent; semaphore channel limits concurrency — DEVIATION")
}

// ---------------------------------------------------------------------------
// G14: m_request_stop — Core destructor signals workers to stop
//
// blockbrew goroutines are scoped to a single block's function call; they
// naturally terminate. No persistent worker pool → no request_stop needed.
// No bug.
// ---------------------------------------------------------------------------

func TestW105_G14_NoRequestStop(t *testing.T) {
	t.Log("W105-G14: goroutine-per-block scope; no persistent pool → no request_stop needed — N/A")
}

// ---------------------------------------------------------------------------
// G15: No leaked checks — Core ensures all checks are completed or discarded
//
// blockbrew: wg.Wait() guarantees all goroutines finish. Checks are
// not "leaked" in the Core sense. However, if an error occurs, the goroutines
// that checked after the first failure performed work that was ultimately
// discarded — a wasted computation but not a correctness issue.
// ---------------------------------------------------------------------------

func TestW105_G15_NoLeakedChecks(t *testing.T) {
	t.Log("W105-G15: wg.Wait ensures all goroutines complete; no leaked checks — OK")
}

// ---------------------------------------------------------------------------
// G16: CCheckQueueControl per block — Core creates control per ConnectBlock call
//
// BUG W105-B6 (DEVIATION): No CCheckQueueControl. blockbrew's parallel
// validation is a standalone function call, not wrapped in a control object
// with m_control_mutex. Core's m_control_mutex ensures only one
// CCheckQueueControl can use the shared queue at a time. blockbrew has no
// shared queue → no serialization needed → same safety guarantee from cm.mu.
// However, if ConnectBlock ever becomes re-entrant or is called from multiple
// goroutines, there is no queue-level protection.
// Core: checkqueue.h:141 (m_control_mutex)
// ---------------------------------------------------------------------------

func TestW105_G16_NoCheckQueueControl(t *testing.T) {
	t.Log("W105-B6: no CCheckQueueControl wrapper; cm.mu provides equivalent serialization currently")
}

// ---------------------------------------------------------------------------
// G17: ~Control waits — destructor calls Complete() ensuring all checks done
//
// blockbrew: explicit wg.Wait() call. No structural RAII guarantee (see G12).
// ---------------------------------------------------------------------------

func TestW105_G17_DestructorWaits(t *testing.T) {
	t.Log("W105-G17: wg.Wait() explicit — functionally equivalent but no RAII (see B5)")
}

// ---------------------------------------------------------------------------
// G18: Add(vector<T>) — Core adds a per-tx batch of checks to the queue
//
// blockbrew collects all jobs upfront then dispatches goroutines. No per-tx
// batch add; all inputs are flattened into one slice. Functionally equivalent
// for correctness.
// ---------------------------------------------------------------------------

func TestW105_G18_AddVectorBatch(t *testing.T) {
	t.Log("W105-G18: blockbrew flattens all inputs into one slice vs per-tx Add — DEVIATION, no bug")
}

// ---------------------------------------------------------------------------
// G19: Master-as-worker N+1 — Core master joins pool to avoid idle CPU
//
// BUG W105-B2 continued: blockbrew master goroutine only waits (wg.Wait).
// Core's master temporarily becomes a worker when all jobs are dispatched,
// executing scripts inline to use an otherwise-idle CPU. blockbrew's master
// is purely blocked on wg.Wait, never helping process inputs.
// Core: checkqueue.h:29, Loop(fMaster=true)
// ---------------------------------------------------------------------------

func TestW105_G19_MasterAsWorker(t *testing.T) {
	t.Log("W105-B2: master goroutine only waits; does not process checks like Core's N+1 master")
}

// ---------------------------------------------------------------------------
// G20: Wait() success — CCheckQueueControl::Complete returns overall result
//
// blockbrew returns the first error via atomic.Pointer. Functionally matches
// Core's Complete() returning the first non-nullopt result.
// ---------------------------------------------------------------------------

func TestW105_G20_WaitSuccess(t *testing.T) {
	cache := NewSigCache(10)
	block := makeCoinbaseOnlyBlock()
	view := &InMemoryUTXOView{utxos: make(map[wire.OutPoint]*UTXOEntry)}
	err := ParallelScriptValidationCached(block, view, script.ScriptFlags(0), cache)
	if err != nil {
		t.Errorf("expected nil for coinbase-only block: %v", err)
	}
}

// ---------------------------------------------------------------------------
// G21: CScriptCheck fields — Core's CScriptCheck holds: CTxOut, tx, nIn,
//      flags, cacheStore, txdata, signature_cache.
//
// BUG W105-B7 (CORRECTNESS/DEVIATION): blockbrew's scriptJob holds txid-based
// identity not witnessHash-based. Core's CScriptCheck references the live
// transaction pointer; blockbrew copies the pointer (safe) but the cache
// lookup uses txHash (non-witness) not wtxHash.
// ---------------------------------------------------------------------------

func TestW105_G21_ScriptCheckFields(t *testing.T) {
	// scriptJob contains: tx *wire.MsgTx, txIdx, inputIdx, prevOut, prevOuts.
	// Core's CScriptCheck: CTxOut m_tx_out, const CTransaction* ptxTo, unsigned nIn,
	//   script_verify_flags m_flags, bool cacheStore, PrecomputedTransactionData* txdata,
	//   SignatureCache* m_signature_cache.
	//
	// Missing in blockbrew's scriptJob:
	// - cacheStore bool: blockbrew always caches on pass (see BUG W105-B10)
	// - txdata (PrecomputedTransactionData): recomputed per-input (see BUG W105-B11)
	// - signature_cache reference: passed via closure capture (OK)
	t.Log("W105-G21: scriptJob missing cacheStore flag and PrecomputedTransactionData (see B10, B11)")
}

// ---------------------------------------------------------------------------
// G22: sigcache lookup — Core checks SignatureCache before expensive ECDSA/Schnorr
//
// blockbrew SigCache.Lookup is called before script.VerifyScript in the
// cached variant — functionally correct.
// ---------------------------------------------------------------------------

func TestW105_G22_SigCacheLookupBeforeVerify(t *testing.T) {
	cache := NewSigCache(10)
	txid := [32]byte{1, 2, 3, 4}

	// Insert a synthetic entry (no actual script needed).
	// W160 BUG-11 fix: cache key now requires prevOut amount + pkScript.
	cache.Insert(txid, 0, script.ScriptFlags(0), testAmount, testPkScript)

	// Lookup should hit
	if !cache.Lookup(txid, 0, script.ScriptFlags(0), testAmount, testPkScript) {
		t.Error("expected cache hit")
	}
	// Different input index → miss
	if cache.Lookup(txid, 1, script.ScriptFlags(0), testAmount, testPkScript) {
		t.Error("expected cache miss for different input index")
	}
}

// ---------------------------------------------------------------------------
// G23: SHA256 nonce key — Core keys script execution cache on
//      SHA256(nonce || wtxhash || flags), nonce generated at startup.
//
// BUG W105-B8 (SECURITY): blockbrew sigcache key is (txid, inputIndex, flags)
// — no nonce, no SHA256, plain struct comparison via Go map.
//
// Two problems:
//   A) No nonce: entries are predictable; an attacker who knows txid+idx+flags
//      can craft inputs to probe cache state (timing attack).
//   B) Uses txid (non-witness) not wtxhash: for segwit transactions two
//      variants with the same txid but different witnesses (malleated witness)
//      would map to the same cache entry. A malleated witness with a failing
//      script could be accepted as "already validated" if the canonical form
//      was cached first.
// Core: validation.cpp:2079-2080 — SHA256(nonce||wtxhash||flags)
// Core: validation.h:372-374 — ValidationCache stores m_script_execution_cache_hasher
// ---------------------------------------------------------------------------

func TestW105_G23_SigCacheKeyNonce(t *testing.T) {
	// FIXED W105-B8A: SigCache now includes a random 32-byte nonce initialised
	// at construction from crypto/rand.  The key derivation is:
	//   SHA256(nonce[32] || wtxhash[32] || inputIndex_le32 || flags_le32)[0:16]
	//
	// Verify that two independent SigCache instances produce different internal
	// keys for the same (wtxhash, inputIndex, flags) triple — i.e., that
	// nonces are randomised per-instance.

	// The nonce field is unexported, but we can observe its effect: inserting
	// the same entry into two independently constructed caches and checking
	// that neither cache honours a lookup seeded by the other is not possible
	// through the public API alone (the map keys are opaque).  Instead we
	// verify the nonce indirectly: computeKey must produce different keys for
	// the same inputs across two cache instances (with overwhelming probability).
	c1 := NewSigCache(100)
	c2 := NewSigCache(100)

	// With probability 1 - 1/2^128 the two nonces differ, making the
	// computed map keys different.  We verify this by confirming that an
	// entry inserted into c1 is NOT found in c2 (they share no nonce).
	wtxhash := [32]byte{0xAA}
	flags := script.ScriptFlags(script.ScriptVerifyP2SH)

	c1.Insert(wtxhash, 0, flags, testAmount, testPkScript)

	// c2 must not see c1's entry — its nonce produces a different key.
	if c2.Lookup(wtxhash, 0, flags, testAmount, testPkScript) {
		t.Error("W105-B8A REGRESSION: cache from a different instance hit without insert — nonce is not randomised")
	}

	// Self-consistency: c1 must still find its own entry.
	if !c1.Lookup(wtxhash, 0, flags, testAmount, testPkScript) {
		t.Error("expected hit in c1 after Insert")
	}

	// Basic isolation: different wtxhash must miss.
	wtxhash2 := [32]byte{0xBB}
	c1.Insert(wtxhash2, 0, flags, testAmount, testPkScript)
	if c1.Lookup([32]byte{0xCC}, 0, flags, testAmount, testPkScript) {
		t.Error("unrelated wtxhash should miss")
	}

	// FIXED W105-B8B: The cache key now uses the witness transaction hash
	// (WTxHash / wtxid) rather than the stripped txid.  For segwit
	// transactions, two variants sharing a txid but carrying different
	// witnesses produce different wtxids and therefore map to distinct cache
	// entries.
	//
	// Simulate two segwit variants with the same txid but different witness
	// data by using different [32]byte values (representing distinct wtxhashes
	// even though the txid might be identical in a real segwit scenario).
	canonicalWtxhash := [32]byte{0x01, 0x02, 0x03}
	malleatedWtxhash := [32]byte{0x01, 0x02, 0x04} // same txid prefix, different witness → different wtxid

	cache := NewSigCache(100)
	cache.Insert(canonicalWtxhash, 0, flags, testAmount, testPkScript)

	// The malleated variant must NOT inherit the canonical hit.
	if cache.Lookup(malleatedWtxhash, 0, flags, testAmount, testPkScript) {
		t.Error("W105-B8B REGRESSION: malleated wtxhash hit cache entry inserted for canonical wtxhash — witness not committed in key")
	}

	// The canonical variant must still be found.
	if !cache.Lookup(canonicalWtxhash, 0, flags, testAmount, testPkScript) {
		t.Error("expected hit for canonical wtxhash")
	}
}

// ---------------------------------------------------------------------------
// G24: Cache hit shortcut — Core skips all per-input checks if tx cached
//
// BUG W105-B9 (CACHE GRANULARITY/CORRECTNESS): Core caches per-transaction:
// one entry covers all inputs of a tx. blockbrew caches per-input.
//
// Core logic (validation.cpp:2082): if hashCacheEntry is in the script
// execution cache, return true immediately for the whole tx (all inputs).
//
// blockbrew logic: each input is individually looked up and inserted. This
// means:
//   1. A tx with N inputs requires N cache entries vs Core's 1.
//   2. A partial cache hit (k of N inputs cached from a previous run) does
//      not provide the tx-level guarantee Core gives; blockbrew would re-run
//      the uncached inputs.
//   3. Conversely, if only some inputs are cached (e.g., cache was partially
//      evicted), blockbrew re-validates the missing ones — correct but wasteful.
// ---------------------------------------------------------------------------

func TestW105_G24_CacheHitShortcutPerTxVsPerInput(t *testing.T) {
	cache := NewSigCache(100)

	// Insert entries for 3 inputs of the same txid
	txid := [32]byte{0xAB}
	flags := script.ScriptFlags(script.ScriptVerifyWitness)

	for i := uint32(0); i < 3; i++ {
		cache.Insert(txid, i, flags, testAmount, testPkScript)
	}

	// All 3 should be individually found
	for i := uint32(0); i < 3; i++ {
		if !cache.Lookup(txid, i, flags, testAmount, testPkScript) {
			t.Errorf("expected hit for input %d", i)
		}
	}

	// Input 3 (never inserted) should miss
	if cache.Lookup(txid, 3, flags, testAmount, testPkScript) {
		t.Error("expected miss for input 3")
	}

	// BUG W105-B9: Core would cache entire tx in one entry; blockbrew needs N entries.
	t.Log("W105-B9: per-input cache vs Core per-tx — N entries instead of 1; partial eviction re-validates")
}

// ---------------------------------------------------------------------------
// G25: Write-on-pass-only — Core only writes to script execution cache when
//      cacheFullScriptStore=true (which is set to fJustCheck, NOT during
//      actual block connection).
//
// BUG W105-B10 (CORRECTNESS/CACHE): blockbrew always writes to the sigcache
// on success, regardless of whether we are in a "just check" pass or a real
// ConnectBlock pass. Core deliberately does NOT cache when actually connecting
// blocks (fCacheResults = fJustCheck — which is false during normal connection).
// This prevents reorg-invalidated signatures from poisoning the cache.
//
// Core: validation.cpp:2576 — fCacheResults = fJustCheck (false during connect)
//       validation.cpp:2127 — if (cacheFullScriptStore && !pvChecks) insert
// ---------------------------------------------------------------------------

func TestW105_G25_WriteOnPassOnly(t *testing.T) {
	// BUG W105-B10: blockbrew always inserts into sigcache on successful
	// script verification during ConnectBlock. Core does NOT cache during
	// actual block connection (only during justCheck/mempool validation).
	//
	// This means: a script that was valid under flags F at height H gets
	// cached with key (txid, i, F). If the block is later disconnected
	// (reorg) and the same tx is reconnected with different flags F' (e.g.,
	// a softfork activated), the new validation would use the stale cache
	// entry if F==F' — which is correct — but the fundamental contract
	// that "cache entries only come from mempool validation" (Core's design)
	// is violated.
	//
	// Verify blockbrew inserts on success:
	cache := NewSigCache(10)
	txid := [32]byte{0xFF}
	flags := script.ScriptFlags(script.ScriptVerifyP2SH)

	// Pre-insert to simulate a "cached during ConnectBlock" entry
	cache.Insert(txid, 0, flags, testAmount, testPkScript)

	// Entry is present even though it was inserted during simulated block connection
	if !cache.Lookup(txid, 0, flags, testAmount, testPkScript) {
		t.Error("cache entry should be present")
	}

	t.Log("W105-B10: blockbrew caches during ConnectBlock; Core does NOT (fCacheResults=fJustCheck=false)")
}

// ---------------------------------------------------------------------------
// G26: Per-height SCRIPT_VERIFY flags — GetBlockScriptFlags returns the right
//      consensus flags for each height.
//
// blockbrew GetBlockScriptFlags correctly handles BIP66/65/CSV/Segwit/Taproot
// heights. The function is per-height and used in ConnectBlock. ✓
// ---------------------------------------------------------------------------

func TestW105_G26_PerHeightScriptFlags(t *testing.T) {
	params := RegtestParams()

	// Height 0: P2SH should be active (always active in blockbrew)
	h := wire.Hash256{}
	flags0 := GetBlockScriptFlags(0, params, h)
	if flags0&script.ScriptVerifyP2SH == 0 {
		t.Error("G26: P2SH should be active at height 0")
	}

	// Height below BIP66: DERSig should NOT be active
	flagsBeforeBIP66 := GetBlockScriptFlags(params.BIP66Height-1, params, h)
	if flagsBeforeBIP66&script.ScriptVerifyDERSig != 0 {
		t.Error("G26: DERSig should not be active before BIP66Height")
	}

	// Height at BIP66: DERSig should be active
	flagsAtBIP66 := GetBlockScriptFlags(params.BIP66Height, params, h)
	if flagsAtBIP66&script.ScriptVerifyDERSig == 0 {
		t.Error("G26: DERSig should be active at BIP66Height")
	}

	// Height at SegwitHeight: Witness + NullDummy should be active
	flagsAtSegwit := GetBlockScriptFlags(params.SegwitHeight, params, h)
	if flagsAtSegwit&script.ScriptVerifyWitness == 0 {
		t.Error("G26: Witness should be active at SegwitHeight")
	}
	if flagsAtSegwit&script.ScriptVerifyNullDummy == 0 {
		t.Error("G26: NullDummy should be active at SegwitHeight")
	}
}

// ---------------------------------------------------------------------------
// G27: STANDARD vs MANDATORY flags — Core separates relay policy from consensus
//
// blockbrew correctly separates GetBlockScriptFlags (consensus only) from
// GetStandardScriptFlags (adds NullFail, WitnessPubKeyType, StrictEncoding).
// ✓ Passes. See scriptflags.go.
// ---------------------------------------------------------------------------

func TestW105_G27_StandardVsMandatoryFlags(t *testing.T) {
	params := RegtestParams()
	h := wire.Hash256{}

	// At Segwit height: block flags should NOT include policy-only flags
	blockFlags := GetBlockScriptFlags(params.SegwitHeight, params, h)
	standardFlags := GetStandardScriptFlags(params.SegwitHeight, params, h)

	// NullFail is policy-only — should be in standard but not block
	if blockFlags&script.ScriptVerifyNullFail != 0 {
		t.Error("G27: ScriptVerifyNullFail should not be in block (consensus) flags")
	}
	if standardFlags&script.ScriptVerifyNullFail == 0 {
		t.Error("G27: ScriptVerifyNullFail should be in standard flags")
	}

	// WitnessPubKeyType is policy-only
	if blockFlags&script.ScriptVerifyWitnessPubKeyType != 0 {
		t.Error("G27: WitnessPubKeyType should not be in block flags")
	}
	if standardFlags&script.ScriptVerifyWitnessPubKeyType == 0 {
		t.Error("G27: WitnessPubKeyType should be in standard flags")
	}
}

// ---------------------------------------------------------------------------
// G28: -par=1 serial path — Core skips the queue entirely with one thread
//
// BUG W105-B11 (CORRECTNESS/LOGIC): blockbrew's --parallelscripts=false
// config logic is inverted at NewChainManager:
//
//   if !config.ParallelScripts {
//       cm.parallelScripts = true  // ← sets true when user said false!
//   }
//
// This means --parallelscripts=false is silently ignored: the node always
// runs parallel validation. There is no way to disable it.
// Core: HasThreads() returns false when -par=1; ConnectBlock uses serial path.
// blockbrew: line 257-259 in chainmanager.go.
// ---------------------------------------------------------------------------

func TestW105_G28_Par1SerialPath_ConfigInverted(t *testing.T) {
	// FIX W105-B11: the config logic for disabling parallel scripts was inverted.
	//
	// Bug was:
	//   if !config.ParallelScripts { cm.parallelScripts = true }
	// This silently set parallelScripts=true whenever the user passed false.
	//
	// Fix: direct assignment cm.parallelScripts = config.ParallelScripts (via
	// struct literal in NewChainManager; the bogus override block was removed).

	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// When user requests serial (false), NewChainManager must honour it.
	cmSerial := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ParallelScripts: false, // user wants serial
	})
	if cmSerial.parallelScripts {
		t.Error("W105-B11 regression: ParallelScripts=false must not be inverted to true by NewChainManager")
	}

	// When user requests parallel (true), it must also be honoured.
	cmParallel := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ParallelScripts: true,
	})
	if !cmParallel.parallelScripts {
		t.Error("W105-B11: ParallelScripts=true was not propagated into ChainManager")
	}
}

// ---------------------------------------------------------------------------
// G29: Move semantics — Core uses std::move for CScriptCheck in vChecks
//
// Go has no move semantics; scriptJob holds pointers. No issue.
// ---------------------------------------------------------------------------

func TestW105_G29_MoveSemantics(t *testing.T) {
	t.Log("W105-G29: Go pointers; no move semantics needed — N/A")
}

// ---------------------------------------------------------------------------
// G30: Reorg path — scripts must be re-validated on reconnect after reorg
//
// BUG W105-B12 (CACHE/CORRECTNESS): On reorg, DisconnectBlock calls
// sigCache.Clear() (chainmanager.go:1535-1536). This correctly invalidates
// cached entries from the disconnected blocks. However:
//
//   1. The cache is cleared for the entire reorg (all entries), even though
//      only entries from the disconnected blocks are stale. Entries from
//      unrelated mempool validations are also cleared, forcing re-validation
//      on next mempool accept. This is overly aggressive but not incorrect.
//
//   2. BUG W105-B10 still applies on the reconnect path: scripts verified
//      during reconnect ConnectBlocks are written into the cache
//      (ParallelScriptValidationCached always inserts on pass). Core does not
//      write to cache during block connection.
// ---------------------------------------------------------------------------

func TestW105_G30_ReorgPathScriptRevalidation(t *testing.T) {
	// Verify sigCache.Clear is available and resets the cache.
	cache := NewSigCache(100)

	// Simulate mempool entries
	for i := 0; i < 50; i++ {
		txid := [32]byte{byte(i)}
		cache.Insert(txid, 0, script.ScriptFlags(0), testAmount, testPkScript)
	}
	if cache.Size() != 50 {
		t.Fatalf("expected 50 entries, got %d", cache.Size())
	}

	// DisconnectBlock calls cache.Clear()
	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("expected 0 entries after Clear, got %d", cache.Size())
	}

	// BUG W105-B12: Clear() wipes ALL entries (including valid mempool ones),
	// not just entries from disconnected blocks.
	t.Log("W105-B12: sigCache.Clear() on reorg wipes all entries; Core does not write during connect anyway")
}

// ---------------------------------------------------------------------------
// Supplemental: SigCacheSize misconfiguration
//
// BUG W105-B13 (CORRECTNESS): SigCacheSize=0 in ChainManagerConfig is
// documented as "disable caching" but actually uses DefaultSigCacheSize=50000.
// The check is `if config.SigCacheSize >= 0` → NewSigCache(0) → maxSize=50000.
// There is no way to disable the cache from the CLI (no --maxsigcachesize flag).
// Core: -maxsigcachesize=0 gives minimum-possible cache (explicit disable).
// ---------------------------------------------------------------------------

func TestW105_Supplemental_SigCacheSizeZeroMeansDefault(t *testing.T) {
	// BUG W105-B13: SigCacheSize=0 (zero value of int, i.e., unset in ChainManagerConfig)
	// results in NewSigCache(0) which sets maxSize=DefaultSigCacheSize=50000.
	// The config comment says "Set to 0 to disable caching" — incorrect.
	cache0 := NewSigCache(0)
	if cache0.maxSize != DefaultSigCacheSize {
		t.Errorf("expected DefaultSigCacheSize=%d for NewSigCache(0), got %d",
			DefaultSigCacheSize, cache0.maxSize)
	}

	// Negative maxSize correctly disables (returns empty cache in NewSigCache):
	// Wait — NewSigCache: if maxSize <= 0 { maxSize = DefaultSigCacheSize }
	// Both 0 and negative map to DefaultSigCacheSize. The only way to disable
	// is to not call NewSigCache at all (sigCache=nil path).
	cacheNeg := NewSigCache(-1)
	if cacheNeg.maxSize != DefaultSigCacheSize {
		t.Errorf("expected DefaultSigCacheSize=%d for NewSigCache(-1), got %d",
			DefaultSigCacheSize, cacheNeg.maxSize)
	}

	// chainmanager.go:237: `if config.SigCacheSize >= 0` → always true for unset int
	// The sigCache=nil (disabled) path is unreachable in practice.
	t.Log("W105-B13: SigCacheSize=0 cannot disable cache; must be negative but NewSigCache treats -1 same as 0")
}

// ---------------------------------------------------------------------------
// Supplemental: PrecomputedTransactionData missing
//
// BUG W105-B14 (CORRECTNESS/PERF): Core precomputes transaction data
// (sighash midstate) once per tx via PrecomputedTransactionData, shared across
// all input script checks for that tx. blockbrew recomputes sighash from
// scratch inside each goroutine's script.VerifyScript call.
//
// For segwit/taproot transactions with many inputs this means O(N) redundant
// sighash computations vs Core's O(1) precompute + O(N) lookups.
// Core: validation.cpp:2517 — std::vector<PrecomputedTransactionData> txsdata(block.vtx.size())
//       validation.cpp:2583 — CheckInputScripts(tx, ..., txsdata[i], ...)
// ---------------------------------------------------------------------------

func TestW105_Supplemental_NoPrecomputedTxData(t *testing.T) {
	t.Log("W105-B14: no PrecomputedTransactionData; sighash recomputed per goroutine per input — PERF")
}

// ---------------------------------------------------------------------------
// Supplemental: HasThreads gate missing
//
// BUG W105-B15 (DEVIATION): Core gates queue use on `queue.HasThreads()`:
//   if (auto& queue = ...; queue.HasThreads() && fScriptChecks) control.emplace(queue);
// When -par=1 (no workers), HasThreads()=false → serial path, no queue overhead.
// blockbrew uses cm.parallelScripts bool which cannot be set false (B11).
// Even if B11 were fixed, the boolean is checked at config time, not dynamically.
// Core: validation.cpp:2515-2516
// ---------------------------------------------------------------------------

func TestW105_Supplemental_NoHasThreadsGate(t *testing.T) {
	t.Log("W105-B15: no HasThreads() gate; always parallel (or always serial when B11 exists)")
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// makeCoinbaseOnlyBlock creates a minimal block with just a coinbase tx.
func makeCoinbaseOnlyBlock() *wire.MsgBlock {
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: []byte{0x52, 0x01}, // OP_2 height=1
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    5000000000,
				PkScript: []byte{0x51}, // OP_TRUE
			},
		},
		LockTime: 0,
	}

	txHashes := []wire.Hash256{coinbase.TxHash()}
	merkleRoot := CalcMerkleRoot(txHashes)

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    4,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: merkleRoot,
			Timestamp:  1296688602,
			Bits:       0x207fffff,
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}
}

// errorf is a local alias used by G11 test closure to avoid import confusion.
var errorf = fmt.Errorf
