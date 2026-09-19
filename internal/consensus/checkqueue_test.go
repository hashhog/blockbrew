package consensus

// Parallel script verification — QUEUES.md 2026-09-19 control.
//
// Bitcoin Core: -par (init.cpp:513), CCheckQueue (src/checkqueue.h),
// CScriptCheck batched per-input in ConnectBlock (validation.cpp).
// Extra workers drain a bounded job queue; the block is accepted only if
// every check returns true; the decision must not depend on how the work
// was split.
//
// REQUIRED:
//   (1) decision identity — accept/reject AND reject reason identical at
//       1 worker and at N
//   (2) failure propagation — one failing check rejects the whole batch
//       with the same reason as the serial path
//   (3) measured scaling — wall time at 1, 2, 4, 8 workers, printed
//   (4) bounded RSS — more workers must not mean unbounded buffers
//
// CONTROL: go test ./internal/consensus/ -count=1 -timeout 180s -run 'TestParallelScript'

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

func parallelScriptDummyTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x11}, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut:    []*wire.TxOut{{Value: 0, PkScript: []byte{}}},
		LockTime: 0,
	}
}

func makeParallelScriptJob(tx *wire.MsgTx, spk []byte) ScriptCheckJob {
	amount := int64(100_000)
	return ScriptCheckJob{
		Tx:       tx,
		TxIdx:    0,
		InputIdx: 0,
		PrevOut:  &UTXOEntry{Amount: amount, PkScript: spk},
		PrevOuts: []*wire.TxOut{{Value: amount, PkScript: spk}},
		Flags:    0,
	}
}

func runParallelScriptBatch(extra int, jobs []ScriptCheckJob) BatchResult {
	q := NewScriptCheckQueue(extra)
	defer q.Stop()
	return q.Run(jobs)
}

func jobErrString(j ScriptCheckJob) string {
	if j.err == nil {
		return ""
	}
	return j.err.Error()
}

// ---------------------------------------------------------------------------
// -par mapping (Core chainstatemanager_args.cpp:53-60)
// ---------------------------------------------------------------------------

func TestParallelScriptResolvePar1IsSerial(t *testing.T) {
	if got := ResolveScriptCheckWorkers(1); got != 0 {
		t.Fatalf("ResolveScriptCheckWorkers(1)=%d, want 0 extra workers (Core -par=1)", got)
	}
}

func TestParallelScriptResolvePar2IsOneExtra(t *testing.T) {
	if got := ResolveScriptCheckWorkers(2); got != 1 {
		t.Fatalf("ResolveScriptCheckWorkers(2)=%d, want 1 extra worker", got)
	}
}

func TestParallelScriptResolveAutoNeverExceedsCPUMinus1(t *testing.T) {
	cores := runtime.NumCPU()
	if cores < 1 {
		cores = 1
	}
	extra := ResolveScriptCheckWorkers(0)
	if extra > cores-1 {
		t.Fatalf("auto extra=%d exceeds NumCPU()-1=%d", extra, cores-1)
	}
	if extra != cores-1 {
		t.Fatalf("auto extra=%d, want NumCPU()-1=%d (Core -par=0 = every core)", extra, cores-1)
	}
}

func TestParallelScriptInitWithWorkers0SpawnsNone(t *testing.T) {
	q := NewScriptCheckQueue(0)
	defer q.Stop()
	if q.ExtraWorkers() != 0 {
		t.Fatalf("ExtraWorkers=%d, want 0", q.ExtraWorkers())
	}
	if q.HasThreads() {
		t.Fatal("HasThreads() true with 0 extra workers")
	}
}

func TestParallelScriptInitWithWorkersNSpawnsN(t *testing.T) {
	q := NewScriptCheckQueue(4)
	defer q.Stop()
	if q.ExtraWorkers() != 4 {
		t.Fatalf("ExtraWorkers=%d, want 4", q.ExtraWorkers())
	}
	if !q.HasThreads() {
		t.Fatal("HasThreads() false with 4 extra workers")
	}
}

// ---------------------------------------------------------------------------
// (1) Decision identity — 1 worker vs N, mixed corpus
// ---------------------------------------------------------------------------

func TestParallelScriptDecisionIdentity1VsNMixedCorpus(t *testing.T) {
	tx := parallelScriptDummyTx()

	spkTrue := []byte{script.OP_TRUE}
	spkFalse := []byte{script.OP_0}
	spkReturn := []byte{script.OP_RETURN}
	spkCat := []byte{script.OP_CAT}
	spkIf := []byte{script.OP_IF}
	spkDrop := []byte{script.OP_DROP}

	corpus := [][]byte{
		spkTrue, spkTrue, spkFalse, spkTrue,
		spkReturn, spkTrue, spkCat, spkTrue,
		spkIf, spkTrue, spkDrop, spkTrue,
		spkFalse, spkReturn, spkTrue, spkCat,
		spkTrue, spkIf, spkTrue, spkDrop,
		spkTrue, spkFalse, spkTrue, spkReturn,
		spkTrue, spkCat, spkTrue, spkIf,
		spkTrue, spkDrop, spkTrue, spkTrue,
	}

	jobsSerial := make([]ScriptCheckJob, len(corpus))
	jobsPar := make([]ScriptCheckJob, len(corpus))
	for i, spk := range corpus {
		jobsSerial[i] = makeParallelScriptJob(tx, spk)
		jobsPar[i] = makeParallelScriptJob(tx, spk)
	}

	serial := runParallelScriptBatch(0, jobsSerial)
	parallel := runParallelScriptBatch(8, jobsPar)

	if serial.OK != parallel.OK {
		t.Fatalf("OK serial=%v parallel=%v", serial.OK, parallel.OK)
	}
	if serial.FirstFailIndex != parallel.FirstFailIndex {
		t.Fatalf("FirstFailIndex serial=%d parallel=%d", serial.FirstFailIndex, parallel.FirstFailIndex)
	}
	if (serial.FirstFailErr == nil) != (parallel.FirstFailErr == nil) {
		t.Fatalf("FirstFailErr nil mismatch serial=%v parallel=%v", serial.FirstFailErr, parallel.FirstFailErr)
	}
	if serial.FirstFailErr != nil && serial.FirstFailErr.Error() != parallel.FirstFailErr.Error() {
		t.Fatalf("reject reason serial=%q parallel=%q", serial.FirstFailErr, parallel.FirstFailErr)
	}
	for i := range corpus {
		if jobErrString(jobsSerial[i]) != jobErrString(jobsPar[i]) {
			t.Fatalf("job %d err serial=%q parallel=%q", i, jobErrString(jobsSerial[i]), jobErrString(jobsPar[i]))
		}
	}
	if serial.OK {
		t.Fatal("mixed corpus must reject")
	}
}

// ---------------------------------------------------------------------------
// (2) Failure propagation — one bad input rejects the whole batch
// ---------------------------------------------------------------------------

func TestParallelScriptFailurePropagationOneBadInput(t *testing.T) {
	tx := parallelScriptDummyTx()
	spkTrue := []byte{script.OP_TRUE}
	spkReturn := []byte{script.OP_RETURN}
	const failAt = 17
	const n = 64

	jobsSerial := make([]ScriptCheckJob, n)
	jobsPar := make([]ScriptCheckJob, n)
	for i := 0; i < n; i++ {
		spk := spkTrue
		if i == failAt {
			spk = spkReturn
		}
		jobsSerial[i] = makeParallelScriptJob(tx, spk)
		jobsPar[i] = makeParallelScriptJob(tx, spk)
	}

	serial := runParallelScriptBatch(0, jobsSerial)
	parallel := runParallelScriptBatch(8, jobsPar)

	if serial.OK || parallel.OK {
		t.Fatalf("want reject, serial.OK=%v parallel.OK=%v", serial.OK, parallel.OK)
	}
	if serial.FirstFailIndex != failAt || parallel.FirstFailIndex != failAt {
		t.Fatalf("FirstFailIndex serial=%d parallel=%d want %d", serial.FirstFailIndex, parallel.FirstFailIndex, failAt)
	}
	if serial.FirstFailErr == nil || parallel.FirstFailErr == nil {
		t.Fatal("missing reject reason")
	}
	if serial.FirstFailErr.Error() != parallel.FirstFailErr.Error() {
		t.Fatalf("reason serial=%q parallel=%q", serial.FirstFailErr, parallel.FirstFailErr)
	}
	if !errors.Is(serial.FirstFailErr, script.ErrOpReturn) {
		t.Fatalf("serial reason %v, want ErrOpReturn", serial.FirstFailErr)
	}
}

func TestParallelScriptFailurePropagationAllPass(t *testing.T) {
	tx := parallelScriptDummyTx()
	spkTrue := []byte{script.OP_TRUE}
	jobsSerial := make([]ScriptCheckJob, 32)
	jobsPar := make([]ScriptCheckJob, 32)
	for i := range jobsSerial {
		jobsSerial[i] = makeParallelScriptJob(tx, spkTrue)
		jobsPar[i] = makeParallelScriptJob(tx, spkTrue)
	}
	serial := runParallelScriptBatch(0, jobsSerial)
	parallel := runParallelScriptBatch(8, jobsPar)
	if !serial.OK || !parallel.OK {
		t.Fatalf("want accept, serial=%v (%v) parallel=%v (%v)", serial.OK, serial.FirstFailErr, parallel.OK, parallel.FirstFailErr)
	}
	if serial.FirstFailIndex != parallel.FirstFailIndex {
		t.Fatalf("FirstFailIndex serial=%d parallel=%d", serial.FirstFailIndex, parallel.FirstFailIndex)
	}
}

func TestParallelScriptLowestIndexFailureDeterministic(t *testing.T) {
	// Three distinct failures. The reported reason MUST be the lowest index
	// (job 5), never the race-winner. A parallel verifier that returns
	// whichever worker finished first would split on reject-reason.
	tx := parallelScriptDummyTx()
	spkTrue := []byte{script.OP_TRUE}
	spkReturn := []byte{script.OP_RETURN} // index 5
	spkCat := []byte{script.OP_CAT}       // index 20
	spkIf := []byte{script.OP_IF}         // index 40

	jobsSerial := make([]ScriptCheckJob, 48)
	jobsPar := make([]ScriptCheckJob, 48)
	for i := 0; i < 48; i++ {
		spk := spkTrue
		switch i {
		case 5:
			spk = spkReturn
		case 20:
			spk = spkCat
		case 40:
			spk = spkIf
		}
		jobsSerial[i] = makeParallelScriptJob(tx, spk)
		jobsPar[i] = makeParallelScriptJob(tx, spk)
	}

	serial := runParallelScriptBatch(0, jobsSerial)
	parallel := runParallelScriptBatch(8, jobsPar)
	if serial.FirstFailIndex != 5 || parallel.FirstFailIndex != 5 {
		t.Fatalf("FirstFailIndex serial=%d parallel=%d want 5", serial.FirstFailIndex, parallel.FirstFailIndex)
	}
	if serial.FirstFailErr.Error() != parallel.FirstFailErr.Error() {
		t.Fatalf("reason serial=%q parallel=%q", serial.FirstFailErr, parallel.FirstFailErr)
	}
	if errors.Is(jobsSerial[5].err, jobsSerial[20].err) {
		t.Fatalf("job 5 and job 20 must be distinct reasons: %v vs %v", jobsSerial[5].err, jobsSerial[20].err)
	}
}

func TestParallelScriptOneJobFailIsNotSkipped(t *testing.T) {
	// Negative control: a 1-job fail must not be lost (off-by-one on the
	// claim / next-index counter). Beamchain caught this class.
	tx := parallelScriptDummyTx()
	jobs := []ScriptCheckJob{makeParallelScriptJob(tx, []byte{script.OP_RETURN})}
	res := runParallelScriptBatch(4, jobs)
	if res.OK {
		t.Fatal("1-job OP_RETURN must reject")
	}
	if res.FirstFailIndex != 0 {
		t.Fatalf("FirstFailIndex=%d, want 0", res.FirstFailIndex)
	}
	if !errors.Is(res.FirstFailErr, script.ErrOpReturn) {
		t.Fatalf("reason %v, want ErrOpReturn", res.FirstFailErr)
	}
}

// ---------------------------------------------------------------------------
// (3) Measured scaling — 1, 2, 4, 8 extra workers
// ---------------------------------------------------------------------------

func sha256HammerScript(rounds int) []byte {
	// <32-byte push> OP_HASH256{rounds} OP_DROP OP_TRUE
	buf := make([]byte, 33+rounds+2)
	buf[0] = 0x20
	for i := 1; i < 33; i++ {
		buf[i] = 0x11
	}
	for i := 0; i < rounds; i++ {
		buf[33+i] = script.OP_HASH256
	}
	buf[33+rounds] = script.OP_DROP
	buf[33+rounds+1] = script.OP_TRUE
	return buf
}

func TestParallelScriptMeasuredScaling(t *testing.T) {
	tx := parallelScriptDummyTx()
	const rounds = 180
	hammer := sha256HammerScript(rounds)
	const nJobs = 8192

	widths := []int{1, 2, 4, 8}
	ns := make([]time.Duration, len(widths))

	for wi, w := range widths {
		jobs := make([]ScriptCheckJob, nJobs)
		for ji := range jobs {
			// Unique amount per job so a shared SigCache cannot collapse
			// the batch. We are measuring script-eval scaling.
			amount := int64(100_000 + ji)
			jobs[ji] = ScriptCheckJob{
				Tx:       tx,
				TxIdx:    0,
				InputIdx: 0,
				PrevOut:  &UTXOEntry{Amount: amount, PkScript: hammer},
				PrevOuts: []*wire.TxOut{{Value: amount, PkScript: hammer}},
			}
		}
		q := NewScriptCheckQueue(w)
		t0 := time.Now()
		result := q.Run(jobs)
		elapsed := time.Since(t0)
		q.Stop()
		if !result.OK {
			t.Fatalf("workers=%d: unexpected reject: %v", w, result.FirstFailErr)
		}
		ns[wi] = elapsed
		wallS := elapsed.Seconds()
		if wallS < 1e-9 {
			wallS = 1e-9
		}
		jobsPerS := float64(nJobs) / wallS
		blkH := 3600.0 / wallS
		t.Logf("scaling workers=%d wall_ns=%d wall_s=%.4f jobs_per_s=%.0f blk_h=%.1f (n_jobs=%d hash256_rounds=%d)",
			w, elapsed.Nanoseconds(), wallS, jobsPerS, blkH, nJobs, rounds)
	}

	speedup := float64(ns[0]) / float64(ns[len(ns)-1])
	if ns[len(ns)-1] < 1 {
		speedup = float64(ns[0])
	}
	t.Logf("scaling speedup 1→8 workers: %.2fx", speedup)
	if ns[len(ns)-1] >= ns[0] {
		t.Fatalf("8 workers (%s) did not beat 1 worker (%s)", ns[len(ns)-1], ns[0])
	}
	if speedup < 1.3 {
		t.Fatalf("speedup 1→8 = %.2fx, want >= 1.3 (parallelism is load-bearing)", speedup)
	}
}

// ---------------------------------------------------------------------------
// (4) Bounded RSS — more workers must not mean unbounded buffers
// ---------------------------------------------------------------------------

func TestParallelScriptBoundedRSS(t *testing.T) {
	tx := parallelScriptDummyTx()
	spkTrue := []byte{script.OP_TRUE}
	jobs := make([]ScriptCheckJob, 256)
	for i := range jobs {
		jobs[i] = makeParallelScriptJob(tx, spkTrue)
	}

	q1 := NewScriptCheckQueue(1)
	defer q1.Stop()
	q8 := NewScriptCheckQueue(8)
	defer q8.Stop()

	r1 := q1.Run(jobs)
	r8 := q8.Run(jobs)
	if !r1.OK || !r8.OK {
		t.Fatalf("want accept, r1=%v r8=%v", r1.FirstFailErr, r8.FirstFailErr)
	}

	// Borrowed slice, not an owned copy that grows with worker count.
	if !q1.jobSliceIs(jobs) || !q8.jobSliceIs(jobs) {
		t.Fatal("queue copied the job slice; buffer must stay borrowed")
	}
	if q1.ExtraWorkers() != 1 || q8.ExtraWorkers() != 8 {
		t.Fatalf("worker counts drifted: q1=%d q8=%d", q1.ExtraWorkers(), q8.ExtraWorkers())
	}

	// In-flight checks are bounded by batch_size × (workers+master), not by
	// the job count. More workers must not mean an unbounded buffer.
	cap1 := scriptCheckBatchSize * (q1.ExtraWorkers() + 1)
	cap8 := scriptCheckBatchSize * (q8.ExtraWorkers() + 1)
	if q1.MaxInFlight() > int64(cap1) {
		t.Fatalf("q1 maxInFlight=%d exceeds bound %d", q1.MaxInFlight(), cap1)
	}
	if q8.MaxInFlight() > int64(cap8) {
		t.Fatalf("q8 maxInFlight=%d exceeds bound %d", q8.MaxInFlight(), cap8)
	}
	if cap8 <= cap1 {
		t.Fatalf("8-worker cap %d should exceed 1-worker cap %d", cap8, cap1)
	}
}

func TestParallelScriptPersistentPoolTwoBatches(t *testing.T) {
	tx := parallelScriptDummyTx()
	spkTrue := []byte{script.OP_TRUE}
	spkFalse := []byte{script.OP_0}

	q := NewScriptCheckQueue(4)
	defer q.Stop()
	extra := q.ExtraWorkers()

	passJobs := make([]ScriptCheckJob, 16)
	for i := range passJobs {
		passJobs[i] = makeParallelScriptJob(tx, spkTrue)
	}
	if res := q.Run(passJobs); !res.OK {
		t.Fatalf("first batch: %v", res.FirstFailErr)
	}

	failJobs := make([]ScriptCheckJob, 16)
	for i := range failJobs {
		spk := spkTrue
		if i == 1 {
			spk = spkFalse
		}
		failJobs[i] = makeParallelScriptJob(tx, spk)
	}
	failed := q.Run(failJobs)
	if failed.OK {
		t.Fatal("second batch must reject")
	}
	if failed.FirstFailIndex != 1 {
		t.Fatalf("FirstFailIndex=%d, want 1", failed.FirstFailIndex)
	}
	if q.ExtraWorkers() != extra {
		t.Fatalf("pool respawned: ExtraWorkers %d → %d", extra, q.ExtraWorkers())
	}
	if q.ExtraWorkers() != 4 {
		t.Fatalf("ExtraWorkers=%d, want 4", q.ExtraWorkers())
	}
}

func TestParallelScriptChainManagerOwnsPool(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	cmSerial := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ParallelScripts: false,
		Par:             8,
	})
	defer cmSerial.StopScriptCheckQueue()
	if cmSerial.ScriptCheckQueue() != nil {
		t.Fatal("ParallelScripts=false must not start a worker pool")
	}

	cmPar := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ParallelScripts: true,
		Par:             4,
	})
	defer cmPar.StopScriptCheckQueue()
	q := cmPar.ScriptCheckQueue()
	if q == nil {
		t.Fatal("ParallelScripts=true must own a ScriptCheckQueue")
	}
	if q.ExtraWorkers() != ResolveScriptCheckWorkers(4) {
		t.Fatalf("ExtraWorkers=%d, want Resolve(4)=%d", q.ExtraWorkers(), ResolveScriptCheckWorkers(4))
	}

	tx := parallelScriptDummyTx()
	jobs := []ScriptCheckJob{makeParallelScriptJob(tx, []byte{script.OP_TRUE})}
	if res := q.Run(jobs); !res.OK {
		t.Fatalf("pool Run: %v", res.FirstFailErr)
	}
}

func TestParallelScriptCollectAndValidateCachedUsesQueue(t *testing.T) {
	// ParallelScriptValidationCached must go through the queue so verifychain
	// / one-shot callers get the same lowest-index reason as ConnectBlock.
	spkTrue := []byte{script.OP_TRUE}
	spkReturn := []byte{script.OP_RETURN}

	prevTrue := &wire.TxOut{Value: 100000, PkScript: spkTrue}
	prevFail := &wire.TxOut{Value: 100000, PkScript: spkReturn}

	spendTrue := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 50000, PkScript: spkTrue}},
	}
	spendFail := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 50000, PkScript: spkTrue}},
	}

	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
			SignatureScript:  []byte{0x02, 0x01, 0x00},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 50e8, PkScript: spkTrue}},
	}

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 4, Bits: 0x207fffff},
		Transactions: []*wire.MsgTx{coinbase, spendTrue, spendFail, spendTrue},
	}

	view := &InMemoryUTXOView{utxos: map[wire.OutPoint]*UTXOEntry{
		spendTrue.TxIn[0].PreviousOutPoint: {Amount: prevTrue.Value, PkScript: prevTrue.PkScript},
		spendFail.TxIn[0].PreviousOutPoint: {Amount: prevFail.Value, PkScript: prevFail.PkScript},
	}}

	err := ParallelScriptValidationCached(block, view, 0, nil)
	if err == nil {
		t.Fatal("expected reject")
	}
	if !errors.Is(err, script.ErrOpReturn) {
		t.Fatalf("got %v, want ErrOpReturn (lowest-index fail, tx 2)", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("tx 2 input 0")) {
		t.Fatalf("error %q must name tx 2 input 0 (not a race-winner sibling)", err)
	}
}
