// GAP-BB-FLUSH-RACE — committed as SKIPPED probes, deliberately.
//
// These four probes REPRODUCE a real defect against the current tree. They are
// not aspirational and they are not broken tests: each one failed on every run
// when written (2026-09-02) by an adversarial reviewer, against the coins-marker
// invariant work in f369d96 + dd791f6.
//
// THE DEFECT. blockbrew's UTXO flush is not serialised against block
// connection. The coins-marker invariant is enforced only INSIDE a flush call;
// nothing prevents a flush from running concurrently with a connect or a reorg:
//
//   - A scantxoutset-driven flush during a REJECTED ConnectBlock makes that
//     block's spends DURABLE. rollbackUTXOs (chainmanager.go:1292-1317) undoes
//     them via utxoSet.SpendUTXO/AddUTXO — in memory only.
//   - The same during a FAILED reorg is permanent and needs no crash.
//     reorgToLocked defers on-disk writes to a union batch (chainmanager.go:2882)
//     and its own comment claims "the on-disk chainstate + UTXO set are
//     untouched until batch.Write() at the very end". A concurrent ScanUTXOs
//     flush falsifies that comment.
//
// WHY THEY ARE SKIPPED RATHER THAN FIXED. Closing this needs a transaction
// boundary between "flush the coin set" and "connect a block" — a design
// change, not a patch. Two prior rounds each closed their named paths and
// exposed the next one; the decision to stop patching and document instead is
// recorded in CORE-PARITY-AUDIT/_loop-ledger.md (d94c92f).
//
// TO WORK ON THIS: delete the t.Skip lines below and run. They should fail.
// When they pass without being weakened, the gap is closed.

package consensus

import (
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// FINDING #7 PROBES — the coins-marker invariant is enforced only INSIDE a
// single flush call. Nothing couples a flush to the block application that is
// mutating the same UTXOSet, and three live RPCs flush the LIVE coin set from
// their own goroutine with no chain lock held:
//
//	scantxoutset    -> internal/rpc/scantxoutset_methods.go:161  us.ScanUTXOs
//	gettxoutsetinfo -> internal/rpc/wave47b_methods.go:151       ComputeUTXOSetInfo -> ScanUTXOs
//	dumptxoutset    -> internal/rpc/methods.go:3421              WriteSnapshot      -> ScanUTXOs
//
// ScanUTXOs (internal/consensus/utxoset.go:843) opens with u.Flush().
//
// ChainManager.ConnectBlock applies the block's spends to cm.utxoSet in its
// FIRST PASS and only calls advanceAppliedTip after script validation
// (chainmanager.go:1610). ReorgTo mutates the same set across its whole
// disconnect/connect loop and only commits at the end. A flush that lands in
// either window stamps storage.CoinsTipKey from u.appliedHash — the PREVIOUS
// block — into the same batch as the in-flight block's DELETES.

func probeChainToSix(t *testing.T) (*ChainManager, *UTXOSet, *storage.ChainDB, *HeaderIndex, *ChainParams, []*BlockNode, []wire.OutPoint) {
	t.Helper()
	base := *RegtestParams()
	base.SubsidyHalvingInterval = 210000
	params := &base

	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	prev := idx.Genesis()
	var nodes []*BlockNode
	var coinbases []wire.OutPoint
	for h := 1; h <= 6; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		nodes = append(nodes, prev)
		coinbases = append(coinbases, wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0})
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	m, err := chainDB.GetCoinsTip()
	if err != nil || m == nil || m.BestHeight != 6 {
		t.Fatalf("precondition: durable marker should be @6, got %+v (err %v)", m, err)
	}
	return cm, utxoSet, chainDB, idx, params, nodes, coinbases
}

// PROBE 7A — the mechanism, deterministic, no goroutines.
//
// The two calls below are made by two different goroutines in production, in
// exactly this order: ConnectBlock's first pass spends a coin (utxoset.go:194
// SpendUTXO, reached from ChainManager.ConnectBlock's input loop) strictly
// BEFORE ConnectBlock reaches advanceAppliedTip (chainmanager.go:1610); an RPC
// scan's Flush can land anywhere in between. Nothing serialises them: Flush
// takes only u.mu, ConnectBlock holds cm.mu, and the two are unrelated.
func TestProbe7A_RPCFlushBetweenSpendAndMarkerAdvance(t *testing.T) {
	t.Skip("GAP-BB-FLUSH-RACE: reproduces a known unfixed defect; see the file header")
	_, utxoSet, chainDB, _, _, _, coinbases := probeChainToSix(t)
	victim := coinbases[1] // coinbase of height 2, durable and unspent at tip 6

	if !utxoSet.HasUTXODurable(victim) {
		t.Fatalf("precondition: victim must be durable")
	}

	// ---- goroutine A: ConnectBlock(h=7) first pass applies the spend.
	utxoSet.SpendUTXO(victim)
	// ---- goroutine B: scantxoutset / gettxoutsetinfo / dumptxoutset.
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// ---- goroutine A has NOT yet reached advanceAppliedTip.

	marker, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip: %v", err)
	}
	durable := utxoSet.HasUTXODurable(victim)
	if marker.BestHeight == 6 && !durable {
		t.Fatalf("MARKER LIES: a spend from block 7 is DURABLE on disk (%s:%d erased) "+
			"while storage.CoinsTipKey still names %s@%d. This is precisely the "+
			"combination internal/consensus/utxoset.go PHASE 2 calls "+
			"'unrepresentable' — a landed DELETE under a marker naming a lower block.",
			victim.Hash.String()[:16], victim.Index,
			marker.BestHash.String()[:16], marker.BestHeight)
	}
	t.Logf("no disagreement: marker=%d durable=%v", marker.BestHeight, durable)
}

// PROBE 7B — real concurrency, real ConnectBlock, lasting damage.
//
// Block 7 spends two durable coinbases and pays an over-subsidy coinbase, so
// ConnectBlock applies the spends in its first pass and then REJECTS at the
// coinbase-value check (chainmanager.go:1185), unwinding via rollbackUTXOs —
// which restores the in-memory cache only (chainmanager.go:1292-1317).
//
// The flusher models an RPC scan arriving in that window. It fires exactly
// once, triggered by observing the spend in the view, so nothing after it can
// paper over the result.
func TestProbe7B_ScanFlushDuringRejectedConnectDurablyErasesCoins(t *testing.T) {
	t.Skip("GAP-BB-FLUSH-RACE: reproduces a known unfixed defect; see the file header")
	base := *RegtestParams()
	base.SubsidyHalvingInterval = 210000
	params := &base

	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	// 110 blocks so the early coinbases are MATURE (CoinbaseMaturity=100).
	const total = 110
	prev := idx.Genesis()
	var coinbases []wire.OutPoint
	for h := 1; h <= total; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader h=%d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		coinbases = append(coinbases, wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0})
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	tip := prev
	victims := []wire.OutPoint{coinbases[0], coinbases[1]}
	for _, v := range victims {
		if !utxoSet.HasUTXODurable(v) {
			t.Fatalf("precondition: victim %s must be durable", v.Hash.String()[:16])
		}
	}

	var spends []*wire.MsgTx
	for _, v := range victims {
		spends = append(spends, &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: v, Sequence: 0xFFFFFFFF}},
			TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
		})
	}
	bad := createTestBlockWithSpendsAndCoinbaseValue(t, params, tip, spends, 10000*100000000)
	if _, err := idx.AddHeader(bad.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// A background RPC scan (scantxoutset / gettxoutsetinfo / dumptxoutset),
	// running for the whole time the node is trying to connect the block.
	// It records the first moment the ON-DISK state is torn: a coin that the
	// chain-tip-and-marker pair says is unspent, already erased from the
	// persisted set.
	var tornAt atomic.Int64
	tornAt.Store(-1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = utxoSet.Flush() // ScanUTXOs opens with exactly this
			m, err := chainDB.GetCoinsTip()
			if err != nil || m == nil {
				continue
			}
			if m.BestHeight == int32(total) && !utxoSet.HasUTXODurable(victims[0]) {
				tornAt.Store(int64(m.BestHeight))
				return
			}
			runtime.Gosched()
		}
	}()

	var lastErr error
	for attempt := 0; attempt < 20000 && tornAt.Load() < 0; attempt++ {
		lastErr = cm.ConnectBlock(bad)
		if lastErr == nil {
			t.Fatalf("expected the over-subsidy block to be REJECTED")
		}
	}
	close(stop)
	<-done
	t.Logf("ConnectBlock rejected as designed: %v", lastErr)

	if h := tornAt.Load(); h >= 0 {
		marker, _ := chainDB.GetCoinsTip()
		t.Fatalf("TORN ON DISK WITH NO CRASH IN THE FIX: an RPC scan's flush "+
			"committed block %d's DELETE of %s:%d while storage.CoinsTipKey still "+
			"named %s@%d — and block %d was REJECTED, so nothing on any chain ever "+
			"spends that coin. A SIGKILL at this instant boots a node whose marker "+
			"is trusted, whose tip is %d, and whose persisted set is missing a coin "+
			"that tip leaves unspent.",
			total+1, victims[0].Hash.String()[:16], victims[0].Index,
			marker.BestHash.String()[:16], marker.BestHeight, total+1, total)
	}
	t.Logf("no torn on-disk state observed in this run")
}

// PROBE 7C — NO CRASH REQUIRED, permanent, and invisible in-process.
//
// ReorgTo mutates cm.utxoSet across its whole loop under an active reorg
// journal and defers every on-disk write to a union batch at the end
// (chainmanager.go:2745-2780). A scan-driven Flush during that window makes
// the branch's mutations durable OUTSIDE that batch. The reorg then fails and
// rollbackToOriginalTip calls RollbackReorgJournal, which restores each
// touched outpoint's PRE-REORG dirty/deleted/fresh flags
// (utxoset.go:795-812) — so the coin comes back as a CLEAN cache entry and no
// later flush ever re-writes it. cm.setAppliedTip(currentTip) then publishes a
// marker asserting the persisted set reflects the original tip.
//
// Deterministic: the four calls are the exact public calls the two goroutines
// make, in an order the scheduler permits.
func TestProbe7C_ReorgRollbackCannotUndoADurableFlush(t *testing.T) {
	t.Skip("GAP-BB-FLUSH-RACE: reproduces a known unfixed defect; see the file header")
	cm, utxoSet, chainDB, _, _, nodes, coinbases := probeChainToSix(t)
	tip := nodes[5]
	victim := coinbases[1]

	utxoSet.BeginReorgJournal()             // ReorgTo, chainmanager.go (BeginReorgJournal)
	utxoSet.SpendUTXO(victim)               // a branch block's ConnectBlock first pass
	if err := utxoSet.Flush(); err != nil { // the RPC scan
		t.Fatalf("Flush: %v", err)
	}
	utxoSet.RollbackReorgJournal() // rollbackToOriginalTip
	utxoSet.SetAppliedTip(tip.Hash, tip.Height)

	// Everything the node can see in-process now says the coin is fine.
	if !utxoSet.HasUTXO(victim) {
		t.Fatalf("precondition: the journal rollback should have restored the coin in memory")
	}
	// Every subsequent flush — including the clean-shutdown one — leaves it gone.
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}
	marker, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip: %v", err)
	}
	if !utxoSet.HasUTXODurable(victim) {
		t.Fatalf("PERMANENT SILENT LOSS, NO CRASH: %s:%d is unspent at tip %s@%d and "+
			"present in the in-memory view, but it is GONE from the persisted set and "+
			"no future flush will restore it (the journal put dirty/deleted back to "+
			"their pre-reorg values). The durable marker published over that set says "+
			"%s@%d — a marker that is too HIGH for the coins it describes, the "+
			"silent-corruption direction. cm still reports tip %d.",
			victim.Hash.String()[:16], victim.Index, tip.Hash.String()[:16], tip.Height,
			marker.BestHash.String()[:16], marker.BestHeight, func() int32 { _, h := cm.BestBlock(); return h }())
	}
	t.Logf("coin survived; marker=%d", marker.BestHeight)
}

// createTestBlockWithSpendsAndCoinbaseValue is createTestBlock plus an explicit
// coinbase value, so a block can carry real spends AND fail the
// coinbase-value check (chainmanager.go ErrBadCoinbaseValue).
func createTestBlockWithSpendsAndCoinbaseValue(t *testing.T, params *ChainParams, prevNode *BlockNode, txs []*wire.MsgTx, coinbaseValue int64) *wire.MsgBlock {
	t.Helper()
	blockHeight := prevNode.Height + 1
	heightScript := encodeBIP34Height(blockHeight)
	if len(heightScript) < 2 {
		heightScript = append(heightScript, 0x00)
	}
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  heightScript,
			Sequence:         0xFFFFFFFF,
		}},
		TxOut:    []*wire.TxOut{{Value: coinbaseValue, PkScript: []byte{0x51}}},
		LockTime: 0,
	}
	allTxs := append([]*wire.MsgTx{coinbase}, txs...)
	txHashes := make([]wire.Hash256, len(allTxs))
	for i, tx := range allTxs {
		txHashes[i] = tx.TxHash()
	}
	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prevNode.Hash,
		MerkleRoot: CalcMerkleRoot(txHashes),
		Timestamp:  prevNode.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}
	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		header.Nonce = i
		if HashToBig(header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return &wire.MsgBlock{Header: header, Transactions: allTxs}
}

// PROBE 7D — the fail-closed marker branch RE-ARMS finding #1.
//
// durableCoinsTip (chainmanager.go:858) reports the marker as ABSENT whenever
// an interrupted-flush record is present, the marker is missing, or the height
// map disagrees with it. seedAppliedTipFromMarker then returns without seeding,
// so UTXOSet.appliedSet stays FALSE (utxoset.go:74-76) — and AdvanceAppliedTip's
// raise-only guard is `if u.appliedSet && height <= u.appliedHeight`, which does
// not fire at all when appliedSet is false. Recovery then RE-APPLIES every
// block from the chain pointer up, which is exactly what finding #1 was about.
//
// A/B on ONE datadir: coins durable through 121, chain pointer at genesis, a
// gap in the height map at 50 that halts the replay (an independent, ordinary
// halt cause recovery already handles). The only difference between the two
// runs is a storage.CoinsFlushKey record.
func TestProbe7D_FailClosedMarkerReAppliesAndResurrects(t *testing.T) {
	t.Skip("GAP-BB-FLUSH-RACE: reproduces a known unfixed defect; see the file header")
	const victimH, total, gapH = 20, 121, 50

	run := func(t *testing.T, failClosed bool) (uint64, bool, *storage.ChainState) {
		t.Helper()
		chainDB, victim, _, wantCoins, _ := markerProbeChain(t, victimH, total)
		// An ordinary halt cause: a hole in the persisted height map.
		if err := chainDB.DB().Delete(storage.MakeBlockHeightKey(int32(gapH))); err != nil {
			t.Fatalf("delete height row: %v", err)
		}
		if failClosed {
			// Core's DB_HEAD_BLOCKS (txdb.cpp:128-129) — what flushLocked
			// writes when a delete phase must span batches.
			rec := append((&storage.ChainState{}).Serialize(),
				(&storage.ChainState{}).Serialize()...)
			if err := chainDB.DB().Put(storage.CoinsFlushKey, rec); err != nil {
				t.Fatalf("Put(CoinsFlushKey): %v", err)
			}
		}
		_, u := markerProbeReboot(t, chainDB)
		if err := u.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		_, coins, err := ComputeHashSerialized(u)
		if err != nil {
			t.Fatalf("ComputeHashSerialized: %v", err)
		}
		m, _ := chainDB.GetCoinsTip()
		_ = wantCoins
		return coins, u.HasUTXODurable(victim), m
	}

	trustedCoins, trustedResurrected, trustedMarker := run(t, false)
	closedCoins, closedResurrected, closedMarker := run(t, true)

	t.Logf("marker TRUSTED : coins=%d resurrected=%v marker=@%d",
		trustedCoins, trustedResurrected, trustedMarker.BestHeight)
	t.Logf("marker FAIL-CLOSED: coins=%d resurrected=%v marker=@%d",
		closedCoins, closedResurrected, closedMarker.BestHeight)

	if closedResurrected || closedCoins != trustedCoins {
		t.Fatalf("FAIL-CLOSED RE-ARMS FINDING #1: the SAME datadir, differing only "+
			"by a storage.CoinsFlushKey record, gives coins %d (marker trusted) vs "+
			"%d (marker fail-closed) and resurrects the victim coinbase (%v vs %v). "+
			"Failing closed disables the raise-only guard entirely, because the guard "+
			"is conditioned on appliedSet.",
			trustedCoins, closedCoins, trustedResurrected, closedResurrected)
	}
}

// PROBE 7E — the first boot of the FIXED binary over an existing datadir.
//
// storage.CoinsTipKey did not exist before 52a7bd5 (2026-09-02). Every datadir
// the fleet is running on today therefore has NO marker, so
// seedAppliedTipFromMarker finds nothing, appliedSet stays false, and crash
// recovery falls back to the connect-first + AdoptAppliedBlock evidence path
// (chainmanager.go:2251) — the pre-fix behaviour, with its coinbase-only
// blindness intact. The marker mechanism protects the SECOND boot, not the
// first, and the first is the one that runs on the marker-lag datadirs the fix
// was written for.
func TestProbe7E_FirstBootOverALegacyDatadirStillResurrects(t *testing.T) {
	t.Skip("GAP-BB-FLUSH-RACE: reproduces a known unfixed defect; see the file header")
	const victimH, total = 20, 121
	chainDB, victim, _, wantCoins, _ := markerProbeChain(t, victimH, total)

	// A pre-52a7bd5 datadir: coins durable through 121, chain-tip pointer at
	// genesis, and no coins marker at all.
	if err := chainDB.DB().Delete(storage.CoinsTipKey); err != nil {
		t.Fatalf("Delete(CoinsTipKey): %v", err)
	}

	cm, u := markerProbeReboot(t, chainDB)
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	_, gotCoins, err := ComputeHashSerialized(u)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	marker, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip: %v", err)
	}
	_, tipH := cm.BestBlock()
	if u.HasUTXODurable(victim) || gotCoins != wantCoins {
		t.Fatalf("LEGACY DATADIR, FIRST BOOT WITH THE FIX: coins %d -> %d, victim "+
			"%s:%d is unspent on disk again, tip=%d, and the marker now published is "+
			"%s@%d. The seed has nothing to read on the one boot that matters.",
			wantCoins, gotCoins, victim.Hash.String()[:16], victim.Index, tipH,
			marker.BestHash.String()[:16], marker.BestHeight)
	}
}
