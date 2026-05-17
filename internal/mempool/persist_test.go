package mempool

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestDumpHeaderIsCoreCompatible(t *testing.T) {
	dir := t.TempDir()
	mp := newTestMempool(newTestUTXOSet())

	// Manually splice one tx into the pool so the dump is not totally empty.
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xAA}, Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1234, PkScript: []byte{0x00, 0x14, 0x01}}},
	}
	mp.mu.Lock()
	mp.pool[tx.TxHash()] = &TxEntry{
		Tx:     tx,
		TxHash: tx.TxHash(),
		Time:   time.Unix(1_700_000_000, 0),
		Fee:    1000,
		Size:   200,
	}
	mp.mu.Unlock()

	if err := mp.Dump(dir); err != nil {
		t.Fatalf("dump: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "mempool.dat"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Header sanity: 8 bytes version + compact-size 8 + 8 bytes key.
	if len(raw) < 17 {
		t.Fatalf("file too small: %d", len(raw))
	}
	version := binary.LittleEndian.Uint64(raw[0:8])
	if version != mempoolDumpVersion {
		t.Fatalf("version = %d, want %d", version, mempoolDumpVersion)
	}
	if raw[8] != 0x08 {
		t.Fatalf("expected key length 0x08, got %#x", raw[8])
	}
	for i := 9; i < 17; i++ {
		if raw[i] != 0 {
			t.Fatalf("expected zero key, got byte %#x at %d", raw[i], i)
		}
	}
	// Payload starts at offset 17 with the count uint64.
	count := binary.LittleEndian.Uint64(raw[17:25])
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
}

func TestLoadAcceptsZeroKeyDump(t *testing.T) {
	dir := t.TempDir()
	utxoSet := newTestUTXOSet()

	// Build a fundable tx + UTXO entry so AcceptToMemoryPool will succeed.
	var fundingHash wire.Hash256
	fundingHash[0] = 0xCC
	outpoint, entry := createFundingUTXO(fundingHash, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)
	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)
	mp.mu.Lock()
	mp.pool[tx.TxHash()] = &TxEntry{
		Tx:     tx,
		TxHash: tx.TxHash(),
		Time:   time.Now(),
		Fee:    1000,
		Size:   200,
	}
	for _, in := range tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = tx.TxHash()
	}
	mp.totalSize = 200
	mp.mu.Unlock()

	if err := mp.Dump(dir); err != nil {
		t.Fatalf("dump: %v", err)
	}

	// Fresh mempool, fresh UTXO. Reload should accept the tx (script
	// validation is skipped because the test-mempool config maps to regtest
	// and the UTXO has a P2WPKH script with no witness expected).
	utxo2 := newTestUTXOSet()
	utxo2.AddUTXO(outpoint, entry)
	mp2 := newTestMempool(utxo2)
	res, err := mp2.Load(dir, LoadOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result for existing file")
	}
	if res.Read != 1 {
		t.Fatalf("Read = %d, want 1", res.Read)
	}
	// Acceptance may or may not pass full script validation depending on
	// fixture details; what matters is that the format was parsed correctly.
	if res.Read != res.Accepted+res.Failed+res.Expired {
		t.Fatalf("counter mismatch: read=%d accepted=%d failed=%d expired=%d",
			res.Read, res.Accepted, res.Failed, res.Expired)
	}
}

func TestLoadReturnsNilForMissingFile(t *testing.T) {
	dir := t.TempDir()
	mp := newTestMempool(newTestUTXOSet())
	res, err := mp.Load(dir, LoadOptions{})
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil result for missing file, got %+v", res)
	}
}

func TestLoadRejectsBadVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mempool.dat")
	var hdr bytes.Buffer
	// Write a bogus version number.
	_ = binary.Write(&hdr, binary.LittleEndian, uint64(0xDEADBEEF))
	if err := os.WriteFile(path, hdr.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	mp := newTestMempool(newTestUTXOSet())
	_, err := mp.Load(dir, LoadOptions{})
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestLoadExpiresOldEntries(t *testing.T) {
	dir := t.TempDir()
	// Build a one-tx dump where the timestamp is 30 days old.
	mp := newTestMempool(newTestUTXOSet())
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xEE}, Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}
	mp.mu.Lock()
	mp.pool[tx.TxHash()] = &TxEntry{
		Tx:     tx,
		TxHash: tx.TxHash(),
		Time:   time.Now().Add(-30 * 24 * time.Hour),
	}
	mp.mu.Unlock()
	if err := mp.Dump(dir); err != nil {
		t.Fatal(err)
	}

	mp2 := newTestMempool(newTestUTXOSet())
	res, err := mp2.Load(dir, LoadOptions{MaxAge: 14 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if res.Read != 1 || res.Expired != 1 || res.Accepted != 0 {
		t.Fatalf("expected 1 read / 1 expired / 0 accepted, got %+v", res)
	}
}

// TestDumpLoadRoundTripWithObfuscation forces a non-zero key into the dump
// path and confirms Load can decode it back. We exercise the xorReader/xorWriter
// directly so we don't have to bake non-zero keys into the public Dump API.
func TestDumpLoadRoundTripWithObfuscation(t *testing.T) {
	var buf bytes.Buffer
	key := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Header (raw, not obfuscated).
	if err := wire.WriteUint64LE(&buf, mempoolDumpVersion); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteCompactSize(&buf, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := buf.Write(key[:]); err != nil {
		t.Fatal(err)
	}

	// Obfuscated payload: count=0 (no txs) + empty mapDeltas + empty unbroadcast.
	xw := &xorWriter{w: &buf, key: key, pos: 17}
	if err := wire.WriteUint64LE(xw, 0); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteCompactSize(xw, 0); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteCompactSize(xw, 0); err != nil {
		t.Fatal(err)
	}

	// Write to a temp dir and try Load.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mempool.dat"), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	mp := newTestMempool(newTestUTXOSet())
	res, err := mp.Load(dir, LoadOptions{})
	if err != nil {
		t.Fatalf("load with obfuscation: %v", err)
	}
	if res.Read != 0 {
		t.Fatalf("Read = %d, want 0", res.Read)
	}
}

// ---- FIX-76: mapDeltas persistence (Core mempool_persist.cpp:101+166-203) ----
//
// FIX-72 dc8e1a0 commit message claimed "delta lost on restart matches Core"
// but Core actually persists mapDeltas in mempool.dat. FIX-76 closes that
// brief-error: per-entry deltas ride along in the per-tx nFeeDelta slot,
// and deltas for txids NOT in the pool are emitted in the standalone tail
// block. Both round-trip through PrioritiseTransaction on load.

// TestFIX76_AbsentTxidDeltaSurvivesRestart: prioritise a txid that is NOT
// in the pool (operator pre-prioritises before broadcast), dump, load into
// a fresh mempool, and assert the delta sits in mapDeltas ready to apply
// when the tx later arrives. Core's PrioritiseTransaction is happy to
// operate on absent txids — see txmempool.cpp::PrioritiseTransaction.
func TestFIX76_AbsentTxidDeltaSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	mpA := newTestMempool(newTestUTXOSet())
	var orphanTxid wire.Hash256
	orphanTxid[0] = 0xBE
	orphanTxid[1] = 0xEF
	mpA.PrioritiseTransaction(orphanTxid, 12345)

	if err := mpA.Dump(dir); err != nil {
		t.Fatalf("dump: %v", err)
	}

	mpB := newTestMempool(newTestUTXOSet())
	if _, err := mpB.Load(dir, LoadOptions{}); err != nil {
		t.Fatalf("load: %v", err)
	}

	got := mpB.GetFeeDelta(orphanTxid)
	if got != 12345 {
		t.Fatalf("FIX-76: standalone tail-block delta for absent txid "+
			"should be restored via PrioritiseTransaction on load "+
			"(Core mempool_persist.cpp:128-132 ApplyDelta loop). "+
			"got %d, want 12345", got)
	}
}

// TestFIX76_MixedInPoolAndAbsentDeltasRoundTrip: combines both channels —
// one delta on an in-pool tx (rides in per-entry nFeeDelta slot) plus one
// delta on an absent txid (rides in standalone tail block). Mirrors the
// `mapDeltas.erase()` step at mempool_persist.cpp:200 — neither delta
// should be double-counted.
func TestFIX76_MixedInPoolAndAbsentDeltasRoundTrip(t *testing.T) {
	dir := t.TempDir()

	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x76
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	mpA := newTestMempool(utxoSet)
	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	inPoolTxid := tx.TxHash()
	mpA.mu.Lock()
	addPoolEntry(mpA, &TxEntry{TxHash: inPoolTxid, Tx: tx, Fee: 1000, Size: 150})
	mpA.mu.Unlock()
	mpA.PrioritiseTransaction(inPoolTxid, 5000)

	var absentTxid wire.Hash256
	absentTxid[0] = 0xCA
	absentTxid[1] = 0xFE
	mpA.PrioritiseTransaction(absentTxid, -3000)

	if err := mpA.Dump(dir); err != nil {
		t.Fatalf("dump: %v", err)
	}

	utxoSetB := newTestUTXOSet()
	utxoSetB.AddUTXO(op, e)
	mpB := newTestMempool(utxoSetB)
	if _, err := mpB.Load(dir, LoadOptions{}); err != nil {
		t.Fatalf("load: %v", err)
	}

	if got := mpB.GetFeeDelta(inPoolTxid); got != 5000 {
		t.Errorf("in-pool delta: got %d, want 5000 (per-entry nFeeDelta path)", got)
	}
	if got := mpB.GetFeeDelta(absentTxid); got != -3000 {
		t.Errorf("absent-txid delta: got %d, want -3000 (tail-block path)", got)
	}

	// Belt-and-suspenders: no double-counting. The dump must not also
	// emit the in-pool txid in the tail block (Core's mapDeltas.erase()
	// step). Re-load with a fresh mempool and confirm the in-pool delta
	// is still exactly 5000, not 10000.
	mpC := newTestMempool(newTestUTXOSet())
	if _, err := mpC.Load(dir, LoadOptions{}); err != nil {
		t.Fatalf("re-load: %v", err)
	}
	if got := mpC.GetFeeDelta(inPoolTxid); got != 5000 {
		t.Errorf("double-count guard: in-pool delta = %d, want 5000 "+
			"(if both channels emitted the same txid we'd see 10000)", got)
	}
}

// TestFIX76_EmptyMapDeltasSurvivesRoundTrip: a fresh mempool with no
// prioritisations dumps successfully and loads back with no deltas.
func TestFIX76_EmptyMapDeltasSurvivesRoundTrip(t *testing.T) {
	dir := t.TempDir()

	mpA := newTestMempool(newTestUTXOSet())
	if err := mpA.Dump(dir); err != nil {
		t.Fatalf("dump: %v", err)
	}

	mpB := newTestMempool(newTestUTXOSet())
	if _, err := mpB.Load(dir, LoadOptions{}); err != nil {
		t.Fatalf("load: %v", err)
	}

	mpB.mu.RLock()
	defer mpB.mu.RUnlock()
	if len(mpB.mapDeltas) != 0 {
		t.Fatalf("mapDeltas should be empty after empty round-trip, got %d entries",
			len(mpB.mapDeltas))
	}
}

// TestFIX76_OldFormatFileWithoutTailBlockLoadsCleanly: a v2 file truncated
// before the mapDeltas tail block (the FIX-72 dump shape) must load
// without error and accept the txs that were present. Backward-compat is
// load-side EOF tolerance (matches Core's catch-block at
// mempool_persist.cpp:144-147).
func TestFIX76_OldFormatFileWithoutTailBlockLoadsCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mempool.dat")

	// Hand-craft a v2 file: header + count=0 (no txs) + truncate.
	// No mapDeltas tail block, no unbroadcast block — EOF immediately
	// after the per-entry section.
	var buf bytes.Buffer
	if err := wire.WriteUint64LE(&buf, mempoolDumpVersion); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteCompactSize(&buf, 8); err != nil {
		t.Fatal(err)
	}
	var key [8]byte // zero key, no obfuscation
	if _, err := buf.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	xw := &xorWriter{w: &buf, key: key, pos: 17}
	if err := wire.WriteUint64LE(xw, 0); err != nil {
		t.Fatal(err)
	}
	// NOTE: deliberately do NOT write the tail block.

	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	mp := newTestMempool(newTestUTXOSet())
	res, err := mp.Load(dir, LoadOptions{})
	if err != nil {
		t.Fatalf("FIX-76: old-format file (no tail block) should load "+
			"cleanly via EOF tolerance, got error %v", err)
	}
	if res.Read != 0 {
		t.Fatalf("Read = %d, want 0", res.Read)
	}
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if len(mp.mapDeltas) != 0 {
		t.Fatalf("mapDeltas should be empty after old-format load, got %d", len(mp.mapDeltas))
	}
}

// TestFIX76_ForwardRegressionSourceGuardRejectsOldComment: a forward-
// regression guard on the source files themselves. If anyone in the
// future restores the "Not persisted across restart" comment shape, this
// test fails loudly and points them at the FIX-76 brief-error closure.
// Mirrors the W120 BUG-5 "comment-as-confession" pattern: an inaccurate
// comment is a real bug that diverges shape from Core.
func TestFIX76_ForwardRegressionSourceGuardRejectsOldComment(t *testing.T) {
	// Read the live source files in this package — the test runs from
	// the package directory.
	files := []string{
		"mempool.go",
		"persist.go",
	}
	// Phrases the FIX-72-era code used that would re-introduce the brief
	// error if they came back. The actual prose: "NOT persisted across
	// restart" / "Not persisted across restart" / "blockbrew intentionally
	// emits zero deltas".
	forbidden := []string{
		"NOT persisted across restart",
		"Not persisted across restart (Core parity",
		"blockbrew intentionally emits zero deltas",
		"intentionally emits zero deltas in mempool.dat",
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(data)
		for _, phrase := range forbidden {
			if strings.Contains(body, phrase) {
				t.Errorf("FIX-76 regression: %s contains forbidden phrase %q "+
					"— Core DOES persist mapDeltas (mempool_persist.cpp:101 "+
					"+166-203). If you genuinely want to revert FIX-76, "+
					"update the comment AND the dump path AND the tests "+
					"together.", name, phrase)
			}
		}
	}
}
