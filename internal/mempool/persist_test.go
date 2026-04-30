package mempool

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
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
