package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestWriteTxOutSerLayout pins the byte layout of WriteTxOutSer to match the
// reference in bitcoin-core/src/kernel/coinstats.cpp::TxOutSer:
//
//	[ 32B txid LE ] [ 4B vout LE ] [ 4B (height<<1)|coinbase LE ]
//	[ 8B nValue LE ] [ CompactSize len(script) ] [ script bytes ]
//
// If anyone reorders fields, omits a length prefix, or "helpfully" replaces
// the uint32 code with a varint (we have a CoreSerializeCoin path that does
// that — different code path), the assumeutxo digest stops matching Core.
// This test catches that statically.
func TestWriteTxOutSerLayout(t *testing.T) {
	op := wire.OutPoint{}
	for i := 0; i < 32; i++ {
		op.Hash[i] = byte(0x10 + i)
	}
	op.Index = 0xdeadbeef

	entry := &UTXOEntry{
		Amount:     0x0011223344556677,
		PkScript:   []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x88, 0xac},
		Height:     0x12345,
		IsCoinbase: true,
	}

	var buf bytes.Buffer
	if err := WriteTxOutSer(&buf, op, entry); err != nil {
		t.Fatalf("WriteTxOutSer: %v", err)
	}

	got := buf.Bytes()

	// Hand-build the expected stream.
	var want []byte
	want = append(want, op.Hash[:]...)
	idx := make([]byte, 4)
	binary.LittleEndian.PutUint32(idx, op.Index)
	want = append(want, idx...)

	codeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(codeBuf, uint32(entry.Height)<<1|1)
	want = append(want, codeBuf...)

	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, uint64(entry.Amount))
	want = append(want, val...)

	// CompactSize for length 11 fits in one byte.
	want = append(want, byte(len(entry.PkScript)))
	want = append(want, entry.PkScript...)

	if !bytes.Equal(got, want) {
		t.Fatalf("TxOutSer mismatch\n  got:  %x\n  want: %x", got, want)
	}
}

// TestComputeHashSerializedTrivial: a one-coin UTXO set produces SHA256d over
// the single TxOutSer record. Pinning this guards the actual digest function.
func TestComputeHashSerializedTrivial(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	us := NewUTXOSet(chainDB)

	op := wire.OutPoint{Index: 0}
	op.Hash[0] = 0xab // distinguishable txid; rest zero.
	entry := &UTXOEntry{
		Amount:     1_00000000, // 1 BTC
		PkScript:   []byte{0x51},
		Height:     0,
		IsCoinbase: true,
	}
	us.AddUTXO(op, entry)

	got, count, err := ComputeHashSerialized(us)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	if count != 1 {
		t.Errorf("count: got %d, want 1", count)
	}

	var buf bytes.Buffer
	if err := WriteTxOutSer(&buf, op, entry); err != nil {
		t.Fatalf("WriteTxOutSer: %v", err)
	}
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])

	if !bytes.Equal(got[:], second[:]) {
		t.Fatalf("hash mismatch\n  got:  %x\n  want: %x", got[:], second[:])
	}
}

// TestComputeHashSerializedDeterministic: the iteration order of the cache map
// is randomized in Go, but ComputeHashSerialized must sort coins before
// hashing so the digest is stable across runs.
func TestComputeHashSerializedDeterministic(t *testing.T) {
	const n = 50
	build := func() *UTXOSet {
		memDB := storage.NewMemDB()
		chainDB := storage.NewChainDB(memDB)
		us := NewUTXOSet(chainDB)
		for i := 0; i < n; i++ {
			var op wire.OutPoint
			op.Hash[0] = byte(i)
			op.Hash[1] = byte(i * 7)
			op.Index = uint32(i % 4)
			entry := &UTXOEntry{
				Amount:     int64(1000 + i),
				PkScript:   []byte{0x51, byte(i)},
				Height:     int32(i + 100),
				IsCoinbase: i%2 == 0,
			}
			us.AddUTXO(op, entry)
		}
		return us
	}

	h1, n1, err := ComputeHashSerialized(build())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	h2, n2, err := ComputeHashSerialized(build())
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if n1 != n || n2 != n {
		t.Errorf("count mismatch: %d / %d, want %d", n1, n2, n)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic hash:\n  h1=%x\n  h2=%x", h1[:], h2[:])
	}
}

// TestComputeMuHashUTXOIsOrderInvariant: as a sanity check on the wiring,
// build the same set in two different insertion orders and confirm MuHash
// finalize digests match. This is testing the wiring layer; the underlying
// MuHash3072 primitive has its own order-invariance test in internal/crypto.
func TestComputeMuHashUTXOIsOrderInvariant(t *testing.T) {
	build := func(order []int) *UTXOSet {
		memDB := storage.NewMemDB()
		chainDB := storage.NewChainDB(memDB)
		us := NewUTXOSet(chainDB)
		for _, i := range order {
			var op wire.OutPoint
			op.Hash[0] = byte(i)
			op.Index = uint32(i)
			entry := &UTXOEntry{
				Amount:     int64(i + 1),
				PkScript:   []byte{0x76, byte(i)},
				Height:     int32(i),
				IsCoinbase: false,
			}
			us.AddUTXO(op, entry)
		}
		return us
	}

	h1, _, err := ComputeMuHashUTXO(build([]int{1, 2, 3, 4, 5}))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	h2, _, err := ComputeMuHashUTXO(build([]int{5, 1, 4, 2, 3}))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("MuHash UTXO digest depends on insertion order:\n  h1=%x\n  h2=%x", h1[:], h2[:])
	}
}
