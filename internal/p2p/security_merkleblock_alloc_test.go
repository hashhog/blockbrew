package p2p

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Security audit C1:
// an 89-byte merkleblock payload with TxCount=0xFFFFFFFF and a hash count of
// 0x02000000 made MsgMerkleBlock.Deserialize reserve 32M × 32 B = 1 GiB before
// reading a single hash. Core never sizes a vector from an untrusted count
// (serialize.h MAX_VECTOR_ALLOCATE grows in 5 MB steps bounded by the data
// actually present), and it does not process an inbound merkleblock at all.

// c1MerkleBlockPayload is the audit's payload: an all-zero 80-byte header,
// TxCount=0xFFFFFFFF, hashCount=0x02000000 (FE 00 00 00 02), and nothing else.
func c1MerkleBlockPayload() []byte {
	var buf bytes.Buffer
	buf.Write(make([]byte, 80))
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	buf.Write([]byte{0xFE, 0x00, 0x00, 0x00, 0x02})
	return buf.Bytes()
}

// bytesAllocated reports the heap bytes allocated while running f.
func bytesAllocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestSecurityMerkleBlockAlloc_C1FrameRejectedWithoutGiBAlloc(t *testing.T) {
	payload := c1MerkleBlockPayload()
	if len(payload) != 89 {
		t.Fatalf("setup: payload is %d bytes, want 89", len(payload))
	}

	var err error
	allocated := bytesAllocated(func() {
		msg := &MsgMerkleBlock{}
		err = msg.Deserialize(bytes.NewReader(payload))
	})
	if err == nil {
		t.Fatal("Deserialize accepted a merkleblock claiming 0x02000000 hashes in 89 bytes")
	}
	const limit = 1 << 20
	if allocated >= limit {
		t.Fatalf("Deserialize of an 89-byte merkleblock allocated %d bytes (limit %d)", allocated, limit)
	}
}

// A hash count above what a 4,000,000-byte message can carry is refused by
// the constant bound even when the reader would have the bytes, so the bound
// does not depend on the reader type.
func TestSecurityMerkleBlockAlloc_HashCountAboveConstantRejected(t *testing.T) {
	const maxHashes = MaxPayloadSize / 32 // 125,000
	var buf bytes.Buffer
	buf.Write(make([]byte, 80))
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	wire.WriteCompactSize(&buf, maxHashes+1)
	buf.Write(make([]byte, 32*(maxHashes+1)))
	buf.WriteByte(0) // empty flags: the message is otherwise complete
	// A plain io.Reader with no Len(): only the constant can catch it.
	r := io.LimitReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	var err error
	allocated := bytesAllocated(func() {
		err = (&MsgMerkleBlock{}).Deserialize(r)
	})
	if err == nil {
		t.Fatal("Deserialize accepted a hash count above MaxPayloadSize/32")
	}
	if allocated >= 1<<20 {
		t.Fatalf("Deserialize allocated %d bytes before refusing", allocated)
	}
}

// The flags vector must be bounded by the bytes present, not a 1 MiB cap
// allocated up front.
func TestSecurityMerkleBlockAlloc_FlagsLengthBoundedByRemaining(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(make([]byte, 80))
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	wire.WriteCompactSize(&buf, 1)
	buf.Write(make([]byte, 32))
	wire.WriteCompactSize(&buf, 1<<20) // claims 1 MiB of flags, sends none
	var err error
	allocated := bytesAllocated(func() {
		err = (&MsgMerkleBlock{}).Deserialize(bytes.NewReader(buf.Bytes()))
	})
	if err == nil {
		t.Fatal("Deserialize accepted a flags length past the end of the payload")
	}
	if allocated >= 512<<10 {
		t.Fatalf("Deserialize allocated %d bytes for flags that were never sent", allocated)
	}
}

// A valid merkleblock still round-trips after the bound.
func TestSecurityMerkleBlockAlloc_ValidRoundTrip(t *testing.T) {
	in := &MsgMerkleBlock{
		TxCount: 3,
		Hashes:  []wire.Hash256{{0x01}, {0x02}, {0x03}},
		Flags:   []byte{0x1d},
	}
	var buf bytes.Buffer
	if err := in.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	out := &MsgMerkleBlock{}
	if err := out.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Deserialize of a valid merkleblock failed: %v", err)
	}
	if out.TxCount != 3 || len(out.Hashes) != 3 || out.Hashes[2] != in.Hashes[2] ||
		!bytes.Equal(out.Flags, in.Flags) {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

// A merkleblock that fails to parse must disconnect the peer: ReadMessage
// returns a fatal error, not a NonFatalMessageError that keeps the socket open
// for the next frame.
func TestSecurityMerkleBlockAlloc_ParseFailureIsFatal(t *testing.T) {
	if isNonCriticalMessage("merkleblock") {
		t.Fatal("merkleblock is still in isNonCriticalMessage")
	}
	payload := c1MerkleBlockPayload()
	sum1 := sha256.Sum256(payload)
	sum2 := sha256.Sum256(sum1[:])
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], RegtestMagic)
	copy(hdr[4:16], "merkleblock")
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	copy(hdr[20:24], sum2[:4])
	_, err := ReadMessage(bytes.NewReader(append(hdr, payload...)), RegtestMagic)
	if err == nil {
		t.Fatal("ReadMessage accepted the C1 merkleblock frame")
	}
	var nf *NonFatalMessageError
	if errors.As(err, &nf) {
		t.Fatalf("ReadMessage returned a non-fatal error for a bad merkleblock: %v", err)
	}
}
