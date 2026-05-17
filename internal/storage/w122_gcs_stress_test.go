package storage

// W122 — BIP-158 GCS codec stress-vector audit.
//
// Background: haskoin W121 BUG-16 discovered a Word64 boundary bug in its GCS
// encoder that Core's `blockfilters.json` test vectors missed (because the
// quotients in those vectors stay small — q ≥ 64 essentially never fires for
// realistic block contents at M=784931, P=19). The bug only triggered when an
// element's Golomb quotient ≥ 64 AND the bit-stream had a non-zero prior
// `numBits` accumulator. Round-trip tests hide it because encode and decode
// share the same buggy shift.
//
// This test file exercises blockbrew's `bitStreamWriter` and
// `golombRiceEncode` at the same boundary conditions, plus stress vectors
// targeting the specific patterns that haskoin's audit recommended. It also
// asserts byte-exact compatibility with Bitcoin Core's `BitStreamWriter`
// (MSB-first packing) — round-trip alone is not sufficient.
//
// Findings (encoded as failing tests, not skipped):
//
//   BUG-1 (BLOCKBREW-W122-1, P0-CDIV)
//     bitStreamWriter.writeBits truncates when v shifted by numBits crosses
//     the uint64 boundary. Specifically, calling writeBits(0xFF..FF, 64) when
//     numBits > 0 silently drops the top numBits bits of v. Consequence: the
//     unary-Rice "all-ones run of 64" chunk loses bits if the previous element
//     left bits in the buffer, producing a corrupted Golomb-Rice stream that
//     no Core-compliant decoder can read.
//
//   BUG-2 (BLOCKBREW-W122-2, P0-CDIV)
//     bitStreamWriter / bitStreamReader use LSB-first bit packing within each
//     byte. Bitcoin Core's BitStreamWriter packs MSB-first (see
//     src/streams.h::BitStreamWriter::Write at lines 329-344 of bitcoin-core).
//     Effect: every filter blockbrew produces is byte-incompatible with Core,
//     even though the same buggy decoder reads them back correctly. Light
//     clients fetching filters via getcfilters from a blockbrew node will
//     compute the wrong filter header chain.
//
// Reference: bitcoin-core/src/streams.h BitStreamWriter, bitcoin-core/src/
// util/golombrice.h, BIP-158, haskoin commit 4a2de0f.

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// -----------------------------------------------------------------------------
// Reference encoder: byte-exact mirror of bitcoin-core/src/streams.h
// BitStreamWriter, packing MSB-first within each byte.
// -----------------------------------------------------------------------------

// coreBitStreamWriter mirrors Bitcoin Core's BitStreamWriter — MSB-first.
type coreBitStreamWriter struct {
	out     bytes.Buffer
	buf     uint8
	offset  int // number of bits already written into buf, 0..7
}

func (w *coreBitStreamWriter) Write(data uint64, nbits int) {
	for nbits > 0 {
		bits := 8 - w.offset
		if bits > nbits {
			bits = nbits
		}
		// Core's expression: m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
		var shifted uint64
		if nbits == 64 {
			// data << 0
			shifted = data
		} else {
			shifted = data << (64 - uint(nbits))
		}
		shifted = shifted >> (64 - 8 + uint(w.offset))
		w.buf |= uint8(shifted)
		w.offset += bits
		nbits -= bits
		if w.offset == 8 {
			w.out.WriteByte(w.buf)
			w.buf = 0
			w.offset = 0
		}
	}
}

func (w *coreBitStreamWriter) Flush() {
	if w.offset == 0 {
		return
	}
	w.out.WriteByte(w.buf)
	w.buf = 0
	w.offset = 0
}

func (w *coreBitStreamWriter) Bytes() []byte { return w.out.Bytes() }

// coreGolombRiceEncode mirrors Core's GolombRiceEncode in util/golombrice.h.
func coreGolombRiceEncode(w *coreBitStreamWriter, p uint, value uint64) {
	q := value >> p
	for q > 0 {
		n := q
		if n > 64 {
			n = 64
		}
		// Write n ones — Core: bitwriter.Write(std::bitset<64>(~0ULL << (64-n)).to_ullong(), n)
		// Equivalent: write (1<<n)-1 as the low n bits when n<64, or 0xFF..FF when n==64.
		var ones uint64
		if n == 64 {
			ones = ^uint64(0)
		} else {
			ones = (uint64(1) << n) - 1
		}
		w.Write(ones, int(n))
		q -= n
	}
	w.Write(0, 1)
	w.Write(value&((uint64(1)<<p)-1), int(p))
}

// coreEncodeGCS is a byte-exact reference implementation, mirroring
// bitcoin-core/src/blockfilter.cpp GCSFilter ctor that takes an ElementSet.
// Inputs must already be unique pkScripts; we re-hash + sort here.
func coreEncodeGCS(elements [][]byte, blockHash wire.Hash256) []byte {
	if len(elements) == 0 {
		return []byte{0}
	}
	k0 := binary.LittleEndian.Uint64(blockHash[:8])
	k1 := binary.LittleEndian.Uint64(blockHash[8:16])
	N := uint64(len(elements))
	F := N * BasicFilterM

	hashes := make([]uint64, len(elements))
	for i, e := range elements {
		h := siphash(k0, k1, e)
		hashes[i] = fastRange64(h, F)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })

	var out bytes.Buffer
	wire.WriteCompactSize(&out, N)

	bw := &coreBitStreamWriter{}
	var prev uint64
	for _, h := range hashes {
		delta := h - prev
		prev = h
		coreGolombRiceEncode(bw, BasicFilterP, delta)
	}
	bw.Flush()
	out.Write(bw.Bytes())
	return out.Bytes()
}

// -----------------------------------------------------------------------------
// BUG-1 — writeBits truncates v when numBits + n crosses uint64 width.
// -----------------------------------------------------------------------------

// TestW122_WriteBits64BitOverflow proves blockbrew's bitStreamWriter loses bits
// when writeBits(v, 64) is called with numBits > 0. The buffered prior bits
// + 64 new bits exceed the 64-bit accumulator, but the implementation does
// `accumBits |= v << numBits` which discards the top numBits bits of v.
//
// Concretely: write 5 bits (any nonzero), then write 64 ones, then read it back
// as 5 + 64 = 69 bits. We should observe 64 ones in the middle. With the bug,
// only 59 ones land before the buffer is flushed to bytes — the top 5 of the
// 64-bit value were shifted off into the void.
func TestW122_WriteBits64BitOverflow(t *testing.T) {
	w := &bitStreamWriter{}
	w.writeBits(0x1F, 5)                  // 5 ones in the accumulator
	w.writeBits(^uint64(0), 64)           // try to add 64 ones
	w.writeBits(0, 1)                     // terminator
	w.flush()

	// Decode it back: 5 ones + as many trailing ones as got encoded + a 0.
	r := newBitStreamReader(bytes.NewReader(w.bytes))
	first5, err := r.readBits(5)
	if err != nil {
		t.Fatalf("read first 5: %v", err)
	}
	if first5 != 0x1F {
		t.Errorf("first 5 bits = %#x, want 0x1F", first5)
	}

	// Count trailing ones until a zero.
	count := 0
	for {
		b, err := r.readBits(1)
		if err != nil {
			t.Fatalf("read bit: %v", err)
		}
		if b == 0 {
			break
		}
		count++
	}
	if count != 64 {
		t.Errorf("BUG-1 confirmed (P0-CDIV): expected 64 trailing ones after 5-bit prefix, "+
			"got %d. bitStreamWriter.writeBits silently drops bits when v<<numBits overflows uint64. "+
			"Symptom: golombRiceEncode emits a corrupted unary run whenever an element's Golomb "+
			"quotient ≥ 64 AND the prior element left bits in the accumulator.", count)
	}
}

// TestW122_WriteBits64WithVariousNumBits exhaustively covers every starting
// numBits in [1..7] paired with writeBits(0xFF..FF, 64). The encoder bug fires
// whenever numBits > 0 because `v << numBits` for v with the top numBits bits
// set discards exactly those bits.
func TestW122_WriteBits64WithVariousNumBits(t *testing.T) {
	for prior := uint(1); prior <= 7; prior++ {
		prior := prior
		t.Run("prior_"+string(rune('0'+prior)), func(t *testing.T) {
			w := &bitStreamWriter{}
			// Write `prior` ones to set numBits = prior.
			for i := uint(0); i < prior; i++ {
				w.writeBits(1, 1)
			}
			w.writeBits(^uint64(0), 64)
			w.writeBits(0, 1)
			w.flush()

			r := newBitStreamReader(bytes.NewReader(w.bytes))
			for i := uint(0); i < prior; i++ {
				b, _ := r.readBits(1)
				if b != 1 {
					t.Errorf("prior bit %d != 1", i)
				}
			}
			count := 0
			for {
				b, err := r.readBits(1)
				if err != nil {
					t.Fatalf("eof after %d ones", count)
				}
				if b == 0 {
					break
				}
				count++
			}
			if count != 64 {
				t.Errorf("BUG-1 with prior=%d: counted %d ones, want 64", prior, count)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// BUG-2 — bit ordering within a byte differs from Bitcoin Core.
// -----------------------------------------------------------------------------

// TestW122_BitOrderingVsCore verifies that bytes emitted by blockbrew's
// bitStreamWriter match what Core's BitStreamWriter produces for the same
// sequence of (value, nbits) calls. They do not: blockbrew packs LSB-first
// within each byte; Core packs MSB-first.
//
// This means every BIP-158 filter byte-string produced by blockbrew differs
// from what Core produces for the same block, breaking the BIP-157
// getcfilters / getcfheaders / getcfcheckpt service contract for any peer
// that fetches filters from a blockbrew node and validates them against the
// expected Core-format filter-header chain.
func TestW122_BitOrderingVsCore(t *testing.T) {
	// Write a known short pattern: 4 bits = 0xA (= 0b1010), 4 bits = 0x5 (= 0b0101).
	// Core MSB-first → first byte 0xA5. Blockbrew LSB-first → first byte 0x5A.
	bb := &bitStreamWriter{}
	bb.writeBits(0xA, 4)
	bb.writeBits(0x5, 4)
	bb.flush()

	core := &coreBitStreamWriter{}
	core.Write(0xA, 4)
	core.Write(0x5, 4)
	core.Flush()

	if bytes.Equal(bb.bytes, core.Bytes()) {
		t.Logf("OK — orderings agreed for this case")
		return
	}
	t.Errorf("BUG-2 confirmed (P0-CDIV): bit ordering within byte differs from Bitcoin Core.\n"+
		"  blockbrew bytes = %x (LSB-first packing)\n"+
		"  Core bytes      = %x (MSB-first packing per src/streams.h BitStreamWriter)\n"+
		"Effect: every BIP-158 filter blockbrew emits is byte-incompatible with Core's "+
		"GetEncoded(). Cross-node filter-header chains (BIP-157) will diverge for any peer "+
		"fetching cfilters from a blockbrew node.",
		bb.bytes, core.Bytes())
}

// TestW122_GenesisFilterByteExact checks the most basic conformance: the
// BIP-158 basic filter for the Bitcoin Core blockfilters.json vector entry at
// height 0 must equal the hex string `019dfca8` (4 bytes, from bitcoin-core/
// src/test/data/blockfilters.json, "Basic Filter" field). The leading 01 is
// the CompactSize element count; the remaining 3 bytes encode the single
// Golomb-Rice value for the lone coinbase P2PK output. Core's
// blockfilter_tests.cpp `blockfilters_json_test` performs exactly this byte-
// exact comparison on every CI build, so the existing blockbrew comment
// ("vectors don't match current Core") is incorrect.
//
// Note: blockfilters.json's "height 0" entry uses a synthetic block whose
// hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
// (not the mainnet genesis hash). The block hash drives the SipHash key.
func TestW122_GenesisFilterByteExact(t *testing.T) {
	// Coinbase output script from the height-0 vector's raw block: 65-byte
	// uncompressed pubkey + OP_CHECKSIG (P2PK).
	genesisScript := []byte{
		0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
		0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61,
		0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1,
		0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1,
		0x1d, 0x5f, 0xac,
	}
	// Display-form (big-endian) hash from the vector entry. The internal
	// memory layout is little-endian (reversed).
	displayHash := []byte{
		0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97, 0x79, 0xba,
		0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8, 0xd7, 0x7f, 0x49, 0x43,
	}
	var blockHash wire.Hash256
	for i := 0; i < 32; i++ {
		blockHash[i] = displayHash[31-i]
	}

	got := encodeGCS([][]byte{genesisScript}, blockHash)
	want := []byte{0x01, 0x9d, 0xfc, 0xa8}

	if bytes.Equal(got, want) {
		t.Logf("OK — blockbrew emits Core-compatible bytes for blockfilters.json height-0 vector")
		return
	}

	// Cross-check with our reference encoder.
	ref := coreEncodeGCS([][]byte{genesisScript}, blockHash)

	t.Errorf("BUG-2 confirmed (P0-CDIV): height-0 vector filter bytes do not match Bitcoin Core.\n"+
		"  blockbrew = %x\n"+
		"  Core JSON = %x\n"+
		"  reference (this file's coreEncodeGCS) = %x\n"+
		"Comment at blockfilterindex_test.go:541 (\"vectors were generated by an older build\") "+
		"is incorrect — Core's blockfilters_json_test BOOST_CHECKs filter_basic byte-exactly on "+
		"every CI build. Cause: bitStreamWriter packs LSB-first; Core packs MSB-first.",
		got, want, ref)
}

// -----------------------------------------------------------------------------
// Stress vectors recommended by W122 brief: quotients 0/1/63/64/65/100/200/1000
// plus sequential patterns, empty/single/all-zero. These exercise the unary
// loop boundary.
// -----------------------------------------------------------------------------

// TestW122_GolombRiceQuotientStress encodes specific (q, r) pairs by feeding
// in values value = (q << p) | r and verifies round-trip. With BUG-1, round-
// trips for q ≥ 64 with a non-zero prior bit-stream state CAN succeed (the
// decoder reads the same broken format) but the byte string differs from a
// Core encoder. We use the reference coreEncodeGCS / coreGolombRiceEncode +
// MSB-first reader (not implemented here; we compare byte strings only) to
// pinpoint divergence.
func TestW122_GolombRiceQuotientStress(t *testing.T) {
	cases := []struct {
		name string
		q    uint64
		r    uint64
	}{
		{"q0_r0", 0, 0},
		{"q0_rmax", 0, (1 << BasicFilterP) - 1},
		{"q1_r0", 1, 0},
		{"q63_r123", 63, 123},
		{"q64_r0", 64, 0},           // BOUNDARY: unary loop emits exactly one chunk of 64
		{"q64_rmax", 64, (1 << BasicFilterP) - 1},
		{"q65_r0", 65, 0},           // BOUNDARY: 64 + 1
		{"q100_r99", 100, 99},
		{"q128_r0", 128, 0},         // BOUNDARY: 2 chunks of 64
		{"q200_r12345", 200, 12345},
		{"q1000_r7", 1000, 7},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			value := (tc.q << BasicFilterP) | tc.r

			// blockbrew encoder
			bw := &bitStreamWriter{}
			golombRiceEncode(bw, BasicFilterP, value)
			bw.flush()

			// reference (Core-shaped) encoder
			cw := &coreBitStreamWriter{}
			coreGolombRiceEncode(cw, BasicFilterP, value)
			cw.Flush()

			if !bytes.Equal(bw.bytes, cw.Bytes()) {
				t.Errorf("BUG-2 byte divergence at (q=%d,r=%d):\n  blockbrew = %x\n  Core ref  = %x",
					tc.q, tc.r, bw.bytes, cw.Bytes())
			}

			// Round-trip on blockbrew side
			br := newBitStreamReader(bytes.NewReader(bw.bytes))
			decoded, err := golombRiceDecode(&br, BasicFilterP)
			if err != nil {
				t.Errorf("round-trip decode failed: %v", err)
				return
			}
			if decoded != value {
				t.Errorf("round-trip mismatch: encoded %d (q=%d r=%d), decoded %d",
					value, tc.q, tc.r, decoded)
			}
		})
	}
}

// TestW122_UnaryRunsAfterPriorBits is the targeted regression for BUG-1.
// It composes the exact pattern that fires the bug in practice: encode an
// element with q small (leaving prior bits in the buffer), then a second
// element with q ≥ 64. Decode and verify both values come back.
func TestW122_UnaryRunsAfterPriorBits(t *testing.T) {
	// First element: q=1, r=5. After encoding: "10" + 19-bit r → 21 bits.
	// 21 mod 8 = 5 → numBits=5 in the writer when we start encoding element 2.
	v1 := (uint64(1) << BasicFilterP) | 5
	// Second element: q=64, r=0. Delta = 64*2^19. With BUG-1, the 64-ones
	// unary chunk loses the top 5 bits when shifted by numBits=5.
	v2Delta := uint64(64) << BasicFilterP

	bw := &bitStreamWriter{}
	golombRiceEncode(bw, BasicFilterP, v1)
	golombRiceEncode(bw, BasicFilterP, v2Delta)
	bw.flush()

	br := newBitStreamReader(bytes.NewReader(bw.bytes))
	got1, err := golombRiceDecode(&br, BasicFilterP)
	if err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	got2, err := golombRiceDecode(&br, BasicFilterP)
	if err != nil {
		t.Fatalf("decode v2: %v", err)
	}

	if got1 != v1 {
		t.Errorf("v1 mismatch: got %d, want %d", got1, v1)
	}
	if got2 != v2Delta {
		t.Errorf("BUG-1 manifests on round-trip: v2 mismatch got %d, want %d. "+
			"With numBits=5 left from v1, writeBits(^uint64(0), 64) truncates "+
			"the top 5 bits — the unary run becomes 59 ones instead of 64, and the "+
			"decoder reads quotient=59 instead of 64.", got2, v2Delta)
	}
}

// -----------------------------------------------------------------------------
// CompactSize / Empty / All-zero sanity vectors.
// -----------------------------------------------------------------------------

// TestW122_EmptyFilterByteExact: a block with zero matching elements MUST
// encode as exactly the single byte 0x00 (CompactSize 0) with no trailing
// bit-stream payload. Same in Core, see blockfilter.cpp ctor early-return.
func TestW122_EmptyFilterByteExact(t *testing.T) {
	bh := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
	got := encodeGCS(nil, bh)
	want := []byte{0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("empty filter = %x, want %x", got, want)
	}
}

// TestW122_SingleElementSweep stress-tests round-trip for a sweep of element
// values that produce a range of quotients including the q=64 boundary.
func TestW122_SingleElementSweep(t *testing.T) {
	bh := wire.Hash256{0x01, 0x02, 0x03}
	for n := 0; n < 200; n++ {
		// Synthetic element whose value-space stretches over many quotients.
		elem := []byte{byte(n), byte(n >> 8), 0xAA, 0xBB}
		filter := encodeGCS([][]byte{elem}, bh)
		match, err := matchGCS(filter, bh, [][]byte{elem})
		if err != nil {
			t.Errorf("n=%d match err: %v", n, err)
			continue
		}
		if !match {
			t.Errorf("n=%d: element does not match its own filter (round-trip broken)", n)
		}
	}
}

// TestW122_LargeFilterStress builds a filter with many elements designed to
// produce a quotient ≥ 64 somewhere in the encoding. Round-trip should
// preserve match semantics; byte-exact equality with a Core reference is
// what we verify here so the BUG-2 LSB-first issue surfaces consistently
// across element counts.
func TestW122_LargeFilterStress(t *testing.T) {
	bh := wire.Hash256{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	elements := make([][]byte, 0, 256)
	for i := 0; i < 256; i++ {
		elements = append(elements, []byte{byte(i), byte(i ^ 0xAA), 0xCC, 0xDD, byte(i * 3)})
	}

	got := encodeGCS(elements, bh)
	ref := coreEncodeGCS(elements, bh)
	if !bytes.Equal(got, ref) {
		t.Errorf("BUG-2 large-filter divergence:\n  blockbrew first 32 bytes: %x...\n  Core ref first 32 bytes:  %x...\n"+
			"lengths: blockbrew=%d core=%d",
			got[:min(32, len(got))], ref[:min(32, len(ref))], len(got), len(ref))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
