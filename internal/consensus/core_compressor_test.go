package consensus

import (
	"bytes"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestCompressAmountKnownVectors checks CompressAmount against the
// canonical examples from Bitcoin Core (compressor.cpp comment block):
//
//	0           -> 0
//	1           -> 1 + 10*(0*9 + 1 - 1) + 0 = 1
//	100000000   -> 1 + 10*(0)*9 + 9 = 8 (i.e. 1 BTC; e=8, n=1, d=1 nope...)
//
// The simpler invariants are: f(0)=0, and f(g(x))=x for any x, and
// CompressAmount(100_000_000_00) ("1 BTC" = 100M sats) round-trips, etc.
func TestCompressAmountKnownVectors(t *testing.T) {
	cases := []struct {
		in   uint64
		want uint64 // computed from the Python reference implementation of CompressAmount.
	}{
		{0, 0},
		// 1 sat: e=0, n=0 after dropping d=1 → 1 + (0*9 + 1 - 1)*10 + 0 = 1.
		{1, 1},
		// 9 sats: e=0, d=9, n=0 → 1 + (0*9 + 9 - 1)*10 + 0 = 81.
		{9, 81},
		// 10 sats: e=1, n→1 with d=1 (since 10/10=1, 1%10=1, 1/10=0): 1 + (0*9 + 1 - 1)*10 + 1 = 2.
		{10, 2},
		// 100_000_000 sats (= 1 BTC). 1e8 = 1 * 10^8 → e=8, n=1, d=1: 1 + (0*9+0)*10+8 = 9.
		{100_000_000, 9},
		// MaxMoney (21M BTC = 2.1e15 sats) round-trips.
	}
	for _, c := range cases {
		got := CompressAmount(c.in)
		if got != c.want {
			t.Errorf("CompressAmount(%d) = %d, want %d", c.in, got, c.want)
		}
		back := DecompressAmount(got)
		if back != c.in {
			t.Errorf("DecompressAmount(CompressAmount(%d)) = %d, want %d", c.in, back, c.in)
		}
	}
}

// TestCompressAmountRoundTrip exercises a battery of values across the
// representable amount space.
func TestCompressAmountRoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 9, 10, 99, 100, 1000, 12345, 99999999,
		100_000_000,           // 1 BTC
		2_100_000_000_000_000, // MaxMoney
		1_111_111_111,
		7_654_321_000,
	}
	for _, v := range values {
		c := CompressAmount(v)
		d := DecompressAmount(c)
		if d != v {
			t.Errorf("round-trip failed: %d -> %d -> %d", v, c, d)
		}
	}
}

// TestCoreVarIntKnownVectors checks Core's VARINT encoding against the
// reference (serialize.h WriteVarInt) for canonical values.  These bytes
// were computed by hand from the algorithm.
func TestCoreVarIntKnownVectors(t *testing.T) {
	cases := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7F, []byte{0x7F}},
		{0x80, []byte{0x80, 0x00}},
		{0xFF, []byte{0x80, 0x7F}},
		{0x100, []byte{0x81, 0x00}},
		{0x3FFF, []byte{0xFE, 0x7F}},
		{0x4000, []byte{0xFF, 0x00}},
		{0x4001, []byte{0xFF, 0x01}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := WriteCoreVarInt(&buf, c.n); err != nil {
			t.Fatalf("WriteCoreVarInt(%d): %v", c.n, err)
		}
		got := buf.Bytes()
		if !bytes.Equal(got, c.want) {
			t.Errorf("WriteCoreVarInt(%d) = %x, want %x", c.n, got, c.want)
		}
		v, err := ReadCoreVarInt(bytes.NewReader(got))
		if err != nil {
			t.Errorf("ReadCoreVarInt(%x): %v", got, err)
		}
		if v != c.n {
			t.Errorf("ReadCoreVarInt(%x) = %d, want %d", got, v, c.n)
		}
	}
}

// TestCoreVarIntRoundTrip exercises a wider range.
func TestCoreVarIntRoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 127, 128, 255, 256, 16383, 16384,
		1 << 20, 1 << 32, (1 << 56), ^uint64(0) >> 1,
	}
	for _, v := range values {
		var buf bytes.Buffer
		if err := WriteCoreVarInt(&buf, v); err != nil {
			t.Fatalf("WriteCoreVarInt(%d): %v", v, err)
		}
		got, err := ReadCoreVarInt(&buf)
		if err != nil {
			t.Fatalf("ReadCoreVarInt: %v", err)
		}
		if got != v {
			t.Errorf("VARINT round-trip: %d -> %d", v, got)
		}
	}
}

// TestCoreCompressScriptP2PKH verifies a P2PKH script compresses to
// 0x00 + 20-byte hash and decompresses back to the original bytes.
func TestCoreCompressScriptP2PKH(t *testing.T) {
	// hash160 = 0x11..0x14 repeated for 20 bytes (a stand-in)
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	script := append([]byte{0x76, 0xa9, 0x14}, hash[:]...)
	script = append(script, 0x88, 0xac)

	compressed, ok := CoreCompressScript(script)
	if !ok {
		t.Fatalf("expected P2PKH to compress, got ok=false")
	}
	if len(compressed) != 21 || compressed[0] != coreScriptP2PKH {
		t.Fatalf("compressed[0]=%d len=%d, want tag=0x00 len=21", compressed[0], len(compressed))
	}
	if !bytes.Equal(compressed[1:], hash[:]) {
		t.Errorf("compressed body mismatch")
	}

	roundtrip, err := CoreDecompressScript(0x00, compressed[1:])
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(roundtrip, script) {
		t.Errorf("P2PKH round-trip mismatch:\n  got  %x\n  want %x", roundtrip, script)
	}
}

// TestCoreCompressScriptP2SH verifies P2SH compression to 0x01 + 20.
func TestCoreCompressScriptP2SH(t *testing.T) {
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(0xA0 + i)
	}
	script := append([]byte{0xa9, 0x14}, hash[:]...)
	script = append(script, 0x87)

	compressed, ok := CoreCompressScript(script)
	if !ok || compressed[0] != coreScriptP2SH || len(compressed) != 21 {
		t.Fatalf("P2SH compress: ok=%v tag=%d len=%d", ok, compressed[0], len(compressed))
	}
	if !bytes.Equal(compressed[1:], hash[:]) {
		t.Errorf("P2SH body mismatch")
	}
	roundtrip, err := CoreDecompressScript(0x01, compressed[1:])
	if err != nil {
		t.Fatalf("decompress P2SH: %v", err)
	}
	if !bytes.Equal(roundtrip, script) {
		t.Errorf("P2SH round-trip mismatch")
	}
}

// TestCoreCompressScriptP2PKCompressed verifies the 33-byte compressed
// pubkey form: 33 <33B pubkey> OP_CHECKSIG → tag 0x02 or 0x03 + 32B.
func TestCoreCompressScriptP2PKCompressed(t *testing.T) {
	// Real curve point: G's x-coord (0x79be...) with parity 0x02.
	// Using a known compressed pubkey (secp256k1 generator).
	pubkey := []byte{
		0x02,
		0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
		0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
		0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
		0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	}
	script := append([]byte{33}, pubkey...)
	script = append(script, 0xac)

	compressed, ok := CoreCompressScript(script)
	if !ok {
		t.Fatalf("expected P2PK compressed to be recognised")
	}
	if compressed[0] != 0x02 || len(compressed) != 33 {
		t.Fatalf("tag=%d len=%d, want 0x02 + 33", compressed[0], len(compressed))
	}
	if !bytes.Equal(compressed[1:], pubkey[1:]) {
		t.Errorf("P2PK body mismatch")
	}
	roundtrip, err := CoreDecompressScript(0x02, compressed[1:])
	if err != nil {
		t.Fatalf("decompress P2PK compressed: %v", err)
	}
	if !bytes.Equal(roundtrip, script) {
		t.Errorf("P2PK compressed round-trip mismatch")
	}
}

// TestCoreCompressScriptP2PKUncompressed verifies the 65-byte
// uncompressed P2PK form: 65 <65B pubkey> OP_CHECKSIG → tag 0x04|parity
// + 32B (x-coord), and that decompression via secp256k1 recovers the
// full 65-byte form bit-for-bit.
func TestCoreCompressScriptP2PKUncompressed(t *testing.T) {
	// Derive an uncompressed form by parsing G then re-serialising.
	// This avoids hard-coding 65 bytes that could go stale.
	compressedG := []byte{
		0x02,
		0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
		0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
		0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
		0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	}
	// Parse + re-serialize uncompressed, then build the script.
	pub, err := parseAndUncompress(compressedG)
	if err != nil {
		t.Fatalf("parse compressed G: %v", err)
	}
	if len(pub) != 65 {
		t.Fatalf("uncompressed pubkey len = %d, want 65", len(pub))
	}
	script := append([]byte{65}, pub...)
	script = append(script, 0xac)

	compressed, ok := CoreCompressScript(script)
	if !ok {
		t.Fatalf("expected uncompressed P2PK to be recognised")
	}
	// G's Y coordinate is even, so tag should be 0x04.
	if compressed[0] != 0x04 && compressed[0] != 0x05 {
		t.Fatalf("expected 0x04/0x05 tag, got 0x%02x", compressed[0])
	}
	if len(compressed) != 33 {
		t.Fatalf("compressed len = %d, want 33", len(compressed))
	}
	roundtrip, err := CoreDecompressScript(uint64(compressed[0]), compressed[1:])
	if err != nil {
		t.Fatalf("decompress P2PK uncompressed: %v", err)
	}
	if !bytes.Equal(roundtrip, script) {
		t.Errorf("P2PK uncompressed round-trip mismatch:\n  got  %x\n  want %x", roundtrip, script)
	}
}

// parseAndUncompress is a tiny helper to derive an uncompressed pubkey
// from a compressed one, used only in tests so we don't hard-code 65B.
func parseAndUncompress(compressed []byte) ([]byte, error) {
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, err
	}
	return pub.SerializeUncompressed(), nil
}

// TestCoreCompressScriptUnknown checks that non-special scripts fall
// through to the raw-script path.
func TestCoreCompressScriptUnknown(t *testing.T) {
	// OP_RETURN <push 4 bytes> "test"  — non-special.
	script := []byte{0x6a, 0x04, 't', 'e', 's', 't'}
	if _, ok := CoreCompressScript(script); ok {
		t.Errorf("OP_RETURN should not be recognised as special")
	}
}

// TestCoreSerializeCoinRoundTrip exercises Coin serialisation across
// every script variant.
func TestCoreSerializeCoinRoundTrip(t *testing.T) {
	mkP2PKH := func() []byte {
		out := []byte{0x76, 0xa9, 0x14}
		for i := 0; i < 20; i++ {
			out = append(out, byte(i))
		}
		return append(out, 0x88, 0xac)
	}
	mkP2SH := func() []byte {
		out := []byte{0xa9, 0x14}
		for i := 0; i < 20; i++ {
			out = append(out, byte(0x80+i))
		}
		return append(out, 0x87)
	}
	mkUnknown := func() []byte {
		return []byte{0x00, 0x14, 'a', 'b', 'c', 'd'} // OP_0 push 0x14 — wrong length, treated as raw
	}
	cases := []struct {
		name  string
		entry *UTXOEntry
	}{
		{"p2pkh-1btc-coinbase", &UTXOEntry{Amount: 100_000_000, PkScript: mkP2PKH(), Height: 1, IsCoinbase: true}},
		{"p2sh-zero", &UTXOEntry{Amount: 0, PkScript: mkP2SH(), Height: 0, IsCoinbase: false}},
		{"unknown-50btc", &UTXOEntry{Amount: 50_00000000, PkScript: mkUnknown(), Height: 100000, IsCoinbase: false}},
		{"empty-script", &UTXOEntry{Amount: 1, PkScript: []byte{}, Height: 700000, IsCoinbase: false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := CoreSerializeCoin(&buf, c.entry); err != nil {
				t.Fatalf("CoreSerializeCoin: %v", err)
			}
			got, err := CoreDeserializeCoin(&buf)
			if err != nil {
				t.Fatalf("CoreDeserializeCoin: %v", err)
			}
			if got.Amount != c.entry.Amount ||
				got.Height != c.entry.Height ||
				got.IsCoinbase != c.entry.IsCoinbase ||
				!bytes.Equal(got.PkScript, c.entry.PkScript) {
				t.Errorf("round-trip mismatch:\n  in  amount=%d h=%d cb=%v script=%x\n  out amount=%d h=%d cb=%v script=%x",
					c.entry.Amount, c.entry.Height, c.entry.IsCoinbase, c.entry.PkScript,
					got.Amount, got.Height, got.IsCoinbase, got.PkScript)
			}
		})
	}
}

// TestCoreSerializeCoinByteLayout pins the exact byte layout for a
// known P2PKH coin so any future regression is caught immediately.
//
// For amount = 1 BTC = 100_000_000 sats:
//   CompressAmount(100_000_000) = 9
//   VARINT(9) = 0x09
// For code = (height=1 << 1) | coinbase=1 = 3: VARINT(3) = 0x03
// For P2PKH script tag + 20-byte hash (no length prefix in compressed
//   form because the tag IS the size discriminator).
//
// Expected bytes: 0x03 0x09 0x00 <20 bytes of hash>.
func TestCoreSerializeCoinByteLayout(t *testing.T) {
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	script := append([]byte{0x76, 0xa9, 0x14}, hash[:]...)
	script = append(script, 0x88, 0xac)
	entry := &UTXOEntry{
		Amount:     100_000_000,
		PkScript:   script,
		Height:     1,
		IsCoinbase: true,
	}
	var buf bytes.Buffer
	if err := CoreSerializeCoin(&buf, entry); err != nil {
		t.Fatalf("CoreSerializeCoin: %v", err)
	}
	got := buf.Bytes()
	want := append([]byte{0x03, 0x09, 0x00}, hash[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("byte layout mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestSnapshotRoundTrip exercises the full WriteSnapshot → LoadSnapshot
// path on a small in-memory UTXOSet.  This is the end-to-end integration
// test for `dumptxoutset` / `loadtxoutset` / `--load-snapshot`.
func TestSnapshotRoundTrip(t *testing.T) {
	srcDB := storage.NewChainDB(storage.NewMemDB())
	src := NewUTXOSet(srcDB)

	mkP2PKH := func(seed byte) []byte {
		out := []byte{0x76, 0xa9, 0x14}
		for i := 0; i < 20; i++ {
			out = append(out, seed+byte(i))
		}
		return append(out, 0x88, 0xac)
	}

	// Populate with 4 coins across 2 txids, mixed flags.
	op := func(seed byte, idx uint32) wire.OutPoint {
		var h wire.Hash256
		for i := range h {
			h[i] = seed
		}
		return wire.OutPoint{Hash: h, Index: idx}
	}
	src.AddUTXO(op(0xAA, 0), &UTXOEntry{Amount: 50_00000000, PkScript: mkP2PKH(0x11), Height: 100, IsCoinbase: true})
	src.AddUTXO(op(0xAA, 1), &UTXOEntry{Amount: 1, PkScript: mkP2PKH(0x22), Height: 100, IsCoinbase: true})
	src.AddUTXO(op(0xBB, 0), &UTXOEntry{Amount: 25_00000000, PkScript: mkP2PKH(0x33), Height: 200, IsCoinbase: false})
	src.AddUTXO(op(0xBB, 7), &UTXOEntry{Amount: 12345, PkScript: []byte{0x6a, 0x02, 'h', 'i'}, Height: 300, IsCoinbase: false})

	var blockHash wire.Hash256
	for i := range blockHash {
		blockHash[i] = byte(0xC0 + i)
	}
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}

	var buf bytes.Buffer
	stats, err := WriteSnapshot(&buf, src, blockHash, netMagic)
	if err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	if stats.CoinsWritten != 4 {
		t.Errorf("coins written = %d, want 4", stats.CoinsWritten)
	}

	// Magic + version + 4-byte network magic + 32-byte hash + 8-byte count = 51-byte header.
	if buf.Len() < 51 {
		t.Fatalf("snapshot too short: %d bytes", buf.Len())
	}
	if !bytes.Equal(buf.Bytes()[:5], []byte{'u', 't', 'x', 'o', 0xff}) {
		t.Errorf("bad magic: %x", buf.Bytes()[:5])
	}

	// Load into a fresh UTXOSet via a fresh DB.
	dstDB := storage.NewChainDB(storage.NewMemDB())
	loaded, lstats, err := LoadSnapshot(&buf, dstDB, netMagic)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if lstats.CoinsLoaded != 4 {
		t.Errorf("coins loaded = %d, want 4", lstats.CoinsLoaded)
	}
	if lstats.BlockHash != blockHash {
		t.Errorf("blockhash mismatch: got %s want %s", lstats.BlockHash.String(), blockHash.String())
	}

	// Each coin must come back identical.
	for _, tc := range []struct {
		op   wire.OutPoint
		want *UTXOEntry
	}{
		{op(0xAA, 0), &UTXOEntry{Amount: 50_00000000, PkScript: mkP2PKH(0x11), Height: 100, IsCoinbase: true}},
		{op(0xAA, 1), &UTXOEntry{Amount: 1, PkScript: mkP2PKH(0x22), Height: 100, IsCoinbase: true}},
		{op(0xBB, 0), &UTXOEntry{Amount: 25_00000000, PkScript: mkP2PKH(0x33), Height: 200, IsCoinbase: false}},
		{op(0xBB, 7), &UTXOEntry{Amount: 12345, PkScript: []byte{0x6a, 0x02, 'h', 'i'}, Height: 300, IsCoinbase: false}},
	} {
		got := loaded.GetUTXO(tc.op)
		if got == nil {
			t.Errorf("missing coin %x:%d", tc.op.Hash, tc.op.Index)
			continue
		}
		if got.Amount != tc.want.Amount || got.Height != tc.want.Height ||
			got.IsCoinbase != tc.want.IsCoinbase || !bytes.Equal(got.PkScript, tc.want.PkScript) {
			t.Errorf("coin %x:%d round-trip mismatch:\n  got  amount=%d h=%d cb=%v script=%x\n  want amount=%d h=%d cb=%v script=%x",
				tc.op.Hash, tc.op.Index,
				got.Amount, got.Height, got.IsCoinbase, got.PkScript,
				tc.want.Amount, tc.want.Height, tc.want.IsCoinbase, tc.want.PkScript)
		}
	}
}

// TestSnapshotRejectsWrongMagic confirms a corrupted/stranger file is
// rejected at the magic-bytes check.
func TestSnapshotRejectsWrongMagic(t *testing.T) {
	junk := bytes.Repeat([]byte{0x42}, 64)
	dstDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err := LoadSnapshot(bytes.NewReader(junk), dstDB, [4]byte{0xf9, 0xbe, 0xb4, 0xd9})
	if err == nil {
		t.Fatalf("expected magic-bytes rejection, got nil")
	}
}

// TestSnapshotRejectsNetworkMismatch confirms a snapshot from another
// network is refused even if the magic + version are otherwise valid.
func TestSnapshotRejectsNetworkMismatch(t *testing.T) {
	srcDB := storage.NewChainDB(storage.NewMemDB())
	src := NewUTXOSet(srcDB)
	src.AddUTXO(wire.OutPoint{Index: 0}, &UTXOEntry{Amount: 1, PkScript: []byte{0x51}, Height: 1})

	var blockHash wire.Hash256
	mainnet := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	testnet := [4]byte{0x0b, 0x11, 0x09, 0x07}

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, src, blockHash, mainnet); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	dstDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err := LoadSnapshot(&buf, dstDB, testnet)
	if err == nil {
		t.Fatalf("expected network-mismatch error, got nil")
	}
}
