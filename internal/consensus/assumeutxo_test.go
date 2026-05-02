package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestMainnetAssumeUTXO944183 pins the hashhog-local snapshot entry that
// covers /data/nvme1/hashhog-mainnet/utxo-snapshot-raw.dat (165,095,935 coins,
// base block 0000...d817 at height 944,183). This snapshot recovered blockbrew
// after a chainstate-corruption wedge at h=938,344 from a SIGKILL-during-flush;
// the entry is NOT in Bitcoin Core's chainparams.cpp but the four 840k/880k/
// 910k/935k entries are.
//
// What this test pins:
//
//   - Display-order strings in the source compile to internal-order bytes
//     (mustParseHash reverses display→raw), so loadtxoutset's
//     ForBlockHash(meta.BlockHash) lookup against the snapshot file's raw
//     base block hash succeeds.
//   - HashSerialized (after the same display→raw reversal) equals the raw
//     SHA256d output of ComputeHashSerialized for this snapshot. The raw form
//     "a888bcbc...af2e" was produced by tools/compute-snapshot-hash.py from
//     the actual 9.4 GB on-disk file. If a future edit accidentally stores
//     the source-code string in raw order, this test catches it.
//
// If this test starts failing, do NOT change the snapshot — verify against
// tools/compute-snapshot-hash.py output and check that the four sibling
// entries still parse with the same display-order convention.
func TestMainnetAssumeUTXO944183(t *testing.T) {
	const (
		// raw SHA256d (HashWriter::GetHash() output) over TxOutSer of all
		// 165,095,935 coins; reproducible via tools/compute-snapshot-hash.py.
		rawHashSerializedHex = "a888bcbc200384747c0813c8e7f4650d9bc0847b5147791c3ca869567271af2e"
		// uint256.ToString() of the same digest (raw bytes reversed). This is
		// the form that appears in MainnetAssumeUTXOParams.
		displayHashSerializedHex = "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
		// snapshot base block hash (display order = blockchain.com / explorer
		// view), at height 944,183.
		displayBlockHashHex = "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
		expectedHeight      = int32(944183)
		expectedChainTxCnt  = uint64(1334000000)
	)

	auData := MainnetAssumeUTXOParams.ForHeight(expectedHeight)
	if auData == nil {
		t.Fatalf("ForHeight(%d) returned nil; expected the hashhog-local snapshot entry",
			expectedHeight)
	}
	if auData.Height != expectedHeight {
		t.Errorf("Height = %d, want %d", auData.Height, expectedHeight)
	}
	if auData.ChainTxCount != expectedChainTxCnt {
		t.Errorf("ChainTxCount = %d, want %d", auData.ChainTxCount, expectedChainTxCnt)
	}

	// Reading the snapshot header (od -t x1 utxo-snapshot-raw.dat | head -2)
	// shows BlockHash bytes "17 d8 ce 98 33 32 45 ab a5 17 0d c0 c6 9a 0e 9d
	// 83 03 16 0a 18 46 01 00 00 00 00 00 00 00 00 00" — i.e. the display
	// hash with bytes reversed. ForBlockHash takes a wire.Hash256 in that
	// raw/internal order, so we reverse the display string here.
	wantBlockHash, err := wire.NewHash256FromHex(displayBlockHashHex)
	if err != nil {
		t.Fatalf("NewHash256FromHex(blockhash): %v", err)
	}
	if auData.BlockHash != wantBlockHash {
		t.Errorf("BlockHash = %x, want %x (raw/internal order, reversed display)",
			auData.BlockHash[:], wantBlockHash[:])
	}

	// HashSerialized comparison: the field is wire.Hash256 in raw byte order
	// (it gets compared directly against ComputeHashSerialized's output, which
	// is sha256.Sum256(...) — naturally raw). NewHash256FromHex reverses, so
	// passing displayHashSerializedHex through it produces the raw form.
	wantHashSerialized, err := wire.NewHash256FromHex(displayHashSerializedHex)
	if err != nil {
		t.Fatalf("NewHash256FromHex(hash_serialized): %v", err)
	}
	if auData.HashSerialized != wantHashSerialized {
		t.Errorf("HashSerialized = %x, want %x (raw/internal order)",
			auData.HashSerialized[:], wantHashSerialized[:])
	}

	// Belt-and-braces: explicitly assert that the raw bytes of HashSerialized
	// equal the 32-byte big-endian decoding of rawHashSerializedHex. This
	// catches a regression where someone "helpfully" pre-reverses the source
	// string to match the raw form, which would double-flip after mustParseHash.
	for i := 0; i < 32; i++ {
		var expected byte
		if _, err := fmtSscanf(rawHashSerializedHex[i*2:i*2+2], &expected); err != nil {
			t.Fatalf("decode raw hex byte %d: %v", i, err)
		}
		if auData.HashSerialized[i] != expected {
			t.Errorf("HashSerialized[%d] = %02x, want %02x (raw form: %s)",
				i, auData.HashSerialized[i], expected, rawHashSerializedHex)
		}
	}

	// ForBlockHash is the path loadtxoutset takes — verify it resolves.
	auByHash := MainnetAssumeUTXOParams.ForBlockHash(wantBlockHash)
	if auByHash == nil {
		t.Fatalf("ForBlockHash(%x) returned nil; would block loadtxoutset",
			wantBlockHash[:])
	}
	if auByHash.Height != expectedHeight {
		t.Errorf("ForBlockHash returned height %d, want %d", auByHash.Height, expectedHeight)
	}
}

// fmtSscanf is a tiny shim for the byte-by-byte verification above; it parses
// a 2-char hex byte. We avoid pulling in fmt.Sscanf directly because that
// import is otherwise unused in this test file.
func fmtSscanf(s string, b *byte) (int, error) {
	hi, err := hexNibble(s[0])
	if err != nil {
		return 0, err
	}
	lo, err := hexNibble(s[1])
	if err != nil {
		return 0, err
	}
	*b = (hi << 4) | lo
	return 1, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, errBadHexNibble
	}
}

var errBadHexNibble = &hexErr{}

type hexErr struct{}

func (*hexErr) Error() string { return "bad hex nibble" }
