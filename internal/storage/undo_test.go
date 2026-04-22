package storage

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestSpentCoinSerialize(t *testing.T) {
	tests := []struct {
		name     string
		coin     SpentCoin
	}{
		{
			name: "p2pkh output",
			coin: SpentCoin{
				TxOut: wire.TxOut{
					Value:    100000000, // 1 BTC
					PkScript: []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac},
				},
				Height:   500000,
				Coinbase: false,
			},
		},
		{
			name: "coinbase output",
			coin: SpentCoin{
				TxOut: wire.TxOut{
					Value:    5000000000, // 50 BTC
					PkScript: []byte{0x51}, // OP_TRUE
				},
				Height:   1,
				Coinbase: true,
			},
		},
		{
			name: "zero height non-coinbase",
			coin: SpentCoin{
				TxOut: wire.TxOut{
					Value:    0,
					PkScript: []byte{},
				},
				Height:   0,
				Coinbase: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.coin.Serialize(&buf); err != nil {
				t.Fatalf("Serialize failed: %v", err)
			}

			restored, err := DeserializeSpentCoin(&buf)
			if err != nil {
				t.Fatalf("DeserializeSpentCoin failed: %v", err)
			}

			if restored.Height != tt.coin.Height {
				t.Errorf("Height = %d, want %d", restored.Height, tt.coin.Height)
			}
			if restored.Coinbase != tt.coin.Coinbase {
				t.Errorf("Coinbase = %v, want %v", restored.Coinbase, tt.coin.Coinbase)
			}
			if restored.TxOut.Value != tt.coin.TxOut.Value {
				t.Errorf("Value = %d, want %d", restored.TxOut.Value, tt.coin.TxOut.Value)
			}
			if !bytes.Equal(restored.TxOut.PkScript, tt.coin.TxOut.PkScript) {
				t.Errorf("PkScript mismatch")
			}
		})
	}
}

func TestTxUndoSerialize(t *testing.T) {
	txUndo := TxUndo{
		SpentCoins: []SpentCoin{
			{
				TxOut:    wire.TxOut{Value: 1000000, PkScript: []byte{0x51}},
				Height:   100,
				Coinbase: false,
			},
			{
				TxOut:    wire.TxOut{Value: 2000000, PkScript: []byte{0x52}},
				Height:   200,
				Coinbase: true,
			},
		},
	}

	var buf bytes.Buffer
	if err := txUndo.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	restored, err := DeserializeTxUndo(&buf)
	if err != nil {
		t.Fatalf("DeserializeTxUndo failed: %v", err)
	}

	if len(restored.SpentCoins) != len(txUndo.SpentCoins) {
		t.Fatalf("SpentCoins count = %d, want %d", len(restored.SpentCoins), len(txUndo.SpentCoins))
	}

	for i := range txUndo.SpentCoins {
		if restored.SpentCoins[i].Height != txUndo.SpentCoins[i].Height {
			t.Errorf("coin %d Height = %d, want %d", i, restored.SpentCoins[i].Height, txUndo.SpentCoins[i].Height)
		}
		if restored.SpentCoins[i].Coinbase != txUndo.SpentCoins[i].Coinbase {
			t.Errorf("coin %d Coinbase = %v, want %v", i, restored.SpentCoins[i].Coinbase, txUndo.SpentCoins[i].Coinbase)
		}
	}
}

func TestBlockUndoSerialize(t *testing.T) {
	blockUndo := BlockUndo{
		TxUndos: []TxUndo{
			{
				SpentCoins: []SpentCoin{
					{TxOut: wire.TxOut{Value: 1000}, Height: 10, Coinbase: false},
				},
			},
			{
				SpentCoins: []SpentCoin{
					{TxOut: wire.TxOut{Value: 2000}, Height: 20, Coinbase: true},
					{TxOut: wire.TxOut{Value: 3000}, Height: 30, Coinbase: false},
				},
			},
		},
	}

	data := blockUndo.Serialize()

	restored, err := DeserializeBlockUndo(data)
	if err != nil {
		t.Fatalf("DeserializeBlockUndo failed: %v", err)
	}

	if len(restored.TxUndos) != len(blockUndo.TxUndos) {
		t.Fatalf("TxUndos count = %d, want %d", len(restored.TxUndos), len(blockUndo.TxUndos))
	}

	for i := range blockUndo.TxUndos {
		if len(restored.TxUndos[i].SpentCoins) != len(blockUndo.TxUndos[i].SpentCoins) {
			t.Errorf("tx %d SpentCoins count = %d, want %d",
				i, len(restored.TxUndos[i].SpentCoins), len(blockUndo.TxUndos[i].SpentCoins))
		}
	}
}

func TestBlockUndoEmptySerialize(t *testing.T) {
	// Genesis block has empty undo data
	blockUndo := BlockUndo{
		TxUndos: []TxUndo{},
	}

	data := blockUndo.Serialize()

	restored, err := DeserializeBlockUndo(data)
	if err != nil {
		t.Fatalf("DeserializeBlockUndo failed: %v", err)
	}

	if len(restored.TxUndos) != 0 {
		t.Errorf("TxUndos count = %d, want 0", len(restored.TxUndos))
	}
}

func TestBlockUndoPersistence(t *testing.T) {
	db := NewChainDB(NewMemDB())

	blockHash := wire.Hash256{0x01, 0x02, 0x03}
	blockUndo := &BlockUndo{
		TxUndos: []TxUndo{
			{
				SpentCoins: []SpentCoin{
					{
						TxOut:    wire.TxOut{Value: 5000000000, PkScript: []byte{0x76, 0xa9}},
						Height:   100,
						Coinbase: true,
					},
				},
			},
		},
	}

	// Write undo data
	if err := db.WriteBlockUndo(blockHash, blockUndo); err != nil {
		t.Fatalf("WriteBlockUndo failed: %v", err)
	}

	// Read it back
	restored, err := db.ReadBlockUndo(blockHash)
	if err != nil {
		t.Fatalf("ReadBlockUndo failed: %v", err)
	}

	// Verify
	if len(restored.TxUndos) != 1 {
		t.Fatalf("TxUndos count = %d, want 1", len(restored.TxUndos))
	}
	if len(restored.TxUndos[0].SpentCoins) != 1 {
		t.Fatalf("SpentCoins count = %d, want 1", len(restored.TxUndos[0].SpentCoins))
	}
	coin := restored.TxUndos[0].SpentCoins[0]
	if coin.Height != 100 {
		t.Errorf("Height = %d, want 100", coin.Height)
	}
	if !coin.Coinbase {
		t.Error("Coinbase should be true")
	}
	if coin.TxOut.Value != 5000000000 {
		t.Errorf("Value = %d, want 5000000000", coin.TxOut.Value)
	}

	// Delete undo data
	if err := db.DeleteBlockUndo(blockHash); err != nil {
		t.Fatalf("DeleteBlockUndo failed: %v", err)
	}

	// Should not exist anymore
	_, err = db.ReadBlockUndo(blockHash)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBlockUndoNotFound(t *testing.T) {
	db := NewChainDB(NewMemDB())

	unknownHash := wire.Hash256{0xff, 0xfe, 0xfd}
	_, err := db.ReadBlockUndo(unknownHash)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestBlockUndoCompressedRoundTrip exercises the v1 compressed undo format
// across a representative mix of script types.  It verifies that the
// compressed blob has the expected 0xFF leading tag, deserializes back to
// the input, and that the on-disk size is meaningfully smaller than the
// legacy uncompressed format.
func TestBlockUndoCompressedRoundTrip(t *testing.T) {
	// Mix of every script type CompressScript recognises plus a non-standard
	// one to exercise the scriptTypeUnknown branch.
	p2pkh := []byte{
		0x76, 0xa9, 0x14,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x88, 0xac,
	}
	p2sh := []byte{
		0xa9, 0x14,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
		0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
		0x87,
	}
	p2wpkh := []byte{
		0x00, 0x14,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
		0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	}
	p2wsh := []byte{
		0x00, 0x20,
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
		0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
		0x7f, 0x80,
	}
	p2tr := []byte{
		0x51, 0x20,
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
		0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
		0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
		0xaf, 0xb0,
	}
	weird := []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef} // OP_RETURN + 4 bytes

	original := &BlockUndo{
		TxUndos: []TxUndo{
			{
				SpentCoins: []SpentCoin{
					{TxOut: wire.TxOut{Value: 5_000_000_000, PkScript: p2pkh}, Height: 100, Coinbase: true},
					{TxOut: wire.TxOut{Value: 1, PkScript: p2sh}, Height: 0, Coinbase: false},
				},
			},
			{
				SpentCoins: []SpentCoin{
					{TxOut: wire.TxOut{Value: 12345, PkScript: p2wpkh}, Height: 700_000, Coinbase: false},
					{TxOut: wire.TxOut{Value: 21_000_000_00000000, PkScript: p2wsh}, Height: 800_000, Coinbase: false},
					{TxOut: wire.TxOut{Value: 1_000_000, PkScript: p2tr}, Height: 850_000, Coinbase: false},
					{TxOut: wire.TxOut{Value: 0, PkScript: weird}, Height: 1, Coinbase: false},
				},
			},
		},
	}

	compressed := original.Serialize()
	if len(compressed) == 0 {
		t.Fatal("Serialize returned empty blob")
	}
	if compressed[0] != undoTagCompressedV1 {
		t.Fatalf("Serialize first byte = 0x%02x, want 0x%02x (undoTagCompressedV1)",
			compressed[0], undoTagCompressedV1)
	}

	restored, err := DeserializeBlockUndo(compressed)
	if err != nil {
		t.Fatalf("DeserializeBlockUndo failed: %v", err)
	}

	if len(restored.TxUndos) != len(original.TxUndos) {
		t.Fatalf("TxUndos count = %d, want %d",
			len(restored.TxUndos), len(original.TxUndos))
	}
	for i := range original.TxUndos {
		oc := original.TxUndos[i].SpentCoins
		rc := restored.TxUndos[i].SpentCoins
		if len(rc) != len(oc) {
			t.Fatalf("tx %d coin count = %d, want %d", i, len(rc), len(oc))
		}
		for j := range oc {
			if rc[j].Height != oc[j].Height {
				t.Errorf("tx %d coin %d Height = %d, want %d",
					i, j, rc[j].Height, oc[j].Height)
			}
			if rc[j].Coinbase != oc[j].Coinbase {
				t.Errorf("tx %d coin %d Coinbase = %v, want %v",
					i, j, rc[j].Coinbase, oc[j].Coinbase)
			}
			if rc[j].TxOut.Value != oc[j].TxOut.Value {
				t.Errorf("tx %d coin %d Value = %d, want %d",
					i, j, rc[j].TxOut.Value, oc[j].TxOut.Value)
			}
			if !bytes.Equal(rc[j].TxOut.PkScript, oc[j].TxOut.PkScript) {
				t.Errorf("tx %d coin %d PkScript mismatch:\n got %x\nwant %x",
					i, j, rc[j].TxOut.PkScript, oc[j].TxOut.PkScript)
			}
		}
	}

	// Sanity-check the size win.  The legacy encoding writes 8 bytes per
	// amount + raw script bytes; the compressed encoding writes a varuint
	// amount + a (mostly) shorter compressed script.  For this fixture the
	// compressed form must be strictly smaller than the legacy form.
	legacy := serializeBlockUndoLegacy(original)
	if len(compressed) >= len(legacy) {
		t.Errorf("compressed size %d not smaller than legacy size %d",
			len(compressed), len(legacy))
	} else {
		t.Logf("undo size: legacy=%d compressed=%d (%.1f%% reduction)",
			len(legacy), len(compressed),
			100*(1-float64(len(compressed))/float64(len(legacy))))
	}
}

// TestBlockUndoLegacyDispatchStillReadable hand-constructs a legacy
// uncompressed blob (the format used before the v1 compression landed) and
// confirms DeserializeBlockUndo still parses it correctly.  This guards the
// backwards-compatibility contract on read for already-written undo data.
func TestBlockUndoLegacyDispatchStillReadable(t *testing.T) {
	original := &BlockUndo{
		TxUndos: []TxUndo{
			{
				SpentCoins: []SpentCoin{
					{
						TxOut:    wire.TxOut{Value: 5_000_000_000, PkScript: []byte{0x76, 0xa9, 0x14}},
						Height:   100,
						Coinbase: true,
					},
					{
						TxOut:    wire.TxOut{Value: 12345, PkScript: []byte{}},
						Height:   1,
						Coinbase: false,
					},
				},
			},
			{
				SpentCoins: []SpentCoin{
					{
						TxOut:    wire.TxOut{Value: 0, PkScript: []byte{0x6a}},
						Height:   200_000,
						Coinbase: false,
					},
				},
			},
		},
	}

	legacy := serializeBlockUndoLegacy(original)
	if legacy[0] == undoTagCompressedV1 {
		t.Fatalf("legacy blob unexpectedly starts with the compressed tag 0x%02x",
			undoTagCompressedV1)
	}

	restored, err := DeserializeBlockUndo(legacy)
	if err != nil {
		t.Fatalf("DeserializeBlockUndo (legacy) failed: %v", err)
	}

	if len(restored.TxUndos) != len(original.TxUndos) {
		t.Fatalf("TxUndos count = %d, want %d",
			len(restored.TxUndos), len(original.TxUndos))
	}
	for i := range original.TxUndos {
		oc := original.TxUndos[i].SpentCoins
		rc := restored.TxUndos[i].SpentCoins
		if len(rc) != len(oc) {
			t.Fatalf("tx %d coin count = %d, want %d", i, len(rc), len(oc))
		}
		for j := range oc {
			if rc[j].Height != oc[j].Height {
				t.Errorf("tx %d coin %d Height = %d, want %d",
					i, j, rc[j].Height, oc[j].Height)
			}
			if rc[j].Coinbase != oc[j].Coinbase {
				t.Errorf("tx %d coin %d Coinbase = %v, want %v",
					i, j, rc[j].Coinbase, oc[j].Coinbase)
			}
			if rc[j].TxOut.Value != oc[j].TxOut.Value {
				t.Errorf("tx %d coin %d Value = %d, want %d",
					i, j, rc[j].TxOut.Value, oc[j].TxOut.Value)
			}
			if !bytes.Equal(rc[j].TxOut.PkScript, oc[j].TxOut.PkScript) {
				t.Errorf("tx %d coin %d PkScript mismatch:\n got %x\nwant %x",
					i, j, rc[j].TxOut.PkScript, oc[j].TxOut.PkScript)
			}
		}
	}
}

// TestBlockUndoCompressedEmptyBlock verifies an empty BlockUndo (e.g. a
// block whose only tx is the coinbase) round-trips through the compressed
// format.  The blob is a single tag byte + a single 0x00 CompactSize count.
func TestBlockUndoCompressedEmptyBlock(t *testing.T) {
	bu := &BlockUndo{TxUndos: []TxUndo{}}
	blob := bu.Serialize()
	if len(blob) != 2 || blob[0] != undoTagCompressedV1 || blob[1] != 0x00 {
		t.Errorf("empty BlockUndo blob = %x, want [%02x 00]", blob, undoTagCompressedV1)
	}
	restored, err := DeserializeBlockUndo(blob)
	if err != nil {
		t.Fatalf("DeserializeBlockUndo failed: %v", err)
	}
	if len(restored.TxUndos) != 0 {
		t.Errorf("restored TxUndos count = %d, want 0", len(restored.TxUndos))
	}
}
