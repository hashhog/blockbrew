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
