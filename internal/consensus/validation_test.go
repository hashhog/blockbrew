package consensus

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestCalcMerkleRoot tests Merkle root calculation with various transaction counts.
func TestCalcMerkleRoot(t *testing.T) {
	// Test single transaction - merkle root equals the hash itself
	t.Run("single transaction", func(t *testing.T) {
		hash, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
		hashes := []wire.Hash256{hash}
		result := CalcMerkleRoot(hashes)
		if result != hash {
			t.Errorf("Single tx merkle root should equal tx hash")
		}
	})

	// Test two transactions
	t.Run("two transactions", func(t *testing.T) {
		hash1, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
		hash2, _ := wire.NewHash256FromHex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
		hashes := []wire.Hash256{hash1, hash2}
		result := CalcMerkleRoot(hashes)
		// Result should be different from both inputs
		if result == hash1 || result == hash2 {
			t.Errorf("Two tx merkle root should differ from inputs")
		}
		// Result should be deterministic
		result2 := CalcMerkleRoot(hashes)
		if result != result2 {
			t.Errorf("Merkle root should be deterministic")
		}
	})

	// Test three transactions (odd count)
	t.Run("three transactions", func(t *testing.T) {
		hash1, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
		hash2, _ := wire.NewHash256FromHex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
		hash3, _ := wire.NewHash256FromHex("9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5")
		hashes := []wire.Hash256{hash1, hash2, hash3}
		result := CalcMerkleRoot(hashes)
		// With odd count, last hash is duplicated - test produces valid result
		if result.IsZero() {
			t.Errorf("Three tx merkle root should not be zero")
		}
	})

	// Test four transactions
	t.Run("four transactions", func(t *testing.T) {
		hash1, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
		hash2, _ := wire.NewHash256FromHex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
		hash3, _ := wire.NewHash256FromHex("9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5")
		hash4, _ := wire.NewHash256FromHex("999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644")
		hashes := []wire.Hash256{hash1, hash2, hash3, hash4}
		result := CalcMerkleRoot(hashes)
		// Four txs should produce valid merkle
		if result.IsZero() {
			t.Errorf("Four tx merkle root should not be zero")
		}
	})

	// Test that order matters
	t.Run("order matters", func(t *testing.T) {
		hash1, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
		hash2, _ := wire.NewHash256FromHex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
		result1 := CalcMerkleRoot([]wire.Hash256{hash1, hash2})
		result2 := CalcMerkleRoot([]wire.Hash256{hash2, hash1})
		if result1 == result2 {
			t.Errorf("Different ordering should produce different merkle root")
		}
	})
}

// TestCalcMerkleRootEmpty tests Merkle root with empty input.
func TestCalcMerkleRootEmpty(t *testing.T) {
	result := CalcMerkleRoot(nil)
	if !result.IsZero() {
		t.Errorf("CalcMerkleRoot(nil) should return zero hash, got %s", result.String())
	}

	result = CalcMerkleRoot([]wire.Hash256{})
	if !result.IsZero() {
		t.Errorf("CalcMerkleRoot([]) should return zero hash, got %s", result.String())
	}
}

// TestCalcWitnessMerkleRoot tests witness Merkle root calculation.
func TestCalcWitnessMerkleRoot(t *testing.T) {
	// With witness Merkle, the first hash (coinbase) is replaced with zeros
	hashes := []wire.Hash256{
		{0x01, 0x02, 0x03}, // This will be replaced with zeros
		{0x11, 0x12, 0x13},
	}

	result := CalcWitnessMerkleRoot(hashes)

	// Verify the result is different from regular merkle with same inputs
	regularResult := CalcMerkleRoot(hashes)
	if result == regularResult {
		t.Error("CalcWitnessMerkleRoot should differ from CalcMerkleRoot for non-zero coinbase wtxid")
	}

	// Verify with zero coinbase, results should match
	hashesWithZeroCoinbase := []wire.Hash256{
		{}, // All zeros
		{0x11, 0x12, 0x13},
	}
	regularWithZero := CalcMerkleRoot(hashesWithZeroCoinbase)
	if result != regularWithZero {
		t.Error("CalcWitnessMerkleRoot should match CalcMerkleRoot when coinbase is already zero")
	}
}

// TestCheckTransactionSanity tests transaction sanity checks.
func TestCheckTransactionSanity(t *testing.T) {
	tests := []struct {
		name    string
		tx      *wire.MsgTx
		wantErr error
	}{
		{
			name: "valid non-coinbase tx",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{
							Hash:  wire.Hash256{0x01, 0x02, 0x03},
							Index: 0,
						},
						SignatureScript: []byte{0x00},
						Sequence:        0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: []byte{0x76, 0xa9}},
				},
				LockTime: 0,
			},
			wantErr: nil,
		},
		{
			name: "valid coinbase tx",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{
							Hash:  wire.Hash256{}, // All zeros
							Index: 0xffffffff,
						},
						SignatureScript: []byte{0x03, 0x01, 0x00, 0x00}, // Valid length 2-100
						Sequence:        0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 5000000000, PkScript: []byte{0x76, 0xa9}},
				},
				LockTime: 0,
			},
			wantErr: nil,
		},
		{
			name: "no inputs",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: []byte{0x76, 0xa9}},
				},
			},
			wantErr: ErrNoInputs,
		},
		{
			name: "no outputs",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{},
			},
			wantErr: ErrNoOutputs,
		},
		{
			name: "negative output value",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: -1, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrNegativeOutput,
		},
		{
			name: "output exceeds max money",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: MaxMoney + 1, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrOutputTooLarge,
		},
		{
			name: "duplicate inputs",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, // Same as first
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrDuplicateInput,
		},
		{
			name: "coinbase script too short",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
						SignatureScript:  []byte{0x00}, // Only 1 byte, need 2-100
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 5000000000, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrCoinbaseScriptSize,
		},
		{
			name: "coinbase script too long",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
						SignatureScript:  make([]byte, 101), // 101 bytes, max is 100
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 5000000000, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrCoinbaseScriptSize,
		},
		{
			name: "non-coinbase with null input",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, // Regular input first
						SignatureScript:  []byte{0x00},
						Sequence:         0xffffffff,
					},
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff}, // Null input second
						SignatureScript:  []byte{0x00},
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: []byte{0x76}},
				},
			},
			wantErr: ErrNullInput, // Non-coinbase tx can't have null inputs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTransactionSanity(tt.tx)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("CheckTransactionSanity() expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr && !containsError(err, tt.wantErr) {
					t.Errorf("CheckTransactionSanity() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("CheckTransactionSanity() unexpected error: %v", err)
			}
		})
	}
}

// containsError checks if err contains target error (for wrapped errors)
func containsError(err, target error) bool {
	return err.Error() == target.Error() || bytes.Contains([]byte(err.Error()), []byte(target.Error()))
}

// TestCheckTransactionInputs tests transaction input validation.
func TestCheckTransactionInputs(t *testing.T) {
	// Create a mock UTXO view
	utxoView := NewInMemoryUTXOView()

	// Add some UTXOs
	utxoView.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, &UTXOEntry{
		Amount:     100000,
		PkScript:   []byte{0x76, 0xa9},
		Height:     100,
		IsCoinbase: false,
	})
	utxoView.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0}, &UTXOEntry{
		Amount:     50000,
		PkScript:   []byte{0x76, 0xa9},
		Height:     100,
		IsCoinbase: true, // Coinbase UTXO
	})

	tests := []struct {
		name      string
		tx        *wire.MsgTx
		txHeight  int32
		wantErr   error
		wantFee   int64
	}{
		{
			name: "valid transaction",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 90000, PkScript: []byte{0x76}},
				},
			},
			txHeight: 200,
			wantErr:  nil,
			wantFee:  10000, // 100000 - 90000
		},
		{
			name: "missing UTXO",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x99}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: []byte{0x76}},
				},
			},
			txHeight: 200,
			wantErr:  ErrMissingInput,
		},
		{
			name: "immature coinbase",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 40000, PkScript: []byte{0x76}},
				},
			},
			txHeight: 150, // Only 50 confirmations, need 100
			wantErr:  ErrImmatureCoinbase,
		},
		{
			name: "mature coinbase",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 40000, PkScript: []byte{0x76}},
				},
			},
			txHeight: 200, // 100 confirmations
			wantErr:  nil,
			wantFee:  10000, // 50000 - 40000
		},
		{
			name: "insufficient funds",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{0x00},
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 150000, PkScript: []byte{0x76}}, // More than input
				},
			},
			txHeight: 200,
			wantErr:  ErrInsufficientFunds,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee, err := CheckTransactionInputs(tt.tx, tt.txHeight, utxoView)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("CheckTransactionInputs() expected error %v, got nil", tt.wantErr)
				} else if !containsError(err, tt.wantErr) {
					t.Errorf("CheckTransactionInputs() error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("CheckTransactionInputs() unexpected error: %v", err)
				}
				if fee != tt.wantFee {
					t.Errorf("CheckTransactionInputs() fee = %d, want %d", fee, tt.wantFee)
				}
			}
		})
	}
}

// TestCalcTxWeight tests transaction weight calculation.
func TestCalcTxWeight(t *testing.T) {
	tests := []struct {
		name       string
		tx         *wire.MsgTx
		wantWeight int64
	}{
		{
			name: "legacy transaction (no witness)",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  make([]byte, 100),
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: make([]byte, 25)},
				},
				LockTime: 0,
			},
			// Legacy tx: all bytes are non-witness, so weight = size * 4
		},
		{
			name: "segwit transaction",
			tx: &wire.MsgTx{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						SignatureScript:  []byte{},
						Witness:          [][]byte{{0x30, 0x44}, {0x02, 0x21}}, // Example witness
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 50000, PkScript: make([]byte, 22)}, // P2WPKH
				},
				LockTime: 0,
			},
			// Segwit: weight = (non_witness * 3) + total
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			weight := CalcTxWeight(tt.tx)

			// Calculate expected weight
			var baseBuf, totalBuf bytes.Buffer
			tt.tx.SerializeNoWitness(&baseBuf)
			tt.tx.Serialize(&totalBuf)
			baseSize := int64(baseBuf.Len())
			totalSize := int64(totalBuf.Len())
			expectedWeight := baseSize*3 + totalSize

			if weight != expectedWeight {
				t.Errorf("CalcTxWeight() = %d, want %d (baseSize=%d, totalSize=%d)",
					weight, expectedWeight, baseSize, totalSize)
			}
		})
	}
}

// TestCalcBlockSubsidyHalvings tests block subsidy calculation at various halving boundaries.
func TestCalcBlockSubsidyHalvings(t *testing.T) {
	tests := []struct {
		height  int32
		subsidy int64
	}{
		{0, 5000000000},          // Genesis block: 50 BTC
		{1, 5000000000},          // Block 1: 50 BTC
		{209999, 5000000000},     // Last block before first halving: 50 BTC
		{210000, 2500000000},     // First halving: 25 BTC
		{420000, 1250000000},     // Second halving: 12.5 BTC
		{630000, 625000000},      // Third halving: 6.25 BTC
		{840000, 312500000},      // Fourth halving: 3.125 BTC
		{13440000, 0},            // After 64 halvings: 0 (64 * 210000 = 13440000)
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			subsidy := CalcBlockSubsidy(tt.height)
			if subsidy != tt.subsidy {
				t.Errorf("CalcBlockSubsidy(%d) = %d, want %d",
					tt.height, subsidy, tt.subsidy)
			}
		})
	}
}

// TestCheckBIP34Height tests BIP34 height encoding in coinbase.
// Reference: Bitcoin Core validation.cpp:4151-4159, script.h:433-448.
func TestCheckBIP34Height(t *testing.T) {
	tests := []struct {
		name       string
		scriptSig  []byte
		height     int32
		shouldPass bool
	}{
		// --- Canonical forms (must pass) ---
		{
			name:       "height 0 (OP_0)",
			scriptSig:  []byte{0x00},
			height:     0,
			shouldPass: true,
		},
		{
			name:       "height 1 (OP_1 = 0x51)",
			scriptSig:  []byte{0x51},
			height:     1,
			shouldPass: true,
		},
		{
			name:       "height 16 (OP_16 = 0x60)",
			scriptSig:  []byte{0x60},
			height:     16,
			shouldPass: true,
		},
		{
			name:       "height 17 (length-prefixed, no sign pad)",
			scriptSig:  []byte{0x01, 0x11},
			height:     17,
			shouldPass: true,
		},
		{
			name:       "height 100 (1 byte push)",
			scriptSig:  []byte{0x01, 0x64},
			height:     100,
			shouldPass: true,
		},
		{
			name:       "height 127 (0x7f, no sign pad)",
			scriptSig:  []byte{0x01, 0x7f},
			height:     127,
			shouldPass: true,
		},
		{
			name:       "height 128 (0x80 needs sign-pad: 0x02 0x80 0x00)",
			scriptSig:  []byte{0x02, 0x80, 0x00},
			height:     128,
			shouldPass: true,
		},
		{
			name:       "height 32768 (0x8000 needs sign-pad: 0x03 0x00 0x80 0x00)",
			scriptSig:  []byte{0x03, 0x00, 0x80, 0x00},
			height:     32768,
			shouldPass: true,
		},
		{
			name:       "height 500000 (3 byte push, 0x07A120 LE)",
			scriptSig:  []byte{0x03, 0x20, 0xa1, 0x07},
			height:     500000,
			shouldPass: true,
		},
		{
			name:       "height 227931 (mainnet BIP34 activation, 0x37A5B LE)",
			scriptSig:  []byte{0x03, 0x5b, 0x7a, 0x03},
			height:     227931,
			shouldPass: true,
		},
		{
			name:       "scriptSig has extra bytes after canonical prefix (prefix match)",
			scriptSig:  []byte{0x01, 0x64, 0xde, 0xad},
			height:     100,
			shouldPass: true,
		},
		// --- Non-canonical / rejected forms ---
		{
			name:       "reject: wrong height",
			scriptSig:  []byte{0x01, 0x64},
			height:     200,
			shouldPass: false,
		},
		{
			name:       "reject: length-prefixed 0x01 0x01 for height 1 (must be OP_1)",
			scriptSig:  []byte{0x01, 0x01},
			height:     1,
			shouldPass: false,
		},
		{
			name:       "reject: length-prefixed 0x01 0x10 for height 16 (must be OP_16)",
			scriptSig:  []byte{0x01, 0x10},
			height:     16,
			shouldPass: false,
		},
		{
			name:       "reject: zero-padded height 100 (0x02 0x64 0x00)",
			scriptSig:  []byte{0x02, 0x64, 0x00},
			height:     100,
			shouldPass: false,
		},
		{
			name:       "reject: OP_PUSHDATA1 prefix for height 1",
			scriptSig:  []byte{0x4c, 0x01, 0x01},
			height:     1,
			shouldPass: false,
		},
		{
			name:       "reject: redundant sign byte at height 100 (0x02 0x64 0x00 not needed)",
			scriptSig:  []byte{0x02, 0x64, 0x00},
			height:     100,
			shouldPass: false,
		},
		{
			name:       "reject: too short scriptSig",
			scriptSig:  []byte{},
			height:     100,
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{SignatureScript: tt.scriptSig},
				},
			}
			err := checkBIP34Height(tx, tt.height)
			if tt.shouldPass && err != nil {
				t.Errorf("checkBIP34Height() unexpected error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("checkBIP34Height() expected error, got nil")
			}
		})
	}
}

// TestEncodeBIP34Height tests the canonical BIP-34 height encoder.
func TestEncodeBIP34Height(t *testing.T) {
	tests := []struct {
		height   int32
		expected []byte
	}{
		{0, []byte{0x00}},                         // OP_0
		{1, []byte{0x51}},                         // OP_1
		{16, []byte{0x60}},                        // OP_16
		{17, []byte{0x01, 0x11}},                  // 1-byte push
		{127, []byte{0x01, 0x7f}},                 // no sign pad
		{128, []byte{0x02, 0x80, 0x00}},           // sign pad at 0x80
		{32768, []byte{0x03, 0x00, 0x80, 0x00}},   // sign pad at 0x8000
		{500000, []byte{0x03, 0x20, 0xa1, 0x07}},  // 3-byte push
		{227931, []byte{0x03, 0x5b, 0x7a, 0x03}},  // mainnet BIP34 (0x37A5B LE)
	}
	for _, tt := range tests {
		got := encodeBIP34Height(tt.height)
		if !bytes.Equal(got, tt.expected) {
			t.Errorf("encodeBIP34Height(%d) = %x, want %x", tt.height, got, tt.expected)
		}
	}
}

// TestCountSigOps tests signature operation counting.
func TestCountSigOps(t *testing.T) {
	tests := []struct {
		name     string
		script   []byte
		expected int
	}{
		{
			name:     "empty script",
			script:   []byte{},
			expected: 0,
		},
		{
			name:     "P2PKH output script",
			script:   []byte{0x76, 0xa9, 0x14, /* 20 bytes pubkeyhash */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac},
			expected: 1, // OP_CHECKSIG
		},
		{
			name:     "bare multisig 2-of-3",
			script:   []byte{0x52, /* OP_2 */ 0x21, /* push 33 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, /* OP_3 */ 0xae /* OP_CHECKMULTISIG */},
			expected: 3, // 3 pubkeys
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := CountSigOps(tt.script)
			if count != tt.expected {
				t.Errorf("CountSigOps() = %d, want %d", count, tt.expected)
			}
		})
	}
}

// TestCalcMedianTimePast tests median time past calculation.
func TestCalcMedianTimePast(t *testing.T) {
	tests := []struct {
		name       string
		timestamps []uint32
		expected   uint32
	}{
		{
			name:       "empty",
			timestamps: []uint32{},
			expected:   0,
		},
		{
			name:       "single",
			timestamps: []uint32{1000},
			expected:   1000,
		},
		{
			name:       "odd count",
			timestamps: []uint32{1000, 2000, 3000, 4000, 5000},
			expected:   3000, // Middle element
		},
		{
			name:       "even count",
			timestamps: []uint32{1000, 2000, 3000, 4000},
			expected:   3000, // For even count, we take index len/2 which is higher of two middles
		},
		{
			name:       "unsorted",
			timestamps: []uint32{5000, 1000, 3000, 4000, 2000},
			expected:   3000,
		},
		{
			name:       "11 timestamps (typical MTP)",
			timestamps: []uint32{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100},
			expected:   600, // Middle of 11
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalcMedianTimePast(tt.timestamps)
			if result != tt.expected {
				t.Errorf("CalcMedianTimePast() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestIsCoinbaseTx tests coinbase transaction detection.
func TestIsCoinbaseTx(t *testing.T) {
	tests := []struct {
		name     string
		tx       *wire.MsgTx
		expected bool
	}{
		{
			name: "valid coinbase",
			tx: &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
					},
				},
			},
			expected: true,
		},
		{
			name: "non-coinbase (non-zero hash)",
			tx: &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0xffffffff},
					},
				},
			},
			expected: false,
		},
		{
			name: "non-coinbase (wrong index)",
			tx: &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0},
					},
				},
			},
			expected: false,
		},
		{
			name: "non-coinbase (multiple inputs)",
			tx: &wire.MsgTx{
				TxIn: []*wire.TxIn{
					{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff}},
					{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCoinbaseTx(tt.tx)
			if result != tt.expected {
				t.Errorf("IsCoinbaseTx() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetBlockScriptFlags tests script flag generation for different heights.
func TestGetBlockScriptFlags(t *testing.T) {
	params := MainnetParams()

	tests := []struct {
		height              int32
		expectP2SH          bool
		expectBIP66         bool
		expectBIP65         bool
		expectCSV           bool
		expectSegwit        bool
		expectNullFail      bool
		expectWitnessPubKey bool
	}{
		{
			height:              0,
			expectP2SH:          true,
			expectBIP66:         false,
			expectBIP65:         false,
			expectCSV:           false,
			expectSegwit:        false,
			expectNullFail:      false,
			expectWitnessPubKey: false,
		},
		{
			height:              params.BIP66Height,
			expectP2SH:          true,
			expectBIP66:         true,
			expectBIP65:         false,
			expectCSV:           false,
			expectSegwit:        false,
			expectNullFail:      false,
			expectWitnessPubKey: false,
		},
		{
			height:              params.BIP65Height,
			expectP2SH:          true,
			expectBIP66:         true,
			expectBIP65:         true,
			expectCSV:           false,
			expectSegwit:        false,
			expectNullFail:      false,
			expectWitnessPubKey: false,
		},
		{
			height:              params.CSVHeight,
			expectP2SH:          true,
			expectBIP66:         true,
			expectBIP65:         true,
			expectCSV:           true,
			expectSegwit:        false,
			expectNullFail:      false,
			expectWitnessPubKey: false,
		},
		{
			height:              params.SegwitHeight,
			expectP2SH:          true,
			expectBIP66:         true,
			expectBIP65:         true,
			expectCSV:           true,
			expectSegwit:        true,
			expectNullFail:      false, // NULLFAIL is policy-only (not consensus)
			expectWitnessPubKey: false, // WITNESS_PUBKEYTYPE is policy-only (not consensus)
		},
		{
			height:              params.SegwitHeight - 1,
			expectP2SH:          true,
			expectBIP66:         true,
			expectBIP65:         true,
			expectCSV:           true,
			expectSegwit:        false,
			expectNullFail:      false, // NULLFAIL not active (policy-only regardless)
			expectWitnessPubKey: false, // WITNESS_PUBKEYTYPE not active (policy-only regardless)
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			// Use a zero hash — tests are for height-based flag logic, not exceptions
			var zeroHash wire.Hash256
			flags := GetBlockScriptFlags(tt.height, params, zeroHash)

			// Note: We import script package for ScriptFlags constants
			hasP2SH := flags&0x01 != 0
			hasSegwit := flags&0x02 != 0
			hasDERSig := flags&0x08 != 0
			hasCLTV := flags&0x200 != 0
			hasCSV := flags&0x400 != 0
			hasNullFail := flags&0x800 != 0    // ScriptVerifyNullFail = 1 << 11
			hasWitnessPubKey := flags&0x2000 != 0 // ScriptVerifyWitnessPubKeyType = 1 << 13

			if hasP2SH != tt.expectP2SH {
				t.Errorf("P2SH at height %d: got %v, want %v", tt.height, hasP2SH, tt.expectP2SH)
			}
			if hasDERSig != tt.expectBIP66 {
				t.Errorf("BIP66 at height %d: got %v, want %v", tt.height, hasDERSig, tt.expectBIP66)
			}
			if hasCLTV != tt.expectBIP65 {
				t.Errorf("BIP65 at height %d: got %v, want %v", tt.height, hasCLTV, tt.expectBIP65)
			}
			if hasCSV != tt.expectCSV {
				t.Errorf("CSV at height %d: got %v, want %v", tt.height, hasCSV, tt.expectCSV)
			}
			if hasSegwit != tt.expectSegwit {
				t.Errorf("Segwit at height %d: got %v, want %v", tt.height, hasSegwit, tt.expectSegwit)
			}
			if hasNullFail != tt.expectNullFail {
				t.Errorf("NullFail at height %d: got %v, want %v", tt.height, hasNullFail, tt.expectNullFail)
			}
			if hasWitnessPubKey != tt.expectWitnessPubKey {
				t.Errorf("WitnessPubKeyType at height %d: got %v, want %v", tt.height, hasWitnessPubKey, tt.expectWitnessPubKey)
			}
		})
	}
}

// TestInMemoryUTXOView tests the in-memory UTXO view implementation.
func TestInMemoryUTXOView(t *testing.T) {
	view := NewInMemoryUTXOView()

	outpoint := wire.OutPoint{Hash: wire.Hash256{0x01, 0x02, 0x03}, Index: 0}
	entry := &UTXOEntry{
		Amount:     100000,
		PkScript:   []byte{0x76, 0xa9},
		Height:     100,
		IsCoinbase: false,
	}

	// Test AddUTXO and GetUTXO
	view.AddUTXO(outpoint, entry)
	got := view.GetUTXO(outpoint)
	if got == nil {
		t.Fatal("GetUTXO returned nil after AddUTXO")
	}
	if got.Amount != entry.Amount {
		t.Errorf("Amount = %d, want %d", got.Amount, entry.Amount)
	}

	// Test SpendUTXO
	view.SpendUTXO(outpoint)
	got = view.GetUTXO(outpoint)
	if got != nil {
		t.Error("GetUTXO should return nil after SpendUTXO")
	}

	// Test missing UTXO
	got = view.GetUTXO(wire.OutPoint{Hash: wire.Hash256{0x99}, Index: 0})
	if got != nil {
		t.Error("GetUTXO should return nil for missing UTXO")
	}
}

// TestCalcBlockWeight tests block weight calculation.
func TestCalcBlockWeight(t *testing.T) {
	// Create a simple block
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 1231006505,
			Bits:      0x1d00ffff,
		},
		Transactions: []*wire.MsgTx{
			{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
						SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
						Sequence:         0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 5000000000, PkScript: []byte{0x76, 0xa9}},
				},
				LockTime: 0,
			},
		},
	}

	weight := CalcBlockWeight(block)

	// Header weight is 80 × 4 = 320 WU.
	// Tx-count varint: 1 tx → 1 byte → 1 × 4 = 4 WU.
	// Plus transaction weight.
	txWeight := CalcTxWeight(block.Transactions[0])
	expectedWeight := int64(320) + 4 + txWeight // varint contributes 4 WU

	if weight != expectedWeight {
		t.Errorf("CalcBlockWeight() = %d, want %d", weight, expectedWeight)
	}
}

// TestWitnessCommitmentMagic tests the witness commitment magic bytes.
func TestWitnessCommitmentMagic(t *testing.T) {
	expected, _ := hex.DecodeString("aa21a9ed")
	if !bytes.Equal(WitnessCommitmentMagic, expected) {
		t.Errorf("WitnessCommitmentMagic = %x, want %x", WitnessCommitmentMagic, expected)
	}
}

// TestBIP68SequenceLockConstants verifies the BIP68 sequence lock constants.
func TestBIP68SequenceLockConstants(t *testing.T) {
	// BIP68 constants from consensus/params.go
	if SequenceLockTimeDisabledFlag != 0x80000000 {
		t.Errorf("SequenceLockTimeDisabledFlag = %x, want 0x80000000", SequenceLockTimeDisabledFlag)
	}
	if SequenceLockTimeTypeFlag != 0x00400000 {
		t.Errorf("SequenceLockTimeTypeFlag = %x, want 0x00400000", SequenceLockTimeTypeFlag)
	}
	if SequenceLockTimeMask != 0x0000ffff {
		t.Errorf("SequenceLockTimeMask = %x, want 0x0000ffff", SequenceLockTimeMask)
	}
	if SequenceLockTimeGranularity != 9 {
		t.Errorf("SequenceLockTimeGranularity = %d, want 9", SequenceLockTimeGranularity)
	}
	// 2^9 = 512 seconds
	if (1 << SequenceLockTimeGranularity) != 512 {
		t.Errorf("Time granularity should be 512 seconds")
	}
}

// TestCalculateSequenceLocks tests BIP68 sequence lock calculation.
func TestCalculateSequenceLocks(t *testing.T) {
	// Create a mock MTP lookup function
	// Simulates MTP increasing by 600 seconds (10 min) per block
	mockMTP := func(height int32) int64 {
		if height < 0 {
			return 0
		}
		return int64(1600000000) + int64(height)*600
	}

	tests := []struct {
		name        string
		txVersion   int32
		sequences   []uint32
		prevHeights []int32
		wantHeight  int32
		wantTime    int64
	}{
		{
			name:        "version 1 tx ignores sequence locks",
			txVersion:   1,
			sequences:   []uint32{10}, // Would be height lock of 10
			prevHeights: []int32{100},
			wantHeight:  -1, // No lock
			wantTime:    -1,
		},
		{
			name:        "version 2 tx with disabled flag",
			txVersion:   2,
			sequences:   []uint32{SequenceLockTimeDisabledFlag | 10},
			prevHeights: []int32{100},
			wantHeight:  -1, // No lock
			wantTime:    -1,
		},
		{
			name:        "height-based lock of 10 blocks",
			txVersion:   2,
			sequences:   []uint32{10},
			prevHeights: []int32{100},
			wantHeight:  100 + 10 - 1, // 109
			wantTime:    -1,
		},
		{
			name:        "height-based lock of 1 block (minimum)",
			txVersion:   2,
			sequences:   []uint32{1},
			prevHeights: []int32{100},
			wantHeight:  100, // 100 + 1 - 1
			wantTime:    -1,
		},
		{
			name:        "time-based lock of 512 seconds (1 unit)",
			txVersion:   2,
			sequences:   []uint32{SequenceLockTimeTypeFlag | 1},
			prevHeights: []int32{100},
			// MTP at height 99 (prevHeight - 1) = 1600000000 + 99*600 = 1600059400
			// lockedTime = (1 << 9) - 1 = 511
			// minTime = 1600059400 + 511 = 1600059911
			wantHeight: -1,
			wantTime:   mockMTP(99) + 511,
		},
		{
			name:        "time-based lock of 65535 units (max)",
			txVersion:   2,
			sequences:   []uint32{SequenceLockTimeTypeFlag | 0xFFFF},
			prevHeights: []int32{100},
			// lockedTime = (65535 << 9) - 1 = 33553919
			wantHeight: -1,
			wantTime:   mockMTP(99) + 33553919,
		},
		{
			name:        "multiple inputs - take maximum height",
			txVersion:   2,
			sequences:   []uint32{5, 10, 3},
			prevHeights: []int32{100, 50, 200},
			// Input 0: 100 + 5 - 1 = 104
			// Input 1: 50 + 10 - 1 = 59
			// Input 2: 200 + 3 - 1 = 202 (maximum)
			wantHeight: 202,
			wantTime:   -1,
		},
		{
			name:      "mixed height and time locks",
			txVersion: 2,
			sequences: []uint32{
				10,                                // Height lock: 10 blocks
				SequenceLockTimeTypeFlag | 100,    // Time lock: 100 * 512 seconds
				SequenceLockTimeDisabledFlag | 99, // Disabled
			},
			prevHeights: []int32{100, 50, 200},
			// Height: 100 + 10 - 1 = 109
			// Time: MTP(49) + (100 << 9) - 1 = MTP(49) + 51199
			wantHeight: 109,
			wantTime:   mockMTP(49) + 51199,
		},
		{
			name:        "zero height lock (immediate)",
			txVersion:   2,
			sequences:   []uint32{0},
			prevHeights: []int32{100},
			// 100 + 0 - 1 = 99
			wantHeight: 99,
			wantTime:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create transaction with specified version and inputs
			tx := &wire.MsgTx{
				Version: tt.txVersion,
				TxIn:    make([]*wire.TxIn, len(tt.sequences)),
				TxOut:   []*wire.TxOut{{Value: 1000}},
			}

			for i, seq := range tt.sequences {
				tx.TxIn[i] = &wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  wire.Hash256{byte(i + 1)}, // Non-zero hash
						Index: 0,
					},
					Sequence: seq,
				}
			}

			lock := CalculateSequenceLocks(tx, tt.prevHeights, mockMTP)

			if lock.MinHeight != tt.wantHeight {
				t.Errorf("MinHeight = %d, want %d", lock.MinHeight, tt.wantHeight)
			}
			if lock.MinTime != tt.wantTime {
				t.Errorf("MinTime = %d, want %d", lock.MinTime, tt.wantTime)
			}
		})
	}
}

// TestEvaluateSequenceLocks tests sequence lock evaluation.
func TestEvaluateSequenceLocks(t *testing.T) {
	tests := []struct {
		name        string
		lock        *SequenceLock
		blockHeight int32
		blockMTP    int64
		want        bool
	}{
		{
			name:        "no locks (both -1)",
			lock:        &SequenceLock{MinHeight: -1, MinTime: -1},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        true,
		},
		{
			name:        "height lock satisfied",
			lock:        &SequenceLock{MinHeight: 99, MinTime: -1},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        true,
		},
		{
			name:        "height lock exactly at boundary (not satisfied)",
			lock:        &SequenceLock{MinHeight: 100, MinTime: -1},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false, // MinHeight >= blockHeight
		},
		{
			name:        "height lock not satisfied",
			lock:        &SequenceLock{MinHeight: 150, MinTime: -1},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false,
		},
		{
			name:        "time lock satisfied",
			lock:        &SequenceLock{MinHeight: -1, MinTime: 1599999999},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        true,
		},
		{
			name:        "time lock exactly at boundary (not satisfied)",
			lock:        &SequenceLock{MinHeight: -1, MinTime: 1600000000},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false, // MinTime >= blockMTP
		},
		{
			name:        "time lock not satisfied",
			lock:        &SequenceLock{MinHeight: -1, MinTime: 1600001000},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false,
		},
		{
			name:        "both locks satisfied",
			lock:        &SequenceLock{MinHeight: 50, MinTime: 1599999000},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        true,
		},
		{
			name:        "height satisfied, time not",
			lock:        &SequenceLock{MinHeight: 50, MinTime: 1600001000},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false,
		},
		{
			name:        "time satisfied, height not",
			lock:        &SequenceLock{MinHeight: 150, MinTime: 1599999000},
			blockHeight: 100,
			blockMTP:    1600000000,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateSequenceLocks(tt.lock, tt.blockHeight, tt.blockMTP)
			if got != tt.want {
				t.Errorf("EvaluateSequenceLocks() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBIP68TimeLockGranularity verifies that time locks use 512-second granularity.
func TestBIP68TimeLockGranularity(t *testing.T) {
	baseMTP := int64(1600000000)
	mockMTP := func(height int32) int64 {
		return baseMTP
	}

	tests := []struct {
		sequenceValue uint16
		expectedDelta int64 // Expected delta from base MTP
	}{
		{1, (1 << 9) - 1},      // 511 seconds
		{2, (2 << 9) - 1},      // 1023 seconds
		{10, (10 << 9) - 1},    // 5119 seconds
		{100, (100 << 9) - 1},  // 51199 seconds
		{1000, (1000 << 9) - 1}, // ~8.5 hours
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 2,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
					Sequence:         SequenceLockTimeTypeFlag | uint32(tt.sequenceValue),
				}},
				TxOut: []*wire.TxOut{{Value: 1000}},
			}

			// prevHeight = 1, so we get MTP at height 0
			lock := CalculateSequenceLocks(tx, []int32{1}, mockMTP)

			expectedMinTime := baseMTP + tt.expectedDelta
			if lock.MinTime != expectedMinTime {
				t.Errorf("sequence %d: MinTime = %d, want %d (delta %d)",
					tt.sequenceValue, lock.MinTime, expectedMinTime, tt.expectedDelta)
			}
		})
	}
}

// TestBIP68CoinbaseInput verifies that coinbase inputs are skipped.
func TestBIP68CoinbaseInput(t *testing.T) {
	mockMTP := func(height int32) int64 { return 1600000000 }

	// Create a transaction with a coinbase-like input (null hash, max index)
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{}, // All zeros
					Index: 0xFFFFFFFF,
				},
				Sequence: 10, // Would be a 10-block lock if not skipped
			},
		},
		TxOut: []*wire.TxOut{{Value: 1000}},
	}

	lock := CalculateSequenceLocks(tx, []int32{100}, mockMTP)

	// Coinbase input should be skipped, so no locks
	if lock.MinHeight != -1 {
		t.Errorf("MinHeight = %d, want -1 (coinbase input should be skipped)", lock.MinHeight)
	}
	if lock.MinTime != -1 {
		t.Errorf("MinTime = %d, want -1 (coinbase input should be skipped)", lock.MinTime)
	}
}

// TestBIP68CorrectMTPHeight verifies that time-based locks use MTP at (prevHeight - 1).
func TestBIP68CorrectMTPHeight(t *testing.T) {
	// Track which heights the MTP lookup was called with
	calledHeights := make(map[int32]bool)
	mockMTP := func(height int32) int64 {
		calledHeights[height] = true
		return int64(1600000000) + int64(height)*600
	}

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         SequenceLockTimeTypeFlag | 1, // Time-based lock
		}},
		TxOut: []*wire.TxOut{{Value: 1000}},
	}

	// Input UTXO was confirmed at height 100
	// BIP68 should use MTP at height 99 (prevHeight - 1)
	_ = CalculateSequenceLocks(tx, []int32{100}, mockMTP)

	if !calledHeights[99] {
		t.Errorf("MTP lookup should have been called with height 99 (prevHeight - 1)")
	}
	if calledHeights[100] {
		t.Errorf("MTP lookup should NOT use the UTXO's confirmation height directly")
	}
}

// TestBIP68EdgeCasePrevHeightZero tests edge case when UTXO was confirmed at height 0.
func TestBIP68EdgeCasePrevHeightZero(t *testing.T) {
	calledHeights := make(map[int32]bool)
	mockMTP := func(height int32) int64 {
		calledHeights[height] = true
		return int64(1231006505) // Genesis timestamp
	}

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         SequenceLockTimeTypeFlag | 1,
		}},
		TxOut: []*wire.TxOut{{Value: 1000}},
	}

	// UTXO confirmed at height 0 (genesis)
	// max(0 - 1, 0) = 0, so should use MTP at height 0
	_ = CalculateSequenceLocks(tx, []int32{0}, mockMTP)

	if !calledHeights[0] {
		t.Errorf("For prevHeight=0, MTP should be fetched at height 0")
	}
}

// TestCalcMerkleRootMutationCVE20122459 tests the CVE-2012-2459 defense.
//
// CVE-2012-2459 describes how Bitcoin's merkle tree, which duplicates the
// last hash when the level has odd length, lets an attacker construct a
// "mutated" transaction list that produces the same merkle root as the
// honest list. For example: leaves [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6]
// produce the same root because at the second level, [H(1,2), H(3,4),
// H(5,6)] becomes [D, E, F, F] (after odd-duplication) — exactly the
// same as [D, E, F, F] from [1,2,3,4,5,6,5,6] without odd-duplication.
//
// The defense: if any adjacent pair of hashes at any tree level is equal,
// flag the tree as "mutated". The block must be rejected, but it must NOT
// be permanently marked invalid, because the honest form has the same
// block hash and is still potentially valid.
func TestCalcMerkleRootMutationCVE20122459(t *testing.T) {
	hash := func(b byte) wire.Hash256 {
		var h wire.Hash256
		h[0] = b
		return h
	}

	t.Run("no mutation (4 distinct leaves)", func(t *testing.T) {
		hashes := []wire.Hash256{hash(1), hash(2), hash(3), hash(4)}
		_, mutated := CalcMerkleRootMutation(hashes)
		if mutated {
			t.Errorf("expected no mutation flag for 4 distinct leaves")
		}
	})

	t.Run("no mutation (single leaf)", func(t *testing.T) {
		hashes := []wire.Hash256{hash(1)}
		_, mutated := CalcMerkleRootMutation(hashes)
		if mutated {
			t.Errorf("expected no mutation flag for 1 leaf")
		}
	})

	t.Run("no mutation (odd count, 3 distinct leaves)", func(t *testing.T) {
		// 3 leaves: odd-duplication of leaf-3 happens but adjacent pair
		// (leaf-1, leaf-2) is fine. The duplicated (leaf-3, leaf-3) IS
		// adjacent equal — but Core does this check BEFORE the odd
		// duplication step, so naturally-odd lists must not be flagged.
		hashes := []wire.Hash256{hash(1), hash(2), hash(3)}
		_, mutated := CalcMerkleRootMutation(hashes)
		if mutated {
			t.Errorf("expected no mutation flag for natural odd-list (3 leaves)")
		}
	})

	t.Run("CVE-2012-2459 mutation (adjacent dup at leaf level)", func(t *testing.T) {
		// [1, 2, 3, 4, 5, 6] vs [1, 2, 3, 4, 5, 6, 5, 6] — the canonical
		// CVE example. The mutated form has adjacent duplicates at the
		// SECOND level (level pairs are [D, E, F, F]), so the leaf-level
		// 8-leaf list is the attack signature.
		honest := []wire.Hash256{hash(1), hash(2), hash(3), hash(4), hash(5), hash(6)}
		mutated := []wire.Hash256{hash(1), hash(2), hash(3), hash(4), hash(5), hash(6), hash(5), hash(6)}

		honestRoot, honestMut := CalcMerkleRootMutation(honest)
		mutatedRoot, mutatedMut := CalcMerkleRootMutation(mutated)

		if honestMut {
			t.Errorf("honest 6-leaf list must NOT be flagged as mutated")
		}
		if !mutatedMut {
			t.Errorf("8-leaf mutated list MUST be flagged as mutated (CVE-2012-2459)")
		}
		if honestRoot != mutatedRoot {
			t.Errorf("CVE-2012-2459 invariant: honest and mutated roots must match\n  honest=%s\n  mutated=%s",
				honestRoot.String(), mutatedRoot.String())
		}
	})

	t.Run("adjacent duplicate at leaf level", func(t *testing.T) {
		// Simplest attack: [A, B, C, C] — adjacent C, C at the leaf level.
		// Equivalent (un-mutated) form would be [A, B, C] with odd-
		// duplication, but [A, B, C, C] looks like a 4-leaf list.
		hashes := []wire.Hash256{hash(1), hash(2), hash(3), hash(3)}
		_, mutated := CalcMerkleRootMutation(hashes)
		if !mutated {
			t.Errorf("expected mutation flag for adjacent-duplicate leaves")
		}
	})

	t.Run("CalcMerkleRoot wrapper preserves backward compat", func(t *testing.T) {
		// The non-mutation-aware wrapper must still return the correct
		// root (the mutation flag is just discarded).
		hashes := []wire.Hash256{hash(1), hash(2), hash(3), hash(3)}
		rootViaWrapper := CalcMerkleRoot(hashes)
		rootViaMutation, _ := CalcMerkleRootMutation(hashes)
		if rootViaWrapper != rootViaMutation {
			t.Errorf("CalcMerkleRoot must equal CalcMerkleRootMutation root\n  wrapper=%s\n  mutation=%s",
				rootViaWrapper.String(), rootViaMutation.String())
		}
	})
}

// TestCheckBlockSanityCVE20122459 verifies that CheckBlockSanity returns
// ErrBlockMutated (transient — must NOT mark block permanently invalid)
// instead of ErrBadMerkleRoot (real — mark permanently invalid) when the
// transaction list contains a CVE-2012-2459 mutation.
//
// This is the regression for blockbrew P0-1: any peer can otherwise
// permanently dead-end a node by sending the mutated form before the
// legitimate form arrives — the block hash gets marked StatusInvalid in
// the header index and the legitimate block can never be accepted.
func TestCheckBlockSanityCVE20122459(t *testing.T) {
	params := RegtestParams()

	// Build a 6-tx block (1 coinbase + 5 padding non-coinbase txs) and a
	// duplicated form (1 coinbase + 5 padding + 4 of the padding repeated
	// to form an 8-tx mutated list with the same merkle root).
	//
	// We can't reuse the coinbase as a non-coinbase tx, so we use 6 txs at
	// the leaf level: [coinbase, B, C, D, E, F] honest vs
	// [coinbase, B, C, D, E, F, E, F] mutated. By Core's diagram both
	// produce the same merkle root.
	makeCoinbase := func() *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
				SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x76, 0xa9}}},
		}
	}
	makeTx := func(salt byte) *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{salt}, Index: 0},
				SignatureScript:  []byte{0x00},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 50000, PkScript: []byte{0x76, 0xa9}}},
		}
	}

	cb := makeCoinbase()
	b := makeTx(0xb1)
	c := makeTx(0xc1)
	d := makeTx(0xd1)
	e := makeTx(0xe1)
	f := makeTx(0xf1)

	honestTxs := []*wire.MsgTx{cb, b, c, d, e, f}
	// Mutated: append e, f again. [cb, B, C, D, E, F, E, F].
	mutatedTxs := []*wire.MsgTx{cb, b, c, d, e, f, e, f}

	// Compute merkle root for the honest form (which equals the mutated
	// form's root by the CVE invariant).
	honestHashes := make([]wire.Hash256, len(honestTxs))
	for i, tx := range honestTxs {
		honestHashes[i] = tx.TxHash()
	}
	mutatedHashes := make([]wire.Hash256, len(mutatedTxs))
	for i, tx := range mutatedTxs {
		mutatedHashes[i] = tx.TxHash()
	}
	honestRoot, _ := CalcMerkleRootMutation(honestHashes)
	mutatedRoot, mutatedFlag := CalcMerkleRootMutation(mutatedHashes)
	if honestRoot != mutatedRoot {
		t.Fatalf("test setup invariant: honest root %s != mutated root %s",
			honestRoot.String(), mutatedRoot.String())
	}
	if !mutatedFlag {
		t.Fatalf("test setup invariant: mutated form must be flagged")
	}

	// Build the block header. We need it to pass PoW on regtest, which is
	// trivial (target = 7fff...).
	header := wire.BlockHeader{
		Version:    0x20000000,
		PrevBlock:  params.GenesisHash,
		MerkleRoot: mutatedRoot, // Same as honestRoot
		Timestamp:  uint32(time.Now().Unix()),
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}
	// Mine to find a nonce satisfying regtest PoW.
	for nonce := uint32(0); nonce < 0xffffffff; nonce++ {
		header.Nonce = nonce
		if CheckProofOfWork(header.BlockHash(), header.Bits, params.PowLimit) == nil {
			break
		}
	}

	// Send the MUTATED block: same hash as the honest block would have,
	// but a different transaction list. This is the attack.
	mutatedBlock := &wire.MsgBlock{
		Header:       header,
		Transactions: mutatedTxs,
	}

	err := CheckBlockSanity(mutatedBlock, params.PowLimit)
	if err == nil {
		t.Fatalf("expected mutated block to be rejected, got nil")
	}
	if !errors.Is(err, ErrBlockMutated) {
		t.Fatalf("expected ErrBlockMutated (transient) for CVE-2012-2459, got: %v", err)
	}
	if errors.Is(err, ErrBadMerkleRoot) {
		t.Errorf("must NOT return ErrBadMerkleRoot for mutated block: a real " +
			"merkle mismatch would mark the block permanently invalid, " +
			"creating the CVE-2012-2459 dead-end DoS")
	}

	// Sanity check: the honest block must still pass merkle validation
	// (it may fail other checks like duplicate inputs in the dummy txs,
	// but it must NOT trip ErrBlockMutated or ErrBadMerkleRoot).
	honestBlock := &wire.MsgBlock{
		Header:       header,
		Transactions: honestTxs,
	}
	err = CheckBlockSanity(honestBlock, params.PowLimit)
	if errors.Is(err, ErrBlockMutated) {
		t.Errorf("honest block must NOT be flagged as mutated, got: %v", err)
	}
	if errors.Is(err, ErrBadMerkleRoot) {
		t.Errorf("honest block must NOT have merkle mismatch, got: %v", err)
	}
}

// TestBIP30ExceptionHeights verifies that the BIP-30 duplicate-coinbase check
// uses the correct exception logic: BOTH the right height AND the exact block
// hash must match (IsBIP30Repeat).  The two historical mainnet duplicate-coinbase
// blocks (h=91842 and h=91880 with their specific hashes) are exempt; all other
// heights and any block at those heights with a DIFFERENT hash are enforced.
//
// Also verifies that the old "unspendable" heights (91722 and 91812) are NOT
// exempt from BIP-30 enforcement.
//
// Reference: Bitcoin Core validation.cpp IsBIP30Repeat() line 6189-6193.
func TestBIP30ExceptionHeights(t *testing.T) {
	// Use regtest params (maximal PoW limit) so any block hash passes PoW.
	// Override activation heights so BIP-context checks don't interfere:
	// push all soft-fork activations above h=200000 so the test heights
	// (91842, 91843, 91880, 91722, 91812) are all pre-BIP34 (BIP30 always on).
	params := *RegtestParams()
	params.BIP34Height = 200_000
	params.BIP34Hash = wire.Hash256{} // zero = no short-circuit
	params.BIP65Height = 200_000
	params.BIP66Height = 200_000
	params.CSVHeight = 200_000
	params.SegwitHeight = 200_000
	params.TaprootHeight = 200_000

	// The exact historical hashes from Bitcoin Core IsBIP30Repeat().
	hash91842, _ := wire.NewHash256FromHex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
	hash91880, _ := wire.NewHash256FromHex("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
	// A dummy hash that does NOT match any exception.
	wrongHash := wire.Hash256{0xde, 0xad, 0xbe, 0xef}

	// Build a minimal coinbase transaction with a known txid.
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
				SignatureScript:  []byte{0x51, 0x00}, // 2-byte coinbase script (min length)
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 5_000_000_000, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}
	coinbaseTxid := coinbaseTx.TxHash()

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{coinbaseTxid}),
			Timestamp:  1231006506,
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}

	// A UTXO view that contains the coinbase output — simulating a duplicate.
	newView := func() *InMemoryUTXOView {
		v := NewInMemoryUTXOView()
		v.AddUTXO(
			wire.OutPoint{Hash: coinbaseTxid, Index: 0},
			&UTXOEntry{Amount: 100, PkScript: []byte{0x51}, Height: 1000, IsCoinbase: true},
		)
		return v
	}

	// Test 1: height=91842 + CORRECT hash — EXEMPT (IsBIP30Repeat).
	if err := CheckBIP30(block, 91842, hash91842, &params, newView(), nil); errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=91842 correct hash: BIP-30 exception must NOT reject, got ErrDuplicateTx")
	}

	// Test 2: height=91842 + WRONG hash — NOT exempt (hash must match).
	if err := CheckBIP30(block, 91842, wrongHash, &params, newView(), nil); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=91842 wrong hash: must be enforced (hash mismatch), got: %v", err)
	}

	// Test 3: height=91843 — NOT exempt at all.
	if err := CheckBIP30(block, 91843, wrongHash, &params, newView(), nil); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=91843: BIP-30 must reject duplicate coinbase, got: %v", err)
	}

	// Test 4: height=91880 + CORRECT hash — EXEMPT (IsBIP30Repeat).
	if err := CheckBIP30(block, 91880, hash91880, &params, newView(), nil); errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=91880 correct hash: BIP-30 exception must NOT reject, got ErrDuplicateTx")
	}

	// Test 5: height=91880 + WRONG hash — NOT exempt.
	if err := CheckBIP30(block, 91880, wrongHash, &params, newView(), nil); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=91880 wrong hash: must be enforced (hash mismatch), got: %v", err)
	}

	// Test 6: heights 91722 and 91812 (IsBIP30Unspendable) — NOT exempt from BIP-30.
	// These are the blocks whose outputs became unspendable (pre-BIP30 originals),
	// not the repeat blocks. Core never exempts them from ConnectBlock BIP-30.
	for _, wrongHeight := range []int32{91722, 91812} {
		if err := CheckBIP30(block, wrongHeight, wrongHash, &params, newView(), nil); !errors.Is(err, ErrDuplicateTx) {
			t.Errorf("h=%d: must NOT be BIP-30 exempt (IsBIP30Unspendable heights are not repeats), got: %v", wrongHeight, err)
		}
	}
}

// TestIsBIP30Repeat verifies IsBIP30Repeat requires both height AND hash.
func TestIsBIP30Repeat(t *testing.T) {
	hash91842, _ := wire.NewHash256FromHex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
	hash91880, _ := wire.NewHash256FromHex("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
	wrongHash := wire.Hash256{0x01}

	tests := []struct {
		height   int32
		hash     wire.Hash256
		expected bool
	}{
		{91842, hash91842, true},  // correct height + correct hash
		{91842, wrongHash, false}, // correct height + wrong hash
		{91843, hash91842, false}, // wrong height (off by 1)
		{91880, hash91880, true},  // correct height + correct hash
		{91880, wrongHash, false}, // correct height + wrong hash
		{91879, hash91880, false}, // wrong height (off by 1)
		// IsBIP30Unspendable heights are NOT IsBIP30Repeat
		{91722, wire.Hash256{}, false},
		{91812, wire.Hash256{}, false},
		{0, wire.Hash256{}, false},
		{227931, wire.Hash256{}, false},
	}
	for _, tt := range tests {
		got := IsBIP30Repeat(tt.height, tt.hash)
		if got != tt.expected {
			t.Errorf("IsBIP30Repeat(%d, %s) = %v, want %v", tt.height, tt.hash, got, tt.expected)
		}
	}
}

// TestIsBIP30Unspendable verifies IsBIP30Unspendable requires both height AND hash.
func TestIsBIP30Unspendable(t *testing.T) {
	hash91722, _ := wire.NewHash256FromHex("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")
	hash91812, _ := wire.NewHash256FromHex("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f")
	wrongHash := wire.Hash256{0x02}

	tests := []struct {
		height   int32
		hash     wire.Hash256
		expected bool
	}{
		{91722, hash91722, true},
		{91722, wrongHash, false},
		{91723, hash91722, false},
		{91812, hash91812, true},
		{91812, wrongHash, false},
		{91813, hash91812, false},
		// IsBIP30Repeat heights are NOT IsBIP30Unspendable
		{91842, wire.Hash256{}, false},
		{91880, wire.Hash256{}, false},
	}
	for _, tt := range tests {
		got := IsBIP30Unspendable(tt.height, tt.hash)
		if got != tt.expected {
			t.Errorf("IsBIP30Unspendable(%d, %s) = %v, want %v", tt.height, tt.hash, got, tt.expected)
		}
	}
}

// TestCheckBIP30BIP34ShortCircuit verifies that the BIP34 short-circuit
// disables BIP-30 enforcement once BIP34 is active at the right hash, and that
// it re-enables at BIP34_IMPLIES_BIP30_LIMIT (1,983,702).
func TestCheckBIP30BIP34ShortCircuit(t *testing.T) {
	// Use a custom BIP34Hash that matches the mock ancestor.
	fakeBIP34Hash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000aabbcc")
	params := *RegtestParams()
	params.BIP34Height = 227_931
	params.BIP34Hash = fakeBIP34Hash
	params.BIP65Height = 500_000
	params.BIP66Height = 500_000
	params.CSVHeight = 500_000
	params.SegwitHeight = 500_000
	params.TaprootHeight = 500_000

	// Ancestor lookup that returns the fake BIP34Hash at height 227,931.
	rightAncestor := func(h int32) (wire.Hash256, bool) {
		if h == 227_931 {
			return fakeBIP34Hash, true
		}
		return wire.Hash256{}, false
	}
	// Ancestor lookup that returns the WRONG hash at height 227,931.
	wrongAncestor := func(h int32) (wire.Hash256, bool) {
		return wire.Hash256{0xff}, true
	}

	// Build a coinbase with a duplicate UTXO in the view.
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff, SignatureScript: []byte{0x51}}},
		TxOut:   []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x51}}},
	}
	txid := coinbaseTx.TxHash()
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Bits: 0x207fffff},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
	newView := func() *InMemoryUTXOView {
		v := NewInMemoryUTXOView()
		v.AddUTXO(wire.OutPoint{Hash: txid, Index: 0}, &UTXOEntry{Amount: 100, PkScript: []byte{0x51}})
		return v
	}
	anyHash := wire.Hash256{0x99}

	// Pre-BIP34 (height 100): BIP30 enforced.
	if err := CheckBIP30(block, 100, anyHash, &params, newView(), rightAncestor); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("pre-BIP34 h=100: expected ErrDuplicateTx, got: %v", err)
	}

	// Post-BIP34, RIGHT hash: BIP30 skipped (short-circuit).
	if err := CheckBIP30(block, 300_000, anyHash, &params, newView(), rightAncestor); err != nil {
		t.Errorf("post-BIP34 right-hash: BIP30 should be skipped, got: %v", err)
	}

	// Post-BIP34, WRONG hash: BIP30 still enforced (chain not canonical).
	if err := CheckBIP30(block, 300_000, anyHash, &params, newView(), wrongAncestor); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("post-BIP34 wrong-hash: expected ErrDuplicateTx (non-canonical chain), got: %v", err)
	}

	// Post-BIP34, nil ancestorHashAt: BIP30 enforced (safe fallback — no short-circuit).
	if err := CheckBIP30(block, 300_000, anyHash, &params, newView(), nil); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("post-BIP34 nil ancestor: expected ErrDuplicateTx (safe fallback), got: %v", err)
	}

	// BIP34_IMPLIES_BIP30_LIMIT (1,983,702): always enforced regardless of BIP34.
	if err := CheckBIP30(block, 1_983_702, anyHash, &params, newView(), rightAncestor); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=1,983,702: expected ErrDuplicateTx (re-enforce), got: %v", err)
	}

	// Above BIP34_IMPLIES_BIP30_LIMIT: still enforced.
	if err := CheckBIP30(block, 2_000_000, anyHash, &params, newView(), rightAncestor); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("h=2,000,000: expected ErrDuplicateTx (re-enforce), got: %v", err)
	}

	// Below BIP34_IMPLIES_BIP30_LIMIT, BIP34 active, right hash: still skipped.
	if err := CheckBIP30(block, 1_983_701, anyHash, &params, newView(), rightAncestor); err != nil {
		t.Errorf("h=1,983,701 right-hash: BIP30 should be skipped (just below limit), got: %v", err)
	}
}

// buildSegwitBlock assembles a minimal segwit block:
// - one coinbase with a proper witness commitment output
// - one coinbase input whose scriptWitness stack is the witnessStack parameter
// Returns the block and the params with SegwitHeight=0 (always active).
//
// commitment = SHA256d(witnessMerkleRoot || nonce) where the witness merkle root
// treats the coinbase wtxid as all-zeros.
func buildSegwitBlock(t *testing.T, witnessStack [][]byte, extraOutputs ...*wire.TxOut) *wire.MsgBlock {
	t.Helper()

	// Build a minimal coinbase with OP_RETURN witness commitment and the
	// provided witness stack.
	coinbase := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00}, // BIP34 height=1
			Sequence:         0xFFFFFFFF,
			Witness:          witnessStack,
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_0000_0000, PkScript: []byte{0x51}}, // miner payout
		},
		LockTime: 0,
	}

	// Append any extra outputs before the commitment output so the test can
	// exercise LAST-occurrence scan.
	coinbase.TxOut = append(coinbase.TxOut, extraOutputs...)

	// Compute the witness merkle root: coinbase wtxid = 0x00..00, no other txs.
	nonce := witnessStack
	var nonceBuf []byte
	if len(nonce) == 1 && len(nonce[0]) == 32 {
		nonceBuf = nonce[0]
	} else {
		nonceBuf = make([]byte, 32) // use zeros so computation doesn't panic
	}
	wtxids := []wire.Hash256{{}} // coinbase wtxid = all zeros (Gate 5)
	witnessRoot := CalcWitnessMerkleRoot(wtxids)

	// commitment = SHA256d(witnessRoot || nonce) — double-SHA256 (Gate 7)
	data := make([]byte, 64)
	copy(data[:32], witnessRoot[:])
	copy(data[32:], nonceBuf)
	commitment := wire.DoubleHashB(data)

	// Build the OP_RETURN witness commitment script (38 bytes, Gate 2)
	commitScript := make([]byte, 38)
	commitScript[0] = 0x6a // OP_RETURN
	commitScript[1] = 0x24 // push 36 bytes
	commitScript[2] = 0xaa
	commitScript[3] = 0x21
	commitScript[4] = 0xa9
	commitScript[5] = 0xed
	copy(commitScript[6:], commitment[:])
	coinbase.TxOut = append(coinbase.TxOut, &wire.TxOut{Value: 0, PkScript: commitScript})

	txid := coinbase.TxHash()
	root := CalcMerkleRoot([]wire.Hash256{txid})

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x20000000,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: root,
			Timestamp:  1231006505 + 1,
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}
}

// buildSegwitParams returns regtest params with SegwitHeight=0 (always active)
// and all other soft-forks pushed above height 1 so they don't interfere.
func buildSegwitParams() *ChainParams {
	p := *RegtestParams()
	p.SegwitHeight = 0
	p.BIP34Height = 200_000
	p.BIP65Height = 200_000
	p.BIP66Height = 200_000
	p.CSVHeight = 200_000
	p.TaprootHeight = 200_000
	return &p
}

// TestWitnessCommitment_Gate2_MinimumSize verifies Gate 2: MINIMUM_WITNESS_COMMITMENT=38.
// A coinbase output whose PkScript is only 37 bytes (off-by-one) must be ignored
// (not treated as a commitment), causing the block to be accepted with no commitment
// expected (since no witness data in txs) OR rejected as missing commitment when
// witness data is present.
func TestWitnessCommitment_Gate2_MinimumSize(t *testing.T) {
	params := buildSegwitParams()

	// Build a 37-byte script that would otherwise match (one byte short of 38).
	shortScript := make([]byte, 37)
	shortScript[0] = 0x6a // OP_RETURN
	shortScript[1] = 0x24
	shortScript[2] = 0xaa
	shortScript[3] = 0x21
	shortScript[4] = 0xa9
	shortScript[5] = 0xed
	// only 31 bytes of commitment hash follow (not 32)

	coinbase := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
			Witness:          nil,
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_0000_0000, PkScript: []byte{0x51}},
			{Value: 0, PkScript: shortScript}, // 37 bytes — too short
		},
		LockTime: 0,
	}

	txid := coinbase.TxHash()
	root := CalcMerkleRoot([]wire.Hash256{txid})
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x20000000,
			Timestamp:  1231006506,
			MerkleRoot: root,
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}

	// Block has no real witness data and no valid commitment (37 < 38).
	// Should be accepted (no witness data → commitment is optional).
	err := CheckBlockContext(block, nil, 1, params)
	if err != nil {
		t.Errorf("Gate2: 37-byte script (too short) must be ignored; block should pass, got: %v", err)
	}
}

// TestWitnessCommitment_Gate3_LastOccurrence verifies Gate 3: the LAST matching
// coinbase output wins (Core overwrites commitpos on every match; blockbrew scans
// backward and breaks on first).
func TestWitnessCommitment_Gate3_LastOccurrence(t *testing.T) {
	params := buildSegwitParams()

	// We build a block with two witness commitment outputs: one with a wrong hash
	// (at index 1) and one with the correct hash (at index 2, the LAST one).
	// Core uses the last one, so the block should pass.

	validNonce := make([]byte, 32)
	wtxids := []wire.Hash256{{}} // coinbase wtxid = zeros
	witnessRoot := CalcWitnessMerkleRoot(wtxids)

	data := make([]byte, 64)
	copy(data[:32], witnessRoot[:])
	copy(data[32:], validNonce)
	correctCommitment := wire.DoubleHashB(data)

	// Wrong commitment: all-0xff
	wrongHash := make([]byte, 32)
	for i := range wrongHash {
		wrongHash[i] = 0xff
	}

	makeCommitScript := func(hash []byte) []byte {
		s := make([]byte, 38)
		s[0] = 0x6a
		s[1] = 0x24
		s[2] = 0xaa; s[3] = 0x21; s[4] = 0xa9; s[5] = 0xed
		copy(s[6:], hash)
		return s
	}

	coinbase := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
			Witness:          [][]byte{validNonce},
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_0000_0000, PkScript: []byte{0x51}},
			{Value: 0, PkScript: makeCommitScript(wrongHash)},   // FIRST — wrong
			{Value: 0, PkScript: makeCommitScript(correctCommitment[:])}, // LAST — correct
		},
		LockTime: 0,
	}
	txid := coinbase.TxHash()
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version: 0x20000000, Timestamp: 1231006506,
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{txid}),
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}

	// Must succeed: last commitment is correct.
	if err := CheckBlockContext(block, nil, 1, params); err != nil {
		t.Errorf("Gate3 (last wins): should accept block with correct LAST commitment, got: %v", err)
	}

	// Now flip: first is correct, last is wrong → should FAIL.
	coinbase2 := *coinbase
	txin2 := *coinbase.TxIn[0]
	txin2.Witness = [][]byte{validNonce}
	coinbase2.TxIn = []*wire.TxIn{&txin2}
	coinbase2.TxOut = []*wire.TxOut{
		{Value: 50_0000_0000, PkScript: []byte{0x51}},
		{Value: 0, PkScript: makeCommitScript(correctCommitment[:])}, // FIRST — correct
		{Value: 0, PkScript: makeCommitScript(wrongHash)},             // LAST — wrong
	}
	txid2 := coinbase2.TxHash()
	block2 := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version: 0x20000000, Timestamp: 1231006506,
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{txid2}),
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{&coinbase2},
	}
	if err := CheckBlockContext(block2, nil, 1, params); err == nil {
		t.Error("Gate3 (last wins): should reject block where LAST commitment is wrong but FIRST is correct")
	}
}

// TestWitnessCommitment_Gate5_CoinbaseWtxidZeros verifies Gate 5: the coinbase
// wtxid used in the witness merkle tree is 0x00..00 (not the real txid/wtxid).
// This is enforced by CalcWitnessMerkleRoot: it zeroes index 0.
func TestWitnessCommitment_Gate5_CoinbaseWtxidZeros(t *testing.T) {
	params := buildSegwitParams()

	// Build a block where the commitment is computed with coinbase wtxid = zeros.
	nonce := make([]byte, 32)
	block := buildSegwitBlock(t, [][]byte{nonce})

	if err := CheckBlockContext(block, nil, 1, params); err != nil {
		t.Errorf("Gate5: block with coinbase-wtxid=zeros commitment should pass, got: %v", err)
	}

	// Now corrupt the commitment to use the real coinbase txid instead of zeros.
	coinbase := block.Transactions[0]
	realWtxid := coinbase.WTxHash() // real witness txid
	wtxidsReal := []wire.Hash256{realWtxid}
	witnessRootBad := CalcMerkleRoot(wtxidsReal) // using real txid, not zeros

	data := make([]byte, 64)
	copy(data[:32], witnessRootBad[:])
	copy(data[32:], nonce)
	badCommit := wire.DoubleHashB(data)

	// Patch the commitment output of the coinbase.
	lastOut := coinbase.TxOut[len(coinbase.TxOut)-1]
	badScript := make([]byte, 38)
	copy(badScript, lastOut.PkScript[:6])
	copy(badScript[6:], badCommit[:])
	coinbase.TxOut[len(coinbase.TxOut)-1] = &wire.TxOut{Value: 0, PkScript: badScript}

	txid2 := coinbase.TxHash()
	block.Header.MerkleRoot = CalcMerkleRoot([]wire.Hash256{txid2})

	if err := CheckBlockContext(block, nil, 1, params); err == nil {
		t.Error("Gate5: commitment using real coinbase wtxid (not zeros) should fail")
	}
}

// TestWitnessCommitment_Gate6_NonceSizeValidation verifies Gate 6:
// the coinbase scriptWitness must have exactly 1 stack element of exactly 32 bytes.
// Core: "bad-witness-nonce-size" (validation.cpp:3880-3885).
func TestWitnessCommitment_Gate6_NonceSizeValidation(t *testing.T) {
	params := buildSegwitParams()

	tests := []struct {
		name        string
		witnessStack [][]byte
		wantErr     bool
	}{
		{
			name:         "valid: exactly 1 element of 32 bytes",
			witnessStack: [][]byte{make([]byte, 32)},
			wantErr:      false,
		},
		{
			name:         "invalid: empty witness stack",
			witnessStack: [][]byte{},
			wantErr:      true,
		},
		{
			name:         "invalid: nil witness stack",
			witnessStack: nil,
			wantErr:      true,
		},
		{
			name:         "invalid: one element of 31 bytes (too short)",
			witnessStack: [][]byte{make([]byte, 31)},
			wantErr:      true,
		},
		{
			name:         "invalid: one element of 33 bytes (too long)",
			witnessStack: [][]byte{make([]byte, 33)},
			wantErr:      true,
		},
		{
			name:         "invalid: two elements of 32 bytes each",
			witnessStack: [][]byte{make([]byte, 32), make([]byte, 32)},
			wantErr:      true,
		},
		{
			name:         "invalid: one element of 0 bytes",
			witnessStack: [][]byte{{}},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := buildSegwitBlock(t, tt.witnessStack)
			err := CheckBlockContext(block, nil, 1, params)
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
			// For the error cases, confirm we get ErrBadWitnessNonceSize.
			if tt.wantErr && err != nil && !errors.Is(err, ErrBadWitnessNonceSize) {
				t.Errorf("expected ErrBadWitnessNonceSize, got: %v", err)
			}
		})
	}
}

// TestWitnessCommitment_Gate7_DoubleSHA256 verifies Gate 7: the witness commitment
// hash uses SHA256d (double SHA256), not single SHA256.
// We test this by:
// 1. Verifying a block with a correct SHA256d commitment passes.
// 2. Verifying a block with a wrong (all-zeros) commitment fails with ErrBadWitnessCommitment.
// If the implementation used single-SHA256, case 1 would fail, exposing the bug.
func TestWitnessCommitment_Gate7_DoubleSHA256(t *testing.T) {
	params := buildSegwitParams()

	// A correctly double-SHA256'd block should pass.
	nonce := make([]byte, 32)
	block := buildSegwitBlock(t, [][]byte{nonce})
	if err := CheckBlockContext(block, nil, 1, params); err != nil {
		t.Errorf("Gate7: block with SHA256d commitment should pass, got: %v", err)
	}

	// Corrupt the commitment to all-zeros (a value that matches neither SHA256
	// nor SHA256d of the real input). Should fail with ErrBadWitnessCommitment.
	coinbase := block.Transactions[0]
	badScript := make([]byte, 38)
	copy(badScript, coinbase.TxOut[len(coinbase.TxOut)-1].PkScript[:6]) // preserve magic
	// bytes [6:38] remain zero — wrong commitment
	coinbase.TxOut[len(coinbase.TxOut)-1] = &wire.TxOut{Value: 0, PkScript: badScript}

	txid2 := coinbase.TxHash()
	block.Header.MerkleRoot = CalcMerkleRoot([]wire.Hash256{txid2})

	if err := CheckBlockContext(block, nil, 1, params); err == nil {
		t.Error("Gate7: block with corrupted commitment should fail")
	} else if !errors.Is(err, ErrBadWitnessCommitment) {
		t.Errorf("Gate7: expected ErrBadWitnessCommitment, got: %v", err)
	}
}

// TestWitnessCommitment_Gate9_UnexpectedWitness verifies Gate 9: when segwit is
// NOT active (height < SegwitHeight), any transaction with witness data must be
// rejected. Bitcoin Core: "unexpected-witness" (validation.cpp:3905-3913).
func TestWitnessCommitment_Gate9_UnexpectedWitness(t *testing.T) {
	params := *RegtestParams()
	params.SegwitHeight = 100 // segwit activates at 100
	params.BIP34Height = 200_000
	params.BIP65Height = 200_000
	params.BIP66Height = 200_000
	params.CSVHeight = 200_000
	params.TaprootHeight = 200_000

	// Build a coinbase with witness data (in a pre-segwit block).
	coinbase := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
			Witness:          [][]byte{make([]byte, 32)}, // witness data — unexpected
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_0000_0000, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}
	txid := coinbase.TxHash()
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version: 0x20000000, Timestamp: 1231006506,
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{txid}),
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}

	// At height 50 (< SegwitHeight=100): witness data → must be rejected.
	err := CheckBlockContext(block, nil, 50, &params)
	if err == nil {
		t.Error("Gate9: pre-segwit block with witness data should be rejected")
	} else if !errors.Is(err, ErrUnexpectedWitnessInBlock) {
		t.Errorf("Gate9: expected ErrUnexpectedWitnessInBlock, got: %v", err)
	}

	// At height 99 (still < SegwitHeight=100): same block must be rejected.
	err = CheckBlockContext(block, nil, 99, &params)
	if err == nil {
		t.Error("Gate9: pre-segwit block (h=99) with witness data should be rejected")
	}

	// Sanity: no-witness coinbase at height 50 must pass (no spurious rejection).
	coinbaseNoWitness := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_0000_0000, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}
	txid2 := coinbaseNoWitness.TxHash()
	blockNoWitness := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version: 0x20000000, Timestamp: 1231006506,
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{txid2}),
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{coinbaseNoWitness},
	}
	if err := CheckBlockContext(blockNoWitness, nil, 50, &params); err != nil {
		t.Errorf("Gate9: pre-segwit block without witness should pass, got: %v", err)
	}
}

// TestWitnessCommitment_FullValid verifies the complete happy-path: a segwit block
// with a valid commitment, a correct 32-byte nonce, and coinbase wtxid=zeros.
func TestWitnessCommitment_FullValid(t *testing.T) {
	params := buildSegwitParams()
	nonce := make([]byte, 32)
	block := buildSegwitBlock(t, [][]byte{nonce})
	if err := CheckBlockContext(block, nil, 1, params); err != nil {
		t.Errorf("FullValid: should pass, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// W84 — CheckTransaction + CheckTxInputs + CVE-2018-17144 + GetBlockSubsidy
// Comprehensive gate tests.  Reference: bitcoin-core/src/consensus/tx_check.cpp,
// tx_verify.cpp:164-214, validation.cpp:1839-1850, consensus/amount.h.
// ---------------------------------------------------------------------------

// TestCheckTransactionSanity_OversizeBug tests that the oversize check uses
// the non-witness serialized size × WITNESS_SCALE_FACTOR (Core tx_check.cpp:19)
// rather than the full weight.  A tx with large witness but small non-witness
// body is valid in Core but was falsely rejected by the old CalcTxWeight check.
func TestCheckTransactionSanity_OversizeBug(t *testing.T) {
	// Build a tx whose non-witness size is just under 1 MB (the implicit limit
	// from the Core formula: non_witness * 4 > 4_000_000 → non_witness > 1_000_000).
	// We use a 999,900-byte scriptSig so non_witness ≈ 999,946 bytes.
	// Then add 4 MB of witness data to push actual weight far above 4,000,000.
	// Core would ACCEPT this (non_witness * 4 < 4,000,000); old blockbrew would REJECT.
	const scriptSigSize = 999_900
	largeSig := make([]byte, scriptSigSize)

	// Build witness with total bytes exceeding 4 MB.
	// Each witness stack item is ~50 KB; 100 items = ~5 MB witness.
	witnessItem := make([]byte, 50_000)
	var witnessStack [][]byte
	for i := 0; i < 100; i++ {
		witnessStack = append(witnessStack, witnessItem)
	}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
				SignatureScript:  largeSig,
				Witness:          witnessStack,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 1000, PkScript: []byte{0x76, 0xa9}},
		},
	}

	// Verify the tx is actually oversized in actual weight but within non-witness limit
	strippedSize := CalcTxSerializeSizeNoWitness(tx)
	weight := CalcTxWeight(tx)
	if strippedSize*WitnessScaleFactor > MaxBlockWeight {
		t.Skipf("test setup: non-witness size %d × 4 = %d exceeds limit; adjust scriptSigSize",
			strippedSize, strippedSize*WitnessScaleFactor)
	}
	if weight <= MaxBlockWeight {
		t.Skipf("test setup: actual weight %d does not exceed limit; add more witness data", weight)
	}

	// After the fix: should PASS (non-witness body is within limit)
	err := CheckTransactionSanity(tx)
	if err != nil {
		t.Errorf("oversized-witness tx should pass after fix (non-witness within limit), got: %v", err)
	}
}

// TestCheckTransactionSanity_OversizeNonWitness tests that a tx whose non-witness
// body exceeds 1 MB is rejected (Core: non_witness * 4 > MAX_BLOCK_WEIGHT).
func TestCheckTransactionSanity_OversizeNonWitness(t *testing.T) {
	// non_witness_size = 1_000_100 → non_witness * 4 = 4_000_400 > 4_000_000
	largeSig := make([]byte, 1_000_100)
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
				SignatureScript:  largeSig,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 1000, PkScript: []byte{0x76, 0xa9}},
		},
	}
	err := CheckTransactionSanity(tx)
	if err == nil {
		t.Errorf("expected ErrOversizedTx for large non-witness tx, got nil")
	}
	if err != ErrOversizedTx {
		t.Errorf("expected ErrOversizedTx, got %v", err)
	}
}

// TestCheckTransactionSanity_CVE_2018_17144 tests the duplicate-input check
// that prevents the inflation bug (CVE-2018-17144).
// Reference: bitcoin-core/src/consensus/tx_check.cpp:36-45.
func TestCheckTransactionSanity_CVE_2018_17144(t *testing.T) {
	hash1 := wire.Hash256{0x01}
	hash2 := wire.Hash256{0x02}

	tests := []struct {
		name    string
		inputs  []*wire.TxIn
		wantErr bool
	}{
		{
			name: "same hash same index → duplicate (must reject)",
			inputs: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
			},
			wantErr: true,
		},
		{
			name: "same hash different index → not duplicate (must accept)",
			inputs: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 1}, SignatureScript: []byte{0x00}},
			},
			wantErr: false,
		},
		{
			name: "different hash same index → not duplicate (must accept)",
			inputs: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
				{PreviousOutPoint: wire.OutPoint{Hash: hash2, Index: 0}, SignatureScript: []byte{0x00}},
			},
			wantErr: false,
		},
		{
			name: "three inputs, third duplicates first",
			inputs: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
				{PreviousOutPoint: wire.OutPoint{Hash: hash2, Index: 0}, SignatureScript: []byte{0x00}},
				{PreviousOutPoint: wire.OutPoint{Hash: hash1, Index: 0}, SignatureScript: []byte{0x00}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    tt.inputs,
				TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{0x76, 0xa9}}},
			}
			err := CheckTransactionSanity(tx)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error (duplicate input), got nil")
				} else if err != ErrDuplicateInput {
					t.Errorf("expected ErrDuplicateInput, got %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCheckTransactionSanity_CoinbaseScriptBoundaries tests the exact 2-byte
// and 100-byte boundaries for coinbase scriptSig length.
// Reference: bitcoin-core/src/consensus/tx_check.cpp:49.
func TestCheckTransactionSanity_CoinbaseScriptBoundaries(t *testing.T) {
	makeCoibaseTx := func(scriptLen int) *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
					SignatureScript:  make([]byte, scriptLen),
					Sequence:         0xffffffff,
				},
			},
			TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: []byte{0x76, 0xa9}}},
		}
	}

	tests := []struct {
		name    string
		len     int
		wantErr bool
	}{
		{"length 1 (too short)", 1, true},
		{"length 2 (minimum, must pass)", 2, false},
		{"length 50 (middle, must pass)", 50, false},
		{"length 100 (maximum, must pass)", 100, false},
		{"length 101 (too long)", 101, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeCoibaseTx(tt.len)
			err := CheckTransactionSanity(tx)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected ErrCoinbaseScriptSize for len=%d, got nil", tt.len)
				} else if err != ErrCoinbaseScriptSize {
					t.Errorf("expected ErrCoinbaseScriptSize for len=%d, got %v", tt.len, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for len=%d: %v", tt.len, err)
				}
			}
		})
	}
}

// TestCheckTransactionSanity_OutputSumOverflow tests that two outputs each
// below MaxMoney but summing above MaxMoney are rejected.
// Reference: bitcoin-core/src/consensus/tx_check.cpp:31-33 (bad-txns-txouttotal-toolarge).
func TestCheckTransactionSanity_OutputSumOverflow(t *testing.T) {
	// MaxMoney/2 + 1 + MaxMoney/2 + 1 > MaxMoney
	half := MaxMoney/2 + 1
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, SignatureScript: []byte{0x00}},
		},
		TxOut: []*wire.TxOut{
			{Value: half, PkScript: []byte{0x76, 0xa9}},
			{Value: half, PkScript: []byte{0x76, 0xa9}},
		},
	}
	err := CheckTransactionSanity(tx)
	if err == nil {
		t.Errorf("expected ErrTotalOutputTooLarge for output sum > MaxMoney, got nil")
	}
	if err != ErrTotalOutputTooLarge {
		t.Errorf("expected ErrTotalOutputTooLarge, got %v", err)
	}
}

// TestCheckTransactionSanity_OutputsExactMaxMoney tests that a single output
// of exactly MaxMoney is accepted.
func TestCheckTransactionSanity_OutputsExactMaxMoney(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, SignatureScript: []byte{0x00}},
		},
		TxOut: []*wire.TxOut{
			{Value: MaxMoney, PkScript: []byte{0x76, 0xa9}},
		},
	}
	if err := CheckTransactionSanity(tx); err != nil {
		t.Errorf("exact MaxMoney output should pass, got: %v", err)
	}
}

// TestCheckTransactionInputs_CoinbaseMaturityBoundaries tests the exact
// COINBASE_MATURITY (100) depth boundary.
// Reference: bitcoin-core/src/consensus/tx_verify.cpp:179.
func TestCheckTransactionInputs_CoinbaseMaturityBoundaries(t *testing.T) {
	utxoView := NewInMemoryUTXOView()
	// Coinbase UTXO created at height 100
	utxoView.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0xAB}, Index: 0}, &UTXOEntry{
		Amount:     5_000_000_000,
		PkScript:   []byte{0x76, 0xa9},
		Height:     100,
		IsCoinbase: true,
	})

	spendTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xAB}, Index: 0}, SignatureScript: []byte{0x00}},
		},
		TxOut: []*wire.TxOut{
			{Value: 4_000_000_000, PkScript: []byte{0x76, 0xa9}},
		},
	}

	tests := []struct {
		name      string
		txHeight  int32
		wantErr   bool
		errTarget error
	}{
		// depth = txHeight - utxoHeight = 99/100/101
		{"depth 99 (immature)", 199, true, ErrImmatureCoinbase},
		{"depth 100 (exactly mature)", 200, false, nil},
		{"depth 101 (more than mature)", 201, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CheckTransactionInputs(spendTx, tt.txHeight, utxoView)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error at depth %d, got nil", tt.txHeight-100)
				} else if !containsError(err, tt.errTarget) {
					t.Errorf("expected %v, got %v", tt.errTarget, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error at depth %d: %v", tt.txHeight-100, err)
				}
			}
		})
	}
}

// TestCheckTransactionInputs_InputValueRange tests MoneyRange enforcement on
// individual and accumulated input values.
// Reference: bitcoin-core/src/consensus/tx_verify.cpp:186-188.
func TestCheckTransactionInputs_InputValueRange(t *testing.T) {
	// Negative input value
	viewNeg := NewInMemoryUTXOView()
	viewNeg.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, &UTXOEntry{
		Amount:     -1,
		PkScript:   []byte{0x76},
		Height:     0,
		IsCoinbase: false,
	})
	txNeg := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, SignatureScript: []byte{0x00}}},
		TxOut:   []*wire.TxOut{{Value: 0, PkScript: []byte{0x76}}},
	}
	if _, err := CheckTransactionInputs(txNeg, 500, viewNeg); err == nil {
		t.Errorf("negative input amount should be rejected")
	}

	// Input amount > MaxMoney
	viewLarge := NewInMemoryUTXOView()
	viewLarge.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0}, &UTXOEntry{
		Amount:     MaxMoney + 1,
		PkScript:   []byte{0x76},
		Height:     0,
		IsCoinbase: false,
	})
	txLarge := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0}, SignatureScript: []byte{0x00}}},
		TxOut:   []*wire.TxOut{{Value: 0, PkScript: []byte{0x76}}},
	}
	if _, err := CheckTransactionInputs(txLarge, 500, viewLarge); err == nil {
		t.Errorf("input amount > MaxMoney should be rejected")
	}

	// Accumulated inputs > MaxMoney (two inputs each at MaxMoney)
	viewAccum := NewInMemoryUTXOView()
	viewAccum.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 0}, &UTXOEntry{
		Amount:     MaxMoney,
		PkScript:   []byte{0x76},
		Height:     0,
		IsCoinbase: false,
	})
	viewAccum.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 1}, &UTXOEntry{
		Amount:     MaxMoney,
		PkScript:   []byte{0x76},
		Height:     0,
		IsCoinbase: false,
	})
	txAccum := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 0}, SignatureScript: []byte{0x00}},
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 1}, SignatureScript: []byte{0x00}},
		},
		TxOut: []*wire.TxOut{{Value: 0, PkScript: []byte{0x76}}},
	}
	if _, err := CheckTransactionInputs(txAccum, 500, viewAccum); err == nil {
		t.Errorf("accumulated inputs > MaxMoney should be rejected")
	}
}

// TestCheckTransactionInputs_FeeCalculation tests correct fee calculation
// at various input/output combinations including zero-fee and exact-match.
func TestCheckTransactionInputs_FeeCalculation(t *testing.T) {
	utxoView := NewInMemoryUTXOView()
	utxoView.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0x10}, Index: 0}, &UTXOEntry{
		Amount:     1_000_000,
		PkScript:   []byte{0x76},
		Height:     0,
		IsCoinbase: false,
	})

	tests := []struct {
		name     string
		outValue int64
		wantFee  int64
		wantErr  bool
	}{
		{"zero fee (in == out)", 1_000_000, 0, false},
		{"normal fee", 900_000, 100_000, false},
		{"outputs > inputs (reject)", 1_000_001, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x10}, Index: 0}, SignatureScript: []byte{0x00}}},
				TxOut:   []*wire.TxOut{{Value: tt.outValue, PkScript: []byte{0x76}}},
			}
			fee, err := CheckTransactionInputs(tx, 500, utxoView)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if fee != tt.wantFee {
					t.Errorf("fee = %d, want %d", fee, tt.wantFee)
				}
			}
		})
	}
}

// TestCalcBlockSubsidyAllHalvingBoundaries tests every significant halving
// boundary including the critical halvings >= 64 UB-guard.
// Reference: bitcoin-core/src/validation.cpp:1839-1850.
func TestCalcBlockSubsidyAllHalvingBoundaries(t *testing.T) {
	// InitialSubsidy = 50 BTC = 5,000,000,000 satoshis
	// Last non-zero halving: halving 32 (5,000,000,000 >> 32 = 1 sat).
	// Halving 33+: 0 sats.
	// The halvings >= 64 guard prevents UB in C++ (Go right-shifts are always safe,
	// but the gate is required for consensus-equivalence with Core).
	tests := []struct {
		name    string
		height  int32
		subsidy int64
	}{
		// --- Boundaries of the first halving ---
		{"last block before halving 1 (h=209999)", 209_999, 5_000_000_000},
		{"first block of halving 1 (h=210000)", 210_000, 2_500_000_000},

		// --- Last non-zero subsidy ---
		{"last block before halving 32 (h=6719999)", 6_719_999, 2},
		{"first block of halving 32 (h=6720000, subsidy=1 sat)", 6_720_000, 1},
		{"last block at halving 32 (h=6929999)", 6_929_999, 1},

		// --- First zero-subsidy halving ---
		{"first block of halving 33 (h=6930000)", 6_930_000, 0},
		{"mid-halving 33 (h=7000000)", 7_000_000, 0},

		// --- halvings >= 64 guard (critical: prevents >> 64 UB in C++) ---
		{"last block before halvings=64 (h=13439999)", 13_439_999, 0},
		{"first block at halvings=64 (h=13440000)", 13_440_000, 0},
		{"block well past halvings=64 (h=14000000)", 14_000_000, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalcBlockSubsidy(tt.height)
			if got != tt.subsidy {
				t.Errorf("CalcBlockSubsidy(%d) = %d, want %d", tt.height, got, tt.subsidy)
			}
		})
	}
}

// TestCalcBlockSubsidyAllHalvings verifies every halving from 0 to 64
// matches the reference formula: InitialSubsidy >> halving (capped at 0 for >= 64).
func TestCalcBlockSubsidyAllHalvings(t *testing.T) {
	for halving := int32(0); halving <= 65; halving++ {
		height := halving * SubsidyHalvingInterval
		got := CalcBlockSubsidy(height)

		var want int64
		if halving < 64 {
			want = InitialSubsidy >> uint(halving)
		}
		if got != want {
			t.Errorf("CalcBlockSubsidy(%d) [halving=%d] = %d, want %d", height, halving, got, want)
		}
	}
}

// TestGetBlockSubsidyMoneyRange verifies that CalcBlockSubsidy always returns
// a value in MoneyRange [0, MaxMoney].
func TestGetBlockSubsidyMoneyRange(t *testing.T) {
	testHeights := []int32{
		0, 1, 209_999, 210_000, 420_000, 6_720_000, 6_930_000,
		13_440_000, 13_440_001, 14_000_000,
	}
	for _, h := range testHeights {
		s := CalcBlockSubsidy(h)
		if s < 0 || s > MaxMoney {
			t.Errorf("CalcBlockSubsidy(%d) = %d is outside MoneyRange [0, %d]", h, s, MaxMoney)
		}
	}
}
