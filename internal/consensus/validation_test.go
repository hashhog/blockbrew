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

	// Header weight is 80 * 4 = 320
	// Plus transaction weight
	txWeight := CalcTxWeight(block.Transactions[0])
	expectedWeight := int64(320) + txWeight

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
// uses the correct exception heights (91842 and 91880), not the previously
// wrong values (91722 and 91812).
//
// Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().
// The two mainnet blocks at h=91842 and h=91880 intentionally duplicate earlier
// coinbase txids and must be exempted; all other heights must be enforced.
//
// This test calls CheckBIP30 directly — the same helper invoked by
// ChainManager.ConnectBlock — so it exercises the live production code path.
func TestBIP30ExceptionHeights(t *testing.T) {
	// Use regtest params (maximal PoW limit) so any block hash passes PoW.
	// Override activation heights so BIP-context checks don't interfere with
	// the BIP-30 assertion: push all soft-fork activations above h=200000 so
	// the test heights (91842, 91843, 91880, 91722, 91812) are all pre-activation.
	params := *RegtestParams()
	params.BIP34Height = 200_000
	params.BIP65Height = 200_000
	params.BIP66Height = 200_000
	params.CSVHeight = 200_000
	params.SegwitHeight = 200_000
	params.TaprootHeight = 200_000

	// Build a minimal coinbase transaction.
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

	newView := func() *InMemoryUTXOView {
		v := NewInMemoryUTXOView()
		v.AddUTXO(
			wire.OutPoint{Hash: coinbaseTxid, Index: 0},
			&UTXOEntry{Amount: 100, PkScript: []byte{0x51}, Height: 1000, IsCoinbase: true},
		)
		return v
	}

	// Test 1: height=91842 — EXEMPT.
	if err := CheckBIP30(block, 91842, &params, newView()); errors.Is(err, ErrDuplicateTx) {
		t.Errorf("height 91842: BIP-30 exception must NOT reject duplicate coinbase, got ErrDuplicateTx")
	}

	// Test 2: height=91843 — NOT exempt.
	if err := CheckBIP30(block, 91843, &params, newView()); !errors.Is(err, ErrDuplicateTx) {
		t.Errorf("height 91843: BIP-30 must reject duplicate coinbase, got: %v", err)
	}

	// Test 3: height=91880 — EXEMPT.
	if err := CheckBIP30(block, 91880, &params, newView()); errors.Is(err, ErrDuplicateTx) {
		t.Errorf("height 91880: BIP-30 exception must NOT reject duplicate coinbase, got ErrDuplicateTx")
	}

	// Verify old wrong heights (91722 and 91812) are NOT exempt.
	for _, wrongHeight := range []int32{91722, 91812} {
		if err := CheckBIP30(block, wrongHeight, &params, newView()); !errors.Is(err, ErrDuplicateTx) {
			t.Errorf("height %d: must NOT be BIP-30 exempt (wrong old height), got: %v", wrongHeight, err)
		}
	}
}
