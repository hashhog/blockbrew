package consensus

import (
	"bytes"
	"encoding/hex"
	"testing"

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
func TestCheckBIP34Height(t *testing.T) {
	tests := []struct {
		name       string
		scriptSig  []byte
		height     int32
		shouldPass bool
	}{
		{
			name:       "height 0 (OP_0)",
			scriptSig:  []byte{0x00},
			height:     0,
			shouldPass: true,
		},
		{
			name:       "height 1 (OP_1)",
			scriptSig:  []byte{0x51},
			height:     1,
			shouldPass: true,
		},
		{
			name:       "height 16 (OP_16)",
			scriptSig:  []byte{0x60},
			height:     16,
			shouldPass: true,
		},
		{
			name:       "height 100 (1 byte push)",
			scriptSig:  []byte{0x01, 0x64},
			height:     100,
			shouldPass: true,
		},
		{
			name:       "height 500000 (3 byte push)",
			scriptSig:  []byte{0x03, 0x20, 0xa1, 0x07}, // Little-endian 500000
			height:     500000,
			shouldPass: true,
		},
		{
			name:       "wrong height",
			scriptSig:  []byte{0x01, 0x64}, // height 100
			height:     200,                // expected 200
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
		height        int32
		expectP2SH    bool
		expectBIP66   bool
		expectBIP65   bool
		expectCSV     bool
		expectSegwit  bool
		expectNullFail bool
	}{
		{
			height:        0,
			expectP2SH:    true,
			expectBIP66:   false,
			expectBIP65:   false,
			expectCSV:     false,
			expectSegwit:  false,
			expectNullFail: false,
		},
		{
			height:        params.BIP66Height,
			expectP2SH:    true,
			expectBIP66:   true,
			expectBIP65:   false,
			expectCSV:     false,
			expectSegwit:  false,
			expectNullFail: false,
		},
		{
			height:        params.BIP65Height,
			expectP2SH:    true,
			expectBIP66:   true,
			expectBIP65:   true,
			expectCSV:     false,
			expectSegwit:  false,
			expectNullFail: false,
		},
		{
			height:        params.CSVHeight,
			expectP2SH:    true,
			expectBIP66:   true,
			expectBIP65:   true,
			expectCSV:     true,
			expectSegwit:  false,
			expectNullFail: false,
		},
		{
			height:        params.SegwitHeight,
			expectP2SH:    true,
			expectBIP66:   true,
			expectBIP65:   true,
			expectCSV:     true,
			expectSegwit:  true,
			expectNullFail: true, // BIP146 NULLFAIL activates with segwit
		},
		{
			height:        params.SegwitHeight - 1,
			expectP2SH:    true,
			expectBIP66:   true,
			expectBIP65:   true,
			expectCSV:     true,
			expectSegwit:  false,
			expectNullFail: false, // NULLFAIL not active before segwit
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			flags := GetBlockScriptFlags(tt.height, params)

			// Note: We import script package for ScriptFlags constants
			hasP2SH := flags&0x01 != 0
			hasSegwit := flags&0x02 != 0
			hasDERSig := flags&0x08 != 0
			hasCLTV := flags&0x200 != 0
			hasCSV := flags&0x400 != 0
			hasNullFail := flags&0x800 != 0 // ScriptVerifyNullFail = 1 << 11

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
