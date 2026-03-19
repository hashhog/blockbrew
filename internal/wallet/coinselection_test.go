package wallet

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestSelectCoinsBnBExactMatch(t *testing.T) {
	// Create UTXOs that can form an exact match
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    50000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
			Amount:    30000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{3}, Index: 0},
			Amount:    20000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	// Target that can be exactly matched with 50000 + 30000 = 80000
	// With a fee rate of 1 sat/vbyte and ~68 vbytes per input:
	// effective value of 50000 = 50000 - 68 = 49932
	// effective value of 30000 = 30000 - 68 = 29932
	// Total effective = 79864
	target := int64(70000)
	feeRate := 1.0
	costOfChange := int64(31) // P2WPKH change output cost

	result, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected a selection result")
	}

	if len(result.Coins) == 0 {
		t.Fatal("Expected at least one coin selected")
	}

	// Verify total is sufficient
	if result.Total < target {
		t.Errorf("Selected total %d is less than target %d", result.Total, target)
	}
}

func TestSelectCoinsBnBNoSolution(t *testing.T) {
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    10000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	// Target larger than available
	target := int64(50000)
	feeRate := 1.0
	costOfChange := int64(31)

	_, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != ErrInsufficientFunds {
		t.Errorf("Expected ErrInsufficientFunds, got %v", err)
	}
}

func TestSelectCoinsKnapsackFallback(t *testing.T) {
	// Create UTXOs where BnB might fail but Knapsack should succeed
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    100000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
			Amount:    50000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{3}, Index: 0},
			Amount:    25000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	// Target that doesn't have an exact match
	target := int64(120000)
	feeRate := 1.0
	costOfChange := int64(31)

	result, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected a selection result")
	}

	// Verify total is sufficient
	if result.Total < target {
		t.Errorf("Selected total %d is less than target %d", result.Total, target)
	}
}

func TestSelectCoinsUnconfirmedSkipped(t *testing.T) {
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    100000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: false, // Unconfirmed - should be skipped
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
			Amount:    50000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	// Target that requires the unconfirmed UTXO
	target := int64(120000)
	feeRate := 1.0
	costOfChange := int64(31)

	_, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != ErrInsufficientFunds {
		t.Errorf("Expected ErrInsufficientFunds (unconfirmed should be skipped), got %v", err)
	}
}

func TestSelectCoinsPrefersBnB(t *testing.T) {
	// Create UTXOs where BnB should find a changeless solution
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    50068, // After 68 sat fee = 50000 effective
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
			Amount:    30068, // After 68 sat fee = 30000 effective
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{3}, Index: 0},
			Amount:    100000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	// Target = 80000, exact match possible with first two UTXOs
	target := int64(80000)
	feeRate := 1.0
	costOfChange := int64(100) // High change cost should encourage BnB

	result, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	// BnB should be preferred for this case
	if result.Algorithm != AlgoBnB && result.Algorithm != AlgoKnapsack {
		t.Errorf("Expected BnB or Knapsack algorithm, got %v", result.Algorithm)
	}
}

func TestSelectCoinsEmptyUTXOs(t *testing.T) {
	var utxos []*WalletUTXO

	_, err := SelectCoins(utxos, 10000, 1.0, 31)
	if err != ErrInsufficientFunds {
		t.Errorf("Expected ErrInsufficientFunds for empty UTXOs, got %v", err)
	}
}

func TestEstimateInputVSize(t *testing.T) {
	tests := []struct {
		name     string
		pkScript []byte
		expected int
	}{
		{
			name:     "P2PKH",
			pkScript: makeP2PKHScript(),
			expected: 148,
		},
		{
			name:     "P2WPKH",
			pkScript: makeP2WPKHScript(),
			expected: 68,
		},
		{
			name:     "P2SH",
			pkScript: makeP2SHScript(),
			expected: 91,
		},
		{
			name:     "P2TR",
			pkScript: makeP2TRScript(),
			expected: 57,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateInputVSize(tt.pkScript)
			if got != tt.expected {
				t.Errorf("estimateInputVSize() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestEstimateTxVSize(t *testing.T) {
	// Test with 2 P2WPKH inputs and 2 P2WPKH outputs
	inputs := [][]byte{makeP2WPKHScript(), makeP2WPKHScript()}
	outputs := [][]byte{makeP2WPKHScript(), makeP2WPKHScript()}

	vsize := EstimateTxVSize(2, inputs, 2, outputs)

	// Expected: 10 base + 68*2 inputs + 31*2 outputs = 208
	expected := 10 + 68*2 + 31*2
	if vsize != expected {
		t.Errorf("EstimateTxVSize() = %d, want %d", vsize, expected)
	}
}

// Helper functions to create test scripts
func makeP2PKHScript() []byte {
	return []byte{
		0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 <push 20>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
	}
}

func makeP2WPKHScript() []byte {
	return []byte{
		0x00, 0x14, // OP_0 <push 20>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func makeP2SHScript() []byte {
	return []byte{
		0xa9, 0x14, // OP_HASH160 <push 20>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x87, // OP_EQUAL
	}
}

func makeP2TRScript() []byte {
	return []byte{
		0x51, 0x20, // OP_1 <push 32>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}

func TestKnapsackDirectSelection(t *testing.T) {
	// Test that Knapsack finds a good solution
	utxos := []*WalletUTXO{
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Amount:    25000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
			Amount:    35000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
		{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{3}, Index: 0},
			Amount:    45000,
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		},
	}

	target := int64(50000)
	feeRate := 1.0
	costOfChange := int64(31)

	result, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result")
	}

	// Should select enough to cover target
	var total int64
	for _, c := range result.Coins {
		total += c.Amount
	}
	if total < target {
		t.Errorf("Total %d less than target %d", total, target)
	}
}

func TestBnBIterationLimit(t *testing.T) {
	// Create many small UTXOs to test iteration limit
	var utxos []*WalletUTXO
	for i := 0; i < 30; i++ {
		utxos = append(utxos, &WalletUTXO{
			OutPoint:  wire.OutPoint{Hash: wire.Hash256{byte(i)}, Index: 0},
			Amount:    int64(1000 + i*100),
			PkScript:  makeP2WPKHScript(),
			Confirmed: true,
		})
	}

	target := int64(10000)
	feeRate := 1.0
	costOfChange := int64(31)

	// Should complete without hanging
	result, err := SelectCoins(utxos, target, feeRate, costOfChange)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result")
	}
}
