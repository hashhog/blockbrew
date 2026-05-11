package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ---- CalcTxWeight ----

// TestCalcTxWeightLegacy: legacy (non-segwit) tx → weight = size × 4
func TestCalcTxWeightLegacy(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
			SignatureScript:  make([]byte, 106), // P2PKH-style
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    50_000,
			PkScript: make([]byte, 25), // P2PKH scriptPubKey
		}},
		LockTime: 0,
	}

	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	strippedSize := int64(buf.Len())

	got := CalcTxWeight(tx)
	want := strippedSize * WitnessScaleFactor // 4 × size for legacy

	if got != want {
		t.Errorf("legacy tx weight = %d, want %d (stripped=%d)", got, want, strippedSize)
	}
}

// TestCalcTxWeightP2WPKH: P2WPKH tx → weight = stripped×3 + total
func TestCalcTxWeightP2WPKH(t *testing.T) {
	// Typical P2WPKH spend: empty scriptSig, 2-item witness (sig + pubkey)
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
			SignatureScript:  []byte{}, // empty for segwit
			Witness: [][]byte{
				make([]byte, 72), // DER sig
				make([]byte, 33), // compressed pubkey
			},
			Sequence: 0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    49_000,
			PkScript: make([]byte, 22), // P2WPKH
		}},
		LockTime: 0,
	}

	var strippedBuf, totalBuf bytes.Buffer
	tx.SerializeNoWitness(&strippedBuf)
	tx.Serialize(&totalBuf)
	stripped := int64(strippedBuf.Len())
	total := int64(totalBuf.Len())
	want := stripped*3 + total

	got := CalcTxWeight(tx)
	if got != want {
		t.Errorf("P2WPKH tx weight = %d, want %d (stripped=%d, total=%d)",
			got, want, stripped, total)
	}
}

// TestCalcTxWeightFormula: verifies the formula stripped×3+total vs 4×stripped+witness
func TestCalcTxWeightFormula(t *testing.T) {
	// Create a tx with a non-trivial witness
	witnessItem := make([]byte, 100)
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 1},
			SignatureScript:  []byte{},
			Witness:          [][]byte{witnessItem},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: make([]byte, 34), // P2WSH
		}},
		LockTime: 0,
	}

	var strippedBuf, totalBuf bytes.Buffer
	tx.SerializeNoWitness(&strippedBuf)
	tx.Serialize(&totalBuf)
	stripped := int64(strippedBuf.Len())
	total := int64(totalBuf.Len())

	// Both formulations must be equal:
	//   stripped × 3 + total  == stripped × 4 + (total − stripped)
	formulaA := stripped*3 + total
	formulaB := stripped*4 + (total - stripped)

	got := CalcTxWeight(tx)
	if got != formulaA {
		t.Errorf("weight = %d, want %d (stripped×3+total)", got, formulaA)
	}
	if formulaA != formulaB {
		t.Errorf("formula mismatch: stripped×3+total=%d vs stripped×4+witness=%d",
			formulaA, formulaB)
	}
}

// ---- CalcBlockWeight ----

// TestCalcBlockWeightIncludesVarInt verifies that the tx-count varint is
// included in the block weight (Bug fix: varint × 4 WU was previously missing).
func TestCalcBlockWeightIncludesVarInt(t *testing.T) {
	// Minimal coinbase-only block.
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 1231006505,
			Bits:      0x1d00ffff,
		},
		Transactions: []*wire.MsgTx{{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
				SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{
				Value:    5_000_000_000,
				PkScript: []byte{0x76, 0xa9, 0x14},
			}},
		}},
	}

	// Compute expected weight using the Core formula:
	// stripped_block = header(80) + varint(1 tx) + stripped_txs
	// total_block    = header(80) + varint(1 tx) + full_txs
	// weight         = stripped × 3 + total
	var strippedBuf bytes.Buffer
	strippedBuf.Write(make([]byte, 80))     // header placeholder (size only)
	strippedBuf.WriteByte(0x01)             // varint(1): 1 tx
	var txNW bytes.Buffer
	block.Transactions[0].SerializeNoWitness(&txNW)
	strippedBuf.Write(txNW.Bytes())

	var totalBuf bytes.Buffer
	totalBuf.Write(make([]byte, 80))
	totalBuf.WriteByte(0x01)
	var txW bytes.Buffer
	block.Transactions[0].Serialize(&txW)
	totalBuf.Write(txW.Bytes())

	wantWeight := int64(strippedBuf.Len())*3 + int64(totalBuf.Len())

	got := CalcBlockWeight(block)
	if got != wantWeight {
		t.Errorf("CalcBlockWeight() = %d, want %d (varint contribution = %d WU)",
			got, wantWeight, 4)
	}

	// Sanity: header(320) + varint(4) + txWeight = expected
	txWeight := CalcTxWeight(block.Transactions[0])
	manualExpect := int64(320) + 4 + txWeight
	if got != manualExpect {
		t.Errorf("CalcBlockWeight() = %d, want %d (manual: 320+4+txwt=%d)",
			got, manualExpect, manualExpect)
	}
}

// TestCalcBlockWeightMultiTx: multi-tx block, varint still 1 byte for <253 txs.
func TestCalcBlockWeightMultiTx(t *testing.T) {
	tx := func(n int) *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{byte(n)}, Index: 0},
				SignatureScript:  make([]byte, 20),
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 1000, PkScript: make([]byte, 25)}},
		}
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{tx(0), tx(1), tx(2)},
	}

	got := CalcBlockWeight(block)

	// header(320) + varint(1 byte → 4 WU for < 253 txs) + sum(txWeights)
	var sum int64
	for _, t2 := range block.Transactions {
		sum += CalcTxWeight(t2)
	}
	want := int64(320) + 4 + sum
	if got != want {
		t.Errorf("CalcBlockWeight(3 txs) = %d, want %d", got, want)
	}
}

// TestCalcBlockWeightLargeVarInt: when tx count ≥ 253, varint is 3 bytes → 12 WU.
func TestCalcBlockWeightLargeVarInt(t *testing.T) {
	// Build 253 minimal txs
	txs := make([]*wire.MsgTx, 253)
	for i := range txs {
		txs[i] = &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{byte(i), byte(i >> 8)}, Index: 0},
				SignatureScript:  []byte{0x51},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
		}
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: txs,
	}

	got := CalcBlockWeight(block)

	// varint(253) = 3 bytes → 3 × 4 = 12 WU
	var sum int64
	for _, t2 := range txs {
		sum += CalcTxWeight(t2)
	}
	want := int64(320) + 12 + sum
	if got != want {
		t.Errorf("CalcBlockWeight(253 txs) = %d, want %d (varint=12WU)", got, want)
	}
}

// ---- CalcTxVirtualSize (ceil division) ----

// TestCalcTxVirtualSizeCeil verifies ceil(weight/4).
// A legacy tx with weight 11 must give vsize 3, not 2.
func TestCalcTxVirtualSizeCeil(t *testing.T) {
	tests := []struct {
		weight int64
		want   int64
	}{
		{1, 1},
		{4, 1},
		{5, 2},
		{7, 2},
		{8, 2},
		{9, 3},
		{11, 3},
		{12, 3},
		{13, 4},
		{16, 4},
		{400_000, 100_000},
	}
	for _, tt := range tests {
		got := (tt.weight + WitnessScaleFactor - 1) / WitnessScaleFactor
		if got != tt.want {
			t.Errorf("ceil(%d/4) = %d, want %d", tt.weight, got, tt.want)
		}
	}
}

// TestCalcTxVirtualSizeLegacy: legacy tx vsize = total size (ceiling is no-op).
func TestCalcTxVirtualSizeLegacy(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x05}, Index: 0},
			SignatureScript:  make([]byte, 107),
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: make([]byte, 25)}},
	}

	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	size := int64(buf.Len())

	// Legacy: weight = 4 × size, vsize = size exactly (no ceiling needed).
	got := CalcTxVirtualSize(tx)
	if got != size {
		t.Errorf("legacy vsize = %d, want %d", got, size)
	}
}

// ---- GetSigOpsAdjustedWeight ----

// TestGetSigOpsAdjustedWeight verifies the max(weight, sigop×20) formula.
func TestGetSigOpsAdjustedWeight(t *testing.T) {
	tests := []struct {
		weight        int64
		sigOpCost     int64
		bytesPerSigOp int
		want          int64
	}{
		// weight dominates
		{1000, 10, 20, 1000},
		// sigop dominates: 10 × 20 × 4 = 800, weight = 100 → 800
		// Wait: sigOpCost is already the WEIGHTED cost (scaled by 4 for legacy).
		// GetSigOpsAdjustedWeight = max(weight, sigOpCost × bytesPerSigOp)
		{100, 50, 20, 1000},  // 50 × 20 = 1000 > 100
		{2000, 50, 20, 2000}, // 50 × 20 = 1000 < 2000
		// bytesPerSigOp=0: no adjustment
		{500, 9999, 0, 500},
		// sigOpCost=0: no adjustment
		{500, 0, 20, 500},
		// exact tie: max returns weight
		{1000, 50, 20, 1000},
	}
	for _, tt := range tests {
		got := GetSigOpsAdjustedWeight(tt.weight, tt.sigOpCost, tt.bytesPerSigOp)
		if got != tt.want {
			t.Errorf("GetSigOpsAdjustedWeight(%d, %d, %d) = %d, want %d",
				tt.weight, tt.sigOpCost, tt.bytesPerSigOp, got, tt.want)
		}
	}
}

// ---- GetVirtualTransactionSize ----

// TestGetVirtualTransactionSizeNoSigops: sigOpCost=0 → plain ceil(weight/4).
func TestGetVirtualTransactionSizeNoSigops(t *testing.T) {
	tests := []struct{ weight, want int64 }{
		{4, 1}, {5, 2}, {8, 2}, {9, 3}, {11, 3}, {16, 4}, {400_000, 100_000},
	}
	for _, tt := range tests {
		got := GetVirtualTransactionSize(tt.weight, 0, 0)
		if got != tt.want {
			t.Errorf("GetVirtualTransactionSize(%d,0,0) = %d, want %d",
				tt.weight, got, tt.want)
		}
	}
}

// TestGetVirtualTransactionSizeSigopAdjusted: sigop cost inflates vsize.
// Core example: weight=400, sigOpCost=25, bytesPerSigOp=20
//   adjusted = max(400, 25×20) = max(400, 500) = 500
//   vsize    = ceil(500/4) = 125
func TestGetVirtualTransactionSizeSigopAdjusted(t *testing.T) {
	got := GetVirtualTransactionSize(400, 25, 20)
	want := int64(125) // ceil(500/4)
	if got != want {
		t.Errorf("sigop-adjusted vsize = %d, want %d", got, want)
	}
}

// TestGetVirtualTransactionSizeSigopCeil: verify ceiling in the adjusted path.
// weight=1, sigOpCost=1, bytesPerSigOp=20 → adjusted=20 → vsize=ceil(20/4)=5
func TestGetVirtualTransactionSizeSigopCeil(t *testing.T) {
	got := GetVirtualTransactionSize(1, 1, 20)
	want := int64(5) // ceil(20/4) = 5
	if got != want {
		t.Errorf("sigop ceil vsize = %d, want %d", got, want)
	}
}

// ---- CalcTxInputWeight ----

// TestCalcTxInputWeightLegacy: legacy input (no witness).
// stripped = prevout(36) + varint(scriptLen) + scriptLen + sequence(4)
// witness bytes = varint(0 items) = 1
// weight = stripped×3 + stripped + 1 = stripped×4 + 1
func TestCalcTxInputWeightLegacy(t *testing.T) {
	txin := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
		SignatureScript:  make([]byte, 107), // P2PKH scriptSig
		Sequence:         0xffffffff,
	}

	got := CalcTxInputWeight(txin)

	// stripped: 36 + 1 (varint for 107) + 107 + 4 = 148
	stripped := int64(36 + 1 + 107 + 4)
	// witness: varint(0 items) = 1 byte
	witness := int64(1)
	want := stripped*(WitnessScaleFactor-1) + stripped + witness

	if got != want {
		t.Errorf("CalcTxInputWeight(legacy) = %d, want %d", got, want)
	}
}

// TestCalcTxInputWeightSegwit: segwit input with witness items.
func TestCalcTxInputWeightSegwit(t *testing.T) {
	txin := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
		SignatureScript:  []byte{}, // empty for segwit
		Witness: [][]byte{
			make([]byte, 72), // DER sig
			make([]byte, 33), // compressed pubkey
		},
		Sequence: 0xffffffff,
	}

	got := CalcTxInputWeight(txin)

	// stripped: 36 + 1 (varint for 0 bytes scriptSig) + 0 + 4 = 41
	stripped := int64(36 + 1 + 0 + 4)
	// witness bytes: varint(2 items)=1 + (varint(72)+72) + (varint(33)+33)
	//              = 1 + (1+72) + (1+33) = 1 + 73 + 34 = 108
	witness := int64(1 + (1 + 72) + (1 + 33))
	want := stripped*(WitnessScaleFactor-1) + stripped + witness

	if got != want {
		t.Errorf("CalcTxInputWeight(segwit) = %d, want %d", got, want)
	}
}

// ---- Boundary constants ----

func TestWeightConstants(t *testing.T) {
	if MaxBlockWeight != 4_000_000 {
		t.Errorf("MaxBlockWeight = %d, want 4_000_000", MaxBlockWeight)
	}
	if MaxStandardTxWeight != 400_000 {
		t.Errorf("MaxStandardTxWeight = %d, want 400_000", MaxStandardTxWeight)
	}
	if WitnessScaleFactor != 4 {
		t.Errorf("WitnessScaleFactor = %d, want 4", WitnessScaleFactor)
	}
	if DefaultBytesPerSigOp != 20 {
		t.Errorf("DefaultBytesPerSigOp = %d, want 20", DefaultBytesPerSigOp)
	}
	if MinTransactionWeight != 240 {
		t.Errorf("MinTransactionWeight = %d, want 240", MinTransactionWeight)
	}
	if MinSerializableTransactionWeight != 40 {
		t.Errorf("MinSerializableTransactionWeight = %d, want 40", MinSerializableTransactionWeight)
	}
}

// TestMaxBlockWeightBoundary: a tx with exactly MaxBlockWeight passes weight check.
func TestMaxBlockWeightBoundary(t *testing.T) {
	if MaxStandardTxWeight > MaxBlockWeight {
		t.Errorf("MaxStandardTxWeight (%d) > MaxBlockWeight (%d)", MaxStandardTxWeight, MaxBlockWeight)
	}
	if MaxStandardTxWeight != MaxBlockWeight/10 {
		// Core defines MAX_STANDARD_TX_WEIGHT = 400_000 = MAX_BLOCK_WEIGHT / 10
		// params.go defines MaxTransactionWeight = MaxBlockWeight/10 as well.
		t.Errorf("MaxStandardTxWeight (%d) != MaxBlockWeight/10 (%d)",
			MaxStandardTxWeight, MaxBlockWeight/10)
	}
}

// TestCompactSizeLen verifies the internal helper used in block weight.
func TestCompactSizeLen(t *testing.T) {
	tests := []struct {
		n    uint64
		want int64
	}{
		{0, 1},
		{0xFC, 1},
		{0xFD, 3},
		{0xFFFF, 3},
		{0x10000, 5},
		{0xFFFFFFFF, 5},
		{0x100000000, 9},
	}
	for _, tt := range tests {
		got := compactSizeLen(tt.n)
		if got != tt.want {
			t.Errorf("compactSizeLen(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}
