package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// nullOutPoint is the coinbase input's prevout (all-zero hash, index 0xffffffff).
func nullOutPoint() wire.OutPoint {
	return wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff}
}

// p2pkhScript returns a 25-byte standard P2PKH scriptPubKey (spendable).
func p2pkhScript() []byte {
	s := make([]byte, 25)
	s[0] = 0x76 // OP_DUP
	s[1] = 0xa9 // OP_HASH160
	s[2] = 0x14 // push 20
	// 20 bytes hash (3..23) left zero
	s[23] = 0x88 // OP_EQUALVERIFY
	s[24] = 0xac // OP_CHECKSIG
	return s
}

// opReturnScript returns an unspendable OP_RETURN script of the given payload len.
func opReturnScript(payloadLen int) []byte {
	s := make([]byte, 0, payloadLen+1)
	s = append(s, 0x6a) // OP_RETURN
	s = append(s, make([]byte, payloadLen)...)
	return s
}

// TestComputeBlockStats_FeeMath builds a block with a coinbase plus two
// non-coinbase transactions whose input prevout values come from undo data, and
// asserts the fee/feerate/median/percentile statistics against hand-computed,
// Core-equivalent values. This is the load-bearing path: wrong fee stats are
// worse than a missing method.
//
//	coinbase: 1 null input, 2 outputs (P2PKH spendable + OP_RETURN unspendable)
//	tx1: 1 input  spending 10_000 sat, 1 output 9_000 sat  -> fee 1_000
//	tx2: 2 inputs spending 5_000+5_000, 1 output 8_000 sat -> fee 2_000
func TestComputeBlockStats_FeeMath(t *testing.T) {
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: nullOutPoint(), SignatureScript: []byte{0x51}, Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{
			{Value: 5_000_003_000, PkScript: p2pkhScript()}, // subsidy(50 BTC) + fees(3000)
			{Value: 0, PkScript: opReturnScript(36)},        // witness-commitment-like, unspendable
		},
		LockTime: 0,
	}

	tx1 := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0}, SignatureScript: []byte{0x01, 0x02}, Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{
			{Value: 9_000, PkScript: p2pkhScript()},
		},
		LockTime: 0,
	}

	tx2 := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0}, SignatureScript: []byte{0x03}, Sequence: 0xffffffff},
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 1}, SignatureScript: []byte{0x04}, Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{
			{Value: 8_000, PkScript: p2pkhScript()},
		},
		LockTime: 0,
	}

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1_700_000_000, Bits: 0x207fffff},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	// Undo data: one TxUndo per non-coinbase tx, prevout values supply inputs.
	undo := &storage.BlockUndo{
		TxUndos: []storage.TxUndo{
			{SpentCoins: []storage.SpentCoin{
				{TxOut: wire.TxOut{Value: 10_000, PkScript: p2pkhScript()}, Height: 100, Coinbase: false},
			}},
			{SpentCoins: []storage.SpentCoin{
				{TxOut: wire.TxOut{Value: 5_000, PkScript: p2pkhScript()}, Height: 100, Coinbase: false},
				{TxOut: wire.TxOut{Value: 5_000, PkScript: p2pkhScript()}, Height: 100, Coinbase: false},
			}},
		},
	}

	node := &consensus.BlockNode{
		Hash:   wire.Hash256{0xaa, 0xbb, 0xcc},
		Header: block.Header,
		Height: 200,
	}

	stats, rpcErr := computeBlockStats(block, undo, node, consensus.SubsidyHalvingInterval)
	if rpcErr != nil {
		t.Fatalf("computeBlockStats: %v", rpcErr)
	}

	// --- Fee statistics (the teeth). ---
	if *stats.TotalFee != 3_000 {
		t.Errorf("totalfee = %d, want 3000", *stats.TotalFee)
	}
	if *stats.MinFee != 1_000 {
		t.Errorf("minfee = %d, want 1000", *stats.MinFee)
	}
	if *stats.MaxFee != 2_000 {
		t.Errorf("maxfee = %d, want 2000", *stats.MaxFee)
	}
	// avgfee = totalfee / (txs-1) = 3000 / 2 = 1500
	if *stats.AvgFee != 1_500 {
		t.Errorf("avgfee = %d, want 1500", *stats.AvgFee)
	}
	// medianfee over [1000, 2000] (even count) = (1000+2000)/2 = 1500
	if *stats.MedianFee != 1_500 {
		t.Errorf("medianfee = %d, want 1500", *stats.MedianFee)
	}

	// --- Counts. ---
	if *stats.Txs != 3 {
		t.Errorf("txs = %d, want 3 (incl coinbase)", *stats.Txs)
	}
	if *stats.Ins != 3 { // tx1(1) + tx2(2); coinbase excluded
		t.Errorf("ins = %d, want 3", *stats.Ins)
	}
	if *stats.Outs != 4 { // coinbase(2) + tx1(1) + tx2(1)
		t.Errorf("outs = %d, want 4", *stats.Outs)
	}
	// utxo_increase = outs - ins = 4 - 3 = 1
	if *stats.UTXOIncrease != 1 {
		t.Errorf("utxo_increase = %d, want 1", *stats.UTXOIncrease)
	}
	// utxo_increase_actual = spendable outputs - ins.
	// Spendable outputs: coinbase P2PKH(1) + tx1(1) + tx2(1) = 3; OP_RETURN excluded.
	// 3 - 3 = 0.
	if *stats.UTXOIncreaseActual != 0 {
		t.Errorf("utxo_increase_actual = %d, want 0", *stats.UTXOIncreaseActual)
	}

	// --- Total out (non-coinbase outputs only). ---
	if *stats.TotalOut != 17_000 { // 9000 + 8000
		t.Errorf("total_out = %d, want 17000", *stats.TotalOut)
	}

	// --- Subsidy at height 200 (no halving). ---
	if *stats.Subsidy != consensus.InitialSubsidy {
		t.Errorf("subsidy = %d, want %d", *stats.Subsidy, consensus.InitialSubsidy)
	}

	// --- blockhash / height / time / mediantime. ---
	if *stats.BlockHash != node.Hash.String() {
		t.Errorf("blockhash = %s, want %s", *stats.BlockHash, node.Hash.String())
	}
	if *stats.Height != 200 {
		t.Errorf("height = %d, want 200", *stats.Height)
	}
	if *stats.Time != int64(block.Header.Timestamp) {
		t.Errorf("time = %d, want %d", *stats.Time, block.Header.Timestamp)
	}

	// --- feerate_percentiles: 5 values, weakly increasing, in [minfeerate, maxfeerate]. ---
	if len(*stats.FeeRatePercentiles) != numGetBlockStatsPercentiles {
		t.Fatalf("feerate_percentiles len = %d, want %d", len(*stats.FeeRatePercentiles), numGetBlockStatsPercentiles)
	}
	fp := *stats.FeeRatePercentiles
	for i := 1; i < len(fp); i++ {
		if fp[i] < fp[i-1] {
			t.Errorf("feerate_percentiles not non-decreasing: %v", fp)
		}
	}
	if fp[0] < *stats.MinFeeRate || fp[len(fp)-1] > *stats.MaxFeeRate {
		t.Errorf("feerate_percentiles %v outside [min %d, max %d]", fp, *stats.MinFeeRate, *stats.MaxFeeRate)
	}

	// --- Segwit stats: this block has no witnesses. ---
	if *stats.SwTxs != 0 || *stats.SwTotalSize != 0 || *stats.SwTotalWeight != 0 {
		t.Errorf("segwit stats nonzero for witness-free block: swtxs=%d swsize=%d swweight=%d",
			*stats.SwTxs, *stats.SwTotalSize, *stats.SwTotalWeight)
	}

	// --- Sizes/weight sanity: total_weight = 3*stripped + total >= 4*total_size
	// would only hold for witness txs; here total_weight == 4*total_size since
	// no witnesses. Just assert positivity + the no-witness identity. ---
	if *stats.TotalSize <= 0 || *stats.TotalWeight <= 0 {
		t.Errorf("non-positive size/weight: size=%d weight=%d", *stats.TotalSize, *stats.TotalWeight)
	}
	if *stats.TotalWeight != 4*(*stats.TotalSize) {
		t.Errorf("no-witness total_weight = %d, want 4*total_size = %d", *stats.TotalWeight, 4*(*stats.TotalSize))
	}
}

// TestComputeBlockStats_UndoMissingFailsLoud verifies that a block with a
// non-coinbase tx but no undo data refuses rather than reporting a wrong fee.
func TestComputeBlockStats_UndoMissingFailsLoud(t *testing.T) {
	tx1 := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 9_000, PkScript: p2pkhScript()}},
	}
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: nullOutPoint(), SignatureScript: []byte{0x51}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5_000_000_000, PkScript: p2pkhScript()}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1_700_000_000},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	node := &consensus.BlockNode{Hash: wire.Hash256{0x11}, Header: block.Header, Height: 5}

	if _, err := computeBlockStats(block, nil, node, consensus.SubsidyHalvingInterval); err == nil {
		t.Fatal("expected error when undo data is missing for a non-coinbase tx, got nil")
	}
}

// TestComputeBlockStats_CoinbaseOnly verifies a coinbase-only block: no fees,
// zero feerate percentiles, mintxsize/minfee fall back to 0 (no non-coinbase tx).
func TestComputeBlockStats_CoinbaseOnly(t *testing.T) {
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: nullOutPoint(), SignatureScript: []byte{0x51}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{
			{Value: 5_000_000_000, PkScript: p2pkhScript()},
			{Value: 0, PkScript: opReturnScript(36)},
		},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1_700_000_500},
		Transactions: []*wire.MsgTx{coinbase},
	}
	node := &consensus.BlockNode{Hash: wire.Hash256{0x22}, Header: block.Header, Height: 101}

	stats, rpcErr := computeBlockStats(block, &storage.BlockUndo{}, node, consensus.SubsidyHalvingInterval)
	if rpcErr != nil {
		t.Fatalf("computeBlockStats: %v", rpcErr)
	}
	if *stats.Txs != 1 || *stats.Ins != 0 {
		t.Errorf("txs=%d ins=%d, want 1 and 0", *stats.Txs, *stats.Ins)
	}
	if *stats.TotalFee != 0 || *stats.AvgFee != 0 || *stats.MinFee != 0 || *stats.MaxFee != 0 {
		t.Errorf("fees nonzero for coinbase-only block")
	}
	if *stats.MinTxSize != 0 || *stats.MaxTxSize != 0 || *stats.TotalSize != 0 {
		t.Errorf("non-coinbase tx sizes nonzero: min=%d max=%d total=%d",
			*stats.MinTxSize, *stats.MaxTxSize, *stats.TotalSize)
	}
	for _, p := range *stats.FeeRatePercentiles {
		if p != 0 {
			t.Errorf("feerate percentile nonzero for coinbase-only block: %v", *stats.FeeRatePercentiles)
			break
		}
	}
	// outs = 2 (both coinbase outputs); utxo_increase = 2 - 0 = 2.
	if *stats.Outs != 2 || *stats.UTXOIncrease != 2 {
		t.Errorf("outs=%d utxo_increase=%d, want 2 and 2", *stats.Outs, *stats.UTXOIncrease)
	}
	// utxo_increase_actual: only the P2PKH output is spendable -> 1 - 0 = 1.
	if *stats.UTXOIncreaseActual != 1 {
		t.Errorf("utxo_increase_actual = %d, want 1", *stats.UTXOIncreaseActual)
	}
}

// TestCalculateTruncatedMedian covers the empty/odd/even branches against
// Core's CalculateTruncatedMedian.
func TestCalculateTruncatedMedian(t *testing.T) {
	if got := calculateTruncatedMedian(nil); got != 0 {
		t.Errorf("median(empty) = %d, want 0", got)
	}
	if got := calculateTruncatedMedian([]int64{5}); got != 5 {
		t.Errorf("median([5]) = %d, want 5", got)
	}
	if got := calculateTruncatedMedian([]int64{3, 1, 2}); got != 2 {
		t.Errorf("median([3,1,2]) = %d, want 2", got)
	}
	// Even: (10+20)/2 = 15, truncated.
	if got := calculateTruncatedMedian([]int64{20, 10, 30, 0}); got != 15 {
		t.Errorf("median([20,10,30,0]) = %d, want 15", got)
	}
	// Even with truncation: (3+4)/2 = 3 (integer division).
	if got := calculateTruncatedMedian([]int64{4, 3}); got != 3 {
		t.Errorf("median([4,3]) = %d, want 3 (truncated)", got)
	}
}

// TestCalculatePercentilesByWeight verifies weight-ranked percentile selection
// against Core's CalculatePercentilesByWeight semantics, including the empty
// case and the fill-remaining-with-largest rule.
func TestCalculatePercentilesByWeight(t *testing.T) {
	// Empty -> all zeros.
	got := calculatePercentilesByWeight(nil, 0)
	for _, v := range got {
		if v != 0 {
			t.Fatalf("empty percentiles not all zero: %v", got)
		}
	}

	// Single element carries every percentile.
	got = calculatePercentilesByWeight([]feerateScore{{rate: 42, weight: 100}}, 100)
	for i, v := range got {
		if v != 42 {
			t.Errorf("percentile[%d] = %d, want 42", i, v)
		}
	}

	// Two equal-weight elements: feerate 1 (weight 50) then 9 (weight 50),
	// total_weight 100. Boundaries: 10,25,50 -> after first element
	// (cumulative 50 >= 10,25,50) so 10th/25th/50th = 1; 75th(75) & 90th(90)
	// crossed by the second element -> 9.
	got = calculatePercentilesByWeight([]feerateScore{
		{rate: 9, weight: 50},
		{rate: 1, weight: 50},
	}, 100)
	want := []int64{1, 1, 1, 9, 9}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("percentile[%d] = %d, want %d (full %v)", i, got[i], want[i], got)
		}
	}
}

// TestFilterBlockStats verifies the stats-subset path: only requested keys are
// returned, and an unknown stat name is an error (Core parity).
func TestFilterBlockStats(t *testing.T) {
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: nullOutPoint(), SignatureScript: []byte{0x51}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5_000_000_000, PkScript: p2pkhScript()}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1_700_000_000},
		Transactions: []*wire.MsgTx{coinbase},
	}
	node := &consensus.BlockNode{Hash: wire.Hash256{0x33}, Header: block.Header, Height: 10}
	stats, rpcErr := computeBlockStats(block, &storage.BlockUndo{}, node, consensus.SubsidyHalvingInterval)
	if rpcErr != nil {
		t.Fatalf("computeBlockStats: %v", rpcErr)
	}

	out, rpcErr := filterBlockStats(stats, map[string]bool{"height": true, "subsidy": true})
	if rpcErr != nil {
		t.Fatalf("filterBlockStats: %v", rpcErr)
	}
	m, ok := out.(map[string]interface{})
	if !ok {
		t.Fatalf("filtered result type = %T, want map", out)
	}
	if len(m) != 2 {
		t.Errorf("filtered result has %d keys, want 2: %v", len(m), m)
	}
	if _, ok := m["height"]; !ok {
		t.Error("missing 'height' in filtered result")
	}
	if _, ok := m["subsidy"]; !ok {
		t.Error("missing 'subsidy' in filtered result")
	}

	// Unknown stat -> error.
	if _, err := filterBlockStats(stats, map[string]bool{"notastat": true}); err == nil {
		t.Error("expected error for unknown stat name, got nil")
	} else if err.Code != RPCErrInvalidParameter {
		t.Errorf("unknown-stat error code = %d, want %d", err.Code, RPCErrInvalidParameter)
	}
}
