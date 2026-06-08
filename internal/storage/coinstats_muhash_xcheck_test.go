package storage

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// expectedTxOutSer builds the Core kernel/coinstats.cpp::TxOutSer record
// independently of coinRecord, to cross-check the index produces the exact
// byte layout Core's MuHash3072 consumes.
func expectedTxOutSer(op wire.OutPoint, height int32, coinbase bool, value int64, pk []byte) []byte {
	var b bytes.Buffer
	b.Write(op.Hash[:])
	var v4 [4]byte
	binary.LittleEndian.PutUint32(v4[:], op.Index)
	b.Write(v4[:])
	code := uint32(height) << 1
	if coinbase {
		code |= 1
	}
	binary.LittleEndian.PutUint32(v4[:], code)
	b.Write(v4[:])
	var v8 [8]byte
	binary.LittleEndian.PutUint64(v8[:], uint64(value))
	b.Write(v8[:])
	// CompactSize len
	wire.WriteCompactSize(&b, uint64(len(pk)))
	b.Write(pk)
	return b.Bytes()
}

// TestCoinRecordMatchesCoreTxOutSer asserts coinRecord == TxOutSer byte layout.
func TestCoinRecordMatchesCoreTxOutSer(t *testing.T) {
	op := wire.OutPoint{Hash: wire.Hash256{1, 2, 3, 0xab, 0xcd}, Index: 7}
	pk := []byte{0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33}
	got := coinRecord(op, 100, false, 4999990000, pk)
	want := expectedTxOutSer(op, 100, false, 4999990000, pk)
	if !bytes.Equal(got, want) {
		t.Fatalf("coinRecord mismatch:\n got=%x\nwant=%x", got, want)
	}
}

// TestCoinStatsMuHashEqualsDirectInsert verifies that after WriteBlock the
// per-height stored muhash digest equals a MuHash3072 built directly from the
// same coin records (order-independent), confirming the index's running
// accumulator is a faithful MuHash, not the old XOR.
func TestCoinStatsMuHashEqualsDirectInsert(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	block := createTestBlockForStats(1)
	hash := block.Header.BlockHash()
	if err := idx.WriteBlock(block, 1, hash, nil); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	// Build the expected MuHash directly from the same spendable outputs.
	mh := crypto.NewMuHash3072()
	for _, tx := range block.Transactions {
		txid := tx.TxHash()
		isCb := tx == block.Transactions[0]
		for j, out := range tx.TxOut {
			if isUnspendable(out.PkScript) {
				continue
			}
			op := wire.OutPoint{Hash: txid, Index: uint32(j)}
			mh.Insert(expectedTxOutSer(op, 1, isCb, out.Value, out.PkScript))
		}
	}
	want := mh.Finalize()

	stats, err := idx.GetStats(1)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	var got [32]byte
	copy(got[:], stats.HashSerialized[:])
	if got != want {
		t.Fatalf("stored muhash digest mismatch:\n got=%x\nwant=%x", got, want)
	}
}

// TestCoinStatsMuHashSpendCancels verifies insert(coin) then remove(same coin)
// returns the accumulator to the empty-set value — the core property the old
// asymmetric XOR remove failed (BUG-21). Done via WriteBlock+spend.
func TestCoinStatsMuHashSpendCancels(t *testing.T) {
	emptyDigest := crypto.NewMuHash3072().Finalize()

	db := NewMemDB()
	defer db.Close()
	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Block with a single spendable coinbase output (no OP_RETURN noise) at h1.
	cbPk := []byte{0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}
	cb := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5_000_000_000, PkScript: cbPk}},
	}
	blk1 := &wire.MsgBlock{Header: wire.BlockHeader{Version: 1}, Transactions: []*wire.MsgTx{cb}}
	h1 := blk1.Header.BlockHash()
	if err := idx.WriteBlock(blk1, 1, h1, nil); err != nil {
		t.Fatalf("WriteBlock h1: %v", err)
	}
	cbTxid := cb.TxHash()

	// Block 2 spends that coinbase output via a regular tx (matured assumed).
	spend := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: cbTxid, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{}, // all spent to fees / OP_RETURN-free: net empties the set
	}
	cb2 := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 0, PkScript: []byte{0x6a}}}, // OP_RETURN, unspendable
	}
	blk2 := &wire.MsgBlock{Header: wire.BlockHeader{Version: 1, PrevBlock: h1}, Transactions: []*wire.MsgTx{cb2, spend}}
	h2 := blk2.Header.BlockHash()
	undo := &BlockUndo{TxUndos: []TxUndo{{SpentCoins: []SpentCoin{{
		TxOut:    wire.TxOut{Value: 5_000_000_000, PkScript: cbPk},
		Height:   1,
		Coinbase: true,
	}}}}}
	if err := idx.WriteBlock(blk2, 2, h2, undo); err != nil {
		t.Fatalf("WriteBlock h2: %v", err)
	}

	stats, err := idx.GetStats(2)
	if err != nil {
		t.Fatalf("GetStats h2: %v", err)
	}
	if stats.UTXOCount != 0 {
		t.Fatalf("expected 0 utxos after full spend, got %d", stats.UTXOCount)
	}
	var got [32]byte
	copy(got[:], stats.HashSerialized[:])
	if got != emptyDigest {
		t.Fatalf("muhash did not return to empty-set after insert+remove:\n got=%x\nwant=%x", got, emptyDigest)
	}
}
