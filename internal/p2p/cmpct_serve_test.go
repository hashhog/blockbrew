package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func serveTestBlock(n int) *wire.MsgBlock {
	b := &wire.MsgBlock{Header: wire.BlockHeader{Version: 4, Bits: 0x207fffff, Timestamp: 1700000000}}
	for i := 0; i < n; i++ {
		b.Transactions = append(b.Transactions, simpleTestTx(uint32(i+1)))
	}
	return b
}

// A tip-adjacent getdata(MSG_CMPCT_BLOCK) gets a cmpctblock (coinbase prefilled,
// one wtxid short id per other tx); beyond MaxCmpctBlockDepth there is none.
func TestBuildCmpctBlockReplyDepth(t *testing.T) {
	blk := serveTestBlock(4)
	for _, d := range []int32{0, 1, MaxCmpctBlockDepth} {
		cb := buildCmpctBlockReply(blk, d)
		if cb == nil {
			t.Fatalf("depth %d: want cmpctblock, got nil", d)
		}
		if len(cb.PrefilledTxs) != 1 || cb.PrefilledTxs[0].Index != 0 || len(cb.ShortIDs) != 3 {
			t.Fatalf("depth %d: prefilled=%d shortids=%d", d, len(cb.PrefilledTxs), len(cb.ShortIDs))
		}
	}
	if cb := buildCmpctBlockReply(blk, MaxCmpctBlockDepth+1); cb != nil {
		t.Fatalf("depth %d must fall back to the full block", MaxCmpctBlockDepth+1)
	}
}

// Short ids are SipHash(key from header+nonce) of the wtxid, so a receiver with
// none of the txs can rebuild the block from cmpctblock + the blocktxn we serve.
func TestCmpctBlockRoundTripViaBlocktxn(t *testing.T) {
	blk := serveTestBlock(5)
	cb := buildCmpctBlockReply(blk, 0)
	key := ComputeSipHashKey(&blk.Header, cb.Nonce)
	for i, sid := range cb.ShortIDs {
		if want := ComputeShortID(key, blk.Transactions[i+1].WTxHash()); sid != want {
			t.Fatalf("short id %d mismatch", i)
		}
	}
	pdb := NewPartiallyDownloadedBlock()
	if _, err := pdb.InitData(cb, nil, nil); err != nil {
		t.Fatalf("InitData: %v", err)
	}
	missing := pdb.GetMissingIndexes()
	if len(missing) != 4 {
		t.Fatalf("missing=%v", missing)
	}
	reply, err := buildBlockTxnReply(blk, CreateGetBlockTxn(blk.Header.BlockHash(), missing))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Txs) != 4 || reply.BlockHash != blk.Header.BlockHash() {
		t.Fatalf("bad blocktxn: %d txs", len(reply.Txs))
	}
	for i, idx := range missing {
		if reply.Txs[i].TxHash() != blk.Transactions[idx].TxHash() {
			t.Fatalf("tx %d differs", i)
		}
	}
}

// Out-of-range index (incl. via differential overflow) is an error -> misbehaving.
func TestBuildBlockTxnReplyOutOfRange(t *testing.T) {
	blk := serveTestBlock(3)
	if _, err := buildBlockTxnReply(blk, &MsgGetBlockTxn{Indexes: []uint32{3}}); err == nil {
		t.Fatal("index 3 of 3 txs must be rejected")
	}
	// diffs 1,1 decode to absolute indexes 1,3 -> 3 is out of range.
	if _, err := buildBlockTxnReply(blk, &MsgGetBlockTxn{Indexes: []uint32{1, 1}}); err == nil {
		t.Fatal("decoded index 3 of 3 txs must be rejected")
	}
	if _, err := buildBlockTxnReply(blk, &MsgGetBlockTxn{Indexes: []uint32{1, 0}}); err != nil {
		t.Fatalf("indexes 1,2 are valid: %v", err)
	}
}
