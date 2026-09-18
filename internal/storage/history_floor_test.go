package storage

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// HistoryFloor is the honest-limitation detector for snapshot-boot /
// assume-valid datadirs that do not retain bodies from height 1.
// CONTROL companion to internal/rpc/pruned_history_test.go.

func historyFloorHash(n int32) wire.Hash256 {
	var h wire.Hash256
	h[0] = byte(n >> 24)
	h[1] = byte(n >> 16)
	h[2] = byte(n >> 8)
	h[3] = byte(n)
	return h
}

func historyFloorBlock(n int32) *wire.MsgBlock {
	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  historyFloorHash(n - 1),
			MerkleRoot: historyFloorHash(n),
			Timestamp:  1231006505 + uint32(n),
			Bits:       0x207fffff,
			Nonce:      uint32(n),
		},
		Transactions: []*wire.MsgTx{{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
				SignatureScript:  []byte{byte(n)},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{
				Value:    50 * 100000000,
				PkScript: []byte{0x51},
			}},
		}},
	}
}

func seedHeight(t *testing.T, c *ChainDB, n int32, withBody bool) {
	t.Helper()
	h := historyFloorHash(n)
	if err := c.SetBlockHeight(n, h); err != nil {
		t.Fatalf("SetBlockHeight(%d): %v", n, err)
	}
	if withBody {
		if err := c.StoreBlock(h, historyFloorBlock(n)); err != nil {
			t.Fatalf("StoreBlock(%d): %v", n, err)
		}
	}
}

func TestHistoryFloor_NoneWhenTipIsGenesis(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	if floor, ok := c.HistoryFloor(0, nil); ok {
		t.Fatalf("tip=0 must report no hole, got floor=%d ok=%v", floor, ok)
	}
}

func TestHistoryFloor_NoneWhenHeightOneHasBody(t *testing.T) {
	c := NewChainDB(NewMemDB())
	for n := int32(0); n <= 10; n++ {
		seedHeight(t, c, n, true)
	}
	if floor, ok := c.HistoryFloor(10, nil); ok {
		t.Fatalf("dense bodies must report no hole, got floor=%d ok=%v", floor, ok)
	}
}

func TestHistoryFloor_FindsAssumeutxoTailStart(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	for n := int32(10); n <= 20; n++ {
		seedHeight(t, c, n, true)
	}
	floor, ok := c.HistoryFloor(20, nil)
	if !ok || floor != 10 {
		t.Fatalf("HistoryFloor = %d, %v; want 10, true", floor, ok)
	}
	if _, err := c.GetBlockHashByHeight(9); err != ErrNotFound {
		t.Fatalf("height 9 should be absent from the index, err=%v", err)
	}
	if h, err := c.GetBlockHashByHeight(10); err != nil || h != historyFloorHash(10) {
		t.Fatalf("height 10 hash = %v, %v", h, err)
	}
}

func TestHistoryFloor_FindsBodyHoleBehindDenseIndex(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	for n := int32(1); n <= 20; n++ {
		seedHeight(t, c, n, n >= 10)
	}
	floor, ok := c.HistoryFloor(20, nil)
	if !ok || floor != 10 {
		t.Fatalf("body hole behind dense index: HistoryFloor = %d, %v; want 10, true", floor, ok)
	}
}

func TestHistoryFloor_TipMissingReportsTip(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	floor, ok := c.HistoryFloor(50, nil)
	if !ok || floor != 50 {
		t.Fatalf("no bodies at all: HistoryFloor = %d, %v; want 50, true", floor, ok)
	}
}

func TestHistoryFloor_HashAtCallbackBeatsMissingIndex(t *testing.T) {
	c := NewChainDB(NewMemDB())
	// Bodies stored under hashes 10..20, but the height index is empty
	// except genesis. The callback supplies height→hash the way RPC's
	// in-memory ancestor walk does on live mainnet.
	seedHeight(t, c, 0, true)
	for n := int32(10); n <= 20; n++ {
		if err := c.StoreBlock(historyFloorHash(n), historyFloorBlock(n)); err != nil {
			t.Fatalf("StoreBlock(%d): %v", n, err)
		}
	}
	hashAt := func(h int32) (wire.Hash256, bool) {
		if h < 0 || h > 20 {
			return wire.Hash256{}, false
		}
		return historyFloorHash(h), true
	}
	floor, ok := c.HistoryFloor(20, hashAt)
	if !ok || floor != 10 {
		t.Fatalf("callback-driven floor = %d, %v; want 10, true", floor, ok)
	}
}

func TestHistoryFloor_InteriorHoleStillReportsFirstBody(t *testing.T) {
	// HistoryFloor is first-body (audit floor). pruneheight is BodyFloor
	// (contiguous suffix). This fixture is the live 87ac1d8 shape:
	// prefix miss 1..5, island 6..10, hole 11..13, suffix 14..20.
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	for n := int32(1); n <= 20; n++ {
		withBody := (n >= 6 && n <= 10) || n >= 14
		seedHeight(t, c, n, withBody)
	}
	floor, ok := c.HistoryFloor(20, nil)
	if !ok || floor != 6 {
		t.Fatalf("HistoryFloor (first body) = %d, %v; want 6, true", floor, ok)
	}
}

func TestBodyFloor_CompleteChainIsZero(t *testing.T) {
	c := NewChainDB(NewMemDB())
	for n := int32(0); n <= 8; n++ {
		seedHeight(t, c, n, true)
	}
	if floor, ok := c.BodyFloor(8, nil); ok {
		t.Fatalf("complete chain BodyFloor = %d, %v; want 0, false", floor, ok)
	}
}

func TestBodyFloor_PrefixGapMatchesFirstBody(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	for n := int32(1); n <= 20; n++ {
		seedHeight(t, c, n, n >= 10)
	}
	floor, ok := c.BodyFloor(20, nil)
	if !ok || floor != 10 {
		t.Fatalf("prefix-only BodyFloor = %d, %v; want 10, true", floor, ok)
	}
	first, fok := c.FirstBody(20, nil)
	if !fok || first != 10 {
		t.Fatalf("FirstBody = %d, %v; want 10, true", first, fok)
	}
}

func TestBodyFloor_InteriorHoleRaisesToContiguousSuffix(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	for n := int32(1); n <= 20; n++ {
		withBody := (n >= 6 && n <= 10) || n >= 14
		seedHeight(t, c, n, withBody)
	}
	first, ok := c.FirstBody(20, nil)
	if !ok || first != 6 {
		t.Fatalf("FirstBody = %d, %v; want 6, true", first, ok)
	}
	floor, ok := c.BodyFloor(20, nil)
	if !ok || floor != 14 {
		t.Fatalf("BodyFloor = %d, %v; want 14, true (contiguous suffix)", floor, ok)
	}
}

func TestBodyFloor_TipMissingReportsTip(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedHeight(t, c, 0, true)
	floor, ok := c.BodyFloor(50, nil)
	if !ok || floor != 50 {
		t.Fatalf("no bodies at all: BodyFloor = %d, %v; want 50, true", floor, ok)
	}
}

func TestFirstBody_NoneWhenHeightOneHasBody(t *testing.T) {
	c := NewChainDB(NewMemDB())
	for n := int32(0); n <= 10; n++ {
		seedHeight(t, c, n, true)
	}
	if floor, ok := c.FirstBody(10, nil); ok {
		t.Fatalf("dense bodies FirstBody = %d, %v; want 0, false", floor, ok)
	}
}
