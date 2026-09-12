package consensus

import (
	"bytes"
	"os"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// C(958794) is the fleet UTXO-set pin: Core's hash_serialized_3 over
// 166,180,925 coins at height 958,794. Two committed captures disagreed
// about whether blockbrew reproduced it:
//
//	2026-08-14  MATCH  29692050…7af0  166,180,925 coins
//	2026-08-15  MISS   24ec9202…7a5a  166,180,926 coins  (+1)
//
// The 08-15 miss measured a chainstate crash recovery had mutated
// (coinbase-only blocks re-applied; TestRecoveryDoesNotResurrectSpentCoinbase
// pins that defect). The matching 08-14 datadir and binary are gone, so
// R4 stayed DISPUTED until a third capture on the current tree.
//
// This file is that third capture. It does not re-run genesis IBD: it
// streams Core's dumptxoutset at the pin through blockbrew's TxOutSer
// hasher. The ladder covers the validator; a hasher miss here is a
// hasher bug, not a crash-recovery ghost.

const (
	c958794DumpPath = "/data/nvme1/hashhog-mainnet/snapshots/utxo-958794.dat"
	// Core uint256.ToString / Hash256.String display order.
	c958794HashDisplay  = "29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0"
	c958794BlockDisplay = "000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e"
	c958794Coins        = uint64(166180925)
	// The 08-15 mutated capture. A third capture that lands here has
	// re-created the crash-recovery +1, not adjudicated it.
	c958794Hash08_15 = "24ec9202799b6eafbee0a931fb6f4ac543c0e520652cbae594cec6c3168e7a5a"
)

func TestHashSnapshotFile_MatchesComputeHashSerialized(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x11, 0x22, 0x33}

	// Several txids, mixed vouts, a coinbase, an empty scriptPubKey (the
	// DIV-blockbrew-001 class), and a P2PKH-shaped script.
	coins := []struct {
		txid0 byte
		vout  uint32
		entry *UTXOEntry
	}{
		{0x01, 0, &UTXOEntry{Amount: 50 * 100000000, PkScript: []byte{0x51}, Height: 1, IsCoinbase: true}},
		{0x01, 1, &UTXOEntry{Amount: 1, PkScript: []byte{}, Height: 1, IsCoinbase: true}},
		{0x02, 0, &UTXOEntry{Amount: 12345, PkScript: []byte{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac}, Height: 100, IsCoinbase: false}},
		{0xaa, 7, &UTXOEntry{Amount: 999999, PkScript: []byte{0x6a, 0x01, 0xff}, Height: 200000, IsCoinbase: false}},
	}
	for _, c := range coins {
		var op wire.OutPoint
		op.Hash[0] = c.txid0
		op.Index = c.vout
		us.AddUTXO(op, c.entry)
	}

	want, wantN, err := ComputeHashSerialized(us)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	got, err := HashSnapshotReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("HashSnapshotReader: %v", err)
	}
	if got.Coins != wantN {
		t.Errorf("coins = %d, want %d", got.Coins, wantN)
	}
	if got.Hash != want {
		t.Errorf("hash = %s, want %s", got.Hash.String(), want.String())
	}
	if got.BlockHash != blockHash {
		t.Errorf("blockhash = %s, want %s", got.BlockHash.String(), blockHash.String())
	}
}

func TestHashSnapshotFile_C958794(t *testing.T) {
	path := os.Getenv("BLOCKBREW_C958794_DUMP")
	if path == "" {
		path = c958794DumpPath
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("C(958794) dump not present at %s: %v", path, err)
	}

	got, err := HashSnapshotFile(path)
	if err != nil {
		t.Fatalf("HashSnapshotFile: %v", err)
	}

	if got.Coins != c958794Coins {
		t.Errorf("coins = %d, want %d (08-15 mutated capture was %d)",
			got.Coins, c958794Coins, c958794Coins+1)
	}
	gotDisp := got.Hash.String()
	if gotDisp == c958794Hash08_15 {
		t.Fatalf("hash = %s — that is the 08-15 +1-coin miss, not C(958794)", gotDisp)
	}
	if gotDisp != c958794HashDisplay {
		t.Errorf("hash_serialized_3 = %s, want C(958794) %s", gotDisp, c958794HashDisplay)
	}
	if got.BlockHash.String() != c958794BlockDisplay {
		t.Errorf("snapshot base = %s, want %s", got.BlockHash.String(), c958794BlockDisplay)
	}
	t.Logf("C(958794) MATCH coins=%d hash=%s base=%s", got.Coins, gotDisp, got.BlockHash.String())
}
