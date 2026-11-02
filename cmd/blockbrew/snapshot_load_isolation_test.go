package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// testdata/utxo-299.dat is tools/boot-smoke-fixtures/utxo-299.dat from the
// meta-repo (sha256 02f40f19…0635c): Core's own regtest chain at height 299,
// the entry RegtestCoreParityAssumeUTXOData pins (hash_serialized d2b051ff…).
// testdata/regtest-299-block1.hex is line 1 of the same fixture's blocks.hex.
const isolationFixtureCoins = 299

// copyFixtureSnapshot writes testdata/utxo-299.dat to dir, with byte 57
// (1-based, inside the first txid) XOR 0xff when corrupt is set — exactly
// the audit's make-bad-299.py. The file still parses; only its hash is wrong.
func copyFixtureSnapshot(t *testing.T, dir string, corrupt bool) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "utxo-299.dat"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	name := "good-299.dat"
	if corrupt {
		b[56] ^= 0xff
		name = "bad-299.dat"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixtureBlock1(t *testing.T) *wire.MsgBlock {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "regtest-299-block1.hex"))
	if err != nil {
		t.Fatalf("read block 1: %v", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode block 1: %v", err)
	}
	var blk wire.MsgBlock
	if err := blk.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("deserialize block 1: %v", err)
	}
	return &blk
}

// isolationBoot is main()'s boot up to -load-snapshot on a Pebble datadir:
// fresh chainstate at genesis on first open, then step 3/4/4b.
type isolationBoot struct {
	pdb   *storage.PebbleDB
	db    *storage.ChainDB
	idx   *consensus.HeaderIndex
	utxos *consensus.UTXOSet
}

func openIsolationBoot(t *testing.T, chaindata string) *isolationBoot {
	t.Helper()
	params := consensus.RegtestParams()
	pdb, err := storage.NewPebbleDB(chaindata)
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	n := &isolationBoot{pdb: pdb, db: storage.NewChainDB(pdb), idx: consensus.NewHeaderIndex(params)}
	if _, err := n.db.GetChainState(); err != nil {
		genesis := params.GenesisBlock.Header.BlockHash()
		if err := n.db.StoreBlock(genesis, params.GenesisBlock); err != nil {
			t.Fatalf("store genesis: %v", err)
		}
		if err := n.db.SetBlockHeight(0, genesis); err != nil {
			t.Fatal(err)
		}
		if err := n.db.SetChainState(&storage.ChainState{BestHash: genesis, BestHeight: 0}); err != nil {
			t.Fatal(err)
		}
	}
	n.utxos = consensus.NewUTXOSet(n.db)
	return n
}

func (n *isolationBoot) close(t *testing.T) {
	t.Helper()
	if err := n.pdb.Close(); err != nil {
		t.Fatalf("close pebble: %v", err)
	}
}

func liveCoinCount(t *testing.T, db *storage.ChainDB) int {
	t.Helper()
	it := db.DB().NewIterator(storage.UTXOPrefix)
	defer it.Release()
	n := 0
	for it.Next() {
		n++
	}
	if err := it.Error(); err != nil {
		t.Fatalf("iterate coins: %v", err)
	}
	return n
}

func liveHashSerialized(t *testing.T, db *storage.ChainDB) string {
	t.Helper()
	h, _, err := consensus.ComputeHashSerialized(consensus.NewUTXOSet(db))
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	return h.String()
}

// connectFixtureBlock1 is plain IBD's first step on the datadir: chain
// manager + crash recovery, then header and body of fixture block 1.
func connectFixtureBlock1(t *testing.T, n *isolationBoot) error {
	t.Helper()
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: consensus.RegtestParams(), HeaderIndex: n.idx, ChainDB: n.db, UTXOSet: n.utxos,
	})
	if _, err := cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	blk := fixtureBlock1(t)
	if _, err := n.idx.AddHeader(blk.Header, true); err != nil {
		t.Fatalf("AddHeader block 1: %v", err)
	}
	if err := n.db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
		t.Fatalf("StoreBlock block 1: %v", err)
	}
	return cm.ConnectBlock(blk)
}

// TestLoadSnapshotRejectedFileLeavesLiveCoinsUntouched is audit H5: a
// -load-snapshot whose coins do not hash to the committed value must not
// leave a single coin in the live UTXO keyspace. On the base commit the
// coins were flushed into UTXOPrefix before the hash gate, so the datadir
// came back with 299 foreign coins: the genuine snapshot was then refused
// forever (the leftovers hash with it) and plain IBD rejected block 1 with
// bad-txns-BIP30. Core loads into a separate chainstate_snapshot DB and
// deletes it on failure (validation.cpp:5548, 5677-5698).
func TestLoadSnapshotRejectedFileLeavesLiveCoinsUntouched(t *testing.T) {
	dir := t.TempDir()
	bad := copyFixtureSnapshot(t, dir, true)
	good := copyFixtureSnapshot(t, dir, false)
	params := consensus.RegtestParams()

	// 1. The corrupt file is refused, and nothing reaches the live set.
	chaindata := filepath.Join(dir, "dd-b", "chaindata")
	n := openIsolationBoot(t, chaindata)
	err := loadSnapshotFromFile(bad, n.db, n.utxos, params, n.idx, 0)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("corrupt snapshot: want a hash-mismatch error, got %v", err)
	}
	if c := liveCoinCount(t, n.db); c != 0 {
		t.Fatalf("rejected snapshot left %d coins in the live UTXO keyspace (want 0): "+
			"the datadir is poisoned (live hash %s)", c, liveHashSerialized(t, n.db))
	}
	n.close(t)

	// 2. Restart with no snapshot: still empty, still at genesis, and plain
	// IBD accepts fixture block 1 (base: bad-txns-BIP30).
	n = openIsolationBoot(t, chaindata)
	if c := liveCoinCount(t, n.db); c != 0 {
		t.Fatalf("after restart: %d coins in the live set, want 0", c)
	}
	if err := connectFixtureBlock1(t, n); err != nil {
		t.Fatalf("plain IBD after a rejected snapshot must accept fixture block 1: %v", err)
	}
	n.close(t)

	// 3. A second rejected-then-genuine datadir: the genuine fixture loads
	// on the very datadir the corrupt one was refused on.
	chaindata = filepath.Join(dir, "dd-b2", "chaindata")
	n = openIsolationBoot(t, chaindata)
	if err := loadSnapshotFromFile(bad, n.db, n.utxos, params, n.idx, 0); err == nil {
		t.Fatal("corrupt snapshot accepted")
	}
	n.close(t)
	n = openIsolationBoot(t, chaindata)
	defer n.close(t)
	if err := loadSnapshotFromFile(good, n.db, n.utxos, params, n.idx, 0); err != nil {
		t.Fatalf("genuine snapshot refused after a rejected load on the same datadir: %v", err)
	}
	assertGenuineSnapshotState(t, n.db)
}

// TestLoadSnapshotGenuineFixtureIsDurableAndActive is the good-path
// regression for the scratch-DB load: every coin reaches the live keyspace,
// the live set hashes to the committed value, and the chain pointer, height
// index and coins marker all name the base — in the state a restart reads.
func TestLoadSnapshotGenuineFixtureIsDurableAndActive(t *testing.T) {
	dir := t.TempDir()
	good := copyFixtureSnapshot(t, dir, false)
	chaindata := filepath.Join(dir, "dd-c", "chaindata")
	n := openIsolationBoot(t, chaindata)
	if err := loadSnapshotFromFile(good, n.db, n.utxos, consensus.RegtestParams(), n.idx, 0); err != nil {
		t.Fatalf("genuine snapshot: %v", err)
	}
	n.close(t)

	n = openIsolationBoot(t, chaindata)
	defer n.close(t)
	assertGenuineSnapshotState(t, n.db)
	if entries, err := os.ReadDir(filepath.Dir(chaindata)); err == nil {
		for _, e := range entries {
			if e.Name() != "chaindata" {
				t.Errorf("snapshot load left %q next to chaindata/", e.Name())
			}
		}
	}
}

func assertGenuineSnapshotState(t *testing.T, db *storage.ChainDB) {
	t.Helper()
	const wantHash = "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"
	const wantBase = "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"
	if c := liveCoinCount(t, db); c != isolationFixtureCoins {
		t.Fatalf("live coins = %d, want %d", c, isolationFixtureCoins)
	}
	if got := liveHashSerialized(t, db); got != wantHash {
		t.Fatalf("live hash_serialized = %s, want %s", got, wantHash)
	}
	cs, err := db.GetChainState()
	if err != nil || cs.BestHeight != 299 || cs.BestHash.String() != wantBase {
		t.Fatalf("chain state = %+v (%v), want %s@299", cs, err, wantBase)
	}
	marker, err := db.GetCoinsTip()
	if err != nil || marker.BestHeight != 299 || marker.BestHash.String() != wantBase {
		t.Fatalf("coins marker = %+v (%v), want %s@299", marker, err, wantBase)
	}
	if h, err := db.GetBlockHashByHeight(299); err != nil || h.String() != wantBase {
		t.Fatalf("height 299 -> %v (%v), want %s", h, err, wantBase)
	}
}

// poisonLikeOldBinary reproduces what a rejected -load-snapshot did before the
// scratch-DB load: the corrupt file's coins parsed straight into the live
// keyspace and flushed, no marker, chain still at genesis.
func poisonLikeOldBinary(t *testing.T, dir string, n *isolationBoot) {
	t.Helper()
	f, err := os.Open(copyFixtureSnapshot(t, dir, true))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sr, err := consensus.NewSnapshotReader(f)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	set, _, err := consensus.LoadSnapshotCoins(sr, n.db, 299)
	if err != nil {
		t.Fatalf("LoadSnapshotCoins: %v", err)
	}
	if err := set.Flush(); err != nil {
		t.Fatal(err)
	}
	if c := liveCoinCount(t, n.db); c != isolationFixtureCoins {
		t.Fatalf("poison setup: %d coins, want %d", c, isolationFixtureCoins)
	}
}

// TestBootDiscardsOrphanCoinsAtGenesis: a datadir already poisoned (by an
// older binary, or by a crash in the middle of the scratch -> live copy) heals
// at boot: the foreign coins go, the genuine snapshot loads, and block 1 is
// accepted.
func TestBootDiscardsOrphanCoinsAtGenesis(t *testing.T) {
	dir := t.TempDir()
	params := consensus.RegtestParams()

	t.Run("then-genuine-snapshot", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "a", "chaindata"))
		defer n.close(t)
		poisonLikeOldBinary(t, dir, n)
		if got, err := discardOrphanCoinsAtGenesis(n.db); err != nil || got != isolationFixtureCoins {
			t.Fatalf("discardOrphanCoinsAtGenesis = %d, %v; want %d, nil", got, err, isolationFixtureCoins)
		}
		if c := liveCoinCount(t, n.db); c != 0 {
			t.Fatalf("%d coins remain", c)
		}
		if err := loadSnapshotFromFile(copyFixtureSnapshot(t, dir, false), n.db, n.utxos, params, n.idx, 0); err != nil {
			t.Fatalf("genuine snapshot after cleanup: %v", err)
		}
		assertGenuineSnapshotState(t, n.db)
	})

	t.Run("then-block-1", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "b", "chaindata"))
		defer n.close(t)
		poisonLikeOldBinary(t, dir, n)
		if _, err := discardOrphanCoinsAtGenesis(n.db); err != nil {
			t.Fatal(err)
		}
		if err := connectFixtureBlock1(t, n); err != nil {
			t.Fatalf("block 1 after cleanup: %v", err)
		}
	})

	// Negative control: without the cleanup the same datadir rejects block 1,
	// so the subtest above is measuring the cleanup and not the fixture.
	t.Run("control-without-cleanup-block-1-rejected", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "c", "chaindata"))
		defer n.close(t)
		poisonLikeOldBinary(t, dir, n)
		err := connectFixtureBlock1(t, n)
		if err == nil || !strings.Contains(err.Error(), "BIP30") {
			t.Fatalf("poisoned datadir without cleanup: want bad-txns-BIP30, got %v", err)
		}
	})

	// Coins a marker accounts for are NOT foreign: an IBD flush that landed
	// before the chain pointer moved is adopted by recovery from the marker.
	// Deleting them would make every later spend of them "missing inputs".
	t.Run("keeps-coins-under-a-marker", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "d", "chaindata"))
		defer n.close(t)
		poisonLikeOldBinary(t, dir, n)
		marker := &storage.ChainState{BestHash: wire.Hash256{1}, BestHeight: 5}
		batch := n.db.NewBatch()
		n.db.SetCoinsTipBatch(batch, marker)
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if got, err := discardOrphanCoinsAtGenesis(n.db); err != nil || got != 0 {
			t.Fatalf("discardOrphanCoinsAtGenesis under a marker = %d, %v; want 0, nil", got, err)
		}
		if c := liveCoinCount(t, n.db); c != isolationFixtureCoins {
			t.Fatalf("coins under a marker: %d left, want %d", c, isolationFixtureCoins)
		}
	})

	t.Run("keeps-coins-under-an-interrupted-flush-record", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "e", "chaindata"))
		defer n.close(t)
		poisonLikeOldBinary(t, dir, n)
		rec := make([]byte, 72)
		if err := n.db.DB().Put(storage.CoinsFlushKey, rec); err != nil {
			t.Fatal(err)
		}
		if got, err := discardOrphanCoinsAtGenesis(n.db); err != nil || got != 0 {
			t.Fatalf("discardOrphanCoinsAtGenesis under a flush record = %d, %v; want 0, nil", got, err)
		}
	})
}

// TestPromoteSnapshotCoinsMultiBatchAndRefusesNonEmptyLiveSet covers the two
// ways the copy itself could publish a set nobody authenticated: losing coins
// across batch boundaries, and adding the snapshot onto coins already there
// (phantom coins: spends of outputs that do not exist would be accepted).
func TestPromoteSnapshotCoinsMultiBatchAndRefusesNonEmptyLiveSet(t *testing.T) {
	dir := t.TempDir()
	params := consensus.RegtestParams()

	t.Run("multi-batch", func(t *testing.T) {
		saved := snapshotPromoteBatchBytes
		snapshotPromoteBatchBytes = 1 // one coin per batch
		defer func() { snapshotPromoteBatchBytes = saved }()
		n := openIsolationBoot(t, filepath.Join(dir, "m", "chaindata"))
		defer n.close(t)
		if err := loadSnapshotFromFile(copyFixtureSnapshot(t, dir, false), n.db, n.utxos, params, n.idx, 0); err != nil {
			t.Fatalf("genuine snapshot, one coin per batch: %v", err)
		}
		assertGenuineSnapshotState(t, n.db)
	})

	t.Run("refuses-non-empty-live-set", func(t *testing.T) {
		n := openIsolationBoot(t, filepath.Join(dir, "r", "chaindata"))
		defer n.close(t)
		extra := consensus.NewUTXOSet(n.db)
		extra.AddUTXO(wire.OutPoint{Hash: wire.Hash256{0xaa}, Index: 0},
			&consensus.UTXOEntry{Amount: 1, PkScript: opTrue, Height: 1})
		if err := extra.Flush(); err != nil {
			t.Fatal(err)
		}
		err := loadSnapshotFromFile(copyFixtureSnapshot(t, dir, false), n.db, n.utxos, params, n.idx, 0)
		if err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("snapshot onto a non-empty live set: want refusal, got %v", err)
		}
		if c := liveCoinCount(t, n.db); c != 1 {
			t.Fatalf("refused promote changed the live set: %d coins, want 1", c)
		}
		if cs, _ := n.db.GetChainState(); cs == nil || cs.BestHeight != 0 {
			t.Fatalf("refused promote moved the chain pointer: %+v", cs)
		}
	})
}
