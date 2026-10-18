package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// opTrue is an anyone-can-spend scriptPubKey, so the test chain can carry
// real spends (the probe only reads undo data for blocks with non-coinbase
// inputs) without a wallet.
var opTrue = []byte{0x51}

const (
	probeTestBase = 105 // snapshot base; coinbases 1..5 are mature above it
	probeTestTip  = 110 // blocks connected above the base after the load
)

// mineProbeTestBlock builds and connects one regtest block on tc's tip whose
// coinbase pays OP_TRUE and which spends `spend` (if non-nil) to OP_TRUE.
func mineProbeTestBlock(t *testing.T, params *consensus.ChainParams, idx *consensus.HeaderIndex,
	db *storage.ChainDB, cm *consensus.ChainManager, spend *wire.OutPoint) *wire.MsgBlock {
	t.Helper()
	tipHash, tipHeight := cm.BestBlock()
	tipNode := idx.GetNode(tipHash)
	if tipNode == nil {
		t.Fatalf("tip %s not in header index", tipHash.String())
	}
	height := tipHeight + 1
	const fee = 1000
	fees := int64(0)
	if spend != nil {
		fees = fee
	}
	txs := []*wire.MsgTx{mining.CreateCoinbaseTx(height, opTrue, nil, consensus.CalcBlockSubsidy(height), fees, nil)}
	if spend != nil {
		txs = append(txs, &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: *spend, Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{Value: consensus.CalcBlockSubsidy(1) - fee, PkScript: opTrue}},
		})
	}
	hashes := make([]wire.Hash256, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxHash()
	}
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x20000000,
			PrevBlock:  tipHash,
			MerkleRoot: consensus.CalcMerkleRoot(hashes),
			Timestamp:  tipNode.Header.Timestamp + 600,
			Bits:       params.PowLimitBits,
		},
		Transactions: txs,
	}
	for ; ; block.Header.Nonce++ {
		if consensus.CheckProofOfWork(block.Header.BlockHash(), block.Header.Bits, params.PowLimit) == nil {
			break
		}
	}
	hash := block.Header.BlockHash()
	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader %d: %v", height, err)
	}
	if err := db.StoreBlock(hash, block); err != nil {
		t.Fatalf("StoreBlock %d: %v", height, err)
	}
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock %d: %v", height, err)
	}
	return block
}

// probeTestChain is a regtest chain 1..probeTestTip built in memory, plus a
// Core-format snapshot of its UTXO set at probeTestBase registered as a
// regtest assumeutxo entry WITHOUT base-tail headers — the shape of Core's
// own regtest entries (110/200/299), which is what boot-smoke loads.
type probeTestChain struct {
	params   *consensus.ChainParams
	blocks   []*wire.MsgBlock // index h-1 = height h
	snapPath string
}

func buildProbeTestChain(t *testing.T) *probeTestChain {
	t.Helper()
	params := consensus.RegtestParams()
	db := storage.NewChainDB(storage.NewMemDB())
	idx := consensus.NewHeaderIndex(params)
	genesis := params.GenesisBlock.Header.BlockHash()
	if err := db.StoreBlock(genesis, params.GenesisBlock); err != nil {
		t.Fatalf("store genesis: %v", err)
	}
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: consensus.NewUTXOSet(db),
	})
	tc := &probeTestChain{params: params}
	for h := int32(1); h <= probeTestTip; h++ {
		var spend *wire.OutPoint
		if h > probeTestBase {
			// Spend the (mature) coinbase of block h-probeTestBase.
			cb := tc.blocks[h-probeTestBase-1].Transactions[0]
			spend = &wire.OutPoint{Hash: cb.TxHash(), Index: 0}
		}
		tc.blocks = append(tc.blocks, mineProbeTestBlock(t, params, idx, db, cm, spend))
	}

	// Snapshot coins = genesis->base replay in a separate set.
	coins := consensus.NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	for h := int32(1); h <= probeTestBase; h++ {
		if _, err := coins.ConnectBlockUTXOs(tc.blocks[h-1], h); err != nil {
			t.Fatalf("ConnectBlockUTXOs %d: %v", h, err)
		}
	}
	commitment, _, err := consensus.ComputeHashSerialized(coins)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	baseHash := tc.blocks[probeTestBase-1].Header.BlockHash()
	tc.snapPath = filepath.Join(t.TempDir(), "utxo.dat")
	f, err := os.Create(tc.snapPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.WriteSnapshot(f, coins, baseHash, params.NetworkMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	consensus.RegisterRegtestAssumeUTXO(consensus.AssumeUTXOData{
		Height:         probeTestBase,
		HashSerialized: commitment,
		ChainTxCount:   uint64(probeTestBase + 1),
		BlockHash:      baseHash,
	})
	return tc
}

// probeTestNode is one boot of a Pebble datadir, wired the way main() wires
// the pieces the startup consistency probe depends on.
type probeTestNode struct {
	pdb   *storage.PebbleDB
	db    *storage.ChainDB
	idx   *consensus.HeaderIndex
	utxos *consensus.UTXOSet
	cm    *consensus.ChainManager
}

// bootProbeTestNode follows main(): load chain state, hydrate the header index
// (step 3b), -load-snapshot on a fresh datadir (step 4b), chain manager,
// crash recovery, then header sync from a peer that has tc's chain and the
// OnSyncComplete hook (ReloadChainState + VerifyChainstateConsistency(200)).
func bootProbeTestNode(t *testing.T, dir string, tc *probeTestChain, loadSnapshot string) (*probeTestNode, consensus.ChainstateConsistencyResult) {
	t.Helper()
	pdb, err := storage.NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	n := &probeTestNode{pdb: pdb, db: storage.NewChainDB(pdb)}
	n.idx = consensus.NewHeaderIndex(tc.params)

	chainState, err := n.db.GetChainState()
	fresh := err != nil || chainState.BestHeight == 0
	if err != nil {
		genesis := tc.params.GenesisBlock.Header.BlockHash()
		if err := n.db.StoreBlock(genesis, tc.params.GenesisBlock); err != nil {
			t.Fatalf("store genesis: %v", err)
		}
	}
	if chainState != nil && chainState.BestHeight > 0 {
		// Step 3b as main() does it: re-graft a recorded detached band, then
		// ordinary hydration from the saved tip.
		if sb, err := n.db.GetSnapshotBase(); err == nil && sb != nil && sb.Chainwork.Sign() > 0 {
			if _, err := n.idx.HydrateSnapshotBaseFromDB(n.db, sb.Hash, sb.Height, sb.Chainwork); err != nil {
				t.Fatalf("re-graft snapshot base: %v", err)
			}
		}
		if _, err := n.idx.HydrateFromDB(n.db, chainState.BestHash, chainState.BestHeight); err != nil {
			t.Fatalf("HydrateFromDB: %v", err)
		}
	}
	n.utxos = consensus.NewUTXOSet(n.db)
	if loadSnapshot != "" {
		if !fresh {
			t.Fatalf("test bug: -load-snapshot on a non-fresh datadir")
		}
		if err := loadSnapshotFromFile(loadSnapshot, n.db, n.utxos, tc.params, n.idx, 0); err != nil {
			t.Fatalf("loadSnapshotFromFile: %v", err)
		}
	}
	n.cm = consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: tc.params, HeaderIndex: n.idx, ChainDB: n.db, UTXOSet: n.utxos,
	})
	if _, err := n.cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}

	// Header sync: the peer serves every header; the node persists them.
	for _, b := range tc.blocks {
		hash := b.Header.BlockHash()
		if !n.idx.HasHeader(hash) {
			if _, err := n.idx.AddHeader(b.Header, true); err != nil {
				t.Fatalf("header sync AddHeader: %v", err)
			}
		}
		if err := n.db.StoreBlockHeader(hash, &b.Header); err != nil {
			t.Fatalf("header sync StoreBlockHeader: %v", err)
		}
	}
	n.cm.ReloadChainState()
	return n, n.cm.VerifyChainstateConsistency(200)
}

// connectAbove downloads and connects tc's blocks above the node's tip.
func (n *probeTestNode) connectAbove(t *testing.T, tc *probeTestChain) {
	t.Helper()
	_, tip := n.cm.BestBlock()
	for h := tip + 1; h <= int32(len(tc.blocks)); h++ {
		b := tc.blocks[h-1]
		if err := n.db.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock %d: %v", h, err)
		}
		if err := n.cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock %d: %v", h, err)
		}
	}
}

// stop is main()'s clean shutdown: one atomic batch of UTXO flush + tip, then
// close the DB.
func (n *probeTestNode) stop(t *testing.T) {
	t.Helper()
	bestHash, bestHeight := n.cm.BestBlock()
	batch := n.db.NewBatch()
	staged, err := n.utxos.StageFlush(batch)
	if err != nil {
		t.Fatalf("StageFlush: %v", err)
	}
	n.db.SetChainStateBatch(batch, &storage.ChainState{BestHash: bestHash, BestHeight: bestHeight})
	if err := batch.Write(); err != nil {
		t.Fatalf("shutdown batch: %v", err)
	}
	staged.Commit()
	if err := n.pdb.Close(); err != nil {
		t.Fatalf("close pebble: %v", err)
	}
}

func assertCleanProbe(t *testing.T, boot string, n *probeTestNode, res consensus.ChainstateConsistencyResult, wantTip int32, wantProbed int) {
	t.Helper()
	_, tip := n.cm.BestBlock()
	if res.CorruptionAtHeight != 0 || res.RolledBackBlocks != 0 || res.RollbackFailed || tip != wantTip {
		t.Fatalf("%s: consistency probe on a healthy snapshot-loaded datadir must be clean at tip %d; "+
			"got %+v tip=%d (a RollbackFailed here is the false [CHAINSTATE-CORRUPTION] \"remove chaindata/\")",
			boot, wantTip, res, tip)
	}
	if res.BlocksProbed != wantProbed {
		t.Fatalf("%s: want the %d blocks above the snapshot base probed, got %d", boot, wantProbed, res.BlocksProbed)
	}
}

// TestSnapshotLoadedDatadirBootsTwiceWithoutFalseCorruption is the regression
// for the false [CHAINSTATE-CORRUPTION] on snapshot-loaded datadirs.
//
// A snapshot whose assumeutxo entry carries no base-tail headers (Core's own
// regtest entries, so boot-smoke's 299 fixture) left no snapshot-base record,
// so the startup probe had no floor. It walked from the tip into heights
// 1..base, which have no bodies by design, read each as "block body missing",
// disconnected every block connected above the base and failed at the base
// with "remove chaindata/". Seen on regtest with Core as the peer: boot 1 at
// tip 299, then every later boot rolled 405 back to 299.
func TestSnapshotLoadedDatadirBootsTwiceWithoutFalseCorruption(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)
	tc := buildProbeTestChain(t)
	dir := t.TempDir()

	n, res := bootProbeTestNode(t, dir, tc, tc.snapPath)
	assertCleanProbe(t, "boot 1 (fresh -load-snapshot)", n, res, probeTestBase, 0)
	n.connectAbove(t, tc)
	if _, tip := n.cm.BestBlock(); tip != probeTestTip {
		t.Fatalf("boot 1: connected to %d, want %d", tip, probeTestTip)
	}
	n.stop(t)

	for _, boot := range []string{"boot 2", "boot 3"} {
		n, res = bootProbeTestNode(t, dir, tc, "")
		assertCleanProbe(t, boot, n, res, probeTestTip, probeTestTip-probeTestBase)
		n.stop(t)
	}
}

// TestSnapshotLoadedDatadirProbeStillDetectsRealCorruption is the other half:
// the floor must not blind the probe above the base. A connected block whose
// body or undo data is gone is still corruption on a snapshot datadir, and a
// datadir with no snapshot record still has no floor at all.
func TestSnapshotLoadedDatadirProbeStillDetectsRealCorruption(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)
	tc := buildProbeTestChain(t)
	hashAt := func(h int32) wire.Hash256 { return tc.blocks[h-1].Header.BlockHash() }

	cases := []struct {
		name     string
		damage   func(t *testing.T, pdb *storage.PebbleDB)
		wantBad  int32
		wantFail bool
	}{
		{
			// Lowest block above the base: the probe must reach it.
			name: "body missing just above the base",
			damage: func(t *testing.T, pdb *storage.PebbleDB) {
				if err := pdb.Delete(storage.MakeBlockDataKey(hashAt(probeTestBase + 1))); err != nil {
					t.Fatal(err)
				}
			},
			wantBad: probeTestBase + 1, wantFail: true,
		},
		{
			name: "undo missing at the tip",
			damage: func(t *testing.T, pdb *storage.PebbleDB) {
				if err := pdb.Delete(storage.MakeUndoBlockKey(hashAt(probeTestTip))); err != nil {
					t.Fatal(err)
				}
			},
			wantBad: probeTestTip, wantFail: true,
		},
		{
			// Undo of a mid block gone, tip undo intact: detected, and the
			// rollback peels the tip down to it.
			name: "undo missing below the tip",
			damage: func(t *testing.T, pdb *storage.PebbleDB) {
				if err := pdb.Delete(storage.MakeUndoBlockKey(hashAt(probeTestTip - 2))); err != nil {
					t.Fatal(err)
				}
			},
			wantBad: probeTestTip - 2, wantFail: true,
		},
		{
			// Without a record the probe has no floor (pre-fix datadirs, and
			// every non-snapshot datadir): the body-less range reads as
			// corruption, exactly as before.
			name: "snapshot record removed",
			damage: func(t *testing.T, pdb *storage.PebbleDB) {
				if err := pdb.Delete(storage.SnapshotBaseKey); err != nil {
					t.Fatal(err)
				}
			},
			wantBad: -1, wantFail: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			n, _ := bootProbeTestNode(t, dir, tc, tc.snapPath)
			n.connectAbove(t, tc)
			n.stop(t)

			pdb, err := storage.NewPebbleDB(dir)
			if err != nil {
				t.Fatal(err)
			}
			c.damage(t, pdb)
			if err := pdb.Close(); err != nil {
				t.Fatal(err)
			}

			n, res := bootProbeTestNode(t, dir, tc, "")
			defer n.pdb.Close()
			if res.CorruptionAtHeight == 0 {
				t.Fatalf("damaged datadir read as clean: %+v", res)
			}
			if c.wantBad > 0 && res.CorruptionAtHeight != c.wantBad {
				t.Fatalf("corruption reported at %d, want %d (%+v)", res.CorruptionAtHeight, c.wantBad, res)
			}
			if c.wantBad < 0 && res.CorruptionAtHeight > probeTestBase {
				t.Fatalf("without a record the band (<= %d) must be what is flagged, got %d", probeTestBase, res.CorruptionAtHeight)
			}
			if res.RollbackFailed != c.wantFail {
				t.Fatalf("RollbackFailed=%v, want %v (%+v)", res.RollbackFailed, c.wantFail, res)
			}
		})
	}
}
