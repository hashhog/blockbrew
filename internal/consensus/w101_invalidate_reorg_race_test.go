package consensus

import (
	"sync"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// InvalidateBlock must serialise against ReorgTo.
//
// InvalidateBlock's disconnect loop releases cm.mu around every
// DisconnectBlock call (it has to — DisconnectBlock takes cm.mu itself).
// ReorgTo serialises only against other ReorgTo calls via cm.reorgMu, and the
// disconnect loop was not participating in that lock. So the P2P/sync path
// could run a complete reorg INTO THE MIDDLE of a rollback.
//
// Observed live on genesis-blockbrew (mainnet) 2026-07-27:
//
//	21:59:55 sync: received block height=959908 from 127.0.0.1:8333
//	21:59:55 chainmgr: reorg from height 959898 to 959908
//	         (fork at 959898, disconnect=0 connect=10)
//	22:00:11 chainmgr: DisconnectBlock unclean for ... at h=959908
//	         (BIP-30 aftermath or undo-mismatch)
//
// InvalidateBlock had the tip at 959898 mid-rollback; sync connected 10 blocks
// on top of the half-rewound state. The resulting UTXO set matched neither
// tip, was flushed on shutdown, and the node came back with an unrecoverable
// [CHAINSTATE-CORRUPTION] wedge. Cost: an 83-hour from-genesis datadir.
// ---------------------------------------------------------------------------

// buildConnectedChain connects n blocks onto genesis through the real
// ConnectBlock path and returns the block nodes in height order.
func buildConnectedChain(t *testing.T, cm *ChainManager, idx *HeaderIndex, params *ChainParams, n int) []*BlockNode {
	t.Helper()
	db := cm.chainDB
	nodes := []*BlockNode{idx.Genesis()}
	for i := 0; i < n; i++ {
		blk := createTestBlock(t, params, nodes[len(nodes)-1], nil)
		node, err := idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock %d: %v", i, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock %d: %v", i, err)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// TestInvalidateBlockHoldsReorgMuDuringDisconnect proves the invariant
// directly: while InvalidateBlock is rewinding, cm.reorgMu must be held, so no
// concurrent ReorgTo can start.
//
// The probe runs from the onBlockDisconnected hook, which fires inside the
// disconnect loop — exactly the window that was unguarded. TryLock succeeding
// there means a racing reorg could have proceeded.
func TestInvalidateBlockHoldsReorgMuDuringDisconnect(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	nodes := buildConnectedChain(t, cm, idx, params, 6)

	var mu sync.Mutex
	fired := 0
	reorgMuWasFree := 0

	cm.SetOnBlockDisconnected(func(_ *wire.MsgBlock, _ int32) {
		mu.Lock()
		defer mu.Unlock()
		fired++
		// If reorgMu is acquirable here, InvalidateBlock is NOT holding it and
		// a concurrent ReorgTo could interleave with this rollback.
		if cm.reorgMu.TryLock() {
			reorgMuWasFree++
			cm.reorgMu.Unlock()
		}
	})

	// Invalidate 3 deep so the disconnect loop runs several iterations.
	target := nodes[4]
	if err := cm.InvalidateBlock(target.Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if fired == 0 {
		t.Fatal("disconnect hook never fired — the probe proved nothing; " +
			"check that InvalidateBlock still rewinds through DisconnectBlock")
	}
	if reorgMuWasFree != 0 {
		t.Errorf("INVALIDATE/REORG RACE: cm.reorgMu was free on %d of %d "+
			"disconnects inside InvalidateBlock. The rollback is not mutually "+
			"exclusive with ReorgTo, so the sync path can connect blocks onto a "+
			"half-rewound chain and corrupt the chainstate (genesis-blockbrew "+
			"2026-07-27, h=959898->959908).", reorgMuWasFree, fired)
	}
	t.Logf("probe fired on %d disconnects; reorgMu held every time", fired)
}
