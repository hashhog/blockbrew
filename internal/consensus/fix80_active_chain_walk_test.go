package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
)

// TestFIX80_ActiveChainWalk_GetAncestorAtEveryHeight verifies the
// primitive that handleGetBlockHash relies on after FIX-80:
// `chainMgr.BestBlockNode().GetAncestor(height)` returns the correct
// canonical hash for every height in [0, tipHeight].
//
// Bitcoin Core's rpc/blockchain.cpp::getblockhash walks the in-memory
// active chain (`chainman.ActiveChain()[nHeight]`).  blockbrew's
// equivalent is `cm.BestBlockNode().GetAncestor(height).Hash`.  This
// test plants a 10-block regtest chain and asserts the walk yields
// the same hash that ConnectBlock published for each height — including
// genesis (height 0) and the tip itself.
//
// The bug this test guards against: the live mainnet node had no
// chainDB height->hash mapping for any height below the launched-from
// IBD tip, but the in-memory chain (built from header sync) was
// complete.  If GetAncestor were buggy at any depth, the FIX-80 RPC
// would silently regress to the same "Block not found" error as the
// pre-fix code.
func TestFIX80_ActiveChainWalk_GetAncestorAtEveryHeight(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Connect 10 blocks on top of genesis.  Record the hash at each
	// height so we can compare against the GetAncestor walk afterwards.
	const numBlocks = 10
	hashes := make(map[int32]string, numBlocks+1)
	hashes[0] = params.GenesisHash.String()

	prev := idx.Genesis()
	for h := int32(1); h <= numBlocks; h++ {
		block := createTestBlock(t, params, prev, nil)
		blockHash := block.Header.BlockHash()

		if _, err := idx.AddHeader(block.Header, true); err != nil {
			t.Fatalf("AddHeader at height %d: %v", h, err)
		}
		if err := db.StoreBlock(blockHash, block); err != nil {
			t.Fatalf("StoreBlock at height %d: %v", h, err)
		}
		if err := cm.ConnectBlock(block); err != nil {
			t.Fatalf("ConnectBlock at height %d: %v", h, err)
		}

		hashes[h] = blockHash.String()
		prev = idx.GetNode(blockHash)
	}

	// Tip should now be at numBlocks.
	tipNode := cm.BestBlockNode()
	if tipNode == nil {
		t.Fatal("BestBlockNode returned nil after connecting blocks")
	}
	if tipNode.Height != numBlocks {
		t.Fatalf("tip height = %d, want %d", tipNode.Height, numBlocks)
	}

	// For every height [0, numBlocks], walk the in-memory chain and
	// compare against the ConnectBlock-recorded hash.  This is the
	// exact primitive handleGetBlockHash uses on the primary path.
	for h := int32(0); h <= numBlocks; h++ {
		anc := tipNode.GetAncestor(h)
		if anc == nil {
			t.Errorf("GetAncestor(%d) = nil; want hash %s", h, hashes[h])
			continue
		}
		got := anc.Hash.String()
		if got != hashes[h] {
			t.Errorf("GetAncestor(%d) = %s; want %s", h, got, hashes[h])
		}
	}

	// Above-tip and below-genesis must return nil; the RPC layer
	// translates these to "Block height out of range".
	if got := tipNode.GetAncestor(numBlocks + 1); got != nil {
		t.Errorf("GetAncestor(%d) above tip = %v; want nil",
			numBlocks+1, got)
	}
	if got := tipNode.GetAncestor(-1); got != nil {
		t.Errorf("GetAncestor(-1) = %v; want nil", got)
	}
}
