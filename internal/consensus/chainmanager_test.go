package consensus

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// createTestBlock creates a valid test block that spends the previous coinbase.
func createTestBlock(t *testing.T, params *ChainParams, prevNode *BlockNode, txs []*wire.MsgTx) *wire.MsgBlock {
	t.Helper()

	blockHeight := prevNode.Height + 1
	heightScript := encodeBIP34Height(blockHeight)
	// Append some extra data to make the coinbase scriptSig at least 2 bytes
	if len(heightScript) < 2 {
		heightScript = append(heightScript, 0x00)
	}

	// Create coinbase transaction
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: heightScript,
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    CalcBlockSubsidy(blockHeight),
				PkScript: []byte{0x51}, // OP_TRUE
			},
		},
		LockTime: 0,
	}

	// Build the block
	allTxs := make([]*wire.MsgTx, 0, len(txs)+1)
	allTxs = append(allTxs, coinbase)
	allTxs = append(allTxs, txs...)

	// Calculate merkle root
	txHashes := make([]wire.Hash256, len(allTxs))
	for i, tx := range allTxs {
		txHashes[i] = tx.TxHash()
	}
	merkleRoot := CalcMerkleRoot(txHashes)

	// Create header
	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prevNode.Hash,
		MerkleRoot: merkleRoot,
		Timestamp:  prevNode.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}

	// Find valid nonce (regtest difficulty is very high)
	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		header.Nonce = i
		hash := header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}

	return &wire.MsgBlock{
		Header:       header,
		Transactions: allTxs,
	}
}

func TestChainManagerCreation(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	if cm == nil {
		t.Fatal("chain manager should not be nil")
	}

	hash, height := cm.BestBlock()
	if height != 0 {
		t.Errorf("initial height = %d, want 0", height)
	}
	if hash != params.GenesisHash {
		t.Errorf("initial hash = %s, want genesis", hash.String()[:16])
	}
}

func TestConnectBlockValidBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Create a valid block
	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	blockHash := block.Header.BlockHash()

	// Add header to index first
	_, err := idx.AddHeader(block.Header)
	if err != nil {
		t.Fatalf("failed to add header: %v", err)
	}

	// Store block data
	err = db.StoreBlock(blockHash, block)
	if err != nil {
		t.Fatalf("failed to store block: %v", err)
	}

	// Connect the block
	err = cm.ConnectBlock(block)
	if err != nil {
		t.Fatalf("ConnectBlock failed: %v", err)
	}

	// Verify tip updated
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 1 {
		t.Errorf("tip height = %d, want 1", tipHeight)
	}
	if tipHash != blockHash {
		t.Errorf("tip hash = %s, want %s", tipHash.String()[:16], blockHash.String()[:16])
	}
}

func TestConnectBlockInvalidPoW(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Chain manager is created but not used directly - the test is about
	// header validation which happens before ConnectBlock
	_ = NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	genesis := idx.Genesis()

	// Create coinbase
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: []byte{0x01, 0x01},
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    CalcBlockSubsidy(1),
				PkScript: []byte{0x51},
			},
		},
		LockTime: 0,
	}

	// Create block with invalid PoW (all zeros nonce won't meet target)
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    4,
			PrevBlock:  genesis.Hash,
			MerkleRoot: coinbase.TxHash(),
			Timestamp:  genesis.Header.Timestamp + 600,
			Bits:       0x1d00ffff, // Mainnet difficulty (too hard)
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}

	// Try to add header - should fail due to invalid PoW
	_, err := idx.AddHeader(block.Header)
	if err == nil {
		t.Error("expected error for invalid PoW header")
	}
}

func TestConnectBlockInvalidTransaction(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	genesis := idx.Genesis()

	// Create coinbase that exceeds subsidy
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: []byte{0x01, 0x01},
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    CalcBlockSubsidy(1) + 1000000, // Too much!
				PkScript: []byte{0x51},
			},
		},
		LockTime: 0,
	}

	txHashes := []wire.Hash256{coinbase.TxHash()}
	merkleRoot := CalcMerkleRoot(txHashes)

	// Create block with valid PoW
	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  genesis.Hash,
		MerkleRoot: merkleRoot,
		Timestamp:  genesis.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}

	// Find valid nonce
	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		header.Nonce = i
		hash := header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}

	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{coinbase},
	}

	// Add header to index
	_, err := idx.AddHeader(block.Header)
	if err != nil {
		t.Fatalf("failed to add header: %v", err)
	}

	// Try to connect - should fail due to excessive coinbase
	err = cm.ConnectBlock(block)
	if err == nil {
		t.Error("expected error for excessive coinbase value")
	}
}

func TestChainReorg(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Build chain A: genesis -> A1 -> A2
	blockA1 := createTestBlock(t, params, genesis, nil)
	nodeA1, err := idx.AddHeader(blockA1.Header)
	if err != nil {
		t.Fatalf("failed to add A1 header: %v", err)
	}
	db.StoreBlock(blockA1.Header.BlockHash(), blockA1)
	if err := cm.ConnectBlock(blockA1); err != nil {
		t.Fatalf("failed to connect A1: %v", err)
	}

	blockA2 := createTestBlock(t, params, nodeA1, nil)
	nodeA2, err := idx.AddHeader(blockA2.Header)
	if err != nil {
		t.Fatalf("failed to add A2 header: %v", err)
	}
	db.StoreBlock(blockA2.Header.BlockHash(), blockA2)
	if err := cm.ConnectBlock(blockA2); err != nil {
		t.Fatalf("failed to connect A2: %v", err)
	}

	// Verify we're on chain A
	_, tipHeight := cm.BestBlock()
	if tipHeight != 2 {
		t.Errorf("expected height 2, got %d", tipHeight)
	}

	// Build competing chain B: genesis -> B1 -> B2 -> B3 (more work)
	blockB1 := createTestBlock(t, params, genesis, nil)
	blockB1.Header.Nonce++ // Different block
	// Re-mine with new nonce
	target := CompactToBig(blockB1.Header.Bits)
	for i := uint32(100000); i < 20000000; i++ {
		blockB1.Header.Nonce = i
		hash := blockB1.Header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}

	nodeB1, err := idx.AddHeader(blockB1.Header)
	if err != nil {
		t.Fatalf("failed to add B1 header: %v", err)
	}
	db.StoreBlock(blockB1.Header.BlockHash(), blockB1)

	blockB2 := createTestBlock(t, params, nodeB1, nil)
	nodeB2, err := idx.AddHeader(blockB2.Header)
	if err != nil {
		t.Fatalf("failed to add B2 header: %v", err)
	}
	db.StoreBlock(blockB2.Header.BlockHash(), blockB2)

	blockB3 := createTestBlock(t, params, nodeB2, nil)
	nodeB3, err := idx.AddHeader(blockB3.Header)
	if err != nil {
		t.Fatalf("failed to add B3 header: %v", err)
	}
	db.StoreBlock(blockB3.Header.BlockHash(), blockB3)

	// Chain B has more work, trying to connect B3 should trigger reorg
	// Note: In our implementation, connecting a block that doesn't extend
	// the tip but has more work will trigger reorg
	err = cm.ReorgTo(nodeB3)
	if err != nil {
		t.Fatalf("reorg failed: %v", err)
	}

	// Verify we're now on chain B
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 3 {
		t.Errorf("expected height 3 after reorg, got %d", tipHeight)
	}
	if tipHash != nodeB3.Hash {
		t.Errorf("expected tip B3, got %s", tipHash.String()[:16])
	}

	// Verify A2 is not in main chain
	if cm.IsInMainChain(nodeA2.Hash) {
		t.Error("A2 should not be in main chain after reorg")
	}
}

func TestIsInMainChain(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Genesis should be in main chain
	if !cm.IsInMainChain(params.GenesisHash) {
		t.Error("genesis should be in main chain")
	}

	// Unknown hash should not be in main chain
	unknownHash := wire.Hash256{0x12, 0x34}
	if cm.IsInMainChain(unknownHash) {
		t.Error("unknown hash should not be in main chain")
	}
}

func TestUTXOSetUpdates(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Create and connect first block
	block1 := createTestBlock(t, params, genesis, nil)
	_, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add header: %v", err)
	}
	db.StoreBlock(block1.Header.BlockHash(), block1)

	err = cm.ConnectBlock(block1)
	if err != nil {
		t.Fatalf("ConnectBlock failed: %v", err)
	}

	// Check that coinbase output is in UTXO set
	coinbaseTxHash := block1.Transactions[0].TxHash()
	utxo := cm.UTXOSet().GetUTXO(wire.OutPoint{Hash: coinbaseTxHash, Index: 0})
	if utxo == nil {
		t.Error("coinbase output should be in UTXO set")
	}
	if utxo.IsCoinbase != true {
		t.Error("coinbase UTXO should be marked as coinbase")
	}
	if utxo.Height != 1 {
		t.Errorf("coinbase UTXO height = %d, want 1", utxo.Height)
	}
}

func TestChainManagerWithNilUTXOSet(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create chain manager without UTXO set - should create one automatically
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	if cm.UTXOSet() == nil {
		t.Error("chain manager should create UTXO set if none provided")
	}
}

// TestConnectDisconnectRestoresUTXO verifies that after ConnectBlock + DisconnectBlock,
// the UTXO set is restored to its previous state.
func TestConnectDisconnectRestoresUTXO(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Connect block 1 (just a coinbase)
	block1 := createTestBlock(t, params, genesis, nil)
	block1Hash := block1.Header.BlockHash()
	node1, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add block1 header: %v", err)
	}
	if err := db.StoreBlock(block1Hash, block1); err != nil {
		t.Fatalf("failed to store block1: %v", err)
	}
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("failed to connect block1: %v", err)
	}

	// Verify block1 coinbase output is in UTXO set
	coinbase1Hash := block1.Transactions[0].TxHash()
	coinbase1Outpoint := wire.OutPoint{Hash: coinbase1Hash, Index: 0}
	utxo1 := cm.UTXOSet().GetUTXO(coinbase1Outpoint)
	if utxo1 == nil {
		t.Fatal("block1 coinbase should be in UTXO set")
	}

	// Connect block 2 (another coinbase only)
	block2 := createTestBlock(t, params, node1, nil)
	block2Hash := block2.Header.BlockHash()
	_, err = idx.AddHeader(block2.Header)
	if err != nil {
		t.Fatalf("failed to add block2 header: %v", err)
	}
	if err := db.StoreBlock(block2Hash, block2); err != nil {
		t.Fatalf("failed to store block2: %v", err)
	}
	if err := cm.ConnectBlock(block2); err != nil {
		t.Fatalf("failed to connect block2: %v", err)
	}

	// Verify tip is at block 2
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 2 {
		t.Errorf("tip height = %d, want 2", tipHeight)
	}
	if tipHash != block2Hash {
		t.Errorf("tip hash mismatch")
	}

	// Verify block2 coinbase is in UTXO set
	coinbase2Hash := block2.Transactions[0].TxHash()
	coinbase2Outpoint := wire.OutPoint{Hash: coinbase2Hash, Index: 0}
	utxo2 := cm.UTXOSet().GetUTXO(coinbase2Outpoint)
	if utxo2 == nil {
		t.Fatal("block2 coinbase should be in UTXO set")
	}

	// Disconnect block 2
	if err := cm.DisconnectBlock(block2Hash); err != nil {
		t.Fatalf("failed to disconnect block2: %v", err)
	}

	// Verify tip is back at block 1
	tipHash, tipHeight = cm.BestBlock()
	if tipHeight != 1 {
		t.Errorf("tip height after disconnect = %d, want 1", tipHeight)
	}
	if tipHash != block1Hash {
		t.Errorf("tip hash after disconnect should be block1")
	}

	// Verify block2 coinbase is no longer in UTXO set
	utxo2After := cm.UTXOSet().GetUTXO(coinbase2Outpoint)
	if utxo2After != nil {
		t.Error("block2 coinbase should NOT be in UTXO set after disconnect")
	}

	// Verify block1 coinbase is still in UTXO set
	utxo1After := cm.UTXOSet().GetUTXO(coinbase1Outpoint)
	if utxo1After == nil {
		t.Error("block1 coinbase should still be in UTXO set after disconnect")
	}
}

// TestBlockUndoPersistence verifies that undo data is persisted to the database.
func TestBlockUndoPersistence(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Connect a block
	block1 := createTestBlock(t, params, genesis, nil)
	block1Hash := block1.Header.BlockHash()
	_, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add header: %v", err)
	}
	if err := db.StoreBlock(block1Hash, block1); err != nil {
		t.Fatalf("failed to store block: %v", err)
	}
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("failed to connect block: %v", err)
	}

	// Verify undo data was persisted
	undo, err := db.ReadBlockUndo(block1Hash)
	if err != nil {
		t.Fatalf("failed to read undo data: %v", err)
	}

	// Block 1 has only coinbase, so TxUndos should be empty
	if len(undo.TxUndos) != 0 {
		t.Errorf("TxUndos count = %d, want 0 (coinbase-only block)", len(undo.TxUndos))
	}

	// After disconnect, undo data should be deleted
	if err := cm.DisconnectBlock(block1Hash); err != nil {
		t.Fatalf("failed to disconnect block: %v", err)
	}

	_, err = db.ReadBlockUndo(block1Hash)
	if err != storage.ErrNotFound {
		t.Errorf("undo data should be deleted after disconnect, got err=%v", err)
	}
}

// TestInvalidateBlock tests the InvalidateBlock functionality.
func TestInvalidateBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Build a chain: genesis -> block1 -> block2 -> block3
	block1 := createTestBlock(t, params, genesis, nil)
	node1, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add block1 header: %v", err)
	}
	db.StoreBlock(block1.Header.BlockHash(), block1)
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("failed to connect block1: %v", err)
	}

	block2 := createTestBlock(t, params, node1, nil)
	node2, err := idx.AddHeader(block2.Header)
	if err != nil {
		t.Fatalf("failed to add block2 header: %v", err)
	}
	db.StoreBlock(block2.Header.BlockHash(), block2)
	if err := cm.ConnectBlock(block2); err != nil {
		t.Fatalf("failed to connect block2: %v", err)
	}

	block3 := createTestBlock(t, params, node2, nil)
	node3, err := idx.AddHeader(block3.Header)
	if err != nil {
		t.Fatalf("failed to add block3 header: %v", err)
	}
	db.StoreBlock(block3.Header.BlockHash(), block3)
	if err := cm.ConnectBlock(block3); err != nil {
		t.Fatalf("failed to connect block3: %v", err)
	}

	// Verify we're at height 3
	_, tipHeight := cm.BestBlock()
	if tipHeight != 3 {
		t.Errorf("expected height 3, got %d", tipHeight)
	}

	// Invalidate block2
	err = cm.InvalidateBlock(node2.Hash)
	if err != nil {
		t.Fatalf("InvalidateBlock failed: %v", err)
	}

	// Verify block2 is marked as invalid
	if node2.Status&StatusInvalid == 0 {
		t.Error("block2 should be marked as invalid")
	}

	// Verify block3 is marked as invalid child
	if node3.Status&StatusInvalidChild == 0 {
		t.Error("block3 should be marked as invalid child")
	}

	// Verify tip is now at block1
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 1 {
		t.Errorf("expected height 1 after invalidation, got %d", tipHeight)
	}
	if tipHash != node1.Hash {
		t.Errorf("expected tip to be block1 after invalidation")
	}
}

// TestInvalidateBlockNonMainChain tests invalidating a block not in the main chain.
func TestInvalidateBlockNonMainChain(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Build main chain: genesis -> block1
	block1 := createTestBlock(t, params, genesis, nil)
	node1, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add block1 header: %v", err)
	}
	db.StoreBlock(block1.Header.BlockHash(), block1)
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("failed to connect block1: %v", err)
	}

	// Create a fork at genesis (not connected to main chain)
	forkBlock := createTestBlock(t, params, genesis, nil)
	forkBlock.Header.Nonce += 1000000 // Different nonce
	// Re-mine
	target := CompactToBig(forkBlock.Header.Bits)
	for i := uint32(2000000); i < 30000000; i++ {
		forkBlock.Header.Nonce = i
		hash := forkBlock.Header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}
	forkNode, err := idx.AddHeader(forkBlock.Header)
	if err != nil {
		t.Fatalf("failed to add fork header: %v", err)
	}
	db.StoreBlock(forkBlock.Header.BlockHash(), forkBlock)

	// Invalidate the fork block (which is not in main chain)
	err = cm.InvalidateBlock(forkNode.Hash)
	if err != nil {
		t.Fatalf("InvalidateBlock failed: %v", err)
	}

	// Verify fork block is marked as invalid
	if forkNode.Status&StatusInvalid == 0 {
		t.Error("fork block should be marked as invalid")
	}

	// Verify main chain is unaffected
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 1 {
		t.Errorf("expected height 1, got %d", tipHeight)
	}
	if tipHash != node1.Hash {
		t.Errorf("expected tip to still be block1")
	}
}

// TestReconsiderBlock tests the ReconsiderBlock functionality.
func TestReconsiderBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Build a chain: genesis -> block1 -> block2
	block1 := createTestBlock(t, params, genesis, nil)
	node1, err := idx.AddHeader(block1.Header)
	if err != nil {
		t.Fatalf("failed to add block1 header: %v", err)
	}
	db.StoreBlock(block1.Header.BlockHash(), block1)
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("failed to connect block1: %v", err)
	}

	block2 := createTestBlock(t, params, node1, nil)
	node2, err := idx.AddHeader(block2.Header)
	if err != nil {
		t.Fatalf("failed to add block2 header: %v", err)
	}
	db.StoreBlock(block2.Header.BlockHash(), block2)
	if err := cm.ConnectBlock(block2); err != nil {
		t.Fatalf("failed to connect block2: %v", err)
	}

	// Invalidate block2
	err = cm.InvalidateBlock(node2.Hash)
	if err != nil {
		t.Fatalf("InvalidateBlock failed: %v", err)
	}

	// Verify tip is at block1
	_, tipHeight := cm.BestBlock()
	if tipHeight != 1 {
		t.Errorf("expected height 1 after invalidation, got %d", tipHeight)
	}

	// Reconsider block2
	err = cm.ReconsiderBlock(node2.Hash)
	if err != nil {
		t.Fatalf("ReconsiderBlock failed: %v", err)
	}

	// Verify block2 is no longer marked as invalid
	if node2.Status&StatusInvalid != 0 {
		t.Error("block2 should not be marked as invalid after reconsideration")
	}

	// Verify tip is back at block2 (since it has more work)
	tipHash, tipHeight := cm.BestBlock()
	if tipHeight != 2 {
		t.Errorf("expected height 2 after reconsideration, got %d", tipHeight)
	}
	if tipHash != node2.Hash {
		t.Errorf("expected tip to be block2 after reconsideration")
	}
}

// TestPreciousBlock tests the PreciousBlock functionality.
func TestPreciousBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Build chain A: genesis -> A1
	blockA1 := createTestBlock(t, params, genesis, nil)
	nodeA1, err := idx.AddHeader(blockA1.Header)
	if err != nil {
		t.Fatalf("failed to add A1 header: %v", err)
	}
	db.StoreBlock(blockA1.Header.BlockHash(), blockA1)
	if err := cm.ConnectBlock(blockA1); err != nil {
		t.Fatalf("failed to connect A1: %v", err)
	}

	// Build competing chain B at same height: genesis -> B1
	blockB1 := createTestBlock(t, params, genesis, nil)
	blockB1.Header.Nonce += 1000000 // Different nonce
	// Re-mine
	target := CompactToBig(blockB1.Header.Bits)
	for i := uint32(2000000); i < 30000000; i++ {
		blockB1.Header.Nonce = i
		hash := blockB1.Header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}
	nodeB1, err := idx.AddHeader(blockB1.Header)
	if err != nil {
		t.Fatalf("failed to add B1 header: %v", err)
	}
	db.StoreBlock(blockB1.Header.BlockHash(), blockB1)

	// Currently on chain A (it was connected first)
	tipHash, _ := cm.BestBlock()
	if tipHash != nodeA1.Hash {
		t.Errorf("expected tip to be A1 initially")
	}

	// Mark B1 as precious - should trigger a reorg since equal work
	err = cm.PreciousBlock(nodeB1.Hash)
	if err != nil {
		t.Fatalf("PreciousBlock failed: %v", err)
	}

	// Verify tip is now B1
	tipHash, _ = cm.BestBlock()
	if tipHash != nodeB1.Hash {
		t.Errorf("expected tip to be B1 after marking as precious")
	}
}

// TestInvalidateGenesisBlock tests that genesis block cannot be invalidated.
func TestInvalidateGenesisBlock(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Try to invalidate genesis
	err := cm.InvalidateBlock(params.GenesisHash)
	if err == nil {
		t.Error("should not be able to invalidate genesis block")
	}
}

// TestInvalidateBlockNotFound tests that invalidating unknown block returns error.
func TestInvalidateBlockNotFound(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	// Try to invalidate non-existent block
	unknownHash := wire.Hash256{0x12, 0x34, 0x56}
	err := cm.InvalidateBlock(unknownHash)
	if err == nil {
		t.Error("should return error for unknown block")
	}
}

// TestStartupRecoverySavedTipPresent is the happy-path regression for the
// W17 chainmgr-startup fix: when the header index already contains the
// saved tip at startup (e.g. after a hot restart where the header-index
// was never torn down) the chain manager must adopt the saved height
// without spuriously setting pendingRecovery or emitting a rewind warning.
func TestStartupRecoverySavedTipPresent(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	// Seed the header index with one real block beyond genesis.
	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	blockHash := block.Header.BlockHash()
	if _, err := idx.AddHeader(block.Header); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	// Persist the height->hash mapping and saved chain state at height 1.
	if err := db.SetBlockHeight(1, blockHash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}
	if err := db.SetChainState(&storage.ChainState{BestHash: blockHash, BestHeight: 1}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	gotHash, gotHeight := cm.BestBlock()
	if gotHeight != 1 {
		t.Errorf("saved-tip-present: height = %d, want 1", gotHeight)
	}
	if gotHash != blockHash {
		t.Errorf("saved-tip-present: hash = %s, want %s", gotHash.String(), blockHash.String())
	}
	if cm.HasPendingRecovery() {
		t.Error("saved-tip-present: pendingRecovery should be false when tip was resolved")
	}
}

// TestStartupRecoverySavedTipMissingThenReload is the deferred-recovery
// regression for the W17 chainmgr-startup fix.  At construction time the
// header index contains only genesis, so a saved tip at height > 0 cannot
// be resolved; the manager must defer (pendingRecovery=true) rather than
// silently resetting to genesis.  Once P2P header sync has added the
// saved tip's header, ReloadChainState must restore it without warning.
func TestStartupRecoverySavedTipMissingThenReload(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	// Build a chain of 2 headers past genesis OUTSIDE the header index
	// so we can simulate "saved tip exists on disk but index has only
	// genesis" — mimicking the real startup path.
	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	block1Hash := block1.Header.BlockHash()

	// Persist the saved state pointing at height 1.
	if err := db.SetBlockHeight(1, block1Hash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}
	if err := db.SetChainState(&storage.ChainState{BestHash: block1Hash, BestHeight: 1}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	// Construct the chain manager BEFORE the block1 header is added
	// to the index.  This is the mainnet startup shape.
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	if !cm.HasPendingRecovery() {
		t.Fatal("saved-tip-missing: pendingRecovery should be true pre-reload")
	}
	if _, h := cm.BestBlock(); h != 0 {
		t.Errorf("saved-tip-missing: tip should still be at genesis pre-reload, got height %d", h)
	}

	// Simulate P2P header sync catching up.
	if _, err := idx.AddHeader(block1.Header); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// Reloading now should adopt the saved tip.
	cm.ReloadChainState()

	gotHash, gotHeight := cm.BestBlock()
	if gotHeight != 1 {
		t.Errorf("saved-tip-missing: height after reload = %d, want 1", gotHeight)
	}
	if gotHash != block1Hash {
		t.Errorf("saved-tip-missing: hash after reload = %s, want %s", gotHash.String(), block1Hash.String())
	}
	if cm.HasPendingRecovery() {
		t.Error("saved-tip-missing: pendingRecovery should clear after successful reload")
	}
}

// TestStartupRecoveryUnreachableTipStaysAtGenesis verifies that when the
// saved chain tip is genuinely unreachable (e.g. the previously-active
// chain is a fork no peer advertises) AND header sync has passed the
// saved height, the chain manager refuses to rewind and stays at
// genesis with a loud warning.
//
// Rationale: the persisted UTXO set reflects the saved tip's post-state.
// Rewinding the tip pointer to an ancestor without replaying undo data
// leaves the UTXO set inconsistent, causing every subsequent
// ConnectBlock at low heights to fail with "missing UTXO" errors
// (observed on maxbox during the W17 first deploy when an earlier
// rewind-to-ancestor variant corrupted the UTXO set).  Proper
// UTXO-consistent rewind is deferred to W18.
func TestStartupRecoveryUnreachableTipStaysAtGenesis(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	block1Hash := block1.Header.BlockHash()
	if _, err := idx.AddHeader(block1.Header); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.SetBlockHeight(1, block1Hash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}

	// Saved tip sits at height 2 on an unreachable fork.
	unreachableHash := wire.Hash256{0x99, 0x99, 0x99, 0x99}
	if err := db.SetBlockHeight(2, unreachableHash); err != nil {
		t.Fatalf("SetBlockHeight 2: %v", err)
	}
	if err := db.SetChainState(&storage.ChainState{BestHash: unreachableHash, BestHeight: 2}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	// Simulate header sync having reached past the saved height on the
	// canonical chain (block2 is a child of block1, not of unreachableHash).
	block2 := createTestBlock(t, params, &BlockNode{
		Hash:   block1Hash,
		Height: 1,
		Header: block1.Header,
	}, nil)
	if _, err := idx.AddHeader(block2.Header); err != nil {
		t.Fatalf("AddHeader block2: %v", err)
	}

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	if !cm.HasPendingRecovery() {
		t.Fatal("unreachable: pendingRecovery should be true when saved tip is missing")
	}

	cm.ReloadChainState()
	if _, h := cm.BestBlock(); h != 0 {
		t.Errorf("unreachable: tip must stay at genesis to preserve UTXO consistency, got height %d", h)
	}
	if cm.HasPendingRecovery() {
		t.Error("unreachable: pendingRecovery should clear after loud warning (no further retries)")
	}
}

// TestStartupRecoveryDeferredUntilHeadersPast verifies the W17 rewind
// guard: when the saved tip's hash is missing from the header index
// AND the header index is still below the saved tip height, the chain
// manager must defer (pendingRecovery=true) instead of rewinding.
// Without this guard the recovery walker would pick the deepest ancestor
// currently in the index (e.g. block at height 2000) and discard
// ~500k blocks of already-validated persisted state.
func TestStartupRecoveryDeferredUntilHeadersPast(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	genesis := idx.Genesis()
	block1 := createTestBlock(t, params, genesis, nil)
	block1Hash := block1.Header.BlockHash()
	if _, err := idx.AddHeader(block1.Header); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.SetBlockHeight(1, block1Hash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}

	// Saved tip pretends to be at height 100 — far above what the
	// header index knows (only genesis + block1 = height 1).
	savedHash := wire.Hash256{0xaa, 0xbb, 0xcc, 0xdd}
	if err := db.SetChainState(&storage.ChainState{BestHash: savedHash, BestHeight: 100}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	if !cm.HasPendingRecovery() {
		t.Fatal("deferred: pendingRecovery should be true pre-reload")
	}

	cm.ReloadChainState()
	if _, h := cm.BestBlock(); h != 0 {
		t.Errorf("deferred: tip should stay at genesis while headers < saved height; got %d", h)
	}
	if !cm.HasPendingRecovery() {
		t.Error("deferred: pendingRecovery must remain true so later header batches retry")
	}
}

// TestConnectBlockOneGetUTXOPerInputW69d proves the W69d optimization:
// ConnectBlock must call the underlying UTXOSet's GetUTXO *exactly once*
// per non-coinbase input, by populating cachedView.cache up front and
// reading through it for CheckTransactionInputs, BIP68, and spentCoins.
//
// Before W69d those three passes each made their own GetUTXO calls, so a
// block with N non-coinbase inputs produced 3N–4N mutex acquisitions on
// UTXOSet.mu. The post-W69 profile showed connCh saturated at 1024/1024
// and the connector stuck at ~77 blk/hr; per-input mutex thrash inside
// ConnectBlock was the diagnosed bottleneck. This test guards against a
// future change silently re-introducing redundant fetches.
func TestConnectBlockOneGetUTXOPerInputW69d(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(db)

	cm := NewChainManager(ChainManagerConfig{
		Params:       params,
		HeaderIndex:  idx,
		ChainDB:      db,
		UTXOSet:      utxoSet,
		SigCacheSize: -1, // disable cache so it doesn't affect counts
	})

	// Pre-seed three mature non-coinbase UTXOs with OP_TRUE scriptPubKeys.
	// Using a synthetic prevTxid so we don't need to mine 100 blocks to
	// satisfy CoinbaseMaturity.
	prevTxid := wire.Hash256{0xfe, 0xed, 0xfa, 0xce}
	preOutpoints := []wire.OutPoint{
		{Hash: prevTxid, Index: 0},
		{Hash: prevTxid, Index: 1},
		{Hash: prevTxid, Index: 2},
	}
	for _, op := range preOutpoints {
		utxoSet.AddUTXO(op, &UTXOEntry{
			Amount:     1_000_000_000,
			PkScript:   []byte{0x51}, // OP_TRUE
			Height:     0,
			IsCoinbase: false,
		})
	}

	// Build a spending tx with three inputs (Sequence=MaxSequence disables
	// BIP68 locks but the BIP68 loop still runs — which is exactly what we
	// want to cover, since pre-W69d that loop called GetUTXO per input).
	spendTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: preOutpoints[0], Sequence: 0xFFFFFFFF},
			{PreviousOutPoint: preOutpoints[1], Sequence: 0xFFFFFFFF},
			{PreviousOutPoint: preOutpoints[2], Sequence: 0xFFFFFFFF},
		},
		TxOut: []*wire.TxOut{
			{Value: 2_500_000_000, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}

	block := createTestBlock(t, params, idx.Genesis(), []*wire.MsgTx{spendTx})
	blockHash := block.Header.BlockHash()

	if _, err := idx.AddHeader(block.Header); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}

	before := utxoSet.Stats()
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	after := utxoSet.Stats()

	// Expected: exactly one Hits-or-Misses bump per non-coinbase input.
	// Pre-W69d this would have been 3× (CheckTransactionInputs + BIP68 +
	// spentCoins), or 4× with the original cache-populate loop.
	nonCoinbaseInputs := uint64(len(spendTx.TxIn))
	delta := (after.Hits - before.Hits) + (after.Misses - before.Misses)
	if delta != nonCoinbaseInputs {
		t.Errorf("UTXOSet.GetUTXO called %d times; want %d (one per non-coinbase input). "+
			"A count of 2×, 3×, or 4× indicates a redundant fetch regression.",
			delta, nonCoinbaseInputs)
	}

	// Sanity: the block actually connected.
	if _, h := cm.BestBlock(); h != 1 {
		t.Fatalf("tip height = %d, want 1", h)
	}
}

// TestCachedUTXOViewHitBypassesFallbackW69d documents the cachedUTXOView
// contract that W69d leans on: a cache hit must not call the fallback
// UTXOView. If a future refactor breaks this invariant, the ConnectBlock
// hot path regresses back to the 3N–4N mutex-acquisition shape.
func TestCachedUTXOViewHitBypassesFallbackW69d(t *testing.T) {
	op := wire.OutPoint{Hash: wire.Hash256{0x01, 0x02, 0x03}, Index: 0}
	entry := &UTXOEntry{Amount: 100, PkScript: []byte{0x51}, Height: 10}

	fallback := &countingUTXOView{}
	cached := &cachedUTXOView{
		cache:    map[wire.OutPoint]*UTXOEntry{op: entry},
		fallback: fallback,
	}

	got := cached.GetUTXO(op)
	if got != entry {
		t.Errorf("cached.GetUTXO returned wrong entry")
	}
	if fallback.calls != 0 {
		t.Errorf("fallback called %d times on a cache hit; want 0", fallback.calls)
	}

	// Cache miss must fall through.
	missOP := wire.OutPoint{Hash: wire.Hash256{0x99}, Index: 0}
	cached.GetUTXO(missOP)
	if fallback.calls != 1 {
		t.Errorf("fallback called %d times on a cache miss; want 1", fallback.calls)
	}
}

// countingUTXOView is a test-only UTXOView that counts GetUTXO calls.
type countingUTXOView struct {
	calls int
}

func (c *countingUTXOView) GetUTXO(wire.OutPoint) *UTXOEntry {
	c.calls++
	return nil
}

// TestVerifyChainstateConsistencyClean covers the happy path: a freshly-
// connected chain has UTXO + undo data + block bodies for every block,
// so the consistency probe reports zero corruption and zero rollback.
//
// This is one of the three new tests added with the BUG-REPORT.md
// chainstate-corruption fixes (May 2 2026).  Same defensive recovery
// class as lunarblock c6fd8a0 / nimrod 4920988.
func TestVerifyChainstateConsistencyClean(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	prev := idx.Genesis()
	for i := 0; i < 5; i++ {
		blk := createTestBlock(t, params, prev, nil)
		hash := blk.Header.BlockHash()
		node, err := idx.AddHeader(blk.Header)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		if err := db.StoreBlock(hash, blk); err != nil {
			t.Fatalf("StoreBlock %d: %v", i, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock %d: %v", i, err)
		}
		prev = node
	}

	res := cm.VerifyChainstateConsistency(10)
	if res.CorruptionAtHeight != 0 {
		t.Errorf("expected no corruption, got at height %d", res.CorruptionAtHeight)
	}
	if res.RolledBackBlocks != 0 {
		t.Errorf("expected zero rollback, got %d blocks", res.RolledBackBlocks)
	}
	if res.RollbackFailed {
		t.Error("RollbackFailed should be false on a clean chain")
	}
	if res.TipBefore != 5 || res.TipAfter != 5 {
		t.Errorf("tip stayed at 5, got before=%d after=%d", res.TipBefore, res.TipAfter)
	}
	if res.BlocksProbed == 0 {
		t.Error("BlocksProbed should be > 0 on a non-empty chain")
	}
}

// TestVerifyChainstateConsistencyMissingBlockBody simulates the
// `block_in_storage=no` corruption pattern (lunarblock h=938344, May 1
// blockbrew h=938360): chain_tip points at a block whose body is no
// longer reachable from the block store.  The probe must detect the
// miss and roll back through that height.
func TestVerifyChainstateConsistencyMissingBlockBody(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	memDB := storage.NewMemDB()
	db := storage.NewChainDB(memDB)
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	prev := idx.Genesis()
	hashes := make([]wire.Hash256, 0, 5)
	for i := 0; i < 5; i++ {
		blk := createTestBlock(t, params, prev, nil)
		hash := blk.Header.BlockHash()
		node, err := idx.AddHeader(blk.Header)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		if err := db.StoreBlock(hash, blk); err != nil {
			t.Fatalf("StoreBlock %d: %v", i, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock %d: %v", i, err)
		}
		prev = node
		hashes = append(hashes, hash)
	}

	if _, h := cm.BestBlock(); h != 5 {
		t.Fatalf("setup failed: tip=%d, want 5", h)
	}

	// Simulate the corruption: delete the body for block 4 (the one
	// before tip).  This mimics the persisted-tip-ahead-of-body crash
	// window the BUG-REPORT.md atomic-barrier fix is closing.
	bodyKey := storage.MakeBlockDataKey(hashes[3])
	if err := memDB.Delete(bodyKey); err != nil {
		t.Fatalf("Delete body: %v", err)
	}

	res := cm.VerifyChainstateConsistency(10)
	if res.CorruptionAtHeight == 0 {
		t.Fatal("expected corruption to be reported, got none")
	}
	if res.RolledBackBlocks == 0 {
		t.Errorf("expected rollback to fire, got 0 blocks")
	}
	// The probe walks tip-side and finds the bad block (h=4). It then
	// peels via DisconnectBlock until tip<deepestBad. We deleted the
	// body at h=4, so disconnecting h=4 fails (DisconnectBlock needs
	// the block body to walk transactions in reverse). The probe halts
	// at tip=4 and surfaces RollbackFailed=true so the operator knows
	// to wipe chaindata/.
	if _, h := cm.BestBlock(); h >= 5 {
		t.Errorf("expected tip rolled back below the original tip 5, got %d", h)
	}
	if !res.RollbackFailed {
		t.Errorf("expected RollbackFailed=true when undo path is blocked by missing body")
	}
}

// TestVerifyChainstateConsistencyGenesisOnly: probe must be a no-op on
// a fresh chainstate.  Mirrors lunarblock spec/chainstate_corruption_spec.lua.
func TestVerifyChainstateConsistencyGenesisOnly(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	res := cm.VerifyChainstateConsistency(10)
	if res.CorruptionAtHeight != 0 || res.RolledBackBlocks != 0 || res.RollbackFailed {
		t.Errorf("genesis-only chain should produce a no-op probe; got %+v", res)
	}
	if res.BlocksProbed != 0 {
		t.Errorf("BlocksProbed should be 0 on a genesis-only chain, got %d", res.BlocksProbed)
	}
}

// TestAtomicShutdownFlushBatch validates that UTXO mutations and the
// chain-tip pointer can be written in a single atomic batch — the core
// invariant the BUG-REPORT.md fix #2 relies on for crash safety.
//
// The pre-fix shutdown path called utxoSet.Flush() then chainDB
// .SetChainState() as two separate writes; a SIGKILL between them left
// UTXOs persisted ahead of the tip, the same corruption pattern that
// produced the May 1 blockbrew h=938360 wedge.  This test demonstrates
// the FlushBatch + SetChainStateBatch primitives compose into one
// atomic Pebble batch.
func TestAtomicShutdownFlushBatch(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	memDB := storage.NewMemDB()
	db := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(db)
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
		UTXOSet:     utxoSet,
	})

	prev := idx.Genesis()
	for i := 0; i < 3; i++ {
		blk := createTestBlock(t, params, prev, nil)
		hash := blk.Header.BlockHash()
		node, err := idx.AddHeader(blk.Header)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		if err := db.StoreBlock(hash, blk); err != nil {
			t.Fatalf("StoreBlock %d: %v", i, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock %d: %v", i, err)
		}
		prev = node
	}

	bestHash, bestHeight := cm.BestBlock()
	if bestHeight != 3 {
		t.Fatalf("setup: bestHeight=%d, want 3", bestHeight)
	}

	// Build the atomic shutdown batch the same way main.go now does.
	batch := db.NewBatch()
	if err := utxoSet.FlushBatch(batch); err != nil {
		t.Fatalf("FlushBatch: %v", err)
	}
	db.SetChainStateBatch(batch, &storage.ChainState{
		BestHash:   bestHash,
		BestHeight: bestHeight,
	})
	if err := batch.Write(); err != nil {
		t.Fatalf("batch.Write: %v", err)
	}

	// After the batch commits, both the chain state and the UTXO set
	// must be readable from disk and consistent.
	state, err := db.GetChainState()
	if err != nil {
		t.Fatalf("GetChainState: %v", err)
	}
	if state.BestHeight != 3 || state.BestHash != bestHash {
		t.Errorf("chain state mismatch: got h=%d hash=%s", state.BestHeight, state.BestHash.String()[:16])
	}
}

// ============================================================================
// Pattern Y closure (2026-05-05) — submitblock side-branch acceptance.
//
// Cross-impl reference fix: rustoshi 68a422b. Corpus entry:
// tools/diff-test-corpus/regression/reorg-via-submitblock.
//
// Pre-fix: handleSubmitBlock unconditionally called ConnectBlock, which
// rejected any block whose parent was not the active tip with a generic
// "rejected" string — even though the parent was already in the header
// index. The reorg dispatcher could never fire for a competing fork because
// the first competing-branch block was dropped on arrival.
//
// Post-fix: ProcessSubmittedBlock decouples block storage (header index +
// chainDB.StoreBlock) from active-chain extension. Mirrors Bitcoin Core's
// AcceptBlock + ActivateBestChain split (validation.cpp).
// ============================================================================

// createSiblingBlock creates a block at the same height as a previously-mined
// sibling but with different content (extranonce in the coinbase scriptSig)
// so the resulting block hash differs. Used to exercise side-branch
// acceptance and reorg-via-submitblock paths.
func createSiblingBlock(t *testing.T, params *ChainParams, prevNode *BlockNode, extraNonce byte) *wire.MsgBlock {
	t.Helper()

	blockHeight := prevNode.Height + 1
	heightScript := encodeBIP34Height(blockHeight)
	// Append extraNonce so two siblings of the same parent produce distinct
	// coinbase scripts → distinct merkle roots → distinct block hashes.
	heightScript = append(heightScript, 0x00, extraNonce)

	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: heightScript,
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    CalcBlockSubsidy(blockHeight),
				PkScript: []byte{0x51}, // OP_TRUE
			},
		},
		LockTime: 0,
	}

	allTxs := []*wire.MsgTx{coinbase}
	txHashes := []wire.Hash256{coinbase.TxHash()}
	merkleRoot := CalcMerkleRoot(txHashes)

	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prevNode.Hash,
		MerkleRoot: merkleRoot,
		Timestamp:  prevNode.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}

	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		header.Nonce = i
		hash := header.BlockHash()
		if HashToBig(hash).Cmp(target) <= 0 {
			break
		}
	}

	return &wire.MsgBlock{
		Header:       header,
		Transactions: allTxs,
	}
}

// submitBlockToManager mimics what handleSubmitBlock in internal/rpc/methods.go
// does: AddHeader + StoreBlock + ProcessSubmittedBlock. Returns the result of
// ProcessSubmittedBlock so tests can assert on the three outcomes (nil /
// ErrSideBranchAccepted / other-error).
func submitBlockToManager(t *testing.T, cm *ChainManager, idx *HeaderIndex, db *storage.ChainDB, block *wire.MsgBlock) error {
	t.Helper()
	if _, err := idx.AddHeader(block.Header); err != nil {
		return err
	}
	if err := db.StoreBlock(block.Header.BlockHash(), block); err != nil {
		return err
	}
	return cm.ProcessSubmittedBlock(block)
}

// TestProcessSubmittedBlock_HappyPathExtendsActiveTip exercises the
// extend-tip path: a single block whose parent is the current active tip.
// ProcessSubmittedBlock must call ConnectBlock and return nil. The tip must
// advance.
func TestProcessSubmittedBlock_HappyPathExtendsActiveTip(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	hash := block.Header.BlockHash()

	if err := submitBlockToManager(t, cm, idx, db, block); err != nil {
		t.Fatalf("submit happy-path block: unexpected err=%v", err)
	}

	gotHash, gotHeight := cm.BestBlock()
	if gotHeight != 1 {
		t.Errorf("tip height = %d, want 1", gotHeight)
	}
	if gotHash != hash {
		t.Errorf("tip hash = %s, want %s", gotHash.String()[:16], hash.String()[:16])
	}
}

// TestProcessSubmittedBlock_SideBranchAcceptanceAtSameHeight exercises the
// Pattern Y bug: submit A1 (becomes tip), then submit B1 (sibling of A1,
// same parent = genesis, equal work). B1 must be stored, header indexed, and
// return ErrSideBranchAccepted. Tip must NOT flip.
//
// Pre-fix this test would fail at submit_b1: ConnectBlock rejected with a
// "block does not connect to tip during IBD" error.
func TestProcessSubmittedBlock_SideBranchAcceptanceAtSameHeight(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// A1 — becomes tip via happy path.
	a1 := createSiblingBlock(t, params, genesis, 0xA1)
	a1Hash := a1.Header.BlockHash()
	if err := submitBlockToManager(t, cm, idx, db, a1); err != nil {
		t.Fatalf("A1: unexpected err=%v", err)
	}
	if got, _ := cm.BestBlock(); got != a1Hash {
		t.Fatalf("after A1: tip = %s, want %s", got.String()[:16], a1Hash.String()[:16])
	}

	// B1 — sibling of A1. Same parent (genesis), distinct content. Must be
	// stored as side-branch with equal work; tip stays at A1.
	b1 := createSiblingBlock(t, params, genesis, 0xB1)
	b1Hash := b1.Header.BlockHash()
	if a1Hash == b1Hash {
		t.Fatal("createSiblingBlock did not produce distinct hashes")
	}

	err := submitBlockToManager(t, cm, idx, db, b1)
	if !errors.Is(err, ErrSideBranchAccepted) {
		t.Fatalf("B1: want ErrSideBranchAccepted, got err=%v", err)
	}

	// Tip MUST remain at A1 (equal work; tie-break to first-arrived).
	if got, h := cm.BestBlock(); got != a1Hash || h != 1 {
		t.Errorf("after B1 side-branch: tip = %s height = %d, want %s height=1",
			got.String()[:16], h, a1Hash.String()[:16])
	}

	// B1 must be in the header index (sibling under genesis).
	if idx.GetNode(b1Hash) == nil {
		t.Errorf("B1 not in header index after side-branch acceptance")
	}
	// B1's body must be persisted.
	if !db.HasBlock(b1Hash) {
		t.Errorf("B1 body not persisted after side-branch acceptance")
	}
}

// TestProcessSubmittedBlock_ReorgsToHeavierBranch exercises the full
// reorg-via-submitblock scenario from the corpus entry: submit A1, A2 (chain
// A becomes tip at height 2), then submit B1, B2 (stored as side-branch),
// then B3 (the heavier-tip block; triggers reorg from A2 to B3).
//
// Pre-fix this test would fail at submit_b1: ConnectBlock rejected with
// "rejected" because B1's parent (genesis) was not the active tip (A1).
//
// Post-fix: B1, B2 are stored as side-branch (ErrSideBranchAccepted); B3 is
// the heavier-work tip → ReorgTo fires → A1+A2 disconnected, B1+B2+B3
// connected, tip = B3 at height 3.
func TestProcessSubmittedBlock_ReorgsToHeavierBranch(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()

	// Chain A: A1 → A2.
	a1 := createSiblingBlock(t, params, genesis, 0xA1)
	if err := submitBlockToManager(t, cm, idx, db, a1); err != nil {
		t.Fatalf("A1: unexpected err=%v", err)
	}
	a1Node := idx.GetNode(a1.Header.BlockHash())
	a2 := createSiblingBlock(t, params, a1Node, 0xA2)
	a2Hash := a2.Header.BlockHash()
	if err := submitBlockToManager(t, cm, idx, db, a2); err != nil {
		t.Fatalf("A2: unexpected err=%v", err)
	}
	if got, h := cm.BestBlock(); got != a2Hash || h != 2 {
		t.Fatalf("after A1+A2: tip = %s height = %d, want %s height=2",
			got.String()[:16], h, a2Hash.String()[:16])
	}

	// Chain B: B1 → B2 → B3, all sharing genesis as fork point.
	b1 := createSiblingBlock(t, params, genesis, 0xB1)
	b1Hash := b1.Header.BlockHash()
	if err := submitBlockToManager(t, cm, idx, db, b1); !errors.Is(err, ErrSideBranchAccepted) {
		t.Fatalf("B1: want ErrSideBranchAccepted, got err=%v", err)
	}
	b1Node := idx.GetNode(b1Hash)
	if b1Node == nil {
		t.Fatal("B1 not in header index")
	}
	if got, _ := cm.BestBlock(); got != a2Hash {
		t.Errorf("after B1: tip moved unexpectedly to %s", got.String()[:16])
	}

	b2 := createSiblingBlock(t, params, b1Node, 0xB2)
	b2Hash := b2.Header.BlockHash()
	if err := submitBlockToManager(t, cm, idx, db, b2); !errors.Is(err, ErrSideBranchAccepted) {
		t.Fatalf("B2: want ErrSideBranchAccepted, got err=%v", err)
	}
	b2Node := idx.GetNode(b2Hash)
	if b2Node == nil {
		t.Fatal("B2 not in header index")
	}
	// At this point B-chain has equal work to A-chain (both height 2). Tip
	// stays at A2 (tie-break to first-arrived).
	if got, _ := cm.BestBlock(); got != a2Hash {
		t.Errorf("after B2 (equal work): tip = %s, want %s (tie-break)",
			got.String()[:16], a2Hash.String()[:16])
	}

	// B3 — height 3 → strictly heavier than A-chain → triggers reorg.
	b3 := createSiblingBlock(t, params, b2Node, 0xB3)
	b3Hash := b3.Header.BlockHash()
	if err := submitBlockToManager(t, cm, idx, db, b3); err != nil {
		t.Fatalf("B3: want nil (reorg accept), got err=%v", err)
	}

	// Tip flipped to B3 at height 3.
	if got, h := cm.BestBlock(); got != b3Hash || h != 3 {
		t.Errorf("after B3 reorg: tip = %s height = %d, want %s height=3",
			got.String()[:16], h, b3Hash.String()[:16])
	}

	// Both fork branches must remain in the header index — Core retains
	// the displaced A-chain blocks (BLOCK_HAVE_DATA) for potential future
	// reactivation via reconsiderblock or another reorg.
	if idx.GetNode(a1.Header.BlockHash()) == nil {
		t.Errorf("displaced A1 not in header index")
	}
	if idx.GetNode(a2Hash) == nil {
		t.Errorf("displaced A2 not in header index")
	}
}
