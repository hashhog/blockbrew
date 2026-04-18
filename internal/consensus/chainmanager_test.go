package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// encodeBIP34Height encodes a block height for BIP34 coinbase scriptSig.
func encodeBIP34Height(height int32) []byte {
	if height == 0 {
		return []byte{0x00} // OP_0
	}
	if height >= 1 && height <= 16 {
		return []byte{byte(script.OP_1 + height - 1)}
	}
	// Encode as minimally-encoded little-endian with push opcode
	// Need to handle negative (shouldn't happen for heights)
	var data []byte
	if height < 128 {
		data = []byte{byte(height)}
	} else if height < 32768 {
		data = []byte{byte(height), byte(height >> 8)}
	} else {
		data = []byte{byte(height), byte(height >> 8), byte(height >> 16)}
		// If high bit of last byte is set, need sign byte
		if data[len(data)-1]&0x80 != 0 {
			data = append(data, 0x00)
		}
	}
	// Prepend push length
	return append([]byte{byte(len(data))}, data...)
}

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
