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
