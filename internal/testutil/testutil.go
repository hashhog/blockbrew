// Package testutil provides test helpers for blockbrew packages.
package testutil

import (
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// MustDecodeHex decodes a hex string and panics on error.
func MustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex string: " + err.Error())
	}
	return b
}

// MustParseHash parses a hash from display hex format and panics on error.
func MustParseHash(s string) wire.Hash256 {
	h, err := wire.NewHash256FromHex(s)
	if err != nil {
		panic("invalid hash string: " + err.Error())
	}
	return h
}

// TestChain holds all components for a test blockchain.
type TestChain struct {
	Params      *consensus.ChainParams
	ChainMgr    *consensus.ChainManager
	HeaderIndex *consensus.HeaderIndex
	ChainDB     *storage.ChainDB
	UTXOSet     *consensus.UTXOSet
	DB          storage.DB
}

// NewTestChain creates a new regtest chain with all components initialized.
// Uses an in-memory database for testing.
func NewTestChain(t *testing.T) *TestChain {
	t.Helper()

	params := consensus.RegtestParams()
	db := storage.NewMemDB()
	chainDB := storage.NewChainDB(db)
	headerIndex := consensus.NewHeaderIndex(params)
	utxoSet := consensus.NewUTXOSet(chainDB)

	// Store genesis block
	genesisHash := params.GenesisBlock.Header.BlockHash()
	err := chainDB.StoreBlock(genesisHash, params.GenesisBlock)
	if err != nil {
		t.Fatalf("failed to store genesis block: %v", err)
	}

	// Initialize chain manager
	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: headerIndex,
		ChainDB:     chainDB,
		UTXOSet:     utxoSet,
	})

	return &TestChain{
		Params:      params,
		ChainMgr:    chainMgr,
		HeaderIndex: headerIndex,
		ChainDB:     chainDB,
		UTXOSet:     utxoSet,
		DB:          db,
	}
}

// MineBlocks mines n blocks on top of the current chain tip.
// Returns the mined blocks.
func MineBlocks(t *testing.T, tc *TestChain, n int) []*wire.MsgBlock {
	t.Helper()

	blocks := make([]*wire.MsgBlock, 0, n)

	for i := 0; i < n; i++ {
		block := MineNextBlock(t, tc)
		blocks = append(blocks, block)
	}

	return blocks
}

// MineNextBlock mines a single block on top of the current chain tip.
func MineNextBlock(t *testing.T, tc *TestChain) *wire.MsgBlock {
	t.Helper()

	tipHash, tipHeight := tc.ChainMgr.BestBlock()
	tipNode := tc.HeaderIndex.GetNode(tipHash)
	if tipNode == nil {
		t.Fatal("tip node not found in header index")
	}

	newHeight := tipHeight + 1

	// Simple miner script (P2PKH to zeros for testing)
	minerScript := MustDecodeHex("76a914" + "0000000000000000000000000000000000000000" + "88ac")

	// Create coinbase transaction
	coinbaseTx := mining.CreateCoinbaseTx(
		newHeight,
		minerScript,
		nil,
		consensus.CalcBlockSubsidy(newHeight),
		0,
		nil,
	)

	// Create block header
	header := wire.BlockHeader{
		Version:   0x20000000,
		PrevBlock: tipHash,
		Timestamp: tipNode.Header.Timestamp + 600, // 10 minutes later
		Bits:      tc.Params.PowLimitBits,
		Nonce:     0,
	}

	// Compute merkle root
	txHashes := []wire.Hash256{coinbaseTx.TxHash()}
	header.MerkleRoot = consensus.CalcMerkleRoot(txHashes)

	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{coinbaseTx},
	}

	// Mine the block (find valid nonce)
	for nonce := uint32(0); ; nonce++ {
		block.Header.Nonce = nonce
		hash := block.Header.BlockHash()
		if consensus.CheckProofOfWork(hash, block.Header.Bits, tc.Params.PowLimit) == nil {
			break
		}
		if nonce == 0xFFFFFFFF {
			t.Fatal("failed to mine block (exhausted nonce space)")
		}
	}

	// Add header to index
	_, err := tc.HeaderIndex.AddHeader(block.Header)
	if err != nil {
		t.Fatalf("failed to add header to index: %v", err)
	}

	// Store block
	blockHash := block.Header.BlockHash()
	err = tc.ChainDB.StoreBlock(blockHash, block)
	if err != nil {
		t.Fatalf("failed to store block: %v", err)
	}

	// Connect block
	err = tc.ChainMgr.ConnectBlock(block)
	if err != nil {
		t.Fatalf("failed to connect block at height %d: %v", newHeight, err)
	}

	return block
}

// MakeP2PKHScript creates a P2PKH scriptPubKey from a 20-byte hash.
func MakeP2PKHScript(pubKeyHash []byte) []byte {
	if len(pubKeyHash) != 20 {
		panic("pubKeyHash must be 20 bytes")
	}
	script := make([]byte, 25)
	script[0] = 0x76 // OP_DUP
	script[1] = 0xa9 // OP_HASH160
	script[2] = 0x14 // Push 20 bytes
	copy(script[3:23], pubKeyHash)
	script[23] = 0x88 // OP_EQUALVERIFY
	script[24] = 0xac // OP_CHECKSIG
	return script
}

// MakeP2WPKHScript creates a P2WPKH scriptPubKey from a 20-byte hash.
func MakeP2WPKHScript(pubKeyHash []byte) []byte {
	if len(pubKeyHash) != 20 {
		panic("pubKeyHash must be 20 bytes")
	}
	script := make([]byte, 22)
	script[0] = 0x00 // OP_0
	script[1] = 0x14 // Push 20 bytes
	copy(script[2:22], pubKeyHash)
	return script
}

// MakeP2TRScript creates a P2TR scriptPubKey from a 32-byte x-only pubkey.
func MakeP2TRScript(pubKey []byte) []byte {
	if len(pubKey) != 32 {
		panic("pubKey must be 32 bytes")
	}
	script := make([]byte, 34)
	script[0] = 0x51 // OP_1
	script[1] = 0x20 // Push 32 bytes
	copy(script[2:34], pubKey)
	return script
}

// RandomHash returns a pseudo-random hash for testing.
// Uses a simple counter-based approach (not cryptographically random).
var hashCounter uint64

func RandomHash() wire.Hash256 {
	hashCounter++
	var h wire.Hash256
	h[0] = byte(hashCounter)
	h[1] = byte(hashCounter >> 8)
	h[2] = byte(hashCounter >> 16)
	h[3] = byte(hashCounter >> 24)
	h[4] = byte(hashCounter >> 32)
	h[5] = byte(hashCounter >> 40)
	h[6] = byte(hashCounter >> 48)
	h[7] = byte(hashCounter >> 56)
	return h
}

// CreateTestTx creates a simple test transaction.
func CreateTestTx(inputs []wire.OutPoint, outputValue int64, outputScript []byte) *wire.MsgTx {
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 0,
	}

	for _, in := range inputs {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: in,
			SignatureScript:  []byte{0x00}, // Empty signature for testing
			Sequence:         0xFFFFFFFF,
		})
	}

	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    outputValue,
		PkScript: outputScript,
	})

	return tx
}
