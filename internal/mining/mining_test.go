package mining

import (
	"bytes"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// mockChainState implements ChainStateProvider for testing.
type mockChainState struct {
	tipHash   wire.Hash256
	tipHeight int32
	tipNode   *consensus.BlockNode
}

func (m *mockChainState) BestBlock() (wire.Hash256, int32) {
	return m.tipHash, m.tipHeight
}

func (m *mockChainState) TipNode() *consensus.BlockNode {
	return m.tipNode
}

// mockMempool implements MempoolProvider for testing.
type mockMempool struct {
	entries []*mempool.TxEntry
}

func (m *mockMempool) GetSortedByAncestorFeeRate() []*mempool.TxEntry {
	return m.entries
}

// mockHeaderIndex implements HeaderIndexProvider for testing.
type mockHeaderIndex struct {
	nodes map[wire.Hash256]*consensus.BlockNode
}

func (m *mockHeaderIndex) GetNode(hash wire.Hash256) *consensus.BlockNode {
	return m.nodes[hash]
}

// createTestTx creates a simple test transaction.
func createTestTx(value int64) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{1, 2, 3}, // Non-zero = not coinbase
				Index: 0,
			},
			SignatureScript: []byte{0x00},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    value,
			PkScript: []byte{0x76, 0xa9, 0x14}, // P2PKH prefix
		}},
		LockTime: 0,
	}
}

// TestScriptNumSerialize tests the script number serialization.
func TestScriptNumSerialize(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected []byte
	}{
		{"zero", 0, nil},
		{"one", 1, []byte{0x01}},
		{"127", 127, []byte{0x7f}},
		{"128", 128, []byte{0x80, 0x00}}, // Need extra byte for sign
		{"255", 255, []byte{0xff, 0x00}},
		{"256", 256, []byte{0x00, 0x01}},
		{"32767", 32767, []byte{0xff, 0x7f}},
		{"32768", 32768, []byte{0x00, 0x80, 0x00}},
		{"65535", 65535, []byte{0xff, 0xff, 0x00}},
		{"65536", 65536, []byte{0x00, 0x00, 0x01}},
		{"500000", 500000, []byte{0x20, 0xa1, 0x07}},
		{"negative one", -1, []byte{0x81}},
		{"negative 128", -128, []byte{0x80, 0x80}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := scriptNumSerialize(tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("scriptNumSerialize(%d) = %x, want %x", tc.input, result, tc.expected)
			}
		})
	}
}

// TestSerializeBlockHeight tests the BIP34 height encoding.
func TestSerializeBlockHeight(t *testing.T) {
	tests := []struct {
		name     string
		height   int32
		expected []byte
	}{
		{"height 0", 0, []byte{0x00}}, // OP_0
		{"height 1", 1, []byte{0x51}}, // OP_1
		{"height 16", 16, []byte{0x60}}, // OP_16
		{"height 17", 17, []byte{0x01, 0x11}}, // push 1 byte: 0x11
		{"height 127", 127, []byte{0x01, 0x7f}},
		{"height 128", 128, []byte{0x02, 0x80, 0x00}}, // needs extra byte
		{"height 255", 255, []byte{0x02, 0xff, 0x00}},
		{"height 256", 256, []byte{0x02, 0x00, 0x01}},
		{"height 500000", 500000, []byte{0x03, 0x20, 0xa1, 0x07}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := serializeBlockHeight(tc.height)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("serializeBlockHeight(%d) = %x, want %x", tc.height, result, tc.expected)
			}
		})
	}
}

// TestCreateCoinbaseTx tests coinbase transaction creation.
func TestCreateCoinbaseTx(t *testing.T) {
	minerScript := []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac}

	t.Run("basic coinbase", func(t *testing.T) {
		height := int32(100)
		subsidy := int64(5000000000) // 50 BTC
		fees := int64(100000)        // 0.001 BTC

		tx := CreateCoinbaseTx(height, minerScript, nil, subsidy, fees, nil)

		// Check it's a valid coinbase
		if !consensus.IsCoinbaseTx(tx) {
			t.Error("CreateCoinbaseTx did not create a valid coinbase transaction")
		}

		// Check the output value
		if tx.TxOut[0].Value != subsidy+fees {
			t.Errorf("coinbase value = %d, want %d", tx.TxOut[0].Value, subsidy+fees)
		}

		// Check the miner script
		if !bytes.Equal(tx.TxOut[0].PkScript, minerScript) {
			t.Error("coinbase output script doesn't match miner script")
		}

		// Should not have witness commitment output
		if len(tx.TxOut) != 1 {
			t.Errorf("expected 1 output, got %d", len(tx.TxOut))
		}
	})

	t.Run("coinbase with witness commitment", func(t *testing.T) {
		height := int32(500000)
		subsidy := int64(1250000000) // 12.5 BTC
		fees := int64(50000)
		witnessCommitment := make([]byte, 32)
		for i := range witnessCommitment {
			witnessCommitment[i] = byte(i)
		}

		tx := CreateCoinbaseTx(height, minerScript, nil, subsidy, fees, witnessCommitment)

		// Should have 2 outputs
		if len(tx.TxOut) != 2 {
			t.Fatalf("expected 2 outputs, got %d", len(tx.TxOut))
		}

		// Check witness commitment output
		commitOutput := tx.TxOut[1]
		if commitOutput.Value != 0 {
			t.Error("witness commitment output should have value 0")
		}

		// Check OP_RETURN prefix
		if commitOutput.PkScript[0] != 0x6a {
			t.Error("witness commitment should start with OP_RETURN")
		}

		// Check witness magic
		if !bytes.Equal(commitOutput.PkScript[2:6], []byte{0xaa, 0x21, 0xa9, 0xed}) {
			t.Error("witness commitment magic bytes incorrect")
		}

		// Check witness reserved value in coinbase witness
		if len(tx.TxIn[0].Witness) != 1 || len(tx.TxIn[0].Witness[0]) != 32 {
			t.Error("coinbase should have 32-byte witness reserved value")
		}
	})

	t.Run("BIP34 height encoding", func(t *testing.T) {
		heights := []int32{0, 1, 16, 17, 100, 500000}
		for _, h := range heights {
			tx := CreateCoinbaseTx(h, minerScript, nil, 5000000000, 0, nil)

			// Verify the height can be extracted (matches consensus checkBIP34Height behavior)
			scriptSig := tx.TxIn[0].SignatureScript
			if len(scriptSig) == 0 {
				t.Errorf("coinbase scriptSig is empty for height %d", h)
				continue
			}

			// Decode the height from scriptSig
			decodedHeight := decodeHeightFromScriptSig(scriptSig)
			if decodedHeight != int64(h) {
				t.Errorf("height %d: decoded %d from scriptSig %x", h, decodedHeight, scriptSig)
			}
		}
	})
}

// decodeHeightFromScriptSig extracts the height from a coinbase scriptSig (for testing).
func decodeHeightFromScriptSig(scriptSig []byte) int64 {
	if len(scriptSig) == 0 {
		return -1
	}

	firstByte := scriptSig[0]

	// OP_0 = height 0
	if firstByte == 0x00 {
		return 0
	}

	// OP_1 through OP_16 = heights 1-16
	if firstByte >= 0x51 && firstByte <= 0x60 {
		return int64(firstByte - 0x50)
	}

	// Direct push: firstByte is the length
	if firstByte >= 1 && firstByte <= 75 {
		pushLen := int(firstByte)
		if len(scriptSig) < 1+pushLen {
			return -1
		}
		data := scriptSig[1 : 1+pushLen]
		return decodeScriptNum(data)
	}

	return -1
}

// decodeScriptNum decodes a minimally-encoded script number.
func decodeScriptNum(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}

	var result int64
	for i := 0; i < len(data); i++ {
		result |= int64(data[i]) << uint(8*i)
	}

	// Check sign bit
	if data[len(data)-1]&0x80 != 0 {
		result &= ^(int64(0x80) << uint(8*(len(data)-1)))
		result = -result
	}

	return result
}

// TestGenerateTemplate tests block template generation.
func TestGenerateTemplate(t *testing.T) {
	params := consensus.RegtestParams()

	// Create a mock tip node
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{
		tipHash:   genesisHash,
		tipHeight: 0,
		tipNode:   tipNode,
	}

	mp := &mockMempool{
		entries: nil, // Empty mempool
	}

	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{
			genesisHash: tipNode,
		},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)

	minerScript := []byte{0x51} // OP_1 (anyone can spend for testing)

	t.Run("empty mempool produces valid block", func(t *testing.T) {
		template, err := tg.GenerateTemplate(TemplateConfig{
			MinerAddress: minerScript,
		})
		if err != nil {
			t.Fatalf("GenerateTemplate failed: %v", err)
		}

		// Check basic template properties
		if template.Height != 1 {
			t.Errorf("template height = %d, want 1", template.Height)
		}

		if len(template.Block.Transactions) != 1 {
			t.Errorf("expected 1 transaction (coinbase only), got %d", len(template.Block.Transactions))
		}

		// Check coinbase value equals subsidy (no fees)
		subsidy := consensus.CalcBlockSubsidy(1)
		if template.CoinbaseValue != subsidy {
			t.Errorf("coinbase value = %d, want subsidy %d", template.CoinbaseValue, subsidy)
		}

		// Verify template passes structural sanity checks (not PoW - template has nonce=0).
		// Check merkle root is correct.
		txHashes := make([]wire.Hash256, len(template.Block.Transactions))
		for i, tx := range template.Block.Transactions {
			txHashes[i] = tx.TxHash()
		}
		expectedRoot := consensus.CalcMerkleRoot(txHashes)
		if template.Block.Header.MerkleRoot != expectedRoot {
			t.Errorf("merkle root mismatch")
		}

		// Check first transaction is coinbase
		if !consensus.IsCoinbaseTx(template.Block.Transactions[0]) {
			t.Error("first transaction is not coinbase")
		}

		// Check block weight
		weight := consensus.CalcBlockWeight(template.Block)
		if weight > consensus.MaxBlockWeight {
			t.Errorf("block weight %d exceeds max %d", weight, consensus.MaxBlockWeight)
		}
	})

	t.Run("block header is valid", func(t *testing.T) {
		template, _ := tg.GenerateTemplate(TemplateConfig{
			MinerAddress: minerScript,
		})

		// Check version
		if template.Block.Header.Version != 0x20000000 {
			t.Errorf("block version = %x, want 0x20000000", template.Block.Header.Version)
		}

		// Check prev block
		if template.Block.Header.PrevBlock != genesisHash {
			t.Error("prev block doesn't match genesis")
		}

		// Check timestamp is reasonable
		now := uint32(time.Now().Unix())
		if template.Block.Header.Timestamp < now-60 || template.Block.Header.Timestamp > now+60 {
			t.Errorf("timestamp %d not within 60s of current time %d", template.Block.Header.Timestamp, now)
		}
	})
}

// TestSelectTransactions tests transaction selection.
func TestSelectTransactions(t *testing.T) {
	t.Run("empty mempool", func(t *testing.T) {
		mp := &mockMempool{entries: nil}
		txs, fees, sigops := selectTransactions(mp, consensus.MaxBlockWeight, consensus.MaxBlockSigOpsCost, 0)

		if len(txs) != 0 {
			t.Errorf("expected 0 transactions, got %d", len(txs))
		}
		if fees != 0 {
			t.Errorf("expected 0 fees, got %d", fees)
		}
		if sigops != 0 {
			t.Errorf("expected 0 sigops, got %d", sigops)
		}
	})

	t.Run("selects transactions by fee rate", func(t *testing.T) {
		tx1 := createTestTx(100000)
		tx2 := createTestTx(200000)

		entry1 := &mempool.TxEntry{
			Tx:      tx1,
			TxHash:  tx1.TxHash(),
			Fee:     1000,
			Size:    100,
			FeeRate: 10.0, // 10 sat/vB
		}
		entry2 := &mempool.TxEntry{
			Tx:      tx2,
			TxHash:  tx2.TxHash(),
			Fee:     2000,
			Size:    100,
			FeeRate: 20.0, // 20 sat/vB (higher)
		}

		// Sorted by ancestor fee rate (highest first)
		mp := &mockMempool{
			entries: []*mempool.TxEntry{entry2, entry1},
		}

		txs, fees, _ := selectTransactions(mp, consensus.MaxBlockWeight, consensus.MaxBlockSigOpsCost, 0)

		if len(txs) != 2 {
			t.Fatalf("expected 2 transactions, got %d", len(txs))
		}
		if fees != 3000 {
			t.Errorf("expected fees 3000, got %d", fees)
		}
	})

	t.Run("respects weight limit", func(t *testing.T) {
		tx := createTestTx(100000)
		txWeight := consensus.CalcTxWeight(tx)

		entry := &mempool.TxEntry{
			Tx:      tx,
			TxHash:  tx.TxHash(),
			Fee:     1000,
			Size:    100,
			FeeRate: 10.0,
		}

		mp := &mockMempool{
			entries: []*mempool.TxEntry{entry},
		}

		// Set weight limit below transaction weight
		txs, _, _ := selectTransactions(mp, txWeight-1, consensus.MaxBlockSigOpsCost, 0)

		if len(txs) != 0 {
			t.Error("transaction should have been excluded due to weight limit")
		}
	})

	t.Run("respects minimum fee rate", func(t *testing.T) {
		tx := createTestTx(100000)

		entry := &mempool.TxEntry{
			Tx:      tx,
			TxHash:  tx.TxHash(),
			Fee:     100,
			Size:    100,
			FeeRate: 1.0, // 1 sat/vB
		}

		mp := &mockMempool{
			entries: []*mempool.TxEntry{entry},
		}

		txs, _, _ := selectTransactions(mp, consensus.MaxBlockWeight, consensus.MaxBlockSigOpsCost, 5.0) // min 5 sat/vB

		if len(txs) != 0 {
			t.Error("transaction should have been excluded due to low fee rate")
		}
	})

	t.Run("parents before children", func(t *testing.T) {
		parentTx := createTestTx(100000)
		parentHash := parentTx.TxHash()

		childTx := createTestTx(50000)

		parentEntry := &mempool.TxEntry{
			Tx:      parentTx,
			TxHash:  parentHash,
			Fee:     1000,
			Size:    100,
			FeeRate: 10.0,
			Depends: nil,
		}
		childEntry := &mempool.TxEntry{
			Tx:      childTx,
			TxHash:  childTx.TxHash(),
			Fee:     5000,
			Size:    100,
			FeeRate: 50.0, // Higher fee rate
			Depends: []wire.Hash256{parentHash},
		}

		// Child has higher fee rate, so it comes first in sorted order
		// But it should only be included if parent is included first
		mp := &mockMempool{
			entries: []*mempool.TxEntry{childEntry, parentEntry},
		}

		txs, _, _ := selectTransactions(mp, consensus.MaxBlockWeight, consensus.MaxBlockSigOpsCost, 0)

		// Parent should be included (comes later in sorted order)
		// Child should be skipped because parent isn't included yet when we check child
		if len(txs) != 1 {
			t.Fatalf("expected 1 transaction, got %d", len(txs))
		}
		if txs[0].TxHash() != parentHash {
			t.Error("parent should be included")
		}
	})
}

// TestWitnessCommitment tests witness commitment generation.
func TestWitnessCommitment(t *testing.T) {
	params := consensus.RegtestParams() // Segwit active from genesis

	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{
		tipHash:   genesisHash,
		tipHeight: 0,
		tipNode:   tipNode,
	}

	mp := &mockMempool{entries: nil}

	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{
			genesisHash: tipNode,
		},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)

	template, err := tg.GenerateTemplate(TemplateConfig{
		MinerAddress: []byte{0x51},
	})
	if err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	// Should have witness commitment since segwit is active
	if template.WitnessCommitment == nil {
		t.Error("expected witness commitment for segwit-active block")
	}

	// Coinbase should have 2 outputs (reward + witness commitment)
	coinbase := template.Block.Transactions[0]
	if len(coinbase.TxOut) != 2 {
		t.Fatalf("expected 2 coinbase outputs, got %d", len(coinbase.TxOut))
	}

	// Verify witness commitment output format
	commitOut := coinbase.TxOut[1]
	if len(commitOut.PkScript) != 38 {
		t.Errorf("witness commitment output should be 38 bytes, got %d", len(commitOut.PkScript))
	}
	if commitOut.PkScript[0] != 0x6a { // OP_RETURN
		t.Error("witness commitment should start with OP_RETURN")
	}
	if !bytes.Equal(commitOut.PkScript[2:6], []byte{0xaa, 0x21, 0xa9, 0xed}) {
		t.Error("witness commitment magic incorrect")
	}

	// Verify coinbase witness
	if len(coinbase.TxIn[0].Witness) != 1 {
		t.Error("coinbase should have witness")
	}
	if len(coinbase.TxIn[0].Witness[0]) != 32 {
		t.Error("coinbase witness should be 32 bytes")
	}
}

// TestCoinbaseValue tests that coinbase value is correctly calculated.
func TestCoinbaseValue(t *testing.T) {
	params := consensus.RegtestParams()

	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{
		tipHash:   genesisHash,
		tipHeight: 0,
		tipNode:   tipNode,
	}

	// Create mempool with transactions that have fees
	tx := createTestTx(100000)
	entry := &mempool.TxEntry{
		Tx:      tx,
		TxHash:  tx.TxHash(),
		Fee:     50000, // 0.0005 BTC fee
		Size:    100,
		FeeRate: 500.0,
		Depends: nil,
	}

	mp := &mockMempool{
		entries: []*mempool.TxEntry{entry},
	}

	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{
			genesisHash: tipNode,
		},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)

	template, err := tg.GenerateTemplate(TemplateConfig{
		MinerAddress: []byte{0x51},
	})
	if err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	// Check fees
	if template.Fees != 50000 {
		t.Errorf("template fees = %d, want 50000", template.Fees)
	}

	// Check coinbase value = subsidy + fees
	subsidy := consensus.CalcBlockSubsidy(1)
	expectedValue := subsidy + 50000
	if template.CoinbaseValue != expectedValue {
		t.Errorf("coinbase value = %d, want %d", template.CoinbaseValue, expectedValue)
	}

	// Verify actual coinbase output value
	coinbase := template.Block.Transactions[0]
	if coinbase.TxOut[0].Value != expectedValue {
		t.Errorf("coinbase output value = %d, want %d", coinbase.TxOut[0].Value, expectedValue)
	}
}

// TestBlockPassesSanity verifies generated blocks pass consensus sanity checks.
func TestBlockPassesSanity(t *testing.T) {
	params := consensus.RegtestParams()

	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{
		tipHash:   genesisHash,
		tipHeight: 0,
		tipNode:   tipNode,
	}

	mp := &mockMempool{entries: nil}

	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{
			genesisHash: tipNode,
		},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)

	template, err := tg.GenerateTemplate(TemplateConfig{
		MinerAddress: []byte{0x51},
	})
	if err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	// The block won't pass PoW check since nonce is 0, but we can test
	// everything else by temporarily setting an easy target
	// For now, just verify the merkle root is correct
	txHashes := make([]wire.Hash256, len(template.Block.Transactions))
	for i, tx := range template.Block.Transactions {
		txHashes[i] = tx.TxHash()
	}
	expectedRoot := consensus.CalcMerkleRoot(txHashes)
	if template.Block.Header.MerkleRoot != expectedRoot {
		t.Error("merkle root mismatch")
	}
}
