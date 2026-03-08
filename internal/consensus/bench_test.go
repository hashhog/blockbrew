package consensus

import (
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

func BenchmarkCalcMerkleRoot_10(b *testing.B) {
	hashes := make([]wire.Hash256, 10)
	for i := range hashes {
		hashes[i] = crypto.DoubleSHA256([]byte(fmt.Sprintf("tx%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(hashes)
	}
}

func BenchmarkCalcMerkleRoot_100(b *testing.B) {
	hashes := make([]wire.Hash256, 100)
	for i := range hashes {
		hashes[i] = crypto.DoubleSHA256([]byte(fmt.Sprintf("tx%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(hashes)
	}
}

func BenchmarkCalcMerkleRoot_1000(b *testing.B) {
	hashes := make([]wire.Hash256, 1000)
	for i := range hashes {
		hashes[i] = crypto.DoubleSHA256([]byte(fmt.Sprintf("tx%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(hashes)
	}
}

func BenchmarkCalcMerkleRoot_3000(b *testing.B) {
	hashes := make([]wire.Hash256, 3000)
	for i := range hashes {
		hashes[i] = crypto.DoubleSHA256([]byte(fmt.Sprintf("tx%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(hashes)
	}
}

func BenchmarkCompactToBig(b *testing.B) {
	bits := uint32(0x1d00ffff) // Genesis block difficulty
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompactToBig(bits)
	}
}

func BenchmarkBigToCompact(b *testing.B) {
	target := CompactToBig(0x1d00ffff)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BigToCompact(target)
	}
}

func BenchmarkCalcBlockSubsidy(b *testing.B) {
	heights := []int32{0, 100000, 210000, 420000, 630000, 840000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, h := range heights {
			CalcBlockSubsidy(h)
		}
	}
}

func BenchmarkCalcTxWeight(b *testing.B) {
	// Create a realistic transaction with 2 inputs and 2 outputs
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
				SignatureScript:  make([]byte, 107), // P2PKH sig + pubkey
				Sequence:         0xFFFFFFFF,
			},
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{2}, Index: 1},
				SignatureScript:  make([]byte, 107),
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50000000, PkScript: make([]byte, 25)}, // P2PKH
			{Value: 49990000, PkScript: make([]byte, 25)}, // P2PKH change
		},
		LockTime: 0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcTxWeight(tx)
	}
}

func BenchmarkCalcTxWeightSegwit(b *testing.B) {
	// Create a segwit transaction
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
				SignatureScript:  []byte{},
				Witness: [][]byte{
					make([]byte, 72), // Signature
					make([]byte, 33), // Compressed pubkey
				},
				Sequence: 0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50000000, PkScript: make([]byte, 22)}, // P2WPKH
			{Value: 49990000, PkScript: make([]byte, 22)}, // P2WPKH change
		},
		LockTime: 0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcTxWeight(tx)
	}
}

func BenchmarkCheckProofOfWork(b *testing.B) {
	params := RegtestParams()
	hash := wire.Hash256{0x00, 0x00, 0x00, 0x01} // Easy hash
	bits := params.PowLimitBits
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckProofOfWork(hash, bits, params.PowLimit)
	}
}

func BenchmarkCalcWork(b *testing.B) {
	bits := uint32(0x1d00ffff)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalcWork(bits)
	}
}

func BenchmarkCheckTransactionSanity(b *testing.B) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
				SignatureScript:  make([]byte, 100),
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50000000, PkScript: make([]byte, 25)},
		},
		LockTime: 0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckTransactionSanity(tx)
	}
}

func BenchmarkScriptCompression(b *testing.B) {
	scripts := [][]byte{
		// P2PKH
		{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac},
		// P2SH
		{0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x87},
		// P2WPKH
		{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	}

	b.Run("Compress", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range scripts {
				CompressScript(s)
			}
		}
	})

	compressed := make([][]byte, len(scripts))
	for i, s := range scripts {
		compressed[i] = CompressScript(s)
	}

	b.Run("Decompress", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, c := range compressed {
				DecompressScript(c)
			}
		}
	})
}

func BenchmarkUTXOEntrySerialization(b *testing.B) {
	entry := &UTXOEntry{
		Amount:     5000000000,
		PkScript:   make([]byte, 25), // P2PKH
		Height:     500000,
		IsCoinbase: false,
	}
	// Make it look like a real P2PKH
	entry.PkScript[0] = 0x76
	entry.PkScript[1] = 0xa9
	entry.PkScript[2] = 0x14
	entry.PkScript[23] = 0x88
	entry.PkScript[24] = 0xac

	b.Run("Serialize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			SerializeUTXOEntry(entry)
		}
	})

	data := SerializeUTXOEntry(entry)

	b.Run("Deserialize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = DeserializeUTXOEntry(data)
		}
	})
}

func BenchmarkHeaderIndexAdd(b *testing.B) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Create a chain of headers with valid PoW and proper timestamps
	prevHash := params.GenesisHash
	prevBits := params.PowLimitBits
	prevTimestamp := params.GenesisBlock.Header.Timestamp
	headers := make([]wire.BlockHeader, b.N)
	for i := 0; i < b.N; i++ {
		headers[i] = wire.BlockHeader{
			Version:    0x20000000,
			PrevBlock:  prevHash,
			MerkleRoot: wire.Hash256{byte(i)},
			Timestamp:  prevTimestamp + 600, // 10 minutes after previous
			Bits:       prevBits,
			Nonce:      0,
		}
		// Mine the header
		for nonce := uint32(0); ; nonce++ {
			headers[i].Nonce = nonce
			hash := headers[i].BlockHash()
			if CheckProofOfWork(hash, headers[i].Bits, params.PowLimit) == nil {
				break
			}
		}
		prevHash = headers[i].BlockHash()
		prevTimestamp = headers[i].Timestamp
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.AddHeader(headers[i])
	}
}

func BenchmarkBlockNodeGetAncestor(b *testing.B) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build a chain of 1000 blocks (need valid PoW and increasing timestamps)
	prevNode := idx.Genesis()
	prevHash := params.GenesisHash
	var lastNode *BlockNode = prevNode
	for i := 0; i < 1000; i++ {
		header := wire.BlockHeader{
			Version:    0x20000000,
			PrevBlock:  prevHash,
			MerkleRoot: wire.Hash256{byte(i)},
			Timestamp:  prevNode.Header.Timestamp + 600, // 10 minutes after parent
			Bits:       params.PowLimitBits,
			Nonce:      0,
		}
		// Mine the header
		for nonce := uint32(0); ; nonce++ {
			header.Nonce = nonce
			hash := header.BlockHash()
			if CheckProofOfWork(hash, header.Bits, params.PowLimit) == nil {
				break
			}
		}
		node, err := idx.AddHeader(header)
		if err != nil {
			b.Fatalf("AddHeader failed at %d: %v", i, err)
		}
		lastNode = node
		prevNode = node
		prevHash = header.BlockHash()
	}

	if lastNode == nil {
		b.Fatal("lastNode is nil")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Get ancestor at height 500
		lastNode.GetAncestor(500)
	}
}

func BenchmarkInMemoryUTXOView(b *testing.B) {
	view := NewInMemoryUTXOView()

	// Pre-populate with some UTXOs
	for i := 0; i < 1000; i++ {
		outpoint := wire.OutPoint{Hash: wire.Hash256{byte(i), byte(i >> 8)}, Index: 0}
		view.AddUTXO(outpoint, &UTXOEntry{
			Amount:     int64(i * 1000),
			PkScript:   make([]byte, 25),
			Height:     int32(i),
			IsCoinbase: false,
		})
	}

	b.Run("GetUTXO", func(b *testing.B) {
		outpoint := wire.OutPoint{Hash: wire.Hash256{0x00, 0x01}, Index: 0}
		for i := 0; i < b.N; i++ {
			view.GetUTXO(outpoint)
		}
	})

	b.Run("AddUTXO", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			outpoint := wire.OutPoint{Hash: wire.Hash256{byte(i), byte(i >> 8), 0xFF}, Index: uint32(i)}
			view.AddUTXO(outpoint, &UTXOEntry{
				Amount:     int64(i * 1000),
				PkScript:   make([]byte, 25),
				Height:     int32(i),
				IsCoinbase: false,
			})
		}
	})
}
