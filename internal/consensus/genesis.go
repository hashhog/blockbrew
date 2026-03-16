package consensus

import (
	"encoding/hex"

	"github.com/hashhog/blockbrew/internal/wire"
)

// genesisCoinbaseTx creates the coinbase transaction for the mainnet genesis block.
// This is the famous "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks" message.
func genesisCoinbaseTx() *wire.MsgTx {
	// The coinbase scriptSig containing the famous Times headline
	// 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73
	scriptSig, _ := hex.DecodeString("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73")

	// Satoshi's public key + OP_CHECKSIG
	// 4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
	pkScript, _ := hex.DecodeString("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")

	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{}, // All zeros
					Index: 0xFFFFFFFF,      // Coinbase marker
				},
				SignatureScript: scriptSig,
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    50 * SatoshiPerBitcoin, // 50 BTC
				PkScript: pkScript,
			},
		},
		LockTime: 0,
	}
}

// MainnetGenesisBlock returns the genesis block for the Bitcoin mainnet.
// Block hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
func MainnetGenesisBlock() *wire.MsgBlock {
	coinbaseTx := genesisCoinbaseTx()

	// MerkleRoot: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
	merkleRoot, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{}, // All zeros
			MerkleRoot: merkleRoot,
			Timestamp:  1231006505, // 2009-01-03 18:15:05 UTC
			Bits:       0x1d00ffff,
			Nonce:      2083236893,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
}

// testnetGenesisCoinbaseTx creates the coinbase transaction for testnet genesis.
// Uses the same format as mainnet.
func testnetGenesisCoinbaseTx() *wire.MsgTx {
	return genesisCoinbaseTx()
}

// TestnetGenesisBlock returns the genesis block for Bitcoin testnet3.
// Block hash: 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
func TestnetGenesisBlock() *wire.MsgBlock {
	coinbaseTx := testnetGenesisCoinbaseTx()

	// Same merkle root as mainnet (same coinbase tx)
	merkleRoot, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{}, // All zeros
			MerkleRoot: merkleRoot,
			Timestamp:  1296688602, // 2011-02-02 23:16:42 UTC
			Bits:       0x1d00ffff,
			Nonce:      414098458,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
}

// regtestGenesisCoinbaseTx creates the coinbase transaction for regtest genesis.
func regtestGenesisCoinbaseTx() *wire.MsgTx {
	return genesisCoinbaseTx()
}

// RegtestGenesisBlock returns the genesis block for regtest.
// Block hash: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
func RegtestGenesisBlock() *wire.MsgBlock {
	coinbaseTx := regtestGenesisCoinbaseTx()

	// Same merkle root as mainnet (same coinbase tx)
	merkleRoot, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{}, // All zeros
			MerkleRoot: merkleRoot,
			Timestamp:  1296688602, // Same as testnet
			Bits:       0x207fffff, // Very easy difficulty
			Nonce:      2,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
}

// signetGenesisCoinbaseTx creates the coinbase transaction for signet genesis.
func signetGenesisCoinbaseTx() *wire.MsgTx {
	return genesisCoinbaseTx()
}

// SignetGenesisBlock returns the genesis block for signet.
// Block hash: 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
func SignetGenesisBlock() *wire.MsgBlock {
	coinbaseTx := signetGenesisCoinbaseTx()

	// Same merkle root as mainnet (same coinbase tx)
	merkleRoot, _ := wire.NewHash256FromHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{}, // All zeros
			MerkleRoot: merkleRoot,
			Timestamp:  1598918400, // 2020-09-01 00:00:00 UTC
			Bits:       0x1e0377ae,
			Nonce:      52613770,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
}

// testnet4GenesisCoinbaseTx creates the coinbase transaction for testnet4 genesis.
// Testnet4 uses a different message and output script than mainnet.
// Message: "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
// Output script: <32 zero bytes> OP_CHECKSIG
func testnet4GenesisCoinbaseTx() *wire.MsgTx {
	// The coinbase scriptSig: 0x04ffff001d0104 + len + "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
	// Built using the same formula as mainnet: << 486604799 << CScriptNum(4) << message
	// 486604799 in little-endian with push opcode = 04 ffff001d
	// CScriptNum(4) = 01 04
	// Message length = 79 bytes = 0x4f
	scriptSig, _ := hex.DecodeString("04ffff001d01044f30332f4d61792f32303234203030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065")

	// Output script: <push 32 bytes of zeros> OP_CHECKSIG
	// 0x20 (push 32 bytes) + 32 zeros + 0xac (OP_CHECKSIG)
	pkScript, _ := hex.DecodeString("200000000000000000000000000000000000000000000000000000000000000000ac")

	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{}, // All zeros
					Index: 0xFFFFFFFF,      // Coinbase marker
				},
				SignatureScript: scriptSig,
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    50 * SatoshiPerBitcoin, // 50 BTC
				PkScript: pkScript,
			},
		},
		LockTime: 0,
	}
}

// Testnet4GenesisBlock returns the genesis block for testnet4 (BIP 94).
// Block hash: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
// Merkle root: 7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e
func Testnet4GenesisBlock() *wire.MsgBlock {
	coinbaseTx := testnet4GenesisCoinbaseTx()

	// Merkle root for testnet4
	merkleRoot, _ := wire.NewHash256FromHex("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e")

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{}, // All zeros
			MerkleRoot: merkleRoot,
			Timestamp:  1714777860, // 2024-05-03 23:11:00 UTC
			Bits:       0x1d00ffff,
			Nonce:      393743547,
		},
		Transactions: []*wire.MsgTx{coinbaseTx},
	}
}
