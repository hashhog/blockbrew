package consensus

import (
	"math/big"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ChainParams defines the parameters for a Bitcoin network.
type ChainParams struct {
	Name                   string
	DefaultPort            uint16
	DNSSeeds               []string
	GenesisBlock           *wire.MsgBlock
	GenesisHash            wire.Hash256
	PowLimitBits           uint32   // Highest allowed target in compact form
	PowLimit               *big.Int // Highest allowed target as big.Int
	TargetTimespan         int64    // In seconds
	TargetSpacing          int64    // In seconds
	DifficultyAdjInterval  int64
	SubsidyHalvingInterval int32
	BIP34Height            int32
	BIP65Height            int32
	BIP66Height            int32
	CSVHeight              int32
	SegwitHeight           int32
	TaprootHeight          int32
	Bech32HRP              string
	PubKeyHashAddrID       byte
	ScriptHashAddrID       byte
	PrivateKeyID           byte // WIF prefix
	HDCoinType             uint32
	MinDiffReductionTime   bool // Testnet allows min-difficulty blocks after 20min gap
	PowNoRetargeting       bool // Regtest: never adjust difficulty
	EnforceBIP94           bool // Testnet4: use first block of period for retarget base
}

// mainnetPowLimit is the highest proof of work value a Bitcoin block can have
// for the main network: 00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
var mainnetPowLimit = func() *big.Int {
	limit := new(big.Int)
	limit.SetString("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return limit
}()

// regtestPowLimit is the highest proof of work value for regtest:
// 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
var regtestPowLimit = func() *big.Int {
	limit := new(big.Int)
	limit.SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return limit
}()

// mainnetParams holds the chain parameters for mainnet.
var mainnetParams *ChainParams

// testnetParams holds the chain parameters for testnet3.
var testnetParams *ChainParams

// regtestParams holds the chain parameters for regtest.
var regtestParams *ChainParams

// signetParams holds the chain parameters for signet.
var signetParams *ChainParams

// testnet4Params holds the chain parameters for testnet4.
var testnet4Params *ChainParams

// MainnetParams returns the chain parameters for mainnet.
func MainnetParams() *ChainParams {
	if mainnetParams != nil {
		return mainnetParams
	}

	genesisBlock := MainnetGenesisBlock()
	genesisHash := genesisBlock.Header.BlockHash()

	mainnetParams = &ChainParams{
		Name:        "mainnet",
		DefaultPort: 8333,
		DNSSeeds: []string{
			"seed.bitcoin.sipa.be",
			"dnsseed.bluematt.me",
			"dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
			"seed.bitcoinstats.com",
			"seed.bitcoin.jonasschnelli.ch",
			"seed.btc.petertodd.net",
			"seed.bitcoin.sprovoost.nl",
			"dnsseed.emzy.de",
			"seed.bitcoin.wiz.biz",
		},
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x1d00ffff,
		PowLimit:               mainnetPowLimit,
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: SubsidyHalvingInterval,
		BIP34Height:            227931,
		BIP65Height:            388381,
		BIP66Height:            363725,
		CSVHeight:              419328,
		SegwitHeight:           481824,
		TaprootHeight:          709632,
		Bech32HRP:              "bc",
		PubKeyHashAddrID:       0x00,
		ScriptHashAddrID:       0x05,
		PrivateKeyID:           0x80,
		HDCoinType:             0,
		MinDiffReductionTime:   false,
		PowNoRetargeting:       false,
		EnforceBIP94:           false,
	}
	return mainnetParams
}

// TestnetParams returns the chain parameters for testnet3.
func TestnetParams() *ChainParams {
	if testnetParams != nil {
		return testnetParams
	}

	genesisBlock := TestnetGenesisBlock()
	genesisHash := genesisBlock.Header.BlockHash()

	testnetParams = &ChainParams{
		Name:        "testnet3",
		DefaultPort: 18333,
		DNSSeeds: []string{
			"testnet-seed.bitcoin.jonasschnelli.ch",
			"seed.tbtc.petertodd.net",
			"seed.testnet.bitcoin.sprovoost.nl",
			"testnet-seed.bluematt.me",
		},
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x1d00ffff,
		PowLimit:               mainnetPowLimit,
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: SubsidyHalvingInterval,
		BIP34Height:            21111,
		BIP65Height:            581885,
		BIP66Height:            330776,
		CSVHeight:              770112,
		SegwitHeight:           834624,
		TaprootHeight:          0, // Active from genesis for testnet4
		Bech32HRP:              "tb",
		PubKeyHashAddrID:       0x6f,
		ScriptHashAddrID:       0xc4,
		PrivateKeyID:           0xef,
		HDCoinType:             1,
		MinDiffReductionTime:   true,
		PowNoRetargeting:       false,
		EnforceBIP94:           false,
	}
	return testnetParams
}

// RegtestParams returns the chain parameters for regtest.
func RegtestParams() *ChainParams {
	if regtestParams != nil {
		return regtestParams
	}

	genesisBlock := RegtestGenesisBlock()
	genesisHash := genesisBlock.Header.BlockHash()

	regtestParams = &ChainParams{
		Name:                   "regtest",
		DefaultPort:            18444,
		DNSSeeds:               nil, // No DNS seeds for regtest
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x207fffff, // Very easy mining
		PowLimit:               regtestPowLimit,
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: 150, // Faster halving for testing
		BIP34Height:            0,   // All active from genesis
		BIP65Height:            0,
		BIP66Height:            0,
		CSVHeight:              0,
		SegwitHeight:           0,
		TaprootHeight:          0,
		Bech32HRP:              "bcrt",
		PubKeyHashAddrID:       0x6f,
		ScriptHashAddrID:       0xc4,
		PrivateKeyID:           0xef,
		HDCoinType:             1,
		MinDiffReductionTime:   true,
		PowNoRetargeting:       true,
	}
	return regtestParams
}

// SignetParams returns the chain parameters for signet.
func SignetParams() *ChainParams {
	if signetParams != nil {
		return signetParams
	}

	genesisBlock := SignetGenesisBlock()
	genesisHash := genesisBlock.Header.BlockHash()

	signetParams = &ChainParams{
		Name:        "signet",
		DefaultPort: 38333,
		DNSSeeds: []string{
			"seed.signet.bitcoin.sprovoost.nl",
		},
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x1e0377ae,
		PowLimit:               mainnetPowLimit, // Same as mainnet
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: SubsidyHalvingInterval,
		BIP34Height:            1,
		BIP65Height:            1,
		BIP66Height:            1,
		CSVHeight:              1,
		SegwitHeight:           1,
		TaprootHeight:          0, // Active from genesis
		Bech32HRP:              "tb",
		PubKeyHashAddrID:       0x6f,
		ScriptHashAddrID:       0xc4,
		PrivateKeyID:           0xef,
		HDCoinType:             1,
		MinDiffReductionTime:   false,
		PowNoRetargeting:       false,
		EnforceBIP94:           false,
	}
	return signetParams
}

// Testnet4Params returns the chain parameters for testnet4 (BIP 94).
func Testnet4Params() *ChainParams {
	if testnet4Params != nil {
		return testnet4Params
	}

	genesisBlock := Testnet4GenesisBlock()
	genesisHash := genesisBlock.Header.BlockHash()

	testnet4Params = &ChainParams{
		Name:        "testnet4",
		DefaultPort: 48333,
		DNSSeeds: []string{
			"seed.testnet4.bitcoin.sprovoost.nl",
			"seed.testnet4.wiz.biz",
		},
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x1d00ffff,
		PowLimit:               mainnetPowLimit,
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: SubsidyHalvingInterval,
		BIP34Height:            1,  // All BIPs active from genesis
		BIP65Height:            1,
		BIP66Height:            1,
		CSVHeight:              1,
		SegwitHeight:           1,
		TaprootHeight:          1,
		Bech32HRP:              "tb",
		PubKeyHashAddrID:       0x6f,
		ScriptHashAddrID:       0xc4,
		PrivateKeyID:           0xef,
		HDCoinType:             1,
		MinDiffReductionTime:   true,
		PowNoRetargeting:       false,
		EnforceBIP94:           true,
	}
	return testnet4Params
}
