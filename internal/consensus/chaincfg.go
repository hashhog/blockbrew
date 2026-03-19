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

	// BIP9 deployments tracked via version bits.
	Deployments []*BIP9Deployment

	// AssumeUTXO parameters for snapshot-based sync.
	AssumeUTXO *AssumeUTXOParams

	// NetworkMagic is the 4-byte message start bytes for this network.
	NetworkMagic [4]byte
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

		// BIP9 deployments - mainnet uses height-based activation (buried deployments)
		// These are historical for reference; actual activation uses hardcoded heights.
		Deployments: []*BIP9Deployment{
			// DEPLOYMENT_TESTDUMMY - only used for testing BIP9 mechanics
			{
				Name:                "testdummy",
				Bit:                 28,
				StartTime:           NeverActive,
				Timeout:             NoTimeout,
				MinActivationHeight: 0,
				Period:              2016,
				Threshold:           1815, // 90%
			},
		},

		// AssumeUTXO snapshot data
		AssumeUTXO: &MainnetAssumeUTXOParams,

		// Network magic (message start bytes)
		NetworkMagic: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
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

		// BIP9 deployments for testnet3
		Deployments: []*BIP9Deployment{
			{
				Name:                "testdummy",
				Bit:                 28,
				StartTime:           NeverActive,
				Timeout:             NoTimeout,
				MinActivationHeight: 0,
				Period:              2016,
				Threshold:           1512, // 75%
			},
		},

		// No assumeUTXO data for testnet3 (deprecated)
		AssumeUTXO: nil,

		// Network magic
		NetworkMagic: [4]byte{0x0b, 0x11, 0x09, 0x07},
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

		// BIP9 deployments for regtest - always active for easy testing
		Deployments: []*BIP9Deployment{
			{
				Name:                "testdummy",
				Bit:                 28,
				StartTime:           AlwaysActive, // Always active on regtest
				Timeout:             NoTimeout,
				MinActivationHeight: 0,
				Period:              144, // Shorter period for regtest
				Threshold:           108, // 75%
			},
		},

		// No assumeUTXO data for regtest (create your own snapshots)
		AssumeUTXO: nil,

		// Network magic
		NetworkMagic: [4]byte{0xfa, 0xbf, 0xb5, 0xda},
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

		// BIP9 deployments for signet
		Deployments: []*BIP9Deployment{
			{
				Name:                "testdummy",
				Bit:                 28,
				StartTime:           NeverActive,
				Timeout:             NoTimeout,
				MinActivationHeight: 0,
				Period:              2016,
				Threshold:           1815, // 90%
			},
		},

		// No assumeUTXO data for signet
		AssumeUTXO: nil,

		// Network magic
		NetworkMagic: [4]byte{0x0a, 0x03, 0xcf, 0x40},
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

		// BIP9 deployments for testnet4
		Deployments: []*BIP9Deployment{
			{
				Name:                "testdummy",
				Bit:                 28,
				StartTime:           NeverActive,
				Timeout:             NoTimeout,
				MinActivationHeight: 0,
				Period:              2016,
				Threshold:           1512, // 75%
			},
		},

		// AssumeUTXO data for testnet4
		AssumeUTXO: &Testnet4AssumeUTXOParams,

		// Network magic
		NetworkMagic: [4]byte{0x1c, 0x16, 0x3f, 0x28},
	}
	return testnet4Params
}
