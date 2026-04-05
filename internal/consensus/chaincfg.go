package consensus

import (
	"math/big"

	"github.com/hashhog/blockbrew/internal/script"
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

	// ScriptFlagExceptions maps block hashes to override script verification
	// flags. Bitcoin Core uses this to handle historical blocks that would fail
	// under current rules (e.g., BIP16 P2SH exception at block 170,060 on
	// mainnet, and one Taproot exception block).
	ScriptFlagExceptions map[wire.Hash256]script.ScriptFlags

	// BIP9 deployments tracked via version bits.
	Deployments []*BIP9Deployment

	// AssumeValidHash is the hash of the block below which script
	// verification is skipped during IBD (in internal/little-endian byte order).
	AssumeValidHash wire.Hash256

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

		// Script flag exceptions for historical blocks that violate current rules.
		// BIP16 exception: block 170,060 has a transaction that fails P2SH validation.
		// Taproot exception: one historical block violates taproot rules.
		ScriptFlagExceptions: func() map[wire.Hash256]script.ScriptFlags {
			m := make(map[wire.Hash256]script.ScriptFlags)
			// BIP16 exception (block 170,060) — skip all script flags
			bip16Ex, _ := wire.NewHash256FromHex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
			m[bip16Ex] = script.ScriptFlags(0) // SCRIPT_VERIFY_NONE
			// Taproot exception — allow P2SH + witness but not taproot
			taprootEx, _ := wire.NewHash256FromHex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
			m[taprootEx] = script.ScriptVerifyP2SH | script.ScriptVerifyWitness
			return m
		}(),

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

		// Assume-valid block hash for mainnet (height 938343)
		// Display: 00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac
		AssumeValidHash: wire.Hash256{
			0xac, 0xa5, 0x1b, 0xd5, 0xfa, 0x4b, 0x09, 0x8e,
			0x47, 0x7c, 0x17, 0x1d, 0xdc, 0xdc, 0xd8, 0x94,
			0x91, 0x4d, 0xd7, 0xd6, 0xeb, 0xcc, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

		// Script flag exceptions for testnet3 (BIP16 exception)
		ScriptFlagExceptions: func() map[wire.Hash256]script.ScriptFlags {
			m := make(map[wire.Hash256]script.ScriptFlags)
			bip16Ex, _ := wire.NewHash256FromHex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")
			m[bip16Ex] = script.ScriptFlags(0)
			return m
		}(),

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

		// Assume-valid block hash for testnet4 (height 123613)
		// Display: 0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a
		AssumeValidHash: wire.Hash256{
			0x8a, 0xcf, 0xf7, 0x0b, 0x17, 0x2c, 0xa8, 0xe9,
			0x93, 0x90, 0xb2, 0x79, 0x95, 0xe6, 0xf9, 0xf9,
			0xe6, 0x6a, 0x67, 0x85, 0x2e, 0x7e, 0xe2, 0x4e,
			0x1e, 0x8b, 0x36, 0x02, 0x00, 0x00, 0x00, 0x00,
		},

		// AssumeUTXO data for testnet4
		AssumeUTXO: &Testnet4AssumeUTXOParams,

		// Network magic
		NetworkMagic: [4]byte{0x1c, 0x16, 0x3f, 0x28},
	}
	return testnet4Params
}
