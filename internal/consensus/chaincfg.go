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
	// FixedSeeds is the curated last-resort bootstrap peer list, used only when
	// DNS seeding returns nothing (or is disabled) AND the address book is empty
	// for a reachable network — mirroring Bitcoin Core's vFixedSeeds
	// (kernel/chainparams.cpp:153, ConvertSeeds in net.cpp, and the
	// ThreadOpenConnections fixed-seed trigger at net.cpp:2607-2643).
	// Each entry is an "ip:port" string. Default-ON; only mainnet is populated
	// for this campaign. Regtest/test/signet/testnet4 leave this nil (no
	// fixed-seed fallback), matching Core clearing vFixedSeeds for regtest.
	FixedSeeds             []string
	GenesisBlock           *wire.MsgBlock
	GenesisHash            wire.Hash256
	PowLimitBits           uint32   // Highest allowed target in compact form
	PowLimit               *big.Int // Highest allowed target as big.Int
	TargetTimespan         int64    // In seconds
	TargetSpacing          int64    // In seconds
	DifficultyAdjInterval  int64
	SubsidyHalvingInterval int32
	BIP34Height            int32
	// BIP34Hash is the hash of the block at BIP34Height. Used by the BIP-30
	// short-circuit: once BIP34 is active and the block at BIP34Height on the
	// current chain matches this hash, BIP-30 duplicate-UTXO checking is skipped
	// (unique coinbase heights make duplicates structurally impossible).
	// Mirrors Bitcoin Core consensus/params.h BIP34Hash + validation.cpp:2460-2462.
	// Zero for networks where BIP34 is active from genesis (testnet4, regtest, signet).
	BIP34Hash              wire.Hash256
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

	// MinimumChainWork is the minimum cumulative chain work required to
	// consider a headers chain worth storing.  Mirrors Bitcoin Core's
	// Consensus::Params::nMinimumChainWork.  Used by HeadersSyncState to
	// determine when the PRESYNC phase has seen enough work to transition
	// to REDOWNLOAD.  Must be non-nil; use big.NewInt(0) for networks with
	// no effective threshold (e.g. regtest).
	MinimumChainWork *big.Int
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
		// FixedSeeds: curated last-resort bootstrap set of 40 Core-vetted
		// mainnet :8333 listeners, extracted verbatim from
		// bitcoin-core/contrib/seeds/nodes_main.txt (the makeseeds-filtered
		// live set that generates chainparamsseeds.h). Selected one-per-leading
		// -octet for AS/netgroup diversity (no two share a /8), maximizing
		// eclipse resistance for a tiny bootstrap set. Used only when DNS
		// seeding returns empty/fails and the address book is empty — see
		// PeerManager.addFixedSeeds (Core net.cpp:2607-2643 parity).
		FixedSeeds: []string{
			"2.121.116.198:8333",
			"3.86.179.235:8333",
			"4.2.51.251:8333",
			"5.2.23.226:8333",
			"12.11.29.34:8333",
			"14.49.142.41:8333",
			"18.27.125.103:8333",
			"23.93.18.82:8333",
			"24.16.202.74:8333",
			"27.83.109.113:8333",
			"31.41.23.249:8333",
			"34.65.45.157:8333",
			"35.78.97.86:8333",
			"37.15.61.236:8333",
			"38.52.3.192:8333",
			"40.160.1.232:8333",
			"44.223.26.178:8333",
			"45.19.130.200:8333",
			"46.126.216.3:8333",
			"47.90.137.13:8333",
			"50.4.123.66:8333",
			"51.154.0.142:8333",
			"52.182.185.242:8333",
			"60.241.1.72:8333",
			"62.34.57.141:8333",
			"63.247.147.166:8333",
			"64.23.97.128:8333",
			"65.94.134.253:8333",
			"66.35.84.14:8333",
			"67.4.139.122:8333",
			"68.61.69.53:8333",
			"69.4.94.226:8333",
			"70.44.20.24:8333",
			"71.56.178.136:8333",
			"72.88.192.74:8333",
			"73.42.33.255:8333",
			"74.48.195.218:8333",
			"75.80.3.4:8333",
			"76.124.35.108:8333",
			"77.38.72.37:8333",
		},
		GenesisBlock:           genesisBlock,
		GenesisHash:            genesisHash,
		PowLimitBits:           0x1d00ffff,
		PowLimit:               mainnetPowLimit,
		TargetTimespan:         TargetTimespan,
		TargetSpacing:          TargetSpacing,
		DifficultyAdjInterval:  DifficultyAdjustmentInterval,
		SubsidyHalvingInterval: SubsidyHalvingInterval,
		BIP34Height: 227931,
		// BIP34Hash: hash of mainnet block 227,931 — the block whose coinbase
		// first included the block height, confirming BIP34 activation.
		// Bitcoin Core kernel/chainparams.cpp:90
		// "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
		BIP34Hash: func() wire.Hash256 {
			h, _ := wire.NewHash256FromHex("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8")
			return h
		}(),
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

		// Minimum chain work for mainnet (Core kernel/chainparams.cpp:109).
		// "0000000000000000000000000000000000000001128750f82f4c366153a3a030"
		MinimumChainWork: func() *big.Int {
			n := new(big.Int)
			n.SetString("0000000000000000000000000000000000000001128750f82f4c366153a3a030", 16)
			return n
		}(),
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
		BIP34Height: 21111,
		// BIP34Hash: hash of testnet3 block 21,111.
		// Bitcoin Core kernel/chainparams.cpp:213
		// "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
		BIP34Hash: func() wire.Hash256 {
			h, _ := wire.NewHash256FromHex("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8")
			return h
		}(),
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

		// Assume-valid block hash for testnet3 (height 4842348)
		// Display: 000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4
		AssumeValidHash: wire.Hash256{
			0xf4, 0x67, 0x5b, 0x50, 0xa6, 0x2f, 0x7d, 0x98,
			0xf8, 0xf2, 0xfa, 0xc1, 0x7a, 0xe3, 0x0d, 0x13,
			0xa0, 0xe5, 0xb5, 0xb6, 0x5c, 0xac, 0x28, 0x0b,
			0x23, 0xe4, 0x61, 0x7a, 0x00, 0x00, 0x00, 0x00,
		},

		// No assumeUTXO data for testnet3 (deprecated)
		AssumeUTXO: nil,

		// Network magic
		NetworkMagic: [4]byte{0x0b, 0x11, 0x09, 0x07},

		// Minimum chain work for testnet3 (Core kernel/chainparams.cpp:232).
		// "0000000000000000000000000000000000000000000017dde1c649f3708d14b6"
		MinimumChainWork: func() *big.Int {
			n := new(big.Int)
			n.SetString("0000000000000000000000000000000000000000000017dde1c649f3708d14b6", 16)
			return n
		}(),
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

		// Regtest: no minimum chain work (accept any chain for testing).
		MinimumChainWork: big.NewInt(0),
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

		// Minimum chain work for signet (Core kernel/chainparams.cpp:423).
		// "00000000000000000000000000000000000000000000000000000b463ea0a4b8"
		MinimumChainWork: func() *big.Int {
			n := new(big.Int)
			n.SetString("00000000000000000000000000000000000000000000000000000b463ea0a4b8", 16)
			return n
		}(),
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

		// Minimum chain work for testnet4 (Core kernel/chainparams.cpp:332).
		// "0000000000000000000000000000000000000000000009a0fe15d0177d086304"
		MinimumChainWork: func() *big.Int {
			n := new(big.Int)
			n.SetString("0000000000000000000000000000000000000000000009a0fe15d0177d086304", 16)
			return n
		}(),
	}
	return testnet4Params
}
