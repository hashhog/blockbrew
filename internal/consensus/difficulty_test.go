package consensus

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestCompactToBigRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		compact uint32
	}{
		{"genesis difficulty", 0x1d00ffff},
		{"high difficulty", 0x170bdd6f},
		{"regtest difficulty", 0x207fffff},
		{"zero mantissa", 0x03000000},
		{"small exponent", 0x02008000},
		{"one byte target", 0x01003456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			big := CompactToBig(tt.compact)
			result := BigToCompact(big)

			// Normalize by converting back and comparing the resulting big.Int values
			// since there can be multiple compact representations of the same value
			bigResult := CompactToBig(result)
			if big.Cmp(bigResult) != 0 {
				t.Errorf("round trip failed: input=%x, big=%s, output=%x, bigOutput=%s",
					tt.compact, big.String(), result, bigResult.String())
			}
		})
	}
}

func TestCompactToBigKnownValues(t *testing.T) {
	tests := []struct {
		name     string
		compact  uint32
		expected string // hex string of expected big.Int
	}{
		{
			name:     "genesis target 0x1d00ffff",
			compact:  0x1d00ffff,
			expected: "00000000ffff0000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "regtest target 0x207fffff",
			compact:  0x207fffff,
			expected: "7fffff0000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompactToBig(tt.compact)
			expected := new(big.Int)
			expected.SetString(tt.expected, 16)

			if result.Cmp(expected) != 0 {
				t.Errorf("CompactToBig(%x) = %s, want %s",
					tt.compact, result.Text(16), expected.Text(16))
			}
		})
	}
}

func TestBigToCompact(t *testing.T) {
	tests := []struct {
		name     string
		input    string // hex string
		expected uint32
	}{
		{
			name:     "genesis target",
			input:    "00000000ffff0000000000000000000000000000000000000000000000000000",
			expected: 0x1d00ffff,
		},
		{
			name:     "regtest target",
			input:    "7fffff0000000000000000000000000000000000000000000000000000000000",
			expected: 0x207fffff,
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := new(big.Int)
			n.SetString(tt.input, 16)
			result := BigToCompact(n)

			if result != tt.expected {
				t.Errorf("BigToCompact(%s) = %x, want %x",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestCalcBlockSubsidy(t *testing.T) {
	tests := []struct {
		height   int32
		expected int64
	}{
		{0, 5000000000},        // Genesis: 50 BTC
		{1, 5000000000},        // Block 1: 50 BTC
		{209999, 5000000000},   // Last block before first halving
		{210000, 2500000000},   // First halving: 25 BTC
		{419999, 2500000000},   // Last block before second halving
		{420000, 1250000000},   // Second halving: 12.5 BTC
		{630000, 625000000},    // Third halving: 6.25 BTC
		{840000, 312500000},    // Fourth halving: 3.125 BTC
		{6720000, 1},           // 32nd halving: 1 satoshi (5000000000 >> 32 = 1)
		{6719999, 2},           // Just before: 2 satoshis (halving 31: 5000000000 >> 31 = 2)
		{6930000, 0},           // 33rd halving: 0 (5000000000 >> 33 = 0)
		{13440000, 0},          // 64th halving: 0
		{100000000, 0},         // Far future: still 0
	}

	for _, tt := range tests {
		result := CalcBlockSubsidy(tt.height)
		if result != tt.expected {
			t.Errorf("CalcBlockSubsidy(%d) = %d, want %d",
				tt.height, result, tt.expected)
		}
	}
}

// TestCalcBlockSubsidyRegtestInterval verifies that CalcBlockSubsidyForInterval
// uses the caller-supplied halving interval, not the hardcoded mainnet 210000.
// Specifically, the regtest halving interval is 150 (Core kernel/chainparams.cpp:535),
// so subsidy must halve at height 150, not at height 210000.
//
// This is the unit-level evidence for Finding 6C: CalcBlockSubsidy always uses
// SubsidyHalvingInterval=210000, whereas CalcBlockSubsidyForInterval (and the
// now-fixed ConnectBlock call) uses the network-aware value from ChainParams.
func TestCalcBlockSubsidyRegtestInterval(t *testing.T) {
	const regtestInterval = 150 // RegtestParams().SubsidyHalvingInterval

	tests := []struct {
		height      int32
		wantSubsidy int64  // expected with regtestInterval=150
		wrongSubsidy int64 // what the mainnet interval (210000) would compute
	}{
		// height < 150: both intervals agree (no halving has occurred yet).
		{1, 5_000_000_000, 5_000_000_000},
		{149, 5_000_000_000, 5_000_000_000},
		// height == 150: first halving with regtestInterval; mainnet hasn't halved.
		{150, 2_500_000_000, 5_000_000_000},
		{151, 2_500_000_000, 5_000_000_000},
		// height == 300: second halving with regtestInterval; mainnet still hasn't halved.
		{300, 1_250_000_000, 5_000_000_000},
	}
	for _, tt := range tests {
		// The correct (network-aware) call.
		got := CalcBlockSubsidyForInterval(tt.height, regtestInterval)
		if got != tt.wantSubsidy {
			t.Errorf("CalcBlockSubsidyForInterval(%d, %d) = %d, want %d",
				tt.height, regtestInterval, got, tt.wantSubsidy)
		}
		// The old (buggy) call that hardcodes 210000.
		wrong := CalcBlockSubsidy(tt.height)
		if wrong != tt.wrongSubsidy {
			t.Errorf("CalcBlockSubsidy(%d) [mainnet] = %d, want %d (confirming bug-side value)",
				tt.height, wrong, tt.wrongSubsidy)
		}
	}
}

func TestMainnetGenesisBlockHash(t *testing.T) {
	block := MainnetGenesisBlock()
	hash := block.Header.BlockHash()

	// Expected: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
	expected, err := wire.NewHash256FromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	if err != nil {
		t.Fatalf("failed to parse expected hash: %v", err)
	}

	if hash != expected {
		t.Errorf("mainnet genesis hash = %s, want %s", hash.String(), expected.String())
	}
}

func TestTestnetGenesisBlockHash(t *testing.T) {
	block := TestnetGenesisBlock()
	hash := block.Header.BlockHash()

	// Expected: 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
	expected, err := wire.NewHash256FromHex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
	if err != nil {
		t.Fatalf("failed to parse expected hash: %v", err)
	}

	if hash != expected {
		t.Errorf("testnet genesis hash = %s, want %s", hash.String(), expected.String())
	}
}

func TestRegtestGenesisBlockHash(t *testing.T) {
	block := RegtestGenesisBlock()
	hash := block.Header.BlockHash()

	// Expected: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
	expected, err := wire.NewHash256FromHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
	if err != nil {
		t.Fatalf("failed to parse expected hash: %v", err)
	}

	if hash != expected {
		t.Errorf("regtest genesis hash = %s, want %s", hash.String(), expected.String())
	}
}

func TestGenesisBlockProofOfWork(t *testing.T) {
	tests := []struct {
		name   string
		block  *wire.MsgBlock
		limit  *big.Int
	}{
		{"mainnet", MainnetGenesisBlock(), MainnetParams().PowLimit},
		{"testnet", TestnetGenesisBlock(), TestnetParams().PowLimit},
		{"regtest", RegtestGenesisBlock(), RegtestParams().PowLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.block.Header.BlockHash()
			err := CheckProofOfWork(hash, tt.block.Header.Bits, tt.limit)
			if err != nil {
				t.Errorf("genesis block failed proof of work check: %v", err)
			}
		})
	}
}

func TestCheckProofOfWorkFailure(t *testing.T) {
	// Create a hash that's too high (all 0xff)
	var badHash wire.Hash256
	for i := range badHash {
		badHash[i] = 0xff
	}

	err := CheckProofOfWork(badHash, 0x1d00ffff, MainnetParams().PowLimit)
	if err != ErrDifficultyTooLow {
		t.Errorf("expected ErrDifficultyTooLow, got %v", err)
	}
}

func TestCalcNextRequiredDifficulty(t *testing.T) {
	params := MainnetParams()

	// Use a higher difficulty target (not at powLimit) for testing target increases
	// 0x1c00ffff represents a higher difficulty than genesis
	higherDiffBits := uint32(0x1c00ffff)

	tests := []struct {
		name           string
		prevBits       uint32
		firstTimestamp int64
		lastTimestamp  int64
		expected       uint32
	}{
		{
			name:           "exact target timespan",
			prevBits:       0x1d00ffff,
			firstTimestamp: 0,
			lastTimestamp:  TargetTimespan, // 2 weeks exactly
			expected:       0x1d00ffff,     // No change
		},
		{
			name:           "double timespan (halve difficulty) - clamped at powLimit",
			prevBits:       0x1d00ffff, // Already at powLimit
			firstTimestamp: 0,
			lastTimestamp:  TargetTimespan * 2, // 4 weeks
			expected:       0x1d00ffff,         // Clamped at powLimit
		},
		{
			name:           "double timespan from higher difficulty",
			prevBits:       higherDiffBits,
			firstTimestamp: 0,
			lastTimestamp:  TargetTimespan * 2, // 4 weeks
			expected:       0x1c01fffe,         // Target doubles (difficulty halves)
		},
		{
			name:           "half timespan (double difficulty)",
			prevBits:       0x1d00ffff,
			firstTimestamp: 0,
			lastTimestamp:  TargetTimespan / 2, // 1 week
			expected:       0x1c7fff80,         // Target halves
		},
		{
			name:           "minimum clamping (blocks too fast)",
			prevBits:       0x1d00ffff,
			firstTimestamp: 0,
			lastTimestamp:  1, // Almost instant
			expected:       0x1c3fffc0, // Clamped to 4x difficulty increase
		},
		{
			name:           "maximum clamping from higher difficulty",
			prevBits:       higherDiffBits,
			firstTimestamp: 0,
			lastTimestamp:  TargetTimespan * 10, // 20 weeks (clamped to 4x)
			expected:       0x1c03fffc,          // 4x target increase (clamped)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalcNextRequiredDifficulty(params, tt.prevBits, tt.firstTimestamp, tt.lastTimestamp)

			// Compare the resulting targets since compact encoding can vary
			resultTarget := CompactToBig(result)
			expectedTarget := CompactToBig(tt.expected)

			// Allow small rounding differences (within 0.1%)
			diff := new(big.Int).Sub(resultTarget, expectedTarget)
			diff.Abs(diff)
			tolerance := new(big.Int).Div(expectedTarget, big.NewInt(1000))

			if diff.Cmp(tolerance) > 0 {
				t.Errorf("CalcNextRequiredDifficulty() = %x (target %s), want %x (target %s)",
					result, resultTarget.Text(16), tt.expected, expectedTarget.Text(16))
			}
		})
	}
}

func TestIsMinDifficultyBlock(t *testing.T) {
	tests := []struct {
		name              string
		params            *ChainParams
		blockTimestamp    int64
		prevTimestamp     int64
		expectedMinDiff   bool
	}{
		{
			name:            "mainnet never uses min diff",
			params:          MainnetParams(),
			blockTimestamp:  1000000,
			prevTimestamp:   0,
			expectedMinDiff: false,
		},
		{
			name:            "testnet block on time",
			params:          TestnetParams(),
			blockTimestamp:  600, // 10 minutes
			prevTimestamp:   0,
			expectedMinDiff: false,
		},
		{
			name:            "testnet block 20 minutes late",
			params:          TestnetParams(),
			blockTimestamp:  1200, // 20 minutes
			prevTimestamp:   0,
			expectedMinDiff: false, // Exactly 20 min doesn't trigger
		},
		{
			name:            "testnet block over 20 minutes late",
			params:          TestnetParams(),
			blockTimestamp:  1201, // 20 min + 1 sec
			prevTimestamp:   0,
			expectedMinDiff: true,
		},
		{
			name:            "regtest over 20 minutes",
			params:          RegtestParams(),
			blockTimestamp:  1201,
			prevTimestamp:   0,
			expectedMinDiff: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMinDifficultyBlock(tt.params, tt.blockTimestamp, tt.prevTimestamp)
			if result != tt.expectedMinDiff {
				t.Errorf("IsMinDifficultyBlock() = %v, want %v", result, tt.expectedMinDiff)
			}
		})
	}
}

func TestHashToBig(t *testing.T) {
	// Test with the mainnet genesis hash
	block := MainnetGenesisBlock()
	hash := block.Header.BlockHash()
	target := CompactToBig(0x1d00ffff)

	hashBig := HashToBig(hash)

	// The genesis hash should be less than the target
	if hashBig.Cmp(target) > 0 {
		t.Errorf("genesis hash should be less than target")
	}

	// Verify the hash starts with zeros (high bits should be zero)
	// The genesis hash is 000000000019d6689c...
	if hashBig.BitLen() > 256-32 { // Should have at least 32 leading zero bits
		t.Errorf("genesis hash should have leading zeros, bitLen = %d", hashBig.BitLen())
	}
}

func TestChainParams(t *testing.T) {
	tests := []struct {
		name     string
		params   *ChainParams
		port     uint16
		hrp      string
		coinType uint32
	}{
		{"mainnet", MainnetParams(), 8333, "bc", 0},
		{"testnet", TestnetParams(), 18333, "tb", 1},
		{"regtest", RegtestParams(), 18444, "bcrt", 1},
		{"signet", SignetParams(), 38333, "tb", 1},
		{"testnet4", Testnet4Params(), 48333, "tb", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.params.DefaultPort != tt.port {
				t.Errorf("port = %d, want %d", tt.params.DefaultPort, tt.port)
			}
			if tt.params.Bech32HRP != tt.hrp {
				t.Errorf("hrp = %s, want %s", tt.params.Bech32HRP, tt.hrp)
			}
			if tt.params.HDCoinType != tt.coinType {
				t.Errorf("coinType = %d, want %d", tt.params.HDCoinType, tt.coinType)
			}
			if tt.params.GenesisBlock == nil {
				t.Error("genesis block is nil")
			}
			if tt.params.GenesisHash.IsZero() {
				t.Error("genesis hash is zero")
			}
		})
	}
}

// mockBlockProvider implements BlockProvider for testing
type mockBlockProvider struct {
	nodes map[int32]*BlockNode
}

func newMockBlockProvider() *mockBlockProvider {
	return &mockBlockProvider{
		nodes: make(map[int32]*BlockNode),
	}
}

func (m *mockBlockProvider) addNode(node *BlockNode) {
	m.nodes[node.Height] = node
}

func (m *mockBlockProvider) GetHeaderByHeight(height int32) *BlockNode {
	return m.nodes[height]
}

func (m *mockBlockProvider) GetPrevHeader(node *BlockNode) *BlockNode {
	if node == nil {
		return nil
	}
	return node.Parent
}

func TestGetNextWorkRequiredRegtest(t *testing.T) {
	params := RegtestParams()

	// Create a simple chain for regtest
	genesis := &BlockNode{
		Height: 0,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602,
		},
	}

	block1 := &BlockNode{
		Height: 1,
		Parent: genesis,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602 + 600, // 10 minutes later
		},
	}

	provider := newMockBlockProvider()
	provider.addNode(genesis)
	provider.addNode(block1)

	// Regtest should always return the same difficulty
	result := GetNextWorkRequired(params, 2, int64(block1.Header.Timestamp)+600, block1, provider)
	if result != params.PowLimitBits {
		t.Errorf("regtest: expected PowLimitBits %x, got %x", params.PowLimitBits, result)
	}

	// Even at a retarget boundary, regtest should not adjust
	block2015 := &BlockNode{
		Height: 2015,
		Parent: block1,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602 + 2015*600,
		},
	}
	provider.addNode(block2015)

	result = GetNextWorkRequired(params, 2016, int64(block2015.Header.Timestamp)+600, block2015, provider)
	if result != params.PowLimitBits {
		t.Errorf("regtest at retarget: expected PowLimitBits %x, got %x", params.PowLimitBits, result)
	}
}

func TestGetNextWorkRequiredTestnetMinDiff(t *testing.T) {
	params := TestnetParams()

	// Create a chain with normal difficulty
	normalBits := uint32(0x1c00ffff) // Higher difficulty than min

	genesis := &BlockNode{
		Height: 0,
		Header: wire.BlockHeader{
			Bits:      normalBits,
			Timestamp: 1296688602,
		},
	}

	block1 := &BlockNode{
		Height: 1,
		Parent: genesis,
		Header: wire.BlockHeader{
			Bits:      normalBits,
			Timestamp: 1296688602 + 600,
		},
	}

	provider := newMockBlockProvider()
	provider.addNode(genesis)
	provider.addNode(block1)

	// Block arriving on time should use normal difficulty
	result := GetNextWorkRequired(params, 2, int64(block1.Header.Timestamp)+600, block1, provider)
	if result != normalBits {
		t.Errorf("on-time block: expected %x, got %x", normalBits, result)
	}

	// Block arriving > 20 minutes late should use min difficulty
	lateTimestamp := int64(block1.Header.Timestamp) + 1201 // > 20 minutes
	result = GetNextWorkRequired(params, 2, lateTimestamp, block1, provider)
	if result != params.PowLimitBits {
		t.Errorf("late block: expected PowLimitBits %x, got %x", params.PowLimitBits, result)
	}
}

func TestGetNextWorkRequiredTestnetWalkback(t *testing.T) {
	params := TestnetParams()

	normalBits := uint32(0x1c00ffff)

	// Create a chain with mixed difficulties
	genesis := &BlockNode{
		Height: 0,
		Header: wire.BlockHeader{
			Bits:      normalBits,
			Timestamp: 1296688602,
		},
	}

	block1 := &BlockNode{
		Height: 1,
		Parent: genesis,
		Header: wire.BlockHeader{
			Bits:      normalBits,
			Timestamp: 1296688602 + 600,
		},
	}

	// Blocks 2-4 are min difficulty (simulating late blocks)
	block2 := &BlockNode{
		Height: 2,
		Parent: block1,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602 + 2*600 + 1201,
		},
	}

	block3 := &BlockNode{
		Height: 3,
		Parent: block2,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602 + 3*600 + 2402,
		},
	}

	block4 := &BlockNode{
		Height: 4,
		Parent: block3,
		Header: wire.BlockHeader{
			Bits:      params.PowLimitBits,
			Timestamp: 1296688602 + 4*600 + 3603,
		},
	}

	provider := newMockBlockProvider()
	provider.addNode(genesis)
	provider.addNode(block1)
	provider.addNode(block2)
	provider.addNode(block3)
	provider.addNode(block4)

	// Block 5 arriving on time should walk back and find block1's difficulty
	onTimeTimestamp := int64(block4.Header.Timestamp) + 600
	result := GetNextWorkRequired(params, 5, onTimeTimestamp, block4, provider)
	if result != normalBits {
		t.Errorf("walkback: expected %x (block1's bits), got %x", normalBits, result)
	}
}

func TestGetNextWorkRequiredBIP94(t *testing.T) {
	params := Testnet4Params()

	// For BIP94, the retarget uses the first block's difficulty, not the last
	firstBits := uint32(0x1d00ffff)
	lastBits := uint32(0x1c00ffff) // Different difficulty

	// Build a minimal chain for retarget
	genesis := &BlockNode{
		Height: 0,
		Header: wire.BlockHeader{
			Bits:      firstBits,
			Timestamp: 1714777860,
		},
	}

	provider := newMockBlockProvider()
	provider.addNode(genesis)

	// Add blocks up to height 2015
	var prev *BlockNode = genesis
	for h := int32(1); h <= 2015; h++ {
		node := &BlockNode{
			Height: h,
			Parent: prev,
			Header: wire.BlockHeader{
				Bits:      lastBits, // Later blocks have different difficulty
				Timestamp: genesis.Header.Timestamp + uint32(h*600),
			},
		}
		provider.addNode(node)
		prev = node
	}

	// At height 2016 (retarget), BIP94 should use firstBits (height 0), not lastBits
	newTimestamp := int64(prev.Header.Timestamp) + 600
	result := GetNextWorkRequired(params, 2016, newTimestamp, prev, provider)

	// Calculate expected: based on firstBits with the actual timespan
	// Since we had exact 600s between blocks, timespan = 2015 * 600 = 1,209,000
	// (slightly less than TargetTimespan of 1,209,600)
	// New target should be slightly lower than firstBits target
	expectedTarget := CompactToBig(firstBits)
	actualTimespan := int64(2015 * 600)
	expectedTarget.Mul(expectedTarget, big.NewInt(actualTimespan))
	expectedTarget.Div(expectedTarget, big.NewInt(params.TargetTimespan))
	expectedBits := BigToCompact(expectedTarget)

	// Allow for rounding differences
	resultTarget := CompactToBig(result)
	diff := new(big.Int).Sub(resultTarget, expectedTarget)
	diff.Abs(diff)
	tolerance := new(big.Int).Div(expectedTarget, big.NewInt(100)) // 1% tolerance

	if diff.Cmp(tolerance) > 0 {
		t.Errorf("BIP94 retarget: expected ~%x, got %x", expectedBits, result)
	}
}

func TestTestnet4GenesisBlockHash(t *testing.T) {
	block := Testnet4GenesisBlock()
	hash := block.Header.BlockHash()

	// Expected: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
	expected, err := wire.NewHash256FromHex("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")
	if err != nil {
		t.Fatalf("failed to parse expected hash: %v", err)
	}

	if hash != expected {
		t.Errorf("testnet4 genesis hash = %s, want %s", hash.String(), expected.String())
	}
}

func TestChainParamsFlags(t *testing.T) {
	tests := []struct {
		name           string
		params         *ChainParams
		minDiffReduce  bool
		noRetarget     bool
		enforceBIP94   bool
	}{
		{"mainnet", MainnetParams(), false, false, false},
		{"testnet3", TestnetParams(), true, false, false},
		{"testnet4", Testnet4Params(), true, false, true},
		{"regtest", RegtestParams(), true, true, false},
		{"signet", SignetParams(), false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.params.MinDiffReductionTime != tt.minDiffReduce {
				t.Errorf("MinDiffReductionTime = %v, want %v", tt.params.MinDiffReductionTime, tt.minDiffReduce)
			}
			if tt.params.PowNoRetargeting != tt.noRetarget {
				t.Errorf("PowNoRetargeting = %v, want %v", tt.params.PowNoRetargeting, tt.noRetarget)
			}
			if tt.params.EnforceBIP94 != tt.enforceBIP94 {
				t.Errorf("EnforceBIP94 = %v, want %v", tt.params.EnforceBIP94, tt.enforceBIP94)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BUG-1: compact overflow detection in CheckProofOfWork
// ---------------------------------------------------------------------------

// TestCompactToBigFullOverflow verifies that compactToBigFull correctly detects
// overflow. Core's SetCompact overflow conditions (arith_uint256.cpp:190-192):
//   - nSize > 34 (exponent > 34)
//   - nWord > 0xff && nSize > 33
//   - nWord > 0xffff && nSize > 32
func TestCompactToBigFullOverflow(t *testing.T) {
	tests := []struct {
		name       string
		compact    uint32
		wantNeg    bool
		wantOvfl   bool
	}{
		// Valid values — no overflow
		{"genesis 0x1d00ffff", 0x1d00ffff, false, false},
		{"regtest 0x207fffff", 0x207fffff, false, false},
		{"zero mantissa", 0x03000000, false, false},
		// Negative flag: bit 23 (0x00800000) of mantissa set AND mantissa != 0.
		// Core: *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0
		// 0x03800001: exponent=3, mantissa_raw=0x800001, nWord=0x000001 (after mask), bit23 set.
		{"negative mantissa", 0x03800001, true, false},
		// 0x03800000: exponent=3, mantissa_raw=0x800000, nWord=0x000000 → NOT negative (mantissa is zero).
		{"zero mantissa with bit23 is not negative", 0x03800000, false, false},
		// Overflow: exponent > 34
		{"exponent=35 mantissa=1", 0x23000001, false, true},
		{"exponent=36", 0x24000001, false, true},
		// Overflow: mantissa > 0xff and exponent == 34
		{"exponent=34 mantissa=0x100", 0x22000100, false, true},
		// Overflow: mantissa > 0xffff and exponent == 33
		{"exponent=33 mantissa=0x10000", 0x21010000, false, true},
		// No overflow: mantissa==0xff exponent==34 is exactly at boundary
		{"exponent=34 mantissa=0xff", 0x220000ff, false, false},
		// No overflow: mantissa==0xffff exponent==33 is exactly at boundary
		{"exponent=33 mantissa=0xffff", 0x2100ffff, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotNeg, gotOvfl := compactToBigFull(tt.compact)
			if gotNeg != tt.wantNeg {
				t.Errorf("compact=%08x: isNegative=%v, want %v", tt.compact, gotNeg, tt.wantNeg)
			}
			if gotOvfl != tt.wantOvfl {
				t.Errorf("compact=%08x: isOverflow=%v, want %v", tt.compact, gotOvfl, tt.wantOvfl)
			}
		})
	}
}

// TestCheckProofOfWorkOverflow verifies that an overflowing compact target is
// rejected by CheckProofOfWork, not silently accepted as a huge target.
// Before the fix, CompactToBig returned a huge positive number for overflow
// compacts; CheckProofOfWork would then compare the block hash against a
// 256+-bit target which could always pass.
func TestCheckProofOfWorkOverflow(t *testing.T) {
	// exponent=35, mantissa=1 → overflow. Old code accepted this as a huge target.
	overflowBits := uint32(0x23000001)
	var anyHash wire.Hash256 // all-zero hash is always "easy" — would pass with huge target

	err := CheckProofOfWork(anyHash, overflowBits, MainnetParams().PowLimit)
	if err == nil {
		t.Errorf("CheckProofOfWork with overflow bits should return an error, got nil")
	}
	if err != ErrTargetTooHigh {
		t.Errorf("CheckProofOfWork with overflow bits: want ErrTargetTooHigh, got %v", err)
	}
}

// TestCheckProofOfWorkNegative verifies that a negative compact target is rejected.
func TestCheckProofOfWorkNegative(t *testing.T) {
	// mantissa has bit 23 set → negative
	negativeBits := uint32(0x03800001)
	var anyHash wire.Hash256

	err := CheckProofOfWork(anyHash, negativeBits, MainnetParams().PowLimit)
	if err == nil {
		t.Errorf("CheckProofOfWork with negative bits should return an error, got nil")
	}
	if err != ErrNegativeTarget {
		t.Errorf("CheckProofOfWork with negative bits: want ErrNegativeTarget, got %v", err)
	}
}

// TestCheckProofOfWorkZeroTarget verifies that a zero target is rejected.
func TestCheckProofOfWorkZeroTarget(t *testing.T) {
	// exponent=3, mantissa=0 → target==0
	zeroBits := uint32(0x03000000)
	var anyHash wire.Hash256

	err := CheckProofOfWork(anyHash, zeroBits, MainnetParams().PowLimit)
	if err == nil {
		t.Errorf("CheckProofOfWork with zero target should return an error, got nil")
	}
}

// ---------------------------------------------------------------------------
// BUG-2: PermittedDifficultyTransition
// ---------------------------------------------------------------------------

// TestPermittedDifficultyTransitionMainnet exercises all gate paths on mainnet.
func TestPermittedDifficultyTransitionMainnet(t *testing.T) {
	params := MainnetParams()

	// Reference bits: genesis 0x1d00ffff.
	genesisBits := uint32(0x1d00ffff)

	// Higher difficulty (smaller target): 0x1c00ffff.
	hardBits := uint32(0x1c00ffff)

	// ---- Non-retarget heights (height % 2016 != 0) ----
	// Must keep nBits identical.
	t.Run("non-retarget same bits allowed", func(t *testing.T) {
		if !PermittedDifficultyTransition(params, 1, genesisBits, genesisBits) {
			t.Error("same nBits at non-retarget height should be permitted")
		}
	})
	t.Run("non-retarget different bits rejected", func(t *testing.T) {
		if PermittedDifficultyTransition(params, 1, genesisBits, hardBits) {
			t.Error("different nBits at non-retarget height should NOT be permitted")
		}
	})
	t.Run("non-retarget different bits rejected height 2015", func(t *testing.T) {
		if PermittedDifficultyTransition(params, 2015, genesisBits, hardBits) {
			t.Error("different nBits at non-retarget height 2015 should NOT be permitted")
		}
	})

	// ---- Retarget heights (height % 2016 == 0) ----
	t.Run("retarget same bits allowed", func(t *testing.T) {
		if !PermittedDifficultyTransition(params, 2016, genesisBits, genesisBits) {
			t.Error("same nBits at retarget height should be permitted")
		}
	})

	// Maximum 4× increase in target (difficulty halved by 4): should be allowed.
	// new_target = old_target * 4  →  new_bits encodes that
	oldTarget := CompactToBig(genesisBits)
	maxNewTarget := new(big.Int).Mul(oldTarget, big.NewInt(4))
	// Clamp to powLimit
	if maxNewTarget.Cmp(params.PowLimit) > 0 {
		maxNewTarget.Set(params.PowLimit)
	}
	maxNewBits := BigToCompact(maxNewTarget)
	t.Run("retarget 4x target increase allowed", func(t *testing.T) {
		if !PermittedDifficultyTransition(params, 2016, genesisBits, maxNewBits) {
			t.Errorf("4x target increase at retarget should be permitted (new bits %08x)", maxNewBits)
		}
	})

	// 4× difficulty increase (target ÷ 4): should be allowed from non-min-limit bits.
	smallNewTarget := new(big.Int).Div(CompactToBig(hardBits), big.NewInt(4))
	smallNewBits := BigToCompact(smallNewTarget)
	t.Run("retarget 4x difficulty increase allowed", func(t *testing.T) {
		if !PermittedDifficultyTransition(params, 2016, hardBits, smallNewBits) {
			t.Errorf("4x difficulty increase at retarget should be permitted (new bits %08x)", smallNewBits)
		}
	})

	// Target increase beyond 4× must be rejected.
	// We compute old_target * 5 to exceed the 4x limit.
	wayTooEasyTarget := new(big.Int).Mul(CompactToBig(hardBits), big.NewInt(5))
	if wayTooEasyTarget.Cmp(params.PowLimit) <= 0 {
		wayTooEasyBits := BigToCompact(wayTooEasyTarget)
		t.Run("retarget 5x target increase rejected", func(t *testing.T) {
			if PermittedDifficultyTransition(params, 2016, hardBits, wayTooEasyBits) {
				t.Error("5x target increase at retarget should NOT be permitted")
			}
		})
	}
}

// TestPermittedDifficultyTransitionTestnet verifies the testnet bypass: all
// transitions are allowed when MinDiffReductionTime is true. This mirrors
// Core's fPowAllowMinDifficultyBlocks early-return.
func TestPermittedDifficultyTransitionTestnet(t *testing.T) {
	for _, params := range []*ChainParams{TestnetParams(), Testnet4Params(), RegtestParams()} {
		name := params.Name
		t.Run(name+" non-retarget different bits allowed", func(t *testing.T) {
			// Any transition should pass on testnet/regtest.
			if !PermittedDifficultyTransition(params, 1, 0x1d00ffff, 0x1c00ffff) {
				t.Errorf("%s: different nBits at non-retarget height should be allowed (fPowAllowMinDifficultyBlocks)", name)
			}
		})
		t.Run(name+" retarget absurd transition allowed", func(t *testing.T) {
			if !PermittedDifficultyTransition(params, 2016, 0x1d00ffff, 0x207fffff) {
				t.Errorf("%s: absurd retarget should be allowed (fPowAllowMinDifficultyBlocks)", name)
			}
		})
	}
}

// TestPermittedDifficultyTransitionSignet verifies mainnet-like strictness on
// signet (MinDiffReductionTime=false).
func TestPermittedDifficultyTransitionSignet(t *testing.T) {
	params := SignetParams()
	if !params.MinDiffReductionTime {
		// Non-retarget must keep bits equal
		if PermittedDifficultyTransition(params, 1, 0x1e0377ae, 0x1d00ffff) {
			t.Error("signet non-retarget with different bits should NOT be permitted")
		}
		if !PermittedDifficultyTransition(params, 1, 0x1e0377ae, 0x1e0377ae) {
			t.Error("signet non-retarget with same bits should be permitted")
		}
	}
}

// TestPermittedDifficultyTransitionBoundary tests the exact 4× boundary.
// The boundary value should be ALLOWED; one step beyond should be REJECTED.
// This mirrors the round-trip compact comparison in Core pow.cpp:113-114.
func TestPermittedDifficultyTransitionBoundary(t *testing.T) {
	params := MainnetParams()
	// Use a moderate difficulty so 4× doesn't hit powLimit.
	oldBits := uint32(0x1b00ffff)
	oldTarget := CompactToBig(oldBits)

	// Exact 4× target increase — should be permitted.
	exactMax := new(big.Int).Mul(oldTarget, big.NewInt(params.TargetTimespan*4))
	exactMax.Div(exactMax, big.NewInt(params.TargetTimespan))
	if exactMax.Cmp(params.PowLimit) > 0 {
		exactMax.Set(params.PowLimit)
	}
	exactMaxBits := BigToCompact(exactMax)
	if !PermittedDifficultyTransition(params, 2016, oldBits, exactMaxBits) {
		t.Errorf("exact 4x boundary (%08x→%08x) should be permitted", oldBits, exactMaxBits)
	}

	// One bit beyond the maximum (larger target = easier) — should be rejected.
	// Increment the decoded target by 1 and re-encode.
	beyondMax := new(big.Int).Add(CompactToBig(exactMaxBits), big.NewInt(1))
	beyondMaxBits := BigToCompact(beyondMax)
	// Only test if the beyond value is actually different after compact encoding.
	if beyondMaxBits != exactMaxBits && beyondMax.Cmp(params.PowLimit) <= 0 {
		if PermittedDifficultyTransition(params, 2016, oldBits, beyondMaxBits) {
			t.Errorf("one-beyond-4x boundary (%08x→%08x) should NOT be permitted", oldBits, beyondMaxBits)
		}
	}

	// Exact ÷4 difficulty (×4 target decrease) — should be permitted.
	exactMin := new(big.Int).Mul(oldTarget, big.NewInt(params.TargetTimespan/4))
	exactMin.Div(exactMin, big.NewInt(params.TargetTimespan))
	exactMinBits := BigToCompact(exactMin)
	if !PermittedDifficultyTransition(params, 2016, oldBits, exactMinBits) {
		t.Errorf("exact ÷4 boundary (%08x→%08x) should be permitted", oldBits, exactMinBits)
	}
}

// ---------------------------------------------------------------------------
// BUG-3: validateDifficulty exact comparison (no tolerance)
// ---------------------------------------------------------------------------

// TestValidateDifficultyExact verifies that validateDifficulty rejects a
// header whose nBits differs from GetNextWorkRequired by even one compact step,
// even if the targets are numerically close. The old code allowed ±0.1%.
func TestValidateDifficultyExact(t *testing.T) {
	params := MainnetParams()
	idx := NewHeaderIndex(params)

	// Build a retarget-boundary chain so we can test a subtle nBits mismatch.
	// Create 2016 blocks at genesis difficulty with exact 600s spacing.
	genesisTS := uint32(1231006505) // mainnet genesis timestamp
	var prev *BlockNode = idx.genesis
	for h := int32(1); h <= 2015; h++ {
		node := &BlockNode{
			Hash:      wire.Hash256{byte(h), byte(h >> 8)}, // unique fake hash
			Height:    h,
			Parent:    prev,
			TotalWork: prev.TotalWork,
			Header: wire.BlockHeader{
				Bits:      params.PowLimitBits,
				Timestamp: genesisTS + uint32(h)*600,
			},
		}
		node.buildSkip()
		idx.nodes[node.Hash] = node
		idx.bestTip = node
		idx.cachedBestHeight.Store(h)
		prev = node
	}

	// Compute expected nBits for block 2016.
	newTimestamp := int64(genesisTS) + 2016*600
	expectedBits := GetNextWorkRequired(params, 2016, newTimestamp, prev, idx)

	// Build a header with expected bits — should pass.
	goodHeader := wire.BlockHeader{
		Bits:      expectedBits,
		Timestamp: uint32(newTimestamp),
	}
	if err := idx.validateDifficulty(goodHeader, prev, 2016); err != nil {
		t.Errorf("correct nBits: validateDifficulty returned error: %v", err)
	}

	// Tweak nBits by adding 1 to the compact mantissa — very small target
	// change, formerly within the 0.1% tolerance. Should now be rejected.
	tweakedBits := expectedBits + 1
	if tweakedBits != expectedBits { // guard against wrapping
		badHeader := wire.BlockHeader{
			Bits:      tweakedBits,
			Timestamp: uint32(newTimestamp),
		}
		if err := idx.validateDifficulty(badHeader, prev, 2016); err == nil {
			t.Errorf("tweaked nBits (+1 compact) should be rejected (no tolerance), was accepted")
		}
	}
}
