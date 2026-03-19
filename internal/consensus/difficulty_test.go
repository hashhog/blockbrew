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
