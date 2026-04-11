package consensus

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// mockChain builds a mock chain of block nodes with specific timestamps and versions.
type mockChain struct {
	nodes     []*BlockNode
	params    *ChainParams
	nodeByHash map[wire.Hash256]*BlockNode
}

func newMockChain(params *ChainParams) *mockChain {
	return &mockChain{
		params:    params,
		nodeByHash: make(map[wire.Hash256]*BlockNode),
	}
}

// addBlock adds a block with the given version and timestamp to the chain.
// Returns the new block node.
func (c *mockChain) addBlock(version int32, timestamp uint32) *BlockNode {
	var parent *BlockNode
	var height int32
	var prevHash wire.Hash256

	if len(c.nodes) > 0 {
		parent = c.nodes[len(c.nodes)-1]
		height = parent.Height + 1
		prevHash = parent.Hash
	}

	// Create a unique hash for this block (use height as a simple identifier)
	var hash wire.Hash256
	hash[0] = byte(height)
	hash[1] = byte(height >> 8)
	hash[2] = byte(height >> 16)
	hash[3] = byte(height >> 24)

	node := &BlockNode{
		Hash: hash,
		Header: wire.BlockHeader{
			Version:   version,
			PrevBlock: prevHash,
			Timestamp: timestamp,
			Bits:      0x1d00ffff,
		},
		Height:    height,
		Parent:    parent,
		TotalWork: big.NewInt(int64(height + 1)),
		Status:    StatusHeaderValid,
	}

	c.nodes = append(c.nodes, node)
	c.nodeByHash[hash] = node

	return node
}

// tip returns the current chain tip.
func (c *mockChain) tip() *BlockNode {
	if len(c.nodes) == 0 {
		return nil
	}
	return c.nodes[len(c.nodes)-1]
}

// addBlocksWithVersion adds n blocks with the given version.
func (c *mockChain) addBlocksWithVersion(n int, version int32, baseTimestamp uint32) {
	for i := 0; i < n; i++ {
		timestamp := baseTimestamp + uint32(len(c.nodes)*600)
		c.addBlock(version, timestamp)
	}
}

func TestDeploymentStateString(t *testing.T) {
	tests := []struct {
		state    DeploymentState
		expected string
	}{
		{DeploymentDefined, "defined"},
		{DeploymentStarted, "started"},
		{DeploymentLockedIn, "locked_in"},
		{DeploymentActive, "active"},
		{DeploymentFailed, "failed"},
		{DeploymentState(99), "unknown"},
	}

	for _, tc := range tests {
		got := tc.state.String()
		if got != tc.expected {
			t.Errorf("DeploymentState(%d).String() = %q, want %q", tc.state, got, tc.expected)
		}
	}
}

func TestBIP9DeploymentMask(t *testing.T) {
	tests := []struct {
		bit      int
		expected int32
	}{
		{0, 1},
		{1, 2},
		{2, 4},
		{28, 1 << 28},
	}

	for _, tc := range tests {
		d := &BIP9Deployment{Bit: tc.bit}
		got := d.Mask()
		if got != tc.expected {
			t.Errorf("Bit %d: Mask() = 0x%x, want 0x%x", tc.bit, got, tc.expected)
		}
	}
}

func TestBlockSignals(t *testing.T) {
	tests := []struct {
		name     string
		version  int32
		mask     int32
		expected bool
	}{
		{
			name:     "BIP9 signaling bit 0",
			version:  0x20000001, // BIP9 base + bit 0
			mask:     1,
			expected: true,
		},
		{
			name:     "BIP9 not signaling bit 0",
			version:  0x20000000, // BIP9 base, no bits
			mask:     1,
			expected: false,
		},
		{
			name:     "BIP9 signaling bit 1",
			version:  0x20000002, // BIP9 base + bit 1
			mask:     2,
			expected: true,
		},
		{
			name:     "old version format",
			version:  4, // Pre-BIP9 version
			mask:     1,
			expected: false,
		},
		{
			name:     "wrong top bits",
			version:  0x40000001, // Wrong top bits
			mask:     1,
			expected: false,
		},
		{
			name:     "BIP9 signaling bit 28",
			version:  0x30000000, // BIP9 base + bit 28
			mask:     1 << 28,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BlockSignals(tc.version, tc.mask)
			if got != tc.expected {
				t.Errorf("BlockSignals(0x%x, 0x%x) = %v, want %v",
					tc.version, tc.mask, got, tc.expected)
			}
		})
	}
}

func TestVersionBitsTopMask(t *testing.T) {
	// Verify that VersionBitsTopMask correctly masks the top 3 bits
	// 0xE0000000 = 11100000 00000000 00000000 00000000 in binary
	// In two's complement for int32, this is -0x20000000

	// Test that BIP9 version passes
	if (0x20000000 & VersionBitsTopMask) != VersionBitsTopBits {
		t.Errorf("BIP9 base version should match top bits pattern")
	}

	// Test that old versions don't pass
	if (4 & VersionBitsTopMask) == VersionBitsTopBits {
		t.Errorf("Old version 4 should not match BIP9 pattern")
	}
}

func TestGetDeploymentState_AlwaysActive(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	// Add some blocks
	chain.addBlocksWithVersion(10, 0x20000000, 1600000000)

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: AlwaysActive, // Always active
		Timeout:   NoTimeout,
		Period:    2016,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentActive {
		t.Errorf("AlwaysActive deployment should be Active, got %s", state)
	}
}

func TestGetDeploymentState_NeverActive(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	// Add some blocks
	chain.addBlocksWithVersion(10, 0x20000000, 1600000000)

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: NeverActive, // Never active
		Timeout:   NoTimeout,
		Period:    2016,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentFailed {
		t.Errorf("NeverActive deployment should be Failed, got %s", state)
	}
}

func TestGetDeploymentState_NilTip(t *testing.T) {
	params := RegtestParams()

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: 1600000000,
		Timeout:   NoTimeout,
		Period:    2016,
	}

	state := GetDeploymentState(deployment, 0, nil, params, nil)
	if state != DeploymentDefined {
		t.Errorf("Nil tip should return Defined, got %s", state)
	}
}

func TestGetDeploymentState_Defined(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	// Start time is in the future
	startTime := int64(1700000000)
	currentTime := uint32(1600000000)

	// Add blocks before start time
	chain.addBlocksWithVersion(100, 0x20000001, currentTime)

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime, // Future
		Timeout:   NoTimeout,
		Period:    100,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentDefined {
		t.Errorf("Before start time should be Defined, got %s", state)
	}
}

func TestGetDeploymentState_Started(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Add enough blocks to get past start time, but not enough signaling
	// First period: no signaling
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Second period: partial signaling (not enough to lock in)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000, // Past
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: 8, // Need 80%
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentStarted {
		t.Errorf("After start time without threshold should be Started, got %s", state)
	}
}

func TestGetDeploymentState_LockedIn(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// First period: past start time, enable signaling
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}

	// Second period: signal with enough blocks to lock in (9 out of 10)
	for i := 0; i < int(period); i++ {
		var version int32 = 0x20000000
		if i < 9 { // 9 signaling blocks
			version = 0x20000001 // Signal bit 0
		}
		chain.addBlock(version, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000, // Past
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: threshold,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentLockedIn {
		t.Errorf("After threshold reached should be LockedIn, got %s", state)
	}
}

func TestGetDeploymentState_Active(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// First period: past start time
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}

	// Second period: signal with enough blocks to lock in
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	// Third period: activation
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:                "test",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           threshold,
		MinActivationHeight: 0,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentActive {
		t.Errorf("After lock in period should be Active, got %s", state)
	}
}

func TestGetDeploymentState_Failed(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	timeout := startTime + 6000 // Timeout after first period

	// First period: past start time, no signaling
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}

	// Second period: past timeout, still no signaling
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(timeout+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   timeout,
		Period:    period,
		Threshold: 8,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentFailed {
		t.Errorf("After timeout without lock-in should be Failed, got %s", state)
	}
}

func TestGetDeploymentState_MinActivationHeight(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)
	minActivationHeight := int32(100)

	// First period
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}

	// Second period: achieve lock in
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	// Third period: would normally activate, but below minActivationHeight
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:                "test",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           threshold,
		MinActivationHeight: minActivationHeight,
	}

	state := GetDeploymentState(deployment, 0, chain.tip(), params, nil)
	if state != DeploymentLockedIn {
		t.Errorf("Below MinActivationHeight should stay LockedIn, got %s", state)
	}
}

func TestComputeBlockVersion_NoDeployments(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)
	chain.addBlocksWithVersion(10, 0x20000000, 1600000000)

	version := ComputeBlockVersion(chain.tip(), nil, params, nil)
	if version != VersionBitsTopBits {
		t.Errorf("No deployments should return base version 0x%x, got 0x%x",
			VersionBitsTopBits, version)
	}
}

func TestComputeBlockVersion_SingleDeploymentStarted(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Build chain: need 2 periods to reach STARTED state
	// Period 1 (heights 0-9): before start time, state = DEFINED
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2 (heights 10-19): MTP has passed start time, state = STARTED
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployments := []*BIP9Deployment{
		{
			Name:      "test",
			Bit:       1,
			StartTime: startTime - 10000, // Well before the chain starts
			Timeout:   NoTimeout,
			Period:    period,
			Threshold: 8,
		},
	}

	// Debug
	state := GetDeploymentState(deployments[0], 0, chain.tip(), params, nil)
	t.Logf("Deployment state at tip (height %d): %s", chain.tip().Height, state)

	version := ComputeBlockVersion(chain.tip(), deployments, params, nil)
	expected := VersionBitsTopBits | (1 << 1) // Base + bit 1

	if version != expected {
		t.Errorf("Started deployment should set bit: got 0x%x, want 0x%x", version, expected)
	}
}

func TestComputeBlockVersion_MultipleDeployments(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Build chain: 2 periods to reach STARTED state
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployments := []*BIP9Deployment{
		{
			Name:      "deploy0",
			Bit:       0,
			StartTime: startTime - 10000, // Should be STARTED
			Timeout:   NoTimeout,
			Period:    period,
			Threshold: 8,
		},
		{
			Name:      "deploy1",
			Bit:       1,
			StartTime: NeverActive, // Never active (failed)
			Timeout:   NoTimeout,
			Period:    period,
		},
		{
			Name:      "deploy2",
			Bit:       2,
			StartTime: startTime - 10000, // Should be STARTED
			Timeout:   NoTimeout,
			Period:    period,
			Threshold: 8,
		},
	}

	version := ComputeBlockVersion(chain.tip(), deployments, params, nil)
	expected := VersionBitsTopBits | (1 << 0) | (1 << 2) // Base + bit 0 + bit 2

	if version != expected {
		t.Errorf("Multiple deployments: got 0x%x, want 0x%x", version, expected)
	}
}

func TestVersionBitsCache(t *testing.T) {
	cache := NewVersionBitsCache()

	// Test initial state
	if _, ok := cache.Get(0, 100); ok {
		t.Error("New cache should return false for Get")
	}

	// Test Set and Get
	cache.Set(0, 100, DeploymentStarted)
	state, ok := cache.Get(0, 100)
	if !ok || state != DeploymentStarted {
		t.Errorf("After Set, Get should return (Started, true), got (%s, %v)", state, ok)
	}

	// Test different deployment index
	cache.Set(1, 100, DeploymentActive)
	state1, _ := cache.Get(0, 100)
	state2, _ := cache.Get(1, 100)
	if state1 != DeploymentStarted || state2 != DeploymentActive {
		t.Error("Cache should differentiate by deployment index")
	}

	// Test Clear
	cache.Clear()
	if _, ok := cache.Get(0, 100); ok {
		t.Error("After Clear, cache should be empty")
	}
}

func TestGetDeploymentStats(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Add 5 blocks, 3 signaling
	for i := 0; i < 5; i++ {
		var version int32 = 0x20000000
		if i < 3 {
			version = 0x20000001 // Signal bit 0
		}
		chain.addBlock(version, uint32(startTime+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: 8,
	}

	stats := GetDeploymentStats(deployment, chain.tip(), params)
	if stats == nil {
		t.Fatal("GetDeploymentStats returned nil")
	}

	if stats.Period != period {
		t.Errorf("Period = %d, want %d", stats.Period, period)
	}
	if stats.Threshold != 8 {
		t.Errorf("Threshold = %d, want 8", stats.Threshold)
	}
	if stats.Elapsed != 5 {
		t.Errorf("Elapsed = %d, want 5", stats.Elapsed)
	}
	if stats.Count != 3 {
		t.Errorf("Count = %d, want 3", stats.Count)
	}
	// 3 signaling + 5 remaining = 8, threshold is 8, so possible
	if !stats.Possible {
		t.Errorf("Possible = %v, want true", stats.Possible)
	}
}

func TestGetDeploymentStats_Impossible(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Add 8 blocks, only 2 signaling
	for i := 0; i < 8; i++ {
		var version int32 = 0x20000000
		if i < 2 {
			version = 0x20000001
		}
		chain.addBlock(version, uint32(startTime+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: 8,
	}

	stats := GetDeploymentStats(deployment, chain.tip(), params)
	// 2 signaling + 2 remaining = 4 < 8 threshold
	if stats.Possible {
		t.Errorf("Should be impossible: count=%d, remaining=%d, threshold=%d",
			stats.Count, period-stats.Elapsed, stats.Threshold)
	}
}

func TestDeploymentActiveAt(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Build chain to active state
	// Period 1 (heights 0-9)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2 (heights 10-19): lock in with signaling
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}
	// Period 3 (heights 20-29): post-lock-in
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}
	// Period 4 (heights 30-39): activation
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(3*period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:      "test",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: 8,
	}

	// Debug: check state at various heights
	t.Logf("Tip height: %d", chain.tip().Height)
	for _, h := range []int32{9, 19, 29, 39} {
		node := chain.tip().GetAncestor(h)
		if node != nil {
			state := GetDeploymentState(deployment, 0, node, params, nil)
			t.Logf("State at height %d: %s", h, state)
		}
	}

	// Check at tip (should be active)
	state := GetDeploymentState(deployment, 0, chain.tip().Parent, params, nil)
	t.Logf("State at tip's parent (height %d): %s", chain.tip().Parent.Height, state)

	if !DeploymentActiveAt(deployment, 0, chain.tip(), params, nil) {
		t.Error("Should be active at tip")
	}

	// Check at period 2 end (should not be active - just locked in)
	node := chain.tip().GetAncestor(int32(2*period) - 1)
	if DeploymentActiveAt(deployment, 0, node, params, nil) {
		t.Error("Should not be active during lock-in period")
	}
}

func TestDeploymentActiveAfter(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)

	// Build chain to locked-in state
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployment := &BIP9Deployment{
		Name:                "test",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           8,
		MinActivationHeight: 0,
	}

	// At end of period 2, deployment is locked in but not yet active
	// DeploymentActiveAfter checks if the NEXT block would have the deployment active
	if DeploymentActiveAfter(deployment, 0, chain.tip(), params, nil) {
		t.Error("Should not be active after lock-in period end")
	}

	// Add one more period to activate
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}

	if !DeploymentActiveAfter(deployment, 0, chain.tip(), params, nil) {
		t.Error("Should be active after activation period")
	}
}

func TestGetPeriodEndHeight(t *testing.T) {
	// getPeriodEndHeight returns the boundary height used to compute the state
	// for the block AFTER height (Bitcoin Core GetStateFor(pindexPrev) semantics).
	// When height is at the END of a period (height+1 divisible by period), the
	// state for the next block is determined by counting signals in the CURRENT
	// period, so we return height itself. Otherwise we return the previous period end.
	tests := []struct {
		height   int32
		period   int32
		expected int32
	}{
		{0, 10, -1},   // Mid-period 0; previous period end = -1 (before genesis)
		{5, 10, -1},   // Mid-period 0; previous period end = -1
		{9, 10, 9},    // End of period 0 (9+1=10, divisible by 10); return 9
		{10, 10, 9},   // Mid-period 1; previous end = 9
		{15, 10, 9},   // Mid-period 1; previous end = 9
		{19, 10, 19},  // End of period 1 (19+1=20, divisible by 10); return 19
		{20, 10, 19},  // Mid-period 2; previous end = 19
		{2015, 2016, 2015}, // End of period 0 (Bitcoin-style); return 2015
		{2016, 2016, 2015}, // Mid-period 1; previous end = 2015
		{4031, 2016, 4031}, // End of period 1; return 4031
		{4032, 2016, 4031}, // Mid-period 2; previous end = 4031
	}

	for _, tc := range tests {
		got := getPeriodEndHeight(tc.height, tc.period)
		if got != tc.expected {
			t.Errorf("getPeriodEndHeight(%d, %d) = %d, want %d",
				tc.height, tc.period, got, tc.expected)
		}
	}
}
