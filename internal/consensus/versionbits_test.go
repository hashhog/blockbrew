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

// TestGetDeploymentState_StartedThresholdBoundary exercises the exact threshold
// boundary: count == threshold-1 must NOT lock in; count == threshold MUST.
func TestGetDeploymentState_StartedThresholdBoundary(t *testing.T) {
	params := RegtestParams()

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Helper: build a chain where the second period contains `signalers` blocks
	// signaling for bit 0.
	build := func(signalers int) *BlockNode {
		chain := newMockChain(params)
		// Period 1: before start time → DEFINED at end of this period
		for i := 0; i < int(period); i++ {
			chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
		}
		// Period 2: MTP past start time → STARTED.  Fill with `signalers` signaling
		// blocks and the rest non-signaling.
		for i := 0; i < int(period); i++ {
			ver := int32(0x20000000)
			if i < signalers {
				ver = 0x20000001 // bit 0
			}
			chain.addBlock(ver, uint32(startTime+int64(period)*600+int64(i)*600))
		}
		return chain.tip()
	}

	dep := &BIP9Deployment{
		Name:      "boundary",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: threshold,
	}

	// count = threshold-1 → still STARTED
	tip := build(int(threshold) - 1)
	got := GetDeploymentState(dep, 0, tip, params, nil)
	if got != DeploymentStarted {
		t.Errorf("count=threshold-1 (%d): want started, got %s", threshold-1, got)
	}

	// count = threshold → LOCKED_IN
	tip = build(int(threshold))
	got = GetDeploymentState(dep, 0, tip, params, nil)
	if got != DeploymentLockedIn {
		t.Errorf("count=threshold (%d): want locked_in, got %s", threshold, got)
	}
}

// TestGetDeploymentState_StartedThresholdBeatsTimeout verifies that Bitcoin Core
// semantics are respected: if count >= threshold AND MTP >= timeout in the same
// period, the transition is LOCKED_IN (not FAILED).
// Core versionbits.cpp:83-98 — count is checked before timeout.
func TestGetDeploymentState_StartedThresholdBeatsTimeout(t *testing.T) {
	params := RegtestParams()

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)
	// Timeout expires exactly at the MTP of the second period's end block.
	// We will set the block timestamps so MTP at period-end >= timeout AND
	// the block also carries threshold-many signals.
	timeout := startTime + int64(period)*600 // expires right when period 2 starts/ends

	chain := newMockChain(params)
	// Period 1 (before start): all non-signaling, timestamps below start
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2: timestamps >= timeout (so MTP will reach timeout), but ALL blocks
	// signal — count == period >= threshold.
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(timeout+int64(i)*600))
	}

	dep := &BIP9Deployment{
		Name:      "lockin-beats-timeout",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   timeout,
		Period:    period,
		Threshold: threshold,
	}

	got := GetDeploymentState(dep, 0, chain.tip(), params, nil)
	if got != DeploymentLockedIn {
		t.Errorf("threshold reached AND timeout expired: want locked_in, got %s", got)
	}
}

// TestGetDeploymentState_TimeoutExactBoundary verifies that a deployment
// transitions to FAILED when MTP first reaches (>=) the timeout value and the
// threshold has NOT been reached.
func TestGetDeploymentState_TimeoutExactBoundary(t *testing.T) {
	params := RegtestParams()

	period := int32(10)
	startTime := int64(1600000000)
	// Timeout fires in the second signaling period.
	timeout := startTime + int64(period)*600 + 1 // just after period 1's MTP

	chain := newMockChain(params)
	// Period 1 (DEFINED→STARTED transition)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2: no signaling, timestamps push MTP past timeout
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(timeout+int64(i)*600))
	}

	dep := &BIP9Deployment{
		Name:      "timeout-boundary",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   timeout,
		Period:    period,
		Threshold: 8,
	}

	got := GetDeploymentState(dep, 0, chain.tip(), params, nil)
	if got != DeploymentFailed {
		t.Errorf("MTP>=timeout without threshold: want failed, got %s", got)
	}
}

// TestGetDeploymentState_LockedInExactActivationHeight checks the fence-post on
// min_activation_height:
//   - activationHeight == minActivationHeight → ACTIVE
//   - activationHeight == minActivationHeight-1 → stays LOCKED_IN
func TestGetDeploymentState_LockedInExactActivationHeight(t *testing.T) {
	params := RegtestParams()

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Build enough periods to reach LOCKED_IN (period 2 has threshold signals).
	buildToLockedIn := func() *mockChain {
		c := newMockChain(params)
		for i := 0; i < int(period); i++ {
			c.addBlock(0x20000000, uint32(startTime+int64(i)*600))
		}
		for i := 0; i < int(period); i++ {
			c.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
		}
		return c
	}

	chain := buildToLockedIn()
	// At end of period 2 the chain is at height 19 (LOCKED_IN after eval of period 2).
	// activationHeight for the NEXT period = 20; minActivationHeight = 21 → stays LOCKED_IN.
	depStaysLocked := &BIP9Deployment{
		Name:                "locked-stays",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           threshold,
		MinActivationHeight: 21, // first block of period 3 is 20, below 21
	}
	got := GetDeploymentState(depStaysLocked, 0, chain.tip(), params, nil)
	if got != DeploymentLockedIn {
		t.Errorf("activationHeight<minActivationHeight: want locked_in, got %s", got)
	}

	// Add one more period (heights 20-29).  activationHeight = 30 >= 21 → ACTIVE.
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}
	depActivates := &BIP9Deployment{
		Name:                "locked-activates",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           threshold,
		MinActivationHeight: 21, // 30 >= 21 → ACTIVE
	}
	got = GetDeploymentState(depActivates, 0, chain.tip(), params, nil)
	if got != DeploymentActive {
		t.Errorf("activationHeight>=minActivationHeight: want active, got %s", got)
	}
}

// TestGetDeploymentState_CacheCorrectness verifies that cached results are
// reused and that Clear() invalidates them.
func TestGetDeploymentState_CacheCorrectness(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Build to LOCKED_IN.
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	dep := &BIP9Deployment{
		Name:      "cache-test",
		Bit:       0,
		StartTime: startTime - 10000,
		Timeout:   NoTimeout,
		Period:    period,
		Threshold: threshold,
	}

	cache := NewVersionBitsCache()

	// First call: primes the cache.
	got1 := GetDeploymentState(dep, 0, chain.tip(), params, cache)
	// Second call: must return the same result using the cache.
	got2 := GetDeploymentState(dep, 0, chain.tip(), params, cache)
	if got1 != got2 {
		t.Errorf("cache: first=%s, second=%s (must be equal)", got1, got2)
	}
	if got1 != DeploymentLockedIn {
		t.Errorf("cache: expected locked_in, got %s", got1)
	}

	// Clear and re-compute: same result but cache was rebuilt.
	cache.Clear()
	got3 := GetDeploymentState(dep, 0, chain.tip(), params, cache)
	if got3 != DeploymentLockedIn {
		t.Errorf("after Clear: expected locked_in, got %s", got3)
	}
}

// TestComputeBlockVersion_LockedInSetsSignalingBit verifies that
// ComputeBlockVersion ORs in the deployment bit for LOCKED_IN state (not just
// STARTED). Core versionbits.cpp:273: sets bit for LOCKED_IN || STARTED.
func TestComputeBlockVersion_LockedInSetsSignalingBit(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Period 1: DEFINED→STARTED transition (no signaling)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2: signal for bit 3 to achieve threshold → LOCKED_IN.
	// Version 0x20000008 = VERSIONBITS_TOP_BITS | (1<<3).
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000008, uint32(startTime+int64(period)*600+int64(i)*600))
	}

	deployments := []*BIP9Deployment{
		{
			Name:      "locked-bit",
			Bit:       3,
			StartTime: startTime - 10000,
			Timeout:   NoTimeout,
			Period:    period,
			Threshold: threshold,
		},
	}

	// Verify state is indeed LOCKED_IN at tip.
	state := GetDeploymentState(deployments[0], 0, chain.tip(), params, nil)
	if state != DeploymentLockedIn {
		t.Fatalf("prerequisite: expected locked_in, got %s", state)
	}

	version := ComputeBlockVersion(chain.tip(), deployments, params, nil)
	expected := VersionBitsTopBits | (1 << 3)
	if version != expected {
		t.Errorf("LOCKED_IN bit not set: got 0x%x, want 0x%x", version, expected)
	}
}

// TestComputeBlockVersion_ActiveDoesNotSetBit verifies that deployments in
// ACTIVE state do NOT set their signaling bit (Core only signals for
// STARTED and LOCKED_IN; once ACTIVE there is nothing to signal).
func TestComputeBlockVersion_ActiveDoesNotSetBit(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Period 1
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2: lock in — version 0x20000020 = VERSIONBITS_TOP_BITS | (1<<5)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000020, uint32(startTime+int64(period)*600+int64(i)*600))
	}
	// Period 3: transition to ACTIVE
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}

	deployments := []*BIP9Deployment{
		{
			Name:                "active-no-bit",
			Bit:                 5,
			StartTime:           startTime - 10000,
			Timeout:             NoTimeout,
			Period:              period,
			Threshold:           threshold,
			MinActivationHeight: 0,
		},
	}

	state := GetDeploymentState(deployments[0], 0, chain.tip(), params, nil)
	if state != DeploymentActive {
		t.Fatalf("prerequisite: expected active, got %s", state)
	}

	version := ComputeBlockVersion(chain.tip(), deployments, params, nil)
	if version != VersionBitsTopBits {
		t.Errorf("ACTIVE state should not set bit: got 0x%x, want 0x%x (base only)",
			version, VersionBitsTopBits)
	}
}

// TestComputeBlockVersion_FailedDoesNotSetBit verifies that a FAILED deployment
// does NOT set its bit in the computed version.
func TestComputeBlockVersion_FailedDoesNotSetBit(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	timeout := startTime + int64(period)*600 + 1

	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(timeout+int64(i)*600))
	}

	deployments := []*BIP9Deployment{
		{
			Name:      "failed-no-bit",
			Bit:       7,
			StartTime: startTime - 10000,
			Timeout:   timeout,
			Period:    period,
			Threshold: 8,
		},
	}

	state := GetDeploymentState(deployments[0], 0, chain.tip(), params, nil)
	if state != DeploymentFailed {
		t.Fatalf("prerequisite: expected failed, got %s", state)
	}

	version := ComputeBlockVersion(chain.tip(), deployments, params, nil)
	if version != VersionBitsTopBits {
		t.Errorf("FAILED state should not set bit: got 0x%x, want 0x%x (base only)",
			version, VersionBitsTopBits)
	}
}

// TestGetStateSinceHeight_AlwaysActiveAndNeverActive checks that ALWAYS_ACTIVE
// and NEVER_ACTIVE both return since=0 (genesis), matching Core.
func TestGetStateSinceHeight_AlwaysActiveAndNeverActive(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)
	chain.addBlocksWithVersion(20, 0x20000000, 1600000000)

	depAlways := &BIP9Deployment{
		Name:      "always",
		Bit:       0,
		StartTime: AlwaysActive,
		Timeout:   NoTimeout,
		Period:    10,
	}
	depNever := &BIP9Deployment{
		Name:      "never",
		Bit:       1,
		StartTime: NeverActive,
		Timeout:   NoTimeout,
		Period:    10,
	}

	if h := GetStateSinceHeight(depAlways, 0, chain.tip(), params, nil); h != 0 {
		t.Errorf("AlwaysActive since: got %d, want 0", h)
	}
	if h := GetStateSinceHeight(depNever, 1, chain.tip(), params, nil); h != 0 {
		t.Errorf("NeverActive since: got %d, want 0", h)
	}
}

// TestGetStateSinceHeight_ActiveSince verifies that GetStateSinceHeight returns
// the correct height since which ACTIVE state applies.
//
// Blockbrew follows Bitcoin Core's GetStateSinceHeightFor convention:
// GetDeploymentState(tip=X) returns the state for the block AFTER X.  So at
// tip height 29 (end of the third period) the state is ACTIVE for block 30
// onward.  GetStateSinceHeight walks the period-aligned pointers and returns
// pindexPrev.Height + 1, which is 30 in this configuration.
func TestGetStateSinceHeight_ActiveSince(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)

	period := int32(10)
	startTime := int64(1600000000)
	threshold := int32(8)

	// Period 1 (heights 0-9): DEFINED
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(i)*600))
	}
	// Period 2 (heights 10-19): STARTED → LOCKED_IN (all 10 signal bit 0)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000001, uint32(startTime+int64(period)*600+int64(i)*600))
	}
	// Period 3 (heights 20-29): LOCKED_IN → ACTIVE (one period after lock-in)
	for i := 0; i < int(period); i++ {
		chain.addBlock(0x20000000, uint32(startTime+int64(2*period)*600+int64(i)*600))
	}

	dep := &BIP9Deployment{
		Name:                "active-since",
		Bit:                 0,
		StartTime:           startTime - 10000,
		Timeout:             NoTimeout,
		Period:              period,
		Threshold:           threshold,
		MinActivationHeight: 0,
	}

	// Verify state is indeed ACTIVE at tip height 29.
	state := GetDeploymentState(dep, 0, chain.tip(), params, nil)
	if state != DeploymentActive {
		t.Fatalf("prerequisite: expected active at height 29, got %s", state)
	}

	// GetStateSinceHeight with tip=29: aligns to period end at 29,
	// checks parent at 19 (LOCKED_IN ≠ ACTIVE), stops.
	// Returns 29 + 1 = 30.  Block 30 is the first block in ACTIVE state.
	since := GetStateSinceHeight(dep, 0, chain.tip(), params, nil)
	if since != 30 {
		t.Errorf("ACTIVE since: got %d, want 30", since)
	}
}

// TestGetStateSinceHeight_Defined verifies that DEFINED state returns 0
// (genesis), matching Core's GetStateSinceHeightFor behaviour.
func TestGetStateSinceHeight_Defined(t *testing.T) {
	params := RegtestParams()
	chain := newMockChain(params)
	chain.addBlocksWithVersion(5, 0x20000000, 1600000000)

	dep := &BIP9Deployment{
		Name:      "far-future",
		Bit:       0,
		StartTime: int64(9999999999), // far in the future
		Timeout:   NoTimeout,
		Period:    10,
		Threshold: 8,
	}

	since := GetStateSinceHeight(dep, 0, chain.tip(), params, nil)
	if since != 0 {
		t.Errorf("DEFINED since: got %d, want 0", since)
	}
}

// TestBlockSignals_Bit28Mask verifies the highest signaling bit (28) works
// correctly with the VersionBitsTopMask.  0x30000000 = 0x20000000 | (1<<28).
func TestBlockSignals_Bit28Mask(t *testing.T) {
	// 0x30000000 = 0x20000000 | 0x10000000; top-3 bits = 001 → valid BIP9 + bit 28 set.
	if !BlockSignals(0x30000000, 1<<28) {
		t.Error("bit 28 should signal in version 0x30000000")
	}
	// 0x20000000 alone: bit 28 NOT set.
	if BlockSignals(0x20000000, 1<<28) {
		t.Error("bit 28 should NOT signal in base version 0x20000000")
	}
}

// TestVersionBitsConstants verifies the three BIP9 protocol constants match
// the values specified in BIP-9 and Bitcoin Core.
func TestVersionBitsConstants(t *testing.T) {
	// Core src/versionbits.h: VERSIONBITS_TOP_BITS = 0x20000000UL
	if VersionBitsTopBits != 0x20000000 {
		t.Errorf("VersionBitsTopBits = 0x%x, want 0x20000000", VersionBitsTopBits)
	}
	// Core: VERSIONBITS_TOP_MASK = 0xE0000000UL (= -0x20000000 in int32 two's complement)
	if VersionBitsTopMask != -0x20000000 {
		t.Errorf("VersionBitsTopMask = 0x%x, want 0xe0000000 (−0x20000000 as int32)", VersionBitsTopMask)
	}
	// Core: VERSIONBITS_NUM_BITS = 29
	if VersionBitsNumBits != 29 {
		t.Errorf("VersionBitsNumBits = %d, want 29", VersionBitsNumBits)
	}
	// Special time constants
	if AlwaysActive != -1 {
		t.Errorf("AlwaysActive = %d, want -1", AlwaysActive)
	}
	if NeverActive != -2 {
		t.Errorf("NeverActive = %d, want -2", NeverActive)
	}
}
