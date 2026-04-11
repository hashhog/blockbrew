// Package consensus provides BIP9 version bits deployment tracking.
package consensus

import "sync"

// BIP9 version bit constants.
const (
	// VersionBitsTopBits is the top 3 bits that must be set for BIP9 signaling.
	// Binary: 001xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	VersionBitsTopBits int32 = 0x20000000

	// VersionBitsTopMask is the mask to check the top 3 bits.
	// Note: Using negative representation for 0xE0000000 which overflows int32.
	VersionBitsTopMask int32 = -0x20000000 // Equivalent to 0xE0000000 in two's complement

	// VersionBitsNumBits is the number of bits available for signaling (0-28).
	VersionBitsNumBits = 29
)

// Special deployment timing values.
const (
	// AlwaysActive indicates a deployment that is always active (for testing).
	AlwaysActive int64 = -1

	// NeverActive indicates a deployment that is disabled.
	NeverActive int64 = -2

	// NoTimeout indicates no timeout for a deployment.
	NoTimeout int64 = 0x7FFFFFFFFFFFFFFF
)

// DeploymentState represents the current state of a BIP9 soft fork deployment.
type DeploymentState int

const (
	// DeploymentDefined is the initial state before the start time.
	DeploymentDefined DeploymentState = iota

	// DeploymentStarted means signaling period has begun (past start time).
	DeploymentStarted

	// DeploymentLockedIn means threshold was reached, waiting for activation.
	DeploymentLockedIn

	// DeploymentActive means the deployment rules are enforced (terminal state).
	DeploymentActive

	// DeploymentFailed means the deployment timed out without activation (terminal state).
	DeploymentFailed
)

// String returns a human-readable name for the deployment state.
func (s DeploymentState) String() string {
	switch s {
	case DeploymentDefined:
		return "defined"
	case DeploymentStarted:
		return "started"
	case DeploymentLockedIn:
		return "locked_in"
	case DeploymentActive:
		return "active"
	case DeploymentFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// BIP9Deployment defines a soft fork deployment tracked via version bits.
type BIP9Deployment struct {
	// Name is the human-readable name for this deployment.
	Name string

	// Bit is the version bit position (0-28) used for signaling.
	Bit int

	// StartTime is the earliest median time past at which signaling begins.
	// Use AlwaysActive (-1) for always-on deployments.
	// Use NeverActive (-2) for disabled deployments.
	StartTime int64

	// Timeout is the median time past after which the deployment fails
	// if not locked in. Use NoTimeout for deployments that never expire.
	Timeout int64

	// MinActivationHeight is the minimum height at which activation can occur,
	// even if locked in earlier. Used by Speedy Trial (BIP 341).
	MinActivationHeight int32

	// Period is the number of blocks per signaling period (usually 2016).
	Period int32

	// Threshold is the number of signaling blocks required in a period
	// to achieve lock-in (usually 1815 for ~90% on mainnet).
	Threshold int32
}

// Mask returns the bitmask for this deployment's signaling bit.
func (d *BIP9Deployment) Mask() int32 {
	return 1 << d.Bit
}

// BIP9Stats contains statistics about the current signaling period.
type BIP9Stats struct {
	Period    int32 // Length of the signaling period
	Threshold int32 // Required signals to lock in
	Elapsed   int32 // Blocks elapsed in the current period
	Count     int32 // Signaling blocks counted so far
	Possible  bool  // Can threshold still be reached in this period?
}

// VersionBitsCache caches deployment states per period boundary.
// Thread-safe for concurrent access.
type VersionBitsCache struct {
	mu    sync.RWMutex
	cache map[cacheKey]DeploymentState
}

// cacheKey uniquely identifies a deployment state at a period boundary.
type cacheKey struct {
	deploymentIndex int
	periodEndHeight int32
}

// NewVersionBitsCache creates a new version bits state cache.
func NewVersionBitsCache() *VersionBitsCache {
	return &VersionBitsCache{
		cache: make(map[cacheKey]DeploymentState),
	}
}

// Get retrieves a cached state, returning (state, true) if found.
func (c *VersionBitsCache) Get(deploymentIndex int, periodEndHeight int32) (DeploymentState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.cache[cacheKey{deploymentIndex, periodEndHeight}]
	return state, ok
}

// Set stores a state in the cache.
func (c *VersionBitsCache) Set(deploymentIndex int, periodEndHeight int32, state DeploymentState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[cacheKey{deploymentIndex, periodEndHeight}] = state
}

// Clear empties the cache (useful after a reorg).
func (c *VersionBitsCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[cacheKey]DeploymentState)
}

// GetDeploymentState computes the current state of a deployment at the given chain tip.
// The state is determined by walking backwards through retarget periods.
//
// Parameters:
//   - deployment: the BIP9 deployment to check
//   - deploymentIndex: index for caching purposes
//   - tip: the current chain tip (pass nil for genesis)
//   - params: chain parameters
//   - cache: optional state cache (can be nil)
func GetDeploymentState(
	deployment *BIP9Deployment,
	deploymentIndex int,
	tip *BlockNode,
	params *ChainParams,
	cache *VersionBitsCache,
) DeploymentState {
	// Handle special deployment modes
	if deployment.StartTime == AlwaysActive {
		return DeploymentActive
	}
	if deployment.StartTime == NeverActive {
		return DeploymentFailed
	}

	// Genesis block (nil tip) is always DEFINED
	if tip == nil {
		return DeploymentDefined
	}

	period := deployment.Period
	if period == 0 {
		period = int32(params.DifficultyAdjInterval)
	}

	threshold := deployment.Threshold
	if threshold == 0 {
		// Default: ~90% for mainnet (1815/2016), 75% for testnet
		if params.Name == "mainnet" {
			threshold = 1815
		} else {
			threshold = period * 75 / 100
		}
	}

	// Find the last block of the previous retarget period
	// State is computed at period boundaries: height % period == period - 1
	periodEndHeight := getPeriodEndHeight(tip.Height, period)

	// Walk backwards collecting period boundaries to compute
	var toCompute []int32
	currentHeight := periodEndHeight

	for currentHeight >= 0 {
		// Check cache
		if cache != nil {
			if _, ok := cache.Get(deploymentIndex, currentHeight); ok {
				// Found a cached state, compute forward from here
				break
			}
		}

		// If we're before the start time, we know the state is DEFINED
		node := tip.GetAncestor(currentHeight)
		if node == nil {
			// Before genesis, state is DEFINED
			break
		}
		mtp := node.GetMedianTimePast()
		if mtp < deployment.StartTime {
			// Before start time, state is DEFINED (optimization)
			if cache != nil {
				cache.Set(deploymentIndex, currentHeight, DeploymentDefined)
			}
			break
		}

		toCompute = append(toCompute, currentHeight)
		currentHeight -= period
	}

	// Get the starting state
	var state DeploymentState
	if currentHeight < 0 {
		state = DeploymentDefined
	} else if cache != nil {
		if s, ok := cache.Get(deploymentIndex, currentHeight); ok {
			state = s
		} else {
			state = DeploymentDefined
		}
	} else {
		state = DeploymentDefined
	}

	// Walk forward computing states for each period
	for i := len(toCompute) - 1; i >= 0; i-- {
		height := toCompute[i]
		node := tip.GetAncestor(height)
		if node == nil {
			continue
		}

		mtp := node.GetMedianTimePast()
		state = computeNextState(state, deployment, node, mtp, period, threshold, tip)

		if cache != nil {
			cache.Set(deploymentIndex, height, state)
		}
	}

	return state
}

// getPeriodEndHeight returns the height used to determine the deployment state
// applicable to the block AFTER height. This follows Bitcoin Core semantics where
// GetStateFor(pindexPrev) returns the state for the next block.
//
// If height is exactly at a period boundary (height % period == period-1), the
// state for the next block is determined by counting signals in the CURRENT period
// (ending at height), so we return height itself.
//
// Otherwise, the next block is mid-period and inherits the state computed at the
// end of the PREVIOUS period.
//
// For period=2016, where ^ marks the evaluated boundary:
//   - Heights 0-2015 are in period 0; computing for block 2016 uses height 2015^
//   - Heights 2016-4031 are in period 1; computing for block 4032 uses height 4031^
//   - Computing for any block 2016-4031 mid-period uses height 2015^ (previous end)
func getPeriodEndHeight(height int32, period int32) int32 {
	if height >= 0 && (height+1)%period == 0 {
		// height is the last block of its period; state for the next block is
		// computed from this period's signaling.
		return height
	}
	// height is mid-period; the next block inherits the state from the previous
	// period boundary.
	periodNum := height / period
	return periodNum*period - 1
}

// computeNextState calculates the next deployment state given the current state
// and the block at the end of the retarget period.
func computeNextState(
	currentState DeploymentState,
	deployment *BIP9Deployment,
	periodEnd *BlockNode,
	mtp int64,
	period int32,
	threshold int32,
	tip *BlockNode,
) DeploymentState {
	switch currentState {
	case DeploymentDefined:
		// Transition to STARTED when MTP >= StartTime
		if mtp >= deployment.StartTime {
			return DeploymentStarted
		}
		return DeploymentDefined

	case DeploymentStarted:
		// Check for timeout first (MTP >= Timeout means FAILED)
		if deployment.Timeout != NoTimeout && mtp >= deployment.Timeout {
			return DeploymentFailed
		}

		// Count signaling blocks in this period
		count := countSignalingBlocks(deployment, periodEnd, period, tip)
		if count >= threshold {
			return DeploymentLockedIn
		}
		return DeploymentStarted

	case DeploymentLockedIn:
		// Transition to ACTIVE at the next period boundary if height >= MinActivationHeight
		// The activation height is the first block of the NEXT period
		activationHeight := periodEnd.Height + 1
		if activationHeight >= deployment.MinActivationHeight {
			return DeploymentActive
		}
		return DeploymentLockedIn

	case DeploymentActive:
		// Terminal state
		return DeploymentActive

	case DeploymentFailed:
		// Terminal state
		return DeploymentFailed
	}

	return currentState
}

// countSignalingBlocks counts how many blocks in the period ending at periodEnd
// are signaling for the deployment.
func countSignalingBlocks(deployment *BIP9Deployment, periodEnd *BlockNode, period int32, tip *BlockNode) int32 {
	var count int32
	mask := deployment.Mask()

	node := periodEnd
	for i := int32(0); i < period && node != nil; i++ {
		if BlockSignals(node.Header.Version, mask) {
			count++
		}
		node = node.Parent
	}

	return count
}

// BlockSignals returns true if the block version signals for a deployment.
// A block signals if:
// 1. The top 3 bits match the BIP9 pattern (001)
// 2. The deployment's bit is set
func BlockSignals(version int32, mask int32) bool {
	return (version&VersionBitsTopMask) == VersionBitsTopBits && (version&mask) != 0
}

// ComputeBlockVersion calculates the block version to use for a new block.
// It sets the BIP9 base version (0x20000000) and adds signaling bits for
// all deployments in STARTED or LOCKED_IN state.
func ComputeBlockVersion(
	tip *BlockNode,
	deployments []*BIP9Deployment,
	params *ChainParams,
	cache *VersionBitsCache,
) int32 {
	version := VersionBitsTopBits

	for i, deployment := range deployments {
		state := GetDeploymentState(deployment, i, tip, params, cache)
		if state == DeploymentStarted || state == DeploymentLockedIn {
			version |= deployment.Mask()
		}
	}

	return version
}

// GetDeploymentStats returns statistics about the current signaling period
// for a deployment.
func GetDeploymentStats(
	deployment *BIP9Deployment,
	tip *BlockNode,
	params *ChainParams,
) *BIP9Stats {
	if tip == nil {
		return nil
	}

	period := deployment.Period
	if period == 0 {
		period = int32(params.DifficultyAdjInterval)
	}

	threshold := deployment.Threshold
	if threshold == 0 {
		if params.Name == "mainnet" {
			threshold = 1815
		} else {
			threshold = period * 75 / 100
		}
	}

	// Find position in current period
	// Blocks 0 to period-1 are in period 0
	posInPeriod := (tip.Height % period) + 1
	elapsed := posInPeriod

	// Count signaling blocks in the current (incomplete) period
	periodStartHeight := (tip.Height / period) * period
	var count int32

	node := tip
	for node != nil && node.Height >= periodStartHeight {
		if BlockSignals(node.Header.Version, deployment.Mask()) {
			count++
		}
		node = node.Parent
	}

	// Can we still reach the threshold?
	remaining := period - elapsed
	possible := count+remaining >= threshold

	return &BIP9Stats{
		Period:    period,
		Threshold: threshold,
		Elapsed:   elapsed,
		Count:     count,
		Possible:  possible,
	}
}

// DeploymentActiveAt returns true if the deployment is active at the given block.
// This means the deployment was ACTIVE when the block was mined.
func DeploymentActiveAt(
	deployment *BIP9Deployment,
	deploymentIndex int,
	node *BlockNode,
	params *ChainParams,
	cache *VersionBitsCache,
) bool {
	if node == nil {
		return false
	}
	// State is computed based on the parent
	state := GetDeploymentState(deployment, deploymentIndex, node.Parent, params, cache)
	return state == DeploymentActive
}

// DeploymentActiveAfter returns true if the deployment will be active for
// the block AFTER the given tip.
func DeploymentActiveAfter(
	deployment *BIP9Deployment,
	deploymentIndex int,
	tip *BlockNode,
	params *ChainParams,
	cache *VersionBitsCache,
) bool {
	state := GetDeploymentState(deployment, deploymentIndex, tip, params, cache)
	return state == DeploymentActive
}

// GetStateSinceHeight returns the height of the first block for which the
// current deployment state applied.  It mirrors Bitcoin Core's
// AbstractThresholdConditionChecker::GetStateSinceHeightFor.
//
// The caller passes the block PRIOR to the one being evaluated (pindexPrev in
// Core nomenclature), which matches the convention used by GetDeploymentState.
func GetStateSinceHeight(
	deployment *BIP9Deployment,
	deploymentIndex int,
	tip *BlockNode, // the block prior to the one being evaluated
	params *ChainParams,
	cache *VersionBitsCache,
) int32 {
	// Special modes: always-active or never-active deployments are treated as
	// active/failed from genesis height 0.
	if deployment.StartTime == AlwaysActive || deployment.StartTime == NeverActive {
		return 0
	}

	currentState := GetDeploymentState(deployment, deploymentIndex, tip, params, cache)

	// DEFINED state has been active since genesis.
	if currentState == DeploymentDefined {
		return 0
	}

	period := deployment.Period
	if period == 0 {
		period = int32(params.DifficultyAdjInterval)
	}

	// Align tip to the last block of its retarget period so that we walk
	// period-by-period backwards.  Bitcoin Core: pindexPrev->GetAncestor(
	//   pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod))
	if tip == nil {
		return 0
	}
	alignedHeight := tip.Height - ((tip.Height + 1) % period)
	pindexPrev := tip.GetAncestor(alignedHeight)
	if pindexPrev == nil {
		return 0
	}

	// Walk backwards one period at a time while the state matches.
	for {
		parentHeight := pindexPrev.Height - period
		if parentHeight < 0 {
			break
		}
		parent := pindexPrev.GetAncestor(parentHeight)
		if parent == nil {
			break
		}
		if GetDeploymentState(deployment, deploymentIndex, parent, params, cache) != currentState {
			break
		}
		pindexPrev = parent
	}

	// pindexPrev now points to the last block of the period before the
	// state change; the state first applies to the block at height+1.
	return pindexPrev.Height + 1
}
