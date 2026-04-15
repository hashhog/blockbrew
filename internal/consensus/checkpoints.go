package consensus

import (
	"github.com/hashhog/blockbrew/internal/wire"
)

// Checkpoint represents a known-good block hash at a specific height.
// Checkpoints protect against long-range attacks during initial sync.
type Checkpoint struct {
	Height int32
	Hash   wire.Hash256
}

// CheckpointData contains all checkpoints for a network.
type CheckpointData struct {
	Checkpoints []Checkpoint
	// Map for O(1) lookup by height
	byHeight map[int32]wire.Hash256
	// Highest checkpoint for fork rejection
	lastCheckpoint *Checkpoint
}

// NewCheckpointData creates checkpoint data from a list of checkpoints.
func NewCheckpointData(checkpoints []Checkpoint) *CheckpointData {
	cd := &CheckpointData{
		Checkpoints: checkpoints,
		byHeight:    make(map[int32]wire.Hash256, len(checkpoints)),
	}

	for i := range checkpoints {
		cp := &checkpoints[i]
		cd.byHeight[cp.Height] = cp.Hash
		if cd.lastCheckpoint == nil || cp.Height > cd.lastCheckpoint.Height {
			cd.lastCheckpoint = cp
		}
	}

	return cd
}

// GetCheckpointByHeight returns the expected hash at a checkpoint height.
// Returns the hash and true if found, zero hash and false otherwise.
func (cd *CheckpointData) GetCheckpointByHeight(height int32) (wire.Hash256, bool) {
	if cd == nil || cd.byHeight == nil {
		return wire.Hash256{}, false
	}
	hash, ok := cd.byHeight[height]
	return hash, ok
}

// GetLastCheckpoint returns the highest checkpoint, or nil if none.
func (cd *CheckpointData) GetLastCheckpoint() *Checkpoint {
	if cd == nil {
		return nil
	}
	return cd.lastCheckpoint
}

// IsEmpty returns true if there are no checkpoints.
func (cd *CheckpointData) IsEmpty() bool {
	return cd == nil || len(cd.Checkpoints) == 0
}

// MainnetCheckpoints contains hardcoded known-good blocks for mainnet.
// These are taken from Bitcoin Core's chainparams.cpp.
var MainnetCheckpoints = []Checkpoint{
	{11111, mustParseHash("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
	{33333, mustParseHash("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
	{74000, mustParseHash("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
	{105000, mustParseHash("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
	{134444, mustParseHash("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
	{168000, mustParseHash("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
	{193000, mustParseHash("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
	{210000, mustParseHash("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
	{250000, mustParseHash("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
	{295000, mustParseHash("00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
}

// Testnet3Checkpoints contains known-good blocks for testnet3.
// Testnet3 is less stable, so fewer checkpoints are useful.
var Testnet3Checkpoints = []Checkpoint{
	{546, mustParseHash("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
}

// Testnet4Checkpoints contains known-good blocks for testnet4.
var Testnet4Checkpoints = []Checkpoint{
	// Testnet4 is new (BIP 94), limited checkpoint history available
}

// SignetCheckpoints contains known-good blocks for signet.
var SignetCheckpoints = []Checkpoint{
	// Signet uses challenge-based block signing, checkpoints less critical
}

// RegtestCheckpoints contains known-good blocks for regtest.
// Regtest has no checkpoints - it's a private testing network.
var RegtestCheckpoints = []Checkpoint{}

// GetCheckpointsForNetwork returns the checkpoint data for a given network name.
func GetCheckpointsForNetwork(networkName string) *CheckpointData {
	switch networkName {
	case "mainnet":
		return NewCheckpointData(MainnetCheckpoints)
	case "testnet3":
		return NewCheckpointData(Testnet3Checkpoints)
	case "testnet4":
		return NewCheckpointData(Testnet4Checkpoints)
	case "signet":
		return NewCheckpointData(SignetCheckpoints)
	case "regtest":
		return NewCheckpointData(RegtestCheckpoints)
	default:
		return NewCheckpointData(nil)
	}
}

// VerifyCheckpoint checks if a block at the given height matches the expected checkpoint hash.
// Returns nil if no checkpoint exists at this height, or if the hash matches.
// Returns ErrCheckpointMismatch if the hash doesn't match the checkpoint.
func VerifyCheckpoint(cd *CheckpointData, height int32, hash wire.Hash256) error {
	if cd == nil {
		return nil
	}

	expectedHash, ok := cd.GetCheckpointByHeight(height)
	if !ok {
		// No checkpoint at this height - that's fine
		return nil
	}

	if hash != expectedHash {
		return ErrCheckpointMismatch
	}

	return nil
}

// CheckForkBeforeLastCheckpoint checks if a header chain would fork before the last checkpoint.
// This rejects any chain that diverges from the known-good chain at a height <= last checkpoint.
//
// Parameters:
//   - cd: checkpoint data for the network
//   - headerHeight: height of the header being added
//   - isFork: true if this header creates a fork (i.e., there's already a different block at this height on the best chain)
//
// Returns ErrForkBeforeCheckpoint if the header would create a fork at or below the checkpoint.
//
// NOTE (W15 root-cause fix): this function is preserved for test compatibility but
// is no longer used in the live header-validation path.  It was over-aggressive —
// "would create a fork" as computed by wouldCreateFork() fires for ANY header whose
// parent is off the current best chain, which during IBD catch-up includes every
// honest peer's legitimate header batch (W8/W12/W13/W14 cascade).  The production
// path now calls CheckForkConflictsWithCheckpoint (below), which only rejects
// when an ancestor of the new header AT a known-checkpoint height hashes
// differently from the known checkpoint — matching Bitcoin Core semantics.
func CheckForkBeforeLastCheckpoint(cd *CheckpointData, headerHeight int32, isFork bool) error {
	if cd == nil || cd.IsEmpty() {
		return nil
	}

	lastCP := cd.GetLastCheckpoint()
	if lastCP == nil {
		return nil
	}

	// If the header's height is <= the last checkpoint height and
	// it would create a fork, reject it.
	if headerHeight <= lastCP.Height && isFork {
		return ErrForkBeforeCheckpoint
	}

	return nil
}

// checkpointAncestorGetter is the minimal interface a BlockNode satisfies for
// the checkpoint-conflict check.  Kept as a tiny interface so checkpoints.go
// has no dependency on the BlockNode struct layout.
type checkpointAncestorGetter interface {
	GetAncestorHashAtHeight(height int32) (wire.Hash256, bool)
}

// CheckForkConflictsWithCheckpoint rejects a candidate header ONLY when its
// ancestor chain has an ACTUAL hash conflict with a known checkpoint.
//
// Semantics (Core-like, per src/validation.cpp checkpoint handling):
//   - Walk each known checkpoint at height h where h <= headerHeight.
//   - If the candidate's parent chain has an ancestor at height h with a hash
//     different from the known checkpoint hash, reject: this peer is feeding
//     us a chain that contradicts a hard-coded checkpoint.
//   - If the candidate's parent chain doesn't reach height h (e.g. candidate
//     is itself below h or ancestor lookup returns not-found), do NOT reject —
//     we simply don't have the evidence to call it a conflict.  The caller's
//     orphan / PoW / VerifyCheckpoint checks will handle those paths.
//
// This replaces the W8-era rule "fork before last checkpoint is not allowed"
// which fired on every wouldCreateFork() == true at height <= lastCP, and
// which (with a +100 misbehavior penalty) drained the outbound peer pool
// during IBD catch-up.  See wave14-2026-04-14/BLOCKBREW-DURABILITY.md.
func CheckForkConflictsWithCheckpoint(cd *CheckpointData, parent checkpointAncestorGetter, headerHeight int32) error {
	if cd == nil || cd.IsEmpty() || parent == nil {
		return nil
	}

	for i := range cd.Checkpoints {
		cp := &cd.Checkpoints[i]
		if cp.Height > headerHeight-1 {
			// Checkpoint is above parent's height; the candidate's ancestor
			// chain cannot contradict it yet.
			continue
		}
		ancestorHash, ok := parent.GetAncestorHashAtHeight(cp.Height)
		if !ok {
			// Parent chain doesn't reach this checkpoint height in-memory.
			// Don't treat missing evidence as a conflict.
			continue
		}
		if ancestorHash != cp.Hash {
			return ErrForkBeforeCheckpoint
		}
	}
	return nil
}
