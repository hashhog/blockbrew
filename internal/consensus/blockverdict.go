package consensus

import (
	"errors"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ErrScriptPrevoutMissing is the script-check pass's "prevout not in the view"
// error. Its text ("missing UTXO") is unchanged from the untyped error it
// replaces; it exists so classification below can use errors.Is instead of
// matching the string. Like ErrMissingInput it is NOT treated as a verdict on
// the block (see blockVerdict).
var ErrScriptPrevoutMissing = errors.New("missing UTXO")

// ErrInvalidParentHeader is returned by AddHeader for a header whose parent is
// already known to be invalid (failed itself, or descends from a failed
// block). Bitcoin Core: AcceptBlockHeader -> "bad-prevblk"
// (BLOCK_INVALID_PREV), which MaybePunishNodeForBlock punishes.
var ErrInvalidParentHeader = errors.New("bad-prevblk: header extends a block known to be invalid")

// BlockInvalidError is a consensus VERDICT on one specific block: the block
// itself breaks a consensus rule, so (like Core's BlockValidationResult::
// BLOCK_CONSENSUS) it must be marked failed, never re-requested, and the peer
// that delivered it punished. Core: Chainstate::InvalidBlockFound
// (validation.cpp) sets BLOCK_FAILED_VALID unless the result is BLOCK_MUTATED.
//
// ConnectBlock wraps only the failures that are a verdict (see blockVerdict);
// everything else — a mutated body, a missing ancestor header, a prevout absent
// from the local UTXO set, I/O — stays a plain error, so callers keep treating
// it as "cannot decide / local problem" and never mark the block.
//
// Error() is the wrapped error's text unchanged, so string-based consumers
// (BIP-22 reason mapping, logs) see exactly what they saw before.
type BlockInvalidError struct {
	Hash wire.Hash256 // the block that failed (not necessarily the one submitted: a reorg names the culprit)
	Err  error
}

func (e *BlockInvalidError) Error() string { return e.Err.Error() }
func (e *BlockInvalidError) Unwrap() error { return e.Err }

// AsBlockInvalid extracts the BlockInvalidError from err's chain, if any.
func AsBlockInvalid(err error) (*BlockInvalidError, bool) {
	var bie *BlockInvalidError
	if errors.As(err, &bie) {
		return bie, true
	}
	return nil, false
}

// IsBlockMutationErr reports whether err is a BLOCK_MUTATED-class failure: the
// delivered BODY does not match what the (still possibly valid) header commits
// to, so the hash must not be marked failed — an honest peer can deliver the
// real block under the same hash. Core: CheckBlock "bad-txnmrklroot" /
// "bad-txns-duplicate", CheckWitnessMalleation "bad-witness-nonce-size" /
// "bad-witness-merkle-match" / "unexpected-witness" (validation.cpp).
func IsBlockMutationErr(err error) bool {
	return errors.Is(err, ErrBlockMutated) ||
		errors.Is(err, ErrBadMerkleRoot) ||
		errors.Is(err, ErrBadWitnessNonceSize) ||
		errors.Is(err, ErrUnexpectedWitnessInBlock) ||
		errors.Is(err, ErrBadWitnessCommitment)
}

// isLocalUTXOGap reports whether err says an input's prevout is absent from the
// local UTXO view. In Core that is bad-txns-inputs-missingorspent, a consensus
// verdict; blockbrew deliberately does NOT treat it as one on the active-tip
// connect path, because blockbrew has a documented history of LOCAL UTXO
// damage (lost flush windows, marker lag) that produces exactly this error on
// a valid block. The P2P connect loop runs the marker-lag adopt probe and then
// HALTS loudly ([CHAINSTATE-CORRUPTION]) rather than blacklisting what may be
// the honest chain. A deliberate, documented divergence from Core.
func isLocalUTXOGap(err error) bool {
	return errors.Is(err, ErrMissingInput) || errors.Is(err, ErrScriptPrevoutMissing)
}

// blockVerdict wraps err as a BlockInvalidError for block `hash` when it is a
// consensus verdict on that block, and returns it unchanged otherwise.
func blockVerdict(hash wire.Hash256, err error) error {
	if err == nil || IsMissingAncestorErr(err) || IsBlockMutationErr(err) || isLocalUTXOGap(err) {
		return err
	}
	if _, already := AsBlockInvalid(err); already {
		return err
	}
	return &BlockInvalidError{Hash: hash, Err: err}
}
