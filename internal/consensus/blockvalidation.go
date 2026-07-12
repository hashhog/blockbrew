package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Block validation errors.
var (
	ErrNoTransactions     = errors.New("block has no transactions")
	ErrFirstTxNotCoinbase = errors.New("first transaction is not coinbase")
	ErrMultipleCoinbase   = errors.New("block has multiple coinbase transactions")
	ErrBadMerkleRoot      = errors.New("merkle root mismatch")
	// ErrBlockMutated signals CVE-2012-2459: the merkle tree contains a
	// duplicated adjacent pair, so a different transaction list could
	// produce the same merkle root. Treat as TRANSIENT — the block must
	// be rejected but MUST NOT be permanently marked invalid, because
	// the legitimate (un-mutated) form has the same block hash and is
	// still potentially valid. Bitcoin Core uses BLOCK_MUTATED for this
	// (validation.cpp:3850-3858, "bad-txns-duplicate").
	ErrBlockMutated = errors.New("block merkle tree mutated (CVE-2012-2459)")
	// ErrBlockLengthTooHigh is the context-free CheckBlock size gate: the
	// non-witness serialized size × WITNESS_SCALE_FACTOR exceeds
	// MAX_BLOCK_WEIGHT. Bitcoin Core reports this as "bad-blk-length"
	// (validation.cpp:3947-3948, CheckBlock — "size limits failed"). Kept
	// distinct from ErrBlockWeightTooHigh so the submitblock BIP-22 reason
	// string matches Core's two separate tokens (length vs. weight).
	ErrBlockLengthTooHigh = errors.New("block base size exceeds maximum")
	// ErrBlockWeightTooHigh is the witness-inclusive weight gate applied in
	// ContextualCheckBlock after the witness commitment is verified. Bitcoin
	// Core reports this as "bad-blk-weight" (validation.cpp:4179-4180 —
	// "weight limit failed").
	ErrBlockWeightTooHigh       = errors.New("block weight exceeds maximum")
	ErrTimestampTooFar          = errors.New("block timestamp too far in the future")
	ErrBlockVersionTooLow       = errors.New("block version too low for height")
	ErrTimestampBeforeMTP       = errors.New("block timestamp before median time past")
	ErrBadBIP34Height           = errors.New("coinbase does not contain valid block height")
	ErrMissingWitnessCommitment = errors.New("segwit block missing witness commitment")
	ErrBadWitnessCommitment     = errors.New("witness commitment mismatch")
	// ErrBadWitnessNonceSize signals that the coinbase scriptWitness does not
	// contain exactly one 32-byte element. Bitcoin Core: "bad-witness-nonce-size"
	// (validation.cpp:3880-3885, CheckWitnessMalleation).
	ErrBadWitnessNonceSize = errors.New("bad-witness-nonce-size")
	// ErrUnexpectedWitnessInBlock signals that witness data was found in a block
	// where no witness commitment exists (pre-segwit or malformed post-segwit
	// block). Bitcoin Core: "unexpected-witness"
	// (validation.cpp:3906-3912, CheckWitnessMalleation).
	ErrUnexpectedWitnessInBlock = errors.New("unexpected-witness")
	ErrSigOpsCostTooHigh        = errors.New("block sigops cost exceeds maximum")
	ErrBadCoinbaseValue         = errors.New("coinbase value exceeds allowed subsidy plus fees")
	ErrDuplicateTx              = errors.New("block contains duplicate transaction outputs (BIP30)")
	ErrDuplicateCoinbase        = errors.New("block contains duplicate coinbase outputs (BIP30)")
	ErrBadDifficultyBits        = errors.New("block difficulty bits do not match expected value")
)

// WitnessCommitmentMagic is the magic prefix for witness commitment in coinbase.
// Format: OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>
var WitnessCommitmentMagic = []byte{0xaa, 0x21, 0xa9, 0xed}

// CheckBlockSanity performs context-free checks on a block.
// powLimit is the maximum allowed proof of work target.
//
// The optional variadic skipPOW arg (default false) gates ONLY the
// CheckProofOfWork call, mirroring Bitcoin Core's CheckBlock(..., fCheckPOW)
// (validation.cpp CheckBlock signature, where the caller passes fCheckPOW=false
// for already-validated / differentially-mutated blocks). It defaults to false
// so every existing caller — CheckBlockSanity(block, powLimit) — is byte-for-byte
// unaffected and PoW is still enforced. It is set true ONLY by the validate-only
// differential checkblock shim, which feeds FINAL mutated block bytes whose hash
// no longer satisfies the (unchanged) bits target; without this gate a body
// mutation that recomputes nothing would be silently rejected on high-hash/PoW
// before its real body gate ever runs (a dead-gate). Max-powLimit alone does NOT
// bypass PoW because CheckProofOfWork also enforces hash <= target(bits), and
// target is derived from the block's OWN bits, not from powLimit.
func CheckBlockSanity(block *wire.MsgBlock, powLimit *big.Int, skipPOW ...bool) error {
	skip := len(skipPOW) > 0 && skipPOW[0]

	// 1. Block header proof of work is valid (hash <= target from bits)
	if !skip {
		blockHash := block.Header.BlockHash()
		if err := CheckProofOfWork(blockHash, block.Header.Bits, powLimit); err != nil {
			return err
		}
	}

	// 2. Block timestamp is not more than 2 hours in the future.
	//
	// In Bitcoin Core this "time-too-new" check is NOT part of CheckBlock (the
	// body sanity); it lives in ContextualCheckBlockHeader (validation.cpp:4108,
	// `block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME`) — a HEADER-
	// acceptance check run against wall-clock-now when a header is first
	// received, and NOT re-run during ConnectBlock re-validation on a reorg.
	// blockbrew folds it into CheckBlockSanity for convenience. Because it reads
	// time.Now() it is the one non-deterministic, wall-clock-dependent gate
	// here. The same `skip` flag that gates PoW (set true ONLY by the validate-
	// only differential shim, which feeds crafted/mutated blocks that were
	// already header-accepted on the live path) therefore also skips this
	// header-receipt time gate: a deterministic body re-validation must not
	// depend on wall-clock-now, and Core's ConnectBlock does not re-check it.
	// Default-preserving: every production caller passes skipPOW=false, so the
	// future-time gate stays fully active in real validation.
	if !skip {
		maxTime := time.Now().Unix() + MaxTimeAdjustment
		if int64(block.Header.Timestamp) > maxTime {
			return fmt.Errorf("%w: block time %d, max allowed %d",
				ErrTimestampTooFar, block.Header.Timestamp, maxTime)
		}
	}

	// 8. Block must have at least one transaction
	if len(block.Transactions) == 0 {
		return ErrNoTransactions
	}

	// 8b. Block size gate: non-witness serialized size × WITNESS_SCALE_FACTOR
	// must not exceed MaxBlockWeight. Mirrors Bitcoin Core CheckBlock
	// (validation.cpp:3947-3948, "bad-blk-length", "size limits failed"). Core
	// runs this "size limits" gate BEFORE the coinbase-shape checks and the
	// per-transaction CheckTransaction loop, so an oversize block built from a
	// single huge transaction reports bad-blk-length rather than the per-tx
	// oversize reason. We match that ordering so the reject-reason token equals
	// Core's on this path. Decision is unchanged: an oversize block is rejected
	// regardless of which gate fires, and a within-size block passes this gate
	// and proceeds to every subsequent check exactly as before. The witness-
	// inclusive weight check ("bad-blk-weight") stays deferred to
	// CheckBlockContext (after CheckWitnessMalleation) so a witness-padded block
	// sharing its hash with a legitimate block is not permanently failed before
	// witness integrity is verified (Core ContextualCheckBlock, validation.cpp:
	// 4173-4181).
	strippedWeight := CalcStrippedBlockWeight(block)
	if strippedWeight > MaxBlockWeight {
		return fmt.Errorf("%w: stripped weight %d > %d", ErrBlockLengthTooHigh, strippedWeight, MaxBlockWeight)
	}

	// 3. First transaction must be coinbase
	if !IsCoinbaseTx(block.Transactions[0]) {
		return ErrFirstTxNotCoinbase
	}

	// 4. No other transaction may be coinbase
	for i := 1; i < len(block.Transactions); i++ {
		if IsCoinbaseTx(block.Transactions[i]) {
			return ErrMultipleCoinbase
		}
	}

	// 5. All transactions pass CheckTransactionSanity
	for i, tx := range block.Transactions {
		if err := CheckTransactionSanity(tx); err != nil {
			return fmt.Errorf("transaction %d: %w", i, err)
		}
	}

	// 6. Merkle root matches computed Merkle root from transaction IDs.
	// The mutation flag detects CVE-2012-2459: if the tree contains a
	// duplicated adjacent pair, the matching merkle root could have come
	// from a different transaction list. Returning ErrBlockMutated
	// (instead of ErrBadMerkleRoot) lets the caller treat this as
	// transient — the block is rejected but the block hash must NOT be
	// permanently marked invalid, otherwise an attacker can DoS the node
	// by sending the mutated form before the legitimate form arrives.
	// Mirrors Core CheckMerkleRoot (validation.cpp:3837-3862).
	txHashes := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.TxHash()
	}
	calculatedMerkle, mutated := CalcMerkleRootMutation(txHashes)
	if calculatedMerkle != block.Header.MerkleRoot {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrBadMerkleRoot, calculatedMerkle.String(), block.Header.MerkleRoot.String())
	}
	if mutated {
		return ErrBlockMutated
	}
	// (The block size gate "bad-blk-length" runs earlier, as step 8b above,
	// to match Bitcoin Core's CheckBlock ordering — see that comment.)

	// 9. Block-wide legacy sigop-cost cap ("bad-blk-sigops").
	// Mirrors Bitcoin Core CheckBlock (validation.cpp:3971-3977): sum the
	// LEGACY sigop count over EVERY transaction INCLUDING the coinbase, scale
	// by WITNESS_SCALE_FACTOR, and reject if it exceeds MAX_BLOCK_SIGOPS_COST.
	// This underestimates the true cost (it omits P2SH and witness sigops,
	// which need the UTXO view and are re-counted in ConnectBlock) but is a
	// sound context-free gate. Crucially it counts the COINBASE's own sigops:
	// ConnectBlock's first-pass loop accumulates the coinbase sigops then
	// `continue`s before its own cap check, so a coinbase-only block whose
	// coinbase outputs carry excessive sigops (e.g. scriptPubKey = 1001× bare
	// OP_CHECKMULTISIG = 20020 legacy × 4 = 80080 > 80000) previously connected
	// on BOTH the submitblock and P2P paths. Being in the context-free
	// CheckBlockSanity, this gate runs on every path (submitblock, P2P
	// validationWorker, ConnectBlock re-check). Legacy count uses INACCURATE
	// CHECKMULTISIG=20, matching Core GetLegacySigOpCount → GetSigOpCount(false).
	legacySigOps := 0
	for _, tx := range block.Transactions {
		for _, txIn := range tx.TxIn {
			legacySigOps += CountSigOpsInaccurate(txIn.SignatureScript)
		}
		for _, txOut := range tx.TxOut {
			legacySigOps += CountSigOpsInaccurate(txOut.PkScript)
		}
	}
	if legacySigOps*WitnessScaleFactor > MaxBlockSigOpsCost {
		return fmt.Errorf("%w: %d > %d", ErrSigOpsCostTooHigh,
			legacySigOps*WitnessScaleFactor, MaxBlockSigOpsCost)
	}

	return nil
}

// CheckBlockHeaderVersion enforces the BIP34/66/65 mandatory-version-bump
// gates Bitcoin Core applies in ContextualCheckBlockHeader (validation.cpp:4112-
// 4124): once each soft-fork's activation height is reached, headers carrying an
// older version are rejected ("bad-version"). It is the single source of truth
// shared by CheckBlockContext (the block-level pipeline) and the header-level
// ContextualCheckBlockHeader differential, so a divergence is one real bug, not
// two parallel re-implementations. Production behavior is byte-identical to the
// inlined checks it replaces.
func CheckBlockHeaderVersion(version int32, height int32, params *ChainParams) error {
	if height >= params.BIP34Height && version < 2 {
		return fmt.Errorf("%w: version %d, need >= 2 for BIP34",
			ErrBlockVersionTooLow, version)
	}
	if height >= params.BIP66Height && version < 3 {
		return fmt.Errorf("%w: version %d, need >= 3 for BIP66",
			ErrBlockVersionTooLow, version)
	}
	if height >= params.BIP65Height && version < 4 {
		return fmt.Errorf("%w: version %d, need >= 4 for BIP65",
			ErrBlockVersionTooLow, version)
	}
	return nil
}

// CheckBlockContext performs context-dependent checks (requires chain state).
// medianTimePast is the MTP of the previous 11 blocks (0 to skip MTP check).
func CheckBlockContext(block *wire.MsgBlock, prevHeader *wire.BlockHeader, height int32, params *ChainParams, medianTimePast ...uint32) error {
	// 1-3. Block version checks based on BIP34/66/65 activation
	if err := CheckBlockHeaderVersion(block.Header.Version, height, params); err != nil {
		return err
	}

	// 4. Block timestamp must be greater than median time past (MTP)
	if len(medianTimePast) > 0 && medianTimePast[0] > 0 {
		if err := CheckBlockTimestamp(block.Header.Timestamp, medianTimePast[0]); err != nil {
			return err
		}
	}

	// 5. Witness commitment / malleation check.
	//
	// When segwit is active: require a valid witness commitment AND validate the
	// witness reserved value size.
	//
	// When segwit is NOT active: no transaction in the block may carry witness
	// data. Bitcoin Core calls CheckWitnessMalleation with expect_witness_commitment
	// = (segwit active) and — in the "no commitment" branch — rejects any block
	// whose transactions contain witness data with "unexpected-witness"
	// (validation.cpp:3905-3913).
	if height >= params.SegwitHeight {
		if err := checkWitnessCommitment(block); err != nil {
			return err
		}
	} else {
		// Pre-segwit: witness data in any transaction is invalid.
		for _, tx := range block.Transactions {
			if tx.HasWitness() {
				return ErrUnexpectedWitnessInBlock
			}
		}
	}

	// Witness-inclusive block weight check, deferred from CheckBlockSanity to
	// here so a witness-padded block (same hash, inflated witness) is rejected as
	// BLOCK_MUTATED (transient) by the witness commitment check above, rather than
	// permanently rejected on weight before witness integrity is verified.
	// Mirrors Bitcoin Core ContextualCheckBlock (validation.cpp:4173-4181):
	//   "After the coinbase witness reserved value and commitment are verified,
	//    we can check if the block weight passes (before we've checked the
	//    coinbase witness, it would be possible for the weight to be too large
	//    by filling up the coinbase witness, which doesn't change the block hash,
	//    so we couldn't mark the block as permanently failed)."
	// For pre-segwit blocks the witness is empty so CalcBlockWeight ==
	// CalcStrippedBlockWeight and this check is redundant but harmless.
	weight := CalcBlockWeight(block)
	if weight > MaxBlockWeight {
		return fmt.Errorf("%w: %d > %d", ErrBlockWeightTooHigh, weight, MaxBlockWeight)
	}

	// BIP34: coinbase must include the block height as a script number push
	if height >= params.BIP34Height {
		if err := checkBIP34Height(block.Transactions[0], height); err != nil {
			return err
		}
	}

	// Difficulty validation is handled by the header index during header sync
	// using GetNextWorkRequired(), which correctly handles all network-specific
	// rules including testnet min-difficulty walk-back, BIP94, and retarget
	// boundaries. We skip the redundant check here to avoid rejecting valid
	// blocks with a simplified check that doesn't handle all edge cases
	// (e.g., non-min-difficulty blocks after a min-difficulty parent on testnet4).

	// Check all transactions are final (IsFinalTx)
	// Use MTP as block time for BIP113 if CSV is active, otherwise use block timestamp
	var blockTime uint32
	if height >= params.CSVHeight && len(medianTimePast) > 0 {
		blockTime = medianTimePast[0]
	} else {
		blockTime = block.Header.Timestamp
	}
	for i, tx := range block.Transactions {
		if !IsFinalTx(tx, height, blockTime) {
			return fmt.Errorf("tx %d: %w", i, ErrNonFinalTx)
		}
	}

	return nil
}

// checkWitnessCommitment validates the witness commitment in a segwit block.
func checkWitnessCommitment(block *wire.MsgBlock) error {
	// Find witness commitment in coinbase outputs (use last matching output)
	coinbase := block.Transactions[0]
	var witnessCommitment []byte

	for i := len(coinbase.TxOut) - 1; i >= 0; i-- {
		out := coinbase.TxOut[i]
		// Look for OP_RETURN output with witness commitment magic
		// Format: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commitment>
		if len(out.PkScript) >= 38 &&
			out.PkScript[0] == script.OP_RETURN &&
			out.PkScript[1] == 0x24 && // 36 bytes push
			bytes.Equal(out.PkScript[2:6], WitnessCommitmentMagic) {
			witnessCommitment = out.PkScript[6:38]
			break
		}
	}

	// Check if any transaction has witness data
	hasWitness := false
	for _, tx := range block.Transactions {
		if tx.HasWitness() {
			hasWitness = true
			break
		}
	}

	// If no witness data, commitment is optional
	if !hasWitness && witnessCommitment == nil {
		return nil
	}

	// If there's witness data, commitment is required
	if witnessCommitment == nil {
		return ErrMissingWitnessCommitment
	}

	// Validate witness reserved value: coinbase input[0] scriptWitness must have
	// exactly one stack element of exactly 32 bytes. Bitcoin Core:
	//   if (witness_stack.size() != 1 || witness_stack[0].size() != 32)
	//       return state.Invalid(BLOCK_MUTATED, "bad-witness-nonce-size", ...)
	// (validation.cpp:3880-3885, CheckWitnessMalleation).
	witnessStack := coinbase.TxIn[0].Witness
	if len(witnessStack) != 1 || len(witnessStack[0]) != 32 {
		return ErrBadWitnessNonceSize
	}
	witnessReservedValue := witnessStack[0]

	// Calculate witness transaction IDs
	wtxids := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		wtxids[i] = tx.WTxHash()
	}

	// Calculate expected commitment
	expectedCommitment := CalcWitnessCommitment(wtxids, witnessReservedValue)

	// Compare
	if !bytes.Equal(witnessCommitment, expectedCommitment[:]) {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrBadWitnessCommitment, expectedCommitment[:], witnessCommitment)
	}

	return nil
}

// checkBIP34Height validates that the coinbase scriptSig starts with the
// byte-exact canonical encoding of expectedHeight, matching Bitcoin Core's
// ContextualCheckBlock (validation.cpp:4151-4159):
//
//	CScript expect = CScript() << nHeight;
//	sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
//
// The canonical encoding mirrors Core's CScript::push_int64 (script.h:433-448):
//   - height == 0  → OP_0 (0x00), single byte
//   - 1..16        → OP_1..OP_16 (0x51..0x60), single byte
//   - otherwise    → length-prefixed CScriptNum (sign-magnitude little-endian)
//
// Non-canonical forms (OP_PUSHDATA1 prefix, zero-padded mantissa, redundant
// sign byte, wrong OP_N for low heights) are rejected.
func checkBIP34Height(coinbase *wire.MsgTx, expectedHeight int32) error {
	if len(coinbase.TxIn) == 0 {
		return ErrBadBIP34Height
	}
	scriptSig := coinbase.TxIn[0].SignatureScript
	expect := encodeBIP34Height(expectedHeight)
	if len(scriptSig) < len(expect) || !bytes.Equal(scriptSig[:len(expect)], expect) {
		return fmt.Errorf("%w: expected prefix %x in scriptSig %x",
			ErrBadBIP34Height, expect, scriptSig)
	}
	return nil
}

// encodeBIP34Height returns the canonical BIP-34 byte encoding of height,
// matching Bitcoin Core's CScript() << nHeight (script.h:433-448).
func encodeBIP34Height(height int32) []byte {
	if height == 0 {
		// OP_0 — single byte 0x00
		return []byte{0x00}
	}
	if height >= 1 && height <= 16 {
		// OP_1..OP_16 — single byte 0x51..0x60
		return []byte{byte(0x50 + height)}
	}
	// CScriptNum: minimal sign-magnitude little-endian, prefixed by byte count.
	h := uint32(height)
	var le [4]byte
	n := 0
	for h > 0 {
		le[n] = byte(h & 0xff)
		h >>= 8
		n++
	}
	// If the high bit of the last byte is set, append a zero sign byte.
	if le[n-1]&0x80 != 0 {
		le[n] = 0x00
		n++
	}
	out := make([]byte, 1+n)
	out[0] = byte(n)
	copy(out[1:], le[:n])
	return out
}

// decodeScriptNum decodes a minimally-encoded script number (little-endian with sign bit).
func decodeScriptNum(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}

	// Little-endian with sign in high bit of last byte
	var result int64
	for i := 0; i < len(data); i++ {
		result |= int64(data[i]) << uint(8*i)
	}

	// Check sign bit
	if data[len(data)-1]&0x80 != 0 {
		// Clear the sign bit and negate
		result &= ^(int64(0x80) << uint(8*(len(data)-1)))
		result = -result
	}

	return result
}

// IsBIP30Repeat reports whether blockIndex is one of the two historical
// mainnet blocks that intentionally duplicated a coinbase transaction before
// BIP-30 was enforced.  These blocks are exempt from the duplicate-UTXO check.
//
// Mirrors Bitcoin Core validation.cpp IsBIP30Repeat() (line 6189-6193):
//
//	h=91842, hash=00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec
//	h=91880, hash=00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721
//
// NOTE: the check requires BOTH the correct height AND the exact block hash.
// A block at h=91842 with a different hash is NOT exempt.
func IsBIP30Repeat(height int32, blockHash wire.Hash256) bool {
	if height == 91842 {
		h, _ := wire.NewHash256FromHex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
		return blockHash == h
	}
	if height == 91880 {
		h, _ := wire.NewHash256FromHex("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
		return blockHash == h
	}
	return false
}

// IsBIP30Unspendable reports whether blockHash/height is one of the two
// historical mainnet blocks whose coinbase outputs are unspendable due to
// the BIP-30 duplicate coinbase situation.  Used during DisconnectBlock to
// skip the UTXO consistency check for those blocks.
//
// Mirrors Bitcoin Core validation.cpp IsBIP30Unspendable() (line 6195-6199):
//
//	h=91722, hash=00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e
//	h=91812, hash=00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f
func IsBIP30Unspendable(height int32, blockHash wire.Hash256) bool {
	if height == 91722 {
		h, _ := wire.NewHash256FromHex("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")
		return blockHash == h
	}
	if height == 91812 {
		h, _ := wire.NewHash256FromHex("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f")
		return blockHash == h
	}
	return false
}

// CheckBIP30 reports whether a block at the given height must enforce the
// BIP-30 duplicate-UTXO rule and, if so, whether any of its transactions
// would overwrite an existing UTXO entry in utxoView.
//
// BIP-30 is the live path for duplicate-UTXO detection; see
// ChainManager.ConnectBlock in chainmanager.go for production usage.
// This helper exists so the rule can also be unit-tested without a full
// ChainManager.
//
// Parameters:
//   - blockHash: the hash of the block being connected (for IsBIP30Repeat check)
//   - ancestorHashAt: optional fn that returns the hash of the block at a given
//     height on the current chain (used for BIP34 short-circuit).  May be nil,
//     in which case the BIP34 short-circuit is skipped (safe: over-checking).
//
// Exemption logic (mirrors Bitcoin Core ConnectBlock validation.cpp:2402-2476):
//  1. IsBIP30Repeat: h=91842 OR h=91880 with EXACT matching hash → exempt.
//  2. BIP34 short-circuit: if BIP34 is active AND the block at BIP34Height on
//     this chain matches params.BIP34Hash → exempt (unique heights prevent dups).
//  3. BIP34_IMPLIES_BIP30_LIMIT (1,983,702): always enforce at this height or
//     above, regardless of BIP34 (modular arithmetic could create duplicates).
func CheckBIP30(block *wire.MsgBlock, height int32, blockHash wire.Hash256, params *ChainParams, utxoView UTXOView, ancestorHashAt func(int32) (wire.Hash256, bool)) error {
	const bip34ImpliesBIP30Limit int32 = 1_983_702

	// Gate 1+2: IsBIP30Repeat — exempt the two historical duplicate-coinbase blocks.
	// Requires BOTH correct height AND exact block hash (Core IsBIP30Repeat, line 6189).
	enforce := !IsBIP30Repeat(height, blockHash)

	// Gate 4: BIP34 short-circuit — once BIP34 is unambiguously active on this
	// chain (block at BIP34Height matches the expected BIP34Hash), unique coinbase
	// heights make duplicates structurally impossible.
	//
	// W93 fix #5 (use PREVIOUS block's ancestor): Bitcoin Core looks up the
	// ancestor of pindex->pprev (validation.cpp:2460), not pindex itself. The
	// distinction matters at exactly height == BIP34Height: pprev sits at
	// BIP34Height-1 and has NO ancestor at BIP34Height, so Core leaves
	// fEnforceBIP30 = true. The previous blockbrew code used the current node
	// (height == BIP34Height) for the ancestor lookup, returning the block's
	// own hash. If that hash happened to equal BIP34Hash the short-circuit
	// fired one block too early. The fix is to compare against ancestor at
	// (height-1) which mirrors Core. For height > BIP34Height the result is
	// identical to the previous code.
	if enforce && height > params.BIP34Height && ancestorHashAt != nil && !params.BIP34Hash.IsZero() {
		if ancHash, ok := ancestorHashAt(params.BIP34Height); ok && ancHash == params.BIP34Hash {
			enforce = false
		}
	}

	// Gate 5: BIP34_IMPLIES_BIP30_LIMIT — re-enforce above height 1,983,702.
	// Mirrors: validation.cpp:2467 "if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT)".
	if height >= bip34ImpliesBIP30Limit {
		enforce = true
	}

	if !enforce {
		return nil
	}

	// Gate 1 (UTXO lookup): reject if any output would overwrite an existing UTXO.
	// Mirrors: validation.cpp:2468-2475.
	for _, tx := range block.Transactions {
		txHash := tx.TxHash()
		for i := range tx.TxOut {
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(i)}
			if utxoView.GetUTXO(outpoint) != nil {
				return fmt.Errorf("%w: output %s:%d already exists",
					ErrDuplicateTx, txHash.String()[:16], i)
			}
		}
	}
	return nil
}

// CalcMedianTimePast calculates the median time past for a block.
// This is the median timestamp of the previous MedianTimeSpan (11) blocks.
func CalcMedianTimePast(timestamps []uint32) uint32 {
	if len(timestamps) == 0 {
		return 0
	}

	// Copy and sort timestamps
	sorted := make([]uint32, len(timestamps))
	copy(sorted, timestamps)

	// Simple insertion sort (only 11 elements max)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Return median
	return sorted[len(sorted)/2]
}

// CheckBlockTimestamp validates a block's timestamp against the median time past.
func CheckBlockTimestamp(blockTimestamp uint32, medianTimePast uint32) error {
	if blockTimestamp <= medianTimePast {
		return fmt.Errorf("%w: block time %d <= MTP %d",
			ErrTimestampBeforeMTP, blockTimestamp, medianTimePast)
	}
	return nil
}

// CheckWitnessCommitment runs the context-free segwit witness-commitment /
// malleation gate (Core CheckWitnessMalleation, "bad-witness-merkle-match")
// as an exported entry point. It is the same check CheckBlockContext runs when
// segwit is active; exposed so the submitblock RPC side-branch store path can
// enforce it before persisting a non-tip-extending block (Core runs CheckBlock
// — which subsumes this via IsBlockMutated — in ProcessNewBlock before storage;
// see CORE-PARITY-AUDIT/submitblock-path-differential-2026-07-11.md). Callers
// must only invoke this when segwit is active for the block's height.
func CheckWitnessCommitment(block *wire.MsgBlock) error {
	return checkWitnessCommitment(block)
}

// IsBlockMutated returns true if the block's merkle root or witness commitment
// is inconsistent with its transactions, indicating a possible short-ID collision
// or block malleation.
//
// checkWitnessRoot controls whether the segwit witness commitment is validated;
// pass true when segwit is active for the block's height.
//
// Mirrors Bitcoin Core validation.cpp:4027-4056:
//
//	bool IsBlockMutated(const CBlock& block, bool check_witness_root)
//	{
//	    BlockValidationState state;
//	    if (!CheckMerkleRoot(block, state)) return true;
//	    if (!CheckWitnessMalleation(block, check_witness_root, state)) return true;
//	    return false;
//	}
func IsBlockMutated(block *wire.MsgBlock, checkWitnessRoot bool) bool {
	if len(block.Transactions) == 0 {
		return true
	}

	// Check txid merkle root (CVE-2012-2459 mutation detection).
	txHashes := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.TxHash()
	}
	root, mutated := CalcMerkleRootMutation(txHashes)
	if root != block.Header.MerkleRoot || mutated {
		return true
	}

	// Check witness malleation when segwit is active.
	if checkWitnessRoot {
		if err := checkWitnessCommitment(block); err != nil {
			return true
		}
	} else {
		// Pre-segwit: no witness data allowed.
		for _, tx := range block.Transactions {
			if tx.HasWitness() {
				return true
			}
		}
	}

	return false
}

// AddTxOutputs adds all outputs from a transaction to the UTXO view.
// This is implemented on InMemoryUTXOView, defined here as a method on the interface
// for documentation purposes.
func (v *InMemoryUTXOView) AddTxOutputsAtHeight(tx *wire.MsgTx, height int32) {
	v.AddTxOutputs(tx, height)
}

// scriptJob represents a single script validation job.
type scriptJob struct {
	tx       *wire.MsgTx
	txIdx    int
	inputIdx int
	prevOut  *UTXOEntry
	prevOuts []*wire.TxOut
}

// ParallelScriptValidation validates all transaction scripts in a block using parallel workers.
// Script validation is CPU-intensive and embarrassingly parallel since each input is independent.
// This function provides significant speedup on multi-core systems (roughly 6-7x on 8 cores).
func ParallelScriptValidation(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags) error {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Collect all script validation jobs
	var jobs []scriptJob

	for txIdx, tx := range block.Transactions {
		// Skip coinbase (first transaction has no real inputs)
		if txIdx == 0 {
			continue
		}

		// Build prevOuts slice for this transaction (needed for sighash)
		prevOuts := make([]*wire.TxOut, len(tx.TxIn))
		for i, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d: %s:%d",
					txIdx, i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			}
			prevOuts[i] = &wire.TxOut{
				Value:    utxo.Amount,
				PkScript: utxo.PkScript,
			}
		}

		// Create a job for each input
		for inputIdx, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d", txIdx, inputIdx)
			}
			jobs = append(jobs, scriptJob{
				tx:       tx,
				txIdx:    txIdx,
				inputIdx: inputIdx,
				prevOut:  utxo,
				prevOuts: prevOuts,
			})
		}
	}

	// If no jobs, validation passes
	if len(jobs) == 0 {
		return nil
	}

	// For small job counts, validate sequentially to avoid goroutine overhead
	if len(jobs) <= 4 {
		for _, job := range jobs {
			err := script.VerifyScript(
				job.tx.TxIn[job.inputIdx].SignatureScript,
				job.prevOut.PkScript,
				job.tx,
				job.inputIdx,
				flags,
				job.prevOut.Amount,
				job.prevOuts,
			)
			if err != nil {
				return fmt.Errorf("tx %d input %d: script failed: %w", job.txIdx, job.inputIdx, err)
			}
		}
		return nil
	}

	// Use atomic.Pointer to store the first error without race conditions.
	// Workers check this to exit early once any script fails.
	var firstErr atomic.Pointer[error]

	// WaitGroup to track completion
	var wg sync.WaitGroup

	// Semaphore to limit concurrent workers
	sem := make(chan struct{}, numWorkers)

	for _, job := range jobs {
		wg.Add(1)
		go func(j scriptJob) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if we already have an error (early exit)
			if firstErr.Load() != nil {
				return
			}

			// Validate the script
			err := script.VerifyScript(
				j.tx.TxIn[j.inputIdx].SignatureScript,
				j.prevOut.PkScript,
				j.tx,
				j.inputIdx,
				flags,
				j.prevOut.Amount,
				j.prevOuts,
			)
			if err != nil {
				// Store the first error atomically (only first wins)
				wrapped := fmt.Errorf("tx %d input %d: script failed: %w", j.txIdx, j.inputIdx, err)
				firstErr.CompareAndSwap(nil, &wrapped)
			}
		}(job)
	}

	// Wait for all workers to finish
	wg.Wait()

	// Check if there was an error
	if errPtr := firstErr.Load(); errPtr != nil {
		return *errPtr
	}
	return nil
}

// ParallelScriptValidationCached validates scripts with signature cache support.
// Cached entries are looked up before expensive script verification, and successful
// verifications are added to the cache for future reuse.
func ParallelScriptValidationCached(block *wire.MsgBlock, utxoView UTXOView, flags script.ScriptFlags, cache *SigCache) error {
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Collect all script validation jobs
	var jobs []scriptJob

	for txIdx, tx := range block.Transactions {
		// Skip coinbase (first transaction has no real inputs)
		if txIdx == 0 {
			continue
		}

		// Build prevOuts slice for this transaction (needed for sighash)
		prevOuts := make([]*wire.TxOut, len(tx.TxIn))
		for i, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d: %s:%d",
					txIdx, i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			}
			prevOuts[i] = &wire.TxOut{
				Value:    utxo.Amount,
				PkScript: utxo.PkScript,
			}
		}

		// Create a job for each input
		for inputIdx, in := range tx.TxIn {
			utxo := utxoView.GetUTXO(in.PreviousOutPoint)
			if utxo == nil {
				return fmt.Errorf("missing UTXO for tx %d input %d", txIdx, inputIdx)
			}
			jobs = append(jobs, scriptJob{
				tx:       tx,
				txIdx:    txIdx,
				inputIdx: inputIdx,
				prevOut:  utxo,
				prevOuts: prevOuts,
			})
		}
	}

	// If no jobs, validation passes
	if len(jobs) == 0 {
		return nil
	}

	// For small job counts, validate sequentially to avoid goroutine overhead
	if len(jobs) <= 4 {
		for _, job := range jobs {
			// Use WTxHash (witness txid) so that segwit transactions with the
			// same txid but different witnesses map to distinct cache entries
			// (fix for W105-B8B).
			wtxhash := job.tx.WTxHash()
			// Also commit to prevOut amount + pkScript so the cache key
			// uniquely identifies every input to script evaluation, including
			// the sighash material that comes from the UTXO rather than the
			// spending tx (W160 BUG-11 "sigcache-omits-sighash").
			if cache != nil && cache.Lookup(wtxhash, uint32(job.inputIdx), flags, job.prevOut.Amount, job.prevOut.PkScript) {
				continue
			}

			err := script.VerifyScript(
				job.tx.TxIn[job.inputIdx].SignatureScript,
				job.prevOut.PkScript,
				job.tx,
				job.inputIdx,
				flags,
				job.prevOut.Amount,
				job.prevOuts,
			)
			if err != nil {
				return fmt.Errorf("tx %d input %d: script failed: %w", job.txIdx, job.inputIdx, err)
			}

			// Cache successful verification
			if cache != nil {
				cache.Insert(wtxhash, uint32(job.inputIdx), flags, job.prevOut.Amount, job.prevOut.PkScript)
			}
		}
		return nil
	}

	// Use atomic.Pointer to store the first error without race conditions.
	var firstErr atomic.Pointer[error]
	var wg sync.WaitGroup
	sem := make(chan struct{}, numWorkers)

	for _, job := range jobs {
		wg.Add(1)
		go func(j scriptJob) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if we already have an error (early exit)
			if firstErr.Load() != nil {
				return
			}

			// Use WTxHash (witness txid) so that segwit transactions with the
			// same txid but different witnesses map to distinct cache entries
			// (fix for W105-B8B).
			wtxhash := j.tx.WTxHash()
			// Also commit to prevOut amount + pkScript so the cache key
			// uniquely identifies every input to script evaluation, including
			// the sighash material that comes from the UTXO rather than the
			// spending tx (W160 BUG-11 "sigcache-omits-sighash").
			if cache != nil && cache.Lookup(wtxhash, uint32(j.inputIdx), flags, j.prevOut.Amount, j.prevOut.PkScript) {
				return
			}

			// Validate the script
			err := script.VerifyScript(
				j.tx.TxIn[j.inputIdx].SignatureScript,
				j.prevOut.PkScript,
				j.tx,
				j.inputIdx,
				flags,
				j.prevOut.Amount,
				j.prevOuts,
			)
			if err != nil {
				wrapped := fmt.Errorf("tx %d input %d: script failed: %w", j.txIdx, j.inputIdx, err)
				firstErr.CompareAndSwap(nil, &wrapped)
				return
			}

			// Cache successful verification
			if cache != nil {
				cache.Insert(wtxhash, uint32(j.inputIdx), flags, j.prevOut.Amount, j.prevOut.PkScript)
			}
		}(job)
	}

	wg.Wait()

	if errPtr := firstErr.Load(); errPtr != nil {
		return *errPtr
	}
	return nil
}
