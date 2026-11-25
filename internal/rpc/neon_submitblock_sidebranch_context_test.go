package rpc

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// submitblock must run the block-contextual checks on a side-branch block
// before storing it and answering "inconclusive".
//
// Core: ProcessNewBlock -> AcceptBlock runs CheckBlock + ContextualCheckBlock
// (validation.cpp:4350-4357) for every block it is about to store, including a
// lower- or equal-work side branch that will not be connected. A failure marks
// the block failed (InvalidBlockFound) and BlockChecked hands the reason to
// submitblock, which answers it (bad-txns-nonfinal, bad-cb-height,
// unexpected-witness / bad-witness-*, bad-blk-weight). blockbrew's side-branch
// arm only ran the witness commitment and the header version, so such a block
// was stored and answered "inconclusive".

// neonSBMine re-mines blk after its transactions changed.
func neonSBMine(t *testing.T, blk *wire.MsgBlock) *wire.MsgBlock {
	t.Helper()
	hashes := make([]wire.Hash256, len(blk.Transactions))
	for i, tx := range blk.Transactions {
		hashes[i] = tx.TxHash()
	}
	blk.Header.MerkleRoot = consensus.CalcMerkleRoot(hashes)
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return blk
		}
	}
	t.Fatalf("could not mine block")
	return nil
}

// neonSBAssertRejected submits a lighter side-branch block and checks the
// answer, that the body was not stored, and that the tip did not move.
func neonSBAssertRejected(t *testing.T, rig *submitBlockTestRig, blk *wire.MsgBlock, want string) {
	t.Helper()
	tipBefore, hBefore := rig.cm.BestBlock()
	hash := blk.Header.BlockHash()

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock: RPC error %+v", rpcErr)
	}
	if got, _ := res.(string); got != want {
		t.Fatalf("side-branch submitblock = %v, want %q (Core AcceptBlock -> ContextualCheckBlock)", res, want)
	}
	if rig.db.HasBlock(hash) {
		t.Fatalf("rejected side-branch block body was stored")
	}
	if n := rig.idx.GetNode(hash); n != nil && n.Status&consensus.StatusDataStored != 0 {
		t.Fatalf("rejected side-branch block marked StatusDataStored")
	}
	if tip, h := rig.cm.BestBlock(); tip != tipBefore || h != hBefore {
		t.Fatalf("tip moved")
	}
}

func TestNeonSubmitBlockSideBranchBadCbHeight(t *testing.T) {
	rig := newSubmitBlockRig(t, 2) // tip at height 2; side block at height 1 is lighter
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	// Coinbase claims height 5 (OP_5) at height 1 (expects OP_1).
	blk.Transactions[0].TxIn[0].SignatureScript = []byte{0x55, 0x00}
	neonSBMine(t, blk)
	neonSBAssertRejected(t, rig, blk, "bad-cb-height")

	// Core marked it failed (InvalidBlockFound); a resubmit is answered from
	// the cached verdict by AcceptBlockHeader: "duplicate-invalid".
	if n := rig.idx.GetNode(blk.Header.BlockHash()); n == nil || !n.Status.IsInvalid() {
		t.Fatalf("bad-cb-height side-branch block not marked failed")
	}
	if res, rpcErr := rig.submitBlock(t, blk); rpcErr != nil || res != "duplicate-invalid" {
		t.Fatalf("resubmit: got %v %+v, want \"duplicate-invalid\"", res, rpcErr)
	}
}

func TestNeonSubmitBlockSideBranchNonFinal(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	// Height-based nLockTime 1000 with a non-final sequence: not final at height 1.
	blk.Transactions[0].LockTime = 1000
	blk.Transactions[0].TxIn[0].Sequence = 0
	neonSBMine(t, blk)
	neonSBAssertRejected(t, rig, blk, "bad-txns-nonfinal")
}

// Witness-inclusive weight over 4,000,000 WU with a serialized size under
// 4,000,000 bytes and a stripped weight well under the limit: only the
// contextual weight check (Core ContextualCheckBlock "bad-blk-weight") sees it.
func TestNeonSubmitBlockSideBranchBlockWeight(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())

	spend := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x4e, 0x53, 0x42}, Index: 0},
			Sequence:         0xFFFFFFFF,
			Witness:          [][]byte{bytes.Repeat([]byte{0x01}, 3_790_000)},
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: append([]byte{0x6a}, make([]byte, 100_000)...)}},
	}
	cb := blk.Transactions[0]
	reserved := make([]byte, 32)
	cb.TxIn[0].Witness = [][]byte{reserved}
	blk.Transactions = append(blk.Transactions, spend)

	wtxids := []wire.Hash256{cb.WTxHash(), spend.WTxHash()}
	commitment := consensus.CalcWitnessCommitment(wtxids, reserved)
	script := append([]byte{0x6a, 0x24}, consensus.WitnessCommitmentMagic...)
	script = append(script, commitment[:]...)
	cb.TxOut = append(cb.TxOut, &wire.TxOut{Value: 0, PkScript: script})
	neonSBMine(t, blk)

	// Preconditions: the block is well-formed apart from its weight.
	if w := consensus.CalcBlockWeight(blk); w <= consensus.MaxBlockWeight {
		t.Fatalf("fixture weight %d not above %d", w, consensus.MaxBlockWeight)
	}
	if err := consensus.CheckWitnessCommitment(blk); err != nil {
		t.Fatalf("fixture witness commitment invalid: %v", err)
	}
	if err := consensus.CheckBlockSanity(blk, rig.params.PowLimit); err != nil {
		t.Fatalf("fixture fails CheckBlockSanity: %v", err)
	}
	neonSBAssertRejected(t, rig, blk, "bad-blk-weight")
}

// Controls: valid lighter and equal-work side-branch blocks are still stored
// and answered "inconclusive".
func TestNeonSubmitBlockSideBranchValidStillInconclusive(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	tipBefore, hBefore := rig.cm.BestBlock()

	s1 := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	s1.Header.Timestamp++
	neonSBMine(t, s1)
	if res, rpcErr := rig.submitBlock(t, s1); rpcErr != nil || res != "inconclusive" {
		t.Fatalf("valid lighter side block: got %v %+v, want \"inconclusive\"", res, rpcErr)
	}
	n1 := rig.idx.GetNode(s1.Header.BlockHash())
	if n1 == nil || n1.Status&consensus.StatusDataStored == 0 || n1.Status.IsInvalid() {
		t.Fatalf("valid side block not stored as valid data")
	}

	// Equal work: a valid height-2 block on the side branch, with a height-2
	// coinbase and a final locktime.
	s2 := buildRegtestBlock(t, rig.params, n1)
	s2.Transactions[0].LockTime = 1 // height lock below 2: final
	s2.Transactions[0].TxIn[0].Sequence = 0
	neonSBMine(t, s2)
	if res, rpcErr := rig.submitBlock(t, s2); rpcErr != nil || res != "inconclusive" {
		t.Fatalf("valid equal-work side block: got %v %+v, want \"inconclusive\"", res, rpcErr)
	}
	if !rig.db.HasBlock(s2.Header.BlockHash()) {
		t.Fatalf("valid equal-work side block not stored")
	}
	if tip, h := rig.cm.BestBlock(); tip != tipBefore || h != hBefore {
		t.Fatalf("tip moved on equal work")
	}
}

// Control: the side-branch bad-version gate this arm already had (corpus
// submitblock-sidebranch/bad-version-v3) still answers Core's
// bad-version(0x%08x) form and does not store the block.
func TestNeonSubmitBlockSideBranchBadVersionStillReported(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	blk.Header.Version = 3
	neonSBMine(t, blk)
	neonSBAssertRejected(t, rig, blk, "bad-version(0x00000003)")
}
