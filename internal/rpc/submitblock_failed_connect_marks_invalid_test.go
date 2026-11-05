package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// A block submitted on top of the active tip that fails to connect must be
// left in the block index as FAILED, the way Core leaves it:
// ActivateBestChainStep -> ConnectTip -> ConnectBlock fails ->
// Chainstate::InvalidBlockFound sets BLOCK_FAILED_VALID and InvalidChainFound
// recalculates m_best_header (bitcoin-core/src/validation.cpp).
//
// blockbrew's submitblock tip-extension path returned the verdict but never
// marked the block, so it stayed in the index unflagged:
//   - getchaintips listed it "headers-only" (body not stored, no failure flag)
//     where Core says "invalid" — the 17 Core regtest rows
//     {chain,seed_invalidated_submit,warden_invalidated_submit}/.../tips:<hash>.status;
//   - getblockchaininfo.headers stayed one above Core, counting the failed
//     block as the best header;
//   - a resubmission was re-validated instead of answering "duplicate-invalid".

// failedConnectBlock builds a block on prev whose coinbase claims one satoshi
// more than the subsidy: it passes CheckBlock (the header and merkle root are
// sound) and fails only in ConnectBlock with bad-cb-amount.
func failedConnectBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode) *wire.MsgBlock {
	t.Helper()
	blk := buildRegtestBlock(t, params, prev)
	blk.Transactions[0].TxOut[0].Value++
	blk.Header.MerkleRoot = consensus.CalcMerkleRoot([]wire.Hash256{blk.Transactions[0].TxHash()})
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return blk
		}
	}
	t.Fatal("could not mine the failing block")
	return nil
}

func TestSubmitBlockFailedConnectAtTipIsInvalidTip(t *testing.T) {
	rig := newSubmitBlockRig(t, 3)
	tip := rig.tips[2]
	blk := failedConnectBlock(t, rig.params, tip)
	hash := blk.Header.BlockHash()

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock: RPC error %v", rpcErr)
	}
	if res != "bad-cb-amount" {
		t.Fatalf("submitblock = %v, want bad-cb-amount (Core's reject reason)", res)
	}
	if best, h := rig.cm.BestBlock(); best != tip.Hash || h != tip.Height {
		t.Fatalf("active tip moved to %s/%d, want %s/%d", best, h, tip.Hash, tip.Height)
	}

	node := rig.idx.GetNode(hash)
	if node == nil {
		t.Fatal("failed block missing from the block index")
	}
	if !node.Status.IsInvalid() {
		t.Errorf("failed block status %v carries no failure flag (Core: BLOCK_FAILED_VALID)", node.Status)
	}

	res2, rpcErr := rig.server.handleGetChainTips()
	if rpcErr != nil {
		t.Fatalf("getchaintips: %v", rpcErr)
	}
	var found bool
	for _, ct := range res2.([]ChainTip) {
		if ct.Hash != hash.String() {
			continue
		}
		found = true
		want := ChainTip{Height: tip.Height + 1, Hash: hash.String(), BranchLen: 1, Status: "invalid"}
		if ct != want {
			t.Errorf("getchaintips entry = %+v, want %+v", ct, want)
		}
	}
	if !found {
		t.Errorf("getchaintips does not list the failed block %s", hash)
	}
}

func TestSubmitBlockFailedConnectAtTipLeavesBestHeaderAtTip(t *testing.T) {
	rig := newSubmitBlockRig(t, 3)
	tip := rig.tips[2]
	if _, rpcErr := rig.submitBlock(t, failedConnectBlock(t, rig.params, tip)); rpcErr != nil {
		t.Fatalf("submitblock: RPC error %v", rpcErr)
	}
	res, rpcErr := rig.server.handleGetBlockchainInfo()
	if rpcErr != nil {
		t.Fatalf("getblockchaininfo: %v", rpcErr)
	}
	info := res.(*BlockchainInfo)
	if info.Headers != tip.Height {
		t.Errorf("getblockchaininfo headers = %d, want %d (Core recalculates the best header past a failed block)",
			info.Headers, tip.Height)
	}
}

func TestSubmitBlockFailedConnectAtTipResubmitIsDuplicateInvalid(t *testing.T) {
	rig := newSubmitBlockRig(t, 3)
	blk := failedConnectBlock(t, rig.params, rig.tips[2])
	if _, rpcErr := rig.submitBlock(t, blk); rpcErr != nil {
		t.Fatalf("submitblock: RPC error %v", rpcErr)
	}
	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("resubmit: RPC error %v", rpcErr)
	}
	if res != "duplicate-invalid" {
		t.Errorf("resubmit = %v, want duplicate-invalid (Core: BLOCK_CACHED_INVALID)", res)
	}
}

// Negative control: a block that connects is not marked, and the next valid
// block on it still connects. Guards against marking on success.
func TestSubmitBlockValidAtTipIsNotMarked(t *testing.T) {
	rig := newSubmitBlockRig(t, 3)
	blk := buildRegtestBlock(t, rig.params, rig.tips[2])
	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil || res != nil {
		t.Fatalf("submitblock = %v / %v, want null", res, rpcErr)
	}
	node := rig.idx.GetNode(blk.Header.BlockHash())
	if node == nil || node.Status.IsInvalid() {
		t.Fatalf("connected block is missing or marked failed: %+v", node)
	}
	next := buildRegtestBlock(t, rig.params, node)
	if res, rpcErr := rig.submitBlock(t, next); rpcErr != nil || res != nil {
		t.Fatalf("next block submitblock = %v / %v, want null", res, rpcErr)
	}
}
