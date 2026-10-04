package rpc

// Gate 6 at the submitblock RPC (receipts/gate6-resource-limit-audit-2026-10-04.md,
// tier 3): a system failure is not a BIP-22 verdict. Core: BIP22ValidationResult
// -> state.IsError() -> JSONRPCError(RPC_VERIFY_ERROR, ...). And once the node
// has aborted, submitblock must not connect anything.

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

func newGate6SubmitRig(t *testing.T) (*submitBlockTestRig, *storage.FaultDB) {
	t.Helper()
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	fdb := storage.NewFaultDB(storage.NewMemDB())
	db := storage.NewChainDB(fdb)
	utxo := consensus.NewUTXOSet(db)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
	})
	cm.SetIBD(false)
	prev := idx.Genesis()
	var tips []*consensus.BlockNode
	for i := 0; i < 2; i++ {
		blk := buildRegtestBlock(t, params, prev)
		node, err := idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock: %v", err)
		}
		tips = append(tips, node)
		prev = node
	}
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params), WithChainManager(cm), WithHeaderIndex(idx), WithChainDB(db))
	return &submitBlockTestRig{params: params, idx: idx, db: db, utxo: utxo, cm: cm, server: server, tips: tips}, fdb
}

// The block's atomic batch fails to write (twice). Pre-fix submitblock answered
// the BIP-22 token "rejected" — a verdict string for a disk-full condition.
func TestGate6_SubmitBlockWriteFailureIsRPCVerifyError(t *testing.T) {
	rig, fdb := newGate6SubmitRig(t)
	tip := rig.tips[len(rig.tips)-1]
	blk := buildRegtestBlock(t, rig.params, tip)
	fdb.FailNextWrites(2, nil)
	res, rpcErr := rig.submitBlock(t, blk)
	if fdb.WritesFailed() == 0 {
		t.Fatal("instrument: the write fault never fired")
	}
	if rpcErr == nil {
		t.Fatalf("disk-full answered as BIP-22 result %v, want RPC_VERIFY_ERROR (-25)", res)
	}
	if rpcErr.Code != RPCErrVerify {
		t.Fatalf("RPC error code %d, want %d (RPC_VERIFY_ERROR)", rpcErr.Code, RPCErrVerify)
	}
	if h, _ := rig.cm.BestBlock(); h != tip.Hash {
		t.Fatal("tip moved although the block's batch never landed")
	}
	if n := rig.idx.GetNode(blk.Header.BlockHash()); n != nil && n.Status.IsInvalid() {
		t.Fatal("block marked invalid for a write failure")
	}
}

// After AbortNode, submitblock refuses: no connect, RPC_VERIFY_ERROR.
func TestGate6_SubmitBlockRefusedAfterAbort(t *testing.T) {
	rig, _ := newGate6SubmitRig(t)
	tip := rig.tips[len(rig.tips)-1]
	blk := buildRegtestBlock(t, rig.params, tip)
	consensus.AbortNode(errors.New("test: injected fatal error"))
	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr == nil || rpcErr.Code != RPCErrVerify {
		t.Fatalf("submitblock after AbortNode: res=%v err=%+v, want RPC_VERIFY_ERROR", res, rpcErr)
	}
	if h, _ := rig.cm.BestBlock(); h != tip.Hash {
		t.Fatal("submitblock connected a block after AbortNode")
	}
}

// Control: a valid block is still accepted (null) and an invalid one still
// gets its BIP-22 token, with no fault injected.
func TestGate6_Control_SubmitBlockVerdictsUnchanged(t *testing.T) {
	rig, _ := newGate6SubmitRig(t)
	tip := rig.tips[len(rig.tips)-1]
	bad := buildRegtestBlock(t, rig.params, tip)
	bad.Transactions[0].TxOut[0].Value += 1 // bad-cb-amount
	reseal(t, rig.params, bad)
	if res, rpcErr := rig.submitBlock(t, bad); rpcErr != nil || res != "bad-cb-amount" {
		t.Fatalf("invalid block: res=%v err=%+v, want bad-cb-amount", res, rpcErr)
	}
	good := buildRegtestBlock(t, rig.params, tip)
	if res, rpcErr := rig.submitBlock(t, good); rpcErr != nil || res != nil {
		t.Fatalf("valid block: res=%v err=%+v, want null", res, rpcErr)
	}
	if consensus.IsAborted() {
		t.Error("ordinary submitblock latched AbortNode")
	}
}

// reseal recomputes the merkle root and regtest PoW after a test edit.
func reseal(t *testing.T, params *consensus.ChainParams, b *wire.MsgBlock) {
	t.Helper()
	hashes := make([]wire.Hash256, len(b.Transactions))
	for i, tx := range b.Transactions {
		hashes[i] = tx.TxHash()
	}
	b.Header.MerkleRoot = consensus.CalcMerkleRoot(hashes)
	target := consensus.CompactToBig(b.Header.Bits)
	for i := uint32(0); ; i++ {
		b.Header.Nonce = i
		if consensus.HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			return
		}
	}
}
