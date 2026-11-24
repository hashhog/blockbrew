package consensus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Bitcoin Core's ConnectBlock always runs CheckBlock (validation.cpp:2320;
// the result is cached only on the same in-memory CBlock via fChecked). So
// every connection path — -loadblock import, reorg replay, boot replay —
// rejects a block with a wrong merkle root (bad-txnmrklroot), a second
// coinbase (bad-cb-multiple), or excessive legacy sigops (bad-blk-sigops).
//
// blockbrew's ChainManager.ConnectBlock skipped CheckBlockSanity whenever the
// chain manager was in IBD mode (the default for a fresh manager), assuming
// the P2P validation worker had already checked the block. import-blocks,
// ReorgTo and boot recovery replay call ConnectBlock without that check.

// neonCBSIRig returns a fresh chain manager in IBD mode on regtest genesis.
func neonCBSIRig(t *testing.T) (*ChainManager, *HeaderIndex, *BlockNode) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: NewUTXOSet(db)})
	cm.SetIBD(true)
	if !cm.IsIBD() {
		t.Fatal("rig: chain manager is not in IBD mode")
	}
	return cm, idx, idx.Genesis()
}

// neonCBSIBlock builds a regtest block on prev with a BIP34 coinbase paying
// the subsidy, followed by extra txs, then optionally overrides the merkle
// root, and mines it.
func neonCBSIBlock(t *testing.T, params *ChainParams, prev *BlockNode, coinbaseScript []byte, extra []*wire.MsgTx, merkleOverride *wire.Hash256) *wire.MsgBlock {
	t.Helper()
	height := prev.Height + 1
	sig := encodeBIP34Height(height)
	if len(sig) < 2 {
		sig = append(sig, 0x00)
	}
	if coinbaseScript == nil {
		coinbaseScript = []byte{0x51}
	}
	cb := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  sig,
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: CalcBlockSubsidy(height), PkScript: coinbaseScript}},
	}
	txs := append([]*wire.MsgTx{cb}, extra...)
	hashes := make([]wire.Hash256, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxHash()
	}
	root := CalcMerkleRoot(hashes)
	if merkleOverride != nil {
		root = *merkleOverride
	}
	hdr := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prev.Hash,
		MerkleRoot: root,
		Timestamp:  prev.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
	}
	target := CompactToBig(hdr.Bits)
	for n := uint32(0); ; n++ {
		hdr.Nonce = n
		if HashToBig(hdr.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return &wire.MsgBlock{Header: hdr, Transactions: txs}
}

// neonCBSIConnect adds the header and connects the block the way
// import-blocks does (AddHeader + raw ConnectBlock), and reports whether the
// tip moved.
func neonCBSIConnect(t *testing.T, cm *ChainManager, idx *HeaderIndex, blk *wire.MsgBlock) (error, bool) {
	t.Helper()
	if _, err := idx.AddHeader(blk.Header, true); err != nil && err != ErrDuplicateHeader {
		t.Fatalf("AddHeader: %v", err)
	}
	err := cm.ConnectBlock(blk)
	tipHash, _ := cm.BestBlock()
	return err, tipHash == blk.Header.BlockHash()
}

// Control: a valid block still connects in IBD mode.
func TestNeonConnectBlockSanityIBDValidBlockConnects(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	blk := neonCBSIBlock(t, cm.params, gen, nil, nil, nil)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if err != nil || !moved {
		t.Fatalf("valid block in IBD mode: err=%v tipMoved=%v, want connected", err, moved)
	}
}

// bad-txnmrklroot: header commits to a merkle root that is not the root of
// the block's transactions.
func TestNeonConnectBlockSanityIBDBadMerkleRootRejected(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	bogus := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
	blk := neonCBSIBlock(t, cm.params, gen, nil, nil, &bogus)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if moved {
		t.Fatalf("IBD-mode ConnectBlock connected a block with a wrong merkle root (err=%v); Core rejects bad-txnmrklroot", err)
	}
	if !errors.Is(err, ErrBadMerkleRoot) {
		t.Fatalf("want ErrBadMerkleRoot (bad-txnmrklroot), got: %v", err)
	}
}

// bad-cb-multiple: a second coinbase-shaped tx at index 1. On master the
// block is still refused, but only by accident: input validation skips the
// tx as "a coinbase", and the later spend-recording pass then trips its
// internal-invariant guard ("bad-txns-inputs-missingorspent: prevout ... not
// in cached view"), a plain unclassified error rather than a verdict, so the
// block is never marked failed. Core rejects it in CheckBlock as a consensus
// failure (BLOCK_CONSENSUS, bad-cb-multiple), which marks the block failed.
func TestNeonConnectBlockSanityIBDSecondCoinbaseRejected(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	second := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x01, 0x02, 0x03},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 21_000_000 * 100_000_000, PkScript: []byte{0x51}}},
	}
	blk := neonCBSIBlock(t, cm.params, gen, nil, []*wire.MsgTx{second}, nil)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if moved {
		t.Fatalf("IBD-mode ConnectBlock connected a block with two coinbases (err=%v); Core rejects bad-cb-multiple", err)
	}
	if !errors.Is(err, ErrMultipleCoinbase) {
		t.Fatalf("want ErrMultipleCoinbase (bad-cb-multiple), got: %v", err)
	}
	if _, ok := AsBlockInvalid(err); !ok {
		t.Fatalf("bad-cb-multiple must be a verdict on the block (BlockInvalidError), got %T: %v", err, err)
	}
}

// bad-blk-sigops: a coinbase-only block whose coinbase output carries
// 1001 bare OP_CHECKMULTISIG = 20,020 legacy sigops (x4 = 80,080 > 80,000).
// ConnectBlock's own sigop cap is only reached for non-coinbase txs, so the
// context-free CheckBlock gate is the only thing that catches this.
func TestNeonConnectBlockSanityIBDCoinbaseSigopsRejected(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	script := bytes.Repeat([]byte{0xae}, 1001)
	blk := neonCBSIBlock(t, cm.params, gen, script, nil, nil)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if moved {
		t.Fatalf("IBD-mode ConnectBlock connected a block with 80,080 sigop cost (err=%v); Core rejects bad-blk-sigops", err)
	}
	if !errors.Is(err, ErrSigOpsCostTooHigh) {
		t.Fatalf("want ErrSigOpsCostTooHigh (bad-blk-sigops), got: %v", err)
	}
}

// Control at the boundary: 1000 OP_CHECKMULTISIG = 80,000 sigop cost exactly
// is allowed (Core: > MAX_BLOCK_SIGOPS_COST rejects).
func TestNeonConnectBlockSanityIBDCoinbaseSigopsAtLimitConnects(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	script := bytes.Repeat([]byte{0xae}, 1000)
	blk := neonCBSIBlock(t, cm.params, gen, script, nil, nil)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if err != nil || !moved {
		t.Fatalf("80,000-sigop-cost coinbase block: err=%v tipMoved=%v, want connected", err, moved)
	}
}

// ReorgTo replays bodies read back from chainDB through ConnectBlock. In IBD
// mode those bodies were never sanity-checked on that path.
//
//	genesis ── A1                 <- active tip
//	        └─ B1 ── B2(bad merkle root)
func TestNeonConnectBlockSanityIBDReorgReplayRejectsBadMerkle(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	db := cm.chainDB
	stage := func(blk *wire.MsgBlock) *BlockNode {
		t.Helper()
		if _, err := idx.AddHeader(blk.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock: %v", err)
		}
		return idx.GetNode(blk.Header.BlockHash())
	}
	a1 := neonCBSIBlock(t, cm.params, gen, []byte{0x51, 0x51}, nil, nil)
	stage(a1)
	if err := cm.ConnectBlock(a1); err != nil {
		t.Fatalf("connect A1: %v", err)
	}
	b1 := neonCBSIBlock(t, cm.params, gen, []byte{0x52}, nil, nil)
	b1n := stage(b1)
	bogus := wire.Hash256{0xba, 0xd0}
	b2 := neonCBSIBlock(t, cm.params, b1n, nil, nil, &bogus)
	b2n := stage(b2)

	err := cm.ReorgTo(b2n)
	tipHash, _ := cm.BestBlock()
	if tipHash == b2.Header.BlockHash() {
		t.Fatalf("IBD-mode ReorgTo replayed a wrong-merkle-root body from disk onto the tip (err=%v); Core rejects bad-txnmrklroot", err)
	}
	if !errors.Is(err, ErrBadMerkleRoot) {
		t.Fatalf("want ErrBadMerkleRoot from the reorg, got: %v", err)
	}
}

// The same bad-merkle block is rejected when the manager is NOT in IBD
// (unchanged behaviour), so the outcome no longer depends on the IBD flag.
func TestNeonConnectBlockSanityPostIBDBadMerkleRootRejected(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	cm.SetIBD(false)
	bogus := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
	blk := neonCBSIBlock(t, cm.params, gen, nil, nil, &bogus)
	err, moved := neonCBSIConnect(t, cm, idx, blk)
	if moved || !errors.Is(err, ErrBadMerkleRoot) {
		t.Fatalf("post-IBD bad merkle: err=%v tipMoved=%v, want ErrBadMerkleRoot", err, moved)
	}
}
