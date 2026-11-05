package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ProcessSubmittedBlock on a block extending the active tip must leave a
// block that fails with a consensus verdict marked failed (Core: ConnectTip ->
// InvalidBlockFound -> BLOCK_FAILED_VALID, persisted), and must NOT mark a
// block whose failure is not a verdict on that hash: a mutated body (Core
// excludes BLOCK_MUTATED) or a prevout missing from the local UTXO view
// (blockbrew's local-gap rule, see isLocalUTXOGap). Marking either would make
// a valid block invalid for good.

func mineVerdictBlock(t *testing.T, blk *wire.MsgBlock) {
	t.Helper()
	hashes := make([]wire.Hash256, len(blk.Transactions))
	for i, tx := range blk.Transactions {
		hashes[i] = tx.TxHash()
	}
	blk.Header.MerkleRoot = CalcMerkleRoot(hashes)
	target := CompactToBig(blk.Header.Bits)
	for i := uint32(0); ; i++ {
		blk.Header.Nonce = i
		if HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return
		}
	}
}

func TestProcessSubmittedBlockFailedConnectMarksAndPersists(t *testing.T) {
	cm, idx, db, tip := newVerdictRig(t)
	bad := createSaltedBlock(t, cm.params, tip, 0xC1, CalcBlockSubsidy(tip.Height+1)+1)
	hash := bad.Header.BlockHash()
	if _, err := idx.AddHeader(bad.Header, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := AsBlockInvalid(cm.ProcessSubmittedBlock(bad)); !ok {
		t.Fatal("bad-cb-amount at the tip did not return a verdict")
	}
	if n := idx.GetNode(hash); n == nil || n.Status&StatusInvalid == 0 {
		t.Fatalf("failed block not marked StatusInvalid: %+v", n)
	}
	if idx.BestHeight() != tip.Height {
		t.Errorf("best header height %d, want %d (recalculated past the failed block)", idx.BestHeight(), tip.Height)
	}
	fails, err := db.ReadBlockFailures()
	if err != nil {
		t.Fatal(err)
	}
	var persisted bool
	for _, f := range fails {
		if f.Hash == hash && BlockStatus(f.Flags)&StatusInvalid != 0 {
			persisted = true
		}
	}
	if !persisted {
		t.Errorf("failure flag not persisted (Core writes BLOCK_FAILED_VALID to the block index): %v", fails)
	}
}

func TestProcessSubmittedBlockMutatedBodyIsNotMarked(t *testing.T) {
	cm, idx, _, tip := newVerdictRig(t)
	good := createSaltedBlock(t, cm.params, tip, 0xC2, -1)
	hash := good.Header.BlockHash()
	if _, err := idx.AddHeader(good.Header, true); err != nil {
		t.Fatal(err)
	}
	// Same header, body that no longer matches its merkle root.
	mutated := &wire.MsgBlock{Header: good.Header}
	cb := *good.Transactions[0]
	cb.TxOut = []*wire.TxOut{{Value: good.Transactions[0].TxOut[0].Value - 1, PkScript: good.Transactions[0].TxOut[0].PkScript}}
	mutated.Transactions = []*wire.MsgTx{&cb}
	if mutated.Header.BlockHash() != hash {
		t.Fatal("test setup: mutated block must keep the header hash")
	}
	if err := cm.ProcessSubmittedBlock(mutated); err == nil {
		t.Fatal("mutated body connected")
	}
	if n := idx.GetNode(hash); n == nil || n.Status.IsInvalid() {
		t.Fatalf("mutated body marked the real block failed: %+v", n)
	}
	// The genuine block still connects.
	if err := cm.ProcessSubmittedBlock(good); err != nil {
		t.Fatalf("genuine block after a mutated delivery: %v", err)
	}
	if best, _ := cm.BestBlock(); best != hash {
		t.Fatal("genuine block is not the active tip")
	}
}

func TestProcessSubmittedBlockMissingUTXOIsNotMarked(t *testing.T) {
	cm, idx, _, tip := newVerdictRig(t)
	blk := createSaltedBlock(t, cm.params, tip, 0xC3, -1)
	blk.Transactions = append(blk.Transactions, &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xbe, 0xef}}, SignatureScript: []byte{0x51}, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
	})
	mineVerdictBlock(t, blk)
	if _, err := idx.AddHeader(blk.Header, true); err != nil {
		t.Fatal(err)
	}
	if err := cm.ProcessSubmittedBlock(blk); err == nil {
		t.Fatal("block spending a missing prevout connected")
	}
	if n := idx.GetNode(blk.Header.BlockHash()); n == nil || n.Status.IsInvalid() {
		t.Fatalf("local UTXO gap marked the block failed: %+v", n)
	}
}
