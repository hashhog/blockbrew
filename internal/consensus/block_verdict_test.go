package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

func newVerdictRig(t *testing.T) (*ChainManager, *HeaderIndex, *storage.ChainDB, *BlockNode) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: NewUTXOSet(db)})
	cm.SetIBD(false)
	tip := idx.Genesis()
	for i := 0; i < 2; i++ {
		b := createSaltedBlock(t, params, tip, 0xA0, -1)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatal(err)
		}
		if err := db.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatal(err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatal(err)
		}
		tip = idx.GetNode(b.Header.BlockHash())
	}
	return cm, idx, db, tip
}

// A consensus failure from ConnectBlock is a typed verdict naming the block,
// and its text/sentinel are unchanged for existing consumers.
func TestConnectBlock_ConsensusFailureIsTypedVerdict(t *testing.T) {
	cm, idx, _, tip := newVerdictRig(t)
	bad := createSaltedBlock(t, cm.params, tip, 0xB1, CalcBlockSubsidy(tip.Height+1)+1)
	if _, err := idx.AddHeader(bad.Header, true); err != nil {
		t.Fatal(err)
	}
	err := cm.ConnectBlock(bad)
	bie, ok := AsBlockInvalid(err)
	if !ok {
		t.Fatalf("bad-cb-amount: got %v (%T), want a BlockInvalidError verdict", err, err)
	}
	if bie.Hash != bad.Header.BlockHash() {
		t.Fatal("verdict names the wrong block")
	}
	if !errors.Is(err, ErrBadCoinbaseValue) || !strings.Contains(err.Error(), "coinbase value exceeds") {
		t.Fatalf("sentinel/text changed: %v", err)
	}
}

// Non-verdicts stay plain errors: missing UTXO (local-state gap), mutation,
// missing ancestor, and anything ConnectBlock does not classify (I/O, lookup).
func TestConnectBlock_NonVerdictsAreNotTyped(t *testing.T) {
	cm, idx, _, tip := newVerdictRig(t)

	// Missing UTXO: a tx spending an outpoint that does not exist.
	blk := createSaltedBlock(t, cm.params, tip, 0xB2, -1)
	blk.Transactions = append(blk.Transactions, &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xde, 0xad}}, SignatureScript: []byte{0x51}, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
	})
	blk.Header.MerkleRoot = CalcMerkleRoot([]wire.Hash256{blk.Transactions[0].TxHash(), blk.Transactions[1].TxHash()})
	target := CompactToBig(blk.Header.Bits)
	for i := uint32(0); ; i++ {
		blk.Header.Nonce = i
		if HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	if _, err := idx.AddHeader(blk.Header, true); err != nil {
		t.Fatal(err)
	}
	err := cm.ConnectBlock(blk)
	if err == nil || !strings.Contains(err.Error(), "references missing UTXO") {
		t.Fatalf("expected a missing-UTXO failure, got %v", err)
	}
	if _, ok := AsBlockInvalid(err); ok {
		t.Fatal("missing UTXO classified as a consensus verdict")
	}

	// Classifier-level non-verdicts.
	h := wire.Hash256{1}
	for _, e := range []error{
		fmt.Errorf("x: %w", ErrMissingAncestorHeader),
		fmt.Errorf("x: %w", ErrSnapshotHeadersIncomplete),
		fmt.Errorf("block sanity check failed: %w", ErrBadMerkleRoot),
		fmt.Errorf("block sanity check failed: %w", ErrBlockMutated),
		fmt.Errorf("block context check failed: %w: x", ErrBadWitnessCommitment),
		ErrBadWitnessNonceSize, ErrUnexpectedWitnessInBlock,
		fmt.Errorf("tx 1 input validation failed: %w", ErrMissingInput),
		fmt.Errorf("script validation failed: %w for tx 1 input 0", ErrScriptPrevoutMissing),
	} {
		if _, ok := AsBlockInvalid(blockVerdict(h, e)); ok {
			t.Errorf("non-verdict %q was classified as a consensus verdict", e)
		}
	}
	if _, ok := AsBlockInvalid(blockVerdict(h, fmt.Errorf("tx 1: %w", ErrSequenceLockNotMet))); !ok {
		t.Error("BIP68 sequence-lock failure must be a verdict")
	}
}

// A reorg that fails on a consensus-invalid block marks the CULPRIT failed
// (descendants invalid-child, persisted), recomputes the best header, rolls
// back, and reports the culprit — so the caller can punish without halting.
func TestReorgTo_ConsensusFailureMarksCulpritAndReports(t *testing.T) {
	cm, idx, db, tip := newVerdictRig(t) // tip = A2
	a1 := tip.Parent
	// B1 (bad-cb) forks off A1; B2 + B3 on top make the branch heavier.
	b1 := createSaltedBlock(t, cm.params, a1, 0xB1, CalcBlockSubsidy(a1.Height+1)+1)
	stage := func(b *wire.MsgBlock) *BlockNode {
		n, err := idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.StoreBlock(n.Hash, b); err != nil {
			t.Fatal(err)
		}
		idx.MarkDataStored(n.Hash)
		return n
	}
	b1n := stage(b1)
	b2 := createSaltedBlock(t, cm.params, b1n, 0xB2, -1)
	b2n := stage(b2)
	b3 := createSaltedBlock(t, cm.params, b2n, 0xB3, -1)
	b3n := stage(b3)

	err := cm.ProcessSubmittedBlock(b3)
	bie, ok := AsBlockInvalid(err)
	if !ok {
		t.Fatalf("failed reorg returned %v, want a BlockInvalidError", err)
	}
	if bie.Hash != b1n.Hash {
		t.Fatal("verdict does not name the culprit B1")
	}
	if b1n.Status&StatusInvalid == 0 || b2n.Status&StatusInvalidChild == 0 || b3n.Status&StatusInvalidChild == 0 {
		t.Fatalf("flags: B1=%v B2=%v B3=%v", b1n.Status, b2n.Status, b3n.Status)
	}
	if h, _ := cm.BestBlock(); h != tip.Hash {
		t.Fatal("tip not restored to A2")
	}
	if idx.BestTip().Status.IsInvalid() {
		t.Fatal("best header still on the invalid branch")
	}
	fails, _ := db.ReadBlockFailures()
	if len(fails) < 3 {
		t.Fatalf("failure flags not persisted: %d entries", len(fails))
	}
	// bad-prevblk: the invalid branch cannot be extended.
	b4 := createSaltedBlock(t, cm.params, b3n, 0xB4, -1)
	if _, err := idx.AddHeader(b4.Header, true); err != ErrInvalidParentHeader {
		t.Fatalf("header on invalid branch: %v, want ErrInvalidParentHeader", err)
	}
}

// MarkBlockFailed refuses a block on the active chain, and RecalculateBestHeader
// does not require block data (a heavier header-only chain wins).
func TestMarkBlockFailed_GuardsAndBestHeader(t *testing.T) {
	cm, idx, _, tip := newVerdictRig(t)
	if cm.MarkBlockFailed(tip.Hash) || tip.Status.IsInvalid() {
		t.Fatal("MarkBlockFailed marked a block on the active chain")
	}
	bad := createSaltedBlock(t, cm.params, tip, 0xB1, -1)
	badN, _ := idx.AddHeader(bad.Header, true)
	sib := createSaltedBlock(t, cm.params, tip, 0xC1, -1)
	sibN, _ := idx.AddHeader(sib.Header, true)
	sib2 := createSaltedBlock(t, cm.params, sibN, 0xC2, -1)
	sib2N, _ := idx.AddHeader(sib2.Header, true)
	_ = badN
	if !cm.MarkBlockFailed(badN.Hash) {
		t.Fatal("MarkBlockFailed refused an off-chain block")
	}
	if idx.BestTip() != sib2N {
		t.Fatalf("best header = h%d, want the header-only valid sibling chain tip", idx.BestTip().Height)
	}
}
