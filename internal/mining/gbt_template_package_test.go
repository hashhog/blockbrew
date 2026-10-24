package mining

// getblocktemplate transaction selection against Core's BlockAssembler
// (node/miner.cpp addChunks / AddToBlock): a child is selected together with
// its unselected in-mempool ancestors at the child's own turn, parents first,
// and each transaction's sigops cost is GetTransactionSigOpCost evaluated with
// the mempool's outputs visible, as Core stores it on the mempool entry.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// p2wpkhScript is OP_0 <20 bytes>.
func p2wpkhScript(seed byte) []byte {
	s := []byte{0x00, 0x14}
	for i := 0; i < 20; i++ {
		s = append(s, seed)
	}
	return s
}

// pkgTx spends prev and pays one P2WPKH output. A non-nil witness marks the
// input as a P2WPKH spend.
func pkgTx(prev wire.OutPoint, value int64, seed byte, witness [][]byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prev,
			Witness:          witness,
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: value, PkScript: p2wpkhScript(seed)}},
	}
}

func pkgEntry(tx *wire.MsgTx, fee int64, parents ...*mempool.TxEntry) *mempool.TxEntry {
	vsize := int64(consensus.CalcTxWeight(tx)+3) / 4
	e := &mempool.TxEntry{
		Tx:           tx,
		TxHash:       tx.TxHash(),
		Fee:          fee,
		Size:         vsize,
		FeeRate:      float64(fee) / float64(vsize),
		AncestorFee:  fee,
		AncestorSize: vsize,
	}
	for _, p := range parents {
		e.Depends = append(e.Depends, p.TxHash)
		e.AncestorFee += p.AncestorFee
		e.AncestorSize += p.AncestorSize
	}
	return e
}

func pkgGenerator(t *testing.T, entries []*mempool.TxEntry) *TemplateGenerator {
	t.Helper()
	params := consensus.RegtestParams()
	tipNode := &consensus.BlockNode{
		Hash:   params.GenesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}
	return NewTemplateGenerator(params,
		&mockChainState{tipHash: params.GenesisHash, tipHeight: 0, tipNode: tipNode},
		&mockMempool{entries: entries},
		&mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{params.GenesisHash: tipNode}})
}

// The gbt/template/segwit shape from the Core regtest harness: a low-fee
// parent A with a high-fee child B (CPFP), and an unrelated C whose feerate
// sits between A's and the A+B package's. Core selects the A+B package first
// (A, B, C); blockbrew parked B, took C, then A, then B (C, A, B).
func TestGBTTemplate_AncestorPackageSelectedAtChildTurn(t *testing.T) {
	sig := [][]byte{make([]byte, 71), make([]byte, 33)}
	a := pkgEntry(pkgTx(wire.OutPoint{Hash: wire.Hash256{0xa0}}, 100_000, 0xa1, sig), 9)
	b := pkgEntry(pkgTx(wire.OutPoint{Hash: a.TxHash, Index: 0}, 50_000, 0xb1, sig), 50_000, a)
	c := pkgEntry(pkgTx(wire.OutPoint{Hash: wire.Hash256{0xc0}}, 100_000, 0xc1, sig), 2_000)

	// Mempool order by ancestor feerate: B (A+B package), C, A.
	tmpl, err := pkgGenerator(t, []*mempool.TxEntry{b, c, a}).GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}
	got := tmpl.Block.Transactions[1:]
	want := []wire.Hash256{a.TxHash, b.TxHash, c.TxHash}
	if len(got) != len(want) {
		t.Fatalf("template has %d txs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].TxHash() != want[i] {
			t.Errorf("transactions[%d] = %s, want %s (Core order A, B, C)", i, got[i].TxHash(), want[i])
		}
	}
	if tmpl.Fees != 52_009 {
		t.Errorf("template fees = %d, want 52009", tmpl.Fees)
	}
}

// A child whose parent cannot go in the block (non-final here) must not be
// selected either, and must not drag the parent in: the template would
// otherwise spend an output that does not exist.
func TestGBTTemplate_PackageWithNonFinalParentIsSkipped(t *testing.T) {
	sig := [][]byte{make([]byte, 71), make([]byte, 33)}
	parentTx := pkgTx(wire.OutPoint{Hash: wire.Hash256{0xa0}}, 100_000, 0xa1, sig)
	parentTx.LockTime = 500 // height lock above the template height (1)
	parentTx.TxIn[0].Sequence = 0
	a := pkgEntry(parentTx, 9)
	b := pkgEntry(pkgTx(wire.OutPoint{Hash: a.TxHash, Index: 0}, 50_000, 0xb1, sig), 50_000, a)
	c := pkgEntry(pkgTx(wire.OutPoint{Hash: wire.Hash256{0xc0}}, 100_000, 0xc1, sig), 2_000)

	tmpl, err := pkgGenerator(t, []*mempool.TxEntry{b, c, a}).GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}
	got := tmpl.Block.Transactions[1:]
	if len(got) != 1 || got[0].TxHash() != c.TxHash {
		ids := make([]string, len(got))
		for i, tx := range got {
			ids[i] = tx.TxHash().String()
		}
		t.Fatalf("template txs = %v, want only C %s", ids, c.TxHash)
	}
	if tmpl.Fees != 2_000 {
		t.Errorf("template fees = %d, want 2000", tmpl.Fees)
	}
}

// warden_e shape: a chain of P2WPKH spends where every child's prevout is a
// mempool output. Core reports sigops 1 for each (the witness sigop of the
// P2WPKH spend); blockbrew resolved prevouts only against the chain UTXO set,
// so every child counted 0.
func TestGBTTemplate_WitnessSigOpsSeeMempoolParents(t *testing.T) {
	sig := [][]byte{make([]byte, 71), make([]byte, 33)}
	confirmed := wire.OutPoint{Hash: wire.Hash256{0xee}}
	root := pkgEntry(pkgTx(confirmed, 100_000, 0x11, sig), 10_000)
	child := pkgEntry(pkgTx(wire.OutPoint{Hash: root.TxHash}, 90_000, 0x22, sig), 9_000, root)
	grandchild := pkgEntry(pkgTx(wire.OutPoint{Hash: child.TxHash}, 80_000, 0x33, sig), 8_000, child)

	tg := pkgGenerator(t, []*mempool.TxEntry{root, child, grandchild})
	// Chain view holds only the confirmed coin the root spends.
	view := consensus.NewInMemoryUTXOView()
	view.AddUTXO(confirmed, &consensus.UTXOEntry{Amount: 110_000, PkScript: p2wpkhScript(0x01), Height: 1})
	tg.SetUTXOSource(&viewUTXOSource{view: view})
	tmpl, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}
	if len(tmpl.TxSigOpsCost) != 3 {
		t.Fatalf("TxSigOpsCost has %d entries, want 3", len(tmpl.TxSigOpsCost))
	}
	for i, got := range tmpl.TxSigOpsCost {
		if got != 1 {
			t.Errorf("transactions[%d] sigops = %d, want 1 (P2WPKH witness sigop)", i, got)
		}
	}
	if tmpl.SigOpsCost != 3 {
		t.Errorf("template sigops cost = %d, want 3", tmpl.SigOpsCost)
	}
}

type viewUTXOSource struct{ view consensus.UpdatableUTXOView }

func (s *viewUTXOSource) UTXOSet() consensus.UpdatableUTXOView { return s.view }
