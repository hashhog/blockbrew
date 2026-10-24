package rpc

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Tests for the getrawmempool(verbose) / getmempoolentry fields Core 31's
// entryToJSON (bitcoin-core/src/rpc/mempool.cpp) computes from the mempool
// graph: weight, the ancestor/descendant count/size/fees, depends and
// spentby.

// opTrueP2WSH is the P2WSH output for witness script OP_TRUE, spent with a
// one-item witness [OP_TRUE]. Standard as both output and input.
func opTrueP2WSH() []byte {
	h := sha256.Sum256([]byte{0x51})
	return append([]byte{0x00, 0x20}, h[:]...)
}

// spendOpTrue builds a tx spending each outpoint with the OP_TRUE witness and
// paying outValue to each of nOut OP_TRUE P2WSH outputs.
func spendOpTrue(ins []wire.OutPoint, nOut int, outValue int64) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for _, op := range ins {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			Sequence:         0xFFFFFFFE,
			Witness:          [][]byte{{0x51}},
		})
	}
	for i := 0; i < nOut; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: outValue, PkScript: opTrueP2WSH()})
	}
	return tx
}

// mempoolFamily is P -> {C1, C2} -> G, where G spends both outputs of C1 and
// the output of C2: a diamond (P reaches G twice) with a parent spent twice.
//
// C2's output value is chosen so that the two children's three orderings
// differ: admission order is C1, C2; Core's txid order (memcmp of the
// internal bytes) puts C2 first; hex-string order puts C1 first.
type mempoolFamily struct {
	mp               *mempool.Mempool
	p, c1, c2, g     *wire.MsgTx
	pH, c1H, c2H, gH wire.Hash256
	feeC2            int64
}

func newMempoolFamily(t *testing.T) *mempoolFamily {
	t.Helper()
	funding := wire.OutPoint{Hash: wire.Hash256{0x31, 0x01}, Index: 0}
	utxo := consensus.NewInMemoryUTXOView()
	utxo.AddUTXO(funding, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: opTrueP2WSH(), Height: 1})
	mp := mempool.New(mempool.DefaultConfig(), utxo)

	f := &mempoolFamily{mp: mp}
	f.p = spendOpTrue([]wire.OutPoint{funding}, 2, 490_000) // fee 20_000
	f.pH = f.p.TxHash()
	f.c1 = spendOpTrue([]wire.OutPoint{{Hash: f.pH, Index: 0}}, 2, 240_000) // fee 10_000
	f.c1H = f.c1.TxHash()
	for fee := int64(5_000); ; fee++ {
		f.c2 = spendOpTrue([]wire.OutPoint{{Hash: f.pH, Index: 1}}, 1, 490_000-fee)
		f.c2H = f.c2.TxHash()
		f.feeC2 = fee
		if coreHashLess(f.c2H, f.c1H) && f.c1H.String() < f.c2H.String() {
			break
		}
	}
	f.g = spendOpTrue([]wire.OutPoint{{Hash: f.c1H, Index: 0}, {Hash: f.c1H, Index: 1}, {Hash: f.c2H, Index: 0}}, 1, 480_000+490_000-f.feeC2-5_000) // fee 5_000
	f.gH = f.g.TxHash()
	for _, tx := range []*wire.MsgTx{f.p, f.c1, f.c2, f.g} {
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("AddTransaction %s: %v", tx.TxHash(), err)
		}
	}
	return f
}

func (f *mempoolFamily) vsize(t *testing.T, h wire.Hash256) int64 {
	t.Helper()
	e := f.mp.GetEntry(h)
	if e == nil {
		t.Fatalf("%s not in mempool", h)
	}
	return e.Size
}

func btc(sats int64) float64 { return float64(sats) / satoshiPerBitcoin }

// TestMempoolEntryWeightIsTxWeight: Core reports GetTxWeight, the real
// BIP-141 weight, not vsize*4. A segwit tx's weight is rarely a multiple of
// 4, so vsize*4 rounds it up (the regtest rows: 440 vs Core's 437).
func TestMempoolEntryWeightIsTxWeight(t *testing.T) {
	f := newMempoolFamily(t)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))
	for _, tx := range []*wire.MsgTx{f.p, f.c1, f.c2, f.g} {
		h := tx.TxHash()
		want := consensus.CalcTxWeight(tx)
		got := server.mempoolEntryFromTxEntry(f.mp.GetEntry(h)).Weight
		if got != want {
			t.Errorf("%s weight = %d, want GetTxWeight %d (vsize %d)", h, got, want, f.vsize(t, h))
		}
	}
	// The fixture must exercise the rounding, or this test proves nothing.
	if w := consensus.CalcTxWeight(f.p); w%4 == 0 {
		t.Fatalf("fixture weight %d is a multiple of 4; pick a tx that is not", w)
	}
}

// TestMempoolEntryAncestorDescendantTransitive: Core's CalculateAncestorData /
// CalculateDescendantData walk the whole in-mempool ancestor / descendant set
// (each tx once, self included) and sum vsize and MODIFIED fee. blockbrew
// reported only the tx itself for a parent admitted before its child.
func TestMempoolEntryAncestorDescendantTransitive(t *testing.T) {
	f := newMempoolFamily(t)
	const delta = 50_000
	f.mp.PrioritiseTransaction(f.c2H, delta)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))

	vP, vC1, vC2, vG := f.vsize(t, f.pH), f.vsize(t, f.c1H), f.vsize(t, f.c2H), f.vsize(t, f.gH)
	fP, fC1, fC2, fG := int64(20_000), int64(10_000), f.feeC2+delta, int64(5_000)
	all := vP + vC1 + vC2 + vG
	allFee := fP + fC1 + fC2 + fG

	type want struct {
		ancCount, descCount int
		ancSize, descSize   int64
		ancFee, descFee     int64
	}
	cases := []struct {
		name string
		h    wire.Hash256
		w    want
	}{
		{"parent", f.pH, want{1, 4, vP, all, fP, allFee}},
		{"child1", f.c1H, want{2, 2, vP + vC1, vC1 + vG, fP + fC1, fC1 + fG}},
		{"child2_prioritised", f.c2H, want{2, 2, vP + vC2, vC2 + vG, fP + fC2, fC2 + fG}},
		{"grandchild_diamond", f.gH, want{4, 1, all, vG, allFee, fG}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := server.mempoolEntryFromTxEntry(f.mp.GetEntry(tc.h))
			if e.AncestorCount != tc.w.ancCount || e.AncestorSize != tc.w.ancSize || e.Fees.Ancestor != btc(tc.w.ancFee) {
				t.Errorf("ancestor count/size/fee = %d/%d/%v, want %d/%d/%v",
					e.AncestorCount, e.AncestorSize, e.Fees.Ancestor, tc.w.ancCount, tc.w.ancSize, btc(tc.w.ancFee))
			}
			if e.DescendantCount != tc.w.descCount || e.DescendantSize != tc.w.descSize || e.Fees.Descendant != btc(tc.w.descFee) {
				t.Errorf("descendant count/size/fee = %d/%d/%v, want %d/%d/%v",
					e.DescendantCount, e.DescendantSize, e.Fees.Descendant, tc.w.descCount, tc.w.descSize, btc(tc.w.descFee))
			}
		})
	}
}

// coreHashLess is Core's txid ordering (uint256 operator<, a memcmp of the
// internal little-endian bytes), which is NOT the order of the hex strings.
func coreHashLess(a, b wire.Hash256) bool { return bytes.Compare(a[:], b[:]) < 0 }

// TestMempoolEntrySpentByCoreOrder: Core's GetChildren sorts the children by
// txid (CompareIteratorByHash) and lists each child once. blockbrew listed
// them in admission order, once per spent output.
func TestMempoolEntrySpentByCoreOrder(t *testing.T) {
	f := newMempoolFamily(t)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))

	// Core order is C2, C1 (fixture guarantees it; admission and hex order are C1, C2).
	kids := []wire.Hash256{f.c2H, f.c1H}
	got := server.mempoolEntryFromTxEntry(f.mp.GetEntry(f.pH)).SpentBy
	want := []string{kids[0].String(), kids[1].String()}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parent spentby = %v, want Core order %v", got, want)
	}

	// C1 has one child spending two of its outputs: listed once.
	if got := server.mempoolEntryFromTxEntry(f.mp.GetEntry(f.c1H)).SpentBy; len(got) != 1 || got[0] != f.gH.String() {
		t.Errorf("child1 spentby = %v, want [%s] (one entry per child)", got, f.gH)
	}
}

// TestMempoolEntryDependsSortedUnique: Core collects depends into a
// std::set<std::string>, so each in-mempool parent appears once and the list
// is in hex-string order.
func TestMempoolEntryDependsSortedUnique(t *testing.T) {
	f := newMempoolFamily(t)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))

	want := []string{f.c1H.String(), f.c2H.String()}
	sort.Strings(want)
	got := server.mempoolEntryFromTxEntry(f.mp.GetEntry(f.gH)).Depends
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("grandchild depends = %v, want %v", got, want)
	}
}

// TestMempoolEntryBIP125NonSignalingIsFalse drives the real admission path:
// a non-signaling tx (nSequence 0xfffffffe, Core createrawtransaction's
// default) in a default (full-RBF) mempool reports bip125-replaceable=false,
// as Core 31 does for every tx the regtest harness sends.
func TestMempoolEntryBIP125NonSignalingIsFalse(t *testing.T) {
	f := newMempoolFamily(t)
	if !f.mp.FullRBF() {
		t.Fatal("DefaultConfig is expected to run full RBF")
	}
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(f.mp))
	if server.mempoolEntryFromTxEntry(f.mp.GetEntry(f.gH)).BIP125Replaceable {
		t.Error("non-signaling tx under full RBF: bip125-replaceable=true, Core reports false")
	}
}
