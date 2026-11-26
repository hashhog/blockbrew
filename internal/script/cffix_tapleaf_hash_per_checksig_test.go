package script

// cffix-blockbrew-tapleaf-hash-per-checksig (Claude Security secscan3 F5).
//
// Every tapscript CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD used to call
// TapLeaf(0xc0, script), which re-serialises the whole leaf into a fresh
// buffer and SHA256-hashes it. BIP342 allows about witness_size/50 signature
// checks, so the hashing grew as ~S^2/50 in the attacker's leaf size. Core
// computes execdata.m_tapleaf_hash once per spend (interpreter.cpp:1973,
// m_tapleaf_hash_init :1977) and SignatureHashSchnorr writes that cached
// value in (:1561-1562).
//
// The cost tests drive real P2TR script-path spends through VerifyScript.
// The equality tests pin that the cached hash is the very value the old
// per-opcode TapLeaf call produced, so no sighash changes: the leaf hash is
// always over the WHOLE leaf, never the part after OP_CODESEPARATOR
// (OP_CODESEPARATOR only moves codesep_pos in the tapscript sighash).

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

const cffixTapleafFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot

type cffixTapleafSpend struct {
	tx       *wire.MsgTx
	spk      []byte
	prevOuts []*wire.TxOut
}

func cffixTapleafKey() *crypto.PrivateKey {
	k := make([]byte, 32)
	k[31] = 0x07
	return crypto.PrivateKeyFromBytes(k)
}

// cffixTapleafBuildSpend commits to `leaf` as the single tapscript leaf of a
// fresh P2TR output and returns a one-input spend of it. stackFn gets the
// signing key and the tx/prevouts so it can compute whatever sighash it needs.
func cffixTapleafBuildSpend(t *testing.T, leaf []byte, stackFn func(tx *wire.MsgTx, prevOuts []*wire.TxOut, priv *crypto.PrivateKey) [][]byte) *cffixTapleafSpend {
	t.Helper()
	priv := cffixTapleafKey()
	internal := priv.PubKey().XOnlyPubKey()
	leafHash := TapLeaf(TaprootLeafTapscript, leaf)
	tweak := TapTweak(internal, leafHash[:])
	outKey, parity := crypto.ComputeTaprootOutputKey(internal, tweak)
	spk := append([]byte{OP_1, 0x20}, outKey...)
	control := append([]byte{TaprootLeafTapscript | parity}, internal...)

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_RETURN}}},
	}
	prevOuts := []*wire.TxOut{{Value: 100000, PkScript: spk}}

	var stack [][]byte
	if stackFn != nil {
		stack = stackFn(tx, prevOuts, priv)
	}
	tx.TxIn[0].Witness = append(append(stack, leaf), control)
	return &cffixTapleafSpend{tx: tx, spk: spk, prevOuts: prevOuts}
}

func (s *cffixTapleafSpend) verify() error {
	return VerifyScript(nil, s.spk, s.tx, 0, cffixTapleafFlags, s.prevOuts[0].Value, s.prevOuts)
}

func (s *cffixTapleafSpend) allocBytes() (uint64, error) {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	err := s.verify()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc, err
}

// cffixTapleafSign signs the BIP341 script-path sighash (SIGHASH_DEFAULT)
// for leaf hash `lh` and codesep position `codesep`.
func cffixTapleafSign(t *testing.T, tx *wire.MsgTx, prevOuts []*wire.TxOut, priv *crypto.PrivateKey, lh [32]byte, codesep uint32) []byte {
	t.Helper()
	sighash, err := CalcTaprootSignatureHash(SigHashDefault, tx, 0, prevOuts, &TaprootSigHashOptions{
		TapLeafHash: &lh, KeyVersion: 0, CodeSepPos: codesep,
	})
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	sig, err := crypto.SignSchnorr(priv, sighash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

func cffixTapleafSignWholeLeaf(t *testing.T, leaf []byte) func(*wire.MsgTx, []*wire.TxOut, *crypto.PrivateKey) [][]byte {
	return func(tx *wire.MsgTx, prevOuts []*wire.TxOut, priv *crypto.PrivateKey) [][]byte {
		return [][]byte{cffixTapleafSign(t, tx, prevOuts, priv, TapLeaf(TaprootLeafTapscript, leaf), 0xFFFFFFFF)}
	}
}

// cffixChecksigLeaf: n x (OP_DUP <pk> OP_CHECKSIGVERIFY), 16n OP_NOPs so the
// BIP342 budget (50 + witness size) covers n checks, then OP_DROP OP_1. The
// one witness item is a valid signature; every check has the same sighash.
func cffixChecksigLeaf(n int, pk []byte) []byte {
	leaf := make([]byte, 0, 51*n+2)
	for i := 0; i < n; i++ {
		leaf = append(leaf, OP_DUP, 0x20)
		leaf = append(leaf, pk...)
		leaf = append(leaf, OP_CHECKSIGVERIFY)
	}
	for i := 0; i < 16*n; i++ {
		leaf = append(leaf, OP_NOP)
	}
	return append(leaf, OP_DROP, OP_1)
}

// cffixChecksigAddLeaf: OP_0, n x (OP_OVER OP_SWAP <pk> OP_CHECKSIGADD),
// <n> OP_NUMEQUALVERIFY, 16n OP_NOPs, OP_DROP OP_1.
func cffixChecksigAddLeaf(n int, pk []byte) []byte {
	leaf := make([]byte, 0, 52*n+16)
	leaf = append(leaf, OP_0)
	for i := 0; i < n; i++ {
		leaf = append(leaf, OP_OVER, OP_SWAP, 0x20)
		leaf = append(leaf, pk...)
		leaf = append(leaf, OP_CHECKSIGADD)
	}
	num := ScriptNumSerialize(int64(n))
	leaf = append(leaf, byte(len(num)))
	leaf = append(leaf, num...)
	leaf = append(leaf, OP_NUMEQUALVERIFY)
	for i := 0; i < 16*n; i++ {
		leaf = append(leaf, OP_NOP)
	}
	return append(leaf, OP_DROP, OP_1)
}

func cffixTapleafAllocRatio(t *testing.T, what string, mk func(n int, pk []byte) []byte) {
	t.Helper()
	pk := cffixTapleafKey().PubKey().XOnlyPubKey()
	smallLeaf, largeLeaf := mk(100, pk), mk(400, pk)
	small := cffixTapleafBuildSpend(t, smallLeaf, cffixTapleafSignWholeLeaf(t, smallLeaf))
	large := cffixTapleafBuildSpend(t, largeLeaf, cffixTapleafSignWholeLeaf(t, largeLeaf))
	a1, err := small.allocBytes()
	if err != nil {
		t.Fatalf("control: the 100-%s spend must be valid, got %v", what, err)
	}
	a2, err := large.allocBytes()
	if err != nil {
		t.Fatalf("control: the 400-%s spend must be valid, got %v", what, err)
	}
	ratio := float64(a2) / float64(a1)
	t.Logf("100 x %s / %d B leaf: %d B allocated; 400 x %s / %d B leaf: %d B; ratio %.1f (linear ~4, quadratic ~16)",
		what, len(smallLeaf), a1, what, len(largeLeaf), a2, ratio)
	if ratio > 8 {
		t.Fatalf("4x the %s on a 4x leaf allocated %.1fx (linear ~4x, quadratic ~16x): the tapleaf hash is recomputed per signature check; Core computes it once per spend", what, ratio)
	}
}

// TestCffixTapleafHashedOncePerSpend: master 13.3x (FAIL), fixed ~4x.
func TestCffixTapleafHashedOncePerSpend(t *testing.T) {
	cffixTapleafAllocRatio(t, "CHECKSIGVERIFY", cffixChecksigLeaf)
}

// TestCffixTapleafHashedOncePerSpendChecksigAdd: the second site,
// opCheckSigAdd, is a separate function and gets its own proof.
func TestCffixTapleafHashedOncePerSpendChecksigAdd(t *testing.T) {
	cffixTapleafAllocRatio(t, "CHECKSIGADD", cffixChecksigAddLeaf)
}

// cffixCodesepLeaf: <pk> OP_CHECKSIGVERIFY OP_CODESEPARATOR <pk> OP_CHECKSIG.
// The first check signs with codesep_pos 0xFFFFFFFF, the second with
// codesep_pos 2 (opcode index of OP_CODESEPARATOR). Both commit to the
// tapleaf hash of the WHOLE leaf.
func cffixCodesepLeaf(pk []byte) []byte {
	leaf := []byte{0x20}
	leaf = append(leaf, pk...)
	leaf = append(leaf, OP_CHECKSIGVERIFY, OP_CODESEPARATOR, 0x20)
	leaf = append(leaf, pk...)
	return append(leaf, OP_CHECKSIG)
}

// TestCffixTapleafCachedHashEqualsTapLeafWithCodesep pins the cached value:
// after executing a script-path spend whose leaf contains OP_CODESEPARATOR,
// the Engine's cached leaf hash must equal TapLeaf(0xc0, whole leaf) — the
// value every CHECKSIG used to recompute — and not the hash of the part
// after OP_CODESEPARATOR.
func TestCffixTapleafCachedHashEqualsTapLeafWithCodesep(t *testing.T) {
	pk := cffixTapleafKey().PubKey().XOnlyPubKey()
	leaf := cffixCodesepLeaf(pk)
	sp := cffixTapleafBuildSpend(t, leaf, func(tx *wire.MsgTx, prevOuts []*wire.TxOut, priv *crypto.PrivateKey) [][]byte {
		lh := TapLeaf(TaprootLeafTapscript, leaf)
		// witness order: bottom first; the first CHECKSIGVERIFY pops the top.
		return [][]byte{
			cffixTapleafSign(t, tx, prevOuts, priv, lh, 2),
			cffixTapleafSign(t, tx, prevOuts, priv, lh, 0xFFFFFFFF),
		}
	})
	eng, err := NewEngine(sp.spk, sp.tx, 0, cffixTapleafFlags, sp.prevOuts[0].Value, sp.prevOuts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.Execute(); err != nil {
		t.Fatalf("control: the OP_CODESEPARATOR spend must be valid, got %v", err)
	}
	// Reflection so this file compiles on the base commit, where the field
	// does not exist; there the test fails here by name.
	f := reflect.ValueOf(eng).Elem().FieldByName("tapLeafHash")
	if !f.IsValid() {
		t.Fatalf("Engine has no cached tapLeafHash field: the leaf is re-hashed per signature check")
	}
	if f.Kind() != reflect.Ptr || f.IsNil() {
		t.Fatalf("Engine.tapLeafHash is not set after a tapscript script-path spend (kind %v)", f.Kind())
	}
	got := f.Elem()
	var cached [32]byte
	for i := 0; i < 32; i++ {
		cached[i] = byte(got.Index(i).Uint())
	}
	want := TapLeaf(TaprootLeafTapscript, leaf)
	if cached != want {
		t.Fatalf("cached leaf hash %x != TapLeaf(0xc0, leaf) %x", cached, want)
	}
	afterSep := TapLeaf(TaprootLeafTapscript, leaf[35:])
	if cached == afterSep {
		t.Fatalf("cached leaf hash is over the post-OP_CODESEPARATOR suffix, not the whole leaf")
	}
}

// TestCffixTapleafSighashUnchangedWithCodesep is the consensus guard, by
// behaviour only (passes on base and head): a valid OP_CODESEPARATOR spend
// stays valid, and signatures that commit to the wrong leaf hash (the
// post-codesep suffix, or a leaf version other than 0xc0) or the wrong
// codesep position are still rejected, for both CHECKSIG and CHECKSIGADD.
func TestCffixTapleafSighashUnchangedWithCodesep(t *testing.T) {
	pk := cffixTapleafKey().PubKey().XOnlyPubKey()

	// CHECKSIG leaf variant and a CHECKSIGADD variant of the same shape:
	// <pk> OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_0 <pk> OP_CHECKSIGADD OP_1 OP_NUMEQUAL
	checksigLeaf := cffixCodesepLeaf(pk)
	addLeaf := []byte{0x20}
	addLeaf = append(addLeaf, pk...)
	addLeaf = append(addLeaf, OP_CHECKSIGVERIFY, OP_CODESEPARATOR, OP_0, 0x20)
	addLeaf = append(addLeaf, pk...)
	addLeaf = append(addLeaf, OP_CHECKSIGADD, OP_1, OP_NUMEQUAL)
	// Witness is [sig2, sig1] (sig1 on top). CHECKSIGVERIFY consumes sig1;
	// the leaf then pushes OP_0 and <pk>, so CHECKSIGADD sees [sig2, 0, pk].
	// The second check runs after OP_CODESEPARATOR (opcode index 2).
	leaves := []struct {
		name string
		leaf []byte
	}{{"CHECKSIG", checksigLeaf}, {"CHECKSIGADD", addLeaf}}

	for _, l := range leaves {
		leaf := l.leaf
		whole := TapLeaf(TaprootLeafTapscript, leaf)
		suffix := TapLeaf(TaprootLeafTapscript, leaf[35:])
		otherVer := TapLeaf(0xc2, leaf)
		cases := []struct {
			name      string
			lh2       [32]byte
			codesep2  uint32
			wantValid bool
		}{
			{"whole leaf, codesep 2", whole, 2, true},
			{"post-codesep suffix leaf hash", suffix, 2, false},
			{"leaf version 0xc2", otherVer, 2, false},
			{"whole leaf, codesep 0xFFFFFFFF", whole, 0xFFFFFFFF, false},
		}
		for _, c := range cases {
			sp := cffixTapleafBuildSpend(t, leaf, func(tx *wire.MsgTx, prevOuts []*wire.TxOut, priv *crypto.PrivateKey) [][]byte {
				return [][]byte{
					cffixTapleafSign(t, tx, prevOuts, priv, c.lh2, c.codesep2),
					cffixTapleafSign(t, tx, prevOuts, priv, whole, 0xFFFFFFFF),
				}
			})
			err := sp.verify()
			if c.wantValid && err != nil {
				t.Errorf("%s / %s: want valid, got %v", l.name, c.name, err)
			}
			if !c.wantValid && err == nil {
				t.Errorf("%s / %s: want invalid, got valid", l.name, c.name)
			}
		}
	}
}
