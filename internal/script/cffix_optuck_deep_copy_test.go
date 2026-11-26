package script

// OP_TUCK must copy only the top element (item cffix-blockbrew-optuck-deep-copy).
//
// Core v31.1 src/script/interpreter.cpp:862-869:
//
//	case OP_TUCK:
//	    valtype vch = stacktop(-1);
//	    stack.insert(stack.end()-2, vch);
//
// That copies the 520-byte-max top element once and moves the rest. blockbrew
// used to rebuild the stack and hand it to Stack.SetItems, which deep-copies
// every item, so one OP_TUCK cost O(total stack bytes) (up to 1000 x 520 B).
// Tapscript has no 201-opcode limit, so a ~382 KB leaf of OP_TUCK OP_DROP
// pairs over a full stack took ~28.5 s to verify while holding the mempool
// lock.

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

const cffixTuckFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot

// cffixTuckLeaf: one 520-byte push, OP_DUP x998 (999 items of 520 B), then
// `pairs` x (OP_TUCK OP_DROP), then OP_2DROP x499 OP_DROP leaves an empty
// stack and OP_1 makes the spend succeed.
func cffixTuckLeaf(pairs int) []byte {
	leaf := []byte{OP_PUSHDATA2, 0x08, 0x02}
	leaf = append(leaf, make([]byte, 520)...)
	for i := 0; i < 998; i++ {
		leaf = append(leaf, OP_DUP)
	}
	for i := 0; i < pairs; i++ {
		leaf = append(leaf, OP_TUCK, OP_DROP)
	}
	for i := 0; i < 499; i++ {
		leaf = append(leaf, OP_2DROP)
	}
	return append(leaf, OP_DROP, OP_1)
}

type cffixTuckSpend struct {
	tx       *wire.MsgTx
	spk      []byte
	prevOuts []*wire.TxOut
}

// cffixTuckBuildSpend commits to `leaf` as the single tapscript leaf of a
// fresh P2TR output and returns a one-input script-path spend of it.
func cffixTuckBuildSpend(leaf []byte) *cffixTuckSpend {
	key := make([]byte, 32)
	key[31] = 0x07
	priv := crypto.PrivateKeyFromBytes(key)
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
			Witness:          [][]byte{leaf, control},
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_RETURN}}},
	}
	prevOuts := []*wire.TxOut{{Value: 100000, PkScript: spk}}
	return &cffixTuckSpend{tx: tx, spk: spk, prevOuts: prevOuts}
}

// allocBytes returns the heap bytes allocated during one VerifyScript.
func (s *cffixTuckSpend) allocBytes() (uint64, error) {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	err := VerifyScript(nil, s.spk, s.tx, 0, cffixTuckFlags, s.prevOuts[0].Value, s.prevOuts)
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc, err
}

func TestCffixOpTuckCopiesOnlyTopElement(t *testing.T) {
	small := cffixTuckBuildSpend(cffixTuckLeaf(50))
	large := cffixTuckBuildSpend(cffixTuckLeaf(250))
	a1, err := small.allocBytes()
	if err != nil {
		t.Fatalf("control: the 50-pair spend must be valid, got %v", err)
	}
	a2, err := large.allocBytes()
	if err != nil {
		t.Fatalf("control: the 250-pair spend must be valid, got %v", err)
	}
	perPair := (float64(a2) - float64(a1)) / 200
	t.Logf("OP_TUCK+OP_DROP with 999 x 520 B on the stack: %.0f bytes allocated per pair", perPair)
	// Core copies only the duplicated top element (520 B). Allow 8 KiB for
	// slice growth; a deep copy of the stack is about 999 x 520 B = 520 KB.
	if perPair > 8192 {
		t.Fatalf("OP_TUCK allocates %.0f bytes per execution with 999 x 520 B on the stack; Core copies only the top element (520 B)", perPair)
	}
}

// TestCffixOpTuckStackContent pins the result stack of OP_TUCK byte for byte
// (so the cheaper insert cannot change what any script evaluates to) and
// checks the inserted element is an independent copy, as Core's valtype copy
// is: later changes to the top item must not show through the tucked one.
func TestCffixOpTuckStackContent(t *testing.T) {
	big := bytes.Repeat([]byte{0xab}, 520)
	cases := []struct {
		name  string
		setup [][]byte
		want  [][]byte
	}{
		{"two items", [][]byte{{1}, {2}}, [][]byte{{2}, {1}, {2}}},
		{"empty top", [][]byte{{1}, {}}, [][]byte{{}, {1}, {}}},
		{"empty second", [][]byte{{}, {3, 4}}, [][]byte{{3, 4}, {}, {3, 4}}},
		{"deep stack", [][]byte{{9}, {8, 7}, {6}, big, {5}}, [][]byte{{9}, {8, 7}, {6}, {5}, big, {5}}},
		{"big top", [][]byte{{0}, {1}, big}, [][]byte{{0}, big, {1}, big}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newBareEngine()
			for _, it := range tc.setup {
				e.stack.Push(it)
			}
			if err := e.executeScript([]byte{OP_TUCK}); err != nil {
				t.Fatalf("OP_TUCK: %v", err)
			}
			got := e.stack.Items()
			if len(got) != len(tc.want) {
				t.Fatalf("stack size %d, want %d", len(got), len(tc.want))
			}
			for i := range tc.want {
				if !bytes.Equal(got[i], tc.want[i]) {
					t.Fatalf("item %d = %x, want %x", i, got[i], tc.want[i])
				}
			}
			n := len(got)
			if len(got[n-1]) > 0 {
				before := append([]byte(nil), got[n-3]...)
				got[n-1][0] ^= 0xff
				if !bytes.Equal(got[n-3], before) {
					t.Fatalf("tucked element aliases the top element")
				}
			}
		})
	}

	// Fewer than two items: Core fails with SCRIPT_ERR_INVALID_STACK_OPERATION.
	e := newBareEngine()
	e.stack.Push([]byte{1})
	if err := e.executeScript([]byte{OP_TUCK}); err == nil {
		t.Fatalf("OP_TUCK on a one-item stack must fail")
	}
}

// TestCffixOpTuckRepeatedKeepsItemsDistinct runs OP_TUCK many times without
// dropping and then checks every item is still the right bytes and that no
// two stack slots share a backing array (the in-place insert must move slice
// headers, not leave two slots pointing at one item).
func TestCffixOpTuckRepeatedKeepsItemsDistinct(t *testing.T) {
	e := newBareEngine()
	e.stack.Push([]byte{0xaa})
	e.stack.Push([]byte{0xbb})
	script := bytes.Repeat([]byte{OP_TUCK}, 50)
	if err := e.executeScript(script); err != nil {
		t.Fatalf("OP_TUCK x50: %v", err)
	}
	got := e.stack.Items()
	// Expected stack from a reference model of Core's
	// stack.insert(stack.end()-2, stacktop(-1)).
	want := [][]byte{{0xaa}, {0xbb}}
	for i := 0; i < 50; i++ {
		top := append([]byte(nil), want[len(want)-1]...)
		n := len(want)
		want = append(want[:n-2], append([][]byte{top}, want[n-2:]...)...)
	}
	if len(got) != len(want) {
		t.Fatalf("stack size %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("item %d = %x, want %x", i, got[i], want[i])
		}
	}
	for i := range got {
		got[i][0] = byte(i)
	}
	for i := range got {
		if got[i][0] != byte(i) {
			t.Fatalf("stack slot %d shares its backing array with another slot", i)
		}
	}
}
