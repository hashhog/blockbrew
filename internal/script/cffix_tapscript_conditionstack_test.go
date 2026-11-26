package script

// Item cffix-blockbrew-tapscript-conditionstack (finding F4 of the
// secscan3-blockbrew scan).
//
// executeScript asked isExecuting() before every opcode, and isExecuting
// walked the whole condition stack. Tapscript has no opcode limit and no
// IF-nesting limit, so the leaf (OP_1 OP_IF) x d, OP_NOP x d, OP_ENDIF x d,
// OP_1 cost O(d^2): about 5.7 s for the 399,601 B (standard-size) leaf at
// d = 99,900, against about 4 ms for a 400 KB leaf of OP_NOPs. Bitcoin
// Core's ConditionStack (src/script/interpreter.cpp:273-318) keeps only the
// stack size and the position of the first false entry, so every operation
// on it is O(1).
//
// TestCffixNestedIfCostLinear is the cost check (fails on master). The
// verdict tests below pin IF/NOTIF/ELSE/ENDIF semantics and pass both
// before and after the fix.

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---- cost: real P2TR script-path spends ------------------------------------

const cffixCondFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot

type cffixCondSpend struct {
	tx       *wire.MsgTx
	spk      []byte
	prevOuts []*wire.TxOut
}

// cffixCondBuildSpend commits to leaf as the single tapscript leaf of a
// fresh P2TR output and returns a one-input script-path spend of it.
func cffixCondBuildSpend(t *testing.T, leaf []byte) *cffixCondSpend {
	t.Helper()
	k := make([]byte, 32)
	k[31] = 0x07
	priv := crypto.PrivateKeyFromBytes(k)
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
	return &cffixCondSpend{tx: tx, spk: spk, prevOuts: []*wire.TxOut{{Value: 100000, PkScript: spk}}}
}

func (s *cffixCondSpend) verify() error {
	return VerifyScript(nil, s.spk, s.tx, 0, cffixCondFlags, s.prevOuts[0].Value, s.prevOuts)
}

// minDuration is the fastest of n verifies, to damp scheduler noise.
func (s *cffixCondSpend) minDuration(n int) (time.Duration, error) {
	best := time.Duration(1<<63 - 1)
	var err error
	for i := 0; i < n; i++ {
		start := time.Now()
		err = s.verify()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best, err
}

// cffixNestedIfLeaf: (OP_1 OP_IF) x d, OP_NOP x d, OP_ENDIF x d, OP_1.
func cffixNestedIfLeaf(d int) []byte {
	leaf := make([]byte, 0, 4*d+1)
	for i := 0; i < d; i++ {
		leaf = append(leaf, OP_1, OP_IF)
	}
	for i := 0; i < d; i++ {
		leaf = append(leaf, OP_NOP)
	}
	for i := 0; i < d; i++ {
		leaf = append(leaf, OP_ENDIF)
	}
	return append(leaf, OP_1)
}

func TestCffixNestedIfCostLinear(t *testing.T) {
	small := cffixCondBuildSpend(t, cffixNestedIfLeaf(4000))
	large := cffixCondBuildSpend(t, cffixNestedIfLeaf(16000))
	d1, err := small.minDuration(5)
	if err != nil {
		t.Fatalf("control: the depth-4000 spend must be valid, got %v", err)
	}
	d2, err := large.minDuration(3)
	if err != nil {
		t.Fatalf("control: the depth-16000 spend must be valid, got %v", err)
	}
	ratio := float64(d2) / float64(d1)
	t.Logf("nested IF depth 4000: %v, depth 16000: %v, ratio %.1f (linear ~4, quadratic ~16)", d1, d2, ratio)
	if ratio > 8 {
		t.Fatalf("4x the IF nesting cost %.1fx the time (linear ~4x, quadratic ~16x): the condition stack is scanned per opcode; Core's ConditionStack is O(1)", ratio)
	}
}

// ---- verdicts: hand vectors --------------------------------------------------

// cffixRunCond runs script on a bare engine (no tx needed: the scripts below
// have no signature opcodes) and returns the error and the final stack.
func cffixRunCond(sv SigVersion, script []byte) (error, [][]byte) {
	e := &Engine{stack: NewStack(), altStack: NewStack(), sigVersion: sv}
	err := e.executeScript(script)
	return err, e.stack.items
}

var cffixCondSigVersions = []struct {
	name string
	sv   SigVersion
}{{"base", SigVersionBase}, {"tapscript", SigVersionTapscript}}

func cffixStackString(st [][]byte) string {
	var b bytes.Buffer
	for i, it := range st {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%x", it)
	}
	return "[" + b.String() + "]"
}

func TestCffixConditionalVerdicts(t *testing.T) {
	one := []byte{1}
	empty := []byte{}
	cases := []struct {
		name   string
		script []byte
		err    error    // nil = success
		stack  [][]byte // checked on success
	}{
		{"if true", []byte{OP_1, OP_IF, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"if false skips", []byte{OP_0, OP_IF, OP_1, OP_ENDIF}, nil, nil},
		{"notif false runs", []byte{OP_0, OP_NOTIF, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"if false else runs", []byte{OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"if true else skipped", []byte{OP_1, OP_IF, OP_1, OP_ELSE, OP_RETURN, OP_ENDIF}, nil, [][]byte{one}},
		{"double else toggles back", []byte{OP_1, OP_IF, OP_1, OP_ELSE, OP_RETURN, OP_ELSE, OP_0, OP_ENDIF}, nil, [][]byte{one, empty}},
		{"triple else", []byte{OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ELSE, OP_RETURN, OP_ELSE, OP_0, OP_ENDIF}, nil, [][]byte{one, empty}},
		// A false parent: nothing inside executes, whatever the inner ELSEs do.
		{"else under false parent", []byte{OP_0, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ENDIF}, nil, nil},
		{"else under false parent twice", []byte{OP_0, OP_IF, OP_1, OP_IF, OP_RETURN, OP_ELSE, OP_RETURN, OP_ELSE, OP_RETURN, OP_ENDIF, OP_RETURN, OP_ENDIF}, nil, nil},
		{"else under false grandparent", []byte{OP_0, OP_IF, OP_IF, OP_IF, OP_RETURN, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ENDIF}, nil, nil},
		// Leaving the false region resumes execution at the right depth.
		{"resume after inner false endif", []byte{OP_1, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"resume after outer else", []byte{OP_0, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"inner else flips under true parent", []byte{OP_1, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF, OP_ENDIF}, nil, [][]byte{one}},
		{"false then true sibling", []byte{OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1, OP_IF, OP_1, OP_ENDIF}, nil, [][]byte{one}},
		{"deep false then else at top", []byte{OP_1, OP_IF, OP_1, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ENDIF}, nil, [][]byte{one}},
		{"false at bottom true above", []byte{OP_0, OP_IF, OP_ELSE, OP_1, OP_IF, OP_1, OP_ENDIF, OP_ENDIF}, nil, [][]byte{one}},
		{"executed return inside true branch", []byte{OP_1, OP_IF, OP_RETURN, OP_ENDIF}, ErrOpReturn, nil},
		{"executed return after else", []byte{OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_RETURN, OP_ENDIF}, ErrOpReturn, nil},
		{"executed verify fails in else", []byte{OP_0, OP_IF, OP_ELSE, OP_0, OP_VERIFY, OP_ENDIF}, ErrVerifyFailed, nil},
		// Unbalanced.
		{"else without if", []byte{OP_ELSE}, ErrUnbalancedConditional, nil},
		{"endif without if", []byte{OP_ENDIF}, ErrUnbalancedConditional, nil},
		{"if without endif", []byte{OP_1, OP_IF}, ErrUnbalancedConditional, nil},
		{"false if without endif", []byte{OP_0, OP_IF, OP_1}, ErrUnbalancedConditional, nil},
		{"else after closed if", []byte{OP_1, OP_IF, OP_ENDIF, OP_ELSE}, ErrUnbalancedConditional, nil},
		{"extra endif", []byte{OP_1, OP_IF, OP_ENDIF, OP_ENDIF}, ErrUnbalancedConditional, nil},
		{"nested missing endif", []byte{OP_1, OP_IF, OP_0, OP_IF, OP_ENDIF}, ErrUnbalancedConditional, nil},
		{"unbalanced inside false branch", []byte{OP_0, OP_IF, OP_IF, OP_ENDIF}, ErrUnbalancedConditional, nil},
	}
	for _, sv := range cffixCondSigVersions {
		for _, c := range cases {
			err, st := cffixRunCond(sv.sv, c.script)
			name := sv.name + "/" + c.name
			if c.err == nil {
				if err != nil {
					t.Errorf("%s: want success, got %v", name, err)
					continue
				}
				if cffixStackString(st) != cffixStackString(c.stack) {
					t.Errorf("%s: final stack %s, want %s", name, cffixStackString(st), cffixStackString(c.stack))
				}
				continue
			}
			if !errors.Is(err, c.err) {
				t.Errorf("%s: want %v, got %v", name, c.err, err)
			}
		}
	}
}

// A long false region (one false entry at the bottom of 3000 true entries,
// and 3000 false entries under a true one) behaves the same as a short one.
func TestCffixConditionalDeepRegions(t *testing.T) {
	const d = 3000
	// OP_0 OP_IF (OP_1 OP_IF) x d OP_RETURN (OP_ENDIF) x d OP_ELSE OP_1 OP_ENDIF
	s := []byte{OP_0, OP_IF}
	for i := 0; i < d; i++ {
		s = append(s, OP_1, OP_IF)
	}
	s = append(s, OP_RETURN)
	for i := 0; i < d; i++ {
		s = append(s, OP_ENDIF)
	}
	s = append(s, OP_ELSE, OP_1, OP_ENDIF)
	err, st := cffixRunCond(SigVersionTapscript, s)
	if err != nil || cffixStackString(st) != "[01]" {
		t.Fatalf("false bottom under %d nested IFs: err=%v stack=%s, want success [01]", d, err, cffixStackString(st))
	}
	// (OP_1 OP_IF) x d OP_0 OP_IF OP_RETURN OP_ELSE OP_1 OP_ENDIF (OP_ENDIF) x d
	s = nil
	for i := 0; i < d; i++ {
		s = append(s, OP_1, OP_IF)
	}
	s = append(s, OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF)
	for i := 0; i < d; i++ {
		s = append(s, OP_ENDIF)
	}
	err, st = cffixRunCond(SigVersionTapscript, s)
	if err != nil || cffixStackString(st) != "[01]" {
		t.Fatalf("false top over %d true entries: err=%v stack=%s, want success [01]", d, err, cffixStackString(st))
	}
	// Same, missing one ENDIF: unbalanced.
	err, _ = cffixRunCond(SigVersionTapscript, s[:len(s)-1])
	if !errors.Is(err, ErrUnbalancedConditional) {
		t.Fatalf("missing one of %d ENDIFs: want unbalanced, got %v", d, err)
	}
}

// ---- verdicts: differential against a reference model -----------------------

// cffixRefOutcome is the reference model: an explicit vector of branch
// values with the pre-0.21 Core rule (execute iff no false entry; OP_ELSE
// flips the top unconditionally). It is deliberately the simplest correct
// model, independent of the engine's representation.
func cffixRefOutcome(script []byte) (error, [][]byte) {
	var vf []bool
	var st [][]byte
	exec := func() bool {
		for _, v := range vf {
			if !v {
				return false
			}
		}
		return true
	}
	for _, op := range script {
		x := exec()
		switch op {
		case OP_IF, OP_NOTIF:
			v := false
			if x {
				if len(st) == 0 {
					return ErrStackUnderflow, nil
				}
				top := st[len(st)-1]
				st = st[:len(st)-1]
				v = len(top) != 0
				if op == OP_NOTIF {
					v = !v
				}
			}
			vf = append(vf, v)
			continue
		case OP_ELSE:
			if len(vf) == 0 {
				return ErrUnbalancedConditional, nil
			}
			vf[len(vf)-1] = !vf[len(vf)-1]
			continue
		case OP_ENDIF:
			if len(vf) == 0 {
				return ErrUnbalancedConditional, nil
			}
			vf = vf[:len(vf)-1]
			continue
		}
		if !x {
			continue
		}
		switch op {
		case OP_0:
			st = append(st, []byte{})
		case OP_1:
			st = append(st, []byte{1})
		case OP_DUP:
			if len(st) == 0 {
				return ErrStackUnderflow, nil
			}
			st = append(st, st[len(st)-1])
		case OP_DROP:
			if len(st) == 0 {
				return ErrStackUnderflow, nil
			}
			st = st[:len(st)-1]
		case OP_VERIFY:
			if len(st) == 0 {
				return ErrStackUnderflow, nil
			}
			top := st[len(st)-1]
			st = st[:len(st)-1]
			if len(top) == 0 {
				return ErrVerifyFailed, nil
			}
		case OP_RETURN:
			return ErrOpReturn, nil
		}
	}
	if len(vf) != 0 {
		return ErrUnbalancedConditional, nil
	}
	return nil, st
}

func TestCffixConditionalDifferential(t *testing.T) {
	// Weighted toward control flow so deep nesting, false regions and
	// ELSE-under-false-parent all occur often.
	ops := []byte{OP_0, OP_1, OP_1, OP_IF, OP_IF, OP_NOTIF, OP_ELSE, OP_ELSE, OP_ENDIF, OP_ENDIF, OP_ENDIF, OP_DUP, OP_DROP, OP_VERIFY, OP_RETURN}
	rng := rand.New(rand.NewSource(20261126))
	outcomes := map[string]int{}
	for i := 0; i < 20000; i++ {
		// A few leading pushes so IF/VERIFY do not mostly underflow, then
		// up to 60 random opcodes (< 201, so the base op limit never fires).
		var s []byte
		for j := rng.Intn(8); j > 0; j-- {
			s = append(s, OP_0+byte(rng.Intn(2))*(OP_1-OP_0))
		}
		for j := 1 + rng.Intn(60); j > 0; j-- {
			s = append(s, ops[rng.Intn(len(ops))])
		}
		wantErr, wantSt := cffixRefOutcome(s)
		key := "ok"
		if wantErr != nil {
			key = wantErr.Error()
		}
		outcomes[key]++
		for _, sv := range cffixCondSigVersions {
			gotErr, gotSt := cffixRunCond(sv.sv, s)
			if wantErr == nil {
				if gotErr != nil || cffixStackString(gotSt) != cffixStackString(wantSt) {
					t.Fatalf("%s script %x: got err=%v stack=%s, model says success %s", sv.name, s, gotErr, cffixStackString(gotSt), cffixStackString(wantSt))
				}
			} else if !errors.Is(gotErr, wantErr) {
				t.Fatalf("%s script %x: got err=%v, model says %v", sv.name, s, gotErr, wantErr)
			}
		}
	}
	t.Logf("differential outcomes over 20000 scripts: %v", outcomes)
	for _, k := range []string{"ok", ErrUnbalancedConditional.Error(), ErrOpReturn.Error(), ErrVerifyFailed.Error(), ErrStackUnderflow.Error()} {
		if outcomes[k] < 100 {
			t.Fatalf("differential reached outcome %q only %d times; the generator is not exercising it", k, outcomes[k])
		}
	}
}
