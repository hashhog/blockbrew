package script

import (
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// coreScriptError is the shape every failure of the validation engine must
// have: an error that names the Bitcoin Core ScriptError_t it mirrors
// (script/script_error.h). The block-connect classifier turns a Core code into
// a BLOCK_CONSENSUS verdict and anything else into a system fault, so an
// engine failure WITHOUT a code is a failure a crafted block could turn into
// a node halt.
type coreScriptError interface {
	error
	ScriptError() string
}

// blockConsensusFlags is the full set of consensus flags a post-taproot block
// is validated with (Core GetBlockScriptFlags).
const blockConsensusFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyDERSig |
	ScriptVerifyCLTV | ScriptVerifyCSV | ScriptVerifyNullDummy | ScriptVerifyTaproot

// secp256k1 G, a valid x-only key.
var testXOnlyKey, _ = hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

type scriptErrCase struct {
	name     string
	sig      []byte   // scriptSig
	pk       []byte   // scriptPubKey of the coin being spent
	witness  [][]byte // input witness
	flags    ScriptFlags
	nIn      int // inputs in the spending tx (default 1); the LAST one is verified
	nOut     int // outputs in the spending tx (default 1)
	wantCore string
}

// tapscriptSpend builds the scriptPubKey and witness for a script-path spend of
// leaf `leaf` with the given stack items below the leaf.
func tapscriptSpend(t *testing.T, leaf []byte, stack ...[]byte) ([]byte, [][]byte) {
	t.Helper()
	leafHash := TapLeaf(TaprootLeafTapscript, leaf)
	tweak := TapTweak(testXOnlyKey, leafHash[:])
	out, parity := crypto.ComputeTaprootOutputKey(testXOnlyKey, tweak)
	if out == nil {
		t.Fatal("ComputeTaprootOutputKey failed")
	}
	pk := append([]byte{OP_1, 32}, out...)
	control := append([]byte{TaprootLeafTapscript | parity}, testXOnlyKey...)
	w := append(append([][]byte{}, stack...), leaf, control)
	return pk, w
}

func keyPathPK() []byte { return append([]byte{OP_1, 32}, testXOnlyKey...) }

func sig65(hashType byte) []byte {
	s := make([]byte, 65)
	s[0] = 1
	s[64] = hashType
	return s
}

// scriptErrCases is one crafted input per engine failure site whose error was
// untyped (errors.New / fmt.Errorf inline, or a sentinel reused for a
// consensus failure), plus a sample of the long-standing sentinels.
func scriptErrCases(t *testing.T) []scriptErrCase {
	op1 := []byte{OP_1}
	minimalIfLeaf := []byte{OP_IF, OP_1, OP_ENDIF}
	v0Script := []byte{OP_IF, OP_1, OP_ENDIF}
	v0Hash := crypto.SHA256Hash(v0Script)
	v0PK := append([]byte{OP_0, 32}, v0Hash[:]...)

	tsPD1, tsPD1W := tapscriptSpend(t, []byte{OP_PUSHDATA1})
	tsPD2, tsPD2W := tapscriptSpend(t, []byte{OP_PUSHDATA2, 0x01})
	tsPD4, tsPD4W := tapscriptSpend(t, []byte{OP_PUSHDATA4, 0x01, 0x00})
	tsIf, tsIfW := tapscriptSpend(t, minimalIfLeaf, []byte{0x02})
	tsSucc, tsSuccW := tapscriptSpend(t, []byte{0x50})

	return []scriptErrCase{
		// Truncated pushes: Core GetOp fails -> SCRIPT_ERR_BAD_OPCODE.
		{name: "push_direct_truncated", sig: []byte{0x05, 0x01}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata1_no_length", sig: []byte{OP_PUSHDATA1}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata1_short_data", sig: []byte{OP_PUSHDATA1, 0x05, 0x01}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata2_no_length", sig: []byte{OP_PUSHDATA2, 0x01}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata2_short_data", sig: []byte{OP_PUSHDATA2, 0x05, 0x00, 0x01}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata4_no_length", sig: []byte{OP_PUSHDATA4, 0x01, 0x00}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "pushdata4_short_data", sig: []byte{OP_PUSHDATA4, 0x05, 0, 0, 0, 0x01}, pk: op1, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		// Undefined opcodes executed in legacy script (engine default case).
		{name: "opcode_0xff_executed", pk: []byte{OP_INVALIDOPCODE}, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "opcode_0xbb_executed", pk: []byte{0xbb}, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "op_reserved_executed", pk: []byte{OP_RESERVED}, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "op_reserved1_executed", pk: []byte{OP_RESERVED1}, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "checksigadd_in_legacy", pk: []byte{OP_CHECKSIGADD}, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		// Tapscript OP_SUCCESS pre-scan hits a truncated push: BAD_OPCODE.
		{name: "tapscript_prescan_pushdata1", pk: tsPD1, witness: tsPD1W, flags: blockConsensusFlags, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "tapscript_prescan_pushdata2", pk: tsPD2, witness: tsPD2W, flags: blockConsensusFlags, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		{name: "tapscript_prescan_pushdata4", pk: tsPD4, witness: tsPD4W, flags: blockConsensusFlags, wantCore: "SCRIPT_ERR_BAD_OPCODE"},
		// BIP-342 minimal IF (consensus in tapscript).
		{name: "tapscript_minimalif", pk: tsIf, witness: tsIfW, flags: blockConsensusFlags, wantCore: "SCRIPT_ERR_TAPSCRIPT_MINIMALIF"},
		// Witness v0 MINIMALIF (policy flag).
		{name: "witness_v0_minimalif", pk: v0PK, witness: [][]byte{{0x02}, v0Script}, flags: blockConsensusFlags | ScriptVerifyMinimalIf, wantCore: "SCRIPT_ERR_MINIMALIF"},
		// Taproot sighash failures: Core SignatureHashSchnorr returns false ->
		// SCRIPT_ERR_SCHNORR_SIG_HASHTYPE.
		{name: "taproot_keypath_undefined_hashtype", pk: keyPathPK(), witness: [][]byte{sig65(0x04)}, flags: blockConsensusFlags, wantCore: "SCRIPT_ERR_SCHNORR_SIG_HASHTYPE"},
		{name: "taproot_keypath_sighash_single_no_output", pk: keyPathPK(), witness: [][]byte{sig65(0x03)}, flags: blockConsensusFlags, nIn: 2, nOut: 1, wantCore: "SCRIPT_ERR_SCHNORR_SIG_HASHTYPE"},
		// Policy-only failures (never set for a block, typed all the same).
		{name: "discourage_upgradable_nop", pk: []byte{OP_NOP4, OP_1}, flags: ScriptVerifyDiscourageUpgradableNops, wantCore: "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS"},
		{name: "const_scriptcode_codeseparator", pk: []byte{OP_CODESEPARATOR, OP_1}, flags: ScriptVerifyConstScriptCode, wantCore: "SCRIPT_ERR_OP_CODESEPARATOR"},
		{name: "discourage_op_success", pk: tsSucc, witness: tsSuccW, flags: blockConsensusFlags | ScriptVerifyDiscourageOpSuccess, wantCore: "SCRIPT_ERR_DISCOURAGE_OP_SUCCESS"},
		// Long-standing sentinels.
		{name: "scriptnum_overflow", pk: []byte{0x05, 1, 2, 3, 4, 5, OP_1ADD}, wantCore: "SCRIPT_ERR_UNKNOWN_ERROR"},
		{name: "op_return", pk: []byte{OP_RETURN}, wantCore: "SCRIPT_ERR_OP_RETURN"},
		{name: "eval_false", pk: []byte{OP_0}, wantCore: "SCRIPT_ERR_EVAL_FALSE"},
		{name: "disabled_op_cat", pk: []byte{OP_1, OP_1, OP_CAT}, wantCore: "SCRIPT_ERR_DISABLED_OPCODE"},
		{name: "stack_underflow", pk: []byte{OP_DUP}, wantCore: "SCRIPT_ERR_INVALID_STACK_OPERATION"},
		{name: "unbalanced_conditional", pk: []byte{OP_1, OP_IF}, wantCore: "SCRIPT_ERR_UNBALANCED_CONDITIONAL"},
		{name: "verify_false", pk: []byte{OP_0, OP_VERIFY}, wantCore: "SCRIPT_ERR_VERIFY"},
	}
}

func runScriptErrCase(c scriptErrCase) error {
	nIn, nOut := c.nIn, c.nOut
	if nIn == 0 {
		nIn = 1
	}
	if nOut == 0 {
		nOut = 1
	}
	tx := &wire.MsgTx{Version: 2}
	prevOuts := make([]*wire.TxOut, nIn)
	for i := 0; i < nIn; i++ {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{byte(i + 1)}}, Sequence: 0xFFFFFFFF})
		prevOuts[i] = &wire.TxOut{Value: 10_000, PkScript: []byte{OP_1}}
	}
	for i := 0; i < nOut; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 1_000, PkScript: []byte{OP_1}})
	}
	idx := nIn - 1
	tx.TxIn[idx].SignatureScript = c.sig
	tx.TxIn[idx].Witness = c.witness
	prevOuts[idx] = &wire.TxOut{Value: 10_000, PkScript: c.pk}
	return VerifyScript(c.sig, c.pk, tx, idx, c.flags, 10_000, prevOuts)
}

// Every crafted failure carries the Core ScriptError it mirrors. An untyped
// failure fails here by name.
func TestScriptErrorsCarryCoreCode(t *testing.T) {
	for _, c := range scriptErrCases(t) {
		t.Run(c.name, func(t *testing.T) {
			err := runScriptErrCase(c)
			if err == nil {
				t.Fatal("script passed; the case no longer reaches its failure site")
			}
			var ce coreScriptError
			if !errors.As(err, &ce) {
				t.Fatalf("untyped script error %q (%T): no Core ScriptError code", err, err)
			}
			if got := ce.ScriptError(); got != c.wantCore {
				t.Fatalf("%q classified as %s, want %s", err, got, c.wantCore)
			}
		})
	}
}

// An out-of-range input index is a caller bug, not a property of any
// transaction: it must NOT carry a Core code (the classifier then treats it
// as a system fault, never a verdict on a block).
func TestScriptInvalidIndexIsInternal(t *testing.T) {
	tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{OP_1}}}}
	err := VerifyScript(nil, []byte{OP_1}, tx, 5, blockConsensusFlags, 1, nil)
	var ce coreScriptError
	if !errors.As(err, &ce) {
		t.Fatalf("untyped error %q (%T)", err, err)
	}
	if got := ce.ScriptError(); got != "BLOCKBREW_INTERNAL_ERROR" {
		t.Fatalf("invalid input index classified as %s, want BLOCKBREW_INTERNAL_ERROR", got)
	}
}

// Exhaustiveness guard: the files that make up the validation engine construct
// no untyped error. Every failure goes through a typed constructor, so a new
// failure site cannot silently become an unclassified error.
func TestScriptEngineHasNoUntypedErrorConstructors(t *testing.T) {
	files := []string{"engine.go", "opcodes_impl.go", "stack.go", "sighash.go", "opcode.go"}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if (pkg.Name == "errors" && sel.Sel.Name == "New") || (pkg.Name == "fmt" && sel.Sel.Name == "Errorf") {
				t.Errorf("%s: untyped %s.%s in the validation engine", fset.Position(call.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
}
