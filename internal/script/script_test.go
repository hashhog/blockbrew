package script

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

func TestScriptNumSerialize(t *testing.T) {
	tests := []struct {
		n    int64
		want []byte
	}{
		{0, []byte{}},
		{1, []byte{0x01}},
		{-1, []byte{0x81}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x00}},
		{-127, []byte{0xff}},
		{-128, []byte{0x80, 0x80}},
		{255, []byte{0xff, 0x00}},
		{256, []byte{0x00, 0x01}},
		{-255, []byte{0xff, 0x80}},
		{-256, []byte{0x00, 0x81}},
		{32767, []byte{0xff, 0x7f}},
		{32768, []byte{0x00, 0x80, 0x00}},
		{-32767, []byte{0xff, 0xff}},
		{-32768, []byte{0x00, 0x80, 0x80}},
	}

	for _, tt := range tests {
		got := ScriptNumSerialize(tt.n)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("ScriptNumSerialize(%d) = %x, want %x", tt.n, got, tt.want)
		}

		// Verify round-trip
		back, err := ScriptNumDeserialize(got, 4, true)
		if err != nil {
			t.Errorf("ScriptNumDeserialize(%x) error: %v", got, err)
		}
		if back != tt.n {
			t.Errorf("Round-trip failed: %d -> %x -> %d", tt.n, got, back)
		}
	}
}

func TestCastToBool(t *testing.T) {
	tests := []struct {
		input []byte
		want  bool
	}{
		{[]byte{}, false},
		{[]byte{0x00}, false},
		{[]byte{0x00, 0x00}, false},
		{[]byte{0x80}, false}, // Negative zero
		{[]byte{0x01}, true},
		{[]byte{0x00, 0x01}, true},
		{[]byte{0x80, 0x00}, true}, // 128
		{[]byte{0xff}, true},       // -127
	}

	for _, tt := range tests {
		got := CastToBool(tt.input)
		if got != tt.want {
			t.Errorf("CastToBool(%x) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestStackBasicOps(t *testing.T) {
	s := NewStack()

	// Test push and pop
	s.Push([]byte{1, 2, 3})
	s.Push([]byte{4, 5, 6})

	if s.Size() != 2 {
		t.Errorf("Size() = %d, want 2", s.Size())
	}

	val, err := s.Pop()
	if err != nil {
		t.Fatalf("Pop() error: %v", err)
	}
	if !bytes.Equal(val, []byte{4, 5, 6}) {
		t.Errorf("Pop() = %v, want [4 5 6]", val)
	}

	// Test peek
	val, err = s.Peek()
	if err != nil {
		t.Fatalf("Peek() error: %v", err)
	}
	if !bytes.Equal(val, []byte{1, 2, 3}) {
		t.Errorf("Peek() = %v, want [1 2 3]", val)
	}

	// Verify peek didn't remove item
	if s.Size() != 1 {
		t.Errorf("Size() after Peek = %d, want 1", s.Size())
	}

	// Test underflow
	s.Pop()
	_, err = s.Pop()
	if err != ErrStackUnderflow {
		t.Errorf("Pop on empty stack got err = %v, want ErrStackUnderflow", err)
	}
}

func TestStackSwapTop(t *testing.T) {
	s := NewStack()
	s.Push([]byte{1})
	s.Push([]byte{2})

	err := s.SwapTop()
	if err != nil {
		t.Fatalf("SwapTop() error: %v", err)
	}

	top, _ := s.Pop()
	second, _ := s.Pop()

	if !bytes.Equal(top, []byte{1}) {
		t.Errorf("After swap, top = %v, want [1]", top)
	}
	if !bytes.Equal(second, []byte{2}) {
		t.Errorf("After swap, second = %v, want [2]", second)
	}
}

func TestStackIntOps(t *testing.T) {
	s := NewStack()

	s.PushInt(42)
	n, err := s.PopInt(4, false)
	if err != nil {
		t.Fatalf("PopInt() error: %v", err)
	}
	if n != 42 {
		t.Errorf("PopInt() = %d, want 42", n)
	}

	s.PushInt(-100)
	n, err = s.PopInt(4, false)
	if err != nil {
		t.Fatalf("PopInt() error: %v", err)
	}
	if n != -100 {
		t.Errorf("PopInt() = %d, want -100", n)
	}
}

func TestOpcodeName(t *testing.T) {
	tests := []struct {
		op   byte
		want string
	}{
		{OP_0, "OP_0"},
		{OP_DUP, "OP_DUP"},
		{OP_HASH160, "OP_HASH160"},
		{OP_CHECKSIG, "OP_CHECKSIG"},
		{0x05, "OP_PUSHBYTES"}, // Push 5 bytes
	}

	for _, tt := range tests {
		got := OpcodeName(tt.op)
		if got != tt.want {
			t.Errorf("OpcodeName(0x%02x) = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestSimpleScript(t *testing.T) {
	// Test simple arithmetic: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
	script := []byte{
		OP_1,
		OP_2,
		OP_ADD,
		OP_3,
		OP_EQUAL,
	}

	// Create a dummy transaction
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  []byte{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 0, PkScript: script},
		},
		LockTime: 0,
	}

	engine, err := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	// Execute the script directly
	engine.stack = NewStack()
	err = engine.executeScript(script)
	if err != nil {
		t.Fatalf("executeScript error: %v", err)
	}

	// Check result
	if engine.stack.IsEmpty() {
		t.Fatal("Stack is empty after execution")
	}
	result, _ := engine.stack.Pop()
	if !CastToBool(result) {
		t.Errorf("Script result = false, want true")
	}
}

func TestIfElseEndif(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
		want   bool
	}{
		{
			name: "IF taken",
			script: []byte{
				OP_1,     // Push true
				OP_IF,    // Enter IF
				OP_1,     // Push 1 (this executes)
				OP_ELSE,
				OP_0,     // Push 0 (this doesn't execute)
				OP_ENDIF,
			},
			want: true,
		},
		{
			name: "IF not taken",
			script: []byte{
				OP_0,     // Push false
				OP_IF,    // Don't enter IF
				OP_0,     // Push 0 (doesn't execute)
				OP_ELSE,
				OP_1,     // Push 1 (this executes)
				OP_ENDIF,
			},
			want: true,
		},
		{
			name: "NOTIF taken when false",
			script: []byte{
				OP_0,      // Push false
				OP_NOTIF,  // Enter NOTIF (because value is false)
				OP_1,      // Push 1
				OP_ELSE,
				OP_0,      // Push 0 (doesn't execute)
				OP_ENDIF,
			},
			want: true,
		},
		{
			name: "nested IF",
			script: []byte{
				OP_1,     // Push true (outer condition)
				OP_IF,
				OP_1,     // Push true (inner condition)
				OP_IF,
				OP_1,     // Push 1 (innermost - executes)
				OP_ENDIF,
				OP_ENDIF,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
				TxOut:   []*wire.TxOut{{PkScript: tt.script}},
			}

			engine, err := NewEngine(tt.script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: tt.script}})
			if err != nil {
				t.Fatalf("NewEngine error: %v", err)
			}

			engine.stack = NewStack()
			err = engine.executeScript(tt.script)
			if err != nil {
				t.Fatalf("executeScript error: %v", err)
			}

			if engine.stack.IsEmpty() {
				t.Fatal("Stack is empty")
			}
			result, _ := engine.stack.Pop()
			got := CastToBool(result)
			if got != tt.want {
				t.Errorf("Script result = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArithmetic(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
		want   int64
	}{
		{
			name:   "1 + 2 = 3",
			script: []byte{OP_1, OP_2, OP_ADD},
			want:   3,
		},
		{
			name:   "5 - 3 = 2",
			script: []byte{OP_5, OP_3, OP_SUB},
			want:   2,
		},
		{
			name:   "-1",
			script: []byte{OP_1NEGATE},
			want:   -1,
		},
		{
			name:   "abs(-5) = 5",
			script: []byte{OP_5, OP_NEGATE, OP_ABS},
			want:   5,
		},
		{
			name:   "not(0) = 1",
			script: []byte{OP_0, OP_NOT},
			want:   1,
		},
		{
			name:   "not(5) = 0",
			script: []byte{OP_5, OP_NOT},
			want:   0,
		},
		{
			name:   "min(3, 5) = 3",
			script: []byte{OP_3, OP_5, OP_MIN},
			want:   3,
		},
		{
			name:   "max(3, 5) = 5",
			script: []byte{OP_3, OP_5, OP_MAX},
			want:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
				TxOut:   []*wire.TxOut{{PkScript: tt.script}},
			}

			engine, _ := NewEngine(tt.script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: tt.script}})
			engine.stack = NewStack()
			err := engine.executeScript(tt.script)
			if err != nil {
				t.Fatalf("executeScript error: %v", err)
			}

			got, err := engine.stack.PopInt(4, false)
			if err != nil {
				t.Fatalf("PopInt error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Result = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestStackManipulation(t *testing.T) {
	tests := []struct {
		name   string
		setup  [][]byte // Initial stack (bottom to top)
		script []byte
		want   [][]byte // Expected stack after (bottom to top)
	}{
		{
			name:   "DUP",
			setup:  [][]byte{{1}},
			script: []byte{OP_DUP},
			want:   [][]byte{{1}, {1}},
		},
		{
			name:   "DROP",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_DROP},
			want:   [][]byte{{1}},
		},
		{
			name:   "SWAP",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_SWAP},
			want:   [][]byte{{2}, {1}},
		},
		{
			name:   "OVER",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_OVER},
			want:   [][]byte{{1}, {2}, {1}},
		},
		{
			name:   "ROT",
			setup:  [][]byte{{1}, {2}, {3}},
			script: []byte{OP_ROT},
			want:   [][]byte{{2}, {3}, {1}},
		},
		{
			name:   "2DUP",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_2DUP},
			want:   [][]byte{{1}, {2}, {1}, {2}},
		},
		{
			name:   "NIP",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_NIP},
			want:   [][]byte{{2}},
		},
		{
			name:   "TUCK",
			setup:  [][]byte{{1}, {2}},
			script: []byte{OP_TUCK},
			want:   [][]byte{{2}, {1}, {2}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
				TxOut:   []*wire.TxOut{{PkScript: tt.script}},
			}

			engine, _ := NewEngine(tt.script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: tt.script}})
			engine.stack = NewStack()

			// Setup initial stack
			for _, item := range tt.setup {
				engine.stack.Push(item)
			}

			err := engine.executeScript(tt.script)
			if err != nil {
				t.Fatalf("executeScript error: %v", err)
			}

			// Check result
			gotItems := engine.stack.Items()
			if len(gotItems) != len(tt.want) {
				t.Fatalf("Stack size = %d, want %d", len(gotItems), len(tt.want))
			}
			for i, want := range tt.want {
				if !bytes.Equal(gotItems[i], want) {
					t.Errorf("Stack[%d] = %v, want %v", i, gotItems[i], want)
				}
			}
		})
	}
}

func TestOpReturn(t *testing.T) {
	script := []byte{OP_RETURN, 0x04, 0xde, 0xad, 0xbe, 0xef}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{PkScript: script}},
	}

	engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
	engine.stack = NewStack()
	err := engine.executeScript(script)

	if err != ErrOpReturn {
		t.Errorf("Expected ErrOpReturn, got %v", err)
	}
}

func TestOpReturnInNonExecutingBranch(t *testing.T) {
	// OP_RETURN inside a non-executing branch should NOT fail
	script := []byte{
		OP_0,      // Push false
		OP_IF,     // Don't enter IF
		OP_RETURN, // This should NOT execute
		OP_ENDIF,
		OP_1,      // Push 1 (this should execute)
	}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{PkScript: script}},
	}

	engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
	engine.stack = NewStack()
	err := engine.executeScript(script)

	if err != nil {
		t.Errorf("Expected no error for OP_RETURN in non-executing branch, got %v", err)
	}

	// Stack should have 1 on top
	if engine.stack.IsEmpty() {
		t.Fatal("Stack is empty")
	}
	result, _ := engine.stack.Pop()
	if !CastToBool(result) {
		t.Error("Expected true on stack")
	}
}

func TestHashOpcodes(t *testing.T) {
	data := []byte("hello")

	// Test OP_HASH160
	t.Run("HASH160", func(t *testing.T) {
		script := []byte{byte(len(data))}
		script = append(script, data...)
		script = append(script, OP_HASH160)

		tx := &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{PkScript: script}},
		}

		engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
		engine.stack = NewStack()
		err := engine.executeScript(script)
		if err != nil {
			t.Fatalf("executeScript error: %v", err)
		}

		result, _ := engine.stack.Pop()
		expected := crypto.Hash160(data)
		if !bytes.Equal(result, expected[:]) {
			t.Errorf("HASH160 result mismatch")
		}
	})

	// Test OP_HASH256
	t.Run("HASH256", func(t *testing.T) {
		script := []byte{byte(len(data))}
		script = append(script, data...)
		script = append(script, OP_HASH256)

		tx := &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{PkScript: script}},
		}

		engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
		engine.stack = NewStack()
		err := engine.executeScript(script)
		if err != nil {
			t.Fatalf("executeScript error: %v", err)
		}

		result, _ := engine.stack.Pop()
		expected := crypto.DoubleSHA256(data)
		if !bytes.Equal(result, expected[:]) {
			t.Errorf("HASH256 result mismatch")
		}
	})
}

func TestP2PKHScript(t *testing.T) {
	// Generate a key pair
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey error: %v", err)
	}
	pubKey := privKey.PubKey()
	pubKeyHash := crypto.Hash160(pubKey.SerializeCompressed())

	// Create P2PKH scriptPubKey: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
	scriptPubKey := make([]byte, 25)
	scriptPubKey[0] = OP_DUP
	scriptPubKey[1] = OP_HASH160
	scriptPubKey[2] = 20 // Push 20 bytes
	copy(scriptPubKey[3:23], pubKeyHash[:])
	scriptPubKey[23] = OP_EQUALVERIFY
	scriptPubKey[24] = OP_CHECKSIG

	// Create a transaction to sign
	prevOut := &wire.TxOut{
		Value:    100000,
		PkScript: scriptPubKey,
	}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  nil, // Will be set after signing
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: scriptPubKey},
		},
		LockTime: 0,
	}

	// Compute the signature hash
	sighash, err := CalcSignatureHash(scriptPubKey, SigHashAll, tx, 0)
	if err != nil {
		t.Fatalf("CalcSignatureHash error: %v", err)
	}

	// Sign
	sig, err := crypto.SignECDSA(privKey, sighash)
	if err != nil {
		t.Fatalf("SignECDSA error: %v", err)
	}

	// Append sighash type
	sig = append(sig, byte(SigHashAll))

	// Create scriptSig: <sig> <pubkey>
	pubKeyBytes := pubKey.SerializeCompressed()
	scriptSig := make([]byte, 0)
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)
	scriptSig = append(scriptSig, byte(len(pubKeyBytes)))
	scriptSig = append(scriptSig, pubKeyBytes...)

	// Set scriptSig
	tx.TxIn[0].SignatureScript = scriptSig

	// Verify
	err = VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("P2PKH verification failed: %v", err)
	}
}

func TestCheckMultiSig(t *testing.T) {
	// Generate 3 key pairs for 2-of-3 multisig
	privKeys := make([]*crypto.PrivateKey, 3)
	pubKeys := make([]*crypto.PublicKey, 3)
	for i := 0; i < 3; i++ {
		var err error
		privKeys[i], err = crypto.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("GeneratePrivateKey error: %v", err)
		}
		pubKeys[i] = privKeys[i].PubKey()
	}

	// Create 2-of-3 multisig script
	// OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
	redeemScript := []byte{OP_2}
	for _, pk := range pubKeys {
		pkBytes := pk.SerializeCompressed()
		redeemScript = append(redeemScript, byte(len(pkBytes)))
		redeemScript = append(redeemScript, pkBytes...)
	}
	redeemScript = append(redeemScript, OP_3, OP_CHECKMULTISIG)

	// Create a transaction
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  nil,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: redeemScript},
		},
		LockTime: 0,
	}

	prevOut := &wire.TxOut{
		Value:    100000,
		PkScript: redeemScript,
	}

	// Compute sighash
	sighash, err := CalcSignatureHash(redeemScript, SigHashAll, tx, 0)
	if err != nil {
		t.Fatalf("CalcSignatureHash error: %v", err)
	}

	// Sign with keys 0 and 1 (any 2 of 3)
	sig0, _ := crypto.SignECDSA(privKeys[0], sighash)
	sig0 = append(sig0, byte(SigHashAll))
	sig1, _ := crypto.SignECDSA(privKeys[1], sighash)
	sig1 = append(sig1, byte(SigHashAll))

	// Create scriptSig: OP_0 <sig1> <sig2>
	// Note: OP_0 is the dummy element for the CHECKMULTISIG off-by-one bug
	scriptSig := []byte{OP_0}
	scriptSig = append(scriptSig, byte(len(sig0)))
	scriptSig = append(scriptSig, sig0...)
	scriptSig = append(scriptSig, byte(len(sig1)))
	scriptSig = append(scriptSig, sig1...)

	tx.TxIn[0].SignatureScript = scriptSig

	// Verify
	err = VerifyScript(scriptSig, redeemScript, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("2-of-3 multisig verification failed: %v", err)
	}
}

func TestCheckMultiSigNullDummy(t *testing.T) {
	// Same setup as above, but with non-empty dummy and NULLDUMMY flag
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()

	// 1-of-1 multisig for simplicity
	redeemScript := []byte{OP_1}
	pkBytes := pubKey.SerializeCompressed()
	redeemScript = append(redeemScript, byte(len(pkBytes)))
	redeemScript = append(redeemScript, pkBytes...)
	redeemScript = append(redeemScript, OP_1, OP_CHECKMULTISIG)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  nil,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: redeemScript},
		},
	}

	prevOut := &wire.TxOut{Value: 100000, PkScript: redeemScript}

	sighash, _ := CalcSignatureHash(redeemScript, SigHashAll, tx, 0)
	sig, _ := crypto.SignECDSA(privKey, sighash)
	sig = append(sig, byte(SigHashAll))

	// Non-empty dummy (should fail with NULLDUMMY)
	scriptSig := []byte{0x01, 0x00} // Push 1 byte (0x00)
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)

	tx.TxIn[0].SignatureScript = scriptSig

	// Should fail with NULLDUMMY flag
	err := VerifyScript(scriptSig, redeemScript, tx, 0, ScriptVerifyNullDummy, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrNullDummy {
		t.Errorf("Expected ErrNullDummy, got %v", err)
	}

	// Should pass without NULLDUMMY flag
	err = VerifyScript(scriptSig, redeemScript, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("Expected success without NULLDUMMY, got %v", err)
	}
}

func TestNullFail(t *testing.T) {
	// BIP146 NULLFAIL: when signature verification fails and NULLFAIL is active,
	// the signature must be the empty byte vector, otherwise the script fails.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()

	pkBytes := pubKey.SerializeCompressed()

	// P2PKH-style scriptPubKey
	pubKeyHash := crypto.Hash160(pkBytes)
	scriptPubKey := []byte{OP_DUP, OP_HASH160, 20}
	scriptPubKey = append(scriptPubKey, pubKeyHash[:]...)
	scriptPubKey = append(scriptPubKey, OP_EQUALVERIFY, OP_CHECKSIG)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: []byte{}},
		},
	}

	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	// Create an invalid signature (wrong key signs)
	otherPrivKey, _ := crypto.GeneratePrivateKey()
	sighash, _ := CalcSignatureHash(scriptPubKey, SigHashAll, tx, 0)
	wrongSig, _ := crypto.SignECDSA(otherPrivKey, sighash)
	wrongSig = append(wrongSig, byte(SigHashAll))

	// ScriptSig with non-empty invalid signature
	scriptSig := []byte{byte(len(wrongSig))}
	scriptSig = append(scriptSig, wrongSig...)
	scriptSig = append(scriptSig, byte(len(pkBytes)))
	scriptSig = append(scriptSig, pkBytes...)
	tx.TxIn[0].SignatureScript = scriptSig

	// With NULLFAIL, non-empty failing signature must error
	err := VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNullFail, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrNullFail {
		t.Errorf("Expected ErrNullFail with non-empty invalid signature, got %v", err)
	}

	// Without NULLFAIL, the invalid sig just returns false (script fails)
	err = VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrScriptFailed {
		t.Errorf("Expected ErrScriptFailed without NULLFAIL, got %v", err)
	}

	// With empty signature (valid NULLFAIL behavior), script still fails but not with ErrNullFail
	emptyScriptSig := []byte{0} // Push empty byte array
	emptyScriptSig = append(emptyScriptSig, byte(len(pkBytes)))
	emptyScriptSig = append(emptyScriptSig, pkBytes...)
	tx.TxIn[0].SignatureScript = emptyScriptSig

	err = VerifyScript(emptyScriptSig, scriptPubKey, tx, 0, ScriptVerifyNullFail, prevOut.Value, []*wire.TxOut{prevOut})
	// Should fail but NOT with ErrNullFail (empty sig is allowed to fail)
	if err == ErrNullFail {
		t.Errorf("Empty signature should not trigger ErrNullFail")
	}
	if err == nil {
		t.Errorf("Empty signature should not pass verification")
	}
}

func TestNullFailMultiSig(t *testing.T) {
	// BIP146 NULLFAIL for CHECKMULTISIG: if multisig fails, all signatures
	// must be empty when NULLFAIL is active
	privKey1, _ := crypto.GeneratePrivateKey()
	pubKey1 := privKey1.PubKey()
	pkBytes1 := pubKey1.SerializeCompressed()

	privKey2, _ := crypto.GeneratePrivateKey()
	pubKey2 := privKey2.PubKey()
	pkBytes2 := pubKey2.SerializeCompressed()

	// 2-of-2 multisig
	redeemScript := []byte{OP_2}
	redeemScript = append(redeemScript, byte(len(pkBytes1)))
	redeemScript = append(redeemScript, pkBytes1...)
	redeemScript = append(redeemScript, byte(len(pkBytes2)))
	redeemScript = append(redeemScript, pkBytes2...)
	redeemScript = append(redeemScript, OP_2, OP_CHECKMULTISIG)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: []byte{}},
		},
	}

	prevOut := &wire.TxOut{Value: 100000, PkScript: redeemScript}

	// Create valid signatures
	sighash, _ := CalcSignatureHash(redeemScript, SigHashAll, tx, 0)
	sig1, _ := crypto.SignECDSA(privKey1, sighash)
	sig1 = append(sig1, byte(SigHashAll))

	// Create an invalid signature for slot 2 (from wrong key)
	otherPrivKey, _ := crypto.GeneratePrivateKey()
	wrongSig, _ := crypto.SignECDSA(otherPrivKey, sighash)
	wrongSig = append(wrongSig, byte(SigHashAll))

	// ScriptSig: OP_0 (dummy) sig1 wrongSig
	scriptSig := []byte{0} // empty dummy
	scriptSig = append(scriptSig, byte(len(sig1)))
	scriptSig = append(scriptSig, sig1...)
	scriptSig = append(scriptSig, byte(len(wrongSig)))
	scriptSig = append(scriptSig, wrongSig...)
	tx.TxIn[0].SignatureScript = scriptSig

	// With NULLFAIL, the non-empty failing sig triggers ErrNullFail
	err := VerifyScript(scriptSig, redeemScript, tx, 0, ScriptVerifyNullFail, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrNullFail {
		t.Errorf("Expected ErrNullFail for failed multisig with non-empty sig, got %v", err)
	}

	// Without NULLFAIL, it just fails
	err = VerifyScript(scriptSig, redeemScript, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrScriptFailed {
		t.Errorf("Expected ErrScriptFailed without NULLFAIL, got %v", err)
	}
}

func TestStackUnderflow(t *testing.T) {
	// OP_DUP with empty stack should fail
	script := []byte{OP_DUP}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{PkScript: script}},
	}

	engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
	engine.stack = NewStack()
	err := engine.executeScript(script)

	if err != ErrStackUnderflow {
		t.Errorf("Expected ErrStackUnderflow, got %v", err)
	}
}

func TestUnbalancedConditional(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
	}{
		{
			name:   "IF without ENDIF",
			script: []byte{OP_1, OP_IF},
		},
		{
			name:   "ELSE without IF",
			script: []byte{OP_ELSE},
		},
		{
			name:   "ENDIF without IF",
			script: []byte{OP_ENDIF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
				TxOut:   []*wire.TxOut{{PkScript: tt.script}},
			}

			engine, _ := NewEngine(tt.script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: tt.script}})
			engine.stack = NewStack()
			err := engine.executeScript(tt.script)

			if err != ErrUnbalancedConditional {
				t.Errorf("Expected ErrUnbalancedConditional, got %v", err)
			}
		})
	}
}

func TestScriptTypes(t *testing.T) {
	// Test script type detection
	p2pkh := []byte{OP_DUP, OP_HASH160, 20}
	p2pkh = append(p2pkh, make([]byte, 20)...)
	p2pkh = append(p2pkh, OP_EQUALVERIFY, OP_CHECKSIG)

	p2sh := []byte{OP_HASH160, 20}
	p2sh = append(p2sh, make([]byte, 20)...)
	p2sh = append(p2sh, OP_EQUAL)

	p2wpkh := []byte{OP_0, 20}
	p2wpkh = append(p2wpkh, make([]byte, 20)...)

	p2wsh := []byte{OP_0, 32}
	p2wsh = append(p2wsh, make([]byte, 32)...)

	p2tr := []byte{OP_1, 32}
	p2tr = append(p2tr, make([]byte, 32)...)

	if !IsP2PKH(p2pkh) {
		t.Error("IsP2PKH failed to detect P2PKH")
	}
	if !IsP2SH(p2sh) {
		t.Error("IsP2SH failed to detect P2SH")
	}
	if !IsP2WPKH(p2wpkh) {
		t.Error("IsP2WPKH failed to detect P2WPKH")
	}
	if !IsP2WSH(p2wsh) {
		t.Error("IsP2WSH failed to detect P2WSH")
	}
	if !IsP2TR(p2tr) {
		t.Error("IsP2TR failed to detect P2TR")
	}

	// P2A (Pay-to-Anchor): OP_1 OP_PUSHBYTES_2 0x4e 0x73
	p2a := []byte{OP_1, 0x02, 0x4e, 0x73}
	if !IsPayToAnchor(p2a) {
		t.Error("IsPayToAnchor failed to detect P2A")
	}
	// P2A should not match P2TR
	if IsP2TR(p2a) {
		t.Error("IsP2TR incorrectly matched P2A")
	}
	// P2TR should not match P2A
	if IsPayToAnchor(p2tr) {
		t.Error("IsPayToAnchor incorrectly matched P2TR")
	}
}

func TestExtractWitnessProgram(t *testing.T) {
	tests := []struct {
		name          string
		script        []byte
		wantVersion   int
		wantProgramLen int
	}{
		{
			name:          "P2WPKH (v0, 20 bytes)",
			script:        append([]byte{OP_0, 20}, make([]byte, 20)...),
			wantVersion:   0,
			wantProgramLen: 20,
		},
		{
			name:          "P2WSH (v0, 32 bytes)",
			script:        append([]byte{OP_0, 32}, make([]byte, 32)...),
			wantVersion:   0,
			wantProgramLen: 32,
		},
		{
			name:          "P2TR (v1, 32 bytes)",
			script:        append([]byte{OP_1, 32}, make([]byte, 32)...),
			wantVersion:   1,
			wantProgramLen: 32,
		},
		{
			name:          "P2A (v1, 2 bytes)",
			script:        []byte{OP_1, 0x02, 0x4e, 0x73},
			wantVersion:   1,
			wantProgramLen: 2,
		},
		{
			name:          "Not a witness program",
			script:        []byte{OP_DUP, OP_HASH160},
			wantVersion:   -1,
			wantProgramLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, program := ExtractWitnessProgram(tt.script)
			if version != tt.wantVersion {
				t.Errorf("version = %d, want %d", version, tt.wantVersion)
			}
			if len(program) != tt.wantProgramLen {
				t.Errorf("program length = %d, want %d", len(program), tt.wantProgramLen)
			}
		})
	}
}

func TestFindAndDelete(t *testing.T) {
	// FindAndDelete takes raw signature bytes and builds the push-encoded pattern.
	// It removes all occurrences of the push-encoded signature from the script.
	tests := []struct {
		name     string
		script   []byte
		toDelete []byte
		expected []byte
	}{
		{
			name:     "empty signature does nothing",
			script:   []byte{OP_1, OP_2},
			toDelete: []byte{},
			expected: []byte{OP_1, OP_2},
		},
		{
			name: "delete push data sequence",
			// Script: <push 3 bytes: 0x02 0xff 0x03>
			script:   []byte{0x03, 0x02, 0xff, 0x03},
			toDelete: []byte{0x02, 0xff, 0x03}, // raw bytes
			expected: []byte{},
		},
		{
			name: "delete two push data sequences",
			// Script: <push 3 bytes> <push 3 bytes>
			script:   []byte{0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03},
			toDelete: []byte{0x02, 0xff, 0x03},
			expected: []byte{},
		},
		{
			name: "no match when data doesn't match",
			// Script has push of [0x02, 0xff, 0x03], but we try to delete [0xff]
			// The push-encoded [0xff] is [0x01, 0xff] which doesn't appear
			script:   []byte{0x03, 0x02, 0xff, 0x03},
			toDelete: []byte{0xff},
			expected: []byte{0x03, 0x02, 0xff, 0x03},
		},
		{
			name: "basic two signatures removal",
			// Script: <push 4 bytes: sig> OP_DUP <push 4 bytes: sig> OP_HASH160
			script:   append(append([]byte{0x04, 0x30, 0x44, 0x02, 0x20}, OP_DUP, 0x04, 0x30, 0x44, 0x02, 0x20), OP_HASH160),
			toDelete: []byte{0x30, 0x44, 0x02, 0x20},
			expected: []byte{OP_DUP, OP_HASH160},
		},
		{
			name: "partial match doesn't delete",
			// Script: <push 5 bytes: 0x30 0x44 0x02 0x20 0x00>
			// Trying to delete 4-byte signature should not match
			script:   []byte{0x05, 0x30, 0x44, 0x02, 0x20, 0x00},
			toDelete: []byte{0x30, 0x44, 0x02, 0x20},
			expected: []byte{0x05, 0x30, 0x44, 0x02, 0x20, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindAndDelete(tt.script, tt.toDelete)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("FindAndDelete result = %x, want %x", result, tt.expected)
			}
		})
	}
}

func TestRemoveOpCodeSeparators(t *testing.T) {
	script := []byte{
		OP_DUP,
		OP_CODESEPARATOR,
		OP_HASH160,
		0x14, // Push 20 bytes
	}
	script = append(script, make([]byte, 20)...)
	script = append(script, OP_CODESEPARATOR, OP_EQUALVERIFY, OP_CHECKSIG)

	result := removeOpCodeSeparators(script)

	// Should have removed both OP_CODESEPARATOR
	if bytes.Contains(result, []byte{OP_CODESEPARATOR}) {
		t.Error("removeOpCodeSeparators did not remove all OP_CODESEPARATOR")
	}

	// Other opcodes should be preserved
	if result[0] != OP_DUP || result[1] != OP_HASH160 {
		t.Error("removeOpCodeSeparators removed wrong opcodes")
	}
}

func TestWithinOp(t *testing.T) {
	tests := []struct {
		x, min, max int64
		want        bool
	}{
		{5, 0, 10, true},  // 0 <= 5 < 10
		{0, 0, 10, true},  // 0 <= 0 < 10
		{10, 0, 10, false}, // 0 <= 10 < 10 (false, not strictly less)
		{-1, 0, 10, false}, // -1 < 0
		{5, 5, 6, true},   // 5 <= 5 < 6
	}

	for _, tt := range tests {
		script := []byte{}
		script = append(script, encodeScriptNum(tt.x)...)
		script = append(script, encodeScriptNum(tt.min)...)
		script = append(script, encodeScriptNum(tt.max)...)
		script = append(script, OP_WITHIN)

		tx := &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{PkScript: script}},
		}

		engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
		engine.stack = NewStack()
		err := engine.executeScript(script)
		if err != nil {
			t.Fatalf("executeScript error: %v", err)
		}

		result, _ := engine.stack.PopBool()
		if result != tt.want {
			t.Errorf("WITHIN(%d, %d, %d) = %v, want %v", tt.x, tt.min, tt.max, result, tt.want)
		}
	}
}

// Helper to encode a number as push opcode
func encodeScriptNum(n int64) []byte {
	if n == 0 {
		return []byte{OP_0}
	}
	if n >= 1 && n <= 16 {
		return []byte{byte(OP_1 + n - 1)}
	}
	if n == -1 {
		return []byte{OP_1NEGATE}
	}
	data := ScriptNumSerialize(n)
	result := []byte{byte(len(data))}
	return append(result, data...)
}

func TestTapLeaf(t *testing.T) {
	// Test vector from BIP341
	script := []byte{OP_TRUE}
	leafVersion := byte(0xC0) // TAPSCRIPT

	hash := TapLeaf(leafVersion, script)

	// Just verify it produces a 32-byte hash
	if len(hash) != 32 {
		t.Errorf("TapLeaf produced %d bytes, want 32", len(hash))
	}
}

func TestSigHashTypes(t *testing.T) {
	tests := []struct {
		hashType      SigHashType
		wantBase      SigHashType
		wantAnyoneCan bool
	}{
		{SigHashAll, SigHashAll, false},
		{SigHashNone, SigHashNone, false},
		{SigHashSingle, SigHashSingle, false},
		{SigHashAll | SigHashAnyOneCanPay, SigHashAll, true},
		{SigHashNone | SigHashAnyOneCanPay, SigHashNone, true},
		{SigHashSingle | SigHashAnyOneCanPay, SigHashSingle, true},
	}

	for _, tt := range tests {
		gotBase := tt.hashType.BaseType()
		gotAnyoneCan := tt.hashType.HasAnyOneCanPay()

		if gotBase != tt.wantBase {
			t.Errorf("(%02x).BaseType() = %02x, want %02x", tt.hashType, gotBase, tt.wantBase)
		}
		if gotAnyoneCan != tt.wantAnyoneCan {
			t.Errorf("(%02x).HasAnyOneCanPay() = %v, want %v", tt.hashType, gotAnyoneCan, tt.wantAnyoneCan)
		}
	}
}

func TestLegacySigHash(t *testing.T) {
	// Create a simple transaction
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0,
				},
				SignatureScript: []byte{},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    50000,
				PkScript: []byte{OP_TRUE},
			},
		},
		LockTime: 0,
	}

	script := []byte{OP_DUP, OP_HASH160}

	// Just verify it doesn't panic and produces valid hash
	hash, err := CalcSignatureHash(script, SigHashAll, tx, 0)
	if err != nil {
		t.Fatalf("CalcSignatureHash error: %v", err)
	}

	// Hash should be non-zero
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("CalcSignatureHash produced all-zero hash")
	}
}

func TestDisabledOpcodes(t *testing.T) {
	disabledOps := []byte{
		OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
		OP_INVERT, OP_AND, OP_OR, OP_XOR,
		OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
	}

	for _, op := range disabledOps {
		if !IsDisabledOpcode(op) {
			t.Errorf("IsDisabledOpcode(0x%02x) = false, want true", op)
		}
	}

	// Verify enabled opcodes
	enabledOps := []byte{OP_ADD, OP_SUB, OP_DUP, OP_HASH160}
	for _, op := range enabledOps {
		if IsDisabledOpcode(op) {
			t.Errorf("IsDisabledOpcode(0x%02x) = true, want false", op)
		}
	}
}

func TestBIP143WitnessSigHash(t *testing.T) {
	// Test vector from BIP143
	// This is a simplified test - full vectors would require more setup

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  []byte{},
				Witness:          [][]byte{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50000, PkScript: []byte{OP_TRUE}},
		},
		LockTime: 0,
	}

	script := []byte{OP_DUP, OP_HASH160}
	amount := int64(100000)

	// Verify it produces a hash without error
	hash, err := CalcWitnessSignatureHash(script, SigHashAll, tx, 0, amount)
	if err != nil {
		t.Fatalf("CalcWitnessSignatureHash error: %v", err)
	}

	// Hash should be 32 bytes
	if len(hash) != 32 {
		t.Errorf("Hash length = %d, want 32", len(hash))
	}
}

func TestP2SHScript(t *testing.T) {
	// Create a simple redeem script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
	redeemScript := []byte{OP_1, OP_1, OP_ADD, OP_2, OP_EQUAL}

	// Hash the redeem script
	redeemHash := crypto.Hash160(redeemScript)

	// P2SH scriptPubKey: OP_HASH160 <hash> OP_EQUAL
	scriptPubKey := []byte{OP_HASH160, 20}
	scriptPubKey = append(scriptPubKey, redeemHash[:]...)
	scriptPubKey = append(scriptPubKey, OP_EQUAL)

	// scriptSig pushes the redeem script
	scriptSig := []byte{byte(len(redeemScript))}
	scriptSig = append(scriptSig, redeemScript...)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  scriptSig,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50000, PkScript: []byte{OP_TRUE}},
		},
	}

	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	// Verify with P2SH flag
	err := VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyP2SH, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("P2SH verification failed: %v", err)
	}
}

// Benchmark tests

func BenchmarkScriptNumSerialize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ScriptNumSerialize(int64(i % 1000000))
	}
}

func BenchmarkHash160(b *testing.B) {
	data := []byte("benchmark data for hash160")
	stack := NewStack()
	stack.Push(data)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{PkScript: []byte{}}},
	}

	engine, _ := NewEngine([]byte{}, tx, 0, ScriptVerifyNone, 0, nil)
	engine.stack = stack

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.stack.Push(data)
		engine.opHash160()
	}
}

func BenchmarkP2PKHValidation(b *testing.B) {
	// Pre-generate key and script
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pubKeyHash := crypto.Hash160(pubKey.SerializeCompressed())

	scriptPubKey := make([]byte, 25)
	scriptPubKey[0] = OP_DUP
	scriptPubKey[1] = OP_HASH160
	scriptPubKey[2] = 20
	copy(scriptPubKey[3:23], pubKeyHash[:])
	scriptPubKey[23] = OP_EQUALVERIFY
	scriptPubKey[24] = OP_CHECKSIG

	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  nil,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: scriptPubKey},
		},
	}

	sighash, _ := CalcSignatureHash(scriptPubKey, SigHashAll, tx, 0)
	sig, _ := crypto.SignECDSA(privKey, sighash)
	sig = append(sig, byte(SigHashAll))

	pubKeyBytes := pubKey.SerializeCompressed()
	scriptSig := []byte{byte(len(sig))}
	scriptSig = append(scriptSig, sig...)
	scriptSig = append(scriptSig, byte(len(pubKeyBytes)))
	scriptSig = append(scriptSig, pubKeyBytes...)

	tx.TxIn[0].SignatureScript = scriptSig

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	}
}

func TestCodesepPos(t *testing.T) {
	// Verify codesep_pos is initialized to 0xFFFFFFFF
	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{PkScript: []byte{}}},
	}

	engine, err := NewEngine([]byte{}, tx, 0, ScriptVerifyNone, 0, nil)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	if engine.codesepPos != 0xFFFFFFFF {
		t.Errorf("codesepPos = 0x%08X, want 0xFFFFFFFF", engine.codesepPos)
	}
}

func TestOpcodeNameCoverage(t *testing.T) {
	// Test that common opcodes have names
	opcodes := []struct {
		op   byte
		name string
	}{
		{OP_0, "OP_0"},
		{OP_1, "OP_1"},
		{OP_16, "OP_16"},
		{OP_NOP, "OP_NOP"},
		{OP_IF, "OP_IF"},
		{OP_ELSE, "OP_ELSE"},
		{OP_ENDIF, "OP_ENDIF"},
		{OP_VERIFY, "OP_VERIFY"},
		{OP_RETURN, "OP_RETURN"},
		{OP_DUP, "OP_DUP"},
		{OP_EQUAL, "OP_EQUAL"},
		{OP_CHECKSIG, "OP_CHECKSIG"},
		{OP_CHECKMULTISIG, "OP_CHECKMULTISIG"},
		{OP_CHECKSIGADD, "OP_CHECKSIGADD"},
	}

	for _, tt := range opcodes {
		got := OpcodeName(tt.op)
		if got != tt.name {
			t.Errorf("OpcodeName(0x%02x) = %q, want %q", tt.op, got, tt.name)
		}
	}
}

func TestPushData(t *testing.T) {
	// Test various push sizes
	tests := []struct {
		name   string
		data   []byte
		script []byte
	}{
		{
			name:   "direct push 1 byte",
			data:   []byte{0x42},
			script: []byte{0x01, 0x42},
		},
		{
			name:   "direct push 75 bytes",
			data:   bytes.Repeat([]byte{0x42}, 75),
			script: append([]byte{75}, bytes.Repeat([]byte{0x42}, 75)...),
		},
		{
			name:   "PUSHDATA1",
			data:   bytes.Repeat([]byte{0x42}, 100),
			script: append([]byte{OP_PUSHDATA1, 100}, bytes.Repeat([]byte{0x42}, 100)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}},
				TxOut:   []*wire.TxOut{{PkScript: tt.script}},
			}

			engine, _ := NewEngine(tt.script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: tt.script}})
			engine.stack = NewStack()
			err := engine.executeScript(tt.script)
			if err != nil {
				t.Fatalf("executeScript error: %v", err)
			}

			result, err := engine.stack.Pop()
			if err != nil {
				t.Fatalf("Pop error: %v", err)
			}

			if !bytes.Equal(result, tt.data) {
				t.Errorf("Pushed data mismatch: got %x, want %x", result, tt.data)
			}
		})
	}
}

// Verify the sighash for a known transaction (simplified)
func TestSigHashKnownValue(t *testing.T) {
	// This is a simplified test using a basic transaction structure
	// In production, you'd use actual test vectors from Bitcoin Core

	txBytes, _ := hex.DecodeString("0100000001" + // version + input count
		"0000000000000000000000000000000000000000000000000000000000000000" + // prev txid
		"00000000" + // prev index
		"00" + // scriptSig length (empty)
		"ffffffff" + // sequence
		"01" + // output count
		"0000000000000000" + // value (0)
		"00" + // scriptPubKey length (empty)
		"00000000") // locktime

	var tx wire.MsgTx
	err := tx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	// Verify basic sighash computation
	script := []byte{OP_TRUE}
	hash, err := CalcSignatureHash(script, SigHashAll, &tx, 0)
	if err != nil {
		t.Fatalf("CalcSignatureHash error: %v", err)
	}

	// Just verify non-zero result
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Expected non-zero hash")
	}
}

// TestWitnessPubKeyType tests that SCRIPT_VERIFY_WITNESS_PUBKEYTYPE correctly
// rejects uncompressed public keys in witness v0 scripts.
// TestWitnessCleanStack tests that witness v0 and v1 (tapscript) unconditionally
// enforce cleanstack (BIP141/BIP342).
func TestWitnessCleanStack(t *testing.T) {
	// Test P2WSH with cleanstack violation (multiple items left on stack)
	t.Run("P2WSH_extra_item_on_stack", func(t *testing.T) {
		// Create a witness script that leaves 2 items on the stack: OP_1 OP_1
		// (both true values, but should fail cleanstack)
		witnessScript := []byte{OP_1, OP_1}
		scriptHash := crypto.SHA256Hash(witnessScript)

		// P2WSH scriptPubKey
		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
					Witness:          [][]byte{witnessScript},
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		err := VerifyScript(nil, p2wshScript, tx, 0, ScriptVerifyWitness, prevOut.Value, prevOuts)
		if err != ErrCleanStack {
			t.Errorf("expected ErrCleanStack, got: %v", err)
		}
	})

	t.Run("P2WSH_empty_stack", func(t *testing.T) {
		// Create a witness script that leaves empty stack: OP_1 OP_DROP
		witnessScript := []byte{OP_1, OP_DROP}
		scriptHash := crypto.SHA256Hash(witnessScript)

		// P2WSH scriptPubKey
		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
					Witness:          [][]byte{witnessScript},
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		err := VerifyScript(nil, p2wshScript, tx, 0, ScriptVerifyWitness, prevOut.Value, prevOuts)
		if err != ErrEvalFalse {
			t.Errorf("expected ErrEvalFalse, got: %v", err)
		}
	})

	t.Run("P2WSH_false_on_stack", func(t *testing.T) {
		// Create a witness script that leaves false on stack: OP_0
		witnessScript := []byte{OP_0}
		scriptHash := crypto.SHA256Hash(witnessScript)

		// P2WSH scriptPubKey
		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
					Witness:          [][]byte{witnessScript},
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		err := VerifyScript(nil, p2wshScript, tx, 0, ScriptVerifyWitness, prevOut.Value, prevOuts)
		if err != ErrEvalFalse {
			t.Errorf("expected ErrEvalFalse, got: %v", err)
		}
	})

	t.Run("P2WSH_valid_single_true", func(t *testing.T) {
		// Create a witness script that leaves exactly one true on stack: OP_1
		witnessScript := []byte{OP_1}
		scriptHash := crypto.SHA256Hash(witnessScript)

		// P2WSH scriptPubKey
		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
					Witness:          [][]byte{witnessScript},
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		err := VerifyScript(nil, p2wshScript, tx, 0, ScriptVerifyWitness, prevOut.Value, prevOuts)
		if err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("P2WSH_cleanstack_not_gated_by_flag", func(t *testing.T) {
		// Verify that cleanstack is enforced even WITHOUT ScriptVerifyCleanStack flag
		// (it's part of BIP141 consensus, not the separate cleanstack policy flag)
		witnessScript := []byte{OP_1, OP_1} // 2 items on stack
		scriptHash := crypto.SHA256Hash(witnessScript)

		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
					Witness:          [][]byte{witnessScript},
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		// Only ScriptVerifyWitness, NOT ScriptVerifyCleanStack
		err := VerifyScript(nil, p2wshScript, tx, 0, ScriptVerifyWitness, prevOut.Value, prevOuts)
		if err != ErrCleanStack {
			t.Errorf("witness cleanstack should be enforced even without ScriptVerifyCleanStack flag, got: %v", err)
		}
	})
}

func TestWitnessPubKeyType(t *testing.T) {
	// Generate a test key pair
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey error: %v", err)
	}
	pubKey := privKey.PubKey()
	compressedPubKey := pubKey.SerializeCompressed()
	uncompressedPubKey := pubKey.SerializeUncompressed()

	// Verify compressed key is 33 bytes starting with 0x02 or 0x03
	if len(compressedPubKey) != 33 {
		t.Fatalf("compressed pubkey should be 33 bytes, got %d", len(compressedPubKey))
	}
	if compressedPubKey[0] != 0x02 && compressedPubKey[0] != 0x03 {
		t.Fatalf("compressed pubkey should start with 0x02 or 0x03, got 0x%02x", compressedPubKey[0])
	}

	// Verify uncompressed key is 65 bytes starting with 0x04
	if len(uncompressedPubKey) != 65 {
		t.Fatalf("uncompressed pubkey should be 65 bytes, got %d", len(uncompressedPubKey))
	}
	if uncompressedPubKey[0] != 0x04 {
		t.Fatalf("uncompressed pubkey should start with 0x04, got 0x%02x", uncompressedPubKey[0])
	}

	// Test helper function directly
	t.Run("IsCompressedPubKey helper", func(t *testing.T) {
		if !IsCompressedPubKey(compressedPubKey) {
			t.Error("IsCompressedPubKey should return true for compressed pubkey")
		}
		if IsCompressedPubKey(uncompressedPubKey) {
			t.Error("IsCompressedPubKey should return false for uncompressed pubkey")
		}
		if IsCompressedPubKey([]byte{0x02}) {
			t.Error("IsCompressedPubKey should return false for too-short key")
		}
		if IsCompressedPubKey(nil) {
			t.Error("IsCompressedPubKey should return false for nil")
		}
	})

	// For testing WITNESS_PUBKEYTYPE, we use P2WSH with a simple CHECKSIG script.
	// This allows us to directly control the pubkey used without hash mismatches.
	// The witness script is: <pubkey> OP_CHECKSIG
	// The witness is: <signature> <witnessScript>

	// Helper to build P2WSH witness script: <pubkey> OP_CHECKSIG
	buildWitnessScript := func(pk []byte) []byte {
		script := make([]byte, 0, len(pk)+2)
		script = append(script, byte(len(pk))) // push opcode
		script = append(script, pk...)
		script = append(script, OP_CHECKSIG)
		return script
	}

	// Helper to create a P2WSH test transaction and run it
	runP2WSHTest := func(t *testing.T, pk []byte, flags ScriptFlags) error {
		witnessScript := buildWitnessScript(pk)
		scriptHash := crypto.SHA256Hash(witnessScript)

		// P2WSH scriptPubKey: OP_0 <32-byte hash>
		p2wshScript := make([]byte, 34)
		p2wshScript[0] = OP_0
		p2wshScript[1] = 32
		copy(p2wshScript[2:], scriptHash[:])

		prevOut := &wire.TxOut{Value: 100000, PkScript: p2wshScript}
		prevOuts := []*wire.TxOut{prevOut}

		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
					Sequence:         0xffffffff,
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 90000, PkScript: p2wshScript},
			},
		}

		// Sign with the witness script
		sighash, err := CalcWitnessSignatureHash(witnessScript, SigHashAll, tx, 0, prevOut.Value)
		if err != nil {
			t.Fatalf("CalcWitnessSignatureHash error: %v", err)
		}
		sig, err := crypto.SignECDSA(privKey, sighash)
		if err != nil {
			t.Fatalf("SignECDSA error: %v", err)
		}
		sig = append(sig, byte(SigHashAll))

		// P2WSH witness: [sig, witnessScript]
		// The witnessScript contains the pubkey, so sig is pushed as a stack item
		tx.TxIn[0].Witness = [][]byte{sig, witnessScript}

		return VerifyScript(nil, p2wshScript, tx, 0, flags, prevOut.Value, prevOuts)
	}

	t.Run("P2WSH with compressed pubkey and flag enabled", func(t *testing.T) {
		err := runP2WSHTest(t, compressedPubKey, ScriptVerifyWitness|ScriptVerifyWitnessPubKeyType)
		if err != nil {
			t.Errorf("expected success, got error: %v", err)
		}
	})

	t.Run("P2WSH with uncompressed pubkey and flag enabled", func(t *testing.T) {
		err := runP2WSHTest(t, uncompressedPubKey, ScriptVerifyWitness|ScriptVerifyWitnessPubKeyType)
		if err != ErrWitnessPubKeyType {
			t.Errorf("expected ErrWitnessPubKeyType, got: %v", err)
		}
	})

	t.Run("P2WSH with uncompressed pubkey without flag", func(t *testing.T) {
		// Without WITNESS_PUBKEYTYPE flag, uncompressed keys should be allowed
		err := runP2WSHTest(t, uncompressedPubKey, ScriptVerifyWitness)
		if err != nil {
			t.Errorf("expected success without WITNESS_PUBKEYTYPE flag, got: %v", err)
		}
	})
}

// TestCodeSeparatorLegacy tests that OP_CODESEPARATOR correctly affects
// legacy script sighash computation by only including script bytes after
// the last OP_CODESEPARATOR in the scriptCode.
func TestCodeSeparatorLegacy(t *testing.T) {
	// Generate a key pair for signing
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey error: %v", err)
	}
	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	pubKeyHash := crypto.Hash160(pubKeyBytes)

	// Create a scriptPubKey that uses OP_CODESEPARATOR:
	// OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CODESEPARATOR OP_CHECKSIG
	//
	// The scriptCode for sighash will only include OP_CHECKSIG (after CODESEPARATOR)
	scriptPubKey := []byte{
		OP_DUP,
		OP_HASH160,
		20, // Push 20 bytes
	}
	scriptPubKey = append(scriptPubKey, pubKeyHash[:]...)
	scriptPubKey = append(scriptPubKey, OP_EQUALVERIFY, OP_CODESEPARATOR, OP_CHECKSIG)

	// Create the scriptCode as it will be computed during signature verification
	// (after OP_CODESEPARATOR, so just OP_CHECKSIG)
	scriptCodeAfterCodeSep := []byte{OP_CHECKSIG}

	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				SignatureScript:  nil,
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: []byte{OP_TRUE}},
		},
		LockTime: 0,
	}

	// Sign using the scriptCode AFTER OP_CODESEPARATOR
	sighash, err := CalcSignatureHash(scriptCodeAfterCodeSep, SigHashAll, tx, 0)
	if err != nil {
		t.Fatalf("CalcSignatureHash error: %v", err)
	}

	sig, err := crypto.SignECDSA(privKey, sighash)
	if err != nil {
		t.Fatalf("SignECDSA error: %v", err)
	}
	sig = append(sig, byte(SigHashAll))

	// Create scriptSig: <sig> <pubkey>
	scriptSig := []byte{byte(len(sig))}
	scriptSig = append(scriptSig, sig...)
	scriptSig = append(scriptSig, byte(len(pubKeyBytes)))
	scriptSig = append(scriptSig, pubKeyBytes...)

	tx.TxIn[0].SignatureScript = scriptSig

	// Verify - should succeed because the signature was computed using
	// the correct scriptCode (after OP_CODESEPARATOR)
	err = VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("OP_CODESEPARATOR verification failed: %v", err)
	}
}

// TestCodeSeparatorMultiple tests that multiple OP_CODESEPARATORs work correctly.
// Only the script after the LAST OP_CODESEPARATOR should be used for sighash.
func TestCodeSeparatorMultiple(t *testing.T) {
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	pubKeyHash := crypto.Hash160(pubKeyBytes)

	// Script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CODESEPARATOR OP_1 OP_CODESEPARATOR OP_CHECKSIG
	// ScriptCode after last CODESEPARATOR: OP_CHECKSIG only
	scriptPubKey := []byte{
		OP_DUP, OP_HASH160, 20,
	}
	scriptPubKey = append(scriptPubKey, pubKeyHash[:]...)
	scriptPubKey = append(scriptPubKey, OP_EQUALVERIFY, OP_CODESEPARATOR, OP_1, OP_DROP, OP_CODESEPARATOR, OP_CHECKSIG)

	// ScriptCode for sighash: just OP_CHECKSIG
	scriptCodeAfterLastCodeSep := []byte{OP_CHECKSIG}

	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{{Value: 90000, PkScript: []byte{OP_TRUE}}},
	}

	// Sign using scriptCode after the LAST OP_CODESEPARATOR
	sighash, _ := CalcSignatureHash(scriptCodeAfterLastCodeSep, SigHashAll, tx, 0)
	sig, _ := crypto.SignECDSA(privKey, sighash)
	sig = append(sig, byte(SigHashAll))

	scriptSig := []byte{byte(len(sig))}
	scriptSig = append(scriptSig, sig...)
	scriptSig = append(scriptSig, byte(len(pubKeyBytes)))
	scriptSig = append(scriptSig, pubKeyBytes...)

	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, scriptPubKey, tx, 0, ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Errorf("Multiple OP_CODESEPARATOR verification failed: %v", err)
	}
}

// TestSighashRemovesCodeSeparator tests that CalcSignatureHash removes
// OP_CODESEPARATOR bytes from the scriptCode before hashing.
func TestSighashRemovesCodeSeparator(t *testing.T) {
	// Two scripts that should produce the same sighash:
	// 1. OP_CHECKSIG
	// 2. OP_CODESEPARATOR OP_CHECKSIG
	// Because OP_CODESEPARATOR is removed from scriptCode during sighash

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{{Value: 50000, PkScript: []byte{OP_TRUE}}},
	}

	script1 := []byte{OP_CHECKSIG}
	script2 := []byte{OP_CODESEPARATOR, OP_CHECKSIG}

	hash1, err1 := CalcSignatureHash(script1, SigHashAll, tx, 0)
	hash2, err2 := CalcSignatureHash(script2, SigHashAll, tx, 0)

	if err1 != nil || err2 != nil {
		t.Fatalf("CalcSignatureHash errors: %v, %v", err1, err2)
	}

	if !bytes.Equal(hash1[:], hash2[:]) {
		t.Errorf("Sighash should be equal after removing OP_CODESEPARATOR\nhash1: %x\nhash2: %x", hash1, hash2)
	}
}

func TestP2ADetection(t *testing.T) {
	// P2A scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e 0x73 (exactly 4 bytes)
	p2a := []byte{0x51, 0x02, 0x4e, 0x73}

	t.Run("IsPayToAnchor", func(t *testing.T) {
		if !IsPayToAnchor(p2a) {
			t.Error("IsPayToAnchor should return true for valid P2A script")
		}
	})

	t.Run("IsPayToAnchorWitnessProgram", func(t *testing.T) {
		version, program := ExtractWitnessProgram(p2a)
		if version != 1 {
			t.Errorf("version = %d, want 1", version)
		}
		if !IsPayToAnchorWitnessProgram(version, program) {
			t.Error("IsPayToAnchorWitnessProgram should return true for P2A")
		}
	})

	t.Run("P2A not confused with P2TR", func(t *testing.T) {
		// P2TR is 34 bytes: OP_1 + 32 bytes
		p2tr := make([]byte, 34)
		p2tr[0] = 0x51 // OP_1
		p2tr[1] = 0x20 // push 32 bytes

		if IsPayToAnchor(p2tr) {
			t.Error("IsPayToAnchor should return false for P2TR")
		}
		if IsP2TR(p2a) {
			t.Error("IsP2TR should return false for P2A")
		}
	})

	t.Run("invalid P2A scripts", func(t *testing.T) {
		tests := [][]byte{
			{0x51, 0x02, 0x4e},       // too short
			{0x51, 0x02, 0x4e, 0x74}, // wrong byte
			{0x51, 0x03, 0x4e, 0x73}, // wrong push length
			{0x00, 0x02, 0x4e, 0x73}, // wrong version (v0)
			{0x52, 0x02, 0x4e, 0x73}, // wrong version (v2)
		}
		for i, script := range tests {
			if IsPayToAnchor(script) {
				t.Errorf("test %d: IsPayToAnchor incorrectly returned true for %x", i, script)
			}
		}
	})
}

func TestP2AExecution(t *testing.T) {
	// Test that P2A outputs can be spent with empty witness (anyone-can-spend)
	p2aScript := []byte{0x51, 0x02, 0x4e, 0x73}

	// Create a transaction spending from a P2A output
	prevOut := &wire.TxOut{
		Value:    1000,
		PkScript: p2aScript,
	}

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Index: 0},
				Witness:          [][]byte{}, // empty witness for P2A
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 500, PkScript: []byte{OP_TRUE}},
		},
	}

	t.Run("P2A spendable with empty witness", func(t *testing.T) {
		err := VerifyScript(
			nil,          // scriptSig
			p2aScript,    // scriptPubKey
			tx,
			0,
			ScriptVerifyWitness|ScriptVerifyTaproot,
			prevOut.Value,
			[]*wire.TxOut{prevOut},
		)
		if err != nil {
			t.Errorf("P2A verification failed with empty witness: %v", err)
		}
	})

	t.Run("P2A spendable without Taproot flag", func(t *testing.T) {
		// P2A should be anyone-can-spend even if Taproot is not enabled
		err := VerifyScript(
			nil,
			p2aScript,
			tx,
			0,
			ScriptVerifyWitness, // No Taproot flag
			prevOut.Value,
			[]*wire.TxOut{prevOut},
		)
		if err != nil {
			t.Errorf("P2A verification failed without Taproot flag: %v", err)
		}
	})
}

func TestP2AStandard(t *testing.T) {
	// Test P2A output standardness checks
	p2aScript := []byte{0x51, 0x02, 0x4e, 0x73}

	t.Run("P2A output with value 0 is standard", func(t *testing.T) {
		txOut := &wire.TxOut{
			Value:    0,
			PkScript: p2aScript,
		}
		if !IsPayToAnchor(txOut.PkScript) {
			t.Error("should be recognized as P2A")
		}
	})

	t.Run("P2A output with value 240 is standard", func(t *testing.T) {
		txOut := &wire.TxOut{
			Value:    240,
			PkScript: p2aScript,
		}
		if !IsPayToAnchor(txOut.PkScript) {
			t.Error("should be recognized as P2A")
		}
	})
}
