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
		back, err := ScriptNumDeserialize(got, 4)
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
	n, err := s.PopInt(4)
	if err != nil {
		t.Fatalf("PopInt() error: %v", err)
	}
	if n != 42 {
		t.Errorf("PopInt() = %d, want 42", n)
	}

	s.PushInt(-100)
	n, err = s.PopInt(4)
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

			got, err := engine.stack.PopInt(4)
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
	sig := []byte{0x30, 0x44, 0x02, 0x20} // Partial DER sig
	script := []byte{byte(len(sig))}
	script = append(script, sig...)
	script = append(script, OP_DUP, byte(len(sig)))
	script = append(script, sig...)
	script = append(script, OP_HASH160)

	result := FindAndDelete(script, sig)

	// Should have removed both occurrences of the push-encoded signature
	expected := []byte{OP_DUP, OP_HASH160}
	if !bytes.Equal(result, expected) {
		t.Errorf("FindAndDelete result = %x, want %x", result, expected)
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
