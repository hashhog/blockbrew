package script

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test key for use in tests (33 bytes compressed)
var testKey = mustDecodeHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

// Additional test keys
var testKey2 = mustDecodeHex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
var testKey3 = mustDecodeHex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")

// Test hash (32 bytes)
var testHash32 = mustDecodeHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

// Test hash (20 bytes)
var testHash20 = mustDecodeHex("0102030405060708090a0b0c0d0e0f1011121314")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestMiniscriptTypeSystem(t *testing.T) {
	tests := []struct {
		name     string
		fragment Fragment
		k        uint32
		keys     [][]byte
		data     []byte
		subs     []*MiniscriptNode
		ctx      MiniscriptContext
		wantB    bool
		wantV    bool
		wantK    bool
		wantW    bool
	}{
		{
			name:     "pk_k",
			fragment: FragPkK,
			keys:     [][]byte{testKey},
			ctx:      P2WSH,
			wantK:    true,
		},
		{
			name:     "pk_h",
			fragment: FragPkH,
			keys:     [][]byte{testKey},
			ctx:      P2WSH,
			wantK:    true,
		},
		{
			name:     "older",
			fragment: FragOlder,
			k:        100,
			ctx:      P2WSH,
			wantB:    true,
		},
		{
			name:     "after",
			fragment: FragAfter,
			k:        500000,
			ctx:      P2WSH,
			wantB:    true,
		},
		{
			name:     "sha256",
			fragment: FragSHA256,
			data:     testHash32,
			ctx:      P2WSH,
			wantB:    true,
		},
		{
			name:     "just_0",
			fragment: FragJust0,
			ctx:      P2WSH,
			wantB:    true,
		},
		{
			name:     "just_1",
			fragment: FragJust1,
			ctx:      P2WSH,
			wantB:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &MiniscriptNode{
				Fragment: tt.fragment,
				K:        tt.k,
				Keys:     tt.keys,
				Data:     tt.data,
				Subs:     tt.subs,
				Ctx:      tt.ctx,
			}

			typ := node.GetType()

			if tt.wantB && !typ.HasType(TypeB) {
				t.Errorf("expected type B")
			}
			if tt.wantV && !typ.HasType(TypeV) {
				t.Errorf("expected type V")
			}
			if tt.wantK && !typ.HasType(TypeK) {
				t.Errorf("expected type K")
			}
			if tt.wantW && !typ.HasType(TypeW) {
				t.Errorf("expected type W")
			}
		})
	}
}

func TestMiniscriptWrappers(t *testing.T) {
	// pk_k(KEY) has type K
	pkK := &MiniscriptNode{
		Fragment: FragPkK,
		Keys:     [][]byte{testKey},
		Ctx:      P2WSH,
	}

	// c:pk_k(KEY) has type B (wrapper C converts K to B)
	cPkK := &MiniscriptNode{
		Fragment: FragWrapC,
		Subs:     []*MiniscriptNode{pkK},
		Ctx:      P2WSH,
	}

	typ := cPkK.GetType()
	if !typ.HasType(TypeB) {
		t.Errorf("c:pk_k should have type B, got %v", typ)
	}

	// v:c:pk_k(KEY) has type V
	vcPkK := &MiniscriptNode{
		Fragment: FragWrapV,
		Subs:     []*MiniscriptNode{cPkK},
		Ctx:      P2WSH,
	}

	typV := vcPkK.GetType()
	if !typV.HasType(TypeV) {
		t.Errorf("v:c:pk_k should have type V, got %v", typV)
	}
}

func TestParseMiniscript(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "pk",
			input:   "pk(" + hex.EncodeToString(testKey) + ")",
			wantErr: false,
		},
		{
			name:    "pkh",
			input:   "pkh(" + hex.EncodeToString(testKey) + ")",
			wantErr: false,
		},
		{
			name:    "pk_k",
			input:   "pk_k(" + hex.EncodeToString(testKey) + ")",
			wantErr: false,
		},
		{
			name:    "older",
			input:   "older(100)",
			wantErr: false,
		},
		{
			name:    "after",
			input:   "after(500000)",
			wantErr: false,
		},
		{
			name:    "sha256",
			input:   "sha256(" + hex.EncodeToString(testHash32) + ")",
			wantErr: false,
		},
		{
			name:    "hash160",
			input:   "hash160(" + hex.EncodeToString(testHash20) + ")",
			wantErr: false,
		},
		{
			name:    "and_v",
			input:   "and_v(v:pk(" + hex.EncodeToString(testKey) + "),pk(" + hex.EncodeToString(testKey2) + "))",
			wantErr: false,
		},
		{
			name:    "or_i",
			input:   "or_i(pk(" + hex.EncodeToString(testKey) + "),pk(" + hex.EncodeToString(testKey2) + "))",
			wantErr: false,
		},
		{
			name:    "wrappers_asc",
			input:   "a:s:c:pk_k(" + hex.EncodeToString(testKey) + ")",
			wantErr: false,
		},
		{
			name:    "thresh",
			input:   "thresh(2,pk(" + hex.EncodeToString(testKey) + "),s:pk(" + hex.EncodeToString(testKey2) + "),s:pk(" + hex.EncodeToString(testKey3) + "))",
			wantErr: false,
		},
		{
			name:    "invalid_empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid_unknown",
			input:   "unknown()",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseMiniscript(tt.input, P2WSH)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMiniscript() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && node == nil {
				t.Error("ParseMiniscript() returned nil node without error")
			}
		})
	}
}

func TestMiniscriptToScript(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		ctx    MiniscriptContext
		verify func([]byte) bool
	}{
		{
			name:  "pk compiles to pubkey checksig",
			input: "pk(" + hex.EncodeToString(testKey) + ")",
			ctx:   P2WSH,
			verify: func(script []byte) bool {
				// Should end with OP_CHECKSIG (0xac)
				return len(script) > 0 && script[len(script)-1] == OP_CHECKSIG
			},
		},
		{
			name:  "older compiles to CSV",
			input: "older(100)",
			ctx:   P2WSH,
			verify: func(script []byte) bool {
				// Should contain OP_CHECKSEQUENCEVERIFY (0xb2)
				for _, b := range script {
					if b == OP_CHECKSEQUENCEVERIFY {
						return true
					}
				}
				return false
			},
		},
		{
			name:  "after compiles to CLTV",
			input: "after(500000)",
			ctx:   P2WSH,
			verify: func(script []byte) bool {
				// Should contain OP_CHECKLOCKTIMEVERIFY (0xb1)
				for _, b := range script {
					if b == OP_CHECKLOCKTIMEVERIFY {
						return true
					}
				}
				return false
			},
		},
		{
			name:  "sha256 compiles correctly",
			input: "sha256(" + hex.EncodeToString(testHash32) + ")",
			ctx:   P2WSH,
			verify: func(script []byte) bool {
				// Should contain OP_SHA256 (0xa8) and OP_EQUAL (0x87)
				hasOpSHA256 := false
				hasOpEqual := false
				for _, b := range script {
					if b == OP_SHA256 {
						hasOpSHA256 = true
					}
					if b == OP_EQUAL || b == OP_EQUALVERIFY {
						hasOpEqual = true
					}
				}
				return hasOpSHA256 && hasOpEqual
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseMiniscript(tt.input, tt.ctx)
			if err != nil {
				t.Fatalf("ParseMiniscript() error = %v", err)
			}

			script, err := node.ToScript()
			if err != nil {
				t.Fatalf("ToScript() error = %v", err)
			}

			if !tt.verify(script) {
				t.Errorf("ToScript() verification failed, script = %x", script)
			}
		})
	}
}

func TestMiniscriptString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "pk",
			input: "pk(" + hex.EncodeToString(testKey) + ")",
		},
		{
			name:  "pkh",
			input: "pkh(" + hex.EncodeToString(testKey) + ")",
		},
		{
			name:  "older",
			input: "older(100)",
		},
		{
			name:  "after",
			input: "after(500000)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseMiniscript(tt.input, P2WSH)
			if err != nil {
				t.Fatalf("ParseMiniscript() error = %v", err)
			}

			output := node.String()
			if output != tt.input {
				t.Errorf("String() = %v, want %v", output, tt.input)
			}
		})
	}
}

func TestMiniscriptSatisfaction(t *testing.T) {
	// Create a simple pk() miniscript
	input := "pk(" + hex.EncodeToString(testKey) + ")"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	// Create a mock signature
	mockSig := bytes.Repeat([]byte{0x30}, 72)

	// Create satisfaction context
	ctx := &SatisfactionContext{
		Sign: func(pubkey []byte) ([]byte, Availability) {
			if bytes.Equal(pubkey, testKey) {
				return mockSig, AvailYes
			}
			return nil, AvailNo
		},
	}

	// Try to satisfy
	witness, err := node.Satisfy(ctx)
	if err != nil {
		t.Fatalf("Satisfy() error = %v", err)
	}

	if len(witness) != 1 {
		t.Errorf("Expected 1 witness element, got %d", len(witness))
	}

	if !bytes.Equal(witness[0], mockSig) {
		t.Errorf("Witness signature mismatch")
	}
}

func TestMiniscriptSatisfactionSHA256(t *testing.T) {
	// Create sha256() miniscript
	input := "sha256(" + hex.EncodeToString(testHash32) + ")"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	// Create mock preimage
	mockPreimage := bytes.Repeat([]byte{0x42}, 32)

	// Create satisfaction context
	ctx := &SatisfactionContext{
		SatSHA256: func(hash []byte) ([]byte, Availability) {
			if bytes.Equal(hash, testHash32) {
				return mockPreimage, AvailYes
			}
			return nil, AvailNo
		},
	}

	// Try to satisfy
	witness, err := node.Satisfy(ctx)
	if err != nil {
		t.Fatalf("Satisfy() error = %v", err)
	}

	if len(witness) != 1 {
		t.Errorf("Expected 1 witness element, got %d", len(witness))
	}

	if !bytes.Equal(witness[0], mockPreimage) {
		t.Errorf("Witness preimage mismatch")
	}
}

func TestMiniscriptSatisfactionTimelock(t *testing.T) {
	// Create older() miniscript
	input := "older(100)"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	// Create satisfaction context with timelock satisfied
	ctx := &SatisfactionContext{
		CheckOlder: func(n uint32) bool {
			return n <= 100
		},
	}

	// Try to satisfy
	witness, err := node.Satisfy(ctx)
	if err != nil {
		t.Fatalf("Satisfy() error = %v", err)
	}

	// older() doesn't add witness elements - the satisfaction is via script
	if len(witness) != 0 {
		t.Errorf("Expected 0 witness elements, got %d", len(witness))
	}
}

func TestMiniscriptNoSatisfaction(t *testing.T) {
	// Create pk() miniscript
	input := "pk(" + hex.EncodeToString(testKey) + ")"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	// Create satisfaction context with no signature available
	ctx := &SatisfactionContext{
		Sign: func(pubkey []byte) ([]byte, Availability) {
			return nil, AvailNo
		},
	}

	// Try to satisfy - should fail
	_, err = node.Satisfy(ctx)
	if err == nil {
		t.Error("Expected error when no satisfaction available")
	}
}

func TestMiniscriptAnalysis(t *testing.T) {
	// Create a complex miniscript
	input := "or_i(pk(" + hex.EncodeToString(testKey) + "),older(100))"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	analysis := node.Analyze()

	if analysis.ScriptSize <= 0 {
		t.Error("ScriptSize should be positive")
	}

	// Should have relative height timelock
	if !analysis.RelativeHeight {
		t.Error("Expected relative height timelock")
	}

	// The RequiresSig (TypeS) property is false because the script can be
	// satisfied via the older branch without a signature.
	// TypeS means "safe" = requires signature on ALL satisfaction paths.
	if analysis.RequiresSig {
		t.Error("RequiresSig should be false (older branch doesn't need signature)")
	}
}

func TestMiniscriptMaxWitnessSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		ctx     MiniscriptContext
		minSize uint32
	}{
		{
			name:    "pk",
			input:   "pk(" + hex.EncodeToString(testKey) + ")",
			ctx:     P2WSH,
			minSize: 72, // at least one signature
		},
		{
			name:    "sha256",
			input:   "sha256(" + hex.EncodeToString(testHash32) + ")",
			ctx:     P2WSH,
			minSize: 32, // preimage
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseMiniscript(tt.input, tt.ctx)
			if err != nil {
				t.Fatalf("ParseMiniscript() error = %v", err)
			}

			size, valid := node.MaxWitnessSize()
			if !valid {
				t.Error("MaxWitnessSize() returned invalid")
			}
			if size < tt.minSize {
				t.Errorf("MaxWitnessSize() = %d, want >= %d", size, tt.minSize)
			}
		})
	}
}

func TestMiniscriptGetRequiredKeys(t *testing.T) {
	// Create a miniscript with multiple keys
	input := "or_i(pk(" + hex.EncodeToString(testKey) + "),pk(" + hex.EncodeToString(testKey2) + "))"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	keys := node.GetRequiredKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 required keys, got %d", len(keys))
	}
}

func TestMiniscriptGetTimelocks(t *testing.T) {
	// Create a miniscript with both timelocks
	input := "and_v(v:older(100),after(500000))"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	timelocks := node.GetTimelocks()
	if len(timelocks) != 2 {
		t.Errorf("Expected 2 timelocks, got %d", len(timelocks))
	}

	hasOlder := false
	hasAfter := false
	for _, tl := range timelocks {
		if !tl.IsAbsolute && tl.Value == 100 {
			hasOlder = true
		}
		if tl.IsAbsolute && tl.Value == 500000 {
			hasAfter = true
		}
	}

	if !hasOlder {
		t.Error("Missing older timelock")
	}
	if !hasAfter {
		t.Error("Missing after timelock")
	}
}

func TestMiniscriptMulti(t *testing.T) {
	// multi(2,KEY1,KEY2,KEY3)
	input := "multi(2," + hex.EncodeToString(testKey) + "," + hex.EncodeToString(testKey2) + "," + hex.EncodeToString(testKey3) + ")"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	script, err := node.ToScript()
	if err != nil {
		t.Fatalf("ToScript() error = %v", err)
	}

	// Should contain OP_CHECKMULTISIG (0xae)
	if script[len(script)-1] != OP_CHECKMULTISIG {
		t.Error("Script should end with OP_CHECKMULTISIG")
	}
}

func TestMiniscriptMultiA(t *testing.T) {
	// multi_a(2,KEY1,KEY2,KEY3) - only in tapscript
	input := "multi_a(2," + hex.EncodeToString(testKey) + "," + hex.EncodeToString(testKey2) + "," + hex.EncodeToString(testKey3) + ")"
	node, err := ParseMiniscript(input, Tapscript)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	script, err := node.ToScript()
	if err != nil {
		t.Fatalf("ToScript() error = %v", err)
	}

	// Should contain OP_CHECKSIG (0xac) and OP_CHECKSIGADD (0xba)
	hasChecksig := false
	hasChecksigadd := false
	for _, b := range script {
		if b == OP_CHECKSIG {
			hasChecksig = true
		}
		if b == OP_CHECKSIGADD {
			hasChecksigadd = true
		}
	}

	if !hasChecksig {
		t.Error("Script should contain OP_CHECKSIG")
	}
	if !hasChecksigadd {
		t.Error("Script should contain OP_CHECKSIGADD")
	}
}

func TestMiniscriptThresh(t *testing.T) {
	// thresh(2,pk(KEY1),s:pk(KEY2),s:pk(KEY3))
	input := "thresh(2,pk(" + hex.EncodeToString(testKey) + "),s:pk(" + hex.EncodeToString(testKey2) + "),s:pk(" + hex.EncodeToString(testKey3) + "))"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	script, err := node.ToScript()
	if err != nil {
		t.Fatalf("ToScript() error = %v", err)
	}

	// Should contain OP_ADD (0x93) and OP_EQUAL (0x87)
	hasAdd := false
	hasEqual := false
	for _, b := range script {
		if b == OP_ADD {
			hasAdd = true
		}
		if b == OP_EQUAL {
			hasEqual = true
		}
	}

	if !hasAdd {
		t.Error("Script should contain OP_ADD")
	}
	if !hasEqual {
		t.Error("Script should contain OP_EQUAL")
	}
}

func TestCompilePolicy(t *testing.T) {
	// Test policy compilation
	policy := "pk(" + hex.EncodeToString(testKey) + ")"
	node, err := CompilePolicy(policy, P2WSH)
	if err != nil {
		t.Fatalf("CompilePolicy() error = %v", err)
	}

	if node == nil {
		t.Fatal("CompilePolicy() returned nil")
	}

	// Verify the compiled miniscript is valid
	if !node.IsValid() {
		t.Error("Compiled miniscript is not valid")
	}
}

func TestMiniscriptSugar(t *testing.T) {
	// Test syntactic sugar expansions
	tests := []struct {
		name   string
		input  string
		expand string
	}{
		{
			name:   "l: expands to or_i(0,X)",
			input:  "l:pk(" + hex.EncodeToString(testKey) + ")",
			expand: "or_i",
		},
		{
			name:   "u: expands to or_i(X,0)",
			input:  "u:pk(" + hex.EncodeToString(testKey) + ")",
			expand: "or_i",
		},
		{
			name:   "t: expands to and_v(X,1)",
			input:  "t:v:pk(" + hex.EncodeToString(testKey) + ")",  // t: requires V type, so wrap with v:
			expand: "and_v",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseMiniscript(tt.input, P2WSH)
			if err != nil {
				t.Fatalf("ParseMiniscript() error = %v", err)
			}

			// Check the fragment type matches expected expansion
			switch tt.expand {
			case "or_i":
				if node.Fragment != FragOrI {
					t.Errorf("Expected FragOrI, got %v", node.Fragment)
				}
			case "and_v":
				if node.Fragment != FragAndV {
					t.Errorf("Expected FragAndV, got %v", node.Fragment)
				}
			}
		})
	}
}

func TestMiniscriptIsSane(t *testing.T) {
	// A simple pk() is sane
	input := "pk(" + hex.EncodeToString(testKey) + ")"
	node, err := ParseMiniscript(input, P2WSH)
	if err != nil {
		t.Fatalf("ParseMiniscript() error = %v", err)
	}

	if !node.IsSane() {
		t.Error("pk() should be sane")
	}
}

func TestValidateMiniscript(t *testing.T) {
	// Valid miniscript
	err := ValidateMiniscript("pk("+hex.EncodeToString(testKey)+")", P2WSH)
	if err != nil {
		t.Errorf("ValidateMiniscript() returned error for valid miniscript: %v", err)
	}

	// Invalid miniscript
	err = ValidateMiniscript("invalid()", P2WSH)
	if err == nil {
		t.Error("ValidateMiniscript() should return error for invalid miniscript")
	}
}

func BenchmarkParseMiniscript(b *testing.B) {
	input := "or_i(pk(" + hex.EncodeToString(testKey) + "),and_v(v:pk(" + hex.EncodeToString(testKey2) + "),older(100)))"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseMiniscript(input, P2WSH)
	}
}

func BenchmarkMiniscriptToScript(b *testing.B) {
	input := "or_i(pk(" + hex.EncodeToString(testKey) + "),and_v(v:pk(" + hex.EncodeToString(testKey2) + "),older(100)))"
	node, _ := ParseMiniscript(input, P2WSH)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = node.ToScript()
	}
}

func BenchmarkMiniscriptSatisfy(b *testing.B) {
	input := "pk(" + hex.EncodeToString(testKey) + ")"
	node, _ := ParseMiniscript(input, P2WSH)

	mockSig := bytes.Repeat([]byte{0x30}, 72)
	ctx := &SatisfactionContext{
		Sign: func(pubkey []byte) ([]byte, Availability) {
			return mockSig, AvailYes
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = node.Satisfy(ctx)
	}
}
