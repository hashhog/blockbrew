// Command script_test runs the Bitcoin Core script_tests.json vectors against
// the blockbrew script interpreter.
//
// Test vector file: script_tests.json from Bitcoin Core
// Formats:
//   [scriptSig_asm, scriptPubKey_asm, flags, expected_result]              (4 fields)
//   [scriptSig_asm, scriptPubKey_asm, flags, expected_result, comment]     (5 fields)
//   [[witness...], amount, scriptSig_asm, scriptPubKey_asm, flags, result] (6+ fields, skipped)
//
// Single-element arrays are comments and are skipped.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// vectorPath is the default location for the test vectors.
const vectorPath = "/home/max/hashhog/bitcoin/src/test/data/script_tests.json"

// opcodeMap maps assembly names (without OP_ prefix where appropriate) to byte values.
var opcodeMap map[string]byte

func init() {
	opcodeMap = map[string]byte{
		"0":                    script.OP_0,
		"FALSE":                script.OP_FALSE,
		"OP_0":                 script.OP_0,
		"OP_FALSE":             script.OP_FALSE,
		"OP_PUSHDATA1":         script.OP_PUSHDATA1,
		"OP_PUSHDATA2":         script.OP_PUSHDATA2,
		"OP_PUSHDATA4":         script.OP_PUSHDATA4,
		"OP_1NEGATE":           script.OP_1NEGATE,
		"OP_RESERVED":          script.OP_RESERVED,
		"OP_1":                 script.OP_1,
		"OP_TRUE":              script.OP_TRUE,
		"OP_2":                 script.OP_2,
		"OP_3":                 script.OP_3,
		"OP_4":                 script.OP_4,
		"OP_5":                 script.OP_5,
		"OP_6":                 script.OP_6,
		"OP_7":                 script.OP_7,
		"OP_8":                 script.OP_8,
		"OP_9":                 script.OP_9,
		"OP_10":                script.OP_10,
		"OP_11":                script.OP_11,
		"OP_12":                script.OP_12,
		"OP_13":                script.OP_13,
		"OP_14":                script.OP_14,
		"OP_15":                script.OP_15,
		"OP_16":                script.OP_16,
		"OP_NOP":               script.OP_NOP,
		"OP_VER":               script.OP_VER,
		"OP_IF":                script.OP_IF,
		"OP_NOTIF":             script.OP_NOTIF,
		"OP_VERIF":             script.OP_VERIF,
		"OP_VERNOTIF":          script.OP_VERNOTIF,
		"OP_ELSE":              script.OP_ELSE,
		"OP_ENDIF":             script.OP_ENDIF,
		"OP_VERIFY":            script.OP_VERIFY,
		"OP_RETURN":            script.OP_RETURN,
		"OP_TOALTSTACK":        script.OP_TOALTSTACK,
		"OP_FROMALTSTACK":      script.OP_FROMALTSTACK,
		"OP_2DROP":             script.OP_2DROP,
		"OP_2DUP":              script.OP_2DUP,
		"OP_3DUP":              script.OP_3DUP,
		"OP_2OVER":             script.OP_2OVER,
		"OP_2ROT":              script.OP_2ROT,
		"OP_2SWAP":             script.OP_2SWAP,
		"OP_IFDUP":             script.OP_IFDUP,
		"OP_DEPTH":             script.OP_DEPTH,
		"OP_DROP":              script.OP_DROP,
		"OP_DUP":               script.OP_DUP,
		"OP_NIP":               script.OP_NIP,
		"OP_OVER":              script.OP_OVER,
		"OP_PICK":              script.OP_PICK,
		"OP_ROLL":              script.OP_ROLL,
		"OP_ROT":               script.OP_ROT,
		"OP_SWAP":              script.OP_SWAP,
		"OP_TUCK":              script.OP_TUCK,
		"OP_CAT":               script.OP_CAT,
		"OP_SUBSTR":            script.OP_SUBSTR,
		"OP_LEFT":              script.OP_LEFT,
		"OP_RIGHT":             script.OP_RIGHT,
		"OP_SIZE":              script.OP_SIZE,
		"OP_INVERT":            script.OP_INVERT,
		"OP_AND":               script.OP_AND,
		"OP_OR":                script.OP_OR,
		"OP_XOR":               script.OP_XOR,
		"OP_EQUAL":             script.OP_EQUAL,
		"OP_EQUALVERIFY":       script.OP_EQUALVERIFY,
		"OP_RESERVED1":         script.OP_RESERVED1,
		"OP_RESERVED2":         script.OP_RESERVED2,
		"OP_1ADD":              script.OP_1ADD,
		"OP_1SUB":              script.OP_1SUB,
		"OP_2MUL":              script.OP_2MUL,
		"OP_2DIV":              script.OP_2DIV,
		"OP_NEGATE":            script.OP_NEGATE,
		"OP_ABS":               script.OP_ABS,
		"OP_NOT":               script.OP_NOT,
		"OP_0NOTEQUAL":         script.OP_0NOTEQUAL,
		"OP_ADD":               script.OP_ADD,
		"OP_SUB":               script.OP_SUB,
		"OP_MUL":               script.OP_MUL,
		"OP_DIV":               script.OP_DIV,
		"OP_MOD":               script.OP_MOD,
		"OP_LSHIFT":            script.OP_LSHIFT,
		"OP_RSHIFT":            script.OP_RSHIFT,
		"OP_BOOLAND":           script.OP_BOOLAND,
		"OP_BOOLOR":            script.OP_BOOLOR,
		"OP_NUMEQUAL":          script.OP_NUMEQUAL,
		"OP_NUMEQUALVERIFY":    script.OP_NUMEQUALVERIFY,
		"OP_NUMNOTEQUAL":       script.OP_NUMNOTEQUAL,
		"OP_LESSTHAN":          script.OP_LESSTHAN,
		"OP_GREATERTHAN":       script.OP_GREATERTHAN,
		"OP_LESSTHANOREQUAL":   script.OP_LESSTHANOREQUAL,
		"OP_GREATERTHANOREQUAL": script.OP_GREATERTHANOREQUAL,
		"OP_MIN":               script.OP_MIN,
		"OP_MAX":               script.OP_MAX,
		"OP_WITHIN":            script.OP_WITHIN,
		"OP_RIPEMD160":         script.OP_RIPEMD160,
		"OP_SHA1":              script.OP_SHA1,
		"OP_SHA256":            script.OP_SHA256,
		"OP_HASH160":           script.OP_HASH160,
		"OP_HASH256":           script.OP_HASH256,
		"OP_CODESEPARATOR":     script.OP_CODESEPARATOR,
		"OP_CHECKSIG":          script.OP_CHECKSIG,
		"OP_CHECKSIGVERIFY":    script.OP_CHECKSIGVERIFY,
		"OP_CHECKMULTISIG":     script.OP_CHECKMULTISIG,
		"OP_CHECKMULTISIGVERIFY": script.OP_CHECKMULTISIGVERIFY,
		"OP_NOP1":              script.OP_NOP1,
		"OP_CHECKLOCKTIMEVERIFY": script.OP_CHECKLOCKTIMEVERIFY,
		"OP_CLTV":              script.OP_CHECKLOCKTIMEVERIFY,
		"OP_CHECKSEQUENCEVERIFY": script.OP_CHECKSEQUENCEVERIFY,
		"OP_CSV":               script.OP_CHECKSEQUENCEVERIFY,
		"OP_NOP4":              script.OP_NOP4,
		"OP_NOP5":              script.OP_NOP5,
		"OP_NOP6":              script.OP_NOP6,
		"OP_NOP7":              script.OP_NOP7,
		"OP_NOP8":              script.OP_NOP8,
		"OP_NOP9":              script.OP_NOP9,
		"OP_NOP10":             script.OP_NOP10,
		"OP_CHECKSIGADD":       script.OP_CHECKSIGADD,
		"OP_INVALIDOPCODE":     script.OP_INVALIDOPCODE,
	}

	// Add aliases without OP_ prefix for the most common names used in test vectors.
	// The test vector format uses bare names like "DUP", "HASH160", etc.
	for name, val := range map[string]byte{
		"NOP":                script.OP_NOP,
		"VER":               script.OP_VER,
		"IF":                script.OP_IF,
		"NOTIF":             script.OP_NOTIF,
		"VERIF":             script.OP_VERIF,
		"VERNOTIF":          script.OP_VERNOTIF,
		"ELSE":              script.OP_ELSE,
		"ENDIF":             script.OP_ENDIF,
		"VERIFY":            script.OP_VERIFY,
		"RETURN":            script.OP_RETURN,
		"TOALTSTACK":        script.OP_TOALTSTACK,
		"FROMALTSTACK":      script.OP_FROMALTSTACK,
		"2DROP":             script.OP_2DROP,
		"2DUP":              script.OP_2DUP,
		"3DUP":              script.OP_3DUP,
		"2OVER":             script.OP_2OVER,
		"2ROT":              script.OP_2ROT,
		"2SWAP":             script.OP_2SWAP,
		"IFDUP":             script.OP_IFDUP,
		"DEPTH":             script.OP_DEPTH,
		"DROP":              script.OP_DROP,
		"DUP":               script.OP_DUP,
		"NIP":               script.OP_NIP,
		"OVER":              script.OP_OVER,
		"PICK":              script.OP_PICK,
		"ROLL":              script.OP_ROLL,
		"ROT":               script.OP_ROT,
		"SWAP":              script.OP_SWAP,
		"TUCK":              script.OP_TUCK,
		"CAT":               script.OP_CAT,
		"SUBSTR":            script.OP_SUBSTR,
		"LEFT":              script.OP_LEFT,
		"RIGHT":             script.OP_RIGHT,
		"SIZE":              script.OP_SIZE,
		"INVERT":            script.OP_INVERT,
		"AND":               script.OP_AND,
		"OR":                script.OP_OR,
		"XOR":               script.OP_XOR,
		"EQUAL":             script.OP_EQUAL,
		"EQUALVERIFY":       script.OP_EQUALVERIFY,
		"RESERVED":          script.OP_RESERVED,
		"RESERVED1":         script.OP_RESERVED1,
		"RESERVED2":         script.OP_RESERVED2,
		"1ADD":              script.OP_1ADD,
		"1SUB":              script.OP_1SUB,
		"2MUL":              script.OP_2MUL,
		"2DIV":              script.OP_2DIV,
		"NEGATE":            script.OP_NEGATE,
		"ABS":               script.OP_ABS,
		"NOT":               script.OP_NOT,
		"0NOTEQUAL":         script.OP_0NOTEQUAL,
		"ADD":               script.OP_ADD,
		"SUB":               script.OP_SUB,
		"MUL":               script.OP_MUL,
		"DIV":               script.OP_DIV,
		"MOD":               script.OP_MOD,
		"LSHIFT":            script.OP_LSHIFT,
		"RSHIFT":            script.OP_RSHIFT,
		"BOOLAND":           script.OP_BOOLAND,
		"BOOLOR":            script.OP_BOOLOR,
		"NUMEQUAL":          script.OP_NUMEQUAL,
		"NUMEQUALVERIFY":    script.OP_NUMEQUALVERIFY,
		"NUMNOTEQUAL":       script.OP_NUMNOTEQUAL,
		"LESSTHAN":          script.OP_LESSTHAN,
		"GREATERTHAN":       script.OP_GREATERTHAN,
		"LESSTHANOREQUAL":   script.OP_LESSTHANOREQUAL,
		"GREATERTHANOREQUAL": script.OP_GREATERTHANOREQUAL,
		"MIN":               script.OP_MIN,
		"MAX":               script.OP_MAX,
		"WITHIN":            script.OP_WITHIN,
		"RIPEMD160":         script.OP_RIPEMD160,
		"SHA1":              script.OP_SHA1,
		"SHA256":            script.OP_SHA256,
		"HASH160":           script.OP_HASH160,
		"HASH256":           script.OP_HASH256,
		"CODESEPARATOR":     script.OP_CODESEPARATOR,
		"CHECKSIG":          script.OP_CHECKSIG,
		"CHECKSIGVERIFY":    script.OP_CHECKSIGVERIFY,
		"CHECKMULTISIG":     script.OP_CHECKMULTISIG,
		"CHECKMULTISIGVERIFY": script.OP_CHECKMULTISIGVERIFY,
		"NOP1":              script.OP_NOP1,
		"CHECKLOCKTIMEVERIFY": script.OP_CHECKLOCKTIMEVERIFY,
		"CLTV":              script.OP_CHECKLOCKTIMEVERIFY,
		"CHECKSEQUENCEVERIFY": script.OP_CHECKSEQUENCEVERIFY,
		"CSV":               script.OP_CHECKSEQUENCEVERIFY,
		"NOP4":              script.OP_NOP4,
		"NOP5":              script.OP_NOP5,
		"NOP6":              script.OP_NOP6,
		"NOP7":              script.OP_NOP7,
		"NOP8":              script.OP_NOP8,
		"NOP9":              script.OP_NOP9,
		"NOP10":             script.OP_NOP10,
		"CHECKSIGADD":       script.OP_CHECKSIGADD,
		"INVALIDOPCODE":     script.OP_INVALIDOPCODE,
	} {
		opcodeMap[name] = val
	}
}

// parseScriptAsm parses a Bitcoin Script assembly string into raw bytes.
// Handles: OP_xxx names, bare opcode names, 0xNN hex bytes, 0xNN <hex data>,
// decimal numbers (which map to OP_0, OP_1NEGATE, OP_1..OP_16 or minimal pushes),
// and 'quoted strings'.
func parseScriptAsm(asm string) ([]byte, error) {
	var result []byte
	tokens := strings.Fields(asm)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		// Quoted string: 'text' -> push data
		if len(tok) >= 2 && tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			data := []byte(tok[1 : len(tok)-1])
			result = append(result, pushData(data)...)
			continue
		}

		// Hex literal: 0xNN
		if strings.HasPrefix(tok, "0x") || strings.HasPrefix(tok, "0X") {
			hexStr := tok[2:]
			data, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid hex %q: %v", tok, err)
			}
			// If this is a single-byte hex and it's an opcode-sized value (like 0x4c for OP_PUSHDATA1),
			// check if the next token is also hex data to push
			if len(data) == 1 && i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "0x") {
				// This is a length/opcode prefix followed by hex data
				opByte := data[0]
				if opByte >= 1 && opByte <= 75 {
					// Direct push: the byte IS the length
					i++
					hexData, err := hex.DecodeString(tokens[i][2:])
					if err != nil {
						return nil, fmt.Errorf("invalid hex data %q: %v", tokens[i], err)
					}
					result = append(result, opByte)
					result = append(result, hexData...)
					continue
				} else if opByte == script.OP_PUSHDATA1 {
					i++
					hexData, err := hex.DecodeString(tokens[i][2:])
					if err != nil {
						return nil, fmt.Errorf("invalid hex data %q: %v", tokens[i], err)
					}
					result = append(result, opByte)
					result = append(result, hexData...)
					continue
				} else if opByte == script.OP_PUSHDATA2 {
					i++
					hexData, err := hex.DecodeString(tokens[i][2:])
					if err != nil {
						return nil, fmt.Errorf("invalid hex data %q: %v", tokens[i], err)
					}
					result = append(result, opByte)
					result = append(result, hexData...)
					continue
				} else if opByte == script.OP_PUSHDATA4 {
					i++
					hexData, err := hex.DecodeString(tokens[i][2:])
					if err != nil {
						return nil, fmt.Errorf("invalid hex data %q: %v", tokens[i], err)
					}
					result = append(result, opByte)
					result = append(result, hexData...)
					continue
				}
			}
			// Otherwise just emit the raw bytes
			result = append(result, data...)
			continue
		}

		// Try opcode name lookup (with and without OP_ prefix)
		if op, ok := opcodeMap[tok]; ok {
			result = append(result, op)
			continue
		}
		if op, ok := opcodeMap["OP_"+tok]; ok {
			result = append(result, op)
			continue
		}

		// Decimal number -> script number push
		n, err := strconv.ParseInt(tok, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unknown token %q", tok)
		}
		if n == 0 {
			result = append(result, script.OP_0)
		} else if n == -1 {
			result = append(result, script.OP_1NEGATE)
		} else if n >= 1 && n <= 16 {
			result = append(result, byte(script.OP_1+n-1))
		} else {
			// Encode as minimal script number and push
			data := script.ScriptNumSerialize(n)
			result = append(result, pushData(data)...)
		}
	}
	return result, nil
}

// pushData returns the minimal push-data encoding for data.
func pushData(data []byte) []byte {
	l := len(data)
	if l == 0 {
		return []byte{script.OP_0}
	}
	if l <= 75 {
		return append([]byte{byte(l)}, data...)
	}
	if l <= 255 {
		return append([]byte{script.OP_PUSHDATA1, byte(l)}, data...)
	}
	if l <= 65535 {
		return append([]byte{script.OP_PUSHDATA2, byte(l), byte(l >> 8)}, data...)
	}
	return append([]byte{script.OP_PUSHDATA4, byte(l), byte(l >> 8), byte(l >> 16), byte(l >> 24)}, data...)
}

// parseFlags converts a comma-separated flag string to ScriptFlags.
func parseFlags(s string) script.ScriptFlags {
	var flags script.ScriptFlags
	if s == "" || s == "NONE" {
		return script.ScriptVerifyNone
	}
	for _, f := range strings.Split(s, ",") {
		switch strings.TrimSpace(f) {
		case "P2SH":
			flags |= script.ScriptVerifyP2SH
		case "STRICTENC":
			flags |= script.ScriptVerifyStrictEncoding
		case "DERSIG":
			flags |= script.ScriptVerifyDERSig
		case "LOW_S":
			flags |= script.ScriptVerifyLowS
		case "NULLDUMMY":
			flags |= script.ScriptVerifyNullDummy
		case "SIGPUSHONLY":
			flags |= script.ScriptVerifySigPushOnly
		case "MINIMALDATA":
			flags |= script.ScriptVerifyMinimalData
		case "DISCOURAGE_UPGRADABLE_NOPS":
			flags |= script.ScriptVerifyDiscourageUpgradableNops
		case "CLEANSTACK":
			flags |= script.ScriptVerifyCleanStack
		case "CHECKLOCKTIMEVERIFY":
			flags |= script.ScriptVerifyCLTV
		case "CHECKSEQUENCEVERIFY":
			flags |= script.ScriptVerifyCSV
		case "WITNESS":
			flags |= script.ScriptVerifyWitness
		case "WITNESS_PUBKEYTYPE":
			flags |= script.ScriptVerifyWitnessPubKeyType
		case "NULLFAIL":
			flags |= script.ScriptVerifyNullFail
		case "TAPROOT":
			flags |= script.ScriptVerifyTaproot
		case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
			// Not all flags may be implemented; silently ignore
		case "MINIMALIF":
			// May not have a dedicated flag; ignore
		case "DISCOURAGE_OP_SUCCESS":
			flags |= script.ScriptVerifyDiscourageOpSuccess
		case "CONST_SCRIPTCODE":
			flags |= script.ScriptVerifyConstScriptCode
		}
	}
	return flags
}

// makeCreditingTx creates the crediting transaction per Bitcoin Core's convention:
//   version 1, locktime 0, one input (null prevout, scriptSig = OP_0 OP_0,
//   sequence 0xFFFFFFFF), one output (scriptPubKey = test's scriptPubKey, value = 0).
func makeCreditingTx(scriptPubKey []byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xFFFFFFFF,
				},
				SignatureScript: []byte{script.OP_0, script.OP_0},
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    0,
				PkScript: scriptPubKey,
			},
		},
		LockTime: 0,
	}
}

// makeSpendingTx creates the spending transaction per Bitcoin Core's convention:
//   version 1, locktime 0, one input (prevout = hash of crediting tx : 0,
//   scriptSig = test's scriptSig, sequence 0xFFFFFFFF), one output (empty scriptPubKey, value = 0).
func makeSpendingTx(creditingTx *wire.MsgTx, scriptSig []byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  creditingTx.TxHash(),
					Index: 0,
				},
				SignatureScript: scriptSig,
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    0,
				PkScript: nil,
			},
		},
		LockTime: 0,
	}
}

func main() {
	path := vectorPath
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		os.Exit(1)
	}

	var testCases []json.RawMessage
	if err := json.Unmarshal(data, &testCases); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	passed := 0
	failed := 0
	skipped := 0
	parseErrors := 0

	for i, raw := range testCases {
		var entry []json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			skipped++
			continue
		}

		// Skip comment entries (single-element arrays)
		if len(entry) <= 1 {
			skipped++
			continue
		}

		// Skip witness tests (first element is an array -- detected by trying to
		// unmarshal entry[0] as an array)
		var firstArr []json.RawMessage
		if json.Unmarshal(entry[0], &firstArr) == nil {
			skipped++
			continue
		}

		// Must have 4 or 5 elements: scriptSig, scriptPubKey, flags, expected [, comment]
		if len(entry) < 4 {
			skipped++
			continue
		}

		var scriptSigAsm, scriptPubKeyAsm, flagsStr, expected string
		json.Unmarshal(entry[0], &scriptSigAsm)
		json.Unmarshal(entry[1], &scriptPubKeyAsm)
		json.Unmarshal(entry[2], &flagsStr)
		json.Unmarshal(entry[3], &expected)

		var comment string
		if len(entry) >= 5 {
			json.Unmarshal(entry[4], &comment)
		}

		scriptSig, err := parseScriptAsm(scriptSigAsm)
		if err != nil {
			parseErrors++
			fmt.Fprintf(os.Stderr, "test %d: parse scriptSig error: %v (asm: %q)\n", i, err, scriptSigAsm)
			continue
		}

		scriptPubKey, err := parseScriptAsm(scriptPubKeyAsm)
		if err != nil {
			parseErrors++
			fmt.Fprintf(os.Stderr, "test %d: parse scriptPubKey error: %v (asm: %q)\n", i, err, scriptPubKeyAsm)
			continue
		}

		flags := parseFlags(flagsStr)
		creditingTx := makeCreditingTx(scriptPubKey)
		tx := makeSpendingTx(creditingTx, scriptSig)

		prevOuts := []*wire.TxOut{
			{Value: 0, PkScript: scriptPubKey},
		}

		verifyErr := script.VerifyScript(scriptSig, scriptPubKey, tx, 0, flags, 0, prevOuts)

		expectOK := expected == "OK"
		gotOK := verifyErr == nil

		if expectOK == gotOK {
			passed++
		} else {
			failed++
			if failed <= 50 {
				errStr := "nil"
				if verifyErr != nil {
					errStr = verifyErr.Error()
				}
				fmt.Fprintf(os.Stderr, "FAIL test %d: expected=%s got_err=%s  sigAsm=%q pubkeyAsm=%q flags=%s comment=%q\n",
					i, expected, errStr, scriptSigAsm, scriptPubKeyAsm, flagsStr, comment)
			}
		}
	}

	fmt.Printf("script_tests.json results: %d passed, %d failed, %d skipped, %d parse errors\n",
		passed, failed, skipped, parseErrors)
	if failed > 0 {
		os.Exit(1)
	}
}
