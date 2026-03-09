// Package script implements the Bitcoin Script interpreter.
package script

// Bitcoin Script opcodes
const (
	// Push values
	OP_0           = 0x00
	OP_FALSE       = 0x00
	OP_PUSHDATA1   = 0x4c
	OP_PUSHDATA2   = 0x4d
	OP_PUSHDATA4   = 0x4e
	OP_1NEGATE     = 0x4f
	OP_RESERVED    = 0x50
	OP_1           = 0x51
	OP_TRUE        = 0x51
	OP_2           = 0x52
	OP_3           = 0x53
	OP_4           = 0x54
	OP_5           = 0x55
	OP_6           = 0x56
	OP_7           = 0x57
	OP_8           = 0x58
	OP_9           = 0x59
	OP_10          = 0x5a
	OP_11          = 0x5b
	OP_12          = 0x5c
	OP_13          = 0x5d
	OP_14          = 0x5e
	OP_15          = 0x5f
	OP_16          = 0x60

	// Control flow
	OP_NOP    = 0x61
	OP_VER    = 0x62
	OP_IF     = 0x63
	OP_NOTIF  = 0x64
	OP_VERIF  = 0x65
	OP_VERNOTIF = 0x66
	OP_ELSE   = 0x67
	OP_ENDIF  = 0x68
	OP_VERIFY = 0x69
	OP_RETURN = 0x6a

	// Stack operations
	OP_TOALTSTACK   = 0x6b
	OP_FROMALTSTACK = 0x6c
	OP_2DROP        = 0x6d
	OP_2DUP         = 0x6e
	OP_3DUP         = 0x6f
	OP_2OVER        = 0x70
	OP_2ROT         = 0x71
	OP_2SWAP        = 0x72
	OP_IFDUP        = 0x73
	OP_DEPTH        = 0x74
	OP_DROP         = 0x75
	OP_DUP          = 0x76
	OP_NIP          = 0x77
	OP_OVER         = 0x78
	OP_PICK         = 0x79
	OP_ROLL         = 0x7a
	OP_ROT          = 0x7b
	OP_SWAP         = 0x7c
	OP_TUCK         = 0x7d

	// Splice operations (disabled)
	OP_CAT    = 0x7e
	OP_SUBSTR = 0x7f
	OP_LEFT   = 0x80
	OP_RIGHT  = 0x81
	OP_SIZE   = 0x82

	// Bitwise operations (mostly disabled)
	OP_INVERT      = 0x83
	OP_AND         = 0x84
	OP_OR          = 0x85
	OP_XOR         = 0x86
	OP_EQUAL       = 0x87
	OP_EQUALVERIFY = 0x88
	OP_RESERVED1   = 0x89
	OP_RESERVED2   = 0x8a

	// Arithmetic operations
	OP_1ADD               = 0x8b
	OP_1SUB               = 0x8c
	OP_2MUL               = 0x8d // disabled
	OP_2DIV               = 0x8e // disabled
	OP_NEGATE             = 0x8f
	OP_ABS                = 0x90
	OP_NOT                = 0x91
	OP_0NOTEQUAL          = 0x92
	OP_ADD                = 0x93
	OP_SUB                = 0x94
	OP_MUL                = 0x95 // disabled
	OP_DIV                = 0x96 // disabled
	OP_MOD                = 0x97 // disabled
	OP_LSHIFT             = 0x98 // disabled
	OP_RSHIFT             = 0x99 // disabled
	OP_BOOLAND            = 0x9a
	OP_BOOLOR             = 0x9b
	OP_NUMEQUAL           = 0x9c
	OP_NUMEQUALVERIFY     = 0x9d
	OP_NUMNOTEQUAL        = 0x9e
	OP_LESSTHAN           = 0x9f
	OP_GREATERTHAN        = 0xa0
	OP_LESSTHANOREQUAL    = 0xa1
	OP_GREATERTHANOREQUAL = 0xa2
	OP_MIN                = 0xa3
	OP_MAX                = 0xa4
	OP_WITHIN             = 0xa5

	// Crypto operations
	OP_RIPEMD160           = 0xa6
	OP_SHA1                = 0xa7
	OP_SHA256              = 0xa8
	OP_HASH160             = 0xa9
	OP_HASH256             = 0xaa
	OP_CODESEPARATOR       = 0xab
	OP_CHECKSIG            = 0xac
	OP_CHECKSIGVERIFY      = 0xad
	OP_CHECKMULTISIG       = 0xae
	OP_CHECKMULTISIGVERIFY = 0xaf

	// NOP operations (reserved for future upgrades)
	OP_NOP1                = 0xb0
	OP_CHECKLOCKTIMEVERIFY = 0xb1
	OP_NOP2                = 0xb1 // alias for CLTV
	OP_CHECKSEQUENCEVERIFY = 0xb2
	OP_NOP3                = 0xb2 // alias for CSV
	OP_NOP4                = 0xb3
	OP_NOP5                = 0xb4
	OP_NOP6                = 0xb5
	OP_NOP7                = 0xb6
	OP_NOP8                = 0xb7
	OP_NOP9                = 0xb8
	OP_NOP10               = 0xb9

	// Tapscript opcodes
	OP_CHECKSIGADD = 0xba

	// Invalid/special opcodes
	OP_INVALIDOPCODE = 0xff
)

// OpcodeName returns the human-readable name of an opcode.
func OpcodeName(op byte) string {
	switch op {
	case OP_0:
		return "OP_0"
	case OP_PUSHDATA1:
		return "OP_PUSHDATA1"
	case OP_PUSHDATA2:
		return "OP_PUSHDATA2"
	case OP_PUSHDATA4:
		return "OP_PUSHDATA4"
	case OP_1NEGATE:
		return "OP_1NEGATE"
	case OP_RESERVED:
		return "OP_RESERVED"
	case OP_1:
		return "OP_1"
	case OP_2:
		return "OP_2"
	case OP_3:
		return "OP_3"
	case OP_4:
		return "OP_4"
	case OP_5:
		return "OP_5"
	case OP_6:
		return "OP_6"
	case OP_7:
		return "OP_7"
	case OP_8:
		return "OP_8"
	case OP_9:
		return "OP_9"
	case OP_10:
		return "OP_10"
	case OP_11:
		return "OP_11"
	case OP_12:
		return "OP_12"
	case OP_13:
		return "OP_13"
	case OP_14:
		return "OP_14"
	case OP_15:
		return "OP_15"
	case OP_16:
		return "OP_16"
	case OP_NOP:
		return "OP_NOP"
	case OP_IF:
		return "OP_IF"
	case OP_NOTIF:
		return "OP_NOTIF"
	case OP_ELSE:
		return "OP_ELSE"
	case OP_ENDIF:
		return "OP_ENDIF"
	case OP_VERIFY:
		return "OP_VERIFY"
	case OP_RETURN:
		return "OP_RETURN"
	case OP_TOALTSTACK:
		return "OP_TOALTSTACK"
	case OP_FROMALTSTACK:
		return "OP_FROMALTSTACK"
	case OP_2DROP:
		return "OP_2DROP"
	case OP_2DUP:
		return "OP_2DUP"
	case OP_3DUP:
		return "OP_3DUP"
	case OP_2OVER:
		return "OP_2OVER"
	case OP_2SWAP:
		return "OP_2SWAP"
	case OP_DROP:
		return "OP_DROP"
	case OP_DUP:
		return "OP_DUP"
	case OP_NIP:
		return "OP_NIP"
	case OP_OVER:
		return "OP_OVER"
	case OP_ROT:
		return "OP_ROT"
	case OP_SWAP:
		return "OP_SWAP"
	case OP_TUCK:
		return "OP_TUCK"
	case OP_SIZE:
		return "OP_SIZE"
	case OP_EQUAL:
		return "OP_EQUAL"
	case OP_EQUALVERIFY:
		return "OP_EQUALVERIFY"
	case OP_1ADD:
		return "OP_1ADD"
	case OP_1SUB:
		return "OP_1SUB"
	case OP_NEGATE:
		return "OP_NEGATE"
	case OP_ABS:
		return "OP_ABS"
	case OP_NOT:
		return "OP_NOT"
	case OP_0NOTEQUAL:
		return "OP_0NOTEQUAL"
	case OP_ADD:
		return "OP_ADD"
	case OP_SUB:
		return "OP_SUB"
	case OP_BOOLAND:
		return "OP_BOOLAND"
	case OP_BOOLOR:
		return "OP_BOOLOR"
	case OP_NUMEQUAL:
		return "OP_NUMEQUAL"
	case OP_NUMEQUALVERIFY:
		return "OP_NUMEQUALVERIFY"
	case OP_NUMNOTEQUAL:
		return "OP_NUMNOTEQUAL"
	case OP_LESSTHAN:
		return "OP_LESSTHAN"
	case OP_GREATERTHAN:
		return "OP_GREATERTHAN"
	case OP_LESSTHANOREQUAL:
		return "OP_LESSTHANOREQUAL"
	case OP_GREATERTHANOREQUAL:
		return "OP_GREATERTHANOREQUAL"
	case OP_MIN:
		return "OP_MIN"
	case OP_MAX:
		return "OP_MAX"
	case OP_WITHIN:
		return "OP_WITHIN"
	case OP_RIPEMD160:
		return "OP_RIPEMD160"
	case OP_SHA1:
		return "OP_SHA1"
	case OP_SHA256:
		return "OP_SHA256"
	case OP_HASH160:
		return "OP_HASH160"
	case OP_HASH256:
		return "OP_HASH256"
	case OP_CODESEPARATOR:
		return "OP_CODESEPARATOR"
	case OP_CHECKSIG:
		return "OP_CHECKSIG"
	case OP_CHECKSIGVERIFY:
		return "OP_CHECKSIGVERIFY"
	case OP_CHECKMULTISIG:
		return "OP_CHECKMULTISIG"
	case OP_CHECKMULTISIGVERIFY:
		return "OP_CHECKMULTISIGVERIFY"
	case OP_NOP1:
		return "OP_NOP1"
	case OP_CHECKLOCKTIMEVERIFY:
		return "OP_CHECKLOCKTIMEVERIFY"
	case OP_CHECKSEQUENCEVERIFY:
		return "OP_CHECKSEQUENCEVERIFY"
	case OP_NOP4:
		return "OP_NOP4"
	case OP_NOP5:
		return "OP_NOP5"
	case OP_NOP6:
		return "OP_NOP6"
	case OP_NOP7:
		return "OP_NOP7"
	case OP_NOP8:
		return "OP_NOP8"
	case OP_NOP9:
		return "OP_NOP9"
	case OP_NOP10:
		return "OP_NOP10"
	case OP_CHECKSIGADD:
		return "OP_CHECKSIGADD"
	default:
		if op >= 0x01 && op <= 0x4b {
			return "OP_PUSHBYTES"
		}
		return "OP_UNKNOWN"
	}
}

// IsPushOpcode returns true if the opcode pushes data onto the stack.
func IsPushOpcode(op byte) bool {
	return op <= OP_16 && op != OP_RESERVED
}

// IsDisabledOpcode returns true if the opcode is disabled.
func IsDisabledOpcode(op byte) bool {
	switch op {
	case OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT:
		return true
	case OP_INVERT, OP_AND, OP_OR, OP_XOR:
		return true
	case OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT:
		return true
	case OP_VER, OP_VERIF, OP_VERNOTIF:
		return true
	}
	return false
}

// Script size limits
const (
	MaxScriptSize      = 10000 // Maximum script size in bytes
	MaxStackSize       = 1000  // Maximum stack items
	MaxOpsPerScript    = 201   // Maximum non-push operations per script
	MaxScriptNumLen    = 4     // Maximum script number size in bytes
	MaxPubKeysPerMultisig  = 20  // Maximum public keys in multisig
	MaxScriptElementSize   = 520 // Maximum size of a push data element

	// TapscriptSigopBudgetCost is the cost per signature operation in tapscript (BIP342).
	// The total budget is 50 + witness_size.
	TapscriptSigopBudgetCost = 50
)
