package script

// TxoutType is Bitcoin Core's TxoutType (script/solver.h): the template a
// scriptPubKey matches, as decided by Solver.
type TxoutType int

const (
	TxoutNonstandard TxoutType = iota
	TxoutPubKey
	TxoutPubKeyHash
	TxoutScriptHash
	TxoutMultisig
	TxoutNullData
	TxoutAnchor
	TxoutWitnessV0KeyHash
	TxoutWitnessV0ScriptHash
	TxoutWitnessV1Taproot
	TxoutWitnessUnknown
)

// Solver classifies scriptPubKey exactly like Bitcoin Core's Solver
// (script/solver.cpp), in Core's order: P2SH first, then witness programs
// (v0 of a size other than 20/32 is NONSTANDARD, v1..v16 that are not
// taproot or P2A are WITNESS_UNKNOWN), then OP_RETURN + push-only data,
// P2PK, P2PKH, bare multisig (up to 20 keys), and everything else
// NONSTANDARD. It is the classifier Core's ValidateInputsStandardness
// (policy/policy.cpp) runs on every prevout.
//
// It is NOT the output-standardness test: Core's IsStandard adds further
// limits (multisig n <= 3, -permitbaremultisig) on top of the type.
func Solver(spk []byte) TxoutType {
	if IsP2SH(spk) {
		return TxoutScriptHash
	}

	if version, program := ExtractWitnessProgram(spk); version >= 0 {
		switch {
		case version == 0 && len(program) == 20:
			return TxoutWitnessV0KeyHash
		case version == 0 && len(program) == 32:
			return TxoutWitnessV0ScriptHash
		case version == 1 && len(program) == 32:
			return TxoutWitnessV1Taproot
		case IsPayToAnchor(spk):
			return TxoutAnchor
		case version != 0:
			return TxoutWitnessUnknown
		}
		return TxoutNonstandard
	}

	if len(spk) >= 1 && spk[0] == OP_RETURN && solverIsPushOnly(spk[1:]) {
		return TxoutNullData
	}
	if matchPayToPubkey(spk) {
		return TxoutPubKey
	}
	if IsP2PKH(spk) {
		return TxoutPubKeyHash
	}
	if matchMultisig(spk) {
		return TxoutMultisig
	}
	return TxoutNonstandard
}

// solverGetOp is Core's GetScriptOp (script/script.cpp): it reads one opcode
// and its push data at pc. On failure (end of script, or a push that runs
// past the end) it returns op = OP_INVALIDOPCODE, no data and ok = false.
func solverGetOp(s []byte, pc int) (op byte, data []byte, next int, ok bool) {
	if pc >= len(s) {
		return OP_INVALIDOPCODE, nil, pc, false
	}
	opcode := s[pc]
	pc++
	if opcode <= OP_PUSHDATA4 {
		var n int
		switch {
		case opcode < OP_PUSHDATA1:
			n = int(opcode)
		case opcode == OP_PUSHDATA1:
			if len(s)-pc < 1 {
				return OP_INVALIDOPCODE, nil, pc, false
			}
			n = int(s[pc])
			pc++
		case opcode == OP_PUSHDATA2:
			if len(s)-pc < 2 {
				return OP_INVALIDOPCODE, nil, pc, false
			}
			n = int(s[pc]) | int(s[pc+1])<<8
			pc += 2
		default: // OP_PUSHDATA4
			if len(s)-pc < 4 {
				return OP_INVALIDOPCODE, nil, pc, false
			}
			n = int(uint32(s[pc]) | uint32(s[pc+1])<<8 | uint32(s[pc+2])<<16 | uint32(s[pc+3])<<24)
			pc += 4
		}
		if n < 0 || len(s)-pc < n {
			return OP_INVALIDOPCODE, nil, pc, false
		}
		data = s[pc : pc+n]
		pc += n
	}
	return opcode, data, pc, true
}

// solverIsPushOnly is Core's CScript::IsPushOnly: every op parses and none
// is above OP_16. Unlike IsPushOnly in engine.go, a push that runs past the
// end of the script makes it false, as GetOp fails there.
func solverIsPushOnly(s []byte) bool {
	pc := 0
	for pc < len(s) {
		op, _, next, ok := solverGetOp(s, pc)
		if !ok || op > OP_16 {
			return false
		}
		pc = next
	}
	return true
}

// pubKeyValidSize is Core's CPubKey::ValidSize: the header byte implies the
// length (0x02/0x03 -> 33, 0x04/0x06/0x07 -> 65) and the data has it.
func pubKeyValidSize(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	switch data[0] {
	case 2, 3:
		return len(data) == 33
	case 4, 6, 7:
		return len(data) == 65
	}
	return false
}

// matchPayToPubkey is Core's MatchPayToPubkey: <33 or 65 byte key> OP_CHECKSIG.
func matchPayToPubkey(s []byte) bool {
	if len(s) == 65+2 && s[0] == 65 && s[len(s)-1] == OP_CHECKSIG {
		return pubKeyValidSize(s[1 : 1+65])
	}
	if len(s) == 33+2 && s[0] == 33 && s[len(s)-1] == OP_CHECKSIG {
		return pubKeyValidSize(s[1 : 1+33])
	}
	return false
}

// solverCheckMinimalPush is Core's CheckMinimalPush (script/script.cpp).
func solverCheckMinimalPush(data []byte, op byte) bool {
	switch {
	case len(data) == 0:
		return op == OP_0
	case len(data) == 1 && data[0] >= 1 && data[0] <= 16:
		return false
	case len(data) == 1 && data[0] == 0x81:
		return false
	case len(data) <= 75:
		return int(op) == len(data)
	case len(data) <= 255:
		return op == OP_PUSHDATA1
	case len(data) <= 65535:
		return op == OP_PUSHDATA2
	}
	return true
}

// solverScriptNumber is Core's GetScriptNumber (script/solver.cpp): OP_1..OP_16,
// or a minimally pushed, minimally encoded CScriptNum, in [min, max].
func solverScriptNumber(op byte, data []byte, min, max int) (int, bool) {
	var count int
	switch {
	case op >= OP_1 && op <= OP_16:
		count = int(op-OP_1) + 1
	case op > OP_0 && op <= OP_PUSHDATA4:
		if !solverCheckMinimalPush(data, op) {
			return 0, false
		}
		n, err := ScriptNumDeserialize(data, 4, true)
		if err != nil {
			return 0, false
		}
		count = int(n)
	default:
		return 0, false
	}
	if count < min || count > max {
		return 0, false
	}
	return count, true
}

// matchMultisig is Core's MatchMultisig (script/solver.cpp):
// <m> <key>... <n> OP_CHECKMULTISIG with 1 <= m <= n <= 20 and n keys.
func matchMultisig(s []byte) bool {
	if len(s) < 1 || s[len(s)-1] != OP_CHECKMULTISIG {
		return false
	}
	op, data, pc, ok := solverGetOp(s, 0)
	if !ok {
		return false
	}
	required, ok := solverScriptNumber(op, data, 1, MaxPubKeysPerMultisig)
	if !ok {
		return false
	}
	keys := 0
	for {
		op, data, pc, ok = solverGetOp(s, pc)
		if !ok || !pubKeyValidSize(data) {
			break
		}
		keys++
	}
	numKeys, ok := solverScriptNumber(op, data, required, MaxPubKeysPerMultisig)
	if !ok || keys != numKeys {
		return false
	}
	return pc+1 == len(s)
}
