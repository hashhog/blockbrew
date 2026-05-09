package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// W52 — decodepsbt JSON byte-identity helpers
//
// These helpers produce JSON that is byte-identical (after jq -S
// normalization) to Bitcoin Core 31.99's decodepsbt output. They mirror:
//   - core_io.cpp::ValueFromAmount     (btcAmount type)
//   - core_io.cpp::ScriptToAsmStr      (scriptToAsmStr)
//   - core_io.cpp::ScriptToUniv        (scriptPubKeyToUniv, scriptSigToUniv)
//   - script/descriptor.cpp::InferDescriptor no-provider path (inferDescriptor)
//
// We do NOT reuse the generic TxResult/VoutResult builders because those
// types are also consumed by other RPCs (getrawtransaction, getblock 2,
// REST etc.) where the Core convention slightly differs (e.g. `tx.hex` IS
// emitted there and ScriptSig may be nil-omitted). Threading a
// "decodepsbt mode" flag through every shared builder would cause
// flag-explosion; instead we build a dedicated map[string]any tree here,
// which encoding/json marshals with alphabetically-sorted keys, giving
// full control of the wire format.
// ============================================================================

// btcAmount renders an int64 satoshi count as a JSON number with fixed 8
// decimal places, matching Bitcoin Core's ValueFromAmount (core_io.cpp:285)
// which always emits "%s%d.%08d". encoding/json on float64 emits "1" for
// 100_000_000 sats, which diverges from Core's "1.00000000".
type btcAmount int64

// MarshalJSON renders the amount as a fixed 8-decimal JSON number.
func (a btcAmount) MarshalJSON() ([]byte, error) {
	const coin = int64(satoshiPerBitcoin)
	v := int64(a)
	neg := ""
	if v < 0 {
		neg = "-"
		v = -v
	}
	q := v / coin
	r := v % coin
	return []byte(fmt.Sprintf("%s%d.%08d", neg, q, r)), nil
}

// Compile-time check: btcAmount must satisfy json.Marshaler.
var _ json.Marshaler = btcAmount(0)

// sighashToStr converts a PSBT sighash type byte to its string name, mirroring
// Bitcoin Core's SighashToStr (core_io.cpp:343). Unknown values return "".
// 0x00 is NOT in the table (PSBT treats it as absent/default).
func sighashToStr(t uint32) string {
	switch byte(t) {
	case 0x01:
		return "ALL"
	case 0x02:
		return "NONE"
	case 0x03:
		return "SINGLE"
	case 0x81:
		return "ALL|ANYONECANPAY"
	case 0x82:
		return "NONE|ANYONECANPAY"
	case 0x83:
		return "SINGLE|ANYONECANPAY"
	}
	return ""
}

// isValidSigForAsmDecode returns true when vch looks like a DER-encoded ECDSA
// signature with a defined hashtype, mirroring the condition Core uses before
// stripping the last byte in ScriptToAsmStr (core_io.cpp:382):
//
//	CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)
//
// which requires IsValidSignatureEncoding(vch) && IsDefinedHashtypeSignature(vch).
// The IsDefinedHashtypeSignature check is just: last byte & 0x1f ∈ {1,2,3}.
func isValidSigForAsmDecode(vch []byte) bool {
	// IsValidSignatureEncoding: 9 ≤ len ≤ 73, DER structure
	n := len(vch)
	if n < 9 || n > 73 {
		return false
	}
	if vch[0] != 0x30 {
		return false
	}
	if int(vch[1]) != n-3 {
		return false
	}
	lenR := int(vch[3])
	if 5+lenR >= n {
		return false
	}
	lenS := int(vch[5+lenR])
	if lenR+lenS+7 != n {
		return false
	}
	if vch[2] != 0x02 {
		return false
	}
	// IsDefinedHashtypeSignature: (last & 0x1f) ∈ {1,2,3}
	ht := vch[n-1] & 0x1f
	if ht < 1 || ht > 3 {
		return false
	}
	return true
}

// scriptToAsmStr renders a CScript byte sequence to Bitcoin Core's asm
// representation, mirroring core_io.cpp::ScriptToAsmStr.
//
// When fAttemptSighashDecode is true and a push data item (>4 bytes) passes
// IsValidSignatureEncoding + IsDefinedHashtypeSignature, the last byte (the
// hashtype) is stripped from the displayed hex and a "[ALL]"/"[NONE]"/etc.
// suffix is appended. This is the behaviour Core uses for scriptSig asm in
// finalized PSBT inputs.
//
// Core rules:
//   - Push opcodes: emit the pushed data. If ≤4 bytes, decode as a
//     CScriptNum (signed little-endian) and emit the decimal integer.
//     If >4 bytes, emit lowercase hex (with optional sighash suffix).
//   - OP_1NEGATE (0x4f) → "-1"
//   - OP_1..OP_16 (0x51..0x60) → "1".."16"
//   - All other non-push opcodes → GetOpName string (e.g. "OP_DUP")
func scriptToAsmStr(s []byte, fAttemptSighashDecode bool) string {
	var out []byte
	pc := 0
	first := true
	for pc < len(s) {
		if !first {
			out = append(out, ' ')
		}
		first = false

		op := s[pc]
		pc++

		// Push opcodes: 0x00..0x4e
		if op <= script.OP_PUSHDATA4 {
			var n int
			switch {
			case op < script.OP_PUSHDATA1:
				n = int(op)
			case op == script.OP_PUSHDATA1:
				if pc >= len(s) {
					return string(append(out, []byte("[error]")...))
				}
				n = int(s[pc])
				pc++
			case op == script.OP_PUSHDATA2:
				if pc+2 > len(s) {
					return string(append(out, []byte("[error]")...))
				}
				n = int(s[pc]) | int(s[pc+1])<<8
				pc += 2
			case op == script.OP_PUSHDATA4:
				if pc+4 > len(s) {
					return string(append(out, []byte("[error]")...))
				}
				n = int(s[pc]) | int(s[pc+1])<<8 | int(s[pc+2])<<16 | int(s[pc+3])<<24
				pc += 4
			}
			if n < 0 || pc+n > len(s) {
				return string(append(out, []byte("[error]")...))
			}
			vch := s[pc : pc+n]
			pc += n
			if len(vch) <= 4 {
				v, _ := scriptNumToInt64(vch)
				out = append(out, []byte(strconv.FormatInt(v, 10))...)
			} else if fAttemptSighashDecode && isValidSigForAsmDecode(vch) {
				// Strip last byte (hashtype) from the hex; append "[TYPE]" suffix.
				// Core: vch.pop_back(); str += HexStr(vch) + strSigHashDecode;
				htByte := vch[len(vch)-1]
				body := vch[:len(vch)-1]
				suffix := "[" + sighashToStr(uint32(htByte)) + "]"
				out = append(out, []byte(hex.EncodeToString(body)+suffix)...)
			} else {
				out = append(out, []byte(hex.EncodeToString(vch))...)
			}
			continue
		}

		// Non-push opcodes
		out = append(out, []byte(asmOpName(op))...)
	}
	return string(out)
}

// asmOpName maps a non-push opcode to its Core GetOpName string, with the
// special decimal rendering for OP_1NEGATE and OP_1..OP_16.
func asmOpName(op byte) string {
	switch op {
	case script.OP_1NEGATE:
		return "-1"
	case script.OP_1:
		return "1"
	case script.OP_2:
		return "2"
	case script.OP_3:
		return "3"
	case script.OP_4:
		return "4"
	case script.OP_5:
		return "5"
	case script.OP_6:
		return "6"
	case script.OP_7:
		return "7"
	case script.OP_8:
		return "8"
	case script.OP_9:
		return "9"
	case script.OP_10:
		return "10"
	case script.OP_11:
		return "11"
	case script.OP_12:
		return "12"
	case script.OP_13:
		return "13"
	case script.OP_14:
		return "14"
	case script.OP_15:
		return "15"
	case script.OP_16:
		return "16"
	}
	return script.OpcodeName(op)
}

// scriptNumToInt64 deserializes a CScriptNum byte slice (little-endian,
// sign bit in MSB of last byte, empty == 0). Mirrors CScriptNum::set_vch().
func scriptNumToInt64(vch []byte) (int64, error) {
	if len(vch) == 0 {
		return 0, nil
	}
	var result int64
	for i := 0; i < len(vch); i++ {
		result |= int64(vch[i]) << (8 * i)
	}
	if vch[len(vch)-1]&0x80 != 0 {
		mask := int64(0x80) << (8 * (len(vch) - 1))
		return -(result & ^mask), nil
	}
	return result, nil
}

// scriptTypeName returns the Core GetTxnOutputType string for a scriptPubKey.
func scriptTypeName(s []byte) string {
	switch {
	case consensus.IsP2PKH(s):
		return "pubkeyhash"
	case consensus.IsP2SH(s):
		return "scripthash"
	case consensus.IsP2WPKH(s):
		return "witness_v0_keyhash"
	case consensus.IsP2WSH(s):
		return "witness_v0_scripthash"
	case consensus.IsP2TR(s):
		return "witness_v1_taproot"
	case isBarePubkey(s):
		return "pubkey"
	case isBareMultisig(s):
		return "multisig"
	case isNullData(s):
		return "nulldata"
	case isAnchor(s):
		return "anchor"
	case isWitnessUnknown(s):
		return "witness_unknown"
	}
	return "nonstandard"
}

// isBarePubkey: <33-byte or 65-byte push> OP_CHECKSIG
func isBarePubkey(s []byte) bool {
	if len(s) == 35 && s[0] == 0x21 && s[34] == script.OP_CHECKSIG {
		return true
	}
	if len(s) == 67 && s[0] == 0x41 && s[66] == script.OP_CHECKSIG {
		return true
	}
	return false
}

// isBareMultisig: OP_M <pubkeys...> OP_N OP_CHECKMULTISIG, 1≤M≤N≤16.
func isBareMultisig(s []byte) bool {
	if len(s) < 4 {
		return false
	}
	if s[len(s)-1] != script.OP_CHECKMULTISIG {
		return false
	}
	m := s[0]
	n := s[len(s)-2]
	if m < script.OP_1 || m > script.OP_16 {
		return false
	}
	if n < script.OP_1 || n > script.OP_16 {
		return false
	}
	if m > n {
		return false
	}
	expectedKeys := int(n-script.OP_1) + 1
	pc := 1
	count := 0
	for pc < len(s)-2 {
		op := s[pc]
		pc++
		if op != 0x21 && op != 0x41 {
			return false
		}
		size := int(op)
		if pc+size > len(s)-2 {
			return false
		}
		pc += size
		count++
	}
	return count == expectedKeys && pc == len(s)-2
}

// isNullData: OP_RETURN ...
func isNullData(s []byte) bool {
	return len(s) > 0 && s[0] == script.OP_RETURN
}

// isAnchor: OP_1 <0x4e73> (P2A)
func isAnchor(s []byte) bool {
	return len(s) == 4 && s[0] == script.OP_1 && s[1] == 0x02 && s[2] == 0x4e && s[3] == 0x73
}

// isWitnessUnknown: any unclassified witness program.
func isWitnessUnknown(s []byte) bool {
	if len(s) < 4 || len(s) > 42 {
		return false
	}
	v0 := s[0]
	if v0 != script.OP_0 && (v0 < script.OP_1 || v0 > script.OP_16) {
		return false
	}
	pushLen := int(s[1])
	if pushLen < 2 || pushLen > 40 {
		return false
	}
	return len(s) == 2+pushLen
}

// extractAddressFromScript returns the encoded address for a scriptPubKey,
// mirroring ExtractDestination + EncodeDestination. Returns ("", false) for
// PUBKEY, MULTISIG, OP_RETURN, raw, and other non-addressable scripts.
func extractAddressFromScript(s []byte, net address.Network) (string, bool) {
	switch {
	case consensus.IsP2PKH(s) && len(s) == 25:
		var h [20]byte
		copy(h[:], s[3:23])
		enc, err := address.NewP2PKHAddress(h, net).Encode()
		if err != nil {
			return "", false
		}
		return enc, true
	case consensus.IsP2SH(s) && len(s) == 23:
		var h [20]byte
		copy(h[:], s[2:22])
		enc, err := address.NewP2SHAddress(h, net).Encode()
		if err != nil {
			return "", false
		}
		return enc, true
	case consensus.IsP2WPKH(s) && len(s) == 22:
		var h [20]byte
		copy(h[:], s[2:22])
		enc, err := address.NewP2WPKHAddress(h, net).Encode()
		if err != nil {
			return "", false
		}
		return enc, true
	case consensus.IsP2WSH(s) && len(s) == 34:
		var h [32]byte
		copy(h[:], s[2:34])
		enc, err := address.NewP2WSHAddress(h, net).Encode()
		if err != nil {
			return "", false
		}
		return enc, true
	case consensus.IsP2TR(s) && len(s) == 34:
		var k [32]byte
		copy(k[:], s[2:34])
		enc, err := address.NewP2TRAddress(k, net).Encode()
		if err != nil {
			return "", false
		}
		return enc, true
	}
	return "", false
}

// inferDescriptor returns the BIP-380 descriptor string + 8-char checksum
// for a scriptPubKey, mirroring InferDescriptor(script, DUMMY_SIGNING_PROVIDER)
// from script/descriptor.cpp:2897. Without key material:
//   - bare PUBKEY       → pk(<hex>)#cs
//   - bare MULTISIG     → multi(M,<hex>,...)#cs
//   - witness_v1_taproot → rawtr(<32-byte-x-only-hex>)#cs  (BIP-386)
//   - address-recognizable → addr(<address>)#cs
//   - everything else   → raw(<hex>)#cs
//
// NOTE: P2TR outputs use rawtr() not addr() — Core's InferDescriptor calls
// InferRawtrDescriptor for witness_v1_taproot programs. The address is still
// emitted separately in scriptPubKeyToUniv via extractAddressFromScript.
func inferDescriptor(s []byte, net address.Network) string {
	if isBarePubkey(s) {
		var pk []byte
		if s[0] == 0x21 {
			pk = s[1:34]
		} else {
			pk = s[1:66]
		}
		return wallet.AddChecksum("pk(" + hex.EncodeToString(pk) + ")")
	}
	if isBareMultisig(s) {
		m := int(s[0]) - int(script.OP_1) + 1
		expr := fmt.Sprintf("multi(%d", m)
		pc := 1
		for pc < len(s)-2 {
			pushLen := int(s[pc])
			pc++
			expr += "," + hex.EncodeToString(s[pc:pc+pushLen])
			pc += pushLen
		}
		expr += ")"
		return wallet.AddChecksum(expr)
	}
	// witness_v1_taproot: OP_1 <32-byte push> → rawtr(<x-only-pubkey-hex>)
	// Mirrors Core's InferRawtrDescriptor (script/descriptor.cpp). The desc
	// field carries rawtr() even though an address can also be derived.
	if consensus.IsP2TR(s) && len(s) == 34 {
		xOnly := hex.EncodeToString(s[2:34])
		return wallet.AddChecksum("rawtr(" + xOnly + ")")
	}
	if addr, ok := extractAddressFromScript(s, net); ok {
		return wallet.AddChecksum("addr(" + addr + ")")
	}
	return wallet.AddChecksum("raw(" + hex.EncodeToString(s) + ")")
}

// scriptPubKeyToUniv builds the JSON map for a scriptPubKey, mirroring
// Core's ScriptToUniv (core_io.cpp:409). Always emits {asm, desc, hex, type};
// emits `address` only when extractable and type is not "pubkey" (Core skips
// address for bare-pubkey outputs).
func scriptPubKeyToUniv(s []byte, net address.Network) map[string]any {
	out := map[string]any{
		"asm":  scriptToAsmStr(s, false),
		"desc": inferDescriptor(s, net),
		"hex":  hex.EncodeToString(s),
		"type": scriptTypeName(s),
	}
	// Suppress address for bare-pubkey outputs (matches Core's ScriptToUniv
	// which only emits address when type != PUBKEY).
	if scriptTypeName(s) != "pubkey" {
		if addr, ok := extractAddressFromScript(s, net); ok {
			out["address"] = addr
		}
	}
	return out
}

// scriptSigToUniv builds the JSON map for a scriptSig, always emitting
// {asm, hex} even when the script is empty (PSBT unsigned tx convention).
func scriptSigToUniv(s []byte, attemptSighashDecode bool) map[string]any {
	return map[string]any{
		"asm": scriptToAsmStr(s, attemptSighashDecode),
		"hex": hex.EncodeToString(s),
	}
}

// buildDecodeRawTxJSON builds the JSON result for decoderawtransaction,
// mirroring Bitcoin Core's TxToUniv (core_io.cpp) with fVerbose=true.
//
// This function reuses all W52-W54 helpers (btcAmount, scriptPubKeyToUniv,
// scriptSigToUniv, inferDescriptor, rawtr branch) and adds coinbase-vin
// handling:
//   - Coinbase input: emit {coinbase, sequence, txinwitness?} — no txid/vout/scriptSig
//   - Non-coinbase input: emit {txid, vout, scriptSig, sequence, txinwitness?}
//   - No `hex` field (Core omits it from decoderawtransaction output)
//   - vout.value uses btcAmount (8 fixed decimal places)
func buildDecodeRawTxJSON(tx *wire.MsgTx, net address.Network) map[string]any {
	// Serialize for size/weight
	var buf bytes.Buffer
	tx.Serialize(&buf)
	size := buf.Len()

	weight := int(consensus.CalcTxWeight(tx))
	vsize := (weight + 3) / 4

	// vin array
	vin := make([]map[string]any, len(tx.TxIn))
	for i, in := range tx.TxIn {
		// Coinbase detection: null outpoint (all-zero hash + 0xFFFFFFFF index).
		// Mirrors Bitcoin Core's CTxIn::IsCoinBase() which is used in
		// TxToUniv (core_io.cpp) to emit the coinbase field.
		isCoinbaseIn := in.PreviousOutPoint.Hash.IsZero() && in.PreviousOutPoint.Index == 0xFFFFFFFF
		var vinObj map[string]any
		if isCoinbaseIn {
			vinObj = map[string]any{
				"coinbase": hex.EncodeToString(in.SignatureScript),
				"sequence": in.Sequence,
			}
		} else {
			vinObj = map[string]any{
				"txid":      in.PreviousOutPoint.Hash.String(),
				"vout":      in.PreviousOutPoint.Index,
				"scriptSig": scriptSigToUniv(in.SignatureScript, true),
				"sequence":  in.Sequence,
			}
		}
		if len(in.Witness) > 0 {
			witness := make([]string, len(in.Witness))
			for j, w := range in.Witness {
				witness[j] = hex.EncodeToString(w)
			}
			vinObj["txinwitness"] = witness
		}
		vin[i] = vinObj
	}

	// vout array
	vout := make([]map[string]any, len(tx.TxOut))
	for i, out := range tx.TxOut {
		vout[i] = map[string]any{
			"value":        btcAmount(out.Value),
			"n":            i,
			"scriptPubKey": scriptPubKeyToUniv(out.PkScript, net),
		}
	}

	return map[string]any{
		"txid":     tx.TxHash().String(),
		"hash":     tx.WTxHash().String(),
		"version":  tx.Version,
		"size":     size,
		"vsize":    vsize,
		"weight":   weight,
		"locktime": tx.LockTime,
		"vin":      vin,
		"vout":     vout,
	}
}

// buildPSBTTxJSON builds the embedded `tx` sub-object for decodepsbt output,
// mirroring Bitcoin Core's TxToUniv call in rpc/rawtransaction.cpp::decodepsbt.
//
// Key differences from the generic buildTxResult:
//   - No `hex` field emitted (Core omits it in decodepsbt's tx sub-object)
//   - scriptSig always emitted as {asm, hex} even when empty
//   - vout.value uses btcAmount (8 fixed decimal places)
//   - vout.scriptPubKey includes asm + desc + address
//   - vin.vout=0 must NOT be omitted (valid output index)
func buildPSBTTxJSON(tx *wire.MsgTx, net address.Network) map[string]any {
	// Serialize for size/weight
	var buf bytes.Buffer
	tx.Serialize(&buf)
	size := buf.Len()

	weight := int(consensus.CalcTxWeight(tx))
	vsize := (weight + 3) / 4

	// vin array
	vin := make([]map[string]any, len(tx.TxIn))
	for i, in := range tx.TxIn {
		vinObj := map[string]any{
			"txid":      in.PreviousOutPoint.Hash.String(),
			"vout":      in.PreviousOutPoint.Index,
			"scriptSig": scriptSigToUniv(in.SignatureScript, false),
			"sequence":  in.Sequence,
		}
		if len(in.Witness) > 0 {
			witness := make([]string, len(in.Witness))
			for j, w := range in.Witness {
				witness[j] = hex.EncodeToString(w)
			}
			vinObj["txinwitness"] = witness
		}
		vin[i] = vinObj
	}

	// vout array
	vout := make([]map[string]any, len(tx.TxOut))
	for i, out := range tx.TxOut {
		vout[i] = map[string]any{
			"value":        btcAmount(out.Value),
			"n":            i,
			"scriptPubKey": scriptPubKeyToUniv(out.PkScript, net),
		}
	}

	return map[string]any{
		"txid":     tx.TxHash().String(),
		"hash":     tx.WTxHash().String(),
		"version":  tx.Version,
		"size":     size,
		"vsize":    vsize,
		"weight":   weight,
		"locktime": tx.LockTime,
		"vin":      vin,
		"vout":     vout,
	}
}
