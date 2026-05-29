// Command verifyscript_shim is the Phase B bounded reject-bar `verifyscript`
// shim for blockbrew.
//
// It speaks the line-delimited JSON protocol of the shared Phase B driver
// (tools/phaseb-vectors/phaseb_vectors.py) and drives blockbrew's REAL
// consensus script interpreter (internal/script.VerifyScript,
// internal/script/engine.go:1375).
//
// The driver hands us PRE-ASSEMBLED hex scripts (it does the Core ParseScript
// assembly itself), so this shim only needs to:
//   1. map the 22 Core flag tokens to blockbrew's ScriptFlags bitmask,
//   2. rebuild Core's crediting + spending tx pair using blockbrew's OWN
//      wire.MsgTx serialization + TxHash so the sighash matches byte-for-byte
//      (mirrors cmd/script_test/main.go makeCreditingTx/makeSpendingTx, which
//      in turn mirrors bitcoin-core test/util/transaction_utils.cpp),
//   3. call VerifyScript and report the accept/reject decision.
//
// Protocol (one JSON object per line on stdin, one per line on stdout):
//
//	request:  {"op":"verifyscript",
//	           "scriptSig_hex":"...","scriptPubKey_hex":"...",
//	           "witness":["hex",...],"amount_sats":0,
//	           "flags":["P2SH","WITNESS",...]}
//	response: {"result":true}                  (accept)
//	          {"result":false,"reason":"..."}  (reject)
//	          {"error":"..."}                  (could not evaluate)
//
// Second op `verifytx` (for tx_valid.json / tx_invalid.json): unlike
// `verifyscript` (which rebuilds Core's synthetic credit/spend pair),
// these vectors give a REAL serialized multi-input tx, so the sighash
// must be computed over THAT tx. Mirrors
// bitcoin-core/src/test/transaction_tests.cpp::CheckTxScripts:
// deserialize tx_hex (BIP144 segwit marker/flag + witnesses), build the
// prevout map keyed by (txid, vout) -> (scriptPubKey, amount), then for
// EACH input run blockbrew's real VerifyScript over the REAL tx (so the
// legacy / BIP-143 / BIP-341 sighash commits to the actual surrounding
// transaction + all spent prevouts). The tx is valid iff ALL inputs
// pass; reject on the FIRST failing input (Core's loop is
// `i < vin.size() && fValid`).
//
//	request:  {"op":"verifytx",
//	           "tx_hex":"...",
//	           "prevouts":[{"txid":"<display-hex>","vout":N,
//	                        "scriptPubKey_hex":"...","amount_sats":0},...],
//	           "flags":["P2SH","WITNESS",...]}
//	response: {"valid":true}                   (all inputs verify)
//	          {"valid":false,"reason":"..."}   (>=1 input failed)
//	          {"error":"..."}                  (could not evaluate / map miss)
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

type request struct {
	Op              string   `json:"op"`
	ScriptSigHex    string   `json:"scriptSig_hex"`
	ScriptPubKeyHex string   `json:"scriptPubKey_hex"`
	Witness         []string `json:"witness"`
	AmountSats      int64    `json:"amount_sats"`
	Flags           []string `json:"flags"`

	// verifytx op fields.
	TxHex    string        `json:"tx_hex"`
	Prevouts []prevoutSpec `json:"prevouts"`
}

// prevoutSpec is one entry of the verifytx "prevouts" array: a spent
// output keyed by (txid display-hex, vout) with its scriptPubKey + amount.
type prevoutSpec struct {
	Txid            string `json:"txid"`
	Vout            uint32 `json:"vout"`
	ScriptPubKeyHex string `json:"scriptPubKey_hex"`
	AmountSats      int64  `json:"amount_sats"`
}

// buildFlags maps the 22 Core flag tokens (interpreter.cpp:2168
// ScriptFlagNamesToEnum) to blockbrew's ScriptFlags bitmask. An unknown token
// is returned as an error so the driver skips the row rather than miscounting.
func buildFlags(tokens []string) (script.ScriptFlags, error) {
	var f script.ScriptFlags
	for _, t := range tokens {
		switch t {
		case "P2SH":
			f |= script.ScriptVerifyP2SH
		case "STRICTENC":
			f |= script.ScriptVerifyStrictEncoding
		case "DERSIG":
			f |= script.ScriptVerifyDERSig
		case "LOW_S":
			f |= script.ScriptVerifyLowS
		case "SIGPUSHONLY":
			f |= script.ScriptVerifySigPushOnly
		case "MINIMALDATA":
			f |= script.ScriptVerifyMinimalData
		case "NULLDUMMY":
			f |= script.ScriptVerifyNullDummy
		case "DISCOURAGE_UPGRADABLE_NOPS":
			f |= script.ScriptVerifyDiscourageUpgradableNops
		case "CLEANSTACK":
			f |= script.ScriptVerifyCleanStack
		case "MINIMALIF":
			f |= script.ScriptVerifyMinimalIf
		case "NULLFAIL":
			f |= script.ScriptVerifyNullFail
		case "CHECKLOCKTIMEVERIFY":
			f |= script.ScriptVerifyCLTV
		case "CHECKSEQUENCEVERIFY":
			f |= script.ScriptVerifyCSV
		case "WITNESS":
			f |= script.ScriptVerifyWitness
		case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
			f |= script.ScriptVerifyDiscourageUpgradableWitnessProgram
		case "WITNESS_PUBKEYTYPE":
			f |= script.ScriptVerifyWitnessPubKeyType
		case "CONST_SCRIPTCODE":
			f |= script.ScriptVerifyConstScriptCode
		case "TAPROOT":
			f |= script.ScriptVerifyTaproot
		case "DISCOURAGE_UPGRADABLE_PUBKEYTYPE":
			f |= script.ScriptVerifyDiscourageUpgradablePubKeyType
		case "DISCOURAGE_OP_SUCCESS":
			f |= script.ScriptVerifyDiscourageOpSuccess
		case "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
			f |= script.ScriptVerifyDiscourageUpgradableTaprootVersion
		default:
			return 0, fmt.Errorf("unknown flag token: %s", t)
		}
	}
	return f, nil
}

// makeCreditingTx replicates Core's BuildCreditingTransaction
// (test/util/transaction_utils.cpp): version 1, locktime 0, one input with a
// null prevout (zero hash, index 0xFFFFFFFF) and scriptSig OP_0 OP_0
// (CScriptNum(0) << CScriptNum(0) => bytes 0x00 0x00), sequence 0xFFFFFFFF;
// one output with the test scriptPubKey and the given amount.
func makeCreditingTx(scriptPubKey []byte, amount int64) *wire.MsgTx {
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
				Value:    amount,
				PkScript: scriptPubKey,
			},
		},
		LockTime: 0,
	}
}

// makeSpendingTx replicates Core's BuildSpendingTransaction: version 1,
// locktime 0, one input spending crediting vout 0 (prevout hash = crediting
// txid, computed via blockbrew's OWN MsgTx.TxHash) with the test scriptSig +
// witness, sequence 0xFFFFFFFF; one empty-script output with the same amount.
func makeSpendingTx(creditingTx *wire.MsgTx, scriptSig []byte, witness [][]byte) *wire.MsgTx {
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
				Witness:         witness,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    creditingTx.TxOut[0].Value,
				PkScript: nil,
			},
		},
		LockTime: 0,
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// process handles one request line, returning the response JSON line.
// It dispatches on the "op" field, defaulting to "verifyscript" for
// back-compat with the script_tests driver.
func process(line []byte) string {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("json: "+err.Error()))
	}

	switch req.Op {
	case "", "verifyscript":
		return processVerifyScript(&req)
	case "verifytx":
		return processVerifyTx(&req)
	default:
		return fmt.Sprintf(`{"error":%s}`, jsonString("unknown op: "+req.Op))
	}
}

// processVerifyScript handles the original verifyscript op: rebuild
// Core's synthetic credit/spend tx pair and run VerifyScript once.
func processVerifyScript(req *request) string {
	scriptSig, err := hex.DecodeString(req.ScriptSigHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("scriptSig_hex: "+err.Error()))
	}
	scriptPubKey, err := hex.DecodeString(req.ScriptPubKeyHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("scriptPubKey_hex: "+err.Error()))
	}

	var witness [][]byte
	for _, w := range req.Witness {
		wb, err := hex.DecodeString(w)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("witness elem: "+err.Error()))
		}
		witness = append(witness, wb)
	}

	flags, err := buildFlags(req.Flags)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}

	credit := makeCreditingTx(scriptPubKey, req.AmountSats)
	spend := makeSpendingTx(credit, scriptSig, witness)

	// Single-input spend: prevOuts holds the one spent output (needed for
	// BIP-143 / BIP-341 sighash amounts + scriptCode).
	prevOuts := []*wire.TxOut{
		{Value: req.AmountSats, PkScript: scriptPubKey},
	}

	verifyErr := script.VerifyScript(scriptSig, scriptPubKey, spend, 0, flags, req.AmountSats, prevOuts)
	if verifyErr == nil {
		return `{"result":true}`
	}
	return fmt.Sprintf(`{"result":false,"reason":%s}`, jsonString(verifyErr.Error()))
}

// processVerifyTx mirrors transaction_tests.cpp::CheckTxScripts over a
// REAL tx: deserialize tx_hex with blockbrew's OWN wire deserializer
// (handles the BIP144 segwit marker/flag + per-input witnesses), build
// the prevout->(scriptPubKey, amount) map, then run VerifyScript per
// input with the sighash computed over THE REAL TX so legacy / BIP-143 /
// BIP-341 commit to the actual surrounding transaction. Valid iff ALL
// inputs pass; reject on the FIRST failing input.
func processVerifyTx(req *request) string {
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx_hex: "+err.Error()))
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx deserialize: "+err.Error()))
	}

	flags, err := buildFlags(req.Flags)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}

	// Build the prevout map keyed by OutPoint (wire-order txid + vout) ->
	// (scriptPubKey bytes, amount sats). The request txid is DISPLAY-ORDER
	// hex; wire.NewHash256FromHex reverses it to wire order, matching the
	// deserialized tx's prevout hashes byte-for-byte.
	type prevVal struct {
		pkScript []byte
		amount   int64
	}
	prevMap := make(map[wire.OutPoint]prevVal)
	for _, p := range req.Prevouts {
		h, err := wire.NewHash256FromHex(p.Txid)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout txid: "+err.Error()))
		}
		spk, err := hex.DecodeString(p.ScriptPubKeyHex)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout scriptPubKey_hex: "+err.Error()))
		}
		// amount defaults to 0 when absent (the driver passes 0; Core's
		// map_prevout_values returns 0 for an unlisted prevout).
		prevMap[wire.OutPoint{Hash: h, Index: p.Vout}] = prevVal{pkScript: spk, amount: p.AmountSats}
	}

	// Assemble the per-input prevOuts vector in the tx's OWN input order so
	// prevOuts[i] lines up with input i. blockbrew's engine indexes
	// prevOuts by txIdx for the spent scriptPubKey and hands the whole
	// slice to CalcTaprootSignatureHash (BIP-341 commits to ALL prevouts).
	n := len(tx.TxIn)
	prevOuts := make([]*wire.TxOut, n)
	for i, in := range tx.TxIn {
		pv, ok := prevMap[in.PreviousOutPoint]
		if !ok {
			// Corpus always supplies every spent input; a miss is a
			// malformed/unsupported row -> {"error"} so the driver SKIPS
			// it rather than fake-passing.
			return fmt.Sprintf(`{"error":%s}`,
				jsonString(fmt.Sprintf("no prevout for input %d (%s:%d)",
					i, in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)))
		}
		prevOuts[i] = &wire.TxOut{Value: pv.amount, PkScript: pv.pkScript}
	}

	// Per-input VerifyScript over the real tx. Reject on first failure,
	// matching Core's `i < vin.size() && fValid` short-circuit.
	for i := 0; i < n; i++ {
		spk := prevOuts[i].PkScript
		amount := prevOuts[i].Value
		verifyErr := script.VerifyScript(
			tx.TxIn[i].SignatureScript, spk, &tx, i, flags, amount, prevOuts)
		if verifyErr != nil {
			reason := fmt.Sprintf("input %d: %s", i, verifyErr.Error())
			return fmt.Sprintf(`{"valid":false,"reason":%s}`, jsonString(reason))
		}
	}

	return `{"valid":true}`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// Allow long lines (large scripts / witnesses).
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := safeProcess(line)
		fmt.Fprintln(out, resp)
		out.Flush()
	}
}

// safeProcess wraps process with a panic recover so a single bad row reports
// {"error":...} (skipped by the driver) instead of crashing the whole run.
func safeProcess(line []byte) (resp string) {
	defer func() {
		if r := recover(); r != nil {
			resp = fmt.Sprintf(`{"error":%s}`, jsonString(fmt.Sprintf("panic in verify_script: %v", r)))
		}
	}()
	return process(line)
}
