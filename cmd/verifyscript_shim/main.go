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
//  1. map the 22 Core flag tokens to blockbrew's ScriptFlags bitmask,
//  2. rebuild Core's crediting + spending tx pair using blockbrew's OWN
//     wire.MsgTx serialization + TxHash so the sighash matches byte-for-byte
//     (mirrors cmd/script_test/main.go makeCreditingTx/makeSpendingTx, which
//     in turn mirrors bitcoin-core test/util/transaction_utils.cpp),
//  3. call VerifyScript and report the accept/reject decision.
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
//
// Third op `checktx` (CheckTransaction-level, context-free structural
// validation): mirrors bitcoin-core/src/consensus/tx_check.cpp::
// CheckTransaction. These are the structural checks `verifytx` (per-input
// VerifyScript only) cannot catch — empty vin/vout, serialized size /
// weight limit, output value range and running total, duplicate inputs,
// coinbase scriptSig length, and null prevout in a non-coinbase. We
// deserialize tx_hex and call blockbrew's OWN
// consensus.CheckTransactionSanity (internal/consensus/txvalidation.go:58),
// so a divergence here is a real blockbrew consensus bug, not a
// reimplementation in the shim. No UTXO / chain state is needed.
//
//	request:  {"op":"checktx","tx_hex":"..."}
//	response: {"valid":true}                   (structurally valid)
//	          {"valid":false,"reason":"..."}   (CheckTransaction rejected)
//	          {"error":"..."}                  (could not deserialize)
//
// Fourth op `connecttx` (connect-time economic check): mirrors
// bitcoin-core/src/consensus/tx_verify.cpp:164-214
// Consensus::CheckTxInputs — the no-inflation rule (value-in >= value-out,
// bad-txns-in-belowout), per-input + running-sum MoneyRange
// (bad-txns-inputvalues-outofrange), coinbase maturity of 100 confirmations
// (bad-txns-premature-spend-of-coinbase), and missing/spent inputs
// (bad-txns-inputs-missingorspent). We seed an in-memory UTXO view with one
// coin per prevout (value / height / is_coinbase) and call blockbrew's REAL
// consensus.CheckTransactionInputs(tx, spend_height, view); an OMITTED prevout
// models a missing/spent input. SCRIPT verification is intentionally NOT run
// (this op isolates the ECONOMIC verdict). The shim does NOT re-implement any
// of these rules — it seeds the view and reports CheckTransactionInputs's
// verdict, mapping the sentinel error to the Core bad-txns-* token.
//
//	request:  {"op":"connecttx","tx_hex":"...",
//	           "prevouts":[{"txid":"<display-hex>","vout":N,
//	                        "scriptPubKey_hex":"...","value_sats":0,
//	                        "height":0,"is_coinbase":false},...],
//	           "spend_height":0}
//	response: {"valid":true,"fee_sats":0}      (inputs satisfy CheckTxInputs)
//	          {"valid":false,"reason":"..."}   (bad-txns-* economic reject)
//	          {"error":"..."}                  (could not deserialize)
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"

	"github.com/hashhog/blockbrew/internal/consensus"
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

	// verifytx / connecttx op fields.
	TxHex    string        `json:"tx_hex"`
	Prevouts []prevoutSpec `json:"prevouts"`

	// connecttx op field: nSpendHeight, the height the tx is being
	// connected at (drives coinbase-maturity confirmations). Reused by
	// checkblock as the height the FULL block is being connected at.
	SpendHeight int32 `json:"spend_height"`

	// checkblock op fields. The FINAL (already-mutated) block bytes are
	// validated AS-IS — the shim does NOT recompute the merkle root.
	BlockHex    string `json:"block_hex"`
	SkipPOW     bool   `json:"skip_pow"`
	SkipScripts bool   `json:"skip_scripts"`

	// nextwork op fields.
	Network   string       `json:"network"`
	Height    int32        `json:"height"`
	BlockTime int64        `json:"block_time"`
	Last      *nextworkHdr `json:"last"`
	First     *nextworkHdr `json:"first"`

	// checkheader op fields. HeaderHex is the 80-byte header under test; Prev is
	// the parent-block context (bits/time/hash); MTP is the median-time-past of
	// the parent's 11 ancestors (drives time-too-old); CurrentTime is the
	// injected wall clock (0 = disable time-too-new); ExpectedBits optionally
	// overrides the GetNextWorkRequired result to isolate a non-difficulty gate.
	HeaderHex    string        `json:"header_hex"`
	Prev         *checkHdrPrev `json:"prev"`
	MTP          int64         `json:"mtp"`
	CurrentTime  int64         `json:"current_time"`
	ExpectedBits string        `json:"expected_bits"`

	// merkleroot op fields.
	Txids []string `json:"txids"`

	// reorg op fields. fork_utxo is the WORKING coins-view (pre-disconnect view
	// for disconnect-vectors, fork-point view otherwise), seeded EXACTLY like
	// connecttx/checkblock prevouts. disconnect = old-branch blocks tip-first
	// (0+), connect = ordered side-branch blocks. Work hexes are 32-byte BE.
	ForkUTXO      []prevoutSpec  `json:"fork_utxo"`
	Disconnect    []disconnectBk `json:"disconnect"`
	Connect       []connectBk    `json:"connect"`
	OldTipWorkHex string         `json:"old_tip_work_hex"`
	NewTipWorkHex string         `json:"new_tip_work_hex"`
}

// disconnectBk is one old-branch block to undo: its final bytes, the height it
// occupied, and the per-non-coinbase-tx undo coins (one `vin` list per tx,
// keyed by tx_index within the block). It mirrors Core's per-block CBlockUndo
// (vtxundo[i] holds the spent coins for vtx[i+1]).
type disconnectBk struct {
	BlockHex string     `json:"block_hex"`
	Height   int32      `json:"height"`
	Undo     []txUndoBk `json:"undo"`
}

// txUndoBk is the undo record for one non-coinbase tx in a disconnect block:
// the tx's index within the block and the coins its inputs spent (ordered by
// input). Mirrors Core's CTxUndo (one Coin per CTxIn).
type txUndoBk struct {
	TxIndex int           `json:"tx_index"`
	Vin     []prevoutSpec `json:"vin"`
}

// connectBk is one ordered side-branch block to connect: its final bytes, the
// height it occupies (flags + economics derive from THIS height), and the MTP
// of its parent for BIP-68 time-based sequence locks (0 when unavailable —
// height-based locks are still enforced).
type connectBk struct {
	BlockHex string `json:"block_hex"`
	Height   int32  `json:"height"`
	PrevMTP  uint32 `json:"prev_mtp"`
}

// nextworkHdr is one block-header context entry for the nextwork op: a height
// plus its compact bits (8-lowercase-hex, Core getblockheader format) and unix
// timestamp. "first" is present only on retarget-boundary rows (H%2016==0).
type nextworkHdr struct {
	Height int32  `json:"height"`
	Bits   string `json:"bits"`
	Time   uint32 `json:"time"`
}

// checkHdrPrev is the parent-block context for the checkheader op: the parent's
// compact bits (8-hex), its unix timestamp, and its display-order hash. bits +
// time drive GetNextWorkRequired (bad-diffbits) and the BIP-94 timewarp floor;
// hash is the value ContextualCheckBlockHeader would read as the header's
// PrevBlock (informational here — the parent node is synthesized directly).
type checkHdrPrev struct {
	Bits string `json:"bits"`
	Time uint32 `json:"time"`
	Hash string `json:"hash"`
}

// prevoutSpec is one entry of the verifytx / connecttx "prevouts" array: a
// spent output keyed by (txid display-hex, vout) with its scriptPubKey +
// amount. verifytx reads AmountSats; connecttx reads ValueSats + Height +
// IsCoinbase (the coin's nValue / nHeight / fCoinBase as in Core's Coin).
type prevoutSpec struct {
	Txid            string `json:"txid"`
	Vout            uint32 `json:"vout"`
	ScriptPubKeyHex string `json:"scriptPubKey_hex"`
	AmountSats      int64  `json:"amount_sats"`

	// connecttx coin fields.
	ValueSats  int64 `json:"value_sats"`
	Height     int32 `json:"height"`
	IsCoinbase bool  `json:"is_coinbase"`
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
	case "checktx":
		return processCheckTx(&req)
	case "connecttx":
		return processConnectTx(&req)
	case "checkblock":
		return processCheckBlock(&req)
	case "checkheader":
		return processCheckHeader(&req)
	case "reorg":
		return processReorg(&req)
	case "nextwork":
		return processNextWork(&req)
	case "merkleroot":
		return processMerkleRoot(&req)
	case "subsidy":
		return processSubsidy(&req)
	default:
		return fmt.Sprintf(`{"error":%s}`, jsonString("unknown op: "+req.Op))
	}
}

// processCheckTx mirrors bitcoin-core/src/consensus/tx_check.cpp::
// CheckTransaction (the context-free structural checks). It deserializes
// tx_hex with blockbrew's OWN wire deserializer, then delegates to
// blockbrew's REAL consensus.CheckTransactionSanity
// (internal/consensus/txvalidation.go:58) — empty vin/vout, serialized
// weight limit, per-output value range + running total, duplicate inputs,
// coinbase scriptSig length, non-coinbase null prevout. No UTXO / chain
// state is consulted. Valid iff CheckTransactionSanity returns nil.
//
// A tx that fails to deserialize is reported as {"error"} so the driver
// SKIPS it rather than fake-passing; the driver itself treats a deserialize
// error on a BADTX row as a reject decision.
func processCheckTx(req *request) string {
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx_hex: "+err.Error()))
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx deserialize: "+err.Error()))
	}

	if verr := consensus.CheckTransactionSanity(&tx); verr != nil {
		return fmt.Sprintf(`{"valid":false,"reason":%s}`, jsonString(verr.Error()))
	}
	return `{"valid":true}`
}

// connectTxReason maps blockbrew's CheckTransactionInputs error to the Core
// bad-txns-* token the corpus uses. The DECISION (valid) is what's scored;
// the token is informational, normalized here to Core's
// consensus/tx_verify.cpp wording. This is NOT a re-implementation of the
// rule — the verdict already came from CheckTransactionInputs; we only
// rename the sentinel error for readability of the divergence log.
func connectTxReason(err error) string {
	switch {
	case errors.Is(err, consensus.ErrMissingInput):
		// Core: "bad-txns-inputs-missingorspent" (CheckTxInputs HaveInputs).
		return "bad-txns-inputs-missingorspent"
	case errors.Is(err, consensus.ErrImmatureCoinbase):
		// Core: "bad-txns-premature-spend-of-coinbase".
		return "bad-txns-premature-spend-of-coinbase"
	case errors.Is(err, consensus.ErrInputTooLarge),
		errors.Is(err, consensus.ErrTotalInputTooLarge):
		// Core: "bad-txns-inputvalues-outofrange" (per-input + running-sum
		// MoneyRange).
		return "bad-txns-inputvalues-outofrange"
	case errors.Is(err, consensus.ErrInsufficientFunds):
		// Core: "bad-txns-in-belowout" (no-inflation: value-in >= value-out).
		return "bad-txns-in-belowout"
	default:
		// Includes the fee-out-of-range guard ("bad-txns-fee-outofrange"),
		// which CheckTransactionInputs already names with the Core token, and
		// any future sentinel. Pass the raw message through.
		return err.Error()
	}
}

// bip30Reason maps blockbrew's CheckBIP30 error (ErrDuplicateTx /
// ErrDuplicateCoinbase, blockvalidation.go:49-50) to the Core token the corpus
// scores on, "bad-txns-BIP30" (validation.cpp:2474). The DECISION (reject) is
// what's scored; this only normalizes the sentinel for the divergence log and
// is NOT a re-implementation of the rule — the verdict came from CheckBIP30.
func bip30Reason(err error) string {
	if errors.Is(err, consensus.ErrDuplicateTx) || errors.Is(err, consensus.ErrDuplicateCoinbase) {
		return "bad-txns-BIP30"
	}
	return err.Error()
}

// processConnectTx drives blockbrew's REAL connect-time economic check
// consensus.CheckTransactionInputs (internal/consensus/txvalidation.go:132),
// the exact mirror of Core's Consensus::CheckTxInputs (tx_verify.cpp:164-214):
//   - no-inflation:        sum(value-in) >= sum(value-out)  (bad-txns-in-belowout)
//   - per-input MoneyRange + running-sum MoneyRange         (bad-txns-inputvalues-outofrange)
//   - coinbase maturity:   COINBASE_MATURITY (100) confs     (bad-txns-premature-spend-of-coinbase)
//   - missing/spent input: prevout absent from the view      (bad-txns-inputs-missingorspent)
//
// We seed an in-memory UTXO VIEW (consensus.NewInMemoryUTXOView) with one coin
// per prevout entry carrying its value / nHeight / fCoinBase, then call
// CheckTransactionInputs(tx, spend_height, view). An OMITTED prevout naturally
// models a missing/spent input because GetUTXO returns nil for it. SCRIPT
// verification is intentionally NOT run here — this op isolates the ECONOMIC
// verdict, so a (separately tested) script failure cannot mask the economic
// decision. The shim does NOT re-implement value-in>=value-out / maturity /
// missing; it only seeds the view and reports CheckTransactionInputs's verdict.
//
// A tx that fails to deserialize is reported as {"error"} so the driver SKIPS
// it rather than fake-passing.
func processConnectTx(req *request) string {
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx_hex: "+err.Error()))
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("tx deserialize: "+err.Error()))
	}

	// Seed the in-memory UTXO view: one coin per prevout entry. The request
	// txid is DISPLAY-ORDER hex; wire.NewHash256FromHex reverses it to wire
	// order so the outpoint key matches the deserialized tx's prevout hashes
	// byte-for-byte (same reversal the verifytx op uses). An OMITTED prevout
	// is simply never added, so GetUTXO returns nil -> ErrMissingInput.
	view := consensus.NewInMemoryUTXOView()
	for _, p := range req.Prevouts {
		h, err := wire.NewHash256FromHex(p.Txid)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout txid: "+err.Error()))
		}
		spk, err := hex.DecodeString(p.ScriptPubKeyHex)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout scriptPubKey_hex: "+err.Error()))
		}
		view.AddUTXO(wire.OutPoint{Hash: h, Index: p.Vout}, &consensus.UTXOEntry{
			Amount:     p.ValueSats,
			PkScript:   spk,
			Height:     p.Height,
			IsCoinbase: p.IsCoinbase,
		})
	}

	// Drive the REAL connect-time economic check. No script verification.
	fee, verr := consensus.CheckTransactionInputs(&tx, req.SpendHeight, view)
	if verr != nil {
		return fmt.Sprintf(`{"valid":false,"reason":%s}`, jsonString(connectTxReason(verr)))
	}
	return fmt.Sprintf(`{"valid":true,"fee_sats":%d}`, fee)
}

// maxPowLimit is an all-0xFF 256-bit target — the maximum representable PoW
// ceiling. It is handed to CheckBlockSanity so the `target > powLimit` branch
// of CheckProofOfWork can never trip for the differential checkblock op. (PoW
// is additionally fully gated off via skip_pow; see processCheckBlock.)
var maxPowLimit = func() *big.Int {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xff
	}
	return new(big.Int).SetBytes(b)
}()

// processCheckBlock drives blockbrew's REAL block-validation gates over a FINAL
// (already-mutated) block, validate-only, in ConnectBlock order — the
// decision-level generalization of connecttx from one tx to a full block. It
// mirrors Bitcoin Core's CheckBlock -> ContextualCheckBlock -> ConnectBlock
// pipeline (validation.cpp). The block bytes are validated AS-IS: the shim does
// NOT recompute the header merkle root, so a corrupted-merkle mutant reaches
// blockbrew's OWN merkle gate in CheckBlockSanity.
//
//	(1) CheckBlockSanity(block, maxPowLimit, skip_pow):
//	    coinbase-first / single-coinbase / per-tx sanity / merkle-root match
//	    (CVE-2012-2459 mutation) / block weight. PoW is gated off by skip_pow
//	    (Core CheckBlock fCheckPOW=false) because the FINAL mutated hash no
//	    longer satisfies the unchanged bits target — without the gate every
//	    header-mutating mutant would dead-gate on high-hash before its real
//	    body gate ran.
//	(2) CheckBlockContext(block, &synthPrevHeader, spend_height, MainnetParams):
//	    BIP34/66/65 version gates + BIP34 coinbase-height + segwit witness
//	    commitment/malleation + final-tx. MTP is left at the zero variadic
//	    default (skipped) — no chain history is available in the shim and the
//	    corpus carries no MTP-dependent mutant. A synthetic prevHeader is passed
//	    (its only consensus use here would be a difficulty re-check, which
//	    CheckBlockContext deliberately skips — see its comment).
//	(3) ConnectBlock gates RE-EXPRESSED in Core order over the seeded view:
//	    per non-coinbase tx CheckTransactionInputs(tx, spend_height, view)
//	    accumulating totalFees; per-tx nSigOpsCost =
//	    CountSigOpsInaccurate(scriptSig+pkScript)*WitnessScaleFactor +
//	    CountP2SHSigOps + CountWitnessSigOps, reject > MaxBlockSigOpsCost;
//	    ParallelScriptValidationCached(block, view, GetBlockScriptFlags(height,
//	    MainnetParams, blockHash), sigCache) unless skip_scripts; finally
//	    coinbaseValue <= CalcBlockSubsidy(height)+totalFees (ErrBadCoinbaseValue).
//
// MAINNET params throughout (NOT regtest — regtest's subsidy schedule breaks
// bad-cb-amount and its deployment heights are wrong). spend_height 709742 is
// post-Taproot so every mainnet deployment is active. The UTXO view is seeded
// from prevouts with the SAME display->wire txid reversal + one-coin-per-prevout
// plumbing as processConnectTx; an omitted prevout naturally models a missing
// input (GetUTXO -> nil).
//
// valid iff every gate passes. The reason TOKEN is advisory; the driver scores
// only the valid bool. A block that fails to deserialize is reported as
// {"error"} so the driver treats it as a reject decision without fake-passing.
func processCheckBlock(req *request) string {
	blockBytes, err := hex.DecodeString(req.BlockHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("block_hex: "+err.Error()))
	}

	var block wire.MsgBlock
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("block deserialize: "+err.Error()))
	}

	if len(block.Transactions) == 0 {
		return fmt.Sprintf(`{"valid":false,"reason":%s}`, jsonString("bad-blk-length-no-tx"))
	}

	params := consensus.MainnetParams()
	height := req.SpendHeight

	// Seed the in-memory UTXO view: one coin per prevout (reusing the exact
	// connecttx seeding — display-order txid reversed to wire order via
	// wire.NewHash256FromHex; an OMITTED prevout is never added so GetUTXO
	// returns nil -> missing input).
	//
	// `view` is the SPEND-TRACKING connect-loop view: inputs are removed as each
	// tx is processed so a later tx that re-spends an already-spent outpoint
	// (e.g. the bad-txns-duplicate mutant, two identical txs) is rejected with
	// bad-txns-inputs-missingorspent — mirroring Core ConnectBlock's UpdateCoins
	// + the CVE-2018-17144 duplicate-input semantics.
	//
	// `scriptView` is a NON-spending snapshot holding every prevout (external +
	// all intra-block-created outputs). ParallelScriptValidationCached runs
	// AFTER the connect loop and resolves each input's scriptPubKey via the
	// view; if we ran it over the spend-tracking `view` the inputs would already
	// be gone. Core keeps the prevouts available to its script-check pass the
	// same way (the CCoinsViewCache retains spent coins until flush). Both views
	// are seeded identically from the external prevouts.
	view := consensus.NewInMemoryUTXOView()
	scriptView := consensus.NewInMemoryUTXOView()
	for _, p := range req.Prevouts {
		h, err := wire.NewHash256FromHex(p.Txid)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout txid: "+err.Error()))
		}
		spk, err := hex.DecodeString(p.ScriptPubKeyHex)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("prevout scriptPubKey_hex: "+err.Error()))
		}
		op := wire.OutPoint{Hash: h, Index: p.Vout}
		view.AddUTXO(op, &consensus.UTXOEntry{
			Amount:     p.ValueSats,
			PkScript:   spk,
			Height:     p.Height,
			IsCoinbase: p.IsCoinbase,
		})
		scriptView.AddUTXO(op, &consensus.UTXOEntry{
			Amount:     p.ValueSats,
			PkScript:   bytes.Clone(spk),
			Height:     p.Height,
			IsCoinbase: p.IsCoinbase,
		})
	}

	// Gates (1)-(3) run via the shared connect-block driver. checkblock uses the
	// MAINNET halving interval (its corpus computes coinbase amounts on the
	// mainnet schedule) and MTP omitted (no MTP-dependent corpus mutant).
	res := runConnectBlockGates(&block, view, scriptView, params, height,
		consensus.SubsidyHalvingInterval, 0, req.SkipPOW, req.SkipScripts)
	if !res.ok {
		return fmt.Sprintf(`{"valid":false,"reason":%s}`, jsonString(res.reason))
	}
	return `{"valid":true}`
}

// checkHeaderReason maps a blockbrew header-validation error to the Core bip22
// reject token the checkheader corpus scores on. The DECISION (accept bool) is
// what's scored primarily; this normalizes the sentinel for the divergence log
// and is NOT a re-implementation of any rule — the verdict already came from
// CheckProofOfWork / ContextualCheckBlockHeader. The bad-version token carries
// the offending version in Core's `bad-version(0x%08x)` format (validation.cpp:
// 4112-4124 strprintf), matching the rustoshi reference corpus's expected token.
func checkHeaderReason(err error, version int32) string {
	switch {
	case errors.Is(err, consensus.ErrNegativeTarget),
		errors.Is(err, consensus.ErrTargetTooHigh),
		errors.Is(err, consensus.ErrDifficultyTooLow):
		// CheckProofOfWork: hash>target, target>powLimit, negative/overflow —
		// Core folds all into the single CheckBlockHeader "high-hash" token.
		return "high-hash"
	case errors.Is(err, consensus.ErrBadDifficulty):
		return "bad-diffbits"
	case errors.Is(err, consensus.ErrTimestampTooEarly):
		return "time-too-old"
	case errors.Is(err, consensus.ErrTimeWarpAttack):
		return "time-timewarp-attack"
	case errors.Is(err, consensus.ErrTimestampTooFarFuture):
		return "time-too-new"
	case errors.Is(err, consensus.ErrBlockVersionTooLow):
		return fmt.Sprintf("bad-version(0x%08x)", uint32(version))
	default:
		return err.Error()
	}
}

// processCheckHeader drives blockbrew's REAL header-level reject gates over an
// EXPLICIT (header, prev-context) tuple — never a live tip/clock — mirroring
// Bitcoin Core's CheckBlockHeader (PoW) -> ContextualCheckBlockHeader
// (validation.cpp:4080-4124) split. It is the header-only differential the
// checkblock op cannot reach: checkblock's CheckBlockContext covers only
// BIP34-height + witness commitment, never the difficulty / time / version
// header gates.
//
// It calls the two REAL consensus functions:
//
//   - consensus.CheckProofOfWork(hash, bits, powLimit) for the high-hash class
//     when skip_pow=false (the STRICT path enforcing target<=powLimit — folds
//     hash>target AND nBits-malformed/target>powLimit into one "high-hash"
//     token, exactly as CheckBlockHeader does);
//
//   - (*HeaderIndex).ContextualCheckBlockHeader(header, parent, height, mtp,
//     current_time, expectedBitsOverride, checkVersion=true) for bad-diffbits /
//     time-too-old / timewarp / time-too-new / bad-version. The expected nBits
//     is computed by blockbrew's OWN GetNextWorkRequired over the prev context
//     (NOT the header's claimed bits) unless an explicit expected_bits override
//     isolates a later gate at a retarget boundary. current_time is injected
//     (0 = disable time-too-new); mtp is injected directly.
//
//     request:  {"op":"checkheader","network":"...",
//     "header_hex":"<80-byte header>","height":<int>,
//     "prev":{"bits":"<hex>","time":<u32>,"hash":"<display-hex>"},
//     "first":{height,bits,time}  // opt; retarget-boundary recompute,
//     "mtp":<int64>,"current_time":<int64; 0=disable>,
//     "skip_pow":<bool; default false>,"expected_bits":"<hex>"  // opt}
//     response: {"accept":true} | {"accept":false,"reason":"<bip22 token>"}
func processCheckHeader(req *request) string {
	params, err := paramsForNetwork(req.Network)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}
	if req.Prev == nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("checkheader: missing prev"))
	}

	headerBytes, err := hex.DecodeString(req.HeaderHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("header_hex: "+err.Error()))
	}
	if len(headerBytes) != 80 {
		return fmt.Sprintf(`{"error":%s}`, jsonString(fmt.Sprintf("header_hex not 80 bytes: %d", len(headerBytes))))
	}
	var header wire.BlockHeader
	if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("header deserialize: "+err.Error()))
	}

	height := req.Height

	prevBits, err := strconv.ParseUint(req.Prev.Bits, 16, 32)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("prev.bits: "+err.Error()))
	}

	// ---- Stage 1: high-hash (CheckProofOfWork, strict path) ----
	// Mirrors Core CheckBlockHeader (validation.cpp): the single high-hash token
	// covers hash>target AND nBits malformed/target>powLimit (DeriveTarget).
	// skip_pow defaults FALSE for checkheader (the whole point is to exercise the
	// strict PoW over a crafted header), unlike checkblock whose mutated body no
	// longer meets target.
	if !req.SkipPOW {
		if perr := consensus.CheckProofOfWork(header.BlockHash(), header.Bits, params.PowLimit); perr != nil {
			return fmt.Sprintf(`{"accept":false,"reason":%s}`, jsonString(checkHeaderReason(perr, header.Version)))
		}
	}

	// ---- Build the synthetic parent BlockNode (pindexPrev) ----
	// height-1, prev.bits, prev.time. prev.hash becomes the node hash so a
	// retarget-boundary "first" (if supplied) wires as parent.Parent for the
	// real GetNextWorkRequired recompute; off-boundary corpus rows never reach
	// the provider's ancestor lookup.
	parent := &consensus.BlockNode{
		Height: height - 1,
		Header: wire.BlockHeader{
			Timestamp: req.Prev.Time,
			Bits:      uint32(prevBits),
		},
		TotalWork: big.NewInt(0),
	}
	if req.Prev.Hash != "" {
		if h, herr := wire.NewHash256FromHex(req.Prev.Hash); herr == nil {
			parent.Hash = h
		}
	}

	// Real header index as the BlockProvider for GetNextWorkRequired's ancestor
	// lookups (only exercised on a no-override retarget boundary).
	idx := consensus.NewHeaderIndex(params)

	// Optional retarget-boundary "first" block (height H-2016): wire as
	// parent.Parent so getTestnetNonMinDiffBits / CalculateNextWorkRequired can
	// walk to it via GetPrevHeader, matching the rustoshi reference. The corpus's
	// boundary rows instead supply expected_bits, so this path is defensive.
	if req.First != nil {
		fbits, ferr := strconv.ParseUint(req.First.Bits, 16, 32)
		if ferr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("first.bits: "+ferr.Error()))
		}
		parent.Parent = &consensus.BlockNode{
			Height: req.First.Height,
			Header: wire.BlockHeader{
				Timestamp: req.First.Time,
				Bits:      uint32(fbits),
			},
			TotalWork: big.NewInt(0),
		}
	}

	// ---- expected_bits override (isolates a non-difficulty gate) ----
	var expectedBitsOverride *uint32
	if req.ExpectedBits != "" {
		eb, eerr := strconv.ParseUint(req.ExpectedBits, 16, 32)
		if eerr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("expected_bits: "+eerr.Error()))
		}
		v := uint32(eb)
		expectedBitsOverride = &v
	}

	// ---- Stage 2: ContextualCheckBlockHeader (bad-diffbits / time / version) ----
	// checkVersion=true for full Core-parity header validation (production leaves
	// the version gate to CheckBlockContext; the differential exercises it here).
	if cerr := idx.ContextualCheckBlockHeader(
		header, parent, height,
		req.MTP, req.CurrentTime, expectedBitsOverride, true,
	); cerr != nil {
		return fmt.Sprintf(`{"accept":false,"reason":%s}`, jsonString(checkHeaderReason(cerr, header.Version)))
	}

	return `{"accept":true}`
}

// connectGateResult is the verdict of runConnectBlockGates: ok=true means every
// gate passed; on a reject, reason carries the canonical token and fee carries
// the accumulated fees of the txs that passed before the failure (0 on a
// pre-loop sanity/context reject).
type connectGateResult struct {
	ok     bool
	reason string
	fee    int64
}

// runConnectBlockGates drives blockbrew's REAL block-validation gates over an
// EXTERNALLY-supplied, mutable coins-view in ConnectBlock order — the single
// shared engine behind both the checkblock op (fresh per-tx prevout seeding)
// and the reorg op's CONNECT phase (a working view threaded across side-branch
// blocks). It mirrors Bitcoin Core CheckBlock -> ContextualCheckBlock ->
// ConnectBlock (validation.cpp). Gates in order:
//
//	(1) CheckBlockSanity(block, maxPowLimit, skipPow): coinbase-first /
//	    single-coinbase / per-tx sanity / merkle-root match / weight. PoW gated
//	    by skipPow (the FINAL crafted/mutated hash no longer meets bits).
//	(2) CheckBlockContext(block, synthPrevHeader, height, params, prevMTP):
//	    BIP34/66/65 + segwit commitment + final-tx. prevMTP feeds the block's
//	    median-time-past context (0 = unavailable; height-based locks still run).
//	(3) ConnectBlock economic + sigop + script + coinbase-value gates over the
//	    seeded `view`: per non-coinbase tx CheckTransactionInputs accumulating
//	    fees; block-wide sigop cost cap; ParallelScriptValidationCached at
//	    GetBlockScriptFlags(height,params,hash) unless skipScripts; finally
//	    coinbaseValue <= CalcBlockSubsidyForInterval(height,halvingInterval)+fees.
//
// `view` is the SPEND-TRACKING connect view (inputs removed as each tx is
// processed, outputs added, so an intra-block re-spend / duplicate fails the
// next GetUTXO — CVE-2018-17144). `scriptView` is a NON-spending snapshot that
// must already hold every external prevout the script pass will resolve; this
// fn adds each tx's outputs to BOTH so an intra-block child's scriptPubKey is
// available to the post-loop ParallelScriptValidationCached. The reorg connect
// loop carries `view` to the next block (real ReorgTo semantics) and rebuilds a
// fresh scriptView snapshot per block. This fn does NOT re-implement any rule —
// it calls blockbrew's real CheckBlockSanity / CheckBlockContext /
// CheckTransactionInputs / sigop counters / ParallelScriptValidationCached /
// CalcBlockSubsidyForInterval and reports their verdict.
func runConnectBlockGates(block *wire.MsgBlock, view, scriptView *consensus.InMemoryUTXOView,
	params *consensus.ChainParams, height int32, halvingInterval int32, prevMTP uint32,
	skipPow, skipScripts bool) connectGateResult {

	// (1) Context-free sanity (PoW gated by skipPow).
	if verr := consensus.CheckBlockSanity(block, maxPowLimit, skipPow); verr != nil {
		return connectGateResult{reason: verr.Error()}
	}

	// (2) Contextual checks at this height. A synthetic prevHeader (its only use
	// would be a difficulty recheck that CheckBlockContext skips). prevMTP feeds
	// the block's median-time-past context for time-based locks.
	synthPrevHeader := &wire.BlockHeader{
		Version:   block.Header.Version,
		PrevBlock: block.Header.PrevBlock,
		Bits:      block.Header.Bits,
		Timestamp: block.Header.Timestamp,
	}
	if prevMTP != 0 {
		if verr := consensus.CheckBlockContext(block, synthPrevHeader, height, params, prevMTP); verr != nil {
			return connectGateResult{reason: verr.Error()}
		}
	} else if verr := consensus.CheckBlockContext(block, synthPrevHeader, height, params); verr != nil {
		return connectGateResult{reason: verr.Error()}
	}

	// (3a) BIP-30 (CVE-2012-1909 duplicate-txid / coin-overwrite): reject if any
	// output (txid,o) of any block tx ALREADY has an unspent coin in the view —
	// the tx would overwrite it. Runs at the TOP of ConnectBlock, over the PARENT
	// view (before this block's coinbase/tx outputs are added below), exactly as
	// Core does (validation.cpp:2467-2475) and exactly where blockbrew's
	// production ConnectBlock calls it (chainmanager.go:619). We delegate to
	// blockbrew's OWN consensus.CheckBIP30 — the same fn the live node uses — so a
	// divergence here is a real blockbrew consensus bug, NOT a shim re-expression.
	//
	// The BIP34 short-circuit (Core: skip the HaveCoin scan once BIP34 is active
	// on this chain, i.e. height>params.BIP34Height and the block at BIP34Height
	// matches params.BIP34Hash, unless height>=BIP34_IMPLIES_BIP30_LIMIT) is
	// driven by the ancestorHashAt callback. The shim has no chain history, so we
	// model a node that IS on the canonical mainnet chain: a query for the
	// BIP34Height ancestor returns params.BIP34Hash (the only height CheckBIP30
	// ever queries). This is the faithful answer GetAncestorHashAtHeight returns
	// for any block descending from the real BIP34 block — so pre-BIP34 heights
	// (91000: height<=BIP34Height, branch skipped) still ENFORCE the scan, while
	// post-BIP34 heights (400000) SHORT-CIRCUIT, matching Core.
	blockHashBIP30 := block.Header.BlockHash()
	bip30Ancestor := func(h int32) (wire.Hash256, bool) {
		if h == params.BIP34Height {
			return params.BIP34Hash, true
		}
		return wire.Hash256{}, false
	}
	if verr := consensus.CheckBIP30(block, height, blockHashBIP30, params, view, bip30Ancestor); verr != nil {
		return connectGateResult{reason: bip30Reason(verr)}
	}

	// (3) ConnectBlock economic + sigop + script + coinbase-value gates, in Core
	// order over the seeded view.
	var totalFees int64
	var nSigOpsCost int

	coinbase := block.Transactions[0]
	for _, txIn := range coinbase.TxIn {
		nSigOpsCost += consensus.CountSigOpsInaccurate(txIn.SignatureScript) * consensus.WitnessScaleFactor
	}
	for _, txOut := range coinbase.TxOut {
		nSigOpsCost += consensus.CountSigOpsInaccurate(txOut.PkScript) * consensus.WitnessScaleFactor
	}

	// Add coinbase outputs first (ConnectBlock i==0), then per non-coinbase tx:
	// check inputs -> count sigops (prevouts still present) -> SPEND inputs ->
	// ADD outputs. scriptView only AddCoins (never spends).
	view.AddTxOutputs(coinbase, height)
	scriptView.AddTxOutputs(coinbase, height)

	for i := 1; i < len(block.Transactions); i++ {
		tx := block.Transactions[i]

		fee, verr := consensus.CheckTransactionInputs(tx, height, view)
		if verr != nil {
			return connectGateResult{reason: connectTxReason(verr), fee: totalFees}
		}
		totalFees += fee
		if totalFees > consensus.MaxMoney {
			return connectGateResult{reason: "bad-txns-accumulated-fee-outofrange", fee: totalFees}
		}

		// BIP-68 relative sequence-locks, enforced after CSV activation — the
		// exact gate blockbrew's production ConnectBlock applies
		// (chainmanager.go:774-798) right after CheckTransactionInputs and before
		// the sigop count, mirroring Bitcoin Core ConnectBlock
		// (validation.cpp:2549-2561: CalculateSequenceLocks +
		// SequenceLocks/EvaluateSequenceLocks -> reject "bad-txns-nonfinal"). It
		// was OMITTED from runConnectBlockGates (the same shape as the previously
		// fixed BIP-30 omission), so checkblock/reorg never reached it and a
		// not-yet-mature relative-height lock false-ACCEPTED. We delegate to
		// blockbrew's OWN consensus.CalculateSequenceLocks /
		// consensus.EvaluateSequenceLocks (the same fns the live node + mempool
		// call) — a divergence here is a real blockbrew consensus bug, not a shim
		// re-expression.
		//
		// fEnforceBIP68 in Core is tx.version>=2 && CSV-active; CalculateSequenceLocks
		// already short-circuits tx.Version<2 (returns the no-lock {-1,-1} lock), so
		// gating on height>=CSVHeight here reproduces both halves: pre-CSV blocks skip
		// the gate entirely, and a v1 tx at/after CSV evaluates a no-op lock that
		// always satisfies. prevHeights are the coin heights read from the SAME
		// spend-tracking view CheckTransactionInputs just validated against (inputs
		// not yet spent below), so a coin missing from the view would already have
		// been rejected as bad-txns-inputs-missingorspent above.
		if height >= params.CSVHeight {
			prevHeights := make([]int32, len(tx.TxIn))
			for j, in := range tx.TxIn {
				if utxo := view.GetUTXO(in.PreviousOutPoint); utxo != nil {
					prevHeights[j] = utxo.Height
				}
			}
			// MTP lookup for TIME-based locks (bit-22). This corpus is HEIGHT-based
			// only, so the height-type branch never reads getMTP; the supplied
			// prevMTP (block median-time-past; 0 when unavailable) is passed to
			// EvaluateSequenceLocks as the block MTP exactly as production does
			// (chainmanager.go:794 uses int64(mtp)). For a height-only lock
			// lock.MinTime == -1, so the MTP comparison can never trip — time-based
			// enforcement is a SEPARATE deferred gate, intentionally not exercised here.
			getMTP := func(int32) int64 { return int64(prevMTP) }
			seqLock := consensus.CalculateSequenceLocks(tx, prevHeights, getMTP)
			if !consensus.EvaluateSequenceLocks(seqLock, height, int64(prevMTP)) {
				// Core maps ErrSequenceLockNotMet -> "bad-txns-nonfinal"
				// (validation.cpp:2558; blockbrew rpc/methods.go:1849-1851).
				return connectGateResult{reason: "bad-txns-nonfinal", fee: totalFees}
			}
		}

		for _, txIn := range tx.TxIn {
			nSigOpsCost += consensus.CountSigOpsInaccurate(txIn.SignatureScript) * consensus.WitnessScaleFactor
		}
		for _, txOut := range tx.TxOut {
			nSigOpsCost += consensus.CountSigOpsInaccurate(txOut.PkScript) * consensus.WitnessScaleFactor
		}
		nSigOpsCost += consensus.CountP2SHSigOps(tx, view)
		nSigOpsCost += consensus.CountWitnessSigOps(tx, view)
		if nSigOpsCost > consensus.MaxBlockSigOpsCost {
			return connectGateResult{
				reason: fmt.Sprintf("bad-blk-sigops: %d > %d", nSigOpsCost, consensus.MaxBlockSigOpsCost),
				fee:    totalFees,
			}
		}

		view.SpendTxInputs(tx)
		view.AddTxOutputs(tx, height)
		scriptView.AddTxOutputs(tx, height)
	}

	// Script validation over the NON-spending scriptView (skipped iff
	// skipScripts) — it retains every external + intra-block prevout.
	if !skipScripts {
		blockHash := block.Header.BlockHash()
		flags := consensus.GetBlockScriptFlags(height, params, blockHash)
		sigCache := consensus.NewSigCache(0)
		if verr := consensus.ParallelScriptValidationCached(block, scriptView, flags, sigCache); verr != nil {
			return connectGateResult{reason: "block-script-verify-flag-failed", fee: totalFees}
		}
	}

	// Coinbase value cap: coinbaseValue <= subsidy + totalFees. Network-aware
	// subsidy via the supplied halving interval (Core GetBlockSubsidy reads
	// consensusParams.nSubsidyHalvingInterval; regtest halves every 150).
	subsidy := consensus.CalcBlockSubsidyForInterval(height, halvingInterval)
	var coinbaseValue int64
	for _, out := range coinbase.TxOut {
		coinbaseValue += out.Value
	}
	if coinbaseValue > subsidy+totalFees {
		return connectGateResult{
			reason: fmt.Sprintf("bad-cb-amount: %d > %d (subsidy %d + fees %d)",
				coinbaseValue, subsidy+totalFees, subsidy, totalFees),
			fee: totalFees,
		}
	}

	return connectGateResult{ok: true, fee: totalFees}
}

// stubBlockProvider is a minimal consensus.BlockProvider backed by a
// height->BlockNode map plus parent pointers. For the mainnet retarget case
// blockbrew's CalculateNextWorkRequired only calls GetHeaderByHeight(H-2016)
// (= "first"); GetPrevHeader is used by the testnet min-difficulty walk-back.
// A 2-node chain (last -> first) is sufficient for the mainnet boundary case.
type stubBlockProvider struct {
	byHeight map[int32]*consensus.BlockNode
}

func (p *stubBlockProvider) GetHeaderByHeight(height int32) *consensus.BlockNode {
	return p.byHeight[height]
}

func (p *stubBlockProvider) GetPrevHeader(node *consensus.BlockNode) *consensus.BlockNode {
	if node == nil {
		return nil
	}
	return node.Parent
}

// paramsForNetwork returns the ChainParams for the named network, or an error
// (so the driver SKIPS) for an unknown name.
func paramsForNetwork(name string) (*consensus.ChainParams, error) {
	switch name {
	case "mainnet":
		return consensus.MainnetParams(), nil
	case "testnet", "testnet3":
		return consensus.TestnetParams(), nil
	case "testnet4":
		return consensus.Testnet4Params(), nil
	case "signet":
		return consensus.SignetParams(), nil
	case "regtest":
		return consensus.RegtestParams(), nil
	default:
		return nil, fmt.Errorf("unknown network: %s", name)
	}
}

// nodeFromHdr builds a BlockNode from a nextworkHdr (parsing the 8-hex bits).
func nodeFromHdr(h *nextworkHdr) (*consensus.BlockNode, error) {
	bits, err := strconv.ParseUint(h.Bits, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("bits %q: %w", h.Bits, err)
	}
	return &consensus.BlockNode{
		Height: h.Height,
		Header: wire.BlockHeader{
			Timestamp: h.Time,
			Bits:      uint32(bits),
		},
	}, nil
}

// processNextWork drives blockbrew's REAL GetNextWorkRequired
// (internal/consensus/difficulty.go:263), the BlockIndex/chain-generic
// entrypoint that does the retarget + off-by-one + [÷4,×4] clamp + powLimit +
// BIP94 selection. We rebuild the minimal header context the algorithm reads:
// a "last" node (= pindexLast, the tip the solver builds on) and, on a retarget
// boundary (H%2016==0), a "first" node at height H-2016 wired as last.Parent so
// the provider's GetHeaderByHeight(H-2016) lands on it. The result is formatted
// back to 8-lowercase-hex (Core getblockheader format).
//
// A missing/garbled context or unknown network is reported as {"error"} so the
// driver SKIPS the row rather than faking a value.
func processNextWork(req *request) string {
	params, err := paramsForNetwork(req.Network)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}
	if req.Last == nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("nextwork: missing last"))
	}

	lastNode, err := nodeFromHdr(req.Last)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("nextwork last: "+err.Error()))
	}

	provider := &stubBlockProvider{byHeight: map[int32]*consensus.BlockNode{
		lastNode.Height: lastNode,
	}}

	// On a retarget boundary, "first" is the block at H-2016; wire it as the
	// tip's parent AND register it by height so GetHeaderByHeight(H-2016) finds
	// it. (Off a boundary "first" is absent and the algorithm returns last.bits
	// for mainnet — the passthrough path.)
	if req.First != nil {
		firstNode, err := nodeFromHdr(req.First)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("nextwork first: "+err.Error()))
		}
		lastNode.Parent = firstNode
		provider.byHeight[firstNode.Height] = firstNode
	}

	bits := consensus.GetNextWorkRequired(params, req.Height, req.BlockTime, lastNode, provider)
	return fmt.Sprintf(`{"nbits":%s}`, jsonString(fmt.Sprintf("%08x", bits)))
}

// processMerkleRoot drives blockbrew's REAL merkle primitive
// consensus.CalcMerkleRootMutation (internal/consensus/merkle.go:34), which
// returns (root, mutated) where `mutated` is blockbrew's OWN CVE-2012-2459
// detection (adjacent-pair-equal at every tree level, mirroring Core
// consensus/merkle.cpp:46-63). The shim does NOT re-implement that check; it
// reports whatever CalcMerkleRootMutation concludes, so a cve2459 row that
// comes back mutated=false would be a genuine blockbrew false-accept.
//
// Input txids are DISPLAY order (Core getblock big-endian). We reverse each to
// internal byte order via wire.NewHash256FromHex (the same reversal the
// verifytx op uses on prevout txids), feed the internal hashes to the merkle
// code, then reverse the computed internal root back to display order via
// Hash256.String() so it matches Core's header merkleroot.
//
// A bad/empty txid list is reported as {"error"} so the driver SKIPS the row.
func processMerkleRoot(req *request) string {
	if len(req.Txids) == 0 {
		return fmt.Sprintf(`{"error":%s}`, jsonString("merkleroot: empty txids"))
	}

	hashes := make([]wire.Hash256, len(req.Txids))
	for i, t := range req.Txids {
		h, err := wire.NewHash256FromHex(t)
		if err != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString(fmt.Sprintf("txid %d: %s", i, err.Error())))
		}
		hashes[i] = h
	}

	root, mutated := consensus.CalcMerkleRootMutation(hashes)
	// root.String() reverses internal byte order back to display order.
	return fmt.Sprintf(`{"root":%s,"mutated":%t}`, jsonString(root.String()), mutated)
}

// processSubsidy drives blockbrew's REAL block-subsidy function
// consensus.CalcBlockSubsidy (internal/consensus/difficulty.go:162), the
// coinbase-cap value ConnectBlock uses. It reads the package-level
// SubsidyHalvingInterval (= 210000, mainnet) and InitialSubsidy (50 BTC),
// so a halving-boundary off-by-one or a missing >=64 zero-guard in that fn
// surfaces here rather than being re-implemented in the shim.
func processSubsidy(req *request) string {
	return fmt.Sprintf(`{"subsidy_sats":%d}`, consensus.CalcBlockSubsidy(req.Height))
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

// reorgMaxDepth mirrors blockbrew's production reorg-span cap
// consensus.MaxReorgDepth (chainmanager.go:32) used by ReorgTo
// (chainmanager.go:1740) — a reorg whose disconnect span exceeds this returns
// ErrReorgTooDeep. The corpus's R10 (101 disconnect blocks) trips it.
const reorgMaxDepth = consensus.MaxReorgDepth

// disconnectResult mirrors Core's DisconnectResult: ok < unclean < failed
// (worst-of across a multi-block disconnect span).
type disconnectResult int

const (
	dcOK disconnectResult = iota
	dcUnclean
	dcFailed
)

func (d disconnectResult) String() string {
	switch d {
	case dcUnclean:
		return "unclean"
	case dcFailed:
		return "failed"
	default:
		return "ok"
	}
}

// seedView seeds a fresh InMemoryUTXOView from a list of coin specs (the same
// display->wire txid reversal + one-coin-per-entry plumbing connecttx/checkblock
// use). Shared by the reorg op's fork_utxo seeding.
func seedView(coins []prevoutSpec) (*consensus.InMemoryUTXOView, error) {
	view := consensus.NewInMemoryUTXOView()
	for _, p := range coins {
		h, err := wire.NewHash256FromHex(p.Txid)
		if err != nil {
			return nil, fmt.Errorf("coin txid: %w", err)
		}
		spk, err := hex.DecodeString(p.ScriptPubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("coin scriptPubKey_hex: %w", err)
		}
		view.AddUTXO(wire.OutPoint{Hash: h, Index: p.Vout}, &consensus.UTXOEntry{
			Amount:     p.ValueSats,
			PkScript:   spk,
			Height:     p.Height,
			IsCoinbase: p.IsCoinbase,
		})
	}
	return view, nil
}

// snapshotView returns a deep copy of every coin currently in `src` (cloning
// each PkScript) — the non-spending script-resolution view for one connect
// block's ParallelScriptValidationCached pass.
func snapshotView(src *consensus.InMemoryUTXOView) *consensus.InMemoryUTXOView {
	dst := consensus.NewInMemoryUTXOView()
	src.ForEach(func(op wire.OutPoint, e *consensus.UTXOEntry) {
		dst.AddUTXO(op, &consensus.UTXOEntry{
			Amount:     e.Amount,
			PkScript:   bytes.Clone(e.PkScript),
			Height:     e.Height,
			IsCoinbase: e.IsCoinbase,
		})
	})
	return dst
}

// viewDigest is the canonical coins-view digest the cross-impl reorg corpus
// agrees on (matches rustoshi ShimUtxo.digest + the python view_digest): sort
// entries by (txid wire-bytes, vout), then per coin emit (all little-endian)
//
//	txid[32] || vout u32 || height u32 || is_coinbase u8 || value u64 ||
//	spk_len u32 || spk
//
// then sha256. The golden digests in R4/R8 are computed this exact way.
func viewDigest(view *consensus.InMemoryUTXOView) string {
	type entry struct {
		op wire.OutPoint
		e  *consensus.UTXOEntry
	}
	var entries []entry
	view.ForEach(func(op wire.OutPoint, e *consensus.UTXOEntry) {
		entries = append(entries, entry{op, e})
	})
	sort.Slice(entries, func(i, j int) bool {
		c := bytes.Compare(entries[i].op.Hash[:], entries[j].op.Hash[:])
		if c != 0 {
			return c < 0
		}
		return entries[i].op.Index < entries[j].op.Index
	})
	var buf bytes.Buffer
	var u32 [4]byte
	var u64 [8]byte
	for _, en := range entries {
		buf.Write(en.op.Hash[:])
		binary.LittleEndian.PutUint32(u32[:], en.op.Index)
		buf.Write(u32[:])
		binary.LittleEndian.PutUint32(u32[:], uint32(en.e.Height))
		buf.Write(u32[:])
		if en.e.IsCoinbase {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		binary.LittleEndian.PutUint64(u64[:], uint64(en.e.Amount))
		buf.Write(u64[:])
		binary.LittleEndian.PutUint32(u32[:], uint32(len(en.e.PkScript)))
		buf.Write(u32[:])
		buf.Write(en.e.PkScript)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// driveDisconnect re-expresses blockbrew's REAL DisconnectBlock undo walk
// (chainmanager.go:1517-1602) over an EXPLICIT coins-view instead of the
// disk-backed (chainDB.GetBlock + ReadBlockUndo + tip-node) production path —
// the same accommodation processCheckBlock makes for ConnectBlock. It calls
// blockbrew's REAL primitives (view.SpendUTXOWithCoin, view.ApplyTxInUndo,
// consensus.IsUnspendable, consensus.IsBIP30Unspendable); it does NOT
// re-implement the undo rule.
//
// Per Core validation.cpp:2205-2242 / blockbrew DisconnectBlock:
//   - walk txs in REVERSE order;
//   - for each tx, SpendUTXOWithCoin its outputs and 4-field identity-check
//     (value + script + height + coinbase) the removed coin against the block
//     output; a mismatch (or missing output) sets UNCLEAN unless this is a
//     BIP-30-exempt coinbase (IsBIP30Unspendable keyed by height AND hash);
//   - for non-coinbase txs, ApplyTxInUndo each spent input in REVERSE from the
//     per-tx undo coins (overwrite => UNCLEAN; sibling-recovery exhausted =>
//     FAILED).
//
// undoTxs maps tx_index -> ordered spent coins. The undo count must match the
// non-coinbase tx count (Core validation.cpp:2190).
func driveDisconnect(block *wire.MsgBlock, height int32, undoTxs map[int][]prevoutSpec,
	view *consensus.InMemoryUTXOView) (disconnectResult, error) {

	blockHash := block.Header.BlockHash()
	nonCoinbase := len(block.Transactions) - 1
	if nonCoinbase < 0 {
		nonCoinbase = 0
	}
	if len(undoTxs) != nonCoinbase {
		return dcFailed, fmt.Errorf("undo data mismatch: %d TxUndos but %d non-coinbase transactions",
			len(undoTxs), nonCoinbase)
	}

	// BIP-30 exemption is keyed by BOTH height AND the crafted block hash.
	enforceBIP30 := !consensus.IsBIP30Unspendable(height, blockHash)
	fClean := true

	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()
		isCoinbase := i == 0
		isBIP30Exception := isCoinbase && !enforceBIP30

		// Remove + 4-field identity-check each of this tx's outputs.
		for idx, out := range tx.TxOut {
			if consensus.IsUnspendable(out.PkScript) {
				continue
			}
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			coin, isSpent := view.SpendUTXOWithCoin(outpoint)
			if !isSpent || coin == nil {
				if !isBIP30Exception {
					fClean = false
				}
				continue
			}
			if coin.Amount != out.Value ||
				!bytes.Equal(coin.PkScript, out.PkScript) ||
				coin.Height != height ||
				coin.IsCoinbase != isCoinbase {
				if !isBIP30Exception {
					fClean = false
				}
			}
		}

		// Restore spent inputs for non-coinbase txs.
		if i > 0 {
			spent, ok := undoTxs[i]
			if !ok {
				return dcFailed, fmt.Errorf("missing undo for tx_index %d", i)
			}
			if len(spent) != len(tx.TxIn) {
				return dcFailed, fmt.Errorf("tx %d undo mismatch: %d spent coins but %d inputs",
					i, len(spent), len(tx.TxIn))
			}
			// REVERSE iteration over inputs (Core validation.cpp:2233-2239).
			for j := len(tx.TxIn); j > 0; j-- {
				idx := j - 1
				sc := spent[idx]
				spk, err := hex.DecodeString(sc.ScriptPubKeyHex)
				if err != nil {
					return dcFailed, fmt.Errorf("undo coin scriptPubKey_hex: %w", err)
				}
				outpoint := tx.TxIn[idx].PreviousOutPoint
				undoEntry := &consensus.UTXOEntry{
					Amount:     sc.ValueSats,
					PkScript:   bytes.Clone(spk),
					Height:     sc.Height,
					IsCoinbase: sc.IsCoinbase,
				}
				clean, okUndo := view.ApplyTxInUndo(undoEntry, outpoint)
				if !okUndo {
					return dcFailed, nil
				}
				if !clean {
					fClean = false
				}
			}
		}
	}

	if !fClean {
		return dcUnclean, nil
	}
	return dcOK, nil
}

// processReorg drives blockbrew's REAL deterministic reorg as a PURE function of
// explicit data (most-work DECISION + fork-point COINS-VIEW + per-block UNDO),
// eliminating the live-tip / first-seen / nSequenceId race that made the
// submitblock path SUSPECT for the invalid-block-on-higher-work case. The
// phases mirror ChainManager.ReorgTo (chainmanager.go:1705) / ProcessSubmitted
// Block (chainmanager.go:1286):
//
//	(0) DEPTH CAP: len(disconnect) > consensus.MaxReorgDepth (currently 288) ->
//	    reorg-too-deep (ReorgTo's span bound, chainmanager.go:1740). Core has
//	    no fixed cap — EXPECTED-DIVERGENCE.
//	(1) WORK COMPARE: STRICT new>old via *big.Int.Cmp (the EXACT comparator
//	    ReorgTo's trigger uses, node.TotalWork.Cmp(tip.TotalWork) > 0,
//	    chainmanager.go:505/1314). big.Int.SetBytes reads the 32-byte work hex
//	    big-endian. Not strictly greater -> no-reorg-equal-or-less-work, view
//	    UNTOUCHED.
//	(2) DISCONNECT: per disconnect block tip-first, driveDisconnect (blockbrew's
//	    REAL DisconnectBlock undo over the explicit view). disconnect_result =
//	    worst-of across the span.
//	(3) CONNECT: per side-branch block in order, runConnectBlockGates (the SAME
//	    real ConnectBlock gates checkblock drives) at THAT block's own height,
//	    threading the working view forward, stopping at the FIRST reject
//	    (connected_count = blocks that passed before it; R9 MUST NOT skip ahead).
//
// PoW is gated off (skip_pow) — the crafted blocks' headers don't meet bits;
// disabling PoW does NOT touch any consensus rule under test. Falsification
// hook REORG_NEUTER_SCRIPTS=1 forces skip_scripts on every connect block so the
// flagship R1 WRONGLY flips to reorg-applied, proving the per-input script
// re-validation is the LIVE gate preventing the false-accept.
func processReorg(req *request) string {
	params, err := paramsForNetwork(req.Network)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}

	// (0) DEPTH CAP — refuse before touching the view (the view stays the seeded
	// fork view; report its digest).
	if len(req.Disconnect) > reorgMaxDepth {
		view, verr := seedView(req.ForkUTXO)
		if verr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString(verr.Error()))
		}
		return fmt.Sprintf(
			`{"outcome":"reorg-too-deep","disconnect_result":"ok","connected_count":0,"fork_utxo_digest":%s}`,
			jsonString(viewDigest(view)))
	}

	// (1) WORK COMPARE — STRICT new>old, the production reorg trigger.
	oldW, err := parseWork(req.OldTipWorkHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("old_tip_work_hex: "+err.Error()))
	}
	newW, err := parseWork(req.NewTipWorkHex)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString("new_tip_work_hex: "+err.Error()))
	}
	if newW.Cmp(oldW) <= 0 {
		// No reorg: the (possibly invalid) connect blocks are NEVER evaluated;
		// the view is the seeded fork view, untouched.
		view, verr := seedView(req.ForkUTXO)
		if verr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString(verr.Error()))
		}
		return fmt.Sprintf(
			`{"outcome":"no-reorg-equal-or-less-work","disconnect_result":"ok","connected_count":0,"fork_utxo_digest":%s}`,
			jsonString(viewDigest(view)))
	}

	// Seed the working view from fork_utxo.
	view, err := seedView(req.ForkUTXO)
	if err != nil {
		return fmt.Sprintf(`{"error":%s}`, jsonString(err.Error()))
	}

	// (2) DISCONNECT phase — drive REAL undo per block tip-first; worst-of.
	worst := dcOK
	for _, d := range req.Disconnect {
		blockBytes, derr := hex.DecodeString(d.BlockHex)
		if derr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("disconnect.block_hex: "+derr.Error()))
		}
		var block wire.MsgBlock
		if derr := block.Deserialize(bytes.NewReader(blockBytes)); derr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("disconnect block deserialize: "+derr.Error()))
		}
		undoTxs := make(map[int][]prevoutSpec, len(d.Undo))
		for _, ut := range d.Undo {
			undoTxs[ut.TxIndex] = ut.Vin
		}
		res, derr := driveDisconnect(&block, d.Height, undoTxs, view)
		if derr != nil {
			// Input-shape / undo-count error — surface as a failed disconnect +
			// rejected reorg (decision-first: the reorg cannot be applied).
			return fmt.Sprintf(
				`{"outcome":"reorg-rejected","disconnect_result":"failed","connected_count":0,"reject_reason":%s,"fork_utxo_digest":%s}`,
				jsonString(derr.Error()), jsonString(viewDigest(view)))
		}
		if res > worst {
			worst = res
		}
	}

	// Falsification hook: neuter the per-input script re-validation on EVERY
	// connect block. R1 must then WRONGLY flip to reorg-applied.
	neuterScripts := os.Getenv("REORG_NEUTER_SCRIPTS") == "1"

	// (3) CONNECT phase — drive REAL ConnectBlock gates in order; stop at first
	// reject; thread the working view forward.
	connectedCount := 0
	for _, c := range req.Connect {
		blockBytes, cerr := hex.DecodeString(c.BlockHex)
		if cerr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("connect.block_hex: "+cerr.Error()))
		}
		var block wire.MsgBlock
		if cerr := block.Deserialize(bytes.NewReader(blockBytes)); cerr != nil {
			return fmt.Sprintf(`{"error":%s}`, jsonString("connect block deserialize: "+cerr.Error()))
		}
		if len(block.Transactions) == 0 {
			return reorgRejected(connectedCount, "bad-blk-length-no-tx", worst, view)
		}
		// Fresh non-spending snapshot of the CURRENT working view for this
		// block's script pass (it must see every external prevout still unspent
		// after the prior connect blocks' net effect).
		scriptView := snapshotView(view)
		res := runConnectBlockGates(&block, view, scriptView, params, c.Height,
			params.SubsidyHalvingInterval, c.PrevMTP, true /*skipPow*/, neuterScripts)
		if !res.ok {
			// STOP at the first reject (R9: MUST NOT skip ahead to a later valid
			// block). The view carries every block connected so far + this
			// block's partially-applied txs; decision-first scores outcome +
			// connected_count, not digest, on reject vectors.
			return reorgRejected(connectedCount, res.reason, worst, view)
		}
		connectedCount++
	}

	// All connect blocks passed -> reorg adopted.
	return fmt.Sprintf(
		`{"outcome":"reorg-applied","disconnect_result":%s,"connected_count":%d,"fork_utxo_digest":%s}`,
		jsonString(worst.String()), connectedCount, jsonString(viewDigest(view)))
}

// reorgRejected builds the reorg-rejected response with the current view digest.
func reorgRejected(connectedCount int, reason string, worst disconnectResult,
	view *consensus.InMemoryUTXOView) string {
	return fmt.Sprintf(
		`{"outcome":"reorg-rejected","disconnect_result":%s,"connected_count":%d,"reject_reason":%s,"fork_utxo_digest":%s}`,
		jsonString(worst.String()), connectedCount, jsonString(reason), jsonString(viewDigest(view)))
}

// parseWork parses a 32-byte big-endian work hex into a *big.Int (the same
// magnitude representation blockbrew's BlockNode.TotalWork uses, so .Cmp is the
// identical strict-greater comparator the production reorg trigger applies).
func parseWork(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("work hex not 32 bytes: %d", len(b))
	}
	return new(big.Int).SetBytes(b), nil
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
