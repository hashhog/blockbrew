// W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (DISCOVERY ONLY).
//
// These tests document 24 bugs found in the PSBT codec / role state
// machine / RPC glue. Most are written as PINS — they ASSERT the current
// (buggy) behavior and will FAIL if the bug is fixed (and the pin needs
// to be flipped). A few are negative-assertion XFAILs that DOCUMENT a
// missing arm / check by demonstrating the parser silently accepts what
// Core rejects.
//
// Cross-references:
//   - bitcoin-core/src/psbt.h (Unserialize/Serialize)
//   - bitcoin-core/src/psbt.cpp (Merge, FinalizePSBT, Decode*PSBT)
//   - bitcoin-core/src/rpc/rawtransaction.cpp (joinpsbts, analyzepsbt,
//     createpsbt, utxoupdatepsbt)
//   - blockbrew/audit/w137_psbt.md (severity matrix + impact analysis)

package wallet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// w137MakePSBTBytes constructs a minimal valid PSBT byte stream that
// carries 1 input + 1 output and exposes seams for ALL 24 bug tests.
// We hand-construct bytes (not rely on PSBT struct field assignment) so
// the parser sees foreign-typed entries it would otherwise refuse to
// emit itself.
//
// The base PSBT has:
//   - magic (5 bytes)
//   - global UNSIGNED_TX (1 input with prev=zeros, vout=0, seq=0xffffffff,
//     1 output value=100000, locktime=0, version=2)
//   - global separator
//   - input separator
//   - output separator
//
// Caller-passed `extraGlobal`, `extraInput`, `extraOutput` are spliced in
// BEFORE the respective separators. `trailing` is appended AFTER all
// output maps.
func w137MakePSBTBytes(t *testing.T, extraGlobal, extraInput, extraOutput, trailing []byte) []byte {
	t.Helper()

	// Build the unsigned tx (1-in / 1-out, no witness, locktime=0, version=2).
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{}, // all-zeros prev
				Index: 0,
			},
			Sequence: 0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value: 100000,
			// OP_0 <20 bytes>
			PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		}},
		LockTime: 0,
	}

	var txBuf bytes.Buffer
	if err := tx.SerializeNoWitness(&txBuf); err != nil {
		t.Fatalf("serialize tx: %v", err)
	}

	var buf bytes.Buffer
	buf.Write([]byte{0x70, 0x73, 0x62, 0x74, 0xff}) // magic

	// Global UNSIGNED_TX (type 0x00, empty keydata).
	wire.WriteCompactSize(&buf, 1) // key length
	buf.WriteByte(PSBTGlobalUnsignedTx)
	wire.WriteCompactSize(&buf, uint64(txBuf.Len()))
	buf.Write(txBuf.Bytes())

	// extraGlobal splice
	if len(extraGlobal) > 0 {
		buf.Write(extraGlobal)
	}

	// Global separator
	buf.WriteByte(0x00)

	// Input map
	if len(extraInput) > 0 {
		buf.Write(extraInput)
	}
	buf.WriteByte(0x00) // input separator

	// Output map
	if len(extraOutput) > 0 {
		buf.Write(extraOutput)
	}
	buf.WriteByte(0x00) // output separator

	if len(trailing) > 0 {
		buf.Write(trailing)
	}

	return buf.Bytes()
}

// kvBytes encodes a single PSBT key-value pair.
func kvBytes(key, value []byte) []byte {
	var b bytes.Buffer
	wire.WriteCompactSize(&b, uint64(len(key)))
	b.Write(key)
	wire.WriteCompactSize(&b, uint64(len(value)))
	b.Write(value)
	return b.Bytes()
}

// ── BUG-1: MuSig2 input fields silently bucketed into Unknown ────────────
//
// type=0x1a (PARTICIPANT_PUBKEYS), type=0x1b (PUB_NONCE), type=0x1c
// (PARTIAL_SIG). All three should have dedicated codec arms with key/value
// validation; instead they fall into input.Unknown.
func TestW137_BUG1_MuSig2InputFieldsAreUnknown(t *testing.T) {
	// Build an INPUT-side type=0x1a entry with a 33-byte agg pubkey and
	// 33-byte participant pubkey.
	aggPub := make([]byte, 33)
	aggPub[0] = 0x02
	for i := 1; i < 33; i++ {
		aggPub[i] = byte(i)
	}
	partPub := make([]byte, 33)
	partPub[0] = 0x03
	for i := 1; i < 33; i++ {
		partPub[i] = byte(0xff - i)
	}

	key := append([]byte{PSBTInMuSig2ParticipantPubkeys}, aggPub...)
	val := partPub
	extraInput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-1 parse: %v", err)
	}

	// PIN: the entry currently lands in input.Unknown (not a typed field).
	// If a future fix promotes it to a typed field, this test FAILS and
	// the maintainer flips it to assert the typed field.
	if _, ok := psbt.Inputs[0].Unknown[string(key)]; !ok {
		t.Fatalf("BUG-1 PIN: expected MuSig2 PARTICIPANT_PUBKEYS in input.Unknown; gone — has codec arm landed?")
	}
}

func TestW137_BUG1_MuSig2PubNonceIsUnknown(t *testing.T) {
	partPub := make([]byte, 33)
	partPub[0] = 0x02
	for i := 1; i < 33; i++ {
		partPub[i] = byte(i)
	}
	aggPub := make([]byte, 33)
	aggPub[0] = 0x03
	for i := 1; i < 33; i++ {
		aggPub[i] = byte(i + 1)
	}

	key := append([]byte{PSBTInMuSig2PubNonce}, partPub...)
	key = append(key, aggPub...)
	// MUSIG2_PUBNONCE_SIZE=66 per Core psbt.h:814
	val := make([]byte, 66)
	for i := range val {
		val[i] = byte(i)
	}
	extraInput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-1 PUBNONCE parse: %v", err)
	}
	if _, ok := psbt.Inputs[0].Unknown[string(key)]; !ok {
		t.Fatalf("BUG-1 PUBNONCE PIN broken — has codec arm landed?")
	}
}

// ── BUG-2: Proprietary entries bucketed into Unknown ─────────────────────
//
// Global PSBT_GLOBAL_PROPRIETARY (0xfc) should land in a typed Proprietary
// set; blockbrew puts it in psbt.Unknown.
func TestW137_BUG2_ProprietaryNotSeparated(t *testing.T) {
	// Proprietary key shape (Core PSBTProprietary):
	//   key = type_byte(0xfc) || identifier_len_compact || identifier ||
	//         subtype_varint || keydata
	// Use a tiny example: identifier="BB", subtype=0x42, keydata=0x99.
	key := []byte{PSBTGlobalProprietary, 0x02, 'B', 'B', 0x42, 0x99}
	val := []byte{0xde, 0xad}
	extraGlobal := kvBytes(key, val)

	// Also one regular unknown (type=0x55) — Core would sort proprietary
	// BEFORE this. blockbrew bucket-and-Go-string-sort interleaves them.
	unkKey := []byte{0x55, 'u'}
	unkVal := []byte{0xbe, 0xef}
	extraGlobal = append(extraGlobal, kvBytes(unkKey, unkVal)...)

	raw := w137MakePSBTBytes(t, extraGlobal, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-2 parse: %v", err)
	}

	// PIN: both entries live in psbt.Unknown today (no typed Proprietary
	// field exists).
	if _, ok := psbt.Unknown[string(key)]; !ok {
		t.Fatalf("BUG-2 PIN: proprietary expected in Unknown bucket — typed Proprietary landed?")
	}
	if _, ok := psbt.Unknown[string(unkKey)]; !ok {
		t.Fatalf("BUG-2 PIN: unknown expected in Unknown bucket")
	}
}

// ── BUG-3: BIP-370 v2 global fields silently bucketed into Unknown ───────
func TestW137_BUG3_V2GlobalFieldsAreUnknown(t *testing.T) {
	// PSBT_GLOBAL_TX_VERSION=0x02, value = uint32 LE.
	key := []byte{PSBTGlobalTxVersion}
	val := []byte{2, 0, 0, 0}
	extraGlobal := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, extraGlobal, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-3 parse: %v", err)
	}
	if _, ok := psbt.Unknown[string(key)]; !ok {
		t.Fatalf("BUG-3 PIN: TX_VERSION expected in Unknown — v2 codec arm landed?")
	}
}

// ── BUG-4: BIP-370 v2 input fields silently bucketed into Unknown ────────
func TestW137_BUG4_V2InputFieldsAreUnknown(t *testing.T) {
	// PSBT_IN_PREVIOUS_TXID=0x0e, value = 32 bytes.
	key := []byte{PSBTInPrevTxID}
	val := make([]byte, 32)
	for i := range val {
		val[i] = byte(i)
	}
	extraInput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-4 parse: %v", err)
	}
	if _, ok := psbt.Inputs[0].Unknown[string(key)]; !ok {
		t.Fatalf("BUG-4 PIN: PREVIOUS_TXID expected in input.Unknown — v2 arm landed?")
	}
}

// ── BUG-5: BIP-370 v2 output fields silently bucketed into Unknown ───────
func TestW137_BUG5_V2OutputFieldsAreUnknown(t *testing.T) {
	// PSBT_OUT_AMOUNT=0x03, value = int64 LE.
	key := []byte{PSBTOutAmount}
	val := []byte{0xa0, 0x86, 0x01, 0, 0, 0, 0, 0}
	extraOutput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, nil, extraOutput, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-5 parse: %v", err)
	}
	if _, ok := psbt.Outputs[0].Unknown[string(key)]; !ok {
		t.Fatalf("BUG-5 PIN: OUT_AMOUNT expected in output.Unknown — v2 arm landed?")
	}
}

// ── BUG-6: No PSBT version ceiling check ─────────────────────────────────
//
// Core psbt.h:1322 rejects versions > PSBT_HIGHEST_VERSION (=0).
// blockbrew silently accepts any uint32.
func TestW137_BUG6_NoVersionCeilingCheck(t *testing.T) {
	// PSBT_GLOBAL_VERSION=0xfb, value = 99 (way above 0).
	key := []byte{PSBTGlobalVersion}
	val := []byte{99, 0, 0, 0}
	extraGlobal := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, extraGlobal, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-6 PIN: forged version 99 was rejected — ceiling check landed? err=%v", err)
	}
	if psbt.Version != 99 {
		t.Fatalf("BUG-6: version round-trip lost, got %d", psbt.Version)
	}
}

// ── BUG-7: No DER signature encoding validation on PARTIAL_SIG ───────────
//
// Core psbt.h:540-546 rejects via CheckSignatureEncoding.
// blockbrew stores arbitrary bytes (incl. zero-length and non-DER).
func TestW137_BUG7_NoDERSignatureValidation(t *testing.T) {
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}
	// Garbage "signature" (non-DER, not even a valid SEQUENCE).
	badSig := []byte{0xff, 0xff, 0xff, 0xff}

	key := append([]byte{PSBTInPartialSig}, pubKey...)
	extraInput := kvBytes(key, badSig)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-7 PIN: non-DER sig was rejected — has DER check landed? err=%v", err)
	}
	got, ok := psbt.Inputs[0].PartialSigs[string(pubKey)]
	if !ok || !bytes.Equal(got, badSig) {
		t.Fatalf("BUG-7: non-DER sig should have round-tripped; got %x ok=%v", got, ok)
	}
}

// ── BUG-8: No pubkey IsFullyValid check on PARTIAL_SIG ───────────────────
func TestW137_BUG8_NoPartialSigPubkeyValidation(t *testing.T) {
	// 33-byte pubkey with INVALID prefix byte (Core requires 0x02/0x03 for
	// 33-byte SEC1).
	pubKey := make([]byte, 33)
	pubKey[0] = 0x05 // INVALID
	// 71-byte well-formed DER-ish sig (parser doesn't check anyway).
	sig := make([]byte, 71)
	sig[0] = 0x30
	sig[1] = 0x44

	key := append([]byte{PSBTInPartialSig}, pubKey...)
	extraInput := kvBytes(key, sig)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-8 PIN: invalid pubkey accepted but parser rejected — fully-valid check landed? err=%v", err)
	}
	if _, ok := psbt.Inputs[0].PartialSigs[string(pubKey)]; !ok {
		t.Fatalf("BUG-8: invalid-prefix pubkey should round-trip into PartialSigs")
	}
}

// ── BUG-9: No pubkey IsFullyValid check on BIP32_DERIVATION ──────────────
func TestW137_BUG9_NoBIP32PubkeyValidation(t *testing.T) {
	pubKey := make([]byte, 33)
	pubKey[0] = 0x05 // INVALID SEC1 prefix

	// derivation value: 4-byte fingerprint + 4-byte path index.
	val := make([]byte, 8)
	val[0] = 0x12

	key := append([]byte{PSBTInBIP32Derivation}, pubKey...)
	extraInput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-9 PIN: invalid pubkey rejected by parser — fully-valid check landed? err=%v", err)
	}
	if _, ok := psbt.Inputs[0].BIP32Derivation[string(pubKey)]; !ok {
		t.Fatalf("BUG-9: invalid-prefix pubkey should round-trip into BIP32Derivation")
	}
}

// ── BUG-10: Global xpub size check is a floor, not exact ─────────────────
func TestW137_BUG10_XpubSizeFloorNotExact(t *testing.T) {
	// 80-byte xpub keydata (Core expects EXACTLY 78).
	xpub := make([]byte, 80)
	for i := range xpub {
		xpub[i] = byte(i)
	}
	key := append([]byte{PSBTGlobalXpub}, xpub...)
	val := []byte{0x04, 0x12, 0x34, 0x56, 0x78} // 1-element path

	extraGlobal := kvBytes(key, val)
	raw := w137MakePSBTBytes(t, extraGlobal, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-10 PIN: 80-byte xpub rejected — exact-size check landed? err=%v", err)
	}
	if _, ok := psbt.XPubs[string(xpub)]; !ok {
		t.Fatalf("BUG-10: 80-byte xpub should have been accepted (floor check)")
	}
}

// ── BUG-11: No path-arity bound on BIP32 derivation ──────────────────────
func TestW137_BUG11_NoBIP32PathArityBound(t *testing.T) {
	// 1000-element path (Core's CExtKey path depth ≤ 255).
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}
	const N = 1000
	val := make([]byte, 4+N*4)
	val[0] = 0x12
	// path bytes left at zero
	key := append([]byte{PSBTInBIP32Derivation}, pubKey...)
	extraInput := kvBytes(key, val)

	raw := w137MakePSBTBytes(t, nil, extraInput, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-11 PIN: 1000-element path rejected — arity bound landed? err=%v", err)
	}
	d, ok := psbt.Inputs[0].BIP32Derivation[string(pubKey)]
	if !ok || len(d.Path) != N {
		t.Fatalf("BUG-11: expected 1000-element path round-trip; got ok=%v len=%d", ok, len(d.Path))
	}
}

// ── BUG-12: Combine path bypasses validatePSBTInput ──────────────────────
//
// We construct two PSBTs sharing the same unsigned tx. dst has no UTXO;
// src has a forged NonWitnessUTXO whose hash does NOT match the prevout.
// mergeInput silently emplaces it; the parser's W41 IsSane check ran on
// src's parse (and would have rejected) — but if src was constructed
// in-process (NewPSBT + direct field assignment), the parse check never
// ran, and combine still emplaces.
func TestW137_BUG12_CombineBypassesUTXOSanity(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}

	dst, _ := NewPSBT(tx)
	src, _ := NewPSBT(tx)

	// Forged NonWitnessUTXO that doesn't match prevHash.
	forgedTx := &wire.MsgTx{
		Version: 1,
		TxOut: []*wire.TxOut{{
			Value:    999999, // attacker-chosen value
			PkScript: []byte{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac},
		}},
	}
	src.Inputs[0].NonWitnessUTXO = forgedTx

	merged, err := CombinePSBTs([]*PSBT{dst, src})
	if err != nil {
		t.Fatalf("BUG-12 combine: %v", err)
	}

	// PIN: combine silently emplaces forged NonWitnessUTXO.
	if merged.Inputs[0].NonWitnessUTXO == nil {
		t.Fatalf("BUG-12 PIN: forged NonWitnessUTXO was filtered — has post-merge IsSane landed?")
	}
	if merged.Inputs[0].NonWitnessUTXO.TxOut[0].Value != 999999 {
		t.Fatalf("BUG-12: forged value should have round-tripped via combine")
	}
}

// ── BUG-13: No "extra data after PSBT" rejection ─────────────────────────
func TestW137_BUG13_TrailingDataNotRejected(t *testing.T) {
	trailing := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := w137MakePSBTBytes(t, nil, nil, nil, trailing)

	_, err := DecodePSBT(raw)
	// PIN: trailing junk silently dropped.
	if err != nil {
		t.Fatalf("BUG-13 PIN: trailing data rejected — extra-data check landed? err=%v", err)
	}
}

// ── BUG-14: handleCreatePSBT default sequence is FINAL (0xffffffff) ──────
//
// This pins the WALLET-side default. We don't have a live RPC server in
// this test package; instead we exercise NewPSBT with the same sequence
// the RPC handler uses on the default path (no `replaceable` arg).
//
// The RPC sets `sequence = 0xffffffff` when replaceable=false (default).
// Core's ConstructTransaction picks 0xfffffffe (MAX_SEQUENCE_NONFINAL) so
// anti-fee-sniping applies when locktime>0.
func TestW137_BUG14_CreatePSBTDefaultSequenceNotAntifeeSnipe(t *testing.T) {
	// Build the tx the way handleCreatePSBT does on the default path.
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 700000, // realistic recent height — anti-fee-snipe matters here
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0},
			Sequence:         0xffffffff, // blockbrew default
		}},
		TxOut: []*wire.TxOut{{
			Value:    100000,
			PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		}},
	}
	p, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("BUG-14: %v", err)
	}

	// PIN: sequence is 0xffffffff (final/no-anti-fee-snipe).
	got := p.UnsignedTx.TxIn[0].Sequence
	if got != 0xffffffff {
		t.Fatalf("BUG-14 PIN: default sequence changed from 0xffffffff to 0x%x — has anti-fee-snipe default landed?", got)
	}
	// Core would have set 0xfffffffe.
	if got == 0xfffffffe {
		t.Fatalf("BUG-14: would have passed if blockbrew defaulted to MAX_SEQUENCE_NONFINAL — fix landed early")
	}
}

// ── BUG-15: analyzepsbt next-role machine is coarse ──────────────────────
//
// We can't call handleAnalyzePSBT directly from this package (cycle).
// But we can pin the *struct* shape — blockbrew's AnalyzePSBTInput is
// missing fields Core emits (estimated_vsize, estimated_feerate,
// missing.redeemscript, missing.witnessscript).
//
// Implementation note: we test this via the EXISTENCE of the relevant
// fields on the wallet-side analyze helper (it lives in
// internal/rpc/psbt_methods.go, but the data flow that the analyzer
// consults — `IsComplete` and the input-shape — is wallet-side).
func TestW137_BUG15_AnalyzePSBTNextRoleCoarse(t *testing.T) {
	// Build a PSBT with one input that has UTXO but no signatures.
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	p, _ := NewPSBT(tx)
	p.Inputs[0].WitnessUTXO = &wire.TxOut{Value: 200000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}

	// IsComplete should be false; no estimated_vsize machinery exists in
	// wallet package — this is the pin (no such function).
	if p.IsComplete() {
		t.Fatalf("BUG-15: IsComplete should be false with no sigs")
	}
	// (estimated_vsize / estimated_feerate would be wallet-package
	// concepts in a Core-parity impl; their absence is the bug.)
}

// ── BUG-16: analyzepsbt field-name divergence ────────────────────────────
//
// Pinned at struct-tag level in the RPC package; here we sanity-pin only
// the wallet-side "is finalized" notion vs Core's "is_final".
func TestW137_BUG16_AnalyzeFieldNameDivergence(t *testing.T) {
	// IsComplete returns the wallet-side notion; the RPC layer
	// re-exposes it as `is_finalized` per-input. Core uses `is_final`.
	// We pin the bool semantics here; field-name divergence is at the
	// JSON serialization boundary (rpc package).
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	p, _ := NewPSBT(tx)
	p.Inputs[0].FinalScriptWitness = [][]byte{{0xde, 0xad}}
	if !p.IsComplete() {
		t.Fatalf("BUG-16: IsComplete should be true once final witness set")
	}
}

// ── BUG-17: joinpsbts does not detect duplicate inputs ───────────────────
//
// We exercise the wallet-level path (no RPC server); JoinPSBTs is RPC-only,
// but the bug is in the wallet/RPC integration. Here we just document
// that NewPSBT does NOT reject duplicate prev_outs across PSBTs at this
// level — which is the substrate for the bug.
func TestW137_BUG17_JoinNoDuplicateInputCheck(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	// Two PSBTs sharing the SAME input.
	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	tx2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 50000, PkScript: []byte{0x00, 0x14, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}}},
	}
	p1, _ := NewPSBT(tx1)
	p2, _ := NewPSBT(tx2)
	// PIN: joinpsbts would concatenate without rejecting the duplicate.
	// Both PSBTs reference outpoint (prevHash, 0).
	if p1.UnsignedTx.TxIn[0].PreviousOutPoint != p2.UnsignedTx.TxIn[0].PreviousOutPoint {
		t.Fatalf("BUG-17: test setup broken")
	}
	// If join landed dedup, the RPC handler would return an error here.
	// We pin the substrate.
}

// ── BUG-18: joinpsbts hard-codes Version=2, LockTime=0 ───────────────────
func TestW137_BUG18_JoinHardCodedVersionLockTime(t *testing.T) {
	// Two PSBTs: one with Version=1 + LockTime=500000, another with
	// Version=3 + LockTime=400000. Core would pick version=3 (max) and
	// locktime=400000 (min). blockbrew hard-codes 2/0.
	prevHash1, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	prevHash2, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000002")
	tx1 := &wire.MsgTx{
		Version: 1, LockTime: 500000,
		TxIn:  []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash1, Index: 0}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	tx2 := &wire.MsgTx{
		Version: 3, LockTime: 400000,
		TxIn:  []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash2, Index: 0}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{{Value: 50000, PkScript: []byte{0x00, 0x14, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}}},
	}
	p1, _ := NewPSBT(tx1)
	p2, _ := NewPSBT(tx2)
	// PIN: substrate documents the values that the joiner would IGNORE.
	if p1.UnsignedTx.Version != 1 || p2.UnsignedTx.Version != 3 {
		t.Fatalf("BUG-18 setup broken")
	}
	if p1.UnsignedTx.LockTime != 500000 || p2.UnsignedTx.LockTime != 400000 {
		t.Fatalf("BUG-18 setup broken")
	}
}

// ── BUG-19: joinpsbts does not shuffle ───────────────────────────────────
//
// Substrate-level pin: joinpsbts concatenates in iteration order. Same
// shape as BUG-17/18 — pure RPC-handler omission. We document the
// expectation here.
func TestW137_BUG19_JoinDoesNotShuffle(t *testing.T) {
	// Just assert blockbrew does NOT expose a shuffle helper at wallet
	// level (Core uses FastRandomContext at the RPC layer).
	// This is a documentation pin.
	_ = t // no-op: bug is at the RPC handler layer.
}

// ── BUG-20: mergeInput silently first-wins on UTXO conflict ──────────────
func TestW137_BUG20_MergeSilentFirstWins(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	dst, _ := NewPSBT(tx)
	src, _ := NewPSBT(tx)

	dst.Inputs[0].WitnessUTXO = &wire.TxOut{Value: 200000, PkScript: []byte{0x00, 0x14}}
	src.Inputs[0].WitnessUTXO = &wire.TxOut{Value: 999999, PkScript: []byte{0x00, 0x14}} // different value

	merged, err := CombinePSBTs([]*PSBT{dst, src})
	if err != nil {
		t.Fatalf("BUG-20 combine: %v", err)
	}
	// PIN: dst wins (first), no error/warning surfaced.
	if merged.Inputs[0].WitnessUTXO.Value != 200000 {
		t.Fatalf("BUG-20 PIN: expected first-wins 200000, got %d", merged.Inputs[0].WitnessUTXO.Value)
	}
}

// ── BUG-21: handleCombinePSBT does not validate equal versions ───────────
func TestW137_BUG21_CombineNoVersionCheck(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	dst, _ := NewPSBT(tx)
	src, _ := NewPSBT(tx)
	dst.Version = 0
	src.Version = 2 // PSBT v2 — different from dst

	// PIN: CombinePSBTs accepts mixed versions.
	merged, err := CombinePSBTs([]*PSBT{dst, src})
	if err != nil {
		t.Fatalf("BUG-21 PIN: mixed versions rejected — has version check landed? err=%v", err)
	}
	// Whichever version "wins" is unspecified — pin the actual behavior.
	if merged.Version != 0 && merged.Version != 2 {
		t.Fatalf("BUG-21: unexpected merged version %d", merged.Version)
	}
}

// ── BUG-22: clearInputSigningData over-clears taproot fields ─────────────
func TestW137_BUG22_FinalizeOverclearsTaproot(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	p, _ := NewPSBT(tx)
	internalKey := make([]byte, 32)
	for i := range internalKey {
		internalKey[i] = byte(i)
	}
	merkleRoot := make([]byte, 32)
	for i := range merkleRoot {
		merkleRoot[i] = byte(0xff - i)
	}
	p.Inputs[0].TapInternalKey = internalKey
	p.Inputs[0].TapMerkleRoot = merkleRoot

	clearInputSigningData(&p.Inputs[0])

	// PIN: blockbrew nils both. Core preserves them. Fix would assert
	// non-nil here.
	if p.Inputs[0].TapInternalKey != nil {
		t.Fatalf("BUG-22 PIN: TapInternalKey preserved — has Core-parity landed?")
	}
	if p.Inputs[0].TapMerkleRoot != nil {
		t.Fatalf("BUG-22 PIN: TapMerkleRoot preserved — has Core-parity landed?")
	}
}

// ── BUG-23: Unknown-map sort uses Go string lex (mostly OK, edge case) ───
//
// Construct two keys where Go's string comparison and
// std::map<vector<uint8_t>> lex differ. This requires two keys with a
// prefix relationship where the prefix has bytes that compare differently
// when compared as strings vs as byte slices.
//
// In Go: "a" < "a\x00" (string compare extends, "a" is less).
// In C++ std::map<vector<uint8_t>>: same — "a" < "a\x00".
// So they actually agree on prefix pairs. The divergence is theoretical
// and requires bytes 0x80..0xFF. Document as a pin only.
func TestW137_BUG23_UnknownSortPrefixDivergence(t *testing.T) {
	// Keys: 0x99 "ab" and 0x99 "ab\x00" — strict-prefix pair.
	k1 := []byte{0x99, 'a', 'b'}
	k2 := []byte{0x99, 'a', 'b', 0x00}
	extraGlobal := append(kvBytes(k2, []byte{0x02}), kvBytes(k1, []byte{0x01})...)

	raw := w137MakePSBTBytes(t, extraGlobal, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("BUG-23 parse: %v", err)
	}
	if _, ok := psbt.Unknown[string(k1)]; !ok {
		t.Fatalf("BUG-23: k1 missing from Unknown")
	}
	if _, ok := psbt.Unknown[string(k2)]; !ok {
		t.Fatalf("BUG-23: k2 missing from Unknown")
	}
	// Round-trip and inspect the encoded order.
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("BUG-23 encode: %v", err)
	}
	// k1 should come BEFORE k2 (string lex: "ab" < "ab\x00" in Go).
	// Core's std::map<vector<u8>> ordering: same. PIN: they agree.
	idx1 := bytes.Index(encoded, k1)
	idx2 := bytes.Index(encoded, k2)
	if idx1 < 0 || idx2 < 0 {
		t.Fatalf("BUG-23: keys not present in encoded output")
	}
	if idx1 >= idx2 {
		t.Fatalf("BUG-23: expected k1 before k2; got idx1=%d idx2=%d", idx1, idx2)
	}
}

// ── BUG-24: ExtractTransaction error message uses single-rune index ──────
func TestW137_BUG24_ExtractErrorMsgWrongDigitForI10(t *testing.T) {
	// Build a PSBT with 11 inputs, none finalized.
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	tx := &wire.MsgTx{Version: 2}
	for i := 0; i < 11; i++ {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: uint32(i)},
			Sequence:         0xffffffff,
		})
	}
	tx.TxOut = []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}}
	p, _ := NewPSBT(tx)

	_, err := ExtractTransaction(p)
	if err == nil {
		t.Fatalf("BUG-24: expected ExtractTransaction to fail on unfinalized inputs")
	}
	// PIN: error message uses single-rune index. For i=0, message is
	// "input 0 is not finalized" (correct). The loop short-circuits on
	// the first unfinalized input, so we can't trigger i=10 directly
	// without finalizing inputs 0..9. Document the bug shape only —
	// the rune('0'+10) is ':'. If finalize order changed, the bug
	// would surface as "input : is not finalized".
	if got := err.Error(); got != "input 0 is not finalized" {
		t.Logf("BUG-24 PIN: ExtractTransaction error = %q", got)
		// soft pin
	}
}

// ── Universal pattern: BIP-370 v2 constants declared but not handled ─────
//
// Asserts the type constants are defined (so future fix work has
// stable handles) but the readInput/readOutput/global loop have NO
// case arms for them (witnessed via the round-trip-via-Unknown tests
// above).
func TestW137_UniversalPattern_BIP370ConstantsDeclared(t *testing.T) {
	// Spot-check the constant values match BIP-370.
	if PSBTGlobalTxVersion != 0x02 {
		t.Errorf("BIP-370 PSBT_GLOBAL_TX_VERSION expected 0x02, got 0x%x", PSBTGlobalTxVersion)
	}
	if PSBTGlobalFallbackLock != 0x03 {
		t.Errorf("BIP-370 PSBT_GLOBAL_FALLBACK_LOCKTIME expected 0x03, got 0x%x", PSBTGlobalFallbackLock)
	}
	if PSBTGlobalInputCount != 0x04 {
		t.Errorf("BIP-370 PSBT_GLOBAL_INPUT_COUNT expected 0x04, got 0x%x", PSBTGlobalInputCount)
	}
	if PSBTGlobalOutputCount != 0x05 {
		t.Errorf("BIP-370 PSBT_GLOBAL_OUTPUT_COUNT expected 0x05, got 0x%x", PSBTGlobalOutputCount)
	}
	if PSBTGlobalTxModifiable != 0x06 {
		t.Errorf("BIP-370 PSBT_GLOBAL_TX_MODIFIABLE expected 0x06, got 0x%x", PSBTGlobalTxModifiable)
	}
	if PSBTInPrevTxID != 0x0e {
		t.Errorf("BIP-370 PSBT_IN_PREVIOUS_TXID expected 0x0e, got 0x%x", PSBTInPrevTxID)
	}
	if PSBTInOutputIndex != 0x0f {
		t.Errorf("BIP-370 PSBT_IN_OUTPUT_INDEX expected 0x0f, got 0x%x", PSBTInOutputIndex)
	}
	if PSBTInSequence != 0x10 {
		t.Errorf("BIP-370 PSBT_IN_SEQUENCE expected 0x10, got 0x%x", PSBTInSequence)
	}
	if PSBTOutAmount != 0x03 {
		t.Errorf("BIP-370 PSBT_OUT_AMOUNT expected 0x03, got 0x%x", PSBTOutAmount)
	}
	if PSBTOutScript != 0x04 {
		t.Errorf("BIP-370 PSBT_OUT_SCRIPT expected 0x04, got 0x%x", PSBTOutScript)
	}
}

// ── Universal pattern: MuSig2 input constants declared but not handled ───
func TestW137_UniversalPattern_MuSig2ConstantsDeclared(t *testing.T) {
	if PSBTInMuSig2ParticipantPubkeys != 0x1a {
		t.Errorf("BIP-327 PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS expected 0x1a, got 0x%x", PSBTInMuSig2ParticipantPubkeys)
	}
	if PSBTInMuSig2PubNonce != 0x1b {
		t.Errorf("BIP-327 PSBT_IN_MUSIG2_PUB_NONCE expected 0x1b, got 0x%x", PSBTInMuSig2PubNonce)
	}
	if PSBTInMuSig2PartialSig != 0x1c {
		t.Errorf("BIP-327 PSBT_IN_MUSIG2_PARTIAL_SIG expected 0x1c, got 0x%x", PSBTInMuSig2PartialSig)
	}
}

// ── Cross-bug regression: full round-trip of all V2 / MuSig2 / Proprietary
// entries should preserve them in Unknown (current behavior). If a future
// fix wave promotes any to typed fields, the corresponding bug test above
// will trip; this test ensures the rest still round-trip.
func TestW137_RoundTrip_AllUnknownsPreserved(t *testing.T) {
	// One of each: V2 global, V2 input, V2 output, proprietary, MuSig2 in.
	extraGlobal := bytes.Join([][]byte{
		kvBytes([]byte{PSBTGlobalTxVersion}, []byte{2, 0, 0, 0}),
		kvBytes([]byte{PSBTGlobalProprietary, 0x01, 'P', 0x01, 0xAA}, []byte{0xbb}),
	}, nil)
	extraInput := kvBytes([]byte{PSBTInPrevTxID}, make([]byte, 32))
	extraOutput := kvBytes([]byte{PSBTOutAmount}, []byte{0xa0, 0x86, 0x01, 0, 0, 0, 0, 0})

	raw := w137MakePSBTBytes(t, extraGlobal, extraInput, extraOutput, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if len(psbt.Unknown) < 1 {
		t.Fatalf("expected global Unknown entries; got %d", len(psbt.Unknown))
	}
	if len(psbt.Inputs[0].Unknown) < 1 {
		t.Fatalf("expected input Unknown entries; got %d", len(psbt.Inputs[0].Unknown))
	}
	if len(psbt.Outputs[0].Unknown) < 1 {
		t.Fatalf("expected output Unknown entries; got %d", len(psbt.Outputs[0].Unknown))
	}

	// Re-encode + re-decode + same content.
	enc, err := psbt.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	dec2, err := DecodePSBT(enc)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if len(dec2.Unknown) != len(psbt.Unknown) {
		t.Errorf("global Unknown count differs after re-decode: %d vs %d", len(dec2.Unknown), len(psbt.Unknown))
	}
}

// ── Smoke: ensure the test helpers produce a parseable PSBT ──────────────
func TestW137_BaseHelper_Parses(t *testing.T) {
	raw := w137MakePSBTBytes(t, nil, nil, nil, nil)
	psbt, err := DecodePSBT(raw)
	if err != nil {
		t.Fatalf("base helper: %v", err)
	}
	if len(psbt.Inputs) != 1 {
		t.Errorf("expected 1 input, got %d", len(psbt.Inputs))
	}
	if len(psbt.Outputs) != 1 {
		t.Errorf("expected 1 output, got %d", len(psbt.Outputs))
	}
	if psbt.UnsignedTx.Version != 2 {
		t.Errorf("expected tx.Version=2, got %d", psbt.UnsignedTx.Version)
	}
}

// silence "imported and not used" lint when stripping a test.
var _ = binary.LittleEndian
