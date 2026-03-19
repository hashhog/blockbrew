package wallet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Test vectors from BIP174 and other sources.

func TestPSBTMagic(t *testing.T) {
	// Test that magic bytes are correct
	magic := []byte{0x70, 0x73, 0x62, 0x74, 0xff}
	if string(magic[:4]) != "psbt" {
		t.Error("Magic bytes should spell 'psbt'")
	}
	if magic[4] != 0xff {
		t.Error("Magic separator should be 0xff")
	}
}

func TestPSBTRoundTrip(t *testing.T) {
	// Create a simple PSBT
	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  prevHash,
					Index: 0,
				},
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    100000,
				PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
			},
		},
		LockTime: 0,
	}

	// Create PSBT
	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// Add some input data
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    200000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	}

	// Encode
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	// Decode
	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	// Compare
	if decoded.UnsignedTx.Version != tx.Version {
		t.Error("Transaction version mismatch")
	}

	if len(decoded.Inputs) != 1 {
		t.Fatalf("Expected 1 input, got %d", len(decoded.Inputs))
	}

	if len(decoded.Outputs) != 1 {
		t.Fatalf("Expected 1 output, got %d", len(decoded.Outputs))
	}

	if decoded.Inputs[0].WitnessUTXO == nil {
		t.Fatal("Expected WitnessUTXO to be set")
	}

	if decoded.Inputs[0].WitnessUTXO.Value != 200000 {
		t.Errorf("WitnessUTXO value mismatch: got %d, want 200000", decoded.Inputs[0].WitnessUTXO.Value)
	}
}

func TestPSBTBase64RoundTrip(t *testing.T) {
	// Create a simple PSBT
	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    100000,
				PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
			},
		},
		LockTime: 0,
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// Encode to base64
	b64, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("Failed to encode PSBT to base64: %v", err)
	}

	// Decode from base64
	decoded, err := DecodePSBTBase64(b64)
	if err != nil {
		t.Fatalf("Failed to decode PSBT from base64: %v", err)
	}

	// Re-encode and compare
	b64_2, err := decoded.EncodeBase64()
	if err != nil {
		t.Fatalf("Failed to re-encode PSBT: %v", err)
	}

	if b64 != b64_2 {
		t.Error("Base64 encoding not deterministic")
	}
}

func TestPSBTEmptyInput(t *testing.T) {
	// Test decoding a minimal PSBT with empty maps
	// Magic + version 0 + separator + empty global map + empty input map + empty output map
	// psbt + 0xff + 00 (version) + 00 (separator)

	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    100000,
				PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
			},
		},
		LockTime: 0,
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Verify magic
	if !bytes.HasPrefix(encoded, []byte{0x70, 0x73, 0x62, 0x74, 0xff}) {
		t.Error("Missing or incorrect magic bytes")
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode minimal PSBT: %v", err)
	}

	if len(decoded.Inputs) != 1 {
		t.Errorf("Expected 1 input, got %d", len(decoded.Inputs))
	}

	if len(decoded.Outputs) != 1 {
		t.Errorf("Expected 1 output, got %d", len(decoded.Outputs))
	}
}

func TestPSBTPartialSigs(t *testing.T) {
	// Test that partial signatures are stored correctly
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	// Create a compressed public key (33 bytes, starts with 02 or 03)
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}

	// Create a DER signature (placeholder)
	sig := make([]byte, 71)
	sig[0] = 0x30 // SEQUENCE
	sig[1] = 0x44 // Length
	sig[2] = 0x02 // INTEGER
	sig[3] = 0x20 // Length of r
	// ... rest of signature

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	psbt.Inputs[0].PartialSigs = map[string][]byte{
		hex.EncodeToString(pubKey): sig,
	}

	// Encode and decode
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	if len(decoded.Inputs[0].PartialSigs) != 1 {
		t.Fatalf("Expected 1 partial sig, got %d", len(decoded.Inputs[0].PartialSigs))
	}

	decodedSig, exists := decoded.Inputs[0].PartialSigs[hex.EncodeToString(pubKey)]
	if !exists {
		t.Fatal("Partial sig not found")
	}

	if !bytes.Equal(decodedSig, sig) {
		t.Error("Signature mismatch")
	}
}

func TestPSBTBIP32Derivation(t *testing.T) {
	// Test BIP32 derivation path encoding
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	// BIP84 path: m/84'/0'/0'/0/5
	derivation := BIP32Derivation{
		Fingerprint: [4]byte{0x12, 0x34, 0x56, 0x78},
		Path:        []uint32{0x80000054, 0x80000000, 0x80000000, 0, 5}, // 84', 0', 0', 0, 5
	}

	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	psbt.Inputs[0].BIP32Derivations = map[string]BIP32Derivation{
		hex.EncodeToString(pubKey): derivation,
	}

	// Encode and decode
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	decodedDeriv, exists := decoded.Inputs[0].BIP32Derivations[hex.EncodeToString(pubKey)]
	if !exists {
		t.Fatal("BIP32 derivation not found")
	}

	if decodedDeriv.Fingerprint != derivation.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %x, want %x", decodedDeriv.Fingerprint, derivation.Fingerprint)
	}

	if len(decodedDeriv.Path) != len(derivation.Path) {
		t.Fatalf("Path length mismatch: got %d, want %d", len(decodedDeriv.Path), len(derivation.Path))
	}

	for i, v := range derivation.Path {
		if decodedDeriv.Path[i] != v {
			t.Errorf("Path[%d] mismatch: got %d, want %d", i, decodedDeriv.Path[i], v)
		}
	}
}

func TestPSBTSighashType(t *testing.T) {
	// Test sighash type encoding
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// SIGHASH_ALL
	psbt.Inputs[0].SighashType = 0x01

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	if decoded.Inputs[0].SighashType != 0x01 {
		t.Errorf("Sighash type mismatch: got %d, want 1", decoded.Inputs[0].SighashType)
	}
}

func TestPSBTFinalizedInput(t *testing.T) {
	// Test finalized script sig and witness
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// Set finalized data
	psbt.Inputs[0].FinalScriptSig = []byte{0x00, 0x47, 0x30, 0x44}
	psbt.Inputs[0].FinalScriptWitness = [][]byte{
		{0x30, 0x44, 0x02, 0x20}, // signature
		{0x02, 0x01, 0x02, 0x03}, // pubkey
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	if !bytes.Equal(decoded.Inputs[0].FinalScriptSig, psbt.Inputs[0].FinalScriptSig) {
		t.Error("FinalScriptSig mismatch")
	}

	if len(decoded.Inputs[0].FinalScriptWitness) != 2 {
		t.Fatalf("Expected 2 witness items, got %d", len(decoded.Inputs[0].FinalScriptWitness))
	}

	for i, item := range psbt.Inputs[0].FinalScriptWitness {
		if !bytes.Equal(decoded.Inputs[0].FinalScriptWitness[i], item) {
			t.Errorf("Witness item %d mismatch", i)
		}
	}
}

func TestCombinePSBTs(t *testing.T) {
	// Create base PSBT
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	// Create two PSBTs with different partial signatures
	pubKey1 := make([]byte, 33)
	pubKey1[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey1[i] = byte(i)
	}

	pubKey2 := make([]byte, 33)
	pubKey2[0] = 0x03
	for i := 1; i < 33; i++ {
		pubKey2[i] = byte(i + 32)
	}

	sig1 := []byte{0x30, 0x44, 0x01, 0x01}
	sig2 := []byte{0x30, 0x44, 0x02, 0x02}

	psbt1 := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt1.Inputs[0].PartialSigs = map[string][]byte{
		hex.EncodeToString(pubKey1): sig1,
	}

	psbt2 := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt2.Inputs[0].PartialSigs = map[string][]byte{
		hex.EncodeToString(pubKey2): sig2,
	}

	// Combine
	combined, err := CombinePSBTs([]*PSBT{psbt1, psbt2})
	if err != nil {
		t.Fatalf("Failed to combine PSBTs: %v", err)
	}

	// Check that both signatures are present
	if len(combined.Inputs[0].PartialSigs) != 2 {
		t.Errorf("Expected 2 partial sigs, got %d", len(combined.Inputs[0].PartialSigs))
	}

	if _, exists := combined.Inputs[0].PartialSigs[hex.EncodeToString(pubKey1)]; !exists {
		t.Error("Missing signature from pubKey1")
	}

	if _, exists := combined.Inputs[0].PartialSigs[hex.EncodeToString(pubKey2)]; !exists {
		t.Error("Missing signature from pubKey2")
	}
}

func TestPSBTTaprootFields(t *testing.T) {
	// Test taproot-specific fields (BIP371)
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x51, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	})

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// Set taproot key signature (64 bytes for Schnorr)
	tapKeySig := make([]byte, 64)
	for i := range tapKeySig {
		tapKeySig[i] = byte(i)
	}
	psbt.Inputs[0].TapKeySig = tapKeySig

	// Set tap internal key (32 bytes x-only)
	tapInternalKey := make([]byte, 32)
	for i := range tapInternalKey {
		tapInternalKey[i] = byte(i + 100)
	}
	psbt.Inputs[0].TapInternalKey = tapInternalKey

	// Encode and decode
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	if !bytes.Equal(decoded.Inputs[0].TapKeySig, tapKeySig) {
		t.Error("TapKeySig mismatch")
	}

	if !bytes.Equal(decoded.Inputs[0].TapInternalKey, tapInternalKey) {
		t.Error("TapInternalKey mismatch")
	}
}

func TestPSBTVersion(t *testing.T) {
	// Test PSBT version field
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	psbt := &PSBT{
		Version:    0, // PSBTv0
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode PSBT: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("Failed to decode PSBT: %v", err)
	}

	// Version 0 is the default and may not be explicitly encoded
	if decoded.Version != 0 {
		t.Errorf("Version mismatch: got %d, want 0", decoded.Version)
	}
}

func TestPSBTInvalidMagic(t *testing.T) {
	// Test that invalid magic is rejected
	invalidData := []byte{0x00, 0x00, 0x00, 0x00, 0xff}
	_, err := DecodePSBT(invalidData)
	if err == nil {
		t.Error("Expected error for invalid magic bytes")
	}
}

func TestPSBTTooShort(t *testing.T) {
	// Test that too-short data is rejected
	shortData := []byte{0x70, 0x73, 0x62, 0x74}
	_, err := DecodePSBT(shortData)
	if err == nil {
		t.Error("Expected error for too-short data")
	}
}

func TestFinalizePSBT(t *testing.T) {
	// Test finalizing a PSBT with a P2WPKH input
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	// Create compressed public key
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}

	// Create DER signature with sighash type
	sig := make([]byte, 71)
	sig[0] = 0x30 // SEQUENCE
	sig[1] = 0x44 // Length
	sig[2] = 0x02 // INTEGER
	sig[3] = 0x20 // Length of r
	for i := 4; i < 36; i++ {
		sig[i] = byte(i)
	}
	sig[36] = 0x02 // INTEGER
	sig[37] = 0x20 // Length of s
	for i := 38; i < 70; i++ {
		sig[i] = byte(i)
	}
	sig[70] = 0x01 // SIGHASH_ALL

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// P2WPKH witness UTXO
	witnessProgram := make([]byte, 22)
	witnessProgram[0] = 0x00 // OP_0
	witnessProgram[1] = 0x14 // Push 20 bytes
	copy(witnessProgram[2:], make([]byte, 20))

	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    200000,
		PkScript: witnessProgram,
	}

	psbt.Inputs[0].PartialSigs = map[string][]byte{
		hex.EncodeToString(pubKey): sig,
	}

	// Finalize
	finalized, complete, err := FinalizePSBT(psbt)
	if err != nil {
		t.Fatalf("Failed to finalize PSBT: %v", err)
	}

	if !complete {
		t.Error("Expected PSBT to be complete after finalization")
	}

	if finalized.Inputs[0].FinalScriptWitness == nil {
		t.Error("Expected FinalScriptWitness to be set")
	}

	if len(finalized.Inputs[0].FinalScriptWitness) != 2 {
		t.Errorf("Expected 2 witness items, got %d", len(finalized.Inputs[0].FinalScriptWitness))
	}
}

func TestExtractTransaction(t *testing.T) {
	// Test extracting a finalized transaction
	tx := wire.NewMsgTx(2)
	prevHash, _ := wire.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000001")
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *prevHash, Index: 0},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    100000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}

	// Set finalized witness
	psbt.Inputs[0].FinalScriptWitness = [][]byte{
		{0x30, 0x44, 0x02, 0x20, 0x01}, // signature
		{0x02, 0x01, 0x02, 0x03},        // pubkey
	}

	// Extract
	extracted, err := ExtractTransaction(psbt)
	if err != nil {
		t.Fatalf("Failed to extract transaction: %v", err)
	}

	if extracted.Version != 2 {
		t.Errorf("Transaction version mismatch: got %d, want 2", extracted.Version)
	}

	if len(extracted.TxIn) != 1 {
		t.Errorf("Expected 1 input, got %d", len(extracted.TxIn))
	}

	if len(extracted.TxOut) != 1 {
		t.Errorf("Expected 1 output, got %d", len(extracted.TxOut))
	}

	// Check witness was applied
	if len(extracted.TxIn[0].Witness) != 2 {
		t.Errorf("Expected 2 witness items, got %d", len(extracted.TxIn[0].Witness))
	}
}
