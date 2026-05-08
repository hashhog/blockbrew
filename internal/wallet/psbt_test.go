package wallet

import (
	"bytes"
	"errors"
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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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

	// PartialSigs map key is the raw pubkey bytes cast to string (matches production decode logic)
	psbt.Inputs[0].PartialSigs = map[string][]byte{
		string(pubKey): sig,
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

	decodedSig, exists := decoded.Inputs[0].PartialSigs[string(pubKey)]
	if !exists {
		t.Fatal("Partial sig not found")
	}

	if !bytes.Equal(decodedSig, sig) {
		t.Error("Signature mismatch")
	}
}

func TestPSBTBIP32Derivation(t *testing.T) {
	// Test BIP32 derivation path encoding
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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

	// BIP32Derivation map key is the raw pubkey bytes cast to string (matches production decode logic)
	psbt.Inputs[0].BIP32Derivation = map[string]*BIP32Derivation{
		string(pubKey): &derivation,
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

	decodedDeriv, exists := decoded.Inputs[0].BIP32Derivation[string(pubKey)]
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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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
	// PartialSigs map key is the raw pubkey bytes cast to string (matches production decode logic)
	psbt1.Inputs[0].PartialSigs = map[string][]byte{
		string(pubKey1): sig1,
	}

	psbt2 := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt2.Inputs[0].PartialSigs = map[string][]byte{
		string(pubKey2): sig2,
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

	if _, exists := combined.Inputs[0].PartialSigs[string(pubKey1)]; !exists {
		t.Error("Missing signature from pubKey1")
	}

	if _, exists := combined.Inputs[0].PartialSigs[string(pubKey2)]; !exists {
		t.Error("Missing signature from pubKey2")
	}
}

func TestPSBTTaprootFields(t *testing.T) {
	// Test taproot-specific fields (BIP371)
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
				PkScript: []byte{0x51, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			},
		},
	}

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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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

	// PartialSigs map key is the raw pubkey bytes cast to string (matches production decode logic)
	psbt.Inputs[0].PartialSigs = map[string][]byte{
		string(pubKey): sig,
	}

	// Finalize (mutates psbt in place, returns (complete bool, error))
	complete, err := FinalizePSBT(psbt)
	if err != nil {
		t.Fatalf("Failed to finalize PSBT: %v", err)
	}

	if !complete {
		t.Error("Expected PSBT to be complete after finalization")
	}

	if psbt.Inputs[0].FinalScriptWitness == nil {
		t.Error("Expected FinalScriptWitness to be set")
	}

	if len(psbt.Inputs[0].FinalScriptWitness) != 2 {
		t.Errorf("Expected 2 witness items, got %d", len(psbt.Inputs[0].FinalScriptWitness))
	}
}

func TestExtractTransaction(t *testing.T) {
	// Test extracting a finalized transaction
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
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
	}

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

// TestPSBTTapLeafScriptsRoundTrip exercises the per-input TAP_LEAF_SCRIPT
// (PSBTInTapLeafScript = 0x15) write path at psbt.go:814 — the W33 audit
// flagged that site as latent append-aliasing risk.
//
// We deliberately back leaf.Script with a slice that has SPARE CAPACITY
// (the failure mode for the old `append(leaf.Script, leaf.LeafVersion)`
// idiom) and assert (a) the encode does NOT mutate the caller's backing
// array and (b) the round-trip recovers byte-identical Script + LeafVersion
// + ControlBlock for each leaf. (W34-B.)
func TestPSBTTapLeafScriptsRoundTrip(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000abc")
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
				PkScript: []byte{0x51, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			},
		},
		LockTime: 0,
	}

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}

	// Build TWO TapLeafScripts whose Script slice has spare capacity. If
	// the encode path ever regresses to `append(leaf.Script, leaf.LeafVersion)`
	// this scratch byte at [len(script)] would be silently overwritten.
	leaf1Script := make([]byte, 4, 16)
	copy(leaf1Script, []byte{0x51, 0x52, 0x53, 0x54}) // OP_1 OP_2 OP_3 OP_4
	leaf1Script[len(leaf1Script):16][0] = 0xAA        // canary in spare cap

	leaf2Script := make([]byte, 5, 32)
	copy(leaf2Script, []byte{0x76, 0xa9, 0x14, 0x00, 0xff})
	leaf2Script[len(leaf2Script):32][0] = 0xBB // canary in spare cap

	// Snapshot canaries by extending into the spare capacity through a
	// separate slice header (Script is unchanged, len stays 4 / 5).
	leaf1Spare := leaf1Script[:cap(leaf1Script)]
	leaf2Spare := leaf2Script[:cap(leaf2Script)]
	leaf1CanaryBefore := leaf1Spare[len(leaf1Script)]
	leaf2CanaryBefore := leaf2Spare[len(leaf2Script)]

	// ControlBlock = 33-byte minimum (1 leaf-version + 32-byte internal key).
	cb1 := make([]byte, 33)
	cb1[0] = 0xc0
	for i := 1; i < 33; i++ {
		cb1[i] = byte(i)
	}
	cb2 := make([]byte, 33+32) // one merkle proof step
	cb2[0] = 0xc1
	for i := 1; i < len(cb2); i++ {
		cb2[i] = byte(i ^ 0x55)
	}

	psbt.Inputs[0].TapLeafScripts = []TapLeaf{
		{LeafVersion: 0xc0, Script: leaf1Script, ControlBlock: cb1},
		{LeafVersion: 0xc1, Script: leaf2Script, ControlBlock: cb2},
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// (a) caller's backing arrays must not have been mutated by encode.
	if leaf1Spare[len(leaf1Script)] != leaf1CanaryBefore {
		t.Fatalf("psbt.go:814 append-aliasing regression: leaf1 spare capacity mutated (got 0x%02x want 0x%02x)",
			leaf1Spare[len(leaf1Script)], leaf1CanaryBefore)
	}
	if leaf2Spare[len(leaf2Script)] != leaf2CanaryBefore {
		t.Fatalf("psbt.go:814 append-aliasing regression: leaf2 spare capacity mutated (got 0x%02x want 0x%02x)",
			leaf2Spare[len(leaf2Script)], leaf2CanaryBefore)
	}

	// (b) round-trip byte fidelity.
	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("DecodePSBT: %v", err)
	}
	if got := len(decoded.Inputs); got != 1 {
		t.Fatalf("expected 1 input, got %d", got)
	}
	gotLeaves := decoded.Inputs[0].TapLeafScripts
	if len(gotLeaves) != 2 {
		t.Fatalf("expected 2 tap leaf scripts, got %d", len(gotLeaves))
	}

	// Build a lookup keyed on ControlBlock — decode order should match
	// encode order, but we lookup by control block to be robust.
	wantByCB := map[string]TapLeaf{
		string(cb1): {LeafVersion: 0xc0, Script: leaf1Script, ControlBlock: cb1},
		string(cb2): {LeafVersion: 0xc1, Script: leaf2Script, ControlBlock: cb2},
	}
	for i, leaf := range gotLeaves {
		want, ok := wantByCB[string(leaf.ControlBlock)]
		if !ok {
			t.Fatalf("decoded leaf %d has unrecognized control block %x", i, leaf.ControlBlock)
		}
		if leaf.LeafVersion != want.LeafVersion {
			t.Errorf("leaf %d: LeafVersion got 0x%02x, want 0x%02x", i, leaf.LeafVersion, want.LeafVersion)
		}
		if !bytes.Equal(leaf.Script, want.Script) {
			t.Errorf("leaf %d: Script got %x, want %x", i, leaf.Script, want.Script)
		}
		if !bytes.Equal(leaf.ControlBlock, want.ControlBlock) {
			t.Errorf("leaf %d: ControlBlock got %x, want %x", i, leaf.ControlBlock, want.ControlBlock)
		}
	}

	// (c) re-encode the decoded PSBT and assert byte-for-byte match —
	// confirms write path is deterministic for this leaf set.
	reEncoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Errorf("PSBT TapLeafScripts round-trip not byte-identical (len %d vs %d)", len(encoded), len(reEncoded))
	}
}

// TestPSBTTapTreeRoundTrip exercises the per-output PSBT_OUT_TAP_TREE
// (0x06) write path. (W34-B.)
func TestPSBTTapTreeRoundTrip(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000001234")
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
				Value:    50000,
				PkScript: []byte{0x51, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
			},
		},
		LockTime: 0,
	}

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}

	// Tree of 3 leaves at depths 1, 2, 2 (canonical 2-of-3 taptree shape).
	// W35-B: depth is now a first-class field on TapTreeLeaf, not stuffed
	// into TapLeaf.ControlBlock[0].
	psbt.Outputs[0].TapTree = []TapTreeLeaf{
		{Depth: 1, LeafVersion: 0xc0, Script: []byte{0x51}},                   // depth=1, OP_1
		{Depth: 2, LeafVersion: 0xc0, Script: []byte{0x52, 0x53}},             // depth=2, OP_2 OP_3
		{Depth: 2, LeafVersion: 0xc0, Script: []byte{0x54, 0x55, 0x56}},       // depth=2
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("DecodePSBT: %v", err)
	}
	if len(decoded.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(decoded.Outputs))
	}
	got := decoded.Outputs[0].TapTree
	if len(got) != 3 {
		t.Fatalf("expected 3 tap-tree leaves, got %d", len(got))
	}
	want := psbt.Outputs[0].TapTree
	for i := range want {
		if got[i].LeafVersion != want[i].LeafVersion {
			t.Errorf("tap-tree leaf %d LeafVersion: got 0x%02x want 0x%02x", i, got[i].LeafVersion, want[i].LeafVersion)
		}
		if !bytes.Equal(got[i].Script, want[i].Script) {
			t.Errorf("tap-tree leaf %d Script: got %x want %x", i, got[i].Script, want[i].Script)
		}
		// W35-B: depth is now a first-class field, not ControlBlock[0].
		if got[i].Depth != want[i].Depth {
			t.Errorf("tap-tree leaf %d Depth: got %d want %d", i, got[i].Depth, want[i].Depth)
		}
	}

	// Re-encode and assert byte-for-byte match.
	reEncoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Errorf("PSBT TapTree round-trip not byte-identical (len %d vs %d)", len(encoded), len(reEncoded))
	}
}

// TestPSBTTapTreeAndTapLeafScriptsCoexist exercises the W35-B type split.
// Before the refactor, both per-input PSBT_IN_TAP_LEAF_SCRIPT (0x15) and
// per-output PSBT_OUT_TAP_TREE (0x06) were carried by []TapLeaf, with the
// tap-tree path stuffing depth into ControlBlock[0]. If a caller ever
// constructed both on the same PSBT, the same struct shape meant
// ControlBlock[0] silently meant two different things in the two
// contexts. After W35-B, Output.TapTree is []TapTreeLeaf with an
// explicit Depth field, so the two cannot be confused at the call site.
//
// This test constructs an Input with TapLeafScripts AND an Output with
// TapTree on the same PSBT and verifies both round-trip without
// cross-contamination on the now-separated types.
func TestPSBTTapTreeAndTapLeafScriptsCoexist(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("000000000000000000000000000000000000000000000000000000000000c0e1")
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
				Value:    75000,
				PkScript: []byte{0x51, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf},
			},
		},
		LockTime: 0,
	}

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}

	// Per-input TapLeafScripts: real BIP341 control blocks.
	cbA := make([]byte, 33)
	cbA[0] = 0xc0
	for i := 1; i < 33; i++ {
		cbA[i] = byte(i + 0x10)
	}
	cbB := make([]byte, 33+32)
	cbB[0] = 0xc0
	for i := 1; i < len(cbB); i++ {
		cbB[i] = byte(i + 0x40)
	}
	psbt.Inputs[0].TapLeafScripts = []TapLeaf{
		{LeafVersion: 0xc0, Script: []byte{0x51, 0x52}, ControlBlock: cbA},
		{LeafVersion: 0xc0, Script: []byte{0x76, 0xa9, 0x14, 0xde, 0xad}, ControlBlock: cbB},
	}

	// Per-output TapTree: 3 leaves at depths 1, 2, 2. Crucially the
	// scripts are DIFFERENT from the per-input ones, so any cross-
	// contamination between the two field types would surface as a
	// bytewise mismatch in the round-trip.
	psbt.Outputs[0].TapTree = []TapTreeLeaf{
		{Depth: 1, LeafVersion: 0xc0, Script: []byte{0x6a, 0x01, 0xff}},
		{Depth: 2, LeafVersion: 0xc0, Script: []byte{0xa9, 0x14, 0x00, 0x11, 0x22}},
		{Depth: 2, LeafVersion: 0xc0, Script: []byte{0x21, 0x03, 0xaa, 0xbb, 0xcc, 0xdd}},
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("DecodePSBT: %v", err)
	}

	// --- Per-input TapLeafScripts: verify control blocks are real
	// 33 / 65-byte BIP341 control blocks, not a 1-byte depth stub.
	gotInLeaves := decoded.Inputs[0].TapLeafScripts
	if len(gotInLeaves) != 2 {
		t.Fatalf("expected 2 input TapLeafScripts, got %d", len(gotInLeaves))
	}
	wantByCB := map[string]TapLeaf{
		string(cbA): {LeafVersion: 0xc0, Script: []byte{0x51, 0x52}, ControlBlock: cbA},
		string(cbB): {LeafVersion: 0xc0, Script: []byte{0x76, 0xa9, 0x14, 0xde, 0xad}, ControlBlock: cbB},
	}
	for i, leaf := range gotInLeaves {
		want, ok := wantByCB[string(leaf.ControlBlock)]
		if !ok {
			t.Fatalf("input leaf %d unrecognized control block %x", i, leaf.ControlBlock)
		}
		if len(leaf.ControlBlock) != 33 && len(leaf.ControlBlock) != 65 {
			t.Errorf("input leaf %d: control block length %d, want 33 or 65 (real BIP341)", i, len(leaf.ControlBlock))
		}
		if leaf.LeafVersion != want.LeafVersion {
			t.Errorf("input leaf %d: LeafVersion got 0x%02x want 0x%02x", i, leaf.LeafVersion, want.LeafVersion)
		}
		if !bytes.Equal(leaf.Script, want.Script) {
			t.Errorf("input leaf %d: Script got %x want %x", i, leaf.Script, want.Script)
		}
		if !bytes.Equal(leaf.ControlBlock, want.ControlBlock) {
			t.Errorf("input leaf %d: ControlBlock got %x want %x", i, leaf.ControlBlock, want.ControlBlock)
		}
	}

	// --- Per-output TapTree: verify Depth is recovered as a first-class
	// field; the type is TapTreeLeaf, which has no ControlBlock at all.
	gotOutLeaves := decoded.Outputs[0].TapTree
	if len(gotOutLeaves) != 3 {
		t.Fatalf("expected 3 output TapTree leaves, got %d", len(gotOutLeaves))
	}
	wantOut := psbt.Outputs[0].TapTree
	for i := range wantOut {
		if gotOutLeaves[i].Depth != wantOut[i].Depth {
			t.Errorf("output leaf %d: Depth got %d want %d", i, gotOutLeaves[i].Depth, wantOut[i].Depth)
		}
		if gotOutLeaves[i].LeafVersion != wantOut[i].LeafVersion {
			t.Errorf("output leaf %d: LeafVersion got 0x%02x want 0x%02x", i, gotOutLeaves[i].LeafVersion, wantOut[i].LeafVersion)
		}
		if !bytes.Equal(gotOutLeaves[i].Script, wantOut[i].Script) {
			t.Errorf("output leaf %d: Script got %x want %x", i, gotOutLeaves[i].Script, wantOut[i].Script)
		}
	}

	// --- Cross-contamination guard: ensure no input ControlBlock is
	// 1 byte (i.e. nobody mistook a tap-tree depth for a control block),
	// and ensure all output Depth values are small ints (≤ some sane
	// taproot tree bound), not bytes that look like the leading byte of
	// a control block (0xc0 / 0xc1).
	for i, leaf := range gotInLeaves {
		if len(leaf.ControlBlock) == 1 {
			t.Errorf("input leaf %d: ControlBlock degenerated to 1-byte stub (length %d) — type cross-contamination", i, len(leaf.ControlBlock))
		}
	}
	for i, leaf := range gotOutLeaves {
		if leaf.Depth > 128 {
			t.Errorf("output leaf %d: Depth=%d looks like a control-block tag byte (0xc0/0xc1) — type cross-contamination", i, leaf.Depth)
		}
	}

	// Re-encode and assert byte-for-byte match.
	reEncoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Errorf("PSBT TapTree+TapLeafScripts coexist round-trip not byte-identical (len %d vs %d)", len(encoded), len(reEncoded))
	}
}

// TestPSBTMultiInputRoundTrip — 3-input PSBT round-trip, asserting that
// per-input data stays bound to the correct index after encode+decode.
// (W34-B.)
func TestPSBTMultiInputRoundTrip(t *testing.T) {
	prevHash0, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000001")
	prevHash1, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000002")
	prevHash2, _ := wire.NewHash256FromHex("0000000000000000000000000000000000000000000000000000000000000003")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: prevHash0, Index: 0}, Sequence: 0xffffffff},
			{PreviousOutPoint: wire.OutPoint{Hash: prevHash1, Index: 7}, Sequence: 0xffffffff},
			{PreviousOutPoint: wire.OutPoint{Hash: prevHash2, Index: 42}, Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{
			{Value: 30000, PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}},
		},
		LockTime: 0,
	}

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}

	// Tag each input differently so we can verify ordering.
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{Value: 10000, PkScript: []byte{0xAA, 0x00}}
	psbt.Inputs[0].SighashType = 0x01

	psbt.Inputs[1].WitnessUTXO = &wire.TxOut{Value: 20000, PkScript: []byte{0xBB, 0x00}}
	psbt.Inputs[1].SighashType = 0x02
	psbt.Inputs[1].RedeemScript = []byte{0x21, 0xBB, 0xBB, 0xBB, 0xAC}

	psbt.Inputs[2].WitnessUTXO = &wire.TxOut{Value: 30000, PkScript: []byte{0xCC, 0x00}}
	psbt.Inputs[2].SighashType = 0x03
	psbt.Inputs[2].WitnessScript = []byte{0x52, 0xCC, 0xCC, 0xCC, 0x52, 0xAE}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("DecodePSBT: %v", err)
	}
	if len(decoded.Inputs) != 3 {
		t.Fatalf("expected 3 inputs, got %d", len(decoded.Inputs))
	}

	// Per-index witness UTXO value uniquely identifies each input.
	wantValues := []int64{10000, 20000, 30000}
	for i, want := range wantValues {
		if decoded.Inputs[i].WitnessUTXO == nil {
			t.Fatalf("input %d: WitnessUTXO missing after decode", i)
		}
		if decoded.Inputs[i].WitnessUTXO.Value != want {
			t.Errorf("input %d: WitnessUTXO.Value got %d want %d (input ordering broken)",
				i, decoded.Inputs[i].WitnessUTXO.Value, want)
		}
	}

	// PreviousOutPoint indices preserved 1:1.
	wantOutpointIdx := []uint32{0, 7, 42}
	for i, want := range wantOutpointIdx {
		got := decoded.UnsignedTx.TxIn[i].PreviousOutPoint.Index
		if got != want {
			t.Errorf("input %d: PreviousOutPoint.Index got %d want %d", i, got, want)
		}
	}

	// SighashType + RedeemScript + WitnessScript landed on the right input.
	if decoded.Inputs[0].SighashType != 0x01 || decoded.Inputs[1].SighashType != 0x02 || decoded.Inputs[2].SighashType != 0x03 {
		t.Errorf("SighashType ordering broken: got [%d %d %d]",
			decoded.Inputs[0].SighashType, decoded.Inputs[1].SighashType, decoded.Inputs[2].SighashType)
	}
	if !bytes.Equal(decoded.Inputs[1].RedeemScript, []byte{0x21, 0xBB, 0xBB, 0xBB, 0xAC}) {
		t.Errorf("input 1 RedeemScript not preserved: got %x", decoded.Inputs[1].RedeemScript)
	}
	if !bytes.Equal(decoded.Inputs[2].WitnessScript, []byte{0x52, 0xCC, 0xCC, 0xCC, 0x52, 0xAE}) {
		t.Errorf("input 2 WitnessScript not preserved: got %x", decoded.Inputs[2].WitnessScript)
	}
	if len(decoded.Inputs[0].RedeemScript) != 0 {
		t.Errorf("input 0 should not have RedeemScript, got %x", decoded.Inputs[0].RedeemScript)
	}
}

// TestPSBTEncodedBytesNoSegwitMarker — BIP-174 invariant: the unsigned
// transaction in PSBT_GLOBAL_UNSIGNED_TX MUST be serialized WITHOUT the
// segwit marker+flag, even when the source tx carries witnesses (the
// witnesses are illegal in the unsigned tx anyway, but this covers the
// case where a caller supplies a tx whose witnesses were stripped at
// the API boundary). We verify that the first two bytes after the
// 4-byte version field are NOT 0x00 0x01. (W34-B.)
func TestPSBTEncodedBytesNoSegwitMarker(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("00000000000000000000000000000000000000000000000000000000deadbeef")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
				Sequence:         0xffffffff,
				// NB: NewPSBT rejects pre-populated witness, so leave empty.
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 100000, PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}},
		},
		LockTime: 0,
	}

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Walk the encoded blob: 5-byte magic, then the first global key/value
	// (which by BIP-174 MUST be PSBT_GLOBAL_UNSIGNED_TX, key 0x00).
	if len(encoded) < 5 || !bytes.Equal(encoded[:5], psbtMagic) {
		end := len(encoded)
		if end > 5 {
			end = 5
		}
		t.Fatalf("encoded PSBT does not start with magic: %x", encoded[:end])
	}

	r := bytes.NewReader(encoded[5:])
	key, value, err := readKeyValue(r)
	if err != nil {
		t.Fatalf("readKeyValue (global): %v", err)
	}
	if len(key) != 1 || key[0] != PSBTGlobalUnsignedTx {
		t.Fatalf("first global key must be PSBTGlobalUnsignedTx (0x00), got %x", key)
	}

	// value = serialized unsigned tx. Layout:
	//   [0..4]  version (int32 LE)
	//   [4..]   marker+flag if segwit, else input-count CompactSize
	if len(value) < 6 {
		t.Fatalf("unsigned tx blob too short: %d bytes", len(value))
	}
	if value[4] == 0x00 && value[5] == 0x01 {
		t.Fatalf("BIP-174 violation: PSBT_GLOBAL_UNSIGNED_TX contains segwit marker+flag (0x00 0x01) at offset 4-5; got blob %x", value)
	}

	// Sanity: the blob must also deserialize back to a tx with identical
	// inputs/outputs (and no witnesses, since SerializeNoWitness was used).
	var rt wire.MsgTx
	if err := rt.Deserialize(bytes.NewReader(value)); err != nil {
		t.Fatalf("Deserialize unsigned tx: %v", err)
	}
	if rt.Version != 2 || len(rt.TxIn) != 1 || len(rt.TxOut) != 1 {
		t.Fatalf("unsigned tx round-trip mismatch: version=%d in=%d out=%d", rt.Version, len(rt.TxIn), len(rt.TxOut))
	}
	for i, in := range rt.TxIn {
		if len(in.Witness) != 0 {
			t.Errorf("input %d: unsigned tx must have no witness, got %d items", i, len(in.Witness))
		}
	}
}

// ---------------------------------------------------------------------------
// W41 — PSBT NON_WITNESS_UTXO consistency (Bitcoin Core PSBTInput::IsSane)
// ---------------------------------------------------------------------------

// buildPrevTx returns a 1-output transaction with the given (value,
// pkScript). Asymmetric byte fixture (W32-B): value/pkScript are
// non-palindromic so a byte-swap regression cannot accidentally pass.
func buildPrevTxW41(value int64, pkScript []byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				// Coinbase-style null input is fine for the fixture; we
				// only care about the tx's serialized bytes -> txid.
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
				SignatureScript:  []byte{0x51, 0x52}, // OP_1 OP_2 — asymmetric
				Sequence:         0xfffffffd,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: value, PkScript: append([]byte(nil), pkScript...)},
		},
		LockTime: 0,
	}
}

// TestPSBTValidate_A1_NonWitnessTxidMismatch builds a PSBT whose
// PSBT_IN_NON_WITNESS_UTXO serializes to a tx whose txid does NOT
// match the unsigned tx's input prevout. The parser MUST reject.
// W40-A bug A1: the signer would otherwise consume the forged
// NonWitnessUTXO.TxOut[idx] directly (psbt_ops.go:266) and sign over
// attacker-controlled values.
func TestPSBTValidate_A1_NonWitnessTxidMismatch(t *testing.T) {
	prevTx := buildPrevTxW41(123_456_789, []byte{
		0x76, 0xa9, 0x14,
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x88, 0xac,
	})
	realTxid := prevTx.TxHash()

	// Forge a different prevout hash by flipping one byte. Asymmetric
	// modification — never collides with the real txid.
	var forgedHash wire.Hash256
	copy(forgedHash[:], realTxid[:])
	forgedHash[0] ^= 0x5a

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: forgedHash, Index: 0},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 100_000, PkScript: []byte{0x6a, 0x01, 0x41}}, // OP_RETURN 'A'
		},
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt.Inputs[0].NonWitnessUTXO = prevTx

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode (test fixture build): %v", err)
	}

	_, err = DecodePSBT(encoded)
	if err == nil {
		t.Fatal("DecodePSBT accepted PSBT with mismatched NON_WITNESS_UTXO txid; want reject")
	}
	if !errors.Is(err, ErrPSBTNonWitnessUTXOMismatch) {
		t.Fatalf("got error %v, want ErrPSBTNonWitnessUTXOMismatch", err)
	}

	// And direct in-process validator call (signer-dispatch code path).
	if got := validatePSBTInput(&psbt.Inputs[0], tx.TxIn[0].PreviousOutPoint); !errors.Is(got, ErrPSBTNonWitnessUTXOMismatch) {
		t.Fatalf("validatePSBTInput direct call: got %v, want ErrPSBTNonWitnessUTXOMismatch", got)
	}

	// Sanity: the same NonWitnessUTXO IS accepted when the prevout
	// matches the real txid (proves the test fixture is well-formed
	// and the rejection above is specifically about the txid check).
	tx.TxIn[0].PreviousOutPoint.Hash = realTxid
	psbt2 := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt2.Inputs[0].NonWitnessUTXO = prevTx
	encoded2, err := psbt2.Encode()
	if err != nil {
		t.Fatalf("Encode (positive-control fixture): %v", err)
	}
	if _, err := DecodePSBT(encoded2); err != nil {
		t.Fatalf("DecodePSBT rejected the positive-control PSBT: %v", err)
	}
}

// TestPSBTValidate_A2_WitnessAmountMismatch builds a PSBT where both
// WITNESS_UTXO and NON_WITNESS_UTXO are present and refer to the same
// (txid, vout) — but the WITNESS_UTXO lies about the amount. CVE-
// 2020-14199: the BIP-143 sighash committed by the signer is over
// `value` from WITNESS_UTXO; if the wallet trusts WITNESS_UTXO without
// cross-checking, an attacker can trick the user into signing away
// their full UTXO as fee.
func TestPSBTValidate_A2_WitnessAmountMismatch(t *testing.T) {
	pkScript := []byte{
		0x00, 0x14,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
	}
	const realValue int64 = 50_000_000   // 0.5 BTC
	const liedValue int64 = 1_000        // attacker says it's only 1000 sat
	prevTx := buildPrevTxW41(realValue, pkScript)
	realTxid := prevTx.TxHash()

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: realTxid, Index: 0},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 900, PkScript: []byte{0x6a, 0x02, 0x41, 0x42}},
		},
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt.Inputs[0].NonWitnessUTXO = prevTx
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    liedValue,
		PkScript: append([]byte(nil), pkScript...),
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode (test fixture build): %v", err)
	}

	_, err = DecodePSBT(encoded)
	if err == nil {
		t.Fatal("DecodePSBT accepted PSBT with WITNESS_UTXO amount lie; want reject (CVE-2020-14199)")
	}
	if !errors.Is(err, ErrWitnessUtxoMismatch) {
		t.Fatalf("got error %v, want ErrWitnessUtxoMismatch", err)
	}

	// In-process validator must agree.
	if got := validatePSBTInput(&psbt.Inputs[0], tx.TxIn[0].PreviousOutPoint); !errors.Is(got, ErrWitnessUtxoMismatch) {
		t.Fatalf("validatePSBTInput direct call: got %v, want ErrWitnessUtxoMismatch", got)
	}
}

// TestPSBTValidate_A2_WitnessScriptMismatch — same shape as the amount
// test, but the WITNESS_UTXO's pkScript disagrees with the on-chain
// pkScript at NON_WITNESS_UTXO.TxOut[vout]. Equally fatal: the signer's
// script-type dispatch (P2WPKH vs P2WSH vs P2TR) hangs off
// utxo.PkScript, so a forged witness-utxo can re-route the dispatcher
// into the wrong sighash branch.
func TestPSBTValidate_A2_WitnessScriptMismatch(t *testing.T) {
	realPkScript := []byte{
		0x00, 0x14,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xa1, 0xb2, 0xc3, 0xd4,
	}
	// Asymmetric forgery: same length P2WPKH-shaped script, totally
	// different hash. (Different hash, different value would also
	// trip the value branch — keep value EQUAL so we know this test
	// fails specifically on the script check.)
	forgedPkScript := []byte{
		0x00, 0x14,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	}
	if bytes.Equal(realPkScript, forgedPkScript) {
		t.Fatal("test fixture invariant: realPkScript != forgedPkScript")
	}

	const sharedValue int64 = 7_777_777
	prevTx := buildPrevTxW41(sharedValue, realPkScript)
	realTxid := prevTx.TxHash()

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: realTxid, Index: 0},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 7_000_000, PkScript: []byte{0x6a, 0x03, 0x41, 0x42, 0x43}},
		},
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	psbt.Inputs[0].NonWitnessUTXO = prevTx
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    sharedValue, // identical, isolates the script check
		PkScript: append([]byte(nil), forgedPkScript...),
	}

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode (test fixture build): %v", err)
	}

	_, err = DecodePSBT(encoded)
	if err == nil {
		t.Fatal("DecodePSBT accepted PSBT with WITNESS_UTXO scriptPubKey lie; want reject")
	}
	if !errors.Is(err, ErrWitnessUtxoMismatch) {
		t.Fatalf("got error %v, want ErrWitnessUtxoMismatch", err)
	}

	if got := validatePSBTInput(&psbt.Inputs[0], tx.TxIn[0].PreviousOutPoint); !errors.Is(got, ErrWitnessUtxoMismatch) {
		t.Fatalf("validatePSBTInput direct call: got %v, want ErrWitnessUtxoMismatch", got)
	}

	// Positive control: making both UTXO oracles agree must pass.
	psbt.Inputs[0].WitnessUTXO.PkScript = append([]byte(nil), realPkScript...)
	encoded2, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode (positive control): %v", err)
	}
	if _, err := DecodePSBT(encoded2); err != nil {
		t.Fatalf("DecodePSBT rejected the positive-control PSBT: %v", err)
	}
}

// TestFinalizeMultisig_W43_ClearsProducerFields verifies that finalizing a
// P2WSH 2-of-2 multisig input clears all BIP-174 producer-only key types
// (partial_sigs, redeem_script, witness_script, sighash_type,
// bip32_derivation) so they are not leaked into the serialized PSBT.
//
// Pre-W43, finalizeMultisig set FinalScriptWitness and returned without
// calling clearInputSigningData, causing T3 (finalizepsbt) byte-divergence
// vs Bitcoin Core in tools/psbt-multi-input-test.sh.
//
// Mirrors lunarblock W41 commit 442301d (src/psbt.lua finalize_input).
//
// Asymmetric fixtures: two distinct compressed pubkeys, two distinct DER
// signatures, asymmetric BIP32 derivation paths, non-zero sighash type.
func TestFinalizeMultisig_W43_ClearsProducerFields(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("00000000000000000000000000000000000000000000000000000000abcdef01")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 7},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    98765,
				PkScript: []byte{0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			},
		},
	}

	// Two distinct compressed pubkeys (33 bytes, asymmetric — first byte
	// differs, body bytes also differ).
	pubKey1 := make([]byte, 33)
	pubKey1[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey1[i] = byte(0x10 + i)
	}
	pubKey2 := make([]byte, 33)
	pubKey2[0] = 0x03
	for i := 1; i < 33; i++ {
		pubKey2[i] = byte(0x80 - i)
	}

	// Two distinct DER signatures, sighash byte 0x01 (SIGHASH_ALL).
	mkSig := func(seed byte) []byte {
		sig := make([]byte, 71)
		sig[0] = 0x30
		sig[1] = 0x44
		sig[2] = 0x02
		sig[3] = 0x20
		for i := 4; i < 36; i++ {
			sig[i] = seed ^ byte(i)
		}
		sig[36] = 0x02
		sig[37] = 0x20
		for i := 38; i < 70; i++ {
			sig[i] = seed ^ byte(0xa5-i)
		}
		sig[70] = 0x01
		return sig
	}
	sig1 := mkSig(0x11)
	sig2 := mkSig(0x42)

	// Witness script: OP_2 <pubKey1> <pubKey2> OP_2 OP_CHECKMULTISIG.
	witnessScript := []byte{0x52, 0x21}
	witnessScript = append(witnessScript, pubKey1...)
	witnessScript = append(witnessScript, 0x21)
	witnessScript = append(witnessScript, pubKey2...)
	witnessScript = append(witnessScript, 0x52, 0xae)

	// P2WSH UTXO program: OP_0 <32-byte-hash>. The finalizer does not
	// recompute SHA256(witnessScript) here, so any 32-byte placeholder
	// works; we use an asymmetric one to avoid palindrome fixtures.
	witnessProgram := make([]byte, 34)
	witnessProgram[0] = 0x00
	witnessProgram[1] = 0x20
	for i := 2; i < 34; i++ {
		witnessProgram[i] = byte(0xa0 + i)
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, 1),
		Outputs:    make([]PSBTOutput, 1),
	}
	in := &psbt.Inputs[0]
	in.WitnessUTXO = &wire.TxOut{Value: 200_000, PkScript: witnessProgram}
	in.WitnessScript = witnessScript
	in.SighashType = 0x01
	in.PartialSigs = map[string][]byte{
		string(pubKey1): sig1,
		string(pubKey2): sig2,
	}
	in.BIP32Derivation = map[string]*BIP32Derivation{
		string(pubKey1): {
			Fingerprint: [4]byte{0xde, 0xad, 0xbe, 0xef},
			Path:        []uint32{0x80000000 | 84, 0x80000000, 0x80000000, 0, 5},
		},
		string(pubKey2): {
			Fingerprint: [4]byte{0xca, 0xfe, 0xba, 0xbe},
			Path:        []uint32{0x80000000 | 84, 0x80000000, 0x80000000, 1, 9},
		},
	}

	complete, err := FinalizePSBT(psbt)
	if err != nil {
		t.Fatalf("FinalizePSBT: %v", err)
	}
	if !complete {
		t.Fatal("expected multisig PSBT to be complete after finalization")
	}

	// Finalized fields MUST be set.
	if len(in.FinalScriptWitness) == 0 {
		t.Fatal("FinalScriptWitness empty after finalize")
	}
	// Witness shape: [OP_0, sig1, sig2, witnessScript].
	if len(in.FinalScriptWitness) != 4 {
		t.Fatalf("expected 4 witness items, got %d", len(in.FinalScriptWitness))
	}
	if !bytes.Equal(in.FinalScriptWitness[3], witnessScript) {
		t.Errorf("witness[3] != witnessScript")
	}

	// W43 invariant: producer fields MUST be cleared.
	if len(in.PartialSigs) != 0 {
		t.Errorf("PartialSigs not cleared after finalize: got %d entries", len(in.PartialSigs))
	}
	if len(in.WitnessScript) != 0 {
		t.Errorf("WitnessScript not cleared after finalize: got %x", in.WitnessScript)
	}
	if len(in.RedeemScript) != 0 {
		t.Errorf("RedeemScript not cleared after finalize: got %x", in.RedeemScript)
	}
	if in.SighashType != 0 {
		t.Errorf("SighashType not cleared after finalize: got 0x%x", in.SighashType)
	}
	if len(in.BIP32Derivation) != 0 {
		t.Errorf("BIP32Derivation not cleared after finalize: got %d entries", len(in.BIP32Derivation))
	}

	// And the encoded PSBT must not contain the producer key types for
	// this input. Since we only keep finalized data, an encode/decode
	// round-trip on the finalized PSBT must yield empty producer fields.
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("Encode (finalized): %v", err)
	}
	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("DecodePSBT (finalized): %v", err)
	}
	if len(decoded.Inputs) != 1 {
		t.Fatalf("expected 1 input on decode, got %d", len(decoded.Inputs))
	}
	d := decoded.Inputs[0]
	if len(d.PartialSigs) != 0 {
		t.Errorf("decoded.PartialSigs leaked: %d entries", len(d.PartialSigs))
	}
	if len(d.WitnessScript) != 0 {
		t.Errorf("decoded.WitnessScript leaked: %x", d.WitnessScript)
	}
	if len(d.RedeemScript) != 0 {
		t.Errorf("decoded.RedeemScript leaked: %x", d.RedeemScript)
	}
	if d.SighashType != 0 {
		t.Errorf("decoded.SighashType leaked: 0x%x", d.SighashType)
	}
	if len(d.BIP32Derivation) != 0 {
		t.Errorf("decoded.BIP32Derivation leaked: %d entries", len(d.BIP32Derivation))
	}
	if len(d.FinalScriptWitness) != 4 {
		t.Errorf("decoded FinalScriptWitness shape lost: got %d items", len(d.FinalScriptWitness))
	}
}

