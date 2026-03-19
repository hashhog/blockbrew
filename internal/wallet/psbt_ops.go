package wallet

import (
	"bytes"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// CombinePSBTs merges multiple PSBTs into one.
// All PSBTs must have the same underlying unsigned transaction.
func CombinePSBTs(psbts []*PSBT) (*PSBT, error) {
	if len(psbts) == 0 {
		return nil, errors.New("no PSBTs to combine")
	}

	if len(psbts) == 1 {
		return psbts[0], nil
	}

	// Use the first PSBT as the base
	result := psbts[0]
	baseTxHash := result.UnsignedTx.TxHash()

	// Merge each subsequent PSBT
	for i := 1; i < len(psbts); i++ {
		other := psbts[i]

		// Verify transactions match
		if other.UnsignedTx.TxHash() != baseTxHash {
			return nil, ErrPSBTTxMismatch
		}

		// Verify counts match
		if len(other.Inputs) != len(result.Inputs) {
			return nil, ErrPSBTInputCountMismatch
		}
		if len(other.Outputs) != len(result.Outputs) {
			return nil, ErrPSBTOutputCountMismatch
		}

		// Merge global xpubs
		for k, v := range other.XPubs {
			if _, exists := result.XPubs[k]; !exists {
				result.XPubs[k] = v
			}
		}

		// Merge global unknowns
		for k, v := range other.Unknown {
			if _, exists := result.Unknown[k]; !exists {
				result.Unknown[k] = v
			}
		}

		// Merge inputs
		for j := range result.Inputs {
			mergeInput(&result.Inputs[j], &other.Inputs[j])
		}

		// Merge outputs
		for j := range result.Outputs {
			mergeOutput(&result.Outputs[j], &other.Outputs[j])
		}
	}

	return result, nil
}

// mergeInput merges data from src into dst.
func mergeInput(dst, src *PSBTInput) {
	// Take UTXOs if not present
	if dst.NonWitnessUTXO == nil && src.NonWitnessUTXO != nil {
		dst.NonWitnessUTXO = src.NonWitnessUTXO
	}
	if dst.WitnessUTXO == nil && src.WitnessUTXO != nil {
		dst.WitnessUTXO = src.WitnessUTXO
	}

	// Merge partial signatures
	for k, v := range src.PartialSigs {
		if _, exists := dst.PartialSigs[k]; !exists {
			dst.PartialSigs[k] = v
		}
	}

	// Take sighash type if not set
	if dst.SighashType == 0 && src.SighashType != 0 {
		dst.SighashType = src.SighashType
	}

	// Take scripts if not present
	if len(dst.RedeemScript) == 0 && len(src.RedeemScript) > 0 {
		dst.RedeemScript = src.RedeemScript
	}
	if len(dst.WitnessScript) == 0 && len(src.WitnessScript) > 0 {
		dst.WitnessScript = src.WitnessScript
	}

	// Merge BIP32 derivations
	for k, v := range src.BIP32Derivation {
		if _, exists := dst.BIP32Derivation[k]; !exists {
			dst.BIP32Derivation[k] = v
		}
	}

	// Take final scripts if not present
	if len(dst.FinalScriptSig) == 0 && len(src.FinalScriptSig) > 0 {
		dst.FinalScriptSig = src.FinalScriptSig
	}
	if len(dst.FinalScriptWitness) == 0 && len(src.FinalScriptWitness) > 0 {
		dst.FinalScriptWitness = src.FinalScriptWitness
	}

	// Merge hash preimages
	for k, v := range src.RIPEMD160Preimages {
		if _, exists := dst.RIPEMD160Preimages[k]; !exists {
			dst.RIPEMD160Preimages[k] = v
		}
	}
	for k, v := range src.SHA256Preimages {
		if _, exists := dst.SHA256Preimages[k]; !exists {
			dst.SHA256Preimages[k] = v
		}
	}
	for k, v := range src.HASH160Preimages {
		if _, exists := dst.HASH160Preimages[k]; !exists {
			dst.HASH160Preimages[k] = v
		}
	}
	for k, v := range src.HASH256Preimages {
		if _, exists := dst.HASH256Preimages[k]; !exists {
			dst.HASH256Preimages[k] = v
		}
	}

	// Merge taproot fields
	if len(dst.TapKeySig) == 0 && len(src.TapKeySig) > 0 {
		dst.TapKeySig = src.TapKeySig
	}

	for k, v := range src.TapScriptSigs {
		if _, exists := dst.TapScriptSigs[k]; !exists {
			dst.TapScriptSigs[k] = v
		}
	}

	// Merge tap leaf scripts (by control block)
	existingLeaves := make(map[string]bool)
	for _, leaf := range dst.TapLeafScripts {
		existingLeaves[string(leaf.ControlBlock)] = true
	}
	for _, leaf := range src.TapLeafScripts {
		if !existingLeaves[string(leaf.ControlBlock)] {
			dst.TapLeafScripts = append(dst.TapLeafScripts, leaf)
		}
	}

	for k, v := range src.TapBIP32Derivation {
		if _, exists := dst.TapBIP32Derivation[k]; !exists {
			dst.TapBIP32Derivation[k] = v
		}
	}

	if len(dst.TapInternalKey) == 0 && len(src.TapInternalKey) > 0 {
		dst.TapInternalKey = src.TapInternalKey
	}
	if len(dst.TapMerkleRoot) == 0 && len(src.TapMerkleRoot) > 0 {
		dst.TapMerkleRoot = src.TapMerkleRoot
	}

	// Merge unknowns
	for k, v := range src.Unknown {
		if _, exists := dst.Unknown[k]; !exists {
			dst.Unknown[k] = v
		}
	}
}

// mergeOutput merges data from src into dst.
func mergeOutput(dst, src *PSBTOutput) {
	// Take scripts if not present
	if len(dst.RedeemScript) == 0 && len(src.RedeemScript) > 0 {
		dst.RedeemScript = src.RedeemScript
	}
	if len(dst.WitnessScript) == 0 && len(src.WitnessScript) > 0 {
		dst.WitnessScript = src.WitnessScript
	}

	// Merge BIP32 derivations
	for k, v := range src.BIP32Derivation {
		if _, exists := dst.BIP32Derivation[k]; !exists {
			dst.BIP32Derivation[k] = v
		}
	}

	// Merge taproot fields
	if len(dst.TapInternalKey) == 0 && len(src.TapInternalKey) > 0 {
		dst.TapInternalKey = src.TapInternalKey
	}

	if len(dst.TapTree) == 0 && len(src.TapTree) > 0 {
		dst.TapTree = src.TapTree
	}

	for k, v := range src.TapBIP32Derivation {
		if _, exists := dst.TapBIP32Derivation[k]; !exists {
			dst.TapBIP32Derivation[k] = v
		}
	}

	// Merge unknowns
	for k, v := range src.Unknown {
		if _, exists := dst.Unknown[k]; !exists {
			dst.Unknown[k] = v
		}
	}
}

// PSBTSigner is the interface for signing PSBT inputs.
type PSBTSigner interface {
	// SignPSBTInput signs the input at the given index.
	// Returns true if a signature was added, false if no key was available.
	SignPSBTInput(psbt *PSBT, idx int) (bool, error)
}

// WalletPSBTSigner implements PSBTSigner using wallet keys.
type WalletPSBTSigner struct {
	wallet *Wallet
}

// NewWalletPSBTSigner creates a new signer using the given wallet.
func NewWalletPSBTSigner(w *Wallet) *WalletPSBTSigner {
	return &WalletPSBTSigner{wallet: w}
}

// SignPSBTInput signs the input using wallet keys.
func (s *WalletPSBTSigner) SignPSBTInput(psbt *PSBT, idx int) (bool, error) {
	if s.wallet == nil {
		return false, errors.New("no wallet configured")
	}

	if s.wallet.IsLocked() {
		return false, ErrWalletLocked
	}

	input := &psbt.Inputs[idx]

	// Skip already finalized inputs
	if len(input.FinalScriptSig) > 0 || len(input.FinalScriptWitness) > 0 {
		return false, nil
	}

	// Get the UTXO information
	var utxo *wire.TxOut
	if input.WitnessUTXO != nil {
		utxo = input.WitnessUTXO
	} else if input.NonWitnessUTXO != nil {
		prevOutpoint := psbt.UnsignedTx.TxIn[idx].PreviousOutPoint
		if int(prevOutpoint.Index) >= len(input.NonWitnessUTXO.TxOut) {
			return false, ErrPSBTNoUTXO
		}
		utxo = input.NonWitnessUTXO.TxOut[prevOutpoint.Index]
	} else {
		return false, ErrPSBTNoUTXO
	}

	// Try to find a key we can sign with
	signed := false

	// Check BIP32 derivation paths for keys we own
	for pubKeyStr, deriv := range input.BIP32Derivation {
		pubKeyBytes := []byte(pubKeyStr)

		// Check if this fingerprint matches our master key
		fingerprint, err := s.wallet.GetMasterFingerprint()
		if err != nil {
			continue
		}
		if deriv.Fingerprint != fingerprint {
			continue
		}

		// Derive the key at this path
		privKey, err := s.deriveKey(deriv.Path)
		if err != nil {
			continue
		}

		// Verify the pubkey matches
		derivedPubKey := privKey.PubKey().SerializeCompressed()
		if !bytes.Equal(derivedPubKey, pubKeyBytes) {
			continue
		}

		// Sign based on script type
		err = s.signInputWithKey(psbt, idx, input, utxo, privKey, pubKeyBytes)
		if err != nil {
			return false, err
		}
		signed = true
	}

	// Also check taproot BIP32 derivations
	for xonlyStr, deriv := range input.TapBIP32Derivation {
		xonlyBytes := []byte(xonlyStr)

		// Check fingerprint
		fingerprint, err := s.wallet.GetMasterFingerprint()
		if err != nil {
			continue
		}
		if deriv.Fingerprint != fingerprint {
			continue
		}

		// Derive the key
		privKey, err := s.deriveKey(deriv.Path)
		if err != nil {
			continue
		}

		// For taproot, we need to sign with the tweaked key
		err = s.signTaprootInput(psbt, idx, input, utxo, privKey, xonlyBytes)
		if err != nil {
			return false, err
		}
		signed = true
	}

	return signed, nil
}

// deriveKey derives a private key at the given path.
func (s *WalletPSBTSigner) deriveKey(path []uint32) (*bbcrypto.PrivateKey, error) {
	s.wallet.mu.RLock()
	masterKey := s.wallet.masterKey
	s.wallet.mu.RUnlock()

	if masterKey == nil {
		return nil, ErrNoMasterKey
	}

	key := masterKey
	for _, idx := range path {
		var err error
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}

	return key.ECPrivKey()
}

// signInputWithKey signs a non-taproot input.
func (s *WalletPSBTSigner) signInputWithKey(psbt *PSBT, idx int, input *PSBTInput, utxo *wire.TxOut, privKey *bbcrypto.PrivateKey, pubKey []byte) error {
	pkScript := utxo.PkScript

	// Determine sighash type
	hashType := script.SigHashType(input.SighashType)
	if hashType == 0 {
		hashType = script.SigHashAll
	}

	var sig []byte

	switch {
	case isP2WPKH(pkScript):
		// P2WPKH
		pubKeyHash := bbcrypto.Hash160(pubKey)
		scriptCode := buildP2PKHScriptCode(pubKeyHash[:])
		sighash, err := script.CalcWitnessSignatureHash(scriptCode, hashType, psbt.UnsignedTx, idx, utxo.Value)
		if err != nil {
			return err
		}
		sig, err = bbcrypto.SignECDSA(privKey, sighash)
		if err != nil {
			return err
		}
		sig = append(sig, byte(hashType))

	case isP2WSH(pkScript):
		// P2WSH - use witness script
		if len(input.WitnessScript) == 0 {
			return errors.New("missing witness script for P2WSH")
		}
		sighash, err := script.CalcWitnessSignatureHash(input.WitnessScript, hashType, psbt.UnsignedTx, idx, utxo.Value)
		if err != nil {
			return err
		}
		sig, err = bbcrypto.SignECDSA(privKey, sighash)
		if err != nil {
			return err
		}
		sig = append(sig, byte(hashType))

	case isP2SH(pkScript):
		// P2SH - could be P2SH-P2WPKH or P2SH-P2WSH
		if len(input.RedeemScript) == 0 {
			return errors.New("missing redeem script for P2SH")
		}

		if isP2WPKH(input.RedeemScript) {
			// P2SH-P2WPKH
			pubKeyHash := bbcrypto.Hash160(pubKey)
			scriptCode := buildP2PKHScriptCode(pubKeyHash[:])
			sighash, err := script.CalcWitnessSignatureHash(scriptCode, hashType, psbt.UnsignedTx, idx, utxo.Value)
			if err != nil {
				return err
			}
			sig, err = bbcrypto.SignECDSA(privKey, sighash)
			if err != nil {
				return err
			}
			sig = append(sig, byte(hashType))
		} else if isP2WSH(input.RedeemScript) {
			// P2SH-P2WSH
			if len(input.WitnessScript) == 0 {
				return errors.New("missing witness script for P2SH-P2WSH")
			}
			sighash, err := script.CalcWitnessSignatureHash(input.WitnessScript, hashType, psbt.UnsignedTx, idx, utxo.Value)
			if err != nil {
				return err
			}
			sig, err = bbcrypto.SignECDSA(privKey, sighash)
			if err != nil {
				return err
			}
			sig = append(sig, byte(hashType))
		} else {
			// Legacy P2SH
			sighash, err := script.CalcSignatureHash(input.RedeemScript, hashType, psbt.UnsignedTx, idx)
			if err != nil {
				return err
			}
			sig, err = bbcrypto.SignECDSA(privKey, sighash)
			if err != nil {
				return err
			}
			sig = append(sig, byte(hashType))
		}

	case isP2PKH(pkScript):
		// Legacy P2PKH
		sighash, err := script.CalcSignatureHash(pkScript, hashType, psbt.UnsignedTx, idx)
		if err != nil {
			return err
		}
		sig, err = bbcrypto.SignECDSA(privKey, sighash)
		if err != nil {
			return err
		}
		sig = append(sig, byte(hashType))

	default:
		return errors.New("unsupported script type")
	}

	// Add partial signature
	input.PartialSigs[string(pubKey)] = sig
	return nil
}

// signTaprootInput signs a taproot input.
func (s *WalletPSBTSigner) signTaprootInput(psbt *PSBT, idx int, input *PSBTInput, utxo *wire.TxOut, privKey *bbcrypto.PrivateKey, xonlyPubKey []byte) error {
	// Build prevOuts for taproot sighash
	prevOuts := make([]*wire.TxOut, len(psbt.UnsignedTx.TxIn))
	for i, txIn := range psbt.UnsignedTx.TxIn {
		if i == idx {
			prevOuts[i] = utxo
		} else {
			// Need UTXO info for all inputs
			inp := &psbt.Inputs[i]
			if inp.WitnessUTXO != nil {
				prevOuts[i] = inp.WitnessUTXO
			} else if inp.NonWitnessUTXO != nil {
				prevOut := txIn.PreviousOutPoint
				if int(prevOut.Index) < len(inp.NonWitnessUTXO.TxOut) {
					prevOuts[i] = inp.NonWitnessUTXO.TxOut[prevOut.Index]
				}
			}
			if prevOuts[i] == nil {
				return errors.New("missing UTXO for taproot sighash")
			}
		}
	}

	pubKey := privKey.PubKey()
	compressed := pubKey.SerializeCompressed()
	internalXOnly := compressed[1:33]

	// Calculate tweak
	var merkleRoot []byte
	if len(input.TapMerkleRoot) == 32 {
		merkleRoot = input.TapMerkleRoot
	}
	tweakHash := script.TapTweak(internalXOnly, merkleRoot)

	// Compute tweaked private key
	needsNegate := compressed[0] == 0x03
	tweakedPrivKeyBytes, err := s.computeTweakedPrivKey(privKey.Inner().Serialize(), tweakHash, needsNegate)
	if err != nil {
		return err
	}
	tweakedPrivKey := bbcrypto.PrivateKeyFromBytes(tweakedPrivKeyBytes)

	// Calculate sighash
	sighash, err := script.CalcTaprootSignatureHash(
		script.SigHashDefault,
		psbt.UnsignedTx,
		idx,
		prevOuts,
		nil, // No annex
	)
	if err != nil {
		return err
	}

	// Sign with Schnorr
	sig, err := bbcrypto.SignSchnorr(tweakedPrivKey, sighash)
	if err != nil {
		return err
	}

	// For SIGHASH_DEFAULT, signature is 64 bytes (no suffix)
	input.TapKeySig = sig
	return nil
}

// computeTweakedPrivKey computes the tweaked private key for taproot.
func (s *WalletPSBTSigner) computeTweakedPrivKey(privKeyBytes []byte, tweakHash [32]byte, negate bool) ([]byte, error) {
	var privScalar secp256k1.ModNScalar
	privScalar.SetByteSlice(privKeyBytes)

	if negate {
		privScalar.Negate()
	}

	var tweakScalar secp256k1.ModNScalar
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		return nil, errors.New("tweak overflow")
	}

	privScalar.Add(&tweakScalar)

	result := make([]byte, 32)
	privScalar.PutBytesUnchecked(result)
	return result, nil
}

// SignPSBT signs all inputs of a PSBT using the given signer.
func SignPSBT(psbt *PSBT, signer PSBTSigner) error {
	for i := range psbt.Inputs {
		_, err := signer.SignPSBTInput(psbt, i)
		if err != nil {
			return err
		}
	}
	return nil
}

// FinalizePSBT attempts to finalize all inputs of a PSBT.
// Returns true if all inputs were finalized.
func FinalizePSBT(psbt *PSBT) (bool, error) {
	allFinalized := true

	for i := range psbt.Inputs {
		finalized, err := FinalizeInput(psbt, i)
		if err != nil {
			return false, err
		}
		if !finalized {
			allFinalized = false
		}
	}

	return allFinalized, nil
}

// FinalizeInput attempts to finalize a single input.
// Returns true if the input was finalized.
func FinalizeInput(psbt *PSBT, idx int) (bool, error) {
	input := &psbt.Inputs[idx]

	// Already finalized?
	if len(input.FinalScriptSig) > 0 || len(input.FinalScriptWitness) > 0 {
		return true, nil
	}

	// Get the UTXO
	var utxo *wire.TxOut
	if input.WitnessUTXO != nil {
		utxo = input.WitnessUTXO
	} else if input.NonWitnessUTXO != nil {
		prevOutpoint := psbt.UnsignedTx.TxIn[idx].PreviousOutPoint
		if int(prevOutpoint.Index) >= len(input.NonWitnessUTXO.TxOut) {
			return false, ErrPSBTNoUTXO
		}
		utxo = input.NonWitnessUTXO.TxOut[prevOutpoint.Index]
	} else {
		return false, nil // Can't finalize without UTXO info
	}

	pkScript := utxo.PkScript

	// Try to finalize based on script type
	switch {
	case isP2WPKH(pkScript):
		return finalizeP2WPKH(input)

	case isP2WSH(pkScript):
		return finalizeP2WSH(input)

	case isP2SH(pkScript):
		return finalizeP2SH(input)

	case isP2PKH(pkScript):
		return finalizeP2PKH(input)

	case isP2TR(pkScript):
		return finalizeP2TR(input)

	default:
		return false, nil
	}
}

// finalizeP2WPKH finalizes a P2WPKH input.
func finalizeP2WPKH(input *PSBTInput) (bool, error) {
	// Need exactly one signature
	if len(input.PartialSigs) != 1 {
		return false, nil
	}

	var pubKey, sig []byte
	for k, v := range input.PartialSigs {
		pubKey = []byte(k)
		sig = v
		break
	}

	// Set witness: [sig, pubkey]
	input.FinalScriptWitness = [][]byte{sig, pubKey}

	// Clear signing data
	clearInputSigningData(input)
	return true, nil
}

// finalizeP2WSH finalizes a P2WSH input.
func finalizeP2WSH(input *PSBTInput) (bool, error) {
	// This is more complex - depends on the witness script
	// For now, handle simple cases

	if len(input.WitnessScript) == 0 {
		return false, nil
	}

	// Check for multisig
	if isMultisigScript(input.WitnessScript) {
		return finalizeMultisig(input, true)
	}

	// Simple P2PKH-style inside P2WSH
	if len(input.PartialSigs) == 1 {
		var pubKey, sig []byte
		for k, v := range input.PartialSigs {
			pubKey = []byte(k)
			sig = v
			break
		}
		input.FinalScriptWitness = [][]byte{sig, pubKey, input.WitnessScript}
		clearInputSigningData(input)
		return true, nil
	}

	return false, nil
}

// finalizeP2SH finalizes a P2SH input.
func finalizeP2SH(input *PSBTInput) (bool, error) {
	if len(input.RedeemScript) == 0 {
		return false, nil
	}

	if isP2WPKH(input.RedeemScript) {
		// P2SH-P2WPKH
		if len(input.PartialSigs) != 1 {
			return false, nil
		}

		var pubKey, sig []byte
		for k, v := range input.PartialSigs {
			pubKey = []byte(k)
			sig = v
			break
		}

		// scriptSig pushes the redeem script
		input.FinalScriptSig = buildScriptSig(input.RedeemScript)
		input.FinalScriptWitness = [][]byte{sig, pubKey}
		clearInputSigningData(input)
		return true, nil
	}

	if isP2WSH(input.RedeemScript) {
		// P2SH-P2WSH
		if len(input.WitnessScript) == 0 {
			return false, nil
		}

		// Handle based on witness script
		if isMultisigScript(input.WitnessScript) {
			finalized, err := finalizeMultisig(input, true)
			if err != nil || !finalized {
				return finalized, err
			}
		} else if len(input.PartialSigs) == 1 {
			var pubKey, sig []byte
			for k, v := range input.PartialSigs {
				pubKey = []byte(k)
				sig = v
				break
			}
			input.FinalScriptWitness = [][]byte{sig, pubKey, input.WitnessScript}
		} else {
			return false, nil
		}

		input.FinalScriptSig = buildScriptSig(input.RedeemScript)
		clearInputSigningData(input)
		return true, nil
	}

	// Legacy P2SH
	if isMultisigScript(input.RedeemScript) {
		return finalizeLegacyMultisig(input)
	}

	if len(input.PartialSigs) == 1 {
		var pubKey, sig []byte
		for k, v := range input.PartialSigs {
			pubKey = []byte(k)
			sig = v
			break
		}
		// Build scriptSig: OP_0 sig pubkey redeemScript
		scriptSig := buildLegacyScriptSig([][]byte{sig, pubKey}, input.RedeemScript)
		input.FinalScriptSig = scriptSig
		clearInputSigningData(input)
		return true, nil
	}

	return false, nil
}

// finalizeP2PKH finalizes a P2PKH input.
func finalizeP2PKH(input *PSBTInput) (bool, error) {
	if len(input.PartialSigs) != 1 {
		return false, nil
	}

	var pubKey, sig []byte
	for k, v := range input.PartialSigs {
		pubKey = []byte(k)
		sig = v
		break
	}

	// Build scriptSig: sig pubkey
	scriptSig := buildLegacyScriptSig([][]byte{sig, pubKey}, nil)
	input.FinalScriptSig = scriptSig
	clearInputSigningData(input)
	return true, nil
}

// finalizeP2TR finalizes a P2TR input.
func finalizeP2TR(input *PSBTInput) (bool, error) {
	// Key path spending
	if len(input.TapKeySig) > 0 {
		input.FinalScriptWitness = [][]byte{input.TapKeySig}
		clearInputSigningData(input)
		return true, nil
	}

	// Script path spending
	if len(input.TapScriptSigs) > 0 && len(input.TapLeafScripts) > 0 {
		// Find a leaf with all required signatures
		// This is simplified - real implementation would be more complex
		for _, leaf := range input.TapLeafScripts {
			// Check if we have a signature for this leaf
			for sigKey, sig := range input.TapScriptSigs {
				// Build control block from leaf
				controlBlock := leaf.ControlBlock

				// Build witness: [sig, script, control_block]
				input.FinalScriptWitness = [][]byte{sig, leaf.Script, controlBlock}
				clearInputSigningData(input)
				// Use sigKey to avoid unused variable
				_ = sigKey
				return true, nil
			}
		}
	}

	return false, nil
}

// finalizeMultisig finalizes a multisig input (witness version).
func finalizeMultisig(input *PSBTInput, isWitness bool) (bool, error) {
	wsScript := input.WitnessScript
	if len(wsScript) == 0 {
		return false, nil
	}

	// Parse M and N from script
	m, pubKeys, err := parseMultisigScript(wsScript)
	if err != nil {
		return false, nil
	}

	if len(input.PartialSigs) < m {
		return false, nil // Not enough signatures
	}

	// Collect signatures in pubkey order
	var sigs [][]byte
	for _, pk := range pubKeys {
		if sig, ok := input.PartialSigs[string(pk)]; ok {
			sigs = append(sigs, sig)
			if len(sigs) == m {
				break
			}
		}
	}

	if len(sigs) < m {
		return false, nil
	}

	// Build witness: OP_0 sig1 sig2 ... sigM script
	witness := make([][]byte, 0, m+2)
	witness = append(witness, []byte{}) // OP_0 dummy
	witness = append(witness, sigs...)
	witness = append(witness, wsScript)

	input.FinalScriptWitness = witness
	return true, nil
}

// finalizeLegacyMultisig finalizes a legacy P2SH multisig input.
func finalizeLegacyMultisig(input *PSBTInput) (bool, error) {
	redeemScript := input.RedeemScript
	if len(redeemScript) == 0 {
		return false, nil
	}

	m, pubKeys, err := parseMultisigScript(redeemScript)
	if err != nil {
		return false, nil
	}

	if len(input.PartialSigs) < m {
		return false, nil
	}

	var sigs [][]byte
	for _, pk := range pubKeys {
		if sig, ok := input.PartialSigs[string(pk)]; ok {
			sigs = append(sigs, sig)
			if len(sigs) == m {
				break
			}
		}
	}

	if len(sigs) < m {
		return false, nil
	}

	// Build scriptSig: OP_0 sig1 ... sigM redeemScript
	parts := make([][]byte, 0, m+1)
	parts = append(parts, []byte{}) // OP_0 dummy
	parts = append(parts, sigs...)

	input.FinalScriptSig = buildLegacyScriptSig(parts, redeemScript)
	clearInputSigningData(input)
	return true, nil
}

// clearInputSigningData clears intermediate signing data after finalization.
func clearInputSigningData(input *PSBTInput) {
	input.PartialSigs = make(map[string][]byte)
	input.SighashType = 0
	input.RedeemScript = nil
	input.WitnessScript = nil
	input.BIP32Derivation = make(map[string]*BIP32Derivation)
	input.TapKeySig = nil
	input.TapScriptSigs = make(map[TapScriptSigKey][]byte)
	input.TapLeafScripts = nil
	input.TapBIP32Derivation = make(map[string]*TapBIP32Derivation)
	input.TapInternalKey = nil
	input.TapMerkleRoot = nil
}

// ExtractTransaction extracts the final signed transaction from a PSBT.
func ExtractTransaction(psbt *PSBT) (*wire.MsgTx, error) {
	// Verify all inputs are finalized
	for i, input := range psbt.Inputs {
		if len(input.FinalScriptSig) == 0 && len(input.FinalScriptWitness) == 0 {
			return nil, errors.New("input " + string(rune('0'+i)) + " is not finalized")
		}
	}

	// Copy the transaction
	tx := &wire.MsgTx{
		Version:  psbt.UnsignedTx.Version,
		TxIn:     make([]*wire.TxIn, len(psbt.UnsignedTx.TxIn)),
		TxOut:    make([]*wire.TxOut, len(psbt.UnsignedTx.TxOut)),
		LockTime: psbt.UnsignedTx.LockTime,
	}

	// Copy inputs with final scripts
	for i, in := range psbt.UnsignedTx.TxIn {
		tx.TxIn[i] = &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			SignatureScript:  psbt.Inputs[i].FinalScriptSig,
			Witness:          psbt.Inputs[i].FinalScriptWitness,
			Sequence:         in.Sequence,
		}
	}

	// Copy outputs
	for i, out := range psbt.UnsignedTx.TxOut {
		tx.TxOut[i] = &wire.TxOut{
			Value:    out.Value,
			PkScript: out.PkScript,
		}
	}

	return tx, nil
}

// FinalizeAndExtractTransaction finalizes and extracts the transaction.
func FinalizeAndExtractTransaction(psbt *PSBT) (*wire.MsgTx, error) {
	finalized, err := FinalizePSBT(psbt)
	if err != nil {
		return nil, err
	}
	if !finalized {
		return nil, ErrPSBTNotFinalized
	}
	return ExtractTransaction(psbt)
}

// IsComplete returns true if all inputs are finalized.
func (p *PSBT) IsComplete() bool {
	for _, input := range p.Inputs {
		if len(input.FinalScriptSig) == 0 && len(input.FinalScriptWitness) == 0 {
			return false
		}
	}
	return true
}

// Helper functions

func buildP2PKHScriptCode(pubKeyHash []byte) []byte {
	scriptCode := make([]byte, 25)
	scriptCode[0] = 0x76 // OP_DUP
	scriptCode[1] = 0xa9 // OP_HASH160
	scriptCode[2] = 0x14 // Push 20 bytes
	copy(scriptCode[3:23], pubKeyHash)
	scriptCode[23] = 0x88 // OP_EQUALVERIFY
	scriptCode[24] = 0xac // OP_CHECKSIG
	return scriptCode
}

func buildScriptSig(redeemScript []byte) []byte {
	// Push the redeem script
	var buf bytes.Buffer
	if len(redeemScript) < 76 {
		buf.WriteByte(byte(len(redeemScript)))
	} else if len(redeemScript) < 256 {
		buf.WriteByte(0x4c) // OP_PUSHDATA1
		buf.WriteByte(byte(len(redeemScript)))
	} else {
		buf.WriteByte(0x4d) // OP_PUSHDATA2
		buf.WriteByte(byte(len(redeemScript)))
		buf.WriteByte(byte(len(redeemScript) >> 8))
	}
	buf.Write(redeemScript)
	return buf.Bytes()
}

func buildLegacyScriptSig(parts [][]byte, redeemScript []byte) []byte {
	var buf bytes.Buffer
	for _, part := range parts {
		if len(part) == 0 {
			buf.WriteByte(0x00) // OP_0
		} else if len(part) < 76 {
			buf.WriteByte(byte(len(part)))
			buf.Write(part)
		} else if len(part) < 256 {
			buf.WriteByte(0x4c) // OP_PUSHDATA1
			buf.WriteByte(byte(len(part)))
			buf.Write(part)
		} else {
			buf.WriteByte(0x4d) // OP_PUSHDATA2
			buf.WriteByte(byte(len(part)))
			buf.WriteByte(byte(len(part) >> 8))
			buf.Write(part)
		}
	}
	if redeemScript != nil {
		if len(redeemScript) < 76 {
			buf.WriteByte(byte(len(redeemScript)))
		} else if len(redeemScript) < 256 {
			buf.WriteByte(0x4c) // OP_PUSHDATA1
			buf.WriteByte(byte(len(redeemScript)))
		} else {
			buf.WriteByte(0x4d) // OP_PUSHDATA2
			buf.WriteByte(byte(len(redeemScript)))
			buf.WriteByte(byte(len(redeemScript) >> 8))
		}
		buf.Write(redeemScript)
	}
	return buf.Bytes()
}

func isP2WSH(pkScript []byte) bool {
	// OP_0 <32-byte-hash>
	return len(pkScript) == 34 && pkScript[0] == 0x00 && pkScript[1] == 0x20
}

func isMultisigScript(script []byte) bool {
	if len(script) < 4 {
		return false
	}
	// Check for OP_m ... OP_n OP_CHECKMULTISIG pattern
	// OP_1 to OP_16 are 0x51 to 0x60
	firstOp := script[0]
	lastOp := script[len(script)-1]

	if firstOp < 0x51 || firstOp > 0x60 {
		return false
	}
	if lastOp != 0xae { // OP_CHECKMULTISIG
		return false
	}
	return true
}

func parseMultisigScript(script []byte) (m int, pubKeys [][]byte, err error) {
	if !isMultisigScript(script) {
		return 0, nil, errors.New("not a multisig script")
	}

	// m is encoded as OP_1 (0x51) to OP_16 (0x60)
	m = int(script[0] - 0x50)

	// Parse public keys
	pos := 1
	for pos < len(script)-2 {
		if script[pos] >= 0x51 && script[pos] <= 0x60 {
			// This is n
			break
		}

		var keyLen int
		if script[pos] <= 0x4b {
			keyLen = int(script[pos])
		} else {
			return 0, nil, errors.New("invalid push opcode in multisig")
		}
		pos++

		if pos+keyLen > len(script) {
			return 0, nil, errors.New("truncated pubkey")
		}

		pubKeys = append(pubKeys, script[pos:pos+keyLen])
		pos += keyLen
	}

	return m, pubKeys, nil
}
