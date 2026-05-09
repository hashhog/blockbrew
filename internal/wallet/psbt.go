// Package wallet implements key management and transaction signing.
package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// PSBT magic bytes: "psbt" + 0xff
var psbtMagic = []byte{0x70, 0x73, 0x62, 0x74, 0xff}

// PSBT separator byte (0x00)
const psbtSeparator byte = 0x00

// MaxPSBTFileSize is the maximum allowed PSBT file size (100 MB)
const MaxPSBTFileSize = 100 * 1024 * 1024

// PSBT Global Types (BIP174)
const (
	PSBTGlobalUnsignedTx   = 0x00
	PSBTGlobalXpub         = 0x01
	PSBTGlobalTxVersion    = 0x02 // BIP370 v2
	PSBTGlobalFallbackLock = 0x03 // BIP370 v2
	PSBTGlobalInputCount   = 0x04 // BIP370 v2
	PSBTGlobalOutputCount  = 0x05 // BIP370 v2
	PSBTGlobalTxModifiable = 0x06 // BIP370 v2
	PSBTGlobalVersion      = 0xfb
	PSBTGlobalProprietary  = 0xfc
)

// PSBT Input Types (BIP174)
const (
	PSBTInNonWitnessUTXO    = 0x00
	PSBTInWitnessUTXO       = 0x01
	PSBTInPartialSig        = 0x02
	PSBTInSigHashType       = 0x03
	PSBTInRedeemScript      = 0x04
	PSBTInWitnessScript     = 0x05
	PSBTInBIP32Derivation   = 0x06
	PSBTInFinalScriptSig    = 0x07
	PSBTInFinalScriptWitness = 0x08
	PSBTInPorCommitment     = 0x09 // Reserved
	PSBTInRIPEMD160         = 0x0a
	PSBTInSHA256            = 0x0b
	PSBTInHASH160           = 0x0c
	PSBTInHASH256           = 0x0d
	PSBTInPrevTxID          = 0x0e // BIP370 v2
	PSBTInOutputIndex       = 0x0f // BIP370 v2
	PSBTInSequence          = 0x10 // BIP370 v2
	PSBTInRequiredTimeLock  = 0x11 // BIP370 v2
	PSBTInRequiredHeightLock = 0x12 // BIP370 v2
	PSBTInTapKeySig         = 0x13 // BIP371
	PSBTInTapScriptSig      = 0x14 // BIP371
	PSBTInTapLeafScript     = 0x15 // BIP371
	PSBTInTapBIP32Deriv     = 0x16 // BIP371
	PSBTInTapInternalKey    = 0x17 // BIP371
	PSBTInTapMerkleRoot     = 0x18 // BIP371
	PSBTInMuSig2ParticipantPubkeys = 0x1a
	PSBTInMuSig2PubNonce    = 0x1b
	PSBTInMuSig2PartialSig  = 0x1c
	PSBTInProprietary       = 0xfc
)

// PSBT Output Types (BIP174)
const (
	PSBTOutRedeemScript     = 0x00
	PSBTOutWitnessScript    = 0x01
	PSBTOutBIP32Derivation  = 0x02
	PSBTOutAmount           = 0x03 // BIP370 v2
	PSBTOutScript           = 0x04 // BIP370 v2
	PSBTOutTapInternalKey   = 0x05 // BIP371
	PSBTOutTapTree          = 0x06 // BIP371
	PSBTOutTapBIP32Deriv    = 0x07 // BIP371
	PSBTOutMuSig2ParticipantPubkeys = 0x08
	PSBTOutProprietary      = 0xfc
)

// PSBT errors
var (
	ErrInvalidPSBTMagic       = errors.New("invalid PSBT magic bytes")
	ErrPSBTTooLarge           = errors.New("PSBT file exceeds size limit")
	ErrDuplicatePSBTKey       = errors.New("duplicate key in PSBT")
	ErrMissingUnsignedTx      = errors.New("PSBT missing unsigned transaction")
	ErrInvalidPSBTInput       = errors.New("invalid PSBT input")
	ErrInvalidPSBTOutput      = errors.New("invalid PSBT output")
	ErrPSBTInputCountMismatch = errors.New("PSBT input count mismatch")
	ErrPSBTOutputCountMismatch = errors.New("PSBT output count mismatch")
	ErrPSBTNotFinalized       = errors.New("PSBT is not fully finalized")
	ErrPSBTAlreadyFinalized   = errors.New("PSBT input already finalized")
	ErrPSBTTxMismatch         = errors.New("PSBT transactions do not match")
	ErrPSBTNoUTXO             = errors.New("PSBT input missing UTXO information")
	ErrPSBTInvalidSignature   = errors.New("invalid PSBT signature")

	// ErrPSBTNonWitnessUTXOMismatch is returned when the txid of the
	// PSBT_IN_NON_WITNESS_UTXO transaction does not match the prevout
	// hash referenced by the unsigned transaction's input. Per BIP-174 +
	// Bitcoin Core PSBTInput::IsSane, the wallet MUST refuse to sign
	// against an unverified previous transaction — otherwise an attacker
	// can swap in a forged prevTx to lie about its outputs (W41/W40-A).
	ErrPSBTNonWitnessUTXOMismatch = errors.New("PSBT NON_WITNESS_UTXO txid does not match prevout")

	// ErrPSBTUTXOIndexOutOfRange is returned when the unsigned tx's
	// input references an output index beyond the NON_WITNESS_UTXO's
	// TxOut slice. Caught here so the signer dispatch never indexes a
	// short slice.
	ErrPSBTUTXOIndexOutOfRange = errors.New("PSBT prevout index out of range for NON_WITNESS_UTXO")

	// ErrWitnessUtxoMismatch is returned when both WITNESS_UTXO and
	// NON_WITNESS_UTXO are present but their (value, scriptPubKey) at
	// the prevout index disagree. Defends against CVE-2020-14199 — a
	// malicious wallet can otherwise lie about the input amount through
	// the WITNESS_UTXO oracle and trick the signer into oversigning.
	// See Bitcoin Core PSBTInput::IsSane and W40-A audit.
	ErrWitnessUtxoMismatch = errors.New("PSBT WITNESS_UTXO disagrees with NON_WITNESS_UTXO at prevout index")
)

// BIP32Derivation represents a BIP32 derivation path with fingerprint.
type BIP32Derivation struct {
	Fingerprint [4]byte  // Master key fingerprint
	Path        []uint32 // Derivation path indices
}

// TapScriptSigKey is the key for tapscript signatures.
type TapScriptSigKey struct {
	XOnlyPubKey [32]byte
	LeafHash    [32]byte
}

// TapLeaf represents a taproot script leaf as carried in a per-input
// PSBT_IN_TAP_LEAF_SCRIPT (BIP371). ControlBlock is a real BIP341 control
// block (33 + N*32 bytes).
type TapLeaf struct {
	LeafVersion byte
	Script      []byte
	ControlBlock []byte
}

// TapTreeLeaf represents a single leaf in a per-output PSBT_OUT_TAP_TREE
// (BIP371). The wire format carries Depth + LeafVersion + Script with NO
// control block — the control block is derived by the verifier from the
// tree structure. Kept distinct from TapLeaf so the two BIP371 fields
// can never be confused at the call site (the W34-B refactor previously
// stashed Depth in TapLeaf.ControlBlock[0], a structural overload).
type TapTreeLeaf struct {
	Depth       uint8
	LeafVersion uint8
	Script      []byte
}

// TapBIP32Derivation represents taproot BIP32 derivation info.
type TapBIP32Derivation struct {
	LeafHashes  [][32]byte
	Fingerprint [4]byte
	Path        []uint32
}

// MuSig2ParticipantEntry represents one aggregate-pubkey → participant-pubkeys
// mapping from PSBT_IN/OUT_MUSIG2_PARTICIPANT_PUBKEYS (BIP-327 / type 0x1a/0x08).
// Wire format: key = [type_byte] | agg_pubkey(33 bytes),
//              value = N×33 bytes of participant compressed pubkeys.
type MuSig2ParticipantEntry struct {
	AggregatePubkey  []byte   // 33-byte compressed pubkey
	ParticipantPubkeys [][]byte // N×33-byte compressed pubkeys
}

// PSBTInput contains all data for a single PSBT input.
type PSBTInput struct {
	// UTXOs (at least one required)
	NonWitnessUTXO *wire.MsgTx // Full previous transaction
	WitnessUTXO    *wire.TxOut // Just the previous output

	// Partial signatures: pubkey (33 or 65 bytes) -> signature
	PartialSigs map[string][]byte

	// Sighash type
	SighashType uint32

	// Scripts
	RedeemScript  []byte
	WitnessScript []byte

	// Final scripts (after finalization)
	FinalScriptSig     []byte
	FinalScriptWitness [][]byte

	// BIP32 derivation paths: pubkey -> derivation info
	BIP32Derivation map[string]*BIP32Derivation

	// Hash preimages
	RIPEMD160Preimages map[[20]byte][]byte
	SHA256Preimages    map[[32]byte][]byte
	HASH160Preimages   map[[20]byte][]byte
	HASH256Preimages   map[[32]byte][]byte

	// Taproot fields (BIP371)
	TapKeySig        []byte // 64 or 65 bytes
	TapScriptSigs    map[TapScriptSigKey][]byte
	TapLeafScripts   []TapLeaf
	TapBIP32Derivation map[string]*TapBIP32Derivation // xonly pubkey -> derivation
	TapInternalKey   []byte // 32 bytes
	TapMerkleRoot    []byte // 32 bytes

	// Unknown key-value pairs for forwards compatibility
	Unknown map[string][]byte
}

// PSBTOutput contains all data for a single PSBT output.
type PSBTOutput struct {
	// Scripts
	RedeemScript  []byte
	WitnessScript []byte

	// BIP32 derivation paths: pubkey -> derivation info
	BIP32Derivation map[string]*BIP32Derivation

	// Taproot fields (BIP371)
	TapInternalKey     []byte // 32 bytes
	TapTree            []TapTreeLeaf
	TapBIP32Derivation map[string]*TapBIP32Derivation

	// MuSig2 fields (BIP-327, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08)
	MuSig2Participants []MuSig2ParticipantEntry

	// Unknown key-value pairs
	Unknown map[string][]byte
}

// PSBT represents a Partially Signed Bitcoin Transaction (BIP174/370).
type PSBT struct {
	UnsignedTx *wire.MsgTx
	Inputs     []PSBTInput
	Outputs    []PSBTOutput
	Version    uint32               // PSBT version (0 = BIP174, 2 = BIP370)
	XPubs      map[string][]byte    // Extended public keys
	Unknown    map[string][]byte    // Unknown global key-value pairs
}

// NewPSBT creates a new PSBT from an unsigned transaction.
func NewPSBT(tx *wire.MsgTx) (*PSBT, error) {
	// Verify transaction has empty scripts and witnesses
	for _, in := range tx.TxIn {
		if len(in.SignatureScript) > 0 {
			return nil, errors.New("transaction input has non-empty scriptSig")
		}
		if len(in.Witness) > 0 {
			return nil, errors.New("transaction input has non-empty witness")
		}
	}

	psbt := &PSBT{
		UnsignedTx: tx,
		Inputs:     make([]PSBTInput, len(tx.TxIn)),
		Outputs:    make([]PSBTOutput, len(tx.TxOut)),
		Version:    0,
		XPubs:      make(map[string][]byte),
		Unknown:    make(map[string][]byte),
	}

	// Initialize input maps
	for i := range psbt.Inputs {
		psbt.Inputs[i].PartialSigs = make(map[string][]byte)
		psbt.Inputs[i].BIP32Derivation = make(map[string]*BIP32Derivation)
		psbt.Inputs[i].TapScriptSigs = make(map[TapScriptSigKey][]byte)
		psbt.Inputs[i].TapBIP32Derivation = make(map[string]*TapBIP32Derivation)
		psbt.Inputs[i].Unknown = make(map[string][]byte)
		psbt.Inputs[i].RIPEMD160Preimages = make(map[[20]byte][]byte)
		psbt.Inputs[i].SHA256Preimages = make(map[[32]byte][]byte)
		psbt.Inputs[i].HASH160Preimages = make(map[[20]byte][]byte)
		psbt.Inputs[i].HASH256Preimages = make(map[[32]byte][]byte)
	}

	// Initialize output maps
	for i := range psbt.Outputs {
		psbt.Outputs[i].BIP32Derivation = make(map[string]*BIP32Derivation)
		psbt.Outputs[i].TapBIP32Derivation = make(map[string]*TapBIP32Derivation)
		psbt.Outputs[i].Unknown = make(map[string][]byte)
	}

	return psbt, nil
}

// DecodePSBT parses a PSBT from binary data.
func DecodePSBT(data []byte) (*PSBT, error) {
	if len(data) > MaxPSBTFileSize {
		return nil, ErrPSBTTooLarge
	}

	r := bytes.NewReader(data)
	return DecodePSBTReader(r)
}

// DecodePSBTReader parses a PSBT from a reader.
func DecodePSBTReader(r io.Reader) (*PSBT, error) {
	// Read and verify magic bytes
	magic := make([]byte, 5)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("failed to read PSBT magic: %w", err)
	}
	if !bytes.Equal(magic, psbtMagic) {
		return nil, ErrInvalidPSBTMagic
	}

	psbt := &PSBT{
		XPubs:   make(map[string][]byte),
		Unknown: make(map[string][]byte),
	}

	// Read global map
	seenKeys := make(map[string]bool)
	for {
		key, value, err := readKeyValue(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read global key-value: %w", err)
		}
		if key == nil {
			// Separator reached
			break
		}

		keyStr := string(key)
		if seenKeys[keyStr] {
			return nil, ErrDuplicatePSBTKey
		}
		seenKeys[keyStr] = true

		keyType := key[0]
		keyData := key[1:]

		switch keyType {
		case PSBTGlobalUnsignedTx:
			if len(keyData) > 0 {
				return nil, errors.New("global unsigned tx key must have no data")
			}
			tx := &wire.MsgTx{}
			if err := tx.Deserialize(bytes.NewReader(value)); err != nil {
				return nil, fmt.Errorf("failed to deserialize unsigned tx: %w", err)
			}
			// Verify empty scripts
			for _, in := range tx.TxIn {
				if len(in.SignatureScript) > 0 || len(in.Witness) > 0 {
					return nil, errors.New("unsigned tx must have empty scripts")
				}
			}
			psbt.UnsignedTx = tx

		case PSBTGlobalXpub:
			if len(keyData) < 78 {
				return nil, errors.New("invalid xpub key length")
			}
			psbt.XPubs[string(keyData)] = value

		case PSBTGlobalVersion:
			if len(keyData) > 0 {
				return nil, errors.New("global version key must have no data")
			}
			if len(value) != 4 {
				return nil, errors.New("invalid PSBT version value length")
			}
			psbt.Version = binary.LittleEndian.Uint32(value)

		case PSBTGlobalProprietary:
			psbt.Unknown[keyStr] = value

		default:
			psbt.Unknown[keyStr] = value
		}
	}

	if psbt.UnsignedTx == nil {
		return nil, ErrMissingUnsignedTx
	}

	// Read input maps
	psbt.Inputs = make([]PSBTInput, len(psbt.UnsignedTx.TxIn))
	for i := range psbt.Inputs {
		psbt.Inputs[i].PartialSigs = make(map[string][]byte)
		psbt.Inputs[i].BIP32Derivation = make(map[string]*BIP32Derivation)
		psbt.Inputs[i].TapScriptSigs = make(map[TapScriptSigKey][]byte)
		psbt.Inputs[i].TapBIP32Derivation = make(map[string]*TapBIP32Derivation)
		psbt.Inputs[i].Unknown = make(map[string][]byte)
		psbt.Inputs[i].RIPEMD160Preimages = make(map[[20]byte][]byte)
		psbt.Inputs[i].SHA256Preimages = make(map[[32]byte][]byte)
		psbt.Inputs[i].HASH160Preimages = make(map[[20]byte][]byte)
		psbt.Inputs[i].HASH256Preimages = make(map[[32]byte][]byte)

		err := psbt.readInput(r, &psbt.Inputs[i])
		if err != nil {
			return nil, fmt.Errorf("failed to read input %d: %w", i, err)
		}

		// W41: validate the input's UTXO oracles against the unsigned
		// tx's prevout BEFORE handing the parsed PSBT to any signer.
		// Mirrors Bitcoin Core PSBTInput::IsSane (src/psbt.cpp).
		prevOutpoint := psbt.UnsignedTx.TxIn[i].PreviousOutPoint
		if err := validatePSBTInput(&psbt.Inputs[i], prevOutpoint); err != nil {
			return nil, fmt.Errorf("PSBT input %d failed sanity check: %w", i, err)
		}
	}

	// Read output maps
	psbt.Outputs = make([]PSBTOutput, len(psbt.UnsignedTx.TxOut))
	for i := range psbt.Outputs {
		psbt.Outputs[i].BIP32Derivation = make(map[string]*BIP32Derivation)
		psbt.Outputs[i].TapBIP32Derivation = make(map[string]*TapBIP32Derivation)
		psbt.Outputs[i].Unknown = make(map[string][]byte)

		err := psbt.readOutput(r, &psbt.Outputs[i])
		if err != nil {
			return nil, fmt.Errorf("failed to read output %d: %w", i, err)
		}
	}

	return psbt, nil
}

// readInput reads a single input map from the reader.
func (p *PSBT) readInput(r io.Reader, input *PSBTInput) error {
	seenKeys := make(map[string]bool)
	for {
		key, value, err := readKeyValue(r)
		if err != nil {
			return err
		}
		if key == nil {
			break
		}

		keyStr := string(key)
		if seenKeys[keyStr] {
			return ErrDuplicatePSBTKey
		}
		seenKeys[keyStr] = true

		keyType := key[0]
		keyData := key[1:]

		switch keyType {
		case PSBTInNonWitnessUTXO:
			tx := &wire.MsgTx{}
			if err := tx.Deserialize(bytes.NewReader(value)); err != nil {
				return fmt.Errorf("failed to deserialize non-witness utxo: %w", err)
			}
			input.NonWitnessUTXO = tx

		case PSBTInWitnessUTXO:
			out := &wire.TxOut{}
			if err := out.Deserialize(bytes.NewReader(value)); err != nil {
				return fmt.Errorf("failed to deserialize witness utxo: %w", err)
			}
			input.WitnessUTXO = out

		case PSBTInPartialSig:
			if len(keyData) != 33 && len(keyData) != 65 {
				return errors.New("invalid partial sig pubkey length")
			}
			input.PartialSigs[string(keyData)] = value

		case PSBTInSigHashType:
			if len(value) != 4 {
				return errors.New("invalid sighash type length")
			}
			input.SighashType = binary.LittleEndian.Uint32(value)

		case PSBTInRedeemScript:
			input.RedeemScript = value

		case PSBTInWitnessScript:
			input.WitnessScript = value

		case PSBTInBIP32Derivation:
			if len(keyData) != 33 && len(keyData) != 65 {
				return errors.New("invalid BIP32 derivation pubkey length")
			}
			deriv, err := parseBIP32Derivation(value)
			if err != nil {
				return err
			}
			input.BIP32Derivation[string(keyData)] = deriv

		case PSBTInFinalScriptSig:
			input.FinalScriptSig = value

		case PSBTInFinalScriptWitness:
			witness, err := parseWitnessStack(value)
			if err != nil {
				return err
			}
			input.FinalScriptWitness = witness

		case PSBTInRIPEMD160:
			if len(keyData) != 20 {
				return errors.New("invalid RIPEMD160 key length")
			}
			var hash [20]byte
			copy(hash[:], keyData)
			input.RIPEMD160Preimages[hash] = value

		case PSBTInSHA256:
			if len(keyData) != 32 {
				return errors.New("invalid SHA256 key length")
			}
			var hash [32]byte
			copy(hash[:], keyData)
			input.SHA256Preimages[hash] = value

		case PSBTInHASH160:
			if len(keyData) != 20 {
				return errors.New("invalid HASH160 key length")
			}
			var hash [20]byte
			copy(hash[:], keyData)
			input.HASH160Preimages[hash] = value

		case PSBTInHASH256:
			if len(keyData) != 32 {
				return errors.New("invalid HASH256 key length")
			}
			var hash [32]byte
			copy(hash[:], keyData)
			input.HASH256Preimages[hash] = value

		case PSBTInTapKeySig:
			if len(value) != 64 && len(value) != 65 {
				return errors.New("invalid tap key sig length")
			}
			input.TapKeySig = value

		case PSBTInTapScriptSig:
			if len(keyData) != 64 {
				return errors.New("invalid tap script sig key length")
			}
			var sigKey TapScriptSigKey
			copy(sigKey.XOnlyPubKey[:], keyData[:32])
			copy(sigKey.LeafHash[:], keyData[32:])
			input.TapScriptSigs[sigKey] = value

		case PSBTInTapLeafScript:
			if len(keyData) < 33 || (len(keyData)-33)%32 != 0 {
				return errors.New("invalid tap leaf script control block length")
			}
			if len(value) < 1 {
				return errors.New("invalid tap leaf script value")
			}
			leaf := TapLeaf{
				ControlBlock: keyData,
				LeafVersion:  value[len(value)-1],
				Script:       value[:len(value)-1],
			}
			input.TapLeafScripts = append(input.TapLeafScripts, leaf)

		case PSBTInTapBIP32Deriv:
			if len(keyData) != 32 {
				return errors.New("invalid tap BIP32 derivation pubkey length")
			}
			deriv, err := parseTapBIP32Derivation(value)
			if err != nil {
				return err
			}
			input.TapBIP32Derivation[string(keyData)] = deriv

		case PSBTInTapInternalKey:
			if len(value) != 32 {
				return errors.New("invalid tap internal key length")
			}
			input.TapInternalKey = value

		case PSBTInTapMerkleRoot:
			if len(value) != 32 {
				return errors.New("invalid tap merkle root length")
			}
			input.TapMerkleRoot = value

		default:
			input.Unknown[keyStr] = value
		}
	}
	return nil
}

// readOutput reads a single output map from the reader.
func (p *PSBT) readOutput(r io.Reader, output *PSBTOutput) error {
	seenKeys := make(map[string]bool)
	for {
		key, value, err := readKeyValue(r)
		if err != nil {
			return err
		}
		if key == nil {
			break
		}

		keyStr := string(key)
		if seenKeys[keyStr] {
			return ErrDuplicatePSBTKey
		}
		seenKeys[keyStr] = true

		keyType := key[0]
		keyData := key[1:]

		switch keyType {
		case PSBTOutRedeemScript:
			output.RedeemScript = value

		case PSBTOutWitnessScript:
			output.WitnessScript = value

		case PSBTOutBIP32Derivation:
			if len(keyData) != 33 && len(keyData) != 65 {
				return errors.New("invalid BIP32 derivation pubkey length")
			}
			deriv, err := parseBIP32Derivation(value)
			if err != nil {
				return err
			}
			output.BIP32Derivation[string(keyData)] = deriv

		case PSBTOutTapInternalKey:
			if len(value) != 32 {
				return errors.New("invalid tap internal key length")
			}
			output.TapInternalKey = value

		case PSBTOutTapTree:
			tree, err := parseTapTree(value)
			if err != nil {
				return err
			}
			output.TapTree = tree

		case PSBTOutTapBIP32Deriv:
			if len(keyData) != 32 {
				return errors.New("invalid tap BIP32 derivation pubkey length")
			}
			deriv, err := parseTapBIP32Derivation(value)
			if err != nil {
				return err
			}
			output.TapBIP32Derivation[string(keyData)] = deriv

		case PSBTOutMuSig2ParticipantPubkeys:
			// Wire format: key = [0x08] | agg_pubkey(33 bytes)
			//              value = N×33-byte participant compressed pubkeys
			// Mirrors Core's DeserializeMuSig2ParticipantPubkeys (psbt.h:205).
			if len(keyData) != 33 {
				return errors.New("invalid musig2 aggregate pubkey key length")
			}
			if len(value)%33 != 0 {
				return errors.New("musig2 participant pubkeys value size is not a multiple of 33")
			}
			aggPubkey := make([]byte, 33)
			copy(aggPubkey, keyData)
			numParts := len(value) / 33
			parts := make([][]byte, numParts)
			for i := 0; i < numParts; i++ {
				p := make([]byte, 33)
				copy(p, value[i*33:(i+1)*33])
				parts[i] = p
			}
			output.MuSig2Participants = append(output.MuSig2Participants, MuSig2ParticipantEntry{
				AggregatePubkey:    aggPubkey,
				ParticipantPubkeys: parts,
			})

		default:
			output.Unknown[keyStr] = value
		}
	}
	return nil
}

// Encode serializes the PSBT to binary format.
func (p *PSBT) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := p.EncodeWriter(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeWriter serializes the PSBT to a writer.
func (p *PSBT) EncodeWriter(w io.Writer) error {
	// Write magic bytes
	if _, err := w.Write(psbtMagic); err != nil {
		return err
	}

	// Write unsigned transaction
	var txBuf bytes.Buffer
	if err := p.UnsignedTx.SerializeNoWitness(&txBuf); err != nil {
		return err
	}
	if err := writeKeyValue(w, []byte{PSBTGlobalUnsignedTx}, txBuf.Bytes()); err != nil {
		return err
	}

	// Write xpubs (sorted for deterministic output)
	xpubKeys := make([]string, 0, len(p.XPubs))
	for k := range p.XPubs {
		xpubKeys = append(xpubKeys, k)
	}
	sort.Strings(xpubKeys)
	for _, k := range xpubKeys {
		key := append([]byte{PSBTGlobalXpub}, []byte(k)...)
		if err := writeKeyValue(w, key, p.XPubs[k]); err != nil {
			return err
		}
	}

	// Write version if non-zero
	if p.Version != 0 {
		versionValue := make([]byte, 4)
		binary.LittleEndian.PutUint32(versionValue, p.Version)
		if err := writeKeyValue(w, []byte{PSBTGlobalVersion}, versionValue); err != nil {
			return err
		}
	}

	// Write unknown global entries (sorted)
	unknownKeys := make([]string, 0, len(p.Unknown))
	for k := range p.Unknown {
		unknownKeys = append(unknownKeys, k)
	}
	sort.Strings(unknownKeys)
	for _, k := range unknownKeys {
		if err := writeKeyValue(w, []byte(k), p.Unknown[k]); err != nil {
			return err
		}
	}

	// Write global separator
	if err := wire.WriteUint8(w, psbtSeparator); err != nil {
		return err
	}

	// Write inputs
	for i := range p.Inputs {
		if err := p.writeInput(w, &p.Inputs[i]); err != nil {
			return fmt.Errorf("failed to write input %d: %w", i, err)
		}
	}

	// Write outputs
	for i := range p.Outputs {
		if err := p.writeOutput(w, &p.Outputs[i]); err != nil {
			return fmt.Errorf("failed to write output %d: %w", i, err)
		}
	}

	return nil
}

// writeInput writes a single input map.
func (p *PSBT) writeInput(w io.Writer, input *PSBTInput) error {
	// Non-witness UTXO
	if input.NonWitnessUTXO != nil {
		var buf bytes.Buffer
		if err := input.NonWitnessUTXO.Serialize(&buf); err != nil {
			return err
		}
		if err := writeKeyValue(w, []byte{PSBTInNonWitnessUTXO}, buf.Bytes()); err != nil {
			return err
		}
	}

	// Witness UTXO
	if input.WitnessUTXO != nil {
		var buf bytes.Buffer
		if err := input.WitnessUTXO.Serialize(&buf); err != nil {
			return err
		}
		if err := writeKeyValue(w, []byte{PSBTInWitnessUTXO}, buf.Bytes()); err != nil {
			return err
		}
	}

	// Partial signatures.
	// W45: sort by HASH160(pubkey), not raw pubkey bytes. Bitcoin Core
	// stores partial sigs in `std::map<CKeyID, SigPair>` (see
	// bitcoin-core/src/psbt.h:270 + :315) where CKeyID is the 20-byte
	// HASH160 of the pubkey. Serialization order follows std::map's
	// key ordering, so byte-identity to Core requires sorting by
	// HASH160(pubkey) here as well. NOTE: bip32_derivation is
	// `std::map<CPubKey, KeyOriginInfo>` in Core — keyed by the raw
	// pubkey — so that loop below intentionally still sorts raw.
	sigKeys := make([]string, 0, len(input.PartialSigs))
	for k := range input.PartialSigs {
		sigKeys = append(sigKeys, k)
	}
	sort.Slice(sigKeys, func(i, j int) bool {
		hi := bbcrypto.Hash160([]byte(sigKeys[i]))
		hj := bbcrypto.Hash160([]byte(sigKeys[j]))
		return bytes.Compare(hi[:], hj[:]) < 0
	})
	for _, k := range sigKeys {
		key := append([]byte{PSBTInPartialSig}, []byte(k)...)
		if err := writeKeyValue(w, key, input.PartialSigs[k]); err != nil {
			return err
		}
	}

	// Sighash type
	if input.SighashType != 0 {
		value := make([]byte, 4)
		binary.LittleEndian.PutUint32(value, input.SighashType)
		if err := writeKeyValue(w, []byte{PSBTInSigHashType}, value); err != nil {
			return err
		}
	}

	// Redeem script
	if len(input.RedeemScript) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInRedeemScript}, input.RedeemScript); err != nil {
			return err
		}
	}

	// Witness script
	if len(input.WitnessScript) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInWitnessScript}, input.WitnessScript); err != nil {
			return err
		}
	}

	// BIP32 derivation paths (sorted)
	derivKeys := make([]string, 0, len(input.BIP32Derivation))
	for k := range input.BIP32Derivation {
		derivKeys = append(derivKeys, k)
	}
	sort.Strings(derivKeys)
	for _, k := range derivKeys {
		key := append([]byte{PSBTInBIP32Derivation}, []byte(k)...)
		value := serializeBIP32Derivation(input.BIP32Derivation[k])
		if err := writeKeyValue(w, key, value); err != nil {
			return err
		}
	}

	// Final scriptSig
	if len(input.FinalScriptSig) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInFinalScriptSig}, input.FinalScriptSig); err != nil {
			return err
		}
	}

	// Final witness
	if len(input.FinalScriptWitness) > 0 {
		value := serializeWitnessStack(input.FinalScriptWitness)
		if err := writeKeyValue(w, []byte{PSBTInFinalScriptWitness}, value); err != nil {
			return err
		}
	}

	// Hash preimages
	for hash, preimage := range input.RIPEMD160Preimages {
		key := append([]byte{PSBTInRIPEMD160}, hash[:]...)
		if err := writeKeyValue(w, key, preimage); err != nil {
			return err
		}
	}
	for hash, preimage := range input.SHA256Preimages {
		key := append([]byte{PSBTInSHA256}, hash[:]...)
		if err := writeKeyValue(w, key, preimage); err != nil {
			return err
		}
	}
	for hash, preimage := range input.HASH160Preimages {
		key := append([]byte{PSBTInHASH160}, hash[:]...)
		if err := writeKeyValue(w, key, preimage); err != nil {
			return err
		}
	}
	for hash, preimage := range input.HASH256Preimages {
		key := append([]byte{PSBTInHASH256}, hash[:]...)
		if err := writeKeyValue(w, key, preimage); err != nil {
			return err
		}
	}

	// Taproot fields
	if len(input.TapKeySig) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInTapKeySig}, input.TapKeySig); err != nil {
			return err
		}
	}

	for sigKey, sig := range input.TapScriptSigs {
		key := make([]byte, 65)
		key[0] = PSBTInTapScriptSig
		copy(key[1:33], sigKey.XOnlyPubKey[:])
		copy(key[33:65], sigKey.LeafHash[:])
		if err := writeKeyValue(w, key, sig); err != nil {
			return err
		}
	}

	for _, leaf := range input.TapLeafScripts {
		key := append([]byte{PSBTInTapLeafScript}, leaf.ControlBlock...)
		// Defensive copy: leaf.Script is caller-owned; using append here
		// would mutate the caller's backing array if it has spare capacity
		// (e.g. produced by bytes.Buffer.Bytes()). Pre-size + copy makes
		// the fresh allocation explicit. (W34-B / W33 audit.)
		value := make([]byte, len(leaf.Script)+1)
		copy(value, leaf.Script)
		value[len(leaf.Script)] = leaf.LeafVersion
		if err := writeKeyValue(w, key, value); err != nil {
			return err
		}
	}

	// Tap BIP32 derivation (sorted)
	tapDerivKeys := make([]string, 0, len(input.TapBIP32Derivation))
	for k := range input.TapBIP32Derivation {
		tapDerivKeys = append(tapDerivKeys, k)
	}
	sort.Strings(tapDerivKeys)
	for _, k := range tapDerivKeys {
		key := append([]byte{PSBTInTapBIP32Deriv}, []byte(k)...)
		value := serializeTapBIP32Derivation(input.TapBIP32Derivation[k])
		if err := writeKeyValue(w, key, value); err != nil {
			return err
		}
	}

	if len(input.TapInternalKey) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInTapInternalKey}, input.TapInternalKey); err != nil {
			return err
		}
	}

	if len(input.TapMerkleRoot) > 0 {
		if err := writeKeyValue(w, []byte{PSBTInTapMerkleRoot}, input.TapMerkleRoot); err != nil {
			return err
		}
	}

	// Unknown entries (sorted)
	unknownKeys := make([]string, 0, len(input.Unknown))
	for k := range input.Unknown {
		unknownKeys = append(unknownKeys, k)
	}
	sort.Strings(unknownKeys)
	for _, k := range unknownKeys {
		if err := writeKeyValue(w, []byte(k), input.Unknown[k]); err != nil {
			return err
		}
	}

	// Separator
	return wire.WriteUint8(w, psbtSeparator)
}

// writeOutput writes a single output map.
func (p *PSBT) writeOutput(w io.Writer, output *PSBTOutput) error {
	// Redeem script
	if len(output.RedeemScript) > 0 {
		if err := writeKeyValue(w, []byte{PSBTOutRedeemScript}, output.RedeemScript); err != nil {
			return err
		}
	}

	// Witness script
	if len(output.WitnessScript) > 0 {
		if err := writeKeyValue(w, []byte{PSBTOutWitnessScript}, output.WitnessScript); err != nil {
			return err
		}
	}

	// BIP32 derivation paths (sorted)
	derivKeys := make([]string, 0, len(output.BIP32Derivation))
	for k := range output.BIP32Derivation {
		derivKeys = append(derivKeys, k)
	}
	sort.Strings(derivKeys)
	for _, k := range derivKeys {
		key := append([]byte{PSBTOutBIP32Derivation}, []byte(k)...)
		value := serializeBIP32Derivation(output.BIP32Derivation[k])
		if err := writeKeyValue(w, key, value); err != nil {
			return err
		}
	}

	// Taproot fields
	if len(output.TapInternalKey) > 0 {
		if err := writeKeyValue(w, []byte{PSBTOutTapInternalKey}, output.TapInternalKey); err != nil {
			return err
		}
	}

	if len(output.TapTree) > 0 {
		value := serializeTapTree(output.TapTree)
		if err := writeKeyValue(w, []byte{PSBTOutTapTree}, value); err != nil {
			return err
		}
	}

	// Tap BIP32 derivation (sorted)
	tapDerivKeys := make([]string, 0, len(output.TapBIP32Derivation))
	for k := range output.TapBIP32Derivation {
		tapDerivKeys = append(tapDerivKeys, k)
	}
	sort.Strings(tapDerivKeys)
	for _, k := range tapDerivKeys {
		key := append([]byte{PSBTOutTapBIP32Deriv}, []byte(k)...)
		value := serializeTapBIP32Derivation(output.TapBIP32Derivation[k])
		if err := writeKeyValue(w, key, value); err != nil {
			return err
		}
	}

	// Unknown entries (sorted)
	unknownKeys := make([]string, 0, len(output.Unknown))
	for k := range output.Unknown {
		unknownKeys = append(unknownKeys, k)
	}
	sort.Strings(unknownKeys)
	for _, k := range unknownKeys {
		if err := writeKeyValue(w, []byte(k), output.Unknown[k]); err != nil {
			return err
		}
	}

	// Separator
	return wire.WriteUint8(w, psbtSeparator)
}

// EncodeBase64 returns the PSBT as a base64-encoded string.
func (p *PSBT) EncodeBase64() (string, error) {
	data, err := p.Encode()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodePSBTBase64 parses a PSBT from a base64-encoded string.
func DecodePSBTBase64(s string) (*PSBT, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return DecodePSBT(data)
}

// Helper functions for reading/writing key-value pairs

func readKeyValue(r io.Reader) (key, value []byte, err error) {
	// Read key length
	keyLen, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, nil, err
	}

	// Zero length means separator
	if keyLen == 0 {
		return nil, nil, nil
	}

	// Read key
	key = make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, err
	}

	// Read value length
	valueLen, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, nil, err
	}

	// Read value
	value = make([]byte, valueLen)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, nil, err
	}

	return key, value, nil
}

func writeKeyValue(w io.Writer, key, value []byte) error {
	// Write key length + key
	if err := wire.WriteCompactSize(w, uint64(len(key))); err != nil {
		return err
	}
	if _, err := w.Write(key); err != nil {
		return err
	}

	// Write value length + value
	if err := wire.WriteCompactSize(w, uint64(len(value))); err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}

	return nil
}

// parseBIP32Derivation parses a BIP32 derivation path from bytes.
func parseBIP32Derivation(data []byte) (*BIP32Derivation, error) {
	if len(data) < 4 {
		return nil, errors.New("BIP32 derivation too short")
	}
	if (len(data)-4)%4 != 0 {
		return nil, errors.New("invalid BIP32 derivation length")
	}

	deriv := &BIP32Derivation{}
	copy(deriv.Fingerprint[:], data[:4])

	numIndices := (len(data) - 4) / 4
	deriv.Path = make([]uint32, numIndices)
	for i := 0; i < numIndices; i++ {
		deriv.Path[i] = binary.LittleEndian.Uint32(data[4+i*4:])
	}

	return deriv, nil
}

// serializeBIP32Derivation serializes a BIP32 derivation path.
func serializeBIP32Derivation(deriv *BIP32Derivation) []byte {
	result := make([]byte, 4+len(deriv.Path)*4)
	copy(result[:4], deriv.Fingerprint[:])
	for i, idx := range deriv.Path {
		binary.LittleEndian.PutUint32(result[4+i*4:], idx)
	}
	return result
}

// parseTapBIP32Derivation parses taproot BIP32 derivation from bytes.
func parseTapBIP32Derivation(data []byte) (*TapBIP32Derivation, error) {
	if len(data) < 1 {
		return nil, errors.New("tap BIP32 derivation too short")
	}

	r := bytes.NewReader(data)

	// Read number of leaf hashes
	numHashes, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	deriv := &TapBIP32Derivation{
		LeafHashes: make([][32]byte, numHashes),
	}

	for i := uint64(0); i < numHashes; i++ {
		if _, err := io.ReadFull(r, deriv.LeafHashes[i][:]); err != nil {
			return nil, err
		}
	}

	// Read fingerprint
	if _, err := io.ReadFull(r, deriv.Fingerprint[:]); err != nil {
		return nil, err
	}

	// Read path indices
	remaining := r.Len()
	if remaining%4 != 0 {
		return nil, errors.New("invalid tap BIP32 derivation path length")
	}
	numIndices := remaining / 4
	deriv.Path = make([]uint32, numIndices)
	for i := 0; i < numIndices; i++ {
		idx, err := wire.ReadUint32LE(r)
		if err != nil {
			return nil, err
		}
		deriv.Path[i] = idx
	}

	return deriv, nil
}

// serializeTapBIP32Derivation serializes taproot BIP32 derivation.
func serializeTapBIP32Derivation(deriv *TapBIP32Derivation) []byte {
	var buf bytes.Buffer

	// Write number of leaf hashes
	wire.WriteCompactSize(&buf, uint64(len(deriv.LeafHashes)))

	// Write leaf hashes
	for _, hash := range deriv.LeafHashes {
		buf.Write(hash[:])
	}

	// Write fingerprint
	buf.Write(deriv.Fingerprint[:])

	// Write path indices
	for _, idx := range deriv.Path {
		wire.WriteUint32LE(&buf, idx)
	}

	return buf.Bytes()
}

// parseWitnessStack parses a witness stack from serialized form.
func parseWitnessStack(data []byte) ([][]byte, error) {
	r := bytes.NewReader(data)

	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	stack := make([][]byte, count)
	for i := uint64(0); i < count; i++ {
		length, err := wire.ReadCompactSize(r)
		if err != nil {
			return nil, err
		}
		stack[i] = make([]byte, length)
		if _, err := io.ReadFull(r, stack[i]); err != nil {
			return nil, err
		}
	}

	return stack, nil
}

// serializeWitnessStack serializes a witness stack.
func serializeWitnessStack(stack [][]byte) []byte {
	var buf bytes.Buffer

	wire.WriteCompactSize(&buf, uint64(len(stack)))
	for _, item := range stack {
		wire.WriteCompactSize(&buf, uint64(len(item)))
		buf.Write(item)
	}

	return buf.Bytes()
}

// parseTapTree parses a tap tree (per-output PSBT_OUT_TAP_TREE, BIP371)
// from serialized form. Each leaf is { depth:u8, leafVersion:u8,
// compactSize(script), script }.
func parseTapTree(data []byte) ([]TapTreeLeaf, error) {
	r := bytes.NewReader(data)
	var leaves []TapTreeLeaf

	for r.Len() > 0 {
		// Read depth (1 byte)
		depth, err := wire.ReadUint8(r)
		if err != nil {
			return nil, err
		}

		// Read leaf version (1 byte)
		leafVersion, err := wire.ReadUint8(r)
		if err != nil {
			return nil, err
		}

		// Read script
		scriptLen, err := wire.ReadCompactSize(r)
		if err != nil {
			return nil, err
		}
		script := make([]byte, scriptLen)
		if _, err := io.ReadFull(r, script); err != nil {
			return nil, err
		}

		leaves = append(leaves, TapTreeLeaf{
			Depth:       depth,
			LeafVersion: leafVersion,
			Script:      script,
		})
	}

	return leaves, nil
}

// serializeTapTree serializes a tap tree to its BIP371 PSBT_OUT_TAP_TREE
// wire form. Inverse of parseTapTree.
func serializeTapTree(leaves []TapTreeLeaf) []byte {
	var buf bytes.Buffer

	for _, leaf := range leaves {
		// Write depth
		wire.WriteUint8(&buf, leaf.Depth)

		// Write leaf version
		wire.WriteUint8(&buf, leaf.LeafVersion)

		// Write script
		wire.WriteCompactSize(&buf, uint64(len(leaf.Script)))
		buf.Write(leaf.Script)
	}

	return buf.Bytes()
}

// validatePSBTInput is the IsSane analog from Bitcoin Core
// (`src/psbt.cpp` PSBTInput::IsSane). It ensures the per-input UTXO
// oracles agree with the unsigned transaction's prevout reference,
// before any sighash is computed against them. Two checks:
//
//  1. If NON_WITNESS_UTXO is present, DoubleSHA256 of its serialized
//     (no-witness) bytes MUST equal the prevout hash. Otherwise an
//     attacker can swap in a forged prevTx whose TxOut[vout] lies
//     about the value or scriptPubKey, and the signer will produce a
//     valid signature over forged data (W40-A bug A1).
//
//  2. If both WITNESS_UTXO and NON_WITNESS_UTXO are present, the
//     (value, scriptPubKey) at NON_WITNESS_UTXO.TxOut[vout] MUST
//     match WITNESS_UTXO byte-for-byte. Otherwise the signer's amount
//     oracle (WITNESS_UTXO) can be lied to while the txid check above
//     still passes — CVE-2020-14199 / W40-A bug A2.
//
// Pure function over the input + its prevout. Called from the parser
// (defense against malformed input on the wire) AND from the signer
// dispatch (defense against PSBTs constructed in-process that bypass
// the parser).
func validatePSBTInput(input *PSBTInput, prevOutpoint wire.OutPoint) error {
	if input == nil {
		return nil
	}

	// A1: NON_WITNESS_UTXO txid check.
	if input.NonWitnessUTXO != nil {
		actualTxid := input.NonWitnessUTXO.TxHash()
		if actualTxid != prevOutpoint.Hash {
			return ErrPSBTNonWitnessUTXOMismatch
		}
		if int(prevOutpoint.Index) >= len(input.NonWitnessUTXO.TxOut) {
			return ErrPSBTUTXOIndexOutOfRange
		}
	}

	// A2: WITNESS_UTXO vs NON_WITNESS_UTXO cross-check (both present).
	// CVE-2020-14199: WITNESS_UTXO is the amount oracle for BIP-143
	// sighash; if it disagrees with the verified NON_WITNESS_UTXO the
	// signer must refuse to commit.
	if input.WitnessUTXO != nil && input.NonWitnessUTXO != nil {
		// Index already bounds-checked above.
		nwOut := input.NonWitnessUTXO.TxOut[prevOutpoint.Index]
		if nwOut.Value != input.WitnessUTXO.Value {
			return ErrWitnessUtxoMismatch
		}
		if !bytes.Equal(nwOut.PkScript, input.WitnessUTXO.PkScript) {
			return ErrWitnessUtxoMismatch
		}
	}

	return nil
}
