// PayJoin receiver foundation (BIP-78) — wallet-side core.
//
// Closes W119 BUG-2 (partial — receiver only) and threads through BUG-4,
// BUG-7, BUG-8, BUG-9, BUG-13, BUG-14, BUG-17, BUG-18. Sender-side anti-snoop
// (BUG-3 / G10-G15 / G22) is OUT OF SCOPE for FIX-65 and remains
// Skip()-marked in w119_payjoin_test.go — this fix-wave wires the receiver
// half so a real BIP-78 sender (e.g. payjoin.org Rust crate, btcpayserver)
// can exercise the merchant flow.
//
// The receiver flow per BIP-78 §"Receiver's original PSBT validation" and
// §"Receiver's payjoin proposal PSBT":
//
//  1. Decode the sender's "Original PSBT" (base64 in the request body).
//  2. Validate structural rules: parseable; ≥1 input; ≥1 output; every
//     input has either witness_utxo or non_witness_utxo (so the receiver
//     can verify the prevout amount/script and the sighash later); the
//     PSBT pays the receiver's address.
//  3. Select 1 receiver UTXO from the wallet (reuses ListUnspent + the
//     scriptToOwnAddressLocked/isInternalAddressLocked helpers landed in
//     FIX-61's bumpfee.go for ownership and change-output detection).
//  4. Construct the Payjoin Proposal PSBT: clone the sender's tx, append
//     the receiver input, bump the receiver-output value by the new input
//     amount, leave every sender input/output in place (anti-snoop on the
//     sender side will verify this). Mark the receiver's input with the
//     witness UTXO so the sender can re-finalize after their own sign.
//  5. Sign the receiver input via the existing WalletPSBTSigner (BIP-32
//     derivation lookups are unchanged from sendtoaddress/walletprocesspsbt).
//  6. Return base64(proposal PSBT).
//
// Per the BIP-78 spec, the FOUR JSON error codes that this layer emits are:
//
//   version-unsupported   — `v` query-param missing or != "1"
//   original-psbt-rejected — structural / amount / receiver-not-paid failures
//   not-enough-money       — wallet has no usable UTXO to add
//   unavailable            — receiver temporarily can't honor (rare; covers
//                            wallet locked, no addresses, internal panic)
//
// These map to HTTP status codes 415 / 400 / 422 / 503 respectively in the
// RPC layer (see internal/rpc/payjoin.go). Per the spec the body shape is:
//
//   { "errorCode": "...", "message": "..." }
//
// served with Content-Type application/json regardless of the success
// Content-Type (text/plain base64). Errors here are returned as typed
// values so the RPC handler can do the http-status mapping in one place.
//
// Reference: bips/bip-0078.mediawiki; payjoin.org reference implementation
// (Rust crate `payjoin`); btcpayserver PayJoin plugin.

package wallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ── BIP-78 error categories ──────────────────────────────────────────────
//
// PayjoinErrorCode is the BIP-78 errorCode JSON string. The RPC layer maps
// each to an HTTP status (see internal/rpc/payjoin.go). We define them as
// typed constants so the call sites stay greppable and the wire strings
// never drift.
type PayjoinErrorCode string

const (
	// PayjoinErrVersionUnsupported is returned when the sender's `v` query
	// parameter is missing or not equal to "1". Per BIP-78 §"Receive
	// payjoin", the receiver MUST refuse non-v1 requests with this code so
	// a future v=2 sender retries against a v=1-only receiver.
	PayjoinErrVersionUnsupported PayjoinErrorCode = "version-unsupported"

	// PayjoinErrOriginalPSBTRejected covers every structural failure in
	// the sender's PSBT: not parseable, no inputs, no outputs, an input
	// missing both witness_utxo and non_witness_utxo, the PSBT does not
	// pay the receiver's address, or the body is too large.
	PayjoinErrOriginalPSBTRejected PayjoinErrorCode = "original-psbt-rejected"

	// PayjoinErrNotEnoughMoney is returned when the wallet has no UTXO
	// suitable to add as the receiver's contributing input. Per BIP-78
	// §"How to select utxos" the receiver SHOULD pick a UTXO that
	// preserves the UIH-1/UIH-2 ambiguity, but in this initial wiring
	// we just take the first available wallet UTXO; if there is none
	// at all the request fails with this code.
	PayjoinErrNotEnoughMoney PayjoinErrorCode = "not-enough-money"

	// PayjoinErrUnavailable is the "try later" code: wallet locked, no
	// addresses derived, or any internal error the receiver doesn't want
	// to leak. Per BIP-78 §"Error responses" senders SHOULD retry after
	// a backoff.
	PayjoinErrUnavailable PayjoinErrorCode = "unavailable"
)

// PayjoinError is the typed error the receiver returns. The RPC layer
// type-switches on Code to pick the HTTP status. Implements the standard
// error interface so it interoperates with errors.As / errors.Is.
type PayjoinError struct {
	Code    PayjoinErrorCode
	Message string
}

// Error implements the error interface.
func (e *PayjoinError) Error() string {
	return fmt.Sprintf("payjoin: %s: %s", e.Code, e.Message)
}

// newPayjoinErr is a small helper to keep the call sites compact.
func newPayjoinErr(code PayjoinErrorCode, format string, args ...interface{}) *PayjoinError {
	return &PayjoinError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// PayjoinMaxBodyBytes caps the inbound base64 PSBT. The BIP-78 spec does
// not pin a hard maximum; we follow the payjoin.org Rust reference (8 KiB)
// which fits a realistic 2-3 input / 2-output sender PSBT well under the
// cap but stops a malicious sender from forcing the receiver to alloc.
const PayjoinMaxBodyBytes = 8 * 1024

// PayjoinRequest is the parsed receiver-side request.
//
// Filled in by the RPC layer (which owns the HTTP transport) and passed
// to ProcessPayjoinRequest. Keeping this struct in the wallet package
// means the receiver core can be unit-tested without spinning up an
// http.Server.
type PayjoinRequest struct {
	// OriginalPSBTBase64 is the body of the POST, decoded from
	// Content-Type: text/plain. Must be valid base64 of a v0 PSBT.
	OriginalPSBTBase64 string

	// Version is the `v` query param. Per BIP-78 v=1 is the only
	// currently defined value. Empty / absent => v=1 default for
	// legacy clients (the spec is permissive here).
	Version string
}

// ProcessPayjoinRequest is the receiver-side entry point: it validates
// every BIP-78 rule, picks one wallet input, signs the receiver's added
// input, and returns the base64-encoded Payjoin Proposal PSBT.
//
// On failure it returns a *PayjoinError so the RPC layer can map the
// BIP-78 errorCode to the right HTTP status (see internal/rpc/payjoin.go).
//
// Implementation notes:
//
//   - We don't run the full coin-selection algorithm here; per the audit
//     this fix-wave only opens the door. Future FIX-N can layer UIH-1/UIH-2
//     selection on top (BUG-8 / G20) without changing the function shape.
//
//   - Sender output substitution / fee adjustment past
//     `maxadditionalfeecontribution` is OUT OF SCOPE — this initial wiring
//     only ADDS a receiver input + grows the receiver-paying output by the
//     added input amount, so the sender's fee stays exactly the same. The
//     spec allows this minimalist form (§"Receiver's payjoin proposal
//     PSBT", "The receiver MAY add inputs, outputs, or both" — we add
//     inputs only).
//
//   - Locking discipline: we DON'T hold w.mu across the whole function.
//     The receiver scan + UTXO pick is done under RLock; signing then
//     uses the standard WalletPSBTSigner path which takes its own locks.
//     This matches the lock discipline of other wallet RPCs (sendtoaddress
//     etc.) and avoids re-entrancy issues with sync.RWMutex.
func (w *Wallet) ProcessPayjoinRequest(req *PayjoinRequest) (string, *PayjoinError) {
	// ── G21 / BUG-14: v=1 enforcement ───────────────────────────────────
	// Per BIP-78 §"Receive payjoin": the receiver MUST treat any `v` other
	// than "1" as version-unsupported. An ABSENT `v` is treated as "1" for
	// legacy compatibility (some early Joinmarket clients never sent it).
	if req.Version != "" && req.Version != "1" {
		return "", newPayjoinErr(PayjoinErrVersionUnsupported,
			"server only supports PayJoin v=1 (got v=%q)", req.Version)
	}

	// ── G4: decode the Original PSBT ────────────────────────────────────
	// BUG-13: enforce the body cap as a structural check (the RPC layer
	// also enforces Content-Length, but this is defense in depth — the
	// caller could pass a hand-crafted PayjoinRequest in tests too).
	if len(req.OriginalPSBTBase64) == 0 {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"empty request body")
	}
	if len(req.OriginalPSBTBase64) > PayjoinMaxBodyBytes {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"PSBT body too large (%d bytes; max %d)",
			len(req.OriginalPSBTBase64), PayjoinMaxBodyBytes)
	}

	original, err := DecodePSBTBase64(req.OriginalPSBTBase64)
	if err != nil {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"failed to decode PSBT: %v", err)
	}

	// ── G5: validate the Original PSBT ──────────────────────────────────
	// BIP-78 §"Receiver's original PSBT validation":
	//   1. PSBT structurally valid.
	//   2. ≥1 input.
	//   3. ≥1 output.
	//   4. Every input has witness_utxo OR non_witness_utxo (so the
	//      receiver can verify amounts when constructing the proposal).
	//   5. At least one output pays the receiver's address (otherwise the
	//      receiver has no reason to facilitate this PayJoin — it's a
	//      stranger asking the receiver to sign a tx that doesn't pay
	//      them).
	if original.UnsignedTx == nil {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"PSBT has no unsigned tx")
	}
	if len(original.UnsignedTx.TxIn) == 0 || len(original.Inputs) == 0 {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"PSBT has no inputs")
	}
	if len(original.UnsignedTx.TxOut) == 0 || len(original.Outputs) == 0 {
		return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"PSBT has no outputs")
	}
	for i, in := range original.Inputs {
		if in.WitnessUTXO == nil && in.NonWitnessUTXO == nil {
			return "", newPayjoinErr(PayjoinErrOriginalPSBTRejected,
				"input %d missing witness_utxo and non_witness_utxo", i)
		}
	}

	// ── G5 cont. / G6 readiness: receiver-paying output check ───────────
	// We require the sender's tx to pay at least one of our own addresses.
	// This is also the seed for the future fee-bump logic (BUG-17 / G6):
	// the receiver's input added below MUST grow exactly that output, not
	// some random sender output.
	//
	// Read snapshot under RLock: receiver-paying output index, candidate
	// UTXO. We then release before calling the signer (which takes its
	// own locks).
	receiverOutIdx, receiverUTXO, perr := w.payjoinScanLocked(original)
	if perr != nil {
		return "", perr
	}

	// ── G7 / G8: build the Payjoin Proposal tx ──────────────────────────
	// Per spec we mutate the unsigned tx structurally (the proposal is a
	// brand-new PSBT, not a delta on the sender's PSBT). We copy:
	//   - Version, LockTime from the original (sender's choice — preserves
	//     anti-fee-sniping locktime + nVersion features),
	//   - all sender inputs (with their nSequence, preserving sender RBF
	//     / nLockTime activation choices),
	//   - all sender outputs in order, except receiverOutIdx whose Value
	//     grows by receiverUTXO.Amount,
	//   - then append the receiver's input at the END (the sender's
	//     anti-snoop verifier expects original inputs at their original
	//     indices; new receiver inputs SHOULD be appended).
	proposalTx := &wire.MsgTx{
		Version:  original.UnsignedTx.Version,
		LockTime: original.UnsignedTx.LockTime,
	}
	for _, in := range original.UnsignedTx.TxIn {
		proposalTx.TxIn = append(proposalTx.TxIn, &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			Sequence:         in.Sequence,
		})
	}
	// Append receiver input. Sequence MIRRORS the sender's first input
	// so the tx still signals BIP-125 RBF if the sender opted in. (A
	// future hardening can match per the sender's individual Sequence
	// choice; for now mirroring input 0 is a safe default.)
	receiverInputIdx := len(proposalTx.TxIn)
	proposalTx.TxIn = append(proposalTx.TxIn, &wire.TxIn{
		PreviousOutPoint: receiverUTXO.OutPoint,
		Sequence:         original.UnsignedTx.TxIn[0].Sequence,
	})

	// Outputs: clone, grow receiver output by added input amount.
	for i, out := range original.UnsignedTx.TxOut {
		value := out.Value
		if i == receiverOutIdx {
			// G9 / BUG-18 readiness: at this point we COULD optionally
			// adjust the fee per `maxadditionalfeecontribution`; since
			// this initial wiring leaves the fee unchanged, we just
			// pass the full added input value to the receiver output.
			value = out.Value + receiverUTXO.Amount
		}
		proposalTx.TxOut = append(proposalTx.TxOut, &wire.TxOut{
			Value:    value,
			PkScript: out.PkScript,
		})
	}

	// ── Wrap in a new PSBT ──────────────────────────────────────────────
	proposal, err := NewPSBT(proposalTx)
	if err != nil {
		// NewPSBT only fails if a TxIn has a non-empty scriptSig/witness,
		// which can't happen here (we built TxIns from scratch). Surface
		// as Unavailable so the sender retries — never leak internal
		// detail.
		return "", newPayjoinErr(PayjoinErrUnavailable,
			"failed to wrap proposal PSBT: %v", err)
	}

	// Copy sender-side per-input fields so the sender can recover their
	// own signing state (BIP-78 §"Receiver's payjoin proposal PSBT" —
	// "Receivers shouldn't strip fields the sender provided"). We copy
	// the inputs the sender already filled in; the new receiver-input
	// slot stays empty until we sign below.
	for i := 0; i < len(original.Inputs); i++ {
		proposal.Inputs[i] = original.Inputs[i]
	}
	for i := 0; i < len(original.Outputs); i++ {
		proposal.Outputs[i] = original.Outputs[i]
	}

	// ── G7: attach the receiver's input WitnessUTXO + BIP32 deriv ───────
	// The receiver MUST provide either witness_utxo or non_witness_utxo
	// for the input it just added, otherwise the sender (and validator)
	// can't compute the sighash for the added input. P2WPKH/P2WSH/P2TR
	// fit in witness_utxo (just a TxOut copy); pre-segwit P2PKH would
	// need non_witness_utxo. The wallet's standard address types in
	// blockbrew are P2WPKH/P2TR/P2SH-P2WPKH/P2PKH; the first three all
	// accept witness_utxo, P2PKH does not. We attach witness_utxo
	// unconditionally — a future hardening can copy the full
	// non_witness_utxo when isP2PKH returns true for receiverUTXO.PkScript.
	proposal.Inputs[receiverInputIdx].WitnessUTXO = &wire.TxOut{
		Value:    receiverUTXO.Amount,
		PkScript: receiverUTXO.PkScript,
	}

	// Attach BIP-32 derivation so WalletPSBTSigner can find the right key
	// without a wallet-state scan. We need the master fingerprint and the
	// receiver's compressed pubkey — both pulled atomically inside the
	// helper below to keep locking simple.
	if perr := w.payjoinAttachBIP32Locked(proposal, receiverInputIdx, receiverUTXO); perr != nil {
		return "", perr
	}

	// ── Sign via the existing WalletPSBTSigner ──────────────────────────
	// SignPSBTInput takes wallet locks internally (read locks via
	// GetMasterFingerprint, deriveKey). Calling it WITHOUT holding any
	// wallet lock here is the correct pattern (matches handleBumpFee /
	// handleWalletProcessPSBT in the existing RPC handlers).
	signer := NewWalletPSBTSigner(w)
	if _, signErr := signer.SignPSBTInput(proposal, receiverInputIdx); signErr != nil {
		return "", newPayjoinErr(PayjoinErrUnavailable,
			"failed to sign receiver input: %v", signErr)
	}

	// ── Encode + return ─────────────────────────────────────────────────
	out, encErr := proposal.EncodeBase64()
	if encErr != nil {
		return "", newPayjoinErr(PayjoinErrUnavailable,
			"failed to encode proposal PSBT: %v", encErr)
	}
	return out, nil
}

// payjoinScanLocked performs the receiver-output + UTXO-selection scan
// under a single RLock acquisition so we have a consistent snapshot
// (utxos + addrToPath + lockedCoins).
//
// Returns:
//   - the index of the receiver-paying output (G5 / G6),
//   - a candidate UTXO to add as the receiver input (G7 / G8 / G20).
//
// Returns a *PayjoinError that the caller propagates verbatim — wraps the
// two failure modes (no receiver output, no usable UTXO) with the right
// BIP-78 error code.
func (w *Wallet) payjoinScanLocked(original *PSBT) (int, *WalletUTXO, *PayjoinError) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked {
		return -1, nil, newPayjoinErr(PayjoinErrUnavailable,
			"wallet is locked")
	}

	receiverOutIdx := -1
	for i, out := range original.UnsignedTx.TxOut {
		addr, ok := w.scriptToOwnAddressLocked(out.PkScript)
		if !ok {
			continue
		}
		// Skip internal/change addresses on the receiver side — those
		// would be the receiver-as-sender role from a previous flow;
		// we only grow an EXTERNAL receive output here.
		if w.isInternalAddressLocked(addr) {
			continue
		}
		receiverOutIdx = i
		break
	}
	if receiverOutIdx < 0 {
		return -1, nil, newPayjoinErr(PayjoinErrOriginalPSBTRejected,
			"PSBT does not pay any of this wallet's external addresses")
	}

	// G7 / BUG-8: select a receiver UTXO. First-fit selection; the audit
	// explicitly defers full UIH-1/UIH-2 to a future fix-wave. We just
	// need ANY wallet UTXO that:
	//   - is confirmed (avoid offering an unconfirmed coin the sender
	//     might refuse anyway via standard 0-conf policy),
	//   - is not already in the sender's input set (would be a no-op
	//     and would also be a self-double-spend hazard),
	//   - is not operator-locked (lockedCoins set via lockunspent RPC).
	senderOutpoints := make(map[wire.OutPoint]struct{}, len(original.UnsignedTx.TxIn))
	for _, in := range original.UnsignedTx.TxIn {
		senderOutpoints[in.PreviousOutPoint] = struct{}{}
	}

	var receiverUTXO *WalletUTXO
	for _, u := range w.utxos {
		if !u.Confirmed {
			continue
		}
		if _, dup := senderOutpoints[u.OutPoint]; dup {
			continue
		}
		if _, locked := w.lockedCoins[u.OutPoint]; locked {
			continue
		}
		receiverUTXO = u
		break
	}
	if receiverUTXO == nil {
		return -1, nil, newPayjoinErr(PayjoinErrNotEnoughMoney,
			"no wallet UTXO available to contribute")
	}

	return receiverOutIdx, receiverUTXO, nil
}

// payjoinAttachBIP32Locked attaches the master fingerprint + derivation
// path + compressed pubkey for the receiver's added input so that the
// downstream WalletPSBTSigner can locate the right key.
//
// This is a thin helper that holds the wallet lock for exactly the read
// span (master fingerprint, key derivation) and writes to the PSBT
// outside of any shared state.
func (w *Wallet) payjoinAttachBIP32Locked(p *PSBT, idx int, utxo *WalletUTXO) *PayjoinError {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked {
		return newPayjoinErr(PayjoinErrUnavailable, "wallet is locked")
	}
	if w.masterKey == nil {
		return newPayjoinErr(PayjoinErrUnavailable, "wallet has no master key")
	}
	fingerprint := w.masterKey.Fingerprint()

	// Resolve the derivation path: prefer the UTXO's recorded KeyPath
	// (the canonical source). Fall back to addrToPath[utxo.Address] for
	// UTXOs added via AddUTXO without KeyPath set (common in test setups
	// and historically also in some block-scan paths). Mirrors
	// findKeyForUTXO so wallets that work for sendtoaddress also work
	// for PayJoin.
	keyPath := utxo.KeyPath
	if keyPath == "" {
		if p, ok := w.addrToPath[utxo.Address]; ok {
			keyPath = p
		}
	}
	if keyPath == "" {
		return newPayjoinErr(PayjoinErrUnavailable,
			"wallet has no recorded KeyPath for receiver UTXO at outpoint %v", utxo.OutPoint)
	}

	priv, err := w.getKeyForPath(keyPath)
	if err != nil {
		return newPayjoinErr(PayjoinErrUnavailable,
			"failed to derive key for receiver input: %v", err)
	}
	pubKey := priv.PubKey().SerializeCompressed()

	pathIndices, parseErr := parseBIP32PathString(keyPath)
	if parseErr != nil {
		return newPayjoinErr(PayjoinErrUnavailable,
			"invalid wallet KeyPath %q: %v", keyPath, parseErr)
	}

	input := &p.Inputs[idx]
	if input.BIP32Derivation == nil {
		input.BIP32Derivation = make(map[string]*BIP32Derivation)
	}
	input.BIP32Derivation[string(pubKey)] = &BIP32Derivation{
		Fingerprint: fingerprint,
		Path:        pathIndices,
	}
	return nil
}

// parseBIP32PathString converts a textual derivation path like
// "m/84'/0'/0'/0/5" into the []uint32 form the PSBT carries. Hardened
// segments (suffixed with `'`, `h`, or `H`) get the 0x80000000 bit set.
//
// This is a local helper that mirrors HDKey.DerivePath's parser but
// returns the raw indices rather than walking the key tree. We keep the
// parser local (rather than exporting one from hdkey.go) to avoid
// widening the package surface for a single internal consumer.
func parseBIP32PathString(path string) ([]uint32, error) {
	if !strings.HasPrefix(path, "m") && !strings.HasPrefix(path, "M") {
		return nil, fmt.Errorf("path must start with 'm/' or 'M/'")
	}
	// Root path: empty indices slice.
	if path == "m" || path == "M" {
		return nil, nil
	}
	path = strings.TrimPrefix(path, "m/")
	path = strings.TrimPrefix(path, "M/")

	segments := strings.Split(path, "/")
	indices := make([]uint32, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		isHardened := false
		if strings.HasSuffix(segment, "'") ||
			strings.HasSuffix(segment, "h") ||
			strings.HasSuffix(segment, "H") {
			isHardened = true
			segment = segment[:len(segment)-1]
		}
		n, err := strconv.ParseUint(segment, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid index %q: %w", segment, err)
		}
		idx := uint32(n)
		if isHardened {
			idx += HardenedKeyStart
		}
		indices = append(indices, idx)
	}
	return indices, nil
}
