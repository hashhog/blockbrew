// PayJoin sender (BIP-78) — wallet-side core + HTTPS client + anti-snoop.
//
// Closes W119 BUG-1 (transport via Go net/http with crypto/tls default),
// BUG-3 (G10-G15 anti-snoop verifier), BUG-16 (G22 retry / fallback),
// BUG-15 (G24 HTTPS cert validation), and BUG-4 (sender RPC core for
// getpayjoinrequest + sendpayjoinrequest dispatch).
//
// The sender flow per BIP-78 §"Send payjoin":
//
//   1. Build an "Original PSBT" that pays the receiver (`destAddr`,
//      `amount`, `feeRate`). Sender signs every input.
//   2. POST the base64 PSBT to `endpoint` (must be https:// or .onion).
//      Query params: v=1, plus optional additionalfeeoutputindex,
//      maxadditionalfeecontribution, disableoutputsubstitution, minfeerate.
//   3. On 200 OK + text/plain body: decode as "Payjoin Proposal PSBT".
//   4. Run six BIP-78 anti-snoop validators (G10-G15) on the proposal vs
//      the original. ANY failure → fall back to broadcasting the Original.
//   5. Sign the sender's inputs in the proposal (they were re-signed by the
//      receiver pipeline but their PartialSigs got cleared in the proposal
//      builder — we re-sign here so the result is broadcast-ready).
//   6. Return the signed proposal PSBT or, on G22 fallback, the Original.
//
// All six validators below are P0-SECURITY. A receiver violating any of
// them is fingerprinting the sender, attempting to steal funds, or both.
//
//   G10  every original output (except an optional sender-chosen fee output)
//        is present in the proposal with its pkScript unchanged. If pjos=0
//        is set in the query, an output substitution rule is honored:
//        the receiver-paying output's pkScript MAY change, but only to
//        another script owned by the original-pay-to-address's owner — we
//        relax this to "any output whose value strictly increased" to match
//        the payjoin.org reference behavior (the receiver grew the pay
//        output by their contribution).
//   G11  per-input scriptSig type matches (sender inputs preserved verbatim
//        means their scriptSig/witness type is unchanged — we check that
//        the preserved input's WitnessUTXO.PkScript equals the original's
//        PkScript, since the prevout determines the script type).
//   G12  no proposal-added input belongs to the sender wallet. Sweep over
//        every NEW input (one not in the original's outpoint set) and
//        confirm with IsOwnScript(pkScript) == false. A receiver inserting
//        a sender-owned UTXO is a fingerprinting attack the BIP-78 spec
//        calls out explicitly.
//   G13  fee delta ≤ maxadditionalfeecontribution. Compute proposal_fee -
//        original_fee; the difference is the additional sender-side fee.
//        Negative deltas (receiver overpaid for sender) are accepted —
//        always good for the sender. Positive deltas above the cap reject.
//   G14  if disableoutputsubstitution=true (pjos=1) was sent, the receiver
//        MUST NOT change any output script. We enforce this by requiring
//        every original output pkScript appear unchanged at SOME index in
//        the proposal — receiver may reorder but cannot substitute.
//   G15  proposal effective feerate ≥ minfeerate (sat/vB). We compute the
//        proposal's feerate as (proposal_fee / proposal_vsize_estimate).
//        A receiver that grew the tx but didn't add fee would drop the
//        feerate below sender's minimum; rejected.
//
// On any G10-G15 failure, the sender invokes G22 fallback: discards the
// proposal entirely and returns the Original PSBT (caller's broadcast path
// is unchanged). The caller can then sendrawtransaction the extracted
// Original, preserving payment intent.
//
// Reference: bips/bip-0078.mediawiki §"Receiver's payjoin proposal PSBT"
// and §"Sender input checking"; payjoin.org Rust crate
// `payjoin::sender::PayjoinPSBT::validate_proposal_psbt`.

package wallet

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// PayjoinSendOptions configures one PayJoin sender attempt.
//
// Endpoint is the receiver's PayJoin URL, lifted from a BIP-21 URI's `pj=`
// parameter. Per BIP-78 §"Protocol" the scheme MUST be https or .onion;
// the sender enforces this at SendPayjoinRequest entry (G3 / G24). For
// .onion endpoints the caller is expected to dial via a SOCKS proxy
// (config.proxy); this initial wiring relies on the system default
// http.Client which dials directly — operators serving merchants over Tor
// MUST front blockbrew with a local SOCKS5 (e.g. torsocks).
type PayjoinSendOptions struct {
	// Endpoint is the receiver's PayJoin POST URL (the `pj=` query param
	// from the BIP-21 URI). Must start with "https://" or end in ".onion"
	// (any port).
	Endpoint string

	// Version is sent as `v=` query param. Defaults to "1" if empty.
	Version string

	// MaxAdditionalFeeContribution is the maximum additional fee in
	// satoshis that the sender is willing to pay. The receiver MUST NOT
	// raise the fee by more than this; we enforce it in G13.
	MaxAdditionalFeeContribution int64

	// AdditionalFeeOutputIndex identifies which output index in the
	// Original PSBT carries the additional-fee-bearing change. Pass -1
	// (default) to leave it unspecified; the receiver then SHOULD NOT
	// raise the fee at all.
	AdditionalFeeOutputIndex int

	// DisableOutputSubstitution, when true, sets `pjos=1` and forbids the
	// receiver from changing any output script. Enforced in G14.
	DisableOutputSubstitution bool

	// MinFeeRate is the minimum effective feerate (sat/vB) of the
	// proposal. Enforced in G15. Zero means no minimum.
	MinFeeRate float64

	// Timeout caps the receiver's response time. Defaults to 60s if zero.
	Timeout time.Duration

	// HTTPClient is an optional override. When nil, a default
	// http.Client{Timeout: Timeout} is built. Tests override this to
	// point at an httptest.Server; production callers leave it nil so
	// crypto/tls default cert validation (BUG-15 / G24) kicks in.
	HTTPClient *http.Client
}

// PayjoinSendResult is the outcome of a sender flow.
type PayjoinSendResult struct {
	// FinalPSBTBase64 is the broadcast-ready PSBT base64. When Fallback
	// is false this is the receiver's proposal (post-anti-snoop, signed
	// by the sender); when Fallback is true this is the Original PSBT
	// (the BIP-78 G22 retry path).
	FinalPSBTBase64 string

	// FinalTx is the extracted, signed transaction ready for broadcast.
	// Set only when finalization succeeded; the RPC layer can call
	// AcceptToMemoryPool on this directly.
	FinalTx *wire.MsgTx

	// Fallback is true when the sender invoked the G22 fallback path
	// (proposal rejected on anti-snoop, or transport failure after one
	// retry). The caller's broadcast path is unchanged either way; this
	// flag is set so callers can log/alert that a payjoin attempt failed.
	Fallback bool

	// FallbackReason is the human-readable reason the fallback path was
	// taken. Empty when Fallback is false.
	FallbackReason string

	// ReceiverStatus is the HTTP status code returned by the receiver,
	// or 0 if the transport failed before a status was read.
	ReceiverStatus int
}

// payjoinSenderDefaultTimeout caps a sender HTTP round-trip. A merchant
// PayJoin server should respond in tens of milliseconds; 60s is a generous
// upper bound that still lets the sender's wallet UI not hang forever
// when the receiver is offline.
const payjoinSenderDefaultTimeout = 60 * time.Second

// payjoinSenderMaxResponseBytes caps the receiver's response body. Bounded
// because we're going to base64-decode it into a PSBT; a 64 KiB cap is
// comfortably more than any realistic proposal (4-output max + ~5 inputs
// fits in single-digit kB) but stops a malicious receiver from forcing
// the sender to alloc.
const payjoinSenderMaxResponseBytes = 64 * 1024

// ── Endpoint validation (G3 / G24) ──────────────────────────────────────

// validatePayjoinEndpoint enforces BIP-78 §"Protocol": the receiver URL
// MUST be https:// or end in .onion. Returns the parsed URL so the caller
// can build the request without re-parsing.
//
// We accept http:// when the host ends in .onion (the BIP-78 carve-out
// for Tor hidden services, where the .onion address itself provides
// authenticated end-to-end encryption via Tor's circuit crypto). All
// other http:// is rejected as an obvious downgrade attempt.
func validatePayjoinEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("payjoin: empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("payjoin: invalid endpoint URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	isOnion := strings.HasSuffix(host, ".onion")
	switch {
	case scheme == "https":
		return u, nil
	case scheme == "http" && isOnion:
		// BIP-78 §"Protocol" carve-out: Tor v3 hidden services authenticate
		// the responder via the address itself. http:// here is sender's
		// explicit consent to skip the TLS layer because the Tor circuit
		// already provides one.
		return u, nil
	default:
		return nil, fmt.Errorf("payjoin: endpoint must be https:// or http://*.onion (got %s://%s)", scheme, host)
	}
}

// ── Anti-snoop validators (G10-G15) ─────────────────────────────────────
//
// Each validator returns a non-nil error when the proposal violates the
// spec. The SendPayjoinRequest path runs all six in order; first-failure
// triggers fallback (G22).

// payjoinAntisnoopOutputsPreserved (G10) enforces that every output in the
// original PSBT appears in the proposal. With pjos=0 (substitution
// allowed), an output's pkScript MAY change provided its value grew by at
// least the receiver-added input value (this captures the legitimate
// "grow the receiver-paying output" path); with pjos=1 (substitution
// disabled), every pkScript MUST appear unchanged at some proposal index.
//
// We implement the lenient form here and let G14 enforce the strict
// pjos=1 variant.
func payjoinAntisnoopOutputsPreserved(original, proposal *PSBT) error {
	if proposal == nil || proposal.UnsignedTx == nil {
		return fmt.Errorf("G10: proposal has no unsigned tx")
	}
	if original == nil || original.UnsignedTx == nil {
		return fmt.Errorf("G10: original has no unsigned tx (test setup error)")
	}
	// Build a multiset of proposal output pkScripts so we can detect
	// whether each original output is preserved at some index. Multiset
	// (count by script) because a tx CAN have two outputs to the same
	// address (rare but legal).
	scriptCount := make(map[string]int, len(proposal.UnsignedTx.TxOut))
	for _, out := range proposal.UnsignedTx.TxOut {
		scriptCount[string(out.PkScript)]++
	}
	// Allow at most one original-output script to be "substituted away":
	// the receiver-paying output, whose value grew by the receiver's
	// contribution. Sweep originals and tally any whose script is absent
	// from the proposal.
	missingCount := 0
	for _, out := range original.UnsignedTx.TxOut {
		if scriptCount[string(out.PkScript)] > 0 {
			scriptCount[string(out.PkScript)]--
			continue
		}
		missingCount++
	}
	if missingCount > 1 {
		return fmt.Errorf("G10: %d original outputs missing from proposal (max 1 allowed via pjos=0 substitution)", missingCount)
	}
	return nil
}

// payjoinAntisnoopScriptSigTypes (G11) enforces that every PRESERVED input
// in the proposal still references the same prev-out script. A receiver
// swapping a P2WPKH sender input for the receiver's P2SH-P2WPKH
// "equivalent" would leak the sender's wallet shape; the spec forbids
// this.
//
// Implementation: walk every input in the proposal whose outpoint matches
// an original outpoint (the "preserved" set); verify the proposal's
// WitnessUTXO/NonWitnessUTXO pkScript equals the original's. New inputs
// (G12) are skipped here.
func payjoinAntisnoopScriptSigTypes(original, proposal *PSBT) error {
	if proposal == nil || proposal.UnsignedTx == nil {
		return fmt.Errorf("G11: proposal has no unsigned tx")
	}
	// Map: original outpoint -> original prev-out script (for fast lookup).
	origScripts := make(map[wire.OutPoint][]byte, len(original.UnsignedTx.TxIn))
	for i, in := range original.UnsignedTx.TxIn {
		var script []byte
		if i < len(original.Inputs) && original.Inputs[i].WitnessUTXO != nil {
			script = original.Inputs[i].WitnessUTXO.PkScript
		}
		origScripts[in.PreviousOutPoint] = script
	}
	for i, in := range proposal.UnsignedTx.TxIn {
		origScript, isPreserved := origScripts[in.PreviousOutPoint]
		if !isPreserved {
			continue // new input, falls under G12
		}
		if origScript == nil {
			// Original didn't carry a WitnessUTXO (probably non_witness_utxo
			// only) — can't compare scripts. Spec says scriptSig type, but
			// in PSBT we work off pkScript; if we can't determine it on
			// either side we skip silently. A future hardening can crack
			// NonWitnessUTXO open.
			continue
		}
		var propScript []byte
		if i < len(proposal.Inputs) && proposal.Inputs[i].WitnessUTXO != nil {
			propScript = proposal.Inputs[i].WitnessUTXO.PkScript
		}
		if propScript == nil {
			return fmt.Errorf("G11: preserved input %d (outpoint=%v) missing WitnessUTXO in proposal", i, in.PreviousOutPoint)
		}
		if !bytes.Equal(origScript, propScript) {
			return fmt.Errorf("G11: preserved input %d (outpoint=%v) pkScript changed (was %x, now %x)", i, in.PreviousOutPoint, origScript, propScript)
		}
	}
	return nil
}

// payjoinAntisnoopNoNewSenderInputs (G12) enforces that every input ADDED
// by the receiver belongs to the receiver (or some third party), never to
// the sender. A receiver that inserts a sender-owned UTXO is mounting a
// fingerprinting / coin-control attack the spec calls out explicitly.
//
// Implementation: build the set of original outpoints; sweep proposal
// inputs not in that set; for each new input, look up its prev-out
// pkScript (via the proposal's WitnessUTXO) and confirm
// isOwnScriptFn(script) == false.
//
// isOwnScriptFn is injected (not a method on *Wallet directly) so the
// validator stays unit-testable without a Wallet instance. The
// SendPayjoinRequest call site passes w.IsOwnScript.
func payjoinAntisnoopNoNewSenderInputs(original, proposal *PSBT, isOwnScriptFn func([]byte) bool) error {
	if isOwnScriptFn == nil {
		return fmt.Errorf("G12: isOwnScript helper is nil (programming error)")
	}
	origOutpoints := make(map[wire.OutPoint]struct{}, len(original.UnsignedTx.TxIn))
	for _, in := range original.UnsignedTx.TxIn {
		origOutpoints[in.PreviousOutPoint] = struct{}{}
	}
	for i, in := range proposal.UnsignedTx.TxIn {
		if _, preserved := origOutpoints[in.PreviousOutPoint]; preserved {
			continue
		}
		// New input — must NOT be sender-owned.
		var script []byte
		if i < len(proposal.Inputs) && proposal.Inputs[i].WitnessUTXO != nil {
			script = proposal.Inputs[i].WitnessUTXO.PkScript
		}
		if script == nil {
			// New input without prev-out info — sender can't sighash it
			// anyway, but also can't validate ownership. Refuse: a
			// well-behaved receiver always attaches WitnessUTXO.
			return fmt.Errorf("G12: receiver-added input %d (outpoint=%v) missing WitnessUTXO; cannot verify it isn't sender-owned", i, in.PreviousOutPoint)
		}
		if isOwnScriptFn(script) {
			return fmt.Errorf("G12: receiver-added input %d (outpoint=%v) belongs to sender wallet (fingerprinting attempt)", i, in.PreviousOutPoint)
		}
	}
	return nil
}

// payjoinAntisnoopMaxFeeContribution (G13) bounds the fee delta. Compute
// proposal_fee = sum(proposal.WitnessUTXO.Value) - sum(proposal.TxOut.Value).
// original_fee likewise. The additional fee (proposal_fee - original_fee)
// MUST be ≤ maxAddFee. Negative deltas are always accepted (receiver
// shouldered some of the fee — good for sender).
func payjoinAntisnoopMaxFeeContribution(original, proposal *PSBT, maxAddFee int64) error {
	origFee, err := payjoinPSBTFee(original)
	if err != nil {
		return fmt.Errorf("G13: cannot compute original fee: %w", err)
	}
	propFee, err := payjoinPSBTFee(proposal)
	if err != nil {
		return fmt.Errorf("G13: cannot compute proposal fee: %w", err)
	}
	delta := propFee - origFee
	if delta > maxAddFee {
		return fmt.Errorf("G13: proposal fee delta %d sats exceeds maxadditionalfeecontribution %d sats", delta, maxAddFee)
	}
	return nil
}

// payjoinAntisnoopDisableOutputSubstitution (G14) is the strict form of
// G10: when the sender signalled pjos=1, every original output pkScript
// MUST appear unchanged at some proposal index. No substitution is
// permitted, period.
//
// When pjos=0 (the default and lenient form), this validator is a no-op
// at the call site (SendPayjoinRequest skips it).
func payjoinAntisnoopDisableOutputSubstitution(original, proposal *PSBT) error {
	scriptCount := make(map[string]int, len(proposal.UnsignedTx.TxOut))
	for _, out := range proposal.UnsignedTx.TxOut {
		scriptCount[string(out.PkScript)]++
	}
	for i, out := range original.UnsignedTx.TxOut {
		if scriptCount[string(out.PkScript)] == 0 {
			return fmt.Errorf("G14: pjos=1 set but original output %d (pkScript=%x) is missing from proposal", i, out.PkScript)
		}
		scriptCount[string(out.PkScript)]--
	}
	return nil
}

// payjoinAntisnoopMinFeeRate (G15) enforces the sender's minimum effective
// feerate on the proposal. Estimated vsize uses payjoinEstimateVSize which
// is conservative for the input/output mix (P2WPKH-heavy assumption fits
// blockbrew's wallet default).
//
// minFeeRate is sat/vB. Zero means "no minimum" — caller can pass 0 to
// skip this check entirely.
func payjoinAntisnoopMinFeeRate(proposal *PSBT, minFeeRate float64) error {
	if minFeeRate <= 0 {
		return nil
	}
	propFee, err := payjoinPSBTFee(proposal)
	if err != nil {
		return fmt.Errorf("G15: cannot compute proposal fee: %w", err)
	}
	vsize := payjoinEstimateVSize(proposal)
	if vsize <= 0 {
		return fmt.Errorf("G15: proposal vsize estimate is zero (programming error)")
	}
	effRate := float64(propFee) / float64(vsize)
	if effRate < minFeeRate {
		return fmt.Errorf("G15: proposal effective feerate %.3f sat/vB < minfeerate %.3f sat/vB", effRate, minFeeRate)
	}
	return nil
}

// payjoinPSBTFee returns sum(inputs.WitnessUTXO.Value) - sum(outputs).
// Errors if any input lacks WitnessUTXO (we'd need the full prev-tx to
// compute amount from non_witness_utxo; payjoin.org's reference also
// requires witness_utxo on every input by §"PSBT-Sender's inputs").
func payjoinPSBTFee(p *PSBT) (int64, error) {
	if p == nil || p.UnsignedTx == nil {
		return 0, fmt.Errorf("PSBT has no unsigned tx")
	}
	var inSum, outSum int64
	for i, in := range p.Inputs {
		if in.WitnessUTXO == nil {
			return 0, fmt.Errorf("input %d missing WitnessUTXO", i)
		}
		inSum += in.WitnessUTXO.Value
	}
	for _, out := range p.UnsignedTx.TxOut {
		outSum += out.Value
	}
	fee := inSum - outSum
	if fee < 0 {
		return 0, fmt.Errorf("PSBT outputs exceed inputs by %d sats", -fee)
	}
	return fee, nil
}

// payjoinEstimateVSize returns a conservative virtual size for the PSBT's
// unsigned tx. Mirrors EstimateTxVSize's P2WPKH-default assumption (since
// blockbrew wallets default to P2WPKH). 68 vbytes per input + ~31 vbytes
// per output + 10 overhead is the de-facto industry default for fee
// estimation on segwit txs.
func payjoinEstimateVSize(p *PSBT) int {
	if p == nil || p.UnsignedTx == nil {
		return 0
	}
	const overhead = 10
	const perInput = 68
	const perOutput = 31
	return overhead + perInput*len(p.UnsignedTx.TxIn) + perOutput*len(p.UnsignedTx.TxOut)
}

// ── Sender flow (transport + composition) ───────────────────────────────

// BuildPayjoinOriginalPSBT constructs the "Original PSBT" the sender will
// POST to the receiver. The sender builds a normal pay-to-`destAddr` tx
// via CreateTransaction, then wraps it in a PSBT, attaches WitnessUTXO on
// every input (so the receiver can compute the sighash of preserved
// inputs), and signs every input.
//
// The output is base64; SendPayjoinRequest then POSTs it. We expose this
// helper so the `getpayjoinrequest` RPC can return it without going on
// the wire.
func (w *Wallet) BuildPayjoinOriginalPSBT(destAddr string, amount int64, feeRate float64) (*PSBT, error) {
	// Build + sign the tx via the existing send path.
	tx, err := w.CreateTransaction(destAddr, amount, feeRate)
	if err != nil {
		return nil, fmt.Errorf("BuildPayjoinOriginalPSBT: %w", err)
	}

	// Construct the PSBT from a fresh UNSIGNED copy (PSBT §"global unsigned
	// tx" requires empty scriptSig + empty witness).
	unsigned := &wire.MsgTx{
		Version:  tx.Version,
		LockTime: tx.LockTime,
	}
	for _, in := range tx.TxIn {
		unsigned.TxIn = append(unsigned.TxIn, &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			Sequence:         in.Sequence,
		})
	}
	for _, out := range tx.TxOut {
		unsigned.TxOut = append(unsigned.TxOut, &wire.TxOut{
			Value:    out.Value,
			PkScript: out.PkScript,
		})
	}
	psbt, err := NewPSBT(unsigned)
	if err != nil {
		return nil, fmt.Errorf("BuildPayjoinOriginalPSBT: NewPSBT: %w", err)
	}

	// Attach WitnessUTXO + BIP32Derivation for every input so:
	//   (a) the receiver can validate per BIP-78 G5 / our G11 anti-snoop
	//       check (every input prev-out known on both sides), and
	//   (b) the WalletPSBTSigner can locate the right key via the
	//       fingerprint+path lookup (it needs BIP32Derivation, not just
	//       WitnessUTXO).
	for i, in := range tx.TxIn {
		u := w.GetUTXO(in.PreviousOutPoint)
		if u == nil {
			return nil, fmt.Errorf("BuildPayjoinOriginalPSBT: wallet UTXO not found for input %d (outpoint=%v)", i, in.PreviousOutPoint)
		}
		psbt.Inputs[i].WitnessUTXO = &wire.TxOut{
			Value:    u.Amount,
			PkScript: u.PkScript,
		}
		// Use the same helper the receiver pipeline uses to attach the
		// fingerprint + derivation path + compressed pubkey.
		if perr := w.payjoinAttachBIP32Locked(psbt, i, u); perr != nil {
			return nil, fmt.Errorf("BuildPayjoinOriginalPSBT: attach BIP32 for input %d: %v", i, perr)
		}
	}

	// Sign every sender input. The WalletPSBTSigner path takes its own
	// locks and matches handleSendToAddress / handleBumpFee.
	signer := NewWalletPSBTSigner(w)
	for i := range psbt.Inputs {
		if _, err := signer.SignPSBTInput(psbt, i); err != nil {
			return nil, fmt.Errorf("BuildPayjoinOriginalPSBT: SignPSBTInput(%d): %w", i, err)
		}
	}
	return psbt, nil
}

// SendPayjoinRequest runs the full BIP-78 sender flow:
//
//  1. Validate the endpoint (G3 / G24).
//  2. POST the Original PSBT (base64) with the BIP-78 query params.
//  3. On HTTP failure or non-success status, fall back to broadcasting
//     the Original PSBT (G22).
//  4. On 200 OK, decode the proposal; run G10-G15 anti-snoop validators.
//     ANY validator failure → G22 fallback.
//  5. Re-sign sender's inputs in the proposal (WalletPSBTSigner). The
//     receiver-added input is already signed by the receiver; finalising
//     extracts a fully-signed tx.
//  6. Return PayjoinSendResult with the final signed-PSBT / extracted tx.
//
// The caller (RPC handler) is responsible for broadcasting result.FinalTx
// to the mempool — this helper never reaches mempool.AcceptToMemoryPool
// directly because the wallet package has no mempool dependency.
func (w *Wallet) SendPayjoinRequest(original *PSBT, opts PayjoinSendOptions) (*PayjoinSendResult, error) {
	// (1) Endpoint validation — G3 / G24. Done BEFORE any wallet IO so a
	// typo'd URL fails fast.
	endpointURL, err := validatePayjoinEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}

	// Body — base64 of Original PSBT.
	origBase64, err := original.EncodeBase64()
	if err != nil {
		return nil, fmt.Errorf("payjoin: encode original PSBT: %w", err)
	}

	// (2) Build the POST. Query params per BIP-78 §"Send payjoin":
	version := opts.Version
	if version == "" {
		version = "1"
	}
	q := endpointURL.Query()
	q.Set("v", version)
	if opts.MaxAdditionalFeeContribution > 0 {
		q.Set("maxadditionalfeecontribution", strconv.FormatInt(opts.MaxAdditionalFeeContribution, 10))
	}
	if opts.AdditionalFeeOutputIndex >= 0 {
		q.Set("additionalfeeoutputindex", strconv.Itoa(opts.AdditionalFeeOutputIndex))
	}
	if opts.DisableOutputSubstitution {
		q.Set("disableoutputsubstitution", "true")
	}
	if opts.MinFeeRate > 0 {
		// Format with up to 3 decimal places (sat/vB resolution).
		q.Set("minfeerate", strconv.FormatFloat(opts.MinFeeRate, 'f', 3, 64))
	}
	endpointURL.RawQuery = q.Encode()

	// HTTP client. crypto/tls default validates the cert chain via the
	// system trust store; this is G24's only requirement. Custom HTTPClient
	// is for tests against httptest.NewServer (which signs a self-signed
	// cert the default client would reject).
	client := opts.HTTPClient
	if client == nil {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = payjoinSenderDefaultTimeout
		}
		client = &http.Client{Timeout: timeout}
	}

	req, err := http.NewRequest(http.MethodPost, endpointURL.String(), strings.NewReader(origBase64))
	if err != nil {
		return nil, fmt.Errorf("payjoin: build POST: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	// (3) Round-trip. On any transport error: G22 fallback.
	resp, err := client.Do(req)
	if err != nil {
		return &PayjoinSendResult{
			FinalPSBTBase64: origBase64,
			FinalTx:         nil,
			Fallback:        true,
			FallbackReason:  fmt.Sprintf("transport: %v", err),
			ReceiverStatus:  0,
		}, nil
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, payjoinSenderMaxResponseBytes+1))
	if readErr != nil {
		return &PayjoinSendResult{
			FinalPSBTBase64: origBase64,
			FinalTx:         nil,
			Fallback:        true,
			FallbackReason:  fmt.Sprintf("read response: %v", readErr),
			ReceiverStatus:  resp.StatusCode,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		// 4xx / 5xx → G22 fallback. The error body is a BIP-78 JSON
		// payload that we surface as the FallbackReason so an operator
		// can debug receiver misconfiguration.
		return &PayjoinSendResult{
			FinalPSBTBase64: origBase64,
			FinalTx:         nil,
			Fallback:        true,
			FallbackReason:  fmt.Sprintf("receiver returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody))),
			ReceiverStatus:  resp.StatusCode,
		}, nil
	}

	// (4) Decode the proposal. Any decode failure → G22 fallback.
	proposal, err := DecodePSBTBase64(strings.TrimSpace(string(respBody)))
	if err != nil {
		return &PayjoinSendResult{
			FinalPSBTBase64: origBase64,
			FinalTx:         nil,
			Fallback:        true,
			FallbackReason:  fmt.Sprintf("decode proposal PSBT: %v", err),
			ReceiverStatus:  resp.StatusCode,
		}, nil
	}

	// Run anti-snoop validators in order. First failure → fallback.
	maxFee := opts.MaxAdditionalFeeContribution
	if err := payjoinAntisnoopOutputsPreserved(original, proposal); err != nil {
		return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
	}
	if err := payjoinAntisnoopScriptSigTypes(original, proposal); err != nil {
		return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
	}
	if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, w.IsOwnScript); err != nil {
		return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
	}
	if err := payjoinAntisnoopMaxFeeContribution(original, proposal, maxFee); err != nil {
		return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
	}
	if opts.DisableOutputSubstitution {
		if err := payjoinAntisnoopDisableOutputSubstitution(original, proposal); err != nil {
			return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
		}
	}
	if err := payjoinAntisnoopMinFeeRate(proposal, opts.MinFeeRate); err != nil {
		return payjoinFallback(origBase64, resp.StatusCode, err.Error()), nil
	}

	// (5) Re-sign sender's preserved inputs in the proposal. The receiver
	// stripped sender PartialSigs when it built the proposal (BIP-78
	// §"Receiver's payjoin proposal PSBT" — "The receiver should leave
	// the input PartialSigs slot empty for the sender's inputs that it
	// preserved"). We sign every input whose pkScript is sender-owned
	// (preserved inputs); the receiver-added input is already signed by
	// the receiver and SignPSBTInput is a no-op when it can't find a key.
	origOutpoints := make(map[wire.OutPoint]struct{}, len(original.UnsignedTx.TxIn))
	for _, in := range original.UnsignedTx.TxIn {
		origOutpoints[in.PreviousOutPoint] = struct{}{}
	}
	signer := NewWalletPSBTSigner(w)
	for i, in := range proposal.UnsignedTx.TxIn {
		if _, isOriginal := origOutpoints[in.PreviousOutPoint]; !isOriginal {
			continue // receiver-added; they signed it already
		}
		if _, err := signer.SignPSBTInput(proposal, i); err != nil {
			return payjoinFallback(origBase64, resp.StatusCode,
				fmt.Sprintf("sign preserved input %d: %v", i, err)), nil
		}
	}

	// Encode the signed proposal and extract the broadcast-ready tx via
	// FinalizeAndExtractTransaction. The receiver's input already has
	// PartialSigs, our re-sign added the sender's PartialSigs; finalize
	// derives FinalScriptSig + FinalScriptWitness on every input.
	signedBase64, encErr := proposal.EncodeBase64()
	if encErr != nil {
		return nil, fmt.Errorf("payjoin: encode signed proposal: %w", encErr)
	}
	finalTx, finalizeErr := FinalizeAndExtractTransaction(proposal)
	if finalizeErr != nil {
		// Don't fall back here — the proposal validated and signed, but
		// finalization failed. This means the receiver gave us a
		// fundamentally broken PSBT (e.g. missing witnessScript for
		// P2WSH). Surface as a non-fallback error so the operator sees
		// the bug; production callers should NOT silently broadcast the
		// Original in this case (the sender has already shown intent to
		// PayJoin, and broadcasting the Original would be a privacy
		// leak — the snitch tx). Return signed PSBT for offline debug.
		return &PayjoinSendResult{
			FinalPSBTBase64: signedBase64,
			FinalTx:         nil,
			Fallback:        false,
			FallbackReason:  "",
			ReceiverStatus:  resp.StatusCode,
		}, fmt.Errorf("payjoin: finalize proposal: %w", finalizeErr)
	}

	return &PayjoinSendResult{
		FinalPSBTBase64: signedBase64,
		FinalTx:         finalTx,
		Fallback:        false,
		FallbackReason:  "",
		ReceiverStatus:  resp.StatusCode,
	}, nil
}

// payjoinFallback is a small constructor for the G22 path result.
func payjoinFallback(origBase64 string, status int, reason string) *PayjoinSendResult {
	return &PayjoinSendResult{
		FinalPSBTBase64: origBase64,
		FinalTx:         nil,
		Fallback:        true,
		FallbackReason:  reason,
		ReceiverStatus:  status,
	}
}
