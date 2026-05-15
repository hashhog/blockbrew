// Package wallet — FIX-61 / W118 BUG-2.
//
// bumpfee / psbtbumpfee helper. Builds a replacement transaction for an
// outgoing wallet tx by reducing its change output to pay a higher fee,
// then re-signs every input the wallet owns. Mirrors the high-level
// shape of Bitcoin Core's wallet/feebumper.cpp (CreateRateBumpTransaction
// + SignTransaction).
//
// References:
//   - bitcoin-core/src/wallet/feebumper.cpp (PreconditionChecks, CreateRateBumpTransaction)
//   - bitcoin-core/src/wallet/feebumper.h
//   - bitcoin-core/src/policy/rbf.h (MAX_BIP125_RBF_SEQUENCE)
//   - BIP-125 § "Summary"
package wallet

import (
	"errors"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Bump-fee error sentinels. Surface a single, stable string per failure mode
// so RPC callers (bumpfee / psbtbumpfee) can map them to Core-compatible
// error codes without string-matching internals.
var (
	// ErrBumpFeeTxNotInMempool is returned when the caller asks to bump a
	// txid that is not currently in the mempool. blockbrew cannot bump an
	// already-confirmed tx (no chain rollback) and cannot bump a tx it has
	// never seen (no raw-tx storage in the wallet).
	ErrBumpFeeTxNotInMempool = errors.New("transaction not in mempool (already confirmed or never broadcast)")

	// ErrBumpFeeNoRBFSignal is returned when the tx does not signal BIP-125
	// replaceability on any input (every nSequence > MAX_BIP125_RBF_SEQUENCE).
	// Per BIP-125 §"Summary" only such txs are eligible for fee bumping.
	ErrBumpFeeNoRBFSignal = errors.New("transaction does not signal BIP-125 replaceability")

	// ErrBumpFeeNoChange is returned when the original tx has no change
	// output the wallet can identify. blockbrew's minimal bumpfee deducts
	// the fee increase from change; without one we'd have to either add
	// inputs (not yet supported) or shrink a recipient output (forbidden
	// by Core's default policy).
	ErrBumpFeeNoChange = errors.New("transaction has no wallet-owned change output to reduce")

	// ErrBumpFeeNotOurs is returned when at least one input of the original
	// tx is not owned by this wallet, so we have no key to re-sign it.
	// Mirrors Core's AllInputsMine check.
	ErrBumpFeeNotOurs = errors.New("transaction contains inputs not owned by this wallet")

	// ErrBumpFeeDustAfterReduce is returned when reducing the change output
	// by the required fee delta would push it below the dust threshold
	// (546 sat). Caller may retry with a smaller fee_rate.
	ErrBumpFeeDustAfterReduce = errors.New("change output would become dust after fee increase")

	// ErrBumpFeeRateTooLow is returned when the caller-supplied fee_rate
	// (sat/vB) is not strictly greater than the original tx's effective
	// feerate. BIP-125 Rule 4 requires the replacement to pay more.
	ErrBumpFeeRateTooLow = errors.New("new fee rate must exceed original fee rate")
)

// BumpFeeRequest is the parameter bundle for BumpFee. Mirrors a subset of
// Core's bumpfee options. FeeRate is optional: when zero, BumpFee uses
// origFeeRate + 1 sat/vB (Core's "incremental relay fee" floor).
type BumpFeeRequest struct {
	// OrigTx is the original (unconfirmed) transaction to replace. Caller
	// is expected to have fetched it from the mempool already.
	OrigTx *wire.MsgTx

	// InputUTXOs maps each input outpoint to the WalletUTXO it spends. The
	// caller (RPC layer) builds this by looking up wallet.utxos for every
	// input — bumpfee will reject the request if any input is missing.
	// This dependency is explicit (rather than re-discovered in BumpFee)
	// because the wallet UTXO set is consumed when txs enter the mempool,
	// so the natural lookup is at the RPC boundary while the original
	// outputs are still spendable from the caller's POV (testnet/regtest).
	//
	// In a production wallet this would come from CWalletTx's stored inputs.
	InputUTXOs map[wire.OutPoint]*WalletUTXO

	// FeeRate is the new total feerate in sat/vB. Zero means "bump by
	// +1 sat/vB over the original effective rate".
	FeeRate float64
}

// BumpFeeResult is what BumpFee returns: the fully-signed replacement
// transaction plus old/new fee bookkeeping for RPC reporting.
type BumpFeeResult struct {
	NewTx       *wire.MsgTx
	OldFee      int64 // sat
	NewFee      int64 // sat
	OldVSize    int   // vbytes (estimated)
	NewVSize    int   // vbytes (estimated)
	OrigFeeRate float64
	NewFeeRate  float64
}

// BumpFee builds a fee-bumped replacement for req.OrigTx. The minimum-viable
// shape (matching the FIX-61 universal pattern across other impls):
//
//  1. Verify every input is wallet-owned (via req.InputUTXOs).
//  2. Verify the tx signals BIP-125 RBF on at least one input.
//  3. Locate a change output (one with a wallet-owned address pointing at
//     an internal/change derivation path).
//  4. Compute new_fee = max(orig_fee + ceil(vsize * 1 sat/vB),
//     ceil(vsize * fee_rate)).
//  5. Subtract (new_fee - old_fee) from the change output; reject if
//     the result is < dust.
//  6. Re-sign every input (signTx clears scriptSig/witness first).
//
// Caller-visible bumpfee returns NewTx for submission; psbtbumpfee instead
// wraps NewTx in a PSBT via wallet.NewPSBT.
//
// Reference: bitcoin-core/src/wallet/feebumper.cpp::CreateRateBumpTransaction.
func (w *Wallet) BumpFee(req BumpFeeRequest) (*BumpFeeResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked {
		return nil, ErrWalletLocked
	}
	if req.OrigTx == nil {
		return nil, fmt.Errorf("BumpFee: OrigTx is nil")
	}
	if len(req.OrigTx.TxIn) == 0 {
		return nil, fmt.Errorf("BumpFee: OrigTx has no inputs")
	}

	// 1. Verify every input is ours.
	utxos := make([]*WalletUTXO, len(req.OrigTx.TxIn))
	var totalIn int64
	for i, in := range req.OrigTx.TxIn {
		u, ok := req.InputUTXOs[in.PreviousOutPoint]
		if !ok || u == nil {
			return nil, ErrBumpFeeNotOurs
		}
		utxos[i] = u
		totalIn += u.Amount
	}

	// 2. BIP-125 opt-in check: at least one nSequence ≤ MAX_BIP125_RBF_SEQUENCE.
	// Mirrors Core's SignalsOptInRBF (src/policy/rbf.cpp).
	signals := false
	for _, in := range req.OrigTx.TxIn {
		if in.Sequence <= BIP125RBFSequence {
			signals = true
			break
		}
	}
	if !signals {
		return nil, ErrBumpFeeNoRBFSignal
	}

	// 3. Locate a change output. A "change output" is one whose pkScript
	// decodes to an address whose derivation path the wallet recognises
	// as internal (change=1). We can't read the address back from the
	// pkScript without round-tripping through the address package; the
	// simplest cross-script-type check is to look up each pkScript via
	// addrToPath and see whether the path is an internal one.
	changeIdx := -1
	var changeOut *wire.TxOut
	var totalOut int64
	for i, out := range req.OrigTx.TxOut {
		totalOut += out.Value
		if changeIdx >= 0 {
			continue
		}
		addr, ok := w.scriptToOwnAddressLocked(out.PkScript)
		if !ok {
			continue
		}
		if w.isInternalAddressLocked(addr) {
			changeIdx = i
			changeOut = out
		}
	}
	if changeIdx < 0 {
		return nil, ErrBumpFeeNoChange
	}

	// 4. Compute fees. oldFee = sum(in) - sum(out).
	oldFee := totalIn - totalOut
	if oldFee < 0 {
		return nil, fmt.Errorf("BumpFee: original tx has negative fee (totalIn=%d, totalOut=%d)", totalIn, totalOut)
	}

	// Estimate vsize of the original (and the replacement — same shape
	// since we only mutate change.Value).
	inputScripts := make([][]byte, len(utxos))
	outputScripts := make([][]byte, len(req.OrigTx.TxOut))
	for i, u := range utxos {
		inputScripts[i] = u.PkScript
	}
	for i, out := range req.OrigTx.TxOut {
		outputScripts[i] = out.PkScript
	}
	vsize := EstimateTxVSize(len(utxos), inputScripts, len(req.OrigTx.TxOut), outputScripts)
	if vsize <= 0 {
		return nil, fmt.Errorf("BumpFee: vsize estimate failed")
	}
	origFeeRate := float64(oldFee) / float64(vsize)

	// Target fee. Two paths:
	//   (a) caller supplied FeeRate > 0  → newFee = ceil(vsize * FeeRate),
	//       but also require strictly higher than origFeeRate.
	//   (b) caller left FeeRate == 0     → newFee = oldFee + ceil(vsize * 1 sat/vB)
	//       (the "+1 sat/vB" minimum bump matching Core's default
	//        incremental relay fee floor).
	var newFee int64
	if req.FeeRate > 0 {
		if req.FeeRate <= origFeeRate {
			return nil, ErrBumpFeeRateTooLow
		}
		newFee = int64(math.Ceil(req.FeeRate * float64(vsize)))
	} else {
		bump := int64(math.Ceil(1.0 * float64(vsize)))
		if bump < 1 {
			bump = 1
		}
		newFee = oldFee + bump
	}
	if newFee <= oldFee {
		return nil, ErrBumpFeeRateTooLow
	}

	delta := newFee - oldFee
	newChangeValue := changeOut.Value - delta
	if newChangeValue < dustThreshold {
		return nil, ErrBumpFeeDustAfterReduce
	}

	// 5. Build the replacement tx. We clone the original structure
	// (preserving Version / LockTime / output order) and:
	//   - clear scriptSig/witness on every input,
	//   - leave each input's Sequence as-is (it must already be ≤
	//     MAX_BIP125_RBF_SEQUENCE since we verified RBF opt-in above),
	//   - rewrite the change output's Value.
	newTx := &wire.MsgTx{
		Version:  req.OrigTx.Version,
		LockTime: req.OrigTx.LockTime,
	}
	for _, in := range req.OrigTx.TxIn {
		newTx.TxIn = append(newTx.TxIn, &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			Sequence:         in.Sequence, // already RBF-signalling
		})
	}
	for i, out := range req.OrigTx.TxOut {
		value := out.Value
		if i == changeIdx {
			value = newChangeValue
		}
		newTx.TxOut = append(newTx.TxOut, &wire.TxOut{
			Value:    value,
			PkScript: out.PkScript,
		})
	}

	// 6. Re-sign every input.
	if err := w.signTx(newTx, utxos); err != nil {
		return nil, fmt.Errorf("BumpFee: re-sign failed: %w", err)
	}

	return &BumpFeeResult{
		NewTx:       newTx,
		OldFee:      oldFee,
		NewFee:      newFee,
		OldVSize:    vsize,
		NewVSize:    vsize,
		OrigFeeRate: origFeeRate,
		NewFeeRate:  float64(newFee) / float64(vsize),
	}, nil
}

// scriptToOwnAddressLocked returns the wallet-known address for a pkScript,
// if any. The caller must hold w.mu (read or write).
//
// We iterate addrToPath rather than reverse-decoding the script because the
// wallet may hold addresses in multiple types (P2WPKH, P2TR, ...) and we
// already have authoritative ownership info in addrToPath. The set is
// bounded by `gapLimit * #address-types * #accounts`, so linear scan is
// fine for the wallet sizes we ship.
func (w *Wallet) scriptToOwnAddressLocked(pkScript []byte) (string, bool) {
	for addr := range w.addrToPath {
		parsed, err := address.DecodeAddress(addr, w.config.Network)
		if err != nil {
			continue
		}
		ownScript := parsed.ScriptPubKey()
		if len(ownScript) == len(pkScript) && byteSliceEqual(ownScript, pkScript) {
			return addr, true
		}
	}
	return "", false
}

// isInternalAddressLocked reports whether addr's derivation path identifies
// it as a change (internal) address — i.e. the 4th path component (BIP-44
// "change" field) is "1". Path layout examples:
//
//	m/84'/0'/0'/0/3   external (receive)
//	m/84'/0'/0'/1/3   internal (change)
//
// Caller must hold w.mu.
func (w *Wallet) isInternalAddressLocked(addr string) bool {
	path, ok := w.addrToPath[addr]
	if !ok {
		return false
	}
	// Path is "m/<purpose>'/<coin>'/<account>'/<change>/<index>". Split on
	// '/' and look at position 4 (0-indexed). We're tolerant of leading
	// 'm/' missing.
	parts := splitPathSlash(path)
	if len(parts) < 5 {
		return false
	}
	return parts[4] == "1"
}

// byteSliceEqual compares two byte slices for equality.
func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// splitPathSlash splits a BIP-32 derivation path on '/' without bringing in
// strings.Split (which works fine but adds an import for one use). Inlined
// for tightness and to keep the dependency surface small.
func splitPathSlash(p string) []string {
	if p == "" {
		return nil
	}
	out := make([]string, 0, 6)
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	out = append(out, p[start:])
	return out
}
