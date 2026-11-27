// BIP-78 sender output-value checks.
//
// BIP-78 §"Sender's payjoin proposal checklist": for every output of the
// Original PSBT,
//   - the fee output (additionalfeeoutputindex) may lose at most
//     maxadditionalfeecontribution, and that loss may not exceed the
//     proposal's fee increase (it must go to fee, not to the receiver);
//   - the payment output, when output substitution is allowed, is not
//     checked;
//   - every other output must not decrease in value.
//
// Before this file the sender compared output pkScripts (G10/G14) and the
// total fee delta (G13) only, so a receiver could move value from the
// sender's change output into its own output at an unchanged fee and the
// sender would sign and broadcast it.
//
// Every test here drives the public SendPayjoinRequest flow against an
// httptest TLS receiver, so the file builds on the commit before the fix
// and the attack cases fail there on their assertions.

package wallet

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// payjoinValuesFixture holds a sender wallet, a receiver wallet, the
// Original PSBT and the indices of its payment and change outputs.
type payjoinValuesFixture struct {
	sender    *Wallet
	receiver  *Wallet
	original  *PSBT
	payIdx    int
	changeIdx int
}

func newPayjoinValuesFixture(t *testing.T) *payjoinValuesFixture {
	t.Helper()
	rxw, recvAddr := payjoinReceiverWallet(t)
	sxw := payjoinSenderWallet(t)
	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	f := &payjoinValuesFixture{sender: sxw, receiver: rxw, original: original, payIdx: -1, changeIdx: -1}
	for i, out := range original.UnsignedTx.TxOut {
		if sxw.IsOwnScript(out.PkScript) {
			f.changeIdx = i
		} else {
			f.payIdx = i
		}
	}
	if len(original.UnsignedTx.TxOut) != 2 || f.payIdx < 0 || f.changeIdx < 0 {
		t.Fatalf("fixture: want 1 payment + 1 change output, got %d outputs (pay=%d change=%d)",
			len(original.UnsignedTx.TxOut), f.payIdx, f.changeIdx)
	}
	return f
}

// outputIndexByScript returns the proposal index of the output carrying
// script, or -1.
func outputIndexByScript(p *PSBT, script []byte) int {
	for i, out := range p.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, script) {
			return i
		}
	}
	return -1
}

// payjoinTamperingReceiver runs the real blockbrew receiver pipeline
// (honouring additionalfeeoutputindex / maxadditionalfeecontribution from
// the query string) and then hands the proposal to tamper before it goes
// back to the sender. tamper == nil returns the honest proposal.
func payjoinTamperingReceiver(t *testing.T, rxw *Wallet, tamper func(orig, prop *PSBT)) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, PayjoinMaxBodyBytes+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		req := &PayjoinRequest{
			OriginalPSBTBase64:       strings.TrimSpace(string(body)),
			Version:                  q.Get("v"),
			AdditionalFeeOutputIndex: -1,
		}
		if s := q.Get("additionalfeeoutputindex"); s != "" {
			if v, perr := strconv.Atoi(s); perr == nil {
				req.AdditionalFeeOutputIndex = v
			}
		}
		if s := q.Get("maxadditionalfeecontribution"); s != "" {
			if v, perr := strconv.ParseInt(s, 10, 64); perr == nil {
				req.MaxAdditionalFeeContribution = v
			}
		}
		resp, perr := rxw.ProcessPayjoinRequest(req)
		if perr != nil {
			http.Error(w, perr.Message, http.StatusBadRequest)
			return
		}
		if tamper != nil {
			orig, derr := DecodePSBTBase64(req.OriginalPSBTBase64)
			if derr != nil {
				http.Error(w, "decode original", http.StatusInternalServerError)
				return
			}
			prop, derr := DecodePSBTBase64(resp)
			if derr != nil {
				http.Error(w, "decode proposal", http.StatusInternalServerError)
				return
			}
			tamper(orig, prop)
			if resp, err = prop.EncodeBase64(); err != nil {
				http.Error(w, "encode proposal", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp)
	})
}

// runPayjoinValues runs one sender attempt against a tampering receiver.
func runPayjoinValues(t *testing.T, f *payjoinValuesFixture, opts PayjoinSendOptions, tamper func(orig, prop *PSBT)) *PayjoinSendResult {
	t.Helper()
	srv := httptest.NewTLSServer(payjoinTamperingReceiver(t, f.receiver, tamper))
	t.Cleanup(srv.Close)
	opts.Endpoint = srv.URL + "/payjoin"
	opts.Version = "1"
	opts.HTTPClient = srv.Client()
	res, err := f.sender.SendPayjoinRequest(f.original, opts)
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	return res
}

func requirePayjoinRejected(t *testing.T, res *PayjoinSendResult) {
	t.Helper()
	if !res.Fallback || res.FinalTx != nil {
		t.Fatalf("proposal accepted (Fallback=%v FinalTx!=nil=%v); want fallback to the Original",
			res.Fallback, res.FinalTx != nil)
	}
	if !strings.Contains(res.FallbackReason, "output-values:") {
		t.Errorf("FallbackReason=%q, want the output-values check to be the one that refused", res.FallbackReason)
	}
}

func requirePayjoinAccepted(t *testing.T, res *PayjoinSendResult) {
	t.Helper()
	if res.Fallback || res.FinalTx == nil {
		t.Fatalf("proposal rejected (Fallback=%v reason=%q); want accepted", res.Fallback, res.FallbackReason)
	}
}

// TestPayjoinSenderRejectsChangeDecrease is the reported theft: the
// receiver lowers the sender's change by 10,000 sat and raises its own
// output by 10,000 sat. The fee is unchanged, so G13 passes; no fee output
// was designated, so the change may not lose anything.
func TestPayjoinSenderRejectsChangeDecrease(t *testing.T) {
	f := newPayjoinValuesFixture(t)
	changeScript := f.original.UnsignedTx.TxOut[f.changeIdx].PkScript
	payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
	res := runPayjoinValues(t, f, PayjoinSendOptions{
		MaxAdditionalFeeContribution: 10_000,
		AdditionalFeeOutputIndex:     -1,
	}, func(_, prop *PSBT) {
		prop.UnsignedTx.TxOut[outputIndexByScript(prop, changeScript)].Value -= 10_000
		prop.UnsignedTx.TxOut[outputIndexByScript(prop, payScript)].Value += 10_000
	})
	requirePayjoinRejected(t, res)
}

// TestPayjoinSenderOutputValueChecks covers the rest of the BIP-78
// per-output rules, attacks and honest controls.
func TestPayjoinSenderOutputValueChecks(t *testing.T) {
	type tc struct {
		name   string
		accept bool
		opts   func(f *payjoinValuesFixture) PayjoinSendOptions
		tamper func(f *payjoinValuesFixture) func(orig, prop *PSBT)
	}
	noFeeOutput := func(f *payjoinValuesFixture) PayjoinSendOptions {
		return PayjoinSendOptions{MaxAdditionalFeeContribution: 10_000, AdditionalFeeOutputIndex: -1}
	}
	changeIsFeeOutput := func(maxAdd int64) func(f *payjoinValuesFixture) PayjoinSendOptions {
		return func(f *payjoinValuesFixture) PayjoinSendOptions {
			return PayjoinSendOptions{MaxAdditionalFeeContribution: maxAdd, AdditionalFeeOutputIndex: f.changeIdx}
		}
	}
	// move shifts value from the change output (fromChange sat) to the
	// payment output (toPay sat). fromChange-toPay goes to fee.
	move := func(fromChange, toPay int64) func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
		return func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
			changeScript := f.original.UnsignedTx.TxOut[f.changeIdx].PkScript
			payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
			return func(_, prop *PSBT) {
				prop.UnsignedTx.TxOut[outputIndexByScript(prop, changeScript)].Value -= fromChange
				prop.UnsignedTx.TxOut[outputIndexByScript(prop, payScript)].Value += toPay
			}
		}
	}
	cases := []tc{
		{
			// Fee output designated with a 10k budget, but the 10k it
			// loses goes to the receiver, not to fee. BIP-78: the actual
			// contribution must not exceed the fee increase.
			name:   "fee output contribution paid to receiver, not fee",
			accept: false,
			opts:   changeIsFeeOutput(10_000),
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				// Honest receiver already took 10k as fee; give that fee to
				// the payment output instead (fee back to the original's).
				payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
				return func(_, prop *PSBT) {
					prop.UnsignedTx.TxOut[outputIndexByScript(prop, payScript)].Value += 10_000
				}
			},
		},
		{
			// Fee output loses 6,000 with a 5,000 budget; only 5,000 of
			// it reaches fee, so G13's total-delta check passes.
			name:   "fee output loses more than maxadditionalfeecontribution",
			accept: false,
			opts:   changeIsFeeOutput(5_000),
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				changeScript := f.original.UnsignedTx.TxOut[f.changeIdx].PkScript
				payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
				return func(orig, prop *PSBT) {
					// Reset to the honest 5k bump (receiver already applied
					// it), then take 1k more into the payment output.
					prop.UnsignedTx.TxOut[outputIndexByScript(prop, changeScript)].Value -= 1_000
					prop.UnsignedTx.TxOut[outputIndexByScript(prop, payScript)].Value += 1_000
				}
			},
		},
		{
			// G10's lenient form allowed any ONE original script to vanish;
			// dropping the change and paying it to the receiver passed.
			name:   "change output removed, value paid to receiver",
			accept: false,
			opts:   noFeeOutput,
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				changeScript := f.original.UnsignedTx.TxOut[f.changeIdx].PkScript
				payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
				return func(_, prop *PSBT) {
					ci := outputIndexByScript(prop, changeScript)
					v := prop.UnsignedTx.TxOut[ci].Value
					prop.UnsignedTx.TxOut[outputIndexByScript(prop, payScript)].Value += v
					prop.UnsignedTx.TxOut = append(prop.UnsignedTx.TxOut[:ci], prop.UnsignedTx.TxOut[ci+1:]...)
					prop.Outputs = append(prop.Outputs[:ci], prop.Outputs[ci+1:]...)
				}
			},
		},
		{
			// pjos=1: the payment output is an ordinary protected output
			// and may not decrease either.
			name:   "pjos=1 payment output decreased",
			accept: false,
			opts: func(f *payjoinValuesFixture) PayjoinSendOptions {
				o := noFeeOutput(f)
				o.DisableOutputSubstitution = true
				return o
			},
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				payScript := f.original.UnsignedTx.TxOut[f.payIdx].PkScript
				changeScript := f.original.UnsignedTx.TxOut[f.changeIdx].PkScript
				return func(orig, prop *PSBT) {
					// Lower the payment output 1,000 below its ORIGINAL
					// value and send the receiver's added input to the
					// change, so the fee rises by only 1,000 and G13 (cap
					// 10,000) does not refuse it first.
					pi := outputIndexByScript(prop, payScript)
					ci := outputIndexByScript(prop, changeScript)
					origPay := f.original.UnsignedTx.TxOut[f.payIdx].Value
					grown := prop.UnsignedTx.TxOut[pi].Value - origPay
					prop.UnsignedTx.TxOut[pi].Value = origPay - 1_000
					prop.UnsignedTx.TxOut[ci].Value += grown
				}
			},
		},
		// ── honest controls: must be accepted before and after the fix ──
		{
			name:   "honest proposal, no fee output",
			accept: true,
			opts:   noFeeOutput,
		},
		{
			name:   "honest proposal, change is fee output (10k budget used as fee)",
			accept: true,
			opts:   changeIsFeeOutput(10_000),
		},
		{
			// A receiver may give the sender value (change rises).
			name:   "change increased out of the payment output",
			accept: true,
			opts:   noFeeOutput,
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				return move(-1_000, -1_000)(f)
			},
		},
		{
			name:   "outputs reordered",
			accept: true,
			opts:   noFeeOutput,
			tamper: func(f *payjoinValuesFixture) func(orig, prop *PSBT) {
				return func(_, prop *PSBT) {
					outs := prop.UnsignedTx.TxOut
					outs[0], outs[1] = outs[1], outs[0]
					prop.Outputs[0], prop.Outputs[1] = prop.Outputs[1], prop.Outputs[0]
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPayjoinValuesFixture(t)
			var tamper func(orig, prop *PSBT)
			if c.tamper != nil {
				tamper = c.tamper(f)
			}
			res := runPayjoinValues(t, f, c.opts(f), tamper)
			if c.accept {
				requirePayjoinAccepted(t, res)
			} else {
				requirePayjoinRejected(t, res)
			}
		})
	}
}
