// PayJoin sender tests — round-trip + G10-G15 anti-snoop + G22 fallback.
//
// FIX-66 closures (W119 BUG-1 / BUG-3 / BUG-15 / BUG-16 / BUG-4 sender-half).
//
// The sender flow has three families of assertion:
//
//   TestPayjoinSenderRoundtrip
//     End-to-end: a FIX-65 receiver (real ProcessPayjoinRequest behind
//     an httptest.Server) returns a valid Proposal PSBT; the sender's
//     SendPayjoinRequest passes all six anti-snoop validators, re-signs
//     preserved inputs, and finalises a broadcast-ready tx.
//
//   TestPayjoinSenderAntisnoop{Outputs,ScriptSig,NewInputs,MaxFee,Pjos,MinFeeRate}
//     Each validator independently rejects a hand-crafted malicious
//     proposal; the sender falls back to the Original PSBT (Fallback=true)
//     and the FallbackReason names the failing gate.
//
//   TestPayjoinSenderFallback503
//     Receiver returns HTTP 503; sender falls back (G22) without
//     attempting anti-snoop on the empty body.
//
// We don't exercise the TLS layer here — crypto/tls's default cert
// validation is well-tested by the Go stdlib; FIX-64 has integration tests
// for our server-side TLS termination. The sender's HTTPClient is
// overridden with httptest's client (which trusts httptest's self-signed
// cert) so the validation path executes but cert errors don't drown the
// signal-of-interest (BIP-78 wire compliance).

package wallet

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ── Test fixtures ─────────────────────────────────────────────────────────

// payjoinSenderWallet builds a fully-funded "sender" wallet that owns
// 2 BTC of P2WPKH UTXOs at a single (deterministic) address. The wallet
// has the BIP-39 abandon-12 seed for reproducibility.
//
// The sender's funding UTXO is at outpoint {0xAA, 0}; tests that need
// to inject a fingerprinting attack reuse this outpoint shape so the
// receiver can construct a "sender-owned input" without guessing the
// sender's actual addresses.
func payjoinSenderWallet(t *testing.T) *Wallet {
	t.Helper()
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
		AddressType: AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic(
		// Different from the receiver seed so addresses don't collide
		// across the test wallets (we use the receiver in some tests as
		// a real httptest server). Using "abandon abandon ... art" is
		// the BIP-39 second standard test vector.
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"",
	); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	// Fund the sender at a fresh address so address-derivation pulls a
	// real BIP32 path the signer can derive. We must set KeyPath
	// explicitly on the WalletUTXO — the internal signTx path looks at
	// utxo.KeyPath directly (not addrToPath) and a missing KeyPath
	// would otherwise raise "invalid derivation path".
	fundAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	fundParsed, err := address.DecodeAddress(fundAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	// Mainnet uses coin=0; testnet/regtest use coin=1 per SLIP-44. We
	// derived the address from the wallet (so its path is already
	// stored in addrToPath); pull it via the lookup so we use whatever
	// the wallet uses canonically.
	w.AddUTXO(&WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0xAA}, Index: 0},
		Amount:    200_000_000, // 2 BTC
		PkScript:  fundParsed.ScriptPubKey(),
		Address:   fundAddr,
		KeyPath:   payjoinKeyPathForAddress(t, w, fundAddr),
		Height:    100,
		Confirmed: true,
	})
	return w
}

// payjoinKeyPathForAddress looks up the derivation path the wallet
// associated with `addr` at NewAddress time. Caller is responsible for
// the address actually being owned by the wallet — this is a test
// helper, not production code.
func payjoinKeyPathForAddress(t *testing.T, w *Wallet, addr string) string {
	t.Helper()
	// Use the same exported helper bumpfee_test.go uses; in this package
	// we go through GetAddressInfo if available, else cross-package
	// reflection isn't allowed — we instead synthesize via BIP84 with
	// the wallet's coin type. The wallet's NewAddress for regtest uses
	// the testnet coin (1), external chain (0), index 0 for the first
	// derived address. Subsequent calls increment the index.
	//
	// Simpler: peek into addrToPath under RLock; that's the canonical
	// source of truth that w.signTx ultimately resolves to. We do this
	// via a small reflection-free shim that grabs the map under the
	// wallet's own RLock.
	w.mu.RLock()
	defer w.mu.RUnlock()
	p, ok := w.addrToPath[addr]
	if !ok {
		t.Fatalf("payjoinKeyPathForAddress: addr %q not in addrToPath", addr)
	}
	return p
}

// payjoinReceiverHTTPHandler returns an http.Handler that wraps the
// FIX-65 receiver wallet via its ProcessPayjoinRequest method, mimicking
// the on-wire shape of internal/rpc/payjoin.go without the JSON-RPC
// dependency (this test lives in the wallet package and must not import
// the rpc package — would create a cycle).
func payjoinReceiverHTTPHandler(t *testing.T, rxw *Wallet) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, PayjoinMaxBodyBytes+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		req := &PayjoinRequest{
			OriginalPSBTBase64: strings.TrimSpace(string(body)),
			Version:            r.URL.Query().Get("v"),
		}
		resp, perr := rxw.ProcessPayjoinRequest(req)
		if perr != nil {
			status := http.StatusBadRequest
			switch perr.Code {
			case PayjoinErrVersionUnsupported:
				status = http.StatusUnsupportedMediaType
			case PayjoinErrNotEnoughMoney:
				status = http.StatusUnprocessableEntity
			case PayjoinErrUnavailable:
				status = http.StatusServiceUnavailable
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"errorCode": string(perr.Code),
				"message":   perr.Message,
			})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp)
	})
}

// ── G24 endpoint validation ──────────────────────────────────────────────

// TestPayjoinValidateEndpoint enforces BIP-78 §"Protocol": only https:// or
// http://*.onion. Anything else is rejected before any wallet IO.
func TestPayjoinValidateEndpoint(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		wantOK bool
	}{
		{"https mainstream", "https://merchant.example.com/payjoin", true},
		{"http onion", "http://abc123def456.onion/payjoin", true},
		{"plain http rejected (G24)", "http://merchant.example.com/payjoin", false},
		{"ftp rejected", "ftp://merchant.example.com/payjoin", false},
		{"empty rejected", "", false},
		{"junk rejected", "not a url", false},
		{"https onion accepted too", "https://abc123.onion/payjoin", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validatePayjoinEndpoint(tc.url)
			if (err == nil) != tc.wantOK {
				t.Errorf("validatePayjoinEndpoint(%q) err=%v, want ok=%v", tc.url, err, tc.wantOK)
			}
		})
	}
}

// ── Round-trip ────────────────────────────────────────────────────────────

// TestPayjoinSenderRoundtrip exercises the full sender flow against a real
// FIX-65 receiver in-process. The receiver wallet has its own UTXO and
// receive address; the sender's BuildPayjoinOriginalPSBT pays it; the
// sender's SendPayjoinRequest POSTs to the test server, runs all six
// anti-snoop validators, re-signs preserved inputs, and finalises.
//
// Asserts:
//   - Fallback == false (all gates passed),
//   - ReceiverStatus == 200,
//   - FinalTx is non-nil and broadcast-ready (has all witnesses),
//   - the proposal contained 2 inputs (1 sender + 1 receiver-added).
func TestPayjoinSenderRoundtrip(t *testing.T) {
	rxw, recvAddr := payjoinReceiverWallet(t)
	sxw := payjoinSenderWallet(t)

	// Spin up an httptest server using the FIX-65 receiver pipeline.
	srv := httptest.NewServer(payjoinReceiverHTTPHandler(t, rxw))
	defer srv.Close()

	// Build the sender's Original PSBT.
	const sendAmount = int64(50_000_000) // 0.5 BTC
	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, sendAmount, 5.0 /* sat/vB */)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	if len(original.Inputs) == 0 {
		t.Fatal("original PSBT has 0 inputs")
	}
	if original.Inputs[0].WitnessUTXO == nil {
		t.Fatal("original input 0 missing WitnessUTXO")
	}

	// Run sender flow. We override the URL scheme check by pointing at
	// httptest's plain-http URL via .onion-suffix trick: not feasible,
	// since httptest only does http://127.0.0.1. Use httptest's TLS
	// variant so the "must be https" gate passes; the test client
	// trusts the self-signed cert.
	tlsSrv := httptest.NewTLSServer(payjoinReceiverHTTPHandler(t, rxw))
	defer tlsSrv.Close()

	opts := PayjoinSendOptions{
		Endpoint:                     tlsSrv.URL + "/payjoin",
		Version:                      "1",
		MaxAdditionalFeeContribution: 10_000, // 10k sats — receiver MUST stay below
		AdditionalFeeOutputIndex:     -1,
		HTTPClient:                   tlsSrv.Client(), // trusts httptest's self-signed cert
	}
	res, err := sxw.SendPayjoinRequest(original, opts)
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	if res.Fallback {
		t.Fatalf("Fallback=true; expected anti-snoop to pass. reason=%q", res.FallbackReason)
	}
	if res.ReceiverStatus != http.StatusOK {
		t.Errorf("ReceiverStatus=%d, want 200", res.ReceiverStatus)
	}
	if res.FinalTx == nil {
		t.Fatal("FinalTx is nil; expected broadcast-ready tx")
	}
	// The proposal should have one MORE input than the original.
	proposal, err := DecodePSBTBase64(res.FinalPSBTBase64)
	if err != nil {
		t.Fatalf("decode FinalPSBTBase64: %v", err)
	}
	if got, want := len(proposal.UnsignedTx.TxIn), len(original.UnsignedTx.TxIn)+1; got != want {
		t.Errorf("proposal inputs = %d, want %d", got, want)
	}
}

// ── Anti-snoop validator unit tests ──────────────────────────────────────

// buildSyntheticPSBT constructs a deterministic PSBT for validator tests:
//   - 1 sender input at outpoint {0xCC, 0}, value 200_000_000,
//   - 2 outputs (receiverScript, changeScript) summing 199_999_000.
// Returns the PSBT so tests can mutate it before feeding to validators.
func buildSyntheticPSBT(t *testing.T) *PSBT {
	t.Helper()
	senderPk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xAB}, 20)...)
	recvPk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x11}, 20)...)
	changePk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xEE}, 20)...)

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xCC}, Index: 0},
		Sequence:         BIP125RBFSequence,
	})
	tx.TxOut = append(tx.TxOut,
		&wire.TxOut{Value: 50_000_000, PkScript: recvPk},
		&wire.TxOut{Value: 149_999_000, PkScript: changePk},
	)
	p, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	p.Inputs[0].WitnessUTXO = &wire.TxOut{Value: 200_000_000, PkScript: senderPk}
	return p
}

// cloneAndAddReceiverInput returns a proposal-shape PSBT with one new
// receiver-added input + the receiver output grown by the input value.
// Mirrors what FIX-65's ProcessPayjoinRequest constructs.
func cloneAndAddReceiverInput(t *testing.T, original *PSBT, receiverScript []byte, receiverAmount int64) *PSBT {
	t.Helper()
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
	proposalTx.TxIn = append(proposalTx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xBB}, Index: 0},
		Sequence:         BIP125RBFSequence,
	})
	// Grow the receiver output (which we identify as the first output
	// matching receiverScript).
	for i, out := range original.UnsignedTx.TxOut {
		v := out.Value
		_ = i
		if bytes.Equal(out.PkScript, receiverScript) {
			v += receiverAmount
		}
		proposalTx.TxOut = append(proposalTx.TxOut, &wire.TxOut{
			Value:    v,
			PkScript: out.PkScript,
		})
	}
	prop, err := NewPSBT(proposalTx)
	if err != nil {
		t.Fatalf("NewPSBT(proposal): %v", err)
	}
	// Preserve sender input's WitnessUTXO so G11 can compare scripts.
	prop.Inputs[0].WitnessUTXO = original.Inputs[0].WitnessUTXO
	// Receiver-input WitnessUTXO — script is a synthetic third-party
	// P2WPKH (not the sender's, not the receiver-pay output's).
	prop.Inputs[1].WitnessUTXO = &wire.TxOut{
		Value:    receiverAmount,
		PkScript: append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x33}, 20)...),
	}
	return prop
}

// TestPayjoinAntisnoopOutputsPreserved (G10) — substitution > 1 rejected.
func TestPayjoinAntisnoopOutputsPreserved(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	t.Run("happy path: 1 output substituted, 1 preserved", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopOutputsPreserved(original, proposal); err != nil {
			t.Errorf("unexpected G10 failure: %v", err)
		}
	})
	t.Run("malicious: 2 outputs substituted", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Substitute the CHANGE output with a stranger script — that's 2
		// scripts changed (recv + change), which violates G10's max=1.
		proposal.UnsignedTx.TxOut[1].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x99}, 20)...)
		// Also mutate the receiver script so two are missing.
		proposal.UnsignedTx.TxOut[0].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x77}, 20)...)
		if err := payjoinAntisnoopOutputsPreserved(original, proposal); err == nil {
			t.Error("G10 should reject when 2 original outputs are missing from proposal")
		}
	})
}

// TestPayjoinAntisnoopScriptSigTypes (G11) — script swap rejected.
func TestPayjoinAntisnoopScriptSigTypes(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	t.Run("happy path", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopScriptSigTypes(original, proposal); err != nil {
			t.Errorf("unexpected G11 failure: %v", err)
		}
	})
	t.Run("malicious: preserved input prev-out script changed", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Swap the WitnessUTXO of the preserved sender input to a
		// different script — simulates a receiver substituting a
		// P2SH-wrapped variant on the wire.
		proposal.Inputs[0].WitnessUTXO = &wire.TxOut{
			Value:    200_000_000,
			PkScript: append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0xFF}, 20)...), // P2SH
		}
		if err := payjoinAntisnoopScriptSigTypes(original, proposal); err == nil {
			t.Error("G11 should reject preserved-input script substitution")
		}
	})
}

// TestPayjoinAntisnoopNoNewSenderInputs (G12) — sender-owned input rejected.
func TestPayjoinAntisnoopNoNewSenderInputs(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	t.Run("happy path: new input is third-party", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// IsOwnScript returns false for everything — sender owns nothing.
		alwaysFalse := func([]byte) bool { return false }
		if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, alwaysFalse); err != nil {
			t.Errorf("unexpected G12 failure: %v", err)
		}
	})
	t.Run("malicious: receiver-added input is sender-owned", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Sender owns the receiver-added input's prev-out script.
		senderPk := proposal.Inputs[1].WitnessUTXO.PkScript
		isOwn := func(s []byte) bool { return bytes.Equal(s, senderPk) }
		if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, isOwn); err == nil {
			t.Error("G12 should reject when receiver inserts a sender-owned UTXO")
		}
	})
	t.Run("malicious: new input lacks WitnessUTXO", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		proposal.Inputs[1].WitnessUTXO = nil
		isOwn := func([]byte) bool { return false }
		if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, isOwn); err == nil {
			t.Error("G12 should reject when a new input has no WitnessUTXO (can't verify ownership)")
		}
	})
}

// TestPayjoinAntisnoopMaxFeeContribution (G13) — fee delta > cap rejected.
func TestPayjoinAntisnoopMaxFeeContribution(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript

	t.Run("happy path: fee invariant (delta=0)", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopMaxFeeContribution(original, proposal, 0); err != nil {
			t.Errorf("unexpected G13 failure (delta=0, cap=0): %v", err)
		}
	})
	t.Run("malicious: receiver raises fee by 1000 sats, cap=500", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Lower an output value by 1000 sats — bumps the fee by 1000.
		proposal.UnsignedTx.TxOut[1].Value -= 1000
		if err := payjoinAntisnoopMaxFeeContribution(original, proposal, 500); err == nil {
			t.Error("G13 should reject when fee delta > cap")
		}
	})
	t.Run("receiver pays for sender (delta negative) — accepted", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Bump an output value — lowers the fee. Always accepted.
		proposal.UnsignedTx.TxOut[1].Value += 500
		if err := payjoinAntisnoopMaxFeeContribution(original, proposal, 0); err != nil {
			t.Errorf("G13 should accept negative fee delta (cap=0): %v", err)
		}
	})
}

// TestPayjoinAntisnoopDisableOutputSubstitution (G14) — strict mode.
func TestPayjoinAntisnoopDisableOutputSubstitution(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	t.Run("happy path: all original scripts preserved", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopDisableOutputSubstitution(original, proposal); err != nil {
			t.Errorf("unexpected G14 failure: %v", err)
		}
	})
	t.Run("malicious: even 1 output substituted is rejected", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		proposal.UnsignedTx.TxOut[0].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x99}, 20)...)
		if err := payjoinAntisnoopDisableOutputSubstitution(original, proposal); err == nil {
			t.Error("G14 should reject any output script substitution under pjos=1")
		}
	})
}

// TestPayjoinAntisnoopMinFeeRate (G15) — feerate below minimum rejected.
func TestPayjoinAntisnoopMinFeeRate(t *testing.T) {
	original := buildSyntheticPSBT(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript

	t.Run("minFeeRate=0 is no-op", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopMinFeeRate(proposal, 0); err != nil {
			t.Errorf("G15 with minFeeRate=0 should be a no-op: %v", err)
		}
	})
	t.Run("malicious: proposal feerate below sender minimum", func(t *testing.T) {
		proposal := cloneAndAddReceiverInput(t, original, recvScript, 50_000_000)
		// Sender demands 100 sat/vB — our synthetic proposal is around
		// 1000 sats / 200ish vbytes ≈ 5 sat/vB, well below.
		if err := payjoinAntisnoopMinFeeRate(proposal, 100.0); err == nil {
			t.Error("G15 should reject when effective feerate < minfeerate")
		}
	})
}

// ── G22 retry / fallback ─────────────────────────────────────────────────

// TestPayjoinSenderFallback503 simulates a receiver under maintenance.
// Sender MUST fall back to the Original PSBT, never silently drop the
// payment.
func TestPayjoinSenderFallback503(t *testing.T) {
	sxw := payjoinSenderWallet(t)
	rxw, recvAddr := payjoinReceiverWallet(t)
	_ = rxw

	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}

	// Receiver always returns 503.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"errorCode": "unavailable",
			"message":   "wallet locked",
		})
	}))
	defer srv.Close()

	opts := PayjoinSendOptions{
		Endpoint:                     srv.URL + "/payjoin",
		Version:                      "1",
		MaxAdditionalFeeContribution: 1000,
		AdditionalFeeOutputIndex:     -1,
		HTTPClient:                   srv.Client(),
	}
	res, err := sxw.SendPayjoinRequest(original, opts)
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	if !res.Fallback {
		t.Fatal("expected Fallback=true on 503")
	}
	if res.ReceiverStatus != http.StatusServiceUnavailable {
		t.Errorf("ReceiverStatus=%d, want 503", res.ReceiverStatus)
	}
	if !strings.Contains(res.FallbackReason, "503") {
		t.Errorf("FallbackReason=%q, want it to mention 503", res.FallbackReason)
	}
	// The original (signed) PSBT is what the caller will broadcast.
	if res.FinalPSBTBase64 == "" {
		t.Error("FinalPSBTBase64 is empty; sender lost the original")
	}
	if res.FinalTx != nil {
		t.Error("FinalTx should be nil on fallback (caller extracts original separately)")
	}
}

// TestPayjoinSenderFallbackOnMaliciousProposal exercises the full sender
// flow against a malicious receiver: the receiver's response trips one of
// the anti-snoop validators and the sender falls back.
//
// We simulate "malicious" by returning a hand-crafted proposal where the
// receiver-added input is, in fact, claimed to be at one of the sender's
// own outpoints — the most dangerous attack G12 catches.
func TestPayjoinSenderFallbackOnMaliciousProposal(t *testing.T) {
	sxw := payjoinSenderWallet(t)
	rxw, recvAddr := payjoinReceiverWallet(t)
	_ = rxw

	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}

	// Find the sender's own funding pkScript so we can echo it back as
	// the "receiver-added" input prev-out — that's the fingerprinting
	// pattern G12 must catch.
	utxos := sxw.ListUnspent()
	if len(utxos) == 0 {
		t.Fatal("test setup: sender wallet has no UTXOs")
	}
	senderOwnedScript := utxos[0].PkScript

	// Receiver returns a proposal whose new input is at a fresh outpoint
	// but with the sender's own pkScript in WitnessUTXO (the smoking gun).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, PayjoinMaxBodyBytes+1))
		orig, derr := DecodePSBTBase64(strings.TrimSpace(string(body)))
		if derr != nil {
			http.Error(w, "decode", http.StatusBadRequest)
			return
		}
		// Build a proposal: clone, add a new input pointing at a fake
		// outpoint, set its WitnessUTXO to the sender's own script.
		proposalTx := &wire.MsgTx{
			Version:  orig.UnsignedTx.Version,
			LockTime: orig.UnsignedTx.LockTime,
		}
		for _, in := range orig.UnsignedTx.TxIn {
			proposalTx.TxIn = append(proposalTx.TxIn, &wire.TxIn{
				PreviousOutPoint: in.PreviousOutPoint,
				Sequence:         in.Sequence,
			})
		}
		proposalTx.TxIn = append(proposalTx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xDE, 0xAD}, Index: 7},
			Sequence:         BIP125RBFSequence,
		})
		for _, out := range orig.UnsignedTx.TxOut {
			proposalTx.TxOut = append(proposalTx.TxOut, &wire.TxOut{
				Value: out.Value, PkScript: out.PkScript,
			})
		}
		prop, _ := NewPSBT(proposalTx)
		prop.Inputs[0] = orig.Inputs[0]
		prop.Inputs[1].WitnessUTXO = &wire.TxOut{
			Value:    50_000_000,
			PkScript: senderOwnedScript, // <-- sender's own pkScript
		}
		b64, _ := prop.EncodeBase64()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, b64)
	}))
	defer srv.Close()

	opts := PayjoinSendOptions{
		Endpoint:                     srv.URL + "/payjoin",
		Version:                      "1",
		MaxAdditionalFeeContribution: 10_000,
		AdditionalFeeOutputIndex:     -1,
		HTTPClient:                   srv.Client(),
	}
	res, err := sxw.SendPayjoinRequest(original, opts)
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	if !res.Fallback {
		t.Fatal("expected Fallback=true on G12 fingerprinting attempt")
	}
	if !strings.Contains(res.FallbackReason, "G12") {
		t.Errorf("FallbackReason=%q, want it to mention G12", res.FallbackReason)
	}
}

// ── PSBT fee helper sanity ───────────────────────────────────────────────

func TestPayjoinPSBTFee(t *testing.T) {
	p := buildSyntheticPSBT(t)
	fee, err := payjoinPSBTFee(p)
	if err != nil {
		t.Fatalf("payjoinPSBTFee: %v", err)
	}
	// 200_000_000 - (50_000_000 + 149_999_000) = 1_000
	if fee != 1_000 {
		t.Errorf("fee=%d, want 1000", fee)
	}
}

// TestPayjoinPSBTFeeRejectsNegative checks for negative fees (outputs >
// inputs, which is consensus-invalid). The validator's caller (G13)
// relies on this — if fee math silently underflowed we'd get nonsense
// deltas.
func TestPayjoinPSBTFeeRejectsNegative(t *testing.T) {
	p := buildSyntheticPSBT(t)
	// Inflate output[0] past the input sum.
	p.UnsignedTx.TxOut[0].Value = 999_999_999_999
	if _, err := payjoinPSBTFee(p); err == nil {
		t.Error("payjoinPSBTFee should reject negative-fee PSBTs")
	}
}

// ── IsOwnScript sanity ───────────────────────────────────────────────────

func TestWalletIsOwnScript(t *testing.T) {
	sxw := payjoinSenderWallet(t)
	utxos := sxw.ListUnspent()
	if len(utxos) == 0 {
		t.Fatal("test setup: sender wallet has no UTXOs")
	}
	ownPk := utxos[0].PkScript
	if !sxw.IsOwnScript(ownPk) {
		t.Error("IsOwnScript returned false for sender-owned script")
	}
	stranger := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x55}, 20)...)
	if sxw.IsOwnScript(stranger) {
		t.Error("IsOwnScript returned true for stranger script")
	}
}
