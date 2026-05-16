// PayJoin receiver tests — round-trip + 4 BIP-78 error paths.
//
// Covers FIX-65 (closes W119 BUG-2 / BUG-13 / BUG-14 / BUG-17 receiver-half).
//
// The receiver is exercised directly via Server.handlePayjoin in an
// httptest.ResponseRecorder so we avoid the cost of spinning up a real
// listener; the FIX-64 TLS plumbing has its own integration tests in
// server_tls_test.go that exercise the listener path end-to-end.
//
// Test matrix:
//
//   TestPayjoinReceiverRoundtrip
//     Happy path: sender builds an Original PSBT paying the receiver,
//     POSTs to /payjoin?v=1, receives a base64-encoded Proposal PSBT.
//     Asserts:
//       - HTTP 200, Content-Type text/plain,
//       - response decodes as PSBT,
//       - proposal has one more input than original (the receiver's),
//       - the receiver output's value grew by the added input amount,
//       - the receiver's input is signed (PartialSigs non-empty).
//
//   TestPayjoinReceiverVersionUnsupported
//     v=2 → 415 + errorCode "version-unsupported".
//
//   TestPayjoinReceiverOriginalPSBTRejected
//     Malformed body → 400 + errorCode "original-psbt-rejected".
//
//   TestPayjoinReceiverNotEnoughMoney
//     Wallet has no UTXO → 422 + errorCode "not-enough-money".
//
//   TestPayjoinReceiverUnavailable
//     No wallet loaded → 503 + errorCode "unavailable".

package rpc

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
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// senderUTXO builds a fake "sender" P2WPKH UTXO. The sender is NOT the
// receiver wallet — we only need a (txid, vout, amount, pkScript) tuple
// to populate the Original PSBT's witness_utxo. The receiver doesn't
// sign sender inputs and we never broadcast, so a synthetic UTXO is
// sufficient.
type senderUTXO struct {
	outpoint wire.OutPoint
	amount   int64
	pkScript []byte
}

// newSenderUTXO returns a deterministic test sender UTXO. We use a
// fixed P2WPKH pkScript (any 20-byte hash will do since we never sign
// or validate the script — just exercise BIP-78 wire structure).
func newSenderUTXO(t *testing.T) senderUTXO {
	t.Helper()
	// Arbitrary P2WPKH: OP_0 <20-byte hash>. The hash is deterministic
	// so the test is reproducible across runs.
	pk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xAB}, 20)...)
	return senderUTXO{
		outpoint: wire.OutPoint{Hash: wire.Hash256{0xCC}, Index: 0},
		amount:   200_000_000, // 2 BTC
		pkScript: pk,
	}
}

// buildOriginalPSBT constructs a sender's Original PSBT that pays
// `receiverAddr` `receiverAmount` and leaves the difference as a sender
// change output (we don't actually fund or sign — we just need the wire
// structure to be parseable and to satisfy validateOriginal).
//
// Returns the base64-encoded PSBT.
func buildOriginalPSBT(t *testing.T, sender senderUTXO, receiverAddr string, receiverNetwork address.Network, receiverAmount int64) string {
	t.Helper()

	recvParsed, err := address.DecodeAddress(receiverAddr, receiverNetwork)
	if err != nil {
		t.Fatalf("DecodeAddress(receiver): %v", err)
	}
	recvScript := recvParsed.ScriptPubKey()

	// Sender's change pkScript — deterministic, different bytes from
	// the receiver address so the receiver's pay-output scan disambiguates.
	changeScript := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xEE}, 20)...)

	// Fee budget: 1000 sats. Receiver amount goes to recvScript;
	// remainder (minus fee) returns as change.
	fee := int64(1_000)
	changeAmount := sender.amount - receiverAmount - fee
	if changeAmount < 0 {
		t.Fatalf("test setup: sender UTXO %d too small for recv %d + fee %d", sender.amount, receiverAmount, fee)
	}

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: sender.outpoint,
		Sequence:         wallet.BIP125RBFSequence, // opt-in RBF
	})
	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    receiverAmount,
		PkScript: recvScript,
	})
	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    changeAmount,
		PkScript: changeScript,
	})

	psbt, err := wallet.NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	// Sender witness UTXO populated so the receiver passes G5 (every
	// input must carry witness_utxo or non_witness_utxo).
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    sender.amount,
		PkScript: sender.pkScript,
	}

	b64, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("EncodeBase64: %v", err)
	}
	return b64
}

// newPayjoinTestServer builds a Server with one funded wallet UTXO and
// returns the server, the receive address, and the wallet's UTXO so the
// test can construct a sender PSBT that pays the receiver.
//
// We use regtest + P2WPKH for parity with the rest of the rpc test suite.
func newPayjoinTestServer(t *testing.T) (*Server, *wallet.Wallet, string) {
	t.Helper()
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
		AddressType: wallet.AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}

	// Receive address the sender will pay.
	recvAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	recvParsed, err := address.DecodeAddress(recvAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}

	// Fund the wallet with one confirmed UTXO at a DIFFERENT address
	// so the receiver-output scan doesn't pick this funding UTXO's
	// pkScript by accident. (The receiver MUST grow the OUTPUT that
	// the sender paid to, not just any wallet-owned script.)
	fundAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress(fund): %v", err)
	}
	fundParsed, err := address.DecodeAddress(fundAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress(fund): %v", err)
	}

	w.AddUTXO(&wallet.WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0x77}, Index: 0},
		Amount:    150_000_000, // 1.5 BTC — receiver's contribution
		PkScript:  fundParsed.ScriptPubKey(),
		Address:   fundAddr,
		Height:    100,
		Confirmed: true,
	})

	// Pin the receive address ScriptPubKey in a t.Cleanup-bound variable
	// so a debug-print uses a single source of truth.
	_ = recvParsed.ScriptPubKey() // ensure decode succeeded; lint-quiet

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)
	return server, w, recvAddr
}

// postPayjoin makes a POST /payjoin request with the given body and query
// params and returns the response recorder. Centralised so each test
// stays focused on assertions.
func postPayjoin(t *testing.T, server *Server, body string, query string, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	url := payjoinPath
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	server.handlePayjoin(rr, req)
	return rr
}

// readPayjoinError extracts the BIP-78 JSON error body from an error
// response. Aborts the test if the body is not the expected shape.
func readPayjoinError(t *testing.T, rr *httptest.ResponseRecorder) payjoinErrorBody {
	t.Helper()
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body payjoinErrorBody
	raw, _ := io.ReadAll(rr.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode error body %q: %v", string(raw), err)
	}
	if body.ErrorCode == "" {
		t.Fatalf("missing errorCode in body: %s", string(raw))
	}
	return body
}

// ── TestPayjoinReceiverRoundtrip — happy path G1/G4/G5/G7 ─────────────────

func TestPayjoinReceiverRoundtrip(t *testing.T) {
	server, w, recvAddr := newPayjoinTestServer(t)

	sender := newSenderUTXO(t)
	receiverAmount := int64(50_000_000) // 0.5 BTC
	body := buildOriginalPSBT(t, sender, recvAddr, w.Network(), receiverAmount)

	rr := postPayjoin(t, server, body, "v=1", "text/plain")

	if rr.Code != http.StatusOK {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, string(raw))
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}

	respBody, _ := io.ReadAll(rr.Body)
	proposal, err := wallet.DecodePSBTBase64(strings.TrimSpace(string(respBody)))
	if err != nil {
		t.Fatalf("decode proposal PSBT: %v", err)
	}

	// Proposal must have exactly one MORE input than the original
	// (the receiver's added contribution input).
	if got, want := len(proposal.UnsignedTx.TxIn), 2; got != want {
		t.Errorf("proposal inputs = %d, want %d (1 sender + 1 receiver)", got, want)
	}

	// Receiver output must have grown by the wallet's UTXO amount.
	// Find the receiver output by pkScript: it must match the receive
	// address's scriptPubKey.
	recvParsed, _ := address.DecodeAddress(recvAddr, w.Network())
	recvScript := recvParsed.ScriptPubKey()
	var receiverOutVal int64 = -1
	for _, out := range proposal.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, recvScript) {
			receiverOutVal = out.Value
			break
		}
	}
	if receiverOutVal < 0 {
		t.Fatalf("proposal has no output paying receiver address")
	}
	const walletUTXOAmt = int64(150_000_000)
	wantVal := receiverAmount + walletUTXOAmt
	if receiverOutVal != wantVal {
		t.Errorf("receiver output value = %d, want %d (original %d + added UTXO %d)",
			receiverOutVal, wantVal, receiverAmount, walletUTXOAmt)
	}

	// The added receiver input (index 1) must be signed: PartialSigs
	// non-empty. This proves the WalletPSBTSigner path was exercised.
	if got := len(proposal.Inputs[1].PartialSigs); got != 1 {
		t.Errorf("receiver input PartialSigs count = %d, want 1 (proves signer ran)", got)
	}

	// The receiver input must have its WitnessUTXO attached so a
	// downstream sender / verifier can compute the sighash.
	if proposal.Inputs[1].WitnessUTXO == nil {
		t.Errorf("receiver input WitnessUTXO is nil; sender cannot re-verify the sighash")
	} else if proposal.Inputs[1].WitnessUTXO.Value != walletUTXOAmt {
		t.Errorf("receiver input WitnessUTXO.Value = %d, want %d",
			proposal.Inputs[1].WitnessUTXO.Value, walletUTXOAmt)
	}
}

// ── TestPayjoinReceiverVersionUnsupported — BUG-14 / G21 ─────────────────

func TestPayjoinReceiverVersionUnsupported(t *testing.T) {
	server, w, recvAddr := newPayjoinTestServer(t)
	sender := newSenderUTXO(t)
	body := buildOriginalPSBT(t, sender, recvAddr, w.Network(), 50_000_000)

	rr := postPayjoin(t, server, body, "v=2", "text/plain")

	if rr.Code != http.StatusUnsupportedMediaType {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 415; body=%s", rr.Code, string(raw))
	}
	err := readPayjoinError(t, rr)
	if err.ErrorCode != string(wallet.PayjoinErrVersionUnsupported) {
		t.Errorf("errorCode = %q, want %q", err.ErrorCode, wallet.PayjoinErrVersionUnsupported)
	}
}

// ── TestPayjoinReceiverOriginalPSBTRejected — BUG-2 / G5 / G17 ──────────

func TestPayjoinReceiverOriginalPSBTRejected(t *testing.T) {
	server, _, _ := newPayjoinTestServer(t)

	// Send garbage that is NOT a valid base64 PSBT.
	rr := postPayjoin(t, server, "not-a-real-psbt-just-garbage", "v=1", "text/plain")

	if rr.Code != http.StatusBadRequest {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, string(raw))
	}
	err := readPayjoinError(t, rr)
	if err.ErrorCode != string(wallet.PayjoinErrOriginalPSBTRejected) {
		t.Errorf("errorCode = %q, want %q", err.ErrorCode, wallet.PayjoinErrOriginalPSBTRejected)
	}
}

// ── TestPayjoinReceiverNotEnoughMoney — BUG-2 / G7 / G17 ─────────────────

func TestPayjoinReceiverNotEnoughMoney(t *testing.T) {
	// Build a server WITHOUT any wallet UTXOs so the receiver has nothing
	// to contribute.
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
		AddressType: wallet.AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	recvAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	// NO AddUTXO call here — wallet is empty.

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	sender := newSenderUTXO(t)
	body := buildOriginalPSBT(t, sender, recvAddr, w.Network(), 50_000_000)

	rr := postPayjoin(t, server, body, "v=1", "text/plain")

	if rr.Code != http.StatusUnprocessableEntity {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 422; body=%s", rr.Code, string(raw))
	}
	perr := readPayjoinError(t, rr)
	if perr.ErrorCode != string(wallet.PayjoinErrNotEnoughMoney) {
		t.Errorf("errorCode = %q, want %q", perr.ErrorCode, wallet.PayjoinErrNotEnoughMoney)
	}
}

// ── TestPayjoinReceiverUnavailable — BUG-2 / G17 ─────────────────────────

func TestPayjoinReceiverUnavailable(t *testing.T) {
	// Server with NO wallet loaded — receiver responds with 503 +
	// "unavailable" so a real BIP-78 sender retries with backoff.
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)

	// Body shape is irrelevant — the wallet lookup happens before PSBT
	// decoding, so even valid base64 here would still 503.
	rr := postPayjoin(t, server, "anything", "v=1", "text/plain")

	if rr.Code != http.StatusServiceUnavailable {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, string(raw))
	}
	perr := readPayjoinError(t, rr)
	if perr.ErrorCode != string(wallet.PayjoinErrUnavailable) {
		t.Errorf("errorCode = %q, want %q", perr.ErrorCode, wallet.PayjoinErrUnavailable)
	}
}

// ── TestPayjoinReceiverMethodNotAllowed — non-POST rejection ─────────────
//
// Lower-priority but cheap to assert: GET /payjoin must return 405.

func TestPayjoinReceiverMethodNotAllowed(t *testing.T) {
	server, _, _ := newPayjoinTestServer(t)

	req := httptest.NewRequest(http.MethodGet, payjoinPath+"?v=1", nil)
	rr := httptest.NewRecorder()
	server.handlePayjoin(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// ── TestPayjoinReceiverQueryParams — FIX-67 G16 wire-level parsing ───────
//
// Exercises the BIP-78 query-param parsing in the RPC layer:
//   - v= recognised (already covered by TestPayjoinReceiverVersionUnsupported)
//   - additionalfeeoutputindex + maxadditionalfeecontribution → proposal
//     fee strictly above original (the receiver shrunk the sender's change
//     output by the cap).
//
// The wallet-side counterpart is TestW119G16_QueryParamsParsed in
// internal/wallet/w119_payjoin_test.go — together they prove the full
// round-trip from query-string parsing to proposal arithmetic.

func TestPayjoinReceiverQueryParams(t *testing.T) {
	server, w, recvAddr := newPayjoinTestServer(t)

	sender := newSenderUTXO(t)
	body := buildOriginalPSBT(t, sender, recvAddr, w.Network(), 50_000_000)

	// Decode original to compute the baseline fee.
	original, err := wallet.DecodePSBTBase64(body)
	if err != nil {
		t.Fatalf("decode original: %v", err)
	}
	var origIn, origOut int64
	for _, in := range original.Inputs {
		origIn += in.WitnessUTXO.Value
	}
	for _, out := range original.UnsignedTx.TxOut {
		origOut += out.Value
	}
	origFee := origIn - origOut

	// Query params: sender designates output 1 (change) as fee-source
	// with a 500 sat cap.
	rr := postPayjoin(t, server, body,
		"v=1&additionalfeeoutputindex=1&maxadditionalfeecontribution=500",
		"text/plain")
	if rr.Code != http.StatusOK {
		raw, _ := io.ReadAll(rr.Body)
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, string(raw))
	}
	respBody, _ := io.ReadAll(rr.Body)
	proposal, err := wallet.DecodePSBTBase64(strings.TrimSpace(string(respBody)))
	if err != nil {
		t.Fatalf("decode proposal: %v", err)
	}

	// Net proposal fee must be exactly 500 sats above original.
	var propIn, propOut int64
	for _, in := range proposal.Inputs {
		propIn += in.WitnessUTXO.Value
	}
	for _, out := range proposal.UnsignedTx.TxOut {
		propOut += out.Value
	}
	propFee := propIn - propOut
	if delta := propFee - origFee; delta != 500 {
		t.Errorf("fee delta = %d, want 500 (the cap honored)", delta)
	}
}

// ── TestPayjoinReceiverInvalidContentType — FIX-67 G23 strict CT ─────────
//
// FIX-67 hardened Content-Type validation: an EMPTY Content-Type header
// (which was previously accepted) is now rejected with 415 + the
// version-unsupported error code. application/json is also rejected
// (wrong wire format).

func TestPayjoinReceiverInvalidContentType(t *testing.T) {
	server, w, recvAddr := newPayjoinTestServer(t)
	sender := newSenderUTXO(t)
	body := buildOriginalPSBT(t, sender, recvAddr, w.Network(), 50_000_000)

	for _, tc := range []struct {
		name string
		ct   string
	}{
		{"empty", ""},
		{"application/json", "application/json"},
		{"image/png", "image/png"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := postPayjoin(t, server, body, "v=1", tc.ct)
			if rr.Code != http.StatusUnsupportedMediaType {
				t.Errorf("status = %d, want 415", rr.Code)
			}
			eb := readPayjoinError(t, rr)
			if eb.ErrorCode != "version-unsupported" {
				t.Errorf("errorCode = %q, want version-unsupported", eb.ErrorCode)
			}
		})
	}
}
