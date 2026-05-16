// W119 BIP-78 PayJoin audit — blockbrew (Go).
//
// Bitcoin Core has NO PayJoin (BIP-78) support — this audit grades blockbrew
// against the BIP-78 spec (bips/bip-0078.mediawiki) and the ecosystem
// reference implementations (payjoin.org, btcpayserver/payjoin, JoinMarket),
// not against bitcoin-core/src.
//
// BIP-78 in one paragraph: Receiver publishes a BIP-21 URI carrying `pj=<url>`
// (the PayJoin endpoint) and `pjos=0|1` (disableoutputsubstitution flag).
// Sender builds an "Original PSBT" paying the receiver, POSTs it to `pj`, and
// receives back a "Payjoin Proposal PSBT" in which the receiver has added
// one or more own inputs (breaking common-input-ownership heuristic) and
// rewritten the sender output. Sender then runs the BIP-78 anti-snoop
// checks (original inputs preserved, no sender wallet UTXOs added, fee bounded
// by `maxadditionalfeecontribution`, minfeerate honored, output substitution
// gated by `pjos`), signs the proposal, and broadcasts.
//
// AUDIT SUMMARY (blockbrew, 2026-05-15)
//
// Grade: 0 / 30 PRESENT, 0 / 30 PARTIAL, 30 / 30 MISSING ENTIRELY.
// blockbrew has zero PayJoin code. There is no /payjoin HTTP endpoint, no
// PayJoin sender, no BIP-21 URI parser, no `pj=` / `pjos=` recognition, and
// no `getpayjoinrequest` / `sendpayjoinrequest` RPC. The HTTP server in
// internal/rpc/server.go only serves JSON-RPC at `/` and (optionally) the
// REST API at `/rest/*` (rest.go). TLS is not configured at all — the
// ListenAndServe call (server.go:261) is plaintext-HTTP only, so the
// "must be HTTPS or .onion" rule cannot be honored even by accident.
//
// FIX-61 (BumpFee + BIP125RBFSequence + outgoing change-output detection)
// gives this audit a starting point: the same scriptToOwnAddressLocked /
// isInternalAddressLocked helpers from bumpfee.go are the natural place
// to anchor the sender-side anti-snoop checks (G10–G15). PSBT primitives
// (NewPSBT, DecodePSBT, EncodePSBT, CombinePSBTs, SignPSBT, FinalizePSBT)
// are all in place and usable as building blocks. The major missing pieces
// are (a) an HTTP transport (sender HTTPS client + receiver POST handler),
// (b) BIP-21 URI parsing, (c) BIP-78 wire-format JSON error bodies, and
// (d) the anti-snoop verifier on the sender side.
//
// 30-gate spec (identical across all W119 sub-agents for fleet parity):
//
//   G1  Receiver HTTP endpoint POST /payjoin
//   G2  Sender HTTP client POSTs Original PSBT
//   G3  TLS/HTTPS or .onion required
//   G4  Original PSBT v0 deserialization receiver
//   G5  Receiver validates Original PSBT
//   G6  Receiver identifies fee output
//   G7  Receiver adds own inputs (anti-fingerprinting)
//   G8  Receiver modifies sender output
//   G9  Receiver fee adjustment (max bound)
//   G10 Sender anti-snoop: outputs preserved
//   G11 Sender anti-snoop: scriptSig types preserved
//   G12 Sender anti-snoop: no new sender inputs
//   G13 Sender anti-snoop: max additional fee contribution
//   G14 Sender anti-snoop: disableoutputsubstitution
//   G15 Sender anti-snoop: min-fee-rate
//   G16 BIP-78 query params parsed
//   G17 Receiver error responses (4 BIP-78 codes)
//   G18 Receiver TTL on offered payjoin
//   G19 Receiver no-double-spending guard
//   G20 Receiver UTXO selection (UIH-1/UIH-2)
//   G21 Receiver PSBT v=1 header param
//   G22 Sender retry / fallback to original
//   G23 Receiver request validation (Content-Type, Length)
//   G24 HTTPS cert validation (sender)
//   G25 Tor onion service support
//   G26 getpayjoinrequest RPC
//   G27 sendpayjoinrequest RPC
//   G28 BIP-21 URI parser `pj=`
//   G29 BIP-21 URI parser `pjos=`
//   G30 Receiver replay protection (PSBT-id)
//
// BUG INDEX
//
//   BUG-1 (P0-FEATURE — G1/G2/G3/G24/G25): No HTTP transport for BIP-78
//          at all. internal/rpc/server.go starts a plaintext-HTTP listener
//          (server.go:261 `ListenAndServe`); there is no `ListenAndServeTLS`
//          path, no x509 wiring, no .onion endpoint. Even if a handler were
//          added today, the BIP-78 §"Protocol" rule that "the BIP-21 URI
//          MUST use https or be a .onion" cannot be enforced — both as
//          server (receiver cannot publish a real `pj=` URL) and as
//          client (sender cannot validate the certificate chain).
//
//   BUG-2 (P0-FEATURE — G4/G5/G6/G7/G8/G9/G17/G18/G19/G20/G21/G23/G30):
//          No receiver-side PayJoin handler. There is no `/payjoin` route
//          in internal/rpc/server.go, no Original-PSBT validator, no UTXO
//          selector implementing UIH-1/UIH-2 (Unnecessary Input Heuristic),
//          no proposal-PSBT builder, no `v=1` header param check, no
//          BIP-78 JSON error body emitter, no TTL on offered payjoins,
//          no replay-protection cache keyed by PSBT-id, no
//          double-spending guard. Receiver flow is entirely absent.
//
//   BUG-3 (P0-FEATURE — G10/G11/G12/G13/G14/G15/G22): No sender-side
//          anti-snoop verifier. After receiving a "Payjoin Proposal PSBT"
//          the sender MUST verify: (1) every original input is present;
//          (2) scriptSig type of each preserved input matches; (3) no new
//          input belongs to the sender wallet (would be a fingerprinting
//          attack by a malicious receiver); (4) fee increase
//          ≤ maxadditionalfeecontribution; (5) `pjos=1` blocks output
//          substitution; (6) replacement feerate ≥ minfeerate; (7) on
//          any failure the sender falls back to broadcasting the Original
//          PSBT. None of these are implemented. The wallet has the
//          building blocks (scriptToOwnAddressLocked from bumpfee.go,
//          IsMine semantics via the addrToPath map, PSBT structural
//          helpers in psbt.go / psbt_ops.go) but no anti-snoop layer
//          calling them.
//
//   BUG-4 (P0-MISSING — G26/G27): No PayJoin RPCs. server.go (dispatch
//          map at server.go:444+) lists ~80 method names but neither
//          `getpayjoinrequest` (receiver: produce a `pj=` URI for an
//          invoice / amount), nor `sendpayjoinrequest` (sender: take a
//          bitcoin:... URI carrying `pj=`, build Original PSBT, run the
//          PayJoin handshake, sign, broadcast) exists. Compare with the
//          ecosystem reference (payjoin.org Rust crate exposes
//          `payjoin::receiver::UncheckedProposal::*` and
//          `payjoin::sender::RequestContext`; bitcoin-core JoinMarket
//          plug-in exposes `coinjoin_send` / `coinjoin_receive`).
//
//   BUG-5 (P0-MISSING — G28/G29): No BIP-21 URI parser. blockbrew has
//          no `bitcoin:` URI handling anywhere in the tree (grep
//          `bitcoin:` returns zero non-test hits). The wallet accepts
//          plain address strings (sendtoaddress takes a base58/bech32
//          string, not a URI). Per BIP-21 the URI is the carrier for
//          BIP-78 — without it, `pj=` and `pjos=` are unparseable.
//          A minimally compliant parser must split scheme / address /
//          query, percent-decode each param, validate `pj=` as an absolute
//          URL with https or `.onion` host, and treat `pjos` as a boolean
//          flag (default 1 per spec).
//
//   BUG-6 (HIGH — G16): No BIP-78 query-param recognition. Even if a
//          URI parser were added, the sender code that POSTs to `pj=`
//          must thread four query params through to the request URL:
//          `v=1` (mandatory; receivers reject other versions),
//          `additionalfeeoutputindex` (sender output that may shrink),
//          `maxadditionalfeecontribution` (in sats),
//          `disableoutputsubstitution` (0 or 1, default 1 if `pjos=1`
//          on the URI). None of these are recognized.
//
//   BUG-7 (HIGH — G17): No BIP-78 JSON error body emitter. Per spec
//          §"Error responses", on failure the receiver MUST return
//          Content-Type `application/json` with body
//          `{"errorCode": "<code>", "message": "..."}` and one of the
//          four standardized codes: `unavailable` (receiver temporarily
//          can't), `not-enough-money` (receiver has no UTXO to add),
//          `version-unsupported` (sender's `v=` not honored),
//          `original-psbt-rejected` (validation failed). blockbrew has
//          no shape for these — the rpc layer's RPCError uses JSON-RPC
//          2.0 numeric codes, not BIP-78 string codes, so even if the
//          handler dispatched into the rpc package the error mapping
//          would be wrong.
//
//   BUG-8 (HIGH — G7): No UTXO selection on receiver side. BIP-78 §"How
//          to select utxos" (UIH-1, UIH-2) describes a selection strategy
//          where the receiver picks an input that, after addition, leaves
//          the change-vs-recipient ordering still ambiguous (i.e. doesn't
//          force the heuristic to identify which is which). blockbrew's
//          coin selection (internal/wallet/coinselection.go) is built for
//          standard send paths only — it has no UIH-aware variant.
//
//   BUG-9 (HIGH — G19): No double-spending guard. A PayJoin receiver
//          that offers two distinct Original-PSBT modifications for the
//          same outpoint set risks the sender choosing one, broadcasting,
//          and the other becoming a double-spend the receiver themselves
//          published. Spec §"Receiver's original PSBT validation" requires
//          the receiver to track outpoints across in-flight proposals.
//          No such tracker exists.
//
//   BUG-10 (HIGH — G18/G30): No TTL + replay protection. Without a
//          time-bounded offer (TTL) and a replay cache keyed on
//          PSBT-id (sha256 of the Original PSBT bytes), the receiver
//          must either re-run the full selection on every retry (wasteful
//          and racy) or risk handing out stale proposals. Spec
//          §"Receiver's per-session state" describes both.
//
//   BUG-11 (MEDIUM — G3 hardening): TLS even on the RPC side is absent.
//          server.go:253 builds an `&http.Server{}` without TLSConfig and
//          calls plain `ListenAndServe`. For PayJoin this is a hard block
//          because BIP-78 §"Protocol" explicitly forbids `http://`
//          endpoints — receivers must publish https or .onion URIs.
//          Adding TLSConfig + a `pj_cert_file` / `pj_key_file` config
//          option is the minimum.
//
//   BUG-12 (MEDIUM — G25): No .onion serving infrastructure. blockbrew
//          has Tor v3 awareness on the P2P side (internal/p2p/addrv2.go
//          encodes/decodes 32-byte ed25519 v3 onions per BIP-155) but no
//          ability to host an inbound Tor hidden service for the
//          PayJoin endpoint. The control-port handshake to ADD_ONION
//          (W117 territory) is on the connect-out path, not the listen
//          side.
//
//   BUG-13 (MEDIUM — G23): No request validation skeleton. The sender's
//          POST is expected to be Content-Type `text/plain` (per spec —
//          the body is the base64-encoded Original PSBT) or
//          `application/octet-stream` for raw PSBT bytes, with a sane
//          Content-Length cap. blockbrew has no inbound HTTP path that
//          enforces either.
//
//   BUG-14 (MEDIUM — G21): No `v=1` enforcement. Per BIP-78 the receiver
//          MUST refuse requests where the URL query param `v` is not `1`
//          (or absent — historical Joinmarket compatibility), responding
//          with `version-unsupported`. Without `v=1` recognition the
//          receiver cannot reject a v=2 forward-compatible probe cleanly.
//
//   BUG-15 (LOW — G24): No HTTPS cert validation on the sender side.
//          When the sender POSTs to `pj=https://...`, Go's net/http
//          default-transport validates the system cert pool, which is
//          fine for the common case — but spec §"Protocol" allows the
//          sender to opt-in to a pinned cert (TOFU for self-signed
//          receivers). blockbrew has no `--pj-pinned-cert` flag.
//
//   BUG-16 (LOW — G22): No fallback-to-original logic. On any anti-snoop
//          failure the sender SHOULD broadcast the Original PSBT (sign +
//          send via sendrawtransaction) so the user's payment still
//          completes — degraded to a non-PayJoin send. Without a
//          handshake flow this is N/A today, but documenting the gap.
//
//   BUG-17 (LOW — G6 readiness): No fee-output identification helper.
//          The receiver must identify which output covers the fee delta
//          (the `additionalfeeoutputindex` param, or by heuristic the
//          sender's change output). blockbrew has change-output detection
//          on the wallet side (scriptToOwnAddressLocked +
//          isInternalAddressLocked from FIX-61's bumpfee.go), but no
//          mirror that operates on a foreign sender PSBT.
//
//   BUG-18 (LOW — G9 hardening): No max-additional-fee bound on receiver
//          additions. Even if a receiver flow existed, it must clamp the
//          new fee at `maxadditionalfeecontribution` from the query
//          string, otherwise a malicious receiver could quietly raise
//          the fee to attack a fee-sensitive sender.
//
// All thirty tests below are `t.Skip("BUG-N: ...")` — the gates are
// uniformly MISSING ENTIRELY. When PayJoin lands in blockbrew, the
// natural fix-wave will replace each Skip with a real assertion that
// exercises the new code path.
//
// Author: W119 audit sub-agent, 2026-05-15.
//
//nolint:revive  // Skip-only audit file; intentionally many similar tests.

package wallet

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ── FIX-65 receiver-side test helpers ────────────────────────────────────
//
// These helpers anchor the W119 receiver-side gate tests (G1/G4/G5/G7/G9/G17)
// to the real wallet.ProcessPayjoinRequest implementation that FIX-65
// landed. They're kept local to this file to keep the audit-file/closure
// pairing greppable: someone reading the W119 audit can scroll directly
// to the same file to see what fixture / assertion replaced each Skip.

// payjoinReceiverWallet creates a wallet with one confirmed 1.5 BTC UTXO
// and returns the wallet + the address the sender will pay.
func payjoinReceiverWallet(t *testing.T) (*Wallet, string) {
	t.Helper()
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
		AddressType: AddressTypeP2WPKH,
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

	// Fund a DIFFERENT address (so the receiver scan doesn't accidentally
	// pick the funding pkScript as a "payment to the receiver").
	fundAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress(fund): %v", err)
	}
	fundParsed, err := address.DecodeAddress(fundAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	w.AddUTXO(&WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0x77}, Index: 0},
		Amount:    150_000_000,
		PkScript:  fundParsed.ScriptPubKey(),
		Address:   fundAddr,
		Height:    100,
		Confirmed: true,
	})
	return w, recvAddr
}

// payjoinReceiverOriginalPSBT builds a minimal Original PSBT that pays
// `recvAddr` `recvAmount` sats; the sender input is synthetic (we never
// sign or broadcast). `extraOut` lets a caller append a second output
// for variants like G8 (mismatched amounts).
func payjoinReceiverOriginalPSBT(t *testing.T, w *Wallet, recvAddr string, recvAmount int64) string {
	t.Helper()
	recvParsed, err := address.DecodeAddress(recvAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	senderPk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xAB}, 20)...)
	changePk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xEE}, 20)...)

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xCC}, Index: 0},
		Sequence:         BIP125RBFSequence,
	})
	tx.TxOut = append(tx.TxOut,
		&wire.TxOut{Value: recvAmount, PkScript: recvParsed.ScriptPubKey()},
		&wire.TxOut{Value: 200_000_000 - recvAmount - 1_000, PkScript: changePk},
	)

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    200_000_000,
		PkScript: senderPk,
	}
	b64, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("EncodeBase64: %v", err)
	}
	return b64
}

// ── FIX-66 sender-side test helpers (W119 G2 / G10–G15 / G22 / G24 / G26 / G27) ──
//
// Mirrors the receiver-side helpers above. Kept colocated in the same
// test file so the audit-file/closure pairing stays greppable for both
// halves of the BIP-78 protocol.

// buildPayjoinSenderWalletForG2 builds a sender wallet — different
// BIP-39 mnemonic than the receiver so addresses don't collide if both
// wallets are co-resident in a test. KeyPath is set so the internal
// signTx path can resolve the funding UTXO to a private key.
func buildPayjoinSenderWalletForG2(t *testing.T) *Wallet {
	t.Helper()
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
		AddressType: AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic(
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"",
	); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	fundAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	fundParsed, err := address.DecodeAddress(fundAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	// Resolve KeyPath via the wallet's own derivation map (same shape
	// the bumpfee path uses). Read under RLock to match locking
	// discipline.
	w.mu.RLock()
	path := w.addrToPath[fundAddr]
	w.mu.RUnlock()
	w.AddUTXO(&WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0xAA}, Index: 0},
		Amount:    200_000_000,
		PkScript:  fundParsed.ScriptPubKey(),
		Address:   fundAddr,
		KeyPath:   path,
		Height:    100,
		Confirmed: true,
	})
	return w
}

// w119StartReceiverTLS spins up an httptest.NewTLSServer mounting the
// FIX-65 receiver pipeline at "/payjoin". Sender tests use this to
// drive end-to-end round-trips without import-cycling through the rpc
// package (we live in the wallet package).
func w119StartReceiverTLS(t *testing.T, rxw *Wallet) *httptestTLSServer {
	t.Helper()
	srv := newTestTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			_, _ = w.Write([]byte(`{"errorCode":"` + string(perr.Code) + `","message":"` + perr.Message + `"}`))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp)
	}))
	return srv
}

// w119Start503Server always returns 503 + a JSON BIP-78 error body.
func w119Start503Server(t *testing.T) *httptestTLSServer {
	t.Helper()
	return newTestTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errorCode":"unavailable","message":"wallet locked"}`))
	}))
}

// httptestTLSServer is a thin alias wrapping httptest.Server so we can
// keep the import locally scoped (`net/http/httptest` is added per-file).
type httptestTLSServer = httptest.Server

func newTestTLSServer(h http.Handler) *httptestTLSServer {
	return httptest.NewTLSServer(h)
}

// w119SyntheticOriginal builds a deterministic Original-shape PSBT for
// validator tests: 1 sender input (200_000_000 sats P2WPKH), 2 outputs
// (50_000_000 to "recv" + 149_999_000 change). Fee=1000.
func w119SyntheticOriginal(t *testing.T) *PSBT {
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

// w119SyntheticProposal mirrors what FIX-65's ProcessPayjoinRequest
// would produce: clone original + append a receiver input + grow the
// receiver-paying output by receiverAmount.
func w119SyntheticProposal(t *testing.T, original *PSBT, recvScript []byte, recvAmount int64) *PSBT {
	t.Helper()
	tx := &wire.MsgTx{
		Version:  original.UnsignedTx.Version,
		LockTime: original.UnsignedTx.LockTime,
	}
	for _, in := range original.UnsignedTx.TxIn {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			Sequence:         in.Sequence,
		})
	}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xBB}, Index: 0},
		Sequence:         BIP125RBFSequence,
	})
	for _, out := range original.UnsignedTx.TxOut {
		v := out.Value
		if bytes.Equal(out.PkScript, recvScript) {
			v += recvAmount
		}
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: v, PkScript: out.PkScript})
	}
	prop, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT(proposal): %v", err)
	}
	prop.Inputs[0].WitnessUTXO = original.Inputs[0].WitnessUTXO
	prop.Inputs[1].WitnessUTXO = &wire.TxOut{
		Value:    recvAmount,
		PkScript: append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x33}, 20)...),
	}
	return prop
}

// ── G1: Receiver HTTP endpoint POST /payjoin ─────────────────────────────────
//
// FIX-65 closure: ProcessPayjoinRequest is the wallet-side core that the
// rpc.Server.handlePayjoin /payjoin handler dispatches to. Exercising the
// core here proves the wallet layer is wired even without spinning up an
// httptest server; the rpc/payjoin_receiver_test.go suite covers the
// transport-layer assertions in parallel.

func TestW119G1_ReceiverHTTPEndpoint(t *testing.T) {
	w, recvAddr := payjoinReceiverWallet(t)
	body := payjoinReceiverOriginalPSBT(t, w, recvAddr, 50_000_000)

	resp, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
		OriginalPSBTBase64: body,
		Version:            "1",
	})
	if perr != nil {
		t.Fatalf("ProcessPayjoinRequest failed: %v", perr)
	}
	if resp == "" {
		t.Fatal("expected base64 proposal PSBT, got empty string")
	}
}

// ── G2: Sender HTTP client POSTs Original PSBT ───────────────────────────────
//
// FIX-66 closure: SendPayjoinRequest POSTs base64 Original PSBT to a pj=
// endpoint via Go net/http (crypto/tls validates the cert chain on the
// default client). We exercise the round-trip via httptest.NewTLSServer
// (sender uses srv.Client() so the test cert is trusted) — proves the
// transport layer is wired without requiring a real CA-signed receiver.

func TestW119G2_SenderHTTPClient(t *testing.T) {
	// Use the same helpers the receiver tests use to build a real
	// FIX-65 receiver behind an httptest endpoint, then drive the
	// sender's SendPayjoinRequest path through it.
	rxw, recvAddr := payjoinReceiverWallet(t)
	// Sender wallet — fresh, fully funded.
	sxw := buildPayjoinSenderWalletForG2(t)
	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	// Spin up the FIX-65 receiver behind TLS so G24 https-only gate
	// is satisfied. The handler shape mirrors internal/rpc/payjoin.go.
	tlsSrv := w119StartReceiverTLS(t, rxw)
	defer tlsSrv.Close()

	res, err := sxw.SendPayjoinRequest(original, PayjoinSendOptions{
		Endpoint:                     tlsSrv.URL + "/payjoin",
		Version:                      "1",
		MaxAdditionalFeeContribution: 10_000,
		AdditionalFeeOutputIndex:     -1,
		HTTPClient:                   tlsSrv.Client(),
	})
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	if res.Fallback {
		t.Fatalf("expected sender to complete without fallback; reason=%q", res.FallbackReason)
	}
	if res.ReceiverStatus != 200 {
		t.Errorf("ReceiverStatus=%d, want 200", res.ReceiverStatus)
	}
}

// ── G3: TLS/HTTPS or .onion required ────────────────────────────────────────

func TestW119G3_TLSRequired(t *testing.T) {
	t.Skip("BUG-1/BUG-11: server.go:261 calls ListenAndServe (plaintext); no ListenAndServeTLS, no TLSConfig, no x509 cert plumbing — BIP-78 forbids http:// endpoints")
}

// ── G4: Original PSBT v0 deserialization receiver ────────────────────────────
//
// FIX-65 closure: garbage base64 → original-psbt-rejected. Empty body →
// original-psbt-rejected (separate failure-mode message but same code).
// Together they prove the receiver actually decodes the body rather than
// silently accepting anything.

func TestW119G4_OriginalPSBTDeserialize(t *testing.T) {
	w, _ := payjoinReceiverWallet(t)

	t.Run("garbage base64", func(t *testing.T) {
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: "not-a-real-psbt",
			Version:            "1",
		})
		if perr == nil || perr.Code != PayjoinErrOriginalPSBTRejected {
			t.Fatalf("expected original-psbt-rejected, got %v", perr)
		}
	})
	t.Run("empty body", func(t *testing.T) {
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: "",
			Version:            "1",
		})
		if perr == nil || perr.Code != PayjoinErrOriginalPSBTRejected {
			t.Fatalf("expected original-psbt-rejected, got %v", perr)
		}
	})
}

// ── G5: Receiver validates Original PSBT ────────────────────────────────────
//
// FIX-65 closure: a PSBT that decodes but doesn't pay any receiver-owned
// EXTERNAL address triggers original-psbt-rejected per BIP-78 §"Receiver's
// original PSBT validation".

func TestW119G5_ReceiverValidatesPSBT(t *testing.T) {
	w, _ := payjoinReceiverWallet(t)

	// Build a PSBT that pays a stranger (not the receiver) — recv-output
	// scan finds nothing and we reject.
	strangerPk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xDD}, 20)...)
	senderPk := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0xAB}, 20)...)
	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xCC}, Index: 0},
		Sequence:         BIP125RBFSequence,
	})
	tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 100_000_000, PkScript: strangerPk})

	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	psbt.Inputs[0].WitnessUTXO = &wire.TxOut{
		Value:    200_000_000,
		PkScript: senderPk,
	}
	body, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("EncodeBase64: %v", err)
	}

	_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
		OriginalPSBTBase64: body,
		Version:            "1",
	})
	if perr == nil || perr.Code != PayjoinErrOriginalPSBTRejected {
		t.Fatalf("expected original-psbt-rejected (no recv-output match), got %v", perr)
	}
	// Sanity check that the message identifies the validation failure.
	if !strings.Contains(perr.Message, "external") {
		t.Errorf("error message %q should explain the recv-output check failed", perr.Message)
	}
}

// ── G6: Receiver identifies fee output ───────────────────────────────────────

func TestW119G6_ReceiverIdentifiesFeeOutput(t *testing.T) {
	t.Skip("BUG-17: no helper to identify the sender's fee-bearing output (additionalfeeoutputindex param or change-output heuristic) on a foreign PSBT")
}

// ── G7: Receiver adds own inputs (anti-fingerprinting) ───────────────────────
//
// FIX-65 closure: the proposal MUST contain exactly len(original.TxIn)+1
// inputs — the receiver's added contribution. Full UIH-1/UIH-2 selection
// is still deferred (G20 stays Skip), but the "adds an input at all" gate
// is closed here.

func TestW119G7_ReceiverAddsOwnInputs(t *testing.T) {
	w, recvAddr := payjoinReceiverWallet(t)
	body := payjoinReceiverOriginalPSBT(t, w, recvAddr, 50_000_000)

	resp, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
		OriginalPSBTBase64: body,
		Version:            "1",
	})
	if perr != nil {
		t.Fatalf("ProcessPayjoinRequest: %v", perr)
	}

	proposal, err := DecodePSBTBase64(resp)
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}
	if got, want := len(proposal.UnsignedTx.TxIn), 2; got != want {
		t.Errorf("proposal inputs = %d, want %d (1 sender + 1 receiver-added)", got, want)
	}
	// The receiver's added input is signed: PartialSigs non-empty.
	if got := len(proposal.Inputs[1].PartialSigs); got == 0 {
		t.Errorf("receiver input has no PartialSigs — anti-fingerprinting contribution unsigned")
	}
}

// ── G8: Receiver modifies sender output ──────────────────────────────────────

func TestW119G8_ReceiverModifiesSenderOutput(t *testing.T) {
	t.Skip("BUG-2: no proposal-PSBT builder that rewrites the sender's output amount to account for added receiver input value")
}

// ── G9: Receiver fee adjustment (max bound) ──────────────────────────────────
//
// FIX-65 closure (partial): the receiver MUST grow the receiver-paying
// output by EXACTLY the added input value, so the fee stays unchanged.
// The maxadditionalfeecontribution clamp (BUG-18) is still deferred —
// FIX-65 only opens the structural door — but the "fee is invariant"
// half is closed here.

func TestW119G9_ReceiverFeeAdjustment(t *testing.T) {
	w, recvAddr := payjoinReceiverWallet(t)
	const recvAmount = int64(50_000_000)
	body := payjoinReceiverOriginalPSBT(t, w, recvAddr, recvAmount)

	// Compute original-fee for the comparison.
	original, err := DecodePSBTBase64(body)
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

	resp, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
		OriginalPSBTBase64: body,
		Version:            "1",
	})
	if perr != nil {
		t.Fatalf("ProcessPayjoinRequest: %v", perr)
	}
	proposal, err := DecodePSBTBase64(resp)
	if err != nil {
		t.Fatalf("decode proposal: %v", err)
	}

	// Sum proposal inputs/outputs and verify the fee is identical to the
	// original (receiver added input value == receiver output growth).
	var propIn, propOut int64
	for _, in := range proposal.Inputs {
		if in.WitnessUTXO == nil {
			t.Fatalf("proposal input missing WitnessUTXO; cannot sum")
		}
		propIn += in.WitnessUTXO.Value
	}
	for _, out := range proposal.UnsignedTx.TxOut {
		propOut += out.Value
	}
	propFee := propIn - propOut
	if propFee != origFee {
		t.Errorf("proposal fee = %d, want %d (receiver MUST grow recv output by exactly the added input — fee invariant)",
			propFee, origFee)
	}
}

// ── G10: Sender anti-snoop: outputs preserved ───────────────────────────────
//
// FIX-66 closure: payjoinAntisnoopOutputsPreserved rejects proposals that
// drop or substitute more than one original output. We feed in two
// hand-crafted proposals — one with the legitimate "1 output substituted"
// shape, one with the malicious "2 outputs substituted" shape — and
// verify only the latter is rejected.

func TestW119G10_SenderAntisnoopOutputsPreserved(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript

	t.Run("happy: 1 substitution allowed", func(t *testing.T) {
		proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopOutputsPreserved(original, proposal); err != nil {
			t.Errorf("G10 should accept 1 substitution: %v", err)
		}
	})
	t.Run("malicious: 2 substitutions rejected", func(t *testing.T) {
		proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)
		proposal.UnsignedTx.TxOut[0].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x77}, 20)...)
		proposal.UnsignedTx.TxOut[1].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x99}, 20)...)
		if err := payjoinAntisnoopOutputsPreserved(original, proposal); err == nil {
			t.Error("G10 should reject when 2 original outputs are missing")
		}
	})
}

// ── G11: Sender anti-snoop: scriptSig types preserved ───────────────────────
//
// FIX-66 closure: payjoinAntisnoopScriptSigTypes catches a receiver that
// swaps the WitnessUTXO of a preserved input to a different pkScript
// (the P2WPKH→P2SH-P2WPKH fingerprinting attack).

func TestW119G11_SenderAntisnoopScriptSigTypes(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)

	t.Run("happy", func(t *testing.T) {
		if err := payjoinAntisnoopScriptSigTypes(original, proposal); err != nil {
			t.Errorf("G11 unexpected: %v", err)
		}
	})
	t.Run("malicious: P2WPKH → P2SH swap", func(t *testing.T) {
		mutated := w119SyntheticProposal(t, original, recvScript, 50_000_000)
		mutated.Inputs[0].WitnessUTXO = &wire.TxOut{
			Value:    200_000_000,
			PkScript: append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0xFF}, 20)...),
		}
		if err := payjoinAntisnoopScriptSigTypes(original, mutated); err == nil {
			t.Error("G11 should reject preserved-input script swap")
		}
	})
}

// ── G12: Sender anti-snoop: no new sender inputs ────────────────────────────
//
// FIX-66 closure: payjoinAntisnoopNoNewSenderInputs sweeps every NEW
// proposal input through an IsMine helper. A receiver inserting one of
// the sender's own UTXOs as a "contribution" is rejected.

func TestW119G12_SenderAntisnoopNoNewSenderInputs(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)

	alwaysFalse := func([]byte) bool { return false }
	if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, alwaysFalse); err != nil {
		t.Errorf("G12 happy path failed: %v", err)
	}
	// Mark the receiver-added input's pkScript as "mine" — fingerprinting
	// attempt → reject.
	senderPk := proposal.Inputs[1].WitnessUTXO.PkScript
	isOwn := func(s []byte) bool { return bytes.Equal(s, senderPk) }
	if err := payjoinAntisnoopNoNewSenderInputs(original, proposal, isOwn); err == nil {
		t.Error("G12 must reject sender-owned added input (fingerprinting)")
	}
}

// ── G13: Sender anti-snoop: max additional fee contribution ─────────────────
//
// FIX-66 closure: payjoinAntisnoopMaxFeeContribution enforces the sender's
// cap on proposal_fee - original_fee. Deltas above the cap reject;
// negative deltas (receiver shouldered some fee) always accepted.

func TestW119G13_SenderAntisnoopMaxFeeContribution(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript

	t.Run("delta zero, cap zero — accept", func(t *testing.T) {
		proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)
		if err := payjoinAntisnoopMaxFeeContribution(original, proposal, 0); err != nil {
			t.Errorf("G13 unexpected: %v", err)
		}
	})
	t.Run("delta 1000, cap 500 — reject", func(t *testing.T) {
		proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)
		proposal.UnsignedTx.TxOut[1].Value -= 1000
		if err := payjoinAntisnoopMaxFeeContribution(original, proposal, 500); err == nil {
			t.Error("G13 must reject when fee delta > cap")
		}
	})
}

// ── G14: Sender anti-snoop: disableoutputsubstitution ───────────────────────
//
// FIX-66 closure: payjoinAntisnoopDisableOutputSubstitution is the strict
// pjos=1 variant of G10 — even 1 script substitution is rejected.

func TestW119G14_SenderAntisnoopDisableOutputSubstitution(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)

	if err := payjoinAntisnoopDisableOutputSubstitution(original, proposal); err != nil {
		t.Errorf("G14 happy: %v", err)
	}
	// Mutate ONE script — must reject.
	mutated := w119SyntheticProposal(t, original, recvScript, 50_000_000)
	mutated.UnsignedTx.TxOut[0].PkScript = append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x99}, 20)...)
	if err := payjoinAntisnoopDisableOutputSubstitution(original, mutated); err == nil {
		t.Error("G14 must reject any output substitution under pjos=1")
	}
}

// ── G15: Sender anti-snoop: min-fee-rate ────────────────────────────────────
//
// FIX-66 closure: payjoinAntisnoopMinFeeRate rejects proposals whose
// effective feerate falls below the sender-supplied minimum.

func TestW119G15_SenderAntisnoopMinFeeRate(t *testing.T) {
	original := w119SyntheticOriginal(t)
	recvScript := original.UnsignedTx.TxOut[0].PkScript
	proposal := w119SyntheticProposal(t, original, recvScript, 50_000_000)

	// Synthetic proposal feerate ≈ 5 sat/vB; min=100 should reject.
	if err := payjoinAntisnoopMinFeeRate(proposal, 100.0); err == nil {
		t.Error("G15 must reject when proposal feerate < min")
	}
	// minFeeRate=0 is documented no-op.
	if err := payjoinAntisnoopMinFeeRate(proposal, 0); err != nil {
		t.Errorf("G15 with min=0 should be no-op: %v", err)
	}
}

// ── G16: BIP-78 query params parsed ──────────────────────────────────────────

func TestW119G16_QueryParamsParsed(t *testing.T) {
	t.Skip("BUG-6: no recognition of v / additionalfeeoutputindex / maxadditionalfeecontribution / disableoutputsubstitution / minfeerate query params on the PayJoin POST URL")
}

// ── G17: Receiver error responses (4 BIP-78 codes) ──────────────────────────
//
// FIX-65 closure: all four BIP-78 errorCodes are emittable from the
// wallet-side ProcessPayjoinRequest. The HTTP-status mapping is covered
// by rpc/payjoin_receiver_test.go (TestPayjoinReceiver*); this test
// proves the wallet layer drives each branch correctly.

func TestW119G17_ReceiverErrorResponses(t *testing.T) {
	t.Run("version-unsupported", func(t *testing.T) {
		w, recvAddr := payjoinReceiverWallet(t)
		body := payjoinReceiverOriginalPSBT(t, w, recvAddr, 50_000_000)
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: body,
			Version:            "2",
		})
		if perr == nil || perr.Code != PayjoinErrVersionUnsupported {
			t.Fatalf("expected version-unsupported, got %v", perr)
		}
	})
	t.Run("original-psbt-rejected", func(t *testing.T) {
		w, _ := payjoinReceiverWallet(t)
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: "garbage",
			Version:            "1",
		})
		if perr == nil || perr.Code != PayjoinErrOriginalPSBTRejected {
			t.Fatalf("expected original-psbt-rejected, got %v", perr)
		}
	})
	t.Run("not-enough-money", func(t *testing.T) {
		// Build wallet with NO UTXOs.
		w := NewWallet(WalletConfig{
			DataDir:     t.TempDir(),
			Network:     address.Regtest,
			ChainParams: consensus.RegtestParams(),
			AddressType: AddressTypeP2WPKH,
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
		body := payjoinReceiverOriginalPSBT(t, w, recvAddr, 50_000_000)
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: body,
			Version:            "1",
		})
		if perr == nil || perr.Code != PayjoinErrNotEnoughMoney {
			t.Fatalf("expected not-enough-money, got %v", perr)
		}
	})
	t.Run("unavailable (wallet locked)", func(t *testing.T) {
		w, recvAddr := payjoinReceiverWallet(t)
		// Encrypt + lock so the wallet is in the unavailable state.
		if err := w.EncryptWallet("test-passphrase"); err != nil {
			t.Fatalf("EncryptWallet: %v", err)
		}
		body := payjoinReceiverOriginalPSBT(t, w, recvAddr, 50_000_000)
		_, perr := w.ProcessPayjoinRequest(&PayjoinRequest{
			OriginalPSBTBase64: body,
			Version:            "1",
		})
		if perr == nil || perr.Code != PayjoinErrUnavailable {
			t.Fatalf("expected unavailable (wallet locked), got %v", perr)
		}
	})
}

// ── G18: Receiver TTL on offered payjoin ────────────────────────────────────

func TestW119G18_ReceiverTTL(t *testing.T) {
	t.Skip("BUG-10: no TTL on offered PayJoin proposals; receiver has no per-session state at all")
}

// ── G19: Receiver no-double-spending guard ──────────────────────────────────

func TestW119G19_ReceiverNoDoubleSpending(t *testing.T) {
	t.Skip("BUG-9: no outpoint tracker across in-flight PayJoin proposals; concurrent offers for the same UTXO set risk a self-double-spend")
}

// ── G20: Receiver UTXO selection (UIH-1/UIH-2) ──────────────────────────────

func TestW119G20_ReceiverUTXOSelection(t *testing.T) {
	t.Skip("BUG-8: coinselection.go has no UIH-1/UIH-2 aware variant; receiver-side selection that preserves payment/change ambiguity is unimplemented")
}

// ── G21: Receiver PSBT v=1 header param ─────────────────────────────────────

func TestW119G21_PSBTVersionHeaderParam(t *testing.T) {
	t.Skip("BUG-14: receiver lacks the v=1 query-param enforcement and the version-unsupported error path for v!=1")
}

// ── G22: Sender retry / fallback to original ────────────────────────────────
//
// FIX-66 closure: SendPayjoinRequest falls back to the Original PSBT on
// any transport error or non-200 status. We point at an httptest server
// that always returns 503; the result MUST have Fallback=true and the
// FinalPSBTBase64 MUST still be the Original (caller can broadcast it).

func TestW119G22_SenderRetryFallback(t *testing.T) {
	sxw := buildPayjoinSenderWalletForG2(t)
	_, recvAddr := payjoinReceiverWallet(t)
	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	srv := w119Start503Server(t)
	defer srv.Close()

	res, err := sxw.SendPayjoinRequest(original, PayjoinSendOptions{
		Endpoint:                     srv.URL + "/payjoin",
		Version:                      "1",
		MaxAdditionalFeeContribution: 1000,
		AdditionalFeeOutputIndex:     -1,
		HTTPClient:                   srv.Client(),
	})
	if err != nil {
		t.Fatalf("SendPayjoinRequest: %v", err)
	}
	if !res.Fallback {
		t.Fatal("G22 expected Fallback=true on 503")
	}
	if res.FinalPSBTBase64 == "" {
		t.Error("G22: Original PSBT must be preserved on fallback so caller can broadcast")
	}
	if res.FinalTx != nil {
		t.Error("G22: FinalTx should be nil on fallback")
	}
}

// ── G23: Receiver request validation (Content-Type, Length) ─────────────────

func TestW119G23_ReceiverRequestValidation(t *testing.T) {
	t.Skip("BUG-13: no Content-Type / Content-Length validation for inbound PayJoin POST bodies")
}

// ── G24: HTTPS cert validation (sender) ─────────────────────────────────────
//
// FIX-66 closure: validatePayjoinEndpoint rejects plain http:// to a
// non-onion host. crypto/tls's default RoundTripper validates the cert
// chain via the system trust store — we test the endpoint gate here
// (the TLS gate is exercised live in TestW119G2_SenderHTTPClient).

func TestW119G24_HTTPSCertValidation(t *testing.T) {
	cases := []struct {
		endpoint string
		ok       bool
	}{
		{"https://merchant.example.com/payjoin", true},
		{"http://abc123.onion/payjoin", true},
		{"http://merchant.example.com/payjoin", false},
		{"ftp://merchant.example.com/payjoin", false},
		{"", false},
	}
	for _, tc := range cases {
		_, err := validatePayjoinEndpoint(tc.endpoint)
		if (err == nil) != tc.ok {
			t.Errorf("validatePayjoinEndpoint(%q) err=%v, want ok=%v", tc.endpoint, err, tc.ok)
		}
	}
}

// ── G25: Tor onion service support ──────────────────────────────────────────

func TestW119G25_TorOnionServiceSupport(t *testing.T) {
	t.Skip("BUG-12: blockbrew has p2p-side Tor v3 awareness (addrv2.go) but no inbound hidden-service hosting for the PayJoin endpoint")
}

// ── G26: getpayjoinrequest RPC ──────────────────────────────────────────────
//
// FIX-66 closure: dispatch in internal/rpc/server.go now routes
// "getpayjoinrequest" to handleGetPayjoinRequest. The RPC layer's own
// test (internal/rpc/payjoin_sender_test.go::TestRPCGetPayjoinRequest)
// exercises the full dispatch + result shape; we assert here that the
// wallet-side public API the RPC depends on (BuildPayjoinOriginalPSBT)
// is callable from this package and produces a parseable base64 PSBT.

func TestW119G26_GetPayjoinRequestRPC(t *testing.T) {
	sxw := buildPayjoinSenderWalletForG2(t)
	_, recvAddr := payjoinReceiverWallet(t)
	psbt, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	b64, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("EncodeBase64: %v", err)
	}
	if b64 == "" {
		t.Fatal("EncodeBase64 returned empty")
	}
	// Sanity: round-trip the base64 back through DecodePSBTBase64.
	if _, err := DecodePSBTBase64(b64); err != nil {
		t.Errorf("getpayjoinrequest PSBT does not round-trip: %v", err)
	}
}

// ── G27: sendpayjoinrequest RPC ─────────────────────────────────────────────
//
// FIX-66 closure: dispatch in internal/rpc/server.go now routes
// "sendpayjoinrequest" to handleSendPayjoinRequest. The wallet-side
// helper SendPayjoinRequest is exercised in TestW119G2 + TestW119G22;
// here we assert that the helper exists and returns a typed result.

func TestW119G27_SendPayjoinRequestRPC(t *testing.T) {
	sxw := buildPayjoinSenderWalletForG2(t)
	_, recvAddr := payjoinReceiverWallet(t)
	original, err := sxw.BuildPayjoinOriginalPSBT(recvAddr, 50_000_000, 5.0)
	if err != nil {
		t.Fatalf("BuildPayjoinOriginalPSBT: %v", err)
	}
	// Endpoint validation rejects bad scheme — proves the helper is
	// wired and surfaces a normal Go error (NOT a panic).
	_, sendErr := sxw.SendPayjoinRequest(original, PayjoinSendOptions{
		Endpoint: "http://merchant.example.com/payjoin",
	})
	if sendErr == nil {
		t.Error("expected error on plain-http endpoint (G24)")
	}
}

// ── G28: BIP-21 URI parser `pj=` ─────────────────────────────────────────────
//
// FIX-62 closure (BUG-5 — partial): wallet.ParseBIP21 now recognises and
// percent-decodes the `pj=` PayJoin endpoint from a bitcoin: URI. The
// receiver- and sender-side BIP-78 protocol gates (G1–G27, G30) are still
// MISSING ENTIRELY — but the URI plumbing they would consume is now in place,
// so a future FIX wave that wires PayJoin only has to hand a string here, not
// implement a parser from scratch.

func TestW119G28_BIP21URIParserPj(t *testing.T) {
	// Canonical receiver-published URI: address + amount + pj endpoint.
	// The PJ endpoint is percent-encoded as a URI MUST be when nested in a
	// query value (`?` and `&` would otherwise terminate parsing).
	const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	const pjURL = "https://merchant.example.com/payjoin?session=abc123"
	encoded := "https%3A%2F%2Fmerchant.example.com%2Fpayjoin%3Fsession%3Dabc123"
	uri := "bitcoin:" + addr + "?amount=0.05&pj=" + encoded

	parsed, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseBIP21(%q) error: %v", uri, err)
	}
	if parsed.PJ == nil {
		t.Fatal("BUG-5 fix incomplete: PJ field is nil after parse")
	}
	if *parsed.PJ != pjURL {
		t.Errorf("PJ = %q, want %q (percent-decoded)", *parsed.PJ, pjURL)
	}
	if parsed.Amount == nil || *parsed.Amount != 5_000_000 {
		t.Errorf("Amount = %v, want 5_000_000 sats (0.05 BTC)", parsed.Amount)
	}
}

// ── G29: BIP-21 URI parser `pjos=` ──────────────────────────────────────────
//
// FIX-62 closure: pjos=0 and pjos=1 both parse; anything else is rejected as
// ErrMalformedQuery. The Bip21URI.PJOS pointer is nil when absent so the
// PayJoin sender can apply BIP-78's default (output substitution allowed).

func TestW119G29_BIP21URIParserPjos(t *testing.T) {
	const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	const pjEnc = "https%3A%2F%2Fmerchant.example.com%2Fpayjoin"

	t.Run("pjos=0 → false (substitution allowed)", func(t *testing.T) {
		u, err := ParseBIP21("bitcoin:"+addr+"?pj="+pjEnc+"&pjos=0", address.Mainnet)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if u.PJOS == nil {
			t.Fatal("PJOS should be set when pjos= is present")
		}
		if *u.PJOS != false {
			t.Errorf("PJOS = %v, want false (pjos=0)", *u.PJOS)
		}
	})

	t.Run("pjos=1 → true (substitution disabled)", func(t *testing.T) {
		u, err := ParseBIP21("bitcoin:"+addr+"?pj="+pjEnc+"&pjos=1", address.Mainnet)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if u.PJOS == nil {
			t.Fatal("PJOS should be set when pjos= is present")
		}
		if *u.PJOS != true {
			t.Errorf("PJOS = %v, want true (pjos=1)", *u.PJOS)
		}
	})

	t.Run("pjos absent → PJOS nil (caller applies default)", func(t *testing.T) {
		u, err := ParseBIP21("bitcoin:"+addr+"?pj="+pjEnc, address.Mainnet)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if u.PJOS != nil {
			t.Errorf("PJOS = %v, want nil when pjos= absent", *u.PJOS)
		}
	})

	t.Run("pjos=2 → ErrMalformedQuery (per BIP-78: only 0/1)", func(t *testing.T) {
		_, err := ParseBIP21("bitcoin:"+addr+"?pj="+pjEnc+"&pjos=2", address.Mainnet)
		if !errors.Is(err, ErrMalformedQuery) {
			t.Errorf("err = %v, want ErrMalformedQuery", err)
		}
	})
}

// ── G30: Receiver replay protection (PSBT-id) ───────────────────────────────

func TestW119G30_ReceiverReplayProtection(t *testing.T) {
	t.Skip("BUG-10: no replay cache keyed on sha256(Original PSBT bytes); receiver cannot detect a sender retry vs a fresh proposal")
}
