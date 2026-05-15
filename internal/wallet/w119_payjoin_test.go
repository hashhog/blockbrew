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
	"testing"
)

// ── G1: Receiver HTTP endpoint POST /payjoin ─────────────────────────────────

func TestW119G1_ReceiverHTTPEndpoint(t *testing.T) {
	t.Skip("BUG-2: receiver-side PayJoin handler missing entirely; no /payjoin route in internal/rpc/server.go (mux only registers JSON-RPC at / and REST at /rest/*)")
}

// ── G2: Sender HTTP client POSTs Original PSBT ───────────────────────────────

func TestW119G2_SenderHTTPClient(t *testing.T) {
	t.Skip("BUG-1/BUG-3: no PayJoin sender; no HTTP client that POSTs base64 Original PSBT to a pj= endpoint")
}

// ── G3: TLS/HTTPS or .onion required ────────────────────────────────────────

func TestW119G3_TLSRequired(t *testing.T) {
	t.Skip("BUG-1/BUG-11: server.go:261 calls ListenAndServe (plaintext); no ListenAndServeTLS, no TLSConfig, no x509 cert plumbing — BIP-78 forbids http:// endpoints")
}

// ── G4: Original PSBT v0 deserialization receiver ────────────────────────────

func TestW119G4_OriginalPSBTDeserialize(t *testing.T) {
	t.Skip("BUG-2: DecodePSBT exists in psbt.go but is not called from any /payjoin handler; receiver path absent")
}

// ── G5: Receiver validates Original PSBT ────────────────────────────────────

func TestW119G5_ReceiverValidatesPSBT(t *testing.T) {
	t.Skip("BUG-2: validatePSBTInput exists (psbt.go:1327) but no receiver-side caller enforces BIP-78 'Original PSBT' rules (finalized non-receiver inputs, unsigned receiver inputs, sane fee, sender change identified)")
}

// ── G6: Receiver identifies fee output ───────────────────────────────────────

func TestW119G6_ReceiverIdentifiesFeeOutput(t *testing.T) {
	t.Skip("BUG-17: no helper to identify the sender's fee-bearing output (additionalfeeoutputindex param or change-output heuristic) on a foreign PSBT")
}

// ── G7: Receiver adds own inputs (anti-fingerprinting) ───────────────────────

func TestW119G7_ReceiverAddsOwnInputs(t *testing.T) {
	t.Skip("BUG-8: no UIH-1 / UIH-2 aware UTXO selector on receiver side; coinselection.go targets standard sends only")
}

// ── G8: Receiver modifies sender output ──────────────────────────────────────

func TestW119G8_ReceiverModifiesSenderOutput(t *testing.T) {
	t.Skip("BUG-2: no proposal-PSBT builder that rewrites the sender's output amount to account for added receiver input value")
}

// ── G9: Receiver fee adjustment (max bound) ──────────────────────────────────

func TestW119G9_ReceiverFeeAdjustment(t *testing.T) {
	t.Skip("BUG-18: no clamp at maxadditionalfeecontribution; receiver must not silently raise fee past sender's bound")
}

// ── G10: Sender anti-snoop: outputs preserved ───────────────────────────────

func TestW119G10_SenderAntisnoopOutputsPreserved(t *testing.T) {
	t.Skip("BUG-3: sender lacks the post-receive verifier that checks every original output (except the fee-output) is preserved in the proposal")
}

// ── G11: Sender anti-snoop: scriptSig types preserved ───────────────────────

func TestW119G11_SenderAntisnoopScriptSigTypes(t *testing.T) {
	t.Skip("BUG-3: sender lacks the verifier that checks per-input scriptSig/witness type matches (a receiver swap from p2wpkh→p2sh-p2wpkh would otherwise leak wallet shape)")
}

// ── G12: Sender anti-snoop: no new sender inputs ────────────────────────────

func TestW119G12_SenderAntisnoopNoNewSenderInputs(t *testing.T) {
	t.Skip("BUG-3: sender lacks the IsMine sweep over proposal-added inputs — a malicious receiver attempting fingerprinting by inserting one of the sender's own UTXOs would not be caught")
}

// ── G13: Sender anti-snoop: max additional fee contribution ─────────────────

func TestW119G13_SenderAntisnoopMaxFeeContribution(t *testing.T) {
	t.Skip("BUG-3/BUG-6: sender lacks max-additional-fee-contribution enforcement on proposal fee delta")
}

// ── G14: Sender anti-snoop: disableoutputsubstitution ───────────────────────

func TestW119G14_SenderAntisnoopDisableOutputSubstitution(t *testing.T) {
	t.Skip("BUG-3/BUG-6: sender lacks the pjos=1 → reject-script-change rule; output substitution must be gated by pjos")
}

// ── G15: Sender anti-snoop: min-fee-rate ────────────────────────────────────

func TestW119G15_SenderAntisnoopMinFeeRate(t *testing.T) {
	t.Skip("BUG-3/BUG-6: sender lacks minfeerate enforcement on the proposal's effective feerate")
}

// ── G16: BIP-78 query params parsed ──────────────────────────────────────────

func TestW119G16_QueryParamsParsed(t *testing.T) {
	t.Skip("BUG-6: no recognition of v / additionalfeeoutputindex / maxadditionalfeecontribution / disableoutputsubstitution / minfeerate query params on the PayJoin POST URL")
}

// ── G17: Receiver error responses (4 BIP-78 codes) ──────────────────────────

func TestW119G17_ReceiverErrorResponses(t *testing.T) {
	t.Skip("BUG-7: no JSON {errorCode, message} body emitter; the four BIP-78 codes (unavailable, not-enough-money, version-unsupported, original-psbt-rejected) are unmapped")
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

func TestW119G22_SenderRetryFallback(t *testing.T) {
	t.Skip("BUG-16: no fallback-to-original-PSBT logic on PayJoin failure (receiver unreachable, anti-snoop fail, timeout)")
}

// ── G23: Receiver request validation (Content-Type, Length) ─────────────────

func TestW119G23_ReceiverRequestValidation(t *testing.T) {
	t.Skip("BUG-13: no Content-Type / Content-Length validation for inbound PayJoin POST bodies")
}

// ── G24: HTTPS cert validation (sender) ─────────────────────────────────────

func TestW119G24_HTTPSCertValidation(t *testing.T) {
	t.Skip("BUG-15: no PayJoin sender means no cert-chain validation today; no --pj-pinned-cert opt-in flag for TOFU self-signed receivers")
}

// ── G25: Tor onion service support ──────────────────────────────────────────

func TestW119G25_TorOnionServiceSupport(t *testing.T) {
	t.Skip("BUG-12: blockbrew has p2p-side Tor v3 awareness (addrv2.go) but no inbound hidden-service hosting for the PayJoin endpoint")
}

// ── G26: getpayjoinrequest RPC ──────────────────────────────────────────────

func TestW119G26_GetPayjoinRequestRPC(t *testing.T) {
	t.Skip("BUG-4: no getpayjoinrequest method in server.go dispatch (dispatch lists ~80 methods, none for PayJoin)")
}

// ── G27: sendpayjoinrequest RPC ─────────────────────────────────────────────

func TestW119G27_SendPayjoinRequestRPC(t *testing.T) {
	t.Skip("BUG-4: no sendpayjoinrequest method in server.go dispatch")
}

// ── G28: BIP-21 URI parser `pj=` ─────────────────────────────────────────────

func TestW119G28_BIP21URIParserPj(t *testing.T) {
	t.Skip("BUG-5: no BIP-21 bitcoin: URI parser anywhere in blockbrew; grep for 'bitcoin:' returns zero non-test hits")
}

// ── G29: BIP-21 URI parser `pjos=` ──────────────────────────────────────────

func TestW119G29_BIP21URIParserPjos(t *testing.T) {
	t.Skip("BUG-5: no BIP-21 parser means pjos= disableoutputsubstitution flag is unparseable")
}

// ── G30: Receiver replay protection (PSBT-id) ───────────────────────────────

func TestW119G30_ReceiverReplayProtection(t *testing.T) {
	t.Skip("BUG-10: no replay cache keyed on sha256(Original PSBT bytes); receiver cannot detect a sender retry vs a fresh proposal")
}
