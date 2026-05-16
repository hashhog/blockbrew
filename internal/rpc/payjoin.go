// PayJoin (BIP-78) receiver HTTP route — `POST /payjoin`.
//
// Closes the HTTP-transport half of W119 BUG-2 / BUG-13 / BUG-17, layered
// on top of FIX-64's HTTPS termination support (W119 BUG-11). The receiver
// core lives in internal/wallet/payjoin.go; this file is the transport
// adapter: it parses query params + body, hands a typed PayjoinRequest to
// the wallet, and maps the four BIP-78 error codes to HTTP status codes.
//
// Sender-side (anti-snoop, retry, BIP-21 dispatch) is OUT OF SCOPE for
// FIX-65. This file is receiver-only.
//
// HTTP wire contract per BIP-78 §"Receive payjoin":
//
//   Request:
//     POST /payjoin?v=1[&additionalfeeoutputindex=N
//                      &maxadditionalfeecontribution=SATS
//                      &disableoutputsubstitution=BOOL
//                      &minfeerate=FLOAT]
//     Content-Type: text/plain
//     Body: base64-encoded Original PSBT (max 8 KiB; see PayjoinMaxBodyBytes)
//
//   Success:
//     200 OK
//     Content-Type: text/plain
//     Body: base64-encoded Payjoin Proposal PSBT
//
//   Failure:
//     <status> + Content-Type: application/json
//     Body: { "errorCode": "<bip-78-code>", "message": "..." }
//
// BIP-78 error → HTTP status mapping (the BIP does not pin these; we
// follow the payjoin.org reference implementation):
//
//   version-unsupported     → 415 Unsupported Media Type
//   original-psbt-rejected  → 400 Bad Request
//   not-enough-money        → 422 Unprocessable Entity (receiver fault,
//                              transient — sender SHOULD NOT retry)
//   unavailable             → 503 Service Unavailable (transient —
//                              sender MAY retry after backoff)
//
// Reference: bips/bip-0078.mediawiki §"Error responses"; payjoin.org Rust
// crate `payjoin::receiver::ResponseError`.

package rpc

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/wallet"
)

// payjoinPath is the canonical route. The BIP doesn't pin the path —
// it's whatever the receiver advertises in the `pj=` URI query — but
// `/payjoin` is the de-facto choice across implementations (payjoin.org,
// btcpayserver) and we standardise on it so blockbrew's published
// `pj=https://host/payjoin` URIs work out of the box.
const payjoinPath = "/payjoin"

// payjoinErrorBody is the BIP-78 JSON error shape. Top-level keys are
// `errorCode` (one of the four BIP-78 codes) and `message` (a free-form
// human-readable description for logs / UIs).
type payjoinErrorBody struct {
	ErrorCode string `json:"errorCode"`
	Message   string `json:"message"`
}

// handlePayjoin is the HTTP handler for POST /payjoin.
//
// Order of operations matches the BIP-78 §"Receive payjoin" pseudocode:
//   1. method/auth/content-type/content-length validation,
//   2. extract v= and other query params,
//   3. read the body (capped at PayjoinMaxBodyBytes),
//   4. dispatch into wallet.ProcessPayjoinRequest,
//   5. on success, write base64 proposal PSBT with Content-Type text/plain,
//   6. on PayjoinError, write the mapped HTTP status + JSON error body.
func (s *Server) handlePayjoin(w http.ResponseWriter, r *http.Request) {
	// ── (1) Method: only POST is meaningful for PayJoin ─────────────────
	if r.Method != http.MethodPost {
		s.writePayjoinError(w, http.StatusMethodNotAllowed, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrOriginalPSBTRejected),
			Message:   "only POST is supported on /payjoin",
		})
		return
	}

	// ── (1) AuthN reuses the existing JSON-RPC basic-auth path ──────────
	// PayJoin endpoints SHOULD be authenticated when run on a node that
	// also serves JSON-RPC; otherwise anyone reaching the listening port
	// could ping /payjoin. Operators that want public, no-auth PayJoin
	// (the spec's expected setup for merchant flows) leave Username +
	// Password + cookiePassword all empty — checkAuth then allows
	// everything through (server.go::checkAuth early-returns).
	if !s.checkAuth(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="blockbrew payjoin"`)
		s.writePayjoinError(w, http.StatusUnauthorized, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrUnavailable),
			Message:   "authentication required",
		})
		return
	}

	// ── (1) Content-Type — BIP-78 §"Receive payjoin": text/plain ────────
	// G23 closure: strict validation. We accept text/plain (the spec) and
	// also accept application/octet-stream (some early implementations
	// used it). An empty Content-Type is REJECTED (FIX-67 hardening —
	// previously we silently accepted it). Be lenient with charset
	// suffix: "text/plain; charset=utf-8" parses as text/plain.
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	// strip optional ";..." parameters
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "text/plain" && ct != "application/octet-stream" {
		s.writePayjoinError(w, http.StatusUnsupportedMediaType, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrVersionUnsupported),
			Message:   "Content-Type must be text/plain (got " + ct + ")",
		})
		return
	}

	// ── (1) Content-Length cap ──────────────────────────────────────────
	// G23 hardening: we treat NEGATIVE / UNSET ContentLength (-1) as a
	// hint to read defensively (the body LimitReader below still caps it
	// at PayjoinMaxBodyBytes). A POSITIVE ContentLength larger than the
	// cap is rejected upfront so we don't read N MB before noticing.
	// chunked-transfer-encoded requests have ContentLength=-1 and are
	// permitted as long as the actual body fits under the LimitReader.
	if r.ContentLength > wallet.PayjoinMaxBodyBytes {
		s.writePayjoinError(w, http.StatusBadRequest, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrOriginalPSBTRejected),
			Message:   "request body too large",
		})
		return
	}

	// ── (2) Query params: G16 / BIP-78 §"Send payjoin" ──────────────────
	// All optional params recognised; defaults match the BIP. v= is the
	// only one enforced at this layer (rejected with version-unsupported
	// when != "1"). The rest are forwarded to ProcessPayjoinRequest where
	// they shape the proposal builder.
	q := r.URL.Query()
	version := q.Get("v")
	addFeeIdx := payjoinParseIntQuery(q, "additionalfeeoutputindex", -1)
	maxAddFee := payjoinParseInt64Query(q, "maxadditionalfeecontribution", 0)
	disableSub := payjoinParseBoolQuery(q, "disableoutputsubstitution")
	minFeeRate := payjoinParseFloatQuery(q, "minfeerate", 0)

	// ── (3) Read body ───────────────────────────────────────────────────
	// LimitReader caps at PayjoinMaxBodyBytes+1 so we can detect overflow
	// (length > PayjoinMaxBodyBytes triggers the same error).
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, wallet.PayjoinMaxBodyBytes+1))
	if err != nil {
		s.writePayjoinError(w, http.StatusBadRequest, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrOriginalPSBTRejected),
			Message:   "failed to read body: " + err.Error(),
		})
		return
	}
	if len(bodyBytes) > wallet.PayjoinMaxBodyBytes {
		s.writePayjoinError(w, http.StatusBadRequest, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrOriginalPSBTRejected),
			Message:   "request body too large",
		})
		return
	}
	body := strings.TrimSpace(string(bodyBytes))

	// ── (4) Dispatch to wallet core ─────────────────────────────────────
	// PayJoin needs a wallet to find UTXOs and sign. URL pattern
	// /wallet/<name>/payjoin would extend later; FIX-65 only wires the
	// single-wallet default form (matches handlePayJoin -> /payjoin route).
	walletName := s.extractWalletName(r.URL.Path)
	wlt, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		// No wallet configured at all: report as "unavailable" — a
		// merchant who hasn't loaded a wallet yet returns 503 so the
		// sender retries later. The RPCError-to-PayJoin translation is
		// blunt by design; we never leak the JSON-RPC numeric code.
		s.writePayjoinError(w, http.StatusServiceUnavailable, payjoinErrorBody{
			ErrorCode: string(wallet.PayjoinErrUnavailable),
			Message:   "no wallet loaded",
		})
		return
	}

	resp, perr := wlt.ProcessPayjoinRequest(&wallet.PayjoinRequest{
		OriginalPSBTBase64:           body,
		Version:                      version,
		AdditionalFeeOutputIndex:     addFeeIdx,
		MaxAdditionalFeeContribution: maxAddFee,
		DisableOutputSubstitution:    disableSub,
		MinFeeRate:                   minFeeRate,
	})
	if perr != nil {
		// Map the BIP-78 errorCode to the HTTP status. The mapping table
		// matches payjoin.org's Rust reference; the comment block at the
		// top of this file documents the rationale.
		status := payjoinStatusFor(perr.Code)
		s.writePayjoinError(w, status, payjoinErrorBody{
			ErrorCode: string(perr.Code),
			Message:   perr.Message,
		})
		return
	}

	// ── (5) Success: text/plain base64 proposal PSBT ────────────────────
	// Per spec §"Receive payjoin": "The receiver returns the Payjoin
	// Proposal PSBT to the sender as a base64 encoded text/plain body".
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	if _, werr := io.WriteString(w, resp); werr != nil {
		// Body write failures are unrecoverable (header already sent).
		// Log them so operators can correlate with sender-side timeouts.
		log.Printf("PayJoin: write response failed: %v", werr)
	}
}

// payjoinStatusFor maps a BIP-78 errorCode to its HTTP status. Kept as a
// small switch so the mapping is greppable and a future change to the
// table is a one-place edit.
func payjoinStatusFor(code wallet.PayjoinErrorCode) int {
	switch code {
	case wallet.PayjoinErrVersionUnsupported:
		return http.StatusUnsupportedMediaType // 415
	case wallet.PayjoinErrOriginalPSBTRejected:
		return http.StatusBadRequest // 400
	case wallet.PayjoinErrNotEnoughMoney:
		return http.StatusUnprocessableEntity // 422
	case wallet.PayjoinErrUnavailable:
		return http.StatusServiceUnavailable // 503
	default:
		// Defensive default — any future PayjoinErrorCode that we don't
		// yet know about maps to 500. Easier to grep than to silently
		// fall back to one of the four spec codes.
		return http.StatusInternalServerError
	}
}

// writePayjoinError writes the BIP-78 JSON error body with the given
// HTTP status. Always sets Content-Type: application/json so the sender
// can distinguish an error response from a success (text/plain) without
// reading the body first.
func (s *Server) writePayjoinError(w http.ResponseWriter, status int, body payjoinErrorBody) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("PayJoin: failed to encode error body: %v", err)
	}
}

// payjoinParseIntQuery extracts a signed integer query param. Missing /
// invalid → defaultVal. Used for `additionalfeeoutputindex` whose
// default is -1 ("not specified").
func payjoinParseIntQuery(q map[string][]string, name string, defaultVal int) int {
	vs, ok := q[name]
	if !ok || len(vs) == 0 || vs[0] == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(vs[0])
	if err != nil {
		return defaultVal
	}
	return n
}

// payjoinParseInt64Query is the int64 variant for sat-denominated
// quantities like `maxadditionalfeecontribution`. Missing / invalid →
// defaultVal (typically 0).
func payjoinParseInt64Query(q map[string][]string, name string, defaultVal int64) int64 {
	vs, ok := q[name]
	if !ok || len(vs) == 0 || vs[0] == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(vs[0], 10, 64)
	if err != nil {
		return defaultVal
	}
	return n
}

// payjoinParseBoolQuery parses a query param into a boolean. BIP-78 is
// ambiguous about the exact spelling — we accept "true", "1", "yes" as
// true; everything else (including "0", "false", "no", "") as false.
// This mirrors payjoin.org's reference behavior.
func payjoinParseBoolQuery(q map[string][]string, name string) bool {
	vs, ok := q[name]
	if !ok || len(vs) == 0 {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(vs[0]))
	return v == "true" || v == "1" || v == "yes"
}

// payjoinParseFloatQuery parses a query param into a float (sat/vB for
// `minfeerate`). Missing / invalid → defaultVal.
func payjoinParseFloatQuery(q map[string][]string, name string, defaultVal float64) float64 {
	vs, ok := q[name]
	if !ok || len(vs) == 0 || vs[0] == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(vs[0], 64)
	if err != nil {
		return defaultVal
	}
	return f
}

// ProcessPayjoin is a typed wrapper around wallet.ProcessPayjoinRequest
// for non-HTTP callers (tests, future RPC dispatch). Translates the
// typed PayjoinError to a plain error using errors.Is/errors.As friendly
// semantics — callers that want the status mapping should use
// payjoinStatusFor on the unwrapped error.
func (s *Server) ProcessPayjoin(walletName string, req *wallet.PayjoinRequest) (string, error) {
	wlt, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return "", errors.New("no wallet loaded")
	}
	resp, perr := wlt.ProcessPayjoinRequest(req)
	if perr != nil {
		return "", perr
	}
	return resp, nil
}
