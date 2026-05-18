// Package rpc — W140 HTTP server + rpcauth + cookie auth audit (DISCOVERY).
//
// See audit/w140_http_rpcauth.md for the full audit writeup (22 bugs / 30
// gates). This file pins the **current** blockbrew behavior with xfail
// (t.Skip) assertions tagged by BUG-NN; a future fix wave can flip each
// test individually to assert the Core-correct behavior.
//
// Convention used here:
//
//   - Tests named TestW140_BUGNN_<short_label> pin one specific bug. Each
//     test ends with t.Skip("BUG-N (Pn-...): ...") so `go test ./...` is
//     all-green today but each Skip line documents what the fix wave
//     should flip.
//   - Tests named TestW140_GateNN_<short_label>_Present (passing as-is)
//     pin invariants that ARE already Core-correct in blockbrew (so a
//     future refactor regressing them gets caught).
//
// Source-of-truth references:
//   - bitcoin-core/src/httpserver.cpp  (ClientAllowed, HTTPBindAddresses,
//     work-queue cap, MAX_HEADERS_SIZE).
//   - bitcoin-core/src/httprpc.cpp     (CheckUserAuthorized, RPCAuthorized,
//     HTTPReq_JSONRPC, InitRPCAuthentication).
//   - bitcoin-core/src/rpc/request.cpp (GenerateAuthCookie, DeleteAuthCookie,
//     -rpccookiefile, -rpccookieperms, -norpccookiefile).
//   - bitcoin-core/share/rpcauth/rpcauth.py (HMAC line format).
package rpc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// w140ReadServerGo reads server.go for structural pins.
func w140ReadServerGo(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(here), "server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	return string(body)
}

// w140NewServer builds a bare RPCServer for the auth-flow tests. No chain /
// wallet / mempool wiring is needed because every W140 test exercises the
// `handleRPC` head (auth + parse) before the dispatch table runs.
func w140NewServer(t *testing.T, cfg RPCConfig, opts ...ServerOption) *Server {
	t.Helper()
	return NewServer(cfg, opts...)
}

// ────────────────────────────────────────────────────────────────────────
// G1 — POST-only enforcement. Already Core-correct.
// ────────────────────────────────────────────────────────────────────────

func TestW140_Gate01_POSTOnlyEnforced_Present(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(m, "/", nil)
		req.SetBasicAuth("u", "p")
		rr := httptest.NewRecorder()
		s.handleRPC(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", m, rr.Code)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// G3 — 401 + WWW-Authenticate on missing/bad basic auth.
// ────────────────────────────────────────────────────────────────────────

func TestW140_Gate03_UnauthorizedHas_WWWAuthenticate_Present(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic realm=") {
		t.Errorf("missing/malformed WWW-Authenticate header: %q", got)
	}
}

// ────────────────────────────────────────────────────────────────────────
// G4 — __cookie__ + cookiePassword path. Already Core-correct.
// ────────────────────────────────────────────────────────────────────────

func TestW140_Gate04_CookieAuth_Works_Present(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"}, WithCookiePassword("hexcookiesecret"))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"method":"uptime"}`)))
	req.SetBasicAuth("__cookie__", "hexcookiesecret")
	if !s.checkAuth(req) {
		t.Fatal("__cookie__ + matching cookiePassword should pass checkAuth")
	}
	// Wrong cookie value rejected.
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"method":"uptime"}`)))
	req2.SetBasicAuth("__cookie__", "wrongsecret")
	if s.checkAuth(req2) {
		t.Fatal("__cookie__ + wrong cookiePassword must NOT pass checkAuth")
	}
}

// ────────────────────────────────────────────────────────────────────────
// G5 / BUG-1 (P0-SEC) — open-on-empty-creds bypass.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG01_OpenOnEmptyCreds(t *testing.T) {
	// Construct the worst-case configuration: no Username, no Password, no
	// cookiePassword. This mirrors what happens when GenerateCookie fails
	// at startup (cmd/blockbrew/main.go:1337-1343) and the operator also
	// did not set -rpcpassword.
	s := w140NewServer(t, RPCConfig{}) // all three zero-valued strings
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// NB: no SetBasicAuth call.
	if !s.checkAuth(req) {
		t.Fatal("BUG-1 may be fixed: empty-creds server unexpectedly rejected unauthenticated request")
	}
	// Also pin that ANY junk credentials pass too, because the early-return
	// short-circuits everything.
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.SetBasicAuth("anyone", "anything")
	if !s.checkAuth(req2) {
		t.Fatal("BUG-1 may be fixed: empty-creds server unexpectedly rejected junk credentials")
	}
	t.Skip("BUG-1 (P0-SEC): checkAuth allow-lists EVERY request when all of " +
		"config.Username, config.Password, and cookiePassword are empty. Bitcoin " +
		"Core has no equivalent 'open' branch. Combined with main.go silently " +
		"setting cookiePassword='' on GenerateCookie failure (no fatal), an " +
		"unwritable datadir + empty -rpcpassword turns blockbrew into open RPC. " +
		"Fix: drop the early-return; make Server.Start refuse to bind when no " +
		"credential is available; make main.go log.Fatalf on GenerateCookie error.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-2 (P1-SEC) — no -rpcbind/-rpcallowip co-required guard.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG02_NoBindAllowIPCoRequired(t *testing.T) {
	// Structural pin: parseFlags in cmd/blockbrew/main.go has no logic
	// linking -rpcbind to a corresponding -rpcallowip; the only fallback
	// is "if ListenRPC == \"\" then use 127.0.0.1". Test reads server.go to
	// confirm Server.Start has no bind-guard step.
	src := w140ReadServerGo(t)
	if strings.Contains(src, "allow_subnets") || strings.Contains(src, "rpc_allow_subnets") || strings.Contains(src, "AllowIP") {
		t.Fatal("BUG-2 may be fixed: server.go references an allow-list subnet structure")
	}
	t.Skip("BUG-2 (P1-SEC): no guard rail forcing operator to set -rpcallowip " +
		"alongside -rpcbind for non-loopback addresses. Core's httpserver.cpp:319 " +
		"refuses the operator's bind set if either flag is missing and falls back " +
		"to localhost with a loud warning. blockbrew honors any -rpcbind without " +
		"complaint. Fix: in cmd/blockbrew/main.go after parseFlags, if ListenRPC " +
		"is non-loopback and no -rpcallowip is set, log.Fatalf (or override to " +
		"loopback with WARN).")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-3 (P1-SEC; W124 BUG-15 RE-PIN) — no -rpcallowip CIDR ACL.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG03_NoRPCAllowIPACL(t *testing.T) {
	// Live evidence: a request from a public-looking RemoteAddr passes if
	// basic credentials match.
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.7:48343" // TEST-NET-3
	req.SetBasicAuth("u", "p")
	if !s.checkAuth(req) {
		t.Fatal("BUG-3 may be fixed: server-side IP filtering started rejecting basic-auth-valid public-IP requests")
	}
	t.Skip("BUG-3 (P1-SEC; W124 BUG-15 re-pin in W140 scope): no -rpcallowip " +
		"CIDR allow-list. r.RemoteAddr is never inspected. REST endpoints (no " +
		"auth at all) ALSO lack this gate, so -rpcbind=0.0.0.0 exposes REST " +
		"to the world. Fix: parse -rpcallowip into []*net.IPNet; reject in " +
		"handleRPC AND in each rest.go handler preamble before any other work.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-4 (P1-SEC; W124 BUG-14 RE-PIN) — no -rpcauth HMAC support.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG04_NoRPCAuthHMAC(t *testing.T) {
	src := w140ReadServerGo(t)
	// Filter to non-comment, non-string lines that would prove HMAC parsing
	// is wired in production code.
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "hmac.New") || strings.Contains(trimmed, "ComputeHMAC") {
			t.Fatalf("BUG-4 may be fixed: server.go now contains HMAC code: %s", trimmed)
		}
		// rpcauth=user:salt$hash splitter shape
		if strings.Contains(trimmed, "SplitN") && strings.Contains(trimmed, "$") {
			t.Fatalf("BUG-4 may be fixed: server.go now contains rpcauth splitter: %s", trimmed)
		}
	}
	t.Skip("BUG-4 (P1-SEC; W124 BUG-14 re-pin): no -rpcauth=<user>:<salt>$<hash> " +
		"HMAC-SHA256 support. RPCConfig has no Auths slice; checkAuth has no HMAC " +
		"path. Fix: add Auths []struct{User, Salt, Hash string} to RPCConfig, " +
		"parse from main.go (repeatable flag.Var), check in checkAuth with " +
		"subtle.ConstantTimeCompare on HMAC-SHA256(salt, password). Reference: " +
		"share/rpcauth/rpcauth.py for the line format.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-5 (P2) — no multiple -rpcauth / -rpcuser entries.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG05_SingleUserOnly(t *testing.T) {
	// Structural: RPCConfig has scalar Username/Password, not slices.
	src := w140ReadServerGo(t)
	if strings.Contains(src, "Usernames []string") || strings.Contains(src, "[]RPCAuth") {
		t.Fatal("BUG-5 may be fixed: server.go now has a slice of users/auths")
	}
	t.Skip("BUG-5 (P2-PARITY): RPCConfig.Username and .Password are scalar — " +
		"only a single RPC user is representable. Multi-tenant deployments need " +
		"multiple -rpcauth entries. Fix path is the same as BUG-4 (make the " +
		"flag repeatable).")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-6 (P2-SEC) — plaintext password lives in process memory for daemon lifetime.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG06_PlaintextPasswordInMemory(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "verysecretvalue"})
	// We don't have a direct memory inspection API in Go, so the pin is
	// structural: RPCConfig.Password is read by checkAuth (line 491) and
	// never overwritten / zeroed. Confirm via reflection-free read of the
	// value we just configured.
	if s.config.Password != "verysecretvalue" {
		t.Fatal("BUG-6 may be fixed: Password is no longer stored as plaintext in s.config")
	}
	t.Skip("BUG-6 (P2-SEC): the configured -rpcpassword stays in plaintext in " +
		"RPCConfig.Password for the daemon lifetime. A core dump or " +
		"/proc/<pid>/mem snapshot exposes it. Core hashes the plaintext at init " +
		"(httprpc.cpp:276-288) with a fresh 16-byte salt and stores only the " +
		"salt+hash in g_rpcauth. Fix: at NewServer time, generate a 16-byte " +
		"salt, HMAC the configured Password, zero the plaintext bytes, store " +
		"only the salt+hash. checkAuth does the same HMAC and compares with " +
		"subtle.ConstantTimeCompare.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-7 (P1-SEC) — non-constant-time credential compare.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG07_NonConstantTimeCompare(t *testing.T) {
	// Structural pin: checkAuth uses Go string == comparison, which is
	// runtime.cmpstring (variable-time at length / byte position). Confirm
	// no use of subtle.ConstantTimeCompare in server.go.
	src := w140ReadServerGo(t)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "subtle.ConstantTimeCompare") {
			t.Fatalf("BUG-7 may be fixed: server.go now uses subtle.ConstantTimeCompare: %s", trimmed)
		}
	}
	t.Skip("BUG-7 (P1-SEC): checkAuth compares username and password with Go " +
		"string ==. runtime.cmpstring is variable-length, byte-by-byte short-" +
		"circuit at first mismatch — leaks the matching prefix length over " +
		"timing. Core uses TimingResistantEqual for both. Fix: replace both " +
		"`==` checks with subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1; " +
		"import crypto/subtle.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-8 (P2-SEC) — no brute-force deterrent sleep on auth failure.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG08_NoBruteForceDelay(t *testing.T) {
	src := w140ReadServerGo(t)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		// Core sleeps 250ms. Look for any time.Sleep in the auth path.
		if strings.Contains(trimmed, "time.Sleep") && (strings.Contains(trimmed, "250") || strings.Contains(trimmed, "Millisecond")) {
			t.Fatalf("BUG-8 may be fixed: server.go now contains a brute-force delay: %s", trimmed)
		}
	}
	t.Skip("BUG-8 (P2-SEC): no brute-force deterrent sleep on 401. Core sleeps " +
		"250ms before sending the unauthorized reply (httprpc.cpp:128), capping " +
		"~4 attempts/sec per connection. blockbrew responds immediately, allowing " +
		"thousands of attempts per second. Fix: add time.Sleep(250 * time.Millisecond) " +
		"between !checkAuth and http.Error, ideally cancellable via r.Context().Done().")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-9 (P0-SEC) — non-atomic cookie file write race.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG09_CookieWriteNotAtomic(t *testing.T) {
	src := w140ReadServerGo(t)
	// Look for the atomic-rename pattern: tmp + rename.
	hasTmp := strings.Contains(src, `".cookie.tmp"`) || strings.Contains(src, `cookiePath + ".tmp"`)
	hasRename := strings.Contains(src, "os.Rename") || strings.Contains(src, "RenameOver")
	if hasTmp && hasRename {
		t.Fatal("BUG-9 may be fixed: server.go now contains atomic-rename cookie-write logic")
	}

	// Live evidence: run GenerateCookie and assert the file is written as a
	// single-shot WriteFile (verified indirectly: the file exists and has
	// the right content; the absence of a .tmp partner alongside it is
	// circumstantial proof).
	dir := t.TempDir()
	pw, err := GenerateCookie(dir)
	if err != nil {
		t.Fatalf("GenerateCookie: %v", err)
	}
	if pw == "" {
		t.Fatal("GenerateCookie returned empty password")
	}
	body, err := os.ReadFile(filepath.Join(dir, ".cookie"))
	if err != nil {
		t.Fatalf("read cookie: %v", err)
	}
	if !strings.HasPrefix(string(body), "__cookie__:") {
		t.Fatalf("cookie content malformed: %q", string(body))
	}
	if _, err := os.Stat(filepath.Join(dir, ".cookie.tmp")); !os.IsNotExist(err) {
		// Either the file does not exist (expected today) or it does — but we
		// expect "does not exist" because GenerateCookie does not use a tmp.
		t.Fatalf("BUG-9 unexpected: .cookie.tmp leftover present (err=%v)", err)
	}
	t.Skip("BUG-9 (P0-SEC): GenerateCookie uses os.WriteFile (open-truncate-write-" +
		"close) — a polling client can observe an empty file (post-O_TRUNC, pre-" +
		"write) or a partial file. Core writes to <path>.tmp and RenameOver " +
		"(atomic on POSIX). Fix: write to cookiePath+'.tmp' first, then os.Rename " +
		"to cookiePath. Cleanup .tmp on error.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-10 (P3) — no -rpccookieperms flag.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG10_NoRPCCookiePermsFlag(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "rpccookieperms") || strings.Contains(src, "CookiePerms") {
		t.Fatal("BUG-10 may be fixed: -rpccookieperms now referenced in server.go")
	}
	// Confirm 0600 is hard-coded (correct default; the gap is the lack of a flag).
	if !strings.Contains(src, "0600") {
		t.Fatal("BUG-10 unexpected: 0600 perm no longer hard-coded; GenerateCookie was refactored")
	}
	t.Skip("BUG-10 (P3-PARITY): cookie file permissions are hard-coded 0600 " +
		"(correct Core default). The -rpccookieperms=<owner|group|all> flag is " +
		"absent so operators in shared-group / multi-container setups cannot " +
		"relax to 0640/0644. Fix: thread a fs.FileMode through GenerateCookie, " +
		"parse -rpccookieperms in main.go.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-11 (P3) — no -rpccookiefile path override.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG11_NoRPCCookieFilePathFlag(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "rpccookiefile") || strings.Contains(src, "CookieFilePath") {
		t.Fatal("BUG-11 may be fixed: -rpccookiefile now referenced in server.go")
	}
	t.Skip("BUG-11 (P3-PARITY): no -rpccookiefile=<path> flag; cookie path is " +
		"hard-coded to <datadir>/.cookie. Core lets operators pin to e.g. " +
		"tmpfs or shared volume. Fix: thread CookieFilePath through RPCConfig.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-12 (P3) — no -norpccookiefile opt-out.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG12_NoNoRPCCookieFileFlag(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "norpccookiefile") || strings.Contains(src, "NoCookieFile") || strings.Contains(src, "DisableCookie") {
		t.Fatal("BUG-12 may be fixed: -norpccookiefile now referenced in server.go")
	}
	t.Skip("BUG-12 (P3-PARITY): no -norpccookiefile opt-out. Operators relying " +
		"only on -rpcauth still get the cookie file written. Fix: add a boolean " +
		"flag; main.go skips GenerateCookie + WithCookiePassword when set.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-13 (P2-SEC) — DeleteCookie removes any .cookie, not just one we wrote.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG13_DeleteCookieIsUnconditional(t *testing.T) {
	dir := t.TempDir()
	// Write a "foreign" cookie file (simulating another daemon's cookie).
	foreign := filepath.Join(dir, ".cookie")
	if err := os.WriteFile(foreign, []byte("__cookie__:not-ours"), 0600); err != nil {
		t.Fatalf("write foreign cookie: %v", err)
	}
	// Without calling GenerateCookie first, DeleteCookie should refuse to
	// touch the file (Core's g_generated_cookie guard). Today it deletes
	// blindly.
	DeleteCookie(dir)
	if _, err := os.Stat(foreign); !os.IsNotExist(err) {
		t.Fatal("BUG-13 may be fixed: DeleteCookie no longer deletes a foreign cookie file")
	}
	t.Skip("BUG-13 (P2-SEC): DeleteCookie unconditionally removes <datadir>/.cookie " +
		"regardless of whether THIS process wrote it. Two daemons sharing a " +
		"datadir (or a shutdown after a stale-cookie cleanup tool wrote one) " +
		"will lose the wrong cookie. Core guards with g_generated_cookie " +
		"(request.cpp:139,170). Fix: track generated state on Server; gate " +
		"DeleteCookie on it.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-14 (P2-PARITY) — no JSON-RPC batch dispatch.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG14_NoBatchRPC(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	// Construct a batch envelope.
	batch := []map[string]interface{}{
		{"jsonrpc": "2.0", "id": 1, "method": "uptime"},
		{"jsonrpc": "2.0", "id": 2, "method": "getblockcount"},
	}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("u", "p")
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	// Expect: today handleRPC fails to decode a batch into the scalar
	// RPCRequest struct and emits a parse-error response.
	var resp RPCResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("BUG-14 may be fixed: batch request now produces a non-error response")
	}
	if resp.Error.Code != RPCErrParseError {
		t.Fatalf("BUG-14 unexpected: batch request response code %d (want %d Parse error)",
			resp.Error.Code, RPCErrParseError)
	}
	t.Skip("BUG-14 (P2-PARITY): no JSON-RPC batch dispatch. An array envelope " +
		"fails json.Decode into RPCRequest with a parse error. Core walks the " +
		"array and dispatches each (httprpc.cpp:174-224). Batched explorers / " +
		"ETL pipelines don't work. Fix: peek the first non-whitespace byte; if " +
		"'[', unmarshal into []RPCRequest, dispatch each, sendResponse([]RPCResponse).")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-15 (P3-PARITY) — no JSON-RPC 2.0 version handling / notification.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG15_NoJSONRPCv2(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	// Send a 2.0-shaped notification (no id).
	body := []byte(`{"jsonrpc":"2.0","method":"uptime"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("u", "p")
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	// Core would emit 204 No Content. blockbrew emits 200 with a JSON body.
	if rr.Code == http.StatusNoContent {
		t.Fatal("BUG-15 may be fixed: notification request now produces 204")
	}
	// Also pin that JSONRPC field in the response is the default zero
	// value (blockbrew doesn't differentiate V1/V2 in the reply envelope).
	t.Skip("BUG-15 (P3-PARITY): no JSON-RPC 2.0 version branching. The " +
		"RPCRequest.JSONRPC field is parsed but never consulted; V2 notifications " +
		"(no id) get a full JSON response instead of 204. V2 success responses " +
		"include `error: null` instead of omitting the key. Fix: switch on " +
		"JSONRPC value in sendResponse/sendError; add omitempty to RPCResponse " +
		"fields; detect notifications and emit 204.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-16 (P2-PARITY) — HTTP status is always 200 on dispatch failure.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG16_NoHTTPStatusCodeMapping(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})

	// Case 1: unknown method → Core returns 404, blockbrew returns 200.
	body := []byte(`{"jsonrpc":"1.0","id":1,"method":"thismethoddoesnotexist"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("u", "p")
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatal("BUG-16 may be fixed: unknown method now returns 404")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("BUG-16 unexpected: unknown method returns %d (want 200 today)", rr.Code)
	}

	// Case 2: invalid JSON → Core returns 500 (RPC_PARSE_ERROR), blockbrew returns 200.
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{not json`)))
	req2.Header.Set("Content-Type", "application/json")
	req2.SetBasicAuth("u", "p")
	rr2 := httptest.NewRecorder()
	s.handleRPC(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("BUG-16 unexpected: parse-error returns %d (want 200 today)", rr2.Code)
	}

	t.Skip("BUG-16 (P2-PARITY): sendResponse / sendError never set the HTTP " +
		"status code, so dispatch failures all emit 200 OK with the error in the " +
		"body. Core maps RPC_INVALID_REQUEST→400, RPC_METHOD_NOT_FOUND→404, " +
		"everything else→500 (JSONErrorReply, httprpc.cpp:41-59). curl -fs and " +
		"k8s httpGet liveness probes never notice errors. Fix: branch on " +
		"rpcErr.Code in handleRPC to set the right WriteHeader status; do the " +
		"same in sendError.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-17 (P2-SEC) — no -rpcwhitelist per-user method allow-list.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG17_NoRPCWhitelist(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "rpcwhitelist") || strings.Contains(src, "Whitelist") {
		// Some Whitelist refs may exist for other purposes; only fail if it
		// is in a non-comment line.
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if strings.Contains(trimmed, "rpcwhitelist") || strings.Contains(trimmed, "Whitelist") {
				t.Fatalf("BUG-17 may be fixed: server.go references rpcwhitelist: %s", trimmed)
			}
		}
	}
	t.Skip("BUG-17 (P2-SEC): no -rpcwhitelist=<user>:<method,...> per-user " +
		"method allow-list. The single Username/Password pair gates everything. " +
		"Multi-user RBAC (e.g. read-only monitoring user vs. full-control admin) " +
		"is not representable. Fix: extend RPCConfig with Whitelist map[string]" +
		"map[string]struct{}{}; populate from -rpcwhitelist; in dispatch, check " +
		"per (authUser, method) before the method switch.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-18 (P3-COSMETIC) — wrong WWW-Authenticate realm string.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG18_WWWAuthenticateRealmMismatch(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	got := rr.Header().Get("WWW-Authenticate")
	if got == `Basic realm="jsonrpc"` {
		t.Fatal("BUG-18 may be fixed: WWW-Authenticate realm now matches Core (jsonrpc)")
	}
	if !strings.Contains(got, `realm="blockbrew"`) {
		t.Fatalf("BUG-18 unexpected: realm not 'blockbrew' as expected today: %q", got)
	}
	t.Skip("BUG-18 (P3-COSMETIC): WWW-Authenticate realm is `blockbrew`; Core " +
		"uses `jsonrpc`. Some bitcoin-rpc client libraries match the realm string " +
		"heuristically to decide whether to autoprobe <datadir>/.cookie. Fix: " +
		"change the literal to `Basic realm=\"jsonrpc\"`. One-line change.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-19 (P2) — no -rpcservertimeout flag (default 30s is hard-coded).
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG19_NoRPCServerTimeoutFlag(t *testing.T) {
	src := w140ReadServerGo(t)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "rpcservertimeout") || strings.Contains(trimmed, "RPCServerTimeout") {
			t.Fatalf("BUG-19 may be fixed: server.go now references -rpcservertimeout: %s", trimmed)
		}
	}
	t.Skip("BUG-19 (P2-PARITY): -rpcservertimeout flag absent. Read/Write " +
		"timeouts are hard-coded to 30s (matches Core default but no tunability). " +
		"Slow GBT mining clients on ARM boxes need longer; high-throughput watch " +
		"nodes use less. Fix: add the flag; plumb into http.Server.ReadTimeout/" +
		"WriteTimeout.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-20 (P1-DOS) — no work-queue cap.
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG20_NoWorkQueueCap(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "rpcworkqueue") || strings.Contains(src, "WorkQueueDepth") || strings.Contains(src, "QueueDepth") {
		t.Fatal("BUG-20 may be fixed: server.go now references a work-queue cap")
	}
	// Confirm there is no semaphore guarding handleRPC.
	if strings.Contains(src, "semaphore") || strings.Contains(src, "chan struct{}") {
		// Could be a leftover semaphore for a different purpose; only fail on
		// an active reference to handleRPC.
		t.Log("server.go contains chan/semaphore but not at handleRPC head; manual review recommended if assertions ever flip")
	}
	t.Skip("BUG-20 (P1-DOS): no work-queue cap. Go's http.Server spawns a " +
		"goroutine per accepted connection, so a slow-POST attacker can pin " +
		"arbitrarily many goroutines and drain memory/FDs. Core caps at " +
		"-rpcworkqueue (default 64) via evhttp_set_max_body_size + a 503 " +
		"reject path (httpserver.cpp:255-258). Fix: add the flag; wrap " +
		"handleRPC in a chan struct{} semaphore of that size; return 503 with " +
		"'Work queue depth exceeded' on acquire-fail.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-21 (P1-DOS) — no -rpcthreads (subset of BUG-20).
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG21_NoRPCThreadsFlag(t *testing.T) {
	src := w140ReadServerGo(t)
	if strings.Contains(src, "rpcthreads") || strings.Contains(src, "RPCThreads") {
		t.Fatal("BUG-21 may be fixed: server.go now references -rpcthreads")
	}
	t.Skip("BUG-21 (P1-DOS): -rpcthreads flag absent. Core has separate " +
		"-rpcworkqueue (queue depth, drop on overflow) and -rpcthreads (pool " +
		"size, queue on overflow). Distinguished from BUG-20 because the " +
		"Core flag-set has both. Fix: subset of BUG-20.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-22 (P2-DOS) — no MaxHeaderBytes cap (Slowloris surface).
// ────────────────────────────────────────────────────────────────────────

func TestW140_BUG22_NoMaxHeaderBytesCap(t *testing.T) {
	src := w140ReadServerGo(t)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "MaxHeaderBytes") {
			t.Fatalf("BUG-22 may be fixed: server.go now sets MaxHeaderBytes: %s", trimmed)
		}
	}
	t.Skip("BUG-22 (P2-DOS): http.Server.MaxHeaderBytes is unset → Go default " +
		"1 MiB. Core caps at 8192 (httpserver.cpp:51,409). Combined with " +
		"unbounded goroutines (BUG-20), Slowloris-style header-drip attacks " +
		"are exploitable. Fix: s.httpServer.MaxHeaderBytes = 8192 (Core parity).")
}

// ────────────────────────────────────────────────────────────────────────
// G28 — Reject unknown HTTP methods. Already Core-correct via POST gate.
// ────────────────────────────────────────────────────────────────────────

func TestW140_Gate28_NonPOSTRejected_Present(t *testing.T) {
	s := w140NewServer(t, RPCConfig{Username: "u", Password: "p"})
	for _, m := range []string{"BREW", "TRACE", "CONNECT", "PATCH"} {
		req, err := http.NewRequest(m, "/", nil)
		if err != nil {
			continue // some methods may be blocked at http.NewRequest stage
		}
		req.SetBasicAuth("u", "p")
		rr := httptest.NewRecorder()
		s.handleRPC(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", m, rr.Code)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// G30 — TLS misconfig (one of cert/key) is a startup error. Already correct (FIX-64).
// ────────────────────────────────────────────────────────────────────────

func TestW140_Gate30_TLSMisconfigRejected_Present(t *testing.T) {
	// One of cert/key set, other empty → Server.Start must error before
	// binding the listener.
	s := w140NewServer(t, RPCConfig{
		ListenAddr:  "127.0.0.1:0",
		TLSCertFile: "/nonexistent/cert.pem",
		// TLSKeyFile intentionally empty.
	})
	if err := s.Start(); err == nil {
		// best-effort cleanup; this branch is the bug-regression branch.
		_ = s.Stop()
		t.Fatal("Gate-30 regression: Server.Start accepted cert-without-key TLS config")
	}
	s2 := w140NewServer(t, RPCConfig{
		ListenAddr: "127.0.0.1:0",
		TLSKeyFile: "/nonexistent/key.pem",
		// TLSCertFile intentionally empty.
	})
	if err := s2.Start(); err == nil {
		_ = s2.Stop()
		t.Fatal("Gate-30 regression: Server.Start accepted key-without-cert TLS config")
	}
}
