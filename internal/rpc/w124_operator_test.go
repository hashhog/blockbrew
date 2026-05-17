// Package rpc W124 operator-experience audit tests — RPC-side gates.
//
// Wave W124 (DISCOVERY only — no production code changes). RPC-side mirror
// of the audit in cmd/blockbrew/w124_operator_test.go. See
// audit/w124_operator_experience.md for the full writeup.
//
// Three RPC bugs live here:
//
//   - BUG-3 (G10): `stop` RPC doesn't stop the daemon.
//   - BUG-14:      no -rpcauth=<userpw> HMAC support.
//   - BUG-15:      no -rpcallowip=<subnet> CIDR ACL.
//
// All are xfail (t.Skip("BUG-N: ...")).
package rpc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// w124ReadServerGo reads the package-level server.go file (relative to this
// test file's directory). Used for structural pins.
func w124ReadServerGo(t *testing.T) string {
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

// ────────────────────────────────────────────────────────────────────────
// G10 — BUG-3: `stop` RPC does not signal the daemon process.
// ────────────────────────────────────────────────────────────────────────
//
// Live test (RPC-side flavour): build a Server with a no-op httpServer,
// call handleStop, and confirm:
//
//   - the call returns success (matches Core wire contract);
//   - s.shutdown is closed (RPC HTTP server gets the message);
//   - NO process-level signal was raised — there is no main-level hook
//     to fire from inside the RPC package, so the daemon stays up.
//
// The "stays up" half is implicit (we can't easily check process state
// from a unit test), so the audit relies on the structural pin in
// cmd/blockbrew/w124_operator_test.go::TestW124_G10_StopRPCDoesNotStopDaemon_BUG3.
// Here we record the RPC side: handleStop's effect ends at s.Stop().

func TestW124_G10RPC_HandleStopOnlyClosesShutdownChan_BUG3(t *testing.T) {
	s := NewServer(RPCConfig{
		ListenAddr: "127.0.0.1:0",
		Username:   "u",
		Password:   "p",
	})
	// Sanity: pre-call, shutdown chan is open.
	select {
	case <-s.shutdown:
		t.Fatal("shutdown chan already closed before handleStop")
	default:
	}

	// Call handleStop and verify the dispatched goroutine eventually closes
	// the shutdown channel without doing anything else daemon-level.
	// handleStop sleeps 100ms then calls s.Stop(); we wait up to 1s.
	if _, err := s.handleStop(); err != nil {
		t.Fatalf("handleStop returned RPCError: %v", err)
	}

	// We don't have a public httpServer here; Stop() bails on nil httpServer
	// (server.go:349 nil-guard). It does close(s.shutdown) unconditionally.
	// Wait for that close.
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-s.shutdown:
		// expected
	case <-timer.C:
		t.Fatal("s.shutdown was not closed within 2s of handleStop")
	}

	// The structural pin lives in cmd/blockbrew; here we just record that
	// the RPC-side effect is bounded.
	t.Skip("BUG-3 (P0): handleStop closes s.shutdown and stops the HTTP server. " +
		"It does NOT signal the daemon process — main.go:1526 sigChan is " +
		"untouched. After this call returns 'stopping' to the client, the " +
		"daemon stays up indefinitely. Fix: handleStop must syscall.Kill " +
		"(os.Getpid(), syscall.SIGTERM) so main's signal handler runs the " +
		"full shutdown sequence. See cmd/blockbrew/w124_operator_test.go::" +
		"TestW124_G10_StopRPCDoesNotStopDaemon_BUG3 for the cmd-side pin.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-14: no -rpcauth=<userpw> HMAC-SHA256 support.
// ────────────────────────────────────────────────────────────────────────

func TestW124_NoRPCAuthHMAC_BUG14(t *testing.T) {
	// Structural pin: RPCConfig has no RPCAuth slice / HMAC field; checkAuth
	// does not iterate over HMAC entries. Read server.go and verify.
	src := w124ReadServerGo(t)
	if strings.Contains(src, "RPCAuth") || strings.Contains(src, "rpcauth") {
		// Look only at non-comment lines.
		lines := []string{}
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if strings.Contains(trimmed, "RPCAuth") || strings.Contains(trimmed, "rpcauth") {
				lines = append(lines, trimmed)
			}
		}
		if len(lines) > 0 {
			t.Fatalf("BUG-14 may be fixed: server.go has rpcauth in production code:\n%s",
				strings.Join(lines, "\n"))
		}
	}
	// Live evidence: with no RPCAuth wired, the only paths through checkAuth
	// are (a) empty username + empty password + empty cookie → "open", (b)
	// explicit Username/Password match, (c) cookie. There is no HMAC path.
	s := NewServer(RPCConfig{Username: "u", Password: "p"})
	req := httptest.NewRequest("POST", "/", nil)
	req.SetBasicAuth("u", "p")
	if !s.checkAuth(req) {
		t.Fatal("expected plain-Basic credentials to pass checkAuth — wiring changed?")
	}
	// Confirm there's no HMAC-based fast path: feeding a salted-HMAC-style
	// string in place of the password should fail with the same plain auth.
	hmacReq := httptest.NewRequest("POST", "/", nil)
	hmacReq.SetBasicAuth("u", "$2b$10$abc.def.hmac.salt.style.hash")
	if s.checkAuth(hmacReq) {
		t.Fatal("unexpected: HMAC-shaped pw passed checkAuth as plain — wiring changed?")
	}
	t.Skip("BUG-14 (P1 MISSING): RPCConfig has no RPCAuth field; server.go:checkAuth " +
		"has no HMAC-SHA256 path. Core's -rpcauth=<user>:<salt>$<hash> keeps the " +
		"password off disk; blockbrew only supports plaintext -rpcuser/-rpcpassword " +
		"plus the per-process cookie. Fix: parse repeatable -rpcauth entries; add " +
		"HMAC-SHA256 check inside checkAuth.")
}

// ────────────────────────────────────────────────────────────────────────
// BUG-15: no -rpcallowip CIDR ACL.
// ────────────────────────────────────────────────────────────────────────

func TestW124_NoRPCAllowIPACL_BUG15(t *testing.T) {
	src := w124ReadServerGo(t)
	if strings.Contains(src, "AllowIP") || strings.Contains(src, "rpcallowip") {
		lines := []string{}
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(trimmed, "AllowIP") || strings.Contains(trimmed, "rpcallowip") {
				lines = append(lines, trimmed)
			}
		}
		if len(lines) > 0 {
			t.Fatalf("BUG-15 may be fixed: server.go has rpcallowip in production code:\n%s",
				strings.Join(lines, "\n"))
		}
	}
	// Live evidence: with no ACL, a request from any RemoteAddr passes
	// checkAuth as long as Basic credentials match.
	s := NewServer(RPCConfig{Username: "u", Password: "p"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.1:54321" // public IPv4
	req.SetBasicAuth("u", "p")
	if !s.checkAuth(req) {
		t.Fatal("plain Basic from public IP should pass checkAuth (no ACL today)")
	}
	t.Skip("BUG-15 (P1 MISSING): no -rpcallowip CIDR ACL. checkAuth gates only " +
		"on Basic credentials; r.RemoteAddr is never inspected. An operator who " +
		"binds RPC to non-loopback (e.g. cross-host consensus diff) has no IP-level " +
		"defence. Fix: parse repeatable -rpcallowip, build CIDR list, gate checkAuth " +
		"on r.RemoteAddr ∈ allowed nets ∪ loopback.")
}
