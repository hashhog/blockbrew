// Package rpc — security audit C2 (2026-10-30): default RPC credentials.
//
// blockbrew defaults -rpcuser to "blockbrew" and -rpcpassword to "". Before
// this fix checkAuth accepted "blockbrew:" (empty password) next to the
// cookie, so any local process, or a browser page via DNS rebinding, could
// drive every RPC without reading the 0600 .cookie file.
//
// Core (bitcoin-core/src/httprpc.cpp InitRPCAuthentication): with an empty
// -rpcpassword, auth is cookie-only and -rpcuser is ignored; a failed cookie
// write fails startup (GenerateAuthCookieResult::ERR -> return false).
package rpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const secDefaultCredsCookie = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// secDefaultCredsStatus sends an authenticated `uptime` call through the
// full handleRPC head and returns the HTTP status.
func secDefaultCredsStatus(t *testing.T, s *Server, user, pass string, setAuth bool) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"method":"uptime","params":[],"id":1}`)))
	if setAuth {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	return rr.Code
}

// The default login (rpcuser=blockbrew, empty rpcpassword) must not
// authenticate when a cookie exists: auth is cookie-only.
func TestSecDefaultCreds_EmptyPasswordDefaultUserRejected(t *testing.T) {
	s := NewServer(RPCConfig{Username: "blockbrew", Password: ""}, WithCookiePassword(secDefaultCredsCookie))
	if got := secDefaultCredsStatus(t, s, "blockbrew", "", true); got != http.StatusUnauthorized {
		t.Fatalf("blockbrew: (empty password) got HTTP %d, want 401 (cookie-only auth)", got)
	}
	// Any password for the default user is rejected too: there is no
	// rpcuser/rpcpassword pair in cookie-only mode.
	if got := secDefaultCredsStatus(t, s, "blockbrew", "x", true); got != http.StatusUnauthorized {
		t.Fatalf("blockbrew:x got HTTP %d, want 401", got)
	}
	// An empty user with an empty password must not match an empty
	// configured username either.
	s2 := NewServer(RPCConfig{Username: "", Password: ""}, WithCookiePassword(secDefaultCredsCookie))
	if got := secDefaultCredsStatus(t, s2, "", "", true); got != http.StatusUnauthorized {
		t.Fatalf(": (empty user and password) got HTTP %d, want 401", got)
	}
	if got := secDefaultCredsStatus(t, s, "", "", false); got != http.StatusUnauthorized {
		t.Fatalf("no Authorization header got HTTP %d, want 401", got)
	}
}

// With an empty password and no cookie (cookie write failed), nothing
// authenticates as the default user. Startup refuses this state
// (TestSecDefaultCreds_CookieWriteFailureFatalWithoutPassword); this pins
// the server side so it can never fall back to "blockbrew:".
func TestSecDefaultCreds_EmptyPasswordNoCookieRejectsDefaultUser(t *testing.T) {
	s := NewServer(RPCConfig{Username: "blockbrew", Password: ""})
	if got := secDefaultCredsStatus(t, s, "blockbrew", "", true); got != http.StatusUnauthorized {
		t.Fatalf("blockbrew: with no cookie got HTTP %d, want 401", got)
	}
}

// The cookie login still works in cookie-only mode.
func TestSecDefaultCreds_CookieLoginWorks(t *testing.T) {
	s := NewServer(RPCConfig{Username: "blockbrew", Password: ""}, WithCookiePassword(secDefaultCredsCookie))
	if got := secDefaultCredsStatus(t, s, "__cookie__", secDefaultCredsCookie, true); got != http.StatusOK {
		t.Fatalf("__cookie__:<cookie> got HTTP %d, want 200", got)
	}
	if got := secDefaultCredsStatus(t, s, "__cookie__", "wrong", true); got != http.StatusUnauthorized {
		t.Fatalf("__cookie__:wrong got HTTP %d, want 401", got)
	}
}

// An explicit rpcuser/rpcpassword still works, alongside the cookie.
func TestSecDefaultCreds_ExplicitUserPasswordWorks(t *testing.T) {
	s := NewServer(RPCConfig{Username: "alice", Password: "s3cret"}, WithCookiePassword(secDefaultCredsCookie))
	if got := secDefaultCredsStatus(t, s, "alice", "s3cret", true); got != http.StatusOK {
		t.Fatalf("alice:s3cret got HTTP %d, want 200", got)
	}
	if got := secDefaultCredsStatus(t, s, "__cookie__", secDefaultCredsCookie, true); got != http.StatusOK {
		t.Fatalf("__cookie__:<cookie> with explicit password configured got HTTP %d, want 200", got)
	}
	if got := secDefaultCredsStatus(t, s, "alice", "", true); got != http.StatusUnauthorized {
		t.Fatalf("alice: (empty password) got HTTP %d, want 401", got)
	}
	if got := secDefaultCredsStatus(t, s, "alice", "wrong", true); got != http.StatusUnauthorized {
		t.Fatalf("alice:wrong got HTTP %d, want 401", got)
	}
}
