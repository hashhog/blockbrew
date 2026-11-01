// Package rpc — security audit L7 (2026-10-30), companion to C2: with an
// empty -rpcpassword the cookie is the only credential, so a failed cookie
// write must stop startup instead of leaving RPC unreachable or open.
package rpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With no -rpcpassword the cookie is the only way in, so a failed cookie
// write must fail startup (Core: GenerateAuthCookieResult::ERR).
func TestSecDefaultCreds_CookieWriteFailureFatalWithoutPassword(t *testing.T) {
	// A datadir path that is a regular file: the cookie write fails.
	notDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	cookie, err := InitCookieAuth(notDir, "")
	if err == nil {
		t.Fatalf("InitCookieAuth with empty password and unwritable datadir returned cookie %q and no error; want a fatal error", cookie)
	}
	if !strings.Contains(err.Error(), "cookie") {
		t.Fatalf("error %q does not mention the cookie", err)
	}

	// With an explicit password the node stays reachable, so a failed
	// cookie write is not fatal.
	cookie, err = InitCookieAuth(notDir, "s3cret")
	if err != nil {
		t.Fatalf("InitCookieAuth with explicit password: unexpected error %v", err)
	}
	if cookie != "" {
		t.Fatalf("InitCookieAuth with failed write returned cookie %q, want empty", cookie)
	}

	// Writable datadir: cookie written and returned.
	dir := t.TempDir()
	cookie, err = InitCookieAuth(dir, "")
	if err != nil || cookie == "" {
		t.Fatalf("InitCookieAuth on writable datadir: cookie=%q err=%v", cookie, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, ".cookie"))
	if err != nil || string(body) != "__cookie__:"+cookie {
		t.Fatalf(".cookie content %q err=%v, want __cookie__:%s", body, err, cookie)
	}
}
