// Package rpc — TLS termination tests (W119 BUG / FIX-64).
//
// These tests exercise the optional HTTPS path added to Server.Start so
// regression in the cert/key plumbing surfaces before a release.  They
// generate an ephemeral self-signed ECDSA cert in-memory per test, write
// the cert + key to a tempdir, point an rpc.Server at the pair, and then
// open a real TCP connection through net/http with a permissive client
// (InsecureSkipVerify) so the cert chain check doesn't reject the
// disposable test cert.
//
// Three classes of behavior are covered:
//
//  1. HTTPS round-trip — server with valid cert/key serves a JSON-RPC
//     call over real TLS, the response decodes, and the connection
//     observed by the client is TLS (resp.TLS != nil).
//
//  2. HTTP backward compat — server with no TLS args still serves
//     unmodified plain HTTP (operators fronting blockbrew with
//     nginx/Tor for HTTPS termination must keep working).
//
//  3. Misconfiguration rejection — exactly one of cert/key set is a
//     startup error, and an invalid cert path is a startup error. The
//     server must never silently fall back to plaintext when the
//     operator's intent was HTTPS.
package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateSelfSignedCert creates a fresh ECDSA P-256 keypair, wraps it in
// a self-signed x509 cert valid for "127.0.0.1" and "localhost", writes
// cert + key as PEM files under dir, and returns (certPath, keyPath).
//
// Generating fresh per test avoids any shared on-disk state and keeps the
// test hermetic (no fixture files in the tree, no reliance on openssl).
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "blockbrew-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509 createcert: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("pem encode cert: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("close cert: %v", err)
	}

	keyPath = filepath.Join(dir, "key.pem")
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("pem encode key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("close key: %v", err)
	}

	return certPath, keyPath
}

// freePort asks the kernel for an ephemeral port and closes it. There is a
// tiny race between close and bind, but for in-process Go tests this is
// the common idiom (used by httptest.NewServer's listener under the hood).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ephemeral listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close ephemeral: %v", err)
	}
	return port
}

// waitReachable polls until a TCP connect succeeds, up to a few seconds.
// Server.Start binds the socket in a goroutine, so the test loop sometimes
// races with the first request; this avoids a flaky "connection refused".
func waitReachable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s not reachable within deadline", addr)
}

// TestRPCServerHTTPSRoundtrip — server with valid cert/key serves a real
// JSON-RPC POST over TLS, and the response decodes. Also asserts that the
// http.Response.TLS field is non-nil so we know we actually went over
// HTTPS (not some accidental plain-HTTP fallback that returns 200).
func TestRPCServerHTTPSRoundtrip(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr:  addr,
		TLSCertFile: certPath,
		TLSKeyFile:  keyPath,
		// No Username/Password → checkAuth allows the request through
		// (matches the existing test pattern in server_test.go).
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Stop() }()

	waitReachable(t, addr)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // self-signed test cert
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	body := []byte(`{"jsonrpc":"1.0","id":"tls-test","method":"uptime","params":[]}`)
	resp, err := client.Post(
		fmt.Sprintf("https://%s/", addr),
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		t.Fatalf("HTTPS POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		t.Fatalf("expected TLS response but resp.TLS is nil — server did not actually terminate HTTPS")
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(raw))
	}

	var decoded RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode RPC response: %v", err)
	}
	// uptime returns an int (seconds since startTime). We don't care about
	// the exact value, just that the call dispatched and returned without
	// an RPC-level error — proof the JSON-RPC path runs end-to-end over
	// TLS.
	if decoded.Error != nil {
		t.Fatalf("RPC error on HTTPS roundtrip: code=%d msg=%s", decoded.Error.Code, decoded.Error.Message)
	}
	if decoded.Result == nil {
		t.Fatalf("RPC result missing on HTTPS roundtrip")
	}
}

// TestRPCServerHTTPBackwardCompat — operators who don't pass any TLS args
// keep the legacy plain-HTTP path. This is the explicit backward-compat
// contract; the universal mainnet fleet currently relies on it (nginx /
// Tor terminate TLS in front of the daemon).
func TestRPCServerHTTPBackwardCompat(t *testing.T) {
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr: addr,
		// No TLS fields set → must fall through to plain HTTP.
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Stop() }()

	waitReachable(t, addr)

	client := &http.Client{Timeout: 5 * time.Second}
	body := []byte(`{"jsonrpc":"1.0","id":"plain","method":"uptime","params":[]}`)
	resp, err := client.Post(
		fmt.Sprintf("http://%s/", addr),
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		t.Fatalf("HTTP POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		t.Fatalf("expected plain HTTP but resp.TLS is non-nil (server upgraded to TLS unexpectedly)")
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(raw))
	}
}

// TestRPCServerTLSMismatchedCertWithoutKey — passing cert but not key is
// a startup error. The daemon must NOT silently fall through to plain
// HTTP when the operator clearly intended HTTPS — that would be the
// worst failure mode (the failure is invisible).
func TestRPCServerTLSMismatchedCertWithoutKey(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateSelfSignedCert(t, dir)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr:  addr,
		TLSCertFile: certPath,
		TLSKeyFile:  "", // intentionally unset
	})

	err := server.Start()
	if err == nil {
		_ = server.Stop()
		t.Fatalf("expected Start error for cert-without-key, got nil")
	}
	if !strings.Contains(err.Error(), "TLS misconfiguration") {
		t.Fatalf("expected TLS misconfiguration error, got: %v", err)
	}
}

// TestRPCServerTLSMismatchedKeyWithoutCert — the symmetric case: key set
// but cert empty must also be rejected.
func TestRPCServerTLSMismatchedKeyWithoutCert(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := generateSelfSignedCert(t, dir)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr:  addr,
		TLSCertFile: "",
		TLSKeyFile:  keyPath,
	})

	err := server.Start()
	if err == nil {
		_ = server.Stop()
		t.Fatalf("expected Start error for key-without-cert, got nil")
	}
	if !strings.Contains(err.Error(), "TLS misconfiguration") {
		t.Fatalf("expected TLS misconfiguration error, got: %v", err)
	}
}

// TestRPCServerTLSInvalidCertPath — both cert + key set but cert path
// points at a nonexistent file. The eager LoadX509KeyPair check should
// surface this as a Start error, not a silent goroutine log entry.
func TestRPCServerTLSInvalidCertPath(t *testing.T) {
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr:  addr,
		TLSCertFile: "/nonexistent/path/cert.pem",
		TLSKeyFile:  "/nonexistent/path/key.pem",
	})

	err := server.Start()
	if err == nil {
		_ = server.Stop()
		t.Fatalf("expected Start error for nonexistent cert path, got nil")
	}
	if !strings.Contains(err.Error(), "TLS keypair load failed") {
		t.Fatalf("expected TLS keypair load error, got: %v", err)
	}
}

// TestRPCServerTLSInvalidCertContents — both paths exist but the cert
// file isn't a valid PEM certificate. LoadX509KeyPair must reject it
// before the listener starts.
func TestRPCServerTLSInvalidCertContents(t *testing.T) {
	dir := t.TempDir()
	bogusCert := filepath.Join(dir, "bogus.pem")
	bogusKey := filepath.Join(dir, "bogus.key")
	if err := os.WriteFile(bogusCert, []byte("not a real cert"), 0600); err != nil {
		t.Fatalf("write bogus cert: %v", err)
	}
	if err := os.WriteFile(bogusKey, []byte("not a real key"), 0600); err != nil {
		t.Fatalf("write bogus key: %v", err)
	}

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := NewServer(RPCConfig{
		ListenAddr:  addr,
		TLSCertFile: bogusCert,
		TLSKeyFile:  bogusKey,
	})

	err := server.Start()
	if err == nil {
		_ = server.Stop()
		t.Fatalf("expected Start error for malformed cert, got nil")
	}
	if !strings.Contains(err.Error(), "TLS keypair load failed") {
		t.Fatalf("expected TLS keypair load error, got: %v", err)
	}
}
