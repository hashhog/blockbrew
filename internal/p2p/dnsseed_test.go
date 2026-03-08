// +build !ci

package p2p

import (
	"testing"
)

// Note: These tests require network access and may be skipped in CI.
// Run with: go test -tags=!ci ./internal/p2p/ -run TestDNS

func TestResolveDNSSeedsEmpty(t *testing.T) {
	// Empty seeds should return nil
	ips := ResolveDNSSeeds(nil)
	if ips != nil {
		t.Errorf("expected nil for empty seeds, got %v", ips)
	}

	ips = ResolveDNSSeeds([]string{})
	if ips != nil {
		t.Errorf("expected nil for empty slice, got %v", ips)
	}
}

func TestResolveDNSSeedsInvalid(t *testing.T) {
	// Invalid hostnames should not cause errors, just return empty
	ips := ResolveDNSSeeds([]string{
		"this-is-not-a-real-hostname-12345.invalid",
		"another-fake-hostname-67890.invalid",
	})
	// Should return empty (or possibly nil) without error
	if len(ips) > 0 {
		t.Errorf("expected empty result for invalid hostnames, got %v", ips)
	}
}

func TestResolveDNSSeedsDeduplication(t *testing.T) {
	// If the same seed is passed twice, IPs should be deduplicated
	seeds := []string{
		"localhost",
		"localhost",
	}
	ips := ResolveDNSSeeds(seeds)
	// Check for duplicates
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("duplicate IP found: %s", ip)
		}
		seen[ip] = true
	}
}

func TestShuffleStrings(t *testing.T) {
	// Test that shuffle works and doesn't lose elements
	original := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	s := make([]string, len(original))
	copy(s, original)

	shuffleStrings(s)

	// Check same length
	if len(s) != len(original) {
		t.Errorf("shuffle changed length from %d to %d", len(original), len(s))
	}

	// Check all elements are present
	seen := make(map[string]bool)
	for _, v := range s {
		seen[v] = true
	}
	for _, v := range original {
		if !seen[v] {
			t.Errorf("shuffle lost element: %s", v)
		}
	}
}

func TestShuffleStringsEmpty(t *testing.T) {
	// Shuffling empty slice should not panic
	var s []string
	shuffleStrings(s)

	s = []string{}
	shuffleStrings(s)
}

func TestShuffleStringsSingle(t *testing.T) {
	// Shuffling single element should not panic
	s := []string{"a"}
	shuffleStrings(s)
	if s[0] != "a" {
		t.Error("single element should remain unchanged")
	}
}

// TestResolveDNSSeedsReal tests against real DNS seeds.
// This test is skipped by default as it requires network access.
// Run with: go test ./internal/p2p/ -run TestResolveDNSSeedsReal -v
func TestResolveDNSSeedsReal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}

	// Use a known-good DNS name
	seeds := []string{"dns.google"}
	ips := ResolveDNSSeeds(seeds)

	if len(ips) == 0 {
		t.Skip("could not resolve dns.google - may be network issue")
	}

	t.Logf("Resolved %d IPs from dns.google", len(ips))
	for _, ip := range ips {
		t.Logf("  %s", ip)
	}
}
