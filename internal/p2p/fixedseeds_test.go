package p2p

import (
	"net"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// TestFixedSeeds_ListParses is T1 from the spec: every entry in
// MainNetParams.FixedSeeds is a valid public IPv4 :8333 address, the set has
// the expected size, and all leading octets are distinct (the one-per-/8
// diversity invariant). Also asserts regtest carries no fixed seeds.
//
// This is the load-bearing regression guard: it would have caught a
// placeholder / non-routable / wrong-port entry sneaking into the curated set.
func TestFixedSeeds_ListParses(t *testing.T) {
	seeds := consensus.MainnetParams().FixedSeeds
	if len(seeds) != 40 {
		t.Fatalf("expected 40 mainnet fixed seeds, got %d", len(seeds))
	}

	leadingOctets := make(map[byte]struct{}, len(seeds))
	for _, s := range seeds {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			t.Fatalf("fixed seed %q is not host:port: %v", s, err)
		}
		if portStr != "8333" {
			t.Errorf("fixed seed %q: expected port 8333, got %s", s, portStr)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("fixed seed %q: host %q does not parse as an IP", s, host)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			t.Fatalf("fixed seed %q: not an IPv4 address", s)
		}
		// Reject non-routable / bogon ranges — the regression guard that would
		// have caught a 10.0.0.1-style placeholder.
		if !isRoutableIP(ip.To16()) {
			t.Errorf("fixed seed %q is non-routable/bogon (would be a dead dial)", s)
		}
		first := ip4[0]
		if first == 10 || first == 127 || first == 0 ||
			(first == 192 && ip4[1] == 168) ||
			(first == 172 && ip4[1] >= 16 && ip4[1] <= 31) {
			t.Errorf("fixed seed %q is RFC1918/loopback/bogon", s)
		}
		if _, dup := leadingOctets[first]; dup {
			t.Errorf("fixed seed %q duplicates leading octet %d (breaks /8 diversity)", s, first)
		}
		leadingOctets[first] = struct{}{}
	}
	if len(leadingOctets) != len(seeds) {
		t.Errorf("expected %d distinct leading octets, got %d", len(seeds), len(leadingOctets))
	}

	// Regtest must carry no fixed seeds (Core clears vFixedSeeds for regtest).
	if rs := consensus.RegtestParams().FixedSeeds; rs != nil {
		t.Errorf("regtest FixedSeeds must be nil, got %v", rs)
	}
	// Testnet/signet/testnet4 are out of scope this campaign: must be empty.
	if ts := consensus.TestnetParams().FixedSeeds; len(ts) != 0 {
		t.Errorf("testnet3 FixedSeeds must be empty (out of scope), got %v", ts)
	}
	if t4 := consensus.Testnet4Params().FixedSeeds; len(t4) != 0 {
		t.Errorf("testnet4 FixedSeeds must be empty (out of scope), got %v", t4)
	}
}

// newFixedSeedTestPM builds a PeerManager with an empty address book for
// trigger-predicate testing.
func newFixedSeedTestPM(cfg PeerManagerConfig) *PeerManager {
	if cfg.ChainParams == nil {
		cfg.ChainParams = consensus.MainnetParams()
	}
	cfg.UserAgent = "/blockbrew-test/"
	return NewPeerManager(cfg)
}

// TestFixedSeeds_PredicateFires is T2 from the spec: with an empty address
// book and DNS seeding disabled (the immediate-fire shortcut), the fallback
// injects all 40 seeds; a second call is a one-shot no-op; and -connect /
// -fixedseeds=0 suppress it entirely.
func TestFixedSeeds_PredicateFires(t *testing.T) {
	// (a) Immediate-fire shortcut: NoDNSSeed=true, empty book, no -connect.
	pm := newFixedSeedTestPM(PeerManagerConfig{NoDNSSeed: true})
	if pm.addrBook.Size() != 0 {
		t.Fatalf("precondition: address book should start empty, got %d", pm.addrBook.Size())
	}

	// connStart "just now" — the 60s grace has NOT elapsed, so this proves the
	// firing came from the DNS-disabled immediate-fire path, not the timer.
	if fired := pm.maybeAddFixedSeeds(time.Now()); !fired {
		t.Fatal("expected fixed seeds to fire immediately when DNS seeding is disabled and book is empty")
	}
	if got := pm.addrBook.Size(); got != 40 {
		t.Fatalf("expected 40 addresses after fixed-seed injection, got %d", got)
	}

	// One-shot: a second call must NOT re-inject.
	if fired := pm.maybeAddFixedSeeds(time.Now()); fired {
		t.Error("fixed seeds fired twice — one-shot guard failed")
	}
	if got := pm.addrBook.Size(); got != 40 {
		t.Errorf("address book changed on second call (one-shot violated): got %d", got)
	}

	// (b) 60s-grace path: DNS enabled, empty book, but grace not yet elapsed →
	// must NOT fire; then with start 61s in the past → fires.
	pm2 := newFixedSeedTestPM(PeerManagerConfig{})
	if fired := pm2.maybeAddFixedSeeds(time.Now()); fired {
		t.Error("fixed seeds fired before the 60s grace with DNS enabled — should wait")
	}
	if pm2.addrBook.Size() != 0 {
		t.Errorf("book should be untouched before grace, got %d", pm2.addrBook.Size())
	}
	if fired := pm2.maybeAddFixedSeeds(time.Now().Add(-61 * time.Second)); !fired {
		t.Error("fixed seeds did not fire after the 60s grace elapsed with empty book")
	}
	if got := pm2.addrBook.Size(); got != 40 {
		t.Errorf("expected 40 addresses after grace-path injection, got %d", got)
	}

	// (c) Negative: book non-empty → never fires (Core's reachable-empty-network
	// proxy is false).
	pm3 := newFixedSeedTestPM(PeerManagerConfig{NoDNSSeed: true})
	pm3.addrBook.AddAddress(NetAddress{IP: net.ParseIP("8.8.8.8").To16(), Port: 8333}, "test")
	if pm3.addrBook.Size() == 0 {
		t.Fatal("precondition: seeded one routable address")
	}
	if fired := pm3.maybeAddFixedSeeds(time.Now().Add(-2 * time.Minute)); fired {
		t.Error("fixed seeds fired despite a non-empty address book")
	}

	// (d) Negative: -connect (connectMode) suppresses the fallback entirely,
	// even past the grace window with an empty book.
	pm4 := newFixedSeedTestPM(PeerManagerConfig{
		ConnectPeers: []string{"1.2.3.4:8333"},
		NoDNSSeed:    true, // implied by -connect, set explicitly for clarity
	})
	if fired := pm4.maybeAddFixedSeeds(time.Now().Add(-2 * time.Minute)); fired {
		t.Error("fixed seeds fired under -connect — must be suppressed")
	}
	if pm4.addrBook.Size() != 0 {
		t.Errorf("book mutated under -connect, got %d", pm4.addrBook.Size())
	}

	// (e) Negative: -fixedseeds=0 (NoFixedSeeds) suppresses the fallback.
	pm5 := newFixedSeedTestPM(PeerManagerConfig{NoDNSSeed: true, NoFixedSeeds: true})
	if fired := pm5.maybeAddFixedSeeds(time.Now().Add(-2 * time.Minute)); fired {
		t.Error("fixed seeds fired with -fixedseeds=0 — must be suppressed")
	}
	if pm5.addrBook.Size() != 0 {
		t.Errorf("book mutated with -fixedseeds=0, got %d", pm5.addrBook.Size())
	}
}

// TestFixedSeeds_DirectAddIsOneShot exercises addFixedSeeds() directly (the
// helper the spec names) and asserts the one-shot flag survives a repeat call.
func TestFixedSeeds_DirectAddIsOneShot(t *testing.T) {
	pm := newFixedSeedTestPM(PeerManagerConfig{})
	if !pm.addFixedSeeds() {
		t.Fatal("addFixedSeeds() returned false on first call")
	}
	if got := pm.addrBook.Size(); got != 40 {
		t.Fatalf("expected 40 addresses injected, got %d", got)
	}
	if pm.addFixedSeeds() {
		t.Error("addFixedSeeds() injected twice — fixedSeedsAdded one-shot failed")
	}
	if got := pm.addrBook.Size(); got != 40 {
		t.Errorf("address book grew on repeat addFixedSeeds(), got %d", got)
	}
}
