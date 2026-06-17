package p2p

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestAddressBookSaveLoadRoundTrip is the core persistence regression: populate
// an address book, Save it to a temp dir, then Load it into a FRESH book and
// assert every peer (and its connection-history metadata) is restored. This is
// the "node forgets its peers across restart" production blocker — if the
// Save/Load wiring is disabled, this test must fail.
func TestAddressBookSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir() // temp dir — never touch live datadirs / real peers.dat

	src := NewAddressBook()
	for i, ipStr := range testIPs {
		na := NetAddress{
			Services: uint64(i + 1),
			IP:       net.ParseIP(ipStr),
			Port:     uint16(8333 + i),
		}
		src.AddAddress(na, "test")
	}
	// Give a couple of entries real connection history so we can prove the
	// metadata (not just the bare address) round-trips.
	keyGood := net.JoinHostPort(net.ParseIP(testIPs[0]).String(), itoa(8333))
	src.MarkAttempt(keyGood)
	src.MarkSuccess(keyGood)
	keyTried := net.JoinHostPort(net.ParseIP(testIPs[1]).String(), itoa(8334))
	src.MarkAttempt(keyTried)
	src.MarkAttempt(keyTried)

	wantSize := src.Size()
	if wantSize != len(testIPs) {
		t.Fatalf("setup: expected %d addresses, got %d", len(testIPs), wantSize)
	}

	if err := src.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The file must actually exist on disk.
	path := filepath.Join(dir, AddressBookFilename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("peers file not written: %v", err)
	}

	// Reload into a brand-new book (simulates a process restart).
	restored := NewAddressBook()
	n := restored.Load(dir)
	if n != wantSize {
		t.Fatalf("Load returned %d, want %d", n, wantSize)
	}
	if restored.Size() != wantSize {
		t.Fatalf("restored size = %d, want %d", restored.Size(), wantSize)
	}

	// Every original address must be present after reload.
	for i, ipStr := range testIPs {
		na := NetAddress{IP: net.ParseIP(ipStr).To16(), Port: uint16(8333 + i)}
		key := addrKey(na)
		ka := restored.GetAddress(key)
		if ka == nil {
			t.Fatalf("address %s missing after reload", key)
		}
		if ka.Addr.Services != uint64(i+1) {
			t.Errorf("address %s: services = %d, want %d", key, ka.Addr.Services, i+1)
		}
	}

	// The address with a successful handshake must keep that history (this is
	// what makes a restored book immediately useful vs. a cold bootstrap).
	good := restored.Good()
	if len(good) != 1 {
		t.Fatalf("expected exactly 1 address with success history, got %d", len(good))
	}
	if got := good[0].Addr.IP.String(); got != net.ParseIP(testIPs[0]).String() {
		t.Errorf("good address = %s, want %s", got, testIPs[0])
	}

	// The failed-attempt count must survive the round-trip too.
	triedKA := restored.GetAddress(keyTried)
	if triedKA == nil {
		t.Fatalf("tried address %s missing after reload", keyTried)
	}
	if triedKA.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", triedKA.Attempts)
	}
}

// TestAddressBookLoadCorruptColdStart verifies graceful degradation: a missing,
// empty-dataDir, or corrupt peers file must not panic and must leave the book
// in a clean cold-start state (Core CAddrDB::Read tolerance).
func TestAddressBookLoadCorruptColdStart(t *testing.T) {
	// Missing file in an otherwise-valid dir.
	ab := NewAddressBook()
	if n := ab.Load(t.TempDir()); n != 0 {
		t.Errorf("missing file: Load = %d, want 0", n)
	}

	// Empty dataDir is a no-op.
	if n := NewAddressBook().Load(""); n != 0 {
		t.Errorf("empty dataDir: Load = %d, want 0", n)
	}
	if err := NewAddressBook().Save(""); err != nil {
		t.Errorf("empty dataDir Save should be a no-op, got %v", err)
	}

	// Corrupt JSON cold-starts rather than panicking.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, AddressBookFilename), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ab2 := NewAddressBook()
	if n := ab2.Load(dir); n != 0 {
		t.Errorf("corrupt file: Load = %d, want 0", n)
	}
	if ab2.Size() != 0 {
		t.Errorf("corrupt file should leave book empty, got size %d", ab2.Size())
	}
}

// TestPeerManagerPeersPersistLifecycle proves the LIVE wiring: a PeerManager
// configured with a DataDir saves its address book on Stop(), and a fresh
// PeerManager on the same DataDir restores it at construction time. This is the
// production-path equivalent of "restart the node and keep your learned peers".
func TestPeerManagerPeersPersistLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := PeerManagerConfig{
		DataDir:    dir,
		ListenAddr: "", // no listener — keep the test hermetic
	}

	// First instance: learn some addresses, then Stop() (which must persist).
	pm1 := NewPeerManager(cfg)
	for i, ipStr := range testIPs {
		pm1.addrBook.AddAddress(NetAddress{
			IP:   net.ParseIP(ipStr),
			Port: uint16(8333 + i),
		}, "test")
	}
	want := pm1.addrBook.Size()
	if want == 0 {
		t.Fatal("setup: no addresses learned")
	}
	// Mark one as good so we can assert handshake history survives the restart.
	keyGood := net.JoinHostPort(net.ParseIP(testIPs[0]).String(), itoa(8333))
	pm1.addrBook.MarkSuccess(keyGood)

	pm1.Stop() // saveAnchors + savePeers + close(quit); no goroutines started

	if _, err := os.Stat(filepath.Join(dir, AddressBookFilename)); err != nil {
		t.Fatalf("Stop did not persist peers file: %v", err)
	}

	// Second instance on the same DataDir must come up warm.
	pm2 := NewPeerManager(cfg)
	if got := pm2.addrBook.Size(); got != want {
		t.Fatalf("restarted PeerManager addrBook size = %d, want %d", got, want)
	}
	if good := pm2.addrBook.Good(); len(good) != 1 {
		t.Fatalf("restarted PeerManager lost handshake history: %d good, want 1", len(good))
	}
	pm2.Stop()
}
