package p2p

import (
	"net"
	"testing"
	"time"
)

// testIP returns a routable public IPv4 address in the 1.2.3.x/8.x.x.x/
// range, safe for use in unit tests.  These are publicly assigned addresses
// that are not RFC1918 / RFC3927 / RFC5737 / RFC6598 / RFC4843, so they
// pass the IsRoutable filter added by the BUG-27 fix.
var testIPs = []string{
	"1.2.3.1",
	"1.2.3.2",
	"1.2.3.3",
	"1.2.3.4",
	"1.2.3.5",
	"1.2.3.6",
	"1.2.3.7",
	"1.2.3.8",
	"1.2.3.9",
	"1.2.3.10",
}

func TestNewAddressBook(t *testing.T) {
	ab := NewAddressBook()
	if ab == nil {
		t.Fatal("NewAddressBook returned nil")
	}
	if ab.Size() != 0 {
		t.Errorf("new address book should be empty, got size %d", ab.Size())
	}
}

func TestAddressBookAddAddress(t *testing.T) {
	ab := NewAddressBook()

	// Add a valid routable address
	addr := NetAddress{
		IP:   net.ParseIP("1.2.3.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	if ab.Size() != 1 {
		t.Errorf("expected size 1, got %d", ab.Size())
	}

	// Add same address again - should not duplicate
	ab.AddAddress(addr, "test")
	if ab.Size() != 1 {
		t.Errorf("duplicate address should not increase size, got %d", ab.Size())
	}

	// Add different address
	addr2 := NetAddress{
		IP:   net.ParseIP("1.2.3.2"),
		Port: 8333,
	}
	ab.AddAddress(addr2, "test")
	if ab.Size() != 2 {
		t.Errorf("expected size 2, got %d", ab.Size())
	}
}

func TestAddressBookAddInvalidAddress(t *testing.T) {
	ab := NewAddressBook()

	// Add nil IP - should be ignored
	addr := NetAddress{
		IP:   nil,
		Port: 8333,
	}
	ab.AddAddress(addr, "test")
	if ab.Size() != 0 {
		t.Errorf("nil IP should not be added, got size %d", ab.Size())
	}

	// Add unspecified IP - should be ignored
	addr = NetAddress{
		IP:   net.IPv4zero,
		Port: 8333,
	}
	ab.AddAddress(addr, "test")
	if ab.Size() != 0 {
		t.Errorf("unspecified IP should not be added, got size %d", ab.Size())
	}

	// Add RFC1918 private address - should be rejected (BUG-27 fix)
	addr = NetAddress{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")
	if ab.Size() != 0 {
		t.Errorf("RFC1918 address should not be added, got size %d", ab.Size())
	}
}

func TestAddressBookAddAddresses(t *testing.T) {
	ab := NewAddressBook()

	addrs := []NetAddress{
		{IP: net.ParseIP("1.2.3.1"), Port: 8333},
		{IP: net.ParseIP("1.2.3.2"), Port: 8333},
		{IP: net.ParseIP("1.2.3.3"), Port: 8333},
	}
	ab.AddAddresses(addrs, "test")

	if ab.Size() != 3 {
		t.Errorf("expected size 3, got %d", ab.Size())
	}
}

func TestAddressBookPickAddress(t *testing.T) {
	ab := NewAddressBook()

	// Empty book should return nil
	if ka := ab.PickAddress(); ka != nil {
		t.Error("empty book should return nil")
	}

	// Add some routable addresses
	addrs := []NetAddress{
		{IP: net.ParseIP("1.2.3.1"), Port: 8333},
		{IP: net.ParseIP("1.2.3.2"), Port: 8333},
		{IP: net.ParseIP("1.2.3.3"), Port: 8333},
	}
	ab.AddAddresses(addrs, "test")

	// Should be able to pick an address
	ka := ab.PickAddress()
	if ka == nil {
		t.Error("should return an address")
	}
}

func TestAddressBookMarkAttempt(t *testing.T) {
	ab := NewAddressBook()

	addr := NetAddress{
		IP:   net.ParseIP("1.2.3.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	key := "1.2.3.1:8333"
	ab.MarkAttempt(key)

	ka := ab.GetAddress(key)
	if ka == nil {
		t.Fatal("address not found")
	}
	if ka.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", ka.Attempts)
	}
	if ka.LastAttempt.IsZero() {
		t.Error("LastAttempt should be set")
	}

	// Mark another attempt
	ab.MarkAttempt(key)
	ka = ab.GetAddress(key)
	if ka.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", ka.Attempts)
	}
}

func TestAddressBookMarkSuccess(t *testing.T) {
	ab := NewAddressBook()

	addr := NetAddress{
		IP:   net.ParseIP("1.2.3.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	key := "1.2.3.1:8333"

	// Mark some failed attempts
	ab.MarkAttempt(key)
	ab.MarkAttempt(key)

	ka := ab.GetAddress(key)
	if ka.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", ka.Attempts)
	}

	// Mark success - should reset attempts
	ab.MarkSuccess(key)

	ka = ab.GetAddress(key)
	if ka.Attempts != 0 {
		t.Errorf("success should reset attempts to 0, got %d", ka.Attempts)
	}
	if ka.LastSuccess.IsZero() {
		t.Error("LastSuccess should be set")
	}
}

func TestAddressBookRemoveAddress(t *testing.T) {
	ab := NewAddressBook()

	addr := NetAddress{
		IP:   net.ParseIP("1.2.3.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	if ab.Size() != 1 {
		t.Errorf("expected size 1, got %d", ab.Size())
	}

	ab.RemoveAddress("1.2.3.1:8333")

	if ab.Size() != 0 {
		t.Errorf("expected size 0 after remove, got %d", ab.Size())
	}
}

func TestAddressBookGood(t *testing.T) {
	ab := NewAddressBook()

	addrs := []NetAddress{
		{IP: net.ParseIP("1.2.3.1"), Port: 8333},
		{IP: net.ParseIP("1.2.3.2"), Port: 8333},
		{IP: net.ParseIP("1.2.3.3"), Port: 8333},
	}
	ab.AddAddresses(addrs, "test")

	// No successes yet
	good := ab.Good()
	if len(good) != 0 {
		t.Errorf("expected 0 good addresses, got %d", len(good))
	}

	// Mark one as successful
	ab.MarkSuccess("1.2.3.1:8333")

	good = ab.Good()
	if len(good) != 1 {
		t.Errorf("expected 1 good address, got %d", len(good))
	}

	// Mark another as successful
	ab.MarkSuccess("1.2.3.2:8333")

	good = ab.Good()
	if len(good) != 2 {
		t.Errorf("expected 2 good addresses, got %d", len(good))
	}
}

func TestAddressBookNeedMoreAddresses(t *testing.T) {
	ab := NewAddressBook()

	// Empty book needs more
	if !ab.NeedMoreAddresses() {
		t.Error("empty book should need more addresses")
	}

	// Add some addresses using routable IPs across multiple /24s
	for i := 0; i < 100; i++ {
		ab.AddAddress(NetAddress{
			IP:   net.ParseIP("5." + itoa(i/256+1) + "." + itoa(i%256) + ".1"),
			Port: 8333,
		}, "test")
	}

	// Still needs more (< 1000)
	if !ab.NeedMoreAddresses() {
		t.Error("book with < 1000 addresses should need more")
	}
}

func TestKnownAddressIsRecentlyAttempted(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("1.2.3.1"),
			Port: 8333,
		},
	}

	// No attempt yet
	if ka.IsRecentlyAttempted() {
		t.Error("should not be recently attempted without any attempts")
	}

	// Set last attempt to now
	ka.LastAttempt = time.Now()
	if !ka.IsRecentlyAttempted() {
		t.Error("should be recently attempted")
	}

	// Set last attempt to long ago
	ka.LastAttempt = time.Now().Add(-20 * time.Minute)
	if ka.IsRecentlyAttempted() {
		t.Error("should not be recently attempted after 20 minutes")
	}
}

func TestKnownAddressIsBad(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("1.2.3.1"),
			Port: 8333,
		},
	}

	// Fresh address is not bad
	if ka.IsBad() {
		t.Error("fresh address should not be bad")
	}

	// MaxAttempts alone no longer permanently excludes — only MaxNewAttempts does.
	ka.Attempts = MaxAttempts
	if ka.IsBad() {
		t.Error("address at MaxAttempts (below MaxNewAttempts) should not be bad")
	}

	// Too many attempts without success is bad
	ka.Attempts = MaxNewAttempts
	if !ka.IsBad() {
		t.Error("address with max-new-attempts and no success should be bad")
	}

	// With success, not bad — even if Attempts is high, success gates IsBad.
	ka.LastSuccess = time.Now()
	if ka.IsBad() {
		t.Error("address with success should not be bad")
	}
}

func TestKnownAddressChance(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("1.2.3.1"),
			Port: 8333,
		},
		LastSeen: time.Now(), // recently seen
	}

	// Fresh address should have positive chance
	chance := ka.Chance()
	if chance <= 0 {
		t.Errorf("fresh address should have positive chance, got %f", chance)
	}

	// Address with success should have higher chance
	ka.LastSuccess = time.Now()
	chanceWithSuccess := ka.Chance()
	if chanceWithSuccess <= chance {
		t.Error("address with success should have higher chance")
	}

	// Recently attempted address with prior success gets a reduced but non-zero
	// chance (0.5) to prevent feeler probes from exhausting small networks.
	ka.LastAttempt = time.Now()
	recentlyAttemptedChance := ka.Chance()
	if recentlyAttemptedChance >= chanceWithSuccess {
		t.Errorf("recently attempted address should have lower chance than successful, got %f >= %f", recentlyAttemptedChance, chanceWithSuccess)
	}

	// Recently attempted address with NO prior success should have zero chance
	ka.LastSuccess = time.Time{}
	if ka.Chance() != 0 {
		t.Error("recently attempted address with no success should have zero chance")
	}

	// Bad address should have zero chance
	ka.LastAttempt = time.Time{}
	ka.LastSuccess = time.Time{}
	ka.Attempts = MaxNewAttempts
	if ka.Chance() != 0 {
		t.Error("bad address should have zero chance")
	}
}

func TestKnownAddressKey(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("1.2.3.1"),
			Port: 8333,
		},
	}

	key := ka.Key()
	if key != "1.2.3.1:8333" {
		t.Errorf("expected key 1.2.3.1:8333, got %s", key)
	}
}

func TestAddressBookPickPrefersSucessful(t *testing.T) {
	ab := NewAddressBook()

	// Add routable addresses across different IPs
	for i := 1; i <= 10; i++ {
		ab.AddAddress(NetAddress{
			IP:   net.ParseIP("1.2.3." + itoa(i)),
			Port: 8333,
		}, "test")
	}

	// Mark one as successful
	ab.MarkSuccess("1.2.3.5:8333")

	// Pick many times and count how often we get the successful one
	successCount := 0
	iterations := 100
	for i := 0; i < iterations; i++ {
		ka := ab.PickAddress()
		if ka != nil && ka.Key() == "1.2.3.5:8333" {
			successCount++
		}
	}

	// The successful address should be picked more often than average (10%)
	// With 2x bonus, we expect it to be picked ~18% of the time
	expectedMin := iterations / 10 // At least 10%
	if successCount < expectedMin {
		t.Errorf("successful address should be preferred, got %d/%d picks", successCount, iterations)
	}
}

// TestClampAddrTimestamp verifies the Core net_processing.cpp:5678-5680 timestamp
// clamp: a received nTime that is pre-2001 (<=100000000) or more than 10 minutes
// in the future is replaced by (now - 5*24h).  A normal recent timestamp is kept.
func TestClampAddrTimestamp(t *testing.T) {
	now := time.Now()
	stale := now.Add(-5 * 24 * time.Hour).Unix()

	tests := []struct {
		name      string
		ts        uint32
		wantStale bool // true → expect clamped to ~(now-5d), false → expect ts preserved
	}{
		{"pre-2001 (ts=0)", 0, true},
		{"pre-2001 (ts=100000000)", 100_000_000, true},
		{"far-future (ts=now+20min)", uint32(now.Add(20 * time.Minute).Unix()), true},
		{"recent (ts=now-1h)", uint32(now.Add(-time.Hour).Unix()), false},
		{"exactly 5 days ago", uint32(now.Add(-5 * 24 * time.Hour).Unix()), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampAddrTimestamp(tt.ts, now)
			if tt.wantStale {
				// Must be within 2 seconds of (now-5d).
				diff := got.Unix() - stale
				if diff < -2 || diff > 2 {
					t.Errorf("expected clamped to now-5d (~%d), got %d (diff %d)", stale, got.Unix(), diff)
				}
			} else {
				// Must equal the raw timestamp.
				if got.Unix() != int64(tt.ts) {
					t.Errorf("expected preserved ts=%d, got %d", tt.ts, got.Unix())
				}
			}
		})
	}
}

// TestAddAddressTimestampClamp verifies that AddAddress stores the Core-clamped
// timestamp as LastSeen rather than always using time.Now().
// FAILS before the clamp fix (AddAddress always wrote time.Now()) because the
// pre-2001 address would have a LastSeen≈now instead of ≈now-5d.
func TestAddAddressTimestampClamp(t *testing.T) {
	ab := NewAddressBook()
	now := time.Now()

	// Address with a pre-2001 timestamp — must be clamped to (now-5d).
	pre2001Addr := NetAddress{
		IP:        net.ParseIP("1.2.3.1"),
		Port:      8333,
		Timestamp: 1000, // well before 100000000 cutoff
	}
	ab.AddAddress(pre2001Addr, "test")

	ka := ab.GetAddress("1.2.3.1:8333")
	if ka == nil {
		t.Fatal("address should have been added")
	}
	wantStale := now.Add(-5 * 24 * time.Hour)
	// Allow ±5 second tolerance for test execution time.
	diff := ka.LastSeen.Unix() - wantStale.Unix()
	if diff < -5 || diff > 5 {
		t.Errorf("pre-2001 addr: LastSeen should be clamped to now-5d (~%d), got %d (diff %d)",
			wantStale.Unix(), ka.LastSeen.Unix(), diff)
	}

	// Address with a far-future timestamp — must also be clamped.
	futureAddr := NetAddress{
		IP:        net.ParseIP("1.2.3.2"),
		Port:      8333,
		Timestamp: uint32(now.Add(30 * time.Minute).Unix()),
	}
	ab.AddAddress(futureAddr, "test")

	ka2 := ab.GetAddress("1.2.3.2:8333")
	if ka2 == nil {
		t.Fatal("future-ts address should have been added")
	}
	diff2 := ka2.LastSeen.Unix() - wantStale.Unix()
	if diff2 < -5 || diff2 > 5 {
		t.Errorf("future-ts addr: LastSeen should be clamped to now-5d (~%d), got %d (diff %d)",
			wantStale.Unix(), ka2.LastSeen.Unix(), diff2)
	}

	// Address with a normal recent timestamp — must be preserved.
	recentTs := uint32(now.Add(-time.Hour).Unix())
	recentAddr := NetAddress{
		IP:        net.ParseIP("1.2.3.3"),
		Port:      8333,
		Timestamp: recentTs,
	}
	ab.AddAddress(recentAddr, "test")

	ka3 := ab.GetAddress("1.2.3.3:8333")
	if ka3 == nil {
		t.Fatal("recent-ts address should have been added")
	}
	diff3 := ka3.LastSeen.Unix() - int64(recentTs)
	if diff3 < -2 || diff3 > 2 {
		t.Errorf("recent-ts addr: LastSeen should equal advertised ts %d, got %d (diff %d)",
			recentTs, ka3.LastSeen.Unix(), diff3)
	}
}
