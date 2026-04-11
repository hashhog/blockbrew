package p2p

import (
	"net"
	"testing"
	"time"
)

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

	// Add a valid address
	addr := NetAddress{
		IP:   net.ParseIP("192.168.1.1"),
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
		IP:   net.ParseIP("192.168.1.2"),
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
}

func TestAddressBookAddAddresses(t *testing.T) {
	ab := NewAddressBook()

	addrs := []NetAddress{
		{IP: net.ParseIP("192.168.1.1"), Port: 8333},
		{IP: net.ParseIP("192.168.1.2"), Port: 8333},
		{IP: net.ParseIP("192.168.1.3"), Port: 8333},
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

	// Add some addresses
	addrs := []NetAddress{
		{IP: net.ParseIP("192.168.1.1"), Port: 8333},
		{IP: net.ParseIP("192.168.1.2"), Port: 8333},
		{IP: net.ParseIP("192.168.1.3"), Port: 8333},
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
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	key := "192.168.1.1:8333"
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
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	key := "192.168.1.1:8333"

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
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8333,
	}
	ab.AddAddress(addr, "test")

	if ab.Size() != 1 {
		t.Errorf("expected size 1, got %d", ab.Size())
	}

	ab.RemoveAddress("192.168.1.1:8333")

	if ab.Size() != 0 {
		t.Errorf("expected size 0 after remove, got %d", ab.Size())
	}
}

func TestAddressBookGood(t *testing.T) {
	ab := NewAddressBook()

	addrs := []NetAddress{
		{IP: net.ParseIP("192.168.1.1"), Port: 8333},
		{IP: net.ParseIP("192.168.1.2"), Port: 8333},
		{IP: net.ParseIP("192.168.1.3"), Port: 8333},
	}
	ab.AddAddresses(addrs, "test")

	// No successes yet
	good := ab.Good()
	if len(good) != 0 {
		t.Errorf("expected 0 good addresses, got %d", len(good))
	}

	// Mark one as successful
	ab.MarkSuccess("192.168.1.1:8333")

	good = ab.Good()
	if len(good) != 1 {
		t.Errorf("expected 1 good address, got %d", len(good))
	}

	// Mark another as successful
	ab.MarkSuccess("192.168.1.2:8333")

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

	// Add some addresses
	for i := 0; i < 100; i++ {
		ab.AddAddress(NetAddress{
			IP:   net.ParseIP("192.168.1." + itoa(i)),
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
			IP:   net.ParseIP("192.168.1.1"),
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
			IP:   net.ParseIP("192.168.1.1"),
			Port: 8333,
		},
	}

	// Fresh address is not bad
	if ka.IsBad() {
		t.Error("fresh address should not be bad")
	}

	// Too many attempts without success is bad
	ka.Attempts = MaxAttempts
	if !ka.IsBad() {
		t.Error("address with max attempts and no success should be bad")
	}

	// With success, not bad
	ka.LastSuccess = time.Now()
	if ka.IsBad() {
		t.Error("address with success should not be bad")
	}
}

func TestKnownAddressChance(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("192.168.1.1"),
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
	ka.Attempts = MaxAttempts
	if ka.Chance() != 0 {
		t.Error("bad address should have zero chance")
	}
}

func TestKnownAddressKey(t *testing.T) {
	ka := &KnownAddress{
		Addr: NetAddress{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 8333,
		},
	}

	key := ka.Key()
	if key != "192.168.1.1:8333" {
		t.Errorf("expected key 192.168.1.1:8333, got %s", key)
	}
}

func TestAddressBookPickPrefersSucessful(t *testing.T) {
	ab := NewAddressBook()

	// Add addresses
	for i := 1; i <= 10; i++ {
		ab.AddAddress(NetAddress{
			IP:   net.ParseIP("192.168.1." + itoa(i)),
			Port: 8333,
		}, "test")
	}

	// Mark one as successful
	ab.MarkSuccess("192.168.1.5:8333")

	// Pick many times and count how often we get the successful one
	successCount := 0
	iterations := 100
	for i := 0; i < iterations; i++ {
		ka := ab.PickAddress()
		if ka != nil && ka.Key() == "192.168.1.5:8333" {
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
