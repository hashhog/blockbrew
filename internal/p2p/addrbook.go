package p2p

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// Address selection tuning constants.
const (
	// MinRetryInterval is the minimum time between connection attempts to the same address.
	MinRetryInterval = 10 * time.Minute

	// MaxAttempts is the number of failed attempts before deprioritizing an address.
	MaxAttempts = 3

	// AddressBookMaxSize is the maximum number of addresses to store.
	AddressBookMaxSize = 10000
)

// KnownAddress represents a peer address with metadata about connection history.
type KnownAddress struct {
	Addr        NetAddress // The network address
	Source      string     // Where we learned this address (e.g., "dnsseed", peer address)
	LastAttempt time.Time  // When we last tried to connect
	LastSuccess time.Time  // When we last successfully connected
	Attempts    int        // Number of connection attempts
	LastSeen    time.Time  // When we last saw this address advertised
}

// Key returns a unique string key for this address (ip:port).
func (ka *KnownAddress) Key() string {
	return net.JoinHostPort(ka.Addr.IP.String(), itoa(int(ka.Addr.Port)))
}

// itoa converts an int to a string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf) - 1
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		buf[n] = byte('0' + i%10)
		n--
		i /= 10
	}
	if neg {
		buf[n] = '-'
		n--
	}
	return string(buf[n+1:])
}

// IsBad returns true if this address should not be selected for connection.
func (ka *KnownAddress) IsBad() bool {
	// Too many failed attempts with no success
	if ka.Attempts >= MaxAttempts && ka.LastSuccess.IsZero() {
		return true
	}
	return false
}

// IsRecentlyAttempted returns true if we've tried this address recently.
func (ka *KnownAddress) IsRecentlyAttempted() bool {
	if ka.LastAttempt.IsZero() {
		return false
	}
	return time.Since(ka.LastAttempt) < MinRetryInterval
}

// Chance returns a selection score (higher = better candidate).
// Addresses with successful connections and not recently attempted get higher scores.
func (ka *KnownAddress) Chance() float64 {
	if ka.IsRecentlyAttempted() {
		return 0
	}
	if ka.IsBad() {
		return 0
	}

	// Base chance
	chance := 1.0

	// Bonus for having a successful connection history
	if !ka.LastSuccess.IsZero() {
		chance *= 2.0
	}

	// Penalty for failed attempts
	if ka.Attempts > 0 && ka.LastSuccess.IsZero() {
		chance /= float64(ka.Attempts + 1)
	}

	// Small bonus for recently seen addresses
	if !ka.LastSeen.IsZero() && time.Since(ka.LastSeen) < 3*time.Hour {
		chance *= 1.5
	}

	return chance
}

// AddressBook manages known peer addresses.
type AddressBook struct {
	mu    sync.RWMutex
	addrs map[string]*KnownAddress // key -> KnownAddress
	rand  *rand.Rand
}

// NewAddressBook creates a new address book.
func NewAddressBook() *AddressBook {
	return &AddressBook{
		addrs: make(map[string]*KnownAddress),
		rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// AddAddress adds a new address to the book.
func (ab *AddressBook) AddAddress(addr NetAddress, source string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Skip invalid addresses
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return
	}

	key := addrKey(addr)

	// Check if we already have this address
	if existing, ok := ab.addrs[key]; ok {
		// Update last seen time
		existing.LastSeen = time.Now()
		return
	}

	// Don't exceed max size
	if len(ab.addrs) >= AddressBookMaxSize {
		// Could implement eviction here, for now just reject
		return
	}

	ab.addrs[key] = &KnownAddress{
		Addr:     addr,
		Source:   source,
		LastSeen: time.Now(),
	}
}

// AddAddresses adds multiple addresses.
func (ab *AddressBook) AddAddresses(addrs []NetAddress, source string) {
	for _, addr := range addrs {
		ab.AddAddress(addr, source)
	}
}

// PickAddress returns a random address to connect to, preferring addresses
// that haven't been tried recently and have a history of success.
func (ab *AddressBook) PickAddress() *KnownAddress {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	if len(ab.addrs) == 0 {
		return nil
	}

	// Collect candidates with their chances
	var candidates []*KnownAddress
	var totalChance float64

	for _, ka := range ab.addrs {
		chance := ka.Chance()
		if chance > 0 {
			candidates = append(candidates, ka)
			totalChance += chance
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Weighted random selection
	target := ab.rand.Float64() * totalChance
	var cumulative float64
	for _, ka := range candidates {
		cumulative += ka.Chance()
		if cumulative >= target {
			return ka
		}
	}

	// Fallback to last candidate
	return candidates[len(candidates)-1]
}

// MarkAttempt records a connection attempt.
func (ab *AddressBook) MarkAttempt(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	if ka, ok := ab.addrs[addr]; ok {
		ka.LastAttempt = time.Now()
		ka.Attempts++
	}
}

// MarkSuccess records a successful connection.
func (ab *AddressBook) MarkSuccess(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	if ka, ok := ab.addrs[addr]; ok {
		ka.LastSuccess = time.Now()
		ka.Attempts = 0 // Reset attempts on success
	}
}

// MarkFailed records a connection failure without incrementing attempts.
// Used when we want to track failure time without penalizing the address.
func (ab *AddressBook) MarkFailed(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	if ka, ok := ab.addrs[addr]; ok {
		ka.LastAttempt = time.Now()
	}
}

// Size returns the number of known addresses.
func (ab *AddressBook) Size() int {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return len(ab.addrs)
}

// GetAddress returns the KnownAddress for a given key, or nil if not found.
func (ab *AddressBook) GetAddress(key string) *KnownAddress {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return ab.addrs[key]
}

// RemoveAddress removes an address from the book.
func (ab *AddressBook) RemoveAddress(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	delete(ab.addrs, addr)
}

// Good returns a list of addresses with successful connection history.
func (ab *AddressBook) Good() []*KnownAddress {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	var good []*KnownAddress
	for _, ka := range ab.addrs {
		if !ka.LastSuccess.IsZero() {
			good = append(good, ka)
		}
	}
	return good
}

// NeedMoreAddresses returns true if we should request more addresses from peers.
func (ab *AddressBook) NeedMoreAddresses() bool {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return len(ab.addrs) < 1000
}

// addrKey returns a unique string key for a NetAddress.
func addrKey(addr NetAddress) string {
	return net.JoinHostPort(addr.IP.String(), itoa(int(addr.Port)))
}
