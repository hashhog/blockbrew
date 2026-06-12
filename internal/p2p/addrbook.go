package p2p

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// isRoutableIP returns true if ip is publicly routable on the global internet,
// mirroring Bitcoin Core's CNetAddr::IsRoutable() in netaddress.cpp:462.
//
// Core rejects: RFC1918, RFC2544, RFC3927, RFC4862, RFC6598, RFC5737,
//               RFC4193, RFC4843, RFC7343, local (loopback/unspecified), internal.
//
// Go stdlib covers: loopback (IsLoopback), RFC1918+RFC4193 (IsPrivate),
//                   RFC3927+RFC4862 link-local (IsLinkLocalUnicast).
// The remaining ranges are checked explicitly via CIDR nets.
func isRoutableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalise to 16-byte form so all comparisons work uniformly.
	ip = ip.To16()
	if ip == nil {
		return false
	}

	// Unspecified (0.0.0.0 / ::)
	if ip.IsUnspecified() {
		return false
	}
	// Loopback: 127.0.0.0/8 (IPv4-mapped) and ::1/128
	if ip.IsLoopback() {
		return false
	}
	// RFC1918 (10/8, 172.16/12, 192.168/16) and RFC4193 (fc00::/7 ULA)
	// Go 1.17+ IsPrivate covers exactly these ranges.
	if ip.IsPrivate() {
		return false
	}
	// Link-local unicast: 169.254.0.0/16 (RFC3927) and fe80::/10 (RFC4862)
	if ip.IsLinkLocalUnicast() {
		return false
	}
	// Multicast
	if ip.IsMulticast() {
		return false
	}

	// Ranges not covered by Go stdlib — checked via parsed CIDRs (initialised
	// once at package init).
	for _, cidr := range nonRoutableCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}

	return true
}

// IsRoutableIP reports whether ip is publicly routable, mirroring Bitcoin
// Core's CNetAddr::IsRoutable(). Exported so other packages (e.g. the RPC
// getnodeaddresses network-class mapping) can classify a stored address
// without duplicating the RFC range logic.
func IsRoutableIP(ip net.IP) bool {
	return isRoutableIP(ip)
}

// nonRoutableCIDRs contains IPv4/IPv6 ranges that Core rejects but that Go's
// stdlib helpers do not cover:
//   - 198.18.0.0/15   RFC2544 benchmarking
//   - 100.64.0.0/10   RFC6598 shared address space (CGNAT)
//   - 192.0.2.0/24    RFC5737 TEST-NET-1
//   - 198.51.100.0/24 RFC5737 TEST-NET-2
//   - 203.0.113.0/24  RFC5737 TEST-NET-3
//   - 2001:10::/28    RFC4843 ORCHID
//   - 2001:20::/28    RFC7343 ORCHIDv2
var nonRoutableCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"198.18.0.0/15",    // RFC2544 benchmarking
		"100.64.0.0/10",    // RFC6598 shared address space (CGNAT)
		"192.0.2.0/24",     // RFC5737 TEST-NET-1
		"198.51.100.0/24",  // RFC5737 TEST-NET-2
		"203.0.113.0/24",   // RFC5737 TEST-NET-3
		"2001:10::/28",     // RFC4843 ORCHID
		"2001:20::/28",     // RFC7343 ORCHIDv2
	}
	for _, s := range cidrs {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			panic("isRoutableIP: bad CIDR " + s + ": " + err.Error())
		}
		nonRoutableCIDRs = append(nonRoutableCIDRs, cidr)
	}
}

// Address selection tuning constants.
const (
	// MinRetryInterval is the minimum time between connection attempts to the same address.
	MinRetryInterval = 10 * time.Minute

	// MaxAttempts is the number of failed attempts before deprioritizing an
	// address via the Chance() score. It still influences selection weight
	// but does not permanently exclude.
	MaxAttempts = 3

	// MaxNewAttempts is the attempt budget for addresses that have never
	// completed a successful handshake (LastSuccess is zero). Gossip-learned
	// addresses can need many retries before an initial success — especially
	// behind NAT or during IBD — so a small budget like 3 causes permanent
	// exclusion of otherwise-healthy peers. Bitcoin Core's AddrMan tolerates
	// up to 10 retries before discarding a never-succeeded address; we use
	// the same value here.
	MaxNewAttempts = 10

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
//
// Addresses that have never succeeded are allowed up to MaxNewAttempts
// retries before being excluded — a gossip-learned address frequently
// needs several attempts before the first handshake lands, and the old
// 3-strike rule permanently poisoned the candidate pool after a single
// outage. Addresses that have previously succeeded are never IsBad on
// attempt count alone; transient failures are absorbed by MarkSuccess
// resetting Attempts to zero on the next successful reconnect.
func (ka *KnownAddress) IsBad() bool {
	if ka.LastSuccess.IsZero() && ka.Attempts >= MaxNewAttempts {
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
// Addresses that have had a recent successful connection are always eligible,
// even if recently attempted — this prevents feeler probes from exhausting
// the address pool on networks with few nodes (e.g., testnet4).
func (ka *KnownAddress) Chance() float64 {
	if ka.IsRecentlyAttempted() {
		// If we've successfully connected before, still allow selection
		// with a reduced score rather than excluding entirely
		if !ka.LastSuccess.IsZero() {
			return 0.5
		}
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
// Non-routable addresses (RFC1918 private, loopback, link-local, benchmarking,
// shared address space, documentation ranges, ORCHID/ORCHIDv2) are rejected,
// mirroring Bitcoin Core AddrMan::AddSingle which calls IsRoutable() before
// storing any gossip-learned address (addrman.cpp).
func (ab *AddressBook) AddAddress(addr NetAddress, source string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Reject non-routable addresses (Core: if (!addr.IsRoutable()) return false)
	if !isRoutableIP(addr.IP) {
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

// AddAddressV2 adds a BIP155 ADDRv2 address to the book.
// Currently, only IPv4 and IPv6 addresses are stored.
// Tor v3, I2P, and CJDNS addresses are accepted but not used for connections.
func (ab *AddressBook) AddAddressV2(addr NetAddressV2, source string) {
	// Convert to legacy format if possible
	// Currently we only connect to IPv4/IPv6 addresses
	switch addr.NetworkID {
	case NetIPv4, NetIPv6:
		legacy := addr.ToLegacy()
		if legacy != nil {
			ab.AddAddress(*legacy, source)
		}
	case NetTorV3, NetI2P, NetCJDNS:
		// TODO: In the future, we could store these separately
		// for relay to other peers or for Tor/I2P proxy connections.
		// For now, we ignore them.
	default:
		// Unknown network types are silently ignored per BIP155
	}
}

// AddAddressesV2 adds multiple BIP155 ADDRv2 addresses.
func (ab *AddressBook) AddAddressesV2(addrs []NetAddressV2, source string) {
	for _, addr := range addrs {
		ab.AddAddressV2(addr, source)
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

// AllAddresses returns a snapshot of all known addresses.
// Used by ASMapHealthCheck to enumerate AddrMan entries.
func (ab *AddressBook) AllAddresses() []*KnownAddress {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	all := make([]*KnownAddress, 0, len(ab.addrs))
	for _, ka := range ab.addrs {
		all = append(all, ka)
	}
	return all
}

// ShareableCount returns the number of addresses eligible to be advertised in a
// getaddr response — the pool over which the getaddr 23%-cap is computed. We
// share addresses we have successfully connected to (LastSuccess set), the same
// "Good" filter used by GetAddressesForGetAddr below; this is analogous to Core
// computing the cap over its addrman.
func (ab *AddressBook) ShareableCount() int {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	n := 0
	for _, ka := range ab.addrs {
		if !ka.LastSuccess.IsZero() {
			n++
		}
	}
	return n
}

// GetAddressesForGetAddr returns a randomly-selected subset of shareable
// addresses for answering a getaddr message, capped at the getaddr 23%-cap
// (min(MaxAddresses, floor(MaxPctAddrToSend*size/100))). Mirrors Bitcoin Core
// AddrManImpl::GetAddr_ (addrman.cpp:792): the percentage is applied over the
// shareable pool and the result is a random sample — never the full table.
func (ab *AddressBook) GetAddressesForGetAddr() []NetAddress {
	ab.mu.RLock()
	good := make([]*KnownAddress, 0, len(ab.addrs))
	for _, ka := range ab.addrs {
		if !ka.LastSuccess.IsZero() {
			good = append(good, ka)
		}
	}
	ab.mu.RUnlock()

	limit := getaddrCap(len(good))
	if limit <= 0 {
		return nil
	}

	// Random sample (Core returns a random permutation prefix from vRandom).
	ab.mu.Lock()
	ab.rand.Shuffle(len(good), func(i, j int) { good[i], good[j] = good[j], good[i] })
	ab.mu.Unlock()

	if limit > len(good) {
		limit = len(good)
	}
	out := make([]NetAddress, 0, limit)
	for _, ka := range good[:limit] {
		na := ka.Addr
		na.Timestamp = uint32(ka.LastSeen.Unix())
		if ka.LastSeen.IsZero() {
			na.Timestamp = uint32(time.Now().Unix())
		}
		out = append(out, na)
	}
	return out
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
