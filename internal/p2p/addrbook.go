package p2p

import (
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// isRoutableIP returns true if ip is publicly routable on the global internet,
// mirroring Bitcoin Core's CNetAddr::IsRoutable() in netaddress.cpp:462.
//
// Core rejects: RFC1918, RFC2544, RFC3927, RFC4862, RFC6598, RFC5737,
//
//	RFC4193, RFC4843, RFC7343, local (loopback/unspecified), internal.
//
// Go stdlib covers: loopback (IsLoopback), RFC1918+RFC4193 (IsPrivate),
//
//	RFC3927+RFC4862 link-local (IsLinkLocalUnicast).
//
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
		"198.18.0.0/15",   // RFC2544 benchmarking
		"100.64.0.0/10",   // RFC6598 shared address space (CGNAT)
		"192.0.2.0/24",    // RFC5737 TEST-NET-1
		"198.51.100.0/24", // RFC5737 TEST-NET-2
		"203.0.113.0/24",  // RFC5737 TEST-NET-3
		"2001:10::/28",    // RFC4843 ORCHID
		"2001:20::/28",    // RFC7343 ORCHIDv2
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

// clampAddrTimestamp applies the Bitcoin Core net_processing.cpp:5678-5680
// timestamp clamp to a peer-advertised addr/addrv2 nTime value.
//
// Core clamps a received nTime to (now - 5*24h) when it is either:
//   - pre-2001 (Unix timestamp <= 100000000, i.e., before 2001-03-09), or
//   - more than 10 minutes in the future (> now + 10 min).
//
// This prevents peers from poisoning our address manager with bogus
// last-seen timestamps (either extremely stale or far-future values).
func clampAddrTimestamp(ts uint32, now time.Time) time.Time {
	const (
		pre2001Cutoff = 100_000_000 // Unix seconds ≈ 2001-03-09
		futureSlack   = 10 * time.Minute
		staleDefault  = 5 * 24 * time.Hour // Core: current_time - 5*24h
	)
	t := time.Unix(int64(ts), 0)
	if ts <= pre2001Cutoff || t.After(now.Add(futureSlack)) {
		t = now.Add(-staleDefault)
	}
	return t
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

	// Apply Core net_processing.cpp:5678-5680 timestamp clamp before storing.
	// Zero means "no timestamp supplied" (e.g. DNS seed entries); fall back to
	// now so the address is immediately useful for selection scoring.
	now := time.Now()
	var lastSeen time.Time
	if addr.Timestamp == 0 {
		lastSeen = now
	} else {
		lastSeen = clampAddrTimestamp(addr.Timestamp, now)
	}

	key := addrKey(addr)

	// Check if we already have this address
	if existing, ok := ab.addrs[key]; ok {
		// Update last seen time only if the incoming timestamp is more recent.
		if lastSeen.After(existing.LastSeen) {
			existing.LastSeen = lastSeen
		}
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
		LastSeen: lastSeen,
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

// --- Persistence (peers.json) -----------------------------------------------
//
// Bitcoin Core persists its address manager to peers.dat on shutdown
// (CAddrDB::Write, addrdb.cpp) and reloads it on startup (DumpAddresses /
// CAddrDB::Read) so a node does not forget its learned peer set across a
// restart — losing that set on every restart is an eclipse/bootstrap-fragility
// hazard. blockbrew's live PeerManager uses this flat AddressBook (not the
// Core-exact bucketed AddrMan), so we serialize the AddressBook's entries to a
// JSON peers file. This is P2P/peer-discovery state only — it never touches
// block or transaction validation.

// AddressBookFilename is the file blockbrew persists the live AddressBook to.
// Distinct from PeersDatabaseFilename ("peers.dat", used by the bucketed
// AddrMan) so the two on-disk formats never collide.
const AddressBookFilename = "peers.json"

// knownAddressJSON is the on-disk form of a KnownAddress. Times are stored as
// Unix seconds (0 = zero time) so the format is compact and self-describing;
// the IP is stored as its string form (To16-normalised on load).
type knownAddressJSON struct {
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
	Services    uint64 `json:"services"`
	Source      string `json:"source"`
	LastAttempt int64  `json:"last_attempt"`
	LastSuccess int64  `json:"last_success"`
	Attempts    int    `json:"attempts"`
	LastSeen    int64  `json:"last_seen"`
}

// addressBookJSON is the versioned on-disk container.
type addressBookJSON struct {
	Version int                `json:"version"`
	Addrs   []knownAddressJSON `json:"addrs"`
}

// addressBookDatVersion is the peers.json format version. Bump on any
// incompatible field change; loadFile cold-starts on a version mismatch.
const addressBookDatVersion = 1

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0)
}

// snapshotJSON returns the serializable form of every known address, taken
// under the read lock.
func (ab *AddressBook) snapshotJSON() addressBookJSON {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	out := addressBookJSON{
		Version: addressBookDatVersion,
		Addrs:   make([]knownAddressJSON, 0, len(ab.addrs)),
	}
	for _, ka := range ab.addrs {
		out.Addrs = append(out.Addrs, knownAddressJSON{
			IP:          ka.Addr.IP.String(),
			Port:        ka.Addr.Port,
			Services:    ka.Addr.Services,
			Source:      ka.Source,
			LastAttempt: unixOrZero(ka.LastAttempt),
			LastSuccess: unixOrZero(ka.LastSuccess),
			Attempts:    ka.Attempts,
			LastSeen:    unixOrZero(ka.LastSeen),
		})
	}
	return out
}

// Save atomically writes the address book to <dataDir>/peers.json (temp file +
// rename), mirroring Bitcoin Core's CAddrDB::Write atomicity. An empty dataDir
// is a no-op (matches the PeerManager ban-list / anchors convention). Failures
// are returned but are never fatal to the caller.
func (ab *AddressBook) Save(dataDir string) error {
	if dataDir == "" {
		return nil
	}

	data, err := json.MarshalIndent(ab.snapshotJSON(), "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dataDir, AddressBookFilename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Load reads <dataDir>/peers.json and restores the saved entries into the book.
// A missing file (cold start), an empty dataDir, a corrupt/truncated file, or a
// version mismatch are all non-fatal: the book is simply left unchanged
// (graceful cold start, never a panic), mirroring Core's tolerant CAddrDB::Read.
// Returns the number of addresses restored.
func (ab *AddressBook) Load(dataDir string) int {
	if dataDir == "" {
		return 0
	}
	path := filepath.Join(dataDir, AddressBookFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0 // missing -> cold start
	}

	var container addressBookJSON
	if err := json.Unmarshal(raw, &container); err != nil {
		return 0 // corrupt -> cold start
	}
	if container.Version != addressBookDatVersion {
		return 0 // unknown version -> cold start
	}

	ab.mu.Lock()
	defer ab.mu.Unlock()

	loaded := 0
	for _, r := range container.Addrs {
		ip := net.ParseIP(r.IP)
		if ip == nil {
			continue // skip malformed records rather than aborting the load
		}
		if len(ab.addrs) >= AddressBookMaxSize {
			break // honour the bound
		}
		na := NetAddress{
			Services: r.Services,
			IP:       ip.To16(),
			Port:     r.Port,
		}
		key := addrKey(na)
		if _, exists := ab.addrs[key]; exists {
			continue
		}
		ab.addrs[key] = &KnownAddress{
			Addr:        na,
			Source:      r.Source,
			LastAttempt: timeOrZero(r.LastAttempt),
			LastSuccess: timeOrZero(r.LastSuccess),
			Attempts:    r.Attempts,
			LastSeen:    timeOrZero(r.LastSeen),
		}
		loaded++
	}
	return loaded
}
