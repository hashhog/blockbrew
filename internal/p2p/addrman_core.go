package p2p

// addrman_core.go — full Bitcoin Core CAddrMan NEW/TRIED bucketed address
// manager, completing the half-bucketed AddressBook (addrbook.go) to the real
// stochastic model from bitcoin-core/src/addrman.{cpp,h} + addrman_impl.h.
//
// Northstar axis #2 (persistent bucketed addrman). blockbrew previously stored
// addresses in a flat map keyed by ip:port (AddressBook) with a Chance()-based
// weighted pick but no real buckets, no per-manager salt, and no peers.dat
// persistence (the W104/W128 gap suite documents the absence). This adds the
// Core data structure alongside AddressBook: NEW[1024][64] + TRIED[256][64]
// id-tables + mapInfo/mapAddr + a 256-bit nKey salt, with Core-exact
// deterministic placement, Add (new-bucket placement + IsTerrible/refcount
// collision), Good (promote new->tried, tried-collision evicts the occupant
// back to its new bucket), Select (50/50 new/tried bias), and a versioned,
// corrupt-safe, bounded peers.dat.
//
// Mirrors rustoshi 361d81b (the proven flat-map pilot). The existing
// AddressBook + KnownAddress + W104/W128 tests are left untouched.
//
// Reference: bitcoin-core/src/addrman.cpp
//   GetTriedBucket   = H(nKey, GetKey()) then H(nKey, group(addr), h1%8) % 256
//   GetNewBucket     = H(nKey, group(addr), group(src)) then H(nKey, group(src), h1%64) % 1024
//   GetBucketPosition= H(nKey, 'N'|'K', bucket, GetKey()) % 64
// Like rustoshi, the Core HashWriter::GetCheapHash (SipHash over a serialised
// stream) is replaced with a single SHA-256 cheap-hash of the concatenated
// parts (low 8 bytes, little-endian). blockbrew is a from-scratch impl; the
// placement only needs to be deterministic and Core-shaped (the 1024/256/64/
// 64/8 geometry + group-keyed, salted, anti-Sybil bucketing), not a wire-level
// match of Core's on-disk peers.dat.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Core ADDRMAN_ geometry constants (addrman_impl.h / addrman.h).
const (
	// ADDRMAN_NEW_BUCKET_COUNT = 1 << 10.
	AddrManNewBucketCount = 1024
	// ADDRMAN_TRIED_BUCKET_COUNT = 1 << 8.
	AddrManTriedBucketCount = 256
	// ADDRMAN_BUCKET_SIZE = 1 << 6. Positions per bucket.
	AddrManBucketSize = 64
	// ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP — anti-Sybil cap: a single source
	// group reaches only this many new buckets.
	AddrManNewBucketsPerSourceGroup = 64
	// ADDRMAN_TRIED_BUCKETS_PER_GROUP — anti-Sybil cap for tried.
	AddrManTriedBucketsPerGroup = 8
	// ADDRMAN_NEW_BUCKETS_PER_ADDRESS — max multiplicity in the new table.
	AddrManNewBucketsPerAddress = 8
	// ADDRMAN_HORIZON (30 days, seconds): older entries are terrible.
	AddrManHorizonSecs = 30 * 24 * 60 * 60
	// ADDRMAN_RETRIES — never-succeeded entry is terrible past this many tries.
	AddrManRetries = 3
	// ADDRMAN_MAX_FAILURES — successive-failure terrible gate.
	AddrManMaxFailures = 10
	// ADDRMAN_MIN_FAIL (7 days, seconds).
	AddrManMinFailSecs = 7 * 24 * 60 * 60

	// AddrManCeiling — total bounded slot ceiling: 1024*64 + 256*64 = 81920.
	AddrManCeiling = AddrManNewBucketCount*AddrManBucketSize + AddrManTriedBucketCount*AddrManBucketSize

	// peers.dat format version.
	AddrManDatVersion = 1
	// PeersDatabaseFilename — Core peers.dat equivalent.
	PeersDatabaseFilename = "peers.dat"
)

// nID is an internal entry identifier (Core nid_type). -1 means "empty slot".
type nID = int64

// addrManEntry is Core AddrInfo: a stored address plus connection bookkeeping.
type addrManEntry struct {
	Addr        NetAddress // the network address (ip:port)
	Services    uint64     // service flags
	SourceIP    net.IP     // who told us about this address (for group(src))
	TimeUnix    int64      // nTime — last advertised
	LastSuccess int64      // m_last_success (unix secs; 0 = never)
	LastTry     int64      // m_last_try (unix secs; 0 = never)
	Attempts    int        // nAttempts
	RefCount    int        // nRefCount — number of new buckets referencing this
	InTried     bool       // fInTried
}

// isTerrible mirrors Core AddrInfo::IsTerrible (addrman.cpp:49). now is unix s.
func (e *addrManEntry) isTerrible(now int64) bool {
	if now-e.LastTry <= 60 { // tried in the last minute — never remove
		return false
	}
	if e.TimeUnix > now+10*60 { // came in a flying DeLorean
		return true
	}
	if now-e.TimeUnix > AddrManHorizonSecs { // not seen in recent history
		return true
	}
	if e.LastSuccess == 0 && e.Attempts >= AddrManRetries { // never a success
		return true
	}
	if now-e.LastSuccess > AddrManMinFailSecs && e.Attempts >= AddrManMaxFailures {
		return true // N successive failures in the last week
	}
	return false
}

// AddrMan is the full Core CAddrMan: NEW/TRIED id-tables + maps + salt.
type AddrMan struct {
	mu sync.Mutex

	nKey    [32]byte           // per-manager 256-bit salt (Core nKey)
	vvNew   [][]nID            // [AddrManNewBucketCount][AddrManBucketSize]
	vvTried [][]nID            // [AddrManTriedBucketCount][AddrManBucketSize]
	mapInfo map[nID]*addrManEntry
	mapAddr map[string]nID     // ip:port -> id (Core mapAddr)
	idCount nID                // next id to allocate
	nNew    int                // ids referenced in the new table
	nTried  int                // ids in the tried table

	asmap []byte // optional AS map for GetGroup (nil = /16 fallback)
	rng   *mrand.Rand
}

// allocTable returns a buckets×slots table initialised to -1 (empty).
func allocTable(buckets int) [][]nID {
	t := make([][]nID, buckets)
	for b := range t {
		row := make([]nID, AddrManBucketSize)
		for i := range row {
			row[i] = -1
		}
		t[b] = row
	}
	return t
}

// NewAddrMan creates an empty manager with a random salt.
func NewAddrMan() *AddrMan {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		// crypto/rand failure is fatal-ish in Core; degrade to a math/rand salt
		// rather than panicking so a node never hard-downs on entropy issues.
		binary.LittleEndian.PutUint64(k[:8], uint64(time.Now().UnixNano()))
	}
	return NewAddrManWithKey(k)
}

// NewAddrManWithKey creates an empty manager with a fixed salt (deterministic;
// used by tests and persistence restore).
func NewAddrManWithKey(nKey [32]byte) *AddrMan {
	return &AddrMan{
		nKey:    nKey,
		vvNew:   allocTable(AddrManNewBucketCount),
		vvTried: allocTable(AddrManTriedBucketCount),
		mapInfo: make(map[nID]*addrManEntry),
		mapAddr: make(map[string]nID),
		rng:     mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

// SetASMap installs an AS map used by group() (reuses GetGroup from asmap.go).
func (am *AddrMan) SetASMap(asmap []byte) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.asmap = asmap
}

// NKey returns the salt bytes (test/persistence helper).
func (am *AddrMan) NKey() [32]byte {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.nKey
}

// cheapHash is the Core HashWriter::GetCheapHash analogue: single SHA-256 of
// the concatenated parts, low 8 bytes interpreted little-endian.
func cheapHash(parts ...[]byte) uint64 {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	sum := h.Sum(nil)
	return binary.LittleEndian.Uint64(sum[0:8])
}

// addrKey is the Core CService::GetKey analogue: 16-byte IPv6 representation +
// 2-byte big-endian port.
func addrManKey(addr NetAddress) []byte {
	ip := addr.IP.To16()
	if ip == nil {
		ip = net.IPv6zero
	}
	v := make([]byte, 0, 18)
	v = append(v, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], addr.Port)
	return append(v, pb[:]...)
}

// le8 encodes a uint64 little-endian (for hashing modular sub-indices, matching
// rustoshi's to_le_bytes feed).
func le8(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// le4 encodes a uint32 little-endian (bucket index feed for GetBucketPosition).
func le4(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// group returns the network-group bytes for an IP, reusing GetGroup from
// asmap.go (AS-keyed when an asmap is loaded, /16 fallback otherwise). This is
// the Core NetGroupManager::GetGroup input to the bucket hashes.
func (am *AddrMan) group(ip net.IP) []byte {
	return GetGroup(am.asmap, ip)
}

// getNewBucket mirrors Core AddrInfo::GetNewBucket.
func (am *AddrMan) getNewBucket(addrGroup, srcGroup []byte) int {
	hash1 := cheapHash(am.nKey[:], addrGroup, srcGroup)
	hash2 := cheapHash(am.nKey[:], srcGroup, le8(hash1%AddrManNewBucketsPerSourceGroup))
	return int(hash2 % AddrManNewBucketCount)
}

// getTriedBucket mirrors Core AddrInfo::GetTriedBucket.
func (am *AddrMan) getTriedBucket(addr NetAddress, addrGroup []byte) int {
	hash1 := cheapHash(am.nKey[:], addrManKey(addr))
	hash2 := cheapHash(am.nKey[:], addrGroup, le8(hash1%AddrManTriedBucketsPerGroup))
	return int(hash2 % AddrManTriedBucketCount)
}

// getBucketPosition mirrors Core AddrInfo::GetBucketPosition.
func (am *AddrMan) getBucketPosition(fNew bool, bucket int, addr NetAddress) int {
	tag := byte('K')
	if fNew {
		tag = 'N'
	}
	hash1 := cheapHash(am.nKey[:], []byte{tag}, le4(uint32(bucket)), addrManKey(addr))
	return int(hash1 % AddrManBucketSize)
}

// groupsOf returns the (addrGroup, srcGroup) bytes for an entry.
func (am *AddrMan) groupsOf(e *addrManEntry) (addrGroup, srcGroup []byte) {
	return am.group(e.Addr.IP), am.group(e.SourceIP)
}

// find returns the id for an address (Core Find), or -1.
func (am *AddrMan) find(addr NetAddress) nID {
	if id, ok := am.mapAddr[addrManKey2(addr)]; ok {
		return id
	}
	return -1
}

// addrManKey2 is the map key (ip:port string) for mapAddr lookups.
func addrManKey2(addr NetAddress) string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))
}

// create allocates a fresh entry (Core Create).
func (am *AddrMan) create(addr NetAddress, src net.IP, services uint64, timeUnix int64) nID {
	id := am.idCount
	am.idCount++
	am.mapInfo[id] = &addrManEntry{
		Addr:     addr,
		Services: services,
		SourceIP: src,
		TimeUnix: timeUnix,
	}
	am.mapAddr[addrManKey2(addr)] = id
	return id
}

// deleteIfFloating removes a refcount-0, non-tried id entirely (Core Delete).
func (am *AddrMan) deleteIfFloating(id nID) {
	if info, ok := am.mapInfo[id]; ok && info.RefCount == 0 && !info.InTried {
		delete(am.mapAddr, addrManKey2(info.Addr))
		delete(am.mapInfo, id)
	}
}

// clearNew clears a new-table slot, decrementing the occupant refcount and
// deleting at 0 (Core ClearNew).
func (am *AddrMan) clearNew(bucket, pos int) {
	id := am.vvNew[bucket][pos]
	if id == -1 {
		return
	}
	am.vvNew[bucket][pos] = -1
	info, ok := am.mapInfo[id]
	if !ok {
		return
	}
	if info.RefCount > 0 {
		info.RefCount--
	}
	if info.RefCount == 0 {
		if am.nNew > 0 {
			am.nNew--
		}
		am.deleteIfFloating(id)
	}
}

// Add places a heard-about address in the NEW table (Core Add_/AddSingle).
// source is the peer that advertised it. Returns true if a fresh slot insertion
// occurred. Non-routable addresses and the bounded-ceiling guard return false.
func (am *AddrMan) Add(addr NetAddress, source net.IP, services uint64, timeUnix int64) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.addLocked(addr, source, services, timeUnix)
}

func (am *AddrMan) addLocked(addr NetAddress, source net.IP, services uint64, timeUnix int64) bool {
	if !isRoutableIP(addr.IP) {
		return false
	}
	now := time.Now().Unix()

	id := am.find(addr)
	if id != -1 {
		// Refresh existing (Core AddSingle update path).
		info := am.mapInfo[id]
		if timeUnix > info.TimeUnix {
			info.TimeUnix = timeUnix
		}
		info.Services |= services
		if info.InTried {
			return false
		}
		if info.RefCount >= AddrManNewBucketsPerAddress {
			return false
		}
		// Stochastic multiplicity gate: 2^refcount harder each time.
		if info.RefCount > 0 {
			factor := 1 << uint(info.RefCount)
			if am.rng.Intn(factor) != 0 {
				return false
			}
		}
	} else {
		if len(am.mapInfo) >= AddrManCeiling {
			return false // bounded-ceiling guard
		}
		id = am.create(addr, source, services, timeUnix)
	}

	info := am.mapInfo[id]
	addrGroup, srcGroup := am.groupsOf(info)
	bucket := am.getNewBucket(addrGroup, srcGroup)
	pos := am.getBucketPosition(true, bucket, addr)

	occupant := am.vvNew[bucket][pos]
	insert := occupant == -1
	if occupant != id {
		if !insert {
			// Collision: overwrite iff occupant terrible, or occupant
			// multiply-referenced while the newcomer is fresh (Core rule).
			occ := am.mapInfo[occupant]
			if occ == nil || occ.isTerrible(now) || (occ.RefCount > 1 && info.RefCount == 0) {
				insert = true
			}
		}
		if insert {
			am.clearNew(bucket, pos)
			info.RefCount++
			am.vvNew[bucket][pos] = id
			am.nNew++
		} else if info.RefCount == 0 {
			am.deleteIfFloating(id) // newly created but not inserted -> drop
		}
	}
	return insert
}

// Good promotes an address from NEW to TRIED, evicting an existing tried
// occupant back to its NEW bucket on collision (Core Good_/MakeTried).
func (am *AddrMan) Good(addr NetAddress, nowUnix int64) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.goodLocked(addr, nowUnix)
}

func (am *AddrMan) goodLocked(addr NetAddress, nowUnix int64) bool {
	id := am.find(addr)
	if id == -1 {
		return false
	}
	info := am.mapInfo[id]
	info.LastSuccess = nowUnix
	info.LastTry = nowUnix
	info.Attempts = 0
	if info.InTried {
		return false
	}
	if info.RefCount == 0 {
		return false // not in new — something bad
	}

	// Remove the id from ALL its new buckets (Core MakeTried loop).
	addrGroup, srcGroup := am.groupsOf(info)
	start := am.getNewBucket(addrGroup, srcGroup)
	for n := 0; n < AddrManNewBucketCount; n++ {
		b := (start + n) % AddrManNewBucketCount
		p := am.getBucketPosition(true, b, addr)
		if am.vvNew[b][p] == id {
			am.vvNew[b][p] = -1
			if info.RefCount > 0 {
				info.RefCount--
			}
			if info.RefCount == 0 {
				break
			}
		}
	}
	if am.nNew > 0 {
		am.nNew--
	}
	info.RefCount = 0

	// Compute the tried slot.
	kBucket := am.getTriedBucket(addr, addrGroup)
	kPos := am.getBucketPosition(false, kBucket, addr)

	// On collision evict the existing tried occupant back to NEW.
	if evict := am.vvTried[kBucket][kPos]; evict != -1 {
		am.vvTried[kBucket][kPos] = -1
		if am.nTried > 0 {
			am.nTried--
		}
		old := am.mapInfo[evict]
		if old != nil {
			old.InTried = false
			oag, osg := am.groupsOf(old)
			ob := am.getNewBucket(oag, osg)
			op := am.getBucketPosition(true, ob, old.Addr)
			am.clearNew(ob, op)
			old.RefCount = 1
			am.vvNew[ob][op] = evict
			am.nNew++
		}
	}

	// Place the promoted id into tried.
	am.vvTried[kBucket][kPos] = id
	am.nTried++
	info.InTried = true
	return true
}

// Attempt records a (possibly-failed) connection attempt (Core Attempt_).
func (am *AddrMan) Attempt(addr NetAddress, nowUnix int64) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if id := am.find(addr); id != -1 {
		info := am.mapInfo[id]
		info.LastTry = nowUnix
		info.Attempts++
	}
}

// Select chooses an address with the Core 50/50 new-vs-tried bias. When
// newOnly is true, only the new table is searched. Returns the address and
// true, or a zero NetAddress and false when empty. Bounded scan (never loops
// forever like Core's random-reject Select_; liveness-safe analogue).
func (am *AddrMan) Select(newOnly bool) (NetAddress, bool) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if len(am.mapInfo) == 0 {
		return NetAddress{}, false
	}
	if newOnly && am.nNew == 0 {
		return NetAddress{}, false
	}
	if am.nNew+am.nTried == 0 {
		return NetAddress{}, false
	}

	searchTried := false
	switch {
	case newOnly || am.nTried == 0:
		searchTried = false
	case am.nNew == 0:
		searchTried = true
	default:
		searchTried = am.rng.Intn(2) == 0 // 50/50
	}

	var table [][]nID
	var bucketCount int
	if searchTried {
		table, bucketCount = am.vvTried, AddrManTriedBucketCount
	} else {
		table, bucketCount = am.vvNew, AddrManNewBucketCount
	}

	startBucket := am.rng.Intn(bucketCount)
	initialPos := am.rng.Intn(AddrManBucketSize)
	for nb := 0; nb < bucketCount; nb++ {
		bucket := (startBucket + nb) % bucketCount
		for i := 0; i < AddrManBucketSize; i++ {
			pos := (initialPos + i) % AddrManBucketSize
			id := table[bucket][pos]
			if id != -1 {
				if info, ok := am.mapInfo[id]; ok {
					return info.Addr, true
				}
			}
		}
	}
	return NetAddress{}, false
}

// NewCount returns the number of addresses in the NEW table.
func (am *AddrMan) NewCount() int {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.nNew
}

// TriedCount returns the number of addresses in the TRIED table.
func (am *AddrMan) TriedCount() int {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.nTried
}

// TotalCount returns the number of distinct ids tracked (bounded by ceiling).
func (am *AddrMan) TotalCount() int {
	am.mu.Lock()
	defer am.mu.Unlock()
	return len(am.mapInfo)
}

// IsInTried reports whether addr is in the TRIED table.
func (am *AddrMan) IsInTried(addr NetAddress) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	if id := am.find(addr); id != -1 {
		if info, ok := am.mapInfo[id]; ok {
			return info.InTried
		}
	}
	return false
}

// NewSlotOf recomputes the (bucket, pos) addr currently occupies in NEW, or
// (-1,-1) if not in NEW. Used by determinism tests.
func (am *AddrMan) NewSlotOf(addr NetAddress) (int, int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	id := am.find(addr)
	if id == -1 {
		return -1, -1
	}
	info := am.mapInfo[id]
	if info.InTried {
		return -1, -1
	}
	addrGroup, srcGroup := am.groupsOf(info)
	start := am.getNewBucket(addrGroup, srcGroup)
	for n := 0; n < AddrManNewBucketCount; n++ {
		b := (start + n) % AddrManNewBucketCount
		p := am.getBucketPosition(true, b, addr)
		if am.vvNew[b][p] == id {
			return b, p
		}
	}
	return -1, -1
}

// TriedSlotOf returns the (bucket, pos) addr occupies in TRIED, or (-1,-1).
func (am *AddrMan) TriedSlotOf(addr NetAddress) (int, int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	id := am.find(addr)
	if id == -1 {
		return -1, -1
	}
	info := am.mapInfo[id]
	if !info.InTried {
		return -1, -1
	}
	addrGroup, _ := am.groupsOf(info)
	kb := am.getTriedBucket(addr, addrGroup)
	kp := am.getBucketPosition(false, kb, addr)
	return kb, kp
}

// --- Persistence (peers.dat-equiv) ------------------------------------------

// serialize writes the versioned, line-oriented form. Format:
//   line 0: "ADDRMAN <version> <nkey-hex>"
//   then one record per id:
//     "<n|t> <ip> <port> <services> <source-ip> <time> <last_success> <last_try> <attempts> <ref_count>"
// New records are restored via Add (new-bucket placement recomputed); tried
// records are re-promoted via Good so placement is recomputed from the same
// nKey on load.
func (am *AddrMan) serialize() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ADDRMAN %d %s\n", AddrManDatVersion, hex.EncodeToString(am.nKey[:]))
	for _, info := range am.mapInfo {
		tag := "n"
		if info.InTried {
			tag = "t"
		}
		srcIP := "0.0.0.0"
		if info.SourceIP != nil {
			srcIP = info.SourceIP.String()
		}
		fmt.Fprintf(&sb, "%s %s %d %d %s %d %d %d %d %d\n",
			tag,
			info.Addr.IP.String(),
			info.Addr.Port,
			info.Services,
			srcIP,
			info.TimeUnix,
			info.LastSuccess,
			info.LastTry,
			info.Attempts,
			info.RefCount,
		)
	}
	return sb.String()
}

// Save atomically writes <dataDir>/peers.dat (temp + rename). Best-effort;
// failures are returned but are never fatal to the caller.
func (am *AddrMan) Save(dataDir string) error {
	am.mu.Lock()
	data := am.serialize()
	am.mu.Unlock()

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dataDir, PeersDatabaseFilename)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadAddrMan reads <dataDir>/peers.dat, re-bucketing via Add/Good so placement
// is recomputed from the persisted nKey. Corrupt / truncated / wrong-version /
// missing files yield a graceful empty cold start (never a panic). Bounded by
// the ceiling.
func LoadAddrMan(dataDir string) *AddrMan {
	path := filepath.Join(dataDir, PeersDatabaseFilename)
	f, err := os.Open(path)
	if err != nil {
		return NewAddrMan() // missing -> cold start
	}
	defer f.Close()
	am, ok := parseAddrMan(bufio.NewScanner(f))
	if !ok {
		return NewAddrMan() // corrupt -> cold start
	}
	return am
}

// parseAddrMan parses the serialized form. Returns (nil,false) on any
// structural problem so the caller can cold-start. Split out for in-process
// tests.
func parseAddrMan(sc *bufio.Scanner) (*AddrMan, bool) {
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !sc.Scan() {
		return nil, false
	}
	header := strings.Fields(sc.Text())
	if len(header) != 3 || header[0] != "ADDRMAN" {
		return nil, false
	}
	version, err := strconv.Atoi(header[1])
	if err != nil || version != AddrManDatVersion {
		return nil, false
	}
	keyBytes, err := hex.DecodeString(header[2])
	if err != nil || len(keyBytes) != 32 {
		return nil, false
	}
	var nKey [32]byte
	copy(nKey[:], keyBytes)
	am := NewAddrManWithKey(nKey)

	type rec struct {
		addr        NetAddress
		src         net.IP
		services    uint64
		timeUnix    int64
		lastSuccess int64
		lastTry     int64
		attempts    int
		tried       bool
	}
	var triedRecs []NetAddress

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(am.mapInfo) >= AddrManCeiling {
			break // bounded
		}
		fields := strings.Fields(line)
		if len(fields) != 10 {
			return nil, false // structural problem -> cold start
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			return nil, false
		}
		portN, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil {
			return nil, false
		}
		services, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return nil, false
		}
		srcIP := net.ParseIP(fields[4])
		r := rec{
			addr:     NetAddress{IP: ip.To16(), Port: uint16(portN)},
			src:      srcIP,
			services: services,
			tried:    fields[0] == "t",
		}
		if r.timeUnix, err = strconv.ParseInt(fields[5], 10, 64); err != nil {
			return nil, false
		}
		if r.lastSuccess, err = strconv.ParseInt(fields[6], 10, 64); err != nil {
			return nil, false
		}
		if r.lastTry, err = strconv.ParseInt(fields[7], 10, 64); err != nil {
			return nil, false
		}
		if r.attempts, err = strconv.Atoi(fields[8]); err != nil {
			return nil, false
		}
		// fields[9] (ref_count) is recomputed by Add; parsed for validation.
		if _, err := strconv.Atoi(fields[9]); err != nil {
			return nil, false
		}

		// Re-create via Add so the new-bucket placement is recomputed.
		am.addLocked(r.addr, r.src, r.services, r.timeUnix)
		if id := am.find(r.addr); id != -1 {
			info := am.mapInfo[id]
			info.LastSuccess = r.lastSuccess
			info.LastTry = r.lastTry
			info.Attempts = r.attempts
		}
		if r.tried {
			triedRecs = append(triedRecs, r.addr)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, false
	}

	// Second pass: promote the tried records.
	now := time.Now().Unix()
	for _, addr := range triedRecs {
		am.goodLocked(addr, now)
	}
	return am, true
}
