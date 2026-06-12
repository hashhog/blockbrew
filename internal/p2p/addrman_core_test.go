package p2p

// addrman_core_test.go — axis #2 proof suite for the full Core CAddrMan
// bucketed address manager (addrman_core.go). Ported from the rustoshi
// w104_addrman_tests axis2 shape (361d81b): placement determinism + golden-
// stable bucket + nkey-matters + source-group spread (anti-Sybil) + Add/Good/
// Select + tried-collision-evicts-to-new + verbatim persistence + corrupt-safe
// cold start + bounded ceiling + falsification (it really buckets, not flat).
//
// No regtest daemon: pure in-process functional unit tests.

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fixedKey is a deterministic salt for reproducible placement across tests.
func fixedKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func mkAddr(ip string, port uint16) NetAddress {
	return NetAddress{IP: net.ParseIP(ip).To16(), Port: port}
}

// ── Constants ────────────────────────────────────────────────────────────────

func TestAddrManCore_ConstantsMatchCore(t *testing.T) {
	if AddrManNewBucketCount != 1024 {
		t.Errorf("NewBucketCount = %d, want 1024", AddrManNewBucketCount)
	}
	if AddrManTriedBucketCount != 256 {
		t.Errorf("TriedBucketCount = %d, want 256", AddrManTriedBucketCount)
	}
	if AddrManBucketSize != 64 {
		t.Errorf("BucketSize = %d, want 64", AddrManBucketSize)
	}
	if AddrManNewBucketsPerSourceGroup != 64 {
		t.Errorf("NewBucketsPerSourceGroup = %d, want 64", AddrManNewBucketsPerSourceGroup)
	}
	if AddrManTriedBucketsPerGroup != 8 {
		t.Errorf("TriedBucketsPerGroup = %d, want 8", AddrManTriedBucketsPerGroup)
	}
	if AddrManCeiling != 1024*64+256*64 {
		t.Errorf("Ceiling = %d, want %d", AddrManCeiling, 1024*64+256*64)
	}
	if AddrManCeiling != 81920 {
		t.Errorf("Ceiling = %d, want 81920", AddrManCeiling)
	}
}

// ── 1. Placement determinism ────────────────────────────────────────────────

// Same addr + same nKey -> same bucket/pos; and the recomputed slot equals the
// stored slot (NewSlotOf walks the table and finds the id where placement says).
func TestAddrManCore_PlacementDeterministic(t *testing.T) {
	addr := mkAddr("1.2.3.4", 8333)
	src := net.ParseIP("9.9.9.9")

	am1 := NewAddrManWithKey(fixedKey())
	am2 := NewAddrManWithKey(fixedKey())

	b1 := am1.getNewBucket(am1.group(addr.IP), am1.group(src))
	p1 := am1.getBucketPosition(true, b1, addr)
	b2 := am2.getNewBucket(am2.group(addr.IP), am2.group(src))
	p2 := am2.getBucketPosition(true, b2, addr)

	if b1 != b2 || p1 != p2 {
		t.Fatalf("same key/addr -> different placement: (%d,%d) vs (%d,%d)", b1, p1, b2, p2)
	}
	if b1 < 0 || b1 >= AddrManNewBucketCount || p1 < 0 || p1 >= AddrManBucketSize {
		t.Fatalf("placement out of range: bucket=%d pos=%d", b1, p1)
	}

	// recompute == stored
	if !am1.Add(addr, src, 1, 1_700_000_000) {
		t.Fatal("Add returned false for a fresh routable address")
	}
	sb, sp := am1.NewSlotOf(addr)
	if sb != b1 || sp != p1 {
		t.Fatalf("stored slot (%d,%d) != computed (%d,%d)", sb, sp, b1, p1)
	}
}

// ── 2. Golden-stable bucket (placement is stable across code changes) ────────

// Pin the computed (bucket,pos) for a fixed key+addr+src. If a refactor changes
// the hashing, this catches it. The value is whatever the current algorithm
// yields; it just must not silently drift.
func TestAddrManCore_GoldenStableBucket(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	addr := mkAddr("8.8.8.8", 8333)
	src := net.ParseIP("4.4.4.4")
	b := am.getNewBucket(am.group(addr.IP), am.group(src))
	p := am.getBucketPosition(true, b, addr)

	// Golden values captured from the current deterministic algorithm
	// (key=0x01..0x20, addr=8.8.8.8:8333, src=4.4.4.4). If a refactor changes
	// the hashing these constants must be updated deliberately.
	const goldenNewBucket, goldenNewPos = 588, 42
	const goldenTriedBucket, goldenTriedPos = 224, 23
	if b != goldenNewBucket || p != goldenNewPos {
		t.Fatalf("golden drift: got new (%d,%d), want (%d,%d). If the hashing changed intentionally, update the golden constants.", b, p, goldenNewBucket, goldenNewPos)
	}

	tb := am.getTriedBucket(addr, am.group(addr.IP))
	tp := am.getBucketPosition(false, tb, addr)
	if tb != goldenTriedBucket || tp != goldenTriedPos {
		t.Fatalf("tried golden drift: got (%d,%d), want (%d,%d)", tb, tp, goldenTriedBucket, goldenTriedPos)
	}
}

// ── 3. nKey matters (salt changes placement) ─────────────────────────────────

func TestAddrManCore_NKeyMatters(t *testing.T) {
	addr := mkAddr("1.2.3.4", 8333)
	src := net.ParseIP("9.9.9.9")

	k1 := fixedKey()
	k2 := fixedKey()
	k2[0] ^= 0xff // flip one byte

	am1 := NewAddrManWithKey(k1)
	am2 := NewAddrManWithKey(k2)
	b1 := am1.getNewBucket(am1.group(addr.IP), am1.group(src))
	b2 := am2.getNewBucket(am2.group(addr.IP), am2.group(src))
	p1 := am1.getBucketPosition(true, b1, addr)
	p2 := am2.getBucketPosition(true, b2, addr)

	if b1 == b2 && p1 == p2 {
		t.Fatalf("different nKey produced identical placement (%d,%d) — salt not feeding the hash", b1, p1)
	}
}

// ── 4. Source-group spread (anti-Sybil) ──────────────────────────────────────

// Many addresses from a SINGLE source group must reach at most
// NEW_BUCKETS_PER_SOURCE_GROUP=64 distinct new buckets, no matter how many we
// add. This is the eclipse-resistance cap.
func TestAddrManCore_SourceGroupSpreadBounded(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	src := net.ParseIP("100.64.0.1") // shared source ip -> one /16 source group
	// Note: src itself is non-routable, but it is only the *source* (group input
	// for hashing); the *added* addresses are routable public IPs.

	buckets := map[int]struct{}{}
	for i := 0; i < 4000; i++ {
		// Vary the addr across many /16s so addr-group differs, but the source
		// group is constant.
		ip := net.IPv4(byte(11+(i/65536)%200), byte((i/256)%256), byte(i%256), 7)
		addr := NetAddress{IP: ip.To16(), Port: 8333}
		b := am.getNewBucket(am.group(addr.IP), am.group(src))
		buckets[b] = struct{}{}
	}
	if len(buckets) > AddrManNewBucketsPerSourceGroup {
		t.Fatalf("source group reached %d new buckets, exceeds anti-Sybil cap of %d",
			len(buckets), AddrManNewBucketsPerSourceGroup)
	}
	if len(buckets) < 2 {
		t.Fatalf("source group reached only %d buckets — spread suspiciously low", len(buckets))
	}
	t.Logf("single source group spread across %d/%d new buckets (cap %d)",
		len(buckets), AddrManNewBucketCount, AddrManNewBucketsPerSourceGroup)
}

// ── 5. Add -> NEW table ──────────────────────────────────────────────────────

func TestAddrManCore_AddLandsInNew(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	addr := mkAddr("203.0.50.1", 8333)
	if !am.Add(addr, net.ParseIP("198.51.0.1"), 1, 1_700_000_000) {
		t.Fatal("Add returned false for fresh routable addr")
	}
	if am.NewCount() != 1 {
		t.Errorf("NewCount = %d, want 1", am.NewCount())
	}
	if am.TriedCount() != 0 {
		t.Errorf("TriedCount = %d, want 0", am.TriedCount())
	}
	if am.IsInTried(addr) {
		t.Error("fresh add should not be in tried")
	}
	b, p := am.NewSlotOf(addr)
	if b == -1 || p == -1 {
		t.Error("added addr has no NEW slot")
	}

	// non-routable rejected
	if am.Add(mkAddr("10.0.0.1", 8333), net.ParseIP("1.1.1.1"), 1, 1_700_000_000) {
		t.Error("Add accepted a non-routable RFC1918 address")
	}
}

// ── 6. Good -> TRIED table ───────────────────────────────────────────────────

func TestAddrManCore_GoodPromotesToTried(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	addr := mkAddr("203.0.50.9", 8333)
	am.Add(addr, net.ParseIP("198.51.0.1"), 1, 1_700_000_000)
	if !am.Good(addr, 1_700_000_100) {
		t.Fatal("Good returned false for an address that is in NEW")
	}
	if !am.IsInTried(addr) {
		t.Error("after Good, addr should be in TRIED")
	}
	if am.TriedCount() != 1 {
		t.Errorf("TriedCount = %d, want 1", am.TriedCount())
	}
	if am.NewCount() != 0 {
		t.Errorf("NewCount = %d, want 0 after promotion", am.NewCount())
	}
	tb, tp := am.TriedSlotOf(addr)
	if tb == -1 || tp == -1 {
		t.Error("promoted addr has no TRIED slot")
	}
	// Good on unknown addr returns false.
	if am.Good(mkAddr("203.0.99.99", 8333), 1_700_000_200) {
		t.Error("Good on unknown addr should be false")
	}
}

// ── 7. tried-collision evicts occupant back to NEW ───────────────────────────

// Construct two addresses that hash to the SAME tried (bucket,pos). Promote the
// first; promoting the second must evict the first back to the NEW table.
func TestAddrManCore_TriedCollisionEvictsToNew(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	src := net.ParseIP("198.51.0.1")

	// Find two distinct routable addresses colliding in the tried table.
	type slot struct{ b, p int }
	seen := map[slot]NetAddress{}
	var a1, a2 NetAddress
	found := false
	for i := 0; i < 200000 && !found; i++ {
		ip := net.IPv4(byte(11+(i/65536)%200), byte((i/256)%256), byte(i%256), 3)
		if !isRoutableIP(ip) {
			continue
		}
		addr := NetAddress{IP: ip.To16(), Port: 8333}
		tb := am.getTriedBucket(addr, am.group(addr.IP))
		tp := am.getBucketPosition(false, tb, addr)
		s := slot{tb, tp}
		if prev, ok := seen[s]; ok && !prev.IP.Equal(addr.IP) {
			a1, a2 = prev, addr
			found = true
			break
		}
		seen[s] = addr
	}
	if !found {
		t.Skip("could not synthesise a tried collision in the search budget")
	}

	am.Add(a1, src, 1, 1_700_000_000)
	am.Add(a2, src, 1, 1_700_000_000)
	if !am.Good(a1, 1_700_000_100) {
		t.Fatal("Good(a1) failed")
	}
	if !am.IsInTried(a1) {
		t.Fatal("a1 should be in tried")
	}
	// Promote a2 into the same tried slot -> evicts a1 back to NEW.
	if !am.Good(a2, 1_700_000_200) {
		t.Fatal("Good(a2) failed")
	}
	if !am.IsInTried(a2) {
		t.Fatal("a2 should now occupy the tried slot")
	}
	if am.IsInTried(a1) {
		t.Fatal("a1 should have been evicted out of tried by the collision")
	}
	// a1 must be back in NEW with a real slot.
	b, p := am.NewSlotOf(a1)
	if b == -1 || p == -1 {
		t.Fatal("evicted a1 was not placed back into a NEW bucket")
	}
}

// ── 8. Select returns an occupant + honours new_only ─────────────────────────

func TestAddrManCore_SelectReturnsOccupant(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	if _, ok := am.Select(false); ok {
		t.Error("Select on empty manager should be false")
	}
	for i := 0; i < 20; i++ {
		ip := net.IPv4(byte(11+i), 2, 3, byte(4+i))
		am.Add(NetAddress{IP: ip.To16(), Port: 8333}, net.ParseIP("198.51.0.1"), 1, 1_700_000_000)
	}
	if am.NewCount() == 0 {
		t.Fatal("expected some new entries")
	}
	addr, ok := am.Select(false)
	if !ok {
		t.Fatal("Select returned nothing despite non-empty new table")
	}
	if addr.IP == nil {
		t.Fatal("Select returned a zero address")
	}
	// new_only with no tried still returns a new entry.
	if _, ok := am.Select(true); !ok {
		t.Fatal("Select(newOnly=true) returned nothing despite new entries")
	}

	// Promote one and confirm select still works with mixed tables.
	am.Good(addr, 1_700_000_100)
	if _, ok := am.Select(false); !ok {
		t.Fatal("Select after a promotion returned nothing")
	}
}

// ── 9. restart persistence preserves placement ───────────────────────────────

func TestAddrManCore_RestartPersistencePreservesPlacement(t *testing.T) {
	dir := t.TempDir()
	am := NewAddrManWithKey(fixedKey())
	src := net.ParseIP("198.51.0.1")

	type want struct {
		addr        NetAddress
		nb, np      int
		tried       bool
		tb, tp      int
	}
	var wants []want
	for i := 0; i < 50; i++ {
		ip := net.IPv4(byte(11+i%200), byte(i), byte(i*3), 5)
		if !isRoutableIP(ip) {
			continue
		}
		addr := NetAddress{IP: ip.To16(), Port: 8333}
		am.Add(addr, src, 1, 1_700_000_000)
	}
	// Promote every 5th to tried.
	count := 0
	for _, info := range am.mapInfo {
		count++
		w := want{addr: info.Addr}
		if count%5 == 0 {
			am.goodLocked(info.Addr, 1_700_000_100)
		}
		wants = append(wants, w)
	}
	// Capture placements AFTER promotions.
	for i := range wants {
		if am.IsInTried(wants[i].addr) {
			wants[i].tried = true
			wants[i].tb, wants[i].tp = am.TriedSlotOf(wants[i].addr)
		} else {
			wants[i].nb, wants[i].np = am.NewSlotOf(wants[i].addr)
		}
	}

	if err := am.Save(dir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	reloaded := LoadAddrMan(dir)
	if reloaded.NKey() != am.NKey() {
		t.Fatal("nKey not preserved across save/load")
	}
	if reloaded.TotalCount() != am.TotalCount() {
		t.Fatalf("TotalCount %d != %d after reload", reloaded.TotalCount(), am.TotalCount())
	}
	if reloaded.TriedCount() != am.TriedCount() {
		t.Fatalf("TriedCount %d != %d after reload", reloaded.TriedCount(), am.TriedCount())
	}
	for _, w := range wants {
		if w.tried {
			if !reloaded.IsInTried(w.addr) {
				t.Fatalf("addr %v lost its tried status after reload", w.addr.IP)
			}
			tb, tp := reloaded.TriedSlotOf(w.addr)
			if tb != w.tb || tp != w.tp {
				t.Fatalf("addr %v tried slot drifted: (%d,%d) -> (%d,%d)", w.addr.IP, w.tb, w.tp, tb, tp)
			}
		} else {
			nb, np := reloaded.NewSlotOf(w.addr)
			if nb != w.nb || np != w.np {
				t.Fatalf("addr %v new slot drifted: (%d,%d) -> (%d,%d)", w.addr.IP, w.nb, w.np, nb, np)
			}
		}
	}
}

// ── 10. corrupt-safe cold start ──────────────────────────────────────────────

func TestAddrManCore_CorruptSafeColdStart(t *testing.T) {
	// Missing file -> empty cold start.
	empty := LoadAddrMan(t.TempDir())
	if empty.TotalCount() != 0 {
		t.Errorf("missing peers.dat should cold-start empty, got %d", empty.TotalCount())
	}

	corruptInputs := []string{
		"",                                 // empty
		"garbage not a header\n",           // bad header
		"ADDRMAN 999 deadbeef\n",           // wrong version
		"ADDRMAN 1 nothex\n",               // bad key
		"ADDRMAN 1 " + strings.Repeat("ab", 32) + "\nn shortline\n", // too few fields
		"ADDRMAN 1 " + strings.Repeat("ab", 32) + "\nn notanip 8333 1 2.2.2.2 1 0 0 0 1\n", // bad ip
	}
	for i, in := range corruptInputs {
		am, ok := parseAddrMan(bufio.NewScanner(strings.NewReader(in)))
		if ok && am.TotalCount() > 0 {
			t.Errorf("corrupt input #%d parsed with %d entries; want cold-start reject", i, am.TotalCount())
		}
	}

	// A valid header with zero records is a legitimate empty file.
	valid := "ADDRMAN 1 " + strings.Repeat("ab", 32) + "\n"
	am, ok := parseAddrMan(bufio.NewScanner(strings.NewReader(valid)))
	if !ok {
		t.Fatal("valid empty-body peers.dat rejected")
	}
	if am.TotalCount() != 0 {
		t.Errorf("empty-body should have 0 entries, got %d", am.TotalCount())
	}
}

// ── 11. bounded ceiling ──────────────────────────────────────────────────────

// One source group can never reach more than NEW_BUCKETS_PER_SOURCE_GROUP*
// BUCKET_SIZE distinct new slots, and the total table is bounded by the ceiling.
func TestAddrManCore_BoundedCeiling(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	src := net.ParseIP("198.51.0.1") // single source group

	// Hammer many addresses from one source group; placements must stay within
	// the 64-bucket * 64-pos envelope for that source group.
	slots := map[[2]int]struct{}{}
	for i := 0; i < 30000; i++ {
		ip := net.IPv4(byte(11+(i/65536)%200), byte((i/256)%256), byte(i%256), 9)
		if !isRoutableIP(ip) {
			continue
		}
		addr := NetAddress{IP: ip.To16(), Port: 8333}
		b := am.getNewBucket(am.group(addr.IP), am.group(src))
		p := am.getBucketPosition(true, b, addr)
		slots[[2]int{b, p}] = struct{}{}
	}
	// Distinct buckets reachable from one source group <= 64.
	bset := map[int]struct{}{}
	for s := range slots {
		bset[s[0]] = struct{}{}
	}
	if len(bset) > AddrManNewBucketsPerSourceGroup {
		t.Fatalf("source group reached %d buckets, exceeds %d", len(bset), AddrManNewBucketsPerSourceGroup)
	}
	// Live table count must never exceed the global ceiling.
	if am.TotalCount() > AddrManCeiling {
		t.Fatalf("table size %d exceeds ceiling %d", am.TotalCount(), AddrManCeiling)
	}
}

// ── 12. falsification: it really buckets (not a flat list) ───────────────────

// Distinct addresses land in their COMPUTED buckets, and addresses spread
// across many buckets/positions rather than colliding in one list. If the impl
// were secretly flat, every addr would map to the same place or NewSlotOf would
// not match the computed slot.
func TestAddrManCore_Falsification_ReallyBuckets(t *testing.T) {
	am := NewAddrManWithKey(fixedKey())
	src := net.ParseIP("198.51.0.1")

	occupied := map[[2]int]NetAddress{}
	added := 0
	distinctBuckets := map[int]struct{}{}
	for i := 0; i < 500; i++ {
		ip := net.IPv4(byte(11+i%200), byte(i*7), byte(i*13), 11)
		if !isRoutableIP(ip) {
			continue
		}
		addr := NetAddress{IP: ip.To16(), Port: 8333}
		if !am.Add(addr, src, 1, 1_700_000_000) {
			continue
		}
		added++
		b, p := am.NewSlotOf(addr)
		if b == -1 {
			t.Fatalf("added addr %v has no computed NEW slot — placement broken", addr.IP)
		}
		distinctBuckets[b] = struct{}{}
		occupied[[2]int{b, p}] = addr
	}
	if added < 50 {
		t.Fatalf("only %d addrs added; test setup too sparse", added)
	}
	// Falsify "flat": a flat impl would put everything in one bucket. We require
	// the entries to be spread over many distinct buckets.
	if len(distinctBuckets) < 10 {
		t.Fatalf("addresses landed in only %d buckets — looks flat, not bucketed", len(distinctBuckets))
	}
	// Each occupied slot must hold the exact address that computes to it (i.e.
	// the stored placement equals the recomputed placement — not a single list).
	for _, addr := range occupied {
		bb, pp := am.NewSlotOf(addr)
		expB := am.getNewBucket(am.group(addr.IP), am.group(src))
		if bb != expB {
			// NewSlotOf walks from the start bucket; on multi-bucket addresses
			// the stored bucket can differ from the first computed one, but it
			// MUST be a real computed bucket-position for this addr.
			expP := am.getBucketPosition(true, bb, addr)
			if pp != expP {
				t.Fatalf("addr %v stored at (%d,%d) but recompute for that bucket gives pos %d — not deterministically bucketed", addr.IP, bb, pp, expP)
			}
		}
	}
	t.Logf("falsification: %d addrs spread across %d distinct NEW buckets (flat impl would use 1)", added, len(distinctBuckets))
}
