package p2p

import (
	"net"
	"testing"
	"time"
)

// fillBook fills ab to AddressBookMaxSize. The first `good` entries connected
// an hour ago; the rest are the shape that dominated blockbrew's mainnet book
// on 2026-11-08 (8,441 of 10,000): never connected, 10 failed attempts, last
// advertised 130 days ago. Every one of them is terrible under Core's rule.
func fillBook(t *testing.T, ab *AddressBook, good int) {
	t.Helper()
	now := time.Now()
	for i := 0; i < AddressBookMaxSize; i++ {
		ip := net.IPv4(11, byte(i>>16), byte(i>>8), byte(i)).To16()
		ka := &KnownAddress{Addr: NetAddress{IP: ip, Port: 8333}, Source: "test"}
		if i < good {
			ka.LastSeen = now.Add(-time.Hour)
			ka.LastSuccess = now.Add(-time.Hour)
			ka.LastAttempt = now.Add(-time.Hour)
		} else {
			ka.LastSeen = now.Add(-130 * 24 * time.Hour)
			ka.LastAttempt = now.Add(-2 * time.Hour)
			ka.Attempts = 10
		}
		ab.addrs[ka.Key()] = ka
	}
	if ab.Size() != AddressBookMaxSize {
		t.Fatalf("fill: size %d, want %d", ab.Size(), AddressBookMaxSize)
	}
}

func freshAddr(i int) NetAddress {
	return NetAddress{
		IP:        net.IPv4(12, byte(i>>16), byte(i>>8), byte(i)).To16(),
		Port:      8333,
		Timestamp: uint32(time.Now().Unix()),
	}
}

// A full book of dead entries must still admit newly gossiped addresses, by
// overwriting terrible entries (Core AddrManImpl::AddSingle). On the base
// commit AddAddress returned early whenever the book was full, so not one of
// these addresses got in and the selectable pool could never be refreshed.
func TestAddressBookFullEvictsTerribleForNewAddr(t *testing.T) {
	ab := NewAddressBook()
	fillBook(t, ab, 1500)

	const n = 1000 // one full addr message
	for i := 0; i < n; i++ {
		ab.AddAddress(freshAddr(i), "gossip")
	}
	admitted := 0
	for i := 0; i < n; i++ {
		if ab.GetAddress(net.JoinHostPort(freshAddr(i).IP.String(), "8333")) != nil {
			admitted++
		}
	}
	if admitted != n {
		t.Fatalf("full book admitted %d of %d fresh addresses, want all (terrible entries must make room)", admitted, n)
	}
	if ab.Size() != AddressBookMaxSize {
		t.Fatalf("size %d after evicting inserts, want the cap %d", ab.Size(), AddressBookMaxSize)
	}
}

// The new addresses are what the outbound refill then dials: once gossip has
// replaced the dead entries, picks land on live (fresh or proven) addresses.
func TestAddressBookFullPickReachesFreshAddrs(t *testing.T) {
	ab := NewAddressBook()
	fillBook(t, ab, 0) // no proven entry at all: only the fresh ones are selectable
	if ka := ab.PickAddress(); ka != nil {
		t.Fatalf("precondition: a book of only dead entries picked %s", ka.Key())
	}
	for i := 0; i < 50; i++ {
		ab.AddAddress(freshAddr(i), "gossip")
	}
	if ka := ab.PickAddress(); ka == nil {
		t.Fatal("after gossip into a full dead book, PickAddress still has nothing to dial")
	}
}

// Negative control: entries that are NOT terrible are never evicted. A full
// book of healthy entries rejects the new address, as Core drops a new
// address whose slot holds a non-terrible occupant.
func TestAddressBookFullKeepsHealthyEntries(t *testing.T) {
	ab := NewAddressBook()
	fillBook(t, ab, AddressBookMaxSize)
	before := make(map[string]bool, AddressBookMaxSize)
	for k := range ab.addrs {
		before[k] = true
	}
	for i := 0; i < 200; i++ {
		ab.AddAddress(freshAddr(i), "gossip")
	}
	for k := range before {
		if ab.addrs[k] == nil {
			t.Fatalf("healthy entry %s evicted", k)
		}
	}
	if ab.Size() != AddressBookMaxSize {
		t.Fatalf("size %d, want %d", ab.Size(), AddressBookMaxSize)
	}
}

// A full book whose entries all have one shape admits a new address exactly
// when that shape is a never-connected (Core: new-table) entry that is
// terrible under Core's AddrInfo::IsTerrible (addrman.cpp), case by case.
// Entries that ever connected stand in for Core's tried table, which gossip
// never overwrites, so they are kept whatever their failure count or age.
// Driven through AddAddress so it builds on the base commit.
func TestAddressBookFullEvictionFollowsCoreIsTerrible(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name string
		mk   func(now time.Time) KnownAddress
		want bool // terrible -> the new address is admitted
	}{
		{"fresh, untried", func(n time.Time) KnownAddress { return KnownAddress{LastSeen: n} }, false},
		{"tried within a minute is never terrible", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n.Add(-60 * day), LastAttempt: n.Add(-30 * time.Second), Attempts: 50}
		}, false},
		{"timestamp >10min in the future", func(n time.Time) KnownAddress { return KnownAddress{LastSeen: n.Add(11 * time.Minute)} }, true},
		{"not seen for >30 days", func(n time.Time) KnownAddress { return KnownAddress{LastSeen: n.Add(-31 * day)} }, true},
		{"seen 29 days ago", func(n time.Time) KnownAddress { return KnownAddress{LastSeen: n.Add(-29 * day)} }, false},
		{"3 attempts, never a success", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n, LastAttempt: n.Add(-time.Hour), Attempts: 3}
		}, true},
		{"2 attempts, never a success", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n, LastAttempt: n.Add(-time.Hour), Attempts: 2}
		}, false},
		{"tried: 10 failures, last success 8 days ago", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n, LastSuccess: n.Add(-8 * day), LastAttempt: n.Add(-time.Hour), Attempts: 10}
		}, false},
		{"tried: last success and last advert 60 days ago", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n.Add(-60 * day), LastSuccess: n.Add(-60 * day), LastAttempt: n.Add(-time.Hour)}
		}, false},
		{"tried: 10 failures, last success 6 days ago", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n, LastSuccess: n.Add(-6 * day), LastAttempt: n.Add(-time.Hour), Attempts: 10}
		}, false},
		{"tried: 9 failures, last success 8 days ago", func(n time.Time) KnownAddress {
			return KnownAddress{LastSeen: n, LastSuccess: n.Add(-8 * day), LastAttempt: n.Add(-time.Hour), Attempts: 9}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ab := NewAddressBook()
			now := time.Now()
			for i := 0; i < AddressBookMaxSize; i++ {
				ka := c.mk(now)
				ka.Addr = NetAddress{IP: net.IPv4(11, byte(i>>16), byte(i>>8), byte(i)).To16(), Port: 8333}
				ab.addrs[ka.Key()] = &ka
			}
			ab.AddAddress(freshAddr(1), "gossip")
			got := ab.GetAddress(net.JoinHostPort(freshAddr(1).IP.String(), "8333")) != nil
			if got != c.want {
				t.Fatalf("full book of %q entries: new address admitted=%v, want %v", c.name, got, c.want)
			}
			if ab.Size() != AddressBookMaxSize {
				t.Fatalf("size %d, want %d", ab.Size(), AddressBookMaxSize)
			}
		})
	}
}
