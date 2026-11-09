package p2p

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"testing"
	"time"
)

// deadProven is the entry shape that drew about half of blockbrew's mainnet
// refill dials on 2026-11-08: it connected once, then failed many times
// (364 of the 956 proven entries in the live book had >= 50 failures since
// their last success).
func deadProven(i int, attempts int) *KnownAddress {
	now := time.Now()
	return &KnownAddress{
		Addr:        NetAddress{IP: net.IPv4(13, 0, byte(i>>8), byte(i)).To16(), Port: 8333},
		LastSeen:    now.Add(-40 * 24 * time.Hour),
		LastSuccess: now.Add(-30 * 24 * time.Hour),
		LastAttempt: now.Add(-time.Hour),
		Attempts:    attempts,
	}
}

func freshUntried(i int) *KnownAddress {
	return &KnownAddress{
		Addr:     NetAddress{IP: net.IPv4(14, 0, byte(i>>8), byte(i)).To16(), Port: 8333},
		LastSeen: time.Now().Add(-24 * time.Hour),
	}
}

// A proven address that has failed 50 times since its last success must rank
// below a fresh, untried one. On the base commit the failure penalty applied
// only to never-connected entries, so it kept weight 2 against the fresh 1.
func TestChanceProvenButFailingRanksBelowFresh(t *testing.T) {
	dead, fresh := deadProven(1, 50).Chance(), freshUntried(1).Chance()
	if !(dead < fresh) {
		t.Fatalf("Chance(proven, 50 failures since success)=%.3f, Chance(fresh untried)=%.3f; dead must rank below fresh", dead, fresh)
	}
}

// The penalty is Core's AddrInfo::GetChance factor 0.66^min(nAttempts, 8),
// for proven addresses as for any other.
func TestChanceProvenAttemptDecayMatchesCore(t *testing.T) {
	base := deadProven(1, 0).Chance()
	for _, n := range []int{1, 3, 8, 20} {
		got := deadProven(1, n).Chance() / base
		want := math.Pow(0.66, math.Min(float64(n), 8))
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("proven, %d failures: Chance ratio %.4f, want Core's 0.66^min(n,8)=%.4f", n, got, want)
		}
	}
}

// What the refill sees: with as many dead proven entries as fresh ones, picks
// should mostly land on the fresh ones. Base: ~2/3 of picks were dead.
func TestPickAddressAvoidsProvenButFailing(t *testing.T) {
	ab := NewAddressBook()
	ab.rand = rand.New(rand.NewSource(7))
	for i := 0; i < 100; i++ {
		d, f := deadProven(i, 50), freshUntried(i)
		ab.addrs[d.Key()] = d
		ab.addrs[f.Key()] = f
	}
	deadPicks := 0
	const picks = 5000
	for i := 0; i < picks; i++ {
		if ab.PickAddress().Addr.IP[12] == 13 {
			deadPicks++
		}
	}
	if share := float64(deadPicks) / picks; share > 0.15 {
		t.Fatalf("%.0f%% of picks went to proven entries with 50 failures since success; want < 15%%", 100*share)
	}
}

// Control: a proven address with no failures since its success still ranks
// above a fresh one (blockbrew's success bonus is unchanged), and a recently
// tried proven address is still selectable.
func TestChanceProvenHealthyStillPreferred(t *testing.T) {
	healthy := deadProven(1, 0)
	if !(healthy.Chance() > freshUntried(1).Chance()) {
		t.Fatalf("healthy proven %.3f should outrank fresh %.3f", healthy.Chance(), freshUntried(1).Chance())
	}
	healthy.LastAttempt = time.Now()
	if healthy.Chance() <= 0 {
		t.Fatal("recently tried proven address must stay selectable")
	}
}

// failingDialRig is a PeerManager whose dials all fail, with one proven
// address (connected 30 days ago) in its book.
func failingDialRig(t *testing.T) (*PeerManager, *KnownAddress) {
	t.Helper()
	pm := NewPeerManager(PeerManagerConfig{Network: MainnetMagic})
	pm.dialFn = func(addr string, cfg PeerConfig) (*Peer, error) {
		return nil, errors.New("connection timed out")
	}
	ka := deadProven(1, 0)
	pm.addrBook.mu.Lock()
	pm.addrBook.addrs[ka.Key()] = ka
	pm.addrBook.mu.Unlock()
	return pm, ka
}

func attemptsOf(pm *PeerManager, key string) int {
	pm.addrBook.mu.RLock()
	defer pm.addrBook.mu.RUnlock()
	return pm.addrBook.addrs[key].Attempts
}

// Outage guard (Core net.cpp ThreadOpenConnections count_failures): with
// fewer than 2 outbound peers a failed dial is more likely our fault than
// the address's, so it must not count toward the pick penalty. On the base
// commit every dial counted, so an outage pushed every address down.
func TestDialFailuresNotCountedWithoutOutboundPeers(t *testing.T) {
	pm, ka := failingDialRig(t)
	for i := 0; i < 5; i++ {
		pm.connectOutbound(ka, ConnFullRelay, nil)
	}
	if got := attemptsOf(pm, ka.Key()); got != 0 {
		t.Fatalf("5 failed dials with 0 outbound peers counted %d attempts, want 0", got)
	}
}

// Core AddrManImpl::Attempt_: one counted failure per address between two
// successful connections (to any address).
func TestDialFailureCountedOncePerSuccess(t *testing.T) {
	pm, ka := failingDialRig(t)
	pm.mu.Lock()
	pm.outbound = 2 // enough outbound peers that failures count
	pm.mu.Unlock()
	for i := 0; i < 5; i++ {
		pm.connectOutbound(ka, ConnFullRelay, nil)
	}
	if got := attemptsOf(pm, ka.Key()); got != 1 {
		t.Fatalf("5 failed dials with no success in between counted %d attempts, want 1", got)
	}
	other := freshUntried(9)
	pm.addrBook.mu.Lock()
	pm.addrBook.addrs[other.Key()] = other
	pm.addrBook.mu.Unlock()
	time.Sleep(2 * time.Millisecond) // the success must be later than the counted attempt
	pm.addrBook.MarkSuccess(other.Key())
	pm.connectOutbound(ka, ConnFullRelay, nil)
	if got := attemptsOf(pm, ka.Key()); got != 2 {
		t.Fatalf("a failed dial after another address connected: attempts %d, want 2", got)
	}
}

// A dial that never happens (the address is already connected) must not
// count as a failed attempt. On the base commit the attempt was marked
// before the connected check, so re-picking a healthy connected peer
// counted against it.
func TestConnectedPeerRepickNotCounted(t *testing.T) {
	pm, ka := failingDialRig(t)
	pm.mu.Lock()
	pm.outbound = 2
	pm.peers[ka.Key()] = &PeerInfo{peer: &Peer{addr: ka.Key()}, connType: ConnFullRelay, connectedAt: time.Now()}
	pm.mu.Unlock()
	pm.connectOutbound(ka, ConnFullRelay, nil)
	if got := attemptsOf(pm, ka.Key()); got != 0 {
		t.Fatalf("re-picking an already-connected address counted %d attempts, want 0", got)
	}
}
