package p2p

import (
	"math/rand"
	"net"
	"time"
)

// DNS seed resolution constants.
const (
	// DNSLookupTimeout is the maximum time to wait for a DNS lookup.
	DNSLookupTimeout = 30 * time.Second
)

// ResolveDNSSeeds resolves DNS seed hostnames to IP addresses.
// It queries each seed hostname, collects all A/AAAA records,
// shuffles the results, and returns deduplicated IP addresses.
func ResolveDNSSeeds(seeds []string) []string {
	if len(seeds) == 0 {
		return nil
	}

	// Collect all IPs from all seeds
	seen := make(map[string]struct{})
	var ips []string

	for _, seed := range seeds {
		addrs, err := net.LookupHost(seed)
		if err != nil {
			// DNS lookup failed, continue to next seed
			continue
		}

		for _, addr := range addrs {
			// Skip if we've already seen this IP
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			ips = append(ips, addr)
		}
	}

	// Shuffle the results to avoid all nodes connecting to the same peers
	shuffleStrings(ips)

	return ips
}

// ResolveDNSSeed resolves a single DNS seed hostname to IP addresses.
func ResolveDNSSeed(seed string) ([]string, error) {
	return net.LookupHost(seed)
}

// shuffleStrings randomly shuffles a slice of strings in place.
func shuffleStrings(s []string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := len(s) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}
