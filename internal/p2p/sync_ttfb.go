package p2p

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// ttfbSampleCap keeps an hour of at-tip first-bytes plus a catch-up
// burst. The dist log summarizes the last ttfbDistWindow.
const (
	ttfbSampleCap    = 512
	ttfbDistWindow   = time.Hour
	ttfbDistInterval = time.Hour
	ttfbPeerSpread   = 4
)

// ttfbSample is one getdata→first-body-byte observation.
type ttfbSample struct {
	peer   string
	ttfb   time.Duration
	size   uint32
	height int32
	head   bool
	at     time.Time
}

func (sm *SyncManager) recordTtfbLocked(peer string, ttfb time.Duration, size uint32, height int32, head bool) {
	if peer == "" {
		return
	}
	if ttfb < 0 {
		ttfb = 0
	}
	sm.ttfbSamples = append(sm.ttfbSamples, ttfbSample{
		peer:   peer,
		ttfb:   ttfb,
		size:   size,
		height: height,
		head:   head,
		at:     time.Now(),
	})
	if len(sm.ttfbSamples) > ttfbSampleCap {
		sm.ttfbSamples = append([]ttfbSample(nil), sm.ttfbSamples[len(sm.ttfbSamples)-ttfbSampleCap:]...)
	}
}

func (sm *SyncManager) dropTtfbLocked(peer string, height int32) {
	for i := len(sm.ttfbSamples) - 1; i >= 0; i-- {
		s := sm.ttfbSamples[i]
		if s.peer != peer || s.height != height {
			continue
		}
		sm.ttfbSamples = append(sm.ttfbSamples[:i], sm.ttfbSamples[i+1:]...)
		sm.ttfbRetracted++
		return
	}
}

func (sm *SyncManager) maybeLogTtfbDistLocked() {
	now := time.Now()
	samples := ttfbWindow(sm.ttfbSamples, now)
	if !ttfbDistReady(samples) {
		return
	}
	if !sm.lastTtfbDist.IsZero() && now.Sub(sm.lastTtfbDist) < ttfbDistInterval {
		return
	}
	sm.lastTtfbDist = now
	log.Printf("sync: ttfb dist %s", formatTtfbDist(samples, sm.ttfbRetracted))
}

func ttfbWindow(samples []ttfbSample, now time.Time) []ttfbSample {
	cutoff := now.Add(-ttfbDistWindow)
	out := make([]ttfbSample, 0, len(samples))
	for _, s := range samples {
		if !s.at.Before(cutoff) {
			out = append(out, s)
		}
	}
	return out
}

func ttfbDistReady(samples []ttfbSample) bool {
	heads := make(map[string]struct{})
	nonHead := 0
	for _, s := range samples {
		if s.head {
			heads[s.peer] = struct{}{}
		} else {
			nonHead++
		}
	}
	return len(heads) >= 2 || (len(heads) >= 1 && nonHead >= 1)
}

func formatTtfbDist(samples []ttfbSample, retracted int) string {
	byPeer := make(map[string][]ttfbSample)
	var all, heads []time.Duration
	for _, s := range samples {
		byPeer[s.peer] = append(byPeer[s.peer], s)
		all = append(all, s.ttfb)
		if s.head {
			heads = append(heads, s.ttfb)
		}
	}
	addrs := make([]string, 0, len(byPeer))
	for addr := range byPeer {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	var b strings.Builder
	fmt.Fprintf(&b, "window=%s samples=%d head=%d retracted=%d peers=%d p50=%s p90=%s verdict=%s",
		ttfbDistWindow, len(samples), len(heads), retracted, len(addrs),
		ttfbDur(ttfbPercentile(all, 50)), ttfbDur(ttfbPercentile(all, 90)),
		ttfbVerdict(samples))
	for _, addr := range addrs {
		ps := byPeer[addr]
		var pAll, pHeads []time.Duration
		headN := 0
		for _, s := range ps {
			pAll = append(pAll, s.ttfb)
			if s.head {
				pHeads = append(pHeads, s.ttfb)
				headN++
			}
		}
		fmt.Fprintf(&b, " | peer=%s n=%d head=%d head-p50=%s head-p90=%s all-p50=%s",
			addr, len(ps), headN,
			ttfbDur(ttfbPercentile(pHeads, 50)),
			ttfbDur(ttfbPercentile(pHeads, 90)),
			ttfbDur(ttfbPercentile(pAll, 50)))
	}
	return b.String()
}

func ttfbVerdict(samples []ttfbSample) string {
	headByPeer := make(map[string][]time.Duration)
	var heads, nonHeads []time.Duration
	for _, s := range samples {
		if s.head {
			headByPeer[s.peer] = append(headByPeer[s.peer], s.ttfb)
			heads = append(heads, s.ttfb)
		} else {
			nonHeads = append(nonHeads, s.ttfb)
		}
	}
	peers := false
	if len(headByPeer) >= 2 {
		var p50s []time.Duration
		for _, hs := range headByPeer {
			p50s = append(p50s, ttfbPercentile(hs, 50))
		}
		minP50, maxP50 := p50s[0], p50s[0]
		for _, d := range p50s[1:] {
			if d < minP50 {
				minP50 = d
			}
			if d > maxP50 {
				maxP50 = d
			}
		}
		if minP50 > 0 && maxP50 >= time.Duration(ttfbPeerSpread)*minP50 {
			peers = true
		}
	}
	ask := false
	if len(heads) > 0 && len(nonHeads) > 0 {
		hp50 := ttfbPercentile(heads, 50)
		if hp50 > 0 {
			for _, d := range nonHeads {
				if d >= time.Duration(ttfbPeerSpread)*hp50 {
					ask = true
					break
				}
			}
		}
	}
	switch {
	case peers && ask:
		return "mixed"
	case peers:
		return "peers"
	case ask:
		return "ask"
	default:
		return "unknown"
	}
}

func ttfbPercentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	idx := (p*len(sorted) - 1) / 100
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func ttfbDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return d.Round(time.Millisecond).String()
}
