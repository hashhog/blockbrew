package p2p

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// live967621FirstByteSize is the 1.65 MB body whose 7.628s first-byte
// the operator could not classify as "the peer" vs "we ask badly".
const live967621FirstByteSize uint32 = 1_650_752

// TestTtfbDistributionSeparatesSlowPeerFromPipelineDelay is the 967621 ASK:
// `ttfb=7.628s size=1650752 inflight=2` — is that the peers, or is it us?
//
// Per-fetch first-byte lines already exist (9ccaa90). They cannot answer
// the question: a sibling queued behind a live head has a large ttfb even
// when the peer is fast, and a v2 compact-block stamp (size=162004) is a
// first-byte that is not a block. The distribution must (1) split pipeline
// head (peer latency) from non-head (our ask/pipeline delay), (2) drop
// retracted non-block stamps, and (3) emit a per-peer summary so an hour
// of samples is one line, not a grep.
func TestTtfbDistributionSeparatesSlowPeerFromPipelineDelay(t *testing.T) {
	t.Run("slow_vs_fast_heads_are_the_peers", func(t *testing.T) {
		logs := captureTtfbLogs(t, func() {
			sm, fast, slow, rFast, rSlow := twoPeerInflightHeads(t)
			stampFirstByte(sm, rFast, fast, 50*time.Millisecond, live967621FirstByteSize)
			stampFirstByte(sm, rSlow, slow, 8*time.Second, live967621FirstByteSize)
		})
		if !strings.Contains(logs, "ttfb dist") {
			t.Fatalf("no ttfb dist line after one fast head and one slow head — cannot tell whether 7.6s first-byte is the peer or our pipeline:\n%s", logs)
		}
		if !strings.Contains(logs, "verdict=peers") {
			t.Fatalf("want verdict=peers (head-p50 spread across peers), got:\n%s", logs)
		}
		fastClause := ttfbPeerClause(logs, "fast.example:8333")
		slowClause := ttfbPeerClause(logs, "slow.example:8333")
		if fastClause == "" || slowClause == "" {
			t.Fatalf("dist missing per-peer clauses:\n%s", logs)
		}
		fastP50 := ttfbDurationField(t, fastClause, "head-p50=")
		slowP50 := ttfbDurationField(t, slowClause, "head-p50=")
		if fastP50 > 200*time.Millisecond {
			t.Fatalf("fast head-p50=%s, want ≤200ms (peer latency, not pipeline): %s", fastP50, fastClause)
		}
		if slowP50 < 7*time.Second {
			t.Fatalf("slow head-p50=%s, want ≥7s: %s", slowP50, slowClause)
		}
		if slowP50 < 4*fastP50 {
			t.Fatalf("slow head-p50=%s is not ≥4× fast %s — peers are not separated: %s | %s",
				slowP50, fastP50, fastClause, slowClause)
		}
	})

	t.Run("sibling_ttfb_is_pipeline_delay", func(t *testing.T) {
		logs := captureTtfbLogs(t, func() {
			sm, peer, reqs := twoInflightOnePeer(t)
			head, sib := reqs[0], reqs[1]
			if sib.Height < head.Height {
				head, sib = sib, head
			}
			stampFirstByte(sm, head, peer, 50*time.Millisecond, live967621FirstByteSize)
			stampFirstByte(sm, sib, peer, 8*time.Second, live967621FirstByteSize)
		})
		if !strings.Contains(logs, "head=true") || !strings.Contains(logs, "head=false") {
			t.Fatalf("first-byte lines must tag pipeline head vs sibling (live inflight=2 is ambiguous without this):\n%s", logs)
		}
		if !strings.Contains(logs, "ttfb dist") {
			t.Fatalf("no ttfb dist line after head+sibling first-bytes:\n%s", logs)
		}
		if !strings.Contains(logs, "verdict=ask") {
			t.Fatalf("want verdict=ask (sibling ttfb is our pipeline wait, not a slow peer), got:\n%s", logs)
		}
		if strings.Contains(logs, "verdict=peers") {
			t.Fatalf("one peer with a slow sibling must not be classified as a slow peer:\n%s", logs)
		}
	})

	t.Run("retracted_cmpctblock_excluded", func(t *testing.T) {
		const compactSize uint32 = 162004 // live 967624 / 967626
		logs := captureTtfbLogs(t, func() {
			sm, a, b, rA, rB := twoPeerInflightHeads(t)
			stampFirstByte(sm, rA, a, 50*time.Millisecond, compactSize)
			sm.retractNonBlockFirstByte(a)
			stampFirstByte(sm, rA, a, 50*time.Millisecond, live967621FirstByteSize)
			stampFirstByte(sm, rB, b, 50*time.Millisecond, live967621FirstByteSize)
		})
		if !strings.Contains(logs, "ttfb dist") {
			t.Fatalf("no ttfb dist line after retract + two real heads:\n%s", logs)
		}
		if !strings.Contains(logs, "retracted=1") {
			t.Fatalf("want retracted=1 (v2 cmpctblock size=162004 dropped from the dist), got:\n%s", logs)
		}
		if !strings.Contains(logs, "samples=2") {
			t.Fatalf("want samples=2 (compact stamp must not remain), got:\n%s", logs)
		}
	})
}

func captureTtfbLogs(t *testing.T, fn func()) string {
	t.Helper()
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	log.SetOutput(&lockedLogWriter{mu: &logMu, w: &logBuf})
	defer log.SetOutput(os.Stderr)
	fn()
	return logBuf.String()
}

func stampFirstByte(sm *SyncManager, req *blockRequest, peer *Peer, age time.Duration, size uint32) {
	sm.mu.Lock()
	req.FirstByteAt = time.Time{}
	req.PayloadSize = 0
	req.RequestAt = time.Now().Add(-age)
	sm.mu.Unlock()
	sm.noteBlockFirstByte(peer, size)
}

func twoPeerInflightHeads(t *testing.T) (*SyncManager, *Peer, *Peer, *blockRequest, *blockRequest) {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	nodes := addRegtestInflightHeaders(t, idx, 2)

	pm := &PeerManager{}
	fast := createMockPeer("fast.example:8333", nodes[1].Height)
	slow := createMockPeer("slow.example:8333", nodes[1].Height)
	pm.InsertConnectedPeer(fast)
	pm.InsertConnectedPeer(slow)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		DownloadWindow: 8,
	})
	rFast := &blockRequest{
		Hash:      nodes[0].Hash,
		Height:    nodes[0].Height,
		Peer:      fast,
		State:     BlockDownloadInFlight,
		RequestAt: time.Now(),
	}
	rSlow := &blockRequest{
		Hash:      nodes[1].Hash,
		Height:    nodes[1].Height,
		Peer:      slow,
		State:     BlockDownloadInFlight,
		RequestAt: time.Now(),
	}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{rFast, rSlow}
	sm.inflight[rFast.Hash] = rFast
	sm.inflight[rSlow.Hash] = rSlow
	sm.nextHeight = nodes[0].Height
	sm.mu.Unlock()
	return sm, fast, slow, rFast, rSlow
}

func twoInflightOnePeer(t *testing.T) (*SyncManager, *Peer, []*blockRequest) {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	nodes := addRegtestInflightHeaders(t, idx, 2)

	pm := &PeerManager{}
	peer := createMockPeer("busy.example:8333", nodes[1].Height)
	pm.InsertConnectedPeer(peer)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		DownloadWindow: 8,
	})
	reqs := make([]*blockRequest, 2)
	sm.mu.Lock()
	for i, node := range nodes {
		req := &blockRequest{
			Hash:      node.Hash,
			Height:    node.Height,
			Peer:      peer,
			State:     BlockDownloadInFlight,
			RequestAt: time.Now(),
		}
		reqs[i] = req
		sm.blockQueue = append(sm.blockQueue, req)
		sm.inflight[req.Hash] = req
	}
	sm.nextHeight = nodes[0].Height
	sm.mu.Unlock()
	return sm, peer, reqs
}

func addRegtestInflightHeaders(t *testing.T, idx *consensus.HeaderIndex, n int) []*consensus.BlockNode {
	t.Helper()
	genesis := idx.Genesis()
	prev := genesis.Hash
	ts := genesis.Header.Timestamp
	nodes := make([]*consensus.BlockNode, n)
	for i := 0; i < n; i++ {
		ts += 600
		hdr := createTestBlockHeader(prev, ts, uint32(i+1))
		node, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i+1, err)
		}
		nodes[i] = node
		prev = node.Hash
	}
	return nodes
}

func ttfbPeerClause(logs, addr string) string {
	key := "peer=" + addr
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "ttfb dist") {
			continue
		}
		i := strings.Index(line, key)
		if i < 0 {
			continue
		}
		rest := line[i:]
		if j := strings.Index(rest, " | "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	return ""
}

func ttfbDurationField(t *testing.T, clause, key string) time.Duration {
	t.Helper()
	i := strings.Index(clause, key)
	if i < 0 {
		t.Fatalf("missing %s in %q", key, clause)
	}
	rest := clause[i+len(key):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	d, err := time.ParseDuration(rest)
	if err != nil {
		t.Fatalf("parse %s%q: %v", key, rest, err)
	}
	return d
}
