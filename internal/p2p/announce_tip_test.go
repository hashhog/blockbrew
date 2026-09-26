package p2p

import (
	"os"

	"github.com/hashhog/blockbrew/internal/consensus"
	"strings"
	"testing"
	"time"
)

// ShouldAnnounceTip follows Core's UpdatedBlockTip IBD guard (tip age vs
// DEFAULT_MAX_TIP_AGE = 24h).
func TestShouldAnnounceTipFollowsMaxTipAge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		age  time.Duration
		want bool
	}{
		{0, true},
		{-10 * time.Minute, true}, // header slightly in the future
		{24 * time.Hour, true},    // boundary: Core is in IBD only if age > max
		{24*time.Hour + time.Second, false},
		{30 * 24 * time.Hour, false},
	}
	for _, c := range cases {
		ts := uint32(now.Add(-c.age).Unix())
		if got := ShouldAnnounceTip(ts, now); got != c.want {
			t.Errorf("age %v: got %v want %v", c.age, got, c.want)
		}
	}
}

// Source pin: the SyncManager's P2P connect callback in cmd/blockbrew must
// relay the new tip. It used to be an empty stub, so P2P-received blocks were
// never announced (regtest relay test 2026-09-26: Core B never followed Core A
// through blockbrew).
func TestP2PConnectCallbackAnnouncesBlock(t *testing.T) {
	src, err := os.ReadFile("../../cmd/blockbrew/main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "onBlockConnected := func(block *wire.MsgBlock, height int32) {")
	if i < 0 {
		t.Fatal("onBlockConnected callback not found")
	}
	body := s[i:]
	body = body[:strings.Index(body, "\n\t}\n")]
	if !strings.Contains(body, "peerMgr.AnnounceBlock(block.Header, block.Header.BlockHash())") {
		t.Fatal("P2P connect callback does not announce the connected block")
	}
}

// chain builds a parent-linked node chain of heights 0..n on top of base
// (nil = new genesis). Skip pointers are left nil so GetAncestor walks parents.
func testChain(base *consensus.BlockNode, n int32, tag byte) []*consensus.BlockNode {
	out := []*consensus.BlockNode{}
	prev := base
	start := int32(0)
	if base != nil {
		start = base.Height + 1
	}
	for h := start; h <= n; h++ {
		node := &consensus.BlockNode{Height: h, Parent: prev}
		node.Hash[0] = tag
		node.Hash[1] = byte(h)
		out = append(out, node)
		prev = node
	}
	return out
}

// getheaders is answered from the ACTIVE chain: a locator hit ahead of the
// connected tip (a header-only entry) or on a side branch maps to the fork
// point, so we never serve headers whose bodies we lack (Core
// FindForkInGlobalIndex + ActiveChain().Next).
func TestActiveChainForkCapsAtConnectedTip(t *testing.T) {
	main := testChain(nil, 10, 0xaa) // heights 0..10, "best header" chain
	tip := main[4]                   // connected tip at height 4
	if got := activeChainFork(main[8], tip); got != tip {
		t.Fatalf("locator ahead of tip: got height %d want %d", got.Height, tip.Height)
	}
	if got := activeChainFork(main[2], tip); got != main[2] {
		t.Fatalf("locator on active chain: got height %d want 2", got.Height)
	}
	side := testChain(main[2], 6, 0xbb) // side branch forking after height 2
	if got := activeChainFork(side[len(side)-1], tip); got != main[2] {
		t.Fatalf("side-branch locator: got height %d want fork 2", got.Height)
	}
}

// getdata(MSG_CMPCT_BLOCK) must be served (full block); it used to match no
// case and get no reply at all.
func TestGetDataServesCmpctBlockType(t *testing.T) {
	src, err := os.ReadFile("sync.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "case InvTypeBlock, InvTypeCmpctBlock:") {
		t.Fatal("HandleGetData does not serve MSG_CMPCT_BLOCK")
	}
	if InvTypeCmpctBlock != 4 {
		t.Fatalf("MSG_CMPCT_BLOCK is 4, got %d", InvTypeCmpctBlock)
	}
}
