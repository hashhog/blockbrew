// FIX-74 / W121 BUG-6 + BUG-7 + BUG-8 behavioral tests.
//
// Pins the new stop-hash-anchored ancestor walk against the storage-side
// audit findings in internal/storage/w121_compact_filters_test.go.
//
// Coverage:
//
//   - HandleGetCFilters: orphan stop_hash → returns ancestor-walk filters
//     from THAT fork (or no response when filters not on disk; never
//     active-chain filters labeled with the fork's stop_hash).
//   - HandleGetCFilters: unknown stop_hash → Misbehaving + Disconnect.
//   - HandleGetCFilters: start > stop → Misbehaving + Disconnect.
//   - HandleGetCFilters: too-many-requested → Misbehaving + Disconnect.
//   - HandleGetCFilters: unsupported filter_type → Misbehaving + Disconnect.
//   - HandleGetCFHeaders: prev_filter_header walked via GetAncestor.
//   - HandleGetCFCheckpt: checkpoint heights at multiples of CFCheckptInterval
//     (W121 BUG-7 fix: 1000/2000/..., not 999/1999/...).
//   - Source-level regression guard: HandleGetCFilters does NOT call
//     filterIdx.GetFilter for height h unless the BlockHash at that height
//     on the stop_hash chain matches.

package p2p

import (
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ----------------------------------------------------------------------------
// Test fixtures: mock header index + filter index + peer.
// ----------------------------------------------------------------------------

type mockHeaderIndex struct {
	nodes map[wire.Hash256]*consensus.BlockNode
}

func newMockHeaderIndex() *mockHeaderIndex {
	return &mockHeaderIndex{nodes: make(map[wire.Hash256]*consensus.BlockNode)}
}

func (m *mockHeaderIndex) GetNode(hash wire.Hash256) *consensus.BlockNode {
	return m.nodes[hash]
}

func (m *mockHeaderIndex) addNode(node *consensus.BlockNode) {
	m.nodes[node.Hash] = node
}

// mockFilterIndex stores filter rows keyed by height with optional override
// (used to simulate active-chain entry vs. requested-fork entry collisions).
type mockFilterIndex struct {
	rows map[int32]*storage.BlockFilterData
	// callLog records every height passed to GetFilter so source-level
	// regression tests can assert the call sequence.
	callLog []int32
}

func newMockFilterIndex() *mockFilterIndex {
	return &mockFilterIndex{rows: make(map[int32]*storage.BlockFilterData)}
}

func (m *mockFilterIndex) GetFilter(height int32) (*storage.BlockFilterData, error) {
	m.callLog = append(m.callLog, height)
	row, ok := m.rows[height]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return row, nil
}

func (m *mockFilterIndex) put(height int32, row *storage.BlockFilterData) {
	m.rows[height] = row
}

// mockPeer implements CFilterRequestPeer.
type mockPeer struct {
	disconnected     bool
	misbehavedScore  int
	misbehavedReason string
	sent             []Message
}

func (p *mockPeer) Misbehaving(score int, reason string) bool {
	p.misbehavedScore = score
	p.misbehavedReason = reason
	return true
}

func (p *mockPeer) Disconnect()              { p.disconnected = true }
func (p *mockPeer) SendMessage(msg Message)  { p.sent = append(p.sent, msg) }

// ----------------------------------------------------------------------------
// Chain construction helpers.
// ----------------------------------------------------------------------------

// hashAt synthesizes a deterministic 32-byte hash for height h on a given
// fork (active=0, stale=1, etc). Distinct fork labels at the same height
// produce distinct hashes.
func hashAt(height int32, fork byte) wire.Hash256 {
	var h wire.Hash256
	h[0] = fork
	h[31] = byte(height & 0xff)
	h[30] = byte((height >> 8) & 0xff)
	h[29] = byte((height >> 16) & 0xff)
	h[28] = byte((height >> 24) & 0xff)
	return h
}

// filterHashAt / filterHeaderAt synthesize deterministic filter-related
// hashes from (height, fork) so each block has a unique filter+header.
func filterHashAt(height int32, fork byte) wire.Hash256 {
	var h wire.Hash256
	h[0] = 0xfa
	h[1] = fork
	h[31] = byte(height & 0xff)
	return h
}
func filterHeaderAt(height int32, fork byte) wire.Hash256 {
	var h wire.Hash256
	h[0] = 0xfb
	h[1] = fork
	h[31] = byte(height & 0xff)
	return h
}

// buildChain creates a linked chain of BlockNodes for heights [0..tipHeight]
// on a given fork. Genesis (height 0) has no parent. The slice index is the
// height. Skip pointers are intentionally NOT built — GetAncestor falls back
// to Parent walks, which exercises the same logic at a cost we don't care
// about in tests.
func buildChain(tipHeight int32, fork byte) []*consensus.BlockNode {
	nodes := make([]*consensus.BlockNode, tipHeight+1)
	for h := int32(0); h <= tipHeight; h++ {
		node := &consensus.BlockNode{
			Hash:      hashAt(h, fork),
			Height:    h,
			TotalWork: new(big.Int).SetInt64(int64(h + 1)),
		}
		if h > 0 {
			node.Parent = nodes[h-1]
		}
		nodes[h] = node
	}
	return nodes
}

// joinForkAt creates a fork chain that branches from `mainChain` at
// fork_point and extends through forkTipHeight on a new fork label.
// The block at fork_point itself is shared with the main chain (same
// hash, same parent). Heights fork_point+1..forkTipHeight have new
// hashes on the fork.
func joinForkAt(mainChain []*consensus.BlockNode, forkPoint, forkTipHeight int32, forkLabel byte) []*consensus.BlockNode {
	if forkPoint < 0 || int(forkPoint) >= len(mainChain) {
		panic("joinForkAt: forkPoint out of range")
	}
	if forkTipHeight <= forkPoint {
		panic("joinForkAt: forkTipHeight must exceed forkPoint")
	}
	out := make([]*consensus.BlockNode, forkTipHeight+1)
	// Heights up to (and including) forkPoint share the main chain nodes.
	for h := int32(0); h <= forkPoint; h++ {
		out[h] = mainChain[h]
	}
	// Heights forkPoint+1..forkTipHeight are fork-only.
	for h := forkPoint + 1; h <= forkTipHeight; h++ {
		node := &consensus.BlockNode{
			Hash:      hashAt(h, forkLabel),
			Height:    h,
			Parent:    out[h-1],
			TotalWork: new(big.Int).SetInt64(int64(h + 1)),
		}
		out[h] = node
	}
	return out
}

// populateFilterIndex creates filter rows for an entire active chain at
// `fork` label, using the chain's actual node hashes as the BlockHash
// stored on each row.
func populateFilterIndex(idx *mockFilterIndex, chain []*consensus.BlockNode, fork byte) {
	for _, node := range chain {
		idx.put(node.Height, &storage.BlockFilterData{
			BlockHash:    node.Hash,
			FilterHash:   filterHashAt(node.Height, fork),
			FilterHeader: filterHeaderAt(node.Height, fork),
			Filter:       []byte{byte(node.Height)},
		})
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: happy path (active chain).
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_ActiveChainHappyPath(t *testing.T) {
	chain := buildChain(10, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 3,
		StopHash:    chain[7].Hash,
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("active-chain happy path should not disconnect: reason=%s", peer.misbehavedReason)
	}
	if got, want := len(peer.sent), 5; got != want {
		t.Fatalf("sent %d cfilter messages, want %d (heights 3..7 inclusive)", got, want)
	}
	for i, m := range peer.sent {
		f, ok := m.(*MsgCFilter)
		if !ok {
			t.Fatalf("sent[%d] is %T, want *MsgCFilter", i, m)
		}
		wantHash := chain[3+int32(i)].Hash
		if f.BlockHash != wantHash {
			t.Errorf("cfilter[%d]: BlockHash mismatch — got %x want %x", i, f.BlockHash, wantHash)
		}
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: orphan stop_hash on a fork — must NOT lie with
// active-chain filters at those heights.
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_OrphanStopHashDoesNotLie(t *testing.T) {
	// Active chain heights 0..10 (fork=0). Fork branches at height 5,
	// extending to height 8 on fork label 1.
	active := buildChain(10, 0)
	forkChain := joinForkAt(active, 5, 8, 1)

	hi := newMockHeaderIndex()
	for _, n := range active {
		hi.addNode(n)
	}
	// Register the fork's *unique* nodes (heights 6..8 only — pre-fork
	// is shared by reference so already registered above).
	for h := int32(6); h <= 8; h++ {
		hi.addNode(forkChain[h])
	}

	fi := newMockFilterIndex()
	// Filter index only contains active-chain entries (the height-only
	// store overwrites on every active-chain extension; the fork's
	// filters are never persisted).
	populateFilterIndex(fi, active, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 4,
		StopHash:    forkChain[8].Hash, // orphan tip!
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("well-formed orphan stop_hash should NOT disconnect peer (Core serves; we just lack data)")
	}
	if len(peer.sent) > 0 {
		// CRITICAL: pre-FIX-74 this returned 5 active-chain cfilters
		// labeled with the fork's stop_hash → signed-but-lying response.
		t.Fatalf("orphan stop_hash should not produce any cfilter messages "+
			"when blockbrew lacks fork filters; got %d messages — signed-but-lying regression",
			len(peer.sent))
	}
}

// Companion: when the orphan stop_hash range is wholly on the SHARED
// pre-fork ancestors (start..stop both <= fork_point), filters can be
// served because the ancestor walk lands on the main chain blocks whose
// filters are on disk.
func TestFIX74_GetCFilters_OrphanStopHashSharedAncestors(t *testing.T) {
	active := buildChain(10, 0)
	forkChain := joinForkAt(active, 5, 8, 1)

	hi := newMockHeaderIndex()
	for _, n := range active {
		hi.addNode(n)
	}
	for h := int32(6); h <= 8; h++ {
		hi.addNode(forkChain[h])
	}

	fi := newMockFilterIndex()
	populateFilterIndex(fi, active, 0)

	peer := &mockPeer{}
	// Request range 2..5 ending at the FORK's tip (height 8). The
	// ancestor walk for heights 2..5 lands on the shared ancestors
	// (whose hashes ARE on the active chain), so we can and SHOULD
	// serve those filters.
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 2,
		StopHash:    forkChain[5].Hash, // shared ancestor (same as active[5])
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("shared-ancestor request should not disconnect: %s", peer.misbehavedReason)
	}
	if got, want := len(peer.sent), 4; got != want {
		t.Fatalf("sent %d, want %d (heights 2..5)", got, want)
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: unknown stop_hash → Misbehaving + Disconnect.
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_UnknownStopHashDisconnects(t *testing.T) {
	chain := buildChain(5, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 0,
		StopHash:    wire.Hash256{0xde, 0xad, 0xbe, 0xef}, // never indexed
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if !peer.disconnected {
		t.Errorf("unknown stop_hash should disconnect peer (Core fDisconnect=true)")
	}
	if peer.misbehavedScore <= 0 {
		t.Errorf("unknown stop_hash should call Misbehaving with positive score, got %d", peer.misbehavedScore)
	}
	if len(peer.sent) != 0 {
		t.Errorf("unknown stop_hash should send no messages, got %d", len(peer.sent))
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: start > stop → Misbehaving + Disconnect.
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_StartGreaterThanStopDisconnects(t *testing.T) {
	chain := buildChain(5, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 4,
		StopHash:    chain[2].Hash, // stop_height=2 < start_height=4
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if !peer.disconnected {
		t.Errorf("start>stop should disconnect peer")
	}
	if len(peer.sent) != 0 {
		t.Errorf("start>stop should not send any messages")
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: too many requested → Misbehaving + Disconnect.
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_TooManyRequestedDisconnects(t *testing.T) {
	// Build a chain with > MaxCFiltersPerRequest blocks (1000).
	chain := buildChain(MaxCFiltersPerRequest+10, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 0,
		// Stop at height 1000 — that's stop-start = 1000 = MaxCFiltersPerRequest,
		// which is rejected (Core: stop_height - start_height >= max_height_diff).
		StopHash: chain[MaxCFiltersPerRequest].Hash,
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if !peer.disconnected {
		t.Errorf("too-many-requested should disconnect peer")
	}
	if len(peer.sent) != 0 {
		t.Errorf("too-many-requested should send no messages, got %d", len(peer.sent))
	}
}

// And the boundary: a request asking for exactly MaxCFiltersPerRequest
// filters (stop-start+1 == 1000) is permitted.
func TestFIX74_GetCFilters_MaxRequestBoundaryAccepted(t *testing.T) {
	chain := buildChain(MaxCFiltersPerRequest+10, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 1,
		StopHash:    chain[MaxCFiltersPerRequest].Hash, // count = 1000
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if peer.disconnected {
		t.Errorf("exact-boundary request (count=%d) should be accepted, was disconnected: %s",
			MaxCFiltersPerRequest, peer.misbehavedReason)
	}
	if got := len(peer.sent); got != MaxCFiltersPerRequest {
		t.Errorf("exact-boundary request sent %d cfilters, want %d", got, MaxCFiltersPerRequest)
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFilters: unsupported filter type → Misbehaving + Disconnect.
// ----------------------------------------------------------------------------

func TestFIX74_GetCFilters_UnsupportedFilterTypeDisconnects(t *testing.T) {
	chain := buildChain(5, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFilters{
		FilterType:  0xff, // unknown
		StartHeight: 0,
		StopHash:    chain[3].Hash,
	}
	HandleGetCFilters(peer, msg, hi, fi)

	if !peer.disconnected {
		t.Errorf("unsupported filter type should disconnect peer (Core fDisconnect=true)")
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFHeaders: prev_filter_header is walked via ancestor at
// start_height-1, NOT raw active-chain GetFilter(start-1).
// ----------------------------------------------------------------------------

func TestFIX74_GetCFHeaders_PrevHeaderViaAncestorWalk(t *testing.T) {
	chain := buildChain(10, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFHeaders{
		FilterType:  FilterTypeBasic,
		StartHeight: 3,
		StopHash:    chain[6].Hash,
	}
	HandleGetCFHeaders(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("cfheaders happy path should not disconnect: %s", peer.misbehavedReason)
	}
	if got := len(peer.sent); got != 1 {
		t.Fatalf("cfheaders should send exactly 1 cfheaders message, got %d", got)
	}
	resp, ok := peer.sent[0].(*MsgCFHeaders)
	if !ok {
		t.Fatalf("response[0] is %T, want *MsgCFHeaders", peer.sent[0])
	}
	wantPrev := filterHeaderAt(2, 0) // ancestor at start_height-1 = h=2
	if resp.PrevFilterHeader != wantPrev {
		t.Errorf("PrevFilterHeader = %x, want %x", resp.PrevFilterHeader, wantPrev)
	}
	if got, want := len(resp.FilterHashes), 4; got != want {
		t.Errorf("cfheaders FilterHashes count = %d, want %d (heights 3..6)", got, want)
	}
}

// cfheaders with start_height=0 uses the BIP-158 all-zero sentinel for
// PrevFilterHeader (no GetFilter(-1) lookup required).
func TestFIX74_GetCFHeaders_GenesisSentinel(t *testing.T) {
	chain := buildChain(5, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFHeaders{
		FilterType:  FilterTypeBasic,
		StartHeight: 0,
		StopHash:    chain[3].Hash,
	}
	HandleGetCFHeaders(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("genesis-start cfheaders should not disconnect: %s", peer.misbehavedReason)
	}
	resp := peer.sent[0].(*MsgCFHeaders)
	var zero wire.Hash256
	if resp.PrevFilterHeader != zero {
		t.Errorf("start_height=0 PrevFilterHeader should be all-zero sentinel, got %x", resp.PrevFilterHeader)
	}
}

// ----------------------------------------------------------------------------
// HandleGetCFCheckpt: BUG-7 fix — checkpoint heights are 1000, 2000, ...,
// not 999, 1999, ...
// ----------------------------------------------------------------------------

func TestFIX74_GetCFCheckpt_HeightsAreMultiplesOfInterval(t *testing.T) {
	// Build a chain that crosses 2 checkpoint boundaries (heights 1000, 2000).
	const tip = 2500
	chain := buildChain(tip, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFCheckpt{
		FilterType: FilterTypeBasic,
		StopHash:   chain[tip].Hash,
	}
	HandleGetCFCheckpt(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("happy-path getcfcheckpt should not disconnect: %s", peer.misbehavedReason)
	}
	if got := len(peer.sent); got != 1 {
		t.Fatalf("getcfcheckpt should send exactly 1 cfcheckpt message, got %d", got)
	}
	resp, ok := peer.sent[0].(*MsgCFCheckpt)
	if !ok {
		t.Fatalf("response[0] is %T, want *MsgCFCheckpt", peer.sent[0])
	}
	// stop_height=2500, expected checkpoint count = 2500/1000 = 2,
	// at heights 1000 and 2000 (NOT 999/1999).
	if got, want := len(resp.FilterHeaders), 2; got != want {
		t.Fatalf("cfcheckpt FilterHeaders count = %d, want %d", got, want)
	}
	if got, want := resp.FilterHeaders[0], filterHeaderAt(1000, 0); got != want {
		t.Errorf("cfcheckpt[0]: got header for some wrong height %x, want filterHeaderAt(1000)=%x", got, want)
	}
	if got, want := resp.FilterHeaders[1], filterHeaderAt(2000, 0); got != want {
		t.Errorf("cfcheckpt[1]: got header for some wrong height %x, want filterHeaderAt(2000)=%x", got, want)
	}
	// Regression: pre-FIX-74 the first call would have been GetFilter(999).
	// Verify that 999 / 1999 were NOT queried.
	for _, h := range fi.callLog {
		if h == 999 || h == 1999 {
			t.Errorf("cfcheckpt regression: GetFilter(%d) called — pre-FIX-74 off-by-one bug", h)
		}
	}
}

// At stop_height = 1000 exactly, Core sends 1 checkpoint at h=1000.
func TestFIX74_GetCFCheckpt_AtIntervalBoundary(t *testing.T) {
	chain := buildChain(CFCheckptInterval, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFCheckpt{
		FilterType: FilterTypeBasic,
		StopHash:   chain[CFCheckptInterval].Hash,
	}
	HandleGetCFCheckpt(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("boundary getcfcheckpt should not disconnect: %s", peer.misbehavedReason)
	}
	resp := peer.sent[0].(*MsgCFCheckpt)
	if got, want := len(resp.FilterHeaders), 1; got != want {
		t.Errorf("at stop_height=%d expected 1 checkpoint, got %d", CFCheckptInterval, got)
	}
	if got, want := resp.FilterHeaders[0], filterHeaderAt(CFCheckptInterval, 0); got != want {
		t.Errorf("first checkpoint = %x, want filterHeaderAt(%d)=%x", got, CFCheckptInterval, want)
	}
}

// Below interval boundary, Core sends an empty cfcheckpt.
func TestFIX74_GetCFCheckpt_BelowIntervalEmptyResponse(t *testing.T) {
	chain := buildChain(CFCheckptInterval-1, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFCheckpt{
		FilterType: FilterTypeBasic,
		StopHash:   chain[CFCheckptInterval-1].Hash,
	}
	HandleGetCFCheckpt(peer, msg, hi, fi)

	if peer.disconnected {
		t.Fatalf("below-interval getcfcheckpt should not disconnect: %s", peer.misbehavedReason)
	}
	resp := peer.sent[0].(*MsgCFCheckpt)
	if got := len(resp.FilterHeaders); got != 0 {
		t.Errorf("below-interval should send empty FilterHeaders, got %d", got)
	}
}

// Unknown stop_hash on getcfcheckpt also disconnects.
func TestFIX74_GetCFCheckpt_UnknownStopHashDisconnects(t *testing.T) {
	chain := buildChain(5, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	peer := &mockPeer{}
	msg := &MsgGetCFCheckpt{
		FilterType: FilterTypeBasic,
		StopHash:   wire.Hash256{0xab, 0xcd},
	}
	HandleGetCFCheckpt(peer, msg, hi, fi)

	if !peer.disconnected {
		t.Errorf("unknown stop_hash on getcfcheckpt should disconnect peer")
	}
}

// ----------------------------------------------------------------------------
// Source-level regression guard:
// LookupFilterRangeByStopHash never returns success when the stored
// BlockHash at a height disagrees with the ancestor walk.
// ----------------------------------------------------------------------------

func TestFIX74_LookupFilterRange_RejectsBlockHashMismatch(t *testing.T) {
	chain := buildChain(8, 0)
	fi := newMockFilterIndex()
	populateFilterIndex(fi, chain, 0)

	// Sabotage height 6: store a row whose BlockHash claims to be on fork 9.
	fi.put(6, &storage.BlockFilterData{
		BlockHash:    hashAt(6, 9),
		FilterHash:   filterHashAt(6, 9),
		FilterHeader: filterHeaderAt(6, 9),
		Filter:       []byte{6},
	})

	got, ok := LookupFilterRangeByStopHash(4, chain[7], fi)
	if ok {
		t.Errorf("LookupFilterRange should reject mismatched BlockHash; got %d filters", len(got))
	}
}

// ----------------------------------------------------------------------------
// PrepareBlockFilterRequest: smoke test all 4 disconnect paths.
// ----------------------------------------------------------------------------

func TestFIX74_PrepareBlockFilterRequest_AllDisconnectPaths(t *testing.T) {
	chain := buildChain(20, 0)
	hi := newMockHeaderIndex()
	for _, n := range chain {
		hi.addNode(n)
	}

	cases := []struct {
		name        string
		filterType  uint8
		startHeight uint32
		stopHash    wire.Hash256
		maxDiff     uint32
	}{
		{"unknown_filter_type", 0xff, 0, chain[5].Hash, MaxCFiltersPerRequest},
		{"unknown_stop_hash", FilterTypeBasic, 0, wire.Hash256{0xfe, 0xed}, MaxCFiltersPerRequest},
		{"start_gt_stop", FilterTypeBasic, 10, chain[5].Hash, MaxCFiltersPerRequest},
		{"too_many_requested", FilterTypeBasic, 0, chain[20].Hash, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := &mockPeer{}
			node := PrepareBlockFilterRequest(peer, tc.filterType, tc.startHeight, tc.stopHash, tc.maxDiff, hi)
			if node != nil {
				t.Errorf("expected nil stopNode (disconnect), got %v", node)
			}
			if !peer.disconnected {
				t.Errorf("expected peer.Disconnect() to be called")
			}
			if peer.misbehavedScore <= 0 {
				t.Errorf("expected peer.Misbehaving with positive score")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// LookupFilterHeaderByStopHashAtPrev sanity.
// ----------------------------------------------------------------------------

func TestFIX74_LookupFilterHeaderAtPrev_GenesisSentinel(t *testing.T) {
	fi := newMockFilterIndex()
	header, ok := LookupFilterHeaderByStopHashAtPrev(0, nil, fi)
	if !ok {
		t.Fatalf("startHeight=0 must succeed without consulting the filter index")
	}
	var zero wire.Hash256
	if header != zero {
		t.Errorf("startHeight=0 should yield all-zero header, got %x", header)
	}
	if len(fi.callLog) != 0 {
		t.Errorf("startHeight=0 must not call GetFilter, got %d calls", len(fi.callLog))
	}
}

func TestFIX74_LookupFilterHeaderAtPrev_ErrorPropagates(t *testing.T) {
	chain := buildChain(5, 0)
	fi := newMockFilterIndex()
	// Do NOT populate the filter index at h=2. GetFilter must return
	// (nil, false).
	header, ok := LookupFilterHeaderByStopHashAtPrev(3, chain[5], fi)
	if ok {
		t.Errorf("missing GetFilter(2) entry must propagate ok=false; got header %x", header)
	}
}

// Sanity: assert that ErrNotFound is the error class used by the mock
// — otherwise the table tests above don't reflect what the real index
// returns.
func TestFIX74_MockFilterIndex_NotFoundUsesStorageError(t *testing.T) {
	fi := newMockFilterIndex()
	_, err := fi.GetFilter(0)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("mockFilterIndex.GetFilter should return storage.ErrNotFound; got %v", err)
	}
}
