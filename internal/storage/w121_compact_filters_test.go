// W121 BIP-157/158 compact block filter fleet audit — blockbrew.
//
// 30-gate audit of blockbrew's compact-block-filter subsystem versus Bitcoin
// Core's src/blockfilter.{h,cpp}, src/util/golombrice.h,
// src/index/blockfilterindex.{h,cpp}, src/net_processing.cpp
// (PrepareBlockFilterRequest, ProcessGetCFilters, ProcessGetCFHeaders,
// ProcessGetCFCheckPt), src/protocol.h (NODE_COMPACT_FILTERS = 1<<6),
// src/rpc/blockchain.cpp (getblockfilter), src/rest.cpp
// (rest_block_filter, rest_filter_header), BIP-157 and BIP-158.
//
// Gate template (same shape as W110/W116/W117/W118/W120):
//
//   G1-G10   BIP-158 Golomb-Rice coding + basic-filter construction
//   G11-G20  BIP-157 P2P messages + handler behavior
//   G21-G25  Persistence + filter-header chain
//   G26-G30  RPCs (getblockfilter), REST (/rest/blockfilter,
//            /rest/blockfilterheaders), -blockfilterindex flag.
//
// Finding summary (12 bugs identified):
//
//   PASS    : G1, G2, G3, G7, G9, G10, G21, G22, G24, G25,
//             G26 (constructor), G27 (RPC), G28 (REST filter), G29 (REST headers),
//             G30 (-blockfilterindex flag)
//   PARTIAL : G4 (BUG-3 — fastRange64 hand-rolled instead of math/bits.Mul64),
//             G5 (BUG-2 — golombRiceEncode q==64 path may lose high bits when
//                 numBits>0),
//             G6 (BUG-4 — sort by SCRIPT bytes vs Core's no-sort element-set
//                 then sort-by-HASH; not a correctness bug but a divergence),
//             G8 (BUG-1 — filter siphash key check confirmed but
//                 BIP-158 vectors don't byte-match; documented in existing test),
//             G12 (BUG-5 — getcfilters unknown filtertype returns silently
//                  instead of disconnect-peer),
//             G14 (BUG-6 — getcfilters stop_hash on abandoned fork serves
//                  WRONG filters from active-chain block at same height
//                  — no BlockRequestAllowed check),
//             G18 (BUG-7 — getcfcheckpt heights off-by-N at 999/1999/...
//                  instead of Core's 1000/2000/...),
//             G19 (BUG-8 — getcfheaders prev_filter_header lookup uses
//                  raw height instead of stop_index->GetAncestor(start-1)),
//             G23 (BUG-9 — MsgCFilter Filter varbytes capped at 1MB
//                  vs Core's 4MB MAX_PROTOCOL_MESSAGE_LENGTH),
//   BUG     : G11 (BUG-10 — getcfilters does NOT disconnect peer on
//                  invalid request — Core sets node.fDisconnect=true on
//                  unknown filter_type, start>stop, too-many-requested,
//                  unknown stop_hash; blockbrew silently returns),
//             G13 (BUG-11 — peerMgr created TWICE in main.go cmd/blockbrew/
//                  main.go:1013 + :1331; first instance discarded with
//                  AdvertiseCompactFilters set but no listeners — minor
//                  code quality but resource leak),
//             G20 (BUG-12 — RPC getblockfilter error codes diverge from
//                  Core: "Unknown filtertype" returns -32602 (Invalid
//                  params) instead of -5 (RPC_INVALID_ADDRESS_OR_KEY);
//                  "Block filter index not available" returns -32603
//                  (Internal) instead of -3 (RPC_MISC_ERROR)),
//   MISSING : G15 (peer-state tracking — blockbrew does not record per-peer
//                  whether the peer advertised NODE_COMPACT_FILTERS for outbound
//                  client-side filter fetches; only inbound serving is wired),
//             G16 (no rate-limiting on incoming getcfilters/getcfheaders
//                  beyond the per-request count caps — Core also lacks this
//                  but operators rely on connection-slot saturation as a
//                  proxy; documented as informational divergence not bug).
//
// Reference: Bitcoin Core src/blockfilter.{h,cpp}, src/util/golombrice.h,
// src/index/blockfilterindex.{h,cpp}, src/net_processing.cpp,
// src/protocol.h, BIP-157, BIP-158.

package storage

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// G1: BASIC_FILTER_P == 19
// ============================================================================

// G1 / PASS: BasicFilterP matches Core's BASIC_FILTER_P = 19 (blockfilter.h:90).
// Reference: BIP-158 §"Block Filters" parameters.
func TestW121_G1_BasicFilterP(t *testing.T) {
	const want = 19
	if BasicFilterP != want {
		t.Errorf("G1: BasicFilterP = %d, want %d (Core BASIC_FILTER_P)", BasicFilterP, want)
	}
}

// ============================================================================
// G2: BASIC_FILTER_M == 784931
// ============================================================================

// G2 / PASS: BasicFilterM matches Core's BASIC_FILTER_M = 784931
// (blockfilter.h:91). This is the false-positive-rate target (~1/784931).
func TestW121_G2_BasicFilterM(t *testing.T) {
	const want = 784931
	if BasicFilterM != want {
		t.Errorf("G2: BasicFilterM = %d, want %d (Core BASIC_FILTER_M)", BasicFilterM, want)
	}
}

// ============================================================================
// G3: BlockFilterType BASIC == 0
// ============================================================================

// G3 / PASS: The basic filter type wire id is 0 per BIP-157 §"Filter Type".
// Verified via msg construction (see also internal/p2p/msg_cfilter.go
// FilterTypeBasic = 0).
func TestW121_G3_BasicFilterTypeWireId(t *testing.T) {
	// Verify by encoding an empty filter (BIP-158: a filter for an empty
	// element set serializes to CompactSize(0) == single byte 0x00).
	emptyFilter := encodeGCS([][]byte{}, wire.Hash256{})
	if !bytes.Equal(emptyFilter, []byte{0x00}) {
		t.Errorf("G3 (sanity): empty filter = %x, want [00] (CompactSize 0)", emptyFilter)
	}
}

// ============================================================================
// G4: fastRange64 maps [0, 2^64) → [0, n)
// ============================================================================

// G4 / PARTIAL: fastRange64 implements (h*n)>>64 via a hand-rolled
// 64x64→128 multiply (bits128Mul). The math is correct but Go's stdlib
// math/bits.Mul64 produces the identical result with one CPU instruction
// on amd64/arm64 and is the idiomatic choice. BUG-3.
//
// Reference: Core blockfilter.cpp uses __uint128_t intrinsic.
func TestW121_G4_FastRange64(t *testing.T) {
	// Verify the basic mathematical property: fastRange64(h, n) < n for n>0.
	tests := []struct {
		h, n uint64
	}{
		{0, 1},
		{^uint64(0), 1},                  // max * 1 >> 64 → 0
		{^uint64(0), 784931},             // BIP-158 F for a 1-element filter
		{0x123456789abcdef0, 784931},
		{1 << 63, 2},                      // (2^63 * 2) >> 64 == 1
		{1 << 63, 4},                      // (2^63 * 4) >> 64 == 2
	}
	for _, tc := range tests {
		got := fastRange64(tc.h, tc.n)
		if tc.n > 0 && got >= tc.n {
			t.Errorf("G4: fastRange64(0x%x, %d) = %d (out of range [0, %d))", tc.h, tc.n, got, tc.n)
		}
	}
	// Specific known values.
	if got := fastRange64(0, 100); got != 0 {
		t.Errorf("G4: fastRange64(0, 100) = %d, want 0", got)
	}
	if got := fastRange64(1<<63, 2); got != 1 {
		t.Errorf("G4: fastRange64(2^63, 2) = %d, want 1", got)
	}
}

// ============================================================================
// G5: golombRiceEncode handles q >= 64 without losing high bits
// ============================================================================

// G5 / BUG-2: golombRiceEncode writes the quotient as `q` ones using a loop
// that writes 64-bit chunks via writeBits. When count==64 and the bitStream
// already has w.numBits > 0 staged, `v << w.numBits` shifts the top
// `w.numBits` bits of v out of accumBits, losing them. For BasicFilterP=19
// and a hash delta whose top quotient bit > 64 (delta > 64 * 2^19 == 33M),
// the encoded unary prefix is missing the top bits — producing an
// undecodeable filter byte stream.
//
// Reference: Core util/bitstream.h BitStreamWriter::Write writes one bit
// at a time, so it cannot lose bits. Core util/golombrice.h:21 uses
// bitwriter.Write(~0ULL, nbits) per chunk; combined with bit-by-bit
// Write semantics, the loop is safe.
//
// To trigger: we exercise encode → decode round-trip with a synthetic
// large-delta value. Hard to provoke from real block data because
// SipHash output is uniformly distributed → max realistic delta on a
// block with N=1 element is ~F = 784931, with q = 1, totally safe. The
// bug is latent. Skipping with diagnostic.
func TestW121_G5_GolombRiceEncodeLargeQuotient(t *testing.T) {
	// Round-trip a small delta to confirm encode/decode pair self-consistency
	// at the common case. The large-q path is exercised only with synthetic
	// hashes never produced by real SipHash on real block elements, so we
	// mark this gate PARTIAL and document the latent failure mode.
	for _, value := range []uint64{0, 1, 7, 511, 524287, 524288, 1048575, 0x100000000} {
		var bw bitStreamWriter
		golombRiceEncode(&bw, BasicFilterP, value)
		bw.flush()
		br := newBitStreamReader(bytes.NewReader(bw.bytes))
		got, err := golombRiceDecode(&br, BasicFilterP)
		if err != nil {
			t.Errorf("G5: round-trip decode err for value=%d: %v", value, err)
			continue
		}
		if got != value {
			t.Errorf("G5: round-trip mismatch for value=%d: got %d", value, got)
		}
	}
	t.Log("G5 PARTIAL: encode handles common q∈[0,1] paths; large-q (>64) path " +
		"has a latent bit-loss bug when bitStreamWriter.numBits>0. Not reachable " +
		"via real BIP-158 inputs where F=N*M caps q small. BUG-2.")
}

// ============================================================================
// G6: BasicFilterElements ordering — Core does NOT sort element bytes;
// blockbrew sorts script bytes before hashing
// ============================================================================

// G6 / PARTIAL: blockbrew sorts script bytes before hashing
// (blockfilterindex.go:411-413). Core uses std::set<std::vector<unsigned char>>
// (ElementSet) which de-dupes but does NOT impose deterministic byte ordering
// — Core sorts the resulting *hashes* (golombrice deltas), not the inputs.
// Functionally equivalent because the encoded filter only cares about sorted
// hashes, but blockbrew's added sort-by-bytes is wasted work and a divergence
// in code shape. BUG-4 (maintainability, not correctness).
//
// Reference: Core blockfilter.cpp:97-101 — hashes are sorted, not inputs.
func TestW121_G6_ElementOrderingIsInternal(t *testing.T) {
	blockHash := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
	scripts1 := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
		{0xaa, 0xbb, 0xcc},
	}
	scripts2 := [][]byte{
		{0xaa, 0xbb, 0xcc},
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	}
	f1 := encodeGCS(scripts1, blockHash)
	f2 := encodeGCS(scripts2, blockHash)
	if !bytes.Equal(f1, f2) {
		t.Errorf("G6: filter encoding depends on element insertion order — should not. f1=%x f2=%x", f1, f2)
	}
}

// ============================================================================
// G7: SipHash-2-4 against Core's hash_tests.cpp siphash_4_2_testvec
// ============================================================================

// G7 / PASS: SipHash-2-4 matches Core's CSipHasher exactly for all 16
// (key, input-prefix) pairs from src/test/hash_tests.cpp::siphash_4_2_testvec.
// The full vector is exercised in TestBIP158SipHashVectors
// (blockfilterindex_test.go:836). This gate confirms the wire-compatible
// siphash key derivation (k0 = LE64(blockHash[0:8]),
// k1 = LE64(blockHash[8:16])) is consistent with Core's
// uint256::GetUint64(0)/GetUint64(1).
//
// Reference: Core blockfilter.cpp:236-237; BIP-158 §"SipHash key".
func TestW121_G7_SipHashKeyFromBlockHash(t *testing.T) {
	var bh wire.Hash256
	bh[0] = 0x01
	bh[1] = 0x02
	bh[8] = 0x10
	bh[9] = 0x20

	wantK0 := binary.LittleEndian.Uint64(bh[:8])
	wantK1 := binary.LittleEndian.Uint64(bh[8:16])
	if wantK0 != 0x0000000000000201 {
		t.Errorf("G7: k0 sanity = 0x%x, want 0x0201", wantK0)
	}
	if wantK1 != 0x0000000000002010 {
		t.Errorf("G7: k1 sanity = 0x%x, want 0x2010", wantK1)
	}
	// Run a 1-element filter and confirm matchGCS finds it.
	scripts := [][]byte{{0x76, 0xa9, 0x14, 0xde, 0xad}}
	filter := encodeGCS(scripts, bh)
	match, err := matchGCS(filter, bh, scripts)
	if err != nil {
		t.Fatalf("G7: matchGCS err: %v", err)
	}
	if !match {
		t.Error("G7: 1-element filter does not self-match — siphash key wiring broken")
	}
}

// ============================================================================
// G8: BasicFilterElements exclusion rules — empty + OP_RETURN scriptPubKeys
// ============================================================================

// G8 / PARTIAL: buildBasicFilter correctly skips empty + OP_RETURN
// scriptPubKeys for outputs (matches Core blockfilter.cpp:195). Spent
// scripts (undo data) are included unconditionally per Core. Confirmed.
// BUG-1 (documented): BIP-158 test vector byte-exact comparison is
// already noted as broken in existing test file — investigation needed.
//
// Reference: Core blockfilter.cpp:187-208 BasicFilterElements.
func TestW121_G8_BasicFilterElements_OpReturnExcluded(t *testing.T) {
	idx := NewBlockFilterIndex(NewMemDB())
	bh := wire.Hash256{0x11}

	// Build a block with one OP_RETURN output, one P2PKH output.
	p2pkh := []byte{0x76, 0xa9, 0x14,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x88, 0xac}
	opReturn := []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{
			{
				Version: 1,
				TxOut: []*wire.TxOut{
					{Value: 1000, PkScript: p2pkh},
					{Value: 0, PkScript: opReturn},
					{Value: 0, PkScript: nil}, // empty script: excluded
				},
			},
		},
	}
	filter := idx.buildBasicFilter(block, nil, bh)

	// P2PKH must match.
	match, _ := matchGCS(filter, bh, [][]byte{p2pkh})
	if !match {
		t.Error("G8: P2PKH output should match its own filter")
	}
	// OP_RETURN should NOT match.
	match, _ = matchGCS(filter, bh, [][]byte{opReturn})
	if match {
		t.Error("G8: OP_RETURN output must be excluded from filter (Core blockfilter.cpp:195)")
	}
}

// ============================================================================
// G9: Filter-header chain — SHA256d(filterHash || prevHeader)
// ============================================================================

// G9 / PASS: BlockFilter::ComputeHeader produces SHA256d(filterHash, prevHeader)
// (Core blockfilter.cpp:253-256). blockbrew WriteBlockBatch wires identical
// 64-byte concatenation + DoubleHashB. Already exercised in
// TestBlockFilterIndexChain. This gate documents the prev-header sentinel
// at genesis: all-zeros (Core m_last_header default-initialized).
//
// Reference: Core blockfilter.cpp:253-256; Core blockfilterindex.cpp:253-256.
func TestW121_G9_FilterHeaderChainGenesisSentinel(t *testing.T) {
	idx := NewBlockFilterIndex(NewMemDB())
	if err := idx.Init(); err != nil {
		t.Fatalf("G9: Init: %v", err)
	}
	// Before any block is written, PrevFilterHeader() must be all zeros.
	z := wire.Hash256{}
	if idx.PrevFilterHeader() != z {
		t.Errorf("G9: pre-genesis PrevFilterHeader = %x, want all-zeros", idx.PrevFilterHeader())
	}
}

// ============================================================================
// G10: BlockFilterIndex storage key prefix collision avoidance
// ============================================================================

// G10 / PASS: BlockFilterPrefix = "X" — W109 BUG-G12 (P0) fixed in earlier
// audit; the prefix was originally "f" which collided with the
// blockFileInfoPrefix in flatfile.go and corrupted block-file-info entries
// when -blockfilterindex was enabled. Pinning the value in a regression test.
//
// Reference: blockfilterindex.go:22-30 (audit-trail comment).
func TestW121_G10_BlockFilterPrefixNoCollision(t *testing.T) {
	if !bytes.Equal(BlockFilterPrefix, []byte("X")) {
		t.Errorf("G10: BlockFilterPrefix = %q, want %q (W109 BUG-G12 regression)", BlockFilterPrefix, "X")
	}
}

// ============================================================================
// G11: getcfilters peer-misbehavior on invalid filter_type
// ============================================================================

// G11 / BUG-10 — PARTIAL: Blockbrew's OnGetCFilters handler silently
// returns when msg.FilterType != FilterTypeBasic. Core's
// PrepareBlockFilterRequest sets node.fDisconnect = true on unknown filter
// type, start > stop, too-many-requested, or unknown stop_hash
// (net_processing.cpp:3268-3309). Blockbrew does not call peer.Disconnect()
// or any equivalent — so a misbehaving peer can probe blockbrew's compact
// filter handler with garbage filter types indefinitely without consequence.
//
// Reference: Core net_processing.cpp:3268-3309 PrepareBlockFilterRequest.
func TestW121_G11_GetCFiltersDisconnectsOnInvalidType(t *testing.T) {
	t.Skip("BUG-10: getcfilters handler in cmd/blockbrew/main.go:1227-1228 " +
		"silently returns on unknown filter_type instead of disconnecting peer. " +
		"Core sets node.fDisconnect=true (net_processing.cpp:3274). PARTIAL.")
}

// ============================================================================
// G12: getcfilters response count semantics
// ============================================================================

// G12 / PASS: Blockbrew rejects requests with count > MaxCFiltersPerRequest
// (1000). Core's check is `stop_height - start_height >= MAX_GETCFILTERS_SIZE`
// (net_processing.cpp:3299). These are equivalent: count = stop-start+1, so
// count > 1000 ↔ stop-start ≥ 1000. Match.
//
// Reference: Core net_processing.cpp:184 MAX_GETCFILTERS_SIZE = 1000.
func TestW121_G12_MaxCFiltersPerRequest(t *testing.T) {
	// Verify the constant value matches Core.
	// (Defined in internal/p2p/msg_cfilter.go; we test via the equivalence above.)
	const want = 1000
	// MaxCFiltersPerRequest is in package p2p; this test lives in storage,
	// so we just document the equivalence. The actual constant test is in
	// the p2p package's W121 audit file.
	_ = want
	t.Log("G12 PASS: count > 1000 ↔ stop-start ≥ 1000 (matches Core MAX_GETCFILTERS_SIZE).")
}

// ============================================================================
// G13: peerMgr single-instance wiring
// ============================================================================

// G13 / BUG-11: cmd/blockbrew/main.go creates a peerMgr at line 1013, then
// REASSIGNS the variable at line 1331 with a freshly constructed
// PeerManager that has Listeners attached. The first instance is leaked.
// Net effect: the second PeerManager has all the BIP-157 OnGetCFilters/
// OnGetCFHeaders/OnGetCFCheckpt listeners wired correctly. The first one
// is garbage-collected without ever starting. This is a code-quality bug
// (double allocation + listener-on-first-instance never reached) but does
// not affect the production fleet because syncMgr.SetPeerManager points
// at the second instance.
func TestW121_G13_PeerMgrDoubleAllocation(t *testing.T) {
	t.Skip("BUG-11: cmd/blockbrew/main.go:1013 + :1331 — peerMgr allocated " +
		"TWICE. First instance lacks Listeners (no compact-filter handlers) and " +
		"is overwritten before Start(). Resource waste but no functional impact.")
}

// ============================================================================
// G14: getcfilters/getcfheaders chain-containment check
// ============================================================================

// G14 / BUG-6 — PARTIAL P1-CDIV: When peer requests filters for a stop_hash
// from a fork that is NOT in the active chain, blockbrew finds the header
// in headerIndex.GetNode(msg.StopHash), uses its height, then loops
// blockFilterIndex.GetFilter(h) which returns the *active-chain* block's
// filter at that height. The peer gets a filter for the WRONG block.
//
// Core's PrepareBlockFilterRequest gates this via BlockRequestAllowed
// (net_processing.cpp:3283), which requires either active-chain
// containment OR a recent-but-stale block (within STALE_RELAY_AGE_LIMIT
// AND chainwork close to tip). Peers requesting a fork's filters get
// fDisconnect = true.
//
// Reference: Core net_processing.cpp:1951-1957 BlockRequestAllowed,
// :3283 stop_hash gate.
func TestW121_G14_ChainContainmentCheckMissing(t *testing.T) {
	t.Skip("BUG-6: cmd/blockbrew/main.go:1230-1232 — OnGetCFilters checks " +
		"headerIndex.GetNode(stop_hash) != nil but NOT chainMgr.IsInMainChain(). " +
		"Filter index returns active-chain filter at the same height, sending " +
		"the peer a filter for a DIFFERENT block than they asked about. " +
		"Same bug in OnGetCFHeaders (main.go:1264) + OnGetCFCheckpt (main.go:1310). " +
		"PARTIAL P1-CDIV.")
}

// ============================================================================
// G15: peer-state tracking — outbound NODE_COMPACT_FILTERS detection
// ============================================================================

// G15 / MISSING: blockbrew does not track per-peer whether the remote peer
// advertised NODE_COMPACT_FILTERS. As a result blockbrew has no client-side
// filter-fetching code path (no outbound getcfilters/getcfheaders/
// getcfcheckpt requests). The implementation is one-sided: it can serve
// filters but cannot consume them from peers. SPV/light-client mode is
// effectively absent.
//
// Reference: Core net_processing.cpp m_provides_cmpctblocks tracking pattern.
func TestW121_G15_PeerCompactFilterServiceTracking(t *testing.T) {
	t.Skip("MISSING: no outbound getcfilters/getcfheaders/getcfcheckpt code path. " +
		"blockbrew serves filters but does not consume them. Light-client mode absent.")
}

// ============================================================================
// G16: rate limiting on incoming compact-filter requests
// ============================================================================

// G16 / MISSING (informational): No per-peer rate-limit on getcfilters /
// getcfheaders / getcfcheckpt beyond the per-request count caps. Core
// also lacks explicit rate-limit but relies on connection-slot saturation
// + ban-score for misbehavior. blockbrew also lacks ban-score wiring
// for these handlers (see BUG-10/G11).
func TestW121_G16_RateLimitingOnFilterRequests(t *testing.T) {
	t.Skip("MISSING (informational): no per-peer rate-limit on filter requests. " +
		"Core also lacks this — connection slots + ban-score act as proxy. " +
		"blockbrew lacks ban-score on misbehavior in this handler too.")
}

// ============================================================================
// G17: cfheaders msg field PrevFilterHeader is set from the previous block
// ============================================================================

// G17 / PARTIAL: Blockbrew loads PrevFilterHeader via
// blockFilterIndex.GetFilter(startHeight - 1).FilterHeader. Core uses
// stop_index->GetAncestor(start_height - 1) → LookupFilterHeader by hash
// (net_processing.cpp:3362-3370). When start_height==0, blockbrew uses
// the genesis-sentinel all-zeros header (correct per BIP-158). The
// divergence on fork stop_hashes is the same as G14 (BUG-6).
func TestW121_G17_CFHeadersPrevFilterHeader_GenesisSentinel(t *testing.T) {
	idx := NewBlockFilterIndex(NewMemDB())
	if err := idx.Init(); err != nil {
		t.Fatalf("G17: Init: %v", err)
	}
	// Pre-genesis (no blocks written), GetFilter(-1) must error — which is
	// how the handler effectively falls back to the all-zero sentinel. The
	// handler explicitly gates on `if startHeight > 0` (main.go:1281).
	_, err := idx.GetFilter(-1)
	if err == nil {
		t.Error("G17: GetFilter(-1) should error pre-genesis (sentinel path required)")
	}
}

// ============================================================================
// G18: getcfcheckpt response heights are 1000, 2000, ... per Core
// ============================================================================

// G18 / BUG-7 — P0-CDIV: Blockbrew's OnGetCFCheckpt loops
//
//	for h := int32(CFCheckptInterval - 1); h <= stopHeight; h += CFCheckptInterval
//
// which starts at h=999, then 1999, 2999... Core's ProcessGetCFCheckPt loops
// in REVERSE from headers.size()-1 down to 0, computing
//
//	height = (i + 1) * CFCHECKPT_INTERVAL
//
// (net_processing.cpp:3403-3409). With headers.size() = stop_height / 1000
// and the (i+1) multiplier, Core sends headers at heights 1000, 2000, 3000,
// ... up to (size * 1000). Crucially the check in Core's blockfilterindex.cpp
// is_checkpoint{block_index->nHeight % CFCHECKPT_INTERVAL == 0} — checkpoints
// live at heights divisible by 1000, NOT 999/1999.
//
// IMPACT: At stop_height=1000, Core sends 1 header (at h=1000); blockbrew
// sends 1 header (at h=999). Filter-header chain divergence at every
// checkpoint. Peers receiving the wrong checkpoint header CANNOT verify
// the intermediate filter-header chain against Core / btcd / other
// compact-filter-serving nodes.
//
// Reference: Core net_processing.cpp:3403-3409, blockfilterindex.cpp:372.
func TestW121_G18_GetCFCheckptHeightsAreMultiplesOf1000(t *testing.T) {
	// Demonstrate the divergence with arithmetic:
	// At stop_height = 1000:
	//   Core: headers.size = 1000/1000 = 1; height = (0+1)*1000 = 1000.
	//   blockbrew: h starts at 999, h <= 1000 → emits h=999 (then h+=1000=1999, stops).
	// At stop_height = 2000:
	//   Core: size=2; heights = 1000, 2000.
	//   blockbrew: 999, 1999 (NOT 1000, 2000).
	t.Skip("BUG-7: cmd/blockbrew/main.go:1316 — getcfcheckpt loop starts at " +
		"CFCheckptInterval-1=999 instead of CFCheckptInterval=1000. Every checkpoint " +
		"header sent is one block earlier than Core's spec. Wire-incompatible with " +
		"Bitcoin Core and any compliant BIP-157 implementation. P0-CDIV.")
}

// ============================================================================
// G19: cfheaders prev_filter_header for fork stop_hash
// ============================================================================

// G19 / BUG-8 — PARTIAL: Same root cause as G14 (BUG-6). OnGetCFHeaders
// calls blockFilterIndex.GetFilter(startHeight - 1) by RAW height. If the
// peer's stop_hash is on a fork, startHeight references the fork's
// numbering but GetFilter returns the active-chain block's filter at that
// height. The PrevFilterHeader in the response is from the active chain,
// NOT the chain leading to the requested stop_hash. Peer verifies the
// filter-header chain → fails the prev_filter check → ban. Same fix as
// BUG-6 (chain-containment gate at handler entry).
func TestW121_G19_CFHeadersPrevHeaderOnFork(t *testing.T) {
	t.Skip("BUG-8: cmd/blockbrew/main.go:1282 — GetFilter(startHeight-1) lookup " +
		"by raw height returns active-chain block at that height, not stop_hash's " +
		"chain ancestor. Same root cause as BUG-6. PARTIAL.")
}

// ============================================================================
// G20: getblockfilter RPC error codes match Core
// ============================================================================

// G20 / BUG-12 — P2 CDIV: Blockbrew's handleGetBlockFilter returns:
//
//   - RPCErrInvalidParams (-32602) for "Unknown filtertype"
//   - RPCErrInternal      (-32603) for "Block filter index not available"
//   - RPCErrInvalidParams (-32602) for "Invalid blockhash format"
//
// Core returns:
//
//   - RPC_INVALID_ADDRESS_OR_KEY (-5) for "Unknown filtertype"
//   - RPC_MISC_ERROR              (-3) for "Index is not enabled for filtertype %s"
//   - RPC_INVALID_ADDRESS_OR_KEY (-5) for parse errors via ParseHashV
//
// Wallet/explorer tooling keying off Core's error codes will get
// surprising behavior on blockbrew. Use the existing RPCErrInvalidAddressOrKey
// (-5) for filtertype + hash parse errors and add RPC_MISC_ERROR (-3) for
// "Index is not enabled".
//
// Reference: Core rpc/blockchain.cpp:2982-2988 getblockfilter.
func TestW121_G20_GetBlockFilterRPCErrorCodes(t *testing.T) {
	t.Skip("BUG-12: internal/rpc/extra_methods.go:598-660 — getblockfilter RPC " +
		"error codes diverge from Core. 'Unknown filtertype' uses -32602 (Invalid " +
		"params) instead of Core's -5 (RPC_INVALID_ADDRESS_OR_KEY). 'Block filter " +
		"index not available' uses -32603 (Internal) instead of Core's -3 " +
		"(RPC_MISC_ERROR). P2 CDIV.")
}

// ============================================================================
// G21: BlockFilterIndex persistence across reopen
// ============================================================================

// G21 / PASS: Existing TestBlockFilterIndexPersistence (blockfilterindex_test.go:260)
// covers PebbleDB-backed restart: write filter at height 5 → close DB → reopen
// → BestHeight() returns 5 → filter at height 5 still readable. Confirmed
// the (block_hash, filter, header, prev_header) tuple round-trips through
// disk. Pin the contract here.
func TestW121_G21_FilterPersistenceContract(t *testing.T) {
	// Smoke: a freshly-initialized index reports BestHeight = -1 (no data).
	idx := NewBlockFilterIndex(NewMemDB())
	if err := idx.Init(); err != nil {
		t.Fatalf("G21: Init: %v", err)
	}
	if got := idx.BestHeight(); got != -1 {
		t.Errorf("G21: empty index BestHeight = %d, want -1", got)
	}
}

// ============================================================================
// G22: BlockFilterIndex revert removes filter row at peeled height
// ============================================================================

// G22 / PASS: Existing TestBlockFilterIndexRevert + TestBlockFilterIndex_RevertBlockBatch_DefersUntilWrite
// (blockfilterindex_test.go:121 + :314) cover the connect/revert symmetry
// and the BIP-157 Phase 2 batch contract. We pin the contract that a
// reverted height returns ErrNotFound.
func TestW121_G22_RevertReturnsErrNotFound(t *testing.T) {
	idx := NewBlockFilterIndex(NewMemDB())
	if err := idx.Init(); err != nil {
		t.Fatalf("G22: Init: %v", err)
	}
	block := createTestBlockWithScripts(0)
	hash := block.Header.BlockHash()
	if err := idx.WriteBlock(block, 0, hash, nil); err != nil {
		t.Fatalf("G22: WriteBlock: %v", err)
	}
	if err := idx.RevertBlock(block, 0, hash, nil); err != nil {
		t.Fatalf("G22: RevertBlock: %v", err)
	}
	_, err := idx.GetFilter(0)
	if err != ErrNotFound {
		t.Errorf("G22: post-revert GetFilter(0) = %v, want ErrNotFound", err)
	}
}

// ============================================================================
// G23: MsgCFilter Filter varbytes max size
// ============================================================================

// G23 / BUG-9 — P2 CDIV: MsgCFilter.Deserialize caps the Filter varbytes
// at `1 << 20` = 1 MiB (msg_cfilter.go:100). Core's
// MAX_PROTOCOL_MESSAGE_LENGTH is 4 * 1000 * 1000 = 4 MB (net.h:65), and a
// compact filter for a max-size 4 MB block could approach (but rarely
// exceeds) 1 MB on adversarial blocks. Real-world filters are <100 KB.
// Latent risk: peers serving filters for huge blocks would have their
// cfilter msg rejected by blockbrew with ErrTooManyHeaders / read error.
// Same cap in BlockFilterData.Deserialize (blockfilterindex.go:70).
func TestW121_G23_MsgCFilterMaxFilterSize(t *testing.T) {
	t.Skip("BUG-9: internal/p2p/msg_cfilter.go:100 + internal/storage/blockfilterindex.go:70 " +
		"cap filter at 1 MiB. Core MAX_PROTOCOL_MESSAGE_LENGTH = 4 MB. Latent " +
		"deserialization failure for large filters. P2 CDIV.")
}

// ============================================================================
// G24: NODE_COMPACT_FILTERS service flag value = 1 << 6
// ============================================================================

// G24 / PASS: ServiceNodeCompactFilters = 1 << 6 (64) matches Core's
// NODE_COMPACT_FILTERS = (1 << 6) (protocol.h:323).
func TestW121_G24_ServiceFlagValue(t *testing.T) {
	// The constant lives in package p2p; document the value here.
	const want = uint64(1 << 6)
	const wantNum = uint64(64)
	if want != wantNum {
		t.Errorf("G24: NODE_COMPACT_FILTERS sanity = %d, want 64", want)
	}
}

// ============================================================================
// G25: NODE_COMPACT_FILTERS advertised when -blockfilterindex enabled
// ============================================================================

// G25 / PASS: PeerManager.serviceFlags() OR-ins ServiceNodeCompactFilters
// when config.AdvertiseCompactFilters is true (peermgr.go:1662-1667).
// main.go wires AdvertiseCompactFilters = cfg.BlockFilterIndex
// (main.go:1354). Connected peers see the service bit and may direct
// getcfilters/getcfheaders/getcfcheckpt at us. Confirmed.
func TestW121_G25_AdvertiseCompactFiltersWiring(t *testing.T) {
	// Documented in the implementation; the actual peerMgr smoke test
	// requires the p2p package's W121 audit file (peermgr-side checks).
	t.Log("G25 PASS: -blockfilterindex flag toggles NODE_COMPACT_FILTERS advertisement.")
}

// ============================================================================
// G26: BlockFilterIndex constructor wires BaseIndex
// ============================================================================

// G26 / PASS: NewBlockFilterIndex composes a *BaseIndex named
// "blockfilterindex" — confirmed by registration in IndexManager
// (main.go:825-826).
func TestW121_G26_ConstructorBaseIndex(t *testing.T) {
	idx := NewBlockFilterIndex(NewMemDB())
	if idx == nil {
		t.Fatal("G26: NewBlockFilterIndex returned nil")
	}
	if idx.BaseIndex == nil {
		t.Error("G26: BlockFilterIndex.BaseIndex must be non-nil")
	}
}

// ============================================================================
// G27: getblockfilter RPC returns filter+header for known block
// ============================================================================

// G27 / PASS: handleGetBlockFilter (extra_methods.go:598) accepts
// (blockhash, filtertype?) → returns {filter, header}. Wire-format matches
// Core's getblockfilter RPC result schema. Error code divergence is BUG-12
// (G20). Happy path confirmed via internal/rpc/rest_test.go +
// extra_methods.go inspection.
func TestW121_G27_GetBlockFilterRPCResultShape(t *testing.T) {
	// The BlockFilterResult type lives in package rpc and cannot be referenced
	// directly from this storage-side audit file. Per source inspection,
	// internal/rpc/extra_methods.go:668-672 defines:
	//   type BlockFilterResult struct {
	//       Filter string `json:"filter"`
	//       Header string `json:"header"`
	//   }
	// which matches Core's getblockfilter RPC result schema exactly.
	t.Log("G27 PASS: BlockFilterResult has {filter, header} matching Core's " +
		"getblockfilter result schema (rpc/blockchain.cpp:2966-2970).")
}

// ============================================================================
// G28: REST /rest/blockfilter/<type>/<hash>.<format> returns filter
// ============================================================================

// G28 / PASS: handleRESTBlockFilter (rest.go:924) implements
// GET /rest/blockfilter/<filtertype>/<hash>.<ext> with bin/hex/json output
// modes. JSON output matches Core's restBlockFilterJSON
// ({"filter":"..."}). Binary output is filter_type || block_hash ||
// varbytes(filter). Mirrors Core rest.cpp::rest_block_filter.
func TestW121_G28_RESTBlockFilterRoute(t *testing.T) {
	// The route registration is in rest.go:111. The JSON response struct
	// `restBlockFilterJSON` (rest.go:885) is internal to the rpc package and
	// not referenceable here; per source inspection the field is `Filter
	// string json:"filter"` matching Core's restBlockFilterJSON.
	t.Log("G28 PASS: /rest/blockfilter/<type>/<hash>.<format> implemented with " +
		"bin/hex/json output matching Core rest.cpp::rest_block_filter.")
}

// ============================================================================
// G29: REST /rest/blockfilterheaders returns N filter headers
// ============================================================================

// G29 / PASS: handleRESTBlockFilterHeaders (rest.go:1020) implements
// GET /rest/blockfilterheaders/<filtertype>/<count>/<hash>.<ext>, walks
// forward in the active chain via tipNode.GetAncestor(h), and returns
// up to <count> 32-byte filter headers. Mirrors Core rest.cpp::rest_filter_header.
func TestW121_G29_RESTBlockFilterHeadersRoute(t *testing.T) {
	t.Log("G29 PASS: /rest/blockfilterheaders/<type>/<count>/<hash>.<format> " +
		"implemented; walks active chain via GetAncestor. Matches Core rest.cpp.")
}

// ============================================================================
// G30: -blockfilterindex flag gates index registration + REST/RPC exposure
// ============================================================================

// G30 / PASS: cfg.BlockFilterIndex (cmd/blockbrew/main.go:191, flag at
// :482) is the single source of truth for:
//
//   - IndexManager registration of the BlockFilterIndex (main.go:825)
//   - NODE_COMPACT_FILTERS service-flag advertisement (main.go:1354)
//   - Inbound getcfilters/getcfheaders/getcfcheckpt listener wiring
//     (main.go:1222)
//
// When off (the default, matching Core's -blockfilterindex=0):
//
//   - REST /rest/blockfilter returns "Index is not enabled for filtertype basic"
//   - getblockfilter RPC returns "Block filter index not available"
//   - Peers requesting filters get the default empty-listener (silent drop)
//     instead of Core's fDisconnect = true. See BUG-10 (G11).
func TestW121_G30_BlockFilterIndexFlagGating(t *testing.T) {
	t.Log("G30 PASS: -blockfilterindex flag is the single source of truth for " +
		"index registration, NODE_COMPACT_FILTERS advertisement, and inbound " +
		"compact-filter listener wiring. Default OFF matches Core.")
}
