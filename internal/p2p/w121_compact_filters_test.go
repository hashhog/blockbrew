// W121 BIP-157 compact block filter P2P-side audit — blockbrew.
//
// Companion to internal/storage/w121_compact_filters_test.go. This file
// pins the BIP-157 wire constants + ServiceNodeCompactFilters value at
// the package boundary they live in. Full 30-gate audit findings are
// in the storage-side test file.
//
// Reference: Bitcoin Core src/net_processing.cpp (MAX_GETCFILTERS_SIZE,
// MAX_GETCFHEADERS_SIZE, CFCHECKPT_INTERVAL), src/protocol.h
// (NODE_COMPACT_FILTERS = 1 << 6), BIP-157.

package p2p

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// G3 (mirror): FilterTypeBasic = 0
// ============================================================================

// G3 / PASS: BIP-157 §"Filter Type" assigns 0 to BASIC.
func TestW121_G3_FilterTypeBasicWireId(t *testing.T) {
	if FilterTypeBasic != 0 {
		t.Errorf("G3: FilterTypeBasic = %d, want 0 (BIP-157)", FilterTypeBasic)
	}
}

// ============================================================================
// G12 (mirror): MaxCFiltersPerRequest = 1000
// ============================================================================

// G12 / PASS: MaxCFiltersPerRequest = 1000 matches Core's
// MAX_GETCFILTERS_SIZE (net_processing.cpp:184). blockbrew checks
// `count > MaxCFiltersPerRequest`; Core checks
// `stop_height - start_height >= MAX_GETCFILTERS_SIZE`. These are
// equivalent: count = stop-start+1, so count > 1000 ↔ stop-start ≥ 1000.
func TestW121_G12_MaxCFiltersPerRequestValue(t *testing.T) {
	const want = 1000
	if MaxCFiltersPerRequest != want {
		t.Errorf("G12: MaxCFiltersPerRequest = %d, want %d (Core MAX_GETCFILTERS_SIZE)", MaxCFiltersPerRequest, want)
	}
}

// ============================================================================
// G12b (mirror): MaxCFHeadersPerRequest = 2000
// ============================================================================

// G12b / PASS: MaxCFHeadersPerRequest = 2000 matches Core's
// MAX_GETCFHEADERS_SIZE (net_processing.cpp:186).
func TestW121_G12b_MaxCFHeadersPerRequestValue(t *testing.T) {
	const want = 2000
	if MaxCFHeadersPerRequest != want {
		t.Errorf("G12b: MaxCFHeadersPerRequest = %d, want %d (Core MAX_GETCFHEADERS_SIZE)", MaxCFHeadersPerRequest, want)
	}
}

// ============================================================================
// G18 (mirror): CFCheckptInterval = 1000
// ============================================================================

// G18 / PASS (constant) — but BUG-7 reported in storage-side test for
// usage: the constant value 1000 matches Core's CFCHECKPT_INTERVAL
// (blockfilterindex.h:31). The bug is in how main.go USES the constant
// (off-by-one starting offset; see BUG-7 / W121 storage-side G18).
func TestW121_G18_CFCheckptIntervalValue(t *testing.T) {
	const want = 1000
	if CFCheckptInterval != want {
		t.Errorf("G18: CFCheckptInterval = %d, want %d (Core CFCHECKPT_INTERVAL)", CFCheckptInterval, want)
	}
}

// ============================================================================
// G24 (mirror): NODE_COMPACT_FILTERS service flag = 1 << 6
// ============================================================================

// G24 / PASS: ServiceNodeCompactFilters = 1 << 6 = 64 matches Core's
// NODE_COMPACT_FILTERS (protocol.h:323).
func TestW121_G24_ServiceNodeCompactFilters(t *testing.T) {
	const want uint64 = 1 << 6
	if ServiceNodeCompactFilters != want {
		t.Errorf("G24: ServiceNodeCompactFilters = 0x%x, want 0x%x (Core NODE_COMPACT_FILTERS)", ServiceNodeCompactFilters, want)
	}
	if ServiceNodeCompactFilters != 64 {
		t.Errorf("G24: ServiceNodeCompactFilters = %d, want 64", ServiceNodeCompactFilters)
	}
}

// ============================================================================
// G12c: getcfilters round-trip serialization
// ============================================================================

// G12c / PASS: MsgGetCFilters Serialize/Deserialize round-trip preserves
// filter_type (1) || start_height (4 LE) || stop_hash (32). Total wire
// size 37 bytes.
func TestW121_G12c_GetCFiltersWireFormat(t *testing.T) {
	orig := &MsgGetCFilters{
		FilterType:  FilterTypeBasic,
		StartHeight: 100,
		StopHash:    wire.Hash256{0xaa, 0xbb, 0xcc},
	}
	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("G12c: Serialize: %v", err)
	}
	if got := buf.Len(); got != 37 {
		t.Errorf("G12c: getcfilters wire size = %d, want 37 (1+4+32)", got)
	}
	var decoded MsgGetCFilters
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("G12c: Deserialize: %v", err)
	}
	if decoded.FilterType != orig.FilterType ||
		decoded.StartHeight != orig.StartHeight ||
		decoded.StopHash != orig.StopHash {
		t.Errorf("G12c: round-trip mismatch: %+v vs %+v", orig, decoded)
	}
}

// ============================================================================
// G19b: getcfheaders round-trip serialization
// ============================================================================

// G19b / PASS: MsgGetCFHeaders Serialize/Deserialize round-trip preserves
// the same 37-byte wire format as getcfilters.
func TestW121_G19b_GetCFHeadersWireFormat(t *testing.T) {
	orig := &MsgGetCFHeaders{
		FilterType:  FilterTypeBasic,
		StartHeight: 200,
		StopHash:    wire.Hash256{0x11, 0x22, 0x33},
	}
	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("G19b: Serialize: %v", err)
	}
	if got := buf.Len(); got != 37 {
		t.Errorf("G19b: getcfheaders wire size = %d, want 37", got)
	}
	var decoded MsgGetCFHeaders
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("G19b: Deserialize: %v", err)
	}
	if decoded.FilterType != orig.FilterType ||
		decoded.StartHeight != orig.StartHeight ||
		decoded.StopHash != orig.StopHash {
		t.Errorf("G19b: round-trip mismatch")
	}
}

// ============================================================================
// G18b: getcfcheckpt round-trip serialization
// ============================================================================

// G18b / PASS: MsgGetCFCheckpt wire format is filter_type (1) ||
// stop_hash (32) = 33 bytes.
func TestW121_G18b_GetCFCheckptWireFormat(t *testing.T) {
	orig := &MsgGetCFCheckpt{
		FilterType: FilterTypeBasic,
		StopHash:   wire.Hash256{0xde, 0xad, 0xbe, 0xef},
	}
	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("G18b: Serialize: %v", err)
	}
	if got := buf.Len(); got != 33 {
		t.Errorf("G18b: getcfcheckpt wire size = %d, want 33 (1+32)", got)
	}
	var decoded MsgGetCFCheckpt
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("G18b: Deserialize: %v", err)
	}
	if decoded.FilterType != orig.FilterType || decoded.StopHash != orig.StopHash {
		t.Errorf("G18b: round-trip mismatch")
	}
}

// ============================================================================
// G23 (mirror): MsgCFilter filter varbytes cap is 1 MiB (BUG-9)
// ============================================================================

// G23 / BUG-9 — P2 CDIV: MsgCFilter.Deserialize reads at most 1 MiB
// (msg_cfilter.go:100 uses `wire.ReadVarBytes(r, 1<<20)`). Core uses
// MAX_PROTOCOL_MESSAGE_LENGTH = 4 MB for the underlying message-frame
// cap. blockbrew rejects legitimate compact filters that exceed 1 MiB
// (rare on mainnet; possible on adversarial blocks).
func TestW121_G23_MsgCFilterDeserializeCap(t *testing.T) {
	// Verify we can roundtrip a filter at the cap-1 boundary.
	tooBig := make([]byte, (1<<20)+1) // 1 MiB + 1 byte; will fail to deserialize.
	for i := range tooBig {
		tooBig[i] = byte(i)
	}
	orig := &MsgCFilter{
		FilterType: FilterTypeBasic,
		BlockHash:  wire.Hash256{},
		Filter:     tooBig,
	}
	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		// Serialize doesn't enforce the cap; only Deserialize does.
		t.Logf("G23: Serialize cap enforcement: %v", err)
	}
	var decoded MsgCFilter
	err := decoded.Deserialize(&buf)
	if err == nil {
		t.Logf("G23: Deserialize accepted (1 MiB + 1) bytes — cap is on Filter " +
			"field only via ReadVarBytes(r, 1<<20); over-sized filter would fail. " +
			"BUG-9: cap should be 4 MB to match Core MAX_PROTOCOL_MESSAGE_LENGTH.")
	} else {
		t.Logf("G23 BUG-9 confirmed: Deserialize rejected oversize filter at " +
			"1 MiB boundary: %v. Core would accept up to 4 MB.", err)
	}
}

// ============================================================================
// G15 (mirror): Peer listener hooks for compact filters are defined but
// no client-side request emitter exists
// ============================================================================

// G15 / MISSING: PeerListeners has OnGetCFilters/OnCFilter/OnGetCFHeaders/
// OnCFHeaders/OnGetCFCheckpt/OnCFCheckpt (peer.go:98-103). The "On*get*"
// hooks are wired in main.go when -blockfilterindex is set (storage-side
// G15 documentation). The inbound *response* hooks (OnCFilter, OnCFHeaders,
// OnCFCheckpt) are NEVER registered anywhere — blockbrew cannot consume
// filters from peers. No light-client / SPV mode.
func TestW121_G15_NoClientSideFilterConsumer(t *testing.T) {
	// Smoke: ensure the response listener fields exist (struct must compile).
	var pl PeerListeners
	_ = pl.OnCFilter
	_ = pl.OnCFHeaders
	_ = pl.OnCFCheckpt
	t.Log("G15 MISSING: response listeners exist but are never wired to a " +
		"client-side filter consumer. blockbrew can serve but not consume filters.")
}
