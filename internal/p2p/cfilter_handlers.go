// FIX-74 / W121 BUG-6 + BUG-7 + BUG-8 (PARTIAL):
//
// BIP-157 compact-filter request handler helpers. Mirrors Bitcoin Core's
// PrepareBlockFilterRequest + ProcessGetCFilters / ProcessGetCFHeaders /
// ProcessGetCFCheckPt in src/net_processing.cpp.
//
// The pre-FIX-74 inline handlers in cmd/blockbrew/main.go looked up filters
// by raw height via blockFilterIndex.GetFilter(h). When the peer's stop_hash
// was on an abandoned fork, that returned the *active-chain* block's filter
// at that height — a "signed but lying" response (DoS vector + privacy leak
// about the peer's fork interest).
//
// Core's correct behavior (net_processing.cpp:3262 PrepareBlockFilterRequest
// + src/chain.h CBlockIndex::GetAncestor): resolve stop_hash → stop_index,
// validate range + caps, then for each height h in [start_height,
// stop_index.nHeight] use stop_index->GetAncestor(h) to find the block on
// the stop_hash chain and look up the filter for THAT block's hash.
//
// Note: NO chain.Contains(stop_index) check — Core deliberately serves
// stale-fork filters when the peer provides an orphan stop_hash, because
// compact filters are indexed by block hash regardless of fork. If the
// fork's filters are present on disk Core serves them; if not (because
// blockbrew currently only indexes by height — the active chain's most
// recent winner per height), the handler returns early without lying.
//
// Disconnect-on-violation matches Core's node.fDisconnect=true behavior in
// PrepareBlockFilterRequest (unknown filter type, unknown stop_hash, start
// > stop, range too large).

package p2p

import (
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// CFilterHeaderIndex is the subset of consensus.HeaderIndex used by the
// BIP-157 handlers. Defined as an interface so the helpers below can be
// exercised in unit tests without standing up a full header index.
type CFilterHeaderIndex interface {
	GetNode(hash wire.Hash256) *consensus.BlockNode
}

// CFilterIndex is the subset of storage.BlockFilterIndex used by the
// BIP-157 handlers. Same testability rationale as CFilterHeaderIndex.
type CFilterIndex interface {
	// GetFilter returns the filter row (BlockHash + Filter + FilterHash +
	// FilterHeader) at a given height. Errors with storage.ErrNotFound
	// when the height has no entry (pre-genesis or beyond the index tip).
	GetFilter(height int32) (*storage.BlockFilterData, error)
}

// PeerDisconnector is the minimal Peer surface used by the handlers to
// punish misbehaving peers. Real *Peer implements this; tests stub it.
type PeerDisconnector interface {
	Misbehaving(score int, reason string) bool
	Disconnect()
}

// CFilterMessageSender is the minimal Peer surface used to push cfilter /
// cfheaders / cfcheckpt responses back to the peer.
type CFilterMessageSender interface {
	SendMessage(msg Message)
}

// CFilterRequestPeer combines the disconnect + send surfaces.
type CFilterRequestPeer interface {
	PeerDisconnector
	CFilterMessageSender
}

// MisbehaviorScoreInvalidCFilterRequest is the discourage score used when
// a peer issues a malformed BIP-157 request (matches Core's
// node.fDisconnect=true semantics — single-event discourage).
//
// W99 G1 fix folded this into the single-event-discourage model: any
// Misbehaving() call immediately flags the peer for ban. The score
// remains for diagnostic logging.
const MisbehaviorScoreInvalidCFilterRequest = 100

// PrepareBlockFilterRequest validates a BIP-157 getcfilters / getcfheaders
// request. On success it returns the stop_index BlockNode (the header
// resolved from stop_hash). On failure it disconnects the peer (Core
// behavior: node.fDisconnect=true) and returns nil.
//
// max_height_diff matches Core's MAX_GETCFILTERS_SIZE (1000) or
// MAX_GETCFHEADERS_SIZE (2000) depending on the request type.
//
// Reference: net_processing.cpp:3262 PrepareBlockFilterRequest.
func PrepareBlockFilterRequest(
	peer PeerDisconnector,
	filterType uint8,
	startHeight uint32,
	stopHash wire.Hash256,
	maxHeightDiff uint32,
	headerIdx CFilterHeaderIndex,
) *consensus.BlockNode {
	if filterType != FilterTypeBasic {
		peer.Misbehaving(MisbehaviorScoreInvalidCFilterRequest,
			"unsupported block filter type")
		peer.Disconnect()
		return nil
	}

	stopNode := headerIdx.GetNode(stopHash)
	if stopNode == nil {
		peer.Misbehaving(MisbehaviorScoreInvalidCFilterRequest,
			"invalid block hash in cfilter request")
		peer.Disconnect()
		return nil
	}

	if stopNode.Height < 0 {
		peer.Misbehaving(MisbehaviorScoreInvalidCFilterRequest,
			"negative-height block in cfilter request")
		peer.Disconnect()
		return nil
	}

	stopHeight := uint32(stopNode.Height)
	if startHeight > stopHeight {
		peer.Misbehaving(MisbehaviorScoreInvalidCFilterRequest,
			"start height > stop height in cfilter request")
		peer.Disconnect()
		return nil
	}

	// Core: `stop_height - start_height >= max_height_diff`. We mirror
	// the same off-by-one: a request asking for exactly max_height_diff
	// filters (stop - start + 1 == max_height_diff) is permitted; a
	// request asking for max_height_diff + 1 is rejected.
	if stopHeight-startHeight >= maxHeightDiff {
		peer.Misbehaving(MisbehaviorScoreInvalidCFilterRequest,
			"too many cfilters/cfheaders requested")
		peer.Disconnect()
		return nil
	}

	return stopNode
}

// LookupFilterRangeByStopHash walks stop_index.GetAncestor(h) for each
// height in [start_height, stop_index.Height] and looks up the stored
// filter at that height. Returns the filter slice in ascending-height
// order, or (nil, false) if any expected entry is missing or doesn't
// match the ancestor block hash.
//
// Mirrors Core's BlockFilterIndex::LookupFilterRange in
// src/index/blockfilterindex.cpp:398, with the twist that blockbrew
// currently only indexes filters by height (no secondary DBHashKey
// table), so we cannot serve filters for blocks that have been
// reorganized off the active chain.
//
// If the ancestor at height h has a different hash than the filter row's
// stored BlockHash, the function returns (nil, false) — the caller MUST
// NOT send any cfilters back (signed-but-lying avoidance). This is
// stricter than Core (which would fall back to the hash index), but
// matches blockbrew's storage capabilities; the alternative — sending
// active-chain filters labeled with stale-fork stop_hash — is the
// W121 BUG-6 bug we are fixing.
func LookupFilterRangeByStopHash(
	startHeight int32,
	stopNode *consensus.BlockNode,
	filterIdx CFilterIndex,
) ([]*storage.BlockFilterData, bool) {
	if stopNode == nil {
		return nil, false
	}
	if startHeight < 0 || startHeight > stopNode.Height {
		return nil, false
	}
	count := stopNode.Height - startHeight + 1
	out := make([]*storage.BlockFilterData, 0, count)
	for h := startHeight; h <= stopNode.Height; h++ {
		anc := stopNode.GetAncestor(h)
		if anc == nil {
			return nil, false
		}
		fd, err := filterIdx.GetFilter(h)
		if err != nil || fd == nil {
			return nil, false
		}
		// Verify the filter stored at this height is for the block on
		// the stop_hash chain, not for some other-fork winner. If it's
		// not a match, blockbrew's height-only index lacks the fork's
		// filter — abort without serving (do NOT lie to the peer).
		if fd.BlockHash != anc.Hash {
			return nil, false
		}
		out = append(out, fd)
	}
	return out, true
}

// LookupFilterHeaderByStopHashAtPrev returns the prev_filter_header for a
// getcfheaders response — the filter header of the block at
// (start_height - 1) on the stop_hash chain. Returns the all-zero
// sentinel when start_height == 0 (BIP-158 §genesis).
//
// Mirrors Core's GetCFHeaders prev_block resolution
// (net_processing.cpp:3362-3370).
func LookupFilterHeaderByStopHashAtPrev(
	startHeight int32,
	stopNode *consensus.BlockNode,
	filterIdx CFilterIndex,
) (wire.Hash256, bool) {
	var zero wire.Hash256
	if startHeight < 0 {
		return zero, false
	}
	if startHeight == 0 {
		// BIP-158 genesis-sentinel: prev_filter_header at h=-1 is all zeros.
		return zero, true
	}
	if stopNode == nil {
		return zero, false
	}
	prevAnc := stopNode.GetAncestor(startHeight - 1)
	if prevAnc == nil {
		return zero, false
	}
	fd, err := filterIdx.GetFilter(startHeight - 1)
	if err != nil || fd == nil {
		return zero, false
	}
	if fd.BlockHash != prevAnc.Hash {
		return zero, false
	}
	return fd.FilterHeader, true
}

// HandleGetCFilters implements the getcfilters BIP-157 handler.
// On success it sends one cfilter message per requested height back to
// the peer. On peer misbehavior (unknown stop_hash, range too large,
// etc.) it calls peer.Misbehaving + peer.Disconnect to match Core's
// fDisconnect behavior.
//
// Reference: net_processing.cpp:3315 ProcessGetCFilters.
func HandleGetCFilters(
	peer CFilterRequestPeer,
	msg *MsgGetCFilters,
	headerIdx CFilterHeaderIndex,
	filterIdx CFilterIndex,
) {
	stopNode := PrepareBlockFilterRequest(
		peer,
		msg.FilterType,
		msg.StartHeight,
		msg.StopHash,
		MaxCFiltersPerRequest,
		headerIdx,
	)
	if stopNode == nil {
		return
	}

	filters, ok := LookupFilterRangeByStopHash(
		int32(msg.StartHeight),
		stopNode,
		filterIdx,
	)
	if !ok {
		// Missing data on stop_hash chain — return without sending.
		// Distinct from peer-misbehavior: we don't disconnect because the
		// peer's request was well-formed; we just lack the data.
		return
	}
	for _, fd := range filters {
		peer.SendMessage(&MsgCFilter{
			FilterType: FilterTypeBasic,
			BlockHash:  fd.BlockHash,
			Filter:     fd.Filter,
		})
	}
}

// HandleGetCFHeaders implements the getcfheaders BIP-157 handler.
//
// Reference: net_processing.cpp:3344 ProcessGetCFHeaders.
func HandleGetCFHeaders(
	peer CFilterRequestPeer,
	msg *MsgGetCFHeaders,
	headerIdx CFilterHeaderIndex,
	filterIdx CFilterIndex,
) {
	stopNode := PrepareBlockFilterRequest(
		peer,
		msg.FilterType,
		msg.StartHeight,
		msg.StopHash,
		MaxCFHeadersPerRequest,
		headerIdx,
	)
	if stopNode == nil {
		return
	}

	prevHeader, ok := LookupFilterHeaderByStopHashAtPrev(
		int32(msg.StartHeight),
		stopNode,
		filterIdx,
	)
	if !ok {
		return
	}

	filters, ok := LookupFilterRangeByStopHash(
		int32(msg.StartHeight),
		stopNode,
		filterIdx,
	)
	if !ok {
		return
	}
	hashes := make([]wire.Hash256, 0, len(filters))
	for _, fd := range filters {
		hashes = append(hashes, fd.FilterHash)
	}
	peer.SendMessage(&MsgCFHeaders{
		FilterType:       FilterTypeBasic,
		StopHash:         msg.StopHash,
		PrevFilterHeader: prevHeader,
		FilterHashes:     hashes,
	})
}

// HandleGetCFCheckpt implements the getcfcheckpt BIP-157 handler.
//
// Core: PrepareBlockFilterRequest with start_height=0 + max_height_diff=
// uint32::max (effectively unbounded), then loop in REVERSE from
// headers.size()-1 down to 0, emitting checkpoints at heights
// (i+1) * CFCHECKPT_INTERVAL via stop_index->GetAncestor(height).
//
// W121 BUG-7 (P0-CDIV) FIX: pre-FIX-74 blockbrew started the loop at
// CFCheckptInterval-1 (h=999, 1999, 2999, ...) instead of Core's
// CFCheckptInterval (h=1000, 2000, 3000, ...). Every checkpoint header
// was one block too low → filter-header chain wire-incompatible with
// Bitcoin Core and any compliant BIP-157 implementation.
//
// Reference: net_processing.cpp:3386 ProcessGetCFCheckPt;
// blockfilterindex.h CFCHECKPT_INTERVAL = 1000.
func HandleGetCFCheckpt(
	peer CFilterRequestPeer,
	msg *MsgGetCFCheckpt,
	headerIdx CFilterHeaderIndex,
	filterIdx CFilterIndex,
) {
	// Core uses start_height=0 and max_height_diff=uint32::max for
	// getcfcheckpt; we mirror that as "no per-request range limit".
	// PrepareBlockFilterRequest still validates filter type + stop_hash.
	stopNode := PrepareBlockFilterRequest(
		peer,
		msg.FilterType,
		0,
		msg.StopHash,
		^uint32(0), // uint32::max — effectively unbounded
		headerIdx,
	)
	if stopNode == nil {
		return
	}

	// Core: headers.size() = stop_index->nHeight / CFCHECKPT_INTERVAL,
	// heights at (i+1) * CFCHECKPT_INTERVAL for i in [0, size).
	stopHeight := stopNode.Height
	numCheckpoints := stopHeight / CFCheckptInterval
	if numCheckpoints <= 0 {
		// No checkpoints to send (stop_height < CFCHECKPT_INTERVAL).
		// Match Core's empty response — still send the cfcheckpt message.
		peer.SendMessage(&MsgCFCheckpt{
			FilterType:    FilterTypeBasic,
			StopHash:      msg.StopHash,
			FilterHeaders: nil,
		})
		return
	}

	headers := make([]wire.Hash256, numCheckpoints)
	// Core walks the index backwards: for i in [size-1 .. 0], height =
	// (i+1) * CFCHECKPT_INTERVAL, then block_index = stop_index->
	// GetAncestor(height). We do the same.
	for i := numCheckpoints - 1; i >= 0; i-- {
		height := (i + 1) * CFCheckptInterval
		anc := stopNode.GetAncestor(height)
		if anc == nil {
			return
		}
		fd, err := filterIdx.GetFilter(height)
		if err != nil || fd == nil {
			return
		}
		if fd.BlockHash != anc.Hash {
			return
		}
		headers[i] = fd.FilterHeader
	}

	peer.SendMessage(&MsgCFCheckpt{
		FilterType:    FilterTypeBasic,
		StopHash:      msg.StopHash,
		FilterHeaders: headers,
	})
}
