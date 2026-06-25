package rpc

import (
	"encoding/json"
	"time"
)

// handleGetNetTotals implements the getnettotals RPC.
//
//	getnettotals
//
// Faithful port of bitcoin-core/src/rpc/net.cpp::getnettotals (:560-608).
// PURE read-only network-traffic introspection — no params, no side effects,
// no chain/mempool locks. NOT consensus.
//
// Returns (matching Core's pushKV order exactly, net.cpp:592-604):
//
//	{
//	  "totalbytesrecv": n,   // Total bytes received
//	  "totalbytessent": n,   // Total bytes sent
//	  "timemillis": n,       // Current UNIX epoch time in MILLISECONDS
//	  "uploadtarget": {
//	    "timeframe": n,                  // measuring timeframe in seconds
//	    "target": n,                     // target in bytes
//	    "target_reached": bool,          // true if target reached
//	    "serve_historical_blocks": bool, // true if serving historical blocks
//	    "bytes_left_in_cycle": n,        // bytes left in current time cycle
//	    "time_left_in_cycle": n          // seconds left in current time cycle
//	  }
//	}
//
// totalbytesrecv/totalbytessent: Core returns CConnman's TRUE global counters
// (GetTotalBytesRecv/Sent), which include traffic from disconnected peers.
// blockbrew keeps only per-peer counters, so PeerManager.GetTotalBytes() sums
// the currently-connected peers' counters (same source getpeerinfo reports as
// bytesrecv/bytessent) — an APPROXIMATION that undercounts traffic from peers
// that have since disconnected (documented on GetTotalBytes). This reuses the
// existing P2P byte-counting machinery rather than adding a parallel one.
//
// uploadtarget: blockbrew has no -maxuploadtarget cap (the outbound-quota
// limiter Core gates on). Core's CConnman with no target configured returns the
// "disabled" shape — target=0, target_reached=false, serve_historical_blocks=
// true (= !OutboundTargetReached(true), which is true when there is no target),
// bytes_left_in_cycle=0, time_left_in_cycle=0 — and timeframe is the
// DEFAULT_MAX_UPLOAD_TIMEFRAME of 60*60*24 = 86400 seconds (net.h:
// MaxOutboundTimeframe is initialised to one day even when no target is set).
// We emit that exact Core-faithful zero/disabled shape, NOT a fabricated value.
func (s *Server) handleGetNetTotals(params json.RawMessage) (interface{}, *RPCError) {
	var totalRecv, totalSent uint64
	if s.peerMgr != nil {
		totalRecv, totalSent = s.peerMgr.GetTotalBytes()
	}

	// Core: TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()).
	timeMillis := time.Now().UnixMilli()

	// Assemble verbatim to preserve Core's pushKV key order; json.Marshal of a
	// Go map re-sorts keys alphabetically, which would NOT match Core's wire
	// order (totalbytesrecv, totalbytessent, timemillis, uploadtarget{...}).
	type uploadTarget struct {
		Timeframe             int64 `json:"timeframe"`
		Target                int64 `json:"target"`
		TargetReached         bool  `json:"target_reached"`
		ServeHistoricalBlocks bool  `json:"serve_historical_blocks"`
		BytesLeftInCycle      int64 `json:"bytes_left_in_cycle"`
		TimeLeftInCycle       int64 `json:"time_left_in_cycle"`
	}
	type netTotals struct {
		TotalBytesRecv uint64       `json:"totalbytesrecv"`
		TotalBytesSent uint64       `json:"totalbytessent"`
		TimeMillis     int64        `json:"timemillis"`
		UploadTarget   uploadTarget `json:"uploadtarget"`
	}

	return netTotals{
		TotalBytesRecv: totalRecv,
		TotalBytesSent: totalSent,
		TimeMillis:     timeMillis,
		UploadTarget: uploadTarget{
			// Core's DEFAULT_MAX_UPLOAD_TIMEFRAME (one day) — the measuring
			// window is always reported even with no target configured.
			Timeframe:             86400,
			Target:                0,
			TargetReached:         false,
			ServeHistoricalBlocks: true,
			BytesLeftInCycle:      0,
			TimeLeftInCycle:       0,
		},
	}, nil
}
