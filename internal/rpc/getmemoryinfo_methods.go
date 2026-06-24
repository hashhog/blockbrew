package rpc

import (
	"encoding/json"
	"fmt"
)

// handleGetMemoryInfo implements the getmemoryinfo RPC.
//
//	getmemoryinfo ( "mode" )
//
// Faithful port of bitcoin-core/src/rpc/node.cpp getmemoryinfo (:145-198) +
// RPCLockedMemoryInfo (:113-124) + RPCMallocInfo (:126-143). PURE read-only
// introspection of the daemon's own memory accounting — no side effects, no
// chain/mempool/peer locks. Safe at any lifecycle stage. NOT consensus.
//
// IMPORTANT SEMANTICS: this RPC reports Core's SECURE LOCKED-MEMORY POOL
// (LockedPoolManager — the mlock()-backed allocator that keeps sensitive data
// such as wallet private keys OFF swap), NOT general process or heap memory.
// Do not confuse the "locked" memory here with the transaction "memory pool"
// (mempool).
//
// Param: mode (string, OPTIONAL, default "stats") — what kind of information is
// returned.
//   - "stats": general statistics about memory usage in the daemon.
//   - "mallocinfo": Core returns a glibc malloc_info(3) XML string ONLY when
//     built with glibc (HAVE_MALLOC_INFO); otherwise -8 "mallocinfo mode not
//     available".
//
// Returns (mode-dependent, matching Core exactly):
//
//   - mode == "stats" (default) -> OBJECT, pushKV order top-level {locked},
//     inside used, free, total, locked, chunks_used, chunks_free:
//
//     { "locked": { "used": int, "free": int, "total": int,
//     "locked": int, "chunks_used": int, "chunks_free": int } }
//
//     All six inner values are non-negative integers (Core size_t). blockbrew
//     is a from-scratch Go node with NO Core-style mlock()-backed secure pool
//     (verified: no mlock / VirtualLock / sodium_mlock / LockedPool in the
//     source), so the honest answer is all zeros — but the keys/structure are
//     ALWAYS present and identical to Core. A node with an empty/absent locked
//     pool legitimately reports zeros; shape-match parity holds.
//
//   - mode == "mallocinfo" -> Core's non-glibc path. Go's runtime allocator
//     exposes no glibc malloc_info(3) equivalent, so we faithfully raise Core's
//     non-HAVE_MALLOC_INFO error -8 "mallocinfo mode not available" rather than
//     fabricate a stub XML string Core never emits.
//
// Errors (matching Core code + message exactly):
//   - Unknown mode -> RPC_INVALID_PARAMETER (-8), "unknown mode <mode>"
//     (Core node.cpp:194, tfm::format("unknown mode %s", mode)).
//   - mode == "mallocinfo" -> RPC_INVALID_PARAMETER (-8),
//     "mallocinfo mode not available" (Core node.cpp:191, non-glibc path).
//   - Non-string mode -> RPC_TYPE_ERROR (-3), enforced BEFORE handler logic,
//     matching Core's Arg<std::string_view>("mode") type resolution.
func (s *Server) handleGetMemoryInfo(params json.RawMessage) (interface{}, *RPCError) {
	// mode defaults to "stats" when omitted (Core RPCArg::Default{"stats"}).
	mode := "stats"

	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameters"}
		}
		if len(args) > 0 && args[0] != nil {
			// Core reads the mode arg as Arg<std::string_view>: a non-string
			// value (number/bool/object/array) is a JSON type error (-3) BEFORE
			// any handler logic runs. json.Unmarshal yields a Go string only for
			// JSON strings, so a failed type assertion cleanly rejects all other
			// JSON types — matching Core's strict typing.
			str, ok := args[0].(string)
			if !ok {
				return nil, &RPCError{
					Code:    RPCErrTypeError,
					Message: "JSON value is not a string as expected",
				}
			}
			mode = str
		}
	}

	switch mode {
	case "stats":
		// Core RPCLockedMemoryInfo() reads
		// LockedPoolManager::Instance().stats() and emits the six counters under
		// "locked" in this exact order. blockbrew has no mlock'd secure
		// allocator, so every counter is an honest 0. Keys are always present.
		// json.Marshal of a Go map would re-sort the keys alphabetically, which
		// would NOT preserve Core's pushKV order (used, free, total, locked,
		// chunks_used, chunks_free); assemble the bytes verbatim instead.
		const lockedStats = `{"locked":{"used":0,"free":0,"total":0,"locked":0,"chunks_used":0,"chunks_free":0}}`
		return json.RawMessage(lockedStats), nil

	case "mallocinfo":
		// Core returns glibc malloc_info(3) XML ONLY when built with glibc
		// (HAVE_MALLOC_INFO); on every other build it raises this exact -8 error
		// (node.cpp:191). Go's runtime allocator has no malloc_info equivalent,
		// so we faithfully take Core's non-glibc path rather than fabricate a
		// stub XML string Core never emits.
		return nil, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: "mallocinfo mode not available",
		}

	default:
		// Any other mode is Core's RPC_INVALID_PARAMETER (-8) "unknown mode %s"
		// (node.cpp:194, tfm::format).
		return nil, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("unknown mode %s", mode),
		}
	}
}
