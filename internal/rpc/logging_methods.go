package rpc

import (
	"encoding/json"
	"sort"
)

// DebugLogController is the live per-category debug-logging mask the `logging`
// RPC reads and mutates. It is satisfied by the daemon's global debug state
// (cmd/blockbrew *debugState) and injected via WithDebugLogController, keeping
// the internal/rpc package free of any dependency on package main.
//
// The contract that makes the RPC honour runtime toggles (and avoids the
// "snapshot at construction" trap): every method below operates on the SAME
// in-memory mask the logger consults on every record. Enabling a category here
// makes its debug logs actually start flowing immediately, with no restart —
// exactly like Core's in-memory BCLog::Logger::m_categories mutation.
type DebugLogController interface {
	// Categories returns the full set of REAL category names the node exposes
	// (order unspecified; the RPC sorts). Special tokens (all/1/none/0/"") are
	// NOT categories and never appear here.
	Categories() []string
	// IsCategoryActive reports whether the named category is currently being
	// debug logged (honouring any "all" mask).
	IsCategoryActive(name string) bool
	// IsKnownCategory reports whether name is a real exposed category (NOT a
	// special token). Anything else -> the RPC raises -8.
	IsKnownCategory(name string) bool
	// EnableCategory / DisableCategory flip a single real category. Live.
	EnableCategory(name string)
	DisableCategory(name string)
	// EnableAll / DisableAll set or clear every category (the all/1/""/none/0
	// tokens). Live.
	EnableAll()
	DisableAll()
}

// allTokens are Core's special INPUT-ONLY logging-category names that expand to
// the full mask (logging.cpp GetLogCategory: "", "1", "all"). They are accepted
// as inputs in either array but are NEVER emitted as output keys. In the
// `include` slot they enable everything; in `exclude` they clear everything
// (Core: DisableCategory of the ALL flag — how `logging [], ["all"]` disables
// all). blockbrew also accepts its own "none"/"0" tokens here (its -debug set),
// which clear the mask in either slot — a superset of Core that never conflicts
// with a real category name.
var loggingAllTokens = map[string]bool{"": true, "1": true, "all": true}
var loggingNoneTokens = map[string]bool{"none": true, "0": true}

// handleLogging implements the `logging` RPC.
//
//	logging ( ["include_category",...] ["exclude_category",...] )
//
// Faithful port of bitcoin-core/src/rpc/node.cpp logging (:218-275) +
// EnableOrDisableLogCategories (:200-216) + logging.cpp Enable/DisableCategory /
// LogCategoriesList. Read-and-mutate over the global logger's per-category
// debug mask. NOT consensus, no disk, no network I/O.
//
// blockbrew HAS a real category-based debug-logging system: cmd/blockbrew/
// loglevel.go holds a live (mutex-guarded) enabled-set + "all" bool consulted
// by IsDebugEnabled on every call. This RPC reads and mutates that SAME live
// state through the injected DebugLogController, so enabling a category here
// makes its debug output actually start flowing with no restart — exactly like
// Core mutating m_categories. The category NAMES are blockbrew's own (mirroring
// Core's LOG_CATEGORIES_BY_STR; see loglevel.go), which is permitted — only the
// SHAPE, param-semantics, and the -8 error must match Core.
//
// Params (both OPTIONAL, positional, Core order: include THEN exclude):
//   - include (array of category strings): categories to ENABLE.
//   - exclude (array of category strings): categories to DISABLE.
//
// A param is acted on ONLY if it is a JSON array (Core's isArray() guard); a
// null/omitted/scalar param is a silent no-op for that slot, so `logging` with
// no args is a pure read-and-report (changes nothing). include is applied
// first, then exclude, so a category named in both ends up DISABLED (exclude
// wins). Special input-only tokens all/1/"" expand to the full mask (and
// none/0, blockbrew's own); they are never output keys.
//
// Returns: a single JSON object mapping every REAL category name -> bool
// (whether it is currently being debug logged), emitted in ascending
// alphabetical key order (Core iterates a std::map; alphabetical keeps the
// output byte-stable). all/1/none/0/"" are never output keys.
//
// Errors (matching Core code + message exactly):
//   - Unknown category in either array -> RPC_INVALID_PARAMETER (-8), message
//     "unknown logging category <cat>" (Core node.cpp:213). Thrown as soon as
//     the bad name is hit, after scanning include fully then exclude in order;
//     categories BEFORE the bad one in the same call have ALREADY been applied
//     (partial application, no rollback — Core parity).
//   - Non-string array element -> RPC_TYPE_ERROR (-3) (Core get_str()).
//
// Scope: mutates the running node's in-memory mask immediately; NOT persisted,
// resets on restart to the -debug startup flags. Idempotent.
func (s *Server) handleLogging(params json.RawMessage) (interface{}, *RPCError) {
	c := s.debugLog
	if c == nil {
		// No logging controller wired — surface an internal error rather than
		// fabricate a category map. In production main.go always injects one;
		// this guards a mis-wired build.
		return nil, &RPCError{
			Code:    RPCErrInternal,
			Message: "Error: Logging subsystem unavailable",
		}
	}

	// Parse the (optional) positional params. Core reads request.params[0] and
	// request.params[1] and acts on each ONLY if isArray(); a missing or
	// non-array slot is a silent no-op. We mirror that exactly: decode into a
	// 2-slot positional vector of raw values and treat anything that is not a
	// JSON array as "no action for this slot".
	var args []json.RawMessage
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid parameters"}
		}
	}

	// asCategoryArray returns (names, true) when raw is a JSON array of strings,
	// or (nil, false) when raw is absent/null/non-array (Core isArray() == false
	// -> silently ignored). A non-string element inside an array is Core's
	// get_str() type error (-3).
	asCategoryArray := func(raw json.RawMessage) ([]string, bool, *RPCError) {
		if len(raw) == 0 {
			return nil, false, nil
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			// Not an array (null, scalar, object) -> Core's isArray() is false,
			// so the slot is silently ignored (no error, no action).
			return nil, false, nil
		}
		names := make([]string, 0, len(arr))
		for _, el := range arr {
			var name string
			if err := json.Unmarshal(el, &name); err != nil {
				// Non-string element -> Core get_str() type error.
				return nil, false, &RPCError{
					Code:    RPCErrTypeError,
					Message: "JSON value is not a string as expected",
				}
			}
			names = append(names, name)
		}
		return names, true, nil
	}

	// apply enables (enable=true) or disables (enable=false) each name in order.
	// Special tokens expand to the whole mask; an unknown real-category name is
	// Core's -8, thrown immediately (partial application before the throw — the
	// names already processed in this call have taken effect).
	apply := func(names []string, enable bool) *RPCError {
		for _, name := range names {
			switch {
			case loggingAllTokens[name]:
				if enable {
					c.EnableAll()
				} else {
					c.DisableAll()
				}
			case loggingNoneTokens[name]:
				// blockbrew's own none/0: clears the mask in either slot.
				c.DisableAll()
			case c.IsKnownCategory(name):
				if enable {
					c.EnableCategory(name)
				} else {
					c.DisableCategory(name)
				}
			default:
				// Core node.cpp:213 — EnableCategory/DisableCategory return
				// false for an unknown name -> -8 "unknown logging category".
				return &RPCError{
					Code:    RPCErrInvalidParameter,
					Message: "unknown logging category " + name,
				}
			}
		}
		return nil
	}

	// Core order: include (params[0]) first, then exclude (params[1]); exclude
	// wins on conflict because it is applied second.
	if len(args) > 0 {
		names, isArr, rpcErr := asCategoryArray(args[0])
		if rpcErr != nil {
			return nil, rpcErr
		}
		if isArr {
			if rpcErr := apply(names, true); rpcErr != nil {
				return nil, rpcErr
			}
		}
	}
	if len(args) > 1 {
		names, isArr, rpcErr := asCategoryArray(args[1])
		if rpcErr != nil {
			return nil, rpcErr
		}
		if isArr {
			if rpcErr := apply(names, false); rpcErr != nil {
				return nil, rpcErr
			}
		}
	}

	// Emit the full {category: active} map for every REAL category, in ascending
	// alphabetical key order (Core std::map iteration). all/1/none/0/"" are
	// never keys. We assemble an ordered object literal so json.Marshal of a Go
	// map (which would re-sort but is otherwise fine here) is unnecessary — but
	// sorting then building an ordered struct is the byte-stable choice.
	cats := c.Categories()
	sort.Strings(cats)

	// Build an ordered JSON object: {"<cat>":<bool>, ...} alphabetical.
	buf := make([]byte, 0, len(cats)*24+2)
	buf = append(buf, '{')
	for i, cat := range cats {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, _ := json.Marshal(cat) // safely quotes/escapes the category name
		buf = append(buf, key...)
		buf = append(buf, ':')
		if c.IsCategoryActive(cat) {
			buf = append(buf, "true"...)
		} else {
			buf = append(buf, "false"...)
		}
	}
	buf = append(buf, '}')

	return json.RawMessage(buf), nil
}
