package rpc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Wait-family RPCs: waitfornewblock / waitforblock / waitforblockheight.
//
// Ports Bitcoin Core rpc/blockchain.cpp (waitfornewblock @290, waitforblock
// @349, waitforblockheight @410). Each blocks until its tip predicate holds or
// a millisecond timeout elapses, then returns the CURRENT tip {hash, height}
// in BOTH the match and the timeout case (Core returns the current block in
// both). The wait re-reads the AUTHORITATIVE chain tip (chainMgr.BestBlock())
// on every wake so a coalesced / missed notify can never produce a wrong
// answer — the TipNotifier (internal/consensus/tipnotifier.go) only provides a
// prompt wake, correctness rides on the re-read + the generation snapshot.
//
// Error parity (verified against live Core in the ouroboros pilot):
//   - malformed blockhash / current_tip (not 64-hex) -> -8 (ParseHashV)
//   - negative timeout                                -> -1 "Negative timeout"
//   - non-integer timeout / non-int height            -> -3 (type error)
// For waitforblock the blockhash is parsed BEFORE the timeout, so a malformed
// blockhash errors -8 even when the timeout is also negative.

// waitResult is the {hash, height} object every wait-family RPC returns.
type waitResult struct {
	Hash   string `json:"hash"`
	Height int32  `json:"height"`
}

// parseWaitTimeout validates a wait-family `timeout` argument (milliseconds).
//
// Mirrors Core (rpc/blockchain.cpp): the value is read via getInt<int>, so a
// non-number JSON value is a TYPE error (-3 "JSON value of type X is not of
// expected type number"), a fractional number is also rejected (Core's
// from_chars rejects "1.5"), and a negative value is RPC_MISC_ERROR (-1)
// "Negative timeout". null / omitted -> 0 (wait indefinitely).
//
// In Go's encoding/json every JSON number decodes to float64, so a fractional
// value is detected by comparing against its truncation. The ouroboros pilot
// (which byte-matched live Core) classifies a fractional timeout as the -3
// type error, matching the prompt's "non-integer timeout -> -3" requirement.
func parseWaitTimeout(v interface{}) (int64, *RPCError) {
	if v == nil {
		return 0, nil
	}
	f, ok := v.(float64)
	if !ok {
		// string / bool / array / object: Core's getInt<int> checkType(VNUM)
		// throws a type error before reading the value.
		return 0, &RPCError{
			Code:    RPCErrTypeError,
			Message: fmt.Sprintf("JSON value of type %s is not of expected type number", jsonTypeName(v)),
		}
	}
	if f != float64(int64(f)) {
		// A JSON number with a fractional part is not an integer; Core rejects
		// it. Classify as the -3 type error per the verified pilot semantics.
		return 0, &RPCError{
			Code:    RPCErrTypeError,
			Message: fmt.Sprintf("JSON value of type %s is not of expected type number", jsonTypeName(v)),
		}
	}
	ms := int64(f)
	if ms < 0 {
		return 0, &RPCError{Code: RPCErrMisc, Message: "Negative timeout"}
	}
	return ms, nil
}

// parseWaitHeight reads a required block-height argument as Core's getInt<int>
// does: a non-number is a -3 type error, a fractional number is rejected.
func parseWaitHeight(v interface{}) (int32, *RPCError) {
	f, ok := v.(float64)
	if !ok {
		return 0, &RPCError{
			Code:    RPCErrTypeError,
			Message: fmt.Sprintf("JSON value of type %s is not of expected type number", jsonTypeName(v)),
		}
	}
	if f != float64(int64(f)) {
		return 0, &RPCError{
			Code:    RPCErrTypeError,
			Message: fmt.Sprintf("JSON value of type %s is not of expected type number", jsonTypeName(v)),
		}
	}
	return int32(f), nil
}

// waitForTip is Core's wait-tip-changed loop shared by all three handlers
// (rpc/blockchain.cpp: the `while (predicate fails) { waitTipChanged(...) }`
// pattern). predicate is evaluated against the AUTHORITATIVE tip on every wake.
// timeoutMs is in milliseconds; 0 = wait indefinitely. Returns the current tip
// once the predicate holds OR the timeout elapses (Core returns the current
// block in both cases).
func (s *Server) waitForTip(predicate func(hash wire.Hash256, height int32) bool, timeoutMs int64) (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	hash, height := s.chainMgr.BestBlock()
	if predicate(hash, height) {
		return waitResult{Hash: hash.String(), Height: height}, nil
	}

	notifier := s.chainMgr.TipNotifier()
	if notifier == nil {
		// No notifier wired (degraded boot): we cannot block on tip changes,
		// so return the current tip rather than hang. Defensive fallback only;
		// the daemon always wires one (cmd/blockbrew/main.go).
		return waitResult{Hash: hash.String(), Height: height}, nil
	}

	// Absolute deadline for the bounded case. Core uses a steady-clock deadline
	// and re-derives the remaining slice after each wake; a single time.Timer
	// firing into a channel is the Go analogue. nil timer/channel = unbounded.
	var timer *time.Timer
	var deadlineCh <-chan struct{}
	if timeoutMs > 0 {
		done := make(chan struct{})
		timer = time.AfterFunc(time.Duration(timeoutMs)*time.Millisecond, func() { close(done) })
		deadlineCh = done
		defer timer.Stop()
	}

	for {
		// Snapshot the generation, THEN re-read the authoritative tip and check
		// the predicate. A notify that races in between the check and the Wait
		// bumps the generation, so Wait's fast path returns immediately (no
		// lost wakeup). The re-read is what makes a coalesced notify safe.
		gen := notifier.Generation()
		hash, height = s.chainMgr.BestBlock()
		if predicate(hash, height) {
			return waitResult{Hash: hash.String(), Height: height}, nil
		}
		if timeoutMs > 0 {
			// Re-read the tip one last time on the timeout path so the returned
			// block reflects the latest known tip (Core returns the current
			// block on timeout).
			if !notifier.Wait(gen, deadlineCh) {
				hash, height = s.chainMgr.BestBlock()
				return waitResult{Hash: hash.String(), Height: height}, nil
			}
		} else {
			notifier.Wait(gen, nil)
		}
	}
}

// handleWaitForNewBlock implements waitfornewblock(timeout=0, current_tip=opt).
// Waits until the tip hash differs from current_tip (or, if omitted, from the
// tip observed at call entry), then returns {hash, height}. timeout is in
// milliseconds; 0 = no timeout.
func (s *Server) handleWaitForNewBlock(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}

	// Core order: timeout (params[0]) is read first, then current_tip
	// (params[1]). A negative/non-int timeout errors before current_tip is
	// parsed.
	var timeoutArg interface{}
	if len(args) >= 1 {
		timeoutArg = args[0]
	}
	timeoutMs, rerr := parseWaitTimeout(timeoutArg)
	if rerr != nil {
		return nil, rerr
	}

	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Determine the reference hash the new tip must differ from. With a
	// current_tip arg it is parsed as a 64-hex uint256 (ParseHashV -> -8 on
	// malformed); without it, snapshot the live tip at call entry.
	var refHash wire.Hash256
	if len(args) >= 2 && args[1] != nil {
		s, ok := args[1].(string)
		if !ok {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("current_tip must be hexadecimal string (not '%v')", args[1]),
			}
		}
		h, perr := parseHashV(s, "current_tip")
		if perr != nil {
			return nil, perr
		}
		refHash = h
	} else {
		refHash, _ = s.chainMgr.BestBlock()
	}

	return s.waitForTip(func(hash wire.Hash256, _ int32) bool {
		return hash != refHash
	}, timeoutMs)
}

// handleWaitForBlock implements waitforblock(blockhash, timeout=0). blockhash is
// parsed FIRST (before timeout), so a malformed blockhash errors -8 even when
// the timeout is also negative. Waits until the tip hash equals blockhash.
func (s *Server) handleWaitForBlock(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing blockhash parameter"}
	}

	// Core parses blockhash BEFORE reading timeout.
	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("blockhash must be hexadecimal string (not '%v')", args[0]),
		}
	}
	target, perr := parseHashV(hashStr, "blockhash")
	if perr != nil {
		return nil, perr
	}

	var timeoutArg interface{}
	if len(args) >= 2 {
		timeoutArg = args[1]
	}
	timeoutMs, rerr := parseWaitTimeout(timeoutArg)
	if rerr != nil {
		return nil, rerr
	}

	return s.waitForTip(func(hash wire.Hash256, _ int32) bool {
		return hash == target
	}, timeoutMs)
}

// handleWaitForBlockHeight implements waitforblockheight(height, timeout=0).
// Waits until the tip height >= height.
func (s *Server) handleWaitForBlockHeight(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing height parameter"}
	}

	// Core reads height (params[0]) first, then timeout (params[1]).
	wantHeight, herr := parseWaitHeight(args[0])
	if herr != nil {
		return nil, herr
	}

	var timeoutArg interface{}
	if len(args) >= 2 {
		timeoutArg = args[1]
	}
	timeoutMs, rerr := parseWaitTimeout(timeoutArg)
	if rerr != nil {
		return nil, rerr
	}

	return s.waitForTip(func(_ wire.Hash256, height int32) bool {
		return height >= wantHeight
	}, timeoutMs)
}
