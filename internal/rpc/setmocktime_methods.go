package rpc

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/clock"
)

// handleSetMockTime mirrors Core's setmocktime (rpc/node.cpp): regtest-only,
// one required numeric timestamp, negative is RPC_INVALID_PARAMETER, 0
// restores the wall clock, result is null.
func (s *Server) handleSetMockTime(params json.RawMessage) (interface{}, *RPCError) {
	if s.chainParams == nil || s.chainParams.Name != "regtest" {
		return nil, &RPCError{Code: RPCErrMisc, Message: "setmocktime is for regression testing (-regtest mode) only"}
	}
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Missing required argument: timestamp"}
	}
	v, ok := args[0].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "JSON value is not an integer as expected"}
	}
	if v < 0 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: fmt.Sprintf("Mocktime cannot be negative: %d.", int64(v))}
	}
	if v != math.Trunc(v) || v > math.MaxInt64/2 {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "JSON value is not an integer as expected"}
	}
	clock.SetMock(int64(v))
	return nil, nil
}
