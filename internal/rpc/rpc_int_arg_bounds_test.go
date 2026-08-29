// RPC integer arguments must be read at CORE'S WIDTH -- and honoured.
//
// THE DEFECT (pinned here)
// ------------------------
// Core reads every numeric RPC argument through UniValue::getInt<T>()
// (src/univalue/include/univalue.h), which runs std::from_chars INTO THE
// DESTINATION WIDTH. The width check therefore lives inside the CONVERSION and
// fires BEFORE the handler's own domain test:
//
//	out of width / fractional  ->  RPC_MISC_ERROR (-1) "JSON integer out of
//	                               range"   (rpc/server.cpp:514-515)
//	converts, violates range   ->  RPC_INVALID_PARAMETER (-8)
//
// Go's encoding/json hands every JSON number to an interface{} as a float64, so
// nothing raises -- the handler narrows it and acts. Measured against a regtest
// Bitcoin Core oracle (tools/rpc-arg-differential.py), blockbrew ACCEPTED 11
// arguments Core refuses:
//
//	waitforblockheight 2^31   ->  int32(f) is IMPLEMENTATION-DEFINED for an
//	                              out-of-range float64; the node waited for
//	                              some other height entirely.
//	getnodeaddresses 2^31     ->  int(cf) narrowed.
//	gettxout n -1 / 2^32      ->  uint32(voutFloat) narrowed, and the node
//	                              answered `null` -- a legitimate-looking "no
//	                              such output" -- for an argument Core rejects
//	                              outright (it reads n as getInt<uint32_t>,
//	                              which accepts no sign at all).
//	estimatesmartfee -2^31-1  ->  answered for a target it was not asked about.
//
// estimatesmartfee was also the FABRICATION of the set: it took ANY conf_target
// and ignored estimate_mode entirely, where Core's ParseConfirmTarget
// (rpc/util.cpp) rejects outside [1, HighestTargetTracked] and FeeModeFromString
// (common/messages.cpp) rejects an unknown mode, case-insensitively.
//
// TEETH
// -----
// Every case here is a rejection, and a handler that rejected EVERYTHING would
// satisfy all of them. The CONTROLS make that impossible: they drive the real
// handlers to success at the boundary values (int32 max, uint32 max,
// conf_target 1 and 1008, the three fee modes) and assert the answer, so a
// bound off by one in the tight direction fails loudly.

package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

var outOfInt32 = []interface{}{
	float64(2147483648), float64(-2147483649),
	float64(4294967296), float64(-4294967297),
}

const iabTxid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func iabServer() *Server {
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)
}

func iabCall(t *testing.T, method string, params ...interface{}) *RPCResponse {
	t.Helper()
	return testRPCRequest(t, iabServer().handleRPC, method, params, "", "")
}

func iabExpectError(t *testing.T, resp *RPCResponse, wantCode int, wantMsg string) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("expected an error, got result %v", resp.Result)
	}
	if resp.Error.Code != wantCode {
		t.Errorf("code = %d, want %d (message %q)", resp.Error.Code, wantCode, resp.Error.Message)
	}
	if wantMsg != "" && resp.Error.Message != wantMsg {
		t.Errorf("message = %q, want %q", resp.Error.Message, wantMsg)
	}
}

func iabExpectRange(t *testing.T, resp *RPCResponse) {
	t.Helper()
	iabExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
}

// --- wait family -----------------------------------------------------------

func TestWaitForBlockHeightRejectsOutOfInt32Height(t *testing.T) {
	for _, v := range outOfInt32 {
		iabExpectRange(t, iabCall(t, "waitforblockheight", v))
	}
}

func TestWaitForBlockHeightRejectsOutOfInt32Timeout(t *testing.T) {
	for _, v := range outOfInt32 {
		iabExpectRange(t, iabCall(t, "waitforblockheight", float64(1), v))
	}
}

// CONTROL for the ORDER: an in-range negative timeout converts fine and
// reaches the handler's own domain message.
func TestWaitForBlockHeightNegativeTimeoutKeepsCoreMessage(t *testing.T) {
	iabExpectError(t, iabCall(t, "waitforblockheight", float64(1), float64(-1)),
		RPCErrMisc, "Negative timeout")
}

// --- getnodeaddresses ------------------------------------------------------

func TestGetNodeAddressesRejectsOutOfInt32Count(t *testing.T) {
	for _, v := range outOfInt32 {
		iabExpectRange(t, iabCall(t, "getnodeaddresses", v))
	}
}

// CONTROL for the ORDER: -1 converts, so it reaches Core's -8.
func TestGetNodeAddressesNegativeCountIsDomainError(t *testing.T) {
	iabExpectError(t, iabCall(t, "getnodeaddresses", float64(-1)),
		RPCErrInvalidParameter, "Address count out of range")
}

// CONTROL: an in-range count still succeeds.
func TestGetNodeAddressesInRangeCountSucceeds(t *testing.T) {
	resp := iabCall(t, "getnodeaddresses", float64(1))
	if resp.Error != nil {
		t.Fatalf("count 1 must be accepted: %#v", resp.Error)
	}
}

// --- gettxout --------------------------------------------------------------

func TestGetTxOutRejectsVoutOutsideUint32(t *testing.T) {
	for _, v := range []interface{}{float64(4294967296), float64(-1), float64(-2147483649)} {
		iabExpectRange(t, iabCall(t, "gettxout", iabTxid, v))
	}
}

// CONTROL: uint32 MAX is inside the width, so it must get PAST argument
// validation. The bare test server has no chain manager, so "got past" shows
// up as the chain layer's own -28 "Node is warming up" -- which is exactly the
// proof wanted: the handler did not answer with an argument error.
func TestGetTxOutUint32MaxReachesLookup(t *testing.T) {
	resp := iabCall(t, "gettxout", iabTxid, float64(4294967295))
	if resp.Error != nil && resp.Error.Code != RPCErrInWarmup {
		t.Fatalf("vout 4294967295 must reach the lookup, not be rejected: %#v", resp.Error)
	}
}

// --- estimatesmartfee ------------------------------------------------------

func TestEstimateSmartFeeRejectsOutOfInt32ConfTarget(t *testing.T) {
	for _, v := range outOfInt32 {
		iabExpectRange(t, iabCall(t, "estimatesmartfee", v))
	}
}

func TestEstimateSmartFeeRejectsConfTargetOutOfDomain(t *testing.T) {
	for _, v := range []interface{}{float64(0), float64(-1), float64(1009), float64(99999)} {
		iabExpectError(t, iabCall(t, "estimatesmartfee", v),
			RPCErrInvalidParameter, "Invalid conf_target, must be between 1 and 1008")
	}
}

func TestEstimateSmartFeeRejectsUnknownEstimateMode(t *testing.T) {
	for _, m := range []string{"", "garbage", "ECONOMICALLY"} {
		iabExpectError(t, iabCall(t, "estimatesmartfee", float64(6), m),
			RPCErrInvalidParameter,
			`Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"`)
	}
}

// CONTROLS: the boundary targets and every accepted mode still answer.
func TestEstimateSmartFeeBoundaryTargetsAndModesAccepted(t *testing.T) {
	for _, v := range []interface{}{float64(1), float64(6), float64(1008)} {
		if resp := iabCall(t, "estimatesmartfee", v); resp.Error != nil {
			t.Errorf("conf_target %v must be accepted: %#v", v, resp.Error)
		}
	}
	for _, m := range []string{"unset", "economical", "CONSERVATIVE", "Economical"} {
		if resp := iabCall(t, "estimatesmartfee", float64(6), m); resp.Error != nil {
			t.Errorf("estimate_mode %q must be accepted: %#v", m, resp.Error)
		}
	}
}
