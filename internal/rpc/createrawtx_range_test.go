// createrawtransaction: numeric arguments are RANGE-CHECKED, not truncated.
//
// Found 2026-08-28 by the fleet sweep that began with clearbit's
// unchecked-cast node-kill on this same RPC. blockbrew neither crashed nor
// errored on the out-of-range values -- it TRUNCATED them:
//
//	vout 2^32 and vout 2^33  -> uint32(vout) made both vout 0, so a request
//	                            to spend one outpoint silently became a
//	                            request to spend a DIFFERENT, probably real
//	                            one, returned as success with no log line
//	locktime -1              -> uint32(float64(-1)) came back as nLockTime
//	                            0xFFFFFFFF, the MAXIMUM locktime, having
//	                            been decoded as float64 with the unmarshal
//	                            error swallowed by `err == nil` gating
//
// and reported the values it DID reject with the wrong code: every error in
// the handler used RPCErrInvalidParams (-32602) where Core uses
// RPC_INVALID_PARAMETER (-8). blockbrew had no RPC_MISC_ERROR (-1) constant
// at all, which is what Core returns for an out-of-int32 vout.
//
// Core's ordering is univalue's, not the obvious one: getInt<int>() parses
// into a 32-bit int and fails BEFORE the sign test, so an out-of-int32 vout
// is "JSON integer out of range" at -1 even though it is also out of domain
// for a vout. Locktime is likewise checked BEFORE the inputs are parsed.
//
// References:
//
//	bitcoin-core/src/rpc/rawtransaction_util.cpp AddInputs:38-65
//	bitcoin-core/src/rpc/rawtransaction_util.cpp ConstructTransaction:151-155
//	bitcoin-core/src/rpc/protocol.h              RPC_MISC_ERROR = -1,
//	                                             RPC_INVALID_PARAMETER = -8

package rpc

import (
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

const crtTxid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func crtServer() *Server {
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)
}

// crtCall issues createrawtransaction with one input and no outputs, so the
// only thing in the resulting transaction is the input -- which makes a
// truncated vout directly observable in the hex.
func crtCall(t *testing.T, input map[string]interface{}, extra ...interface{}) *RPCResponse {
	t.Helper()
	args := []interface{}{
		[]interface{}{input},
		map[string]interface{}{},
	}
	args = append(args, extra...)
	return testRPCRequest(t, crtServer().handleRPC, "createrawtransaction", args, "", "")
}

func crtExpectError(t *testing.T, resp *RPCResponse, wantCode int, wantMsg string) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("expected an error, got a transaction: %v", resp.Result)
	}
	if resp.Result != nil {
		t.Errorf("an error response must not also carry a result: %v", resp.Result)
	}
	if resp.Error.Code != wantCode {
		t.Errorf("code = %d, want %d (message was %q)", resp.Error.Code, wantCode, resp.Error.Message)
	}
	if resp.Error.Message != wantMsg {
		t.Errorf("message = %q, want %q", resp.Error.Message, wantMsg)
	}
}

// voutOf decodes the first input's outpoint index straight out of the raw
// hex: version(4) + input count(1) + txid(32) = offset 37, 4 bytes LE.
func voutOf(t *testing.T, resp *RPCResponse) uint32 {
	t.Helper()
	s, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected a transaction, got error %#v", resp.Error)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return uint32(raw[37]) | uint32(raw[38])<<8 | uint32(raw[39])<<16 | uint32(raw[40])<<24
}

// locktimeOf reads the trailing 4 bytes.
func locktimeOf(t *testing.T, resp *RPCResponse) uint32 {
	t.Helper()
	s, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected a transaction, got error %#v", resp.Error)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	n := len(raw)
	return uint32(raw[n-4]) | uint32(raw[n-3])<<8 | uint32(raw[n-2])<<16 | uint32(raw[n-1])<<24
}

// THE REGRESSION. At the parent commit these both returned Ok with vout 0.
func TestCreateRawTx_VoutBeyondUint32IsRejectedNotWrappedToZero(t *testing.T) {
	for _, v := range []float64{4294967296, 8589934592} {
		resp := crtCall(t, map[string]interface{}{"txid": crtTxid, "vout": v})
		crtExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
	}
}

func TestCreateRawTx_VoutBeyondInt32MatchesCoreRangeError(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{"txid": crtTxid, "vout": float64(2147483648)})
	crtExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
}

// THE OTHER REGRESSION. At the parent commit this returned nLockTime
// 0xFFFFFFFF -- the maximum -- for a request of -1.
func TestCreateRawTx_NegativeLocktimeIsRejectedNotWrappedToMax(t *testing.T) {
	resp := crtCall(t,
		map[string]interface{}{"txid": crtTxid, "vout": float64(0)},
		float64(-1))
	crtExpectError(t, resp, RPCErrInvalidParameter, "Invalid parameter, locktime out of range")
}

func TestCreateRawTx_LocktimeBeyondMaxIsRejected(t *testing.T) {
	resp := crtCall(t,
		map[string]interface{}{"txid": crtTxid, "vout": float64(0)},
		float64(4294967296))
	crtExpectError(t, resp, RPCErrInvalidParameter, "Invalid parameter, locktime out of range")
}

// Error-code parity: Core answers -8, not the generic -32602.
func TestCreateRawTx_NegativeVoutUsesCoreErrorCode(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{"txid": crtTxid, "vout": float64(-1)})
	crtExpectError(t, resp, RPCErrInvalidParameter, "Invalid parameter, vout cannot be negative")
}

func TestCreateRawTx_MissingVoutUsesCoreErrorCode(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{"txid": crtTxid})
	crtExpectError(t, resp, RPCErrInvalidParameter, "Invalid parameter, missing vout key")
}

func TestCreateRawTx_SequenceOutOfRangeUsesCoreErrorCode(t *testing.T) {
	for _, seq := range []float64{4294967296, -1} {
		resp := crtCall(t, map[string]interface{}{
			"txid": crtTxid, "vout": float64(0), "sequence": seq,
		})
		crtExpectError(t, resp, RPCErrInvalidParameter,
			"Invalid parameter, sequence number is out of range")
	}
}

// blockbrew had no RPC_MISC_ERROR constant before this change; Core defines
// it in protocol.h and returns it for the univalue range failure.
func TestCreateRawTx_MiscErrorConstantMatchesCore(t *testing.T) {
	if RPCErrMiscError != -1 {
		t.Fatalf("RPCErrMiscError = %d, want -1 (bitcoin-core/src/rpc/protocol.h RPC_MISC_ERROR)",
			RPCErrMiscError)
	}
}

// CONTROLS. Without these, every assertion above is satisfiable by a handler
// that rejects everything.
func TestCreateRawTx_BoundaryValuesStillAccepted(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{
		"txid": crtTxid, "vout": float64(2147483647), "sequence": float64(4294967295),
	}, float64(4294967295))
	if got := voutOf(t, resp); got != 2147483647 {
		t.Errorf("vout = %d, want 2147483647 (int32 max is legal)", got)
	}
	if got := locktimeOf(t, resp); got != 0xFFFFFFFF {
		t.Errorf("locktime = 0x%08x, want 0xffffffff (LOCKTIME_MAX is legal)", got)
	}
}

func TestCreateRawTx_ValidInputStillBuildsTheTransaction(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{"txid": crtTxid, "vout": float64(7)})
	if got := voutOf(t, resp); got != 7 {
		t.Errorf("vout = %d, want 7", got)
	}
	if got := locktimeOf(t, resp); got != 0 {
		t.Errorf("locktime = %d, want 0 (absent locktime defaults to 0)", got)
	}
}
