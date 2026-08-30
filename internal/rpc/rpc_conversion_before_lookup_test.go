// The integer CONVERSION runs before the lookup, and disconnectnode accepts a
// NULL address with a nodeid.  REGRESSION PINS.
//
// #81 fixed the arguments blockbrew ACCEPTED out of range.  This is the other
// half: arguments blockbrew REJECTED, but with the wrong error, because the
// width check ran after -- or instead of -- the conversion.  Measured against
// a regtest Core oracle (tools/rpc-arg-differential.py): 20 findings, all four
// hostile widths on each of
//
//	getblockhash <h>              -8 "Block height out of range"   (Core -1)
//	getblock <hash> <verbosity>   -5 "Block not found"             (Core -1)
//	getrawtransaction <t> <verb>  -5 "No such mempool transaction" (Core -1)
//	getchaintxstats <nblocks>     -8 "Invalid block count..."      (Core -1)
//	disconnectnode [null, <id>]   -32602 "Invalid parameter type"  (Core -29)
//
// Core's UniValue::getInt<T> runs std::from_chars INTO THE DESTINATION WIDTH,
// so the width check fires inside the conversion and only surviving values
// reach the lookup or the domain test.
//
// getblockhash was not merely a wrong code.  It did `height := int32(heightF)`,
// and a float64 outside int32's range converts with IMPLEMENTATION-DEFINED
// behaviour in Go -- so the -8 "Block height out of range" was being decided
// against whatever truncation produced, not against the number the caller sent.
//
// disconnectnode already handled the empty-STRING spelling of Core's by-id
// form, but not a NULL address -- which is what a client sends when it omits
// the first positional argument.  That fell to the type-switch default.
//
// TEETH: a handler that rejected everything would satisfy every rejection
// assertion here, so each block carries a CONTROL that must reach the REAL
// answer (-8 for an in-range illegal height, -29 for an unconnected nodeid).

package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/storage"
)

const cblTxid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const cblAbsentHash = "00000000000000000000000000000000000000000000000000000000000000ff"

// A fully wired server. This matters: with no chain DB, handleGetChainTxStats
// short-circuits on its -28 "Node is warming up" guard BEFORE parsing nblocks,
// and with no peer manager handleDisconnectNode short-circuits on -32603 --
// so the first version of this pin asserted things the handlers never reached,
// and its "control" passed vacuously. A pin must reach the code it pins.
func cblServer(t *testing.T) *Server {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nil)
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
		WithChainManager(cm),
		WithChainDB(db),
		WithMempool(mp),
		WithPeerManager(p2p.NewPeerManager(p2p.PeerManagerConfig{ChainParams: params})),
	)
}

func cblCall(t *testing.T, method string, params ...interface{}) *RPCResponse {
	t.Helper()
	return testRPCRequest(t, cblServer(t).handleRPC, method, params, "", "")
}

func cblExpectError(t *testing.T, resp *RPCResponse, wantCode int, wantMsg string) {
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

func cblExpectRange(t *testing.T, resp *RPCResponse) {
	t.Helper()
	cblExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
}

// --- the conversion beats the lookup ---------------------------------------

func TestGetBlockHashConversionBeatsHeightDomainTest(t *testing.T) {
	for _, v := range outOfInt32 {
		cblExpectRange(t, cblCall(t, "getblockhash", v))
	}
}

func TestGetBlockVerbosityConversionBeatsBlockLookup(t *testing.T) {
	for _, v := range outOfInt32 {
		cblExpectRange(t, cblCall(t, "getblock", cblAbsentHash, v))
	}
}

func TestGetRawTransactionVerbosityConversionBeatsTxLookup(t *testing.T) {
	for _, v := range outOfInt32 {
		cblExpectRange(t, cblCall(t, "getrawtransaction", cblTxid, v))
	}
}

func TestGetChainTxStatsNblocksConversionBeatsDomainTest(t *testing.T) {
	for _, v := range outOfInt32 {
		cblExpectRange(t, cblCall(t, "getchaintxstats", v))
	}
}

// A FRACTIONAL value is a conversion failure too: Core's from_chars refuses
// it, it does not truncate. encoding/json hands every number back as float64,
// so without this check 1.5 would have silently become 1.
func TestFractionalArgumentsAreConversionFailures(t *testing.T) {
	cblExpectRange(t, cblCall(t, "getblockhash", 1.5))
	cblExpectRange(t, cblCall(t, "getchaintxstats", 2.5))
}

// --- disconnectnode by nodeid ----------------------------------------------

func TestDisconnectNodeNullAddressWithNodeIDIsCoresMinus29(t *testing.T) {
	for _, v := range []interface{}{float64(0), float64(99), float64(4294967296)} {
		resp := cblCall(t, "disconnectnode", nil, v)
		cblExpectError(t, resp, RPCErrClientNodeNotConnected, "")
	}
}

func TestDisconnectNodeEmptyStringWithNodeIDStillWorks(t *testing.T) {
	// CONTROL: the spelling that already worked must keep working.
	resp := cblCall(t, "disconnectnode", "", float64(7))
	cblExpectError(t, resp, RPCErrClientNodeNotConnected, "")
}

// --- CONTROLS ---------------------------------------------------------------

func TestControlInRangeHeightStillReachesTheDomainError(t *testing.T) {
	cblExpectError(t, cblCall(t, "getblockhash", float64(-1)),
		RPCErrInvalidParameter, "Block height out of range")
}

func TestControlInRangeNblocksStillReachesTheDomainError(t *testing.T) {
	resp := cblCall(t, "getchaintxstats", float64(-1))
	if resp.Error == nil {
		t.Fatalf("expected an error, got %v", resp.Result)
	}
	if resp.Error.Code == RPCErrMiscError {
		t.Errorf("in-range nblocks must NOT be the conversion error; got %q",
			resp.Error.Message)
	}
}

func TestControlInRangeVerbosityStillReachesTheBlockLookup(t *testing.T) {
	resp := cblCall(t, "getblock", cblAbsentHash, float64(1))
	if resp.Error == nil {
		t.Fatalf("expected an error, got %v", resp.Result)
	}
	if resp.Error.Code == RPCErrMiscError && resp.Error.Message == "JSON integer out of range" {
		t.Errorf("in-range verbosity must reach the lookup, not the conversion error")
	}
}

func TestControlInt32BoundaryValuesConvertCleanly(t *testing.T) {
	// A bound off by one in the tight direction would reject these.
	for _, v := range []interface{}{float64(2147483647), float64(-2147483648)} {
		resp := cblCall(t, "getblockhash", v)
		if resp.Error != nil && resp.Error.Code == RPCErrMiscError &&
			resp.Error.Message == "JSON integer out of range" {
			t.Errorf("int32 boundary %v was rejected by the CONVERSION", v)
		}
	}
}
