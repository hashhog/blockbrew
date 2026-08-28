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
	"encoding/json"
	"strings"
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

// ============================================================================
// createrawtransaction: an EXPLICIT replaceable=true that the sequence numbers
// CONTRADICT is an error, not a silent preference for the sequence.
// ============================================================================
//
// Core's ConstructTransaction ends with a check blockbrew did not have
// (bitcoin-core/src/rpc/rawtransaction_util.cpp:166-168):
//
//	if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
//	    !SignalsOptInRBF(CTransaction(rawTx)))
//	    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter
//	        combination: Sequence number(s) contradict replaceable option");
//
// The caller has asked for two mutually exclusive things: "make this
// replaceable" and "use a sequence number that makes it unreplaceable".
// Nine of the ten nodes in this repo — blockbrew until this change — resolve
// that silently in favour of the sequence and return a perfectly valid-looking
// transaction that can NEVER be fee-bumped, with no error and no log line.
// The caller finds out at bumpfee time, on a stuck transaction, when the fee
// market has already moved. Core refuses to guess.
//
// SignalsOptInRBF (bitcoin-core/src/util/rbf.cpp) is a per-TRANSACTION
// predicate: ANY input with nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd,
// util/rbf.h) makes the whole transaction signaling. It is `<=` 0xfffffffd and
// NOT `< SEQUENCE_FINAL`, so 0xfffffffe — the anti-fee-snipe value many wallets
// use with no RBF intent — does NOT signal and DOES contradict.
//
// THE ASYMMETRY, which is the easiest part to get wrong: an ABSENT replaceable
// argument still DEFAULTS to true for choosing the sequence, yet does NOT arm
// this check. Core carries `std::optional<bool> rbf` that stays nullopt while
// params[3].isNull() (rawtransaction.cpp:398-401); AddInputs reads it as
// rbf.value_or(true) while the contradiction check reads it as
// rbf.has_value() && rbf.value(). Only a caller who literally typed
// replaceable=true has stated an intent a final sequence can contradict.
// blockbrew collapsed both readings into one bool, so preserving that
// distinction is the production change these tests pin.
//
// The rows below are the LIVE-CORE ORACLE, every one reproduced against a
// running Bitcoin Core node. The four ACCEPT rows are controls and matter as
// much as the rejects: an over-eager check that fires on rows 1, 5, 6 or 7
// would break ordinary RBF usage, and rows 1 and 6 are precisely the ones a
// naive "replaceable && !signaling" implementation gets wrong.
//
// References:
//
//	bitcoin-core/src/rpc/rawtransaction_util.cpp ConstructTransaction:147-171
//	bitcoin-core/src/rpc/rawtransaction.cpp      createrawtransaction:398-402
//	bitcoin-core/src/util/rbf.cpp                SignalsOptInRBF
//	bitcoin-core/src/util/rbf.h                  MAX_BIP125_RBF_SEQUENCE 0xfffffffd
//	internal/mempool/mempool.go                  signalsRBF / SignalsRBFForRPC
//	internal/rpc/fix70_sequence_default_test.go  the DEFAULT-sequence guards
//	                                             (that file pins which sequence
//	                                             is chosen; this one pins when a
//	                                             supplied sequence is refused)

// crtRBFRejectMsg is Core's message, verbatim. Any drift in wording is a
// divergence a client string-matching on it would see.
const crtRBFRejectMsg = "Invalid parameter combination: Sequence number(s) contradict replaceable option"

// crtRBFCall drives the REAL handler (via handleRPC, the same path the rest of
// this file uses) with an arbitrary input list and a replaceable argument that
// is either ABSENT (rbf == nil — the argument is not sent at all) or explicitly
// present. Locktime is only sent when replaceable is, since it is positionally
// required to reach argument 4; it is always 0, so it never influences the
// default sequence (sequenceForLocktime only consults locktime when
// !replaceable).
func crtRBFCall(t *testing.T, inputs []interface{}, rbf *bool) *RPCResponse {
	t.Helper()
	args := []interface{}{inputs, map[string]interface{}{}}
	if rbf != nil {
		args = append(args, float64(0), *rbf)
	}
	return testRPCRequest(t, crtServer().handleRPC, "createrawtransaction", args, "", "")
}

// crtSeqsOf decodes EVERY input's nSequence straight out of the returned hex,
// in the same manual-offset style as voutOf above, so the assertions are on
// what was actually SERIALIZED rather than on the handler's intent.
// createrawtransaction never emits a witness or a non-empty scriptSig, so the
// layout is fixed: version(4) | varint vin count | vin[i]{ txid(32) | vout(4) |
// 0x00 | sequence(4) }. Decoding by hand rather than through decodeTxHex also
// lets the ZERO-INPUT row be inspected: a 0-input transaction collides with the
// segwit marker and does not round-trip through the deserializer.
func crtSeqsOf(t *testing.T, resp *RPCResponse) []uint32 {
	t.Helper()
	s, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected a transaction, got error %#v", resp.Error)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	if len(raw) < 5 {
		t.Fatalf("transaction too short to hold an input count: %s", s)
	}
	n := int(raw[4])
	if n >= 0xfd {
		t.Fatalf("input count varint %#x is multi-byte; this helper assumes < 0xfd", raw[4])
	}
	seqs := make([]uint32, 0, n)
	for i, off := 0, 5; i < n; i, off = i+1, off+41 {
		if off+41 > len(raw) {
			t.Fatalf("input %d runs past the end of %s", i, s)
		}
		if raw[off+36] != 0x00 {
			t.Fatalf("input %d has a non-empty scriptSig; helper assumes createrawtransaction leaves it empty", i)
		}
		b := off + 37
		seqs = append(seqs, uint32(raw[b])|uint32(raw[b+1])<<8|uint32(raw[b+2])<<16|uint32(raw[b+3])<<24)
	}
	return seqs
}

// crtIn builds one input object. A negative sequence means "omit the sequence
// key entirely", which is how the handler learns to apply its own default.
func crtIn(vout int, sequence int64) map[string]interface{} {
	in := map[string]interface{}{"txid": crtTxid, "vout": float64(vout)}
	if sequence >= 0 {
		in["sequence"] = float64(sequence)
	}
	return in
}

func TestCreateRawTx_ReplaceableContradictsSequence(t *testing.T) {
	yes, no := true, false

	tests := []struct {
		name string
		// oracle is the row number in the live-Core table this reproduces.
		oracle   int
		inputs   []interface{}
		rbf      *bool // nil => argument ABSENT
		wantMsg  string
		wantSeqs []uint32 // asserted only when wantMsg is empty
		why      string
	}{
		{
			name:     "1_absent_rbf_with_final_sequence_is_accepted",
			oracle:   1,
			inputs:   []interface{}{crtIn(0, 0xFFFFFFFF)},
			rbf:      nil,
			wantSeqs: []uint32{0xFFFFFFFF},
			why: "rbf.has_value() is FALSE, so the check never arms — even though an " +
				"absent argument still defaults to replaceable for the sequence choice. " +
				"An implementation that folds absent into true rejects this.",
		},
		{
			name:     "2_explicit_true_with_signaling_sequence_is_accepted",
			oracle:   2,
			inputs:   []interface{}{crtIn(0, 0xFFFFFFFD)},
			rbf:      &yes,
			wantSeqs: []uint32{0xFFFFFFFD},
			why:      "0xfffffffd == MAX_BIP125_RBF_SEQUENCE, and the predicate is <=, so it signals.",
		},
		{
			name:    "3_explicit_true_with_anti_fee_snipe_sequence_is_rejected",
			oracle:  3,
			inputs:  []interface{}{crtIn(0, 0xFFFFFFFE)},
			rbf:     &yes,
			wantMsg: crtRBFRejectMsg,
			why: "0xfffffffe is non-final but does NOT signal RBF. A check written as " +
				"`sequence < SEQUENCE_FINAL` instead of `<= MAX_BIP125_RBF_SEQUENCE` " +
				"wrongly accepts this row.",
		},
		{
			name:    "4_explicit_true_with_final_sequence_is_rejected",
			oracle:  4,
			inputs:  []interface{}{crtIn(0, 0xFFFFFFFF)},
			rbf:     &yes,
			wantMsg: crtRBFRejectMsg,
			why:     "The plainest contradiction: SEQUENCE_FINAL under an explicit replaceable=true.",
		},
		{
			name:     "5_explicit_true_with_no_inputs_is_accepted",
			oracle:   5,
			inputs:   []interface{}{},
			rbf:      &yes,
			wantSeqs: []uint32{},
			why: "vin.size() > 0 fails. A transaction with no inputs signals nothing, and " +
				"Core lets it through rather than calling that a contradiction.",
		},
		{
			name:     "6_explicit_true_with_one_signaling_input_of_two_is_accepted",
			oracle:   6,
			inputs:   []interface{}{crtIn(0, 0xFFFFFFFF), crtIn(1, 0)},
			rbf:      &yes,
			wantSeqs: []uint32{0xFFFFFFFF, 0},
			why: "SignalsOptInRBF is per-TRANSACTION: one signaling input makes the whole " +
				"transaction signaling. A per-input loop that rejects on the FIRST " +
				"non-signaling input wrongly rejects this row.",
		},
		{
			name:     "7_explicit_false_with_final_sequence_is_accepted",
			oracle:   7,
			inputs:   []interface{}{crtIn(0, 0xFFFFFFFF)},
			rbf:      &no,
			wantSeqs: []uint32{0xFFFFFFFF},
			why:      "rbf.value() is FALSE. Asking for non-replaceable and getting it is no contradiction.",
		},
		{
			name:     "8_explicit_true_with_defaulted_sequence_is_accepted",
			oracle:   8,
			inputs:   []interface{}{crtIn(0, -1)},
			rbf:      &yes,
			wantSeqs: []uint32{0xFFFFFFFD},
			why: "With no explicit sequence the handler's own default IS the RBF sequence " +
				"(AddInputs, rawtransaction_util.cpp:47-50), so the ordinary replaceable=true " +
				"call must keep working. This is the row a naively-placed check breaks.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := crtRBFCall(t, tc.inputs, tc.rbf)

			if tc.wantMsg != "" {
				crtExpectError(t, resp, RPCErrInvalidParameter, tc.wantMsg)
				return
			}

			if resp.Error != nil {
				t.Fatalf("oracle row %d expected ACCEPT, got error %d %q.\nwhy: %s",
					tc.oracle, resp.Error.Code, resp.Error.Message, tc.why)
			}
			got := crtSeqsOf(t, resp)
			if len(got) != len(tc.wantSeqs) {
				t.Fatalf("oracle row %d: got %d inputs %#x, want %d %#x",
					tc.oracle, len(got), got, len(tc.wantSeqs), tc.wantSeqs)
			}
			for i := range got {
				if got[i] != tc.wantSeqs[i] {
					t.Errorf("oracle row %d: input %d serialized sequence = 0x%08x, want 0x%08x.\nwhy: %s",
						tc.oracle, i, got[i], tc.wantSeqs[i], tc.why)
				}
			}
		})
	}
}

// TestCreateRawTx_ExplicitJSONNullReplaceableBehavesAsAbsent is NOT one of the
// eight live-Core oracle rows; it pins the source-level behaviour of
// createrawtransaction's `if (!request.params[3].isNull())` guard
// (rawtransaction.cpp:399), which leaves `rbf` empty for a JSON null exactly as
// for a missing argument. Both consequences are asserted:
//
//   - the contradiction check stays disarmed (a final sequence is accepted), and
//   - the DEFAULT sequence is still the RBF one, because AddInputs reads
//     rbf.value_or(true).
//
// This is a real behaviour change, not just a new error path: encoding/json
// leaves a bool target UNCHANGED when it unmarshals null, so before this fix an
// explicit null read as replaceable=FALSE and produced SEQUENCE_FINAL —
// silently the opposite of Core.
func TestCreateRawTx_ExplicitJSONNullReplaceableBehavesAsAbsent(t *testing.T) {
	args := []interface{}{
		[]interface{}{crtIn(0, 0xFFFFFFFF)},
		map[string]interface{}{},
		float64(0),
		nil, // JSON null
	}
	resp := testRPCRequest(t, crtServer().handleRPC, "createrawtransaction", args, "", "")
	if resp.Error != nil {
		t.Fatalf("null replaceable must behave as absent (no contradiction check), got %d %q",
			resp.Error.Code, resp.Error.Message)
	}
	if got := crtSeqsOf(t, resp); len(got) != 1 || got[0] != 0xFFFFFFFF {
		t.Errorf("explicit sequence must survive: got %#x, want [0xffffffff]", got)
	}

	// Same call, no explicit sequence: value_or(true) still picks the RBF default.
	args[0] = []interface{}{crtIn(0, -1)}
	resp = testRPCRequest(t, crtServer().handleRPC, "createrawtransaction", args, "", "")
	if resp.Error != nil {
		t.Fatalf("null replaceable + defaulted sequence: %d %q", resp.Error.Code, resp.Error.Message)
	}
	if got := crtSeqsOf(t, resp); len(got) != 1 || got[0] != 0xFFFFFFFD {
		t.Errorf("null replaceable must default to the RBF sequence (rbf.value_or(true)): got %#x, want [0xfffffffd]", got)
	}
}

// ============================================================================
// createrawtransaction: a PRESENT but NON-NUMERIC `sequence` must be IGNORED
// ============================================================================
//
// Core guards the ENTIRE read with a type test and takes no else branch
// (bitcoin-core/src/rpc/rawtransaction_util.cpp:57-65):
//
//	const UniValue& sequenceObj = o.find_value("sequence");
//	if (sequenceObj.isNum()) {
//	    int64_t seqNr64 = sequenceObj.getInt<int64_t>();
//	    if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
//	        throw JSONRPCError(RPC_INVALID_PARAMETER,
//	            "Invalid parameter, sequence number is out of range");
//	    } else { nSequence = (uint32_t)seqNr64; }
//	}
//
// A string, bool, object, array or null never enters the branch, so the default
// chosen a few lines above survives and Core ACCEPTS the call. blockbrew
// answered -8 "Invalid parameter, sequence number is out of range" — a message
// wrong twice over: nothing was out of range, and the value was not a number to
// have a range in the first place.
//
// THE ASSERTIONS ARE ON THE EMITTED SEQUENCE, NOT ON MERE ACCEPTANCE. This is a
// two-sided trap. With `replaceable` absent, rbf.value_or(true) is TRUE, so the
// surviving default is MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD) and the transaction
// is REPLACEABLE. An implementation that fell through to SEQUENCE_FINAL would
// also "accept" — while quietly handing back a NON-replaceable transaction.
// rustoshi originally did exactly that.
//
// The rows below were captured from the LIVE Core node on 2026-08-28:
//
//	sequence "nope" / true / false / null / {} / []   ACCEPT, emits 0xFFFFFFFD
//	the same, with replaceable=false                  ACCEPT, emits 0xFFFFFFFF
//	sequence 1.5 / 1e30 / 99999999999999999999        REJECT -1 JSON int out of range
//	sequence 4294967296 / -1  (NUMERIC, in int64)     REJECT -8  (unchanged)
func TestCreateRawTx_NonNumericSequenceIsIgnored(t *testing.T) {
	const maxBIP125RBFSequence = uint32(0xFFFFFFFD)

	for _, tc := range []struct {
		name string
		seq  interface{}
	}{
		{"string", "nope"},
		{"bool_true", true},
		{"bool_false", false},
		// An unset optional serialised as JSON null is the realistic client
		// bug this row protects. encoding/json also leaves an int64 target
		// untouched on null, so a handler without the isNum() guard sees 0 —
		// a valid sequence — instead of "absent".
		{"null", nil},
		{"object", map[string]interface{}{}},
		{"array", []interface{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := crtCall(t, map[string]interface{}{
				"txid": crtTxid, "vout": float64(0), "sequence": tc.seq,
			})
			if resp.Error != nil {
				t.Fatalf("expected the non-numeric sequence to be IGNORED, got error %d %q",
					resp.Error.Code, resp.Error.Message)
			}
			if got := crtSeqsOf(t, resp); len(got) != 1 || got[0] != maxBIP125RBFSequence {
				t.Errorf("sequence in the tx bytes = %#x, want %#x (the RBF default; "+
					"emitting SEQUENCE_FINAL would also 'accept' while building a "+
					"NON-replaceable transaction)", got, maxBIP125RBFSequence)
			}
		})
	}
}

// The ignored field must leave the REAL default computation in charge, not a
// hard-coded 0xFFFFFFFD: with replaceable explicitly false and locktime 0,
// AddInputs picks SEQUENCE_FINAL.
func TestCreateRawTx_IgnoredSequenceStillHonoursReplaceableFalse(t *testing.T) {
	resp := crtCall(t, map[string]interface{}{
		"txid": crtTxid, "vout": float64(0), "sequence": "nope",
	}, float64(0), false)
	if resp.Error != nil {
		t.Fatalf("expected success, got error %d %q", resp.Error.Code, resp.Error.Message)
	}
	if got := crtSeqsOf(t, resp); len(got) != 1 || got[0] != 0xFFFFFFFF {
		t.Errorf("sequence in the tx bytes = %#x, want 0xffffffff", got)
	}
}

// A NUMERIC token that univalue's getInt<int64_t> cannot convert is neither
// ignored nor -8: from_chars stops at the '.' or the 'e', or overflows, and
// Core reports RPC_MISC_ERROR. Verified against the live Core node.
func TestCreateRawTx_NumericSequenceThatIsNotAnIntegerIsMiscError(t *testing.T) {
	for _, tc := range []struct {
		name string
		seq  interface{}
	}{
		{"1.5_fractional", 1.5},
		{"1e30_exponent", 1e30},
		// Integral, but wider than int64 — sent as a raw token so Go's float64
		// cannot round it on the way out.
		{"beyond_int64", json.Number("99999999999999999999")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := crtCall(t, map[string]interface{}{
				"txid": crtTxid, "vout": float64(0), "sequence": tc.seq,
			})
			crtExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
		})
	}
}

// CONTROLS for the isNum() guard. Without these the change above is satisfiable
// by dropping the range check outright, or by ignoring EVERY sequence including
// the valid ones.
func TestCreateRawTx_NumericSequenceBranchIsUntouched(t *testing.T) {
	t.Run("out_of_range_still_rejected", func(t *testing.T) {
		for _, seq := range []float64{4294967296, -1} {
			resp := crtCall(t, map[string]interface{}{
				"txid": crtTxid, "vout": float64(0), "sequence": seq,
			})
			crtExpectError(t, resp, RPCErrInvalidParameter,
				"Invalid parameter, sequence number is out of range")
		}
	})
	t.Run("ordinary_sequence_still_assigned", func(t *testing.T) {
		resp := crtCall(t, map[string]interface{}{
			"txid": crtTxid, "vout": float64(0), "sequence": float64(12345),
		})
		if resp.Error != nil {
			t.Fatalf("expected success, got error %d %q", resp.Error.Code, resp.Error.Message)
		}
		if got := crtSeqsOf(t, resp); len(got) != 1 || got[0] != 12345 {
			t.Errorf("sequence in the tx bytes = %v, want [12345]", got)
		}
	})
}

// ============================================================================
// createrawtransaction: a malformed txid uses ParseHashV's code and wording
// ============================================================================
//
// blockbrew answered -32602 "Invalid txid: abc" from a bare NewHash256FromHex
// call, and it did so only AFTER the outputs had already been parsed. Core uses
// ParseHashV (bitcoin-core/src/rpc/util.cpp:117-125), which has TWO distinct
// messages at RPC_INVALID_PARAMETER (-8):
//
//	wrong length:  "txid must be of length 64 (not 3, for 'abc')"
//	right length, non-hex chars:
//	               "txid must be hexadecimal string (not '<the string>')"
//
// The CODE matters as much as the text: -32602 ("Invalid params") tells a client
// the request envelope was malformed, so a client that switches on the code to
// decide whether the ARGUMENTS need fixing gets the wrong answer.
//
// The ORDER matters too. Core calls ParseHashO as the first statement of
// AddInputs, before the vout check and before AddOutputs runs at all, so a
// request that is wrong in several places must report the TXID. Confirmed on
// the live Core node (2026-08-28): `txid "abc"` alongside a bad address, and
// alongside vout -1, both answer the txid error.
func TestCreateRawTx_MalformedTxidUsesParseHashVWording(t *testing.T) {
	t.Run("wrong_length", func(t *testing.T) {
		resp := crtCall(t, map[string]interface{}{"txid": "abc", "vout": float64(0)})
		crtExpectError(t, resp, RPCErrInvalidParameter,
			"txid must be of length 64 (not 3, for 'abc')")
	})
	t.Run("right_length_non_hex", func(t *testing.T) {
		bad := strings.Repeat("z", 64)
		resp := crtCall(t, map[string]interface{}{"txid": bad, "vout": float64(0)})
		crtExpectError(t, resp, RPCErrInvalidParameter,
			"txid must be hexadecimal string (not '"+bad+"')")
	})
	t.Run("empty_string_reports_length_zero", func(t *testing.T) {
		resp := crtCall(t, map[string]interface{}{"txid": "", "vout": float64(0)})
		crtExpectError(t, resp, RPCErrInvalidParameter,
			"txid must be of length 64 (not 0, for '')")
	})
}

// ParseHashO runs FIRST in AddInputs, so the txid error outranks both a bad
// vout in the same input and a bad output. Pins the placement: parsing the
// txid down in the build loop (where it used to happen, after AddOutputs)
// silently changes which error the caller sees.
func TestCreateRawTx_MalformedTxidOutranksLaterErrors(t *testing.T) {
	const want = "txid must be of length 64 (not 3, for 'abc')"

	t.Run("beats_negative_vout", func(t *testing.T) {
		resp := crtCall(t, map[string]interface{}{"txid": "abc", "vout": float64(-1)})
		crtExpectError(t, resp, RPCErrInvalidParameter, want)
	})
	t.Run("beats_bad_output_address", func(t *testing.T) {
		resp := testRPCRequest(t, crtServer().handleRPC, "createrawtransaction",
			[]interface{}{
				[]interface{}{map[string]interface{}{"txid": "abc", "vout": float64(0)}},
				map[string]interface{}{"notanaddress": 0.1},
			}, "", "")
		crtExpectError(t, resp, RPCErrInvalidParameter, want)
	})
}

// CONTROL: a well-formed txid must still reach the transaction bytes, in
// DISPLAY order reversed to internal order exactly as before. Without this the
// ParseHashV rows above are satisfiable by a handler that rejects every txid.
func TestCreateRawTx_ControlValidTxidStillLandsInTheBytes(t *testing.T) {
	const txidHex = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	resp := crtCall(t, map[string]interface{}{"txid": txidHex, "vout": float64(3)})
	if resp.Error != nil {
		t.Fatalf("expected success, got error %d %q", resp.Error.Code, resp.Error.Message)
	}
	raw, err := hex.DecodeString(resp.Result.(string))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	want, err := hex.DecodeString(txidHex)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	// Wire order is the reverse of display order.
	for i := 0; i < 32; i++ {
		if raw[5+i] != want[31-i] {
			t.Fatalf("txid bytes in the tx do not match the requested txid (byte %d)", i)
		}
	}
	if got := voutOf(t, resp); got != 3 {
		t.Errorf("vout in the tx bytes = %d, want 3", got)
	}
}
