// createrawtransaction must HONOUR the `version` argument, not ignore it.
//
// THE DEFECT
//
// Core's createrawtransaction takes a 5th argument, `version`
// (rpc/rawtransaction.cpp:122). It reads it as self.Arg<uint32_t>("version"),
// bounds it to [TxMinStandardVersion, TxMaxStandardVersion] = [1, 3]
// (policy/policy.h:152-153) and EMITS it (rawtransaction_util.cpp:158-161).
//
// blockbrew hardcoded `Version: 2` and ignored the argument. Asked for version
// 1, 2 or 3 it returned 02000000 every time, and it accepted version 4, which
// Core rejects. That is a success reply for a request that was not honoured,
// and it is not cosmetic: version 3 is TRUC (BIP 431) and carries different
// policy rules, so a caller who asked for v3 and got v2 has a transaction with
// different relay behaviour than the one they requested.
//
// Measured 2026-08-29 by tools/rpc-arg-differential.py against a real regtest
// Core: seven of the ten implementations behaved identically here.
//
// THE UNSIGNED WIDTH DECIDES WHICH ERROR YOU GET
//
// `version` is read as uint32, unlike the int32 used for vout, so 2147483648
// survives the CONVERSION and reaches the DOMAIN error (-8), while -1 and
// 4294967296 fail the conversion FIRST (-1). Those two cases are asserted
// separately below; collapsing them would look close enough and be wrong in
// both directions.
//
// THE ASSERTIONS READ THE VERSION BYTES off the returned transaction. Checking
// only that the call was accepted is exactly the pre-fix behaviour.
//
// References:
//
//	bitcoin-core/src/rpc/rawtransaction.cpp:122          the argument
//	bitcoin-core/src/rpc/rawtransaction_util.cpp:158-161 bound + assign
//	bitcoin-core/src/policy/policy.h:152-153             [1, 3]

package rpc

import (
	"encoding/hex"
	"testing"
)

// versionOf decodes the transaction version: it is the first 4 bytes, LE.
func versionOf(t *testing.T, resp *RPCResponse) uint32 {
	t.Helper()
	s, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected a transaction, got error %#v", resp.Error)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	if len(raw) < 4 {
		t.Fatalf("transaction too short: %q", s)
	}
	return uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
}

func crtVersionCall(t *testing.T, version interface{}) *RPCResponse {
	t.Helper()
	in := map[string]interface{}{"txid": crtTxid, "vout": 0}
	if version == nil {
		return crtCall(t, in, 0, false)
	}
	return crtCall(t, in, 0, false, version)
}

func TestCreateRawTransactionEmitsRequestedVersion(t *testing.T) {
	for _, want := range []uint32{1, 2, 3} {
		resp := crtVersionCall(t, want)
		if resp.Error != nil {
			t.Fatalf("version %d rejected: %#v", want, resp.Error)
		}
		if got := versionOf(t, resp); got != want {
			t.Errorf("asked for version %d, transaction carries version %d", want, got)
		}
	}
}

func TestCreateRawTransactionVersionDefaultsToTwo(t *testing.T) {
	// Core's DEFAULT_RAWTX_VERSION is CTransaction::CURRENT_VERSION = 2.
	// This is a CONTROL: it passes before the fix as well as after, and it is
	// what stops "reject everything" from satisfying the suite.
	resp := crtVersionCall(t, nil)
	if resp.Error != nil {
		t.Fatalf("absent version must be accepted: %#v", resp.Error)
	}
	if got := versionOf(t, resp); got != 2 {
		t.Errorf("absent version produced %d, want 2", got)
	}
	resp = crtVersionCall(t, nil)
	if got := versionOf(t, resp); got != 2 {
		t.Errorf("null version produced %d, want 2", got)
	}
}

func TestCreateRawTransactionVersionOutsideDomainIsRejected(t *testing.T) {
	// In range for a uint32, out of range for a transaction version: Core
	// answers -8 from ConstructTransaction, AFTER a successful conversion.
	for _, bad := range []int64{0, 4, 2147483648} {
		resp := crtVersionCall(t, bad)
		crtExpectError(t, resp, RPCErrInvalidParameter,
			"Invalid parameter, version out of range(1~3)")
	}
}

func TestCreateRawTransactionVersionOutsideUint32FailsConversionFirst(t *testing.T) {
	// Outside uint32 entirely: univalue's conversion fails before the domain
	// test, so the answer is -1, not -8. Paired with the test above, this is
	// what pins the boundary in BOTH directions.
	for _, bad := range []int64{-1, -2147483649, 4294967296} {
		resp := crtVersionCall(t, bad)
		crtExpectError(t, resp, RPCErrMiscError, "JSON integer out of range")
	}
}
