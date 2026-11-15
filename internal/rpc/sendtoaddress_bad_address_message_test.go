package rpc

import "testing"

// sendtoaddress with an address that does not decode.
//
// Core v31.1: sendtoaddress -> ParseOutputs (src/rpc/rawtransaction_util.cpp)
// throws RPC_INVALID_ADDRESS_OR_KEY (-5) with
// std::string("Invalid Bitcoin address: ") + name_, so the message names the
// rejected string: "Invalid Bitcoin address: notanaddress". blockbrew used
// the bare "Invalid Bitcoin address" (Core's wording for other RPCs).

func TestSendToAddressBadAddress_MessageNamesAddress(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"w"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "sendtoaddress", []interface{}{"notanaddress", 1}, "", "")
	if resp.Error == nil {
		t.Fatal("sendtoaddress notanaddress: expected an error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Errorf("code = %d, want %d (RPC_INVALID_ADDRESS_OR_KEY)", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
	if want := "Invalid Bitcoin address: notanaddress"; resp.Error.Message != want {
		t.Errorf("message = %q, want %q (Core ParseOutputs)", resp.Error.Message, want)
	}
}

// Control: a valid address with an amount the empty wallet cannot pay is not
// an address error.
func TestSendToAddressBadAddress_ValidAddressNotAddressError(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"w"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "sendtoaddress",
		[]interface{}{"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 1}, "", "")
	if resp.Error == nil || resp.Error.Code == RPCErrInvalidAddressOrKey {
		t.Fatalf("valid address: got %+v, want a non-address error", resp.Error)
	}
}
