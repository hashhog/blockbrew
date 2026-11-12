package rpc

import "testing"

// Core v31.1 getwalletinfo (wallet/rpc/wallet.cpp) has no balance,
// unconfirmed_balance or immature_balance; those live in getbalances.
func TestWalletCauseB_GetWalletInfo_NoLegacyBalanceFields(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"causeb"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "getwalletinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getwalletinfo: %+v", resp.Error)
	}
	obj, _ := resp.Result.(map[string]interface{})
	for _, f := range []string{"balance", "unconfirmed_balance", "immature_balance"} {
		if _, ok := obj[f]; ok {
			t.Errorf("getwalletinfo still reports %q: Core v31 has no such field", f)
		}
	}
}

func TestWalletCauseB_GetWalletInfo_KeepsCoreFields(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"causeb"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "getwalletinfo", []interface{}{}, "", "")
	obj, _ := resp.Result.(map[string]interface{})
	for _, f := range []string{"walletname", "walletversion", "txcount", "keypoolsize", "private_keys_enabled", "avoid_reuse", "scanning", "descriptors"} {
		if _, ok := obj[f]; !ok {
			t.Errorf("getwalletinfo lost Core field %q", f)
		}
	}
}
