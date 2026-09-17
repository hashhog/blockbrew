package rpc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
)

func newT3WalletServer(t *testing.T) *Server {
	t.Helper()
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, consensus.RegtestParams())
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWalletManager(mgr),
	)
}

func TestR5_CreateWallet_LegacyRefused(t *testing.T) {
	s := newT3WalletServer(t)
	resp := testRPCRequest(t, s.handleRPC, "createwallet",
		[]interface{}{"r5legacy", nil, nil, nil, nil, false}, "", "")
	if resp.Error == nil {
		t.Fatal("createwallet(descriptors=false): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrWalletError {
		t.Fatalf("code = %d, want %d (Core RPC_WALLET_ERROR)", resp.Error.Code, RPCErrWalletError)
	}
}

func TestR5_CreateWallet_AlreadyExistsAndNoName(t *testing.T) {
	s := newT3WalletServer(t)
	resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet r5: %+v", resp.Error)
	}
	resp = testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", "")
	if resp.Error == nil {
		t.Fatal("createwallet already-exists: expected error")
	}
	if resp.Error.Code != RPCErrWalletError {
		t.Fatalf("already-exists code = %d, want %d", resp.Error.Code, RPCErrWalletError)
	}
	resp = testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{}, "", "")
	if resp.Error == nil {
		t.Fatal("createwallet no-name: expected error")
	}
	if resp.Error.Code != RPCErrMisc {
		t.Fatalf("no-name code = %d, want %d (Core arity -1)", resp.Error.Code, RPCErrMisc)
	}
}

func TestR5_ListTransactions_NegativeCountSkip(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "listtransactions", []interface{}{"*", -1}, "", "")
	if resp.Error == nil {
		t.Fatal("listtransactions negative-count: expected JSON-RPC error, got success (or panic)")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("negative-count code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
	resp = testRPCRequest(t, s.handleRPC, "listtransactions", []interface{}{"*", 10, -1}, "", "")
	if resp.Error == nil {
		t.Fatal("listtransactions negative-skip: expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("negative-skip code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_ListUnspent_FilterRejects(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "listunspent",
		[]interface{}{1, 9999999, []string{"notanaddress"}}, "", "")
	if resp.Error == nil {
		t.Fatal("listunspent invalid-address: expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("invalid-address code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
	dup := "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
	resp = testRPCRequest(t, s.handleRPC, "listunspent",
		[]interface{}{1, 9999999, []string{dup, dup}}, "", "")
	if resp.Error == nil {
		t.Fatal("listunspent duplicate-address: expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("duplicate-address code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_WrongArity_WalletZeroArg(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	for _, m := range []string{"getwalletinfo", "getbalances", "listwallets"} {
		resp := testRPCRequest(t, s.handleRPC, m, []interface{}{"unexpected"}, "", "")
		if resp.Error == nil {
			t.Fatalf("%s extra arg: expected error, call succeeded", m)
		}
		if resp.Error.Code != RPCErrMisc {
			t.Fatalf("%s extra arg code = %d, want %d", m, resp.Error.Code, RPCErrMisc)
		}
	}
}

func TestR5_GetWalletInfo_HasFlags(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "getwalletinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getwalletinfo: %+v", resp.Error)
	}
	obj, _ := resp.Result.(map[string]interface{})
	if _, ok := obj["flags"]; !ok {
		t.Fatal("getwalletinfo missing field flags")
	}
	if _, ok := obj["lastprocessedblock"]; !ok {
		t.Fatal("getwalletinfo missing field lastprocessedblock")
	}
}

func TestR5_Send_Rejects(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "send", []interface{}{[]interface{}{}}, "", "")
	if resp.Error == nil {
		t.Fatal("send no-outputs: expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("send no-outputs code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
	resp = testRPCRequest(t, s.handleRPC, "send",
		[]interface{}{[]interface{}{map[string]interface{}{"notanaddress": 0.001}}}, "", "")
	if resp.Error == nil {
		t.Fatal("send invalid-address: expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("send invalid-address code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_SendToAddress_ErrorCodes(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "sendtoaddress",
		[]interface{}{"notanaddress", 0.001}, "", "")
	if resp.Error == nil {
		t.Fatal("sendtoaddress invalid-address: expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("invalid-address code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
	resp = testRPCRequest(t, s.handleRPC, "sendtoaddress",
		[]interface{}{"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", -1}, "", "")
	if resp.Error == nil {
		t.Fatal("sendtoaddress invalid-amount: expected error")
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Fatalf("invalid-amount code = %d, want %d", resp.Error.Code, RPCErrTypeError)
	}
	resp = testRPCRequest(t, s.handleRPC, "sendtoaddress",
		[]interface{}{"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 1000000}, "", "")
	if resp.Error == nil {
		t.Fatal("sendtoaddress insufficient-funds: expected error")
	}
	if resp.Error.Code != RPCErrWalletInsufficientFunds {
		t.Fatalf("insufficient-funds code = %d, want %d", resp.Error.Code, RPCErrWalletInsufficientFunds)
	}
}

func TestR5_RestoreWallet_BackupMissingAndAlreadyExists(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "restorewallet",
		[]interface{}{"r5probe_fresh", "/nonexistent/r5probe-nope.bak"}, "", "")
	if resp.Error == nil {
		t.Fatal("restorewallet backup-missing: expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("backup-missing code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}

	dir := t.TempDir()
	bak := filepath.Join(dir, "wallet.bak")
	resp = testRPCRequest(t, s.handleRPC, "backupwallet", []interface{}{bak}, "", "")
	if resp.Error != nil {
		t.Fatalf("backupwallet: %+v", resp.Error)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	resp = testRPCRequest(t, s.handleRPC, "restorewallet", []interface{}{"r5", bak}, "", "")
	if resp.Error == nil {
		t.Fatal("restorewallet already-exists: expected error")
	}
	if resp.Error.Code != RPCErrWalletAlreadyExists {
		t.Fatalf("already-exists code = %d, want %d", resp.Error.Code, RPCErrWalletAlreadyExists)
	}
	resp = testRPCRequest(t, s.handleRPC, "restorewallet", []interface{}{"r5restored", bak}, "", "")
	if resp.Error != nil {
		t.Fatalf("restorewallet success: %+v", resp.Error)
	}
	obj, _ := resp.Result.(map[string]interface{})
	if obj["name"] != "r5restored" {
		t.Fatalf("restorewallet name = %v, want r5restored", obj["name"])
	}
}

func TestR5_Stop_WrongType(t *testing.T) {
	s := newT3WalletServer(t)
	resp := testRPCRequest(t, s.handleRPC, "stop", []interface{}{"notanumber"}, "", "")
	if resp.Error == nil {
		t.Fatal("stop wrong-type: expected error")
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Fatalf("stop wrong-type code = %d, want %d", resp.Error.Code, RPCErrTypeError)
	}
}

func TestR5_WalletCreateFundedPSBT_NoOutputs(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "walletcreatefundedpsbt",
		[]interface{}{[]interface{}{}, []interface{}{}}, "", "")
	if resp.Error == nil {
		t.Fatal("walletcreatefundedpsbt no-outputs: expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("no-outputs code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_WalletProcessPSBT_DecodeError(t *testing.T) {
	s := newT3WalletServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"r5"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, s.handleRPC, "walletprocesspsbt", []interface{}{"not-a-psbt"}, "", "")
	if resp.Error == nil {
		t.Fatal("walletprocesspsbt decode-error: expected error")
	}
	if resp.Error.Code != RPCErrDeserialization {
		t.Fatalf("decode-error code = %d, want %d", resp.Error.Code, RPCErrDeserialization)
	}
}
