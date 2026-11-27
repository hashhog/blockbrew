package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core's CWallet::Create, when createwallet is given a non-empty passphrase
// for a wallet with private keys (bitcoin-core/src/wallet/wallet.cpp:432-454),
// calls EncryptWallet, then Unlock to set up the keys, then Lock. The wallet
// is encrypted and locked when createwallet returns: getwalletinfo reports
// unlocked_until 0, and every secret-using RPC (getmnemonic here, sendtoaddress
// via EnsureWalletIsUnlocked, wallet/rpc/spend.cpp) fails with
// RPC_WALLET_UNLOCK_NEEDED (-13) until walletpassphrase is called.
//
// Before the fix blockbrew used the passphrase only as the wallet file's
// envelope key: the wallet came back unlocked and unencrypted, so neither
// spending nor exporting the mnemonic ever needed walletpassphrase, and
// walletlock answered -15 "running with an unencrypted wallet".

const cwEncPass = "correct horse battery staple"
const cwEncDest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

func cwEncServer(t *testing.T) (*Server, *wallet.Manager) {
	t.Helper()
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, consensus.RegtestParams())
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", FallbackFee: 0.0002},
		WithChainParams(consensus.RegtestParams()),
		WithWalletManager(mgr),
	)
	return s, mgr
}

// cwEncUnlockedUntil returns getwalletinfo's unlocked_until, and whether the
// field was present at all (Core: present only for encrypted wallets).
func cwEncUnlockedUntil(t *testing.T, s *Server) (float64, bool) {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, "getwalletinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getwalletinfo: %+v", resp.Error)
	}
	info, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("getwalletinfo result is %T, want object", resp.Result)
	}
	v, present := info["unlocked_until"]
	if !present {
		return 0, false
	}
	f, _ := v.(float64)
	return f, true
}

func cwEncWantUnlockNeeded(t *testing.T, s *Server, method string, params []interface{}) {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, method, params, "", "")
	if resp.Error == nil {
		t.Errorf("%s on a locked passphrase wallet succeeded (result %v); want -13 like Core", method, resp.Result)
		return
	}
	if resp.Error.Code != RPCErrWalletUnlockNeeded ||
		resp.Error.Message != "Error: Please enter the wallet passphrase with walletpassphrase first." {
		t.Errorf("%s on a locked passphrase wallet: got %d %q, want -13 \"Error: Please enter the wallet passphrase with walletpassphrase first.\"",
			method, resp.Error.Code, resp.Error.Message)
	}
}

func TestCreateWalletWithPassphraseIsLocked(t *testing.T) {
	s, mgr := cwEncServer(t)

	resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"enc", false, false, cwEncPass}, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet with passphrase: %+v", resp.Error)
	}

	// 1. Straight after createwallet: encrypted and locked.
	if until, present := cwEncUnlockedUntil(t, s); !present {
		t.Errorf("getwalletinfo has no unlocked_until: the wallet is not encrypted (Core reports unlocked_until 0)")
	} else if until != 0 {
		t.Errorf("getwalletinfo unlocked_until = %v right after createwallet, want 0 (locked)", until)
	}
	cwEncWantUnlockNeeded(t, s, "getmnemonic", []interface{}{})

	// Fund the wallet. Getting a receive address needs the master key here,
	// so unlock briefly; then lock again with walletlock.
	resp = testRPCRequest(t, s.handleRPC, "walletpassphrase", []interface{}{cwEncPass, float64(600)}, "", "")
	if resp.Error != nil {
		t.Errorf("walletpassphrase on a passphrase-created wallet: %+v", resp.Error)
	}
	resp = testRPCRequest(t, s.handleRPC, "getnewaddress", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getnewaddress: %+v", resp.Error)
	}
	addr, _ := resp.Result.(string)
	decoded, err := address.DecodeAddress(addr, address.Regtest)
	if err != nil {
		t.Fatalf("DecodeAddress(%q): %v", addr, err)
	}
	w, err := mgr.GetWallet("enc")
	if err != nil {
		t.Fatalf("GetWallet: %v", err)
	}
	w.AddUTXO(&wallet.WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0xce, 0x01}, Index: 0},
		Amount:    1_0000_0000,
		PkScript:  decoded.ScriptPubKey(),
		Address:   addr,
		KeyPath:   "m/84'/1'/0'/0/0", // the first BIP-84 regtest receive address
		Height:    1,
		Confirmed: true,
	})
	resp = testRPCRequest(t, s.handleRPC, "walletlock", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Errorf("walletlock on a passphrase-created wallet: %+v (Core: null)", resp.Error)
	}

	// 2. Locked again: a funded wallet still cannot spend or export.
	if until, present := cwEncUnlockedUntil(t, s); !present || until != 0 {
		t.Errorf("getwalletinfo unlocked_until after walletlock = %v (present=%v), want 0", until, present)
	}
	cwEncWantUnlockNeeded(t, s, "getmnemonic", []interface{}{})
	cwEncWantUnlockNeeded(t, s, "sendtoaddress", []interface{}{cwEncDest, 0.1})

	// 3. After walletpassphrase both work, and unlocked_until is the relock time.
	resp = testRPCRequest(t, s.handleRPC, "walletpassphrase", []interface{}{cwEncPass, float64(600)}, "", "")
	if resp.Error != nil {
		t.Fatalf("walletpassphrase: %+v", resp.Error)
	}
	if until, present := cwEncUnlockedUntil(t, s); !present || until <= 0 {
		t.Errorf("getwalletinfo unlocked_until after walletpassphrase = %v (present=%v), want the relock time", until, present)
	}
	resp = testRPCRequest(t, s.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Errorf("getmnemonic after walletpassphrase: %+v", resp.Error)
	} else if m, _ := resp.Result.(string); !wallet.ValidateMnemonic(m) {
		t.Errorf("getmnemonic after walletpassphrase returned %q, not a valid mnemonic", m)
	}
	resp = testRPCRequest(t, s.handleRPC, "sendtoaddress", []interface{}{cwEncDest, 0.1}, "", "")
	if resp.Error != nil {
		t.Errorf("sendtoaddress after walletpassphrase: %+v", resp.Error)
	}
}

// The wallet must also come back encrypted and locked after an unload and a
// reload with its passphrase (the encrypted state is in the file from the
// first save, not only in memory).
func TestCreateWalletWithPassphraseReloadsLocked(t *testing.T) {
	s, mgr := cwEncServer(t)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"enc", false, false, cwEncPass}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet with passphrase: %+v", resp.Error)
	}
	if resp := testRPCRequest(t, s.handleRPC, "unloadwallet", []interface{}{"enc"}, "", ""); resp.Error != nil {
		t.Fatalf("unloadwallet: %+v", resp.Error)
	}
	// The wallet file is enveloped under the passphrase, so reload through
	// the manager with it (the loadwallet RPC takes no passphrase argument).
	if _, err := mgr.LoadWalletWithPassphrase("enc", cwEncPass, nil); err != nil {
		t.Fatalf("LoadWalletWithPassphrase: %v", err)
	}
	if until, present := cwEncUnlockedUntil(t, s); !present || until != 0 {
		t.Errorf("reloaded passphrase wallet: unlocked_until = %v (present=%v), want 0", until, present)
	}
	cwEncWantUnlockNeeded(t, s, "getmnemonic", []interface{}{})
}

// Controls: no passphrase, or an empty one, leaves the wallet unencrypted
// (Core: "Empty string given as passphrase, wallet will not be encrypted."),
// so getwalletinfo has no unlocked_until and getmnemonic works without an
// unlock. A passphrase-created fresh wallet still returns its mnemonic once
// in the createwallet result, as an unencrypted one does.
func TestCreateWalletWithoutPassphraseStaysUnencrypted(t *testing.T) {
	for label, params := range map[string][]interface{}{
		"no passphrase":    {"plain"},
		"empty passphrase": {"plain", false, false, ""},
	} {
		s, _ := cwEncServer(t)
		if resp := testRPCRequest(t, s.handleRPC, "createwallet", params, "", ""); resp.Error != nil {
			t.Fatalf("%s: createwallet: %+v", label, resp.Error)
		}
		if until, present := cwEncUnlockedUntil(t, s); present {
			t.Errorf("%s: unencrypted wallet reports unlocked_until %v; Core omits the field", label, until)
		}
		if resp := testRPCRequest(t, s.handleRPC, "getmnemonic", []interface{}{}, "", ""); resp.Error != nil {
			t.Errorf("%s: getmnemonic on an unencrypted wallet: %+v", label, resp.Error)
		}
		resp := testRPCRequest(t, s.handleRPC, "walletlock", []interface{}{}, "", "")
		if resp.Error == nil || resp.Error.Code != RPCErrWalletWrongEncState {
			t.Errorf("%s: walletlock on an unencrypted wallet: got %+v, want -15", label, resp.Error)
		}
	}

	s, _ := cwEncServer(t)
	resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"enc", false, false, cwEncPass}, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet with passphrase: %+v", resp.Error)
	}
	result, _ := resp.Result.(map[string]interface{})
	if m, _ := result["mnemonic"].(string); !wallet.ValidateMnemonic(m) {
		t.Errorf("createwallet with passphrase no longer returns the fresh mnemonic once: %v", result)
	}
}
