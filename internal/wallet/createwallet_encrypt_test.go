package wallet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
)

// Manager.CreateWallet with a passphrase must encrypt the master key and lock
// the wallet before the first save, as Core's CWallet::Create does
// (bitcoin-core/src/wallet/wallet.cpp:432-454: EncryptWallet, Unlock to set up
// the keys, Lock). The first wallet file on disk must therefore hold only the
// master-key ciphertext, never the plaintext seed, and the wallet must keep
// the same master key across the encrypt and a later unlock.
func TestManagerCreateWalletWithPassphraseEncryptsBeforeFirstSave(t *testing.T) {
	dir := t.TempDir()
	const pass = "createwallet-encrypt"
	mgr := NewManager(dir, address.Regtest, consensus.RegtestParams())
	w, err := mgr.CreateWallet("e", CreateWalletOpts{Passphrase: pass})
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	if !w.IsEncrypted() {
		t.Errorf("wallet created with a passphrase is not encrypted")
	}
	if !w.IsLocked() {
		t.Errorf("wallet created with a passphrase is not locked")
	}
	if _, err := w.Mnemonic(); err != ErrWalletLocked {
		t.Errorf("Mnemonic() on a fresh passphrase wallet: got %v, want ErrWalletLocked", err)
	}

	// Every wallet file on disk (wallet.dat, and wallet.dat.bak if an
	// auto-flush already rotated one in) must hold only the ciphertext.
	walletDir := filepath.Join(dir, "wallets", "e")
	for _, f := range []string{"wallet.dat", "wallet.dat.bak"} {
		raw, err := os.ReadFile(filepath.Join(walletDir, f))
		if os.IsNotExist(err) && f != "wallet.dat" {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		plain, err := decrypt(raw, pass)
		if err != nil {
			t.Fatalf("%s not decryptable under the passphrase: %v", f, err)
		}
		var data walletData
		if err := json.Unmarshal(plain, &data); err != nil {
			t.Fatalf("%s contents: %v", f, err)
		}
		if !data.Encrypted || len(data.EncryptedMaster) == 0 {
			t.Errorf("%s is not marked encrypted (encrypted=%v, ciphertext %d bytes)", f, data.Encrypted, len(data.EncryptedMaster))
		}
		if len(data.Seed) != 0 {
			t.Errorf("%s carries the plaintext seed (%d bytes) of a passphrase wallet", f, len(data.Seed))
		}
	}

	if err := w.UnlockWithPassphrase(pass, 0); err != nil {
		t.Fatalf("UnlockWithPassphrase: %v", err)
	}
	if _, err := w.Mnemonic(); err != nil {
		t.Errorf("Mnemonic() after unlock: %v", err)
	}
	if _, err := w.GetMasterFingerprint(); err != nil {
		t.Errorf("no master key after unlock: %v", err)
	}
}

// A restore from a caller-supplied mnemonic with a passphrase must come out
// with the same keys as the unencrypted restore, only encrypted.
func TestManagerCreateWalletWithPassphraseRestoreKeepsKeys(t *testing.T) {
	const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	mgr := NewManager(t.TempDir(), address.Regtest, consensus.RegtestParams())
	plain, err := mgr.CreateWallet("plain", CreateWalletOpts{Mnemonic: words})
	if err != nil {
		t.Fatalf("CreateWallet plain: %v", err)
	}
	enc, err := mgr.CreateWallet("enc", CreateWalletOpts{Mnemonic: words, Passphrase: "pw"})
	if err != nil {
		t.Fatalf("CreateWallet enc: %v", err)
	}
	if !enc.IsEncrypted() || !enc.IsLocked() {
		t.Fatalf("restored passphrase wallet: encrypted=%v locked=%v, want both", enc.IsEncrypted(), enc.IsLocked())
	}
	if err := enc.UnlockWithPassphrase("pw", 0); err != nil {
		t.Fatalf("UnlockWithPassphrase: %v", err)
	}
	fpPlain, _ := plain.GetMasterFingerprint()
	fpEnc, err := enc.GetMasterFingerprint()
	if err != nil || fpEnc != fpPlain {
		t.Errorf("restored passphrase wallet master fingerprint %x (err %v), want %x", fpEnc, err, fpPlain)
	}
	a1, _ := plain.NewAddress()
	a2, err := enc.NewAddress()
	if err != nil || a1 != a2 {
		t.Errorf("first address differs: plain %q, encrypted %q (err %v)", a1, a2, err)
	}
}
