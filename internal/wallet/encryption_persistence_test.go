package wallet

// Encryption persistence invariants (the "1a2" defect family, 2026-06-10).
//
// These three tests pin the on-disk behavior contract that Bitcoin Core's
// crypter model guarantees and blockbrew violated:
//
//	T1 — passphrase-stability: a wallet created with a passphrase must NEVER
//	     be re-written under a weaker (empty) envelope password by any
//	     background or management save path. Core analogue: no Core path can
//	     lower at-rest protection because no background path re-derives the
//	     encryption key (wallet.cpp:841-870 — EncryptWallet is transactional
//	     and the master key ciphertext IS the at-rest state).
//	T2 — encryptwallet-persistence: encryptwallet's state must survive a
//	     restart. Core derives HasEncryptionKeys from the persisted
//	     MASTER_KEY records (walletdb.cpp:151-154 + 189-198); blockbrew must
//	     persist encrypted+encryptedMaster and reload the wallet LOCKED.
//	T3 — locked-flush no-key-loss: a flush while the wallet is encrypted +
//	     locked (masterKey == nil) must never drop the master key from disk.
//	     Core's Lock() wipes RAM only (wallet.cpp:3362-3377) and a flush can
//	     never drop secrets because disk already holds them as ciphertext
//	     (walletdb.cpp:225-232 writes ciphertext BEFORE erasing plaintext).
//
// All three FAIL on the pre-fix tree (executed 2026-06-10): the first
// auto-flush/unload re-encrypted the file under "" (T1), walletData had no
// Encrypted/EncryptedMaster fields (T2), and SaveToFile gated the Seed on
// masterKey != nil so a locked flush wrote a wallet file with no key material
// at all (T3 — hard funds loss for seed-only wallets).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
)

// readWalletCiphertext reads the raw on-disk wallet file.
func readWalletCiphertext(t *testing.T, walletDir string) []byte {
	t.Helper()
	ct, err := os.ReadFile(filepath.Join(walletDir, walletFileName))
	if err != nil {
		t.Fatalf("read wallet file: %v", err)
	}
	return ct
}

func encPersistConfig(walletDir string) WalletConfig {
	return WalletConfig{
		DataDir:     walletDir,
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: AddressTypeP2WPKH,
	}
}

// TestEncryptionInvariant1PassphraseStability — a wallet created with
// createwallet(passphrase=P) must stay decryptable ONLY under P across every
// save path: the explicit Flush (the auto-flusher's body) and UnloadWallet.
// Pre-fix both re-encrypted the file under the empty password within one
// autoflush interval, silently stripping the user's protection.
func TestEncryptionInvariant1PassphraseStability(t *testing.T) {
	dir := t.TempDir()
	const pass = "open-sesame"
	mgr := NewManager(dir, address.Mainnet, consensus.MainnetParams())
	w, err := mgr.CreateWallet("t1", CreateWalletOpts{Passphrase: pass})
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	walletDir := filepath.Join(dir, "wallets", "t1")

	// Creation writes under P (this held even pre-fix).
	if _, err := decrypt(readWalletCiphertext(t, walletDir), pass); err != nil {
		t.Fatalf("freshly created wallet not decryptable under its passphrase: %v", err)
	}
	if _, err := decrypt(readWalletCiphertext(t, walletDir), ""); err == nil {
		t.Fatalf("freshly created passphrase-wallet is decryptable under \"\"")
	}

	// A background flush (Flush is the auto-flusher's body) must NOT
	// re-encrypt the file under "".
	w.MarkDirty()
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := decrypt(readWalletCiphertext(t, walletDir), ""); err == nil {
		t.Fatalf("PROTECTION STRIPPED: a background flush re-encrypted the wallet under the empty password")
	}
	if _, err := decrypt(readWalletCiphertext(t, walletDir), pass); err != nil {
		t.Fatalf("wallet no longer decryptable under its passphrase after flush: %v", err)
	}

	// UnloadWallet (save-on-unload) must keep the protection too.
	if err := mgr.UnloadWallet("t1", nil); err != nil {
		t.Fatalf("UnloadWallet: %v", err)
	}
	if _, err := decrypt(readWalletCiphertext(t, walletDir), ""); err == nil {
		t.Fatalf("PROTECTION STRIPPED: UnloadWallet re-encrypted the wallet under the empty password")
	}
	if _, err := decrypt(readWalletCiphertext(t, walletDir), pass); err != nil {
		t.Fatalf("wallet not decryptable under its passphrase after unload: %v", err)
	}
}

// TestEncryptionInvariant2EncryptWalletPersistsAcrossReload — after
// encryptwallet(P) + flush, a simulated restart must (a) refuse the empty
// password, (b) load under P with IsEncrypted()==true and the wallet LOCKED,
// (c) unlock with P (and only P) recovering the same master key, and (d)
// refuse a second encryptwallet. Pre-fix the encrypted state lived only in
// memory: the file reloaded as an unencrypted (and, worse, key-less) wallet.
func TestEncryptionInvariant2EncryptWalletPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	const pass = "hunter2"
	mgr := NewManager(dir, address.Mainnet, consensus.MainnetParams())
	w, err := mgr.CreateWallet("t2", CreateWalletOpts{})
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	origFP, err := w.GetMasterFingerprint()
	if err != nil {
		t.Fatalf("GetMasterFingerprint: %v", err)
	}

	if err := w.EncryptWallet(pass); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush after encrypt: %v", err)
	}

	walletDir := filepath.Join(dir, "wallets", "t2")
	cfg := encPersistConfig(walletDir)

	// (a) the empty password must no longer open the wallet.
	if _, err := LoadFromFile(walletDir, "", cfg); err == nil {
		t.Fatalf("ENCRYPTION DEFEATED: post-encryptwallet wallet file loads under the empty password")
	}

	// (b) reload under the passphrase: encrypted state must survive restart.
	w2, err := LoadFromFile(walletDir, pass, cfg)
	if err != nil {
		t.Fatalf("reload under the passphrase failed: %v", err)
	}
	if !w2.IsEncrypted() {
		t.Fatalf("ENCRYPTION STATE EVAPORATED: IsEncrypted()==false after restart")
	}
	if !w2.IsLocked() {
		t.Errorf("encrypted wallet must boot LOCKED")
	}

	// (c) wrong passphrase refused; right passphrase recovers the SAME key.
	if err := w2.UnlockWithPassphrase("wrong-passphrase", 0); err == nil {
		t.Fatalf("UnlockWithPassphrase accepted a wrong passphrase")
	}
	if err := w2.UnlockWithPassphrase(pass, 0); err != nil {
		t.Fatalf("UnlockWithPassphrase(correct): %v", err)
	}
	fp2, err := w2.GetMasterFingerprint()
	if err != nil {
		t.Fatalf("GetMasterFingerprint after unlock: %v", err)
	}
	if fp2 != origFP {
		t.Fatalf("master key did not round-trip: %x != %x", fp2, origFP)
	}

	// (d) encryptwallet again → already-encrypted error (Core -15).
	if err := w2.EncryptWallet("again"); !errors.Is(err, ErrWalletAlreadyEncrypted) {
		t.Fatalf("second EncryptWallet: want ErrWalletAlreadyEncrypted, got %v", err)
	}
}

// TestEncryptionInvariant3LockedFlushNeverDropsKeyMaterial — EncryptWallet
// locks the wallet (masterKey == nil) and marks it dirty, guaranteeing the
// next flush runs while locked. That flush must persist the master-key
// CIPHERTEXT; pre-fix it wrote a wallet file with NO Seed and NO encrypted
// master — permanent key loss for seed-only (mnemonic-less) wallets.
func TestEncryptionInvariant3LockedFlushNeverDropsKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	const pass = "toplock"
	mgr := NewManager(dir, address.Mainnet, consensus.MainnetParams())
	w, err := mgr.CreateWallet("t3", CreateWalletOpts{})
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	origFP, err := w.GetMasterFingerprint()
	if err != nil {
		t.Fatalf("GetMasterFingerprint: %v", err)
	}

	if err := w.EncryptWallet(pass); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}
	if !w.IsLocked() {
		t.Fatalf("wallet must be locked right after EncryptWallet")
	}
	// THE flush-while-locked the defect family is about.
	if err := w.Flush(); err != nil {
		t.Fatalf("flush while locked: %v", err)
	}

	walletDir := filepath.Join(dir, "wallets", "t3")
	w2, err := LoadFromFile(walletDir, pass, encPersistConfig(walletDir))
	if err != nil {
		t.Fatalf("FUNDS-LOSS: wallet file unreadable after a locked flush: %v", err)
	}
	if err := w2.UnlockWithPassphrase(pass, 0); err != nil {
		t.Fatalf("FUNDS-LOSS: master key did not survive a flush-while-locked: %v", err)
	}
	fp2, err := w2.GetMasterFingerprint()
	if err != nil {
		t.Fatalf("GetMasterFingerprint after reload+unlock: %v", err)
	}
	if fp2 != origFP {
		t.Fatalf("master key corrupted across locked flush: %x != %x", fp2, origFP)
	}
}
