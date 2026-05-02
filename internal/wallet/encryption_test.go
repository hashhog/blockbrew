package wallet

import (
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
)

const encTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	})
	if err := w.CreateFromMnemonic(encTestMnemonic, ""); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	return w
}

// TestEncryptWalletBasic verifies the happy path: an unencrypted wallet is
// encrypted, leaving it locked, and unlocking with the same passphrase
// restores signing capability.
func TestEncryptWalletBasic(t *testing.T) {
	w := newTestWallet(t)

	if w.IsEncrypted() {
		t.Fatal("freshly-created wallet should not be encrypted")
	}
	if w.IsLocked() {
		t.Fatal("freshly-created wallet should not be locked")
	}

	if err := w.EncryptWallet("hunter2"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}
	if !w.IsEncrypted() {
		t.Error("wallet should be encrypted after EncryptWallet")
	}
	if !w.IsLocked() {
		t.Error("wallet should be locked after EncryptWallet")
	}

	// Cannot generate addresses while locked.
	if _, err := w.NewAddress(); !errors.Is(err, ErrWalletLocked) {
		t.Errorf("expected ErrWalletLocked while locked, got %v", err)
	}

	// Unlock with the right passphrase.
	if err := w.UnlockWithPassphrase("hunter2", 60); err != nil {
		t.Fatalf("UnlockWithPassphrase: %v", err)
	}
	if w.IsLocked() {
		t.Error("wallet should be unlocked after UnlockWithPassphrase")
	}
	addr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress after unlock: %v", err)
	}
	if addr == "" {
		t.Error("expected non-empty address")
	}
}

// TestEncryptWalletWrongPassphrase asserts that the wrong passphrase yields
// ErrPassphraseIncorrect and leaves the wallet locked.
func TestEncryptWalletWrongPassphrase(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet("correct horse battery staple"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}

	err := w.UnlockWithPassphrase("not the same", 60)
	if !errors.Is(err, ErrPassphraseIncorrect) {
		t.Fatalf("expected ErrPassphraseIncorrect, got %v", err)
	}
	if !w.IsLocked() {
		t.Error("wallet must remain locked after a failed unlock")
	}

	// Right passphrase must still succeed afterwards.
	if err := w.UnlockWithPassphrase("correct horse battery staple", 60); err != nil {
		t.Fatalf("UnlockWithPassphrase (right pw): %v", err)
	}
}

// TestEncryptWalletAlreadyEncrypted ensures EncryptWallet refuses to operate
// on an already-encrypted wallet, matching Core's WALLET_WRONG_ENC_STATE.
func TestEncryptWalletAlreadyEncrypted(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet("p1"); err != nil {
		t.Fatalf("first EncryptWallet: %v", err)
	}
	err := w.EncryptWallet("p2")
	if !errors.Is(err, ErrWalletAlreadyEncrypted) {
		t.Fatalf("expected ErrWalletAlreadyEncrypted, got %v", err)
	}
}

// TestUnlockWithPassphraseUnencrypted ensures UnlockWithPassphrase rejects
// pre-encryption wallets cleanly so callers can fall back to the legacy path.
func TestUnlockWithPassphraseUnencrypted(t *testing.T) {
	w := newTestWallet(t)
	err := w.UnlockWithPassphrase("anything", 60)
	if !errors.Is(err, ErrWalletNotEncrypted) {
		t.Fatalf("expected ErrWalletNotEncrypted, got %v", err)
	}
}

// TestEmptyPassphraseRejected ensures both EncryptWallet and
// UnlockWithPassphrase reject empty input (Core: RPC_INVALID_PARAMETER).
func TestEmptyPassphraseRejected(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet(""); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("EncryptWallet(\"\"): want ErrEmptyPassphrase, got %v", err)
	}
	if err := w.EncryptWallet("real"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}
	if err := w.UnlockWithPassphrase("", 60); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("UnlockWithPassphrase(\"\"): want ErrEmptyPassphrase, got %v", err)
	}
}

// TestUnlockAutoRelock asserts that the auto-relock timer fires after the
// configured timeout, returning the wallet to the locked state.
func TestUnlockAutoRelock(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet("pw"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}

	// Use a 1-second timeout to keep the test fast but real (the relock
	// path uses time.AfterFunc, which we want to exercise end-to-end).
	if err := w.UnlockWithPassphrase("pw", 1); err != nil {
		t.Fatalf("UnlockWithPassphrase: %v", err)
	}
	if w.IsLocked() {
		t.Fatal("wallet should be unlocked immediately after UnlockWithPassphrase")
	}

	// Poll until the timer fires; bound the wait so a flake fails loudly.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.IsLocked() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !w.IsLocked() {
		t.Fatal("wallet should auto-relock after the timeout elapses")
	}
}

// TestUnlockResetsTimer documents Core behavior: a second walletpassphrase
// call replaces the prior auto-relock schedule rather than stacking.
func TestUnlockResetsTimer(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet("pw"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}

	if err := w.UnlockWithPassphrase("pw", 1); err != nil {
		t.Fatalf("first unlock: %v", err)
	}
	// Push the relock far into the future before the first timer fires.
	if err := w.UnlockWithPassphrase("pw", 60); err != nil {
		t.Fatalf("second unlock: %v", err)
	}

	// After well past the original 1s, the wallet should still be unlocked.
	time.Sleep(1500 * time.Millisecond)
	if w.IsLocked() {
		t.Fatal("second walletpassphrase should have reset the relock timer")
	}

	// Explicit lock works.
	w.Lock()
	if !w.IsLocked() {
		t.Fatal("explicit Lock should re-lock the wallet")
	}
}

// TestExplicitLockAfterEncrypt asserts that calling Lock() after encryption
// scrubs the master key (signing fails until UnlockWithPassphrase is called).
func TestExplicitLockAfterEncrypt(t *testing.T) {
	w := newTestWallet(t)
	if err := w.EncryptWallet("pw"); err != nil {
		t.Fatalf("EncryptWallet: %v", err)
	}
	if err := w.UnlockWithPassphrase("pw", 60); err != nil {
		t.Fatalf("UnlockWithPassphrase: %v", err)
	}
	w.Lock()
	if !w.IsLocked() {
		t.Fatal("Lock should mark wallet locked")
	}
	if _, err := w.NewAddress(); !errors.Is(err, ErrWalletLocked) {
		t.Errorf("after Lock, NewAddress should return ErrWalletLocked, got %v", err)
	}
}

// TestEncryptWalletWithoutMasterKey ensures EncryptWallet refuses a wallet
// that has no master key (e.g. a freshly NewWallet'd instance).
func TestEncryptWalletWithoutMasterKey(t *testing.T) {
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	})
	err := w.EncryptWallet("pw")
	if !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("expected ErrNoMasterKey, got %v", err)
	}
}
