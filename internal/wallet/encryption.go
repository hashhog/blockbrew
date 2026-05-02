// Package wallet implements key management and transaction signing.
//
// This file implements the in-memory wallet encryption layer (Bitcoin Core's
// "crypter" semantics): the master HD key is encrypted under a user-supplied
// passphrase using AES-256-GCM with scrypt key derivation. While encrypted and
// locked, the wallet holds only the ciphertext + salt and cannot sign.
//
// Reference: bitcoin-core/src/wallet/crypter.{h,cpp} and
// bitcoin-core/src/wallet/rpc/encrypt.cpp.
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// Encryption-state errors. The strings deliberately mirror Bitcoin Core's
// JSON-RPC error messages so that downstream tools key off the same text.
var (
	// ErrWalletAlreadyEncrypted is returned by EncryptWallet when the wallet
	// is already encrypted. Maps to RPC_WALLET_WRONG_ENC_STATE.
	ErrWalletAlreadyEncrypted = errors.New("wallet is already encrypted")
	// ErrWalletNotEncrypted is returned by walletpassphrase / walletlock when
	// the wallet has no encryption key. Maps to RPC_WALLET_WRONG_ENC_STATE.
	ErrWalletNotEncrypted = errors.New("running with an unencrypted wallet")
	// ErrPassphraseIncorrect is returned by UnlockWithPassphrase when the
	// passphrase does not decrypt the master key. Maps to
	// RPC_WALLET_PASSPHRASE_INCORRECT.
	ErrPassphraseIncorrect = errors.New("the wallet passphrase entered was incorrect")
	// ErrEmptyPassphrase is returned for empty passphrase input.
	ErrEmptyPassphrase = errors.New("passphrase cannot be empty")
)

// encryptedKeyEnvelope is the on-disk and in-memory format for an encrypted
// master key. Layout: salt (32 B) || nonce (12 B) || ciphertext (key||chaincode
// + 16-byte AES-GCM tag).
type encryptedKeyEnvelope struct {
	// Ciphertext is the full salt||nonce||sealed payload.
	Ciphertext []byte
}

// encryptMasterKey encrypts the 64-byte (key||chaincode) plaintext under
// passphrase using scrypt+AES-256-GCM.
//
// Output layout: salt (saltLen) || nonce (nonceLen) || gcm-sealed payload.
// This intentionally matches the layout used by storage.encrypt() so that
// future on-disk persistence of the encrypted master is straightforward.
func encryptMasterKey(plaintext []byte, passphrase string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, saltLen+nonceLen+len(sealed))
	copy(out[:saltLen], salt)
	copy(out[saltLen:saltLen+nonceLen], nonce)
	copy(out[saltLen+nonceLen:], sealed)
	return out, nil
}

// decryptMasterKey decrypts the envelope produced by encryptMasterKey.
// Returns ErrPassphraseIncorrect on AEAD authentication failure.
func decryptMasterKey(envelope []byte, passphrase string) ([]byte, error) {
	if len(envelope) < saltLen+nonceLen+16 {
		return nil, ErrPassphraseIncorrect
	}
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}

	salt := envelope[:saltLen]
	nonce := envelope[saltLen : saltLen+nonceLen]
	ct := envelope[saltLen+nonceLen:]

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrPassphraseIncorrect
	}
	return plaintext, nil
}

// zeroBytes overwrites b with zeros to limit the lifetime of secret material
// in heap memory. Best-effort: Go has no SecureString primitive.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
