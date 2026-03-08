package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/hashhog/blockbrew/internal/wire"
	"golang.org/x/crypto/scrypt"
)

// Storage errors
var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrCorruptedFile   = errors.New("corrupted wallet file")
)

// Encryption parameters
const (
	scryptN      = 32768 // CPU/memory cost parameter
	scryptR      = 8     // Block size parameter
	scryptP      = 1     // Parallelization parameter
	scryptKeyLen = 32    // AES-256 key length
	saltLen      = 32    // Salt length
	nonceLen     = 12    // AES-GCM nonce length
)

// walletData is the serialized wallet state.
type walletData struct {
	Seed       []byte            `json:"seed,omitempty"`
	Mnemonic   string            `json:"mnemonic,omitempty"`
	Network    int               `json:"network"`
	NextExtIdx uint32            `json:"next_ext_idx"`
	NextIntIdx uint32            `json:"next_int_idx"`
	AddrPaths  map[string]string `json:"addr_paths"`
	UTXOs      []*utxoData       `json:"utxos"`
	TxHistory  []*txData         `json:"tx_history"`
}

// utxoData is the serialized UTXO format.
type utxoData struct {
	TxHash     string `json:"txhash"`
	Index      uint32 `json:"index"`
	Amount     int64  `json:"amount"`
	PkScript   []byte `json:"pk_script"`
	Address    string `json:"address"`
	Height     int32  `json:"height"`
	IsCoinbase bool   `json:"is_coinbase"`
	KeyPath    string `json:"key_path"`
	Confirmed  bool   `json:"confirmed"`
}

// txData is the serialized transaction history format.
type txData struct {
	TxHash    string `json:"txhash"`
	Height    int32  `json:"height"`
	Amount    int64  `json:"amount"`
	Fee       int64  `json:"fee"`
	Timestamp int64  `json:"timestamp"`
	Address   string `json:"address"`
}

// SaveToFile encrypts and saves the wallet to disk.
func (w *Wallet) SaveToFile(password string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Serialize wallet data
	data := walletData{
		Network:    int(w.config.Network),
		NextExtIdx: w.nextExtIdx,
		NextIntIdx: w.nextIntIdx,
		AddrPaths:  w.addrToPath,
		UTXOs:      make([]*utxoData, 0, len(w.utxos)),
		TxHistory:  make([]*txData, 0, len(w.txHistory)),
	}

	// Serialize UTXOs
	for _, utxo := range w.utxos {
		data.UTXOs = append(data.UTXOs, &utxoData{
			TxHash:     utxo.OutPoint.Hash.String(),
			Index:      utxo.OutPoint.Index,
			Amount:     utxo.Amount,
			PkScript:   utxo.PkScript,
			Address:    utxo.Address,
			Height:     utxo.Height,
			IsCoinbase: utxo.IsCoinbase,
			KeyPath:    utxo.KeyPath,
			Confirmed:  utxo.Confirmed,
		})
	}

	// Serialize transaction history
	for _, tx := range w.txHistory {
		data.TxHistory = append(data.TxHistory, &txData{
			TxHash:    tx.TxHash.String(),
			Height:    tx.Height,
			Amount:    tx.Amount,
			Fee:       tx.Fee,
			Timestamp: tx.Timestamp,
			Address:   tx.Address,
		})
	}

	// If we have the master key, serialize the seed for recovery
	if w.masterKey != nil {
		// We can't actually recover the seed from the master key,
		// so in a real implementation we'd store the mnemonic.
		// For this implementation, we store the master key data.
		data.Seed = append(w.masterKey.Key, w.masterKey.ChainCode...)
	}

	// Encode to JSON
	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Encrypt
	ciphertext, err := encrypt(plaintext, password)
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(w.config.DataDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Write file
	walletPath := filepath.Join(w.config.DataDir, "wallet.dat")
	return os.WriteFile(walletPath, ciphertext, 0600)
}

// LoadFromFile decrypts and loads the wallet from disk.
func LoadFromFile(path string, password string, config WalletConfig) (*Wallet, error) {
	// Read file
	walletPath := filepath.Join(path, "wallet.dat")
	ciphertext, err := os.ReadFile(walletPath)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := decrypt(ciphertext, password)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	// Parse JSON
	var data walletData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, ErrCorruptedFile
	}

	// Create wallet
	config.DataDir = path
	w := NewWallet(config)

	// Restore master key from seed
	if len(data.Seed) == 64 {
		// Seed is stored as key || chainCode
		masterKey := &HDKey{
			Key:       data.Seed[:32],
			ChainCode: data.Seed[32:64],
			Depth:     0,
			ParentFP:  [4]byte{},
			Index:     0,
			IsPrivate: true,
		}
		w.masterKey = masterKey
		w.locked = false
	}

	// Restore state
	w.nextExtIdx = data.NextExtIdx
	w.nextIntIdx = data.NextIntIdx
	w.addrToPath = data.AddrPaths
	if w.addrToPath == nil {
		w.addrToPath = make(map[string]string)
	}

	// Restore UTXOs
	for _, u := range data.UTXOs {
		hash, err := parseHash(u.TxHash)
		if err != nil {
			continue
		}
		outpoint := wire.OutPoint{
			Hash:  hash,
			Index: u.Index,
		}
		w.utxos[outpoint] = &WalletUTXO{
			OutPoint:   outpoint,
			Amount:     u.Amount,
			PkScript:   u.PkScript,
			Address:    u.Address,
			Height:     u.Height,
			IsCoinbase: u.IsCoinbase,
			KeyPath:    u.KeyPath,
			Confirmed:  u.Confirmed,
		}
	}

	// Restore transaction history
	for _, t := range data.TxHistory {
		hash, err := parseHash(t.TxHash)
		if err != nil {
			continue
		}
		w.txHistory = append(w.txHistory, &WalletTx{
			TxHash:    hash,
			Height:    t.Height,
			Amount:    t.Amount,
			Fee:       t.Fee,
			Timestamp: t.Timestamp,
			Address:   t.Address,
		})
	}

	return w, nil
}

// encrypt encrypts data using AES-256-GCM with scrypt key derivation.
// Format: salt (32 bytes) || nonce (12 bytes) || ciphertext
func encrypt(plaintext []byte, password string) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive encryption key using scrypt
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine: salt || nonce || ciphertext
	result := make([]byte, saltLen+nonceLen+len(ciphertext))
	copy(result[:saltLen], salt)
	copy(result[saltLen:saltLen+nonceLen], nonce)
	copy(result[saltLen+nonceLen:], ciphertext)

	return result, nil
}

// decrypt decrypts data encrypted with encrypt().
func decrypt(data []byte, password string) ([]byte, error) {
	// Minimum length check: salt + nonce + at least some ciphertext
	if len(data) < saltLen+nonceLen+16 {
		return nil, ErrCorruptedFile
	}

	// Extract components
	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]

	// Derive key using scrypt
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	return plaintext, nil
}

// parseHash parses a hash string (in display order) to a Hash256.
func parseHash(s string) (wire.Hash256, error) {
	return wire.NewHash256FromHex(s)
}
