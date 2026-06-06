package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

// walletFileName is the on-disk wallet file name (under DataDir). The atomic
// writer stages a sibling temp file and rotates the previous good copy into
// walletBakSuffix before swapping the new file in.
const (
	walletFileName  = "wallet.dat"
	walletTmpSuffix = ".new" // staging file (matches mempool.dat's ".new")
	walletBakSuffix = ".bak" // last-known-good copy for fault-tolerant load
)

// walletData is the serialized wallet state.
//
// LastSyncedHeight records the active-chain height the wallet's UTXO ledger has
// been scanned through (the highest height passed to ScanBlock). It is the
// durable cursor the startup reconcile uses to bound the rescan gap — mirrors
// Bitcoin Core's CWallet::m_last_block_processed_height
// (bitcoin-core/src/wallet/wallet.h), persisted so an unclean restart resumes
// the wallet scan from where it left off instead of from genesis. omitempty so
// older on-disk wallets (written before this field existed) load as height 0
// and trigger a full reconcile, which is the safe default.
type walletData struct {
	Seed             []byte            `json:"seed,omitempty"`
	Mnemonic         string            `json:"mnemonic,omitempty"`
	Network          int               `json:"network"`
	NextExtIdx       uint32            `json:"next_ext_idx"`
	NextIntIdx       uint32            `json:"next_int_idx"`
	AddrPaths        map[string]string `json:"addr_paths"`
	AddrLabels       map[string]string `json:"addr_labels,omitempty"`
	UTXOs            []*utxoData       `json:"utxos"`
	TxHistory        []*txData         `json:"tx_history"`
	LastSyncedHeight int32             `json:"last_synced_height,omitempty"`
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
//
// The write is atomic + durable, mirroring this node's mempool dump
// (internal/mempool/persist.go::Dump) and Bitcoin Core's CWallet/BerkeleyBatch
// flush discipline: the new contents are written to a sibling temp file, the
// fd is fsync'd, the previous good copy is rotated into wallet.dat.bak, the
// temp file is atomically renamed over wallet.dat, and finally the containing
// directory is fsync'd so the rename itself is durable. A SIGKILL / OOM /
// power-loss at any point leaves EITHER the old wallet.dat (rename not yet
// committed) OR the new one — never a half-written file — and wallet.dat.bak
// is a recoverable fallback if the active file is ever found corrupt.
func (w *Wallet) SaveToFile(password string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Serialize wallet data
	data := walletData{
		Network:          int(w.config.Network),
		NextExtIdx:       w.nextExtIdx,
		NextIntIdx:       w.nextIntIdx,
		AddrPaths:        w.addrToPath,
		AddrLabels:       w.addrLabels,
		UTXOs:            make([]*utxoData, 0, len(w.utxos)),
		TxHistory:        make([]*txData, 0, len(w.txHistory)),
		LastSyncedHeight: w.lastSyncedHeight,
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

	// Ensure the data dir itself exists (this is where wallet.dat lives).
	// The previous code did MkdirAll(filepath.Dir(DataDir)) which created the
	// PARENT of the data dir, not the data dir, so a save into a not-yet-created
	// data dir could fail. Mkdir the data dir directly.
	if err := os.MkdirAll(w.config.DataDir, 0700); err != nil {
		return err
	}

	return atomicWriteWallet(w.config.DataDir, ciphertext)
}

// atomicWriteWallet performs the temp → fsync → rotate-bak → rename → dir-fsync
// dance for the wallet file. Split out so it can be unit-tested independently of
// the (lock-holding) SaveToFile.
func atomicWriteWallet(dataDir string, ciphertext []byte) error {
	finalPath := filepath.Join(dataDir, walletFileName)
	tmpPath := finalPath + walletTmpSuffix
	bakPath := finalPath + walletBakSuffix

	// Stage to the temp file, fsync the contents before any rename.
	f, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("wallet save: open %s: %w", tmpPath, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		// Best-effort cleanup of a leftover staging file on any error path.
		_ = os.Remove(tmpPath)
	}()
	if _, err := f.Write(ciphertext); err != nil {
		return fmt.Errorf("wallet save: write %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("wallet save: fsync %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("wallet save: close %s: %w", tmpPath, err)
	}
	closed = true

	// Rotate the current good copy into the .bak slot so a future load can
	// fall back if the freshly-written file is ever found unreadable. Done via
	// a copy (not a rename of finalPath) so finalPath is never absent between
	// here and the rename below. Best-effort: a failure here must not abort the
	// save — the temp file is already durable and is the authoritative new
	// state.
	if cur, rerr := os.ReadFile(finalPath); rerr == nil {
		if werr := writeFileSync(bakPath, cur, 0600); werr != nil {
			log.Printf("wallet save: warning: could not refresh %s: %v", bakPath, werr)
		}
	}

	// Atomic swap.
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("wallet save: rename %s -> %s: %w", tmpPath, finalPath, err)
	}
	closed = true // the deferred Remove(tmpPath) is now a harmless no-op

	// fsync the directory so the rename (a metadata op) is itself durable.
	// Without this, a power-loss right after the rename could leave the
	// directory entry pointing at the old inode on some filesystems.
	if derr := fsyncDir(dataDir); derr != nil {
		log.Printf("wallet save: warning: dir fsync failed for %s: %v", dataDir, derr)
	}
	return nil
}

// writeFileSync writes data to path atomically-ish (truncate + write + fsync).
// Used for the .bak rotation, where a partial .bak is acceptable (it's only a
// fallback) but a torn write should still be flushed to stable storage.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// fsyncDir opens the directory and fsyncs it so a preceding rename is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// LoadFromFile decrypts and loads the wallet from disk.
//
// Fault tolerance (mirrors Bitcoin Core's wallet recovery + the node's own
// mempool Load, which logs-and-continues on a corrupt entry rather than
// crashing): if the active wallet.dat is missing, unreadable, fails to decrypt,
// or fails to JSON-parse, LoadFromFile transparently falls back to the
// last-known-good wallet.dat.bak that SaveToFile rotates on every write. Only
// when BOTH the active file and the backup are unusable does it return an
// error — and even then the caller (cmd/blockbrew/main.go) starts with an empty
// wallet rather than aborting node startup. Within a successfully-decrypted
// file, an individual malformed UTXO / history record is skipped (logged) so a
// single bad entry never discards the whole wallet.
//
// A genuinely missing file (no wallet.dat AND no .bak) returns the underlying
// os error unwrapped so the caller can distinguish "no wallet yet" (start
// fresh, no warning) from "corruption" (warn loudly).
func LoadFromFile(path string, password string, config WalletConfig) (*Wallet, error) {
	walletPath := filepath.Join(path, walletFileName)
	bakPath := walletPath + walletBakSuffix

	w, err := loadWalletFile(walletPath, password, config, path)
	if err == nil {
		return w, nil
	}

	// If the primary file is simply absent and there's no backup either, this
	// is a first run — surface the not-exist error untouched.
	primaryMissing := os.IsNotExist(err)
	if _, statErr := os.Stat(bakPath); statErr != nil {
		// No backup to fall back to.
		return nil, err
	}

	// Primary failed but a backup exists: try to recover from it.
	if !primaryMissing {
		log.Printf("wallet load: %s unusable (%v) — recovering from %s",
			walletPath, err, bakPath)
	}
	wBak, bakErr := loadWalletFile(bakPath, password, config, path)
	if bakErr != nil {
		log.Printf("wallet load: backup %s also unusable: %v", bakPath, bakErr)
		return nil, err // return the ORIGINAL error (about the primary)
	}
	log.Printf("wallet load: recovered wallet state from backup %s", bakPath)
	// Re-stamp the recovered state back to the primary path so the next save
	// has a clean baseline and the .bak is regenerated. Best-effort.
	if reErr := wBak.SaveToFile(password); reErr != nil {
		log.Printf("wallet load: warning: could not rewrite primary from backup: %v", reErr)
	}
	return wBak, nil
}

// loadWalletFile reads, decrypts, parses and reconstructs a wallet from a single
// concrete file path. dataDir is the directory recorded back into the wallet's
// config (so a backup-recovered wallet still saves to the canonical location).
func loadWalletFile(filePath, password string, config WalletConfig, dataDir string) (*Wallet, error) {
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err // includes os.IsNotExist for a missing file
	}

	plaintext, err := decrypt(ciphertext, password)
	if err != nil {
		// A wrong password is reported as-is so the RPC layer can surface it;
		// a truncated/torn file decrypts to ErrCorruptedFile via decrypt's
		// length guard, which the .bak fallback handles.
		return nil, err
	}

	var data walletData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, ErrCorruptedFile
	}

	config.DataDir = dataDir
	w := NewWallet(config)

	// Restore master key from seed.
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

	// Restore scalar state.
	w.nextExtIdx = data.NextExtIdx
	w.nextIntIdx = data.NextIntIdx
	w.lastSyncedHeight = data.LastSyncedHeight
	w.addrToPath = data.AddrPaths
	if w.addrToPath == nil {
		w.addrToPath = make(map[string]string)
	}
	w.addrLabels = data.AddrLabels
	if w.addrLabels == nil {
		w.addrLabels = make(map[string]string)
	}

	// Restore UTXOs — skip (don't abort on) a malformed record.
	skippedUTXO := 0
	for _, u := range data.UTXOs {
		hash, err := parseHash(u.TxHash)
		if err != nil {
			skippedUTXO++
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

	// Restore transaction history — skip a malformed record.
	skippedTx := 0
	for _, t := range data.TxHistory {
		hash, err := parseHash(t.TxHash)
		if err != nil {
			skippedTx++
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
	if skippedUTXO > 0 || skippedTx > 0 {
		log.Printf("wallet load: %s recovered with %d UTXO record(s) and %d tx record(s) skipped (malformed)",
			filePath, skippedUTXO, skippedTx)
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
