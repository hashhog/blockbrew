// Package wallet implements key management and transaction signing.
package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Manager errors
var (
	ErrWalletAlreadyLoaded  = errors.New("wallet already loaded")
	ErrWalletNotFound       = errors.New("wallet not found")
	ErrWalletAlreadyExists  = errors.New("wallet already exists")
	ErrNoWalletSpecified    = errors.New("wallet file not specified")
	ErrMultipleWalletsNamed = errors.New("multiple wallets loaded, specify wallet name")
	ErrInvalidWalletName    = errors.New("invalid wallet name")
	ErrTooManyWallets       = errors.New("too many wallets loaded")
)

// MaxLoadedWallets is the maximum number of simultaneously loaded wallets.
const MaxLoadedWallets = 100

// CreateWalletOpts contains options for creating a new wallet.
//
// Two passphrases exist and are semantically distinct (W161 BUG-16
// "passphrase-confusion" fix):
//
//   - `Passphrase` is the WALLET-FILE encryption passphrase. It feeds into
//     scrypt → AES-256-GCM and encrypts the master xprv on disk. Maps to
//     Bitcoin Core's `createwallet` arg `passphrase`.
//
//   - `SeedPassphrase` is the BIP-39 "25th word" passphrase. It feeds into
//     PBKDF2-HMAC-SHA512 alongside the mnemonic to derive a different BIP-32
//     seed (BIP-39 §"From mnemonic to seed"). A non-empty value yields a
//     COMPLETELY DIFFERENT wallet for the same mnemonic — this is the
//     plausible-deniability feature used by Trezor / Ledger / Coldcard /
//     Sparrow. Core does not natively expose this (Core uses descriptor
//     wallets), so it is a blockbrew extension carried in `_options` /
//     positional arg 7 of `createwallet`.
//
// Previously `Manager.CreateWallet` hardcoded the BIP-39 passphrase to "" at
// `manager.go:209`, silently dropping plausible-deniability. See
// `CORE-PARITY-AUDIT/w161-bip32-bip39-bip43-bip44-hd-derivation.md` BUG-16.
type CreateWalletOpts struct {
	DisablePrivateKeys bool   // Create watch-only wallet
	Blank              bool   // Create without keys
	Passphrase         string // Wallet-file encryption passphrase (scrypt+AES-GCM)
	SeedPassphrase     string // BIP-39 "25th word" passphrase (PBKDF2 input)
	Mnemonic           string // BIP-39 mnemonic to RESTORE from (empty = generate fresh)
	AvoidReuse         bool   // Track coin reuse (NYI)
	LoadOnStartup      *bool  // Save to auto-load list
}

// WalletInfo contains information about a wallet directory.
type WalletInfo struct {
	Name     string
	Path     string
	Warnings []string
}

// Manager manages multiple wallet instances.
type Manager struct {
	mu          sync.RWMutex
	wallets     map[string]*Wallet // name → wallet
	dataDir     string
	network     address.Network
	chainParams *consensus.ChainParams
	autoLoad    []string // wallet names to auto-load
}

// NewManager creates a new wallet manager.
func NewManager(dataDir string, network address.Network, chainParams *consensus.ChainParams) *Manager {
	return &Manager{
		wallets:     make(map[string]*Wallet),
		dataDir:     dataDir,
		network:     network,
		chainParams: chainParams,
		autoLoad:    make([]string, 0),
	}
}

// walletDir returns the directory path for a wallet by name.
// Empty name uses the default wallet location.
func (m *Manager) walletDir(name string) string {
	walletsDir := filepath.Join(m.dataDir, "wallets")
	if name == "" {
		return walletsDir
	}
	return filepath.Join(walletsDir, name)
}

// LoadWallet loads an existing wallet from disk with an empty envelope
// password (the default for wallets created without a passphrase).
func (m *Manager) LoadWallet(name string, loadOnStartup *bool) (*Wallet, error) {
	return m.LoadWalletWithPassphrase(name, "", loadOnStartup)
}

// LoadWalletWithPassphrase loads an existing wallet from disk, decrypting the
// wallet file with the given envelope password. Wallets created with a
// createwallet passphrase — or re-encrypted by encryptwallet — require their
// passphrase here; loading them with "" fails with ErrInvalidPassword instead
// of silently falling back to a weaker on-disk copy.
func (m *Manager) LoadWalletWithPassphrase(name, passphrase string, loadOnStartup *bool) (*Wallet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already loaded
	if _, exists := m.wallets[name]; exists {
		return nil, ErrWalletAlreadyLoaded
	}

	// Check limit
	if len(m.wallets) >= MaxLoadedWallets {
		return nil, ErrTooManyWallets
	}

	// Validate name
	if !isValidWalletName(name) {
		return nil, ErrInvalidWalletName
	}

	walletPath := m.walletDir(name)

	// Check if wallet exists
	if _, err := os.Stat(filepath.Join(walletPath, "wallet.dat")); os.IsNotExist(err) {
		return nil, ErrWalletNotFound
	}

	// Load wallet
	config := WalletConfig{
		DataDir:     walletPath,
		Network:     m.network,
		ChainParams: m.chainParams,
		AddressType: AddressTypeP2WPKH,
	}

	w, err := LoadFromFile(walletPath, passphrase, config)
	if err != nil {
		return nil, err
	}

	// Set wallet name
	w.name = name

	m.wallets[name] = w

	// Manager-loaded wallets get the same save-on-mutation durability as the
	// legacy default wallet (pre-fix they persisted only at unload/backup, so
	// a SIGKILL lost every mutation since load).
	w.StartAutoFlush(DefaultAutoFlushInterval)

	// Update auto-load preference
	if loadOnStartup != nil {
		m.updateAutoLoad(name, *loadOnStartup)
	}

	return w, nil
}

// UnloadWallet unloads a wallet.
func (m *Manager) UnloadWallet(name string, loadOnStartup *bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	w, exists := m.wallets[name]
	if !exists {
		return ErrWalletNotFound
	}

	// Stop the background flusher (does a final synchronous flush), then save
	// once more under the wallet's CURRENT envelope password. Never a literal
	// "": pre-fix this re-encrypted passphrase-protected wallets under the
	// empty password on every unload, stripping the user's protection.
	w.StopAutoFlush()
	if err := w.Save(); err != nil {
		// Log warning but continue with unload
	}

	delete(m.wallets, name)

	// Update auto-load preference
	if loadOnStartup != nil {
		m.updateAutoLoad(name, *loadOnStartup)
	}

	return nil
}

// CreateWallet creates a new wallet.
func (m *Manager) CreateWallet(name string, opts CreateWalletOpts) (*Wallet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate name
	if name == "" {
		return nil, ErrInvalidWalletName
	}
	if !isValidWalletName(name) {
		return nil, ErrInvalidWalletName
	}

	// Check if already loaded
	if _, exists := m.wallets[name]; exists {
		return nil, ErrWalletAlreadyLoaded
	}

	// Check limit
	if len(m.wallets) >= MaxLoadedWallets {
		return nil, ErrTooManyWallets
	}

	walletPath := m.walletDir(name)

	// Check if wallet already exists on disk
	if _, err := os.Stat(filepath.Join(walletPath, "wallet.dat")); err == nil {
		return nil, ErrWalletAlreadyExists
	}

	// Create wallet directory
	if err := os.MkdirAll(walletPath, 0700); err != nil {
		return nil, err
	}

	// Create wallet
	config := WalletConfig{
		DataDir:     walletPath,
		Network:     m.network,
		ChainParams: m.chainParams,
		AddressType: AddressTypeP2WPKH,
	}

	w := NewWallet(config)
	w.name = name
	// The createwallet passphrase is the wallet's envelope password from birth;
	// every later save path (auto-flush, unload, backup) re-uses it via
	// w.savePassword instead of a hardcoded "".
	w.savePassword = opts.Passphrase
	// Persist the watch-only flag (Core WALLET_FLAG_DISABLE_PRIVATE_KEYS):
	// importprivkey / private-key descriptor imports are refused with -4 and
	// getwalletinfo reports private_keys_enabled=false, also after reload.
	w.disablePrivateKeys = opts.DisablePrivateKeys

	// Initialize with keys unless blank wallet requested
	if !opts.Blank && !opts.DisablePrivateKeys {
		// Either RESTORE from a caller-supplied BIP-39 mnemonic (deterministic
		// seed-only recovery — same words always re-derive byte-identical keys
		// and addresses, mirroring Bitcoin Core's createwallet+sethdseed restore
		// flow), or generate a fresh random mnemonic when none was supplied.
		// CreateFromMnemonic validates the words+checksum and returns
		// ErrInvalidMnemonic on a bad phrase.
		mnemonic := opts.Mnemonic
		if mnemonic == "" {
			var err error
			mnemonic, err = GenerateMnemonic()
			if err != nil {
				return nil, err
			}
		}
		// W161 BUG-16 fix: pass the BIP-39 seed passphrase (NOT the wallet-
		// file passphrase) through to PBKDF2. opts.SeedPassphrase=="" matches
		// the legacy behaviour (no plausible-deniability passphrase); a
		// non-empty value derives a completely different seed per BIP-39
		// §"From mnemonic to seed", giving Trezor/Ledger-style "25th word"
		// support. NFKD-normalisation is applied inside MnemonicToSeed.
		if err := w.CreateFromMnemonic(mnemonic, opts.SeedPassphrase); err != nil {
			return nil, err
		}
	}

	// Save to disk (under the wallet's envelope password).
	if err := w.Save(); err != nil {
		return nil, err
	}

	m.wallets[name] = w

	// Manager-created wallets get save-on-mutation durability immediately
	// (pre-fix they persisted only at unload/backup).
	w.StartAutoFlush(DefaultAutoFlushInterval)

	// Update auto-load preference
	if opts.LoadOnStartup != nil {
		m.updateAutoLoad(name, *opts.LoadOnStartup)
	}

	return w, nil
}

// GetWallet returns a loaded wallet by name.
func (m *Manager) GetWallet(name string) (*Wallet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w, exists := m.wallets[name]
	if !exists {
		return nil, ErrWalletNotFound
	}
	return w, nil
}

// GetDefaultWallet returns the single loaded wallet if exactly one is loaded,
// or returns an error if zero or multiple wallets are loaded.
func (m *Manager) GetDefaultWallet() (*Wallet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.wallets) == 0 {
		return nil, ErrWalletNotFound
	}
	if len(m.wallets) > 1 {
		return nil, ErrMultipleWalletsNamed
	}

	// Return the single wallet
	for _, w := range m.wallets {
		return w, nil
	}
	return nil, ErrWalletNotFound
}

// ListWallets returns the names of all loaded wallets.
func (m *Manager) ListWallets() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.wallets))
	for name := range m.wallets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListWalletDir returns information about all wallets on disk.
func (m *Manager) ListWalletDir() []WalletInfo {
	walletsDir := filepath.Join(m.dataDir, "wallets")

	var wallets []WalletInfo

	// Check for default wallet
	defaultWalletPath := filepath.Join(walletsDir, "wallet.dat")
	if _, err := os.Stat(defaultWalletPath); err == nil {
		wallets = append(wallets, WalletInfo{
			Name: "",
			Path: walletsDir,
		})
	}

	// List subdirectories
	entries, err := os.ReadDir(walletsDir)
	if err != nil {
		return wallets
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		walletPath := filepath.Join(walletsDir, name, "wallet.dat")
		if _, err := os.Stat(walletPath); err == nil {
			wallets = append(wallets, WalletInfo{
				Name: name,
				Path: filepath.Join(walletsDir, name),
			})
		}
	}

	return wallets
}

// ScanBlock scans a block for transactions relevant to all loaded wallets.
func (m *Manager) ScanBlock(block *wire.MsgBlock, height int32) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, w := range m.wallets {
		w.ScanBlock(block, height)
	}
}

// UnscanBlock reverses the credits of a block across all loaded wallets when
// that block leaves the active chain (reorg disconnect). Symmetric counterpart
// to ScanBlock; see Wallet.UnscanBlock for the best-effort semantics.
func (m *Manager) UnscanBlock(block *wire.MsgBlock, height int32) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, w := range m.wallets {
		w.UnscanBlock(block, height)
	}
}

// SaveAll saves all loaded wallets to disk.
func (m *Manager) SaveAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for _, w := range m.wallets {
		// Each wallet saves under its OWN envelope password (never "").
		if err := w.Save(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// BackupWallet copies a wallet to a destination path.
func (m *Manager) BackupWallet(name, destination string) error {
	m.mu.RLock()
	w, exists := m.wallets[name]
	m.mu.RUnlock()

	if !exists {
		return ErrWalletNotFound
	}

	// Ensure wallet is saved first — under its CURRENT envelope password
	// (a literal "" here used to strip the passphrase protection of the
	// backed-up copy AND of the live wallet.dat itself).
	if err := w.Save(); err != nil {
		return err
	}

	// Copy wallet file
	src := filepath.Join(w.config.DataDir, "wallet.dat")
	srcData, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(destination, srcData, 0600)
}

// AutoLoadWallets returns the list of wallet names configured to auto-load.
func (m *Manager) AutoLoadWallets() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.autoLoad...)
}

// SetAutoLoadWallets sets the list of wallets to auto-load.
func (m *Manager) SetAutoLoadWallets(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoLoad = append([]string{}, names...)
}

// updateAutoLoad adds or removes a wallet from the auto-load list.
func (m *Manager) updateAutoLoad(name string, add bool) {
	idx := -1
	for i, n := range m.autoLoad {
		if n == name {
			idx = i
			break
		}
	}

	if add {
		if idx == -1 {
			m.autoLoad = append(m.autoLoad, name)
		}
	} else {
		if idx >= 0 {
			m.autoLoad = append(m.autoLoad[:idx], m.autoLoad[idx+1:]...)
		}
	}
}

// isValidWalletName checks if a wallet name is valid.
func isValidWalletName(name string) bool {
	// Empty name is allowed (default wallet)
	if name == "" {
		return true
	}

	// Disallow path traversal
	if strings.Contains(name, "..") {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}

	// Disallow special characters
	for _, c := range name {
		if c < 32 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
			return false
		}
	}

	return true
}
