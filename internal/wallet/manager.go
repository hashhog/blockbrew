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
type CreateWalletOpts struct {
	DisablePrivateKeys bool   // Create watch-only wallet
	Blank              bool   // Create without keys
	Passphrase         string // Wallet encryption passphrase
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

// LoadWallet loads an existing wallet from disk.
func (m *Manager) LoadWallet(name string, loadOnStartup *bool) (*Wallet, error) {
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

	w, err := LoadFromFile(walletPath, "", config)
	if err != nil {
		return nil, err
	}

	// Set wallet name
	w.name = name

	m.wallets[name] = w

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

	// Save wallet state before unloading
	if err := w.SaveToFile(""); err != nil {
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

	// Initialize with keys unless blank wallet requested
	if !opts.Blank && !opts.DisablePrivateKeys {
		// Generate new mnemonic and initialize wallet
		mnemonic, err := GenerateMnemonic()
		if err != nil {
			return nil, err
		}
		if err := w.CreateFromMnemonic(mnemonic, ""); err != nil {
			return nil, err
		}
	}

	// Save to disk
	if err := w.SaveToFile(opts.Passphrase); err != nil {
		return nil, err
	}

	m.wallets[name] = w

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

// SaveAll saves all loaded wallets to disk.
func (m *Manager) SaveAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for _, w := range m.wallets {
		if err := w.SaveToFile(""); err != nil {
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

	// Ensure wallet is saved first
	if err := w.SaveToFile(""); err != nil {
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
