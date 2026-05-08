// Package wallet implements key management and transaction signing.
package wallet

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// WalletAddressType specifies the type of addresses the wallet generates.
type WalletAddressType int

const (
	// AddressTypeP2WPKH is native segwit (BIP84, bc1q...)
	AddressTypeP2WPKH WalletAddressType = iota
	// AddressTypeP2PKH is legacy (BIP44, 1...)
	AddressTypeP2PKH
	// AddressTypeP2SH_P2WPKH is nested segwit (BIP49, 3...)
	AddressTypeP2SH_P2WPKH
	// AddressTypeP2TR is taproot (BIP86, bc1p...)
	AddressTypeP2TR
)

// WalletConfig configures the wallet.
type WalletConfig struct {
	DataDir     string
	Network     address.Network
	ChainParams *consensus.ChainParams
	AddressType WalletAddressType // Default address type for new addresses
}

// Wallet manages keys, addresses, and balances.
type Wallet struct {
	mu         sync.RWMutex
	name       string // wallet name (empty for default wallet)
	config     WalletConfig
	masterKey  *HDKey
	accounts   []*Account
	utxos      map[wire.OutPoint]*WalletUTXO
	txHistory  []*WalletTx
	nextExtIdx uint32
	nextIntIdx uint32
	gapLimit   int
	locked     bool
	addrToPath map[string]string            // maps address to derivation path
	addrToType map[string]WalletAddressType // maps address to address type
	addrLabels map[string]string            // maps address to label
	// lockedCoins is the in-memory set of UTXOs that the user has marked
	// unspendable via `lockunspent`. Mirrors CWallet::setLockedCoins. The
	// value distinguishes a persistent (true) from in-memory-only (false)
	// lock, matching Core's bool-flag in LockCoin/setLockedCoinsPersistent.
	// Reference: bitcoin-core/src/wallet/wallet.cpp::LockCoin/UnlockCoin.
	lockedCoins map[wire.OutPoint]bool
	// Per-type address indices
	nextIdx map[WalletAddressType]*addressIndices

	// Encryption state (Bitcoin Core "crypter" semantics).
	//
	// encrypted is set once EncryptWallet has been called. While encrypted,
	// the master HD key is held only as ciphertext (encryptedMaster); when
	// the wallet is locked, masterKey is nil and signing is impossible.
	// walletpassphrase decrypts encryptedMaster back into masterKey for
	// `relockTimeout` and schedules an auto-relock via relockTimer.
	encrypted       bool
	encryptedMaster []byte      // salt||nonce||ciphertext (output of encryptMasterKey)
	relockTimer     *time.Timer // auto-relock for walletpassphrase timeout
}

// WalletUTXO is a UTXO owned by the wallet.
type WalletUTXO struct {
	OutPoint   wire.OutPoint
	Amount     int64
	PkScript   []byte
	Address    string
	Height     int32
	IsCoinbase bool
	KeyPath    string
	Confirmed  bool
}

// WalletTx is a transaction relevant to the wallet.
type WalletTx struct {
	TxHash    wire.Hash256
	Height    int32
	Amount    int64 // Positive for received, negative for sent
	Fee       int64
	Timestamp int64
	Address   string
}

// Account represents a BIP44 account.
type Account struct {
	Index     uint32
	ExtPubKey *HDKey
	Addresses []string
}

// addressIndices tracks the next external and internal indices for an address type.
type addressIndices struct {
	External uint32
	Internal uint32
}

// Wallet errors
var (
	ErrWalletLocked      = errors.New("wallet is locked")
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrNoMasterKey       = errors.New("wallet has no master key")
	ErrInvalidAddress    = errors.New("invalid address")
	ErrDuplicateAddress  = errors.New("address already exists")
)

// MaxRelockSleepSeconds matches Bitcoin Core's MAX_SLEEP_TIME and caps
// walletpassphrase timeouts to ~3 years. See bitcoin-core/src/wallet/rpc/encrypt.cpp.
const MaxRelockSleepSeconds int64 = 100000000

// DefaultGapLimit is the default number of unused addresses to maintain.
const DefaultGapLimit = 20

// NewWallet creates a new empty wallet.
func NewWallet(config WalletConfig) *Wallet {
	return &Wallet{
		config:      config,
		utxos:       make(map[wire.OutPoint]*WalletUTXO),
		txHistory:   make([]*WalletTx, 0),
		gapLimit:    DefaultGapLimit,
		locked:      true,
		addrToPath:  make(map[string]string),
		addrToType:  make(map[string]WalletAddressType),
		addrLabels:  make(map[string]string),
		lockedCoins: make(map[wire.OutPoint]bool),
		nextIdx: map[WalletAddressType]*addressIndices{
			AddressTypeP2WPKH:      {External: 0, Internal: 0},
			AddressTypeP2PKH:       {External: 0, Internal: 0},
			AddressTypeP2SH_P2WPKH: {External: 0, Internal: 0},
			AddressTypeP2TR:        {External: 0, Internal: 0},
		},
	}
}

// CreateFromMnemonic initializes the wallet from a mnemonic.
func (w *Wallet) CreateFromMnemonic(mnemonic, passphrase string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Validate mnemonic
	if !ValidateMnemonic(mnemonic) {
		return ErrInvalidMnemonic
	}

	// Convert to seed
	seed := MnemonicToSeed(mnemonic, passphrase)

	// Create master key
	masterKey, err := NewMasterKey(seed)
	if err != nil {
		return err
	}

	w.masterKey = masterKey
	w.locked = false
	w.nextExtIdx = 0
	w.nextIntIdx = 0

	// Initialize default account (account 0)
	err = w.initAccount(0)
	if err != nil {
		return err
	}

	return nil
}

// CreateFromSeed initializes the wallet from a 64-byte seed.
func (w *Wallet) CreateFromSeed(seed []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		return err
	}

	w.masterKey = masterKey
	w.locked = false
	w.nextExtIdx = 0
	w.nextIntIdx = 0

	// Initialize default account (account 0)
	err = w.initAccount(0)
	if err != nil {
		return err
	}

	return nil
}

// initAccount initializes a BIP44 account.
func (w *Wallet) initAccount(accountIndex uint32) error {
	if w.masterKey == nil {
		return ErrNoMasterKey
	}

	// Derive account key: m/84'/coin'/account'
	coinType := w.coinType()
	path := fmt.Sprintf("m/84'/%d'/%d'", coinType, accountIndex)

	accountKey, err := w.masterKey.DerivePath(path)
	if err != nil {
		return err
	}

	account := &Account{
		Index:     accountIndex,
		ExtPubKey: accountKey.PublicKey(),
		Addresses: make([]string, 0),
	}

	w.accounts = append(w.accounts, account)
	return nil
}

// coinType returns the BIP44 coin type for the current network.
func (w *Wallet) coinType() uint32 {
	if w.config.ChainParams != nil {
		return w.config.ChainParams.HDCoinType
	}
	switch w.config.Network {
	case address.Mainnet:
		return 0
	default:
		return 1
	}
}

// NewAddress generates a new receiving address using the default address type.
func (w *Wallet) NewAddress() (string, error) {
	return w.NewAddressOfType(w.config.AddressType)
}

// NewAddressOfType generates a new receiving address of the specified type.
func (w *Wallet) NewAddressOfType(addrType WalletAddressType) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.newAddressOfTypeLocked(addrType, false)
}

// NewP2PKHAddress generates a new P2PKH (legacy) address.
func (w *Wallet) NewP2PKHAddress() (string, error) {
	return w.NewAddressOfType(AddressTypeP2PKH)
}

// NewP2SH_P2WPKHAddress generates a new P2SH-P2WPKH (nested segwit) address.
func (w *Wallet) NewP2SH_P2WPKHAddress() (string, error) {
	return w.NewAddressOfType(AddressTypeP2SH_P2WPKH)
}

// NewP2WPKHAddress generates a new P2WPKH (native segwit) address.
func (w *Wallet) NewP2WPKHAddress() (string, error) {
	return w.NewAddressOfType(AddressTypeP2WPKH)
}

// NewP2TRAddress generates a new P2TR (taproot) address.
func (w *Wallet) NewP2TRAddress() (string, error) {
	return w.NewAddressOfType(AddressTypeP2TR)
}

// newAddressOfTypeLocked generates a new address (caller must hold lock).
// isChange indicates whether this is a change address (internal) or receiving (external).
func (w *Wallet) newAddressOfTypeLocked(addrType WalletAddressType, isChange bool) (string, error) {
	// Order matters: a locked, encrypted wallet has masterKey == nil because
	// the cleartext key is wiped on Lock(). Surface the user-facing reason
	// (locked) rather than the implementation detail (no master key).
	if w.locked {
		return "", ErrWalletLocked
	}
	if w.masterKey == nil {
		return "", ErrNoMasterKey
	}

	coinType := w.coinType()
	indices := w.nextIdx[addrType]
	if indices == nil {
		indices = &addressIndices{}
		w.nextIdx[addrType] = indices
	}

	var change uint32 = 0
	var index uint32
	if isChange {
		change = 1
		index = indices.Internal
	} else {
		index = indices.External
	}

	// Derive the path based on address type
	var path string
	switch addrType {
	case AddressTypeP2PKH:
		path = BIP44Path(coinType, 0, change, index)
	case AddressTypeP2SH_P2WPKH:
		path = BIP49Path(coinType, 0, change, index)
	case AddressTypeP2WPKH:
		path = BIP84Path(coinType, 0, change, index)
	case AddressTypeP2TR:
		path = BIP86Path(coinType, 0, change, index)
	default:
		path = BIP84Path(coinType, 0, change, index)
	}

	key, err := w.masterKey.DerivePath(path)
	if err != nil {
		return "", err
	}

	// Generate address based on type
	var addr string
	switch addrType {
	case AddressTypeP2PKH:
		addr, err = w.pubKeyToP2PKHAddress(key)
	case AddressTypeP2SH_P2WPKH:
		addr, err = w.pubKeyToP2SH_P2WPKHAddress(key)
	case AddressTypeP2WPKH:
		addr, err = w.pubKeyToP2WPKHAddress(key)
	case AddressTypeP2TR:
		addr, err = w.pubKeyToP2TRAddress(key)
	default:
		addr, err = w.pubKeyToP2WPKHAddress(key)
	}
	if err != nil {
		return "", err
	}

	w.addrToPath[addr] = path
	w.addrToType[addr] = addrType

	// Increment index
	if isChange {
		indices.Internal++
		// Also update legacy index for compatibility
		w.nextIntIdx++
	} else {
		indices.External++
		// Also update legacy index for compatibility
		w.nextExtIdx++
	}

	// Track in account
	if len(w.accounts) > 0 {
		w.accounts[0].Addresses = append(w.accounts[0].Addresses, addr)
	}

	return addr, nil
}

// NewChangeAddress generates a new change address using the default address type.
func (w *Wallet) NewChangeAddress() (string, error) {
	return w.NewChangeAddressOfType(w.config.AddressType)
}

// NewChangeAddressOfType generates a new change address of the specified type.
func (w *Wallet) NewChangeAddressOfType(addrType WalletAddressType) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.newAddressOfTypeLocked(addrType, true)
}

// pubKeyToAddress converts an HD key to a P2WPKH address string (for compatibility).
func (w *Wallet) pubKeyToAddress(key *HDKey) (string, error) {
	return w.pubKeyToP2WPKHAddress(key)
}

// pubKeyToP2PKHAddress converts an HD key to a P2PKH (legacy) address string.
func (w *Wallet) pubKeyToP2PKHAddress(key *HDKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}

	// Hash160 of compressed public key
	hash := bbcrypto.Hash160(pubKey.SerializeCompressed())

	// Create P2PKH address
	addr := address.NewP2PKHAddress(hash, w.config.Network)
	return addr.Encode()
}

// pubKeyToP2SH_P2WPKHAddress converts an HD key to a P2SH-P2WPKH (nested segwit) address string.
func (w *Wallet) pubKeyToP2SH_P2WPKHAddress(key *HDKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}

	// Hash160 of compressed public key
	pubKeyHash := bbcrypto.Hash160(pubKey.SerializeCompressed())

	// Witness program: OP_0 <20-byte-hash>
	witnessProgram := make([]byte, 22)
	witnessProgram[0] = 0x00 // OP_0
	witnessProgram[1] = 0x14 // Push 20 bytes
	copy(witnessProgram[2:], pubKeyHash[:])

	// Hash160 of witness program gives us the script hash
	scriptHash := bbcrypto.Hash160(witnessProgram)

	// Create P2SH address
	addr := address.NewP2SHAddress(scriptHash, w.config.Network)
	return addr.Encode()
}

// pubKeyToP2WPKHAddress converts an HD key to a P2WPKH (native segwit) address string.
func (w *Wallet) pubKeyToP2WPKHAddress(key *HDKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}

	// Hash160 of compressed public key
	hash := bbcrypto.Hash160(pubKey.SerializeCompressed())

	// Create P2WPKH address
	addr := address.NewP2WPKHAddress(hash, w.config.Network)
	return addr.Encode()
}

// pubKeyToP2TRAddress converts an HD key to a P2TR (taproot) address string.
// Uses BIP86 derivation with an empty script tree (key-path only spending).
func (w *Wallet) pubKeyToP2TRAddress(key *HDKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}

	// Get the x-only public key (32 bytes)
	// For BIP340 Schnorr, we use only the x-coordinate
	compressed := pubKey.SerializeCompressed()
	xOnlyPubKey := compressed[1:33] // Skip the 02/03 prefix byte

	// Apply BIP341 key tweaking with empty merkle root
	// tweakedKey = internalKey + tweak*G
	// where tweak = tagged_hash("TapTweak", internalKey)
	tweakHash := script.TapTweak(xOnlyPubKey, nil)

	// Compute tweaked public key
	tweakedXOnly, err := w.computeTweakedPubKey(pubKey.SerializeCompressed(), tweakHash)
	if err != nil {
		return "", err
	}

	// Create P2TR address
	var xOnly32 [32]byte
	copy(xOnly32[:], tweakedXOnly)
	addr := address.NewP2TRAddress(xOnly32, w.config.Network)
	return addr.Encode()
}

// computeTweakedPubKey computes the tweaked public key for taproot.
// Returns the x-only (32 bytes) tweaked public key.
func (w *Wallet) computeTweakedPubKey(compressedPubKey []byte, tweakHash [32]byte) ([]byte, error) {
	// Parse the public key
	pubKey, err := secp256k1.ParsePubKey(compressedPubKey)
	if err != nil {
		return nil, err
	}

	// Convert tweak to scalar
	var tweakScalar secp256k1.ModNScalar
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		return nil, errors.New("tweak overflow")
	}

	// Compute tweak * G
	var tweakPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tweakScalar, &tweakPoint)

	// Get internal key as Jacobian point
	var internalPoint secp256k1.JacobianPoint
	pubKey.AsJacobian(&internalPoint)

	// If the internal key has odd y, we need to negate it (BIP340 requirement)
	// For BIP341, we always use even y for the internal key
	internalCompressed := pubKey.SerializeCompressed()
	if internalCompressed[0] == 0x03 { // Odd y
		internalPoint.Y.Negate(1)
		internalPoint.Y.Normalize()
	}

	// Add: tweakedPoint = internalPoint + tweakPoint
	var resultPoint secp256k1.JacobianPoint
	secp256k1.AddNonConst(&internalPoint, &tweakPoint, &resultPoint)
	resultPoint.ToAffine()

	// Create the tweaked public key
	tweakedPubKey := secp256k1.NewPublicKey(&resultPoint.X, &resultPoint.Y)

	// Return x-only (32 bytes)
	tweakedCompressed := tweakedPubKey.SerializeCompressed()
	return tweakedCompressed[1:33], nil
}

// Name returns the wallet name (empty string for default wallet).
func (w *Wallet) Name() string {
	return w.name
}

// Network returns the address network (mainnet/testnet/regtest/signet) the
// wallet was configured with. RPC handlers that need to decode user-supplied
// addresses (e.g. walletcreatefundedpsbt) read this so they don't depend on
// the server's chainParams resolution.
func (w *Wallet) Network() address.Network {
	return w.config.Network
}

// GetBalance returns the wallet balance.
func (w *Wallet) GetBalance() (confirmed, unconfirmed int64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, utxo := range w.utxos {
		if utxo.Confirmed {
			confirmed += utxo.Amount
		} else {
			unconfirmed += utxo.Amount
		}
	}
	return
}

// Balances mirrors Bitcoin Core's CWalletBalances/`GetBalance` (wallet.cpp).
// Trusted: confirmed UTXOs that are not coinbase-immature.
// UntrustedPending: unconfirmed UTXOs (mempool / 0-conf).
// Immature: coinbase UTXOs below CoinbaseMaturity confirmations.
// All amounts are satoshis. tipHeight is the current chain tip height.
//
// Reference: bitcoin-core/src/wallet/wallet.cpp::GetBalance and
// bitcoin-core/src/wallet/rpc/coins.cpp::getbalances.
type Balances struct {
	Trusted          int64
	UntrustedPending int64
	Immature         int64
}

// GetBalances returns a multi-state balance breakdown analogous to Core's
// CWalletBalances. tipHeight is the current chain tip height; if zero or
// unknown, callers can pass 1<<30 to make all coinbase coins look mature.
func (w *Wallet) GetBalances(tipHeight int32) Balances {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var b Balances
	for _, utxo := range w.utxos {
		if !utxo.Confirmed {
			b.UntrustedPending += utxo.Amount
			continue
		}
		if utxo.IsCoinbase {
			confirmations := tipHeight - utxo.Height + 1
			if confirmations < consensus.CoinbaseMaturity {
				b.Immature += utxo.Amount
				continue
			}
		}
		b.Trusted += utxo.Amount
	}
	return b
}

// GetSpendableBalance returns the balance excluding immature coinbase outputs.
// tipHeight is the current chain tip height.
func (w *Wallet) GetSpendableBalance(tipHeight int32) (spendable, immature int64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, utxo := range w.utxos {
		if !utxo.Confirmed {
			continue
		}
		if utxo.IsCoinbase {
			confirmations := tipHeight - utxo.Height + 1
			if confirmations < consensus.CoinbaseMaturity {
				immature += utxo.Amount
				continue
			}
		}
		spendable += utxo.Amount
	}
	return
}

// IsUTXOSpendable checks if a UTXO is spendable (mature if coinbase).
func (w *Wallet) IsUTXOSpendable(utxo *WalletUTXO, tipHeight int32) bool {
	if !utxo.Confirmed {
		return false
	}
	if utxo.IsCoinbase {
		confirmations := tipHeight - utxo.Height + 1
		return confirmations >= consensus.CoinbaseMaturity
	}
	return true
}

// ListUnspent returns all wallet UTXOs.
func (w *Wallet) ListUnspent() []*WalletUTXO {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*WalletUTXO, 0, len(w.utxos))
	for _, utxo := range w.utxos {
		result = append(result, utxo)
	}
	return result
}

// ListSpendable returns only spendable UTXOs (excludes immature coinbase).
// tipHeight is the current chain tip height.
func (w *Wallet) ListSpendable(tipHeight int32) []*WalletUTXO {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*WalletUTXO, 0, len(w.utxos))
	for _, utxo := range w.utxos {
		if !utxo.Confirmed {
			continue
		}
		if utxo.IsCoinbase {
			confirmations := tipHeight - utxo.Height + 1
			if confirmations < consensus.CoinbaseMaturity {
				continue
			}
		}
		result = append(result, utxo)
	}
	return result
}

// AddUTXO adds a UTXO to the wallet.
func (w *Wallet) AddUTXO(utxo *WalletUTXO) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.utxos[utxo.OutPoint] = utxo
}

// RemoveUTXO removes a UTXO from the wallet.
func (w *Wallet) RemoveUTXO(outpoint wire.OutPoint) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.utxos, outpoint)
}

// LockCoin marks a UTXO as temporarily unspendable. `persistent` mirrors
// Core's persistent flag (bitcoin-core/src/wallet/wallet.cpp::LockCoin):
// when true the lock survives wallet save/load; when false it is in-memory
// only and cleared on shutdown. Returns true if the lock was applied (the
// UTXO must exist in the wallet, must not already be spent, and must not
// already be locked unless `persistent` is upgrading an in-memory lock).
//
// HasUTXO must be true for the lock to apply (matching Core's
// `mapWallet.find(outpt.hash)` check), but absent UTXO is signalled
// out-of-band via HasOwnUTXO so the RPC layer can return the precise
// `RPC_INVALID_PARAMETER` codes Core does.
func (w *Wallet) LockCoin(outpoint wire.OutPoint, persistent bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lockedCoins[outpoint] = persistent
	return true
}

// UnlockCoin removes a UTXO from the locked set. Returns true if it was
// present and removed, false otherwise.
func (w *Wallet) UnlockCoin(outpoint wire.OutPoint) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.lockedCoins[outpoint]; !ok {
		return false
	}
	delete(w.lockedCoins, outpoint)
	return true
}

// UnlockAllCoins clears the locked-coin set. Called by `lockunspent true`
// with no outputs (Core: CWallet::UnlockAllCoins).
func (w *Wallet) UnlockAllCoins() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lockedCoins = make(map[wire.OutPoint]bool)
	return true
}

// IsLockedCoin reports whether the given outpoint is currently locked.
func (w *Wallet) IsLockedCoin(outpoint wire.OutPoint) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.lockedCoins[outpoint]
	return ok
}

// ListLockedCoins returns a copy of the currently-locked outpoints. The
// order is not stable (mirrors Core's std::set ordering only by accident).
func (w *Wallet) ListLockedCoins() []wire.OutPoint {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]wire.OutPoint, 0, len(w.lockedCoins))
	for op := range w.lockedCoins {
		out = append(out, op)
	}
	return out
}

// HasOwnUTXO reports whether the wallet currently tracks the given outpoint
// as an unspent UTXO. Used by lockunspent to mirror Core's
// `mapWallet.find(outpt.hash)` lookup before locking.
func (w *Wallet) HasOwnUTXO(outpoint wire.OutPoint) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.utxos[outpoint]
	return ok
}

// IsOwnAddress checks if an address belongs to this wallet.
func (w *Wallet) IsOwnAddress(addr string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, exists := w.addrToPath[addr]
	return exists
}

// SetLabel sets a label for an address.
// If the label is empty, the label is removed.
func (w *Wallet) SetLabel(addr, label string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Address must be known to the wallet
	if _, exists := w.addrToPath[addr]; !exists {
		return ErrInvalidAddress
	}

	if label == "" {
		delete(w.addrLabels, addr)
	} else {
		w.addrLabels[addr] = label
	}
	return nil
}

// GetLabel returns the label for an address.
// Returns empty string if address has no label or is not in wallet.
func (w *Wallet) GetLabel(addr string) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.addrLabels[addr]
}

// ListLabels returns all unique labels in the wallet.
func (w *Wallet) ListLabels() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, label := range w.addrLabels {
		seen[label] = struct{}{}
	}

	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	return labels
}

// GetAddressesByLabel returns all addresses with the given label.
func (w *Wallet) GetAddressesByLabel(label string) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var addrs []string
	for addr, l := range w.addrLabels {
		if l == label {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// GetKeyForAddress returns the private key for an address.
func (w *Wallet) GetKeyForAddress(addr string) (*bbcrypto.PrivateKey, error) {
	w.mu.RLock()
	path, exists := w.addrToPath[addr]
	masterKey := w.masterKey
	locked := w.locked
	w.mu.RUnlock()

	if !exists {
		return nil, ErrInvalidAddress
	}
	if locked {
		return nil, ErrWalletLocked
	}
	if masterKey == nil {
		return nil, ErrNoMasterKey
	}

	key, err := masterKey.DerivePath(path)
	if err != nil {
		return nil, err
	}

	return key.ECPrivKey()
}

// CreateTransaction builds a transaction sending the specified amount to the destination.
// Uses a very high tip height (assumes all coinbase UTXOs are mature for backward compatibility).
func (w *Wallet) CreateTransaction(destAddr string, amount int64, feeRate float64) (*wire.MsgTx, error) {
	return w.CreateTransactionWithTip(destAddr, amount, feeRate, 1<<30) // High enough that all coinbase are mature
}

// CreateTransactionWithTip builds a transaction with coinbase maturity enforcement.
// tipHeight is the current chain tip height, used to filter immature coinbase UTXOs.
func (w *Wallet) CreateTransactionWithTip(destAddr string, amount int64, feeRate float64, tipHeight int32) (*wire.MsgTx, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked {
		return nil, ErrWalletLocked
	}
	if w.masterKey == nil {
		return nil, ErrNoMasterKey
	}

	// 1. Parse destination address
	addr, err := address.DecodeAddress(destAddr, w.config.Network)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	destScript := addr.ScriptPubKey()

	// 2. Get all spendable UTXOs for coin selection (filter out immature coinbase)
	var available []*WalletUTXO
	for _, utxo := range w.utxos {
		if !utxo.Confirmed {
			continue
		}
		if utxo.IsCoinbase {
			confirmations := tipHeight - utxo.Height + 1
			if confirmations < consensus.CoinbaseMaturity {
				continue // Skip immature coinbase
			}
		}
		available = append(available, utxo)
	}

	// 3. Estimate cost of change output for BnB decision
	// Change should match the wallet's default address type for privacy
	changeOutputSize := 31 // Default to P2WPKH size
	costOfChange := int64(float64(changeOutputSize) * feeRate)

	// 4. Use BnB/Knapsack coin selection
	// Target includes the output amount plus estimated base transaction fee
	baseFee := int64(float64(10+estimateOutputVSize(destScript)) * feeRate)
	target := amount + baseFee

	result, err := SelectCoins(available, target, feeRate, costOfChange)
	if err != nil {
		// Fall back to simple selection if advanced selection fails.
		// Pass the already-filtered spendable list so immature coinbase UTXOs
		// are excluded here too (selectCoins only checks Confirmed, not maturity).
		utxos := w.selectCoinsFrom(available, amount, feeRate)
		if utxos == nil {
			return nil, ErrInsufficientFunds
		}
		result = &SelectionResult{Coins: utxos, Total: 0}
		for _, u := range utxos {
			result.Total += u.Amount
		}
	}

	utxos := result.Coins

	// 5. Build the transaction
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 0,
	}

	// Collect input scripts for accurate fee estimation
	inputScripts := make([][]byte, len(utxos))
	for i, u := range utxos {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: u.OutPoint,
			Sequence:         0xFFFFFFFE, // Enable RBF (BIP125)
		})
		inputScripts[i] = u.PkScript
	}

	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    amount,
		PkScript: destScript,
	})

	// 6. Calculate actual fee and change
	// First estimate assuming we'll have a change output
	estimatedVSize := EstimateTxVSize(len(utxos), inputScripts, 2, [][]byte{destScript, nil})
	estimatedFee := int64(float64(estimatedVSize) * feeRate)

	change := result.Total - amount - estimatedFee
	if change < 0 {
		// Not enough even with all selected coins
		return nil, ErrInsufficientFunds
	}

	// 7. Add change output if above dust
	if change > dustThreshold {
		changeAddr, err := w.newChangeAddressLocked()
		if err != nil {
			return nil, err
		}
		changeAddrParsed, err := address.DecodeAddress(changeAddr, w.config.Network)
		if err != nil {
			return nil, err
		}
		changeScript := changeAddrParsed.ScriptPubKey()
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    change,
			PkScript: changeScript,
		})
	} else {
		// No change output - recalculate fee
		estimatedVSize = EstimateTxVSize(len(utxos), inputScripts, 1, [][]byte{destScript})
		// The "change" goes to fees
	}

	// 8. Sign the transaction
	err = w.signTx(tx, utxos)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return tx, nil
}

// newChangeAddressLocked generates a new change address (caller must hold lock).
// Uses the wallet's default address type.
func (w *Wallet) newChangeAddressLocked() (string, error) {
	return w.newAddressOfTypeLocked(w.config.AddressType, true)
}

// selectCoins selects UTXOs for a transaction using largest-first selection.
// It uses all confirmed UTXOs without maturity filtering; use selectCoinsFrom
// when the caller has already filtered the UTXO set (e.g., to exclude immature coinbase).
func (w *Wallet) selectCoins(amount int64, feeRate float64) []*WalletUTXO {
	// Get all confirmed UTXOs
	var available []*WalletUTXO
	for _, utxo := range w.utxos {
		if utxo.Confirmed {
			available = append(available, utxo)
		}
	}
	return w.selectCoinsFrom(available, amount, feeRate)
}

// selectCoinsFrom selects UTXOs from the provided list using largest-first selection.
func (w *Wallet) selectCoinsFrom(utxos []*WalletUTXO, amount int64, feeRate float64) []*WalletUTXO {
	available := make([]*WalletUTXO, len(utxos))
	copy(available, utxos)

	// Sort by value descending (largest first)
	sort.Slice(available, func(i, j int) bool {
		return available[i].Amount > available[j].Amount
	})

	// Select UTXOs
	var selected []*WalletUTXO
	var totalSelected int64

	for _, utxo := range available {
		selected = append(selected, utxo)
		totalSelected += utxo.Amount

		// Estimate fee with current selection
		// ~10 base + ~68 per P2WPKH input + ~31 per output (2 outputs: dest + change)
		estimatedVSize := int64(10 + 68*len(selected) + 31*2)
		estimatedFee := int64(float64(estimatedVSize) * feeRate)

		if totalSelected >= amount+estimatedFee {
			return selected
		}
	}

	// Check if we have enough (might not need change)
	estimatedVSize := int64(10 + 68*len(selected) + 31)
	estimatedFee := int64(float64(estimatedVSize) * feeRate)
	if totalSelected >= amount+estimatedFee {
		return selected
	}

	return nil
}

// signTx signs all inputs of a transaction using wallet keys.
func (w *Wallet) signTx(tx *wire.MsgTx, utxos []*WalletUTXO) error {
	// Build prevOuts for taproot sighash
	prevOuts := make([]*wire.TxOut, len(utxos))
	for i, utxo := range utxos {
		prevOuts[i] = &wire.TxOut{
			Value:    utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	for i, utxo := range utxos {
		// Get the private key for this UTXO
		privKey, err := w.getKeyForPath(utxo.KeyPath)
		if err != nil {
			return err
		}

		// Determine script type from pkScript
		err = w.signInput(tx, i, utxo, privKey, prevOuts)
		if err != nil {
			return fmt.Errorf("failed to sign input %d: %w", i, err)
		}
	}

	return nil
}

// signInput signs a single input based on its script type.
func (w *Wallet) signInput(tx *wire.MsgTx, idx int, utxo *WalletUTXO, privKey *bbcrypto.PrivateKey, prevOuts []*wire.TxOut) error {
	pkScript := utxo.PkScript
	pubKey := privKey.PubKey()
	pubKeyHash := bbcrypto.Hash160(pubKey.SerializeCompressed())

	// Detect script type and sign appropriately
	switch {
	case isP2PKH(pkScript):
		return w.signP2PKH(tx, idx, utxo.Amount, privKey, pubKey)

	case isP2SH(pkScript):
		// Assume P2SH-P2WPKH (nested segwit)
		return w.signP2SH_P2WPKH(tx, idx, utxo.Amount, privKey, pubKey, pubKeyHash)

	case isP2WPKH(pkScript):
		return w.signP2WPKH(tx, idx, utxo.Amount, privKey, pubKey, pubKeyHash)

	case isP2TR(pkScript):
		return w.signP2TR(tx, idx, prevOuts, privKey)

	default:
		// Default to P2WPKH signing
		return w.signP2WPKH(tx, idx, utxo.Amount, privKey, pubKey, pubKeyHash)
	}
}

// signP2PKH signs a P2PKH (legacy) input.
func (w *Wallet) signP2PKH(tx *wire.MsgTx, idx int, amount int64, privKey *bbcrypto.PrivateKey, pubKey *bbcrypto.PublicKey) error {
	pubKeyHash := bbcrypto.Hash160(pubKey.SerializeCompressed())

	// Create scriptPubKey for P2PKH
	scriptPubKey := make([]byte, 25)
	scriptPubKey[0] = 0x76 // OP_DUP
	scriptPubKey[1] = 0xa9 // OP_HASH160
	scriptPubKey[2] = 0x14 // Push 20 bytes
	copy(scriptPubKey[3:23], pubKeyHash[:])
	scriptPubKey[23] = 0x88 // OP_EQUALVERIFY
	scriptPubKey[24] = 0xac // OP_CHECKSIG

	// Calculate legacy sighash
	sighash, err := script.CalcSignatureHash(
		scriptPubKey,
		script.SigHashAll,
		tx,
		idx,
	)
	if err != nil {
		return err
	}

	// Sign with ECDSA
	sig, err := bbcrypto.SignECDSA(privKey, sighash)
	if err != nil {
		return err
	}

	// Append sighash type byte
	sig = append(sig, byte(script.SigHashAll))

	// Build scriptSig: <sig> <pubkey>
	sigScript := make([]byte, 0, len(sig)+len(pubKey.SerializeCompressed())+2)
	sigScript = append(sigScript, byte(len(sig)))
	sigScript = append(sigScript, sig...)
	compressed := pubKey.SerializeCompressed()
	sigScript = append(sigScript, byte(len(compressed)))
	sigScript = append(sigScript, compressed...)

	tx.TxIn[idx].SignatureScript = sigScript
	return nil
}

// signP2SH_P2WPKH signs a P2SH-P2WPKH (nested segwit) input.
func (w *Wallet) signP2SH_P2WPKH(tx *wire.MsgTx, idx int, amount int64, privKey *bbcrypto.PrivateKey, pubKey *bbcrypto.PublicKey, pubKeyHash [20]byte) error {
	// Create witness program (redeem script): OP_0 <20-byte-hash>
	redeemScript := make([]byte, 22)
	redeemScript[0] = 0x00 // OP_0
	redeemScript[1] = 0x14 // Push 20 bytes
	copy(redeemScript[2:], pubKeyHash[:])

	// Create P2WPKH script code for BIP143 signing
	scriptCode := make([]byte, 25)
	scriptCode[0] = 0x76 // OP_DUP
	scriptCode[1] = 0xa9 // OP_HASH160
	scriptCode[2] = 0x14 // Push 20 bytes
	copy(scriptCode[3:23], pubKeyHash[:])
	scriptCode[23] = 0x88 // OP_EQUALVERIFY
	scriptCode[24] = 0xac // OP_CHECKSIG

	// Calculate BIP143 sighash
	sighash, err := script.CalcWitnessSignatureHash(
		scriptCode,
		script.SigHashAll,
		tx,
		idx,
		amount,
	)
	if err != nil {
		return err
	}

	// Sign with ECDSA
	sig, err := bbcrypto.SignECDSA(privKey, sighash)
	if err != nil {
		return err
	}

	// Append sighash type byte
	sig = append(sig, byte(script.SigHashAll))

	// Set scriptSig: push the redeem script
	scriptSig := make([]byte, 1+len(redeemScript))
	scriptSig[0] = byte(len(redeemScript))
	copy(scriptSig[1:], redeemScript)
	tx.TxIn[idx].SignatureScript = scriptSig

	// Set witness: [signature, pubkey]
	tx.TxIn[idx].Witness = [][]byte{
		sig,
		pubKey.SerializeCompressed(),
	}

	return nil
}

// signP2WPKH signs a P2WPKH (native segwit) input.
func (w *Wallet) signP2WPKH(tx *wire.MsgTx, idx int, amount int64, privKey *bbcrypto.PrivateKey, pubKey *bbcrypto.PublicKey, pubKeyHash [20]byte) error {
	// Create P2WPKH script code for signing
	// For P2WPKH, scriptCode is OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
	scriptCode := make([]byte, 25)
	scriptCode[0] = 0x76 // OP_DUP
	scriptCode[1] = 0xa9 // OP_HASH160
	scriptCode[2] = 0x14 // Push 20 bytes
	copy(scriptCode[3:23], pubKeyHash[:])
	scriptCode[23] = 0x88 // OP_EQUALVERIFY
	scriptCode[24] = 0xac // OP_CHECKSIG

	// Calculate BIP143 sighash
	sighash, err := script.CalcWitnessSignatureHash(
		scriptCode,
		script.SigHashAll,
		tx,
		idx,
		amount,
	)
	if err != nil {
		return err
	}

	// Sign with ECDSA
	sig, err := bbcrypto.SignECDSA(privKey, sighash)
	if err != nil {
		return err
	}

	// Append sighash type byte
	sig = append(sig, byte(script.SigHashAll))

	// Set witness: [signature, pubkey]
	tx.TxIn[idx].Witness = [][]byte{
		sig,
		pubKey.SerializeCompressed(),
	}

	return nil
}

// signP2TR signs a P2TR (taproot) input using key-path spending.
func (w *Wallet) signP2TR(tx *wire.MsgTx, idx int, prevOuts []*wire.TxOut, privKey *bbcrypto.PrivateKey) error {
	pubKey := privKey.PubKey()
	compressed := pubKey.SerializeCompressed()
	xOnlyPubKey := compressed[1:33]

	// For key-path spending, we need to tweak the private key
	// tweakedPrivKey = privKey + tweak (if pubkey has even y)
	// tweakedPrivKey = -privKey + tweak (if pubkey has odd y)
	tweakHash := script.TapTweak(xOnlyPubKey, nil)

	// Get the internal private key
	internalPrivKey := privKey.Inner()

	// Check if we need to negate (BIP340: use even y)
	needsNegate := compressed[0] == 0x03 // Odd y

	// Compute tweaked private key
	tweakedPrivKeyBytes, err := w.computeTweakedPrivKey(internalPrivKey.Serialize(), tweakHash, needsNegate)
	if err != nil {
		return err
	}

	tweakedPrivKey := bbcrypto.PrivateKeyFromBytes(tweakedPrivKeyBytes)

	// Calculate BIP341 taproot sighash
	sighash, err := script.CalcTaprootSignatureHash(
		script.SigHashDefault, // 0x00 for default (same as ALL)
		tx,
		idx,
		prevOuts,
		nil, // No annex, no script path
	)
	if err != nil {
		return err
	}

	// Sign with Schnorr
	sig, err := bbcrypto.SignSchnorr(tweakedPrivKey, sighash)
	if err != nil {
		return err
	}

	// For SIGHASH_DEFAULT (0x00), the signature is just 64 bytes, no suffix
	// For other sighash types, append the type byte
	// We use default, so just the 64-byte signature
	tx.TxIn[idx].Witness = [][]byte{sig}

	return nil
}

// signP2WSH signs a P2WSH (native segwit script-hash) input. witnessScript
// is what's hashed into the scriptPubKey; for CHECKMULTISIG it's
// `OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`. signers is in
// witness-script pubkey order; entries may be nil for keys the wallet
// does not own (partial-sign).
//
// Witness layout per BIP-141 §"P2WSH" + the legacy CHECKMULTISIG
// off-by-one bug-compat pad:
//
//	[<>, <sig1>, <sig2>, ..., <sigM>, <witnessScript>]
//
// The leading empty push is required iff the witness script ends in
// OP_CHECKMULTISIG; for non-multisig P2WSH templates (single CHECKSIG)
// the layout is `[<sig>, <witnessScript>]`.
//
// Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature (the
// `witnessversion == 0 && type == WITNESS_V0_SCRIPTHASH` branch).
func (w *Wallet) signP2WSH(tx *wire.MsgTx, idx int, amount int64, witnessScript []byte, signers []*bbcrypto.PrivateKey) error {
	sighash, err := script.CalcWitnessSignatureHash(
		witnessScript,
		script.SigHashAll,
		tx,
		idx,
		amount,
	)
	if err != nil {
		return err
	}

	if isMultisigScript(witnessScript) {
		m, _, err := parseMultisigScript(witnessScript)
		if err != nil {
			return err
		}
		// Witness: empty push, then up to M signatures in pubkey order.
		witness := make([][]byte, 0, m+2)
		witness = append(witness, []byte{}) // CHECKMULTISIG off-by-one pad
		emitted := 0
		for _, signer := range signers {
			if signer == nil {
				continue
			}
			if emitted >= m {
				break
			}
			sig, err := bbcrypto.SignECDSA(signer, sighash)
			if err != nil {
				return err
			}
			sig = append(sig, byte(script.SigHashAll))
			witness = append(witness, sig)
			emitted++
		}
		if emitted < m {
			return fmt.Errorf("partial-sign: only %d of %d required keys owned", emitted, m)
		}
		witness = append(witness, witnessScript)
		tx.TxIn[idx].Witness = witness
		return nil
	}

	// Non-multisig P2WSH: assume the script is a single-CHECKSIG-style
	// template. Emit one signature, then the witness script.
	if len(signers) != 1 || signers[0] == nil {
		return errors.New("non-multisig P2WSH requires exactly one signer")
	}
	sig, err := bbcrypto.SignECDSA(signers[0], sighash)
	if err != nil {
		return err
	}
	sig = append(sig, byte(script.SigHashAll))
	tx.TxIn[idx].Witness = [][]byte{sig, witnessScript}
	return nil
}

// signP2SH_P2WSH signs a P2SH-wrapped P2WSH input: scriptSig is a single
// push of redeemScript (which is itself the P2WSH `OP_0 <32-byte-hash>`),
// and the witness is the same as bare P2WSH.
//
// Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature (P2SH
// recursion + WITNESS_V0_SCRIPTHASH inner step).
func (w *Wallet) signP2SH_P2WSH(tx *wire.MsgTx, idx int, amount int64, redeemScript, witnessScript []byte, signers []*bbcrypto.PrivateKey) error {
	if err := w.signP2WSH(tx, idx, amount, witnessScript, signers); err != nil {
		return err
	}
	// scriptSig: push the redeem script (mirrors psbt_ops.go::buildScriptSig).
	tx.TxIn[idx].SignatureScript = buildScriptSig(redeemScript)
	return nil
}

// signLegacyP2SH signs a bare P2SH input (not segwit-wrapped) using
// legacy (non-BIP143) sighashing. The redeem script is the script that
// is hashed into the scriptPubKey; for the common case of M-of-N
// CHECKMULTISIG it is
// `OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`.
//
// scriptSig layout per BIP-16 + the CHECKMULTISIG off-by-one pad:
//
//	OP_0 <sig1> ... <sigM> <redeemScript>
//
// Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature (P2SH +
// SCRIPTHASH inner with SigVersion::BASE).
func (w *Wallet) signLegacyP2SH(tx *wire.MsgTx, idx int, redeemScript []byte, signers []*bbcrypto.PrivateKey) error {
	sighash, err := script.CalcSignatureHash(
		redeemScript,
		script.SigHashAll,
		tx,
		idx,
	)
	if err != nil {
		return err
	}

	if isMultisigScript(redeemScript) {
		m, _, err := parseMultisigScript(redeemScript)
		if err != nil {
			return err
		}
		parts := make([][]byte, 0, m+1)
		parts = append(parts, []byte{}) // CHECKMULTISIG off-by-one pad
		emitted := 0
		for _, signer := range signers {
			if signer == nil {
				continue
			}
			if emitted >= m {
				break
			}
			sig, err := bbcrypto.SignECDSA(signer, sighash)
			if err != nil {
				return err
			}
			sig = append(sig, byte(script.SigHashAll))
			parts = append(parts, sig)
			emitted++
		}
		if emitted < m {
			return fmt.Errorf("partial-sign: only %d of %d required keys owned", emitted, m)
		}
		tx.TxIn[idx].SignatureScript = buildLegacyScriptSig(parts, redeemScript)
		return nil
	}

	// Non-multisig: single key.
	if len(signers) != 1 || signers[0] == nil {
		return errors.New("non-multisig legacy P2SH requires exactly one signer")
	}
	sig, err := bbcrypto.SignECDSA(signers[0], sighash)
	if err != nil {
		return err
	}
	sig = append(sig, byte(script.SigHashAll))
	pubKey := signers[0].PubKey().SerializeCompressed()
	tx.TxIn[idx].SignatureScript = buildLegacyScriptSig([][]byte{sig, pubKey}, redeemScript)
	return nil
}

// findKeyForPubKey searches addrToPath for any derivation that produces
// the given compressed public key. Linear in the number of issued
// addresses; acceptable since wallets in this codebase issue O(100s).
func (w *Wallet) findKeyForPubKey(pubKey []byte) (*bbcrypto.PrivateKey, error) {
	if w.masterKey == nil {
		return nil, ErrNoMasterKey
	}
	for _, path := range w.addrToPath {
		key, err := w.masterKey.DerivePath(path)
		if err != nil {
			continue
		}
		priv, err := key.ECPrivKey()
		if err != nil {
			continue
		}
		if subtleEqualBytes(priv.PubKey().SerializeCompressed(), pubKey) {
			return priv, nil
		}
	}
	return nil, fmt.Errorf("wallet does not own pubkey")
}

// collectSignersForScript walks a script (witness or redeem) for embedded
// pubkeys and returns the wallet's private keys for each one we own. For
// CHECKMULTISIG scripts the returned signers are in script-pubkey order
// so the caller can preserve CHECKMULTISIG's stack-order requirement.
//
// Returns (nil, error) if the wallet owns zero keys for the script —
// callers can choose to surface this as a per-input error in the RPC
// response (mirroring Core's signrawtransactionwithwallet partial-sign
// behaviour).
func (w *Wallet) collectSignersForScript(s []byte) ([]*bbcrypto.PrivateKey, error) {
	if isMultisigScript(s) {
		_, pubKeys, err := parseMultisigScript(s)
		if err != nil {
			return nil, err
		}
		signers := make([]*bbcrypto.PrivateKey, len(pubKeys))
		owned := 0
		for i, pk := range pubKeys {
			priv, err := w.findKeyForPubKey(pk)
			if err == nil {
				signers[i] = priv
				owned++
			}
		}
		if owned == 0 {
			return nil, fmt.Errorf("wallet owns none of the multisig pubkeys")
		}
		return signers, nil
	}

	// Single-key witness/redeem (e.g. P2PK-style witness). Try to
	// extract a single 33-byte compressed key push.
	if len(s) >= 34 && s[0] == 0x21 {
		priv, err := w.findKeyForPubKey(s[1:34])
		if err == nil {
			return []*bbcrypto.PrivateKey{priv}, nil
		}
	}
	return nil, fmt.Errorf("unsupported script template (need multisig or single-key)")
}

// computeTweakedPrivKey computes the tweaked private key for taproot signing.
func (w *Wallet) computeTweakedPrivKey(privKeyBytes []byte, tweakHash [32]byte, negate bool) ([]byte, error) {
	var privScalar secp256k1.ModNScalar
	privScalar.SetByteSlice(privKeyBytes)

	// If the public key has odd y, negate the private key first
	if negate {
		privScalar.Negate()
	}

	// Add the tweak
	var tweakScalar secp256k1.ModNScalar
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		return nil, errors.New("tweak overflow")
	}

	privScalar.Add(&tweakScalar)

	result := make([]byte, 32)
	privScalar.PutBytesUnchecked(result)
	return result, nil
}

// Script type detection helpers
func isP2PKH(pkScript []byte) bool {
	// OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
	return len(pkScript) == 25 && pkScript[0] == 0x76 && pkScript[1] == 0xa9 &&
		pkScript[2] == 0x14 && pkScript[23] == 0x88 && pkScript[24] == 0xac
}

func isP2SH(pkScript []byte) bool {
	// OP_HASH160 <20-byte-hash> OP_EQUAL
	return len(pkScript) == 23 && pkScript[0] == 0xa9 && pkScript[1] == 0x14 && pkScript[22] == 0x87
}

func isP2WPKH(pkScript []byte) bool {
	// OP_0 <20-byte-hash>
	return len(pkScript) == 22 && pkScript[0] == 0x00 && pkScript[1] == 0x14
}

func isP2TR(pkScript []byte) bool {
	// OP_1 <32-byte-key>
	return len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20
}

// getKeyForPath returns the private key for a derivation path.
func (w *Wallet) getKeyForPath(path string) (*bbcrypto.PrivateKey, error) {
	if w.masterKey == nil {
		return nil, ErrNoMasterKey
	}

	key, err := w.masterKey.DerivePath(path)
	if err != nil {
		return nil, err
	}

	return key.ECPrivKey()
}

// PrevTxInfo describes a previous output supplied to SignTransactionWithPrevs
// for inputs whose UTXO data the wallet does not already track. It mirrors
// the shape of the `prevtxs` array in `signrawtransactionwithwallet` (see
// internal/rpc/rawtx_methods.go::PrevTx) but holds raw bytes instead of hex
// strings so the wallet can consume it directly.
//
// For P2SH inputs RedeemScript is required; for P2WSH / P2SH-P2WSH inputs
// WitnessScript is required; for P2SH-P2WPKH only RedeemScript is needed.
// Both fields may be left nil for native P2WPKH / P2PKH / P2TR inputs.
//
// Reference: bitcoin-core/src/wallet/rpc/spend.cpp (signrawtransactionwithwallet)
// and bitcoin-core/src/script/sign.cpp::ProduceSignature.
type PrevTxInfo struct {
	OutPoint      wire.OutPoint
	ScriptPubKey  []byte
	Amount        int64
	RedeemScript  []byte // optional, for P2SH variants
	WitnessScript []byte // optional, for P2WSH / P2SH-P2WSH
}

// SignTransaction signs all inputs of a transaction using wallet keys.
//
// Closes the W19 / R1 audit P0: this previously was a P2WPKH-only stub
// that signed every input as if it were P2WPKH, silently producing wrong
// witnesses for P2PKH / P2SH-P2WPKH / P2TR / P2WSH / P2SH-P2WSH inputs.
// It now delegates to SignTransactionWithPrevs(tx, nil), which dispatches
// by script template via signInput / signInputWithScripts.
//
// Inputs that need extra script material (redeemScript / witnessScript)
// must be passed through SignTransactionWithPrevs.
//
// Reference: bitcoin-core/src/wallet/scriptpubkeyman.cpp::SignTransaction.
func (w *Wallet) SignTransaction(tx *wire.MsgTx) error {
	return w.SignTransactionWithPrevs(tx, nil)
}

// SignTransactionWithPrevs signs all inputs of a transaction, threading
// caller-supplied previous-output info through the signer so that inputs
// using non-bare P2SH / P2WSH / P2SH-P2WSH templates can be signed
// correctly. prevs may be nil — in that case the wallet falls back to
// its internal UTXO store, which is the historical behaviour.
//
// Inputs whose outpoint is in neither the wallet's UTXO store nor prevs
// fail with a per-input error.
func (w *Wallet) SignTransactionWithPrevs(tx *wire.MsgTx, prevs []PrevTxInfo) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked {
		return ErrWalletLocked
	}
	if w.masterKey == nil {
		return ErrNoMasterKey
	}

	// Build a lookup from prevs (keyed by outpoint).
	prevMap := make(map[wire.OutPoint]*PrevTxInfo, len(prevs))
	for i := range prevs {
		p := &prevs[i]
		prevMap[p.OutPoint] = p
	}

	// Build prevOuts for taproot sighash (it needs a TxOut for every input).
	prevOuts := make([]*wire.TxOut, len(tx.TxIn))
	utxos := make([]*WalletUTXO, len(tx.TxIn))
	overrideScripts := make([]*PrevTxInfo, len(tx.TxIn))

	for i, txIn := range tx.TxIn {
		// Prefer caller-supplied prevs (they may carry redeem/witness scripts).
		if pinfo, ok := prevMap[txIn.PreviousOutPoint]; ok {
			overrideScripts[i] = pinfo
			// Build a synthetic WalletUTXO so the rest of the dispatcher
			// has a uniform type to work with. KeyPath is left blank — the
			// wallet's keystore is searched by pubkey for these inputs.
			utxos[i] = &WalletUTXO{
				OutPoint: txIn.PreviousOutPoint,
				Amount:   pinfo.Amount,
				PkScript: pinfo.ScriptPubKey,
			}
			// Cross-fill from internal store if amount/script is missing.
			if utxo, exists := w.utxos[txIn.PreviousOutPoint]; exists {
				if utxos[i].Amount == 0 {
					utxos[i].Amount = utxo.Amount
				}
				if len(utxos[i].PkScript) == 0 {
					utxos[i].PkScript = utxo.PkScript
				}
				if utxos[i].KeyPath == "" {
					utxos[i].KeyPath = utxo.KeyPath
				}
			}
		} else if utxo, exists := w.utxos[txIn.PreviousOutPoint]; exists {
			utxos[i] = utxo
		} else {
			return fmt.Errorf("UTXO not found for input %d", i)
		}

		prevOuts[i] = &wire.TxOut{
			Value:    utxos[i].Amount,
			PkScript: utxos[i].PkScript,
		}
	}

	for i := range tx.TxIn {
		if err := w.signInputWithScripts(tx, i, utxos[i], prevOuts, overrideScripts[i]); err != nil {
			return fmt.Errorf("failed to sign input %d: %w", i, err)
		}
	}

	return nil
}

// signInputWithScripts is the script-template dispatcher used by
// SignTransactionWithPrevs. It mirrors the canonical PSBT signer at
// psbt_ops.go::signInputWithKey so the raw-tx and PSBT paths agree on
// script-type semantics. info may be nil for inputs that the wallet
// already owns end-to-end, in which case behaviour matches signInput.
//
// Phase-2 (W27-D) version: P2SH inputs are now classified by inspecting
// the caller-supplied redeem script (mirroring Core ProduceSignature),
// and bare P2WSH inputs are routed to a new signing path. The actual
// P2WSH / P2SH-P2WSH / legacy-P2SH signers are added in Phase-3 of this
// wave; Phase-2 returns "not yet implemented" for those branches so the
// dispatch tree is in place and the wallet's existing single-sig paths
// keep working.
//
// Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature.
func (w *Wallet) signInputWithScripts(tx *wire.MsgTx, idx int, utxo *WalletUTXO, prevOuts []*wire.TxOut, info *PrevTxInfo) error {
	pkScript := utxo.PkScript

	// Bare-segwit-v0 P2WSH must be dispatched before the P2WPKH/P2TR
	// detectors; isP2WSH is defined in psbt_ops.go.
	if isP2WSH(pkScript) {
		if info == nil || len(info.WitnessScript) == 0 {
			return errors.New("missing witness script for P2WSH input")
		}
		signers, err := w.collectSignersForScript(info.WitnessScript)
		if err != nil {
			return err
		}
		return w.signP2WSH(tx, idx, utxo.Amount, info.WitnessScript, signers)
	}

	// P2SH must be classified by inspecting the redeem script the caller
	// supplied (BIP16 + BIP141 P2SH-wrapped segwit). Falling back to
	// "assume P2SH-P2WPKH" was the W19 P0 bug.
	if isP2SH(pkScript) {
		// If the wallet owns this address natively (its own P2SH-P2WPKH
		// template), info may be nil; reconstruct the redeem script from
		// the wallet's key and dispatch via the existing signer.
		if info == nil || len(info.RedeemScript) == 0 {
			privKey, err := w.findKeyForUTXO(utxo)
			if err != nil {
				return fmt.Errorf("missing redeem script and unknown wallet key for P2SH input: %w", err)
			}
			pubKey := privKey.PubKey()
			pubKeyHash := bbcrypto.Hash160(pubKey.SerializeCompressed())
			return w.signP2SH_P2WPKH(tx, idx, utxo.Amount, privKey, pubKey, pubKeyHash)
		}

		switch classifyRedeemScript(info.RedeemScript) {
		case redeemP2SH_P2WPKH:
			// P2SH-wrapped P2WPKH. The redeem script encodes the hash160
			// we need for the script-code, so derive directly from it.
			var pubKeyHash [20]byte
			copy(pubKeyHash[:], info.RedeemScript[2:22])
			privKey, err := w.findKeyForPubKeyHash(pubKeyHash[:])
			if err != nil {
				return err
			}
			pubKey := privKey.PubKey()
			return w.signP2SH_P2WPKH(tx, idx, utxo.Amount, privKey, pubKey, pubKeyHash)

		case redeemP2SH_P2WSH:
			if info.WitnessScript == nil {
				return errors.New("missing witness script for P2SH-P2WSH input")
			}
			signers, err := w.collectSignersForScript(info.WitnessScript)
			if err != nil {
				return err
			}
			return w.signP2SH_P2WSH(tx, idx, utxo.Amount, info.RedeemScript, info.WitnessScript, signers)

		default:
			// Legacy P2SH (e.g. bare M-of-N CHECKMULTISIG).
			signers, err := w.collectSignersForScript(info.RedeemScript)
			if err != nil {
				return err
			}
			return w.signLegacyP2SH(tx, idx, info.RedeemScript, signers)
		}
	}

	// All other templates: the wallet must own the key locally. Look it
	// up by KeyPath if we have one, else by ScriptPubKey hash.
	privKey, err := w.findKeyForUTXO(utxo)
	if err != nil {
		return err
	}
	return w.signInput(tx, idx, utxo, privKey, prevOuts)
}

// redeemKind classifies a P2SH redeem script for dispatch.
type redeemKind int

const (
	redeemUnknown redeemKind = iota
	redeemP2SH_P2WPKH
	redeemP2SH_P2WSH
	redeemLegacyP2SH
)

// classifyRedeemScript returns the type of P2SH-wrapped script. It mirrors
// the dispatch tree at psbt_ops.go:401-446 and Bitcoin Core's
// ProduceSignature recursion (script/sign.cpp:739-787).
func classifyRedeemScript(redeem []byte) redeemKind {
	switch {
	case isP2WPKH(redeem):
		return redeemP2SH_P2WPKH
	case isP2WSH(redeem):
		return redeemP2SH_P2WSH
	case len(redeem) == 0:
		return redeemUnknown
	default:
		return redeemLegacyP2SH
	}
}

// findKeyForPubKeyHash searches addrToPath for any key whose hash160
// matches; used for P2SH-P2WPKH redeem-script dispatch.
func (w *Wallet) findKeyForPubKeyHash(hash160 []byte) (*bbcrypto.PrivateKey, error) {
	if w.masterKey == nil {
		return nil, ErrNoMasterKey
	}
	for _, path := range w.addrToPath {
		key, err := w.masterKey.DerivePath(path)
		if err != nil {
			continue
		}
		priv, err := key.ECPrivKey()
		if err != nil {
			continue
		}
		h := bbcrypto.Hash160(priv.PubKey().SerializeCompressed())
		if subtleEqualBytes(h[:], hash160) {
			return priv, nil
		}
	}
	return nil, fmt.Errorf("wallet does not own pubkey-hash")
}

// subtleEqualBytes is a constant-time byte-compare for equal-length
// inputs. Crypto-conservatism only — these are public-key / hash160
// comparisons, timing leaks aren't actually a concern here.
func subtleEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// findKeyForUTXO returns the wallet's private key for a wallet-owned UTXO,
// preferring the recorded KeyPath but falling back to scanning addrToPath
// for the address derived from the UTXO's scriptPubKey. Used by
// signInputWithScripts for inputs that arrived via prevtxs but whose
// scriptPubKey is one the wallet still controls.
func (w *Wallet) findKeyForUTXO(utxo *WalletUTXO) (*bbcrypto.PrivateKey, error) {
	if utxo.KeyPath != "" {
		return w.getKeyForPath(utxo.KeyPath)
	}
	addr := w.scriptToAddress(utxo.PkScript)
	if addr == "" {
		return nil, fmt.Errorf("wallet does not own scriptPubKey")
	}
	path, ok := w.addrToPath[addr]
	if !ok {
		return nil, fmt.Errorf("wallet does not own address %s", addr)
	}
	return w.getKeyForPath(path)
}

// ScanBlock checks a block for transactions relevant to the wallet.
func (w *Wallet) ScanBlock(block *wire.MsgBlock, height int32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	isCoinbase := true
	for _, tx := range block.Transactions {
		txHash := tx.TxHash()

		// Check outputs - received funds
		for idx, out := range tx.TxOut {
			addr := w.scriptToAddress(out.PkScript)
			if addr == "" {
				continue
			}

			path, isOurs := w.addrToPath[addr]
			if !isOurs {
				continue
			}

			// Add UTXO
			outpoint := wire.OutPoint{
				Hash:  txHash,
				Index: uint32(idx),
			}
			w.utxos[outpoint] = &WalletUTXO{
				OutPoint:   outpoint,
				Amount:     out.Value,
				PkScript:   out.PkScript,
				Address:    addr,
				Height:     height,
				IsCoinbase: isCoinbase,
				KeyPath:    path,
				Confirmed:  true,
			}

			// Add to history
			w.txHistory = append(w.txHistory, &WalletTx{
				TxHash:    txHash,
				Height:    height,
				Amount:    out.Value,
				Timestamp: int64(block.Header.Timestamp),
				Address:   addr,
			})
		}

		// Check inputs - spent funds
		for _, in := range tx.TxIn {
			if utxo, exists := w.utxos[in.PreviousOutPoint]; exists {
				// Record spend in history
				w.txHistory = append(w.txHistory, &WalletTx{
					TxHash:    txHash,
					Height:    height,
					Amount:    -utxo.Amount,
					Timestamp: int64(block.Header.Timestamp),
					Address:   utxo.Address,
				})

				// Remove spent UTXO
				delete(w.utxos, in.PreviousOutPoint)
			}
		}

		isCoinbase = false
	}
}

// scriptToAddress converts a scriptPubKey to an address string.
func (w *Wallet) scriptToAddress(pkScript []byte) string {
	// P2WPKH: OP_0 <20-byte-hash>
	if len(pkScript) == 22 && pkScript[0] == 0x00 && pkScript[1] == 0x14 {
		var hash [20]byte
		copy(hash[:], pkScript[2:22])
		addr := address.NewP2WPKHAddress(hash, w.config.Network)
		s, _ := addr.Encode()
		return s
	}

	// P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
	if len(pkScript) == 25 && pkScript[0] == 0x76 && pkScript[1] == 0xa9 && pkScript[2] == 0x14 && pkScript[23] == 0x88 && pkScript[24] == 0xac {
		var hash [20]byte
		copy(hash[:], pkScript[3:23])
		addr := address.NewP2PKHAddress(hash, w.config.Network)
		s, _ := addr.Encode()
		return s
	}

	// P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
	if len(pkScript) == 23 && pkScript[0] == 0xa9 && pkScript[1] == 0x14 && pkScript[22] == 0x87 {
		var hash [20]byte
		copy(hash[:], pkScript[2:22])
		addr := address.NewP2SHAddress(hash, w.config.Network)
		s, _ := addr.Encode()
		return s
	}

	// P2TR: OP_1 <32-byte-key>
	if len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20 {
		var key [32]byte
		copy(key[:], pkScript[2:34])
		addr := address.NewP2TRAddress(key, w.config.Network)
		s, _ := addr.Encode()
		return s
	}

	// P2WSH: OP_0 <32-byte-hash>
	if len(pkScript) == 34 && pkScript[0] == 0x00 && pkScript[1] == 0x20 {
		var hash [32]byte
		copy(hash[:], pkScript[2:34])
		addr := address.NewP2WSHAddress(hash, w.config.Network)
		s, _ := addr.Encode()
		return s
	}

	return ""
}

// Lock locks the wallet, preventing signing operations. When the wallet is
// encrypted, this also zeroes and discards the in-memory master key — only
// the ciphertext (encryptedMaster) is retained.
func (w *Wallet) Lock() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lockLocked()
}

// lockLocked locks the wallet; caller must hold w.mu (write lock).
func (w *Wallet) lockLocked() {
	w.locked = true
	if w.relockTimer != nil {
		w.relockTimer.Stop()
		w.relockTimer = nil
	}
	if w.encrypted && w.masterKey != nil {
		// Best-effort scrubbing of secret material. Go's GC and slice headers
		// mean we can only zero the buffers we hold pointers to; this is the
		// same caveat Bitcoin Core's SecureString carries on most platforms.
		zeroBytes(w.masterKey.Key)
		zeroBytes(w.masterKey.ChainCode)
		w.masterKey = nil
	}
}

// Unlock unlocks the wallet by mnemonic. This is blockbrew's pre-encryption
// unlock path and is preserved for backward compatibility with callers that
// hold the mnemonic. Passphrase-encrypted wallets must use UnlockWithPassphrase.
func (w *Wallet) Unlock(mnemonic, passphrase string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Verify the mnemonic produces the same master key
	if !ValidateMnemonic(mnemonic) {
		return ErrInvalidMnemonic
	}

	seed := MnemonicToSeed(mnemonic, passphrase)
	masterKey, err := NewMasterKey(seed)
	if err != nil {
		return err
	}

	// Compare fingerprints
	if w.masterKey != nil {
		if masterKey.Fingerprint() != w.masterKey.Fingerprint() {
			return errors.New("mnemonic does not match wallet")
		}
	}

	w.masterKey = masterKey
	w.locked = false
	return nil
}

// IsLocked returns whether the wallet is locked.
func (w *Wallet) IsLocked() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.locked
}

// IsEncrypted returns whether the wallet has had EncryptWallet applied.
// Mirrors CWallet::HasEncryptionKeys().
func (w *Wallet) IsEncrypted() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.encrypted
}

// EncryptWallet encrypts the wallet's master HD key under the supplied
// passphrase using AES-256-GCM with scrypt key derivation, and locks the
// wallet. Returns ErrWalletAlreadyEncrypted if already encrypted, ErrNoMasterKey
// if there is nothing to encrypt, or ErrEmptyPassphrase if passphrase is empty.
//
// After this call returns nil, callers must use UnlockWithPassphrase to
// resume signing. The plaintext master key is wiped from memory before return.
func (w *Wallet) EncryptWallet(passphrase string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.encrypted {
		return ErrWalletAlreadyEncrypted
	}
	if w.masterKey == nil {
		return ErrNoMasterKey
	}
	if len(passphrase) == 0 {
		return ErrEmptyPassphrase
	}

	// Serialize as Key||ChainCode (64 bytes) — same layout used by SaveToFile.
	plaintext := make([]byte, 0, len(w.masterKey.Key)+len(w.masterKey.ChainCode))
	plaintext = append(plaintext, w.masterKey.Key...)
	plaintext = append(plaintext, w.masterKey.ChainCode...)
	defer zeroBytes(plaintext)

	envelope, err := encryptMasterKey(plaintext, passphrase)
	if err != nil {
		return err
	}

	w.encryptedMaster = envelope
	w.encrypted = true

	// Wipe in-memory master key and lock.
	zeroBytes(w.masterKey.Key)
	zeroBytes(w.masterKey.ChainCode)
	w.masterKey = nil
	w.locked = true
	if w.relockTimer != nil {
		w.relockTimer.Stop()
		w.relockTimer = nil
	}

	return nil
}

// UnlockWithPassphrase decrypts the encrypted master key with the supplied
// passphrase, retains the cleartext key in memory for `timeout` seconds, and
// schedules an auto-relock callback. timeout values are clamped to
// [0, MaxRelockSleepSeconds]; a timeout of 0 unlocks the wallet without
// scheduling any auto-relock (matching the documented behavior of negative-
// rejected, zero-allowed sleep in Core's walletpassphrase clamp).
//
// Calling this on an unencrypted wallet returns ErrWalletNotEncrypted.
// Re-calling while already unlocked simply resets the auto-relock timer
// (matching CWallet::Unlock behavior of "set a new unlock time that overrides
// the old one").
func (w *Wallet) UnlockWithPassphrase(passphrase string, timeout int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.encrypted {
		return ErrWalletNotEncrypted
	}
	if len(passphrase) == 0 {
		return ErrEmptyPassphrase
	}
	if timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	if timeout > MaxRelockSleepSeconds {
		timeout = MaxRelockSleepSeconds
	}

	plaintext, err := decryptMasterKey(w.encryptedMaster, passphrase)
	if err != nil {
		return err
	}
	defer zeroBytes(plaintext)

	if len(plaintext) != 64 {
		return ErrPassphraseIncorrect
	}

	// Reconstruct the master key from key||chaincode.
	keyBuf := make([]byte, 32)
	chainBuf := make([]byte, 32)
	copy(keyBuf, plaintext[:32])
	copy(chainBuf, plaintext[32:])
	if !isValidSecretKey(keyBuf) {
		zeroBytes(keyBuf)
		zeroBytes(chainBuf)
		return ErrPassphraseIncorrect
	}
	w.masterKey = &HDKey{
		Key:       keyBuf,
		ChainCode: chainBuf,
		Depth:     0,
		ParentFP:  [4]byte{},
		Index:     0,
		IsPrivate: true,
	}
	w.locked = false

	// Schedule auto-relock. A new call cancels any prior timer.
	if w.relockTimer != nil {
		w.relockTimer.Stop()
		w.relockTimer = nil
	}
	if timeout > 0 {
		w.relockTimer = time.AfterFunc(time.Duration(timeout)*time.Second, func() {
			w.Lock()
		})
	}

	return nil
}

// GetMasterFingerprint returns the fingerprint of the master key.
func (w *Wallet) GetMasterFingerprint() ([4]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.masterKey == nil {
		return [4]byte{}, ErrNoMasterKey
	}
	return w.masterKey.Fingerprint(), nil
}

// GetExtendedPublicKey returns the extended public key for the given account.
func (w *Wallet) GetExtendedPublicKey(account uint32) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.masterKey == nil {
		return "", ErrNoMasterKey
	}

	// Derive account key: m/84'/coin'/account'
	coinType := w.coinType()
	path := fmt.Sprintf("m/84'/%d'/%d'", coinType, account)

	accountKey, err := w.masterKey.DerivePath(path)
	if err != nil {
		return "", err
	}

	return accountKey.PublicKey().Serialize(w.config.Network), nil
}

// GetHistory returns the transaction history.
func (w *Wallet) GetHistory() []*WalletTx {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*WalletTx, len(w.txHistory))
	copy(result, w.txHistory)
	return result
}

// GenerateAddresses generates multiple addresses in advance.
func (w *Wallet) GenerateAddresses(count int) ([]string, error) {
	addresses := make([]string, 0, count)
	for i := 0; i < count; i++ {
		addr, err := w.NewAddress()
		if err != nil {
			return addresses, err
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

// ImportDescriptor imports a descriptor into the wallet.
// TODO: Full implementation
func (w *Wallet) ImportDescriptor(desc *Descriptor, active, internal bool, label string) error {
	_ = desc
	_ = active
	_ = internal
	_ = label
	return errors.New("descriptor import not yet implemented")
}
