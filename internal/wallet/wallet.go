// Package wallet implements key management and transaction signing.
package wallet

import (
	"errors"
	"fmt"
	"sort"
	"sync"

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
	mu          sync.RWMutex
	name        string // wallet name (empty for default wallet)
	config      WalletConfig
	masterKey   *HDKey
	accounts    []*Account
	utxos       map[wire.OutPoint]*WalletUTXO
	txHistory   []*WalletTx
	nextExtIdx  uint32
	nextIntIdx  uint32
	gapLimit    int
	locked      bool
	addrToPath  map[string]string            // maps address to derivation path
	addrToType  map[string]WalletAddressType // maps address to address type
	addrLabels  map[string]string            // maps address to label
	// Per-type address indices
	nextIdx map[WalletAddressType]*addressIndices
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

// DefaultGapLimit is the default number of unused addresses to maintain.
const DefaultGapLimit = 20

// NewWallet creates a new empty wallet.
func NewWallet(config WalletConfig) *Wallet {
	return &Wallet{
		config:     config,
		utxos:      make(map[wire.OutPoint]*WalletUTXO),
		txHistory:  make([]*WalletTx, 0),
		gapLimit:   DefaultGapLimit,
		locked:     true,
		addrToPath: make(map[string]string),
		addrToType: make(map[string]WalletAddressType),
		addrLabels: make(map[string]string),
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
	if w.masterKey == nil {
		return "", ErrNoMasterKey
	}
	if w.locked {
		return "", ErrWalletLocked
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

// SignTransaction signs all inputs of a transaction using wallet keys.
func (w *Wallet) SignTransaction(tx *wire.MsgTx) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked {
		return ErrWalletLocked
	}
	if w.masterKey == nil {
		return ErrNoMasterKey
	}

	// For each input, find the corresponding UTXO
	for i, txIn := range tx.TxIn {
		utxo, exists := w.utxos[txIn.PreviousOutPoint]
		if !exists {
			return fmt.Errorf("UTXO not found for input %d", i)
		}

		// Get the private key for this UTXO
		privKey, err := w.getKeyForPath(utxo.KeyPath)
		if err != nil {
			return err
		}

		// Create P2WPKH script code
		pubKey := privKey.PubKey()
		pubKeyHash := bbcrypto.Hash160(pubKey.SerializeCompressed())

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
			i,
			utxo.Amount,
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

		// Set witness
		tx.TxIn[i].Witness = [][]byte{
			sig,
			pubKey.SerializeCompressed(),
		}
	}

	return nil
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

// Lock locks the wallet, preventing signing operations.
func (w *Wallet) Lock() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.locked = true
}

// Unlock unlocks the wallet.
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
