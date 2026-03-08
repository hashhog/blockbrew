// Package wallet implements key management and transaction signing.
package wallet

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// WalletConfig configures the wallet.
type WalletConfig struct {
	DataDir     string
	Network     address.Network
	ChainParams *consensus.ChainParams
}

// Wallet manages keys, addresses, and balances.
type Wallet struct {
	mu          sync.RWMutex
	config      WalletConfig
	masterKey   *HDKey
	accounts    []*Account
	utxos       map[wire.OutPoint]*WalletUTXO
	txHistory   []*WalletTx
	nextExtIdx  uint32
	nextIntIdx  uint32
	gapLimit    int
	locked      bool
	addrToPath  map[string]string // maps address to derivation path
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

// NewAddress generates a new receiving address.
func (w *Wallet) NewAddress() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.masterKey == nil {
		return "", ErrNoMasterKey
	}
	if w.locked {
		return "", ErrWalletLocked
	}

	// Derive external address: m/84'/coin'/0'/0/index
	coinType := w.coinType()
	path := BIP84Path(coinType, 0, 0, w.nextExtIdx)

	key, err := w.masterKey.DerivePath(path)
	if err != nil {
		return "", err
	}

	addr, err := w.pubKeyToAddress(key)
	if err != nil {
		return "", err
	}

	w.addrToPath[addr] = path
	w.nextExtIdx++

	// Track in account
	if len(w.accounts) > 0 {
		w.accounts[0].Addresses = append(w.accounts[0].Addresses, addr)
	}

	return addr, nil
}

// NewChangeAddress generates a new change address.
func (w *Wallet) NewChangeAddress() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.masterKey == nil {
		return "", ErrNoMasterKey
	}
	if w.locked {
		return "", ErrWalletLocked
	}

	// Derive internal (change) address: m/84'/coin'/0'/1/index
	coinType := w.coinType()
	path := BIP84Path(coinType, 0, 1, w.nextIntIdx)

	key, err := w.masterKey.DerivePath(path)
	if err != nil {
		return "", err
	}

	addr, err := w.pubKeyToAddress(key)
	if err != nil {
		return "", err
	}

	w.addrToPath[addr] = path
	w.nextIntIdx++

	return addr, nil
}

// pubKeyToAddress converts an HD key to a P2WPKH address string.
func (w *Wallet) pubKeyToAddress(key *HDKey) (string, error) {
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
func (w *Wallet) CreateTransaction(destAddr string, amount int64, feeRate float64) (*wire.MsgTx, error) {
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

	// 2. Select UTXOs (largest-first coin selection)
	utxos := w.selectCoins(amount, feeRate)
	if utxos == nil {
		return nil, ErrInsufficientFunds
	}

	// 3. Calculate total input value
	var totalInput int64
	for _, u := range utxos {
		totalInput += u.Amount
	}

	// 4. Build the transaction
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 0,
	}

	for _, u := range utxos {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: u.OutPoint,
			Sequence:         0xFFFFFFFE, // Enable RBF (BIP125)
		})
	}

	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    amount,
		PkScript: destScript,
	})

	// 5. Estimate fee
	// Estimate vsize: ~10 base + ~68 per P2WPKH input + ~31 per output
	estimatedVSize := int64(10 + 68*len(utxos) + 31*2)
	estimatedFee := int64(float64(estimatedVSize) * feeRate)

	// 6. Add change output if needed
	change := totalInput - amount - estimatedFee
	if change < 0 {
		return nil, ErrInsufficientFunds
	}

	dustLimit := int64(546)
	if change > dustLimit {
		changeAddr, err := w.newChangeAddressLocked()
		if err != nil {
			return nil, err
		}
		changeAddrParsed, err := address.DecodeAddress(changeAddr, w.config.Network)
		if err != nil {
			return nil, err
		}
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    change,
			PkScript: changeAddrParsed.ScriptPubKey(),
		})
	}

	// 7. Sign the transaction
	err = w.signTx(tx, utxos)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return tx, nil
}

// newChangeAddressLocked generates a new change address (caller must hold lock).
func (w *Wallet) newChangeAddressLocked() (string, error) {
	coinType := w.coinType()
	path := BIP84Path(coinType, 0, 1, w.nextIntIdx)

	key, err := w.masterKey.DerivePath(path)
	if err != nil {
		return "", err
	}

	addr, err := w.pubKeyToAddress(key)
	if err != nil {
		return "", err
	}

	w.addrToPath[addr] = path
	w.nextIntIdx++

	return addr, nil
}

// selectCoins selects UTXOs for a transaction using largest-first selection.
func (w *Wallet) selectCoins(amount int64, feeRate float64) []*WalletUTXO {
	// Get all confirmed UTXOs
	var available []*WalletUTXO
	for _, utxo := range w.utxos {
		if utxo.Confirmed {
			available = append(available, utxo)
		}
	}

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
	for i, utxo := range utxos {
		// Get the private key for this UTXO
		privKey, err := w.getKeyForPath(utxo.KeyPath)
		if err != nil {
			return err
		}

		// Create P2WPKH script code for signing
		// For P2WPKH, scriptCode is OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
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

		// Set witness: [signature, pubkey]
		tx.TxIn[i].Witness = [][]byte{
			sig,
			pubKey.SerializeCompressed(),
		}
	}

	return nil
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
