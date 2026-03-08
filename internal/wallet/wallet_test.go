package wallet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Test mnemonic for reproducible tests
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestNewWallet(t *testing.T) {
	config := WalletConfig{
		DataDir: t.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)
	if w == nil {
		t.Fatal("NewWallet returned nil")
	}

	if !w.IsLocked() {
		t.Error("New wallet should be locked")
	}
}

func TestCreateFromMnemonic(t *testing.T) {
	config := WalletConfig{
		DataDir: t.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)

	err := w.CreateFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("CreateFromMnemonic failed: %v", err)
	}

	if w.IsLocked() {
		t.Error("Wallet should be unlocked after creation")
	}

	// Test with invalid mnemonic
	w2 := NewWallet(config)
	err = w2.CreateFromMnemonic("invalid mnemonic words", "")
	if err == nil {
		t.Error("Expected error for invalid mnemonic")
	}
}

func TestNewAddress(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	err := w.CreateFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("CreateFromMnemonic failed: %v", err)
	}

	// Generate first address
	addr1, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}

	// Should be a bech32 address
	if !strings.HasPrefix(addr1, "bc1q") {
		t.Errorf("Expected bech32 address starting with bc1q, got %s", addr1)
	}

	// Generate second address
	addr2, err := w.NewAddress()
	if err != nil {
		t.Fatalf("Second NewAddress failed: %v", err)
	}

	// Addresses should be different
	if addr1 == addr2 {
		t.Error("Consecutive addresses should be different")
	}

	// Verify addresses are owned by wallet
	if !w.IsOwnAddress(addr1) {
		t.Error("Wallet should recognize addr1 as own")
	}
	if !w.IsOwnAddress(addr2) {
		t.Error("Wallet should recognize addr2 as own")
	}
	if w.IsOwnAddress("bc1qsomeotheraddress") {
		t.Error("Wallet should not recognize random address")
	}
}

func TestNewAddressDeterministic(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create first wallet
	w1 := NewWallet(config)
	w1.CreateFromMnemonic(testMnemonic, "")
	addr1_1, _ := w1.NewAddress()
	addr1_2, _ := w1.NewAddress()

	// Create second wallet with same mnemonic
	w2 := NewWallet(config)
	w2.CreateFromMnemonic(testMnemonic, "")
	addr2_1, _ := w2.NewAddress()
	addr2_2, _ := w2.NewAddress()

	// Addresses should match
	if addr1_1 != addr2_1 {
		t.Errorf("First addresses don't match: %s vs %s", addr1_1, addr2_1)
	}
	if addr1_2 != addr2_2 {
		t.Errorf("Second addresses don't match: %s vs %s", addr1_2, addr2_2)
	}
}

func TestNewChangeAddress(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate change address
	changeAddr, err := w.NewChangeAddress()
	if err != nil {
		t.Fatalf("NewChangeAddress failed: %v", err)
	}

	// Should be a bech32 address
	if !strings.HasPrefix(changeAddr, "bc1q") {
		t.Errorf("Expected bech32 change address, got %s", changeAddr)
	}

	// Generate regular address
	recvAddr, _ := w.NewAddress()

	// Change and receive addresses should be different
	if changeAddr == recvAddr {
		t.Error("Change and receive addresses should be different")
	}

	// Both should be owned by wallet
	if !w.IsOwnAddress(changeAddr) {
		t.Error("Wallet should recognize change address")
	}
}

func TestGetBalance(t *testing.T) {
	config := WalletConfig{
		DataDir: t.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Initial balance should be zero
	confirmed, unconfirmed := w.GetBalance()
	if confirmed != 0 || unconfirmed != 0 {
		t.Errorf("Initial balance should be 0, got confirmed=%d unconfirmed=%d", confirmed, unconfirmed)
	}

	// Add a confirmed UTXO
	addr, _ := w.NewAddress()
	utxo := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{1, 2, 3},
			Index: 0,
		},
		Amount:    100000,
		Address:   addr,
		KeyPath:   "m/84'/0'/0'/0/0",
		Confirmed: true,
	}
	w.AddUTXO(utxo)

	confirmed, unconfirmed = w.GetBalance()
	if confirmed != 100000 {
		t.Errorf("Confirmed balance should be 100000, got %d", confirmed)
	}
	if unconfirmed != 0 {
		t.Errorf("Unconfirmed balance should be 0, got %d", unconfirmed)
	}

	// Add an unconfirmed UTXO
	utxo2 := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{4, 5, 6},
			Index: 0,
		},
		Amount:    50000,
		Address:   addr,
		KeyPath:   "m/84'/0'/0'/0/0",
		Confirmed: false,
	}
	w.AddUTXO(utxo2)

	confirmed, unconfirmed = w.GetBalance()
	if confirmed != 100000 {
		t.Errorf("Confirmed balance should still be 100000, got %d", confirmed)
	}
	if unconfirmed != 50000 {
		t.Errorf("Unconfirmed balance should be 50000, got %d", unconfirmed)
	}
}

func TestListUnspent(t *testing.T) {
	config := WalletConfig{
		DataDir: t.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Add UTXOs
	for i := 0; i < 5; i++ {
		utxo := &WalletUTXO{
			OutPoint: wire.OutPoint{
				Hash:  wire.Hash256{byte(i)},
				Index: 0,
			},
			Amount:    int64(i * 10000),
			Address:   addr,
			KeyPath:   "m/84'/0'/0'/0/0",
			Confirmed: true,
		}
		w.AddUTXO(utxo)
	}

	utxos := w.ListUnspent()
	if len(utxos) != 5 {
		t.Errorf("Expected 5 UTXOs, got %d", len(utxos))
	}
}

func TestCreateTransactionInsufficientFunds(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Try to create transaction with no UTXOs
	_, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 100000, 10.0)
	if err != ErrInsufficientFunds {
		t.Errorf("Expected ErrInsufficientFunds, got %v", err)
	}
}

func TestCreateTransactionSuccess(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate an address and add a UTXO
	addr, _ := w.NewAddress()
	utxo := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{1, 2, 3, 4, 5, 6, 7, 8},
			Index: 0,
		},
		Amount:    1000000, // 0.01 BTC
		Address:   addr,
		KeyPath:   "m/84'/0'/0'/0/0",
		Confirmed: true,
	}
	w.AddUTXO(utxo)

	// Create transaction
	tx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 100000, 1.0)
	if err != nil {
		t.Fatalf("CreateTransaction failed: %v", err)
	}

	// Verify transaction structure
	if tx.Version != 2 {
		t.Errorf("Transaction version = %d, want 2", tx.Version)
	}

	if len(tx.TxIn) != 1 {
		t.Errorf("Expected 1 input, got %d", len(tx.TxIn))
	}

	// Should have 2 outputs (destination + change)
	if len(tx.TxOut) != 2 {
		t.Errorf("Expected 2 outputs, got %d", len(tx.TxOut))
	}

	// First output should be the destination amount
	if tx.TxOut[0].Value != 100000 {
		t.Errorf("Destination output value = %d, want 100000", tx.TxOut[0].Value)
	}

	// Transaction should have witness data
	if !tx.HasWitness() {
		t.Error("Transaction should have witness data")
	}

	// Verify witness structure (should have signature and pubkey)
	if len(tx.TxIn[0].Witness) != 2 {
		t.Errorf("Expected 2 witness elements, got %d", len(tx.TxIn[0].Witness))
	}
}

func TestLockUnlock(t *testing.T) {
	config := WalletConfig{
		DataDir: t.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Should be unlocked
	if w.IsLocked() {
		t.Error("Wallet should be unlocked after creation")
	}

	// Lock
	w.Lock()
	if !w.IsLocked() {
		t.Error("Wallet should be locked")
	}

	// Try to generate address while locked
	_, err := w.NewAddress()
	if err != ErrWalletLocked {
		t.Errorf("Expected ErrWalletLocked, got %v", err)
	}

	// Unlock with correct mnemonic
	err = w.Unlock(testMnemonic, "")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if w.IsLocked() {
		t.Error("Wallet should be unlocked")
	}
}

func TestGetExtendedPublicKey(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	xpub, err := w.GetExtendedPublicKey(0)
	if err != nil {
		t.Fatalf("GetExtendedPublicKey failed: %v", err)
	}

	// Should be an xpub for mainnet
	if !strings.HasPrefix(xpub, "xpub") {
		t.Errorf("Expected xpub prefix, got %s", xpub)
	}
}

func TestTestnetAddresses(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Testnet,
		ChainParams: consensus.TestnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Testnet addresses should start with tb1
	if !strings.HasPrefix(addr, "tb1q") {
		t.Errorf("Expected testnet address starting with tb1q, got %s", addr)
	}
}

func TestRegtestAddresses(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Regtest addresses should start with bcrt1
	if !strings.HasPrefix(addr, "bcrt1q") {
		t.Errorf("Expected regtest address starting with bcrt1q, got %s", addr)
	}
}

func TestSaveLoadWallet(t *testing.T) {
	tmpDir := t.TempDir()
	config := WalletConfig{
		DataDir:     tmpDir,
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create and setup wallet
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate some addresses
	addr1, _ := w.NewAddress()
	addr2, _ := w.NewAddress()

	// Add a UTXO
	utxo := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{1, 2, 3},
			Index: 0,
		},
		Amount:    100000,
		Address:   addr1,
		KeyPath:   "m/84'/0'/0'/0/0",
		Confirmed: true,
	}
	w.AddUTXO(utxo)

	// Save wallet
	password := "testpassword123"
	err := w.SaveToFile(password)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	walletPath := filepath.Join(tmpDir, "wallet.dat")
	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		t.Fatal("Wallet file was not created")
	}

	// Load wallet
	loaded, err := LoadFromFile(tmpDir, password, config)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify addresses are recognized
	if !loaded.IsOwnAddress(addr1) {
		t.Error("Loaded wallet doesn't recognize addr1")
	}
	if !loaded.IsOwnAddress(addr2) {
		t.Error("Loaded wallet doesn't recognize addr2")
	}

	// Verify balance
	confirmed, _ := loaded.GetBalance()
	if confirmed != 100000 {
		t.Errorf("Loaded wallet balance = %d, want 100000", confirmed)
	}

	// Test wrong password
	_, err = LoadFromFile(tmpDir, "wrongpassword", config)
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}
}

func TestGenerateAddresses(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate 10 addresses
	addrs, err := w.GenerateAddresses(10)
	if err != nil {
		t.Fatalf("GenerateAddresses failed: %v", err)
	}

	if len(addrs) != 10 {
		t.Errorf("Expected 10 addresses, got %d", len(addrs))
	}

	// Verify all addresses are unique
	seen := make(map[string]bool)
	for _, addr := range addrs {
		if seen[addr] {
			t.Errorf("Duplicate address: %s", addr)
		}
		seen[addr] = true

		if !w.IsOwnAddress(addr) {
			t.Errorf("Wallet doesn't recognize generated address: %s", addr)
		}
	}
}

func TestScanBlock(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate an address
	addr, _ := w.NewAddress()
	parsedAddr, _ := address.DecodeAddress(addr, address.Mainnet)
	pkScript := parsedAddr.ScriptPubKey()

	// Create a mock block with a transaction to our address
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xffffffff,
				},
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    50000000, // 0.5 BTC
				PkScript: pkScript,
			},
		},
	}

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Timestamp: 1234567890,
		},
		Transactions: []*wire.MsgTx{tx},
	}

	// Scan block
	w.ScanBlock(block, 100)

	// Verify UTXO was added
	utxos := w.ListUnspent()
	if len(utxos) != 1 {
		t.Fatalf("Expected 1 UTXO, got %d", len(utxos))
	}

	if utxos[0].Amount != 50000000 {
		t.Errorf("UTXO amount = %d, want 50000000", utxos[0].Amount)
	}

	if utxos[0].Height != 100 {
		t.Errorf("UTXO height = %d, want 100", utxos[0].Height)
	}

	if utxos[0].IsCoinbase != true {
		t.Error("First tx should be marked as coinbase")
	}

	// Verify balance
	confirmed, _ := w.GetBalance()
	if confirmed != 50000000 {
		t.Errorf("Balance = %d, want 50000000", confirmed)
	}

	// Verify transaction history
	history := w.GetHistory()
	if len(history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(history))
	}
}

func BenchmarkNewAddress(b *testing.B) {
	config := WalletConfig{
		DataDir: b.TempDir(),
		Network: address.Mainnet,
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.NewAddress()
	}
}

func BenchmarkCreateTransaction(b *testing.B) {
	config := WalletConfig{
		DataDir:     b.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Add UTXOs
	for i := 0; i < 10; i++ {
		addr, _ := w.NewAddress()
		utxo := &WalletUTXO{
			OutPoint: wire.OutPoint{
				Hash:  wire.Hash256{byte(i)},
				Index: 0,
			},
			Amount:    1000000,
			Address:   addr,
			KeyPath:   BIP84Path(0, 0, 0, uint32(i)),
			Confirmed: true,
		}
		w.AddUTXO(utxo)
	}

	destAddr := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.CreateTransaction(destAddr, 100000, 1.0)
	}
}
