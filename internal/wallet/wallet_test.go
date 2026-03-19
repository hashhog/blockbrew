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

// Tests for multi-address type support

func TestAddressGeneration(t *testing.T) {
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

	tests := []struct {
		name       string
		genFunc    func() (string, error)
		wantPrefix string
	}{
		{
			name:       "P2WPKH",
			genFunc:    w.NewP2WPKHAddress,
			wantPrefix: "bc1q",
		},
		{
			name:       "P2PKH",
			genFunc:    w.NewP2PKHAddress,
			wantPrefix: "1",
		},
		{
			name:       "P2SH-P2WPKH",
			genFunc:    w.NewP2SH_P2WPKHAddress,
			wantPrefix: "3",
		},
		{
			name:       "P2TR",
			genFunc:    w.NewP2TRAddress,
			wantPrefix: "bc1p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := tt.genFunc()
			if err != nil {
				t.Fatalf("Failed to generate %s address: %v", tt.name, err)
			}

			if !strings.HasPrefix(addr, tt.wantPrefix) {
				t.Errorf("%s address = %s, want prefix %s", tt.name, addr, tt.wantPrefix)
			}

			// Address should be recognized by wallet
			if !w.IsOwnAddress(addr) {
				t.Errorf("Wallet should recognize %s address %s", tt.name, addr)
			}
		})
	}
}

func TestP2PKHAddressDeterministic(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create first wallet
	w1 := NewWallet(config)
	w1.CreateFromMnemonic(testMnemonic, "")
	addr1, _ := w1.NewP2PKHAddress()

	// Create second wallet with same mnemonic
	w2 := NewWallet(config)
	w2.CreateFromMnemonic(testMnemonic, "")
	addr2, _ := w2.NewP2PKHAddress()

	// Addresses should match
	if addr1 != addr2 {
		t.Errorf("P2PKH addresses don't match: %s vs %s", addr1, addr2)
	}
}

func TestP2SH_P2WPKHAddressDeterministic(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create first wallet
	w1 := NewWallet(config)
	w1.CreateFromMnemonic(testMnemonic, "")
	addr1, _ := w1.NewP2SH_P2WPKHAddress()

	// Create second wallet with same mnemonic
	w2 := NewWallet(config)
	w2.CreateFromMnemonic(testMnemonic, "")
	addr2, _ := w2.NewP2SH_P2WPKHAddress()

	// Addresses should match
	if addr1 != addr2 {
		t.Errorf("P2SH-P2WPKH addresses don't match: %s vs %s", addr1, addr2)
	}
}

func TestP2TRAddressDeterministic(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create first wallet
	w1 := NewWallet(config)
	w1.CreateFromMnemonic(testMnemonic, "")
	addr1, _ := w1.NewP2TRAddress()

	// Create second wallet with same mnemonic
	w2 := NewWallet(config)
	w2.CreateFromMnemonic(testMnemonic, "")
	addr2, _ := w2.NewP2TRAddress()

	// Addresses should match
	if addr1 != addr2 {
		t.Errorf("P2TR addresses don't match: %s vs %s", addr1, addr2)
	}
}

func TestAddressTypeChangeAddress(t *testing.T) {
	tests := []struct {
		name       string
		addrType   WalletAddressType
		wantPrefix string
	}{
		{"P2WPKH", AddressTypeP2WPKH, "bc1q"},
		{"P2PKH", AddressTypeP2PKH, "1"},
		{"P2SH-P2WPKH", AddressTypeP2SH_P2WPKH, "3"},
		{"P2TR", AddressTypeP2TR, "bc1p"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := WalletConfig{
				DataDir:     t.TempDir(),
				Network:     address.Mainnet,
				ChainParams: consensus.MainnetParams(),
				AddressType: tt.addrType,
			}

			w := NewWallet(config)
			w.CreateFromMnemonic(testMnemonic, "")

			changeAddr, err := w.NewChangeAddress()
			if err != nil {
				t.Fatalf("NewChangeAddress failed: %v", err)
			}

			if !strings.HasPrefix(changeAddr, tt.wantPrefix) {
				t.Errorf("Change address = %s, want prefix %s", changeAddr, tt.wantPrefix)
			}
		})
	}
}

func TestCoinSelection(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Add multiple UTXOs with different values
	addrs := make([]string, 5)
	for i := 0; i < 5; i++ {
		addr, _ := w.NewAddress()
		addrs[i] = addr
		utxo := &WalletUTXO{
			OutPoint: wire.OutPoint{
				Hash:  wire.Hash256{byte(i)},
				Index: 0,
			},
			Amount:    int64((i + 1) * 100000), // 100k, 200k, 300k, 400k, 500k sats
			Address:   addr,
			KeyPath:   BIP84Path(0, 0, 0, uint32(i)),
			PkScript:  []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Confirmed: true,
		}
		w.AddUTXO(utxo)
	}

	// Test coin selection
	utxos := w.ListUnspent()
	result, err := SelectCoins(utxos, 350000, 1.0, 31)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected selection result")
	}

	// Total should cover target
	if result.Total < 350000 {
		t.Errorf("Selected total %d is less than target 350000", result.Total)
	}
}

func TestBnB(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Create UTXOs that can form an exact match
	// 50000 + 30000 = 80000 effective value (minus fees)
	amounts := []int64{50068, 30068, 20068} // Include input fee in amounts
	for i, amt := range amounts {
		addr, _ := w.NewAddress()
		utxo := &WalletUTXO{
			OutPoint: wire.OutPoint{
				Hash:  wire.Hash256{byte(i)},
				Index: 0,
			},
			Amount:    amt,
			Address:   addr,
			KeyPath:   BIP84Path(0, 0, 0, uint32(i)),
			PkScript:  []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Confirmed: true,
		}
		w.AddUTXO(utxo)
	}

	utxos := w.ListUnspent()
	result, err := SelectCoins(utxos, 80000, 1.0, 100)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected BnB to find a solution")
	}

	// BnB should be preferred when exact match is possible
	if result.Total < 80000 {
		t.Errorf("Total %d less than target", result.Total)
	}
}

func TestKnapsack(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Create UTXOs where no exact match exists
	amounts := []int64{100000, 60000, 35000}
	for i, amt := range amounts {
		addr, _ := w.NewAddress()
		utxo := &WalletUTXO{
			OutPoint: wire.OutPoint{
				Hash:  wire.Hash256{byte(i)},
				Index: 0,
			},
			Amount:    amt,
			Address:   addr,
			KeyPath:   BIP84Path(0, 0, 0, uint32(i)),
			PkScript:  []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Confirmed: true,
		}
		w.AddUTXO(utxo)
	}

	utxos := w.ListUnspent()
	// Target that doesn't have an exact match
	result, err := SelectCoins(utxos, 150000, 1.0, 31)
	if err != nil {
		t.Fatalf("SelectCoins failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected Knapsack to find a solution")
	}

	if result.Total < 150000 {
		t.Errorf("Total %d less than target", result.Total)
	}
}

// ============================================================================
// Address Label Tests
// ============================================================================

func TestSetLabel(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Set a label
	err := w.SetLabel(addr, "savings")
	if err != nil {
		t.Fatalf("SetLabel failed: %v", err)
	}

	// Get the label
	label := w.GetLabel(addr)
	if label != "savings" {
		t.Errorf("GetLabel = %q, want %q", label, "savings")
	}

	// Setting to different address not in wallet should fail
	err = w.SetLabel("bc1qsomeotheraddress", "test")
	if err != ErrInvalidAddress {
		t.Errorf("Expected ErrInvalidAddress for unknown address, got %v", err)
	}

	// Setting empty label removes it
	err = w.SetLabel(addr, "")
	if err != nil {
		t.Fatalf("SetLabel to empty failed: %v", err)
	}
	label = w.GetLabel(addr)
	if label != "" {
		t.Errorf("GetLabel after removal = %q, want empty", label)
	}
}

func TestListLabels(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Initially no labels
	labels := w.ListLabels()
	if len(labels) != 0 {
		t.Errorf("Expected 0 labels initially, got %d", len(labels))
	}

	// Create addresses and set labels
	addr1, _ := w.NewAddress()
	addr2, _ := w.NewAddress()
	addr3, _ := w.NewAddress()

	w.SetLabel(addr1, "savings")
	w.SetLabel(addr2, "business")
	w.SetLabel(addr3, "savings") // Duplicate label

	labels = w.ListLabels()
	if len(labels) != 2 {
		t.Errorf("Expected 2 unique labels, got %d", len(labels))
	}

	// Check that both labels exist
	found := make(map[string]bool)
	for _, l := range labels {
		found[l] = true
	}
	if !found["savings"] || !found["business"] {
		t.Errorf("Expected 'savings' and 'business' labels, got %v", labels)
	}
}

func TestGetAddressesByLabel(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr1, _ := w.NewAddress()
	addr2, _ := w.NewAddress()
	addr3, _ := w.NewAddress()

	w.SetLabel(addr1, "savings")
	w.SetLabel(addr2, "savings")
	w.SetLabel(addr3, "business")

	// Get addresses by label
	savingsAddrs := w.GetAddressesByLabel("savings")
	if len(savingsAddrs) != 2 {
		t.Errorf("Expected 2 savings addresses, got %d", len(savingsAddrs))
	}

	businessAddrs := w.GetAddressesByLabel("business")
	if len(businessAddrs) != 1 {
		t.Errorf("Expected 1 business address, got %d", len(businessAddrs))
	}

	// Non-existent label returns empty
	noAddrs := w.GetAddressesByLabel("nonexistent")
	if len(noAddrs) != 0 {
		t.Errorf("Expected 0 addresses for nonexistent label, got %d", len(noAddrs))
	}
}

func TestLabelsPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	config := WalletConfig{
		DataDir:     tmpDir,
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	// Create wallet and set labels
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr1, _ := w.NewAddress()
	addr2, _ := w.NewAddress()

	w.SetLabel(addr1, "savings")
	w.SetLabel(addr2, "business")

	// Save wallet
	password := "testpassword123"
	err := w.SaveToFile(password)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load wallet
	loaded, err := LoadFromFile(tmpDir, password, config)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Check labels persisted
	if loaded.GetLabel(addr1) != "savings" {
		t.Errorf("Label for addr1 not persisted, got %q", loaded.GetLabel(addr1))
	}
	if loaded.GetLabel(addr2) != "business" {
		t.Errorf("Label for addr2 not persisted, got %q", loaded.GetLabel(addr2))
	}
}

// ============================================================================
// Coinbase Maturity Tests
// ============================================================================

func TestCoinbaseMaturity(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Add a coinbase UTXO at height 100
	coinbaseUTXO := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{1, 2, 3},
			Index: 0,
		},
		Amount:     50_00000000, // 50 BTC
		Address:    addr,
		Height:     100,
		IsCoinbase: true,
		KeyPath:    "m/84'/0'/0'/0/0",
		Confirmed:  true,
	}
	w.AddUTXO(coinbaseUTXO)

	// Add a regular UTXO at same height
	regularUTXO := &WalletUTXO{
		OutPoint: wire.OutPoint{
			Hash:  wire.Hash256{4, 5, 6},
			Index: 0,
		},
		Amount:     10_00000000, // 10 BTC
		Address:    addr,
		Height:     100,
		IsCoinbase: false,
		KeyPath:    "m/84'/0'/0'/0/0",
		Confirmed:  true,
	}
	w.AddUTXO(regularUTXO)

	// At tip=148 (49 confirmations: 148-100+1=49), coinbase is immature
	tipHeight := int32(148)
	if w.IsUTXOSpendable(coinbaseUTXO, tipHeight) {
		t.Error("Coinbase should be immature at 49 confirmations")
	}
	if !w.IsUTXOSpendable(regularUTXO, tipHeight) {
		t.Error("Regular UTXO should be spendable")
	}

	// Check spendable balance
	spendable, immature := w.GetSpendableBalance(tipHeight)
	if spendable != 10_00000000 {
		t.Errorf("Spendable = %d, want 1000000000", spendable)
	}
	if immature != 50_00000000 {
		t.Errorf("Immature = %d, want 5000000000", immature)
	}

	// At tip=198 (99 confirmations: 198-100+1=99), coinbase is still immature
	tipHeight = 198
	if w.IsUTXOSpendable(coinbaseUTXO, tipHeight) {
		t.Error("Coinbase should be immature at 99 confirmations")
	}

	// At tip=199 (100 confirmations: 199-100+1=100), coinbase becomes mature
	tipHeight = 199
	if !w.IsUTXOSpendable(coinbaseUTXO, tipHeight) {
		t.Error("Coinbase should be mature at 100 confirmations")
	}

	spendable, immature = w.GetSpendableBalance(tipHeight)
	if spendable != 60_00000000 {
		t.Errorf("Spendable at maturity = %d, want 6000000000", spendable)
	}
	if immature != 0 {
		t.Errorf("Immature at maturity = %d, want 0", immature)
	}
}

func TestListSpendable(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Add immature coinbase
	w.AddUTXO(&WalletUTXO{
		OutPoint:   wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
		Amount:     100000,
		Address:    addr,
		Height:     100,
		IsCoinbase: true,
		KeyPath:    "m/84'/0'/0'/0/0",
		Confirmed:  true,
	})

	// Add mature coinbase
	w.AddUTXO(&WalletUTXO{
		OutPoint:   wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
		Amount:     200000,
		Address:    addr,
		Height:     50,
		IsCoinbase: true,
		KeyPath:    "m/84'/0'/0'/0/0",
		Confirmed:  true,
	})

	// Add regular UTXO
	w.AddUTXO(&WalletUTXO{
		OutPoint:   wire.OutPoint{Hash: wire.Hash256{3}, Index: 0},
		Amount:     300000,
		Address:    addr,
		Height:     100,
		IsCoinbase: false,
		KeyPath:    "m/84'/0'/0'/0/0",
		Confirmed:  true,
	})

	// ListUnspent should return all
	all := w.ListUnspent()
	if len(all) != 3 {
		t.Errorf("ListUnspent = %d, want 3", len(all))
	}

	// ListSpendable at tip=148 should exclude immature coinbase at height 100
	// Coinbase at height 100: 49 confirmations (148-100+1=49, immature)
	// Coinbase at height 50: 99 confirmations (148-50+1=99, immature)
	spendable := w.ListSpendable(148)
	if len(spendable) != 1 {
		t.Errorf("ListSpendable(148) = %d, want 1 (only regular UTXO)", len(spendable))
	}

	// At tip=149, coinbase at height 50 becomes mature (100 confirmations)
	spendable = w.ListSpendable(149)
	if len(spendable) != 2 {
		t.Errorf("ListSpendable(149) = %d, want 2", len(spendable))
	}

	// At tip=199, all should be spendable
	spendable = w.ListSpendable(199)
	if len(spendable) != 3 {
		t.Errorf("ListSpendable(199) = %d, want 3", len(spendable))
	}
}

func TestCreateTransactionWithImmatureCoinbase(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, _ := w.NewAddress()

	// Only add an immature coinbase UTXO
	w.AddUTXO(&WalletUTXO{
		OutPoint:   wire.OutPoint{Hash: wire.Hash256{1, 2, 3}, Index: 0},
		Amount:     50_00000000,
		Address:    addr,
		Height:     100,
		IsCoinbase: true,
		KeyPath:    "m/84'/0'/0'/0/0",
		PkScript:   []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Confirmed:  true,
	})

	// Try to create transaction at tip=148 (only 49 confirmations: 148-100+1=49)
	// Should fail because coinbase is immature
	_, err := w.CreateTransactionWithTip("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 1000000, 1.0, 148)
	if err != ErrInsufficientFunds {
		t.Errorf("Expected ErrInsufficientFunds for immature coinbase, got %v", err)
	}

	// At tip=199 (100 confirmations: 199-100+1=100), should succeed
	tx, err := w.CreateTransactionWithTip("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 1000000, 1.0, 199)
	if err != nil {
		t.Fatalf("CreateTransactionWithTip should succeed at maturity: %v", err)
	}
	if tx == nil {
		t.Error("Expected transaction to be created")
	}
}
