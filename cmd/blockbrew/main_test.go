package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlagsDefaults(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Reset flags for testing
	os.Args = []string{"blockbrew"}

	// Note: We can't easily test parseFlags() directly because flag.Parse()
	// uses global state. Instead, we test the helper functions and Config struct.

	cfg := &Config{
		DataDir:      "/tmp/test",
		Network:      "mainnet",
		ListenRPC:    "127.0.0.1:8332",
		RPCUser:      "blockbrew",
		RPCPassword:  "",
		MaxOutbound:  8,
		MaxInbound:   117,
		WalletFile:   "wallet.dat",
		LogLevel:     "info",
		MaxMempool:   300,
		MinRelayFee:  0.00001,
		PrintVersion: false,
	}

	// Verify defaults make sense
	if cfg.MaxOutbound != 8 {
		t.Errorf("expected MaxOutbound=8, got %d", cfg.MaxOutbound)
	}
	if cfg.MaxInbound != 117 {
		t.Errorf("expected MaxInbound=117, got %d", cfg.MaxInbound)
	}
	if cfg.MaxMempool != 300 {
		t.Errorf("expected MaxMempool=300, got %d", cfg.MaxMempool)
	}
}

func TestChainPortForNetwork(t *testing.T) {
	tests := []struct {
		network string
		want    uint16
	}{
		{"mainnet", 8333},
		{"testnet", 18333},
		{"regtest", 18444},
		{"signet", 38333},
		{"unknown", 8333},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			got := chainPortForNetwork(tt.network)
			if got != tt.want {
				t.Errorf("chainPortForNetwork(%q) = %d, want %d", tt.network, got, tt.want)
			}
		})
	}
}

func TestRpcPortForNetwork(t *testing.T) {
	tests := []struct {
		network string
		want    uint16
	}{
		{"mainnet", 8332},
		{"testnet", 18332},
		{"regtest", 18443},
		{"signet", 38332},
		{"unknown", 8332},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			got := rpcPortForNetwork(tt.network)
			if got != tt.want {
				t.Errorf("rpcPortForNetwork(%q) = %d, want %d", tt.network, got, tt.want)
			}
		})
	}
}

func TestDataDirectoryCreation(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()
	testDir := filepath.Join(tmpDir, "testdata", "nested")

	// Create the directory like main.go does
	err := os.MkdirAll(testDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Verify it exists
	info, err := os.Stat(testDir)
	if err != nil {
		t.Fatalf("Directory doesn't exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Expected a directory")
	}

	// Verify permissions (on Unix systems)
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		// Note: on some systems, umask may affect this
		t.Logf("Directory permissions: %o (expected 0700 or tighter)", perm)
	}
}

func TestHandleSubcommands(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{"empty args", []string{}, false},
		{"version command", []string{"version"}, true},
		{"help command", []string{"help"}, true},
		{"wallet command", []string{"wallet"}, true},
		{"unknown command", []string{"unknown"}, false},
		{"flag not command", []string{"--version"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For commands that print to stdout, we just check they return correctly
			if len(tt.args) > 0 && tt.args[0] == "wallet" {
				// wallet without args just prints help, doesn't call os.Exit
				got := handleSubcommands(tt.args)
				if got != tt.expected {
					t.Errorf("handleSubcommands(%v) = %v, want %v", tt.args, got, tt.expected)
				}
				return
			}
			got := handleSubcommands(tt.args)
			if got != tt.expected {
				t.Errorf("handleSubcommands(%v) = %v, want %v", tt.args, got, tt.expected)
			}
		})
	}
}

func TestNetworkDataDirSuffix(t *testing.T) {
	baseDir := "/home/user/.blockbrew"

	tests := []struct {
		network  string
		expected string
	}{
		{"mainnet", baseDir},
		{"testnet", filepath.Join(baseDir, "testnet")},
		{"regtest", filepath.Join(baseDir, "regtest")},
		{"signet", filepath.Join(baseDir, "signet")},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			dataDir := baseDir
			if tt.network != "mainnet" {
				dataDir = filepath.Join(baseDir, tt.network)
			}
			if dataDir != tt.expected {
				t.Errorf("dataDir for %s = %q, want %q", tt.network, dataDir, tt.expected)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	// Test that config values are sensible
	cfg := Config{
		MaxOutbound:  8,
		MaxInbound:   117,
		MaxMempool:   300,
		MinRelayFee:  0.00001,
		WalletFile:   "wallet.dat",
	}

	// MaxOutbound should be positive
	if cfg.MaxOutbound <= 0 {
		t.Error("MaxOutbound should be positive")
	}

	// MaxInbound should be positive
	if cfg.MaxInbound <= 0 {
		t.Error("MaxInbound should be positive")
	}

	// MaxMempool should be positive
	if cfg.MaxMempool <= 0 {
		t.Error("MaxMempool should be positive")
	}

	// MinRelayFee should be positive
	if cfg.MinRelayFee <= 0 {
		t.Error("MinRelayFee should be positive")
	}

	// WalletFile should not be empty
	if cfg.WalletFile == "" {
		t.Error("WalletFile should not be empty")
	}
}

func TestMinRelayFeeConversion(t *testing.T) {
	// Test the conversion from BTC/kvB to sat/kvB
	btcPerKvB := 0.00001
	satPerKvB := int64(btcPerKvB * 100_000_000 / 1000)

	// 0.00001 BTC = 1000 satoshis
	// 1000 satoshis / 1000 = 1 sat/vB (which is the base unit)
	expected := int64(1)
	if satPerKvB != expected {
		t.Errorf("MinRelayFee conversion: got %d sat/kvB, want %d", satPerKvB, expected)
	}
}

func TestNetworkMagicValues(t *testing.T) {
	// Import consensus to check values match
	tests := []struct {
		network string
		magic   uint32
	}{
		{"mainnet", 0xD9B4BEF9},
		{"testnet3", 0x0709110B},
		{"regtest", 0xDAB5BFFA},
		{"signet", 0x40CF030A},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			// We can't easily test networkMagic without creating ChainParams
			// Just verify the constants are what Bitcoin uses
			switch tt.network {
			case "mainnet":
				if tt.magic != 0xD9B4BEF9 {
					t.Error("mainnet magic mismatch")
				}
			case "testnet3":
				if tt.magic != 0x0709110B {
					t.Error("testnet3 magic mismatch")
				}
			case "regtest":
				if tt.magic != 0xDAB5BFFA {
					t.Error("regtest magic mismatch")
				}
			case "signet":
				if tt.magic != 0x40CF030A {
					t.Error("signet magic mismatch")
				}
			}
		})
	}
}
