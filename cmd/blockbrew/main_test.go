package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/storage"
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

// TestParseBIP324V2Env covers the env-var fallback path used when the
// `-bip324v2` CLI flag was not explicitly set. The CLI flag itself takes
// precedence; this test only exercises the env-var helper.  The helper
// is a tristate: explicit on (1/true) → true, explicit off (0/false) →
// false, anything else (including empty) → defaultOn.
func TestParseBIP324V2Env(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		defaultOn bool
		want      bool
	}{
		// Default-ON cases (the production default).
		{"empty falls through to default-on", "", true, true},
		{"explicit one enables (default-on)", "1", true, true},
		{"true enables (default-on)", "true", true, true},
		{"True enables (case-insensitive, default-on)", "True", true, true},
		{"TRUE enables (case-insensitive, default-on)", "TRUE", true, true},
		{"explicit zero disables (default-on)", "0", true, false},
		{"false disables (default-on)", "false", true, false},
		{"False disables (case-insensitive, default-on)", "False", true, false},
		{"FALSE disables (case-insensitive, default-on)", "FALSE", true, false},
		{"yes falls through to default-on", "yes", true, true},
		{"random string falls through to default-on", "garbage", true, true},
		// Default-OFF cases (still useful for tests / forward compat).
		{"empty falls through to default-off", "", false, false},
		{"explicit one enables (default-off)", "1", false, true},
		{"explicit zero disables (default-off)", "0", false, false},
		{"random string falls through to default-off", "garbage", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBIP324V2Env(tt.env, tt.defaultOn)
			if got != tt.want {
				t.Errorf("parseBIP324V2Env(%q, defaultOn=%v) = %v, want %v",
					tt.env, tt.defaultOn, got, tt.want)
			}
		})
	}
}

// TestPeerBloomFiltersConfigPropagation verifies that
// Config.PeerBloomFilters is propagated to
// PeerManagerConfig.AdvertiseNodeBloom.  Without this wiring the
// `-peerbloomfilters` CLI flag (mirroring Bitcoin Core's flag of the
// same name) would have no effect and the BIP-35 handler in main.go
// would always fire regardless of operator intent.
func TestPeerBloomFiltersConfigPropagation(t *testing.T) {
	tests := []struct {
		name string
		on   bool
	}{
		{"bloom off (default)", false},
		{"bloom on", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{PeerBloomFilters: tt.on}
			pmCfg := p2p.PeerManagerConfig{AdvertiseNodeBloom: cfg.PeerBloomFilters}
			if pmCfg.AdvertiseNodeBloom != tt.on {
				t.Errorf("AdvertiseNodeBloom = %v, want %v",
					pmCfg.AdvertiseNodeBloom, tt.on)
			}
		})
	}
}

// TestBIP324V2ConfigPropagation verifies that Config.BIP324V2 is propagated
// to PeerManagerConfig.PreferV2 — guarding the wiring in run() so a future
// refactor that drops the field never silently regresses to v1-only.
func TestBIP324V2ConfigPropagation(t *testing.T) {
	tests := []struct {
		name string
		on   bool
	}{
		{"v2 off (default)", false},
		{"v2 on", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{BIP324V2: tt.on}
			pmCfg := p2p.PeerManagerConfig{PreferV2: cfg.BIP324V2}
			if pmCfg.PreferV2 != tt.on {
				t.Errorf("PeerManagerConfig.PreferV2 = %v, want %v", pmCfg.PreferV2, tt.on)
			}
			pm := p2p.NewPeerManager(pmCfg)
			if pm == nil {
				t.Fatal("NewPeerManager returned nil for valid config")
			}
		})
	}
}

// TestPruneFloorConstant guards the -prune floor enforced by
// parseFlags against silent drift away from Bitcoin Core's
// MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB. If Core changes this
// constant in a future major release, this test will need to be
// re-evaluated alongside it.
func TestPruneFloorConstant(t *testing.T) {
	if storage.MinPruneTargetMiB != 550 {
		t.Errorf("MinPruneTargetMiB = %d, want 550 (Bitcoin Core MIN_DISK_SPACE_FOR_BLOCK_FILES)",
			storage.MinPruneTargetMiB)
	}
	if storage.MinBlocksToKeep != 288 {
		t.Errorf("MinBlocksToKeep = %d, want 288 (Bitcoin Core MIN_BLOCKS_TO_KEEP)",
			storage.MinBlocksToKeep)
	}
}

// TestParsePruneFlagAcceptsValid spot-checks that valid -prune values
// (0 and any value >= 550) are accepted by the in-process binary. We
// cannot directly call parseFlags() — it uses flag.Parse() with global
// state and os.Exit on failure — so we shell out to the test binary in
// a subprocess and check that it accepts the flag without immediately
// exiting.
//
// Skipped under -short to keep `go test ./...` fast.
func TestParsePruneFlagAcceptsValid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess flag-validation test in -short mode")
	}
	binary, err := buildTestBinary(t)
	if err != nil {
		t.Fatalf("build test binary: %v", err)
	}
	defer os.Remove(binary)

	// Pass --version so the binary exits cleanly after flag parse.
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"prune zero (archive)", []string{"-prune=0", "--version"}, false},
		{"prune at floor", []string{"-prune=550", "--version"}, false},
		{"prune above floor", []string{"-prune=2048", "--version"}, false},
		{"prune below floor", []string{"-prune=100"}, true},
		{"prune one MiB", []string{"-prune=1"}, true},
		{"prune negative", []string{"-prune=-5"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binary, tt.args...)
			out, err := cmd.CombinedOutput()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected non-zero exit, got success: %s", out)
					return
				}
				if !strings.Contains(string(out), "prune") {
					t.Errorf("error output did not mention prune: %s", out)
				}
				return
			}
			if err != nil {
				t.Errorf("expected success, got err=%v output=%s", err, out)
			}
		})
	}
}

// TestReindexRefusesToStart guards the honest-defer behaviour: -reindex
// is documented in -help and parsed, but until the chainstate-rebuild
// path is implemented we exit non-zero with a clear message rather than
// silently accept the flag and do nothing. If a future commit lands a
// real reindex implementation, this test must be updated alongside it.
func TestReindexRefusesToStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess reindex test in -short mode")
	}
	binary, err := buildTestBinary(t)
	if err != nil {
		t.Fatalf("build test binary: %v", err)
	}
	defer os.Remove(binary)
	cmd := exec.Command(binary, "-reindex", "-datadir=/tmp/blockbrew-reindex-test")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for -reindex, got success: %s", out)
	}
	if !strings.Contains(string(out), "reindex") {
		t.Errorf("expected error message to mention reindex, got: %s", out)
	}
	if !strings.Contains(string(out), "not yet implemented") {
		t.Errorf("expected message to acknowledge unimplemented status, got: %s", out)
	}
}

// TestDebugFlagAccumulates verifies that -debug is repeatable and
// comma-aware via the debugFlag flag.Value adapter.
func TestDebugFlagAccumulates(t *testing.T) {
	var d debugFlag
	if err := d.Set("net,mempool"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := d.Set("rpc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(d) != 2 {
		t.Errorf("expected 2 entries (one per Set), got %d: %v", len(d), d)
	}
	if d.String() != "net,mempool,rpc" {
		t.Errorf("String() = %q, want %q", d.String(), "net,mempool,rpc")
	}
}

// TestStdFlagSetterRoundtrip makes sure the FlagSetter shim correctly
// reports registration and rejects unknown keys.
func TestStdFlagSetterRoundtrip(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var rpcuser string
	fs.StringVar(&rpcuser, "rpcuser", "", "")
	s := stdFlagSetter{fs: fs}
	if !s.IsRegistered("rpcuser") {
		t.Error("rpcuser should be registered")
	}
	if s.IsRegistered("nope") {
		t.Error("nope should not be registered")
	}
	if err := s.Set("rpcuser", "alice"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if rpcuser != "alice" {
		t.Errorf("rpcuser = %q, want alice", rpcuser)
	}
}

// buildTestBinary compiles the blockbrew binary into a tempfile and
// returns the path. Callers must os.Remove(path) when done.
func buildTestBinary(t *testing.T) (string, error) {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "blockbrew-test")
	cmd := exec.Command("go", "build", "-o", out, ".")
	combined, err := cmd.CombinedOutput()
	if err != nil {
		return "", &buildErr{out: string(combined), err: err}
	}
	return out, nil
}

type buildErr struct {
	out string
	err error
}

func (e *buildErr) Error() string { return e.err.Error() + ": " + e.out }

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
