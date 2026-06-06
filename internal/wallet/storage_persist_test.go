package wallet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// These tests pin the DATA-LOSS restart-persistence fix (sweep wa0fq5wtk):
//
//   - atomic + durable SaveToFile (temp + fsync + rename + dir fsync, .bak rota)
//   - fault-tolerant LoadFromFile (recover from .bak; never crash on a
//     corrupt/partial/missing primary; per-record recovery)
//   - save-on-mutation via the dirty flag + Flush, so a mutation survives a
//     SIMULATED unclean restart (no clean-shutdown SaveToFile)
//   - last_synced_height round-trips so the startup reconcile gap stays bounded
//
// "Proven teeth": each test reproduces the data-loss / crash the fix prevents
// (corrupt file, lost-mutation, unbounded rescan) and asserts the recovery.

func persistTestConfig(t *testing.T) WalletConfig {
	t.Helper()
	return WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}
}

// TestSaveRotatesBackupAndRoundTrips proves the atomic writer leaves a
// recoverable .bak after the SECOND save, and that last_synced_height
// round-trips through the file.
func TestSaveRotatesBackupAndRoundTrips(t *testing.T) {
	cfg := persistTestConfig(t)
	w := NewWallet(cfg)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, _ := w.NewAddress()
	w.SetLastSyncedHeight(123456)

	pw := "" // legacy unencrypted wallet uses the empty password
	if err := w.SaveToFile(pw); err != nil {
		t.Fatalf("first SaveToFile: %v", err)
	}
	walletPath := filepath.Join(cfg.DataDir, walletFileName)
	if _, err := os.Stat(walletPath); err != nil {
		t.Fatalf("wallet.dat not created: %v", err)
	}
	// No .bak yet (nothing to rotate on a first write).
	bakPath := walletPath + walletBakSuffix
	if _, err := os.Stat(bakPath); err == nil {
		t.Fatalf("unexpected .bak after first save")
	}
	// No leftover staging file.
	if _, err := os.Stat(walletPath + walletTmpSuffix); err == nil {
		t.Fatalf("leftover staging file after save")
	}

	// Second save rotates the previous good copy into .bak.
	if err := w.SaveToFile(pw); err != nil {
		t.Fatalf("second SaveToFile: %v", err)
	}
	if _, err := os.Stat(bakPath); err != nil {
		t.Fatalf(".bak not created on second save: %v", err)
	}

	// Round-trip: reload and confirm address + last_synced_height survived.
	loaded, err := LoadFromFile(cfg.DataDir, pw, cfg)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if !loaded.IsOwnAddress(addr) {
		t.Errorf("reloaded wallet lost address %s", addr)
	}
	if got := loaded.LastSyncedHeight(); got != 123456 {
		t.Errorf("last_synced_height = %d, want 123456", got)
	}
}

// TestLoadRecoversFromCorruptPrimaryViaBak proves the fault-tolerant load:
// a TRUNCATED / corrupt active wallet.dat must NOT crash startup and must
// transparently recover the prior good state from wallet.dat.bak.
func TestLoadRecoversFromCorruptPrimaryViaBak(t *testing.T) {
	cfg := persistTestConfig(t)
	w := NewWallet(cfg)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, _ := w.NewAddress()
	w.SetLastSyncedHeight(777)

	pw := ""
	// Save twice so a good .bak exists.
	if err := w.SaveToFile(pw); err != nil {
		t.Fatalf("save 1: %v", err)
	}
	// Mutate (advance keypool) then save again so .bak holds the FIRST good copy
	// and the primary holds the second.
	addr2, _ := w.NewAddress()
	if err := w.SaveToFile(pw); err != nil {
		t.Fatalf("save 2: %v", err)
	}

	walletPath := filepath.Join(cfg.DataDir, walletFileName)

	// Corrupt the primary file with a partial / garbage write (simulates a torn
	// write from a power-loss mid-rename on a filesystem without atomic rename,
	// or bit-rot). The .bak from save 1 is still intact.
	if err := os.WriteFile(walletPath, []byte("garbage-not-a-wallet"), 0600); err != nil {
		t.Fatalf("corrupting primary: %v", err)
	}

	// Must not panic and must recover from .bak (which had addr but not addr2).
	loaded, err := LoadFromFile(cfg.DataDir, pw, cfg)
	if err != nil {
		t.Fatalf("LoadFromFile did not recover from .bak: %v", err)
	}
	if !loaded.IsOwnAddress(addr) {
		t.Errorf("recovered wallet lost original address %s", addr)
	}
	if got := loaded.LastSyncedHeight(); got != 777 {
		t.Errorf("recovered last_synced_height = %d, want 777", got)
	}
	_ = addr2 // addr2 was only in the corrupted primary; .bak recovery is acceptable.

	// The recovery path re-stamps the primary from .bak; it must now be loadable
	// directly (no more corruption).
	reloaded, err := LoadFromFile(cfg.DataDir, pw, cfg)
	if err != nil {
		t.Fatalf("primary not repaired after recovery: %v", err)
	}
	if !reloaded.IsOwnAddress(addr) {
		t.Errorf("repaired primary lost address %s", addr)
	}
}

// TestLoadCorruptNoBakDoesNotCrash proves that a corrupt primary with NO backup
// returns an error gracefully (caller starts empty) rather than panicking.
func TestLoadCorruptNoBakDoesNotCrash(t *testing.T) {
	cfg := persistTestConfig(t)
	walletPath := filepath.Join(cfg.DataDir, walletFileName)
	if err := os.WriteFile(walletPath, []byte("xx"), 0600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_, err := LoadFromFile(cfg.DataDir, "", cfg)
	if err == nil {
		t.Fatalf("expected an error for corrupt file with no backup")
	}
	// The point is no panic; reaching here is success.
}

// TestLoadMissingFileReturnsNotExist confirms a genuinely-fresh datadir
// (no wallet.dat, no .bak) surfaces a not-exist error so the caller can start
// fresh without a scary "corruption" warning.
func TestLoadMissingFileReturnsNotExist(t *testing.T) {
	cfg := persistTestConfig(t)
	_, err := LoadFromFile(cfg.DataDir, "", cfg)
	if err == nil {
		t.Fatalf("expected not-exist error on empty datadir")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist error, got %v", err)
	}
}

// TestMutationSurvivesUncleanRestart is the headline regression: a wallet
// mutation (a per-block ScanBlock credit) made AFTER the last clean save must
// survive a SIMULATED unclean restart (SIGKILL/OOM). We model the crash by
// invoking ONLY the auto-flush path (Flush) — never the clean-shutdown
// SaveToFile — then reloading from disk in a brand-new Wallet, exactly as the
// node does on restart.
//
// Teeth: before this fix, ScanBlock did not mark the wallet dirty and the
// wallet only saved at clean shutdown, so this credit would be GONE after a
// kill. The test asserts both (a) ScanBlock flags dirty and (b) the credited
// UTXO + advanced last_synced_height are on disk after Flush alone.
func TestMutationSurvivesUncleanRestart(t *testing.T) {
	cfg := persistTestConfig(t)
	w := NewWallet(cfg)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, _ := w.NewAddress()

	// Baseline clean save (the "last clean shutdown").
	if err := w.SaveToFile(""); err != nil {
		t.Fatalf("baseline save: %v", err)
	}

	// Now a per-block credit arrives via the live connect loop (ScanBlock) —
	// this is the mutation that historically died on a SIGKILL.
	parsed, _ := address.DecodeAddress(addr, address.Mainnet)
	pkScript := parsed.ScriptPubKey()
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xab}, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 4200000, PkScript: pkScript}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Timestamp: 1700000000},
		Transactions: []*wire.MsgTx{tx},
	}
	w.ScanBlock(block, 500)

	// (a) ScanBlock must have flagged the wallet dirty.
	w.mu.RLock()
	dirty := w.dirty
	w.mu.RUnlock()
	if !dirty {
		t.Fatalf("ScanBlock did not mark the wallet dirty — a SIGKILL would lose the credit")
	}

	// (b) Simulate the auto-flusher firing (NOT a clean shutdown). This is the
	// ONLY durability the wallet gets before the simulated crash.
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// ── simulate SIGKILL: drop the in-memory wallet, reload from disk ──
	restarted, err := LoadFromFile(cfg.DataDir, "", cfg)
	if err != nil {
		t.Fatalf("reload after unclean restart: %v", err)
	}

	// The non-coinbase credit must be present (4200000 sat).
	utxos := restarted.ListUnspent()
	if len(utxos) != 1 {
		t.Fatalf("after unclean restart: expected 1 UTXO, got %d", len(utxos))
	}
	if utxos[0].Amount != 4200000 {
		t.Errorf("recovered UTXO amount = %d, want 4200000", utxos[0].Amount)
	}
	confirmed, _ := restarted.GetBalance()
	if confirmed != 4200000 {
		t.Errorf("recovered balance = %d, want 4200000", confirmed)
	}
	if got := restarted.LastSyncedHeight(); got != 500 {
		t.Errorf("recovered last_synced_height = %d, want 500", got)
	}
}

// TestFlushNoopWhenClean proves Flush does not write when there is nothing to
// persist (avoids gratuitous I/O on every tick).
func TestFlushNoopWhenClean(t *testing.T) {
	cfg := persistTestConfig(t)
	w := NewWallet(cfg)
	w.CreateFromMnemonic(testMnemonic, "")
	if err := w.SaveToFile(""); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Clear dirty (SaveToFile does not clear it; only Flush does).
	if err := w.Flush(); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	walletPath := filepath.Join(cfg.DataDir, walletFileName)
	st1, err := os.Stat(walletPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// A second Flush with no intervening mutation must be a no-op: the file
	// mtime must not change (no rewrite).
	if err := w.Flush(); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	st2, err := os.Stat(walletPath)
	if err != nil {
		t.Fatalf("stat2: %v", err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Errorf("clean Flush rewrote the file (mtime changed) — should be a no-op")
	}
}

// TestAutoFlushPersistsInBackground exercises the StartAutoFlush goroutine end
// to end: a mutation made while the flusher runs is durably written, and
// StopAutoFlush does a final drain.
func TestAutoFlushPersistsInBackground(t *testing.T) {
	cfg := persistTestConfig(t)
	w := NewWallet(cfg)
	w.CreateFromMnemonic(testMnemonic, "")
	// Tiny interval so the test is fast.
	w.StartAutoFlush(10 * 1000 * 1000) // 10ms
	addr, _ := w.NewAddress()
	w.SetLabel(addr, "background-label")
	// StopAutoFlush does a final synchronous flush, so by the time it returns
	// the mutation is guaranteed on disk regardless of ticker timing.
	w.StopAutoFlush()

	loaded, err := LoadFromFile(cfg.DataDir, "", cfg)
	if err != nil {
		t.Fatalf("load after auto-flush: %v", err)
	}
	if got := loaded.GetLabel(addr); got != "background-label" {
		t.Errorf("auto-flushed label = %q, want %q", got, "background-label")
	}
	// Double-stop must be safe.
	w.StopAutoFlush()
}
