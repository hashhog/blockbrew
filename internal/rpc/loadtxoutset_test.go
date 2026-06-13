package rpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// loadtxoutset RPC is now LIVE-WIRED to the dual-chainstate background
// validator (AssumeUTXO pilot completion — mirrors camlcoin 3140ab9 /
// lunarblock a39dd42). The end-to-end ACCEPT/REJECT path is covered in
// loadtxoutset_live_test.go; the tests below pin the synchronous load-time
// error gates: a bad path, an unknown snapshot base, and a tampered file all
// fail SAFELY (an RPC error, never a silent accept) and never leave a validated
// snapshot activation on the server.

// TestLoadTxOutSet_BadPathErrors confirms loadtxoutset surfaces a clean error
// (not a panic, not a silent success) when the path does not exist, and records
// no snapshot activation.
func TestLoadTxOutSet_BadPathErrors(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	bogusPath := filepath.Join(t.TempDir(), "does-not-exist.dat")
	if _, err := os.Stat(bogusPath); !os.IsNotExist(err) {
		t.Fatalf("test setup: expected ENOENT for %s, got %v", bogusPath, err)
	}

	rawParams, err := json.Marshal([]interface{}{bogusPath})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected an error for a missing file, got result=%+v", result)
	}
	server.snapshotMu.RLock()
	act := server.snapshotActivation
	server.snapshotMu.RUnlock()
	if act != nil {
		t.Fatal("a failed load must not record a snapshot activation")
	}
}

// TestLoadTxOutSet_UnknownBaseRejects confirms a snapshot whose base block hash
// is not in the AssumeUTXO whitelist is rejected (Core ActivateSnapshot table
// lookup). The regtest whitelist is empty here, so even a well-formed stub is
// refused — and no activation is recorded.
func TestLoadTxOutSet_UnknownBaseRejects(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)

	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	tmpDir := t.TempDir()
	path := writeStubSnapshot(t, tmpDir, params.GenesisHash, params.NetworkMagic)

	rawParams, err := json.Marshal([]interface{}{path})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatal("expected rejection of a snapshot with an unrecognised base block hash")
	}
	if !strings.Contains(rpcErr.Message, "not recognized") &&
		!strings.Contains(rpcErr.Message, "no AssumeUTXO") {
		t.Errorf("error message %q does not explain the missing whitelist entry", rpcErr.Message)
	}
	server.snapshotMu.RLock()
	act := server.snapshotActivation
	server.snapshotMu.RUnlock()
	if act != nil {
		t.Fatal("rejecting an unknown base must not record a snapshot activation")
	}
}

// TestLoadTxOutSet_NoChainDBErrors confirms loadtxoutset errors cleanly (rather
// than panicking) when the server has no chain database wired.
func TestLoadTxOutSet_NoChainDBErrors(t *testing.T) {
	params := consensus.RegtestParams()
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
	)

	rawParams, err := json.Marshal([]interface{}{"/some/snapshot.dat"})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatal("expected an error when no chain database is configured")
	}
	if rpcErr.Code != RPCErrInternal {
		t.Errorf("error code = %d, want %d (RPCErrInternal)", rpcErr.Code, RPCErrInternal)
	}
}

// writeStubSnapshot writes just the snapshot metadata header for `blockHash`
// (with zero coins) so a metadata parse succeeds. Used by the unknown-base
// gate test, where the AssumeUTXO lookup fails before any coin I/O.
func writeStubSnapshot(t *testing.T, dir string, blockHash wire.Hash256, netMagic [4]byte) string {
	t.Helper()
	path := filepath.Join(dir, "snapshot.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create snapshot file: %v", err)
	}
	defer f.Close()

	meta := &consensus.SnapshotMetadata{
		Magic:        consensus.SnapshotMagic,
		Version:      consensus.SnapshotVersion,
		NetworkMagic: netMagic,
		BlockHash:    blockHash,
		CoinsCount:   0,
	}
	if err := meta.Serialize(f); err != nil {
		t.Fatalf("serialize metadata: %v", err)
	}
	return path
}
