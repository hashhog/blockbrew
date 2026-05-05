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

// loadtxoutset RPC is gated to refuse-and-direct-at-CLI in this build, per
// the cross-impl audit at
// CORE-PARITY-AUDIT/_snapshot-cli-rpc-parity-audit-2026-05-05.md and the
// rustoshi 1d0a325 / hotbuns e355cd7 reference fixes. The handler must:
//
//   1. Refuse with RPCErrInternal (-32603).
//   2. Direct the operator at the -load-snapshot CLI flag.
//   3. NOT touch the filesystem (no os.Open, no Read).
//   4. NOT write any chainDB state.
//
// Tests below pin all four of those guarantees.

// TestLoadTxOutSetRefuses_FreshChain confirms the RPC refuses on a fresh,
// genesis-only chain (the most common scenario where an operator might try
// to bootstrap via the RPC instead of the CLI flag).
func TestLoadTxOutSetRefuses_FreshChain(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	rawParams, err := json.Marshal([]interface{}{"/some/snapshot.dat"})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected refusal, got result=%+v", result)
	}
	if rpcErr.Code != RPCErrInternal {
		t.Errorf("error code = %d, want %d (RPCErrInternal)", rpcErr.Code, RPCErrInternal)
	}
	if !strings.Contains(rpcErr.Message, "load-snapshot") {
		t.Errorf("error message %q does not direct operator at -load-snapshot CLI flag",
			rpcErr.Message)
	}
}

// TestLoadTxOutSetRefuses_DoesNotOpenFile verifies the gate fires BEFORE
// any filesystem I/O. We pass a path that doesn't exist; a pre-fix
// implementation would have errored on the os.Open call ("Failed to open
// file") long before reaching the gate. The post-fix path must short-circuit
// to the gate without touching the filesystem.
func TestLoadTxOutSetRefuses_DoesNotOpenFile(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	// Path does not exist; pre-fix would have returned "Failed to open file".
	bogusPath := filepath.Join(t.TempDir(), "does-not-exist.dat")
	if _, err := os.Stat(bogusPath); !os.IsNotExist(err) {
		t.Fatalf("test setup: expected ENOENT for %s, got %v", bogusPath, err)
	}

	rawParams, err := json.Marshal([]interface{}{bogusPath})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected refusal")
	}
	if rpcErr.Code != RPCErrInternal {
		t.Errorf("error code = %d, want %d (RPCErrInternal — gate fires before file I/O)",
			rpcErr.Code, RPCErrInternal)
	}
	if strings.Contains(rpcErr.Message, "Failed to open file") {
		t.Errorf("gate must fire before file I/O; got file-open error: %q", rpcErr.Message)
	}
}

// TestLoadTxOutSetRefuses_DoesNotWriteChainState pins the no-side-effects
// guarantee from the audit: a refused RPC must not bump SetChainState or
// SetBlockHeight on chainDB. Pre-fix, the handler reached utxoSet.Flush()
// and bumped chainDB state silently when the snapshot validated; post-fix
// the gate prevents any chainDB writes regardless of input.
func TestLoadTxOutSetRefuses_DoesNotWriteChainState(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	// Snapshot any pre-call chain state so we can compare after the refusal.
	preState, _ := chainDB.GetChainState()

	tmpDir := t.TempDir()
	path := writeStubSnapshot(t, tmpDir, params.GenesisHash, params.NetworkMagic)

	rawParams, err := json.Marshal([]interface{}{path})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected refusal")
	}

	postState, _ := chainDB.GetChainState()
	// Either both nil or both equal — refusal must not have written state.
	if (preState == nil) != (postState == nil) {
		t.Fatalf("chainDB state changed across refused RPC: pre=%v post=%v",
			preState, postState)
	}
	if preState != nil && postState != nil && *preState != *postState {
		t.Fatalf("chainDB state mutated by refused RPC: pre=%+v post=%+v",
			preState, postState)
	}
}

// writeStubSnapshot writes just the snapshot metadata header for `blockHash`
// (with zero coins) so that, in the (now-removed) code path that opened and
// parsed the snapshot, parsing would succeed. We keep it for the
// no-side-effects test even though the gate refuses without reading.
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
