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

// writeStubSnapshot writes just the snapshot metadata header for `blockHash`
// (with zero coins) so handleLoadTxOutSet can read the metadata and exercise
// the assumeutxo whitelist check without paying the cost of a full UTXO set.
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

// TestLoadTxOutSetRejectsRegtestGenesis verifies that loadtxoutset refuses any
// snapshot whose base_blockhash is not in m_assumeutxo_data for the active
// network, matching Bitcoin Core validation.cpp:5775-5780.
//
// Regtest has no AssumeUTXO entries; submitting a snapshot referencing the
// regtest genesis block must be rejected with the Core-strict wording.
func TestLoadTxOutSetRejectsRegtestGenesis(t *testing.T) {
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

	result, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected rejection, got result=%+v", result)
	}
	if rpcErr.Code != RPCErrVerify {
		t.Errorf("error code = %d, want %d (RPCErrVerify)", rpcErr.Code, RPCErrVerify)
	}
	if !strings.Contains(rpcErr.Message, "Assumeutxo height in snapshot metadata not recognized") {
		t.Errorf("error message %q does not contain Core-strict wording", rpcErr.Message)
	}
	if !strings.Contains(rpcErr.Message, "refusing to load snapshot") {
		t.Errorf("error message %q missing 'refusing to load snapshot'", rpcErr.Message)
	}
}

// TestLoadTxOutSetRejectsUnknownMainnetHash verifies the whitelist on a
// network that DOES have entries: an arbitrary unknown block hash on mainnet
// must still be rejected with the Core-strict wording.
func TestLoadTxOutSetRejectsUnknownMainnetHash(t *testing.T) {
	params := consensus.MainnetParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	// Fabricate a hash that is definitely not in MainnetAssumeUTXOParams.
	var bogus wire.Hash256
	for i := range bogus {
		bogus[i] = 0xab
	}

	tmpDir := t.TempDir()
	path := writeStubSnapshot(t, tmpDir, bogus, params.NetworkMagic)

	rawParams, err := json.Marshal([]interface{}{path})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected rejection of unknown mainnet block hash")
	}
	if rpcErr.Code != RPCErrVerify {
		t.Errorf("error code = %d, want %d (RPCErrVerify)", rpcErr.Code, RPCErrVerify)
	}
	if !strings.Contains(rpcErr.Message, "Assumeutxo height in snapshot metadata not recognized") {
		t.Errorf("error message %q does not contain Core-strict wording", rpcErr.Message)
	}
}

// TestLoadTxOutSetRejectsNetworkMismatch verifies the network-magic guard
// runs before the whitelist check and produces a network-related error.
func TestLoadTxOutSetRejectsNetworkMismatch(t *testing.T) {
	params := consensus.MainnetParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainDB(chainDB),
	)

	// Use one of the whitelisted mainnet hashes but with a bogus net magic.
	auData := consensus.MainnetAssumeUTXOParams.Data[0]
	bogusMagic := [4]byte{0xde, 0xad, 0xbe, 0xef}

	tmpDir := t.TempDir()
	path := writeStubSnapshot(t, tmpDir, auData.BlockHash, bogusMagic)

	rawParams, err := json.Marshal([]interface{}{path})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, rpcErr := server.handleLoadTxOutSet(rawParams)
	if rpcErr == nil {
		t.Fatalf("expected network-magic rejection")
	}
	if !strings.Contains(rpcErr.Message, "network") {
		t.Errorf("error message %q does not mention network", rpcErr.Message)
	}
}
