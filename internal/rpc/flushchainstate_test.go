package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
)

// TestHandleFlushChainState verifies the flushchainstate RPC returns null on
// success and a clear error when no chain DB is attached. Backs the
// stop_mainnet.sh pre-SIGTERM flush (receipts/GEN-BREW-pebble-corruption-sigkill).
func TestHandleFlushChainState(t *testing.T) {
	// Success: MemDB-backed ChainDB flushes to a null result.
	cdb := storage.NewChainDB(storage.NewMemDB())
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithChainDB(cdb))
	res, rerr := s.handleFlushChainState()
	if rerr != nil {
		t.Fatalf("handleFlushChainState error = %v, want nil", rerr)
	}
	if res != nil {
		t.Fatalf("handleFlushChainState result = %v, want nil (BIP-null)", res)
	}

	// No chain DB attached: must return a clear error, not panic.
	s2 := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})
	_, rerr2 := s2.handleFlushChainState()
	if rerr2 == nil {
		t.Fatalf("handleFlushChainState with nil chainDB = nil error, want RPCError")
	}
}
