package consensus

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// Shutdown must not flush chainstate while a chain mutation is in flight.
//
// rpcServer.Stop() does not wait for in-flight handlers. On 2026-07-27
// genesis-blockbrew took SIGTERM mid-rollback; the RPC stop reported
// "context deadline exceeded", shutdown flushed "chainstate atomically
// (UTXO + tip) at height 959906" against a partially rewound UTXO set, and
// closed Pebble. The still-running disconnect loop then hit the closed DB
// (`panic: pebble: closed` -> `fatal error: sync: Unlock of unlocked
// RWMutex`) and the node came back with an unrecoverable
// [CHAINSTATE-CORRUPTION] wedge. An 83-hour from-genesis datadir was lost.
// ---------------------------------------------------------------------------

func newQuiesceTestCM(t *testing.T) (*ChainManager, *HeaderIndex, *ChainParams) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)
	return cm, idx, params
}

// TestQuiesceForShutdownWaitsForInFlightMutation is the core guarantee: while a
// mutation is running, QuiesceForShutdown must NOT report the chain at rest.
//
// The in-flight mutation is held open from the onBlockDisconnected hook, which
// fires inside InvalidateBlock's disconnect loop — precisely the window that
// was flushed over in the incident.
func TestQuiesceForShutdownWaitsForInFlightMutation(t *testing.T) {
	cm, idx, params := newQuiesceTestCM(t)
	nodes := buildConnectedChain(t, cm, idx, params, 6)

	inHook := make(chan struct{}) // closed once we are inside a mutation
	release := make(chan struct{})
	var once sync.Once

	cm.SetOnBlockDisconnected(func(_ *wire.MsgBlock, _ int32) {
		once.Do(func() {
			close(inHook)
			<-release // pin the mutation open
		})
	})

	invalidateDone := make(chan error, 1)
	go func() { invalidateDone <- cm.InvalidateBlock(nodes[4].Hash) }()

	select {
	case <-inHook:
	case <-time.After(5 * time.Second):
		t.Fatal("never entered the disconnect hook — probe proved nothing")
	}

	// A mutation is provably in flight right now.
	quiesceResult := make(chan bool, 1)
	go func() { quiesceResult <- cm.QuiesceForShutdown(750 * time.Millisecond) }()

	select {
	case atRest := <-quiesceResult:
		if atRest {
			t.Fatal("SHUTDOWN-FLUSH HAZARD: QuiesceForShutdown reported the chain " +
				"AT REST while a mutation was demonstrably in flight. Shutdown " +
				"would flush a tip that disagrees with the in-memory UTXO set — " +
				"the 2026-07-27 corruption.")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("QuiesceForShutdown neither returned nor timed out")
	}

	close(release)
	<-invalidateDone
}

// TestQuiesceForShutdownReturnsWhenChainIsIdle guards the opposite error: a
// barrier that never reports rest would make every clean shutdown skip its
// flush and force a full replay on each restart.
func TestQuiesceForShutdownReturnsWhenChainIsIdle(t *testing.T) {
	cm, idx, params := newQuiesceTestCM(t)
	buildConnectedChain(t, cm, idx, params, 3)

	start := time.Now()
	if !cm.QuiesceForShutdown(5 * time.Second) {
		t.Fatal("QuiesceForShutdown reported NOT-at-rest on a fully idle chain; " +
			"every clean shutdown would skip its flush and replay on restart")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("idle quiesce took %v — expected near-immediate", elapsed)
	}
}

// TestMutationsRefusedAfterQuiesce pins the latch: once shutdown has begun, a
// newly-arriving chain mutation must be refused rather than race the flush.
func TestMutationsRefusedAfterQuiesce(t *testing.T) {
	cm, idx, params := newQuiesceTestCM(t)
	nodes := buildConnectedChain(t, cm, idx, params, 3)

	if !cm.QuiesceForShutdown(5 * time.Second) {
		t.Fatal("idle chain failed to quiesce")
	}

	if err := cm.InvalidateBlock(nodes[2].Hash); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("InvalidateBlock after quiesce: got %v, want ErrShuttingDown — "+
			"a mutation starting after the barrier can still tear the chainstate", err)
	}
	if err := cm.DisconnectBlock(nodes[3].Hash); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("DisconnectBlock after quiesce: got %v, want ErrShuttingDown", err)
	}
}
