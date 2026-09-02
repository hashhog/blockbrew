package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestConnectPendingBlocks_MarkerFirstDoesNotReApply pins finding #4.
//
// The in-order connect loop used to learn "this block is already applied" only
// from a FAILED connect: it called ConnectBlock and routed to AdoptAppliedBlock
// when the error contained "references missing UTXO". That inference is
// structurally blind to a coinbase-only block — no inputs, so no such error —
// which is re-applied in full, re-adding a coinbase a later block already
// spent.
//
// No crash is needed to get here: any recovery that halts below the coins
// marker leaves the tip low, and this loop resumes at tip+1 over blocks the
// persisted set already reflects.
//
// The fix asks the durable coins marker FIRST, exactly as recovery now does and
// exactly as Core does — the tip comes from coins_cache.GetBestBlock()
// (bitcoin-core/src/validation.cpp:4546) and only blocks above it are rolled
// forward (validation.cpp:4773 ReplayBlocks).
//
// Model: the coins marker covers height 15; the chain-tip pointer is at 10.
// Heights 11..15 MUST be adopted without a single ConnectBlock call; 16..20
// MUST be connected normally.
func TestConnectPendingBlocks_MarkerFirstDoesNotReApply(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	main := addChain(t, idx, idx.Genesis(), 20, 1)
	idx.MarkDataStored(idx.Genesis().Hash)
	for _, n := range main {
		idx.MarkDataStored(n.Hash)
	}

	const tipPointer = 10
	const coinsMarker = 15

	mock := &mockChainConnector{
		tipHash:   main[tipPointer-1].Hash,
		tipHeight: tipPointer,
	}

	var connected []int32
	var adopted []int32
	mock.connectFn = func(b *wire.MsgBlock) error {
		node := idx.GetNode(b.Header.BlockHash())
		if node == nil {
			t.Fatalf("connect of unknown block")
		}
		connected = append(connected, node.Height)
		mock.tipHash = node.Hash
		mock.tipHeight = node.Height
		return nil
	}
	// The marker covers everything up to coinsMarker: those blocks are already
	// in the persisted set, so the chain manager adopts (tip advance only).
	mock.adoptFlushedFn = func(b *wire.MsgBlock) (bool, error) {
		node := idx.GetNode(b.Header.BlockHash())
		if node == nil || node.Height > coinsMarker {
			return false, nil
		}
		adopted = append(adopted, node.Height)
		mock.tipHash = node.Hash
		mock.tipHeight = node.Height
		return true, nil
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})
	defer close(sm.quit)

	sm.mu.Lock()
	sm.nextHeight = tipPointer + 1
	sm.mu.Unlock()

	pending := make(map[int32]*blockWithRequest)
	for _, n := range main[tipPointer:] {
		pending[n.Height] = &blockWithRequest{
			block: &wire.MsgBlock{Header: n.Header},
			req:   &blockRequest{Hash: n.Hash, Height: n.Height, State: BlockDownloadReceived},
		}
	}

	sm.connectPendingBlocks(pending)

	for _, h := range connected {
		if h <= coinsMarker {
			t.Errorf("height %d was RE-APPLIED through ConnectBlock even though the "+
				"durable coins marker (%d) says the persisted UTXO set already reflects "+
				"it — a coinbase-only block here re-adds an output a later block spent",
				h, coinsMarker)
		}
	}
	if len(adopted) != coinsMarker-tipPointer {
		t.Errorf("adopted heights %v, want the %d blocks in (%d, %d]",
			adopted, coinsMarker-tipPointer, tipPointer, coinsMarker)
	}
	if len(connected) != 20-coinsMarker {
		t.Errorf("connected heights %v, want the %d blocks above the marker",
			connected, 20-coinsMarker)
	}
	if _, h := mock.BestBlock(); h != 20 {
		t.Errorf("tip = %d after the loop, want 20", h)
	}
	if sm.chainstateCorrupted.Load() {
		t.Errorf("chainstateCorrupted latched on a clean marker-first adopt")
	}
}
