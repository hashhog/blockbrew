package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
)

// newGetBlockTxnTestSyncManager returns a SyncManager whose chain DB holds the
// regtest genesis block (indexed at height 0) and whose tip is tipHeight, so
// the genesis block sits tipHeight blocks deep. Block-body reads are counted.
func newGetBlockTxnTestSyncManager(t *testing.T, tipHeight int32) (*SyncManager, *countingBlockDB) {
	t.Helper()
	params := consensus.RegtestParams()
	cdb := &countingBlockDB{DB: storage.NewMemDB()}
	db := storage.NewChainDB(cdb)
	genesis := params.GenesisBlock
	if err := db.StoreBlock(genesis.Header.BlockHash(), genesis); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	cdb.blockReads.Store(0)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  consensus.NewHeaderIndex(params),
		ChainDB:      db,
		ChainManager: &mockChainConnector{tipHeight: tipHeight},
	})
	return sm, cdb
}

// TestDeepGetBlockTxnUsesGetDataQueue pins the getblocktxn half of H2's
// backpressure. Core's ProcessMessage(GETBLOCKTXN) checks MAX_BLOCKTXN_DEPTH
// before any disk read and, for a deeper block, pushes a MSG_WITNESS_BLOCK
// onto m_getdata_requests (net_processing.cpp), which ProcessGetData serves
// subject to fPauseSend. blockbrew read the block first and sent it straight
// to the send queue, so a peer that never reads could make us read every deep
// block it named.
func TestDeepGetBlockTxnUsesGetDataQueue(t *testing.T) {
	sm, cdb := newGetBlockTxnTestSyncManager(t, 1000)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)
	fillSendQueue(t, peer)

	hash := sm.chainParams.GenesisBlock.Header.BlockHash()
	const requests = 100
	for i := 0; i < requests; i++ {
		sm.HandleGetBlockTxn(peer, &MsgGetBlockTxn{BlockHash: hash, Indexes: []uint32{0}})
	}
	if n := cdb.blockReads.Load(); n > 1 {
		t.Fatalf("%d getblocktxn requests for a block 1000 deep read %d blocks for a peer with a full send queue, want <= 1 (served through the paused getdata queue)",
			requests, n)
	}

	// The peer starts reading: the queued requests are served as full
	// witness blocks, not lost.
	deadline := time.Now().Add(5 * time.Second)
	blocks := 0
	for blocks < requests && time.Now().Before(deadline) {
		for _, m := range drainSent(peer) {
			switch msg := m.(type) {
			case *MsgBlock:
				if msg.NoWitness {
					t.Fatal("deep getblocktxn answered with a non-witness block, want MSG_WITNESS_BLOCK")
				}
				blocks++
			case *MsgBlockTxn:
				t.Fatal("deep getblocktxn answered with blocktxn, want the full block")
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if blocks != requests {
		t.Fatalf("served %d blocks after the peer drained its queue, want %d", blocks, requests)
	}
}

// A getblocktxn within MAX_BLOCKTXN_DEPTH is still answered directly with
// blocktxn, and one for an unknown block costs no read and gets no reply.
func TestGetBlockTxnShallowAndUnknown(t *testing.T) {
	sm, cdb := newGetBlockTxnTestSyncManager(t, MaxBlocktxnDepth)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	hash := sm.chainParams.GenesisBlock.Header.BlockHash()
	sm.HandleGetBlockTxn(peer, &MsgGetBlockTxn{BlockHash: hash, Indexes: []uint32{0}})
	sent := drainSent(peer)
	if len(sent) != 1 {
		t.Fatalf("shallow getblocktxn sent %d messages, want 1 blocktxn", len(sent))
	}
	if _, ok := sent[0].(*MsgBlockTxn); !ok {
		t.Fatalf("shallow getblocktxn sent %T, want *MsgBlockTxn", sent[0])
	}

	cdb.blockReads.Store(0)
	var unknown [32]byte
	unknown[0] = 0xab
	sm.HandleGetBlockTxn(peer, &MsgGetBlockTxn{BlockHash: unknown, Indexes: []uint32{0}})
	if n := cdb.blockReads.Load(); n != 0 {
		t.Fatalf("getblocktxn for an unknown block read %d blocks, want 0", n)
	}
	if sent := drainSent(peer); len(sent) != 0 {
		t.Fatalf("getblocktxn for an unknown block sent %d messages, want none", len(sent))
	}
}
