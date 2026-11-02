package p2p

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// countingBlockDB wraps a storage.DB and counts reads of block bodies (the
// "B"-prefixed keys ChainDB.GetBlock reads when no flat-file store is
// attached), i.e. the disk reads a getdata costs us.
type countingBlockDB struct {
	storage.DB
	blockReads atomic.Int64
}

func (c *countingBlockDB) Get(key []byte) ([]byte, error) {
	if bytes.HasPrefix(key, storage.MakeBlockDataKey(wire.Hash256{})[:1]) {
		c.blockReads.Add(1)
	}
	return c.DB.Get(key)
}

// getDataTestBlock returns a distinct, serializable block (nonce makes the
// hash unique).
func getDataTestBlock(nonce uint32) *wire.MsgBlock {
	return &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1296688602, Bits: 0x207fffff, Nonce: nonce},
		Transactions: []*wire.MsgTx{simpleTestTx(nonce)},
	}
}

func newGetDataTestSyncManager(t *testing.T, blocks ...*wire.MsgBlock) (*SyncManager, *countingBlockDB) {
	t.Helper()
	cdb := &countingBlockDB{DB: storage.NewMemDB()}
	db := storage.NewChainDB(cdb)
	for _, b := range blocks {
		if err := db.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock: %v", err)
		}
	}
	cdb.blockReads.Store(0)
	params := consensus.RegtestParams()
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: consensus.NewHeaderIndex(params),
		ChainDB:     db,
	})
	return sm, cdb
}

// TestSecurityGetDataServeBound_H2 pins security finding H2: one getdata
// carrying MAX_INV_SZ (50,000) entries of the same known block must not cost
// 50,000 disk reads and block builds in the peer's read goroutine, read only
// to be dropped on a full send queue. Core's ProcessGetData serves at most
// one BLOCK item per call and stops while fPauseSend is set, leaving the rest
// in Peer::m_getdata_requests (net_processing.cpp); blockbrew must do the
// same and still deliver everything once the peer reads.
func TestSecurityGetDataServeBound_H2(t *testing.T) {
	t.Run("full_send_queue_reads_nothing_and_loses_nothing", testGetDataFullSendQueue)
	t.Run("one_block_per_call_and_pause_while_stalled", testGetDataOneBlockPerCall)
	t.Run("honest_ibd_batch_delivered_in_order", testGetDataHonestIBDBatch)
	t.Run("mixed_blocks_and_txs_every_item_answered", testGetDataMixedAnswered)
}

func fillSendQueue(t *testing.T, peer *Peer) {
	t.Helper()
	for i := 0; i < SendQueueSize; i++ {
		if !peer.SendMessage(&MsgPing{Nonce: uint64(i)}) {
			t.Fatalf("could not pre-fill send queue at %d", i)
		}
	}
}

// A peer whose send queue is already full: HandleGetData must not read a
// single block only to drop it (master read and dropped all 50,000), and the
// requests must stay queued: once the peer reads, they are served.
func testGetDataFullSendQueue(t *testing.T) {
	blk := getDataTestBlock(1)
	sm, cdb := newGetDataTestSyncManager(t, blk)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)
	fillSendQueue(t, peer)

	hash := blk.Header.BlockHash()
	inv := make([]*InvVect, MaxInvVects)
	for i := range inv {
		inv[i] = &InvVect{Type: InvTypeWitnessBlock, Hash: hash}
	}
	sm.HandleGetData(peer, &MsgGetData{InvList: inv})
	if n := cdb.blockReads.Load(); n > 1 {
		t.Fatalf("HandleGetData read %d blocks for a peer with a full send queue, want <= 1", n)
	}

	// The peer starts reading: the queued requests are served, not lost.
	deadline := time.Now().Add(5 * time.Second)
	blocks := 0
	for blocks < 2*SendQueueSize && time.Now().Before(deadline) {
		for _, m := range drainSent(peer) {
			if _, ok := m.(*MsgBlock); ok {
				blocks++
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if blocks < 2*SendQueueSize {
		t.Fatalf("served %d blocks after the peer drained its queue, want the queued requests served", blocks)
	}
}

// One getdata of 50,000 entries must not cost more than one block read before
// the read goroutine returns, and a stalled peer must pause serving.
//
// The send queue starts one message short of half full, so the one block a
// call may serve is the one that backs it up: anything that kept serving in
// the background after the call would be reading past the bound, which keeps
// the "<= 1" check free of a race with the background drain.
func testGetDataOneBlockPerCall(t *testing.T) {
	blk := getDataTestBlock(1)
	sm, cdb := newGetDataTestSyncManager(t, blk)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)
	for i := 0; i < SendQueueSize/2-1; i++ {
		if !peer.SendMessage(&MsgPing{Nonce: uint64(i)}) {
			t.Fatalf("could not pre-fill send queue at %d", i)
		}
	}

	hash := blk.Header.BlockHash()
	inv := make([]*InvVect, MaxInvVects)
	for i := range inv {
		inv[i] = &InvVect{Type: InvTypeWitnessBlock, Hash: hash}
	}

	sm.HandleGetData(peer, &MsgGetData{InvList: inv})
	if n := cdb.blockReads.Load(); n > 1 {
		t.Fatalf("HandleGetData read %d blocks before returning to the read loop, want <= 1", n)
	}

	// Nobody drains the send queue: whatever keeps serving in the background
	// must stop once the queue is full rather than read-and-drop.
	time.Sleep(200 * time.Millisecond)
	if n := cdb.blockReads.Load(); n > int64(SendQueueSize) {
		t.Fatalf("%d block reads with a stalled peer (send queue %d), want serving to pause", n, SendQueueSize)
	}
	paused := cdb.blockReads.Load()

	// Consuming the queue lets serving resume: the request is queued, not lost.
	deadline := time.Now().Add(5 * time.Second)
	served := 0
	for served < 3*SendQueueSize && time.Now().Before(deadline) {
		served += len(drainSent(peer))
		time.Sleep(5 * time.Millisecond)
	}
	if served < 3*SendQueueSize {
		t.Fatalf("served %d blocks after draining (paused at %d reads), want serving to resume", served, paused)
	}
}

// An honest IBD peer's getdata of 16 blocks (MAX_BLOCKS_IN_TRANSIT_PER_PEER)
// still receives all 16, in order, with no further message from the peer.
func testGetDataHonestIBDBatch(t *testing.T) {
	var blocks []*wire.MsgBlock
	for i := uint32(0); i < 16; i++ {
		blocks = append(blocks, getDataTestBlock(100+i))
	}
	sm, _ := newGetDataTestSyncManager(t, blocks...)
	peer := createMockPeer("1.2.3.4:8333", 100)
	defer close(peer.quit)

	inv := make([]*InvVect, len(blocks))
	for i, b := range blocks {
		inv[i] = &InvVect{Type: InvTypeWitnessBlock, Hash: b.Header.BlockHash()}
	}
	sm.HandleGetData(peer, &MsgGetData{InvList: inv})

	var got []wire.Hash256
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < len(blocks) && time.Now().Before(deadline) {
		for _, m := range drainSent(peer) {
			mb, ok := m.(*MsgBlock)
			if !ok {
				t.Fatalf("unexpected %s reply", m.Command())
			}
			got = append(got, mb.Block.Header.BlockHash())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(got) != len(blocks) {
		t.Fatalf("delivered %d of %d blocks", len(got), len(blocks))
	}
	for i, b := range blocks {
		if got[i] != b.Header.BlockHash() {
			t.Fatalf("block %d out of order", i)
		}
	}
}

// A getdata mixing blocks and unknown txs, and a second getdata sent
// while the first is still being served: every block arrives once, in request
// order across both messages, and every tx gets a notfound (no mempool).
func testGetDataMixedAnswered(t *testing.T) {
	var blocks []*wire.MsgBlock
	for i := uint32(0); i < 8; i++ {
		blocks = append(blocks, getDataTestBlock(200+i))
	}
	sm, _ := newGetDataTestSyncManager(t, blocks...)
	peer := createMockPeer("1.2.3.5:8333", 100)
	defer close(peer.quit)

	var wantBlocks []wire.Hash256
	wantTx := map[wire.Hash256]bool{}
	mk := func(bs []*wire.MsgBlock, txSeed uint32) []*InvVect {
		var inv []*InvVect
		for i, b := range bs {
			h := b.Header.BlockHash()
			wantBlocks = append(wantBlocks, h)
			inv = append(inv, &InvVect{Type: InvTypeWitnessBlock, Hash: h})
			th := wire.Hash256{byte(txSeed), byte(i), 0xee}
			wantTx[th] = true
			inv = append(inv, &InvVect{Type: InvTypeWitnessTx, Hash: th})
		}
		return inv
	}
	sm.HandleGetData(peer, &MsgGetData{InvList: mk(blocks[:4], 1)})
	sm.HandleGetData(peer, &MsgGetData{InvList: mk(blocks[4:], 2)})

	var got []wire.Hash256
	gotTx := map[wire.Hash256]int{}
	deadline := time.Now().Add(5 * time.Second)
	for (len(got) < len(wantBlocks) || len(gotTx) < len(wantTx)) && time.Now().Before(deadline) {
		for _, m := range drainSent(peer) {
			switch v := m.(type) {
			case *MsgBlock:
				got = append(got, v.Block.Header.BlockHash())
			case *MsgNotFound:
				for _, iv := range v.InvList {
					gotTx[iv.Hash]++
				}
			default:
				t.Fatalf("unexpected %s reply", m.Command())
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(got) != len(wantBlocks) {
		t.Fatalf("delivered %d of %d blocks", len(got), len(wantBlocks))
	}
	for i := range wantBlocks {
		if got[i] != wantBlocks[i] {
			t.Fatalf("block %d out of order", i)
		}
	}
	for h := range wantTx {
		if gotTx[h] != 1 {
			t.Fatalf("tx %x answered %d times with notfound, want 1", h[:3], gotTx[h])
		}
	}
	if len(gotTx) != len(wantTx) {
		t.Fatalf("notfound for %d items, want %d", len(gotTx), len(wantTx))
	}
}
