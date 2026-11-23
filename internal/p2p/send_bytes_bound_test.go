package p2p

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// sendBytesTestBlockSize is the approximate serialized size of each block the
// test serves: one tx whose single output script carries the bulk.
const sendBytesTestBlockSize = 1_000_000

// sendBytesBudget is the most a peer that never reads may pin in our send
// path: Core's -maxsendbuffer default (1 MB, DEFAULT_MAXSENDBUFFER) plus the
// one message that crosses it (Core sets fPauseSend only once nSendSize is
// already above the limit), with room to spare. Master pins ~26 blocks.
const sendBytesBudget = 5 * sendBytesTestBlockSize

// bigGetDataTestBlock returns a distinct block of about 1 MB.
func bigGetDataTestBlock(nonce uint32) *wire.MsgBlock {
	tx := simpleTestTx(nonce)
	tx.TxOut[0].PkScript = make([]byte, sendBytesTestBlockSize)
	return &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1296688602, Bits: 0x207fffff, Nonce: nonce},
		Transactions: []*wire.MsgTx{tx},
	}
}

// TestSendQueueBoundedByBytes: a peer that asks for 50 distinct 1 MB blocks
// and then never reads must not make us hold 25-50 of them. Core accounts the
// send buffer in bytes (CConnman::PushMessage nSendSize, fPauseSend above
// -maxsendbuffer, net.cpp) and ProcessGetData stops serving while fPauseSend
// is set (net_processing.cpp); blockbrew paused only on a message count
// (half of the 50-slot send queue), so a slow reader pinned ~25 MB here and
// ~100-200 MB with 4 MB blocks.
//
// The peer runs the real writeHandler over a net.Pipe whose far end does not
// read, so one block is stuck in flight in the socket write and the rest sit
// in the send queue. Every block read from the DB is held in one of those two
// places (none can complete), so block reads x block size is exactly the
// bytes queued plus in flight.
func TestSendQueueBoundedByBytes(t *testing.T) {
	const n = 50
	var blocks []*wire.MsgBlock
	for i := uint32(0); i < n; i++ {
		blocks = append(blocks, bigGetDataTestBlock(1000+i))
	}
	sm, cdb := newGetDataTestSyncManager(t, blocks...)

	local, remote := net.Pipe()
	peer := createMockPeer("6.6.6.7:8333", 100)
	peer.conn = local
	peer.transport = NewV1Transport(local, peer.config.Network)
	peer.wg.Add(1)
	go peer.writeHandler()
	defer func() {
		peer.signalDisconnect()
		remote.Close()
		peer.wg.Wait()
	}()

	inv := make([]*InvVect, n)
	for i, b := range blocks {
		inv[i] = &InvVect{Type: InvTypeWitnessBlock, Hash: b.Header.BlockHash()}
	}
	sm.HandleGetData(peer, &MsgGetData{InvList: inv})

	// Let serving run until it stops (paused on backpressure).
	waitStable := func() int64 {
		last := cdb.blockReads.Load()
		stableSince := time.Now()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			cur := cdb.blockReads.Load()
			if cur != last {
				last, stableSince = cur, time.Now()
				continue
			}
			if time.Since(stableSince) > 300*time.Millisecond {
				break
			}
		}
		return last
	}
	reads := waitStable()
	if reads == 0 {
		t.Fatalf("no block served at all; the test is not measuring backpressure")
	}
	pinned := reads * sendBytesTestBlockSize
	t.Logf("a peer that never reads holds %d blocks (~%d bytes) queued + in flight", reads, pinned)
	if pinned > sendBytesBudget {
		t.Fatalf("a peer that never reads pinned %d blocks (~%d bytes queued + in flight), want <= %d bytes",
			reads, pinned, sendBytesBudget)
	}

	// The peer starts reading: every requested block is still delivered,
	// so the byte accounting releases what it counted (no wedge).
	go io.Copy(io.Discard, remote)
	deadline := time.Now().Add(20 * time.Second)
	for cdb.blockReads.Load() < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := cdb.blockReads.Load(); got < n {
		t.Fatalf("served %d of %d blocks after the peer started reading, want all", got, n)
	}
	deadline = time.Now().Add(10 * time.Second)
	for len(peer.sendQueue) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if q := len(peer.sendQueue); q != 0 {
		t.Fatalf("send queue still holds %d messages after the peer read everything", q)
	}
}
