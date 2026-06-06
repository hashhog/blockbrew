package mempool

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestRemoveOrphansForPeer is the proven-teeth counterpart to the (flipped)
// p2p/w103_tx_relay_test.go::TestW103_G24 — it exercises the real orphan
// peer-attribution + EraseForPeer path on a live Mempool.
//
// W103 BUG-24 fix: orphans now carry the announcing peer's address (fromPeer),
// populated via AddTransactionFrom from the P2P tx-message handler. When a peer
// disconnects, RemoveOrphansForPeer evicts exactly that peer's orphans and
// retains everyone else's. Mirrors Bitcoin Core TxOrphanage::EraseForPeer
// (txorphanage.cpp), driven from net_processing.cpp::FinalizeNode.
func TestRemoveOrphansForPeer(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	const peerA = "10.0.0.1:8333"
	const peerB = "10.0.0.2:8333"

	// Build three distinct orphans (each spends a different missing parent
	// outpoint, so they have distinct txids): two announced by peerA, one by
	// peerB. AddTransactionFrom parks each in the orphan pool because its parent
	// is absent from the UTXO set.
	mkOrphan := func(seed byte, fromPeer string) wire.Hash256 {
		var missingHash wire.Hash256
		missingHash[0] = seed
		op := wire.OutPoint{Hash: missingHash, Index: 0}
		orphan := createTestTransaction([]wire.OutPoint{op}, 99_000, 1)
		if err := mp.AddTransactionFrom(orphan, fromPeer); err == nil {
			t.Fatalf("seed %d: expected missing-inputs error (parked as orphan)", seed)
		}
		return orphan.TxHash()
	}

	a1 := mkOrphan(0x21, peerA)
	a2 := mkOrphan(0x22, peerA)
	b1 := mkOrphan(0x23, peerB)

	if got := mp.OrphanCount(); got != 3 {
		t.Fatalf("setup: expected 3 orphans, got %d", got)
	}

	// peerA disconnects → only peerA's two orphans must be erased.
	removed := mp.RemoveOrphansForPeer(peerA)
	if removed != 2 {
		t.Fatalf("RemoveOrphansForPeer(peerA) returned %d, want 2", removed)
	}

	mp.mu.RLock()
	_, haveA1 := mp.orphans[a1]
	_, haveA2 := mp.orphans[a2]
	_, haveB1 := mp.orphans[b1]
	mp.mu.RUnlock()

	if haveA1 || haveA2 {
		t.Error("peerA's orphans should have been erased on disconnect")
	}
	if !haveB1 {
		t.Error("peerB's orphan must be retained when peerA disconnects")
	}
	if got := mp.OrphanCount(); got != 1 {
		t.Fatalf("after peerA disconnect: expected 1 orphan, got %d", got)
	}

	// Disconnecting peerA again is a no-op (idempotent).
	if removed := mp.RemoveOrphansForPeer(peerA); removed != 0 {
		t.Errorf("second RemoveOrphansForPeer(peerA) returned %d, want 0", removed)
	}

	// peerB disconnects → its orphan is erased, pool drains.
	if removed := mp.RemoveOrphansForPeer(peerB); removed != 1 {
		t.Fatalf("RemoveOrphansForPeer(peerB) returned %d, want 1", removed)
	}
	if got := mp.OrphanCount(); got != 0 {
		t.Fatalf("after peerB disconnect: expected 0 orphans, got %d", got)
	}
}

// TestRemoveOrphansForPeerSpareslocallyOriginated verifies that the empty-peer
// guard prevents a blank/missing peer address from wiping locally-originated /
// RPC / reorg-re-added orphans (which carry fromPeer=="").
func TestRemoveOrphansForPeerSparesLocallyOriginated(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Locally-originated orphan (no announcing peer) via the no-arg path.
	var missingHash wire.Hash256
	missingHash[0] = 0x31
	op := wire.OutPoint{Hash: missingHash, Index: 0}
	local := createTestTransaction([]wire.OutPoint{op}, 99_000, 1)
	if err := mp.AddTransaction(local); err == nil {
		t.Fatal("expected missing-inputs error (parked as orphan)")
	}
	if mp.OrphanCount() != 1 {
		t.Fatalf("expected 1 orphan, got %d", mp.OrphanCount())
	}

	// An empty peer address must NEVER erase the whole orphan pool.
	if removed := mp.RemoveOrphansForPeer(""); removed != 0 {
		t.Errorf("RemoveOrphansForPeer(\"\") returned %d, want 0 (empty-peer guard)", removed)
	}
	if mp.OrphanCount() != 1 {
		t.Fatalf("locally-originated orphan must survive empty-peer erase, count=%d", mp.OrphanCount())
	}
}
