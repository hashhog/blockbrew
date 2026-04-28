package p2p

import (
	"github.com/hashhog/blockbrew/internal/wire"
)

// MempoolTxidProvider is the minimal interface required to serve a BIP35
// "mempool" request.  It returns the unspent-tx-pool's known transaction
// hashes (txids).  internal/mempool.Mempool satisfies this via its
// GetAllTxHashes method.  Decoupling avoids an import cycle between p2p
// and mempool and lets the handler be unit-tested without a full pool.
type MempoolTxidProvider interface {
	GetAllTxHashes() []wire.Hash256
}

// HandleMempoolRequest builds the inv-message replies for a peer that sent
// us a "mempool" message (BIP35).  The peer is enumerated through provider
// once; the resulting txid list is split into one or more MsgInv messages
// of up to MaxInvVects entries each, mirroring Bitcoin Core's
// net_processing.cpp NetMsgType::MEMPOOL handler.
//
// Each inv vector is tagged InvTypeWitnessTx so witness-aware peers fetch
// the segwit-serialized transaction.  This matches the peermgr's existing
// RelayTransaction announcement convention (see peermgr.go).
//
// Gating: this function does NOT enforce the BIP111 NODE_BLOOM /
// permission policy that Bitcoin Core's handler does — blockbrew does not
// advertise NODE_BLOOM and has no per-peer permission system, so the
// caller is responsible for any policy checks (e.g. WantsTxRelay).
//
// If provider is nil, returns nil and the caller should silently ignore
// the request (avoids a nil-deref while keeping the dispatcher trivial).
func HandleMempoolRequest(peer *Peer, provider MempoolTxidProvider) []*MsgInv {
	if peer == nil || provider == nil {
		return nil
	}
	hashes := provider.GetAllTxHashes()
	if len(hashes) == 0 {
		return nil
	}

	// Pre-size the outer slice to avoid reallocs on huge mempools (a full
	// mainnet mempool can hold ~250k entries during fee spikes → 5 invs).
	batches := (len(hashes) + MaxInvVects - 1) / MaxInvVects
	invs := make([]*MsgInv, 0, batches)

	for start := 0; start < len(hashes); start += MaxInvVects {
		end := start + MaxInvVects
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := hashes[start:end]
		inv := &MsgInv{InvList: make([]*InvVect, len(batch))}
		for i, h := range batch {
			inv.InvList[i] = &InvVect{Type: InvTypeWitnessTx, Hash: h}
		}
		invs = append(invs, inv)
	}
	return invs
}
