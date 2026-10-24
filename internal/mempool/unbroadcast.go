package mempool

import (
	"bytes"
	"sort"

	"github.com/hashhog/blockbrew/internal/wire"
)

// AddUnbroadcastTx marks a pool transaction as locally submitted and not yet
// requested by any peer. Mirrors CTxMemPool::AddUnbroadcastTx
// (txmempool.cpp); called from sendrawtransaction. A txid that is not in the
// pool is ignored so the set can never name an entry removeSingleTxLocked
// would not clear.
func (mp *Mempool) AddUnbroadcastTx(txid wire.Hash256) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if _, ok := mp.pool[txid]; ok {
		mp.unbroadcast[txid] = struct{}{}
	}
}

// RemoveUnbroadcastTx clears the unbroadcast mark once a peer has fetched the
// tx. Mirrors CTxMemPool::RemoveUnbroadcastTx; net_processing.cpp calls it
// after answering a getdata for the tx.
func (mp *Mempool) RemoveUnbroadcastTx(txid wire.Hash256) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	delete(mp.unbroadcast, txid)
}

// IsUnbroadcastTx reports whether txid is awaiting its first peer request.
// Mirrors CTxMemPool::IsUnbroadcastTx (getmempoolentry "unbroadcast").
func (mp *Mempool) IsUnbroadcastTx(txid wire.Hash256) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	_, ok := mp.unbroadcast[txid]
	return ok
}

// UnbroadcastCount is the size of the unbroadcast set
// (getmempoolinfo "unbroadcastcount").
func (mp *Mempool) UnbroadcastCount() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.unbroadcast)
}

// UnbroadcastTxs returns a sorted copy of the unbroadcast set.
func (mp *Mempool) UnbroadcastTxs() []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	out := make([]wire.Hash256, 0, len(mp.unbroadcast))
	for h := range mp.unbroadcast {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}
