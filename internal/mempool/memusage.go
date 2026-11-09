package mempool

import "github.com/hashhog/blockbrew/internal/wire"

// Core's mempool size limit (-maxmempool) is a limit on
// CTxMemPool::DynamicMemoryUsage (txmempool.cpp), not on the serialized or
// virtual size of the transactions. TrimToSize evicts while
// DynamicMemoryUsage() > sizelimit, GetMinFee picks the rolling-fee halflife
// from DynamicMemoryUsage() against the same limit, and getmempoolinfo /
// REST mempool/info report it as "usage". A transaction's in-memory
// footprint is several times its vsize (each input is a 112-byte CTxIn plus
// a mapNextTx node), so measuring by vsize keeps far more in the pool than
// Core does under the same -maxmempool.
//
// The numbers below are Core v31.1 on x86_64 / libstdc++ / glibc, the build
// the Core regtest harness compares against: the sizeof of each object that
// DynamicMemoryUsage charges, and memusage::MallocUsage for the allocator.

const (
	// sizeof(CTxIn): COutPoint 36 + padding, CScript (prevector<36>), nSequence, CScriptWitness.
	memCTxIn = 112
	// sizeof(CTxOut): nValue 8 + CScript.
	memCTxOut = 48
	// CScript is prevector<36, uint8_t>: up to 36 bytes live inline.
	memScriptInline = 36
	// sizeof(CTransaction).
	memCTransaction = 128
	// sizeof(stl_shared_counter) (memusage.h), the shared_ptr control block.
	memSharedCounter = 24
	// sizeof(std::vector<unsigned char>), one witness stack slot.
	memVectorHeader = 24
	// MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)): the mapTx node
	// charged per entry (txmempool.cpp:781).
	memMapTxElem = 136 + 9*8
	// stl_tree_node<pair<const COutPoint*, const CTransaction*>>: one
	// indirectmap node per spent outpoint (mapNextTx).
	memMapNextNode = 48
	// stl_tree_node<pair<const Txid, CAmount>>: one mapDeltas node.
	memMapDeltaNode = 72
	// sizeof(pair<Wtxid, txiter>): one txns_randomized element.
	memRandPair = 40
	// sizeof(TxGraphImpl::Entry).
	memGraphEntry = 80
	// stl_tree_node<ChunkData>: one m_main_chunkindex node per chunk.
	memChunkNode = 40
	// sizeof(SingletonClusterImpl) / sizeof(GenericClusterImpl).
	memSingletonCluster = 48
	memGenericCluster   = 104
	// The unique_ptr<Cluster> slot in the cluster set.
	memUniquePtr = 8
	// sizeof(DepGraph::Entry) for BitSet<64>: FeeFrac 16 + two 8-byte sets.
	memDepEntry = 32
	// GraphIndex / DepGraphIndex (uint32_t).
	memIndex = 4
)

// mallocUsage is memusage::MallocUsage for glibc on 64-bit: the request
// rounded up to 16 bytes plus 16 bytes of chunk overhead. Zero bytes
// allocate nothing.
func mallocUsage(alloc int64) int64 {
	if alloc <= 0 {
		return 0
	}
	return ((alloc + 31) >> 4) << 4
}

// scriptHeapUsage is the heap part of one CScript: nothing while it fits
// inline, otherwise one allocation of exactly its length (Unserialize
// resizes from empty).
func scriptHeapUsage(n int) int64 {
	if n <= memScriptInline {
		return 0
	}
	return mallocUsage(int64(n))
}

// txInnerUsage is RecursiveDynamicUsage(CTransactionRef) (core_memusage.h),
// which is what CTxMemPoolEntry::DynamicMemoryUsage returns and what
// cachedInnerUsage sums: the shared_ptr allocation, the vin and vout
// arrays, spilled scripts, and each witness stack with its items.
func txInnerUsage(tx *wire.MsgTx) int64 {
	mem := mallocUsage(int64(len(tx.TxIn))*memCTxIn) + mallocUsage(int64(len(tx.TxOut))*memCTxOut)
	for _, in := range tx.TxIn {
		mem += scriptHeapUsage(len(in.SignatureScript))
		mem += mallocUsage(int64(len(in.Witness)) * memVectorHeader)
		for _, item := range in.Witness {
			mem += mallocUsage(int64(len(item)))
		}
	}
	for _, out := range tx.TxOut {
		mem += scriptHeapUsage(len(out.PkScript))
	}
	return mem + mallocUsage(memCTransaction) + mallocUsage(memSharedCounter)
}

// txGraphClusterUsage is Cluster::TotalMemoryUsage for a main-level
// cluster of n transactions after Compact (every capacity equals n), plus
// its unique_ptr slot. One transaction is a SingletonClusterImpl; two or
// more are a GenericClusterImpl with its mapping, linearization and
// DepGraph entry arrays.
func txGraphClusterUsage(n int64) int64 {
	switch {
	case n <= 0:
		return 0
	case n == 1:
		return mallocUsage(memSingletonCluster) + memUniquePtr
	default:
		return mallocUsage(n*memIndex) + mallocUsage(n*memIndex) + mallocUsage(n*memDepEntry) +
			mallocUsage(memGenericCluster) + memUniquePtr
	}
}

// noteEntryAddedLocked does Core addNewTransaction's usage bookkeeping
// (txmempool.cpp:233-254) for an entry just put in mp.pool: it adds the
// entry to cachedInnerUsage and grows txns_randomized.
func (mp *Mempool) noteEntryAddedLocked(entry *TxEntry) {
	if entry.Tx != nil {
		entry.memInner = txInnerUsage(entry.Tx)
		mp.cachedInnerUsage += entry.memInner
	}
	mp.noteRandomizedAddLocked()
}

// noteEntryRemovedLocked undoes noteEntryAddedLocked for an entry just
// deleted from mp.pool (removeUnchecked, txmempool.cpp:289-303).
func (mp *Mempool) noteEntryRemovedLocked(entry *TxEntry) {
	if entry != nil {
		mp.cachedInnerUsage -= entry.memInner
		entry.memInner = 0
	}
	mp.noteRandomizedRemoveLocked()
}

// noteRandomizedAddLocked follows the capacity of Core's txns_randomized
// vector after one emplace_back (txmempool.cpp:253). libstdc++ grows a full
// vector to size + max(size, 1). Call after the entry is in mp.pool.
func (mp *Mempool) noteRandomizedAddLocked() {
	before := int64(len(mp.pool)) - 1
	if before < 0 {
		before = 0
	}
	if before+1 > mp.randomizedCap {
		grow := before
		if grow < 1 {
			grow = 1
		}
		mp.randomizedCap = before + grow
	}
}

// noteRandomizedRemoveLocked follows txns_randomized after removeUnchecked
// (txmempool.cpp:289-299): pop_back then shrink_to_fit when less than half
// full, except that removing the last element is clear(), which keeps the
// capacity. Call after the entry is gone from mp.pool.
func (mp *Mempool) noteRandomizedRemoveLocked() {
	after := int64(len(mp.pool))
	if after >= 1 && after*2 < mp.randomizedCap {
		mp.randomizedCap = after
	}
}

// dynamicMemoryUsageLocked is CTxMemPool::DynamicMemoryUsage
// (txmempool.cpp:778-782) evaluated over this pool:
//
//	MallocUsage(sizeof(CTxMemPoolEntry) + 9 pointers) * mapTx.size()
//	+ DynamicUsage(mapNextTx) + DynamicUsage(mapDeltas)
//	+ DynamicUsage(txns_randomized) + TxGraph::GetMainMemoryUsage()
//	+ cachedInnerUsage
//
// GetMainMemoryUsage (txgraph.cpp:3535) is the cluster usage, one Entry per
// transaction, and one chunk-index node per chunk. mapNextTx has one node
// per spent outpoint, which is mp.outpoints. The cost is one pass over the
// clusters, not over transactions or inputs. Must be called with mu held
// for writing: reading a dirty cluster's chunks relinearizes it.
func (mp *Mempool) dynamicMemoryUsageLocked() int64 {
	n := int64(len(mp.pool))
	inputs := int64(len(mp.outpoints))

	var clustersMem, chunks, clustered int64
	if mp.clusters != nil {
		for _, c := range mp.clusters.clusters {
			k := int64(c.Size())
			if k == 0 {
				continue
			}
			clustersMem += txGraphClusterUsage(k)
			chunks += int64(len(c.GetChunks()))
			clustered += k
		}
	}
	// An entry the cluster manager does not know (test injection) counts as
	// the singleton cluster Core would give it.
	if loose := n - clustered; loose > 0 {
		clustersMem += txGraphClusterUsage(1) * loose
		chunks += loose
	}
	graph := clustersMem + memGraphEntry*n + mallocUsage(memChunkNode)*chunks

	randCap := mp.randomizedCap
	if randCap < n {
		randCap = n
	}
	return mallocUsage(memMapTxElem)*n +
		mallocUsage(memMapNextNode)*inputs +
		mallocUsage(memMapDeltaNode)*int64(len(mp.mapDeltas)) +
		mallocUsage(randCap*memRandPair) +
		graph +
		mp.cachedInnerUsage
}

// feePerKFloor is CFeeRate(fee, vsize).GetFeePerK(): the feerate in
// sat/kvB rounded down (FeeFrac::EvaluateFeeDown(1000)), as TrimToSize uses
// it to bump the rolling minimum fee.
func feePerKFloor(fee, vsize int64) int64 {
	if vsize <= 0 {
		return 0
	}
	num := fee * 1000
	q := num / vsize
	if num%vsize != 0 && num < 0 {
		q--
	}
	return q
}

// DynamicMemoryUsage returns Core's CTxMemPool::DynamicMemoryUsage for this
// pool: the quantity -maxmempool limits and getmempoolinfo reports as
// "usage".
func (mp *Mempool) DynamicMemoryUsage() int64 {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return mp.dynamicMemoryUsageLocked()
}
