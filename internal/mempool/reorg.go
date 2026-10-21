package mempool

import (
	"bytes"
	"sort"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Keeping the mempool consistent with the active chain across block connects,
// disconnects, invalidateblock / reconsiderblock and reorgs.
//
// Bitcoin Core (validation.cpp, txmempool.cpp, kernel/disconnected_transactions):
//
//   - ConnectTip -> CTxMemPool::removeForBlock for EVERY connected block: the
//     confirmed transactions leave the pool, every in-mempool spend of the
//     same prevouts goes with its descendants (removeConflicts), and the
//     confirmed transactions leave the disconnect pool.
//   - DisconnectTip -> DisconnectedBlockTransactions::AddTransactionsFromBlock:
//     the block's non-coinbase transactions are stashed, NOT re-accepted yet.
//   - MaybeUpdateMempoolForReorg, after the disconnects/connects (InvalidateBlock
//     after each disconnected block, ActivateBestChainStep once at the end):
//     re-accept the stash earliest-first with bypass_limits; a transaction that
//     fails is removeRecursive'd (its in-mempool descendants go too); re-added
//     transactions adopt their in-mempool children (UpdateTransactionsFromBlock);
//     then removeForReorg drops every entry that is non-final, BIP68-locked or
//     spending an immature coinbase at tip+1, with descendants; then
//     LimitMempoolSize.
//
// The chain manager drives these under its chain lock (cm.mu), in the order
// Core does, so the mempool has caught up with the tip before the RPC that
// moved the tip returns.

// MaxDisconnectedTxPoolBytes caps the disconnect pool. Core:
// MAX_DISCONNECTED_TX_POOL_BYTES (kernel/disconnected_transactions.h), 20 MB
// of dynamic memory; measured here by transaction weight, which is at least
// the serialized size. A deep rollback (dumptxoutset rollback, a long
// invalidateblock) therefore cannot hold every disconnected transaction in
// memory until the update.
const MaxDisconnectedTxPoolBytes = 20_000_000

// BlockConnected removes the block's transactions from the mempool and every
// in-mempool transaction that conflicts with them (with descendants), and
// drops the block's transactions from the disconnect pool. Also arms the
// rolling-fee decay timer. Core: CTxMemPool::removeForBlock (txmempool.cpp)
// + DisconnectedBlockTransactions::removeForBlock.
func (mp *Mempool) BlockConnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.chainHeight++

	confirmed := make(map[wire.Hash256]struct{}, len(block.Transactions))
	for _, tx := range block.Transactions {
		txHash := tx.TxHash()
		confirmed[txHash] = struct{}{}
		// FIX-73: BLOCK for the confirmed tx itself, CONFLICT for a spender
		// of the same prevout (removeConflicts).
		mp.removeSingleTxLocked(txHash, MempoolRemovalReasonBlock)
		for _, in := range tx.TxIn {
			if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
				mp.removeWithDescendantsLocked(spendingTx, MempoolRemovalReasonConflict)
			}
		}
	}

	// A transaction confirmed again on the new branch must not be
	// re-accepted from the disconnect pool.
	if len(mp.disconnectPool) > 0 {
		for i, txs := range mp.disconnectPool {
			kept := txs[:0:0]
			for _, tx := range txs {
				if _, ok := confirmed[tx.TxHash()]; !ok {
					kept = append(kept, tx)
				} else {
					mp.disconnectBytes -= consensus.CalcTxWeight(tx)
				}
			}
			mp.disconnectPool[i] = kept
		}
	}

	// Core resets lastRollingFeeUpdate to GetTime() in removeForBlock so the
	// 10-second cooldown in getMinFeeRateLocked is measured from the block.
	mp.lastRollingFeeUpdate = time.Now().Unix()
	mp.blockSinceLastRollingFeeBump = true
}

// BlockDisconnected stashes a disconnected block's non-coinbase transactions
// in the disconnect pool. They are re-accepted by UpdateForReorg once the
// chain has reached the tip the transactions must be valid against. Core:
// DisconnectTip -> DisconnectedBlockTransactions::AddTransactionsFromBlock.
func (mp *Mempool) BlockDisconnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.chainHeight--
	if len(block.Transactions) <= 1 {
		return
	}
	txs := make([]*wire.MsgTx, 0, len(block.Transactions)-1)
	txs = append(txs, block.Transactions[1:]...)
	mp.disconnectPool = append(mp.disconnectPool, txs)
	for _, tx := range txs {
		mp.disconnectBytes += consensus.CalcTxWeight(tx)
	}
	// Core DisconnectedBlockTransactions::LimitMemoryUsage: over the cap,
	// evict from the front of the queue — the most recently confirmed
	// transactions (the first-disconnected block, last tx first) — and
	// removeRecursive each one (DisconnectTip).
	for mp.disconnectBytes > MaxDisconnectedTxPoolBytes && len(mp.disconnectPool) > 0 {
		front := mp.disconnectPool[0]
		if len(front) == 0 {
			mp.disconnectPool = mp.disconnectPool[1:]
			continue
		}
		tx := front[len(front)-1]
		mp.disconnectPool[0] = front[:len(front)-1]
		mp.disconnectBytes -= consensus.CalcTxWeight(tx)
		mp.removeRecursiveLocked(tx, MempoolRemovalReasonReorg)
	}
}

// DisconnectPoolSize returns the number of transactions waiting in the
// disconnect pool (diagnostics and tests).
func (mp *Mempool) DisconnectPoolSize() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	n := 0
	for _, txs := range mp.disconnectPool {
		n += len(txs)
	}
	return n
}

// UpdateForReorg drains the disconnect pool against the current tip. Core:
// Chainstate::MaybeUpdateMempoolForReorg (validation.cpp).
//
// With addToMempool, each stashed transaction is re-accepted, earliest
// confirmed first, through the ordinary admission checks minus the fee floor
// and size trim (bypass_limits). A transaction that is not re-accepted — or
// every transaction when addToMempool is false (Core: an InvalidateBlock
// deeper than 10 blocks) — is removed recursively: any in-mempool spender of
// its outputs goes, with descendants. Then every entry that the new tip makes
// invalid is dropped (removeForReorg) and the pool is trimmed to its size
// limit (LimitMempoolSize). All of it under one hold of mp.mu.
//
// Returns the number of transactions re-accepted and the number removed by
// the removeForReorg pass.
func (mp *Mempool) UpdateForReorg(addToMempool bool) (readded, removed int) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	stash := mp.disconnectPool
	mp.disconnectPool = nil
	mp.disconnectBytes = 0
	if consensus.IsAborted() {
		// The chain view may be torn after AbortNode; admit nothing.
		addToMempool = false
	}

	// Earliest confirmed first: the most recently disconnected block holds
	// the earliest transactions and sits last in the stash.
	for i := len(stash) - 1; i >= 0; i-- {
		for _, tx := range stash[i] {
			if _, ok := mp.pool[tx.TxHash()]; ok && addToMempool {
				// Relayed back in while the reorg ran (admission does not
				// take the chain lock): keep it, adopt its children.
				mp.linkInMempoolChildrenLocked(tx.TxHash())
				continue
			}
			if addToMempool {
				if err := mp.acceptLocked(tx, "", acceptOpts{reorg: true}); err == nil {
					mp.linkInMempoolChildrenLocked(tx.TxHash())
					readded++
					continue
				}
			}
			mp.removeRecursiveLocked(tx, MempoolRemovalReasonReorg)
		}
	}

	removed = mp.removeForReorgLocked()
	mp.maybeEvictLocked()
	return readded, removed
}

// removeRecursiveLocked removes tx and its in-mempool descendants; when tx
// itself is not in the pool, removes every in-mempool spender of its outputs
// (with descendants). Core: CTxMemPool::removeRecursive. mu must be held.
func (mp *Mempool) removeRecursiveLocked(tx *wire.MsgTx, reason MemPoolRemovalReason) {
	txHash := tx.TxHash()
	if _, ok := mp.pool[txHash]; ok {
		mp.removeWithDescendantsLocked(txHash, reason)
		return
	}
	for i := range tx.TxOut {
		if spender, ok := mp.outpoints[wire.OutPoint{Hash: txHash, Index: uint32(i)}]; ok {
			mp.removeWithDescendantsLocked(spender, reason)
		}
	}
}

// linkInMempoolChildrenLocked makes a transaction that was just re-accepted
// from a disconnected block the parent of the in-mempool transactions that
// already spend its outputs. Those children were admitted while the parent
// was confirmed, so neither side recorded the edge: without it a later
// removal of the parent (a conflict, removeForReorg) would leave the children
// behind spending an output that no longer exists, and the cluster and
// ancestor package the miner sees would be wrong. Core:
// CTxMemPool::UpdateTransactionsFromBlock. mu must be held.
func (mp *Mempool) linkInMempoolChildrenLocked(parentHash wire.Hash256) {
	parent, ok := mp.pool[parentHash]
	if !ok {
		return
	}
	linked := false
	seen := make(map[wire.Hash256]bool)
	for i := range parent.Tx.TxOut {
		childHash, ok := mp.outpoints[wire.OutPoint{Hash: parentHash, Index: uint32(i)}]
		if !ok || childHash == parentHash || seen[childHash] {
			continue
		}
		seen[childHash] = true
		child, ok := mp.pool[childHash]
		if !ok {
			continue
		}
		if hasParentLink(child.Depends, parentHash) {
			continue // already linked (admitted after the parent)
		}
		// One edge per spent output, the shape admission records.
		for _, in := range child.Tx.TxIn {
			if in.PreviousOutPoint.Hash == parentHash {
				child.Depends = append(child.Depends, parentHash)
				parent.SpentBy = append(parent.SpentBy, childHash)
				linked = true
			}
		}
	}
	if linked {
		mp.rebuildComponentLocked(parentHash)
	}
}

// rebuildComponentLocked recomputes the derived state of the connected
// component (by Depends/SpentBy edges) containing root after an edge was
// added: every member's ancestor and descendant fee/size, and the cluster
// structure, which is rebuilt in topological order so the merged cluster has
// every edge. A member that no longer fits the cluster limits is removed with
// its descendants (Core trims an oversized cluster after
// UpdateTransactionsFromBlock). mu must be held.
func (mp *Mempool) rebuildComponentLocked(root wire.Hash256) {
	comp := make(map[wire.Hash256]bool)
	queue := []wire.Hash256{root}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if comp[h] {
			continue
		}
		e, ok := mp.pool[h]
		if !ok {
			continue
		}
		comp[h] = true
		queue = append(queue, e.Depends...)
		queue = append(queue, e.SpentBy...)
	}

	walk := func(start wire.Hash256, next func(*TxEntry) []wire.Hash256) map[wire.Hash256]bool {
		out := make(map[wire.Hash256]bool)
		stack := append([]wire.Hash256(nil), next(mp.pool[start])...)
		for len(stack) > 0 {
			h := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if out[h] || h == start {
				continue
			}
			e, ok := mp.pool[h]
			if !ok {
				continue
			}
			out[h] = true
			stack = append(stack, next(e)...)
		}
		return out
	}
	deps := func(e *TxEntry) []wire.Hash256 { return e.Depends }
	kids := func(e *TxEntry) []wire.Hash256 { return e.SpentBy }

	type member struct {
		hash   wire.Hash256
		nAnc   int
		adjW   int64
		parent []wire.Hash256
	}
	members := make([]member, 0, len(comp))
	for h := range comp {
		e := mp.pool[h]
		anc := walk(h, deps)
		desc := walk(h, kids)
		e.AncestorFee, e.AncestorSize = e.Fee, e.Size
		for a := range anc {
			e.AncestorFee += mp.pool[a].Fee
			e.AncestorSize += mp.pool[a].Size
		}
		e.DescendantFee, e.DescendantSize = e.Fee, e.Size
		for d := range desc {
			e.DescendantFee += mp.pool[d].Fee
			e.DescendantSize += mp.pool[d].Size
		}
		adjW, ok := mp.clusters.txAdjWeight[h]
		if !ok {
			adjW = e.Size * 4
		}
		var parents []wire.Hash256
		pseen := make(map[wire.Hash256]bool)
		for _, p := range e.Depends {
			if !pseen[p] {
				pseen[p] = true
				parents = append(parents, p)
			}
		}
		members = append(members, member{hash: h, nAnc: len(anc), adjW: adjW, parent: parents})
	}

	// Ancestor count ascending is a topological order (a parent's ancestor
	// set is a strict subset of its child's); ties broken by txid so the
	// rebuilt cluster does not depend on map order.
	sort.Slice(members, func(i, j int) bool {
		if members[i].nAnc != members[j].nAnc {
			return members[i].nAnc < members[j].nAnc
		}
		return bytes.Compare(members[i].hash[:], members[j].hash[:]) < 0
	})

	for _, m := range members {
		mp.clusters.RemoveTransaction(m.hash)
	}
	for _, m := range members {
		e, ok := mp.pool[m.hash]
		if !ok {
			continue // removed with an oversized ancestor below
		}
		if _, err := mp.clusters.AddTransaction(m.hash, e.Fee, int32(e.Size), m.adjW, m.parent); err != nil {
			mp.removeWithDescendantsLocked(m.hash, MempoolRemovalReasonSizeLimit)
		}
	}
}

// RemoveForReorg evicts every mempool transaction the current tip makes
// invalid (see removeForReorgLocked), with descendants. Returns the number of
// transactions removed.
func (mp *Mempool) RemoveForReorg() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return mp.removeForReorgLocked()
}

// removeForReorgLocked drops every entry that at tip+1 is non-final
// (CheckFinalTxAtTip, BIP113), sequence-locked (CheckSequenceLocksAtTip,
// BIP68) or spends a coinbase that is immature at tip+1, with all of its
// in-mempool descendants. Core: CTxMemPool::removeForReorg (txmempool.cpp)
// with the check_final_and_mature callback from MaybeUpdateMempoolForReorg.
// A no-op when no ChainState is wired. mu must be held.
func (mp *Mempool) removeForReorgLocked() int {
	if mp.config.ChainState == nil {
		return 0
	}
	tipHeight := mp.config.ChainState.TipHeight()
	tipMTP := uint32(mp.config.ChainState.TipMTP())

	var invalid []wire.Hash256
	for txHash, entry := range mp.pool {
		if mp.txInvalidAtTip(entry.Tx, tipHeight, tipMTP) {
			invalid = append(invalid, txHash)
		}
	}

	visited := make(map[wire.Hash256]bool)
	stage := make([]wire.Hash256, 0)
	for _, txHash := range invalid {
		if !visited[txHash] {
			descs := mp.collectDescendantsLocked(txHash, visited)
			stage = append(stage, descs...)
			stage = append(stage, txHash)
			visited[txHash] = true
		}
	}

	n := 0
	for _, txHash := range stage {
		if _, ok := mp.pool[txHash]; !ok {
			continue
		}
		// FIX-73: RemoveForReorg -> REORG reason.
		mp.removeSingleTxLocked(txHash, MempoolRemovalReasonReorg)
		n++
	}
	return n
}

// txInvalidAtTip reports whether tx must be evicted after the tip moved to
// tipHeight. Core evaluates the three conditions for the NEXT block
// (tipHeight+1, the tip's median-time-past):
//  1. Non-final: IsFinalTx fails (CheckFinalTxAtTip).
//  2. BIP68 sequence locks not satisfied (CheckSequenceLocksAtTip); an
//     in-mempool parent counts as confirming at tip+1.
//  3. A confirmed coinbase input with fewer than CoinbaseMaturity
//     confirmations at tip+1 (in-mempool parents are skipped).
//
// mu must be held.
func (mp *Mempool) txInvalidAtTip(tx *wire.MsgTx, tipHeight int32, tipMTP uint32) bool {
	if !consensus.IsFinalTx(tx, tipHeight+1, tipMTP) {
		return true
	}
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		return true
	}
	if mp.utxoSet != nil {
		for _, in := range tx.TxIn {
			if _, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
				continue
			}
			utxo := mp.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil && utxo.IsCoinbase {
				if (tipHeight+1)-utxo.Height < consensus.CoinbaseMaturity {
					return true
				}
			}
		}
	}
	return false
}

func hasParentLink(hs []wire.Hash256, h wire.Hash256) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}
