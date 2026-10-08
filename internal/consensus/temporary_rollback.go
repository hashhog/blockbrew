package consensus

// ExternalWriter takes the chain-writer gate shared for one external chain
// mutation (a P2P block connect, submitblock, generate, invalidate/reconsider/
// precious). It waits while a dumptxoutset rollback holds the chain at an
// earlier block, exactly as Core's P2P block processing is suspended by
// NetworkDisable and as RPC writers queue on cs_main. The returned func
// releases the gate; call it once, and never take the gate twice on the same
// goroutine (Go's RWMutex is not reentrant once a pauser is waiting).
func (cm *ChainManager) ExternalWriter() func() {
	cm.extWriters.RLock()
	return cm.extWriters.RUnlock
}

// PauseExternalWriters is the TemporaryRollback side of the gate: it waits for
// in-flight external writers to finish, then excludes new ones until the
// returned func is called. The holder drives ReorgTo directly (ReorgTo does not
// take the gate). Core: rpc/blockchain.cpp dumptxoutset (NetworkDisable +
// TemporaryRollback, restored when the scope ends, success or error).
func (cm *ChainManager) PauseExternalWriters() func() {
	cm.extWriters.Lock()
	cm.rollbackPaused.Store(true)
	return func() {
		cm.rollbackPaused.Store(false)
		cm.extWriters.Unlock()
	}
}

// RollbackPaused reports whether a TemporaryRollback currently holds the chain.
func (cm *ChainManager) RollbackPaused() bool { return cm.rollbackPaused.Load() }
