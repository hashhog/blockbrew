package mempool

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Gate 6: after AbortNode the mempool admits nothing and reports the system
// condition, not a policy/consensus reject reason (the chain view it would
// validate against may be torn; a coins-DB read error reads as "missing
// inputs"). Pre-fix the latch was ignored.
func TestGate6_MempoolRefusesAfterAbort(t *testing.T) {
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)
	utxoSet := newTestUTXOSet()
	var h wire.Hash256
	h[0] = 0x6a
	outpoint, entry := createFundingUTXO(h, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)
	mp := newTestMempool(utxoSet)
	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)

	consensus.AbortNode(errors.New("test: injected fatal error"))
	err := mp.AcceptToMemoryPool(tx)
	if !errors.Is(err, consensus.ErrNodeAborted) {
		t.Fatalf("AcceptToMemoryPool after AbortNode: %v, want ErrNodeAborted", err)
	}
	if mp.HasTransaction(tx.TxHash()) {
		t.Fatal("tx admitted after AbortNode")
	}
	if _, err := mp.AcceptPackage([]*wire.MsgTx{tx}); !errors.Is(err, consensus.ErrNodeAborted) {
		t.Fatalf("AcceptPackage after AbortNode: %v, want ErrNodeAborted", err)
	}
}
