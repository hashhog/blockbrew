package mempool

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// fakeChainState lets a test pin tip height/MTP for BIP-68 evaluation.
type fakeChainState struct {
	tipHeight int32
	tipMTP    int64
	// height -> MTP, optional. Falls back to tipMTP when missing.
	mtps map[int32]int64
}

func (f *fakeChainState) TipHeight() int32 { return f.tipHeight }
func (f *fakeChainState) TipMTP() int64    { return f.tipMTP }
func (f *fakeChainState) MTPAtHeight(h int32) int64 {
	if v, ok := f.mtps[h]; ok {
		return v
	}
	return f.tipMTP
}

func mempoolWithChainState(utxoSet consensus.UTXOView, cs ChainState) *Mempool {
	cfg := Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
		ChainState:      cs,
	}
	return New(cfg, utxoSet)
}

// TestBIP68SequenceLockRejectsHeightLocked covers the case where a tx has a
// height-relative sequence lock that has not yet matured.
func TestBIP68SequenceLockRejectsHeightLocked(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = 0xAB
	outpoint, entry := createFundingUTXO(fundingHash, 0, 100_000)
	// UTXO confirmed at height 100.
	entry.Height = 100
	utxoSet.AddUTXO(outpoint, entry)

	cs := &fakeChainState{
		tipHeight: 100, // tip just confirmed the funding utxo
		tipMTP:    1_700_000_000,
	}

	mp := mempoolWithChainState(utxoSet, cs)
	mp.SetChainHeight(cs.tipHeight)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)
	tx.Version = 2
	// Height-relative lock of 10 blocks — type bit (1<<22) clear.
	tx.TxIn[0].Sequence = 10

	err := mp.checkSequenceLocksLocked(tx)
	if !errors.Is(err, ErrSequenceLockNotMet) {
		t.Fatalf("expected ErrSequenceLockNotMet, got %v", err)
	}

	// Advance tip height so the lock matures.
	cs.tipHeight = 110
	mp.SetChainHeight(cs.tipHeight)
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		t.Fatalf("expected mature lock to pass, got %v", err)
	}
}

// TestBIP68SequenceLockSkipsV1 ensures BIP-68 only applies to v2+ tx.
func TestBIP68SequenceLockSkipsV1(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = 0xAC
	outpoint, entry := createFundingUTXO(fundingHash, 0, 100_000)
	entry.Height = 100
	utxoSet.AddUTXO(outpoint, entry)

	cs := &fakeChainState{tipHeight: 100, tipMTP: 1_700_000_000}
	mp := mempoolWithChainState(utxoSet, cs)
	mp.SetChainHeight(100)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)
	tx.Version = 1
	tx.TxIn[0].Sequence = 10
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		t.Fatalf("v1 tx should bypass BIP-68, got %v", err)
	}
}

// TestBIP68SequenceLockSkipsDisabledFlag covers the SEQUENCE_LOCKTIME_DISABLE_FLAG.
func TestBIP68SequenceLockSkipsDisabledFlag(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = 0xAD
	outpoint, entry := createFundingUTXO(fundingHash, 0, 100_000)
	entry.Height = 100
	utxoSet.AddUTXO(outpoint, entry)

	cs := &fakeChainState{tipHeight: 100, tipMTP: 1_700_000_000}
	mp := mempoolWithChainState(utxoSet, cs)
	mp.SetChainHeight(100)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)
	tx.Version = 2
	tx.TxIn[0].Sequence = consensus.SequenceLockTimeDisabledFlag | 10
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		t.Fatalf("disable-flag tx should pass, got %v", err)
	}
}

// TestBIP68SequenceLockSkippedWithoutChainState makes sure tests/legacy callers
// still work when no ChainState is wired.
func TestBIP68SequenceLockSkippedWithoutChainState(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = 0xAE
	outpoint, entry := createFundingUTXO(fundingHash, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)
	tx := createTestTransaction([]wire.OutPoint{outpoint}, 99_000, 1)
	tx.Version = 2
	tx.TxIn[0].Sequence = 10
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		t.Fatalf("nil ChainState should bypass BIP-68, got %v", err)
	}
}
