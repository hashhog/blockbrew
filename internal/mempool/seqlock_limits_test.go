package mempool

import (
	"errors"
	"testing"
	"time"

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

// TestAncestorLimitRejectsAt26 builds a 25-deep linear chain via the manual
// pool/cluster bypass, then confirms the 26th candidate is rejected.
func TestAncestorLimitRejectsAt26(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Manually splice a 25-deep linear chain into the pool.
	hashes := make([]wire.Hash256, 0, 25)
	mp.mu.Lock()
	var prev wire.Hash256
	for i := 0; i < 25; i++ {
		var h wire.Hash256
		h[0] = byte(0xC0 + i)
		h[1] = byte(i)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            1000,
			Size:           150,
			FeeRate:        6.66,
			Time:           time.Now(),
			Height:         0,
			AncestorFee:    int64(1000 * (i + 1)),
			AncestorSize:   int64(150 * (i + 1)),
			DescendantFee:  1000,
			DescendantSize: 150,
		}
		if i > 0 {
			entry.Depends = []wire.Hash256{prev}
			parent := mp.pool[prev]
			parent.SpentBy = append(parent.SpentBy, h)
		}
		mp.pool[h] = entry
		hashes = append(hashes, h)
		prev = h
	}
	mp.mu.Unlock()

	// Candidate spends the deepest tx — that is, would make the chain 26-long.
	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prev, Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); !errors.Is(err, ErrTooManyAncestors) {
		t.Fatalf("expected ErrTooManyAncestors, got %v", err)
	}
}

// TestAncestorLimitAllowsAt25 confirms a 24-deep chain still admits one more.
func TestAncestorLimitAllowsAt25(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	mp.mu.Lock()
	var prev wire.Hash256
	for i := 0; i < 24; i++ {
		var h wire.Hash256
		h[0] = byte(0xD0 + i)
		h[1] = byte(i)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            1000,
			Size:           150,
			Time:           time.Now(),
			AncestorFee:    int64(1000 * (i + 1)),
			AncestorSize:   int64(150 * (i + 1)),
			DescendantFee:  1000,
			DescendantSize: 150,
		}
		if i > 0 {
			entry.Depends = []wire.Hash256{prev}
			parent := mp.pool[prev]
			parent.SpentBy = append(parent.SpentBy, h)
		}
		mp.pool[h] = entry
		prev = h
	}
	mp.mu.Unlock()

	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prev, Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("25-ancestor candidate should pass, got %v", err)
	}
}

// TestDescendantLimitRejectsAt26 builds a single root with 24 fan-out children,
// then confirms a 25th sibling under the same root is rejected by the
// descendant limit.
func TestDescendantLimitRejectsAt26(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Root tx (will gain many children).
	var rootHash wire.Hash256
	rootHash[0] = 0xE0
	mp.mu.Lock()
	root := &TxEntry{
		Tx:             &wire.MsgTx{},
		TxHash:         rootHash,
		Fee:            1000,
		Size:           150,
		Time:           time.Now(),
		AncestorFee:    1000,
		AncestorSize:   150,
		DescendantFee:  1000,
		DescendantSize: 150,
	}
	mp.pool[rootHash] = root

	// 24 children.
	for i := 0; i < 24; i++ {
		var h wire.Hash256
		h[0] = byte(0xE1 + i)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            500,
			Size:           120,
			Time:           time.Now(),
			Depends:        []wire.Hash256{rootHash},
			AncestorFee:    1500,
			AncestorSize:   270,
			DescendantFee:  500,
			DescendantSize: 120,
		}
		mp.pool[h] = entry
		root.SpentBy = append(root.SpentBy, h)
	}
	mp.mu.Unlock()

	// Candidate also spends the root: would make 25 direct children + root = 26
	// descendants-including-self for the root. Limit is 25.
	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 1},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); !errors.Is(err, ErrTooManyDescendants) {
		t.Fatalf("expected ErrTooManyDescendants, got %v", err)
	}
}
