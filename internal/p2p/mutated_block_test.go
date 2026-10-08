package p2p

// Malleated block bodies (Core IsBlockMutated) on receipt — fleet-conformance
// MAL, 2026-10-08. Core net_processing.cpp ProcessMessage "block": when the
// parent is known, IsBlockMutated runs before anything else; a mutated body
// punishes the SENDER, removes only that peer's in-flight entry and returns.
// The block is not marked failed and the body is never stored.

import (
	"bytes"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// segwitCoinbaseBlock builds a mined regtest block on prev whose coinbase
// carries the witness nonce and the BIP-141 commitment.
func segwitCoinbaseBlock(t *testing.T, prev wire.Hash256, ts uint32, tag byte) *wire.MsgBlock {
	t.Helper()
	nonce := make([]byte, 32)
	cb := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x01, tag, 0x51},
			Sequence:         0xFFFFFFFF,
			Witness:          [][]byte{nonce},
		}},
		TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x51}}},
	}
	commit := consensus.CalcWitnessCommitment([]wire.Hash256{{}}, nonce)
	cb.TxOut = append(cb.TxOut, &wire.TxOut{Value: 0,
		PkScript: append([]byte{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed}, commit[:]...)})
	header := createTestBlockHeader(prev, ts, 0)
	header.MerkleRoot = cb.TxHash()
	header = createTestBlockHeader2(header)
	return &wire.MsgBlock{Header: header, Transactions: []*wire.MsgTx{cb}}
}

// createTestBlockHeader2 re-grinds a header after its merkle root was set.
func createTestBlockHeader2(h wire.BlockHeader) wire.BlockHeader {
	target := consensus.CompactToBig(h.Bits)
	for i := uint32(0); i < 1000000; i++ {
		h.Nonce = i
		if consensus.HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return h
		}
	}
	return h
}

func stripWitness(b *wire.MsgBlock) *wire.MsgBlock {
	var buf bytes.Buffer
	_ = b.Serialize(&buf)
	c := &wire.MsgBlock{}
	_ = c.Deserialize(bytes.NewReader(buf.Bytes()))
	for _, tx := range c.Transactions {
		for _, in := range tx.TxIn {
			in.Witness = nil
		}
	}
	return c
}

func TestBlockMutationCoreOrder(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	b := segwitCoinbaseBlock(t, idx.Genesis().Hash, idx.Genesis().Header.Timestamp+600, 1)
	if err := consensus.BlockMutation(b, true); err != nil {
		t.Fatalf("honest block reported mutated: %v", err)
	}
	s := stripWitness(b)
	if s.Header.BlockHash() != b.Header.BlockHash() {
		t.Fatal("stripping changed the block hash")
	}
	if err := consensus.BlockMutation(s, true); err == nil || err != consensus.ErrBadWitnessNonceSize {
		t.Fatalf("stripped: got %v, want bad-witness-nonce-size", err)
	}
	if err := consensus.BlockMutation(b, false); err != consensus.ErrUnexpectedWitnessInBlock {
		t.Fatalf("witness before segwit: got %v, want unexpected-witness", err)
	}
	// First tx not a coinbase: mutated only with a 64-byte transaction.
	tx := &wire.MsgTx{Version: 2,
		TxIn:  []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0}, Sequence: 0}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51, 0x51, 0x51, 0x51}}}}
	nb := &wire.MsgBlock{Header: b.Header, Transactions: []*wire.MsgTx{tx}}
	nb.Header.MerkleRoot = tx.TxHash()
	if consensus.BlockMutation(nb, true) == nil {
		t.Fatal("64-byte tx without coinbase not reported mutated")
	}
	tx.TxOut[0].PkScript = append(tx.TxOut[0].PkScript, 0x51)
	nb.Header.MerkleRoot = tx.TxHash()
	if err := consensus.BlockMutation(nb, true); err != nil {
		t.Fatalf("65-byte tx without coinbase: got %v, want not mutated (CheckBlock's verdict)", err)
	}
}

// TestHandleBlockMutatedOnReceipt: E serves a witness-stripped body for the
// block it was asked for. E is punished, ITS in-flight entry is freed and
// noted as a failed source, nothing reaches validation, the block is not
// marked. The honest body from H then goes through.
func TestHandleBlockMutatedOnReceipt(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx})
	g := idx.Genesis()
	b := segwitCoinbaseBlock(t, g.Hash, g.Header.Timestamp+600, 1)
	hash := b.Header.BlockHash()
	if _, err := idx.AddHeader(b.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	E := createMockPeer("127.0.0.2:18444", 1)
	H := createMockPeer("127.0.0.3:18444", 1)
	req := &blockRequest{Hash: hash, Height: 1, Peer: E, State: BlockDownloadInFlight, RequestAt: time.Now()}
	sm.mu.Lock()
	sm.inflight[hash] = req
	sm.blockQueue = append(sm.blockQueue, req)
	sm.mu.Unlock()

	sm.HandleBlock(E, &MsgBlock{Block: stripWitness(b)})

	if !E.ShouldBan() {
		t.Error("sender of the mutated body was not punished")
	}
	sm.mu.RLock()
	_, inflight := sm.inflight[hash]
	_, failed := req.FailedPeers[E.Address()]
	st := req.State
	sm.mu.RUnlock()
	if inflight || st != BlockDownloadPending {
		t.Errorf("request not freed: inflight=%v state=%v", inflight, st)
	}
	if !failed {
		t.Error("E not noted as a failed source for the re-request")
	}
	if n := idx.GetNode(hash); n == nil || n.Status.IsInvalid() {
		t.Error("block marked invalid for a mutated body (Core never marks BLOCK_MUTATED)")
	}
	if len(sm.validationChan) != 0 {
		t.Error("mutated body reached validation")
	}

	// The honest body is accepted for validation.
	req.Peer, req.State = H, BlockDownloadInFlight
	sm.mu.Lock()
	sm.inflight[hash] = req
	sm.mu.Unlock()
	sm.HandleBlock(H, &MsgBlock{Block: b})
	if H.ShouldBan() {
		t.Error("honest sender punished")
	}
	if len(sm.validationChan) != 1 {
		t.Errorf("honest body not sent to validation (chan len %d)", len(sm.validationChan))
	}
}

// A mutated body from a peer the block was NOT requested from must not free
// another peer's request (Core RemoveBlockRequest(hash, this peer)).
func TestHandleBlockMutatedLeavesOtherPeersRequest(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx})
	g := idx.Genesis()
	b := segwitCoinbaseBlock(t, g.Hash, g.Header.Timestamp+600, 2)
	hash := b.Header.BlockHash()
	if _, err := idx.AddHeader(b.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	E := createMockPeer("127.0.0.2:18444", 1)
	H := createMockPeer("127.0.0.3:18444", 1)
	req := &blockRequest{Hash: hash, Height: 1, Peer: H, State: BlockDownloadInFlight, RequestAt: time.Now()}
	sm.mu.Lock()
	sm.inflight[hash] = req
	sm.mu.Unlock()
	sm.HandleBlock(E, &MsgBlock{Block: stripWitness(b)})
	if !E.ShouldBan() {
		t.Error("sender not punished")
	}
	sm.mu.RLock()
	got := sm.inflight[hash]
	sm.mu.RUnlock()
	if got != req || req.Peer != H || req.State != BlockDownloadInFlight {
		t.Error("H's request was disturbed by E's mutated body")
	}
}

// BenchmarkBlockMutation: the receipt check on a synthetic ~1.6 MB segwit
// block (2,500 two-input P2WPKH-shaped spends + witness commitment).
func BenchmarkBlockMutation(b *testing.B) {
	nonce := make([]byte, 32)
	cb := &wire.MsgTx{Version: 2,
		TxIn:  []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF}, SignatureScript: []byte{0x01, 0x01}, Sequence: 0xFFFFFFFF, Witness: [][]byte{nonce}}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}}}
	txs := []*wire.MsgTx{cb}
	for i := 0; i < 2500; i++ {
		tx := &wire.MsgTx{Version: 2}
		for j := 0; j < 2; j++ {
			var h wire.Hash256
			h[0], h[1], h[2] = byte(i), byte(i>>8), byte(j)
			tx.TxIn = append(tx.TxIn, &wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: h}, Sequence: 0xFFFFFFFD,
				Witness: [][]byte{bytes.Repeat([]byte{0x30}, 72), bytes.Repeat([]byte{0x02}, 33)}})
		}
		tx.TxOut = []*wire.TxOut{{Value: 1000, PkScript: append([]byte{0x00, 0x14}, bytes.Repeat([]byte{byte(i)}, 20)...)},
			{Value: 2000, PkScript: append([]byte{0x00, 0x14}, bytes.Repeat([]byte{byte(i + 1)}, 20)...)}}
		txs = append(txs, tx)
	}
	wtx := []wire.Hash256{{}}
	for _, tx := range txs[1:] {
		wtx = append(wtx, tx.WTxHash())
	}
	commit := consensus.CalcWitnessCommitment(wtx, nonce)
	cb.TxOut = append(cb.TxOut, &wire.TxOut{PkScript: append([]byte{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed}, commit[:]...)})
	ids := make([]wire.Hash256, len(txs))
	for i, tx := range txs {
		ids[i] = tx.TxHash()
	}
	blk := &wire.MsgBlock{Transactions: txs}
	blk.Header.MerkleRoot = consensus.CalcMerkleRoot(ids)
	var buf bytes.Buffer
	_ = blk.Serialize(&buf)
	if err := consensus.BlockMutation(blk, true); err != nil {
		b.Fatalf("synthetic block mutated: %v", err)
	}
	b.SetBytes(int64(buf.Len()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = consensus.BlockMutation(blk, true)
	}
}
