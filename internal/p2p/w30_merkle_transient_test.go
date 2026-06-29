package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// makeW30Coinbase creates a minimal valid coinbase transaction with a
// two-byte scriptSig (the minimum allowed by CheckTransactionSanity).
// The tag byte distinguishes different coinbase transactions so they have
// distinct TxHashes.
func makeW30Coinbase(tag byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF}, // null prevout = coinbase
			SignatureScript:  []byte{0x51, tag},                // 2 bytes: valid coinbase scriptSig
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    5_000_000_000, // 50 BTC
			PkScript: []byte{0x51}, // OP_1
		}},
	}
}

// makeW30NonCoinbaseTx creates a minimal non-coinbase transaction that passes
// CheckTransactionSanity (non-null outpoint, one output, no null inputs).
func makeW30NonCoinbaseTx(nonce byte) *wire.MsgTx {
	var prevHash wire.Hash256
	prevHash[0] = 0x01
	prevHash[1] = nonce // ensures different txs have different TxHashes
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    0,
			PkScript: []byte{0x51},
		}},
	}
}

// findW30Header builds a valid regtest block header with the given MerkleRoot
// connecting to prevHash, searching for a nonce that satisfies the PoW target.
// Regtest difficulty (0x207fffff) is trivially satisfied by almost any hash.
func findW30Header(prevHash wire.Hash256, merkleRoot wire.Hash256, parentTimestamp uint32) wire.BlockHeader {
	h := wire.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  parentTimestamp + 600,
		Bits:       0x207fffff, // regtest easy mining
		Nonce:      0,
	}
	target := consensus.CompactToBig(h.Bits)
	for i := uint32(0); i < 2_000_000; i++ {
		h.Nonce = i
		if consensus.HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return h
		}
	}
	return h // regtest difficulty is so low this should never be reached
}

// waitForReqStateChange polls until req.State changes from initial, or times out.
// Returns the final state. Uses sm.mu for safe access.
func waitForReqStateChange(sm *SyncManager, req *blockRequest, initial BlockDownloadState, timeout time.Duration) BlockDownloadState {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sm.mu.Lock()
		s := req.State
		sm.mu.Unlock()
		if s != initial {
			return s
		}
		time.Sleep(15 * time.Millisecond)
	}
	sm.mu.Lock()
	s := req.State
	sm.mu.Unlock()
	return s
}

// TestW30MerkleTransientClassification is the EFFECTIVE test for the fix that
// expands the transient-mutation gate in sync.go to include ErrBadMerkleRoot,
// ErrBadWitnessNonceSize, and ErrUnexpectedWitnessInBlock alongside the
// pre-existing ErrBlockMutated.
//
// Pre-fix behaviour:
//   - ErrBadMerkleRoot → StatusInvalid set (permanently invalid) — WRONG per Core.
//
// Post-fix behaviour (verified here):
//   - ErrBadMerkleRoot → StatusInvalid NOT set (transient/requeued) — matches Core
//     BLOCK_MUTATED (validation.cpp:3843-3848 "bad-txnmrklroot").
//   - ErrBlockMutated (CVE-2012-2459 duplicate-tx) → StatusInvalid NOT set —
//     already worked pre-fix, included here as a regression guard.
//   - ErrFirstTxNotCoinbase → StatusInvalid IS set (permanently invalid) — MUST
//     remain permanent (Core BLOCK_CONSENSUS, unchanged by this fix).
func TestW30MerkleTransientClassification(t *testing.T) {
	params := consensus.RegtestParams()
	genesis := params.GenesisBlock

	// ── Shared SyncManager setup ──────────────────────────────────────────────
	// All subtests share one HeaderIndex and SyncManager so the genesis node is
	// already present. We start exactly one validationWorker so blocks sent to
	// validationChan are processed synchronously (from the test's perspective).
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})
	sm.wg.Add(1)
	go sm.validationWorker()
	defer func() {
		close(sm.quit)
		sm.wg.Wait()
	}()

	genesisPrevTimestamp := genesis.Header.Timestamp

	// ── Sub-test 1: ErrBlockMutated (CVE-2012-2459) → TRANSIENT ──────────────
	// Construct a 4-transaction block where tx3 is duplicated. The duplicate
	// produces an equal adjacent pair at level 0 of the merkle tree:
	//   leaves: [cbHash, t1Hash, t2Hash, t2Hash]
	//   → pair (t2Hash, t2Hash) equal → CalcMerkleRootMutation returns mutated=true
	// The header MerkleRoot equals CalcMerkleRoot([cb, t1, t2]) (Bitcoin pads odd
	// lengths by duplicating the last leaf, making [cb,t1,t2] and [cb,t1,t2,t2]
	// produce the same root). The block passes PoW + coinbase checks but the merkle
	// tree is detected as mutated → ErrBlockMutated → MUST be transient.
	t.Run("ErrBlockMutated_transient", func(t *testing.T) {
		cb := makeW30Coinbase(0x10)
		tx1 := makeW30NonCoinbaseTx(0x01)
		tx2 := makeW30NonCoinbaseTx(0x02)

		// MerkleRoot from the "legitimate" 3-tx transaction list; the 4-tx
		// mutated list [cb, tx1, tx2, tx2] produces the same root.
		leavesLegit := []wire.Hash256{cb.TxHash(), tx1.TxHash(), tx2.TxHash()}
		merkleRoot := consensus.CalcMerkleRoot(leavesLegit)

		hdr := findW30Header(genesis.Header.BlockHash(), merkleRoot, genesisPrevTimestamp)
		node, err := idx.AddHeader(hdr, false)
		if err != nil {
			t.Fatalf("AddHeader: %v", err)
		}

		// Mutated block: tx2 appears twice → duplicate pair at merkle level 0.
		block := &wire.MsgBlock{
			Header:       hdr,
			Transactions: []*wire.MsgTx{cb, tx1, tx2, tx2},
		}

		req := &blockRequest{Hash: hdr.BlockHash(), Height: node.Height, State: BlockDownloadReceived}
		sm.validationChan <- &blockWithRequest{block: block, req: req}

		state := waitForReqStateChange(sm, req, BlockDownloadReceived, 5*time.Second)
		if state == BlockDownloadReceived {
			t.Fatal("validationWorker did not process block within timeout")
		}

		if node.Status&consensus.StatusInvalid != 0 {
			t.Errorf("ErrBlockMutated: StatusInvalid set — should be TRANSIENT (no permanent ban)")
		}
		// Transient path resets State to BlockDownloadPending (requeueForRedownload).
		sm.mu.Lock()
		finalState := req.State
		sm.mu.Unlock()
		if finalState != BlockDownloadPending {
			t.Errorf("ErrBlockMutated: req.State = %d, want BlockDownloadPending (%d) after transient requeue",
				finalState, BlockDownloadPending)
		}
	})

	// ── Sub-test 2: ErrBadMerkleRoot → TRANSIENT (the EFFECTIVE proof) ────────
	// A misbehaving peer delivers wrong transactions for an already-accepted header.
	// The header's declared MerkleRoot (H1 = hash of cb1) does NOT match the
	// computed root from the delivered transactions (H2 = hash of cb2, cb2 ≠ cb1).
	// The block hash is determined by the header (including H1), so the block hash
	// is not permanently invalid — an honest peer could deliver cb1 and the block
	// would be valid.
	//
	// PRE-FIX: StatusInvalid was set → permanent ban → block hash could never be
	// accepted from any peer.
	// POST-FIX: StatusInvalid NOT set → transient → requeue for honest peer.
	t.Run("ErrBadMerkleRoot_transient", func(t *testing.T) {
		// cb1 is what the header commits to (MerkleRoot = cb1.TxHash()).
		cb1 := makeW30Coinbase(0x20)
		merkleRoot := cb1.TxHash() // CalcMerkleRoot([cb1]) = cb1.TxHash()

		hdr := findW30Header(genesis.Header.BlockHash(), merkleRoot, genesisPrevTimestamp+1200)
		node, err := idx.AddHeader(hdr, false)
		if err != nil {
			t.Fatalf("AddHeader: %v", err)
		}

		// cb2 is a different coinbase — its TxHash ≠ merkleRoot → ErrBadMerkleRoot.
		cb2 := makeW30Coinbase(0x21)
		block := &wire.MsgBlock{
			Header:       hdr,            // MerkleRoot = cb1.TxHash()
			Transactions: []*wire.MsgTx{cb2}, // delivered tx has different TxHash
		}

		req := &blockRequest{Hash: hdr.BlockHash(), Height: node.Height, State: BlockDownloadReceived}
		sm.validationChan <- &blockWithRequest{block: block, req: req}

		state := waitForReqStateChange(sm, req, BlockDownloadReceived, 5*time.Second)
		if state == BlockDownloadReceived {
			t.Fatal("validationWorker did not process block within timeout")
		}

		// POST-FIX: StatusInvalid must NOT be set (transient, requeued).
		// PRE-FIX: StatusInvalid WOULD be set here.
		if node.Status&consensus.StatusInvalid != 0 {
			t.Errorf("ErrBadMerkleRoot: StatusInvalid set — should be TRANSIENT per Core "+
				"BLOCK_MUTATED (validation.cpp:3843-3848 \"bad-txnmrklroot\"); "+
				"pre-fix this test would fail here, proving the fix is EFFECTIVE")
		}
		sm.mu.Lock()
		finalState := req.State
		sm.mu.Unlock()
		if finalState != BlockDownloadPending {
			t.Errorf("ErrBadMerkleRoot: req.State = %d, want BlockDownloadPending (%d)",
				finalState, BlockDownloadPending)
		}
	})

	// ── Sub-test 3: ErrFirstTxNotCoinbase → PERMANENT (must stay unchanged) ───
	// A block whose first transaction is not a coinbase is BLOCK_CONSENSUS in Core
	// (validation.cpp:3950-3952 "bad-cb-missing", BLOCK_CONSENSUS). This is a
	// fundamental consensus violation that cannot be "fixed" by re-downloading from
	// another peer — no valid block with this hash can have a non-coinbase first tx.
	// StatusInvalid MUST remain set after this fix.
	t.Run("ErrFirstTxNotCoinbase_permanent", func(t *testing.T) {
		ncb := makeW30NonCoinbaseTx(0x30)
		merkleRoot := ncb.TxHash()

		hdr := findW30Header(genesis.Header.BlockHash(), merkleRoot, genesisPrevTimestamp+1800)
		node, err := idx.AddHeader(hdr, false)
		if err != nil {
			t.Fatalf("AddHeader: %v", err)
		}

		block := &wire.MsgBlock{
			Header:       hdr,
			Transactions: []*wire.MsgTx{ncb}, // not a coinbase → ErrFirstTxNotCoinbase
		}

		req := &blockRequest{Hash: hdr.BlockHash(), Height: node.Height, State: BlockDownloadReceived}
		sm.validationChan <- &blockWithRequest{block: block, req: req}

		state := waitForReqStateChange(sm, req, BlockDownloadReceived, 5*time.Second)
		if state == BlockDownloadReceived {
			t.Fatal("validationWorker did not process block within timeout")
		}

		// StatusInvalid MUST be set: ErrFirstTxNotCoinbase is PERMANENT.
		if node.Status&consensus.StatusInvalid == 0 {
			t.Errorf("ErrFirstTxNotCoinbase: StatusInvalid not set — should remain PERMANENT "+
				"(Core BLOCK_CONSENSUS, validation.cpp:3950-3952 \"bad-cb-missing\")")
		}
	})
}
