package consensus

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// createSaltedBlock builds a coinbase-only regtest block on top of prevNode,
// mixing `salt` bytes into the coinbase scriptSig (after the BIP34 height push)
// so a competing chain's block at a given height has a DIFFERENT hash than the
// active chain's block at the same height. coinbaseValue, when >= 0, overrides
// the correct subsidy so the caller can mint an invalid (bad-cb-amount) block.
func createSaltedBlock(t *testing.T, params *ChainParams, prevNode *BlockNode, salt byte, coinbaseValue int64) *wire.MsgBlock {
	t.Helper()

	blockHeight := prevNode.Height + 1
	heightScript := encodeBIP34Height(blockHeight)
	if len(heightScript) < 2 {
		heightScript = append(heightScript, 0x00)
	}
	// Salt AFTER the BIP34 height push so height parsing still succeeds.
	heightScript = append(heightScript, salt, salt)

	value := coinbaseValue
	if value < 0 {
		value = CalcBlockSubsidy(blockHeight)
	}

	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
				SignatureScript:  heightScript,
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: value, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}

	merkleRoot := CalcMerkleRoot([]wire.Hash256{coinbase.TxHash()})
	header := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prevNode.Hash,
		MerkleRoot: merkleRoot,
		Timestamp:  prevNode.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
		Nonce:      0,
	}
	target := CompactToBig(header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		header.Nonce = i
		if HashToBig(header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return &wire.MsgBlock{Header: header, Transactions: []*wire.MsgTx{coinbase}}
}

// TestReorgPartialSwitchRestoresOriginalTip is the EFFECTIVE regression test for
// the "partial reorg to the losing chain on an invalid competing tip" bug.
//
// Scenario (mirrors the differential reorg test S5, submitblock/p2p-reachable):
//
//	genesis ── A1(h1) ── A2(h2)              <- active tip = A2
//	        └─ B1(h1) ── B2(h2) ── B3(h3, INVALID: bad-cb-amount)
//
// A2 and B2 have EQUAL work (both h2), so B1/B2 land as side-branches. Only the
// invalid B3 (h3) outweighs A2 and triggers a reorg. ReorgTo(B3) disconnects
// A2/A1, connects B1/B2, then B3 fails consensus.
//
// Pre-fix: ReorgTo returned the error but left the in-memory tip on B2 (the
// losing chain) with a polluted UTXO cache, and the subsequent valid A3 was
// rejected — the node was stranded on a lower-work invalid-adjacent branch.
//
// Post-fix (Bitcoin Core ActivateBestChainStep parity — a partial connect that
// fails is fully unwound to the pre-reorg tip; the on-disk state was never
// touched because the union batch is only written on full success): the tip is
// restored to A2, the UTXO set is clean (A2's coins present, B1/B2's absent),
// B3 is marked invalid, and a valid A3 then connects.
func TestReorgPartialSwitchRestoresOriginalTip(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	// Wire the production disk-backed UTXO set (NewChainManager otherwise falls
	// back to an in-memory-only view that the live fleet never uses).
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
		UTXOSet:     NewUTXOSet(db),
	})
	// Reorgs only occur post-IBD (the IBD path refuses fork switches); post-IBD
	// each ConnectBlock flushes its UTXO delta to disk per-block, which is what
	// makes the rollback's cache-discard an exact restore.
	cm.SetIBD(false)

	// connectActive stores + connects a block that extends the active tip.
	connectActive := func(blk *wire.MsgBlock) {
		t.Helper()
		if _, err := idx.AddHeader(blk.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock: %v", err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock(active): %v", err)
		}
	}
	// stage records a block's header + body (the ProcessSubmittedBlock caller
	// contract) so its BlockNode/TotalWork is resolvable before submission.
	stage := func(blk *wire.MsgBlock) {
		t.Helper()
		if _, err := idx.AddHeader(blk.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock: %v", err)
		}
	}
	// submit drives the submitblock path (ProcessSubmittedBlock), the
	// p2p/RPC-reachable reorg trigger. The block must already be staged.
	submit := func(blk *wire.MsgBlock) error {
		t.Helper()
		return cm.ProcessSubmittedBlock(blk)
	}
	node := func(blk *wire.MsgBlock) *BlockNode {
		return idx.GetNode(blk.Header.BlockHash())
	}

	genesis := idx.Genesis()

	// --- Active chain: A1(h1), A2(h2). Tip = A2. ---
	a1 := createTestBlock(t, params, genesis, nil)
	connectActive(a1)
	a2 := createTestBlock(t, params, node(a1), nil)
	connectActive(a2)

	a2Hash := a2.Header.BlockHash()
	if tip, h := cm.BestBlock(); tip != a2Hash || h != 2 {
		t.Fatalf("setup: expected tip A2 h2, got %s h%d", tip.String()[:16], h)
	}

	// --- Competing chain forking at genesis: B1(h1), B2(h2), B3(h3 INVALID). ---
	// Stage each block before referencing its node / building its child.
	b1 := createSaltedBlock(t, params, genesis, 0xB1, -1)
	stage(b1)
	b2 := createSaltedBlock(t, params, node(b1), 0xB2, -1)
	stage(b2)
	// B3 overpays its coinbase by 1 satoshi -> bad-cb-amount.
	b3 := createSaltedBlock(t, params, node(b2), 0xB3, CalcBlockSubsidy(3)+1)
	stage(b3)

	// B1 (h1 < A2 h2) and B2 (h2 == A2 h2, equal work) store as side-branches.
	if err := submit(b1); !errors.Is(err, ErrSideBranchAccepted) {
		t.Fatalf("submit(B1): want ErrSideBranchAccepted, got %v", err)
	}
	if err := submit(b2); !errors.Is(err, ErrSideBranchAccepted) {
		t.Fatalf("submit(B2): want ErrSideBranchAccepted, got %v", err)
	}

	// B3 (h3) outweighs A2 -> triggers ReorgTo(B3), which connects B1+B2 then
	// fails on B3's invalid coinbase.
	err := submit(b3)
	if err == nil {
		t.Fatalf("submit(B3): expected reorg to fail on invalid coinbase, got nil")
	}
	if !errors.Is(err, ErrBadCoinbaseValue) {
		t.Fatalf("submit(B3): want ErrBadCoinbaseValue, got %v", err)
	}

	// --- Core assertion: the failed reorg fully restored the original tip A2. ---
	// Pre-fix this FAILS: the tip is stranded on B2 (the losing chain).
	tip, h := cm.BestBlock()
	if tip != a2Hash || h != 2 {
		t.Fatalf("PARTIAL-REORG BUG: after failed reorg tip=%s h%d, want A2 %s h2 "+
			"(node stranded on losing chain)", tip.String()[:16], h, a2Hash.String()[:16])
	}

	// --- UTXO set is clean: A2's coinbase present, B1/B2's coinbases gone. ---
	utxo := cm.UTXOSet()
	a2cb := wire.OutPoint{Hash: a2.Transactions[0].TxHash(), Index: 0}
	if utxo.GetUTXO(a2cb) == nil {
		t.Fatalf("UTXO corrupt: A2 coinbase missing after failed reorg")
	}
	for name, blk := range map[string]*wire.MsgBlock{"B1": b1, "B2": b2} {
		op := wire.OutPoint{Hash: blk.Transactions[0].TxHash(), Index: 0}
		if utxo.GetUTXO(op) != nil {
			t.Fatalf("UTXO corrupt: %s coinbase present after failed (rolled-back) reorg", name)
		}
	}

	// --- B3 marked invalid so the doomed reorg is not chased again. ---
	if n := node(b3); n == nil || !n.Status.IsInvalid() {
		t.Fatalf("B3 not marked invalid after failed reorg")
	}

	// --- A valid A3(h3) extending A2 now connects and advances the tip. ---
	a3 := createTestBlock(t, params, node(a2), nil)
	stage(a3)
	if err := submit(a3); err != nil {
		t.Fatalf("A3 rejected after reorg rollback (node still wedged?): %v", err)
	}
	a3Hash := a3.Header.BlockHash()
	if tip, h := cm.BestBlock(); tip != a3Hash || h != 3 {
		t.Fatalf("A3 did not become tip: got %s h%d, want A3 %s h3",
			tip.String()[:16], h, a3Hash.String()[:16])
	}
}
