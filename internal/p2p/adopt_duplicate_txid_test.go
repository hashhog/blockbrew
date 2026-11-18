package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// bip34Push is the canonical BIP-34 height push (Core CScript() << nHeight).
func bip34Push(h int32) []byte {
	if h >= 1 && h <= 16 {
		return []byte{byte(0x50 + h)}
	}
	var le []byte
	for v := uint32(h); v > 0; v >>= 8 {
		le = append(le, byte(v))
	}
	if le[len(le)-1]&0x80 != 0 {
		le = append(le, 0)
	}
	return append([]byte{byte(len(le))}, le...)
}

// mkDupBlock builds a regtest block on prev: a coinbase paying the subsidy plus
// `overpay`, followed by `txs` verbatim.
func mkDupBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode, overpay int64, txs ...*wire.MsgTx) *wire.MsgBlock {
	t.Helper()
	h := prev.Height + 1
	cb := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  append(bip34Push(h), 0xD7, 0xD7),
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    consensus.CalcBlockSubsidyForInterval(h, params.SubsidyHalvingInterval) + overpay,
			PkScript: []byte{0x51},
		}},
	}
	all := append([]*wire.MsgTx{cb}, txs...)
	hashes := make([]wire.Hash256, len(all))
	for i, tx := range all {
		hashes[i] = tx.TxHash()
	}
	hdr := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prev.Hash,
		MerkleRoot: consensus.CalcMerkleRoot(hashes),
		Timestamp:  prev.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
	}
	target := consensus.CompactToBig(hdr.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		hdr.Nonce = i
		if consensus.HashToBig(hdr.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return &wire.MsgBlock{Header: hdr, Transactions: all}
}

type dupTxidOutcome struct {
	bNode       *consensus.BlockNode
	aNode       *consensus.BlockNode
	tip         wire.Hash256
	cbOutInUTXO bool
	corrupted   bool
	punished    bool
}

// runDupTxidScenario builds, on a REAL ChainManager with a DB-backed UTXO set:
//
//	genesis - 1 .. 101 (coinbase-only) - A (102: confirms T, spending block 1's
//	coinbase, T's output unspent) -- coins flushed -- B (103, from a peer:
//	coinbase overpays by 1 BTC, T re-included verbatim)
//
// and feeds B through the P2P connect loop. bip34Short sets params.BIP34Hash
// to the block at BIP34Height (as mainnet/testnet3 do), so CheckBIP30 is
// short-circuited; with it false BIP30 is enforced (testnet4/signet/regtest).
func runDupTxidScenario(t *testing.T, bip34Short bool) dupTxidOutcome {
	t.Helper()
	p := *consensus.RegtestParams()
	params := &p
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	utxo := consensus.NewUTXOSet(db)
	if bip34Short {
		anc := idx.Genesis()
		if params.BIP34Height != 0 {
			t.Fatalf("setup: regtest BIP34Height=%d, test assumes 0", params.BIP34Height)
		}
		params.BIP34Hash = anc.Hash
	} else {
		params.BIP34Hash = wire.Hash256{}
	}
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
	})
	cm.SetIBD(false)
	r := &invalidBlockRig{t: t, params: params, idx: idx, db: db, cm: cm}
	idx.MarkDataStored(idx.Genesis().Hash)

	tip := idx.Genesis()
	var block1 *wire.MsgBlock
	for h := 1; h <= 101; h++ {
		b := mkDupBlock(t, params, tip, 0)
		r.stage(b)
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("connect %d: %v", h, err)
		}
		if h == 1 {
			block1 = b
		}
		tip = idx.GetNode(b.Header.BlockHash())
	}

	// T spends block 1's (now mature) coinbase, paying it all to an
	// anyone-can-spend output: zero fee, so A's coinbase is exactly the subsidy.
	cb1 := block1.Transactions[0]
	txT := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: cb1.TxHash(), Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: cb1.TxOut[0].Value, PkScript: []byte{0x51}}},
	}
	blockA := mkDupBlock(t, params, tip, 0, txT)
	r.stage(blockA)
	if err := cm.ConnectBlock(blockA); err != nil {
		t.Fatalf("connect A: %v", err)
	}
	aNode := idx.GetNode(blockA.Header.BlockHash())
	if err := utxo.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	tOut := wire.OutPoint{Hash: txT.TxHash(), Index: 0}
	if !utxo.HasUTXODurable(tOut) {
		t.Fatal("precondition: T's output must be durable after the flush")
	}

	r.sm = NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, ChainManager: cm, ChainDB: db})
	t.Cleanup(func() { close(r.sm.quit) })

	// B: coinbase overpaying by 1 BTC, then T re-included verbatim.
	blockB := mkDupBlock(t, params, aNode, 100_000_000, txT)
	r.header(blockB)
	r.sm.StartBlockDownload()
	x := &Peer{addr: "127.0.0.2:40001"}
	pending := map[int32]*blockWithRequest{}
	r.deliver(pending, blockB, x)
	r.sm.connectPendingBlocks(pending)

	tipHash, _ := cm.BestBlock()
	return dupTxidOutcome{
		bNode:       idx.GetNode(blockB.Header.BlockHash()),
		aNode:       aNode,
		tip:         tipHash,
		cbOutInUTXO: utxo.GetUTXO(wire.OutPoint{Hash: blockB.Transactions[0].TxHash(), Index: 0}) != nil,
		corrupted:   r.sm.chainstateCorrupted.Load(),
		punished:    x.ShouldBan(),
	}
}

// TestAdoptRejectsDuplicateTxidBlock: a peer-supplied block that re-includes an
// already-confirmed transaction (outputs unspent, so they are "durable
// evidence") must be rejected as invalid, not adopted as marker lag.
//
// Pre-fix the connect failed with "references missing UTXO" (T's input was
// spent by A), the P2P loop routed it to AdoptAppliedBlock, the evidence probe
// found T's output on disk, and the tolerant roll-forward applied B — its
// 1 BTC overpaying coinbase included — with no script, amount, coinbase-value
// or maturity check, marking it fully valid. Core: CheckTxInputs ->
// bad-txns-inputs-missingorspent, ConnectBlock marks the block invalid.
func TestAdoptRejectsDuplicateTxidBlock(t *testing.T) {
	o := runDupTxidScenario(t, true)
	if o.bNode == nil {
		t.Fatal("B is not in the header index")
	}
	if o.tip != o.aNode.Hash {
		t.Fatalf("tip = %s, want A (%s): the duplicate-txid block was adopted",
			o.tip.String()[:16], o.aNode.Hash.String()[:16])
	}
	if o.cbOutInUTXO {
		t.Fatal("B's overpaying coinbase output is in the UTXO set")
	}
	if o.bNode.Status&consensus.StatusInvalid == 0 {
		t.Fatal("B was not marked invalid")
	}
	if o.bNode.Status&consensus.StatusFullyValid != 0 {
		t.Fatal("B is marked fully valid")
	}
	if o.corrupted {
		t.Fatal("chainstateCorrupted latched: a peer's invalid block halted the node")
	}
	if !o.punished {
		t.Fatal("the peer that delivered B was not punished")
	}
}

// TestAdoptRejectsDuplicateTxidBlock_BIP30Control is the negative control:
// with BIP34Hash zeroed, CheckBIP30 is enforced and rejects B as a duplicate
// (bad-txns-BIP30) before the input check — on master too. It proves the rig
// itself builds a block the node can reject.
func TestAdoptRejectsDuplicateTxidBlock_BIP30Control(t *testing.T) {
	o := runDupTxidScenario(t, false)
	if o.tip != o.aNode.Hash {
		t.Fatalf("tip = %s, want A", o.tip.String()[:16])
	}
	if o.cbOutInUTXO {
		t.Fatal("B's coinbase output is in the UTXO set")
	}
	if o.bNode.Status&consensus.StatusInvalid == 0 {
		t.Fatal("B was not marked invalid under BIP30")
	}
}
