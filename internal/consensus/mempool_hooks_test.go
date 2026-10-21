package consensus

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// The chain -> mempool update sequence, and that it runs under the chain lock
// (audit 2026-10-07 BB-6 / T4). Bitcoin Core (validation.cpp):
//   - ConnectTip -> removeForBlock, every connected block;
//   - DisconnectTip -> disconnectpool.AddTransactionsFromBlock;
//   - InvalidateBlock -> MaybeUpdateMempoolForReorg after EACH disconnected
//     block (re-accept only for the first 10);
//   - ActivateBestChainStep -> MaybeUpdateMempoolForReorg once, after the
//     whole disconnect/connect sequence;
//   all with cs_main held.

type hookRecorder struct {
	cm       *ChainManager
	heights  map[wire.Hash256]string
	events   []string
	unlocked []string
}

func (r *hookRecorder) note(ev string) {
	r.events = append(r.events, ev)
	// cm.mu must be held by the caller: TryLock succeeding means it is not.
	if r.cm.mu.TryLock() {
		r.cm.mu.Unlock()
		r.unlocked = append(r.unlocked, ev)
	}
}

func (r *hookRecorder) name(b *wire.MsgBlock) string {
	if n, ok := r.heights[b.Header.BlockHash()]; ok {
		return n
	}
	return b.Header.BlockHash().String()[:8]
}

func installRecorder(cm *ChainManager, blocks map[wire.Hash256]string) *hookRecorder {
	r := &hookRecorder{cm: cm, heights: blocks}
	cm.SetMempoolHooks(MempoolHooks{
		BlockConnected:    func(b *wire.MsgBlock, _ int32) { r.note("C" + r.name(b)) },
		BlockDisconnected: func(b *wire.MsgBlock, _ int32) { r.note("D" + r.name(b)) },
		UpdateForReorg:    func(add bool) { r.note(fmt.Sprintf("U%v", add)) },
	})
	return r
}

func (r *hookRecorder) expect(t *testing.T, label string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(r.events, want) {
		t.Fatalf("%s: mempool hook sequence = %v, want %v", label, r.events, want)
	}
	if len(r.unlocked) > 0 {
		t.Fatalf("%s: hooks ran without the chain lock: %v", label, r.unlocked)
	}
	r.events, r.unlocked = nil, nil
}

func TestMempoolHooksInvalidateReconsiderReorg(t *testing.T) {
	cm, idx, nodes, blocks := newStickyChain(t, 6)
	names := make(map[wire.Hash256]string)
	for i := 1; i < len(blocks); i++ {
		names[blocks[i].Header.BlockHash()] = fmt.Sprint(i)
	}
	r := installRecorder(cm, names)

	// invalidateblock 5 from tip 6: update after EACH disconnected block.
	if err := cm.InvalidateBlock(nodes[5].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	r.expect(t, "invalidateblock 5", "D6", "Utrue", "D5", "Utrue")

	// reconsiderblock 5: one reorg forward, one update at the end.
	if err := cm.ReconsiderBlock(nodes[5].Hash); err != nil {
		t.Fatalf("ReconsiderBlock: %v", err)
	}
	r.expect(t, "reconsiderblock 5", "C5", "C6", "Utrue")

	// A heavier side branch off 4: 5' 6' 7'. Disconnect 6, 5; connect the
	// branch; ONE update after the whole sequence (not per block).
	params := RegtestParams()
	parent := nodes[4]
	var branch []*BlockNode
	for i := 5; i <= 7; i++ {
		b := createTestBlockWithCoinbaseValue(t, params, parent, CalcBlockSubsidy(int32(i))-1)
		n, err := idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("AddHeader %d': %v", i, err)
		}
		if err := cm.chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock %d': %v", i, err)
		}
		names[b.Header.BlockHash()] = fmt.Sprintf("%d'", i)
		branch = append(branch, n)
		parent = n
	}
	if err := cm.ReorgTo(branch[2]); err != nil {
		t.Fatalf("ReorgTo 7': %v", err)
	}
	r.expect(t, "reorg to 7'", "D6", "D5", "C5'", "C6'", "C7'", "Utrue")

	// A failed reorg rolls back to the original tip; the mempool is replayed
	// back too (branch blocks out, original blocks in) before the update, so
	// it ends consistent with the tip it is really on. Branch off 4 whose
	// block 7'' body is missing: 5'' 6'' connect, 7'' fails.
	parent = nodes[4]
	var branch2 []*BlockNode
	for i := 5; i <= 8; i++ {
		b := createTestBlockWithCoinbaseValue(t, params, parent, CalcBlockSubsidy(int32(i))-2)
		n, err := idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("AddHeader %d'': %v", i, err)
		}
		if i != 7 {
			if err := cm.chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
				t.Fatalf("StoreBlock %d'': %v", i, err)
			}
		}
		names[b.Header.BlockHash()] = fmt.Sprintf("%d''", i)
		branch2 = append(branch2, n)
		parent = n
	}
	if err := cm.ReorgTo(branch2[3]); err == nil {
		t.Fatal("ReorgTo 8'' with 7'' missing succeeded")
	}
	if cm.TipNode() != branch[2] {
		t.Fatalf("failed reorg left tip at %d, want 7'", cm.TipNode().Height)
	}
	r.expect(t, "failed reorg to 8''",
		"D7'", "D6'", "D5'", "C5''", "C6''", // the attempt
		"D6''", "D5''", "C5'", "C6'", "C7'", // the replay back to 7'
		"Utrue")
}
