package consensus

import (
	"bytes"
	"sort"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Chain-tip status strings, as Bitcoin Core's getchaintips reports them.
const (
	ChainTipActive       = "active"
	ChainTipInvalid      = "invalid"
	ChainTipHeadersOnly  = "headers-only"
	ChainTipValidFork    = "valid-fork"
	ChainTipValidHeaders = "valid-headers"
)

// ChainTipInfo is one entry of getchaintips.
type ChainTipInfo struct {
	Hash      wire.Hash256
	Height    int32
	BranchLen int32
	Status    string
}

// ChainTips enumerates every chain tip the block index knows, the way Bitcoin
// Core's getchaintips does (rpc/blockchain.cpp): every index entry that is not
// on the active chain and has no child in the index, plus the active tip.
//
// It only READS the index. The status of each tip is derived from flags the
// index already carries, in Core's order:
//
//   - active: on the active chain (only the active tip itself can be a tip).
//   - invalid: the block, or an ancestor between it and the fork point, is
//     marked failed (StatusInvalid / StatusInvalidChild). Core v31 keeps
//     BLOCK_FAILED_VALID on every descendant of a failed block, so walking to
//     the fork point gives the same answer even where a descendant was added
//     after its ancestor was marked.
//   - headers-only: the block or an ancestor off the active chain has no body
//     (Core: !HaveNumChainTxs()).
//   - valid-fork: the block was connected once (StatusFullyValid; Core:
//     IsValid(BLOCK_VALID_SCRIPTS)).
//   - valid-headers: the body is stored but the block was never connected.
//
// branchlen is height - FindFork(active).height. Tips are ordered by height,
// highest first (Core's CompareBlocksByHeight), ties by hash so the output is
// deterministic.
func (cm *ChainManager) ChainTips() []ChainTipInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	active := cm.tipNode
	if active == nil {
		return nil
	}
	idx := cm.headerIndex

	onActive := func(n *BlockNode) bool {
		if n.Height > active.Height {
			return false
		}
		anc := active.GetAncestor(n.Height)
		return anc != nil && anc.Hash == n.Hash
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	tips := []ChainTipInfo{{Hash: active.Hash, Height: active.Height, Status: ChainTipActive}}
	for _, n := range idx.nodes {
		if len(n.Children) != 0 || n.Hash == active.Hash || onActive(n) {
			continue
		}
		failed, missingData := false, false
		fork := n
		for fork != nil && !onActive(fork) {
			if fork.Status.IsInvalid() {
				failed = true
			}
			if fork.Status&StatusDataStored == 0 {
				missingData = true
			}
			fork = fork.Parent
		}
		forkHeight := int32(0)
		if fork != nil {
			forkHeight = fork.Height
		} else {
			// Detached sub-chain (an assumeUTXO graft): no shared ancestor
			// is known, so there is no body below it either.
			missingData = true
		}
		status := ChainTipValidHeaders
		switch {
		case failed:
			status = ChainTipInvalid
		case missingData:
			status = ChainTipHeadersOnly
		case n.Status&StatusFullyValid != 0:
			status = ChainTipValidFork
		}
		tips = append(tips, ChainTipInfo{
			Hash:      n.Hash,
			Height:    n.Height,
			BranchLen: n.Height - forkHeight,
			Status:    status,
		})
	}

	sort.SliceStable(tips[1:], func(i, j int) bool {
		a, b := tips[1+i], tips[1+j]
		if a.Height != b.Height {
			return a.Height > b.Height
		}
		return bytes.Compare(a.Hash[:], b.Hash[:]) < 0
	})
	// Core sorts the active tip in with the rest by height.
	sort.SliceStable(tips, func(i, j int) bool { return tips[i].Height > tips[j].Height })
	return tips
}
