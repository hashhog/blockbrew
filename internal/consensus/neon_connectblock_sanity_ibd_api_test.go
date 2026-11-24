package consensus

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Tests for ConnectBlockSanityChecked, the entry point the P2P sync connect
// loop uses after its validationWorker has run CheckBlockSanity on the same
// block object. The method is reached through an interface assertion so this
// file compiles on a tree that lacks it (and fails there by name).

type neonCBSISanityChecked interface {
	ConnectBlockSanityChecked(block *wire.MsgBlock) error
}

func neonCBSIChecked(t *testing.T, cm *ChainManager) neonCBSISanityChecked {
	t.Helper()
	m, ok := any(cm).(neonCBSISanityChecked)
	if !ok {
		t.Fatalf("ChainManager has no ConnectBlockSanityChecked: the P2P sync path has no " +
			"separate entry point, so ConnectBlock must keep skipping CheckBlockSanity in IBD " +
			"for every caller (import-blocks, ReorgTo, boot replay)")
	}
	return m
}

// Control: the sync path still connects a valid block during IBD.
func TestNeonConnectBlockSanityCheckedIBDValidConnects(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	m := neonCBSIChecked(t, cm)
	blk := neonCBSIBlock(t, cm.params, gen, nil, nil, nil)
	if _, err := idx.AddHeader(blk.Header, true); err != nil {
		t.Fatal(err)
	}
	if err := m.ConnectBlockSanityChecked(blk); err != nil {
		t.Fatalf("ConnectBlockSanityChecked(valid) in IBD: %v", err)
	}
	if tip, _ := cm.BestBlock(); tip != blk.Header.BlockHash() {
		t.Fatal("tip did not move")
	}
}

// Outside IBD the sanity pass still runs on the sync entry point, exactly as
// before (the old skip was keyed on isIBD only).
func TestNeonConnectBlockSanityCheckedPostIBDStillChecks(t *testing.T) {
	cm, idx, gen := neonCBSIRig(t)
	m := neonCBSIChecked(t, cm)
	cm.SetIBD(false)
	bogus := wire.Hash256{0x0b, 0xad}
	blk := neonCBSIBlock(t, cm.params, gen, nil, nil, &bogus)
	if _, err := idx.AddHeader(blk.Header, true); err != nil {
		t.Fatal(err)
	}
	if err := m.ConnectBlockSanityChecked(blk); !errors.Is(err, ErrBadMerkleRoot) {
		t.Fatalf("post-IBD ConnectBlockSanityChecked(bad merkle): got %v, want ErrBadMerkleRoot", err)
	}
}
