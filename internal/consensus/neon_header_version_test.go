package consensus

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Header acceptance must enforce the BIP34/66/65 mandatory-version gate.
//
// Core: ContextualCheckBlockHeader (validation.cpp:4112-4118) rejects
// "bad-version(0x%08x)" when nVersion < 2/3/4 at or above the BIP34/66/65
// heights, and AcceptBlockHeader runs it before the header is added to the
// block index. So a P2P headers message, submitheader, or submitblock carrying
// such a header leaves nothing in the index. blockbrew's AddHeader (and the
// backfill path's checkLinkedHeaderLocked) called ContextualCheckBlockHeader
// with checkVersion=false, so the header was indexed and could become the
// best header.

// neonHVMineHeader builds a valid-PoW header of the given version on parent.
func neonHVMineHeader(t *testing.T, params *ChainParams, parent *BlockNode, version int32, tag byte) wire.BlockHeader {
	t.Helper()
	h := wire.BlockHeader{
		Version:    version,
		PrevBlock:  parent.Hash,
		MerkleRoot: wire.Hash256{0x4e, 0x48, 0x56, tag},
		Timestamp:  parent.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
	}
	target := CompactToBig(h.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		h.Nonce = i
		if HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return h
		}
	}
	t.Fatalf("could not mine header")
	return h
}

// On regtest BIP34/66/65 are active at height 1 (Core: BIP34Height =
// BIP65Height = BIP66Height = 1), so a v1, v2, v3 or negative-version header at
// height 1 must be refused and must not enter the index.
func TestNeonHeaderVersionAddHeaderRejectsOutdatedVersion(t *testing.T) {
	params := RegtestParams()
	for _, tc := range []struct {
		name    string
		version int32
	}{
		{"v1", 1}, {"v2", 2}, {"v3", 3}, {"v0", 0}, {"neg1", -1}, {"highbit", -2147483648},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx := NewHeaderIndex(params)
			hdr := neonHVMineHeader(t, params, idx.Genesis(), tc.version, 1)
			_, err := idx.AddHeader(hdr, true)
			if !errors.Is(err, ErrBlockVersionTooLow) {
				t.Fatalf("AddHeader(version %d at height 1) = %v, want ErrBlockVersionTooLow (Core bad-version)", tc.version, err)
			}
			if idx.GetNode(hdr.BlockHash()) != nil {
				t.Fatalf("bad-version header was indexed")
			}
			if idx.BestHeight() != 0 {
				t.Fatalf("bad-version header moved the best header to height %d", idx.BestHeight())
			}
		})
	}

	// Control: version 4 and a BIP9-style version are still accepted.
	for _, v := range []int32{4, 0x20000000} {
		idx := NewHeaderIndex(params)
		hdr := neonHVMineHeader(t, params, idx.Genesis(), v, 2)
		if _, err := idx.AddHeader(hdr, true); err != nil {
			t.Fatalf("control: AddHeader(version 0x%08x at height 1) = %v, want accepted", uint32(v), err)
		}
	}
}

// The gate is height-gated exactly like Core's DeploymentActiveAfter: below
// each activation height the old version is still valid (mainnet's first
// 227,930 headers are version 1), at the height it is refused.
func TestNeonHeaderVersionHeightGate(t *testing.T) {
	p := *RegtestParams()
	p.BIP34Height = 3
	p.BIP66Height = 4
	p.BIP65Height = 5
	params := &p
	idx := NewHeaderIndex(params)

	tip := idx.Genesis()
	step := func(height int32, rejectVersion int32, acceptVersion int32) {
		t.Helper()
		if rejectVersion != 0 {
			bad := neonHVMineHeader(t, params, tip, rejectVersion, byte(height)|0x80)
			if _, err := idx.AddHeader(bad, true); !errors.Is(err, ErrBlockVersionTooLow) {
				t.Fatalf("height %d version %d: got %v, want ErrBlockVersionTooLow", height, rejectVersion, err)
			}
			if idx.GetNode(bad.BlockHash()) != nil {
				t.Fatalf("height %d: bad-version header was indexed", height)
			}
		}
		good := neonHVMineHeader(t, params, tip, acceptVersion, byte(height))
		node, err := idx.AddHeader(good, true)
		if err != nil {
			t.Fatalf("control: height %d version %d: got %v, want accepted", height, acceptVersion, err)
		}
		if node.Height != height {
			t.Fatalf("height %d: node at height %d", height, node.Height)
		}
		tip = node
	}
	step(1, 0, 1) // below BIP34: v1 valid
	step(2, 0, 1) // still below BIP34
	step(3, 1, 2) // BIP34 height: v1 refused, v2 valid
	step(4, 2, 3) // BIP66 height: v2 refused, v3 valid
	step(5, 3, 4) // BIP65 height: v3 refused, v4 valid
}

// Control on real data: mainnet block 1 is a version-1 header far below
// BIP34Height (227931) and must still be accepted.
func TestNeonHeaderVersionMainnetBlock1Accepted(t *testing.T) {
	params := MainnetParams()
	idx := NewHeaderIndex(params)
	merkle, err := wire.NewHash256FromHex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
	if err != nil {
		t.Fatal(err)
	}
	hdr := wire.BlockHeader{
		Version:    1,
		PrevBlock:  idx.Genesis().Hash,
		MerkleRoot: merkle,
		Timestamp:  1231469665,
		Bits:       0x1d00ffff,
		Nonce:      2573394689,
	}
	if got := hdr.BlockHash().String(); got != "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" {
		t.Fatalf("fixture is not mainnet block 1: %s", got)
	}
	node, err := idx.AddHeader(hdr, true)
	if err != nil {
		t.Fatalf("mainnet block 1 (version 1, height 1 < BIP34Height): %v", err)
	}
	if node.Height != 1 {
		t.Fatalf("height %d, want 1", node.Height)
	}
}

// The pre-base backfill / band-splice path re-checks linked headers through
// checkLinkedHeaderLocked, which must apply the same version gate.
func TestNeonHeaderVersionLinkedHeaderCheck(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()
	bad := neonHVMineHeader(t, params, genesis, 1, 3)
	good := neonHVMineHeader(t, params, genesis, 4, 4)

	// Genesis() takes idx.mu, so it is read before locking.
	idx.mu.Lock()
	errBad := idx.checkLinkedHeaderLocked(bad, genesis, 1)
	errGood := idx.checkLinkedHeaderLocked(good, genesis, 1)
	idx.mu.Unlock()

	if !errors.Is(errBad, ErrBlockVersionTooLow) {
		t.Fatalf("checkLinkedHeaderLocked(version 1 at height 1) = %v, want ErrBlockVersionTooLow", errBad)
	}
	if errGood != nil {
		t.Fatalf("control: checkLinkedHeaderLocked(version 4 at height 1) = %v, want nil", errGood)
	}
}
