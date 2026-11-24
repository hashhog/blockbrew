package consensus

import (
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Bitcoin Core SigNetParams (kernel/chainparams.cpp):
//
//	consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
//	genesis = CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN);
//
// blockbrew had PowLimitBits 0x1e0377ae but PowLimit = mainnetPowLimit
// (00000000ffff...), 1024x harder, so every check that compares a target
// with PowLimit used the mainnet limit on signet.

var neonSignetCoreLimit = func() *big.Int {
	n, ok := new(big.Int).SetString("00000377ae000000000000000000000000000000000000000000000000000000", 16)
	if !ok {
		panic("bad literal")
	}
	return n
}()

func TestNeonSignetPowLimitMatchesCore(t *testing.T) {
	p := SignetParams()
	if p.PowLimit.Cmp(neonSignetCoreLimit) != 0 {
		t.Fatalf("SignetParams().PowLimit = %064x, Core powLimit = %064x", p.PowLimit, neonSignetCoreLimit)
	}
}

// Every network's compact PowLimitBits must be the compact form of PowLimit
// (Core derives nBits limits from powLimit; they cannot disagree).
func TestNeonSignetPowLimitBitsConsistentAllNetworks(t *testing.T) {
	for _, p := range []*ChainParams{MainnetParams(), TestnetParams(), Testnet4Params(), RegtestParams(), SignetParams()} {
		if got := BigToCompact(p.PowLimit); got != p.PowLimitBits {
			t.Errorf("%s: BigToCompact(PowLimit) = 0x%08x, PowLimitBits = 0x%08x", p.Name, got, p.PowLimitBits)
		}
	}
}

// Core sanity_check_chainparams (test/pow_tests.cpp): genesis nBits target
// <= powLimit, and powLimit * 4 * nPowTargetTimespan does not overflow 256 bits.
func TestNeonSignetSanityCheckChainparams(t *testing.T) {
	for _, p := range []*ChainParams{MainnetParams(), TestnetParams(), Testnet4Params(), RegtestParams(), SignetParams()} {
		if p.GenesisBlock.Header.BlockHash() != p.GenesisHash {
			t.Errorf("%s: genesis hash mismatch", p.Name)
		}
		target, neg, over := compactToBigFull(p.GenesisBlock.Header.Bits)
		if neg || over || target.Sign() == 0 {
			t.Errorf("%s: genesis nBits 0x%08x invalid", p.Name, p.GenesisBlock.Header.Bits)
		}
		if p.PowLimit.Cmp(target) < 0 {
			t.Errorf("%s: genesis target %064x exceeds PowLimit %064x", p.Name, target, p.PowLimit)
		}
		if !p.PowNoRetargeting {
			max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
			max.Div(max, big.NewInt(p.TargetTimespan*4))
			if p.PowLimit.Cmp(max) >= 0 {
				t.Errorf("%s: PowLimit * 4 * timespan overflows 256 bits", p.Name)
			}
		}
	}
}

// The signet genesis header itself (bits 0x1e0377ae) must pass the PoW check
// and the full context-free block check under signet params.
func TestNeonSignetGenesisPassesProofOfWork(t *testing.T) {
	p := SignetParams()
	g := p.GenesisBlock
	if err := CheckProofOfWork(g.Header.BlockHash(), g.Header.Bits, p.PowLimit); err != nil {
		t.Fatalf("CheckProofOfWork(signet genesis, 0x%08x): %v", g.Header.Bits, err)
	}
	if err := CheckBlockSanity(g, p.PowLimit); err != nil {
		t.Fatalf("CheckBlockSanity(signet genesis): %v", err)
	}
}

// Control: a target one compact step above the signet limit is refused on
// the limit test (before the hash is even compared).
func TestNeonSignetTargetAboveLimitRejected(t *testing.T) {
	p := SignetParams()
	err := CheckProofOfWork(wire.Hash256{}, 0x1e0377af, p.PowLimit)
	if !errors.Is(err, ErrTargetTooHigh) {
		t.Fatalf("bits 0x1e0377af on signet: got %v, want ErrTargetTooHigh", err)
	}
}

// neonSignetChain builds a parent-linked chain of n headers at bits with a
// fixed spacing between timestamps.
func neonSignetChain(p *ChainParams, n int, bits uint32, spacing uint32) *BlockNode {
	var prev *BlockNode
	ts := p.GenesisBlock.Header.Timestamp
	for h := 0; h < n; h++ {
		node := &BlockNode{
			Height: int32(h),
			Header: wire.BlockHeader{Version: 1, Bits: bits, Timestamp: ts},
			Parent: prev,
		}
		prev = node
		ts += spacing
	}
	return prev
}

// Retarget on signet: a period that took twice the target timespan doubles
// the target, which Core then clamps to the SIGNET powLimit (0x1e0377ae).
func TestNeonSignetRetargetClampsToSignetLimit(t *testing.T) {
	p := SignetParams()
	last := neonSignetChain(p, int(p.DifficultyAdjInterval), 0x1e0377ae, 1200)
	got := CalculateNextWorkRequired(p, last.Height+1, last)
	if got != 0x1e0377ae {
		t.Fatalf("signet retarget after a slow period: got 0x%08x, want 0x1e0377ae (Core clamps to signet powLimit)", got)
	}
	got = CalcNextRequiredDifficulty(p, 0x1e0377ae, 0, 2*p.TargetTimespan)
	if got != 0x1e0377ae {
		t.Fatalf("CalcNextRequiredDifficulty(signet, slow): got 0x%08x, want 0x1e0377ae", got)
	}
}

// Control: a fast period still raises signet difficulty by the clamped x4.
func TestNeonSignetRetargetFastPeriodHarder(t *testing.T) {
	p := SignetParams()
	last := neonSignetChain(p, int(p.DifficultyAdjInterval), 0x1e0377ae, 60)
	got := CalculateNextWorkRequired(p, last.Height+1, last)
	want := BigToCompact(new(big.Int).Div(CompactToBig(0x1e0377ae), big.NewInt(4)))
	if got != want {
		t.Fatalf("signet retarget after a fast period: got 0x%08x, want 0x%08x", got, want)
	}
}

// PermittedDifficultyTransition (Core pow.cpp:89-136, used in headers
// presync): signet staying at the minimum difficulty across a retarget
// boundary is permitted; going above the limit is not.
func TestNeonSignetPermittedDifficultyTransition(t *testing.T) {
	p := SignetParams()
	boundary := int32(p.DifficultyAdjInterval)
	if !PermittedDifficultyTransition(p, boundary, 0x1e0377ae, 0x1e0377ae) {
		t.Fatal("signet 0x1e0377ae -> 0x1e0377ae at a retarget boundary refused; Core permits it")
	}
	if !PermittedDifficultyTransition(p, boundary+1, 0x1e0377ae, 0x1e0377ae) {
		t.Fatal("signet unchanged bits off-boundary refused")
	}
	if PermittedDifficultyTransition(p, boundary, 0x1e0377ae, 0x1e0377af) {
		t.Fatal("signet transition to a target above powLimit permitted")
	}
}
