package consensus

// Tests for the faithful Bitcoin Core assume-valid script-skip gate
// (shouldSkipScripts, getBlockProofEquivalentTime).
//
// Reference: Bitcoin Core validation.cpp:2346-2382.
//
// The old blockbrew gate was HEIGHT-ONLY:
//   skipScripts = assumeValidHeight > 0 && node.Height <= assumeValidHeight
//
// That incorrectly skips script verification for FORK blocks below av_height.
// The new gate (shouldSkipScripts) requires ALL five conditions:
//   1. assumevalid configured (hash != 0)
//   2. av hash in our block index
//   3a. node is an ancestor of the av block (fork blocks fail here)
//   3b. node is on the best-header chain
//   4. bestHeader.TotalWork >= MinimumChainWork
//   5. getBlockProofEquivalentTime(bestHeader, node) > 2 weeks (1 209 600 s)

import (
	"math/big"
	"testing"
)

// buildTestChainForAV builds a two-block chain and returns (b1Node, b2Node)
// where b2Node has been given a manipulated TotalWork large enough to pass
// the two-week equivalent-time check when b1Node is the block under test.
//
//	genesis → b1 (av_block) → b2 (best header, large TotalWork)
func buildTestChainForAV(t *testing.T) (*HeaderIndex, *BlockNode, *BlockNode) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	// Block at height 1 — will be the assume-valid block.
	h1 := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 0)
	b1Node, err := idx.AddHeader(h1, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	b1Node.Status |= StatusDataStored

	// Block at height 2 — will be the best header.
	h2 := createTestHeader(b1Node.Hash, b1Node.Header.Timestamp+600, 0)
	b2Node, err := idx.AddHeader(h2, true)
	if err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	b2Node.Status |= StatusDataStored

	// Give b2Node enough TotalWork so the equivalent-time check passes for b1Node.
	//
	// getBlockProofEquivalentTime formula:
	//   equiv = (b2.TotalWork - b1.TotalWork) * TargetSpacing / CalcWork(b2.Bits)
	// We need equiv > 1_209_600 s (2 weeks), i.e.:
	//   workDiff > 2016 * CalcWork(b2.Bits)
	// Setting workDiff = 2017 * CalcWork(b2.Bits) gives equiv = 2017 * 600 = 1_210_200 s.
	calWork := CalcWork(b2Node.Header.Bits)
	workNeeded := new(big.Int).Mul(big.NewInt(2017), calWork)
	b2Node.TotalWork = new(big.Int).Add(b1Node.TotalWork, workNeeded)

	return idx, b1Node, b2Node
}

// ---------------------------------------------------------------------------
// EFFECTIVE PROOF:
// A fork block at height <= av_height is now SCRIPT-VERIFIED (was wrongly
// skipped by the height-only gate). An on-chain buried block is still skipped.
// ---------------------------------------------------------------------------

// TestAssumeValidGate_ForkBlockNotSkipped is the EFFECTIVE test.
//
// Setup:
//   - mainchain: genesis → b1 (av_block, height 1) → b2 (best header, large work)
//   - fork:      genesis → forkB1 (different block at height 1)
//
// Old behaviour (height-only):  forkB1.Height (1) <= av_height (1) → skipScripts=true  [WRONG]
// New behaviour (full gate):    condition 3a fails (forkB1 not ancestor of avNode)      → skipScripts=false [CORRECT]
func TestAssumeValidGate_ForkBlockNotSkipped(t *testing.T) {
	idx, b1Node, _ := buildTestChainForAV(t)
	genesis := idx.Genesis()
	avHash := b1Node.Hash

	// Create a fork block at height 1 with a different nonce so it has a
	// different hash from b1Node. Use a high baseNonce to guarantee divergence.
	forkH := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 50000)
	forkNode, err := idx.AddHeader(forkH, true)
	if err != nil {
		t.Fatalf("AddHeader forkB1: %v", err)
	}
	forkNode.Status |= StatusDataStored

	// Sanity: forkNode must be at height 1 (same as b1Node) but different hash.
	if forkNode.Height != 1 {
		t.Fatalf("forkNode.Height = %d, want 1", forkNode.Height)
	}
	if forkNode.Hash == b1Node.Hash {
		t.Fatal("forkNode and b1Node have the same hash — test setup broken")
	}

	params := RegtestParams()
	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: avHash,
	})

	// --- The EFFECTIVE assertion ---
	// Old gate: forkNode.Height (1) <= assumeValidHeight (1) → would skip scripts. WRONG.
	// New gate: avNode.GetAncestor(1) == b1Node ≠ forkNode → condition 3a fails → verify scripts.
	if cm.shouldSkipScripts(forkNode) {
		t.Error("FAIL: fork block below av_height must NOT have scripts skipped (condition 3a must fail)")
	} else {
		t.Log("PASS: fork block below av_height correctly triggers script verification")
	}

	// --- Sanity: the on-chain b1Node (true ancestor of avNode) IS still skipped ---
	if !cm.shouldSkipScripts(b1Node) {
		t.Error("FAIL: on-chain b1Node (av_block itself) with sufficient burial should have scripts skipped")
	} else {
		t.Log("PASS: on-chain block below av_height with sufficient burial is correctly skipped")
	}
}

// ---------------------------------------------------------------------------
// Individual condition gates (each condition when it is the one that fails)
// ---------------------------------------------------------------------------

// TestAssumeValidGate_NoHashConfigured verifies condition 1:
// when assumevalid is not configured (zero hash) → scripts always verified.
func TestAssumeValidGate_NoHashConfigured(t *testing.T) {
	idx, b1Node, _ := buildTestChainForAV(t)
	params := RegtestParams()

	// No AssumeValidHash supplied → zero hash.
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	if cm.shouldSkipScripts(b1Node) {
		t.Error("condition 1: zero assumeValidHash must not skip scripts")
	}
}

// TestAssumeValidGate_HashNotInIndex verifies condition 2:
// when the av hash is not (yet) in our header index → scripts verified.
func TestAssumeValidGate_HashNotInIndex(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Use a hash that is definitely not in the index.
	var unknownHash [32]byte
	unknownHash[0] = 0xde
	unknownHash[31] = 0xad
	avHash := unknownHash

	genesis := idx.Genesis()
	h1 := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 0)
	b1Node, _ := idx.AddHeader(h1, true)
	b1Node.Status |= StatusDataStored

	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: avHash,
	})

	if cm.shouldSkipScripts(b1Node) {
		t.Error("condition 2: av hash not in index must not skip scripts")
	}
}

// TestAssumeValidGate_ForkBlockFailsAncestorCheck verifies condition 3a:
// a fork block at height <= av_height but on a different chain is NOT skipped.
func TestAssumeValidGate_ForkBlockFailsAncestorCheck(t *testing.T) {
	idx, b1Node, _ := buildTestChainForAV(t)
	genesis := idx.Genesis()
	avHash := b1Node.Hash
	params := RegtestParams()

	// Build a two-block fork: genesis → forkB1 → forkB2.
	// forkB2.Height == 2 which is above av_height (1) → old code would NOT skip (correct).
	// But forkB1.Height == 1 == av_height → old code WOULD skip (wrong), new code DOES NOT.
	forkH1 := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 60000)
	forkNode1, err := idx.AddHeader(forkH1, true)
	if err != nil {
		t.Fatalf("AddHeader forkB1: %v", err)
	}
	forkNode1.Status |= StatusDataStored

	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: avHash,
	})

	// forkNode1 is at height 1 (== av_height) but NOT on the av chain.
	// condition 3a: avNode.GetAncestor(1) == b1Node ≠ forkNode1 → false.
	if cm.shouldSkipScripts(forkNode1) {
		t.Errorf("condition 3a: fork block at height 1 must not skip scripts; "+
			"avNode.GetAncestor(1)=%v, forkNode1=%v", b1Node.Hash, forkNode1.Hash)
	}
}

// TestAssumeValidGate_ChainworkBelowMinimum verifies condition 4:
// when bestHeader.TotalWork < MinimumChainWork → scripts always verified.
func TestAssumeValidGate_ChainworkBelowMinimum(t *testing.T) {
	idx, b1Node, b2Node := buildTestChainForAV(t)
	avHash := b1Node.Hash

	// Set a huge MinimumChainWork that b2Node cannot satisfy.
	params := RegtestParams()
	hugeWork := new(big.Int).Lsh(big.NewInt(1), 200) // 2^200 — far above any test chain
	params.MinimumChainWork = hugeWork

	// We must set b2Node.TotalWork < hugeWork for the condition to fire.
	// b2Node.TotalWork was already set to b1.TotalWork + 2017*calWork which is tiny.
	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: avHash,
	})

	// b2Node.TotalWork (small) < MinimumChainWork (2^200) → condition 4 fails.
	if cm.shouldSkipScripts(b1Node) {
		t.Errorf("condition 4: bestHeader.TotalWork (%v) < MinimumChainWork (%v) must not skip scripts",
			b2Node.TotalWork, hugeWork)
	}
}

// TestAssumeValidGate_BlockTooRecent verifies condition 5:
// when getBlockProofEquivalentTime returns <= 2 weeks → scripts verified.
func TestAssumeValidGate_BlockTooRecent(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	h1 := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 0)
	b1Node, err := idx.AddHeader(h1, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	b1Node.Status |= StatusDataStored

	// Build b2Node with DEFAULT (natural) TotalWork — only 2 blocks worth of work,
	// nowhere near the 2016-block threshold for 2 weeks.
	h2 := createTestHeader(b1Node.Hash, b1Node.Header.Timestamp+600, 0)
	b2Node, err := idx.AddHeader(h2, true)
	if err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	b2Node.Status |= StatusDataStored
	// b2Node.TotalWork is the natural value (very small) — do NOT inflate it.

	avHash := b1Node.Hash
	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: avHash,
	})

	// getBlockProofEquivalentTime(b2, b1) = (b2.TotalWork - b1.TotalWork) * 600 / CalcWork(b2.Bits)
	// ≈ 1 block's work * 600 / (1 block's work) = 600 s — far below 1_209_600 s.
	// Condition 5 must fail → scripts verified.
	if cm.shouldSkipScripts(b1Node) {
		t.Error("condition 5: block too recent (tiny TotalWork gap) must not skip scripts")
	}
}

// TestGetBlockProofEquivalentTime verifies the formula directly.
func TestGetBlockProofEquivalentTime(t *testing.T) {
	params := RegtestParams()

	// Construct two synthetic nodes with known TotalWork values.
	pindex := &BlockNode{
		Header:    createTestHeader([32]byte{}, 0, 0),
		TotalWork: big.NewInt(1000),
	}
	calWork := CalcWork(pindex.Header.Bits)

	// bestHeader has 2017 * calWork more work than pindex.
	bestHeader := &BlockNode{
		Header:    pindex.Header,
		TotalWork: new(big.Int).Add(pindex.TotalWork, new(big.Int).Mul(big.NewInt(2017), calWork)),
	}

	got := getBlockProofEquivalentTime(bestHeader, pindex, params)
	const want = int64(2017 * 600) // 2017 * TargetSpacing seconds

	if got != want {
		t.Errorf("getBlockProofEquivalentTime = %d, want %d", got, want)
	}
	if got <= 1209600 {
		t.Errorf("expected > 1209600 (2 weeks), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// -assumevalid=0 DISABLE-KNOB (mainnet-replay harness). EFFECTIVE proof:
// a block that IS script-skipped when assume-valid is configured becomes
// FULLY script-verified once ChainParams.ApplyAssumeValidOverride("0") zeroes
// the hash — the exact transformation the `-assumevalid=0` CLI flag performs
// (cmd/blockbrew/main.go passes chainParams.AssumeValidHash into the manager).
// ---------------------------------------------------------------------------
func TestAssumeValidDisableFlag_ForcesFullVerification(t *testing.T) {
	idx, b1Node, _ := buildTestChainForAV(t)
	params := RegtestParams()

	// RegtestParams() returns a shared instance and an earlier test in this
	// package mutates MinimumChainWork; pin it low so condition 4 is satisfied
	// and this test stays self-contained regardless of run order.
	params.MinimumChainWork = big.NewInt(0)

	// Configure b1Node (a buried, on-chain, sufficiently-aged block) as the
	// network's assume-valid block, exactly as mainnet/testnet4 params do.
	// With AV configured, all five gate conditions hold → scripts are SKIPPED.
	params.AssumeValidHash = b1Node.Hash
	cmConfigured := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: params.AssumeValidHash,
	})
	if !cmConfigured.shouldSkipScripts(b1Node) {
		t.Fatal("baseline broken: with assume-valid configured, buried block below av height must be skipped")
	}

	// --- Apply the flag transformation: -assumevalid=0 ---
	if err := params.ApplyAssumeValidOverride("0"); err != nil {
		t.Fatalf("ApplyAssumeValidOverride(\"0\"): %v", err)
	}
	if !params.AssumeValidHash.IsZero() {
		t.Fatal("-assumevalid=0 must zero AssumeValidHash")
	}

	// Rebuild the manager exactly as cmd/blockbrew/main.go does after the
	// override (AssumeValidHash: chainParams.AssumeValidHash).
	cmDisabled := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		AssumeValidHash: params.AssumeValidHash,
	})

	// --- The EFFECTIVE assertion ---
	// The SAME buried block below the old assume-valid height now goes through
	// FULL script verification: shouldSkipScripts must be false because
	// condition 1 (assumeValidHash.IsZero()) short-circuits to "verify".
	if cmDisabled.shouldSkipScripts(b1Node) {
		t.Error("FAIL: with -assumevalid=0, a block below the old assumevalid height must be fully script-verified (skip=false)")
	} else {
		t.Log("PASS: -assumevalid=0 forces full script verification of a block below the old assumevalid height")
	}
}

// TestApplyAssumeValidOverride_Cases covers the flag-value parsing itself:
// "" is a no-op, "0" disables, a valid 64-hex sets a custom hash (display →
// internal byte order), and a malformed value errors.
func TestApplyAssumeValidOverride_Cases(t *testing.T) {
	// "" leaves the built-in default untouched.
	p := MainnetParams()
	def := p.AssumeValidHash
	if err := p.ApplyAssumeValidOverride(""); err != nil {
		t.Fatalf(`ApplyAssumeValidOverride(""): %v`, err)
	}
	if p.AssumeValidHash != def {
		t.Error(`"" must leave AssumeValidHash unchanged`)
	}

	// "0" zeroes the hash.
	if err := p.ApplyAssumeValidOverride("0"); err != nil {
		t.Fatalf(`ApplyAssumeValidOverride("0"): %v`, err)
	}
	if !p.AssumeValidHash.IsZero() {
		t.Error(`"0" must zero AssumeValidHash`)
	}

	// A valid display-hex hash round-trips to the same String() form.
	const disp = "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
	if err := p.ApplyAssumeValidOverride(disp); err != nil {
		t.Fatalf("ApplyAssumeValidOverride(hex): %v", err)
	}
	if got := p.AssumeValidHash.String(); got != disp {
		t.Errorf("custom hash round-trip: got %s, want %s", got, disp)
	}

	// A malformed value errors and does not silently no-op.
	if err := p.ApplyAssumeValidOverride("not-a-hash"); err == nil {
		t.Error("malformed -assumevalid value must return an error")
	}
}
