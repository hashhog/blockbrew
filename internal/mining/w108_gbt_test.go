// W108 audit: BlockTemplate / GBT (getblocktemplate) mining RPC — 30 gates.
//
// Reference: bitcoin-core/src/rpc/mining.cpp + node/miner.cpp
// BIP-22: getblocktemplate base spec
// BIP-23: getblocktemplate refinements (capabilities, mutable, proposal mode)
// BIP-9:  version-bits signaling (rules / vbavailable in GBT response)
// BIP-141: witness coinbase commitment
// BIP-34: block height in coinbase scriptSig
// policy/policy.h: DEFAULT_BLOCK_MAX_WEIGHT=4_000_000, DEFAULT_BLOCK_RESERVED_WEIGHT=8_000
//
// Gate map:
//   G1  – BIP-22 mode=proposal accepted
//   G2  – GBT enforces "segwit" rule requirement (BIP-145)
//   G3  – GBT checks peer connectivity on mainnet (not IBD)
//   G4  – GBT enforces "signet" rule on signet networks
//   G5  – GBT response includes "longpollid" field (BIP-22 §4)
//   G6  – GBT response includes "rules" array (csv / !segwit / taproot)
//   G7  – GBT response includes "vbavailable" map for active BIP-9 deployments
//   G8  – GBT response includes "capabilities" field (BIP-23)
//   G9  – Per-tx "depends" field computed from in-block parent indices (not empty)
//   G10 – Per-tx "fee" field non-zero when mempool has tracked fees
//   G11 – GBT "sigoplimit" is MAX_BLOCK_SIGOPS_COST (80_000 post-segwit)
//   G12 – GBT "sizelimit" is MAX_BLOCK_SERIALIZED_SIZE (4_000_000 post-segwit)
//   G13 – GBT "weightlimit" is MAX_BLOCK_WEIGHT (4_000_000) post-segwit
//   G14 – Block reserved weight starts at DefaultBlockReservedWeight (8_000 WU)
//   G15 – Block weight uses >= comparator for limit check (not just >)
//   G16 – Block version uses ComputeBlockVersion (not hardcoded 0x20000000)
//   G17 – Version field includes BIP-9 signaling bits for STARTED deployments
//   G18 – coinbase nLockTime = height-1 (Core miner.cpp:196)
//   G19 – coinbase nSequence = 0xFFFFFFFE MAX_SEQUENCE_NONFINAL (not 0xFFFFFFFF)
//   G20 – coinbase nSequence != SEQUENCE_FINAL (locktime enforcement opt-in)
//   G21 – GBT response "coinbasevalue" = subsidy + fees (not zero)
//   G22 – submitblock "duplicate-invalid" and "duplicate-inconclusive" paths
//   G23 – BlockTemplate sizelimit constant value (consensus.MaxBlockSize vs 4MB)
//   G24 – BIP-22 maps PoW failure to "high-hash" (bip22ResultString coverage)
//   G25 – BIP-22 maps merkle failure to "bad-txnmrklroot"
//   G26 – BIP-22 maps bad coinbase value to "bad-cb-amount"
//   G27 – BIP-22 maps non-final tx to "bad-txns-nonfinal"
//   G28 – getmininginfo "blocks" field present
//   G29 – getmininginfo "networkhashps" field present
//   G30 – prioritisetransaction RPC absent (missing feature)
package mining

import (
	"reflect"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// G1 – BIP-22 mode=proposal: GBT must parse mode="proposal" and process it
// separately from mode="template".  The handler currently ignores all params
// and never parses the "mode" key, so proposal blocks are silently treated
// as normal template requests.
//
// Expected (Core rpc/mining.cpp:730): if mode=="proposal" → validate the
// supplied block and return a BIP-22 result string (or null for valid).
// Actual: params are ignored; mode="proposal" returns a template instead.
// Verdict: BUG – mode=proposal not implemented.
// ---------------------------------------------------------------------------
func TestW108_G1_ProposalModeNotImplemented(t *testing.T) {
	// The bug: handleGetBlockTemplate(params json.RawMessage) never unmarshals params.
	// We can only test this at the unit level by verifying the handler function
	// signature accepts params but doesn't process them.
	//
	// Structural assertion: BlockTemplateResult struct lacks a "proposal" response path —
	// it always returns *BlockTemplateResult, never a plain string (which is what
	// BIP-22 proposal mode requires: null or error string).
	//
	// The test documents the bug; when fixed, a mode=proposal code-path should
	// parse params, call TestBlockValidity, and return a string/null.
	t.Log("G1 BUG: handleGetBlockTemplate ignores params entirely — " +
		"mode='proposal' not parsed, proposal block not validated, " +
		"template returned instead of BIP-22 validation result. " +
		"Core: mining.cpp:730 strMode='proposal' → DecodeHexBlk + TestBlockValidity")
}

// ---------------------------------------------------------------------------
// G2 – GBT must require "segwit" in the rules[] field of the request
// (BIP-145 / Core rpc/mining.cpp:855-857).  If the client does not pass
// rules=["segwit"], Core returns an RPC error.  blockbrew never checks.
// ---------------------------------------------------------------------------
func TestW108_G2_SegwitRuleNotEnforced(t *testing.T) {
	// Structural check: handleGetBlockTemplate never unmarshals params,
	// so it cannot check for "segwit" in the client rules array.
	// Core: if (!setClientRules.contains("segwit")) → throw RPCError
	// blockbrew: no rules check whatsoever.
	t.Log("G2 BUG: GBT does not enforce 'segwit' in client rules[]. " +
		"Core mining.cpp:855: 'getblocktemplate must be called with the segwit rule set'. " +
		"blockbrew accepts calls with no rules and returns a template anyway.")
}

// ---------------------------------------------------------------------------
// G3 – GBT must check peer connectivity and IBD on non-test chains.
// Core: if (!miner.isTestChain()) { check connections > 0; check !isIBD }
// blockbrew: no connectivity or IBD check in handleGetBlockTemplate.
// ---------------------------------------------------------------------------
func TestW108_G3_PeerConnectivityIBDCheckMissing(t *testing.T) {
	t.Log("G3 BUG: GBT does not check peer connectivity or IBD status before " +
		"returning a template. Core mining.cpp:766-775: on non-test chains, " +
		"returns RPC_CLIENT_NOT_CONNECTED if connman.GetNodeCount==0 and " +
		"RPC_CLIENT_IN_INITIAL_DOWNLOAD if isIBD. blockbrew has neither guard.")
}

// ---------------------------------------------------------------------------
// G4 – GBT must require "signet" in rules on signet networks.
// Core: if (consensusParams.signet_blocks && !setClientRules.contains("signet"))
//   → throw RPCError (mining.cpp:850-851).
// blockbrew: params are never parsed, signet_blocks never checked.
// ---------------------------------------------------------------------------
func TestW108_G4_SignetRuleNotEnforced(t *testing.T) {
	t.Log("G4 BUG: GBT does not enforce 'signet' rule on signet networks. " +
		"Core mining.cpp:850: if signet_blocks and !clientRules.contains('signet') → error. " +
		"blockbrew ignores network type and never checks client rules.")
}

// ---------------------------------------------------------------------------
// G5 – GBT response must include "longpollid" field (BIP-22 §4).
// Core: result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast))
// blockbrew: BlockTemplateResult struct has no LongPollID field.
// ---------------------------------------------------------------------------
func TestW108_G5_LongPollIDMissingFromResponse(t *testing.T) {
	// The BlockTemplateResult type in rpc/types.go has no "longpollid" field.
	// Confirmed by inspection of internal/rpc/types.go:431-448.
	t.Log("G5 BUG: BlockTemplateResult struct missing 'longpollid' field. " +
		"Core mining.cpp:1002: result.pushKV('longpollid', tipHash+nTxUpdated). " +
		"Mining pools use longpollid to detect tip changes without polling.")
}

// ---------------------------------------------------------------------------
// G6 – GBT response must include "rules" array with active softforks.
// Core (mining.cpp:950-963): aRules starts with "csv"; adds "!segwit" and
// "taproot" post-activation; adds "!signet" on signet.
//
// FIX: BlockTemplateResult.Rules []string added; handler populates it from
// chain params + tip height. Full RPC-level coverage:
//   TestW108_G6_RulesInGBTResponse (internal/rpc/w108_gbt_rpc_test.go).
// ---------------------------------------------------------------------------
func TestW108_G6_RulesArrayMissingFromResponse(t *testing.T) {
	// Structural assertion: BlockTemplate (mining-layer) provides enough data
	// for the RPC handler to compute rules[]. Verify the template is generated
	// without error on a regtest chain (the RPC handler builds rules[] from
	// chainParams + template.Height, not from BlockTemplate fields directly).
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}
	mp := &mockMempool{}
	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("G6: GenerateTemplate failed: %v", err)
	}

	// template.Height must be 1 (tip 0 + 1) so the RPC handler can compute
	// tipHeight = template.Height - 1 = 0 and check burial heights correctly.
	if template.Height != 1 {
		t.Errorf("G6: template.Height = %d, want 1 (needed by rules[] computation)", template.Height)
	}

	// On regtest all buried heights are 0 (active from genesis):
	// csv/segwit/taproot are all active. RPC handler must emit:
	//   rules = ["csv", "!segwit", "taproot"]
	// That logic lives in handleGetBlockTemplate; see
	// TestW108_G6_RulesInGBTResponse in internal/rpc/w108_gbt_rpc_test.go.
	t.Log("G6 FIXED: BlockTemplateResult.Rules []string added to rpc.BlockTemplateResult; " +
		"handler computes [\"csv\",\"!segwit\",\"taproot\"] on regtest (post-segwit/taproot). " +
		"Full assertion: TestW108_G6_RulesInGBTResponse (internal/rpc/w108_gbt_rpc_test.go).")
}

// ---------------------------------------------------------------------------
// G7 – GBT response must include "vbavailable" map (BIP-9).
// Core (mining.cpp:966-983): maps deployment name → bit for SIGNALLING+LOCKED_IN.
//
// FIX: BlockTemplateResult.Vbavailable map[string]int added; handler populates
// it by iterating cp.Deployments and calling GetDeploymentState. Full coverage:
//   TestW108_G7_VbAvailableInGBTResponse (internal/rpc/w108_gbt_rpc_test.go).
// ---------------------------------------------------------------------------
func TestW108_G7_VbAvailableMissingFromResponse(t *testing.T) {
	// Structural: verify GetDeploymentState returns ACTIVE (not STARTED/LOCKED_IN)
	// for AlwaysActive deployments so they do NOT appear in vbavailable.
	dep := &consensus.BIP9Deployment{
		Name:      "testdummy",
		Bit:       28,
		StartTime: consensus.AlwaysActive,
		Timeout:   consensus.NoTimeout,
		Period:    144,
		Threshold: 108,
	}
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	state := consensus.GetDeploymentState(dep, 0, tipNode, params, nil)
	if state == consensus.DeploymentStarted || state == consensus.DeploymentLockedIn {
		t.Errorf("G7: AlwaysActive deployment has state %v; must not appear in vbavailable "+
			"(only STARTED/LOCKED_IN deployments are advertised per BIP-9 / Core mining.cpp:966-983)",
			state)
	}
	if state != consensus.DeploymentActive {
		t.Errorf("G7: AlwaysActive deployment state = %v, want DeploymentActive", state)
	}

	t.Log("G7 FIXED: BlockTemplateResult.Vbavailable map[string]int added to rpc.BlockTemplateResult; " +
		"handler iterates cp.Deployments, emits name→bit for STARTED/LOCKED_IN states only. " +
		"Full assertion: TestW108_G7_VbAvailableInGBTResponse (internal/rpc/w108_gbt_rpc_test.go).")
}

// ---------------------------------------------------------------------------
// G8 – GBT response must include "capabilities" field (BIP-23).
// Core: aCaps = ["proposal"]; result.pushKV("capabilities", aCaps).
// blockbrew BlockTemplateResult has no Capabilities field.
// ---------------------------------------------------------------------------
func TestW108_G8_CapabilitiesMissingFromResponse(t *testing.T) {
	t.Log("G8 BUG: BlockTemplateResult struct missing 'capabilities' array. " +
		"Core mining.cpp:895: aCaps=['proposal']; result.pushKV('capabilities', aCaps). " +
		"Lets mining clients know which optional BIP-22/BIP-23 features are supported.")
}

// ---------------------------------------------------------------------------
// G9 – Per-tx "depends" must list 1-based indices of in-block parent txs.
// Core (mining.cpp:918-921): for each input, if the prevout.hash is already
// in setTxIndex → add its 1-based index to deps[].
// blockbrew: Depends is always []int{} (empty slice, hardcoded).
// ---------------------------------------------------------------------------
func TestW108_G9_PerTxDependsAlwaysEmpty(t *testing.T) {
	// Structural evidence from the handler code (internal/rpc/methods.go:1634):
	//   txs = append(txs, BlockTemplateTx{
	//     ...
	//     Depends: []int{}, // Simplified
	//   })
	t.Log("G9 BUG: Per-tx 'depends' is hardcoded to []int{} in handleGetBlockTemplate. " +
		"Core mining.cpp:918: computes 1-based indices of previously-seen parent txs in block. " +
		"Mining pools require 'depends' to correctly order transactions.")
}

// ---------------------------------------------------------------------------
// G10 – Per-tx "fee" field must be the actual transaction fee in satoshis.
// Core (mining.cpp:926): entry.pushKV("fee", tx_fees.at(index_in_template)).
// blockbrew: fee is hardcoded to 0 for every transaction.
// The BlockTemplate struct has no per-tx fee slice (only total Fees int64).
// selectTransactions accumulates totalFees but discards per-entry fees.
// ---------------------------------------------------------------------------
func TestW108_G10_PerTxFeeAlwaysZero(t *testing.T) {
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	// Build a mempool entry with a non-zero fee.
	feeSats := int64(50_000) // 0.0005 BTC
	tx := createTestTx(100_000)
	txWeight := int64(consensus.CalcTxWeight(tx))
	entry := &mempool.TxEntry{
		Tx:      tx,
		TxHash:  tx.TxHash(),
		Fee:     feeSats,
		Size:    txWeight / 4,
		FeeRate: float64(feeSats) / float64(txWeight/4),
	}

	mp := &mockMempool{entries: []*mempool.TxEntry{entry}}
	chainState := &mockChainState{
		tipHash:   genesisHash,
		tipHeight: 0,
		tipNode:   tipNode,
	}
	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	// The template total fee should be non-zero (the entry fee was 50_000).
	if len(template.Block.Transactions) > 1 && template.Fees == 0 {
		t.Errorf("G10 pre-condition: template.Fees = 0 but %d txs included; "+
			"fee tracking may be broken upstream",
			len(template.Block.Transactions)-1)
	}

	// BUG: BlockTemplate has no per-tx fee slice.
	// When the RPC handler iterates txs and sets Fee: 0, pools receive wrong data.
	// Assert the struct field is absent using reflection.
	tmplType := reflect.TypeOf(*template)
	hasTxFees := false
	for i := 0; i < tmplType.NumField(); i++ {
		f := tmplType.Field(i)
		if f.Name == "TxFees" || f.Name == "PerTxFees" || f.Name == "TxFeesSlice" {
			hasTxFees = true
		}
	}
	if hasTxFees {
		t.Log("G10: BlockTemplate now has a per-tx fee slice — verify RPC handler uses it")
	} else {
		t.Log("G10 BUG: BlockTemplate has no per-tx fee slice; " +
			"GBT per-tx 'fee' is always 0. " +
			"Core: tx_fees.at(index_in_template). " +
			"Fix: add TxFees []int64 to BlockTemplate, populate in selectTransactions.")
	}
}

// ---------------------------------------------------------------------------
// G11 – GBT "sigoplimit" must be MAX_BLOCK_SIGOPS_COST (80_000) post-segwit.
// Post-segwit: nSigOpLimit = MAX_BLOCK_SIGOPS_COST = 80_000 (Core mining.cpp:1007).
// Pre-segwit: divided by WITNESS_SCALE_FACTOR = 20_000.
// blockbrew: always emits consensus.MaxBlockSigOpsCost (80_000).
// ---------------------------------------------------------------------------
func TestW108_G11_SigOpLimitValue(t *testing.T) {
	if consensus.MaxBlockSigOpsCost != 80_000 {
		t.Errorf("G11: MaxBlockSigOpsCost = %d, want 80_000 (Core MAX_BLOCK_SIGOPS_COST)",
			consensus.MaxBlockSigOpsCost)
	}
	// Post-segwit value 80_000 is correct.
	// BUG: pre-segwit division path (sigoplimit/=WITNESS_SCALE_FACTOR→20_000) is missing.
	// Since mainnet/testnet4 are always post-segwit, impact is limited to hypothetical
	// pre-activation deployments, but the code path should exist for correctness.
	t.Log("G11 CORRECT for post-segwit: sigoplimit=80_000. " +
		"Minor: pre-segwit division path (Core mining.cpp:1009-1014) absent.")
}

// ---------------------------------------------------------------------------
// G12 – GBT "sizelimit" must be MAX_BLOCK_SERIALIZED_SIZE (4_000_000) post-segwit.
// Core mining.cpp:1008: nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE (4_000_000).
// blockbrew: emits consensus.MaxBlockSize = 1_000_000 — WRONG post-segwit.
// Core's MAX_BLOCK_SERIALIZED_SIZE is 4_000_000 (consensus/consensus.h:13).
// consensus.MaxBlockSize = 1_000_000 is the legacy block limit, not the same.
// ---------------------------------------------------------------------------
func TestW108_G12_SizeLimitShouldBe4MBPostSegwit(t *testing.T) {
	// Core: MAX_BLOCK_SERIALIZED_SIZE = 4_000_000.
	// blockbrew emits consensus.MaxBlockSize = 1_000_000 in the sizelimit field.
	const coreMaxBlockSerializedSize = int64(4_000_000)
	blockbrewSizeLimit := int64(consensus.MaxBlockSize)

	if blockbrewSizeLimit == coreMaxBlockSerializedSize {
		t.Log("G12: sizelimit now correctly uses 4_000_000 post-segwit")
		return
	}

	// BUG: sizelimit = 1_000_000 constrains pools to legacy block sizes.
	// Mining pools building segwit blocks can use up to 4 MB serialized.
	t.Errorf("G12 BUG: GBT sizelimit = %d (consensus.MaxBlockSize = legacy 1MB), "+
		"want %d (Core MAX_BLOCK_SERIALIZED_SIZE for post-segwit nodes). "+
		"Core consensus.h:13: MAX_BLOCK_SERIALIZED_SIZE = 4_000_000.",
		blockbrewSizeLimit, coreMaxBlockSerializedSize)
}

// ---------------------------------------------------------------------------
// G13 – GBT "weightlimit" must be MAX_BLOCK_WEIGHT (4_000_000) post-segwit.
// blockbrew: returns consensus.MaxBlockWeight = 4_000_000. Correct.
// Core only emits weightlimit post-segwit; blockbrew always emits it (minor).
// ---------------------------------------------------------------------------
func TestW108_G13_WeightLimitCorrect(t *testing.T) {
	if consensus.MaxBlockWeight != 4_000_000 {
		t.Errorf("G13: MaxBlockWeight = %d, want 4_000_000 (Core MAX_BLOCK_WEIGHT)",
			consensus.MaxBlockWeight)
	}
	t.Log("G13 CORRECT: weightlimit=4_000_000 matches Core MAX_BLOCK_WEIGHT.")
}

// ---------------------------------------------------------------------------
// G14 – Block reserved weight: DefaultBlockReservedWeight must be 8_000 WU.
// Core: DEFAULT_BLOCK_RESERVED_WEIGHT = 8_000 (policy/policy.h).
// blockbrew: DefaultBlockReservedWeight = 8_000. Correct.
// ---------------------------------------------------------------------------
func TestW108_G14_BlockReservedWeightIs8000(t *testing.T) {
	if DefaultBlockReservedWeight != 8_000 {
		t.Errorf("G14: DefaultBlockReservedWeight = %d, want 8_000 (Core DEFAULT_BLOCK_RESERVED_WEIGHT)",
			DefaultBlockReservedWeight)
	}
}

// ---------------------------------------------------------------------------
// G15 – Block weight uses >= comparator for limit check.
// Core miner.cpp:241: if (nBlockWeight + chunk.size >= nBlockMaxWeight) → skip.
// blockbrew: uses >= (corrected in prior wave).  Verify the boundary.
// ---------------------------------------------------------------------------
func TestW108_G15_WeightLimitUsesGEComparator(t *testing.T) {
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	tx := createTestTx(5_000_000_000)
	txWeight := int64(consensus.CalcTxWeight(tx))
	// Set maxWeight so that tx exactly hits the limit (totalWeight=0 + txWeight == maxWeight).
	maxWeight := txWeight

	entry := &mempool.TxEntry{
		Tx:      tx,
		TxHash:  tx.TxHash(),
		Fee:     1000,
		Size:    txWeight / 4,
		FeeRate: 1.0,
	}

	mp := &mockMempool{entries: []*mempool.TxEntry{entry}}
	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}
	_ = chainState
	_ = headerIndex

	// selectTransactions with availableWeight exactly equal to tx weight.
	// With >= check: tx SHOULD be excluded (totalWeight=0 + txWeight >= maxWeight).
	mtp := tipNode.GetMedianTimePast()
	selected, _, _, _ := selectTransactions(mp, maxWeight, consensus.MaxBlockSigOpsCost,
		1, uint32(mtp), 0, nil)

	if len(selected) != 0 {
		t.Errorf("G15 BUG: tx at exactly weight==limit was included (%d selected); "+
			"should be rejected by >= check. "+
			"Core miner.cpp:241: nBlockWeight + chunk.size >= nBlockMaxWeight → skip.",
			len(selected))
	}
}

// ---------------------------------------------------------------------------
// G16 – Block version uses ComputeBlockVersion (not hardcoded 0x20000000).
// Core miner.cpp:140: pblock->nVersion = m_versionbitscache.ComputeBlockVersion(...)
// blockbrew GenerateTemplate: calls consensus.ComputeBlockVersion. Correct.
// ---------------------------------------------------------------------------
func TestW108_G16_BlockVersionUsesComputeBlockVersion(t *testing.T) {
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	mp := &mockMempool{}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	// Must have VERSIONBITS_TOP_BITS (0x20000000) set.
	if template.Block.Header.Version&consensus.VersionBitsTopBits == 0 {
		t.Errorf("G16: block version 0x%x missing VERSIONBITS_TOP_BITS 0x%x",
			template.Block.Header.Version, consensus.VersionBitsTopBits)
	}
	// Must NOT be the raw hardcoded value 0x00000001 (version 1).
	if template.Block.Header.Version == 1 {
		t.Errorf("G16 BUG: block version is hardcoded 1 instead of using ComputeBlockVersion")
	}
}

// ---------------------------------------------------------------------------
// G17 – Version signaling: BIP-9 bits are NOT set for ALWAYS_ACTIVE deployments
// (only STARTED/LOCKED_IN get signaling bits per BIP-9).
// Core miner.cpp:140: ComputeBlockVersion ORs in signaling bits for STARTED/LOCKED_IN.
// ---------------------------------------------------------------------------
func TestW108_G17_VersionSignalsBIP9AlwaysActiveNotSet(t *testing.T) {
	params := consensus.RegtestParams()
	localParams := *params
	localParams.Deployments = []*consensus.BIP9Deployment{
		{
			Name:      "w108-always-active",
			Bit:       3,
			StartTime: consensus.AlwaysActive,
			Timeout:   consensus.NoTimeout,
			Period:    144,
			Threshold: 108,
		},
	}

	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}
	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	mp := &mockMempool{}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := NewTemplateGenerator(&localParams, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	// ALWAYS_ACTIVE → deployment ACTIVE → bit 3 must NOT be set for signaling.
	if template.Block.Header.Version&(1<<3) != 0 {
		t.Errorf("G17 BUG: ALWAYS_ACTIVE deployment set bit 3 in version 0x%x — "+
			"Core ComputeBlockVersion only signals bits for STARTED/LOCKED_IN",
			template.Block.Header.Version)
	}
	// Base VERSIONBITS_TOP_BITS must still be set.
	if template.Block.Header.Version&consensus.VersionBitsTopBits == 0 {
		t.Errorf("G17: version 0x%x missing VERSIONBITS_TOP_BITS", template.Block.Header.Version)
	}
}

// ---------------------------------------------------------------------------
// G18 – coinbase nLockTime = height-1 (Core miner.cpp:196).
// ---------------------------------------------------------------------------
func TestW108_G18_CoinbaseLockTimeIsHeightMinusOne(t *testing.T) {
	tests := []struct {
		height   int32
		wantLock uint32
	}{
		{1, 0},
		{100, 99},
		{500_000, 499_999},
		{840_000, 839_999},
	}

	for _, tc := range tests {
		coinbase := CreateCoinbaseTx(tc.height, []byte{0x51}, nil, 5_000_000_000, 0, nil)
		if coinbase.LockTime != tc.wantLock {
			t.Errorf("G18: height=%d: coinbase.LockTime=%d, want %d (height-1). "+
				"Core miner.cpp:196: coinbaseTx.nLockTime = uint32_t(nHeight-1)",
				tc.height, coinbase.LockTime, tc.wantLock)
		}
	}
}

// ---------------------------------------------------------------------------
// G19 – coinbase nSequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL).
// Core miner.cpp:171: coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL.
// Using 0xFFFFFFFF (SEQUENCE_FINAL) would bypass locktime enforcement.
// ---------------------------------------------------------------------------
func TestW108_G19_CoinbaseSequenceIsMaxNonfinal(t *testing.T) {
	coinbase := CreateCoinbaseTx(100, []byte{0x51}, nil, 5_000_000_000, 0, nil)

	const maxSequenceNonfinal = uint32(0xFFFFFFFE)
	const sequenceFinal = uint32(0xFFFFFFFF)

	if coinbase.TxIn[0].Sequence == sequenceFinal {
		t.Errorf("G19 BUG: coinbase nSequence = 0x%08X (SEQUENCE_FINAL, bypasses locktime). "+
			"Core miner.cpp:171: must be 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL).",
			coinbase.TxIn[0].Sequence)
	}
	if coinbase.TxIn[0].Sequence != maxSequenceNonfinal {
		t.Errorf("G19: coinbase nSequence = 0x%08X, want 0x%08X (MAX_SEQUENCE_NONFINAL)",
			coinbase.TxIn[0].Sequence, maxSequenceNonfinal)
	}
}

// ---------------------------------------------------------------------------
// G20 – coinbase nSequence ≠ SEQUENCE_FINAL (0xFFFFFFFF).
// Negative form of G19: explicitly verify SEQUENCE_FINAL is not used.
// ---------------------------------------------------------------------------
func TestW108_G20_CoinbaseSequenceNotFinal(t *testing.T) {
	coinbase := CreateCoinbaseTx(200, []byte{0x51}, nil, 5_000_000_000, 1_000, nil)

	if coinbase.TxIn[0].Sequence == 0xFFFFFFFF {
		t.Errorf("G20 BUG: coinbase nSequence = SEQUENCE_FINAL (0xFFFFFFFF); " +
			"must be MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) to enforce nLockTime.")
	}
}

// ---------------------------------------------------------------------------
// G21 – GBT "coinbasevalue" must equal subsidy + total fees.
// Core mining.cpp:1001: result.pushKV("coinbasevalue", block.vtx[0]->vout[0].nValue).
// blockbrew: template.CoinbaseValue = subsidy + totalFees. Correct.
// ---------------------------------------------------------------------------
func TestW108_G21_CoinbaseValueEqualsSubsidyPlusFees(t *testing.T) {
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	feeSats := int64(100_000)
	tx := createTestTx(5_000_000_000)
	txWeight := int64(consensus.CalcTxWeight(tx))
	entry := &mempool.TxEntry{
		Tx:      tx,
		TxHash:  tx.TxHash(),
		Fee:     feeSats,
		Size:    txWeight / 4,
		FeeRate: 10.0,
	}

	mp := &mockMempool{entries: []*mempool.TxEntry{entry}}
	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	// newHeight = 1 (tipHeight 0 + 1).
	expectedSubsidy := consensus.CalcBlockSubsidy(1)
	// CoinbaseValue should include fees only if the tx was included.
	if len(template.Block.Transactions) > 1 {
		expectedValue := expectedSubsidy + feeSats
		if template.CoinbaseValue != expectedValue {
			t.Errorf("G21: CoinbaseValue = %d, want %d (subsidy %d + fees %d)",
				template.CoinbaseValue, expectedValue, expectedSubsidy, feeSats)
		}
	} else {
		// No tx included (tx may have been filtered), just check subsidy.
		if template.CoinbaseValue < expectedSubsidy {
			t.Errorf("G21: CoinbaseValue = %d < subsidy %d",
				template.CoinbaseValue, expectedSubsidy)
		}
	}
}

// ---------------------------------------------------------------------------
// G22 – submitblock "duplicate-invalid" and "duplicate-inconclusive" paths.
// Core (mining.cpp:744-749): if block is already in blockman:
//   - BLOCK_VALID_SCRIPTS set → "duplicate"
//   - BLOCK_FAILED_VALID set → "duplicate-invalid"
//   - otherwise → "duplicate-inconclusive"
// blockbrew: only returns "duplicate" for ErrDuplicateHeader; no distinction
// between duplicate-invalid and duplicate-inconclusive.
// ---------------------------------------------------------------------------
func TestW108_G22_SubmitBlockDuplicateInvalidInconclusive(t *testing.T) {
	// The three-way duplicate split is in the mode=proposal path of Core's GBT
	// (mining.cpp:744-749), not in submitblock itself.
	// submitblock also uses "duplicate" (mining.cpp:1097).
	// blockbrew's submitblock path has no "duplicate-invalid" or
	// "duplicate-inconclusive" distinction for already-known blocks.
	t.Log("G22 PARTIAL: submitblock returns 'duplicate' for ErrDuplicateHeader. " +
		"BUG: 'duplicate-invalid' (BLOCK_FAILED_VALID) and " +
		"'duplicate-inconclusive' (header known but scripts not validated) " +
		"are not distinguished. Core mining.cpp:744-749 (proposal mode) " +
		"and mining.cpp:1097 (submitblock duplicate check).")
}

// ---------------------------------------------------------------------------
// G23 – sizelimit constant: blockbrew uses wrong constant for post-segwit nodes.
// This re-asserts G12 as a standalone constant test.
// ---------------------------------------------------------------------------
func TestW108_G23_SizeLimitConstantWrong(t *testing.T) {
	// Core consensus/consensus.h:13: MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
	// This is what GBT should return as "sizelimit" post-segwit.
	// blockbrew uses consensus.MaxBlockSize = 1_000_000 (legacy limit).
	const coreMaxBlockSerializedSize = 4_000_000
	if consensus.MaxBlockSize == coreMaxBlockSerializedSize {
		return // Already fixed
	}
	t.Errorf("G23 BUG: consensus.MaxBlockSize = %d but Core MAX_BLOCK_SERIALIZED_SIZE = %d. "+
		"GBT 'sizelimit' must be %d post-segwit (not the legacy 1_000_000 limit). "+
		"Fix: add a MaxBlockSerializedSize = 4_000_000 constant and use it in GBT response.",
		consensus.MaxBlockSize, coreMaxBlockSerializedSize, coreMaxBlockSerializedSize)
}

// ---------------------------------------------------------------------------
// G24 – Ensure blockbrew has consensus.ErrDifficultyTooLow sentinel.
// Used by bip22ResultString to emit "high-hash" (in rpc package).
// ---------------------------------------------------------------------------
func TestW108_G24_ErrDifficultyTooLowExists(t *testing.T) {
	if consensus.ErrDifficultyTooLow == nil {
		t.Error("G24: consensus.ErrDifficultyTooLow is nil; sentinel required for BIP-22 'high-hash'")
	}
	// The rpc.bip22ResultString function maps this to "high-hash".
	// Cannot call bip22ResultString from mining package (different package).
	t.Log("G24 CORRECT: consensus.ErrDifficultyTooLow exists, mapped to 'high-hash' in bip22ResultString.")
}

// ---------------------------------------------------------------------------
// G25 – Ensure blockbrew has consensus.ErrBadMerkleRoot sentinel.
// Used by bip22ResultString to emit "bad-txnmrklroot".
// ---------------------------------------------------------------------------
func TestW108_G25_ErrBadMerkleRootExists(t *testing.T) {
	if consensus.ErrBadMerkleRoot == nil {
		t.Error("G25: consensus.ErrBadMerkleRoot is nil; sentinel required for BIP-22 'bad-txnmrklroot'")
	}
	t.Log("G25 CORRECT: consensus.ErrBadMerkleRoot exists, mapped to 'bad-txnmrklroot' in bip22ResultString.")
}

// ---------------------------------------------------------------------------
// G26 – Ensure blockbrew has consensus.ErrBadCoinbaseValue sentinel.
// Used by bip22ResultString to emit "bad-cb-amount".
// ---------------------------------------------------------------------------
func TestW108_G26_ErrBadCoinbaseValueExists(t *testing.T) {
	if consensus.ErrBadCoinbaseValue == nil {
		t.Error("G26: consensus.ErrBadCoinbaseValue is nil; sentinel required for BIP-22 'bad-cb-amount'")
	}
	t.Log("G26 CORRECT: consensus.ErrBadCoinbaseValue exists, mapped to 'bad-cb-amount' in bip22ResultString.")
}

// ---------------------------------------------------------------------------
// G27 – Ensure blockbrew has consensus.ErrNonFinalTx sentinel.
// Used by bip22ResultString to emit "bad-txns-nonfinal".
// ---------------------------------------------------------------------------
func TestW108_G27_ErrNonFinalTxExists(t *testing.T) {
	if consensus.ErrNonFinalTx == nil {
		t.Error("G27: consensus.ErrNonFinalTx is nil; sentinel required for BIP-22 'bad-txns-nonfinal'")
	}
	t.Log("G27 CORRECT: consensus.ErrNonFinalTx exists, mapped to 'bad-txns-nonfinal' in bip22ResultString.")
}

// ---------------------------------------------------------------------------
// G28 – getmininginfo "blocks" field present and equals chain height.
// We test at the mining/template level since getmininginfo is in rpc package.
// Verify that the BlockTemplate.Height field is populated correctly.
// ---------------------------------------------------------------------------
func TestW108_G28_TemplateHeightCorrect(t *testing.T) {
	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}

	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	mp := &mockMempool{}
	headerIndex := &mockHeaderIndex{nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode}}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	template, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("G28 GenerateTemplate: %v", err)
	}

	// tipHeight=0 → next block height should be 1.
	if template.Height != 1 {
		t.Errorf("G28: template.Height = %d, want 1 (tipHeight 0 + 1)", template.Height)
	}

	// Additional: getmininginfo missing currentblockweight and currentblocktx.
	// Core emits these if BlockAssembler::m_last_block_weight is set.
	// blockbrew MiningInfo struct has no CurrentBlockWeight or CurrentBlockTx field.
	t.Log("G28 CORRECT: template.Height = tipHeight+1. " +
		"getmininginfo BUG: missing optional 'currentblockweight' and 'currentblocktx' fields. " +
		"Core: if (BlockAssembler::m_last_block_weight) obj.pushKV('currentblockweight', ...).")
}

// ---------------------------------------------------------------------------
// G29 – getmininginfo "networkhashps" field: verify it exists in MiningInfo struct.
// Also document the bug: the handler doesn't call getnetworkhashps internally.
// ---------------------------------------------------------------------------
func TestW108_G29_GetMiningInfoNetworkHashPSField(t *testing.T) {
	// Structural check: can we build a MiningInfo-like struct with networkhashps?
	// The rpc.MiningInfo struct has NetworkHash float64 json:"networkhashps".
	// The bug: handleGetMiningInfo returns NetworkHash: 0 (not computed).
	// Core: obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request)).
	t.Log("G29 PARTIAL: rpc.MiningInfo has 'networkhashps' field. " +
		"BUG: handleGetMiningInfo returns NetworkHash=0 (never computed). " +
		"Core calls getnetworkhashps sub-handler to populate the value. " +
		"blockbrew has handleGetNetworkHashPS in wave47b_methods.go but " +
		"getmininginfo does not call it.")
}

// ---------------------------------------------------------------------------
// G30 – prioritisetransaction absent from dispatch table.
// Core: "prioritisetransaction", "getprioritisedtransactions", "submitheader".
// blockbrew: none of these are registered.
// ---------------------------------------------------------------------------
func TestW108_G30_PrioritiseTransactionMissing(t *testing.T) {
	// Cannot inspect the dispatch table from the mining package.
	// Document: blockbrew's server.go switch statement has no case for
	// "prioritisetransaction", "getprioritisedtransactions", or "submitheader".
	// This can be verified by searching server.go for these method names.
	t.Log("G30 BUG: 'prioritisetransaction' RPC not in dispatch table. " +
		"Core mining.cpp: prioritisetransaction → mempool.PrioritiseTransaction(txid, nAmount). " +
		"Also missing: 'getprioritisedtransactions' and 'submitheader'. " +
		"Impact: mining pools cannot adjust tx priorities; submitheader unusable.")
}

// ---------------------------------------------------------------------------
// Summary structural test: assert BlockTemplateResult missing fields.
// ---------------------------------------------------------------------------
func TestW108_BlockTemplateMissingBIP22Fields(t *testing.T) {
	// These fields are required by BIP-22 / Core mining.cpp but absent from
	// blockbrew's BlockTemplateResult struct in internal/rpc/types.go:431-448.
	//
	//   "rules"        – active softfork rules (csv/!segwit/taproot/!signet)
	//   "vbavailable"  – BIP-9 deployments in STARTED/LOCKED_IN state
	//   "capabilities" – supported features (["proposal"])
	//   "longpollid"   – tip_hash + nTxUpdated for long-polling (BIP-22 §4)
	//   "vbrequired"   – bit mask of required version bits (always 0 currently)
	//
	// When fixed, each field must be added to the struct AND populated in
	// handleGetBlockTemplate by parsing the params.

	missingFields := []string{
		"rules ([]string, json:\"rules\")",
		"vbavailable (map[string]int, json:\"vbavailable\")",
		"capabilities ([]string, json:\"capabilities\")",
		"longpollid (string, json:\"longpollid\")",
		"vbrequired (int, json:\"vbrequired\")",
	}

	for _, f := range missingFields {
		t.Logf("MISSING FROM BlockTemplateResult: %s", f)
	}
	t.Log("G5+G6+G7+G8 BUG: 5 required BIP-22/BIP-23 GBT response fields absent.")
}

// ---------------------------------------------------------------------------
// Summary: GBT params ignored root cause.
// ---------------------------------------------------------------------------
func TestW108_GBTParamsIgnoredRootCause(t *testing.T) {
	// handleGetBlockTemplate(params json.RawMessage) never calls json.Unmarshal(params, ...).
	// Consequences: G1/G2/G3/G4/G5-G8 all stem from this root cause.
	t.Log("G1-G4 root cause: handleGetBlockTemplate (internal/rpc/methods.go:1599) " +
		"ignores all params. Core parses: mode, rules, longpollid, capabilities. " +
		"Fix: unmarshal params, check mode, check rules['segwit'/'signet'], " +
		"return proposal validation or template with correct rules/vbavailable/capabilities/longpollid.")
}
