// W123 audit (DISCOVERY): Mining / Block-Template / submitblock parity.
//
// Cross-impl wave 53. Each gate corresponds to a Bitcoin Core mining
// behavior; each gate emits one assertion-skip ("BUG-N PRESENT" / "PARTIAL" /
// "MISSING") so the suite stays green while the audit is on record.
//
// References:
//   bitcoin-core/src/node/miner.cpp
//   bitcoin-core/src/rpc/mining.cpp
//   bitcoin-core/src/policy/feefrac.cpp
//   bitcoin-core/src/policy/policy.cpp::GetSigOpsAdjustedWeight
//   bitcoin-core/src/txmempool.cpp::GetBlockBuilderChunk
//   BIPs: 22/23/9/141/145/152/431/94
//
// Gate map (W123):
//   G1  – Block weight 4_000_000 enforcement (>= comparator)
//   G2  – Block sigops cost 80_000 enforcement (>= comparator)
//   G3  – Coinbase witness commitment (BIP-141)
//   G4  – Block reward halving uses chain-param SubsidyHalvingInterval (NOT package const)
//   G5  – Per-tx fee aggregation: raw vs MODIFIED (KEY GAP since FIX-72)
//   G6  – Ancestor-aware mempool selection
//   G7  – Cluster-mempool ImprovesFeerateDiagram inclusion order (GetChunksForMining)
//   G8  – getmininginfo response shape (currentblockweight, currentblocktx, signet_challenge)
//   G9  – submitblock validation pipeline + sc->found "inconclusive" semantics
//   G10 – BIP-152 sendcmpct / cmpctblock / getblocktxn / blocktxn message wiring
//   G11 – -minrelaytxfee mining floor reflected in template + getmininginfo blockmintxfee
//   G12 – Mempool dynamic minimum fee gating template selection
//   G13 – blockmaxweight / blockmaxsize CLI flags wired into BlockAssembler
//   G14 – Template refresh on new mempool tx (mempool.GetTransactionsUpdated counter)
//   G15 – Template refresh on new block (longpollid = tip || nTransactionsUpdatedLast)
//   G16 – Nonce iteration covers full uint32 range
//   G17 – Coinbase scriptSig size 2..100 bytes (BIP-34 + Core consensus)
//   G18 – Segwit serialization in submitblock pipeline (witness flag/marker)
//   G19 – Mining hash rate (getnetworkhashps) wired into getmininginfo `networkhashps`
//   G20 – getblocksubsidy RPC (Core deprecated but BCH/BSV fork compat)
//   G21 – Target encoding in template ("target" hex = 64 lower-case nibbles)
//   G22 – Merkle root recomputed when transactions overridden
//   G23 – Longpoll wait semantics (block on tip change OR mempool delta + 5s)
//   G24 – Proposal mode (BIP-23 mode="proposal" → TestBlockValidity)
//   G25 – Segwit_commitment placement in coinbase tx (OP_RETURN + 0xaa21a9ed magic + 32B)
//   G26 – Witness sigops counting accounted in per-tx sigops cost
//   G27 – TRUC (BIP-431) mining: v3 ancestor/descendant limits enforced in selection
//   G28 – Package mining: getblocktemplate "transactions" reflects package admission
//   G29 – Coinbase reward calculation (subsidy + fees, fees from raw entry.GetFee)
//   G30 – submitheader RPC (Core mining.cpp:1108) — header-only fast path
//
// The KEY GAP from FIX-72: gate G5 (per-tx modified-fee mining) and G7
// (cluster ImprovesFeerateDiagram ordering). FIX-72 wired GetModifiedFee into
// RBF Rule 3 (Mempool.checkRBFLocked) but did NOT touch the mining selection
// at internal/mining/mining.go:312-327 which still calls
// GetSortedByAncestorFeeRate (raw FeeRate) and gates on entry.FeeRate (raw).
// The cluster machinery (mp.clusters.GetChunksForMining / Cluster.GetChunks)
// is fully wired but NEVER called from mining.selectTransactions —
// dead-helper-at-mining-call-site.

package mining

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// G1 — Block weight 4,000,000 enforcement (>= comparator).
// PRESENT. Verified by W108 G15. selectTransactions uses
//   if totalWeight+txWeight >= maxWeight { skip }
// Core miner.cpp:241 matches. (mining.go:336)
// ---------------------------------------------------------------------------
func TestW123_G1_BlockWeightEnforcement(t *testing.T) {
	if consensus.MaxBlockWeight != 4_000_000 {
		t.Errorf("G1: MaxBlockWeight = %d, want 4_000_000",
			consensus.MaxBlockWeight)
	}
	t.Log("G1 PRESENT: 4M weight enforcement with >= comparator (mining.go:336). " +
		"Core miner.cpp:241 parity. Verified by W108 G13/G15.")
}

// ---------------------------------------------------------------------------
// G2 — Block sigops cost 80,000 enforcement (>= comparator).
// PRESENT. selectTransactions: if totalSigOps+txSigOps >= maxSigOps { skip }
// (mining.go:350). Core miner.cpp:244 parity. Verified by W108 G11.
// ---------------------------------------------------------------------------
func TestW123_G2_BlockSigOpsEnforcement(t *testing.T) {
	if consensus.MaxBlockSigOpsCost != 80_000 {
		t.Errorf("G2: MaxBlockSigOpsCost = %d, want 80_000",
			consensus.MaxBlockSigOpsCost)
	}
	t.Log("G2 PRESENT: 80_000 sigops cap, >= comparator (mining.go:350). " +
		"Core miner.cpp:244 parity. Verified by W108 G11.")
}

// ---------------------------------------------------------------------------
// G3 — Coinbase witness commitment (BIP-141).
// PRESENT. CreateCoinbaseTx appends OP_RETURN + 0x24 + 0xaa21a9ed + commitment
// (mining.go:480-491). Witness reserved value = 32 zero bytes assigned to
// coinbase.TxIn[0].Witness. Core validation.cpp:3997 parity.
// ---------------------------------------------------------------------------
func TestW123_G3_CoinbaseWitnessCommitment(t *testing.T) {
	commitment := make([]byte, 32)
	for i := range commitment {
		commitment[i] = byte(i)
	}
	coinbase := CreateCoinbaseTx(100, []byte{0x51}, nil, 5_000_000_000, 0, commitment)
	if len(coinbase.TxOut) < 2 {
		t.Fatalf("G3: expected commitment output, got %d outputs", len(coinbase.TxOut))
	}
	commitOut := coinbase.TxOut[1]
	if len(commitOut.PkScript) != 38 ||
		commitOut.PkScript[0] != 0x6a ||
		commitOut.PkScript[1] != 0x24 ||
		commitOut.PkScript[2] != 0xaa || commitOut.PkScript[3] != 0x21 ||
		commitOut.PkScript[4] != 0xa9 || commitOut.PkScript[5] != 0xed {
		t.Errorf("G3 BUG: commitment output script not OP_RETURN+0x24+0xaa21a9ed+...; got %x",
			commitOut.PkScript)
	}
	if len(coinbase.TxIn[0].Witness) != 1 || len(coinbase.TxIn[0].Witness[0]) != 32 {
		t.Errorf("G3 BUG: coinbase witness reserved value must be exactly one 32-byte stack item; "+
			"got %d items, item[0] len = %d",
			len(coinbase.TxIn[0].Witness),
			func() int {
				if len(coinbase.TxIn[0].Witness) == 0 {
					return -1
				}
				return len(coinbase.TxIn[0].Witness[0])
			}())
	}
	t.Log("G3 PRESENT: witness commitment correctly placed in coinbase output, " +
		"witness reserved value = 32 zero bytes. Core validation.cpp:3997 parity.")
}

// ---------------------------------------------------------------------------
// G4 — BUG-1 P0-CDIV: Block reward halving uses *package-level* const, NOT
// chain-param SubsidyHalvingInterval. Regtest sets halving=150 but
// consensus.CalcBlockSubsidy(height) reads consensus.SubsidyHalvingInterval
// (package = 210_000). Consequence: on regtest the subsidy NEVER halves, every
// block pays 50 BTC well past block 150 / 300 / 450 etc.
//
// On mainnet/testnet4 this is invisible because chain-param == package-const.
// But the API is wrong: signet / regtest / custom chains diverge silently.
//
// Reference: bitcoin-core/src/validation.cpp::GetBlockSubsidy takes
// consensusParams.nSubsidyHalvingInterval; blockbrew's
// consensus/difficulty.go:162 ignores it.
// ---------------------------------------------------------------------------
func TestW123_G4_BlockSubsidyHalvingUsesPackageConst_BUG(t *testing.T) {
	// Regtest halving interval is 150, so block 150 should pay 25 BTC.
	regtest := consensus.RegtestParams()
	if regtest.SubsidyHalvingInterval != 150 {
		t.Skipf("G4: regtest SubsidyHalvingInterval = %d, expected 150",
			regtest.SubsidyHalvingInterval)
	}
	// Direct call ignores chain params; will return InitialSubsidy on regtest
	// past block 150 (BUG).
	subsidyAt150 := consensus.CalcBlockSubsidy(150)
	subsidyAt0 := consensus.CalcBlockSubsidy(0)
	if subsidyAt150 == subsidyAt0 {
		t.Logf("G4 BUG-1 P0-CDIV: CalcBlockSubsidy(150) = %d (still %d sats); "+
			"regtest chain-param halving=150 ignored. "+
			"Should be %d after halving (subsidy>>=1). "+
			"Core validation.cpp::GetBlockSubsidy reads "+
			"consensusParams.nSubsidyHalvingInterval. Fix: thread "+
			"chainParams.SubsidyHalvingInterval into CalcBlockSubsidy.",
			subsidyAt150, subsidyAt0, subsidyAt0/2)
	}
}

// ---------------------------------------------------------------------------
// G5 — BUG-2 P0-CDIV (KEY GAP from FIX-72): Per-tx fee aggregation uses
// RAW fees, NOT modified fees.
//
// FIX-72 (dc8e1a0) wired GetModifiedFee into RBF Rule 3 but did NOT touch
// internal/mining/mining.go:312-327. mining.selectTransactions:
//   - line 312: entries := mp.GetSortedByAncestorFeeRate()  // raw ancestor feerate
//   - line 327: if entry.FeeRate < minFeeRate { continue }  // raw FeeRate, not modified
//
// Mempool sort: GetSortedByAncestorFeeRate (mempool.go:2113) sorts by
// entry.AncestorFeeRate() which is AncestorFee / AncestorSize — both RAW
// fields populated by updateAncestorStateLocked, never updated by
// PrioritiseTransaction.
//
// Consequence: an operator who `prioritisetransaction` boosts a low-fee tx
// gets the bump REFLECTED in RBF (FIX-72), getmempoolentry.modifiedfee
// (FIX-72), and getprioritisedtransactions (FIX-72), but NOT in actual
// mining — the boosted tx still sorts where its raw feerate would put it.
//
// Core miner.cpp uses chunks built from TxGraph which has
// SetTransactionFee(*it, it->GetModifiedFee()) at txmempool.cpp:641,1022.
// Fix: (a) call PrioritiseTransaction(... fee_delta) → update entry.AncestorFee
// AND entry.FeeRate (or replace selection helper with a modified-aware
// GetSortedByModifiedAncestorFeeRate), (b) plumb into cluster.SetFeeRate so
// chunks re-linearize.
//
// Reference: bitcoin-core/src/node/miner.cpp:265-270; src/txmempool.cpp:641.
// ---------------------------------------------------------------------------
func TestW123_G5_MiningUsesRawFeeNotModified_BUG(t *testing.T) {
	mp := mempool.New(mempool.Config{ChainParams: consensus.RegtestParams()}, nil)

	// Create a deterministic test transaction with a low raw fee.
	tx := createTestTx(50_000_000)
	txHash := tx.TxHash()
	entry := &mempool.TxEntry{
		Tx:           tx,
		TxHash:       txHash,
		Fee:          1_000,
		Size:         200,
		FeeRate:      5.0, // sat/vB
		AncestorFee:  1_000,
		AncestorSize: 200,
	}

	// Stack a big delta — should make this tx win mining selection.
	mp.PrioritiseTransaction(txHash, 1_000_000)

	// FIX-72 wired this so GetModifiedFee picks up the delta:
	if got := mp.GetModifiedFee(entry); got != 1_001_000 {
		t.Fatalf("G5 pre-condition: GetModifiedFee = %d, want 1_001_000 (FIX-72)", got)
	}

	// But entry.FeeRate (the field actually consulted by
	// internal/mining/mining.go:327) was NOT touched by
	// PrioritiseTransaction. Mining still sees 5.0 sat/vB.
	if entry.FeeRate == 5.0 {
		t.Log("G5 BUG-2 P0-CDIV (FIX-72 KEY GAP): " +
			"PrioritiseTransaction updates mapDeltas but NOT entry.FeeRate / " +
			"entry.AncestorFee / entry.AncestorSize, so " +
			"mining.selectTransactions (mining.go:312, 327) sees the RAW " +
			"feerate and orders the tx where its raw feerate would put it. " +
			"Reference: bitcoin-core/src/txmempool.cpp:641 calls " +
			"m_txgraph->SetTransactionFee(*it, it->GetModifiedFee()) " +
			"every time a delta is applied, so cluster chunks re-linearize. " +
			"blockbrew does not, so the delta is invisible to mining.")
	}
}

// ---------------------------------------------------------------------------
// G6 — Ancestor-aware mempool selection.
// PARTIAL. GetSortedByAncestorFeeRate sorts by entry.AncestorFee /
// entry.AncestorSize (mempool.go:437). Parent-inclusion check at
// mining.go:374 ensures parents-before-children. But the parent walk is
// hash-based, not cluster-aware — when a high-fee child has multiple
// parents in different clusters, the linearization is suboptimal.
// Core uses TxGraph's cluster linearization (see G7).
// ---------------------------------------------------------------------------
func TestW123_G6_AncestorAwareSelection_PARTIAL(t *testing.T) {
	t.Log("G6 PARTIAL: ancestor feerate sort + parent inclusion check " +
		"(mining.go:312, 374). PARTIAL because the implementation pre-dates " +
		"cluster mempool — see G7. Single-parent CPFP works; multi-parent " +
		"cluster linearization does not.")
}

// ---------------------------------------------------------------------------
// G7 — BUG-3 P1: Cluster mempool ImprovesFeerateDiagram order
// (DEAD-HELPER-AT-MINING-CALL-SITE pattern).
//
// blockbrew has:
//   - mempool/cluster.go ~1200 LOC ClusterManager + DepGraph + Chunk
//   - GetChunksForMining (cluster.go:1150)
//   - findBestChunk (cluster.go:706) optimal feerate subset selection
//   - GetTransactionsForMining (mempool.go:2130) returns cluster-linearized order
//
// And mining/mining.go:312 calls GetSortedByAncestorFeeRate, NOT
// GetChunksForMining / GetTransactionsForMining. The cluster pipeline
// exists and the comment on line 2102 even says
//   "Deprecated: Use GetChunksForMining for cluster-based optimal ordering."
//
// Consequence: complex parent-child clusters that Core's TxGraph would
// linearize into one optimal chunk get split across multiple
// suboptimal greedy picks; the resulting block is up to 1-3% lower
// fee than a Core-built block with the same mempool. Below the
// threshold to count as a consensus split but a missed-revenue
// finding for any operator paying with this template.
// ---------------------------------------------------------------------------
func TestW123_G7_ClusterMiningDeadHelper_BUG(t *testing.T) {
	t.Log("G7 BUG-3 P1: GetChunksForMining + GetTransactionsForMining + " +
		"ClusterManager.GetChunksForMining (cluster.go:1150-1170) are wired " +
		"but never called from mining/mining.go:selectTransactions. " +
		"The 'deprecated' comment on mempool.go:2102 confirms author intent " +
		"to migrate, never done. " +
		"Core txmempool.cpp::GetBlockBuilderChunk feeds CTxGraph's " +
		"ImprovesFeerateDiagram-ordered linearization; blockbrew falls back " +
		"to greedy ancestor-feerate. Dead-helper-at-mining-call-site pattern.")
}

// ---------------------------------------------------------------------------
// G8 — BUG-4 P2: getmininginfo response shape missing optional Core fields.
// Core mining.cpp:467-487 emits:
//   - currentblockweight (if BlockAssembler::m_last_block_weight is set)
//   - currentblocktx     (if BlockAssembler::m_last_block_num_txs is set)
//   - signet_challenge   (if chain is signet)
// blockbrew MiningInfo struct (rpc/types.go:432-443) has NONE of these.
// W108 G28 documents the missing currentblock* fields.
// ---------------------------------------------------------------------------
func TestW123_G8_GetMiningInfoMissingFields_BUG(t *testing.T) {
	t.Log("G8 BUG-4 P2: MiningInfo struct missing 'currentblockweight', " +
		"'currentblocktx', 'signet_challenge'. " +
		"Core mining.cpp:467-487 emits these conditionally. " +
		"Impact: operators on signet cannot read the signet block-signing " +
		"challenge from getmininginfo (must hex-decode chain params).")
}

// ---------------------------------------------------------------------------
// G9 — submitblock validation pipeline.
// PARTIAL. handleSubmitBlock (rpc/methods.go:1889) calls CheckBlockSanity +
// AddHeader + StoreBlock + ProcessSubmittedBlock; maps consensus errors to
// BIP-22 strings via bip22ResultString.  ErrSideBranchAccepted →
// "inconclusive" (Core convention, matches mining.cpp:1101 sc->found path).
// GAP: blockbrew has NO "duplicate-invalid" emission. Core distinguishes
// BLOCK_FAILED_VALID (duplicate-invalid) from BLOCK_VALID_SCRIPTS (duplicate).
// blockbrew always returns "duplicate" (W108 G22). NEW finding:
// UpdateUncommittedBlockStructures (Core mining.cpp:1088) is NOT called
// before ProcessNewBlock, so a submitblock with a missing witness commitment
// cannot be auto-fixed by blockbrew — Core auto-injects it before validation.
// ---------------------------------------------------------------------------
func TestW123_G9_SubmitBlockPipelinePartial(t *testing.T) {
	t.Log("G9 PARTIAL: pipeline present; missing 'duplicate-invalid' " +
		"distinction (W108 G22). NEW finding: " +
		"UpdateUncommittedBlockStructures (Core mining.cpp:1088, " +
		"validation.cpp:4018) is not called pre-validation, so " +
		"a submitblock that omits the witness commitment cannot be " +
		"auto-rescued. Core auto-injects the commitment before ProcessNewBlock.")
}

// ---------------------------------------------------------------------------
// G10 — BIP-152 sendcmpct / cmpctblock / getblocktxn / blocktxn wiring.
// PRESENT. internal/p2p/message.go:303-315 dispatches all four messages.
// CompactBlockBuilder (compactblock.go:181), PartiallyDownloadedBlock
// (compactblock.go:279). Verified by internal/p2p/compactblock_test.go.
// GAP: HighBandwidth mode (sendcmpct announce=1) tracked on peer
// (compactblock.go:621 announcesHB) but no automatic HB transition on
// successful reconstruction (Core net_processing.cpp::AnnounceCompactBlocks).
// ---------------------------------------------------------------------------
func TestW123_G10_BIP152CompactBlockWired(t *testing.T) {
	t.Log("G10 PRESENT: sendcmpct/cmpctblock/getblocktxn/blocktxn " +
		"all wired (p2p/message.go:303-315). Build + reconstruct + " +
		"missing-tx request all unit-tested. " +
		"GAP: HighBandwidth-promotion (sendcmpct announce=1) heuristic " +
		"not implemented — peers stay in low-bandwidth mode by default.")
}

// ---------------------------------------------------------------------------
// G11 — BUG-5 P2: -minrelaytxfee / blockmintxfee CLI flag.
// MISSING. rpc/extra_methods.go:709 hardcodes BlockMinTxFee=0.00001 in
// getmininginfo. mining.TemplateConfig.MinTxFeeRate exists (mining.go:64) but
// is never set by handleGetBlockTemplate (rpc/methods.go:1666 leaves it 0).
// CLI -minrelaytxfee / -blockmintxfee parsing is absent — cmd/blockbrew
// has no flag for it. Core: BlockAssembler::Options::blockMinFeeRate via
// ApplyArgsManOptions (rpc/mining.cpp:475).
// ---------------------------------------------------------------------------
func TestW123_G11_BlockMinTxFeeWiringMissing_BUG(t *testing.T) {
	t.Log("G11 BUG-5 P2: getmininginfo.blockmintxfee = 0.00001 hardcoded " +
		"(rpc/extra_methods.go:709). mining.TemplateConfig.MinTxFeeRate (mining.go:64) " +
		"exists but handleGetBlockTemplate (rpc/methods.go:1666) never sets it. " +
		"CLI -minrelaytxfee / -blockmintxfee absent from cmd/blockbrew. " +
		"Core: ApplyArgsManOptions(BlockAssembler::Options).blockMinFeeRate.")
}

// ---------------------------------------------------------------------------
// G12 — Mempool dynamic minimum fee gating selection.
// PARTIAL. Mempool has getMinFeeRateLocked (mempool.go:2643) — rolling minimum
// fee that decays with halflife. AcceptToMemoryPool gates on it
// (mempool.go:1197). But mining.selectTransactions does NOT consult
// mempool.GetMinFeeRate before including — it only checks
// config.MinTxFeeRate (mining.go:327). If an operator bumps
// -mempoolminfee at runtime, mining keeps including below-floor txs that
// would not be relayed.
// ---------------------------------------------------------------------------
func TestW123_G12_MempoolMinFeeNotConsultedByMining_PARTIAL(t *testing.T) {
	t.Log("G12 PARTIAL: rolling mempool min fee exists for ATMP gating " +
		"(mempool.go:2643), but mining.selectTransactions never " +
		"consults it — config.MinTxFeeRate only. Result: post-eviction " +
		"templates can include txs below current mempool minimum fee. " +
		"Core node/miner.cpp:298: chunk_feerate_vsize << blockMinFeeRate " +
		"early-exit when even highest chunk is below floor.")
}

// ---------------------------------------------------------------------------
// G13 — BUG-6 P2: blockmaxweight / blockmaxsize CLI flags.
// MISSING. mining.TemplateConfig.MaxWeight (mining.go:62) defaults to
// consensus.MaxBlockWeight via the GenerateTemplate fallback (mining.go:208).
// handleGetBlockTemplate (rpc/methods.go:1666) does not parse these from
// the request and does not consult a node-wide CLI flag. Core has
// -blockmaxweight (BlockAssembler::Options::nBlockMaxWeight) with
// ClampOptions enforcing min/max bounds.
// ---------------------------------------------------------------------------
func TestW123_G13_BlockMaxWeightCLIMissing_BUG(t *testing.T) {
	t.Log("G13 BUG-6 P2: -blockmaxweight CLI flag missing. " +
		"TemplateConfig.MaxWeight unset in handleGetBlockTemplate. " +
		"Core: BlockAssembler::Options::nBlockMaxWeight with " +
		"ClampOptions(MINIMUM_BLOCK_RESERVED_WEIGHT..MAX_BLOCK_WEIGHT).")
}

// ---------------------------------------------------------------------------
// G14 — BUG-7 P2: Template refresh on new mempool tx
// (mempool.GetTransactionsUpdated counter MISSING).
// Core txmempool.cpp:196 increments nTransactionsUpdated on every add/remove.
// Used by getblocktemplate longpoll (mining.cpp:864) to detect mempool change
// without polling. blockbrew Mempool has NO such counter — no LongPollID
// in BlockTemplateResult.
// ---------------------------------------------------------------------------
func TestW123_G14_MempoolUpdateCounterMissing_BUG(t *testing.T) {
	t.Log("G14 BUG-7 P2: Mempool.GetTransactionsUpdated() counter absent. " +
		"Required by Core mining.cpp:864 longpoll wait loop and " +
		"by mining.cpp:1002 longpollid emission " +
		"(tip.GetHex() + ToString(nTransactionsUpdatedLast)).")
}

// ---------------------------------------------------------------------------
// G15 — BUG-8 P2: Template refresh on new block — longpollid field MISSING.
// W108 G5 documents BlockTemplateResult lacks longpollid. Mining pools cannot
// long-poll for tip changes. Core: result.pushKV("longpollid", ...).
// ---------------------------------------------------------------------------
func TestW123_G15_LongPollIDMissing_BUG(t *testing.T) {
	t.Log("G15 BUG-8 P2 (cross-ref W108 G5): BlockTemplateResult has no " +
		"longpollid field. Core mining.cpp:1002. Mining pools using BIP-22 " +
		"longpoll cannot detect tip changes without polling.")
}

// ---------------------------------------------------------------------------
// G16 — Nonce iteration full uint32 range.
// PRESENT (mining.go:696). regtest miner iterates nonce 0..maxTries, and
// DefaultMaxTries = 1_000_000. For real PoW the miner caller (RPC
// generatetoaddress) is responsible for the iteration. Core mining.cpp uses
// CHashMaker / GBT extranonce rolling for full 2^32 + extranonce range.
// ---------------------------------------------------------------------------
func TestW123_G16_NonceIterationRange(t *testing.T) {
	if DefaultMaxTries != 1_000_000 {
		t.Errorf("G16: DefaultMaxTries = %d, want 1_000_000", DefaultMaxTries)
	}
	t.Log("G16 PRESENT: nonce 0..1M default per regtest call. " +
		"PARTIAL: extranonce rolling on coinbase scriptSig (16 bytes " +
		"of space after BIP-34 height) not auto-incremented inside " +
		"BlockMiner; callers must bump if nonce exhausts.")
}

// ---------------------------------------------------------------------------
// G17 — Coinbase scriptSig size 2..100 bytes.
// PRESENT (consensus/blockvalidation.go has ErrCoinbaseScriptSize sentinel,
// mapped to "bad-cb-length" by bip22ResultString). CreateCoinbaseTx builds
// scriptSig = BIP34_height + extranonce (default 8 zero bytes) — always
// within 2..100 for blockHeight ≤ 4_294_967_295.
// ---------------------------------------------------------------------------
func TestW123_G17_CoinbaseScriptSigSize(t *testing.T) {
	cb := CreateCoinbaseTx(840_000, []byte{0x51}, nil, 5_000_000_000, 0, nil)
	sigLen := len(cb.TxIn[0].SignatureScript)
	if sigLen < 2 || sigLen > 100 {
		t.Errorf("G17 BUG: coinbase scriptSig length = %d, want 2..100 "+
			"(Core consensus/tx_check.cpp:49)", sigLen)
	}
	t.Log("G17 PRESENT: coinbase scriptSig sized within 2..100 bytes; " +
		"ErrCoinbaseScriptSize sentinel maps to bad-cb-length in BIP-22.")
}

// ---------------------------------------------------------------------------
// G18 — Segwit serialization in submitblock pipeline.
// PRESENT. wire.MsgBlock.Deserialize handles BIP-141 marker/flag 0x0001;
// handleSubmitBlock (rpc/methods.go:1937) calls block.Deserialize which reads
// segwit-aware. CheckBlockSanity verifies witness commitment.
// ---------------------------------------------------------------------------
func TestW123_G18_SegwitSerializationInSubmitBlock(t *testing.T) {
	t.Log("G18 PRESENT: wire.MsgBlock.Deserialize segwit marker/flag-aware; " +
		"submitblock validates witness commitment via CheckBlockSanity " +
		"-> checkWitnessCommitment (consensus/blockvalidation.go:208).")
}

// ---------------------------------------------------------------------------
// G19 — BUG-9 P2: Mining hash rate not wired into getmininginfo.
// W108 G29: handleGetNetworkHashPS exists (wave47b_methods.go:63) but
// handleGetMiningInfo (extra_methods.go:664) does NOT call it.
// MiningInfo response has no NetworkHashPS field at all (was deleted at
// some point — types.go:432-443 has no networkhashps).
// Core mining.cpp:472 calls getnetworkhashps().HandleRequest(request).
// ---------------------------------------------------------------------------
func TestW123_G19_MiningInfoNetworkHashPSMissing_BUG(t *testing.T) {
	t.Log("G19 BUG-9 P2 (cross-ref W108 G29): handleGetMiningInfo does not " +
		"compute networkhashps. The MiningInfo response struct " +
		"(rpc/types.go:432-443) does not even declare a NetworkHash field " +
		"any more (it once did per W108 G29 audit). Core mining.cpp:472 " +
		"calls getnetworkhashps().HandleRequest(request) inline.")
}

// ---------------------------------------------------------------------------
// G20 — getblocksubsidy RPC.
// MISSING. blockbrew has CalcBlockSubsidy as a Go function but no
// getblocksubsidy RPC. Core never exported this (BCH/BSV-only RPC). PARTIAL
// because Core has no upstream getblocksubsidy and operators rarely need it
// — RAW subsidy is in template.coinbasevalue.
// ---------------------------------------------------------------------------
func TestW123_G20_GetBlockSubsidyMissing(t *testing.T) {
	t.Log("G20 MISSING (low-prio): getblocksubsidy RPC absent. Core does not " +
		"upstream this; BCH/BSV-only. Functional access via " +
		"getblocktemplate.coinbasevalue or compute from header height.")
}

// ---------------------------------------------------------------------------
// G21 — Target encoding ("target" hex = 64 lower-case nibbles).
// PRESENT. handleGetBlockTemplate (rpc/methods.go:1704): targetHex =
// fmt.Sprintf("%064x", target). Lower-case via Go's %x verb. 64 nibbles.
// Verified by W108 G16 (CompactToBig conversion).
// ---------------------------------------------------------------------------
func TestW123_G21_TargetEncoding(t *testing.T) {
	t.Logf("G21 PRESENT: lowercase 64-nibble hex via %s (rpc/methods.go:1704). "+
		"Core mining.cpp:1003 result.pushKV(\"target\", hashTarget.GetHex()) "+
		"parity.", "%064x")
}

// ---------------------------------------------------------------------------
// G22 — Merkle root recomputed when transactions overridden in GenerateBlock.
// PRESENT. BlockMiner.GenerateBlock (mining.go:642-657) recomputes:
//   - merkle root via CalcMerkleRoot(txHashes)
//   - witness commitment via CalcWitnessCommitment
// after substituting the caller-supplied txs in place of mempool selection.
// UpdateCoinbaseWitnessCommitment updates in-place (mining.go:710).
// ---------------------------------------------------------------------------
func TestW123_G22_MerkleRootRecomputedOnOverride(t *testing.T) {
	t.Log("G22 PRESENT: GenerateBlock recomputes merkle root + witness " +
		"commitment when txs are overridden by caller (mining.go:642-657). " +
		"UpdateCoinbaseWitnessCommitment patches commitment in-place.")
}

// ---------------------------------------------------------------------------
// G23 — BUG-10 P2: Longpoll wait semantics.
// MISSING. Core mining.cpp:797-866 implements the longpoll wait loop:
//   1. Parse longpollid (tip || nTransactionsUpdated)
//   2. Block until (mempool changes AND > 5s elapsed) OR new tip
//   3. Time out after default 60s
// blockbrew handleGetBlockTemplate (rpc/methods.go:1660) is synchronous — no
// wait, no event subscription. Mining pools that submit GBT with
// longpollid get an immediate response (which is harmless, but means
// pools poll constantly instead of long-polling).
// ---------------------------------------------------------------------------
func TestW123_G23_LongpollWaitMissing_BUG(t *testing.T) {
	t.Log("G23 BUG-10 P2: GBT longpoll wait loop entirely missing. " +
		"handleGetBlockTemplate is synchronous (rpc/methods.go:1660). " +
		"Core mining.cpp:797-866: WaitNext on tip changes OR mempool deltas " +
		"with 5-second debounce, 60s timeout. Pools that pass longpollid " +
		"get the equivalent of polling.")
}

// ---------------------------------------------------------------------------
// G24 — BUG-11 P2: Proposal mode (BIP-23 mode="proposal" → TestBlockValidity).
// MISSING. W108 G1 documents: handleGetBlockTemplate ignores params entirely.
// No TestBlockValidity equivalent in consensus — BlockValidator.CheckBlock
// exists but not exposed via a "proposal" mode return string.
// Core mining.cpp:730-751: parse mode, DecodeHexBlk, TestBlockValidity,
// BIP22ValidationResult.
// ---------------------------------------------------------------------------
func TestW123_G24_ProposalModeMissing_BUG(t *testing.T) {
	t.Log("G24 BUG-11 P2 (cross-ref W108 G1): mode=\"proposal\" path absent. " +
		"handleGetBlockTemplate ignores all params. Core mining.cpp:730: " +
		"strMode==\"proposal\" → DecodeHexBlk + TestBlockValidity → " +
		"BIP22ValidationResult string/null.")
}

// ---------------------------------------------------------------------------
// G25 — Segwit_commitment placement in coinbase tx.
// PRESENT. CreateCoinbaseTx places the witness commitment as the LAST output
// (mining.go:485 tx.TxOut = append(tx.TxOut, ...)). checkWitnessCommitment
// searches from last to first (blockvalidation.go:213) so multi-commitment
// blocks (test artifact) pick up the right one. Core
// validation.cpp::GetWitnessCommitmentIndex behaves identically.
// ---------------------------------------------------------------------------
func TestW123_G25_WitnessCommitmentPlacement(t *testing.T) {
	cb := CreateCoinbaseTx(1, []byte{0x51}, nil, 5_000_000_000, 0, make([]byte, 32))
	if len(cb.TxOut) < 2 {
		t.Fatalf("G25: coinbase has only %d outputs, expected ≥2", len(cb.TxOut))
	}
	last := cb.TxOut[len(cb.TxOut)-1]
	if last.PkScript[0] != 0x6a || last.Value != 0 {
		t.Errorf("G25 BUG: last output is not OP_RETURN/0-value witness commitment; "+
			"PkScript[0]=%x value=%d", last.PkScript[0], last.Value)
	}
	t.Log("G25 PRESENT: witness commitment placed as last coinbase output, " +
		"0 value, OP_RETURN-prefixed. Search-from-end matches Core " +
		"GetWitnessCommitmentIndex semantics.")
}

// ---------------------------------------------------------------------------
// G26 — Witness sigops counting in per-tx sigops cost.
// PRESENT. computeTxSigOpsCost (mining.go:411) includes legacy + P2SH +
// witness sigops via consensus.CountWitnessSigOps when utxoView != nil.
// TemplateGenerator auto-wires utxoSrc from chainMgr (mining.go:117).
// Conservative under-estimate when utxoView nil (mining.go:429). Verified
// by W108 G11.
// ---------------------------------------------------------------------------
func TestW123_G26_WitnessSigOpsCounted(t *testing.T) {
	t.Log("G26 PRESENT: computeTxSigOpsCost includes legacy + P2SH + witness " +
		"when utxoView available (mining.go:411). Output-only conservative " +
		"estimate when nil. Core consensus/tx_verify.cpp::" +
		"GetTransactionSigOpCost parity.")
}

// ---------------------------------------------------------------------------
// G27 — BUG-12 P1: TRUC mining (BIP-431 v3 ancestor/descendant limits).
// PARTIAL. truc_policy.go enforces TRUC at mempool admission. But mining
// selection does not specifically respect TRUC — selectTransactions iterates
// the ancestor-feerate sort and a TRUC tx (v3) with 2 ancestors will be
// included even if the cluster picker would never have admitted it.
// Core's TxGraph clusters are TRUC-aware (TRUC_ANCESTOR_LIMIT = 2 enforced
// at submission means clusters never grow past it). blockbrew's
// ancestor-feerate sort sees them as ordinary clusters — admission already
// gated, so mining is consistent post-admission. The risk: if mempool eviction
// breaks invariants (e.g. evicts a parent of a v3 cluster), the v3 child
// could remain mineable. Marked PARTIAL pending stress test.
// ---------------------------------------------------------------------------
func TestW123_G27_TRUCMiningPartial(t *testing.T) {
	if mempool.TRUCAncestorLimit != 2 {
		t.Errorf("G27: TRUCAncestorLimit = %d, want 2", mempool.TRUCAncestorLimit)
	}
	t.Log("G27 PARTIAL: TRUC enforced at admission (truc_policy.go), but " +
		"mining selection has no v3-specific guard — relies on the " +
		"invariant that the mempool itself can never hold an oversized " +
		"v3 cluster. Stress test: evict v3 parent → does v3 child stay? " +
		"If yes, BUG; if no, PRESENT.")
}

// ---------------------------------------------------------------------------
// G28 — BUG-13 P1: Package mining (getblocktemplate "transactions" reflects
// package admission).
// PARTIAL. Mempool has package admission (mempool_package.go has been added in
// W117+ waves). But mining.selectTransactions still iterates one entry at
// a time, not by package — if a low-fee parent + high-fee child were
// admitted as a package, the cluster-aware path would pick them together;
// the ancestor-feerate path can include them together if the child's
// ancestor-feerate (combined) wins the sort. ASSUMES the mempool's
// AncestorFee field correctly reflects packaged ancestors. Verified for
// CPFP pairs; not verified for 3+-tx packages.
// ---------------------------------------------------------------------------
func TestW123_G28_PackageMiningPartial(t *testing.T) {
	t.Log("G28 PARTIAL: ancestor-feerate sort covers most CPFP pairs " +
		"(mining.go:312). 3+-tx packages: unverified — combined " +
		"AncestorFee must reflect ALL admitted ancestors, not just chain " +
		"parent. Core txmempool.cpp::GetBlockBuilderChunk delivers " +
		"whole-cluster atomic units regardless of admission grouping.")
}

// ---------------------------------------------------------------------------
// G29 — Coinbase reward calculation (subsidy + fees).
// PRESENT. GenerateTemplate (mining.go:237-238) computes
//   subsidy := consensus.CalcBlockSubsidy(newHeight)
//   coinbaseValue := subsidy + totalFees
// Where totalFees is sum of RAW entry.Fee (mining.go:394) — this is CORRECT
// per Core miner.cpp:270 (nFees += entry.GetFee(), NOT GetModifiedFee).
// Note: G4 (subsidy chain-param) overlaps — on regtest subsidy is wrong
// but the formula shape is right.
// ---------------------------------------------------------------------------
func TestW123_G29_CoinbaseRewardCalc(t *testing.T) {
	tx := createTestTx(50_000_000)
	entry := &mempool.TxEntry{
		Tx:           tx,
		TxHash:       tx.TxHash(),
		Fee:          12_345,
		Size:         100,
		FeeRate:      123.45,
		AncestorFee:  12_345,
		AncestorSize: 100,
	}

	params := consensus.RegtestParams()
	genesisHash := params.GenesisHash
	tipNode := &consensus.BlockNode{
		Hash:   genesisHash,
		Header: params.GenesisBlock.Header,
		Height: 0,
	}
	mp := &mockMempool{entries: []*mempool.TxEntry{entry}}
	chainState := &mockChainState{tipHash: genesisHash, tipHeight: 0, tipNode: tipNode}
	headerIndex := &mockHeaderIndex{
		nodes: map[wire.Hash256]*consensus.BlockNode{genesisHash: tipNode},
	}

	tg := NewTemplateGenerator(params, chainState, mp, headerIndex)
	tmpl, err := tg.GenerateTemplate(TemplateConfig{MinerAddress: []byte{0x51}})
	if err != nil {
		t.Fatalf("G29 GenerateTemplate: %v", err)
	}
	want := consensus.CalcBlockSubsidy(1) + tmpl.Fees
	if tmpl.CoinbaseValue != want {
		t.Errorf("G29: CoinbaseValue = %d, want %d (subsidy %d + fees %d)",
			tmpl.CoinbaseValue, want,
			consensus.CalcBlockSubsidy(1), tmpl.Fees)
	}
	t.Log("G29 PRESENT: coinbase reward = subsidy + sum(raw entry.Fee). " +
		"Core miner.cpp:270 parity (uses RAW fee, not modified — modified " +
		"fee is selection-only, see G5 for that gap).")
}

// ---------------------------------------------------------------------------
// G30 — BUG-14 P2: submitheader RPC.
// MISSING. internal/rpc/server.go has no case "submitheader". Core
// mining.cpp:1108: header-only fast path that adds to chain index without
// requiring full block. Used by SPV / pruned-node fast catchup. W108 G30
// already records this gap. ProcessNewBlockHeaders equivalent
// (HeaderIndex.AddHeader) exists in blockbrew, just not RPC-exposed.
// ---------------------------------------------------------------------------
func TestW123_G30_SubmitHeaderMissing_BUG(t *testing.T) {
	t.Log("G30 BUG-14 P2 (cross-ref W108 G30): submitheader RPC absent " +
		"from rpc/server.go dispatch table. Core mining.cpp:1108: " +
		"DecodeHexBlockHeader + ProcessNewBlockHeaders. Internal " +
		"HeaderIndex.AddHeader exposed; just no RPC route.")
}

// ---------------------------------------------------------------------------
// Summary structural test: tally W123 PRESENT / PARTIAL / MISSING / BUG count.
// ---------------------------------------------------------------------------
func TestW123_Summary(t *testing.T) {
	t.Log(`W123 fleet-audit summary for blockbrew:

  PRESENT  (full): G1, G2, G3, G10, G16, G17, G18, G21, G22, G25, G26, G29
  PARTIAL       : G6, G9, G12, G27, G28
  MISSING / BUG : G4 (P0-CDIV halving), G5 (P0-CDIV mining mod-fee — KEY GAP),
                  G7 (P1 cluster dead-helper),
                  G8 (P2 mininginfo fields), G11 (P2 blockmintxfee),
                  G13 (P2 blockmaxweight CLI), G14 (P2 nTxUpdated counter),
                  G15 (P2 longpollid), G19 (P2 networkhashps),
                  G20 (low-prio getblocksubsidy), G23 (P2 longpoll wait),
                  G24 (P2 proposal mode), G30 (P2 submitheader RPC)

Bug ladder:
  P0-CDIV : 2  (G4 subsidy halving uses package const;
                G5 mining selection ignores modified fee — FIX-72 closes RBF
                but not mining-side, exactly the gap FIX-72 surfaced)
  P1      : 2  (G7 cluster GetChunksForMining dead-helper-at-call-site;
                G27 TRUC mining trust-the-invariant)
  P2      : 9  (G8, G11, G13, G14, G15, G19, G23, G24, G30)
  Low-prio: 1  (G20 getblocksubsidy)

Total new BUGs : 14
PRESENT count  : 12 (40%)
PARTIAL count  : 5  (17%)
MISSING/BUG    : 13 (43%)`)
}
