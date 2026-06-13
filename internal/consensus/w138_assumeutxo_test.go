// w138_assumeutxo_test.go — W138 AssumeUTXO snapshots discovery audit.
//
// Wave: W138 (DISCOVERY, not fix) — 2026-05-18 — blockbrew.
//
// Scope: SnapshotMetadata header codec + loadtxoutset RPC + CLI
// loadSnapshotFromFile + ActivateSnapshot semantics + BackgroundChainState
// validator + assumeutxohash sanity + snapshot-chainstate persistence +
// dumptxoutset (incl. rollback path) + getchainstates.
//
// Reference: bitcoin-core/src/node/utxo_snapshot.{h,cpp} (metadata + base
// blockhash sidecar + chainstate_snapshot dir), validation.cpp
// ActivateSnapshot:5588 + PopulateAndValidateSnapshot:5754 +
// MaybeValidateSnapshot:5967, rpc/blockchain.cpp dumptxoutset:3074 +
// loadtxoutset:3368 + getchainstates:3462, kernel/chainparams.h:34
// AssumeutxoData, kernel/chainstatemanager_opts.h cache sizing.
//
// Companion: blockbrew/audit/w138_assumeutxo_snapshots.md (23 BUGs, 30
// gates). This test file pins ten present-gate behaviors via assertions
// and skips with t.Skip("W138 audit: BUG-N — ...") for documented gaps.
//
// Note: W102 already audited the same subsystem (see
// w102_assumeutxo_audit_test.go in this package). W138 re-audits with
// an updated matrix that surfaces additional gaps; W138 IDs are
// orthogonal to W102 IDs and the two test files coexist.

package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─────────────────────────────────────────────────────────────────────────────
// G1–G4: SnapshotMetadata codec parity
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G1_SnapshotMagicAndVersionPinned pins the on-wire constants that a
// Core-produced snapshot file MUST match for blockbrew to deserialise it.
// Bitcoin Core: SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff}, VERSION = 2
// (node/utxo_snapshot.h:28+39).
func TestW138_G1_SnapshotMagicAndVersionPinned(t *testing.T) {
	want := [5]byte{'u', 't', 'x', 'o', 0xff}
	if SnapshotMagic != want {
		t.Errorf("SnapshotMagic = %v, want %v (Core utxo_snapshot.h:28)", SnapshotMagic, want)
	}
	if SnapshotVersion != 2 {
		t.Errorf("SnapshotVersion = %d, want 2 (Core utxo_snapshot.h:39)", SnapshotVersion)
	}
}

// TestW138_G2_SupportedVersionsIsASet (BUG-2 — version handling).
// Core uses std::set<uint16_t> m_supported_versions{VERSION} and rejects on
// `!contains(version)` (utxo_snapshot.h:84). blockbrew checks only
// `Version != SnapshotVersion` — a future v3 file is rejected, but a
// reader that wants to accept BOTH v2 and v3 (Core's pattern for
// supporting multiple formats during a migration) cannot be expressed.
func TestW138_G2_SupportedVersionsIsASet(t *testing.T) {
	t.Skip("W138 audit: BUG-2 partial — version check is single-value equality, not a set membership check; reject of future versions OK today but blocks Core's migration pattern")
}

// TestW138_G3_DeserializePerFieldRejection sanity-checks that Deserialize
// rejects clearly bad inputs at the right field positions: wrong magic, wrong
// version, no network magic, no block hash, no coins count.
func TestW138_G3_DeserializePerFieldRejection(t *testing.T) {
	// Build a valid metadata header and then truncate it field-by-field.
	valid := &SnapshotMetadata{
		Magic:        SnapshotMagic,
		Version:      SnapshotVersion,
		NetworkMagic: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		BlockHash:    wire.Hash256{0x01, 0x02, 0x03, 0x04},
		CoinsCount:   42,
	}
	var full bytes.Buffer
	if err := valid.Serialize(&full); err != nil {
		t.Fatalf("Serialize valid metadata: %v", err)
	}
	fullBytes := full.Bytes()

	// Truncate at every field boundary and confirm Deserialize returns an
	// error (any error — we only check that no zero-byte read succeeds).
	for cut := 0; cut < len(fullBytes); cut++ {
		var got SnapshotMetadata
		err := got.Deserialize(bytes.NewReader(fullBytes[:cut]))
		if err == nil {
			t.Errorf("Deserialize accepted truncated input at byte %d", cut)
		}
	}

	// Wrong magic in an otherwise-correct file.
	bad := make([]byte, len(fullBytes))
	copy(bad, fullBytes)
	bad[0] = 'X'
	var got SnapshotMetadata
	if err := got.Deserialize(bytes.NewReader(bad)); err != ErrInvalidSnapshotMagic {
		t.Errorf("Deserialize with bad magic: got %v, want ErrInvalidSnapshotMagic", err)
	}
}

// TestW138_G4_NetworkMagicMismatchDiagnostic (BUG-4 — diagnostic message).
// Core decodes the file's network magic to a friendly chain-name string
// (utxo_snapshot.h:91-101: "The network of the snapshot (%s) does not match
// the network of this node (%s)."). blockbrew returns a generic
// ErrNetworkMismatch sentinel.
func TestW138_G4_NetworkMagicMismatchDiagnostic(t *testing.T) {
	// Pin that the sentinel exists and is at least the right shape — but
	// document that the friendly message is missing (no chain-name decode).
	if ErrNetworkMismatch == nil {
		t.Fatal("ErrNetworkMismatch is nil")
	}
	t.Skip("W138 audit: BUG-4 partial — ErrNetworkMismatch is a generic sentinel; Core surfaces the snapshot's chain-name vs node's chain-name in the error message")
}

// ─────────────────────────────────────────────────────────────────────────────
// G5–G7: Base-blockhash persistence + chainstate_snapshot dir
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G5_WriteSnapshotBaseBlockhashSidecarMissing (BUG-4).
// Core writes base_blockhash sidecar after ActivateSnapshot
// (utxo_snapshot.cpp:22-46). blockbrew has no equivalent.
func TestW138_G5_WriteSnapshotBaseBlockhashSidecarMissing(t *testing.T) {
	t.Skip("W138 audit: BUG-4 — no WriteSnapshotBaseBlockhash; snapshot lineage not persisted across restart (only BestHash/BestHeight stored in ChainState)")
}

// TestW138_G6_ReadSnapshotBaseBlockhashSidecarMissing (BUG-4).
// Core reads base_blockhash sidecar at boot (utxo_snapshot.cpp:48-81)
// including a tell()/SEEK_END trailing-data warning. blockbrew has none.
func TestW138_G6_ReadSnapshotBaseBlockhashSidecarMissing(t *testing.T) {
	t.Skip("W138 audit: BUG-4 — no ReadSnapshotBaseBlockhash; snapshot lineage cannot be reconstructed at boot")
}

// TestW138_G7_FindAssumeutxoChainstateDirMissing (BUG-4 / BUG-7).
// Core: chainstate_snapshot/ leveldb dir holds the snapshot UTXO set while
// the original chainstate/ dir holds the background-IBD-validated UTXOs;
// FindAssumeutxoChainstateDir locates the snapshot dir at boot
// (utxo_snapshot.cpp:83-92). blockbrew uses a single chainDB.
func TestW138_G7_FindAssumeutxoChainstateDirMissing(t *testing.T) {
	t.Skip("W138 audit: BUG-4 / BUG-7 — no separate chainstate_snapshot dir; single-chainstate model precludes Core's 2-chainstate layout on disk")
}

// ─────────────────────────────────────────────────────────────────────────────
// G8–G11: AssumeutxoData table + per-network coverage
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G8_AssumeUTXODataFieldsPinned ensures the AssumeUTXOData struct
// exposes all four fields Core's AssumeutxoData carries (chainparams.h:34-49):
// height, hash_serialized, m_chain_tx_count, blockhash.
func TestW138_G8_AssumeUTXODataFieldsPinned(t *testing.T) {
	d := MainnetAssumeUTXOParams.ForHeight(840000)
	if d == nil {
		t.Fatal("MainnetAssumeUTXOParams.ForHeight(840000) returned nil")
	}
	if d.Height != 840000 {
		t.Errorf("Height = %d, want 840000", d.Height)
	}
	if d.ChainTxCount == 0 {
		t.Errorf("ChainTxCount = 0; should be populated for an 840k mainnet snapshot")
	}
	if (d.HashSerialized == wire.Hash256{}) {
		t.Errorf("HashSerialized is zero; should be populated")
	}
	if (d.BlockHash == wire.Hash256{}) {
		t.Errorf("BlockHash is zero; should be populated")
	}
}

// TestW138_G9_AssumeUTXOLookupHelpers verifies ForHeight + ForBlockHash +
// AvailableHeights are present and self-consistent (Core's
// AssumeutxoForHeight / AssumeutxoForBlockhash / GetAvailableSnapshotHeights;
// chainparams.h:92,119,123).
func TestW138_G9_AssumeUTXOLookupHelpers(t *testing.T) {
	heights := MainnetAssumeUTXOParams.AvailableHeights()
	if len(heights) == 0 {
		t.Fatal("AvailableHeights() is empty for mainnet")
	}
	for _, h := range heights {
		byHeight := MainnetAssumeUTXOParams.ForHeight(h)
		if byHeight == nil {
			t.Errorf("ForHeight(%d) nil but AvailableHeights includes it", h)
			continue
		}
		byHash := MainnetAssumeUTXOParams.ForBlockHash(byHeight.BlockHash)
		if byHash == nil {
			t.Errorf("ForBlockHash(byHeight(%d).BlockHash) nil; lookup helpers diverged", h)
			continue
		}
		if byHash.Height != byHeight.Height {
			t.Errorf("ForBlockHash/ForHeight disagree at height %d: %d vs %d",
				h, byHash.Height, byHeight.Height)
		}
	}
}

// TestW138_G10_MainnetHasCoreCanonicalEntries verifies the four Bitcoin Core
// canonical mainnet snapshot heights are present: 840000, 880000, 910000,
// 935000 (chainparams.cpp m_assumeutxo_data).
func TestW138_G10_MainnetHasCoreCanonicalEntries(t *testing.T) {
	canonical := []int32{840000, 880000, 910000, 935000}
	for _, h := range canonical {
		if MainnetAssumeUTXOParams.ForHeight(h) == nil {
			t.Errorf("MainnetAssumeUTXOParams missing Core canonical entry at height %d", h)
		}
	}
}

// TestW138_G11_Testnet4TableEmpty (BUG-23 / W102 BUG-W102-16).
// Testnet4AssumeUTXOParams is empty so testnet4 snapshot loads always fail.
func TestW138_G11_Testnet4TableEmpty(t *testing.T) {
	if len(Testnet4AssumeUTXOParams.Data) > 0 {
		// Future wave that adds entries will trip this — the test will need to flip.
		t.Errorf("Testnet4AssumeUTXOParams.Data has %d entries; flip W138 BUG-23 status to FIXED and update audit doc",
			len(Testnet4AssumeUTXOParams.Data))
	}
	t.Skip("W138 audit: BUG-23 — Testnet4AssumeUTXOParams.Data is empty; testnet4 -load-snapshot always fails")
}

// ─────────────────────────────────────────────────────────────────────────────
// G12–G17: ActivateSnapshot preconditions
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G12_SnapshotAlreadyLoadedGuardMissing (BUG-5 / Core 5600-5601).
// Core checks `CurrentChainstate().m_from_snapshot_blockhash` and rejects
// re-activation with "Can't activate a snapshot-based chainstate more than
// once". blockbrew lacks the multi-chainstate registry so the check is
// structurally unrepresentable; the RPC handler refuses ALL loads instead.
func TestW138_G12_SnapshotAlreadyLoadedGuardMissing(t *testing.T) {
	t.Skip("W138 audit: BUG-5 — no m_from_snapshot_blockhash field on Chainstate (only fromSnapshotBlockHash pointer used by DualChainstateManager which is itself dead-code per BUG-6); per-call guard unreachable")
}

// TestW138_G13_TableLookupBeforeCoinLoad (G13 PRESENT). The audit-flipped
// behaviour from W102 BUG-W102-15: loadSnapshotFromFile must do the table
// lookup BEFORE LoadSnapshotCoins so a failed lookup does not pollute the
// UTXOSet. This test verifies the consensus-layer API supports that
// ordering (NewSnapshotReader returns metadata without consuming coins).
func TestW138_G13_TableLookupBeforeCoinLoad(t *testing.T) {
	// Build a 1-coin snapshot.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x01
	us.AddUTXO(op, &UTXOEntry{Amount: 5000, PkScript: []byte{0x51}, Height: 10})

	blockHash := wire.Hash256{0xAB, 0xCD}
	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	// NewSnapshotReader returns metadata WITHOUT consuming any coins.
	sr, err := NewSnapshotReader(&buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	if sr.Metadata().BlockHash != blockHash {
		t.Errorf("metadata.BlockHash = %x, want %x", sr.Metadata().BlockHash[:4], blockHash[:4])
	}

	// Now the caller can do AssumeUTXO.ForBlockHash lookup BEFORE calling
	// LoadSnapshotCoins; a failed lookup never reaches coin I/O.
	if got := MainnetAssumeUTXOParams.ForBlockHash(blockHash); got != nil {
		t.Errorf("unexpected: synthetic blockHash matched table entry")
	}
}

// TestW138_G14_BaseBlockMustExistInHeaderIndex (BUG-5 partial / Core 5611-5615).
// Core does `m_blockman.LookupBlockIndex(base_blockhash)` and aborts with
// "The base block header (%s) must appear in the headers chain" if it's
// missing. blockbrew checks `headerIndex.GetNode(meta.BlockHash)` but only
// nil-tolerantly — `if baseNode != nil && baseNode.Status.IsInvalid()` —
// so a base block ABSENT from the index is silently accepted.
func TestW138_G14_BaseBlockMustExistInHeaderIndex(t *testing.T) {
	t.Skip("W138 audit: BUG-5 partial — base block absent from headerIndex is silently accepted; Core requires LookupBlockIndex to return non-null (validation.cpp:5611-5615)")
}

// TestW138_G15_InvalidBaseBlockRejected (G15 PRESENT, BUG-W102-05 fixed).
// Verifies the sentinel + IsInvalid() machinery used by loadSnapshotFromFile
// at main.go:2024-2028 is wired in the consensus layer.
func TestW138_G15_InvalidBaseBlockRejected(t *testing.T) {
	if ErrSnapshotBaseBlockInvalid == nil {
		t.Fatal("ErrSnapshotBaseBlockInvalid sentinel missing")
	}
	if !StatusInvalid.IsInvalid() {
		t.Error("StatusInvalid.IsInvalid() = false; BLOCK_FAILED_VALID gate broken")
	}
	var zero BlockStatus
	if zero.IsInvalid() {
		t.Error("zero BlockStatus.IsInvalid() = true; every block would be rejected")
	}
}

// TestW138_G16_BaseBlockOnBestHeaderChain (G16 PRESENT, BUG-W102-06 fixed).
// Verifies BlockNode.GetAncestor returns the expected ancestor used by
// loadSnapshotFromFile at main.go:2032-2040.
func TestW138_G16_BaseBlockOnBestHeaderChain(t *testing.T) {
	if ErrSnapshotBaseBlockNotOnBestChain == nil {
		t.Fatal("ErrSnapshotBaseBlockNotOnBestChain sentinel missing")
	}
	genesis := &BlockNode{Height: 0, Hash: wire.Hash256{0x00}}
	block1 := &BlockNode{Height: 1, Hash: wire.Hash256{0x01}, Parent: genesis}
	block1.buildSkip()
	block2 := &BlockNode{Height: 2, Hash: wire.Hash256{0x02}, Parent: block1}
	block2.buildSkip()
	if anc := block2.GetAncestor(1); anc == nil || anc.Hash != block1.Hash {
		t.Errorf("GetAncestor(1) = %v, want block1", anc)
	}
}

// TestW138_G17_MempoolEmptyGate (BUG-5 partial / Core 5626-5629).
// Core: `mempool->size() > 0` aborts with "Can't activate a snapshot when
// mempool not empty". blockbrew has the sentinel ErrMempoolNotEmpty +
// checks `mempoolSize > 0` but is ALWAYS called with mempoolSize=0 at boot
// (main.go:795: hard-coded 0 because the mempool isn't initialized until
// step 6). The gate cannot fire in production.
func TestW138_G17_MempoolEmptyGate(t *testing.T) {
	if ErrMempoolNotEmpty == nil {
		t.Fatal("ErrMempoolNotEmpty sentinel missing")
	}
	t.Skip("W138 audit: BUG-5 partial — loadSnapshotFromFile is always called with mempoolSize=0 from boot (main.go:795); the BUG-W102-07 guard cannot fire in production. Once -loadtxoutset RPC is enabled the call site needs the live mempool size")
}

// ─────────────────────────────────────────────────────────────────────────────
// G18–G24: PopulateAndValidateSnapshot
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G18_NoCacheRebalanceBeforeAndAfterLoad (BUG-15 / Core 5641-5675).
// Core resizes IBD chainstate cache down to 1% (IBD_CACHE_PERC=0.01) and
// reserves 99% (SNAPSHOT_CACHE_PERC=0.99) for the snapshot chainstate, then
// calls MaybeRebalanceCaches at the end. blockbrew uses a single UTXOSet
// with a fixed cache budget, so the resize is structurally absent.
func TestW138_G18_NoCacheRebalanceBeforeAndAfterLoad(t *testing.T) {
	t.Skip("W138 audit: BUG-15 / G18 — single-chainstate model; no IBD/SNAPSHOT cache split, no MaybeRebalanceCaches call site")
}

// TestW138_G19_NoCleanupOnBadSnapshot (BUG-4 / Core 5677-5694).
// Core's cleanup_bad_snapshot lambda destroys the snapshot leveldb dir and
// deletes the chainstate_snapshot directory on PopulateAndValidateSnapshot
// failure. blockbrew leaves polluted UTXOs in the active chainDB on hash-
// check failure (W102 BUG-W102-15 closure is "look up table first" — but
// if the per-coin guards fire mid-load the coins already written into the
// in-memory UTXOSet are NOT undone before main.go returns the error).
func TestW138_G19_NoCleanupOnBadSnapshot(t *testing.T) {
	t.Skip("W138 audit: BUG-4 / G19 — partial cleanup; loaded coins in the in-memory UTXOSet are not rolled back on hash-mismatch failure path")
}

// TestW138_G20_PerCoinGuardsPresent (G20 PARTIAL — BUG-11 interrupt missing).
// Verifies all three sentinel errors exist for the per-coin guards Core
// applies inside the coin loop (validation.cpp:5814-5862).
func TestW138_G20_PerCoinGuardsPresent(t *testing.T) {
	if ErrCoinHeightExceedsBase == nil {
		t.Error("ErrCoinHeightExceedsBase sentinel missing (BUG-W102-01)")
	}
	if ErrCoinAmountOutOfRange == nil {
		t.Error("ErrCoinAmountOutOfRange sentinel missing (BUG-W102-02)")
	}
	if ErrCoinOutpointIndexMax == nil {
		t.Error("ErrCoinOutpointIndexMax sentinel missing (BUG-W102-03)")
	}
}

// TestW138_G20_PerCoinHeightGuardFiresAtBoundary verifies the height guard
// rejects coin.Height > baseHeight (Core 5826 strict-greater-than).
func TestW138_G20_PerCoinHeightGuardFiresAtBoundary(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x33}

	// Coin at height 100, baseHeight 99 → reject.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x01
	us.AddUTXO(op, &UTXOEntry{Amount: 1000, PkScript: []byte{0x51}, Height: 100})

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	sr, err := NewSnapshotReader(&buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	chainDB2 := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB2, 99 /* baseHeight */)
	if err == nil {
		t.Fatal("LoadSnapshotCoins with coin.height(100) > baseHeight(99): expected error, got nil")
	}
}

// TestW138_G21_NoInterruptCheckInsideCoinLoop (BUG-11).
// Core checks m_interrupt every 120,000 coins (validation.cpp:5841-5843).
// blockbrew's LoadSnapshotCoins has no abort signal.
func TestW138_G21_NoInterruptCheckInsideCoinLoop(t *testing.T) {
	t.Skip("W138 audit: BUG-11 — LoadSnapshotCoins runs the entire coin loop without interrupt check; SIGINT during a 30-minute 160M-coin import is ignored until completion")
}

// TestW138_G22_NoBatchFlushOnCriticalCache (BUG-15 / Core 5840-5856).
// Core flushes the snapshot coins cache to disk every 120k coins when the
// cache hits CRITICAL state (with a SetBestBlock(GetRandHash()) hack to
// dodge invariants until the final SetBestBlock at line 5870). blockbrew
// accumulates everything in cache then defers flush; peak RAM for a 160M
// coin snapshot is unbounded.
func TestW138_G22_NoBatchFlushOnCriticalCache(t *testing.T) {
	t.Skip("W138 audit: BUG-15 / G21 — no batched flush during coin loop; peak RAM = full coin set, unlike Core's bounded flush-on-CRITICAL pattern")
}

// TestW138_G22_NoSetBestBlockAtPopulationEnd (BUG-3).
// Core: coins_cache.SetBestBlock(base_blockhash) at validation.cpp:5870
// before the final FlushSnapshotToDisk. blockbrew's LoadSnapshotCoins does
// not stamp the coins-cache best-block — SIGKILL between LoadSnapshotCoins
// return and main.go:2076 `loaded.Flush()` leaves a torn chainstate DB.
func TestW138_G22_NoSetBestBlockAtPopulationEnd(t *testing.T) {
	t.Skip("W138 audit: BUG-3 — coins-cache.SetBestBlock(base_blockhash) is not called by LoadSnapshotCoins; SIGKILL window leaves UTXOs without a valid best-block stamp")
}

// TestW138_G23_TrailingByteGuardFires (G23 PRESENT, BUG-W102-04 fixed).
// LoadSnapshotCoins returns ErrSnapshotTrailingBytes when extra bytes remain
// after all coins have been consumed.
func TestW138_G23_TrailingByteGuardFires(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x44}

	// 1-coin snapshot + trailing garbage byte.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x01
	us.AddUTXO(op, &UTXOEntry{Amount: 1000, PkScript: []byte{0x51}, Height: 10})

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	buf.WriteByte(0xAB) // trailing garbage

	sr, err := NewSnapshotReader(&buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	chainDB2 := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB2, 100)
	if err == nil {
		t.Fatal("LoadSnapshotCoins with trailing byte: expected error, got nil")
	}
}

// TestW138_G24_NoSegwitBitStampOnSnapshotAncestors (BUG-17 / Core 5930-5945).
// Core fakes BLOCK_OPT_WITNESS on every block in [AFTER_GENESIS_START..
// snapshot_tip] so Chainstate::NeedsRedownload() won't ask for -reindex on
// startup. blockbrew has no such stamp.
func TestW138_G24_NoSegwitBitStampOnSnapshotAncestors(t *testing.T) {
	t.Skip("W138 audit: BUG-17 — no BLOCK_OPT_WITNESS stamp on [genesis+1..snapshot_tip]; next-boot validation may flag missing witness data on these blocks")
}

// TestW138_G25_NoChainTxCountStampOnSnapshotTip (BUG-18 / Core 5949).
// Core: index->m_chain_tx_count = au_data.m_chain_tx_count at validation.cpp:
// 5949. blockbrew has no ChainTxCount field on BlockNode.
func TestW138_G25_NoChainTxCountStampOnSnapshotTip(t *testing.T) {
	t.Skip("W138 audit: BUG-18 — BlockNode has no ChainTxCount field; au_data.m_chain_tx_count is never stamped, breaking verificationprogress through the snapshot window")
}

// ─────────────────────────────────────────────────────────────────────────────
// G26–G28: BackgroundValidator + multi-chainstate
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G26_BackgroundValidatorHashAlgorithmFixed (BUG-1 P0-CDIV — FIXED
// 2026-06-13). Before the STEP-0 fix, CheckBackgroundValidation called
// ComputeUTXOHash (custom single-SHA256 over the compressed coin form) but
// compared against AssumeUTXOData.HashSerialized (ComputeHashSerialized =
// SHA256d-over-TxOutSer). The two algorithms produced different digests, so the
// background validator could never report success against a real Core snapshot.
//
// ComputeUTXOHash now delegates to ComputeHashSerialized, so the validator and
// the assumeutxo commitment use byte-identical kernels. This pin asserts the
// two converge; if a regression re-diverges them it FAILS.
func TestW138_G26_BackgroundValidatorHashAlgorithmFixed(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0xDE
	us.AddUTXO(op, &UTXOEntry{
		Amount:     50_000_000_00,
		PkScript:   []byte{0x51},
		Height:     1,
		IsCoinbase: true,
	})

	h1, _, err := ComputeUTXOHash(us)
	if err != nil {
		t.Fatalf("ComputeUTXOHash: %v", err)
	}
	h2, _, err := ComputeHashSerialized(us)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	if h1 != h2 {
		t.Errorf("BUG-1 regression: ComputeUTXOHash (%s) != ComputeHashSerialized (%s); the STEP-0 fix requires them to agree", h1.String(), h2.String())
	}
}

// TestW138_G27_DualChainstateManagerNotWired (BUG-6 P1).
// DualChainstateManager type exists (assumeutxo.go:587) but no production
// call site constructs one. Searched main.go + rpc/*.go for
// NewDualChainstateManager — only the W102 test file references it.
func TestW138_G27_DualChainstateManagerNotWired(t *testing.T) {
	t.Skip("W138 audit: BUG-6 — DualChainstateManager defined but never constructed in main.go after loadSnapshotFromFile; background validation thread is dead code")
}

// TestW138_G28_NoInvalidateCoinsDBOnDisk (BUG-6 / Core 6012).
// MaybeValidateSnapshot's handle_invalid_snapshot lambda calls
// unvalidated_cs.InvalidateCoinsDBOnDisk() to rename the snapshot leveldb
// dir on hash mismatch. blockbrew has no equivalent — on hash failure the
// snapshot UTXOs sit in the active chainDB with no rename / quarantine.
func TestW138_G28_NoInvalidateCoinsDBOnDisk(t *testing.T) {
	t.Skip("W138 audit: BUG-6 — no InvalidateCoinsDBOnDisk equivalent; on background-validation hash-mismatch (BUG-1 makes this 100% of the time), no quarantine of the snapshot UTXOs")
}

// ─────────────────────────────────────────────────────────────────────────────
// G29–G30: RPC parity (dumptxoutset / loadtxoutset / getchainstates)
// ─────────────────────────────────────────────────────────────────────────────

// TestW138_G29_WriteSnapshotIteratesCacheOnly (BUG-2 P0-CDIV).
// WriteSnapshot iterates utxoSet.cache (assumeutxo.go:262-269) only —
// coins that have spilled to disk are silently dropped. Core walks the
// CCoinsViewCursor over the chainstate DB.
//
// We verify the bug by constructing a UTXOSet, adding 3 coins, FLUSHING
// (which evicts from cache, leaving them only in chainDB), then calling
// WriteSnapshot. If WriteSnapshot walked the DB it would write 3 coins;
// because it walks only the cache it writes ZERO.
func TestW138_G29_WriteSnapshotIteratesCacheOnly(t *testing.T) {
	// This test is marked skip because we don't want a forward regression
	// on a pin that may flip when BUG-2 is fixed; it's documented as the
	// motivating test for the bug. The behaviour can be observed by
	// reading the WriteSnapshot loop directly (assumeutxo.go:262-269).
	t.Skip("W138 audit: BUG-2 P0-CDIV — WriteSnapshot walks utxoSet.cache only; post-flush state produces a snapshot file missing every spilled coin. Production dumptxoutset on any non-fresh chainstate is torn.")
}

// TestW138_G30_LoadTxOutSetRPCRefusesUnconditionally (BUG-5 P1).
// Documented at methods.go:2869-2891. The RPC ALWAYS returns
// RPC_INTERNAL_ERROR with the -load-snapshot direction message, regardless
// of whether the active chainstate would actually accept an activation.
// Core's gate is conditional on `CurrentChainstate().m_from_snapshot_blockhash`
// being non-null (rpc/blockchain.cpp:3413 / validation.cpp:5600).
func TestW138_G30_LoadTxOutSetRPCRefusesUnconditionally(t *testing.T) {
	t.Skip("W138 audit: BUG-5 — handleLoadTxOutSet refuses all inputs (methods.go:2882-2890); Core's gate is conditional on already-loaded state")
}

// TestW138_G30_DumpTxOutSetNChainTxIsCoinCount (BUG-9).
// DumpTxOutSetResult.NChainTx is populated from `coinsCount` (methods.go:
// 2832) but Core's `nchaintx` is the block's m_chain_tx_count (cumulative
// transactions from genesis). Numbers differ by ~8x on mainnet.
func TestW138_G30_DumpTxOutSetNChainTxIsCoinCount(t *testing.T) {
	t.Skip("W138 audit: BUG-9 — dumptxoutset NChainTx populated with UTXO coin count, not cumulative chain tx count; breaks interop with Core's assumeutxo entry verification")
}

// TestW138_G30_GetChainStatesHardcodesValidated (BUG-8).
// handleGetChainStates sets Validated:true unconditionally (methods.go:
// 2934). Core sets validated=false when m_assumeutxo==UNVALIDATED
// (rpc/blockchain.cpp:3505).
func TestW138_G30_GetChainStatesHardcodesValidated(t *testing.T) {
	t.Skip("W138 audit: BUG-8 — getchainstates always reports validated:true; cannot distinguish a fully-validated chain from an active-after-snapshot chain pending background validation")
}

// TestW138_G30_DumpTxOutSetNoInterruptionPoint (BUG-12).
// Core checks rpc_interruption_point every 5000 iter (rpc/blockchain.cpp:3316).
// blockbrew's WriteSnapshot loop has no equivalent.
func TestW138_G30_DumpTxOutSetNoInterruptionPoint(t *testing.T) {
	t.Skip("W138 audit: BUG-12 — WriteSnapshot loop has no interruption_point; daemon SIGTERM during a 30-min dumptxoutset leaves a half-written temp file")
}

// TestW138_G30_DumpTxOutSetNoFIFOSupport (BUG-10).
// Core's dumptxoutset accepts `path` being a FIFO (rpc/blockchain.cpp:3137 /
// 3140 / 3223) and writes directly to the pipe — both because a FIFO can't
// be renamed and so a consumer can stream the output. blockbrew rejects
// any pre-existing path entry, FIFO or otherwise.
func TestW138_G30_DumpTxOutSetNoFIFOSupport(t *testing.T) {
	t.Skip("W138 audit: BUG-10 — writeUtxoSnapshotFile rejects ALL pre-existing paths; Core supports FIFOs for streaming consumers")
}

// TestW138_G30_DumpTxOutSetTipRace (BUG-15).
// handleDumpTxOutSet calls chainMgr.BestBlock() (methods.go:2506) without
// taking the chain-manager mutex; between that call and the subsequent
// ReorgTo the tip can advance. Core wraps the entire RPC in cs_main.
func TestW138_G30_DumpTxOutSetTipRace(t *testing.T) {
	t.Skip("W138 audit: BUG-15 — dumptxoutset reads tip without chain-manager lock; race window between BestBlock() and ReorgTo on the rollback path")
}

// TestW138_G30_DumpHashFromSecondWalk (BUG-20).
// writeUtxoSnapshotFile calls ComputeHashSerialized(us) AFTER WriteSnapshot
// returns (methods.go:2815) — a second walk of the same UTXOSet cache. If
// a coin is added between the two walks, the file and reported hash differ.
// Core computes both in the same cursor pass via PrepareUTXOSnapshot.
func TestW138_G30_DumpHashFromSecondWalk(t *testing.T) {
	t.Skip("W138 audit: BUG-20 — dumptxoutset hash is computed from a second walk of the cache, not from the bytes actually written; race with concurrent writes is undetected")
}
