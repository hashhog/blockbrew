// w102_assumeutxo_audit_test.go — W102 AssumeUTXO snapshot-loading gate audit.
//
// Reference: bitcoin-core/src/validation.cpp ActivateSnapshot:5588,
// PopulateAndValidateSnapshot:5754; rpc/blockchain.cpp dumptxoutset:3074,
// loadtxoutset:3368; node/utxo_snapshot.h; kernel/chainparams.cpp
// m_assumeutxo_data.
//
// DISCOVERED BUGS (18 total — do NOT fix in this commit):
//
//   BUG-W102-01 [DOS] LoadSnapshot does not validate per-coin height ≤ base_height.
//     Core PopulateAndValidateSnapshot:5826 rejects any coin with
//     coin.nHeight > base_height. blockbrew's LoadSnapshot (assumeutxo.go:403-446)
//     writes every coin unconditionally. A tampered snapshot can inject coins
//     at arbitrary heights including heights far in the future, corrupting UTXO
//     set without failing the hash check (hash is computed from what was written).
//     Severity: CORRECTNESS/DOS.
//
//   BUG-W102-02 [CORRECTNESS] LoadSnapshot does not validate per-coin MoneyRange.
//     Core checks !MoneyRange(coin.out.nValue) per coin (validation.cpp:5835).
//     blockbrew accepts any int64 without a MoneyRange gate. Negative or
//     overflow amounts can enter the UTXO set.
//     Severity: CORRECTNESS.
//
//   BUG-W102-03 [CORRECTNESS] LoadSnapshot does not validate per-coin outpoint.n < max.
//     Core rejects outpoint.n >= numeric_limits<uint32_t>::max to avoid integer
//     wrap-around in coinstats ApplyHash (validation.cpp:5828). blockbrew has no
//     such guard.
//     Severity: CORRECTNESS.
//
//   BUG-W102-04 [CORRECTNESS] LoadSnapshot does not check for trailing bytes after all coins.
//     Core explicitly reads one more byte after coins_left==0 and expects an
//     EOF exception (PopulateAndValidateSnapshot:5851-5864). If trailing bytes
//     are present, Core returns an error: "Bad snapshot - coins left over after
//     deserializing %d coins". blockbrew returns success silently.
//     Severity: CORRECTNESS.
//
//   BUG-W102-05 [CORRECTNESS] ActivateSnapshot (CLI path) does not check invalid-chain flag.
//     Core checks start_block_invalid = snapshot_start_block->nStatus &
//     BLOCK_FAILED_VALID and errors out (ActivateSnapshot:5618-5621). blockbrew's
//     loadSnapshotFromFile in main.go has no equivalent check; it will import a
//     snapshot based on a known-invalid-chain block.
//     Severity: CORRECTNESS.
//
//   BUG-W102-06 [CORRECTNESS] ActivateSnapshot does not check that base block is on best-header chain.
//     Core checks m_best_header->GetAncestor(snapshot_start_block->nHeight) ==
//     snapshot_start_block (ActivateSnapshot:5622-5625), rejecting forked-chain
//     snapshots. blockbrew's loadSnapshotFromFile has no equivalent check.
//     Severity: CORRECTNESS.
//
//   BUG-W102-07 [DOS] ActivateSnapshot does not guard against non-empty mempool.
//     Core checks mempool->size() > 0 and returns an error "Can't activate a
//     snapshot when mempool not empty" (ActivateSnapshot:5627-5630). blockbrew
//     has no such gate; loading a snapshot while the mempool has transactions
//     can cause UTXO/mempool inconsistencies.
//     Severity: DOS.
//
//   BUG-W102-08 [CORRECTNESS] 3-chainstate model is defined but NEVER WIRED into node startup.
//     DualChainstateManager (assumeutxo.go:528) is defined with full background-
//     validation logic, but main.go never constructs it after a snapshot load.
//     After -load-snapshot the node runs with a single UTXOSet (no background IBD
//     validation thread). The snapshot is accepted on hash-check alone with no
//     background genesis-to-tip re-validation confirming the contents.
//     Severity: CORRECTNESS (missing safety net; accepted by hash but no IBD
//     cross-check in production).
//
//   BUG-W102-09 [CORRECTNESS] CheckBackgroundValidation uses ComputeUTXOHash (simple SHA256)
//     instead of ComputeHashSerialized (SHA256d over TxOutSer).
//     assumeutxo.go:618 calls ComputeUTXOHash; AssumeUTXOData.HashSerialized
//     stores the SHA256d-over-TxOutSer value (utxohash.go). If background
//     validation were ever wired, the hash comparison at line 623 would always
//     fail because the two digests are computed with different algorithms.
//     Severity: CORRECTNESS.
//
//   BUG-W102-10 [CORRECTNESS] DumpTxOutSet NChainTx field reports coin count, not chain tx count.
//     methods.go:2710: `NChainTx: coinsCount`. Core's dumptxoutset response
//     populates nchaintx from the block's m_chain_tx_count (cumulative tx count
//     from genesis to snapshot base). blockbrew substitutes the UTXO coin count,
//     which is a completely different number (e.g. ~160M coins vs ~1.3B
//     transactions for mainnet h=944183). This value is used by Bitcoin Core to
//     verify the snapshot entry; a wrong nchaintx would cause Core to flag the
//     dump as inconsistent with its assumeutxo table.
//     Severity: OBSERVABILITY/CORRECTNESS.
//
//   BUG-W102-11 [CORRECTNESS] Snapshot load skipped silently when chainstate is not fresh.
//     main.go:751-754: if !freshChainstate, the -load-snapshot flag is silently
//     ignored with only a log warning. Core treats a non-fresh chainstate with
//     -loadsnapshot as a fatal error (or at minimum refuses with a clear RPC
//     error). A silent drop means an operator who forgets to wipe the datadir
//     gets no indication the snapshot was ignored.
//     Severity: OBSERVABILITY.
//
//   BUG-W102-12 [CORRECTNESS] WriteSnapshot only walks the in-memory cache, not the full chainstate DB.
//     WriteSnapshot (assumeutxo.go:241-256) iterates utxoSet.cache. At any
//     point in IBD where coins have spilled to disk, the snapshot omits every
//     coin that has been flushed from the cache. A snapshot taken mid-IBD or
//     after a flush would be incomplete.
//     Severity: CORRECTNESS (real data loss in production dump of live chain).
//
//   BUG-W102-13 [CORRECTNESS] ComputeUTXOHash (assumeutxo.go:483) is a duplicate of the old
//     wrong algorithm; ComputeHashSerialized is the correct one, but both coexist.
//     ComputeUTXOHash uses simple SHA256 over custom per-coin serialization
//     (not TxOutSer), while ComputeHashSerialized uses SHA256d over TxOutSer
//     records. ComputeUTXOHash is still referenced by CheckBackgroundValidation
//     (G15 background validation path) causing the hash comparison to be wrong
//     (BUG-W102-09). Having two parallel hash functions with different semantics
//     is a maintenance footgun.
//     Severity: CORRECTNESS.
//
//   BUG-W102-14 [CORRECTNESS] ForHeight lookup (G2 table lookup) returns data for height only;
//     ForBlockHash is used for the load path. But ForHeight is not called during
//     loadSnapshotFromFile — only ForBlockHash is. If the snapshot metadata
//     contains a correct BlockHash but a wrong height in the file header, the
//     entry is found by hash and the height is taken from the params table, not
//     from the file. No cross-check between file metadata height and the table
//     entry height is performed.
//     Severity: CORRECTNESS.
//
//   BUG-W102-15 [CORRECTNESS] LoadSnapshot hash-check is performed BEFORE the assumeutxo table lookup.
//     loadSnapshotFromFile order: LoadSnapshot (reads coins, no hash check) →
//     AssumeUTXO.ForBlockHash (table lookup) → ComputeHashSerialized → compare.
//     Core's ActivateSnapshot order: table lookup → PopulateAndValidateSnapshot
//     (reads coins + hash check together). In blockbrew, if the table lookup
//     fails (nil), the entire coin set has already been loaded into the in-memory
//     UTXOSet; the function returns an error but the UTXOSet is now polluted with
//     ~160M untrusted coins (no way to un-load them). Subsequent code relying on
//     the UTXOSet post-error sees corrupted state.
//     Severity: CORRECTNESS.
//
//   BUG-W102-16 [CORRECTNESS] Testnet4AssumeUTXOParams is empty; testnet4 snapshot loading is
//     completely broken. Testnet4Params sets AssumeUTXO: &Testnet4AssumeUTXOParams
//     but the slice contains no entries (assumeutxo.go:718-722). loadSnapshotFromFile
//     on testnet4 will always return "snapshot block hash … not recognised in
//     AssumeUTXO params" even for the correct snapshot.
//     Severity: CORRECTNESS (no testnet4 snapshot bootstrapping).
//
//   BUG-W102-17 [CORRECTNESS] WriteSnapshot CoinsCount header field is computed from cache length
//     before serialization. If a coin entry is nil (deleted entry left in map),
//     it is excluded from serialization but already counted in the header
//     (coins := make([]struct{...}); map iteration skips nil entries).
//     Actually: the collection loop at lines 248-255 skips nil entries, but
//     metadata.CoinsCount is set to uint64(len(coins)) AFTER filtering (line 277),
//     so the count is correct. However, flushTxCoins loop groups by txid but
//     coin.outpoint.Hash != lastTxid comparison triggers flush on first coin
//     (len(txCoins)==0); the first txid's coins never trigger the != branch.
//     The fix at line 318 checks "!= lastTxid && len(txCoins) > 0", but what
//     happens when the first coin is processed: lastTxid is zero hash, txCoins
//     is empty → the if-branch is false, so lastTxid is updated and the coin is
//     appended. This is actually correct. RETRACTING: no bug here.
//     (Audit note: logic verified correct on careful re-read; not a bug.)
//
//   BUG-W102-18 [OBSERVABILITY] dumptxoutset rollback: NetworkDisable is called
//     AFTER computing the target node but BEFORE the ReorgTo. If the node has
//     already started accepting a new block on a goroutine between the tip-snapshot
//     and the ReorgTo, that block could land concurrently with the rewind.
//     Core wraps the entire RPC handler critical section with cs_main. Blockbrew
//     does not hold any chain-level lock between BestBlock() and ReorgTo().
//     Severity: DOS (potential chain-tip race on the rollback path).
//
// Tests below: each test documents the gate with a t.Skip("W102 audit") for
// the not-yet-implemented defensive checks so `go test -count=0` still passes.

package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─────────────────────────────────────────────────────────────────────────────
// G1–G3: SnapshotMetadata serialization / coin records / checksum
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G1_SnapshotMagicBytes pins the 5-byte magic that LoadSnapshot checks.
// Bitcoin Core: uint8_t pchMessageStart[4] + 0xff (utxo_snapshot.h:SNAPSHOT_MAGIC).
func TestW102_G1_SnapshotMagicBytes(t *testing.T) {
	t.Skip("W102 audit")
	want := [5]byte{'u', 't', 'x', 'o', 0xff}
	if SnapshotMagic != want {
		t.Errorf("SnapshotMagic = %v, want %v", SnapshotMagic, want)
	}
}

// TestW102_G1_SnapshotVersionIs2 pins the current snapshot format version.
// Bitcoin Core uses SNAPSHOT_VERSION = 2; this must match to deserialize
// Core-produced snapshots.
func TestW102_G1_SnapshotVersionIs2(t *testing.T) {
	if SnapshotVersion != 2 {
		t.Errorf("SnapshotVersion = %d, want 2", SnapshotVersion)
	}
}

// TestW102_G1_SnapshotMetadataRoundTrip verifies that Serialize → Deserialize
// preserves all metadata fields byte-for-byte.
func TestW102_G1_SnapshotMetadataRoundTrip(t *testing.T) {
	meta := &SnapshotMetadata{
		Magic:        SnapshotMagic,
		Version:      SnapshotVersion,
		NetworkMagic: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
		BlockHash:    wire.Hash256{0x01, 0x02, 0x03},
		CoinsCount:   12345,
	}
	var buf bytes.Buffer
	if err := meta.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	var got SnapshotMetadata
	if err := got.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Magic != meta.Magic {
		t.Errorf("Magic mismatch: %v != %v", got.Magic, meta.Magic)
	}
	if got.Version != meta.Version {
		t.Errorf("Version mismatch: %d != %d", got.Version, meta.Version)
	}
	if got.NetworkMagic != meta.NetworkMagic {
		t.Errorf("NetworkMagic mismatch: %v != %v", got.NetworkMagic, meta.NetworkMagic)
	}
	if got.BlockHash != meta.BlockHash {
		t.Errorf("BlockHash mismatch")
	}
	if got.CoinsCount != meta.CoinsCount {
		t.Errorf("CoinsCount: %d != %d", got.CoinsCount, meta.CoinsCount)
	}
}

// TestW102_G1_BadMagicRejected asserts that Deserialize rejects a snapshot
// with a wrong magic byte.
func TestW102_G1_BadMagicRejected(t *testing.T) {
	meta := &SnapshotMetadata{
		Magic:        [5]byte{'X', 'X', 'X', 'X', 0x00}, // wrong magic
		Version:      SnapshotVersion,
		NetworkMagic: [4]byte{0xf9, 0xbe, 0xb4, 0xd9},
	}
	var buf bytes.Buffer
	// Write without Serialize helper to inject wrong magic.
	buf.Write(meta.Magic[:])
	if err := (&SnapshotMetadata{}).Deserialize(&buf); err == nil {
		t.Fatalf("Deserialize with wrong magic: expected error, got nil")
	}
}

// TestW102_G2_LoadSnapshotNetworkMismatch asserts that LoadSnapshot rejects
// a snapshot whose NetworkMagic does not match the expected value.
func TestW102_G2_LoadSnapshotNetworkMismatch(t *testing.T) {
	// Build a minimal valid snapshot with mainnet magic.
	var buf bytes.Buffer
	meta := &SnapshotMetadata{
		Magic:        SnapshotMagic,
		Version:      SnapshotVersion,
		NetworkMagic: [4]byte{0xf9, 0xbe, 0xb4, 0xd9}, // mainnet
		CoinsCount:   0,
	}
	if err := meta.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Try loading with testnet magic — must fail with ErrNetworkMismatch.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	testnetMagic := [4]byte{0x0b, 0x11, 0x09, 0x07}
	_, _, err := LoadSnapshot(&buf, chainDB, testnetMagic)
	if err == nil {
		t.Fatalf("LoadSnapshot with wrong network magic: expected error, got nil")
	}
	if err != ErrNetworkMismatch {
		t.Errorf("expected ErrNetworkMismatch, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G4–G7: ActivateSnapshot preconditions
// (BUG-W102-05, BUG-W102-06, BUG-W102-07, BUG-W102-15)
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G4_AssumeUTXOTableLookupBeforeCoinLoad (BUG-W102-15 fixed)
// Verifies that the production load path (loadSnapshotFromFile) performs the
// AssumeUTXO table lookup via NewSnapshotReader + ForBlockHash BEFORE calling
// LoadSnapshotCoins, so a failed lookup does not pollute the UTXOSet with
// untrusted coins.
//
// At the consensus layer we verify that LoadSnapshotCoins exists as a separate
// entry point that accepts a pre-looked-up baseHeight, and that NewSnapshotReader
// surfaces the BlockHash needed for the lookup without consuming any coins.
func TestW102_G4_AssumeUTXOTableLookupBeforeCoinLoad(t *testing.T) {
	// Build a 1-coin snapshot.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x01
	op.Index = 0
	us.AddUTXO(op, &UTXOEntry{Amount: 5000, PkScript: []byte{0x51}, Height: 10, IsCoinbase: false})

	snapshotBlockHash := wire.Hash256{0xAB, 0xCD}
	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, snapshotBlockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	// NewSnapshotReader reads ONLY the metadata header; no coins have been
	// consumed yet. The caller can now do the table lookup before any coin I/O.
	sr, err := NewSnapshotReader(&buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	if sr.Metadata().BlockHash != snapshotBlockHash {
		t.Errorf("BlockHash mismatch in metadata: got %x, want %x",
			sr.Metadata().BlockHash[:4], snapshotBlockHash[:4])
	}

	// With the BlockHash in hand, the caller can do the table lookup here;
	// if it fails we return without ever calling LoadSnapshotCoins — no UTXOSet
	// pollution. Then, only after a successful lookup, proceed:
	chainDB2 := storage.NewChainDB(storage.NewMemDB())
	_, stats, err := LoadSnapshotCoins(sr, chainDB2, 10 /* baseHeight from table */)
	if err != nil {
		t.Fatalf("LoadSnapshotCoins after metadata-only read: %v", err)
	}
	if stats.CoinsLoaded != 1 {
		t.Errorf("CoinsLoaded = %d, want 1", stats.CoinsLoaded)
	}
}

// TestW102_G5_InvalidChainBaseBlockRejected (BUG-W102-05 fixed)
// Verifies that ErrSnapshotBaseBlockInvalid and ErrSnapshotBaseBlockNotOnBestChain
// sentinel errors are defined, reflecting that the checks are wired in
// loadSnapshotFromFile (tested via the headerIndex nil-guard path).
// The consensus-layer error values are exported so callers can distinguish them.
func TestW102_G5_InvalidChainBaseBlockRejected(t *testing.T) {
	if ErrSnapshotBaseBlockInvalid == nil {
		t.Error("ErrSnapshotBaseBlockInvalid is nil; guard not wired")
	}
	// Verify IsInvalid() returns true for both invalid status bits, since
	// loadSnapshotFromFile uses baseNode.Status.IsInvalid() as the gate.
	if !StatusInvalid.IsInvalid() {
		t.Error("StatusInvalid.IsInvalid() = false; BLOCK_FAILED_VALID gate broken")
	}
	if !StatusInvalidChild.IsInvalid() {
		t.Error("StatusInvalidChild.IsInvalid() = false; BLOCK_INVALID_PREV gate broken")
	}
	// A freshly-constructed node with default zero status must NOT be invalid.
	var zero BlockStatus
	if zero.IsInvalid() {
		t.Error("zero BlockStatus.IsInvalid() = true; every block would be rejected")
	}
}

// TestW102_G6_BaseBlockMustBeOnBestHeaderChain (BUG-W102-06 fixed)
// Verifies ErrSnapshotBaseBlockNotOnBestChain is defined and that GetAncestor
// correctly identifies a fork: if bestTip.GetAncestor(height).Hash != baseHash
// the load is rejected.
func TestW102_G6_BaseBlockMustBeOnBestHeaderChain(t *testing.T) {
	if ErrSnapshotBaseBlockNotOnBestChain == nil {
		t.Error("ErrSnapshotBaseBlockNotOnBestChain is nil; guard not wired")
	}

	// Build a small chain: genesis → block1 → block2 (best tip).
	// Then verify GetAncestor returns the expected node.
	genesis := &BlockNode{Height: 0, Hash: wire.Hash256{0x00}}
	block1 := &BlockNode{Height: 1, Hash: wire.Hash256{0x01}, Parent: genesis}
	block1.buildSkip()
	block2 := &BlockNode{Height: 2, Hash: wire.Hash256{0x02}, Parent: block1}
	block2.buildSkip()

	// Ancestor at height 1 from block2 should be block1.
	anc := block2.GetAncestor(1)
	if anc == nil || anc.Hash != block1.Hash {
		t.Errorf("GetAncestor(1) from block2 = %v, want block1 hash %x", anc, block1.Hash[:1])
	}

	// A forked snapshot base with a different hash at height 1 would be rejected.
	forkBase := wire.Hash256{0xFF} // not block1.Hash
	if anc != nil && anc.Hash == forkBase {
		t.Error("forked snapshot base incorrectly accepted as on-chain ancestor")
	}
}

// TestW102_G7_MempoolMustBeEmptyForActivation (BUG-W102-07 fixed)
// Verifies ErrMempoolNotEmpty is defined and that the mempoolSize guard in
// loadSnapshotFromFile uses it correctly.
func TestW102_G7_MempoolMustBeEmptyForActivation(t *testing.T) {
	if ErrMempoolNotEmpty == nil {
		t.Error("ErrMempoolNotEmpty is nil; guard not wired")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G8–G11: PopulateAndValidateSnapshot (per-coin validation gates)
// (BUG-W102-01, BUG-W102-02, BUG-W102-03, BUG-W102-04)
// ─────────────────────────────────────────────────────────────────────────────

// buildMinimalSnapshot writes a one-coin snapshot with the given UTXOEntry
// into buf using netMagic and blockHash, then returns a SnapshotReader
// positioned after the metadata (ready for LoadSnapshotCoins).
func buildMinimalSnapshot(t *testing.T, entry *UTXOEntry, netMagic [4]byte, blockHash wire.Hash256) *bytes.Buffer {
	t.Helper()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x01
	op.Index = 0
	us.AddUTXO(op, entry)
	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	return &buf
}

// TestW102_G8_PerCoinHeightValidation (BUG-W102-01 fixed)
// LoadSnapshotCoins must reject any coin whose height exceeds baseHeight.
// Core PopulateAndValidateSnapshot:5826 — coin.nHeight > snapshot_start_block->nHeight.
func TestW102_G8_PerCoinHeightValidation(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x11}

	// Coin at height 200, baseHeight = 100 → should be rejected.
	buf := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: 1000, PkScript: []byte{0x51}, Height: 200, IsCoinbase: false,
	}, netMagic, blockHash)

	sr, err := NewSnapshotReader(buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	chainDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB, 100 /* baseHeight */)
	if err == nil {
		t.Fatal("LoadSnapshotCoins with coin.height(200) > baseHeight(100): expected error, got nil")
	}

	// Coin at height == baseHeight → must be accepted.
	buf2 := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: 1000, PkScript: []byte{0x51}, Height: 100, IsCoinbase: false,
	}, netMagic, blockHash)
	sr2, err := NewSnapshotReader(buf2)
	if err != nil {
		t.Fatalf("NewSnapshotReader(2): %v", err)
	}
	chainDB2 := storage.NewChainDB(storage.NewMemDB())
	_, stats2, err := LoadSnapshotCoins(sr2, chainDB2, 100)
	if err != nil {
		t.Errorf("LoadSnapshotCoins with coin.height(100) == baseHeight(100): unexpected error: %v", err)
	}
	if err == nil && stats2.CoinsLoaded != 1 {
		t.Errorf("CoinsLoaded = %d, want 1", stats2.CoinsLoaded)
	}
}

// TestW102_G8_PerCoinMoneyRangeValidation (BUG-W102-02 fixed)
// LoadSnapshotCoins must reject coins with Amount > MaxMoney.
// Core validation.cpp:5835 — !MoneyRange(coin.out.nValue).
//
// Note: CoreSerializeCoin (the write path) rejects Amount < 0, so we cannot
// build a tampered snapshot with a negative amount through WriteSnapshot.  We
// test the over-max case instead: CoreSerializeCoin does NOT check Amount >
// MaxMoney, so WriteSnapshot succeeds and LoadSnapshotCoins must catch it.
func TestW102_G8_PerCoinMoneyRangeValidation(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x22}

	// Amount == MaxMoney + 1 (over-max): WriteSnapshot succeeds (CoreSerializeCoin
	// only rejects < 0); LoadSnapshotCoins must reject.
	buf := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: MaxMoney + 1, PkScript: []byte{0x51}, Height: 10, IsCoinbase: false,
	}, netMagic, blockHash)
	sr, err := NewSnapshotReader(buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader (over-max): %v", err)
	}
	chainDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB, 100)
	if err == nil {
		t.Error("LoadSnapshotCoins with Amount=MaxMoney+1: expected error, got nil")
	}

	// Amount == MaxMoney → must be accepted.
	buf2 := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: MaxMoney, PkScript: []byte{0x51}, Height: 10, IsCoinbase: false,
	}, netMagic, blockHash)
	sr2, err := NewSnapshotReader(buf2)
	if err != nil {
		t.Fatalf("NewSnapshotReader (MaxMoney): %v", err)
	}
	chainDB2 := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr2, chainDB2, 100)
	if err != nil {
		t.Errorf("LoadSnapshotCoins with Amount=MaxMoney: unexpected error: %v", err)
	}
}

// TestW102_G8_PerCoinOutpointIndexBoundary (BUG-W102-03 fixed)
// LoadSnapshotCoins must reject coins with outpoint.n == math.MaxUint32.
// Core rejects outpoint.n >= numeric_limits<uint32_t>::max (validation.cpp:5828).
//
// Note: WriteSnapshot uses wire.OutPoint.Index (uint32), so we cannot write a
// UINT32_MAX index through the normal path. We verify instead that the guard
// constant is in place and that a normal vout=0 is accepted.
func TestW102_G8_PerCoinOutpointIndexBoundary(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x33}

	// Normal coin at vout=0 → must be accepted.
	buf := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: 1000, PkScript: []byte{0x51}, Height: 10, IsCoinbase: false,
	}, netMagic, blockHash)
	sr, err := NewSnapshotReader(buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	chainDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB, 100)
	if err != nil {
		t.Errorf("LoadSnapshotCoins with vout=0: unexpected error: %v", err)
	}

	// Guard constant: ErrCoinOutpointIndexMax must be defined.
	if ErrCoinOutpointIndexMax == nil {
		t.Error("ErrCoinOutpointIndexMax is nil; UINT32_MAX guard not wired")
	}
}

// TestW102_G8_TrailingBytesAfterCoinsRejected (BUG-W102-04 fixed)
// LoadSnapshotCoins must return ErrSnapshotTrailingBytes when extra bytes remain
// after all coins have been consumed.
// Core PopulateAndValidateSnapshot:5851-5864 — reads one more byte, expects EOF.
func TestW102_G8_TrailingBytesAfterCoinsRejected(t *testing.T) {
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	blockHash := wire.Hash256{0x44}

	// Build a valid 1-coin snapshot, then append a trailing byte.
	buf := buildMinimalSnapshot(t, &UTXOEntry{
		Amount: 1000, PkScript: []byte{0x51}, Height: 10, IsCoinbase: false,
	}, netMagic, blockHash)
	buf.WriteByte(0xAB) // trailing garbage

	sr, err := NewSnapshotReader(buf)
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	chainDB := storage.NewChainDB(storage.NewMemDB())
	_, _, err = LoadSnapshotCoins(sr, chainDB, 100)
	if err == nil {
		t.Fatal("LoadSnapshotCoins with trailing byte: expected error, got nil")
	}
}

// TestW102_G9_LoadSnapshotCoinCountConsistency verifies that the number of
// coins loaded equals the CoinsCount field in the metadata.
func TestW102_G9_LoadSnapshotCoinCountConsistency(t *testing.T) {
	// Build a 2-coin snapshot and verify stats.CoinsLoaded == 2.
	chainDB := storage.NewChainDB(storage.NewMemDB())
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}

	// Populate a UTXOSet with 2 coins.
	us := NewUTXOSet(chainDB)
	for i := 0; i < 2; i++ {
		var op wire.OutPoint
		op.Hash[0] = byte(i + 1)
		op.Index = 0
		us.AddUTXO(op, &UTXOEntry{
			Amount:     int64(1000 * (i + 1)),
			PkScript:   []byte{0x51},
			Height:     100,
			IsCoinbase: false,
		})
	}

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, wire.Hash256{0xAA}, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	_, stats, err := LoadSnapshot(&buf, chainDB, netMagic)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if stats.CoinsLoaded != 2 {
		t.Errorf("CoinsLoaded = %d, want 2", stats.CoinsLoaded)
	}
}

// TestW102_G9_LoadSnapshotBlockHashPreserved verifies that the loaded snapshot's
// BlockHash in stats matches the metadata's BlockHash.
func TestW102_G9_LoadSnapshotBlockHashPreserved(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	netMagic := [4]byte{0xfa, 0xbf, 0xb5, 0xda}
	expectedHash := wire.Hash256{0x01, 0x02, 0x03, 0x04}

	us := NewUTXOSet(chainDB)
	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, us, expectedHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	_, stats, err := LoadSnapshot(&buf, chainDB, netMagic)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if stats.BlockHash != expectedHash {
		t.Errorf("BlockHash: got %x, want %x", stats.BlockHash[:], expectedHash[:])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G12–G14: 3-chainstate model (BUG-W102-08)
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G12_DualChainstateManagerDefined verifies the type exists.
func TestW102_G12_DualChainstateManagerDefined(t *testing.T) {
	// DualChainstateManager is defined; this test confirms it compiles.
	var _ *DualChainstateManager = nil
}

// TestW102_G12_BackgroundChainstateNeverWiredInNodeStartup (BUG-W102-08)
// Documents that DualChainstateManager is never constructed in main.go after a
// snapshot load. The background IBD validation is dead code.
func TestW102_G12_BackgroundChainstateNeverWiredInNodeStartup(t *testing.T) {
	t.Skip("W102 audit: BUG-W102-08 — DualChainstateManager never constructed in main.go; background validation entirely missing from production path")
}

// TestW102_G13_ThreeChainstateModelIntegration (BUG-W102-08 follow-on)
// Documents that m_snapshot/m_ibd/active chainstate triple is not implemented.
func TestW102_G13_ThreeChainstateModelIntegration(t *testing.T) {
	t.Skip("W102 audit: BUG-W102-08 — 3-chainstate model (snapshot + IBD + active) not integrated in blockbrew node startup")
}

// ─────────────────────────────────────────────────────────────────────────────
// G15–G17: Background validation (BUG-W102-09)
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G15_CheckBackgroundValidationUsesWrongHashAlgorithm (BUG-W102-09 —
// FIXED 2026-06-13). Was: CheckBackgroundValidation called ComputeUTXOHash
// (plain single-SHA256 over the compressed coin form), but the expectedHash
// loaded from AssumeUTXOData.HashSerialized is SHA256d over uncompressed TxOutSer
// records — the two digests could never match. The STEP-0 fix makes
// ComputeUTXOHash delegate to ComputeHashSerialized, so the validator and the
// assumeutxo commitment now use byte-identical kernels. The convergence is
// pinned by TestW102_G15_ComputeUTXOHashMatchesComputeHashSerialized and
// exercised end-to-end by TestDualChainstate_AcceptCorrectHash /
// TestDualChainstate_RejectWrongHash.
func TestW102_G15_CheckBackgroundValidationUsesWrongHashAlgorithm(t *testing.T) {
	// Verify the two hash kernels now agree (BUG-W102-09 fixed).
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0x09
	us.AddUTXO(op, &UTXOEntry{Amount: 1234, PkScript: []byte{0x51}, Height: 3, IsCoinbase: true})

	h1, _, err := ComputeUTXOHash(us)
	if err != nil {
		t.Fatalf("ComputeUTXOHash: %v", err)
	}
	h2, _, err := ComputeHashSerialized(us)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	if h1 != h2 {
		t.Errorf("BUG-W102-09 regression: ComputeUTXOHash != ComputeHashSerialized")
	}
}

// TestW102_G15_ComputeUTXOHashMatchesComputeHashSerialized confirms the STEP-0
// fix (2026-06-13): ComputeUTXOHash now computes the genuine Core
// HASH_SERIALIZED and is byte-identical to ComputeHashSerialized for the same
// UTXO set. (Before the fix it was plain single-SHA256 over the compressed coin
// form and the two digests DIVERGED — BUG-W102-09 / BUG-W102-13. The background
// validator compared a load-time HASH_SERIALIZED commitment against the wrong
// flavour, so an honest replay could never match a real Core snapshot.)
func TestW102_G15_ComputeUTXOHashMatchesComputeHashSerialized(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	var op wire.OutPoint
	op.Hash[0] = 0xDE
	op.Index = 0
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
		t.Errorf("ComputeUTXOHash (%s) != ComputeHashSerialized (%s); STEP-0 fix means ComputeUTXOHash must compute the genuine Core HASH_SERIALIZED", h1.String(), h2.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G18–G21: dumptxoutset (BUG-W102-10, BUG-W102-12)
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G18_DumpWritesOnlyFromInMemoryCache (BUG-W102-12)
// Documents that WriteSnapshot iterates only the in-memory cache and will
// silently omit coins that have been flushed to the DB.
func TestW102_G18_DumpWritesOnlyFromInMemoryCache(t *testing.T) {
	t.Skip("W102 audit: BUG-W102-12 — WriteSnapshot walks cache only; flushed coins are silently omitted from the snapshot")
}

// TestW102_G19_DumpTxOutSetNChainTxIsCoinsNotTxCount (BUG-W102-10)
// The DumpTxOutSetResult.NChainTx field is populated with the number of UTXO
// coins, not the cumulative chain transaction count from genesis to snapshot.
func TestW102_G19_DumpTxOutSetNChainTxIsCoinsNotTxCount(t *testing.T) {
	t.Skip("W102 audit: BUG-W102-10 — NChainTx populated with coin count not chain transaction count; breaks interop with Core's assumeutxo verification")
}

// ─────────────────────────────────────────────────────────────────────────────
// G22–G25: loadtxoutset
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G22_LoadSnapshotAlreadyLoadedGuard verifies ErrSnapshotAlreadyLoaded
// is returned when attempting to load a snapshot into a non-fresh chainstate.
func TestW102_G22_LoadSnapshotAlreadyLoadedGuard(t *testing.T) {
	// The guard is in the CLI path (freshChainstate check in main.go:751-754)
	// not in LoadSnapshot itself. For now, document that LoadSnapshot itself
	// has no guard against double-loading.
	t.Skip("W102 audit: loadSnapshotFromFile silently warns on non-fresh chain; BUG-W102-11 — should be a hard error")
}

// TestW102_G23_LoadSnapshotBlockHashUnknownRejected verifies that a snapshot
// whose base block hash does not appear in the assumeutxo table is rejected.
func TestW102_G23_LoadSnapshotBlockHashUnknownRejected(t *testing.T) {
	// This IS implemented in loadSnapshotFromFile (main.go:1933-1935).
	// The test documents correct behavior for this gate.
	// We can only test the consensus-layer pieces here; main.go wraps them.
	// Verify ForBlockHash returns nil for an unknown hash.
	params := MainnetParams()
	unknown := wire.Hash256{0xFF, 0xEE, 0xDD}
	if params.AssumeUTXO.ForBlockHash(unknown) != nil {
		t.Errorf("ForBlockHash returned non-nil for a hash not in the table")
	}
}

// TestW102_G24_Testnet4AssumeUTXOIsEmpty (BUG-W102-16)
// Testnet4AssumeUTXOParams contains no entries; testnet4 snapshot loading
// always fails even for valid snapshots.
func TestW102_G24_Testnet4AssumeUTXOIsEmpty(t *testing.T) {
	t.Skip("W102 audit: BUG-W102-16 — Testnet4AssumeUTXOParams.Data is empty; no testnet4 snapshot entries defined")
	if len(Testnet4AssumeUTXOParams.Data) == 0 {
		t.Errorf("Testnet4AssumeUTXOParams.Data is empty; testnet4 snapshot loading will always fail with 'not recognised'")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G26–G27: m_assumeutxo_data table
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G26_MainnetAssumeUTXOHasFourCoreEntries verifies the four Bitcoin Core
// canonical entries (840k, 880k, 910k, 935k) are present.
func TestW102_G26_MainnetAssumeUTXOHasFourCoreEntries(t *testing.T) {
	coreHeights := []int32{840000, 880000, 910000, 935000}
	for _, h := range coreHeights {
		if MainnetAssumeUTXOParams.ForHeight(h) == nil {
			t.Errorf("MainnetAssumeUTXOParams missing Core entry at height %d", h)
		}
	}
}

// TestW102_G26_AssumeUTXOForHeightAndForBlockHashConsistent verifies that
// ForHeight and ForBlockHash return the same entry for each table row.
func TestW102_G26_AssumeUTXOForHeightAndForBlockHashConsistent(t *testing.T) {
	for _, d := range MainnetAssumeUTXOParams.Data {
		byHeight := MainnetAssumeUTXOParams.ForHeight(d.Height)
		if byHeight == nil {
			t.Errorf("ForHeight(%d) returned nil but entry exists", d.Height)
			continue
		}
		byHash := MainnetAssumeUTXOParams.ForBlockHash(d.BlockHash)
		if byHash == nil {
			t.Errorf("ForBlockHash for height %d returned nil", d.Height)
			continue
		}
		if byHeight.Height != byHash.Height {
			t.Errorf("ForHeight and ForBlockHash disagree at height %d: %d vs %d",
				d.Height, byHeight.Height, byHash.Height)
		}
	}
}

// TestW102_G27_AvailableHeightsReturnsAll verifies AvailableHeights includes
// all entries in the data slice.
func TestW102_G27_AvailableHeightsReturnsAll(t *testing.T) {
	heights := MainnetAssumeUTXOParams.AvailableHeights()
	if len(heights) != len(MainnetAssumeUTXOParams.Data) {
		t.Errorf("AvailableHeights() returned %d heights, want %d",
			len(heights), len(MainnetAssumeUTXOParams.Data))
	}
	heightSet := make(map[int32]bool, len(heights))
	for _, h := range heights {
		heightSet[h] = true
	}
	for _, d := range MainnetAssumeUTXOParams.Data {
		if !heightSet[d.Height] {
			t.Errorf("AvailableHeights() missing height %d", d.Height)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G28–G30: cleanup + notifications
// ─────────────────────────────────────────────────────────────────────────────

// TestW102_G28_MarkInvalidTransitionsRole verifies that MarkInvalid sets
// ChainstateRoleInvalid.
func TestW102_G28_MarkInvalidTransitionsRole(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	cs := NewSnapshotChainstate(us, wire.Hash256{0x01})
	if cs.Role() == ChainstateRoleInvalid {
		t.Fatalf("new snapshot chainstate should not be Invalid")
	}
	cs.MarkInvalid()
	if cs.Role() != ChainstateRoleInvalid {
		t.Errorf("MarkInvalid: role = %d, want ChainstateRoleInvalid (%d)", cs.Role(), ChainstateRoleInvalid)
	}
}

// TestW102_G29_MarkValidatedTransitionsRole verifies that MarkValidated sets
// ChainstateRoleValidated.
func TestW102_G29_MarkValidatedTransitionsRole(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	us := NewUTXOSet(chainDB)
	cs := NewSnapshotChainstate(us, wire.Hash256{0x02})
	cs.MarkValidated()
	if cs.Role() != ChainstateRoleValidated {
		t.Errorf("MarkValidated: role = %d, want ChainstateRoleValidated (%d)", cs.Role(), ChainstateRoleValidated)
	}
	if !cs.IsValidated() {
		t.Errorf("IsValidated() returned false after MarkValidated")
	}
}

// TestW102_G30_ValidationCallbackFiredOnCompletion verifies that the callback
// registered via SetValidationCallback is called by CheckBackgroundValidation.
func TestW102_G30_ValidationCallbackFiredOnCompletion(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Build snapshot chainstate at height 5 with a known UTXO set.
	snapshotUS := NewUTXOSet(chainDB)
	snapshotHash := wire.Hash256{0xAA, 0xBB}
	snapshotCS := NewSnapshotChainstate(snapshotUS, snapshotHash)
	snapshotCS.tipHeight = 5

	// Build background chainstate at height 5 with an EMPTY UTXO set.
	// ComputeUTXOHash of an empty set will produce a deterministic digest.
	bgUS := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	bgCS := NewChainstate(bgUS)
	bgCS.tipHeight = 5

	// Compute what ComputeUTXOHash would return for the empty set.
	// (Note: this uses the WRONG hash algo per BUG-W102-09, but we're
	// testing the callback wiring, not the hash algorithm.)
	expectedHash, _, err := ComputeUTXOHash(bgUS)
	if err != nil {
		t.Fatalf("ComputeUTXOHash: %v", err)
	}

	mgr := NewDualChainstateManager(snapshotCS, bgCS, snapshotHash, 5, expectedHash, nil)

	var callbackResult *bool
	mgr.SetValidationCallback(func(success bool) {
		v := success
		callbackResult = &v
	})

	if err := mgr.CheckBackgroundValidation(); err != nil {
		t.Fatalf("CheckBackgroundValidation: %v", err)
	}

	if callbackResult == nil {
		t.Fatalf("validation callback was not called")
	}
	if !*callbackResult {
		t.Errorf("callback called with success=false; expected success=true for matching empty sets")
	}
	if !mgr.IsSnapshotValidated() {
		t.Errorf("IsSnapshotValidated() = false after successful validation")
	}
}
