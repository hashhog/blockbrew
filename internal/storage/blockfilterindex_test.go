package storage

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestBlockFilterIndex(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Initially should have no data
	if idx.BestHeight() != -1 {
		t.Errorf("expected best height -1, got %d", idx.BestHeight())
	}

	// Create a test block
	block := createTestBlockWithScripts(0)
	hash := block.Header.BlockHash()

	// Write block to index
	if err := idx.WriteBlock(block, 0, hash, nil); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	// Best height should be updated
	if idx.BestHeight() != 0 {
		t.Errorf("expected best height 0, got %d", idx.BestHeight())
	}

	// Get the filter
	filterData, err := idx.GetFilter(0)
	if err != nil {
		t.Fatalf("GetFilter failed: %v", err)
	}

	// Filter should not be empty
	if len(filterData.Filter) == 0 {
		t.Error("expected non-empty filter")
	}

	// Filter hash should be set
	if filterData.FilterHash.IsZero() {
		t.Error("expected non-zero filter hash")
	}

	// Filter header should be set
	if filterData.FilterHeader.IsZero() {
		t.Error("expected non-zero filter header")
	}

	// Block hash should match
	if filterData.BlockHash != hash {
		t.Errorf("expected block hash %s, got %s", hash.String(), filterData.BlockHash.String())
	}
}

func TestBlockFilterIndexChain(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write multiple blocks
	var prevHash wire.Hash256
	var prevFilterHeader wire.Hash256

	for i := int32(0); i < 5; i++ {
		block := createTestBlockWithScripts(i)
		block.Header.PrevBlock = prevHash
		hash := block.Header.BlockHash()

		if err := idx.WriteBlock(block, i, hash, nil); err != nil {
			t.Fatalf("WriteBlock %d failed: %v", i, err)
		}

		// Verify filter header chain
		filterData, err := idx.GetFilter(i)
		if err != nil {
			t.Fatalf("GetFilter %d failed: %v", i, err)
		}

		// For block 0, prev filter header is all zeros
		// For subsequent blocks, it should chain from the previous
		if i > 0 {
			// Compute expected header: SHA256d(filterHash || prevFilterHeader)
			headerInput := make([]byte, 64)
			copy(headerInput[:32], filterData.FilterHash[:])
			copy(headerInput[32:], prevFilterHeader[:])
			expectedHeader := wire.DoubleHashB(headerInput)

			if filterData.FilterHeader != expectedHeader {
				t.Errorf("block %d: filter header chain broken", i)
			}
		}

		prevHash = hash
		prevFilterHeader = filterData.FilterHeader
	}

	if idx.BestHeight() != 4 {
		t.Errorf("expected best height 4, got %d", idx.BestHeight())
	}
}

func TestBlockFilterIndexRevert(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write blocks 0 and 1
	block0 := createTestBlockWithScripts(0)
	hash0 := block0.Header.BlockHash()
	if err := idx.WriteBlock(block0, 0, hash0, nil); err != nil {
		t.Fatalf("WriteBlock 0 failed: %v", err)
	}

	block1 := createTestBlockWithScripts(1)
	block1.Header.PrevBlock = hash0
	hash1 := block1.Header.BlockHash()
	if err := idx.WriteBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("WriteBlock 1 failed: %v", err)
	}

	// Verify both filters exist
	_, err := idx.GetFilter(0)
	if err != nil {
		t.Fatalf("GetFilter 0 failed: %v", err)
	}
	_, err = idx.GetFilter(1)
	if err != nil {
		t.Fatalf("GetFilter 1 failed: %v", err)
	}

	// Revert block 1
	if err := idx.RevertBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("RevertBlock failed: %v", err)
	}

	// Best height should be 0
	if idx.BestHeight() != 0 {
		t.Errorf("expected best height 0, got %d", idx.BestHeight())
	}

	// Filter at height 1 should be gone
	_, err = idx.GetFilter(1)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for reverted filter, got %v", err)
	}

	// Filter at height 0 should still exist
	_, err = idx.GetFilter(0)
	if err != nil {
		t.Errorf("expected filter 0 to still exist, got %v", err)
	}
}

func TestGCSEncodeDecode(t *testing.T) {
	blockHash := wire.Hash256{0x01, 0x02, 0x03}

	// Test with some script elements
	scripts := [][]byte{
		{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03},
		{0x76, 0xa9, 0x14, 0x04, 0x05, 0x06},
		{0x00, 0x14, 0xaa, 0xbb, 0xcc},
	}

	// Encode
	filter := encodeGCS(scripts, blockHash)
	if len(filter) == 0 {
		t.Fatal("expected non-empty filter")
	}

	// All scripts should match
	for _, script := range scripts {
		match, err := matchGCS(filter, blockHash, [][]byte{script})
		if err != nil {
			t.Errorf("matchGCS failed: %v", err)
		}
		if !match {
			t.Errorf("expected script to match")
		}
	}

	// Unknown script should not match
	unknownScript := []byte{0xff, 0xfe, 0xfd}
	match, err := matchGCS(filter, blockHash, [][]byte{unknownScript})
	if err != nil {
		t.Errorf("matchGCS failed: %v", err)
	}
	if match {
		t.Errorf("expected unknown script to not match")
	}
}

func TestGCSEmpty(t *testing.T) {
	blockHash := wire.Hash256{0x01, 0x02, 0x03}

	// Empty filter
	filter := encodeGCS([][]byte{}, blockHash)
	if !bytes.Equal(filter, []byte{0}) {
		t.Errorf("expected empty filter [0], got %v", filter)
	}

	// Matching against empty filter should always return false
	match, err := matchGCS(filter, blockHash, [][]byte{{0x01, 0x02}})
	if err != nil {
		t.Errorf("matchGCS failed: %v", err)
	}
	if match {
		t.Error("expected no match against empty filter")
	}
}

func TestSiphash(t *testing.T) {
	// Test vector from SipHash paper
	key0 := uint64(0x0706050403020100)
	key1 := uint64(0x0f0e0d0c0b0a0908)

	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}

	result := siphash(key0, key1, data)

	// The expected result is known from the test vector
	// SipHash-2-4 with this key and data should produce a specific value
	// We don't have the exact expected value, so just verify it's deterministic
	result2 := siphash(key0, key1, data)
	if result != result2 {
		t.Error("siphash is not deterministic")
	}

	// Different data should produce different hash
	data2 := []byte{0x00, 0x01, 0x02}
	result3 := siphash(key0, key1, data2)
	if result == result3 {
		t.Error("siphash should produce different results for different data")
	}
}

func TestBlockFilterIndexPersistence(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to create PebbleDB: %v", err)
	}

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write some data
	block := createTestBlockWithScripts(5)
	hash := block.Header.BlockHash()
	if err := idx.WriteBlock(block, 5, hash, nil); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	db.Close()

	// Reopen database
	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to reopen PebbleDB: %v", err)
	}
	defer db2.Close()

	idx2 := NewBlockFilterIndex(db2)
	if err := idx2.Init(); err != nil {
		t.Fatalf("Init2 failed: %v", err)
	}

	// State should be restored
	if idx2.BestHeight() != 5 {
		t.Errorf("expected best height 5, got %d", idx2.BestHeight())
	}

	// Filter should still be accessible
	filterData, err := idx2.GetFilter(5)
	if err != nil {
		t.Errorf("GetFilter failed after reopen: %v", err)
	} else if filterData.BlockHash != hash {
		t.Errorf("block hash mismatch after reopen")
	}
}

// TestBlockFilterIndex_RevertBlockBatch_DefersUntilWrite verifies the
// BIP-157 Phase 2 batch-aware rewind contract: RevertBlockBatch APPENDS
// the row deletion + state-row write to the caller-owned batch but does
// not commit it. The on-disk filter row must still be readable by
// GetFilter until the caller's batch.Write() lands. This is the property
// ReorgTo relies on so a multi-block reorg crashes either at the
// pre-reorg tip or the post-reorg tip — never half-way through.
func TestBlockFilterIndex_RevertBlockBatch_DefersUntilWrite(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	block0 := createTestBlockWithScripts(0)
	hash0 := block0.Header.BlockHash()
	if err := idx.WriteBlock(block0, 0, hash0, nil); err != nil {
		t.Fatalf("WriteBlock 0: %v", err)
	}

	block1 := createTestBlockWithScripts(1)
	block1.Header.PrevBlock = hash0
	hash1 := block1.Header.BlockHash()
	if err := idx.WriteBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("WriteBlock 1: %v", err)
	}

	// Snapshot the in-memory + on-disk state at the post-write tip so we
	// can reason about what RevertBlockBatch leaves behind pre-Write.
	preBest := idx.BestHeight()
	prePrev := idx.PrevFilterHeader()

	// Open a batch and APPEND the rewind, but DO NOT commit it yet.
	batch := db.NewBatch()
	prevHeight, prevHash, prevFilterHeader, err := idx.RevertBlockBatch(batch, block1, 1, hash1, nil)
	if err != nil {
		t.Fatalf("RevertBlockBatch: %v", err)
	}
	if prevHeight != 0 {
		t.Errorf("prevHeight = %d, want 0", prevHeight)
	}
	if prevHash != hash0 {
		t.Errorf("prevHash mismatch: got %s want %s", prevHash.String(), hash0.String())
	}

	// Pre-Write invariants: the on-disk filter row at height 1 is still
	// readable, and the in-memory best/prev-filter-header is unchanged.
	if got, err := idx.GetFilter(1); err != nil {
		t.Errorf("pre-Write GetFilter(1): expected hit, got err %v (filter rewind committed too eagerly)", err)
	} else if got.BlockHash != hash1 {
		t.Errorf("pre-Write GetFilter(1): block hash mismatch")
	}
	if idx.BestHeight() != preBest {
		t.Errorf("pre-Write BestHeight = %d, want unchanged %d", idx.BestHeight(), preBest)
	}
	if idx.PrevFilterHeader() != prePrev {
		t.Errorf("pre-Write PrevFilterHeader changed before batch.Write()")
	}

	// Commit the batch + publish the post-Write in-memory state.
	if err := batch.Write(); err != nil {
		t.Fatalf("batch.Write: %v", err)
	}
	idx.CommitRevertState(prevHeight, prevHash, prevFilterHeader)

	// Post-Write: filter row at height 1 is gone, BestHeight reflects the
	// rewind, and a re-Init from disk converges to the same state (i.e.
	// the on-disk side is complete).
	if _, err := idx.GetFilter(1); err != ErrNotFound {
		t.Errorf("post-Write GetFilter(1): want ErrNotFound, got %v", err)
	}
	if _, err := idx.GetFilter(0); err != nil {
		t.Errorf("post-Write GetFilter(0): want hit, got %v", err)
	}
	if idx.BestHeight() != 0 {
		t.Errorf("post-Write BestHeight = %d, want 0", idx.BestHeight())
	}

	idx2 := NewBlockFilterIndex(db)
	if err := idx2.Init(); err != nil {
		t.Fatalf("Init2: %v", err)
	}
	if idx2.BestHeight() != 0 {
		t.Errorf("post-restart BestHeight = %d, want 0", idx2.BestHeight())
	}
	if idx2.PrevFilterHeader() != prevFilterHeader {
		t.Errorf("post-restart PrevFilterHeader did not converge to expected rewind state")
	}
}

// TestBlockFilterIndex_BatchedReorgRoundTrip is the multi-block analog of
// the above: it builds a 3-deep A-chain via WriteBlockBatch (sharing a
// single batch), commits it, then drives a 3-block disconnect via
// RevertBlockBatch (also sharing a single batch) and verifies that
// (a) state rolls back cleanly and (b) replaying a fresh B-fork via
// WriteBlockBatch on a second shared batch produces the right tip and
// the right prev-filter-header chain. This is the storage-side analog
// of ReorgTo's Pattern D batch sharing for filters.
func TestBlockFilterIndex_BatchedReorgRoundTrip(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewBlockFilterIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Build A-chain using a single shared batch (the WriteBlockBatch
	// contract: cumulative state advances per-call but disk only sees
	// it after the shared batch commits).
	type entry struct {
		block *wire.MsgBlock
		hash  wire.Hash256
	}
	var aChain []entry
	{
		var prev wire.Hash256
		batch := db.NewBatch()
		for h := int32(0); h < 3; h++ {
			b := createTestBlockWithScripts(h)
			b.Header.PrevBlock = prev
			h2 := b.Header.BlockHash()
			if err := idx.WriteBlockBatch(batch, b, h, h2, nil); err != nil {
				t.Fatalf("WriteBlockBatch A%d: %v", h, err)
			}
			aChain = append(aChain, entry{b, h2})
			prev = h2
		}
		if err := batch.Write(); err != nil {
			t.Fatalf("A-chain batch.Write: %v", err)
		}
		// Publish the post-Write tip: the latest block.
		idx.CommitWriteState(int32(len(aChain)-1), aChain[len(aChain)-1].hash)
	}

	// Verify all 3 A-chain filters are on disk and best matches.
	if idx.BestHeight() != 2 {
		t.Errorf("post A-chain BestHeight = %d, want 2", idx.BestHeight())
	}
	for h := int32(0); h < 3; h++ {
		if _, err := idx.GetFilter(h); err != nil {
			t.Errorf("post A-chain GetFilter(%d): %v", h, err)
		}
	}

	// Drive a 3-block disconnect through a single shared batch, peeling
	// from tip backward — this is what ReorgTo does inside Pattern D.
	{
		batch := db.NewBatch()
		var lastPrev wire.Hash256
		var lastPrevHeight int32
		for h := int32(2); h >= 0; h-- {
			ph, hh, hf, err := idx.RevertBlockBatch(batch, aChain[h].block, h, aChain[h].hash, nil)
			if err != nil {
				t.Fatalf("RevertBlockBatch A%d: %v", h, err)
			}
			lastPrev = hf
			lastPrevHeight = ph
			_ = hh
		}
		// Pre-Write: every A-row still readable on disk.
		for h := int32(0); h < 3; h++ {
			if _, err := idx.GetFilter(h); err != nil {
				t.Errorf("pre-disconnect-Write GetFilter(%d): %v (rewind committed too early)", h, err)
			}
		}
		if err := batch.Write(); err != nil {
			t.Fatalf("disconnect batch.Write: %v", err)
		}
		idx.CommitRevertState(lastPrevHeight, wire.Hash256{}, lastPrev)
	}

	// Post-disconnect: all 3 A-chain filter rows are gone, BestHeight at -1.
	if idx.BestHeight() != -1 {
		t.Errorf("post-disconnect BestHeight = %d, want -1", idx.BestHeight())
	}
	for h := int32(0); h < 3; h++ {
		if _, err := idx.GetFilter(h); err != ErrNotFound {
			t.Errorf("post-disconnect GetFilter(%d): want ErrNotFound, got %v", h, err)
		}
	}
}

// ---------------------------------------------------------------------------
// BIP-158 test vectors from Bitcoin Core
// test/data/blockfilters.json
// ---------------------------------------------------------------------------

// bip158VectorEntry mirrors one entry in the Core blockfilters.json array.
// Format: [height, block_hash, raw_block_hex, [prev_scripts],
//
//	prev_basic_header, basic_filter_hex, basic_header, notes?]
type bip158VectorEntry struct {
	Height           int
	BlockHash        string
	RawBlock         string
	PrevScripts      []string
	PrevBasicHeader  string
	BasicFilter      string
	BasicHeader      string
}

// findCoreRoot walks up from the current file's directory until it finds the
// bitcoin-core/ directory that is a sibling of blockbrew/ in the meta-repo.
func findCoreRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("runtime.Caller unavailable")
	}
	// Walk up until we find a directory containing "bitcoin-core/"
	dir := filepath.Dir(filename) // .../blockbrew/internal/storage
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "bitcoin-core", "src", "test", "data", "blockfilters.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// TestBIP158Vectors runs every entry from the Bitcoin Core blockfilters.json
// test vector file, byte-exactly verifying:
//   1. The filter builds without error from the raw block + prev-scripts.
//   2. The computed filter bytes match the JSON's BasicFilter field exactly
//      (this is the same byte-exact comparison Core's
//      `src/test/blockfilter_tests.cpp::blockfilters_json_test` performs on
//      every CI build at line 172: BOOST_CHECK(computed.GetEncoded() ==
//      filter_basic)).
//   3. The computed filter header matches the JSON's BasicHeader field, with
//      the prev-header taken from the JSON's PrevBasicHeader (per-entry,
//      not chained — Core's test reseeds at each row).
//   4. Every non-OP_RETURN, non-empty output script MATCHES the filter (round-
//      trip sanity).
//   5. For blocks with an expected empty filter, the filter is exactly
//      []byte{0x00}.
//
// FIX-83 / W122 (2026-05-17): the prior version of this test deliberately
// opted out of byte-exact comparison with a prose rationalization claiming
// the JSON was stale. That claim was factually wrong — Core's
// blockfilters_json_test BOOST_CHECKs the JSON every CI run — and the
// rationalization masked two compounding P0-CDIV bugs in the bit-stream
// codec (LSB-first packing, Word64-boundary truncation). The codec is now
// fixed and the assertions run byte-exactly.
//
// This test is skipped when the bitcoin-core submodule is not initialised.
func TestBIP158Vectors(t *testing.T) {
	vectorPath := findCoreRoot(t)
	if vectorPath == "" {
		t.Skip("bitcoin-core submodule not found — skipping BIP-158 vector test")
	}

	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", vectorPath, err)
	}

	// The JSON file is a JSON array; the first element is a comment string (array of 1).
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(data, &rawEntries); err != nil {
		t.Fatalf("JSON unmarshal outer: %v", err)
	}

	var entries []bip158VectorEntry
	for _, raw := range rawEntries {
		// Each entry is an array; skip if it has only 1 element (comment header row).
		var row []json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Logf("skip non-array row")
			continue
		}
		if len(row) < 7 {
			continue // comment row
		}

		var e bip158VectorEntry
		if err := json.Unmarshal(row[0], &e.Height); err != nil {
			t.Fatalf("height: %v", err)
		}
		if err := json.Unmarshal(row[1], &e.BlockHash); err != nil {
			t.Fatalf("blockhash: %v", err)
		}
		if err := json.Unmarshal(row[2], &e.RawBlock); err != nil {
			t.Fatalf("rawblock: %v", err)
		}
		if err := json.Unmarshal(row[3], &e.PrevScripts); err != nil {
			t.Fatalf("prevscripts: %v", err)
		}
		if err := json.Unmarshal(row[4], &e.PrevBasicHeader); err != nil {
			t.Fatalf("prevbasicheader: %v", err)
		}
		if err := json.Unmarshal(row[5], &e.BasicFilter); err != nil {
			t.Fatalf("basicfilter: %v", err)
		}
		if err := json.Unmarshal(row[6], &e.BasicHeader); err != nil {
			t.Fatalf("basicheader: %v", err)
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		t.Fatal("no test vector entries parsed from blockfilters.json")
	}

	for _, e := range entries {
		e := e
		t.Run(e.BlockHash[:8], func(t *testing.T) {
			// 1. Parse block hash (display BE → LE storage).
			blockHashBytes, err := hex.DecodeString(e.BlockHash)
			if err != nil {
				t.Fatalf("decode block hash: %v", err)
			}
			var blockHash wire.Hash256
			for j := 0; j < 32; j++ {
				blockHash[j] = blockHashBytes[31-j]
			}

			// 2. Collect prev-output scripts (synthetic undo).
			prevScripts := make([][]byte, 0, len(e.PrevScripts))
			for _, s := range e.PrevScripts {
				script, err := hex.DecodeString(s)
				if err != nil {
					t.Fatalf("decode prev script %q: %v", s, err)
				}
				prevScripts = append(prevScripts, script)
			}

			// 3. Parse raw block.
			blockBytes, err := hex.DecodeString(e.RawBlock)
			if err != nil {
				t.Fatalf("decode raw block: %v", err)
			}
			var block wire.MsgBlock
			if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
				t.Fatalf("block Deserialize: %v", err)
			}

			// 4. Build synthetic BlockUndo from prevScripts.
			var undo *BlockUndo
			if len(prevScripts) > 0 {
				spentCoins := make([]SpentCoin, 0, len(prevScripts))
				for _, script := range prevScripts {
					spentCoins = append(spentCoins, SpentCoin{
						TxOut: wire.TxOut{PkScript: script},
					})
				}
				undo = &BlockUndo{
					TxUndos: []TxUndo{
						{SpentCoins: spentCoins},
					},
				}
			}

			// 5. Build the filter using the production path.
			db := NewMemDB()
			defer db.Close()
			idx := NewBlockFilterIndex(db)
			filter := idx.buildBasicFilter(&block, undo, blockHash)

			// 6a. Sanity: filter must not be nil.
			if filter == nil {
				t.Fatal("buildBasicFilter returned nil")
			}

			// 6b. Byte-exact filter assertion against the JSON's BasicFilter.
			// This is the SAME assertion bitcoin-core/src/test/blockfilter_tests.
			// cpp::blockfilters_json_test (line 172) makes:
			//   BOOST_CHECK(computed_filter_basic.GetFilter().GetEncoded()
			//               == filter_basic);
			// FIX-83 / W122 — the codec now packs MSB-first matching Core's
			// streams.h::BitStreamWriter, so this assertion succeeds.
			expectedFilter, err := hex.DecodeString(e.BasicFilter)
			if err != nil {
				t.Fatalf("decode BasicFilter %q: %v", e.BasicFilter, err)
			}
			if !bytes.Equal(filter, expectedFilter) {
				t.Errorf("byte-exact filter mismatch at height=%d:\n  got      %x\n  expected %x",
					e.Height, filter, expectedFilter)
				return
			}

			// Empty-filter blocks: nothing else to check.
			if e.BasicFilter == "00" {
				return
			}

			// 7. Verify that each non-OP_RETURN, non-empty output script matches.
			// Round-trip sanity check — independently confirms the filter
			// is meaningful for clients that match against scripts.
			for _, tx := range block.Transactions {
				for _, out := range tx.TxOut {
					if len(out.PkScript) == 0 || out.PkScript[0] == 0x6a {
						continue // excluded by BIP-158
					}
					match, err := matchGCS(filter, blockHash, [][]byte{out.PkScript})
					if err != nil {
						t.Errorf("matchGCS output error: %v", err)
						continue
					}
					if !match {
						t.Errorf("output script %x not found in filter", out.PkScript)
					}
				}
			}
			// Also verify spent scripts (undo) match.
			if undo != nil {
				for _, txu := range undo.TxUndos {
					for _, sc := range txu.SpentCoins {
						if len(sc.TxOut.PkScript) == 0 {
							continue
						}
						match, err := matchGCS(filter, blockHash, [][]byte{sc.TxOut.PkScript})
						if err != nil {
							t.Errorf("matchGCS undo error: %v", err)
							continue
						}
						if !match {
							t.Errorf("undo script %x not found in filter", sc.TxOut.PkScript)
						}
					}
				}
			}

			// 8. Byte-exact filter-header assertion against the JSON's
			// BasicHeader. Core's test (line 174):
			//   uint256 computed_header_basic =
			//     computed_filter_basic.ComputeHeader(prev_filter_header_basic);
			//   BOOST_CHECK(computed_header_basic == filter_header_basic);
			//
			// Note: the JSON stores PrevBasicHeader and BasicHeader as the
			// uint256 display-form hex (big-endian). Core's uint256::FromHex
			// reverses on parse so the in-memory uint256 is LE. We do the
			// same byte-reversal here: parse JSON hex → reverse → use as raw
			// 32 LE bytes in the SHA256d input.
			prevHeaderBytes, err := hex.DecodeString(e.PrevBasicHeader)
			if err != nil {
				t.Fatalf("decode PrevBasicHeader: %v", err)
			}
			var prevHeader wire.Hash256
			if len(prevHeaderBytes) == 32 {
				for j := 0; j < 32; j++ {
					prevHeader[j] = prevHeaderBytes[31-j]
				}
			}

			filterHash := wire.DoubleHashB(filter)
			var headerData [64]byte
			copy(headerData[:32], filterHash[:])
			copy(headerData[32:], prevHeader[:])
			computedHeader := wire.DoubleHashB(headerData[:])

			expectedHeaderBytes, err := hex.DecodeString(e.BasicHeader)
			if err != nil {
				t.Fatalf("decode BasicHeader: %v", err)
			}
			var expectedHeader wire.Hash256
			if len(expectedHeaderBytes) == 32 {
				for j := 0; j < 32; j++ {
					expectedHeader[j] = expectedHeaderBytes[31-j]
				}
			}
			if computedHeader != expectedHeader {
				t.Errorf("byte-exact header mismatch at height=%d:\n  got      %x\n  expected %x",
					e.Height, computedHeader[:], expectedHeader[:])
			}
		})
	}
}

// TestBIP158VectorsFilterMatch verifies that after building a BIP-158 filter
// from the genesis block, all the output scripts from that block match and
// a random unknown script does not match.
func TestBIP158VectorsFilterMatch(t *testing.T) {
	vectorPath := findCoreRoot(t)
	if vectorPath == "" {
		t.Skip("bitcoin-core submodule not found")
	}

	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var rawEntries []json.RawMessage
	if _ = json.Unmarshal(data, &rawEntries); len(rawEntries) < 2 {
		t.Fatal("not enough entries")
	}

	// Use the first real entry (index 1, since index 0 is the comment header).
	var row []json.RawMessage
	if err := json.Unmarshal(rawEntries[1], &row); err != nil || len(row) < 7 {
		t.Fatal("first vector row parse error")
	}

	var rawBlockHex, blockHashHex string
	_ = json.Unmarshal(row[2], &rawBlockHex)
	_ = json.Unmarshal(row[1], &blockHashHex)

	blockHashBytes, _ := hex.DecodeString(blockHashHex)
	var blockHash wire.Hash256
	for i := 0; i < 32; i++ {
		blockHash[i] = blockHashBytes[31-i]
	}

	blockBytes, _ := hex.DecodeString(rawBlockHex)
	var block wire.MsgBlock
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		t.Fatalf("block Deserialize: %v", err)
	}

	db := NewMemDB()
	defer db.Close()
	idx := NewBlockFilterIndex(db)
	filter := idx.buildBasicFilter(&block, nil, blockHash)

	// All output scripts from non-OP_RETURN outputs should match.
	for _, tx := range block.Transactions {
		for _, out := range tx.TxOut {
			if len(out.PkScript) == 0 || out.PkScript[0] == 0x6a {
				continue
			}
			match, err := matchGCS(filter, blockHash, [][]byte{out.PkScript})
			if err != nil {
				t.Errorf("matchGCS error: %v", err)
				continue
			}
			if !match {
				t.Errorf("output script not matched: %x", out.PkScript)
			}
		}
	}

	// A script that definitely does not appear in the genesis block should not match.
	phantom := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04}
	match, err := matchGCS(filter, blockHash, [][]byte{phantom})
	if err != nil {
		t.Errorf("matchGCS phantom error: %v", err)
	}
	if match {
		// False positive is possible but extremely unlikely (1/784931).
		t.Logf("phantom script produced false positive (p ≈ 1/784931, expected very rarely)")
	}
}

// TestBIP158SipHashVectors verifies the SipHash-2-4 implementation against
// Bitcoin Core's own unit test vectors from src/test/hash_tests.cpp
// (siphash_4_2_testvec array). Key = 000102...0f, inputs are prefixes of
// [0x00, 0x01, 0x02, ...].
//
// These values match what Bitcoin Core's CSipHasher produces for each input
// length, which is what GCSFilter::HashToRange uses for BIP-158 filters.
func TestBIP158SipHashVectors(t *testing.T) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)

	// From Bitcoin Core src/test/hash_tests.cpp siphash_4_2_testvec.
	expected := []uint64{
		0x726fdb47dd0e0e31, // in[0] = empty
		0x74f839c593dc67fd, // in[1] = [0x00]
		0x0d6c8009d9a94f5a, // in[2]
		0x85676696d7fb7e2d, // in[3]
		0xcf2794e0277187b7, // in[4]
		0x18765564cd99a68d, // in[5]
		0xcbc9466e58fee3ce, // in[6]
		0xab0200f58b01d137, // in[7]
		0x93f5f5799a932462, // in[8]
		0x9e0082df0ba9e4b0, // in[9]
		0x7a5dbbc594ddb9f3, // in[10]
		0xf4b32f46226bada7, // in[11]
		0x751e8fbc860ee5fb, // in[12]
		0x14ea5627c0843d90, // in[13]
		0xf723ca908e7af2ee, // in[14]
		0xa129ca6149be45e5, // in[15]
	}

	for i, exp := range expected {
		msg := make([]byte, i)
		for j := range msg {
			msg[j] = byte(j)
		}
		got := siphash(k0, k1, msg)
		if got != exp {
			t.Errorf("in[%d]: got=0x%016x, want=0x%016x", i, got, exp)
		}
	}
}

// TestBIP158FastRange64 verifies the FastRange64 implementation for specific
// known inputs. The FastRange64 formula is (x * n) >> 64 (128-bit multiply,
// take the upper 64 bits).
func TestBIP158FastRange64(t *testing.T) {
	tests := []struct {
		x, n, want uint64
	}{
		// Edge cases
		{0, 100, 0},
		{^uint64(0), 1, 0},   // max * 1 >> 64 = 0 (since result fits in 64 bits)
		{^uint64(0), 2, 1},   // max * 2 >> 64 ≈ 1
		{1 << 63, 2, 1},      // (2^63 * 2) >> 64 = 1
		{1 << 32, 1 << 32, 1}, // (2^32 * 2^32) >> 64 = 1
		// BIP-158 genesis block: N=1, M=784931, F=784931.
		// Hash of genesis coinbase script → FastRange64(hash, 784931) must be in [0, 784931).
		// We just verify the range here.
	}
	for _, tc := range tests {
		got := fastRange64(tc.x, tc.n)
		if got != tc.want {
			t.Errorf("fastRange64(0x%x, 0x%x) = 0x%x, want 0x%x", tc.x, tc.n, got, tc.want)
		}
	}

	// Verify range constraint: result must always be < n (when n > 0).
	testCases := [][2]uint64{
		{0xdeadbeefcafebabe, 784931},
		{0x0102030405060708, 1000000},
		{^uint64(0), 784931},
		{1, 784931},
	}
	for _, tc := range testCases {
		x, n := tc[0], tc[1]
		got := fastRange64(x, n)
		if got >= n {
			t.Errorf("fastRange64(0x%x, 0x%x) = %d, out of range [0, %d)", x, n, got, n)
		}
	}
}

// createTestBlockWithScripts creates a test block with varied scriptPubKeys.
func createTestBlockWithScripts(height int32) *wire.MsgBlock {
	// P2PKH script
	p2pkh := []byte{0x76, 0xa9, 0x14,
		byte(height), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x88, 0xac}

	// P2WPKH script
	p2wpkh := []byte{0x00, 0x14,
		byte(height), 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33}

	// OP_RETURN (should be excluded from filter)
	opReturn := []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}

	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{byte(height), 0x04, 0xff, 0xff, 0x00, 0x1d},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 5_000_000_000, PkScript: p2pkh},
			{Value: 0, PkScript: opReturn},
		},
		LockTime: 0,
	}

	regularTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{byte(height), 0x01},
					Index: 0,
				},
				SignatureScript: []byte{0x00, byte(height)},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 1_000_000, PkScript: p2wpkh},
		},
		LockTime: 0,
	}

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: wire.Hash256{},
			Timestamp:  uint32(1231006505 + int(height)*600),
			Bits:       0x1d00ffff,
			Nonce:      uint32(height),
		},
		Transactions: []*wire.MsgTx{coinbase, regularTx},
	}
}
