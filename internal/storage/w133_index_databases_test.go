// w133_index_databases_test.go — W133 discovery-only audit (txindex +
// coinstatsindex). 30 gates of the BaseIndex framework + reorg + prune-mode +
// persistence + format-version + init parity, recorded as t.Skip() shells
// keyed by gate ID. See blockbrew/audit/w133_index_databases.md for the bug
// catalogue (BUG-1..BUG-21).
//
// Scope: txindex + coinstatsindex only. blockfilterindex is W121/W122.
//
// Cross-impl references (from Bitcoin Core, all under bitcoin-core/src/):
//   index/base.{h,cpp}        — BaseIndex framework, Sync thread, prune lock.
//   index/txindex.{h,cpp}     — TxIndex (CDiskTxPos disk layout, FindTx).
//   index/disktxpos.h         — CDiskTxPos struct (FlatFilePos + nTxOffset).
//   index/coinstatsindex.{h,cpp} — CoinStatsIndex (MuHash3072, DBVal 12-field).
//   index/db_key.h            — DBHeightKey + DBHashKey two-index reorg.
//   crypto/muhash.{h,cpp}     — MuHash3072 (3072-bit multiplicative group).
//   kernel/coinstats.{h,cpp}  — ApplyCoinHash/RemoveCoinHash/GetBogoSize.
//   init.cpp                  — -txindex + -coinstatsindex flag wiring.
//
// Why t.Skip(): discovery audit. Implementing these gates as passing tests
// would require either landing the production wiring (BUG-2/BUG-3) and the
// MuHash migration (BUG-1) or stubbing them with the buggy XOR hash, which
// would lock in the divergence. The corresponding fix wave will flip the
// Skip()s into real assertions.

package storage

import "testing"

// ---------------------------------------------------------------------------
// G1 — BaseIndex framework primitives exist
// ---------------------------------------------------------------------------

func TestW133_G1_BaseIndexFrameworkExists(t *testing.T) {
	t.Skip("W133 G1 — PASS: internal/storage/index.go:50-126 defines BaseIndex with name/bestHeight/bestHash/synced fields and Init/WriteBlock/RevertBlock semantics. Recorded as PASS in audit/w133_index_databases.md.")
}

// ---------------------------------------------------------------------------
// G2 — IndexManager fan-out: BlockConnected calls every registered index
// ---------------------------------------------------------------------------

func TestW133_G2_IndexManagerFanOutOnConnect(t *testing.T) {
	t.Skip("W133 G2 — PASS: internal/storage/index.go:181-196 IndexManager.BlockConnected iterates indexes map and calls WriteBlock on each. See audit/w133_index_databases.md.")
}

// ---------------------------------------------------------------------------
// G3 — Reorg fan-out on disconnect (per-index error isolation)
// ---------------------------------------------------------------------------

func TestW133_G3_IndexManagerFanOutOnDisconnect_BUG19(t *testing.T) {
	t.Skip("W133 G3 — PARTIAL / BUG-19: IndexManager.BlockDisconnected (index.go:199-214) fan-out exists but a single index's error halts the loop AND propagates to caller, losing the error chain. Per-index isolation missing. See audit BUG-19.")
}

// ---------------------------------------------------------------------------
// G4 — *TxIndex instantiated and registered in production
// ---------------------------------------------------------------------------

func TestW133_G4_TxIndexInstantiatedInProduction_BUG2(t *testing.T) {
	t.Skip("W133 G4 — MISSING / BUG-2 (HIGH): grep production-side for NewTxIndex shows zero hits outside _test.go. cmd/blockbrew/main.go:841-848 only registers *BlockFilterIndex with IndexManager. The richer *TxIndex schema (TxIndexData with in-block tx index) is dead code. See audit BUG-2.")
}

// ---------------------------------------------------------------------------
// G5 — *CoinStatsIndex instantiated and registered in production
// ---------------------------------------------------------------------------

func TestW133_G5_CoinStatsIndexInstantiatedInProduction_BUG2(t *testing.T) {
	t.Skip("W133 G5 — MISSING / BUG-2 (HIGH): grep production-side for NewCoinStatsIndex shows zero hits outside _test.go. No production path constructs the index. See audit BUG-2.")
}

// ---------------------------------------------------------------------------
// G6 — -coinstatsindex CLI flag present
// ---------------------------------------------------------------------------

func TestW133_G6_CoinStatsIndexCLIFlagPresent_BUG3(t *testing.T) {
	t.Skip("W133 G6 — MISSING / BUG-3 (HIGH): cmd/blockbrew/main.go:463 has -txindex but no -coinstatsindex flag.BoolVar; Config struct has no CoinStatsIndex bool field; help-text omits it. Mirrors Core init.cpp DEFAULT_COINSTATSINDEX gap. See audit BUG-3.")
}

// ---------------------------------------------------------------------------
// G7 — -txindex flag wired through to OnBlockConnected
// ---------------------------------------------------------------------------

func TestW133_G7_TxIndexFlagWiredThroughOnBlockConnected(t *testing.T) {
	t.Skip("W133 G7 — PASS: cmd/blockbrew/main.go:463 declares -txindex, :954-965 gates chainDB.WriteTxIndex on cfg.TxIndex inside the OnBlockConnected hook. Symmetric DeleteTxIndex on disconnect at :880-890. See audit G7.")
}

// ---------------------------------------------------------------------------
// G8 — txindex skips genesis (Core txindex.cpp:77)
// ---------------------------------------------------------------------------

func TestW133_G8_TxIndexSkipsGenesis_BUG4partial(t *testing.T) {
	t.Skip("W133 G8 — PARTIAL: production-wired flat txindex (chaindb.go:343 WriteTxIndex) writes via OnBlockConnected, which fires for height>=1 only (ConnectBlock early-returns for genesis). The orphan *TxIndex.WriteBlock at txindex.go:86 has explicit 'if height == 0' guard but it's dead code. Functional today but semantic is implicit, not explicit. See audit G8/BUG-4.")
}

// ---------------------------------------------------------------------------
// G9 — txindex stores CDiskTxPos analog (file + pos + tx offset)
// ---------------------------------------------------------------------------

func TestW133_G9_TxIndexStoresCDiskTxPosAnalog_BUG4(t *testing.T) {
	t.Skip("W133 G9 — MISSING / BUG-4 (HIGH): chaindb.go:337-368 TxIndexEntry stores ONLY 32-byte block hash. Core CDiskTxPos (disktxpos.h) stores FlatFilePos{nFile, nPos} + VARINT nTxOffset, enabling seek-into-blockfile. blockbrew falls back to whole-block read + O(N) txid scan in methods.go:889-902. See audit BUG-4.")
}

// ---------------------------------------------------------------------------
// G10 — FindTx opens blockfile + seeks + deserialize + verifies hash
// ---------------------------------------------------------------------------

func TestW133_G10_FindTxOpensBlockfileAndVerifies_BUG4(t *testing.T) {
	t.Skip("W133 G10 — MISSING / BUG-4 (HIGH): Core txindex.cpp:93-120 FindTx opens block file, reads header, seeks postx.nTxOffset, deserializes tx, asserts tx->GetHash()==tx_hash. blockbrew (methods.go:889-902) reads whole block then linear-scans. Correctness holds (hash compare in scan) but txid-mismatch self-check is implicit, and the per-tx-read cost is pessimal. See audit BUG-4.")
}

// ---------------------------------------------------------------------------
// G11 — txindex RevertBlock deletes each txid
// ---------------------------------------------------------------------------

func TestW133_G11_TxIndexRevertBlockDeletesEachTxid(t *testing.T) {
	t.Skip("W133 G11 — PASS: cmd/blockbrew/main.go:880-890 OnBlockDisconnected hook iterates block.Transactions and chainDB.DeleteTxIndex(txid) for each (gated on cfg.TxIndex). See audit G11 (PASS but see BUG-12 for IsSynced latch).")
}

// ---------------------------------------------------------------------------
// G12 — txindex_state row carries a format-version byte
// ---------------------------------------------------------------------------

func TestW133_G12_TxIndexStateRowFormatVersion_BUG6(t *testing.T) {
	t.Skip("W133 G12 — MISSING / BUG-6 (MED): txindex.go:178-212 IndexState.Serialize is bare [int32 height, 32-byte hash], no version prefix byte. coinstatsindex.go:400-481 CoinStatsState same. Only blockfilterindex.go:53 has FormatVersion (added in FIX-83). No self-heal-on-mismatch path. See audit BUG-6.")
}

// ---------------------------------------------------------------------------
// G13 — coinstatsindex uses MuHash3072 incremental accumulator
// ---------------------------------------------------------------------------

func TestW133_G13_CoinStatsIndexUsesMuHash3072_BUG1(t *testing.T) {
	t.Skip("W133 G13 — MISSING / BUG-1 (P0-CDIV): coinstatsindex.go:339-367 uses 32-byte XOR-of-SHA256 hash, not Core's 3072-bit MuHash3072 multiplicative group. crypto/muhash.go ships a complete MuHash3072 implementation that's never imported. Every emitted hash_serialized_3 byte-INCOMPATIBLE with Core peer. See audit BUG-1.")
}

// ---------------------------------------------------------------------------
// G14 — ApplyCoinHash uses (outpoint, coin) tuple, not (value, scriptPubKey)
// ---------------------------------------------------------------------------

func TestW133_G14_ApplyCoinHashUsesOutpointTuple_BUG21(t *testing.T) {
	t.Skip("W133 G14 — MISSING / BUG-21 (P0-CDIV): coinstatsindex.go:355-367 removeFromHash explicitly drops outpoint context. Comment at :357-358 confesses 'We need the outpoint to properly hash, but we don't have it here'. Two UTXOs with same (value, scriptPubKey) at different outpoints cancel each other on spend. Mainnet early-2010 same-miner same-P2PK pattern hits this. See audit BUG-21.")
}

// ---------------------------------------------------------------------------
// G15 — Per-height DBVal stores 12 Core-equivalent fields
// ---------------------------------------------------------------------------

func TestW133_G15_PerHeightDBValTwelveFields_BUG10(t *testing.T) {
	t.Skip("W133 G15 — PARTIAL / BUG-10 (MED): coinstatsindex.go:26-36 CoinStats stores 8 fields (height, hash, tx_count, utxo_count, total_amount, bogo_size, hash, subsidy, fees). Core DBVal has 12 fields including total_prevout_spent_amount + total_new_outputs_ex_coinbase_amount + total_coinbase_amount + total_unspendables_{genesis_block, bip30, scripts, unclaimed_rewards}. arith_uint256 width loss too. See audit BUG-10.")
}

// ---------------------------------------------------------------------------
// G16 — BIP-30 duplicate-coinbase blocks skipped
// ---------------------------------------------------------------------------

func TestW133_G16_BIP30DuplicateCoinbaseSkipped_BUG7(t *testing.T) {
	t.Skip("W133 G16 — MISSING / BUG-7 (P0-CDIV): coinstatsindex.go:186-218 has no IsBIP30Unspendable check. Core coinstatsindex.cpp:128-132 skips and credits m_total_unspendables_bip30 += subsidy. blockbrew double-counts the burned coinbases at mainnet heights 91842/91722/91812/91812. blockbrew HAS CheckBIP30 at consensus layer (validation_test.go:1664+) so the data is available. See audit BUG-7.")
}

// ---------------------------------------------------------------------------
// G17 — OP_RETURN with nValue > 0 booked to unspendables_scripts
// ---------------------------------------------------------------------------

func TestW133_G17_OPReturnWithValueBookedToUnspendablesScripts_BUG8(t *testing.T) {
	t.Skip("W133 G17 — MISSING / BUG-8 (P0-CDIV): coinstatsindex.go:192-203 just continues past unspendable scripts. Core coinstatsindex.cpp:140-143 books out.nValue to m_total_unspendables_scripts. blockbrew breaks the Core invariant total_subsidy == total_amount + sum(unspendables_*) by exactly the OP_RETURN-with-value sum. See audit BUG-8.")
}

// ---------------------------------------------------------------------------
// G18 — CustomCommit atomically writes DB_MUHASH and DB_BEST_BLOCK
// ---------------------------------------------------------------------------

func TestW133_G18_CustomCommitAtomicMuHashAndBestBlock_BUG5(t *testing.T) {
	t.Skip("W133 G18 — PARTIAL / BUG-5 (HIGH): coinstatsindex.go:241-261 WriteBlock writes per-height row + state row in one batch. But state row carries the running accumulator REDUNDANTLY with per-height row (two sources of truth). And RevertBlock at :268-323 mutates idx.* in-memory BEFORE batch.Write, so a failed write leaves in-memory rollback ahead of disk. Core coinstatsindex.cpp:308-314 commits DB_MUHASH alongside DB_BEST_BLOCK with explicit comment. See audit BUG-5.")
}

// ---------------------------------------------------------------------------
// G19 — Init asserts in-memory MuHash equals on-disk DB_MUHASH
// ---------------------------------------------------------------------------

func TestW133_G19_InitChecksMuHashAgainstOnDiskValue_BUG1(t *testing.T) {
	t.Skip("W133 G19 — MISSING / BUG-1 (P0-CDIV cascade): coinstatsindex.go:140-167 Init has no consistency check. Core coinstatsindex.cpp:282-289 finalizes m_muhash, compares to on-disk entry.muhash, refuses startup on mismatch (corruption detection). No MuHash → no check. See audit BUG-1.")
}

// ---------------------------------------------------------------------------
// G20 — CustomRemove copies height-keyed row to hash-keyed slot
// ---------------------------------------------------------------------------

func TestW133_G20_CustomRemoveCopiesHeightToHashIndex_BUG9(t *testing.T) {
	t.Skip("W133 G20 — MISSING / BUG-9 (MED): coinstatsindex.go:301 RevertBlock just batch.Delete(heightKey). Core coinstatsindex.cpp:223-225 calls CopyHeightIndexToHashIndex<DBVal> so the orphan block's stats survive under DBHashKey for post-reorg queries. blockbrew loses them. See audit BUG-9.")
}

// ---------------------------------------------------------------------------
// G21 — LookUpStats uses two-index lookup (height-first, hash-fallback)
// ---------------------------------------------------------------------------

func TestW133_G21_LookUpStatsTwoIndexLookup_BUG9(t *testing.T) {
	t.Skip("W133 G21 — MISSING / BUG-9 (MED): coinstatsindex.go:325-336 GetStats reads only the height-keyed slot. Core db_key.h:96-113 LookUpOne tries DBHeightKey first then DBHashKey. blockbrew can't answer 'stats for this orphan block hash' even immediately post-reorg. See audit BUG-9.")
}

// ---------------------------------------------------------------------------
// G22 — gettxoutsetinfo consults coinstatsindex when hash_type=muhash
// ---------------------------------------------------------------------------

func TestW133_G22_GetTxOutSetInfoConsultsCoinStatsIndex_BUG11(t *testing.T) {
	t.Skip("W133 G22 — MISSING / BUG-11 (HIGH): internal/rpc/wave47b_methods.go:26-57 hard-codes 'muhash':'', 'bogosize':0, 'total_amount':0.0. Discards params (no hash_type / hash_or_height parsing). Core rpc/blockchain.cpp::gettxoutsetinfo routes to g_coin_stats_index->LookUpStats(*pindex) when hash_type='muhash'. See audit BUG-11.")
}

// ---------------------------------------------------------------------------
// G23 — getindexinfo includes txindex when -txindex enabled
// ---------------------------------------------------------------------------

func TestW133_G23_GetIndexInfoIncludesTxIndex_BUG2(t *testing.T) {
	t.Skip("W133 G23 — RESOLVED post-da28707: getindexinfo no longer walks AllIndexes()/Status() (which carried best_height/best_hash). handleGetIndexInfo now summarises txindex off the chain tip when -txindex is set and emits blockfilterindex under Core's GetName() string, with the exact Core {synced, best_block_height} value shape. Live coverage moved to the rpc package: internal/rpc/getindexinfo_methods_test.go (TestGetIndexInfo_Shape / _BlockFilterIndexKey / _DisabledEmpty). This stub is retained only as a pointer.")
}

// ---------------------------------------------------------------------------
// G24 — BaseIndex.Init validates on-disk best-hash against active chain
// ---------------------------------------------------------------------------

func TestW133_G24_InitValidatesBestHashAgainstActiveChain_BUG14(t *testing.T) {
	t.Skip("W133 G24 — MISSING / BUG-14 (MED): txindex.go:64-82 + coinstatsindex.go:140-167 just deserialize state row, set fields, return. No equivalent of Core base.cpp:124-134 LookupBlockIndex + rewind-on-fork. Stale-state-after-restore can never self-heal. See audit BUG-14.")
}

// ---------------------------------------------------------------------------
// G25 — BlockUntilSyncedToCurrentChain API exists
// ---------------------------------------------------------------------------

func TestW133_G25_BlockUntilSyncedToCurrentChainAPI_BUG13(t *testing.T) {
	t.Skip("W133 G25 — MISSING / BUG-13 (MED): no equivalent of Core base.cpp:424-446 BlockUntilSyncedToCurrentChain. methods.go:885-911 reads chainDB.GetTxIndex(txid) directly without checking index sync state. RPC handler returns 'not found' for a confirmed-but-not-yet-indexed tx instead of 'node warming up'. See audit BUG-13.")
}

// ---------------------------------------------------------------------------
// G26 — ThreadSync goroutine catches up index from disk on startup
// ---------------------------------------------------------------------------

func TestW133_G26_ThreadSyncGoroutineExists_BUG15(t *testing.T) {
	t.Skip("W133 G26 — MISSING / BUG-15 (MED): no per-index sync goroutine. IndexManager fan-out is purely BlockConnected-notification-driven (index.go:181-196). Restart with -txindex newly enabled after IBD has no catchup path. Core base.cpp:201-268 ThreadSync handles this. See audit BUG-15.")
}

// ---------------------------------------------------------------------------
// G27 — Stop/Interrupt lifecycle on shutdown
// ---------------------------------------------------------------------------

func TestW133_G27_StopAndInterruptLifecycle_BUG15(t *testing.T) {
	t.Skip("W133 G27 — MISSING / BUG-15 (MED): BaseIndex.Stop()/Interrupt() don't exist. IndexManager has no shutdown sequence. Core base.cpp:448-470 unregisters from validation interface and joins the sync thread. See audit BUG-15.")
}

// ---------------------------------------------------------------------------
// G28 — SetBestBlockIndex updates prune lock so the pruner respects it
// ---------------------------------------------------------------------------

func TestW133_G28_SetBestBlockIndexUpdatesPruneLock_BUG15(t *testing.T) {
	t.Skip("W133 G28 — MISSING / BUG-15 (MED): UpdateBest at index.go:104-109 just sets two fields. No prune-lock integration. Core base.cpp:487-504 calls m_blockman.UpdatePruneLock(GetName(), prune_lock). cfg.Prune is wired through to pruner without any index-pinned-blocks check. A -prune=1000 -txindex config WILL prune blocks txindex has tx-pointers into. See audit BUG-15.")
}

// ---------------------------------------------------------------------------
// G29 — AllowPrune signal: coinstats=true, txindex=false
// ---------------------------------------------------------------------------

func TestW133_G29_AllowPruneSignalsPerIndex_BUG15(t *testing.T) {
	t.Skip("W133 G29 — MISSING / BUG-15 (MED): no AllowPrune() method in Index interface (index.go:20-47). Core base.h:111 declares virtual AllowPrune() = 0; txindex.h:34 returns false; coinstatsindex.h:52 returns true. Without this, prune-mode compatibility is undefined per-index. See audit BUG-15.")
}

// ---------------------------------------------------------------------------
// G30 — Reorg-replay: RevertBlock × N then WriteBlock × M atomically
// ---------------------------------------------------------------------------

func TestW133_G30_ReorgReplayAtomicAcrossIndexes_BUG12(t *testing.T) {
	t.Skip("W133 G30 — PARTIAL / BUG-12 (HIGH): cmd/blockbrew/main.go:880-890 + :954-965 OnBlockDisconnected/OnBlockConnected fan out per-block during ReorgTo. But only blockfilterindex rides chainMgr.CurrentReorgBatch() (main.go:893-915, :967-983). chainDB.WriteTxIndex / DeleteTxIndex are NOT batched with the reorg; mid-reorg failure leaves txindex half-rewritten with no rollback. Also BUG-12 IsSynced is one-way latch with no SetSynced(false) recovery. See audit BUG-12.")
}

// ---------------------------------------------------------------------------
// Reorg integration regression — covered by W109/W121 storage_test.go suites
// already exercising the OnBlockConnected/Disconnected hook chain. W133 does
// NOT add new corpus entries because it's discovery; the FIX wave that
// closes BUG-1/2/3 will add Core test-vector pinned cases.
// ---------------------------------------------------------------------------
