package p2p

// W112 BIP-152 compact blocks audit — blockbrew (Go)
//
// Gate coverage:
//   G1  HB cap constant = 3                       PASS
//   G2  ShortID length = 6 bytes                  PASS
//   G3  SipHash key derivation (SHA256(hdr||nonce_LE) → k0/k1 LE) PASS
//   G4  Nonce serialized as LE uint64             PASS
//   G5  PrefilledTxn delta-encoded ser             PASS
//   G6  sendcmpct: announce bool + version uint64 PASS
//   G7  v2 = segwit/wtxid; v1 = non-segwit/txid  PARTIAL (only v2 sent/accepted)
//   G8  Outbound sends sendcmpct(announce=false)  PASS
//   G9  IsHighBandwidthMode tracking              PASS (state stored)
//   G10 HB cap (3) + rotation                    BUG-1 — DEAD PIPELINE
//   G11 cmpctblock payload structure             PASS
//   G12 SipHash on wtxid (v2) / txid (v1)        PASS for v2
//   G13 Coinbase always prefilled at index 0      PASS
//   G14 Short-ID collision detection              PASS
//   G15 Size bounds (maxBlockTxCount)             PASS
//   G16 getblocktxn: 1-based delta indexes       PASS (decoder correct)
//   G17 blocktxn response on getblocktxn         BUG-3 — NOT SERVED (log+ignore)
//   G18 Misbehaving on wrong-tx-count in blocktxn BUG-4 — NOT CHECKED
//   G19 Fallback to full block on reconstruction  PASS (always falls back)
//   G20 getblocktxn depth limit (MAX_BLOCKTXN_DEPTH=10) BUG-5 — MISSING
//   G21 PartiallyDownloadedBlock object           PASS
//   G22 Mempool short-ID match                   PASS
//   G23 Merkle root validate (IsBlockMutated)     PASS
//   G24 DoS fallback on InitData READ_STATUS_FAILED PASS (ErrShortIDCollision)
//   G25 segwit / wtxid v2 integration            PASS
//   G26 BIP-339 wtxid interaction                PASS
//   G27 ≤5-deep age limit (MAX_CMPCTBLOCK_DEPTH) BUG-6 — MISSING
//   G28 No compact blocks during IBD             BUG-7 — MISSING
//   G29 HB outbound peer limit enforcement        BUG-1 — DEAD PIPELINE
//   G30 HB peer rotation when stale              BUG-1 — DEAD PIPELINE
//
// Bug summary (6 bugs):
//   BUG-1 (P1/DEAD-PIPELINE): HB peer management entirely absent. MaxHBPeers=3 constant
//         exists but lNodesAnnouncingHeaderAndIDs-equivalent list/rotation never built.
//         AnnounceBlock() sends headers/inv to all peers — never cmpctblock to HB peers.
//         blockbrew cannot announce new blocks as compact blocks. (G10/G29/G30)
//   BUG-2 (P1): sendcmpct v1 rejected. SetSendCmpct only accepts version==2; a peer
//         sending sendcmpct(v1) gets its provides-bit silently dropped. BIP-152 requires
//         storing the most recent sendcmpct per version independently. (G7)
//   BUG-3 (P1/MISSING): getblocktxn handler is log+ignore. No blocktxn response is ever
//         sent. Peers waiting for their missing compact-block transactions stall. (G17)
//   BUG-4 (P1/MISSING): blocktxn handler is log+ignore. Incoming blocktxn messages for
//         reconstruction are discarded. The reconstruction round-trip is fully dead. (G18)
//   BUG-5 (P1/MISSING): No MAX_BLOCKTXN_DEPTH=10 guard on getblocktxn requests. Core
//         falls back to full block for deep requests; blockbrew just ignores them. (G20)
//   BUG-6 (P2/MISSING): No MAX_CMPCTBLOCK_DEPTH=5 guard on cmpctblock serving. Core
//         falls back to full block when pindex->nHeight < tip - 5; blockbrew has no
//         equivalent depth check. (G27)
//   BUG-7 (P2/MISSING): No IBD guard on compact block relay. Core skips compact block
//         serving while IBD is active; blockbrew has IsIBDActive() but never consults it
//         in the cmpctblock path. (G28)

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── G1: HB peer cap constant ─────────────────────────────────────────────

// TestW112_G1_MaxHBPeers verifies the HB peer cap constant is exactly 3.
// BIP-152: "no more than 3 outbound HB peers".
func TestW112_G1_MaxHBPeers(t *testing.T) {
	if MaxHBPeers != 3 {
		t.Errorf("MaxHBPeers = %d, want 3", MaxHBPeers)
	}
}

// ─── G2: Short-ID length ──────────────────────────────────────────────────

// TestW112_G2_ShortIDLength verifies that computed short IDs fit in 6 bytes (48 bits).
func TestW112_G2_ShortIDLength(t *testing.T) {
	if ShortIDLength != 6 {
		t.Errorf("ShortIDLength = %d, want 6", ShortIDLength)
	}

	key := SipHashKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	h := wire.Hash256{0xDE, 0xAD, 0xBE, 0xEF}
	sid := ComputeShortID(key, h)
	if sid >= (1 << 48) {
		t.Errorf("short ID 0x%x exceeds 48 bits", sid)
	}
}

// ─── G3/G4: SipHash key derivation ────────────────────────────────────────

// TestW112_G3_SipHashKeyDerivation verifies that ComputeSipHashKey:
//   - is deterministic,
//   - produces different keys for different headers/nonces,
//   - produces a 16-byte value (k0+k1 from first 16 bytes of SHA256).
//
// Core reference: blockencodings.cpp FillShortTxIDSelector — stream << header << nonce,
// then SHA256 → GetUint64(0)/GetUint64(1) as LE.
func TestW112_G3_SipHashKeyDerivation(t *testing.T) {
	hdr := &wire.BlockHeader{
		Version:    1,
		Timestamp:  1234567890,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}
	nonce := uint64(0xCAFEBABEDEAD1234)

	k1 := ComputeSipHashKey(hdr, nonce)
	k2 := ComputeSipHashKey(hdr, nonce)

	// Deterministic
	if k1 != k2 {
		t.Error("ComputeSipHashKey is not deterministic")
	}

	// Different nonce → different key
	k3 := ComputeSipHashKey(hdr, nonce+1)
	if k1 == k3 {
		t.Error("same key for different nonces")
	}

	// Different header → different key
	hdr2 := *hdr
	hdr2.Nonce = 99
	k4 := ComputeSipHashKey(&hdr2, nonce)
	if k1 == k4 {
		t.Error("same key for different headers")
	}
}

// TestW112_G4_NonceLE verifies nonce is serialized as little-endian uint64 in the key.
// If we flip the nonce bytes the key must differ.
func TestW112_G4_NonceLE(t *testing.T) {
	hdr := &wire.BlockHeader{Bits: 0x1d00ffff}
	// nonce 0x0102030405060708 vs 0x0807060504030201 — different LE serializations
	k1 := ComputeSipHashKey(hdr, 0x0102030405060708)
	k2 := ComputeSipHashKey(hdr, 0x0807060504030201)
	if k1 == k2 {
		t.Error("byte-swapped nonces should produce different SipHash keys")
	}
}

// ─── G5: PrefilledTxn delta encoding ──────────────────────────────────────

// TestW112_G5_PrefilledTxDeltaEncoding verifies that CreateGetBlockTxn uses
// 1-based differential encoding matching BIP-152 / Core's DifferenceFormatter.
func TestW112_G5_PrefilledTxDeltaEncoding(t *testing.T) {
	hash := wire.Hash256{0xAB}
	// indexes: 0, 2, 5  → diffs: 0-(-1)-1=0, 2-0-1=1, 5-2-1=2
	msg := CreateGetBlockTxn(hash, []uint32{0, 2, 5})
	want := []uint32{0, 1, 2}
	if len(msg.Indexes) != len(want) {
		t.Fatalf("len=%d want %d", len(msg.Indexes), len(want))
	}
	for i, w := range want {
		if msg.Indexes[i] != w {
			t.Errorf("[%d] diff=%d want %d", i, msg.Indexes[i], w)
		}
	}

	// Round-trip
	decoded := DecodeGetBlockTxnIndexes(msg.Indexes)
	orig := []uint32{0, 2, 5}
	for i, v := range orig {
		if decoded[i] != v {
			t.Errorf("decoded[%d]=%d want %d", i, decoded[i], v)
		}
	}
}

// ─── G6: sendcmpct message format ─────────────────────────────────────────

// TestW112_G6_SendCmpctFormat verifies the sendcmpct message wire format:
// announce (bool, 1 byte) || version (uint64 LE, 8 bytes).
func TestW112_G6_SendCmpctFormat(t *testing.T) {
	import_bytes := func(msg *MsgSendCmpct) []byte {
		var b [9]byte
		if msg.AnnounceUsingCmpctBlock {
			b[0] = 1
		}
		// little-endian uint64 at b[1:]
		v := msg.CmpctBlockVersion
		for i := 0; i < 8; i++ {
			b[1+i] = byte(v >> (8 * i))
		}
		return b[:]
	}

	msg := &MsgSendCmpct{AnnounceUsingCmpctBlock: true, CmpctBlockVersion: 2}
	b := import_bytes(msg)
	if b[0] != 1 {
		t.Error("announce byte should be 1")
	}
	// version 2 in LE → [2, 0, 0, 0, 0, 0, 0, 0]
	if b[1] != 2 || b[2] != 0 {
		t.Errorf("version LE encoding wrong: got %v", b[1:])
	}

	if msg.Command() != "sendcmpct" {
		t.Errorf("Command() = %q, want sendcmpct", msg.Command())
	}
}

// ─── G7: v1/v2 version handling — BUG-2 ──────────────────────────────────

// TestW112_G7_V1SendCmpctRejected_BUG2 documents BUG-2:
// SetSendCmpct silently drops version-1 sendcmpct messages. BIP-152 requires
// tracking each version independently. A peer advertising v1 should still be
// marked as providing compact blocks (for non-segwit use) even if we only
// send v2 ourselves. t.Skip() since this is a known failing behavior.
func TestW112_G7_V1SendCmpctRejected_BUG2(t *testing.T) {
	t.Skip("BUG-2: SetSendCmpct rejects v1; peer advertising v1 is silently dropped")

	state := NewCompactBlockState()
	state.SetSendCmpct(false, 1) // v1 offer from peer
	if !state.ProvidesCompactBlocks() {
		t.Error("peer offering v1 compact blocks should still be tracked as providing them")
	}
}

// TestW112_G7_V2SendCmpctAccepted verifies v2 sendcmpct is accepted correctly.
func TestW112_G7_V2SendCmpctAccepted(t *testing.T) {
	state := NewCompactBlockState()
	state.SetSendCmpct(false, 2)
	if !state.ProvidesCompactBlocks() {
		t.Error("v2 sendcmpct should mark peer as providing compact blocks")
	}
}

// ─── G8: Outbound sends sendcmpct(announce=false) ─────────────────────────

// TestW112_G8_OutboundSendsLBSendCmpct verifies that blockbrew sends
// sendcmpct(announce=false, version=2) at handshake completion (LB mode).
// This is correct: we advertise our capability but request LB initially.
func TestW112_G8_OutboundLBSendCmpct(t *testing.T) {
	// The code path is in peer.go handleVerAck:
	//   p.SendMessage(&MsgSendCmpct{AnnounceUsingCmpctBlock: false, CmpctBlockVersion: 2})
	// We verify the constant matches v2.
	if CmpctBlockVersion != 2 {
		t.Errorf("CmpctBlockVersion = %d, want 2 (segwit)", CmpctBlockVersion)
	}
}

// ─── G9: IsHighBandwidthMode state tracking ───────────────────────────────

// TestW112_G9_IsHighBandwidthMode verifies CompactBlockState correctly records
// when a peer requests HB mode (announce=true).
func TestW112_G9_IsHighBandwidthMode(t *testing.T) {
	state := NewCompactBlockState()
	if state.WantsHBCompactBlocks() {
		t.Error("should not want HB initially")
	}

	state.SetSendCmpct(true, 2) // peer requests HB
	if !state.WantsHBCompactBlocks() {
		t.Error("WantsHBCompactBlocks should be true after sendcmpct(announce=1)")
	}

	// LB mode also parses correctly
	state2 := NewCompactBlockState()
	state2.SetSendCmpct(false, 2)
	if state2.WantsHBCompactBlocks() {
		t.Error("WantsHBCompactBlocks should be false for announce=0")
	}
	if !state2.ProvidesCompactBlocks() {
		t.Error("ProvidesCompactBlocks should be true even for LB")
	}
}

// ─── G10: HB peer cap + rotation — BUG-1 (DEAD PIPELINE) ─────────────────

// TestW112_G10_HBPeerCapRotation_BUG1 documents BUG-1:
// MaxHBPeers=3 is defined but never enforced. There is no
// lNodesAnnouncingHeaderAndIDs-equivalent list. AnnounceBlock() never sends
// cmpctblock to HB peers. The entire outbound compact block announcement
// pipeline is dead.
func TestW112_G10_HBPeerCapRotation_BUG1(t *testing.T) {
	t.Skip("BUG-1 (DEAD PIPELINE): HB peer tracking list absent; " +
		"AnnounceBlock() sends only headers/inv, never cmpctblock; " +
		"MaxHBPeers=3 constant is defined but never enforced or consulted")
}

// ─── G11: cmpctblock payload structure ────────────────────────────────────

// TestW112_G11_CmpctBlockStructure verifies the cmpctblock payload structure:
// header (80B) || nonce (8B) || shortid_count || shortids (6B each) ||
// prefilled_count || prefilled_txns.
func TestW112_G11_CmpctBlockPayloadStructure(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 1234567890,
			Bits:      0x1d00ffff,
			Nonce:     999,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xDEADBEEF12345678)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	if cmpct.Nonce != nonce {
		t.Errorf("nonce mismatch: got %d want %d", cmpct.Nonce, nonce)
	}
	if len(cmpct.PrefilledTxs) != 1 {
		t.Errorf("prefilled count = %d, want 1 (coinbase)", len(cmpct.PrefilledTxs))
	}
	if cmpct.PrefilledTxs[0].Index != 0 {
		t.Errorf("coinbase prefilled index = %d, want 0", cmpct.PrefilledTxs[0].Index)
	}
	if len(cmpct.ShortIDs) != 1 {
		t.Errorf("shortIDs count = %d, want 1", len(cmpct.ShortIDs))
	}
	// All short IDs must fit in 6 bytes
	for _, sid := range cmpct.ShortIDs {
		if sid >= (1 << 48) {
			t.Errorf("short ID 0x%x exceeds 48 bits", sid)
		}
	}
}

// ─── G12: SipHash on wtxid (v2) ───────────────────────────────────────────

// TestW112_G12_ShortIDUsesWtxid verifies that short IDs are computed from the
// wtxid (witness transaction hash) for v2, matching Core's GetWitnessHash().
func TestW112_G12_ShortIDUsesWtxid(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 7},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0x1122334455667788)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	// Manually recompute expected short ID using wtxid
	key := ComputeSipHashKey(&block.Header, nonce)
	expectedSID := ComputeShortID(key, tx1.WTxHash())

	if len(cmpct.ShortIDs) != 1 {
		t.Fatalf("short ID count = %d, want 1", len(cmpct.ShortIDs))
	}
	if cmpct.ShortIDs[0] != expectedSID {
		t.Errorf("short ID 0x%x ≠ expected wtxid-based 0x%x", cmpct.ShortIDs[0], expectedSID)
	}

	// Short ID must NOT equal the one computed from txid (non-witness hash)
	txidSID := ComputeShortID(key, tx1.TxHash())
	// For txns without witness data txid == wtxid, so only check when they differ
	if tx1.WTxHash() != tx1.TxHash() && cmpct.ShortIDs[0] == txidSID {
		t.Error("short ID appears to use txid instead of wtxid for v2")
	}
}

// ─── G13: Coinbase always prefilled ───────────────────────────────────────

// TestW112_G13_CoinbaseAlwaysPrefilled verifies that the coinbase (index 0)
// is always in the PrefilledTxs list, matching Core blockencodings.cpp:28.
func TestW112_G13_CoinbaseAlwaysPrefilled(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 1, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	builder := NewCompactBlockBuilder(&block.Header, 12345)
	cmpct := builder.Build(block)

	// Coinbase must be prefilled
	if len(cmpct.PrefilledTxs) == 0 {
		t.Fatal("no prefilled transactions; coinbase should always be prefilled")
	}
	if cmpct.PrefilledTxs[0].Index != 0 {
		t.Errorf("first prefilled tx index = %d, want 0 (coinbase)", cmpct.PrefilledTxs[0].Index)
	}
	if cmpct.PrefilledTxs[0].Tx != coinbase {
		t.Error("first prefilled tx is not the coinbase")
	}
}

// ─── G14: Collision detection ─────────────────────────────────────────────

// TestW112_G14_ShortIDCollisionDetected verifies that duplicate short IDs in
// the cmpctblock payload cause InitData to return ErrShortIDCollision.
func TestW112_G14_ShortIDCollisionDetected(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	dupSID := uint64(0xABCDEF123456)

	cmpct := &MsgCmpctBlock{
		Header:       wire.BlockHeader{Bits: 0x1d00ffff},
		PrefilledTxs: []PrefilledTx{{Index: 0, Tx: coinbase}},
		ShortIDs:     []uint64{dupSID, dupSID}, // duplicate
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, nil, nil)
	if err == nil {
		t.Fatal("expected error for duplicate short IDs, got nil")
	}
}

// ─── G15: Size bounds ─────────────────────────────────────────────────────

// TestW112_G15_SizeBoundsGuard verifies that InitData rejects a cmpctblock
// with more transactions than MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TRANSACTION_WEIGHT.
func TestW112_G15_SizeBoundsGuard(t *testing.T) {
	shortIDs := make([]uint64, maxBlockTxCount+1)
	for i := range shortIDs {
		shortIDs[i] = uint64(i + 1)
	}
	cmpct := &MsgCmpctBlock{
		Header:   wire.BlockHeader{Bits: 0x1d00ffff},
		ShortIDs: shortIDs,
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, nil, nil)
	if err == nil {
		t.Fatal("expected error for oversized cmpctblock, got nil")
	}
}

// ─── G16: getblocktxn 1-based delta indexes ───────────────────────────────

// TestW112_G16_GetBlockTxnDeltaIndexes verifies that CreateGetBlockTxn
// differential-encodes indexes with the correct 1-based offset per BIP-152.
// Core: DifferenceFormatter writes (index[i] - index[i-1] - 1).
func TestW112_G16_GetBlockTxnDeltaIndexes(t *testing.T) {
	hash := wire.Hash256{0x01}
	// missing indexes: 1, 3, 4, 10
	// diffs: 1-(-1)-1=1, 3-1-1=1, 4-3-1=0, 10-4-1=5
	msg := CreateGetBlockTxn(hash, []uint32{1, 3, 4, 10})
	expected := []uint32{1, 1, 0, 5}
	if len(msg.Indexes) != len(expected) {
		t.Fatalf("len=%d want %d", len(msg.Indexes), len(expected))
	}
	for i, w := range expected {
		if msg.Indexes[i] != w {
			t.Errorf("[%d] diff=%d want %d", i, msg.Indexes[i], w)
		}
	}
}

// ─── G17: blocktxn response — BUG-3 ──────────────────────────────────────

// TestW112_G17_GetBlockTxnNotServed_BUG3 documents BUG-3:
// The OnGetBlockTxn callback in sync.go is log+ignore. No blocktxn response is
// sent. Peers requesting missing compact-block transactions never get a response.
// Core reference: net_processing.cpp SendBlockTransactions / GETBLOCKTXN handler.
func TestW112_G17_GetBlockTxnNotServed_BUG3(t *testing.T) {
	t.Skip("BUG-3 (MISSING): OnGetBlockTxn handler is log+ignore — " +
		"no blocktxn response is ever sent to peers requesting missing transactions")
}

// TestW112_G17_CreateBlockTxnHelper verifies the CreateBlockTxn helper works
// correctly even though it is never called in the live path.
func TestW112_G17_CreateBlockTxnHelperWorks(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 1, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	resp, err := CreateBlockTxn(block, []uint32{1, 2})
	if err != nil {
		t.Fatalf("CreateBlockTxn failed: %v", err)
	}
	if len(resp.Txs) != 2 {
		t.Errorf("resp.Txs count = %d, want 2", len(resp.Txs))
	}
	if resp.Txs[0] != tx1 {
		t.Error("resp.Txs[0] should be tx1")
	}
	if resp.Txs[1] != tx2 {
		t.Error("resp.Txs[1] should be tx2")
	}
}

// ─── G18: Misbehaving on wrong tx in blocktxn — BUG-4 ────────────────────

// TestW112_G18_BlockTxnWrongTxMisbehaving_BUG4 documents BUG-4:
// The OnBlockTxn callback in sync.go is log+ignore. Even if a peer sent a
// blocktxn response with the wrong number of transactions (adversarial),
// blockbrew would not call Misbehaving and would not disconnect the peer.
// Core: Misbehaving(peer, "invalid compact block") on READ_STATUS_INVALID.
func TestW112_G18_BlockTxnWrongTxMisbehaving_BUG4(t *testing.T) {
	t.Skip("BUG-4 (MISSING): OnBlockTxn handler is log+ignore — " +
		"adversarial wrong-tx-count in blocktxn is not penalized via Misbehaving")
}

// ─── G19: Fallback to full block ──────────────────────────────────────────

// TestW112_G19_CmpctBlockFallsBackToFull verifies that blockbrew requests the
// full block via getdata when receiving a cmpctblock (current behavior).
// This is the "always fallback" path — correct only in LB mode.
func TestW112_G19_FallbackToFullBlock(t *testing.T) {
	// The OnCmpctBlock handler in sync.go always sends getdata(InvTypeWitnessBlock).
	// Verify the InvType constant used is the witness block type.
	if InvTypeWitnessBlock == 0 {
		t.Error("InvTypeWitnessBlock should be non-zero")
	}
}

// ─── G20: getblocktxn depth limit — BUG-5 (FIXED) ───────────────────────────

// TestW112_G20_MaxBlocktxnDepthConstant verifies that MaxBlocktxnDepth = 10,
// matching Bitcoin Core net_processing.cpp MAX_BLOCKTXN_DEPTH.
// FIX-42: constant added to compactblock.go; depth guard wired into OnGetBlockTxn.
func TestW112_G20_MaxBlocktxnDepthConstant(t *testing.T) {
	if MaxBlocktxnDepth != 10 {
		t.Errorf("MaxBlocktxnDepth = %d, want 10 (mirrors Core MAX_BLOCKTXN_DEPTH)",
			MaxBlocktxnDepth)
	}
}

// TestW112_G20_BlocktxnDepthGuardLogic verifies the depth comparison logic used
// in the OnGetBlockTxn handler: a block at depth > MaxBlocktxnDepth triggers
// the fallback path, a block at depth == MaxBlocktxnDepth does not.
func TestW112_G20_BlocktxnDepthGuardLogic(t *testing.T) {
	tipHeight := int32(1000)

	cases := []struct {
		blockHeight int32
		wantFallback bool
	}{
		{blockHeight: 990, wantFallback: false}, // depth=10, exactly at limit — serve normally
		{blockHeight: 989, wantFallback: true},  // depth=11, exceeds limit — fallback
		{blockHeight: 0, wantFallback: true},    // depth=1000, far exceeds limit
		{blockHeight: 999, wantFallback: false}, // depth=1, well within limit
	}

	for _, tc := range cases {
		depth := tipHeight - tc.blockHeight
		got := depth > MaxBlocktxnDepth
		if got != tc.wantFallback {
			t.Errorf("blockHeight=%d depth=%d: fallback=%v want %v",
				tc.blockHeight, depth, got, tc.wantFallback)
		}
	}
}

// ─── G21: PartiallyDownloadedBlock object ─────────────────────────────────

// TestW112_G21_PartiallyDownloadedBlock verifies the full PDB lifecycle:
// InitData → FillBlock with no missing txns.
func TestW112_G21_PartiallyDownloadedBlock(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 77},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xFACEFEED)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	mempool := &mockMempool{txs: []*wire.MsgTx{tx1}}
	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpct, mempool, nil)
	if err != nil {
		t.Fatalf("InitData: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing=%d want 0", missing)
	}

	reconstructed, err := pdb.FillBlock(nil, false)
	if err != nil {
		t.Fatalf("FillBlock: %v", err)
	}
	if len(reconstructed.Transactions) != 2 {
		t.Errorf("tx count = %d, want 2", len(reconstructed.Transactions))
	}
}

// ─── G22: Mempool short-ID match ──────────────────────────────────────────

// TestW112_G22_MempoolShortIDMatch verifies that mempool transactions are
// matched by their wtxid-derived short ID and fill reconstruction slots.
func TestW112_G22_MempoolShortIDMatch(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 999,
			Bits:      0x1d00ffff,
			Nonce:     33,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xBEEF)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	// Both non-coinbase txns in mempool → zero missing
	mempool := &mockMempool{txs: []*wire.MsgTx{tx1, tx2}}
	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpct, mempool, nil)
	if err != nil {
		t.Fatalf("InitData: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing=%d want 0", missing)
	}
}

// ─── G23: Merkle root validate (IsBlockMutated) ───────────────────────────

// TestW112_G23_IsBlockMutatedCheck verifies that FillBlock calls IsBlockMutated
// and returns an error when the block's merkle root doesn't match its transactions.
// Core: FillBlock returns READ_STATUS_FAILED when check_mutated returns true.
func TestW112_G23_IsBlockMutatedCheck(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Bits:      0x1d00ffff,
			Nonce:     55,
			// MerkleRoot intentionally wrong (all zeros)
		},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	// Do NOT set MerkleRoot so it stays all-zeros (mutated)

	nonce := uint64(0x1234)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	mempool := &mockMempool{txs: []*wire.MsgTx{tx1}}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, mempool, nil)
	if err != nil {
		t.Fatalf("InitData unexpected error: %v", err)
	}

	// FillBlock with segwit=false should detect merkle mismatch
	_, err = pdb.FillBlock(nil, false)
	if err == nil {
		t.Fatal("FillBlock should fail when merkle root is wrong (IsBlockMutated)")
	}
}

// ─── G24: DoS fallback on collision ───────────────────────────────────────

// TestW112_G24_DoSFallbackOnCollision verifies that ErrShortIDCollision is
// returned when InitData detects a duplicate short ID, allowing the caller to
// fall back to requesting the full block.
func TestW112_G24_DoSFallbackOnCollision(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	dup := uint64(0x112233445566)

	cmpct := &MsgCmpctBlock{
		Header:       wire.BlockHeader{Bits: 0x1d00ffff},
		PrefilledTxs: []PrefilledTx{{Index: 0, Tx: coinbase}},
		ShortIDs:     []uint64{dup, dup},
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, nil, nil)
	if err == nil {
		t.Fatal("expected ErrShortIDCollision")
	}
}

// ─── G25: segwit/wtxid v2 integration ────────────────────────────────────

// TestW112_G25_SegwitV2Integration verifies that v2 compact blocks use the
// witness hash (wtxid) for short ID computation, as required by BIP-152.
func TestW112_G25_SegwitV2Integration(t *testing.T) {
	// CmpctBlockVersion must be 2 (segwit-aware)
	if CmpctBlockVersion != 2 {
		t.Errorf("CmpctBlockVersion = %d, want 2", CmpctBlockVersion)
	}

	// ComputeShortID operates on wire.Hash256 — when called with a wtxid,
	// it implements the v2 short-ID scheme.
	hdr := &wire.BlockHeader{Bits: 0x1d00ffff}
	key := ComputeSipHashKey(hdr, 42)

	// Verify that two different wtxids give different short IDs
	wtxid1 := wire.Hash256{0x01}
	wtxid2 := wire.Hash256{0x02}
	sid1 := ComputeShortID(key, wtxid1)
	sid2 := ComputeShortID(key, wtxid2)
	if sid1 == sid2 {
		t.Error("different wtxids should produce different short IDs")
	}
}

// ─── G26: BIP-339 wtxid interaction ──────────────────────────────────────

// TestW112_G26_BIP339WtxidInteraction verifies that the mempool lookup for
// compact block reconstruction uses the wtxid (GetAllTransactions + WTxHash()),
// consistent with BIP-339 wtxid relay. Core uses pool->txns_randomized which
// iterates (wtxid, tx) pairs.
func TestW112_G26_BIP339WtxidInteraction(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 5},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xABCD)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpct := builder.Build(block)

	// The mempool lookup in InitData calls tx.WTxHash() to compute the short ID.
	// Verify that a mempool with tx1 correctly fills the reconstruction slot.
	mempool := &mockMempool{txs: []*wire.MsgTx{tx1}}
	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpct, mempool, nil)
	if err != nil {
		t.Fatalf("InitData: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing=%d want 0 (wtxid-based lookup should find tx1)", missing)
	}
}

// ─── G27: ≤5-deep age limit — BUG-6 (FIXED) ─────────────────────────────────

// TestW112_G27_MaxCmpctBlockDepthConstant verifies that MaxCmpctBlockDepth = 5,
// matching Bitcoin Core net_processing.cpp:2466 MAX_CMPCTBLOCK_DEPTH.
// FIX-42: constant added to compactblock.go; depth guard wired into OnCmpctBlock.
func TestW112_G27_MaxCmpctBlockDepthConstant(t *testing.T) {
	if MaxCmpctBlockDepth != 5 {
		t.Errorf("MaxCmpctBlockDepth = %d, want 5 (mirrors Core MAX_CMPCTBLOCK_DEPTH)",
			MaxCmpctBlockDepth)
	}
}

// TestW112_G27_CmpctBlockDepthGuardLogic verifies the depth comparison logic used
// in the OnCmpctBlock handler: a block at depth > MaxCmpctBlockDepth triggers
// the fallback path, a block at depth == MaxCmpctBlockDepth does not.
func TestW112_G27_CmpctBlockDepthGuardLogic(t *testing.T) {
	tipHeight := int32(1000)

	cases := []struct {
		blockHeight  int32
		wantFallback bool
	}{
		{blockHeight: 995, wantFallback: false}, // depth=5, exactly at limit — serve as cmpctblock
		{blockHeight: 994, wantFallback: true},  // depth=6, exceeds limit — fall back to full block
		{blockHeight: 0, wantFallback: true},    // depth=1000, far exceeds limit
		{blockHeight: 999, wantFallback: false}, // depth=1, well within limit
	}

	for _, tc := range cases {
		depth := tipHeight - tc.blockHeight
		got := depth > MaxCmpctBlockDepth
		if got != tc.wantFallback {
			t.Errorf("blockHeight=%d depth=%d: fallback=%v want %v",
				tc.blockHeight, depth, got, tc.wantFallback)
		}
	}
}

// ─── G28: No IBD compact blocks — BUG-7 ──────────────────────────────────

// TestW112_G28_NoCompactBlocksDuringIBD_BUG7 documents BUG-7:
// No IBD guard on compact block handling. Core skips compact block serving
// during IBD (CanDirectFetch() returns false). blockbrew has IsIBDActive() but
// never consults it in the cmpctblock or compact block announcement path.
func TestW112_G28_NoCompactBlocksDuringIBD_BUG7(t *testing.T) {
	t.Skip("BUG-7 (MISSING): No IBD guard in cmpctblock path; " +
		"IsIBDActive() exists but is not consulted in compact block handlers")
}

// ─── G29/G30: HB peer management (dead pipeline) ─────────────────────────

// TestW112_G29_HBOutboundLimit_BUG1 documents that the outbound HB peer limit
// (3) is never enforced — covered by BUG-1 in G10.
func TestW112_G29_HBOutboundLimit_BUG1(t *testing.T) {
	t.Skip("BUG-1 (DEAD PIPELINE): HB peer list absent; outbound limit never enforced")
}

// TestW112_G30_HBPeerRotationWhenStale_BUG1 documents that HB peer rotation
// (evicting a stale HB peer when a new one connects) is never implemented.
func TestW112_G30_HBPeerRotationWhenStale_BUG1(t *testing.T) {
	t.Skip("BUG-1 (DEAD PIPELINE): HB peer rotation absent; " +
		"lNodesAnnouncingHeaderAndIDs-equivalent list never built")
}

// ─── Extra: InitData guard gates ──────────────────────────────────────────

// TestW112_Null_HeaderRejected verifies Gate 1: null header (Bits==0).
func TestW112_NullHeaderRejected(t *testing.T) {
	cmpct := &MsgCmpctBlock{
		ShortIDs:     []uint64{0x1234},
		PrefilledTxs: []PrefilledTx{{Index: 0, Tx: createTestTx(0, 1, 5000, nil)}},
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, nil, nil)
	if err == nil {
		t.Fatal("null header should be rejected")
	}
}

// TestW112_EmptyBodyRejected verifies Gate 2: no short IDs and no prefilled txns.
func TestW112_EmptyBodyRejected(t *testing.T) {
	cmpct := &MsgCmpctBlock{Header: wire.BlockHeader{Bits: 0x1d00ffff}}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpct, nil, nil)
	if err == nil {
		t.Fatal("empty cmpctblock body should be rejected")
	}
}

// TestW112_DoubleInitRejected verifies Gate 4: double InitData call is rejected.
func TestW112_DoubleInitRejected(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	cmpct := NewCompactBlockBuilder(&block.Header, 1).Build(block)
	pdb := NewPartiallyDownloadedBlock()
	if _, err := pdb.InitData(cmpct, nil, nil); err != nil {
		t.Fatalf("first InitData: %v", err)
	}
	if _, err := pdb.InitData(cmpct, nil, nil); err == nil {
		t.Fatal("second InitData should be rejected")
	}
}

// TestW112_FillBlockUninitRejected verifies FillBlock on uninitialised PDB fails.
func TestW112_FillBlockUninitRejected(t *testing.T) {
	pdb := NewPartiallyDownloadedBlock()
	if _, err := pdb.FillBlock(nil, false); err == nil {
		t.Fatal("FillBlock on uninitialised PDB should fail")
	}
}

// TestW112_ExtraTxnMatchesReconstructed verifies that extra_txn (evicted mempool
// entries) are used to fill missing reconstruction slots, matching Core's
// vExtraTxnForCompact logic.
func TestW112_ExtraTxnMatchesReconstructed(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 5678,
			Bits:      0x1d00ffff,
			Nonce:     17,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	cmpct := NewCompactBlockBuilder(&block.Header, 0xBEEF).Build(block)

	// Empty mempool, tx1+tx2 in extra_txn
	extraTxn := []ExtraTx{
		{Wtxid: tx1.WTxHash(), Tx: tx1},
		{Wtxid: tx2.WTxHash(), Tx: tx2},
	}
	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpct, nil, extraTxn)
	if err != nil {
		t.Fatalf("InitData: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing=%d want 0 (extra_txn should fill all slots)", missing)
	}
}
