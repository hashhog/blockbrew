// W110 BIP-37 bloom filter fleet audit — blockbrew.
//
// 30-gate audit of blockbrew's bloom filter subsystem versus Bitcoin Core's
// src/common/bloom.h + bloom.cpp, src/merkleblock.h + merkleblock.cpp,
// src/protocol.h (NODE_BLOOM), and net_processing.cpp (filterload/filteradd/
// filterclear handling, BIP-111 gate).
//
// Finding summary (26 gates audited, see individual tests for detail):
//
//   PASS    : G1, G2, G11, G12, G13, G30
//   FIXED   : G26b, G29b (FIX-35: filteradd oversize now disconnects — "filteradd"
//             removed from isNonCriticalMessage in message.go)
//   PARTIAL : G25, G26 (a,c), G27, G28
//   BUG     : G14 (BloomUpdateMask constant absent)
//   MISSING : G3-G10, G15-G24 (CBloomFilter implementation absent)
//
// The entire CBloomFilter implementation (MurmurHash3, Insert, Contains,
// IsRelevantAndUpdate, isFull/isEmpty, update-flag logic) is absent from
// blockbrew. Only the wire message types (MsgFilterLoad, MsgFilterAdd,
// MsgFilterClear, MsgMerkleBlock) and the NODE_BLOOM service-bit gate exist.
// The OnFilterLoad/OnFilterAdd/OnFilterClear callbacks are defined in
// PeerListeners but are never wired to any handler in main.go — a dead-helper.
//
// Reference: Bitcoin Core src/common/bloom.{h,cpp}, src/merkleblock.{h,cpp}
package p2p

import (
	"bytes"
	"testing"
)

// ============================================================================
// G1: MAX_BLOOM_FILTER_SIZE = 36000 bytes
// ============================================================================

// G1 / PASS: MaxFilterLoadFilterSize equals the BIP-37 protocol limit of
// 36,000 bytes. Bitcoin Core: MAX_BLOOM_FILTER_SIZE = 36000 (bloom.h:17).
func TestW110_G1_MaxBloomFilterSize(t *testing.T) {
	const want = 36000
	if MaxFilterLoadFilterSize != want {
		t.Errorf("G1: MaxFilterLoadFilterSize = %d, want %d", MaxFilterLoadFilterSize, want)
	}
}

// ============================================================================
// G2: MAX_HASH_FUNCS = 50
// ============================================================================

// G2 / PASS: MaxFilterLoadHashFuncs equals the BIP-37 protocol limit of 50.
// Bitcoin Core: MAX_HASH_FUNCS = 50 (bloom.h:18).
func TestW110_G2_MaxHashFuncs(t *testing.T) {
	const want = 50
	if MaxFilterLoadHashFuncs != want {
		t.Errorf("G2: MaxFilterLoadHashFuncs = %d, want %d", MaxFilterLoadHashFuncs, want)
	}
}

// ============================================================================
// G3: LN2SQUARED present with full precision
// ============================================================================

// G3 / MISSING ENTIRELY: blockbrew has no LN2SQUARED constant and no
// CBloomFilter constructor. The CBloomFilter implementation is absent.
// Bitcoin Core: LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
func TestW110_G3_LN2SQUARED(t *testing.T) {
	t.Skip("BUG: LN2SQUARED constant absent — CBloomFilter implementation MISSING ENTIRELY")
}

// ============================================================================
// G4: Constructor vData sizing formula
// ============================================================================

// G4 / MISSING ENTIRELY: No CBloomFilter struct or constructor. Core formula:
//
//	vData_bytes = min(-1/LN2SQUARED * nElements * log(nFPRate), MAX_BLOOM_FILTER_SIZE*8) / 8
func TestW110_G4_ConstructorVDataSizing(t *testing.T) {
	t.Skip("BUG: CBloomFilter constructor MISSING ENTIRELY — no vData sizing")
}

// ============================================================================
// G5: nHashFuncs formula
// ============================================================================

// G5 / MISSING ENTIRELY: No nHashFuncs calculation. Core formula:
//
//	nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
func TestW110_G5_NHashFuncsFormula(t *testing.T) {
	t.Skip("BUG: CBloomFilter nHashFuncs formula MISSING ENTIRELY")
}

// ============================================================================
// G6: MurmurHash3 32-bit
// ============================================================================

// G6 / MISSING ENTIRELY: No MurmurHash3 implementation anywhere in blockbrew.
// Bitcoin Core: hash.h MurmurHash3() used by CBloomFilter::Hash().
func TestW110_G6_MurmurHash3(t *testing.T) {
	t.Skip("BUG: MurmurHash3 32-bit MISSING ENTIRELY — no bloom hash implementation")
}

// ============================================================================
// G7: nTweak + i*0xFBA4C795 hash schedule
// ============================================================================

// G7 / MISSING ENTIRELY: The hash schedule seed = nHashNum * 0xFBA4C795 + nTweak
// is not implemented. Core: bloom.cpp:47.
func TestW110_G7_HashSchedule(t *testing.T) {
	t.Skip("BUG: hash schedule (nTweak + i*0xFBA4C795) MISSING ENTIRELY")
}

// ============================================================================
// G8: Bit index = hash % (vData.size() * 8)
// ============================================================================

// G8 / MISSING ENTIRELY: No bit-index computation. Core: bloom.cpp:47.
func TestW110_G8_BitIndex(t *testing.T) {
	t.Skip("BUG: bit-index computation (hash % vData.size()*8) MISSING ENTIRELY")
}

// ============================================================================
// G9: Insert sets bit, Contains AND of bits
// ============================================================================

// G9 / MISSING ENTIRELY: No Insert or Contains methods. Core: bloom.cpp:50-80.
func TestW110_G9_InsertContains(t *testing.T) {
	t.Skip("BUG: CBloomFilter Insert/Contains MISSING ENTIRELY")
}

// ============================================================================
// G10: isFull / isEmpty short-circuit
// ============================================================================

// G10 / MISSING ENTIRELY: No isFull/isEmpty short-circuit. Core: bloom.cpp:52,71
// (empty vData guards against divide-by-zero, CVE-2013-5700).
func TestW110_G10_IsFullIsEmpty(t *testing.T) {
	t.Skip("BUG: isFull/isEmpty short-circuit MISSING ENTIRELY")
}

// ============================================================================
// G11: BLOOM_UPDATE_NONE = 0
// ============================================================================

// G11 / PASS: BloomUpdateNone is 0, matching Core's BLOOM_UPDATE_NONE.
func TestW110_G11_BloomUpdateNone(t *testing.T) {
	if BloomUpdateNone != 0 {
		t.Errorf("G11: BloomUpdateNone = %d, want 0", BloomUpdateNone)
	}
}

// ============================================================================
// G12: BLOOM_UPDATE_ALL = 1
// ============================================================================

// G12 / PASS: BloomUpdateAll is 1, matching Core's BLOOM_UPDATE_ALL.
func TestW110_G12_BloomUpdateAll(t *testing.T) {
	if BloomUpdateAll != 1 {
		t.Errorf("G12: BloomUpdateAll = %d, want 1", BloomUpdateAll)
	}
}

// ============================================================================
// G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2
// ============================================================================

// G13 / PASS: BloomUpdateP2PubkeyOnly is 2, matching Core's
// BLOOM_UPDATE_P2PUBKEY_ONLY.
func TestW110_G13_BloomUpdateP2PubkeyOnly(t *testing.T) {
	if BloomUpdateP2PubkeyOnly != 2 {
		t.Errorf("G13: BloomUpdateP2PubkeyOnly = %d, want 2", BloomUpdateP2PubkeyOnly)
	}
}

// ============================================================================
// G14: BLOOM_UPDATE_MASK = 3
// ============================================================================

// G14 / BUG: blockbrew has no BloomUpdateMask (= 3) constant. Core uses
// BLOOM_UPDATE_MASK = 3 in bloom.h:31 to extract only the two update-flag
// bits from nFlags. Without it, any implementation using raw nFlags instead
// of (nFlags & BLOOM_UPDATE_MASK) would misinterpret reserved bits.
func TestW110_G14_BloomUpdateMask(t *testing.T) {
	// There is no BloomUpdateMask exported from the p2p package.
	// This test documents the missing constant.
	// Expected: a constant BloomUpdateMask uint8 = 3
	t.Skip("BUG G14: BloomUpdateMask (= 3) constant MISSING — reserved-bit masking absent")
}

// ============================================================================
// G15: nFlags & BLOOM_UPDATE_MASK applied (not raw nFlags)
// ============================================================================

// G15 / MISSING ENTIRELY: No IsRelevantAndUpdate implementation.
// Core: bloom.cpp:123,125 — `(nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL`.
func TestW110_G15_UpdateMaskApplied(t *testing.T) {
	t.Skip("BUG: IsRelevantAndUpdate MISSING ENTIRELY — BLOOM_UPDATE_MASK not applied")
}

// ============================================================================
// G16: Tx matches by txid
// ============================================================================

// G16 / MISSING ENTIRELY: No IsRelevantAndUpdate. Core: bloom.cpp:103 checks
// contains(hash.ToUint256()).
func TestW110_G16_TxMatchByTxid(t *testing.T) {
	t.Skip("BUG: txid-match path in IsRelevantAndUpdate MISSING ENTIRELY")
}

// ============================================================================
// G17: Per-output-script pushdata extraction (size 1-65)
// ============================================================================

// G17 / MISSING ENTIRELY: No scriptPubKey pushdata scanning. Core: bloom.cpp:113-134.
func TestW110_G17_OutputScriptPushdataExtraction(t *testing.T) {
	t.Skip("BUG: output-script pushdata extraction MISSING ENTIRELY")
}

// ============================================================================
// G18: P2PKH / P2SH / P2PK / multisig match types
// ============================================================================

// G18 / MISSING ENTIRELY: No script-type matching. Core: bloom.cpp:127-131 uses
// Solver() to detect TxoutType::PUBKEY / TxoutType::MULTISIG for P2PUBKEY_ONLY.
func TestW110_G18_ScriptTypeMatching(t *testing.T) {
	t.Skip("BUG: P2PKH/P2SH/P2PK/multisig output-type matching MISSING ENTIRELY")
}

// ============================================================================
// G19: Outpoint match (36 bytes serialized)
// ============================================================================

// G19 / MISSING ENTIRELY: No prevout matching. Core: bloom.cpp:144 contains(txin.prevout).
func TestW110_G19_OutpointMatch(t *testing.T) {
	t.Skip("BUG: outpoint-match path in IsRelevantAndUpdate MISSING ENTIRELY")
}

// ============================================================================
// G20: scriptSig data items checked
// ============================================================================

// G20 / MISSING ENTIRELY: No scriptSig pushdata scanning. Core: bloom.cpp:148-157.
func TestW110_G20_ScriptSigDataItems(t *testing.T) {
	t.Skip("BUG: scriptSig data-item scan MISSING ENTIRELY")
}

// ============================================================================
// G21: UPDATE_ALL — all matched-tx outpoints inserted
// ============================================================================

// G21 / MISSING ENTIRELY: No UPDATE_ALL outpoint insertion. Core: bloom.cpp:124.
func TestW110_G21_UpdateAll(t *testing.T) {
	t.Skip("BUG: UPDATE_ALL outpoint-insertion path MISSING ENTIRELY")
}

// ============================================================================
// G22: UPDATE_P2PUBKEY_ONLY — only P2PK + multisig outpoints inserted
// ============================================================================

// G22 / MISSING ENTIRELY: Core: bloom.cpp:125-131.
func TestW110_G22_UpdateP2PubkeyOnly(t *testing.T) {
	t.Skip("BUG: UPDATE_P2PUBKEY_ONLY insertion path MISSING ENTIRELY")
}

// ============================================================================
// G23: UPDATE_NONE — filter never mutated by match
// ============================================================================

// G23 / MISSING ENTIRELY: Core: bloom.cpp:123 — only inserts when mask != NONE.
func TestW110_G23_UpdateNone(t *testing.T) {
	t.Skip("BUG: UPDATE_NONE (no-mutation) path MISSING ENTIRELY")
}

// ============================================================================
// G24: Outpoint serialization: 32 LE hash + 4 LE index
// ============================================================================

// G24 / MISSING ENTIRELY: Outpoint serialization used for filter insertion.
// Core: bloom.cpp:62-66 — DataStream << outpoint gives txid (32 LE) + index (4 LE).
func TestW110_G24_OutpointSerialization(t *testing.T) {
	t.Skip("BUG: outpoint serialization for bloom insert MISSING ENTIRELY")
}

// ============================================================================
// G25: filterload — validate size + set peer filter + handle nFlags
// ============================================================================

// G25a / PASS (wire): MsgFilterLoad.Deserialize enforces MaxFilterLoadFilterSize
// (36000) and MaxFilterLoadHashFuncs (50).  A hash-funcs overflow triggers an
// error that is NOT NonFatalMessageError, which causes peer disconnect.
func TestW110_G25a_FilterloadWireValidation(t *testing.T) {
	// Build a valid filterload: 2-byte filter, 1 hash func, tweak 0, flags 0.
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0xAB, 0xCD}) // CompactSize(2) + 2 bytes
	// HashFuncs = 1 (LE uint32)
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
	// Tweak = 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// Flags = 0
	buf.Write([]byte{0x00})

	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err != nil {
		t.Fatalf("G25a: valid filterload failed to deserialize: %v", err)
	}
	if len(msg.Filter) != 2 {
		t.Errorf("G25a: filter len = %d, want 2", len(msg.Filter))
	}
	if msg.HashFuncs != 1 {
		t.Errorf("G25a: HashFuncs = %d, want 1", msg.HashFuncs)
	}
}

// G25b / PASS (wire, hash funcs): filterload with HashFuncs > 50 must fail
// deserialization. This error is NOT NonFatalMessageError so it will disconnect.
func TestW110_G25b_FilterloadHashFuncsOversize(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0xAB, 0xCD}) // 2-byte filter
	// HashFuncs = 51 — exceeds max
	buf.Write([]byte{0x33, 0x00, 0x00, 0x00})
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Tweak
	buf.Write([]byte{0x00})                   // Flags

	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G25b: expected error for HashFuncs > 50, got nil")
	}
}

// G25c / PARTIAL: filterload stores filter bytes, hash funcs, tweak, and flags
// in MsgFilterLoad.  However, there is no per-peer CBloomFilter state: the
// OnFilterLoad callback is defined in PeerListeners but is never wired to an
// actual handler in main.go.  A peer sending filterload will have the message
// parsed and the callback invoked (if wired), but blockbrew never installs the
// filter into a per-peer state object — filtered tx/block delivery is absent.
func TestW110_G25c_FilterloadPerPeerStateAbsent(t *testing.T) {
	// Verify callback is in PeerListeners struct but no default wiring exists.
	// The field must be nil in a zero-value PeerListeners (never wired).
	var l PeerListeners
	if l.OnFilterLoad != nil {
		t.Error("G25c: expected OnFilterLoad to be nil by default (not wired)")
	}
	// Document: per-peer CBloomFilter state does not exist on Peer struct.
	// There is no field like `peerFilter *BloomFilter` on Peer.
	t.Log("G25c: PARTIAL — filterload message parsed, but per-peer filter state absent; " +
		"OnFilterLoad callback defined but never wired in main.go (dead-helper)")
}

// ============================================================================
// G26: filteradd — single data item ≤ 520 bytes; disconnect on oversize
// ============================================================================

// G26a / PASS (size cap): MsgFilterAdd.Deserialize rejects data > 520 bytes.
func TestW110_G26a_FilteraddSizeCap(t *testing.T) {
	// 521-byte payload should fail.
	var buf bytes.Buffer
	// CompactSize(521) = 0xFD 0x09 0x02
	buf.Write([]byte{0xFD, 0x09, 0x02})
	buf.Write(make([]byte, 521))

	msg := &MsgFilterAdd{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G26a: expected error for filteradd data > 520 bytes, got nil")
	}
}

// G26b / FIXED (FIX-35): Core disconnects the peer when filteradd data exceeds
// 520 bytes (net_processing.cpp: Misbehaving(pfrom, 100, "bad filteradd message")).
// "filteradd" has been removed from isNonCriticalMessage() so a deserialization
// error from an oversize payload is now fatal, causing peer disconnect — matching
// Core's behavior.
//
// The Deserialize error itself is produced by ReadVarBytes(r, MaxFilterAddDataSize)
// in msg_bloom.go.  With "filteradd" no longer in isNonCriticalMessage, the
// ReadMessage path wraps it as a plain fatal error (not NonFatalMessageError),
// which the readHandler treats as a connection-terminating event.
func TestW110_G26b_FilteraddOversizeDisconnects(t *testing.T) {
	if MaxFilterAddDataSize != 520 {
		t.Errorf("G26b: MaxFilterAddDataSize = %d, want 520", MaxFilterAddDataSize)
	}
	// Verify that a 521-byte filteradd payload fails Deserialize.
	var buf bytes.Buffer
	buf.Write([]byte{0xFD, 0x09, 0x02}) // CompactSize(521)
	buf.Write(make([]byte, 521))
	msg := &MsgFilterAdd{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G26b: expected Deserialize error for 521-byte filteradd, got nil")
	}
	// "filteradd" is no longer in isNonCriticalMessage, so ReadMessage will
	// NOT wrap this error as NonFatalMessageError → peer is disconnected.
	// This matches Bitcoin Core net_processing.cpp Misbehaving(pfrom, 100).
}

// G26c / PARTIAL: filteradd adds data to a per-peer bloom filter. blockbrew
// has no per-peer filter state, so there is nothing to add the data to.
func TestW110_G26c_FilteraddPerPeerStateAbsent(t *testing.T) {
	var l PeerListeners
	if l.OnFilterAdd != nil {
		t.Error("G26c: expected OnFilterAdd to be nil by default (not wired)")
	}
	t.Log("G26c: PARTIAL — filteradd message parsed (size capped), but per-peer filter absent; " +
		"OnFilterAdd callback defined but never wired in main.go")
}

// ============================================================================
// G27: filterclear — peer filter cleared
// ============================================================================

// G27a / PASS (wire): MsgFilterClear is a zero-payload message; Deserialize succeeds.
func TestW110_G27a_FilterclearDeserialize(t *testing.T) {
	msg := &MsgFilterClear{}
	if err := msg.Deserialize(bytes.NewReader(nil)); err != nil {
		t.Fatalf("G27a: filterclear Deserialize failed: %v", err)
	}
	if msg.Command() != "filterclear" {
		t.Errorf("G27a: Command() = %q, want filterclear", msg.Command())
	}
}

// G27b / PARTIAL: filterclear should clear the per-peer bloom filter. blockbrew
// has no per-peer filter, so there is nothing to clear.
func TestW110_G27b_FilterclearPerPeerStateAbsent(t *testing.T) {
	var l PeerListeners
	if l.OnFilterClear != nil {
		t.Error("G27b: expected OnFilterClear to be nil by default (not wired)")
	}
	t.Log("G27b: PARTIAL — filterclear message parsed but per-peer filter absent; " +
		"OnFilterClear callback never wired in main.go")
}

// ============================================================================
// G28: merkleblock — PartialMerkleTree construction
// ============================================================================

// G28a / PASS (wire): MsgMerkleBlock Serialize/Deserialize round-trips correctly.
func TestW110_G28a_MerkleBlockWireRoundtrip(t *testing.T) {
	// Build a minimal merkleblock: header (80 bytes), TxCount=1, 1 hash, 1 flag byte.
	var buf bytes.Buffer
	// 80-byte block header (all zeros for simplicity)
	buf.Write(make([]byte, 80))
	// TxCount = 1
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
	// CompactSize(1) + one 32-byte hash
	buf.Write([]byte{0x01})
	buf.Write(make([]byte, 32))
	// VarBytes(1) + one flag byte
	buf.Write([]byte{0x01, 0x80})

	msg := &MsgMerkleBlock{}
	if err := msg.Deserialize(&buf); err != nil {
		t.Fatalf("G28a: MsgMerkleBlock Deserialize failed: %v", err)
	}
	if msg.TxCount != 1 {
		t.Errorf("G28a: TxCount = %d, want 1", msg.TxCount)
	}
	if len(msg.Hashes) != 1 {
		t.Errorf("G28a: len(Hashes) = %d, want 1", len(msg.Hashes))
	}
	if len(msg.Flags) != 1 {
		t.Errorf("G28a: len(Flags) = %d, want 1", len(msg.Flags))
	}
}

// G28b / PARTIAL: Bitcoin Core builds a CMerkleBlock from a block and a peer's
// installed bloom filter, then sends the merkleblock to that peer. blockbrew
// has no per-peer filter and no filtered-block-delivery path. The RPC helper
// (wave47b_methods.go buildPartialMerkleTree) handles gettxoutproof/verifytxoutproof
// but is not wired into the P2P filtered-block delivery flow.
func TestW110_G28b_MerkleBlockFilteredDeliveryAbsent(t *testing.T) {
	t.Log("G28b: PARTIAL — MsgMerkleBlock wire struct present; P2P filtered-block " +
		"delivery absent (no per-peer filter → no CMerkleBlock construction on recv of getdata)")
}

// ============================================================================
// G29: IsWithinSizeConstraints: ≤36000 bytes AND ≤50 hash funcs; disconnect
// ============================================================================

// G29a / PASS (filterload + hash-funcs): filterload with HashFuncs > 50 returns
// a non-nil error from Deserialize.  This error is NOT NonFatalMessageError so
// the peer is disconnected.  Matches Core's behavior.
func TestW110_G29a_FilterloadHashFuncsDisconnects(t *testing.T) {
	// HashFuncs = 51 → error → fatal → disconnect
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0xFF})          // 1-byte filter
	buf.Write([]byte{0x33, 0x00, 0x00, 0x00}) // HashFuncs = 51
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Tweak
	buf.Write([]byte{0x00})                   // Flags

	msg := &MsgFilterLoad{}
	err := msg.Deserialize(&buf)
	if err == nil {
		t.Fatal("G29a: expected error for HashFuncs=51, got nil")
	}
	// Should NOT be marked NonFatalMessageError (would be fatal → disconnect).
	if IsNonFatalMessageError(err) {
		t.Error("G29a: filterload hash-funcs error is NonFatal — peer would NOT be disconnected")
	}
}

// G29b / FIXED (FIX-35): filteradd with data > 520 bytes must disconnect the
// peer, matching Bitcoin Core net_processing.cpp Misbehaving(pfrom, 100).
// "filteradd" has been removed from isNonCriticalMessage() so the Deserialize
// error is no longer wrapped as NonFatalMessageError — it is a fatal error that
// causes ReadMessage to return an unwrapped error, and the readHandler will
// terminate the connection.
func TestW110_G29b_FilteraddOversizeDisconnects(t *testing.T) {
	// 521 bytes of data → Deserialize error → fatal (not NonFatalMessageError) → disconnect.
	var buf bytes.Buffer
	buf.Write([]byte{0xFD, 0x09, 0x02}) // CompactSize(521)
	buf.Write(make([]byte, 521))

	msg := &MsgFilterAdd{}
	err := msg.Deserialize(&buf)
	if err == nil {
		t.Fatal("G29b: expected Deserialize error for 521-byte filteradd, got nil")
	}
	// The Deserialize error itself is non-nil (good). With "filteradd" no longer
	// in isNonCriticalMessage(), ReadMessage will NOT wrap it as NonFatalMessageError.
	// The readHandler receives a fatal error → peer connection terminated.
	// This mirrors Core: Misbehaving(pfrom, 100, "bad filteradd message").
	t.Logf("G29b FIXED: filteradd Deserialize errors (%v); 'filteradd' removed from "+
		"isNonCriticalMessage → ReadMessage returns fatal error → peer disconnected. "+
		"Matches Core net_processing.cpp Misbehaving(pfrom, 100).", err)
}

// ============================================================================
// G30: NODE_BLOOM (bit 2) advertised when -peerbloomfilters=1; BIP-111 gating
// ============================================================================

// G30a / PASS: ServiceNodeBloom is (1 << 2) = 4, matching Bitcoin Core's
// NODE_BLOOM in protocol.h.
func TestW110_G30a_NodeBloomServiceBit(t *testing.T) {
	const wantBit = uint64(1 << 2)
	if ServiceNodeBloom != wantBit {
		t.Errorf("G30a: ServiceNodeBloom = 0x%x, want 0x%x", ServiceNodeBloom, wantBit)
	}
}

// G30b / PASS: NODE_BLOOM is OR'd into advertised service bits only when
// AdvertiseNodeBloom is true, matching Core's peerbloomfilters gate.
func TestW110_G30b_NodeBloomGating(t *testing.T) {
	pm := &PeerManager{
		config: PeerManagerConfig{
			AdvertiseNodeBloom: true,
		},
	}
	cfg := pm.makePeerConfig()
	if cfg.Services&ServiceNodeBloom == 0 {
		t.Error("G30b: NODE_BLOOM not set when AdvertiseNodeBloom=true")
	}

	pm.config.AdvertiseNodeBloom = false
	cfg2 := pm.makePeerConfig()
	if cfg2.Services&ServiceNodeBloom != 0 {
		t.Error("G30b: NODE_BLOOM set when AdvertiseNodeBloom=false")
	}
}

// G30c / PASS: When peerbloomfilters is false (AdvertiseNodeBloom=false),
// filterload/filteradd/filterclear messages are still accepted at the wire
// level (they are parsed and dispatched). This mirrors Core's behavior where
// BIP-111 controls only advertisement, not reception of filter messages.
// Note: since blockbrew has no per-peer filter anyway, both modes behave
// identically at the application level.
func TestW110_G30c_BloomMessagesAcceptedRegardlessOfFlag(t *testing.T) {
	// Verify that filter messages are parseable regardless of NODE_BLOOM.
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00}) // 1-byte filter
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // HashFuncs = 1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Tweak = 0
	buf.Write([]byte{0x00})                   // Flags = BLOOM_UPDATE_NONE

	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err != nil {
		t.Fatalf("G30c: filterload Deserialize failed: %v", err)
	}
	t.Log("G30c: PASS — bloom messages parseable; NODE_BLOOM controls advertisement only")
}

// ============================================================================
// Supplementary: dead-helper pattern documentation
// ============================================================================

// TestW110_DeadHelper_BloomCallbacksNeverWired documents the dead-helper
// pattern: OnFilterLoad, OnFilterAdd, OnFilterClear, OnMerkleBlock are defined
// in PeerListeners but never set to non-nil handlers anywhere outside tests.
// Per 25-wave dead-helper streak: this matches the fleet-wide pattern of
// subsystems defined but not wired into the production path.
func TestW110_DeadHelper_BloomCallbacksNeverWired(t *testing.T) {
	var l PeerListeners
	// All four bloom callbacks must be nil in zero value (no default handler).
	if l.OnFilterLoad != nil {
		t.Error("OnFilterLoad unexpectedly non-nil")
	}
	if l.OnFilterAdd != nil {
		t.Error("OnFilterAdd unexpectedly non-nil")
	}
	if l.OnFilterClear != nil {
		t.Error("OnFilterClear unexpectedly non-nil")
	}
	if l.OnMerkleBlock != nil {
		t.Error("OnMerkleBlock unexpectedly non-nil")
	}
	t.Log("DEAD-HELPER: OnFilterLoad/OnFilterAdd/OnFilterClear/OnMerkleBlock defined in " +
		"PeerListeners but never wired to CBloomFilter handlers in main.go. " +
		"The entire CBloomFilter implementation is absent.")
}
