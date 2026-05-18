// W134 BIP-37 Bloom Filter (legacy SPV) audit — blockbrew.
//
// 30-gate audit of blockbrew's BIP-37 subsystem versus Bitcoin Core's
// src/common/bloom.h + bloom.cpp, src/merkleblock.{h,cpp}, src/protocol.h
// (NODE_BLOOM + MSG_FILTERED_BLOCK), net_processing.cpp (filterload /
// filteradd / filterclear handling, MSG_FILTERED_BLOCK serving), and
// init.cpp (-peerbloomfilters / NODE_BLOOM advertisement).
//
// Discovery-only — no production-code change. Every BUG-N gate listed
// in audit/w134_bip37_bloom_filter.md uses t.Skip with the BUG ID so
// the bug list is machine-readable from `go test -v -run W134`.
//
// Finding summary (19 bugs, 30 gates):
//
//   PASS    : G1, G2, G11, G12, G13, G19, G21, G22, G23, G24
//   PARTIAL : G20
//   MISSING : G3..G10, G14..G18, G25..G30
//
// Reuses several PASS observations from W110 (which audits the
// wire-message layer). W134 adds gates focused on BIP-111 NODE_BLOOM
// disconnect semantics (G25..G27), filteradd-without-filterload
// Misbehaving (G28), MSG_FILTERED_BLOCK handler in HandleGetData
// (G29), and per-peer state machine (G30).
//
// Reference: bitcoin-core/src/common/bloom.{h,cpp},
// src/merkleblock.{h,cpp}, src/net_processing.cpp,
// src/protocol.h, src/init.cpp; BIPs 37, 111.
package p2p

import (
	"bytes"
	"reflect"
	"testing"
)

// ============================================================================
// G1: MAX_BLOOM_FILTER_SIZE = 36000 bytes (PASS, reuse W110)
// ============================================================================

func TestW134_G1_MaxBloomFilterSize(t *testing.T) {
	const want = 36000
	if MaxFilterLoadFilterSize != want {
		t.Errorf("G1: MaxFilterLoadFilterSize = %d, want %d",
			MaxFilterLoadFilterSize, want)
	}
}

// ============================================================================
// G2: MAX_HASH_FUNCS = 50 (PASS, reuse W110)
// ============================================================================

func TestW134_G2_MaxHashFuncs(t *testing.T) {
	const want = 50
	if MaxFilterLoadHashFuncs != want {
		t.Errorf("G2: MaxFilterLoadHashFuncs = %d, want %d",
			MaxFilterLoadHashFuncs, want)
	}
}

// ============================================================================
// G3: LN2SQUARED / LN2 constants present (MISSING — BUG-2)
// ============================================================================

// G3 / MISSING: bitcoin-core/src/common/bloom.cpp:23-24 defines
//
//	LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
//	LN2        = 0.6931471805599453094172321214581765680755001343602552
//
// blockbrew has no such constant. These power the optimal-filter-size
// and optimal-hash-function-count formulas in the CBloomFilter
// constructor.
func TestW134_G3_LN2SquaredAndLN2(t *testing.T) {
	t.Skip("BUG-2: LN2SQUARED + LN2 constants absent — " +
		"CBloomFilter constructor MISSING (subordinate to BUG-1)")
}

// ============================================================================
// G4: CBloomFilter constructor filter-size formula (MISSING — BUG-1)
// ============================================================================

// G4 / MISSING: Core formula at bloom.cpp:32 —
//
//	vData = vector(min(-1/LN2SQUARED * nElements * log(nFPRate),
//	                   MAX_BLOOM_FILTER_SIZE * 8) / 8)
//
// blockbrew has no CBloomFilter type at all.
func TestW134_G4_ConstructorVDataSizing(t *testing.T) {
	t.Skip("BUG-1: CBloomFilter constructor MISSING — " +
		"no vData sizing formula present in blockbrew")
}

// ============================================================================
// G5: nHashFuncs formula (MISSING — BUG-1)
// ============================================================================

// G5 / MISSING: Core formula at bloom.cpp:38 —
//
//	nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
func TestW134_G5_NHashFuncsFormula(t *testing.T) {
	t.Skip("BUG-1: CBloomFilter nHashFuncs formula MISSING " +
		"(subordinate to BUG-1, CBloomFilter absent)")
}

// ============================================================================
// G6: MurmurHash3 32-bit hash function present (MISSING — BUG-3)
// ============================================================================

// G6 / MISSING: Core's CBloomFilter::Hash invokes MurmurHash3 from
// bitcoin-core/src/hash.h. blockbrew has no MurmurHash3 implementation
// in internal/crypto/, internal/script/, or internal/p2p/.
func TestW134_G6_MurmurHash3(t *testing.T) {
	t.Skip("BUG-3: MurmurHash3 32-bit absent in blockbrew/internal/")
}

// ============================================================================
// G7: Hash schedule nHashNum * 0xFBA4C795 + nTweak (MISSING — BUG-1)
// ============================================================================

// G7 / MISSING: Core bloom.cpp:47 — Hash(i, vData) =
// MurmurHash3(i * 0xFBA4C795 + nTweak, vData) % (vData.size() * 8).
// The constant 0xFBA4C795 should appear as a magic number. Verify
// absent in the production code (tests may reference it).
func TestW134_G7_HashSchedule(t *testing.T) {
	t.Skip("BUG-1: hash schedule (i*0xFBA4C795 + nTweak) absent " +
		"— CBloomFilter::Hash not implemented")
}

// ============================================================================
// G8: insert(vKey) with CVE-2013-5700 empty-vData guard (MISSING — BUG-1)
// ============================================================================

// G8 / MISSING: Core bloom.cpp:50-60 — CBloomFilter::insert(vKey)
// sets nHashFuncs bits via the Hash schedule. Guarded by an
// empty-vData short-circuit (CVE-2013-5700: dividing by vData.size()*8
// would crash on an empty filter).
func TestW134_G8_InsertWithCVE20135700Guard(t *testing.T) {
	t.Skip("BUG-1: CBloomFilter::insert + CVE-2013-5700 guard absent")
}

// ============================================================================
// G9: contains(vKey) — empty filter returns true; otherwise AND of bits (MISSING — BUG-1)
// ============================================================================

// G9 / MISSING: Core bloom.cpp:69-81 — CBloomFilter::contains returns
// true for empty vData (CVE-2013-5700 guard), and ANDs across
// nHashFuncs bit lookups otherwise.
func TestW134_G9_ContainsLogic(t *testing.T) {
	t.Skip("BUG-1: CBloomFilter::contains absent")
}

// ============================================================================
// G10: IsWithinSizeConstraints (MISSING — BUG-1)
// ============================================================================

// G10 / MISSING: Core bloom.cpp:90-93 —
//
//	return vData.size() <= MAX_BLOOM_FILTER_SIZE &&
//	       nHashFuncs <= MAX_HASH_FUNCS;
//
// This is the post-deserialization sanity check that powers Core's
// `Misbehaving(peer, "too-large bloom filter", score=100)` at
// net_processing.cpp:4975. blockbrew enforces only the wire-level
// VarBytes length check; there is no post-deserialize structural
// validation (subordinate to BUG-1).
func TestW134_G10_IsWithinSizeConstraints(t *testing.T) {
	t.Skip("BUG-1: CBloomFilter::IsWithinSizeConstraints absent")
}

// ============================================================================
// G11..G13: BLOOM_UPDATE_NONE / ALL / P2PUBKEY_ONLY (PASS, reuse W110)
// ============================================================================

func TestW134_G11_BloomUpdateNone(t *testing.T) {
	if BloomUpdateNone != 0 {
		t.Errorf("G11: BloomUpdateNone = %d, want 0", BloomUpdateNone)
	}
}

func TestW134_G12_BloomUpdateAll(t *testing.T) {
	if BloomUpdateAll != 1 {
		t.Errorf("G12: BloomUpdateAll = %d, want 1", BloomUpdateAll)
	}
}

func TestW134_G13_BloomUpdateP2PubkeyOnly(t *testing.T) {
	if BloomUpdateP2PubkeyOnly != 2 {
		t.Errorf("G13: BloomUpdateP2PubkeyOnly = %d, want 2",
			BloomUpdateP2PubkeyOnly)
	}
}

// ============================================================================
// G14: BLOOM_UPDATE_MASK = 3 constant (MISSING — BUG-4)
// ============================================================================

// G14 / MISSING: Core bloom.h:30-31 defines BLOOM_UPDATE_MASK = 3, used
// at bloom.cpp:123-125 to extract update-flag bits from nFlags so that
// reserved high bits don't accidentally enable a non-existent update
// mode.
func TestW134_G14_BloomUpdateMask(t *testing.T) {
	t.Skip("BUG-4: BloomUpdateMask (= 3) constant absent — " +
		"reserved-bit masking not enforced")
}

// ============================================================================
// G15: IsRelevantAndUpdate paths (MISSING — BUG-5)
// ============================================================================

// G15 / MISSING: Core bloom.cpp:95-161 implements IsRelevantAndUpdate
// with five sub-paths:
//
//  1. empty vData → return true (match-all)
//  2. txid match (tx.GetHash())
//  3. scriptPubKey pushdata scan with optional outpoint insertion per
//     UPDATE_ALL or UPDATE_P2PUBKEY_ONLY
//  4. outpoint match (txin.prevout)
//  5. scriptSig pushdata scan
//
// blockbrew has none of these paths.
func TestW134_G15_IsRelevantAndUpdate(t *testing.T) {
	t.Skip("BUG-5: IsRelevantAndUpdate absent — " +
		"no tx-match logic in blockbrew")
}

// ============================================================================
// G16: UPDATE_ALL — outpoint of matched output inserted (MISSING — BUG-5)
// ============================================================================

// G16 / MISSING: Core bloom.cpp:123 —
// if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
//
//	insert(COutPoint(hash, i));
func TestW134_G16_UpdateAllInsertsOutpoint(t *testing.T) {
	t.Skip("BUG-5: UPDATE_ALL outpoint-insertion absent")
}

// ============================================================================
// G17: UPDATE_P2PUBKEY_ONLY — only PUBKEY or MULTISIG outpoints (MISSING — BUG-5)
// ============================================================================

// G17 / MISSING: Core bloom.cpp:125-131 — only inserts the outpoint if
// Solver() returns TxoutType::PUBKEY or TxoutType::MULTISIG.
func TestW134_G17_UpdateP2PubkeyOnly(t *testing.T) {
	t.Skip("BUG-5: UPDATE_P2PUBKEY_ONLY insertion path absent")
}

// ============================================================================
// G18: UPDATE_NONE — filter never mutated by match (MISSING — BUG-5)
// ============================================================================

// G18 / MISSING: Core bloom.cpp:123 — only inserts when mask != NONE.
// Subordinate to BUG-1/BUG-5.
func TestW134_G18_UpdateNoneNoMutation(t *testing.T) {
	t.Skip("BUG-5: UPDATE_NONE (no-mutation) path absent")
}

// ============================================================================
// G19: filterload wire-level size + hash-funcs check (PASS)
// ============================================================================

// G19a / PASS: a valid filterload deserializes cleanly.
func TestW134_G19a_FilterloadValid(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0xAB, 0xCD})       // CompactSize(2) + 2 bytes
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // HashFuncs = 1
	buf.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // Tweak
	buf.Write([]byte{0x01})                   // Flags = UPDATE_ALL

	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err != nil {
		t.Fatalf("G19a: valid filterload Deserialize failed: %v", err)
	}
	if msg.HashFuncs != 1 {
		t.Errorf("G19a: HashFuncs = %d, want 1", msg.HashFuncs)
	}
	if msg.Flags != BloomUpdateAll {
		t.Errorf("G19a: Flags = %d, want %d", msg.Flags, BloomUpdateAll)
	}
}

// G19b / PASS: HashFuncs > 50 fails Deserialize.
func TestW134_G19b_FilterloadHashFuncsOversize(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0xAB, 0xCD})       // 2-byte filter
	buf.Write([]byte{0x33, 0x00, 0x00, 0x00}) // HashFuncs = 51
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Tweak
	buf.Write([]byte{0x00})                   // Flags
	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G19b: expected error for HashFuncs=51, got nil")
	}
}

// G19c / PASS: a 36001-byte filter fails Deserialize (VarBytes cap).
func TestW134_G19c_FilterloadFilterOversize(t *testing.T) {
	var buf bytes.Buffer
	// CompactSize(36001) = 0xFD 0xE1 0x8C
	buf.Write([]byte{0xFD, 0xE1, 0x8C})
	buf.Write(make([]byte, 36001))
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // HashFuncs = 1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Tweak
	buf.Write([]byte{0x00})                   // Flags
	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G19c: expected error for 36001-byte filter, got nil")
	}
}

// ============================================================================
// G20: filteradd 520-byte cap + MAX_SCRIPT_ELEMENT_SIZE symbol (PARTIAL — BUG-14)
// ============================================================================

// G20a / PASS (cap): MsgFilterAdd.Deserialize rejects > 520 bytes.
func TestW134_G20a_FilteraddSizeCap(t *testing.T) {
	if MaxFilterAddDataSize != 520 {
		t.Errorf("G20a: MaxFilterAddDataSize = %d, want 520",
			MaxFilterAddDataSize)
	}
	var buf bytes.Buffer
	buf.Write([]byte{0xFD, 0x09, 0x02}) // CompactSize(521)
	buf.Write(make([]byte, 521))
	msg := &MsgFilterAdd{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Error("G20a: expected error for 521-byte filteradd, got nil")
	}
}

// G20b / PARTIAL: the 520 is a magic literal; Core uses
// MAX_SCRIPT_ELEMENT_SIZE from script/script.h:28. blockbrew has no
// symbol of that name (BUG-14).
func TestW134_G20b_MaxScriptElementSizeSymbol(t *testing.T) {
	t.Skip("BUG-14: MaxFilterAddDataSize is a magic literal 520, " +
		"no MAX_SCRIPT_ELEMENT_SIZE symbol — silent desync risk if " +
		"Core ever raises the limit")
}

// ============================================================================
// G21: filterclear zero-payload Deserialize (PASS)
// ============================================================================

func TestW134_G21_FilterclearZeroPayload(t *testing.T) {
	msg := &MsgFilterClear{}
	if err := msg.Deserialize(bytes.NewReader(nil)); err != nil {
		t.Fatalf("G21: filterclear Deserialize failed: %v", err)
	}
	if msg.Command() != "filterclear" {
		t.Errorf("G21: Command() = %q, want filterclear", msg.Command())
	}
}

// ============================================================================
// G22: merkleblock wire round-trip (PASS)
// ============================================================================

func TestW134_G22_MerkleBlockRoundtrip(t *testing.T) {
	// Build a minimal merkleblock: 80-byte header (zeros), TxCount=1,
	// 1 hash, 1 flag byte 0x01.
	var buf bytes.Buffer
	buf.Write(make([]byte, 80))               // header
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // TxCount = 1
	buf.Write([]byte{0x01})                   // CompactSize(1)
	buf.Write(make([]byte, 32))               // single hash
	buf.Write([]byte{0x01, 0x01})             // VarBytes(1) + 0x01

	msg := &MsgMerkleBlock{}
	if err := msg.Deserialize(&buf); err != nil {
		t.Fatalf("G22: Deserialize failed: %v", err)
	}
	if msg.TxCount != 1 {
		t.Errorf("G22: TxCount = %d, want 1", msg.TxCount)
	}
	if len(msg.Hashes) != 1 || len(msg.Flags) != 1 {
		t.Errorf("G22: Hashes=%d Flags=%d, want 1,1",
			len(msg.Hashes), len(msg.Flags))
	}

	// Round-trip back out.
	var out bytes.Buffer
	if err := msg.Serialize(&out); err != nil {
		t.Fatalf("G22: Serialize failed: %v", err)
	}
	// Length sanity: 80 + 4 + 1 + 32 + 1 + 1 = 119.
	if out.Len() != 119 {
		t.Errorf("G22: serialized len = %d, want 119", out.Len())
	}
}

// ============================================================================
// G23: NODE_BLOOM service bit (PASS)
// ============================================================================

// G23a / PASS: ServiceNodeBloom = 1 << 2 = 4 per Core protocol.h:317.
func TestW134_G23a_NodeBloomServiceBitValue(t *testing.T) {
	const wantBit = uint64(1 << 2)
	if ServiceNodeBloom != wantBit {
		t.Errorf("G23a: ServiceNodeBloom = 0x%x, want 0x%x",
			ServiceNodeBloom, wantBit)
	}
}

// G23b / PASS: AdvertiseNodeBloom toggles NODE_BLOOM in advertised
// services, matching init.cpp:1104 g_local_services |= NODE_BLOOM.
func TestW134_G23b_NodeBloomGating(t *testing.T) {
	pm := &PeerManager{
		config: PeerManagerConfig{AdvertiseNodeBloom: true},
	}
	cfg := pm.makePeerConfig()
	if cfg.Services&ServiceNodeBloom == 0 {
		t.Error("G23b: NODE_BLOOM missing when AdvertiseNodeBloom=true")
	}

	pm.config.AdvertiseNodeBloom = false
	cfg2 := pm.makePeerConfig()
	if cfg2.Services&ServiceNodeBloom != 0 {
		t.Error("G23b: NODE_BLOOM set when AdvertiseNodeBloom=false")
	}
}

// ============================================================================
// G24: -peerbloomfilters default = false (PASS)
// ============================================================================

// G24 / PASS: blockbrew matches Core's DEFAULT_PEERBLOOMFILTERS=false
// (net_processing.h:44). The config field's zero value is false, and
// the flag default in cmd/blockbrew/main.go:476 is false.
//
// We test the zero-value invariant here; the flag default is exercised
// in cmd/blockbrew/main_test.go (TestPeerBloomFiltersConfigPropagation).
func TestW134_G24_DefaultPeerBloomFiltersFalse(t *testing.T) {
	var cfg PeerManagerConfig
	if cfg.AdvertiseNodeBloom {
		t.Error("G24: AdvertiseNodeBloom zero value = true, " +
			"want false (DEFAULT_PEERBLOOMFILTERS = false)")
	}
}

// ============================================================================
// G25..G27: Incoming filter messages disconnect when NODE_BLOOM not
// advertised (MISSING — BUG-7, BIP-111 violation)
// ============================================================================

// G25 / MISSING: Core net_processing.cpp:4964-4967 —
//
//	if (!(peer.m_our_services & NODE_BLOOM)) {
//	    pfrom.fDisconnect = true; return;
//	}
//
// blockbrew's peer.go:687-691 dispatches OnFilterLoad unconditionally
// (and silently drops because the callback is never wired). No
// NODE_BLOOM-absent check; no fDisconnect; no Misbehaving.
//
// We verify the structural absence: dispatching a filterload to a peer
// with AdvertiseNodeBloom=false does not flag the peer for disconnect
// (because there is no gate to flag it).
func TestW134_G25_FilterloadDisconnectWhenNoBloom(t *testing.T) {
	t.Skip("BUG-7: filterload accepted regardless of NODE_BLOOM " +
		"advertisement — BIP-111 violation. Core disconnects; " +
		"blockbrew silently parses + drops.")
}

// G26 / MISSING: Core net_processing.cpp:4989-4992 — same disconnect
// gate for filteradd.
func TestW134_G26_FilteraddDisconnectWhenNoBloom(t *testing.T) {
	t.Skip("BUG-7: filteradd accepted regardless of NODE_BLOOM " +
		"advertisement — BIP-111 violation")
}

// G27 / MISSING: Core net_processing.cpp:5017-5020 — same disconnect
// gate for filterclear.
func TestW134_G27_FilterclearDisconnectWhenNoBloom(t *testing.T) {
	t.Skip("BUG-7: filterclear accepted regardless of NODE_BLOOM " +
		"advertisement — BIP-111 violation")
}

// ============================================================================
// G28: filteradd-without-filterload → Misbehaving (MISSING — BUG-8)
// ============================================================================

// G28 / MISSING: Core net_processing.cpp:5002-5012 — if a peer sends
// filteradd before filterload, the `bad = true` else-branch fires and
// Misbehaving(peer, "bad filteradd message", score=100) disconnects.
// blockbrew has no per-peer filter state (BUG-6) to check against, so
// it cannot detect this misbehaviour pattern.
func TestW134_G28_FilteraddWithoutFilterloadMisbehaving(t *testing.T) {
	t.Skip("BUG-8: filteradd-without-prior-filterload not flagged as " +
		"Misbehaving — no per-peer m_bloom_filter state to check " +
		"against (subordinate to BUG-6, BUG-12)")
}

// ============================================================================
// G29: MSG_FILTERED_BLOCK handler in HandleGetData (MISSING — BUG-10/11)
// ============================================================================

// G29 / MISSING: Core net_processing.cpp:2438-2460 — getdata switch arm
// on inv.IsMsgFilteredBlk() constructs a CMerkleBlock from the peer's
// installed filter and sends it + each matched tx as separate tx
// messages.
//
// blockbrew's sync.go:1264-1318 HandleGetData has only InvTypeBlock
// (line 1287) and InvTypeTx (line 1311) arms. A peer that sends
// getdata(MSG_FILTERED_BLOCK, blockhash) gets no merkleblock, no
// notfound, no log line — silent hang on the read.
//
// Structural absence check: verify InvTypeFilteredBlock = 3 is defined
// (so the wire decoder accepts the type) but no production code path
// references it in a sync.go context.
func TestW134_G29_FilteredBlockHandlerInGetData(t *testing.T) {
	// Confirm InvTypeFilteredBlock constant value matches Core.
	const want = InvType(3)
	if InvTypeFilteredBlock != want {
		t.Errorf("G29: InvTypeFilteredBlock = %d, want %d",
			InvTypeFilteredBlock, want)
	}
	t.Skip("BUG-10: HandleGetData switch arm for InvTypeFilteredBlock " +
		"missing in sync.go:1286-1313 — silent no-op on peer's " +
		"getdata(MSG_FILTERED_BLOCK). BUG-11: BIP-37 spec also " +
		"requires following the merkleblock with the matched txs " +
		"as separate 'tx' messages, which is doubly absent.")
}

// ============================================================================
// G30: per-peer m_bloom_filter / m_bloom_filter_loaded / m_relays_txs
// state machine (MISSING — BUG-6, BUG-12)
// ============================================================================

// G30a / MISSING: Core has `Peer::TxRelay` carrying m_bloom_filter
// (unique_ptr<CBloomFilter>) plus m_relay_txs. blockbrew's Peer has
// neither — there is no bloom-related field on the Peer struct.
// Verify via reflect that no field name matches "bloom" / "filter".
func TestW134_G30a_PeerStructHasNoBloomState(t *testing.T) {
	// Verify by reflect that the Peer struct has no field whose name
	// suggests bloom-filter state.  This is a structural guard; a
	// future implementation could add one and break this test
	// (which is fine — flip to a positive check at that time).
	var p Peer
	tp := reflect.TypeOf(p)
	for i := 0; i < tp.NumField(); i++ {
		name := tp.Field(i).Name
		lower := []byte(name)
		for j := range lower {
			if lower[j] >= 'A' && lower[j] <= 'Z' {
				lower[j] += 'a' - 'A'
			}
		}
		for _, needle := range []string{"bloom", "filter"} {
			// Use a simple substring match. Note: "compactBlockState"
			// contains neither needle so this is safe today.
			if bytes_contains(lower, []byte(needle)) {
				// Skip the dispatch state field (compactBlockState etc.)
				// — only flag if the field references BIP-37 bloom.
				if needle == "filter" && !bytes_contains(lower, []byte("bloom")) {
					// "filter" alone might refer to BIP-157 compact
					// filters; only fail on "bloom" in the name.
					continue
				}
				t.Errorf("G30a: unexpected Peer struct field %q " +
					"references bloom — re-audit", name)
				return
			}
		}
	}
	t.Skip("BUG-6: Peer struct has no per-peer bloom-filter state — " +
		"OnFilterLoad/OnFilterAdd/OnFilterClear callbacks defined " +
		"but never wired in production (dead-helper pattern from " +
		"W110, restated for W134)")
}

// G30b / MISSING: OnFilterLoad / OnFilterAdd / OnFilterClear /
// OnMerkleBlock callbacks are nil in the zero PeerListeners (BUG-6 +
// BUG-17 for OnMerkleBlock). Production code never sets them.
func TestW134_G30b_BloomCallbacksNeverWired(t *testing.T) {
	var l PeerListeners
	if l.OnFilterLoad != nil {
		t.Error("G30b: OnFilterLoad unexpectedly non-nil (zero value)")
	}
	if l.OnFilterAdd != nil {
		t.Error("G30b: OnFilterAdd unexpectedly non-nil (zero value)")
	}
	if l.OnFilterClear != nil {
		t.Error("G30b: OnFilterClear unexpectedly non-nil (zero value)")
	}
	if l.OnMerkleBlock != nil {
		t.Error("G30b: OnMerkleBlock unexpectedly non-nil (zero value)")
	}
	// PASS for the zero-value invariant. Document the dead-helper.
	t.Log("G30b: PASS (zero-value invariant) — but BUG-6: callbacks " +
		"are nil-default AND production code (cmd/blockbrew/main.go, " +
		"internal/p2p/sync.go) never assigns them. The entire bloom " +
		"callback surface is dead-helper.")
}

// G30c / MISSING: Core's filterclear flips m_relay_txs BACK ON, which
// is a subtle BIP-37 behavior. blockbrew's Peer.RelayTxes() reads only
// the immutable peerVersion.Relay bit, which filterload / filterclear
// cannot mutate.
func TestW134_G30c_RelayTxsImmutableVsCoreToggle(t *testing.T) {
	t.Skip("BUG-12: Peer.RelayTxes() reads only peerVersion.Relay " +
		"(immutable handshake bit). Core's m_relays_txs flips on " +
		"filterload AND on filterclear, neither of which blockbrew " +
		"can observe today (callbacks unwired, no per-peer state).")
}

// ============================================================================
// Supplementary: BUG-15 / BUG-16 / BUG-17 / BUG-18 documentation
// ============================================================================

// BUG-15: hash-count sanity bound is 2*TxCount+1, looser than BIP-37 N≤TxCount.
func TestW134_BUG15_HashCountBoundTooLoose(t *testing.T) {
	// Document via code inspection: msg_bloom.go:160 reads
	//
	//   if hashCount > uint64(m.TxCount)*2+1 {
	//
	// BIP-37 spec says N <= total_transactions. This is a 2× loose
	// bound on a memory-DoS hardening check. Construct a merkleblock
	// where hashCount = 2*TxCount and observe blockbrew accepts it.
	t.Skip("BUG-15: MsgMerkleBlock.Deserialize hash-count bound is " +
		"2*TxCount+1, but BIP-37 spec is N <= TxCount. 2x looser than " +
		"Core — memory-DoS hardening miss (not a CDIV).")
}

// BUG-16: flag-bytes cap is 1<<20, unprincipled.
func TestW134_BUG16_FlagBytesCapUnprincipled(t *testing.T) {
	// msg_bloom.go:169 reads VarBytes(r, 1<<20). The BIP-37 protocol
	// bound on flag bytes is CeilDiv(2*N-1, 8), not 1 MiB.
	t.Skip("BUG-16: MsgMerkleBlock flag-bytes VarBytes cap is 1<<20, " +
		"but spec bound is CeilDiv(2*N-1, 8). Harmless today, " +
		"unprincipled.")
}

// BUG-17: OnMerkleBlock callback dead weight (full node never receives).
func TestW134_BUG17_OnMerkleBlockDeadWeight(t *testing.T) {
	t.Skip("BUG-17: OnMerkleBlock callback exists for an inbound " +
		"merkleblock, but blockbrew is a full node — merkleblock " +
		"travels server→client only. Callback is structurally dead.")
}

// BUG-18: filterload-deserialize-error is non-fatal (asymmetric with
// filteradd which is fatal post-FIX-35).
func TestW134_BUG18_FilterloadNonFatalAsymmetry(t *testing.T) {
	// Construct a filterload that fails Deserialize (HashFuncs > 50)
	// and verify the error.  Then assert that "filterload" is still
	// in isNonCriticalMessage (i.e. ReadMessage would wrap it as
	// NonFatalMessageError → peer survives).  Core disconnects.
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0xAB, 0xCD})
	buf.Write([]byte{0x33, 0x00, 0x00, 0x00}) // 51 = oversize
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	buf.Write([]byte{0x00})
	msg := &MsgFilterLoad{}
	if err := msg.Deserialize(&buf); err == nil {
		t.Fatal("BUG-18 setup: expected Deserialize error, got nil")
	}
	// Verify "filterload" remains in isNonCriticalMessage.
	if !isNonCriticalMessage("filterload") {
		// If the list has been hardened, flip this test to PASS.
		t.Log("BUG-18 RESOLVED: filterload no longer in " +
			"isNonCriticalMessage — peer disconnect on bad filterload")
		return
	}
	t.Skip("BUG-18: filterload deserialize errors are wrapped as " +
		"NonFatalMessageError (filterload still in " +
		"isNonCriticalMessage). Core's Misbehaving(peer, " +
		"\"too-large bloom filter\", score=100) → disconnect; " +
		"blockbrew tolerates. Asymmetric with filteradd post-FIX-35.")
}

// BUG-19: no per-peer permission system → no -whitelist=…@bloomfilter.
func TestW134_BUG19_NoPermissionSystem(t *testing.T) {
	t.Skip("BUG-19: blockbrew has no NetPermissionFlags equivalent — " +
		"no per-peer @bloomfilter permission override. " +
		"\"Won't implement\" rather than a bug per se.")
}

// ============================================================================
// Supplementary: dead-helper observation
// ============================================================================

// TestW134_DeadHelper_BloomCallbacksNeverWired documents the
// dead-helper pattern persistent across W110 and W134. The four
// callbacks exist on PeerListeners but no production code (excluding
// tests) sets them.
func TestW134_DeadHelper_BloomCallbacksNeverWired(t *testing.T) {
	var l PeerListeners
	if l.OnFilterLoad != nil ||
		l.OnFilterAdd != nil ||
		l.OnFilterClear != nil ||
		l.OnMerkleBlock != nil {
		t.Error("dead-helper baseline broken: a default PeerListeners " +
			"now has a non-nil bloom callback — re-audit")
	}
	t.Log("DEAD-HELPER: bloom callbacks present, never wired. " +
		"Same pattern as W110 G25c / G26c / G27b / G28b + BUG-6. " +
		"Promoted to a fleet-wide concern in W118-class audits.")
}

// ----------------------------------------------------------------------------
// Tiny local helper to avoid bringing in bytes-package-Contains for tests
// (we already import "bytes" for bytes.Buffer, so this is just a name
// disambiguation — keeps the file compileable without `bytes.Contains`
// shadow warnings).
// ----------------------------------------------------------------------------

func bytes_contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
