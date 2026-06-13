// assumeutxo_dual_chainstate_test.go — real background 2nd chainstate for
// AssumeUTXO (Core dual-chainstate parity).
//
// This is the functional gate for ActivateSnapshotWithBackground +
// BackgroundValidator (assumeutxo.go), the blockbrew analogue of Bitcoin Core's
// ActivateSnapshot / AddChainstate / MaybeCompleteSnapshotValidation
// (validation.cpp:5588 / 6170 / 5967). It mirrors lunarblock a39dd42
// (spec/assumeutxo_dual_chainstate_spec.lua) and camlcoin 2675b31
// (test/test_dual_chainstate_spec.ml).
//
// What it proves (the four assertions the cross-impl pilots all pin):
//   (a) SEPARATE store — a write to the active (snapshot) chainstate's coins is
//       NOT visible in the background chainstate's coins (aliasing falsification).
//   (b) REAL connect genesis->base — the background coins, after replaying every
//       block into its OWN store, equal an INDEPENDENTLY-computed UTXO set (not
//       empty, not a counter).
//   (c) ACCEPT — driving the background pass with the CORRECT assumeutxo hash
//       flips the snapshot to validated.
//   (d) REJECT — driving it with a DELIBERATELY-WRONG assumed hash marks the
//       snapshot invalid / returns a fatal error (the most important assertion:
//       a wrong commitment must NEVER silently validate).
//
// Every sub-test uses a UNIQUE temp dir (t.TempDir()) for each Pebble store so
// repeated / combined runs cannot reuse leftover DB state and false-green the
// falsification.

package consensus

import (
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test chain construction
//
// We build a tiny genesis->base chain with REAL spends so the background
// validator does genuine input-spending (not a counter). Blocks are plain
// in-memory wire.MsgBlocks; the dual-chainstate machinery operates on the UTXO
// layer (ConnectBlockUTXOs), which is exactly the Core "connect block coins"
// boundary, so no PoW / header validation is needed here (Core's background
// chainstate replays already-validated blocks forward).
//
// Chain (base height = 2):
//   block 1: coinbase CB1 -> {CB1:0 = 50 BTC, script 0x51}
//   block 2: coinbase CB2 -> {CB2:0 = 50 BTC, script 0x52}
//            tx T spends CB1:0 -> {T:0 = 30 BTC (0x53), T:1 = 19 BTC (0x54)}
//
// Final UTXO set after connecting blocks 1..2 (CB1:0 is SPENT in block 2):
//   {CB2:0, T:0, T:1}
// ─────────────────────────────────────────────────────────────────────────────

// makeCoinbaseTx builds a coinbase transaction with a single output. The
// scriptSig is unique per height so distinct coinbases have distinct txids.
func makeCoinbaseTx(height int32, value int64, pkScript []byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			// Unique scriptSig so each coinbase has a distinct txid.
			SignatureScript: []byte{byte(height), byte(height >> 8), 0xAA},
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: value, PkScript: pkScript}},
	}
}

// makeSpendTx builds a non-coinbase tx spending a single prevout into the given
// outputs.
func makeSpendTx(prev wire.OutPoint, outs []*wire.TxOut) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prev,
			SignatureScript:  []byte{0x00},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: outs,
	}
}

// testChain holds the blocks and the independently-computed expected UTXO set
// at the base height.
type testChain struct {
	blocks      map[int32]*wire.MsgBlock // height -> block (1..base)
	baseHeight  int32
	expectedSet map[wire.OutPoint]*UTXOEntry // ground-truth coins at base
}

// buildTestChain constructs the genesis->base chain described above and computes
// the ground-truth final UTXO set by hand (NOT via the machinery under test).
func buildTestChain(t *testing.T) *testChain {
	t.Helper()

	const baseHeight = int32(2)

	// Block 1: coinbase only.
	cb1 := makeCoinbaseTx(1, 50_0000_0000, []byte{0x51})
	block1 := &wire.MsgBlock{Transactions: []*wire.MsgTx{cb1}}
	cb1Hash := cb1.TxHash()

	// Block 2: coinbase + a tx spending CB1:0.
	cb2 := makeCoinbaseTx(2, 50_0000_0000, []byte{0x52})
	spend := makeSpendTx(
		wire.OutPoint{Hash: cb1Hash, Index: 0},
		[]*wire.TxOut{
			{Value: 30_0000_0000, PkScript: []byte{0x53}},
			{Value: 19_0000_0000, PkScript: []byte{0x54}},
		},
	)
	block2 := &wire.MsgBlock{Transactions: []*wire.MsgTx{cb2, spend}}
	cb2Hash := cb2.TxHash()
	spendHash := spend.TxHash()

	// Ground-truth final set: CB1:0 spent; CB2:0, T:0, T:1 remain.
	expected := map[wire.OutPoint]*UTXOEntry{
		{Hash: cb2Hash, Index: 0}: {
			Amount: 50_0000_0000, PkScript: []byte{0x52}, Height: 2, IsCoinbase: true,
		},
		{Hash: spendHash, Index: 0}: {
			Amount: 30_0000_0000, PkScript: []byte{0x53}, Height: 2, IsCoinbase: false,
		},
		{Hash: spendHash, Index: 1}: {
			Amount: 19_0000_0000, PkScript: []byte{0x54}, Height: 2, IsCoinbase: false,
		},
	}

	return &testChain{
		blocks:      map[int32]*wire.MsgBlock{1: block1, 2: block2},
		baseHeight:  baseHeight,
		expectedSet: expected,
	}
}

// getBlockFn returns a getBlock closure over the chain's block store.
func (tc *testChain) getBlockFn() func(height int32) (*wire.MsgBlock, error) {
	return func(height int32) (*wire.MsgBlock, error) {
		b, ok := tc.blocks[height]
		if !ok {
			return nil, ErrSnapshotBlockNotFound
		}
		return b, nil
	}
}

// newPebbleUTXOSet opens a Pebble-backed UTXO set in a fresh per-test subdir.
func newPebbleUTXOSet(t *testing.T, name string) *UTXOSet {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	db, err := storage.NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("NewPebbleDB(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewUTXOSet(storage.NewChainDB(db))
}

// buildActiveSnapshotCoins replays the chain into an "active" UTXO set so it
// holds the same final coins a loaded snapshot at the base would. It returns the
// active UTXOSet and the hand-computed correct HASH_SERIALIZED of that set.
func buildActiveSnapshotCoins(t *testing.T, tc *testChain) (*UTXOSet, wire.Hash256) {
	t.Helper()
	active := newPebbleUTXOSet(t, "active")
	for h := int32(1); h <= tc.baseHeight; h++ {
		if _, err := active.ConnectBlockUTXOs(tc.blocks[h], h); err != nil {
			t.Fatalf("active ConnectBlockUTXOs(height=%d): %v", h, err)
		}
	}
	info, err := ComputeUTXOSetInfo(active)
	if err != nil {
		t.Fatalf("ComputeUTXOSetInfo(active): %v", err)
	}
	return active, info.HashSerialized3
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) SEPARATE store — aliasing falsification
// ─────────────────────────────────────────────────────────────────────────────

func TestDualChainstate_SeparateStore(t *testing.T) {
	tc := buildTestChain(t)
	active, correctHash := buildActiveSnapshotCoins(t, tc)

	snapshotCS := NewSnapshotChainstate(active, wire.Hash256{0xBA, 0x5E})
	au := &AssumeUTXOData{Height: tc.baseHeight, HashSerialized: correctHash}

	bgUTXO := newPebbleUTXOSet(t, "background")
	act, err := ActivateSnapshotWithBackground(snapshotCS, bgUTXO, au, tc.getBlockFn())
	if err != nil {
		t.Fatalf("ActivateSnapshotWithBackground: %v", err)
	}

	// Write a sentinel coin into the ACTIVE store only.
	sentinel := wire.OutPoint{Hash: wire.Hash256{0xDE, 0xAD, 0xBE, 0xEF}, Index: 7}
	active.AddUTXO(sentinel, &UTXOEntry{Amount: 1, PkScript: []byte{0x55}, Height: 1})

	// It MUST NOT be visible in the background store (separate object).
	if act.Background.BackgroundUTXOSet().HasUTXO(sentinel) {
		t.Fatal("aliasing: a write to the ACTIVE store is visible in the BACKGROUND store; they are not separate")
	}
	if act.Background.BackgroundUTXOSet() == active {
		t.Fatal("aliasing: background and active UTXOSet are the same object")
	}

	// And the activation refuses to share the active store as the bg store.
	if _, err := ActivateSnapshotWithBackground(snapshotCS, active, au, tc.getBlockFn()); err == nil {
		t.Fatal("ActivateSnapshotWithBackground accepted the ACTIVE store as the background store; aliasing guard missing")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) REAL connect genesis->base — bg coins == independently-computed set
// ─────────────────────────────────────────────────────────────────────────────

func TestDualChainstate_RealConnectGenesisToBase(t *testing.T) {
	tc := buildTestChain(t)
	active, correctHash := buildActiveSnapshotCoins(t, tc)

	snapshotCS := NewSnapshotChainstate(active, wire.Hash256{0xBA, 0x5E})
	au := &AssumeUTXOData{Height: tc.baseHeight, HashSerialized: correctHash}

	bgUTXO := newPebbleUTXOSet(t, "background")
	act, err := ActivateSnapshotWithBackground(snapshotCS, bgUTXO, au, tc.getBlockFn())
	if err != nil {
		t.Fatalf("ActivateSnapshotWithBackground: %v", err)
	}

	// Sanity: before running, the bg store is genesis-empty (height 0, no coins).
	if got := act.Background.CurrentHeight(); got != 0 {
		t.Fatalf("background start height = %d, want 0 (genesis-seeded empty)", got)
	}
	preCount, err := act.Background.BackgroundUTXOSet().ScanUTXOs(func(wire.OutPoint, *UTXOEntry) bool { return true })
	if err != nil {
		t.Fatalf("pre-run ScanUTXOs: %v", err)
	}
	if preCount != 0 {
		t.Fatalf("background store has %d coins before running; want 0", preCount)
	}

	// Drive the real genesis->base connection.
	if _, err := act.Background.RunToBase(); err != nil {
		t.Fatalf("RunToBase: %v", err)
	}
	if got := act.Background.CurrentHeight(); got != tc.baseHeight {
		t.Fatalf("background reached height %d, want base %d", got, tc.baseHeight)
	}

	// The bg coins MUST equal the independently-computed final set, coin for
	// coin (proves a REAL connect: spent CB1:0 is absent; CB2:0, T:0, T:1
	// present with correct value/script/height/coinbase) — not empty, not a
	// counter.
	got := map[wire.OutPoint]*UTXOEntry{}
	if _, err := act.Background.BackgroundUTXOSet().ScanUTXOs(func(op wire.OutPoint, e *UTXOEntry) bool {
		cp := *e
		got[op] = &cp
		return true
	}); err != nil {
		t.Fatalf("post-run ScanUTXOs: %v", err)
	}

	if len(got) != len(tc.expectedSet) {
		t.Fatalf("background coin count = %d, want %d (set: %v)", len(got), len(tc.expectedSet), got)
	}
	for op, want := range tc.expectedSet {
		g, ok := got[op]
		if !ok {
			t.Errorf("background store missing expected coin %s:%d", op.Hash.String(), op.Index)
			continue
		}
		if g.Amount != want.Amount || g.Height != want.Height || g.IsCoinbase != want.IsCoinbase ||
			string(g.PkScript) != string(want.PkScript) {
			t.Errorf("coin %s:%d = %+v, want %+v", op.Hash.String(), op.Index, g, want)
		}
	}
	// Explicitly assert the SPENT coin (CB1:0) is gone — the heart of "real
	// connection vs counter".
	cb1Hash := tc.blocks[1].Transactions[0].TxHash()
	if act.Background.BackgroundUTXOSet().HasUTXO(wire.OutPoint{Hash: cb1Hash, Index: 0}) {
		t.Error("background store still has CB1:0, which was SPENT in block 2; connection is not real")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) ACCEPT — correct assumeutxo hash validates the snapshot
// ─────────────────────────────────────────────────────────────────────────────

func TestDualChainstate_AcceptCorrectHash(t *testing.T) {
	tc := buildTestChain(t)
	active, correctHash := buildActiveSnapshotCoins(t, tc)

	snapshotCS := NewSnapshotChainstate(active, wire.Hash256{0xBA, 0x5E})
	au := &AssumeUTXOData{Height: tc.baseHeight, HashSerialized: correctHash}

	bgUTXO := newPebbleUTXOSet(t, "background")
	act, err := ActivateSnapshotWithBackground(snapshotCS, bgUTXO, au, tc.getBlockFn())
	if err != nil {
		t.Fatalf("ActivateSnapshotWithBackground: %v", err)
	}

	// Snapshot starts UNVALIDATED (role Snapshot, getchainstates validated=false).
	if snapshotCS.IsValidated() {
		t.Fatal("snapshot is validated before the background pass ran")
	}

	res, err := act.Background.RunToBase()
	if err != nil {
		t.Fatalf("RunToBase with correct hash returned error: %v", err)
	}
	if res != BackgroundValidated {
		t.Fatalf("RunToBase result = %v, want BackgroundValidated", res)
	}

	validated, err := act.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !validated {
		t.Fatal("Finish returned validated=false for a correct hash")
	}
	if !snapshotCS.IsValidated() {
		t.Fatal("snapshot chainstate not marked Validated after a matching background pass")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) ⭐ REJECT — a deliberately-wrong assumed hash must NEVER validate
// ─────────────────────────────────────────────────────────────────────────────

func TestDualChainstate_RejectWrongHash(t *testing.T) {
	tc := buildTestChain(t)
	active, correctHash := buildActiveSnapshotCoins(t, tc)

	// Flip one bit of the correct hash to produce a deliberately-wrong
	// assumeutxo commitment. A real Core snapshot pins this value; if it does
	// not match the honest replay, the snapshot MUST be rejected.
	wrongHash := correctHash
	wrongHash[0] ^= 0x01
	if wrongHash == correctHash {
		t.Fatal("test bug: wrong hash equals correct hash")
	}

	snapshotCS := NewSnapshotChainstate(active, wire.Hash256{0xBA, 0x5E})
	au := &AssumeUTXOData{Height: tc.baseHeight, HashSerialized: wrongHash}

	bgUTXO := newPebbleUTXOSet(t, "background")
	act, err := ActivateSnapshotWithBackground(snapshotCS, bgUTXO, au, tc.getBlockFn())
	if err != nil {
		t.Fatalf("ActivateSnapshotWithBackground: %v", err)
	}

	res, runErr := act.Background.RunToBase()
	if res != BackgroundInvalid {
		t.Fatalf("RunToBase result = %v, want BackgroundInvalid for a wrong hash", res)
	}
	if runErr == nil {
		t.Fatal("RunToBase returned nil error for a deliberately-wrong hash; a mismatch must surface a fatal error")
	}

	validated, finishErr := act.Finish()
	if validated {
		t.Fatal("⭐ CRITICAL: Finish reported the snapshot VALIDATED with a deliberately-wrong assumeutxo hash; a wrong commitment must NEVER silently validate")
	}
	if finishErr == nil {
		t.Fatal("Finish returned nil error for a wrong-hash snapshot")
	}
	if snapshotCS.IsValidated() {
		t.Fatal("⭐ CRITICAL: snapshot chainstate marked Validated despite a wrong hash")
	}
	if snapshotCS.Role() != ChainstateRoleInvalid {
		t.Fatalf("snapshot role = %d, want ChainstateRoleInvalid after a mismatch", snapshotCS.Role())
	}
}
