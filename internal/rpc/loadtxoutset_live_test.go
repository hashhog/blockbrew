package rpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// loadtxoutset_live_test.go — AssumeUTXO LIVE-RPC dual-chainstate wiring
// (blockbrew pilot completion).
//
// The function-level gate (assumeutxo_dual_chainstate_test.go) proves the
// dual-chainstate MACHINERY works. THIS test proves the LIVE RPC PATH is wired
// to that machinery, the way camlcoin (3140ab9) and lunarblock (a39dd42) wired
// theirs:
//
//   - handleLoadTxOutSet, on a regtest snapshot, authenticates the file via the
//     load-time HASH_SERIALIZED gate AND spins up the REAL background validator
//     (ActivateSnapshotWithBackground + RunToBase + Finish) that re-connects
//     every block genesis->base into its OWN separate coins store and compares
//     the recomputed UTXO hash to the assumeutxo commitment.
//   - handleGetChainStates then reports the snapshot chainstate:
//       * validated  = snapshot chainstate role (false while bg runs / after a
//                      mismatch, true after a match)
//       * snapshot_blockhash = the snapshot base block hash.
//
// Two end-to-end scenarios through the LIVE RPC (plus a no-snapshot sanity):
//   (0) NO SNAPSHOT — getchainstates is the single validated chainstate
//       (validated=true, snapshot_blockhash omitted).
//   (1) ACCEPT — a consistent snapshot whose genesis->base replay matches the
//       committed hash: loadtxoutset succeeds, getchainstates reports
//       validated=true + snapshot_blockhash.
//   (2) ⭐ REJECT — a snapshot whose committed hash matches the snapshot FILE
//       (so the load-time content-hash gate passes) but is INCONSISTENT with
//       the actual chain history: the background re-derivation produces a
//       different UTXO set, the mismatch is caught in the background (Core's
//       AbortNode equivalent), and getchainstates reports validated=false
//       (snapshot invalid). loadtxoutset itself still returns success — Core
//       runs MaybeCompleteSnapshotValidation asynchronously, so the verdict is
//       surfaced via the chainstate state, not the RPC return.
//
// Core reference: bitcoin-core/src/validation.cpp ActivateSnapshot:5588 /
// PopulateAndValidateSnapshot:5754 / MaybeCompleteSnapshotValidation:5967, and
// rpc/blockchain.cpp make_chain_data:3462-3519 for getchainstates fields.
// Cross-impl: camlcoin test_loadtxoutset_live.ml, lunarblock
// spec/assumeutxo_dual_chainstate_spec.lua.
//
// Every case uses a UNIQUE temp dir (t.TempDir()) for the snapshot file and
// registers a FRESH regtest AssumeUTXO entry, cleared in t.Cleanup so no
// verifier-probe state leaks across runs.

// liveGetChainStates round-trips the getchainstates result through JSON and
// extracts (validated, snapshot_blockhash) from the single active chainstate.
func liveGetChainStates(t *testing.T, s *Server) (validated bool, snapshotBlockHash string) {
	t.Helper()
	m := callGetChainStates(t, s)
	csArr, ok := m["chainstates"].([]interface{})
	if !ok || len(csArr) == 0 {
		t.Fatalf("getchainstates: missing/empty chainstates: %v", m["chainstates"])
	}
	cs, ok := csArr[len(csArr)-1].(map[string]interface{})
	if !ok {
		t.Fatalf("getchainstates: chainstate not an object: %T", csArr[0])
	}
	v, ok := cs["validated"].(bool)
	if !ok {
		t.Fatalf("getchainstates: missing/invalid 'validated': %v", cs["validated"])
	}
	snap := ""
	if raw, present := cs["snapshot_blockhash"]; present {
		if sh, ok := raw.(string); ok {
			snap = sh
		}
	}
	return v, snap
}

// liveLoadTxOutSet calls the loadtxoutset RPC handler with a single path arg.
func liveLoadTxOutSet(t *testing.T, s *Server, path string) (*LoadTxOutSetResult, *RPCError) {
	t.Helper()
	raw, err := json.Marshal([]interface{}{path})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	res, rpcErr := s.handleLoadTxOutSet(raw)
	if rpcErr != nil {
		return nil, rpcErr
	}
	lr, ok := res.(*LoadTxOutSetResult)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	return lr, nil
}

// writeLiveSnapshot writes a Core-format snapshot file from the given coins set,
// stamped with baseHash as the metadata BlockHash, and returns the file path +
// the set's HASH_SERIALIZED commitment. The coins set is the authoritative
// content the load-time gate authenticates against; for the REJECT case the
// caller injects an extra spurious coin BEFORE calling this so the file (and
// thus its committed hash) is internally consistent but inconsistent with the
// real genesis->base replay.
func writeLiveSnapshot(t *testing.T, dir string, coins *consensus.UTXOSet, baseHash wire.Hash256, netMagic [4]byte) (string, wire.Hash256) {
	t.Helper()
	commitment, _, err := consensus.ComputeHashSerialized(coins)
	if err != nil {
		t.Fatalf("ComputeHashSerialized(snapshot coins): %v", err)
	}
	path := filepath.Join(dir, "snapshot.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create snapshot file: %v", err)
	}
	if _, err := consensus.WriteSnapshot(f, coins, baseHash, netMagic); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSnapshot: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close snapshot file: %v", err)
	}
	return path, commitment
}

// buildSnapshotCoins replays the rig's chain blocks 1..base into a fresh,
// genuinely separate in-memory UTXO set (its own ChainDB) so a snapshot file
// dumped from it matches the genesis->base replay coin-for-coin. The caller may
// then inject spurious coins to falsify it.
func buildSnapshotCoins(t *testing.T, rig *dumpTxOutSetTestRig, baseHeight int32) *consensus.UTXOSet {
	t.Helper()
	coins := consensus.NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	for h := int32(1); h <= baseHeight; h++ {
		hash, err := rig.db.GetBlockHashByHeight(h)
		if err != nil {
			t.Fatalf("GetBlockHashByHeight(%d): %v", h, err)
		}
		block, err := rig.db.GetBlock(hash)
		if err != nil {
			t.Fatalf("GetBlock(%s) at height %d: %v", hash.String(), h, err)
		}
		if _, err := coins.ConnectBlockUTXOs(block, h); err != nil {
			t.Fatalf("ConnectBlockUTXOs(height=%d): %v", h, err)
		}
	}
	return coins
}

// TestLoadTxOutSetLive_NoSnapshot — sanity: with NO snapshot active,
// getchainstates is the single fully-validated chainstate (validated=true,
// snapshot_blockhash omitted).
func TestLoadTxOutSetLive_NoSnapshot(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)

	rig := newDumpTxOutSetTestRig(t, 4)

	validated, snap := liveGetChainStates(t, rig.server)
	if !validated {
		t.Fatal("no-snapshot chainstate must report validated=true")
	}
	if snap != "" {
		t.Fatalf("no-snapshot chainstate must omit snapshot_blockhash, got %q", snap)
	}
}

// TestLoadTxOutSetLive_Accept — ACCEPT through the LIVE RPC: loadtxoutset -> the
// real bg validator runs genesis->base -> match -> getchainstates
// validated=true + snapshot_blockhash.
func TestLoadTxOutSetLive_Accept(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)

	const nBlocks = 4
	rig := newDumpTxOutSetTestRig(t, nBlocks)
	baseHash, baseHeight := rig.cm.BestBlock()

	// Build a snapshot whose coin set == the real genesis->base replay.
	coins := buildSnapshotCoins(t, rig, baseHeight)
	snapPath, commitment := writeLiveSnapshot(t, t.TempDir(), coins, baseHash, rig.params.NetworkMagic)

	// Register the regtest AssumeUTXO entry committing to the snapshot's hash.
	consensus.RegisterRegtestAssumeUTXO(consensus.AssumeUTXOData{
		Height:         baseHeight,
		HashSerialized: commitment,
		ChainTxCount:   uint64(nBlocks + 1),
		BlockHash:      baseHash,
	})

	// BEFORE: no snapshot -> single validated chainstate.
	if v, s := liveGetChainStates(t, rig.server); !v || s != "" {
		t.Fatalf("pre-load: want single validated chainstate, got validated=%v snapshot=%q", v, s)
	}

	// LIVE call.
	if _, rpcErr := liveLoadTxOutSet(t, rig.server, snapPath); rpcErr != nil {
		t.Fatalf("loadtxoutset returned error: %+v", rpcErr)
	}

	// The wiring must have recorded an activation on the server.
	rig.server.snapshotMu.RLock()
	act := rig.server.snapshotActivation
	rig.server.snapshotMu.RUnlock()
	if act == nil {
		t.Fatal("loadtxoutset must record a snapshot activation (dual-chainstate wired)")
	}

	// getchainstates must now report the snapshot chainstate: validated=true
	// (bg matched) + snapshot_blockhash = the base.
	validated, snap := liveGetChainStates(t, rig.server)
	if !validated {
		t.Fatal("ACCEPT: getchainstates.validated must be true after a matching bg run")
	}
	if snap != baseHash.String() {
		t.Fatalf("snapshot_blockhash = %q, want base %s", snap, baseHash.String())
	}

	// Cross-check the machinery verdict directly.
	if !act.Snapshot.IsValidated() {
		t.Fatal("snapshot chainstate must be marked Validated")
	}
	if act.Snapshot.Role() == consensus.ChainstateRoleInvalid {
		t.Fatal("a validated snapshot must not also be Invalid")
	}
	if got := act.Background.Result(); got != consensus.BackgroundValidated {
		t.Fatalf("background result = %v, want BackgroundValidated", got)
	}
	if got := act.Background.CurrentHeight(); got != baseHeight {
		t.Fatalf("bg reached height %d, want base %d", got, baseHeight)
	}
}

// TestLoadTxOutSetLive_Reject — ⭐ REJECT through the LIVE RPC (falsification):
// a snapshot whose committed hash matches the snapshot FILE (load-time gate
// passes) but is INCONSISTENT with the real chain history -> the bg
// re-derivation mismatches -> snapshot marked Invalid -> getchainstates
// validated=false. THE most important assertion: the mismatch still rejects
// through the LIVE path, and a corrupt snapshot is NEVER silently reported
// validated. loadtxoutset itself still returns success (Core async model).
func TestLoadTxOutSetLive_Reject(t *testing.T) {
	consensus.ClearRegtestAssumeUTXO()
	t.Cleanup(consensus.ClearRegtestAssumeUTXO)

	const nBlocks = 4
	rig := newDumpTxOutSetTestRig(t, nBlocks)
	baseHash, baseHeight := rig.cm.BestBlock()

	// Build the real genesis->base coin set, then inject an EXTRA spurious coin
	// not produced by the real replay. The snapshot file is internally
	// consistent (it hashes to `commitment`), so the load-time content-hash gate
	// PASSES when we commit to `commitment` — but the bg re-connects the real
	// blocks WITHOUT the spurious coin, so it derives a DIFFERENT set and the
	// background comparison MISMATCHES. This is exactly the threat the
	// dual-chainstate exists to catch: a snapshot whose hash matches its own
	// commitment but disagrees with the chain.
	coins := buildSnapshotCoins(t, rig, baseHeight)
	spuriousOut := wire.OutPoint{
		Hash:  wire.Hash256{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB},
		Index: 0,
	}
	coins.AddUTXO(spuriousOut, &consensus.UTXOEntry{
		Amount:     999,
		PkScript:   []byte{0x51}, // OP_TRUE
		Height:     1,            // <= baseHeight so the per-coin height guard passes
		IsCoinbase: false,
	})
	snapPath, commitment := writeLiveSnapshot(t, t.TempDir(), coins, baseHash, rig.params.NetworkMagic)

	// Commit to the snapshot's OWN hash so the load-time gate passes; the bg
	// (which replays the real blocks WITHOUT the spurious coin) will not
	// reproduce `commitment` -> background mismatch.
	consensus.RegisterRegtestAssumeUTXO(consensus.AssumeUTXOData{
		Height:         baseHeight,
		HashSerialized: commitment,
		ChainTxCount:   uint64(nBlocks + 1),
		BlockHash:      baseHash,
	})

	// LIVE call. Per the Core async model, loadtxoutset itself SUCCEEDS even
	// though the background pass will reject; the verdict is surfaced via the
	// chainstate state, read by getchainstates. If the load-time gate had been
	// the rejecter we'd see an error here — that is NOT this scenario (we
	// committed to the snapshot's own hash so the load gate passes and the
	// BACKGROUND is the rejecter).
	if _, rpcErr := liveLoadTxOutSet(t, rig.server, snapPath); rpcErr != nil {
		t.Fatalf("loadtxoutset unexpectedly returned a load-time error (the bg, not the load gate, should reject here): %+v", rpcErr)
	}

	rig.server.snapshotMu.RLock()
	act := rig.server.snapshotActivation
	rig.server.snapshotMu.RUnlock()
	if act == nil {
		t.Fatal("loadtxoutset must still record the activation (so the invalid verdict is visible)")
	}

	// getchainstates must report the snapshot chainstate as NOT validated.
	validated, snap := liveGetChainStates(t, rig.server)
	if validated {
		t.Fatal("⭐ REJECT: getchainstates.validated must be FALSE for a bg-mismatched snapshot")
	}
	if snap != baseHash.String() {
		t.Fatalf("REJECT: snapshot_blockhash = %q, want base %s (the snapshot IS active, just invalid)", snap, baseHash.String())
	}

	// The machinery must have marked the snapshot Invalid (Core AbortNode).
	if act.Snapshot.Role() != consensus.ChainstateRoleInvalid {
		t.Fatalf("snapshot role = %d, want ChainstateRoleInvalid on a bg mismatch", act.Snapshot.Role())
	}
	if act.Snapshot.IsValidated() {
		t.Fatal("⭐ an invalid snapshot must NOT also be Validated")
	}
	if got := act.Background.Result(); got != consensus.BackgroundInvalid {
		t.Fatalf("background result = %v, want BackgroundInvalid", got)
	}
	// It REALLY did the work: bg connected every block genesis->base before
	// catching the mismatch (not short-circuited).
	if got := act.Background.CurrentHeight(); got != baseHeight {
		t.Fatalf("bg must have connected every block genesis->base (height %d) before the mismatch, got %d", baseHeight, got)
	}
}
