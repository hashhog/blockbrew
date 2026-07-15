package consensus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// campaign_assumeutxo_test.go — porter-wave Change-1 (regtest Core-parity
// assumeutxo table) + Change-2 (HASHHOG_CAMPAIGN_ASSUMEUTXO flag).
//
// References: bitcoin-core/src/kernel/chainparams.cpp CRegTestParams
// m_assumeutxo_data (heights 110/200/299); receipts/PORTER-WAVE-WORKORDER.md;
// receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md.

// TestRegtestCoreParityAssumeUTXO_AlwaysPresent pins Change-1: with NO
// runtime registration at all, RegtestAssumeUTXOParams() already carries
// Core's three regtest quadruples, verbatim, matching
// bitcoin-core/src/kernel/chainparams.cpp:607-628 and
// tools/boot-smoke-fixtures/fixture-meta.json (height=299 entry).
func TestRegtestCoreParityAssumeUTXO_AlwaysPresent(t *testing.T) {
	ClearRegtestAssumeUTXO()
	t.Cleanup(ClearRegtestAssumeUTXO)

	params := RegtestAssumeUTXOParams()
	if len(params.Data) != 3 {
		t.Fatalf("expected 3 Core-parity regtest entries with nothing runtime-registered, got %d", len(params.Data))
	}

	cases := []struct {
		height       int32
		blockHashHex string // display order
		hashSerHex   string // display order
		chainTxCount uint64
	}{
		{110, "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397", "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327", 111},
		{200, "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9", "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a", 201},
		{299, "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2", "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2", 334},
	}
	for _, c := range cases {
		d := params.ForHeight(c.height)
		if d == nil {
			t.Fatalf("height %d: not found in RegtestAssumeUTXOParams()", c.height)
		}
		wantBlockHash, err := wire.NewHash256FromHex(c.blockHashHex)
		if err != nil {
			t.Fatalf("height %d: bad test fixture blockhash: %v", c.height, err)
		}
		wantHashSer, err := wire.NewHash256FromHex(c.hashSerHex)
		if err != nil {
			t.Fatalf("height %d: bad test fixture hash_serialized: %v", c.height, err)
		}
		if d.BlockHash != wantBlockHash {
			t.Errorf("height %d: BlockHash = %s, want %s", c.height, d.BlockHash.String(), c.blockHashHex)
		}
		if d.HashSerialized != wantHashSer {
			t.Errorf("height %d: HashSerialized mismatch", c.height)
		}
		if d.ChainTxCount != c.chainTxCount {
			t.Errorf("height %d: ChainTxCount = %d, want %d", c.height, d.ChainTxCount, c.chainTxCount)
		}
		// ForBlockHash must resolve the same entry (loadSnapshotFromFile looks
		// up by hash first, then cross-checks height — BUG-W102-14 guard).
		byHash := params.ForBlockHash(wantBlockHash)
		if byHash == nil || byHash.Height != c.height {
			t.Errorf("height %d: ForBlockHash lookup did not round-trip", c.height)
		}
	}
}

// TestRegtestCoreParityMergesWithRuntimeRegistered proves the Core-parity
// table and a test's own synthetic registration coexist without either
// shadowing the other (the design note in assumeutxo.go).
func TestRegtestCoreParityMergesWithRuntimeRegistered(t *testing.T) {
	ClearRegtestAssumeUTXO()
	t.Cleanup(ClearRegtestAssumeUTXO)

	synthetic := AssumeUTXOData{
		Height:         42,
		HashSerialized: mustParseHash("1111111111111111111111111111111111111111111111111111111111111111"[:64]),
		ChainTxCount:   43,
		BlockHash:      mustParseHash("2222222222222222222222222222222222222222222222222222222222222222"[:64]),
	}
	RegisterRegtestAssumeUTXO(synthetic)

	params := RegtestAssumeUTXOParams()
	if len(params.Data) != 4 {
		t.Fatalf("expected 3 Core-parity + 1 runtime-registered = 4 entries, got %d", len(params.Data))
	}
	if d := params.ForHeight(299); d == nil {
		t.Error("Core-parity height 299 missing after a runtime registration")
	}
	if d := params.ForHeight(42); d == nil || d.ChainTxCount != 43 {
		t.Error("runtime-registered height 42 missing or wrong after merge")
	}
}

// mustWriteCampaignFixture writes a campaign JSON fixture and returns its path.
func mustWriteCampaignFixture(t *testing.T, entries []map[string]any) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "campaign.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestLoadCampaignAssumeUTXO_UnsetIsNoop is the bit-identical-when-unset
// proof: with the env var absent, LoadCampaignAssumeUTXO must not touch
// params at all (same pointer identity on params.AssumeUTXO) and must return
// (0, nil).
func TestLoadCampaignAssumeUTXO_UnsetIsNoop(t *testing.T) {
	t.Setenv(CampaignAssumeUTXOEnvVar, "") // ensure absent regardless of outer env

	original := &AssumeUTXOParams{Data: []AssumeUTXOData{
		{Height: 1, BlockHash: mustParseHash("3333333333333333333333333333333333333333333333333333333333333333"[:64])},
	}}
	params := &ChainParams{Name: "mainnet", AssumeUTXO: original}

	n, err := LoadCampaignAssumeUTXO(params)
	if err != nil {
		t.Fatalf("unexpected error with flag unset: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 entries loaded with flag unset, got %d", n)
	}
	if params.AssumeUTXO != original {
		t.Fatal("params.AssumeUTXO pointer was replaced even though the flag was unset — not bit-identical")
	}
}

// TestLoadCampaignAssumeUTXO_MainnetAppend proves Change-2's mainnet/
// testnet4-style hook: entries from the campaign file become resolvable via
// ForHeight/ForBlockHash on a FRESH ChainParams (isolated from the real
// MainnetParams() singleton to avoid cross-test pollution within this binary).
func TestLoadCampaignAssumeUTXO_MainnetAppend(t *testing.T) {
	fixture := mustWriteCampaignFixture(t, []map[string]any{
		{
			"height":           481823,
			"blockhash":        "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
			"hash_serialized":  "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4",
			"m_chain_tx_count": 249036369,
			"base_mtp":         1503536364,
		},
	})
	t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

	builtin := &AssumeUTXOParams{Data: []AssumeUTXOData{
		{Height: 840000, BlockHash: mustParseHash("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"[:64])},
	}}
	params := &ChainParams{Name: "mainnet", AssumeUTXO: builtin}
	globalBefore := len(MainnetAssumeUTXOParams.Data)

	n, err := LoadCampaignAssumeUTXO(params)
	if err != nil {
		t.Fatalf("LoadCampaignAssumeUTXO: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 entry loaded, got %d", n)
	}
	// The built-in entry must still resolve (append-only merge).
	if d := params.AssumeUTXO.ForHeight(840000); d == nil {
		t.Error("built-in height 840000 lost after campaign append")
	}
	// The campaign entry must now resolve.
	d := params.AssumeUTXO.ForHeight(481823)
	if d == nil {
		t.Fatal("campaign height 481823 not resolvable after LoadCampaignAssumeUTXO")
	}
	wantHash, _ := wire.NewHash256FromHex("000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80")
	if d.BlockHash != wantHash {
		t.Error("campaign entry BlockHash byte order mismatch (display->internal conversion wrong)")
	}
	if d.ChainTxCount != 249036369 {
		t.Errorf("ChainTxCount = %d, want 249036369", d.ChainTxCount)
	}
	// params.AssumeUTXO was swapped to a NEW object, not mutated in place —
	// the original `builtin` object this test constructed must be untouched.
	if len(builtin.Data) != 1 {
		t.Errorf("original builtin AssumeUTXOParams mutated in place: len=%d, want 1", len(builtin.Data))
	}
	if params.AssumeUTXO == builtin {
		t.Error("params.AssumeUTXO still points at the original builtin object — expected a fresh merged copy")
	}
	// This test never touches the real package-level MainnetAssumeUTXOParams
	// (it built its own synthetic `builtin` instead) — confirm that stays
	// untouched too, guarding against any accidental global-state aliasing.
	if got := len(MainnetAssumeUTXOParams.Data); got != globalBefore {
		t.Errorf("MainnetAssumeUTXOParams.Data length changed: before=%d after=%d", globalBefore, got)
	}
}

// TestLoadCampaignAssumeUTXO_RegtestAppend proves the regtest hook: campaign
// entries land in the runtime-registerable whitelist and show up merged with
// the Core-parity table via RegtestAssumeUTXOParams()/AssumeUTXOParamsForNetwork.
func TestLoadCampaignAssumeUTXO_RegtestAppend(t *testing.T) {
	ClearRegtestAssumeUTXO()
	t.Cleanup(ClearRegtestAssumeUTXO)

	fixture := mustWriteCampaignFixture(t, []map[string]any{
		{
			"height":           500,
			"blockhash":        "4444444444444444444444444444444444444444444444444444444444444444"[:64],
			"hash_serialized":  "5555555555555555555555555555555555555555555555555555555555555555"[:64],
			"m_chain_tx_count": 501,
		},
	})
	t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

	params := &ChainParams{Name: "regtest"} // AssumeUTXO field stays nil, as real RegtestParams() has it
	n, err := LoadCampaignAssumeUTXO(params)
	if err != nil {
		t.Fatalf("LoadCampaignAssumeUTXO: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 entry loaded, got %d", n)
	}

	effective := AssumeUTXOParamsForNetwork(params)
	if len(effective.Data) != 4 { // 3 Core-parity + 1 campaign
		t.Fatalf("expected 4 entries (3 Core-parity + 1 campaign), got %d", len(effective.Data))
	}
	if d := effective.ForHeight(299); d == nil {
		t.Error("Core-parity height 299 missing after campaign append on regtest")
	}
	if d := effective.ForHeight(500); d == nil {
		t.Error("campaign height 500 missing after append on regtest")
	}
}

// TestLoadCampaignAssumeUTXO_CollisionRefused: a campaign entry whose height
// OR blockhash matches an existing (built-in / Core-parity) entry must
// refuse to start — campaign data may never override a production hash.
func TestLoadCampaignAssumeUTXO_CollisionRefused(t *testing.T) {
	t.Run("height collision", func(t *testing.T) {
		fixture := mustWriteCampaignFixture(t, []map[string]any{
			{
				"height":           840000, // collides with the built-in mainnet height
				"blockhash":        "6666666666666666666666666666666666666666666666666666666666666666"[:64],
				"hash_serialized":  "7777777777777777777777777777777777777777777777777777777777777777"[:64],
				"m_chain_tx_count": 1,
			},
		})
		t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

		builtin := &AssumeUTXOParams{Data: []AssumeUTXOData{
			{Height: 840000, BlockHash: mustParseHash("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"[:64])},
		}}
		params := &ChainParams{Name: "mainnet", AssumeUTXO: builtin}

		if _, err := LoadCampaignAssumeUTXO(params); err == nil {
			t.Fatal("expected a height-collision error, got nil")
		}
	})

	t.Run("blockhash collision on regtest (Core-parity)", func(t *testing.T) {
		ClearRegtestAssumeUTXO()
		t.Cleanup(ClearRegtestAssumeUTXO)

		fixture := mustWriteCampaignFixture(t, []map[string]any{
			{
				"height":           12345, // different height, but SAME Core-parity blockhash (299 entry)
				"blockhash":        "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2",
				"hash_serialized":  "8888888888888888888888888888888888888888888888888888888888888888"[:64],
				"m_chain_tx_count": 1,
			},
		})
		t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

		params := &ChainParams{Name: "regtest"}
		if _, err := LoadCampaignAssumeUTXO(params); err == nil {
			t.Fatal("expected a blockhash-collision error against the Core-parity table, got nil")
		}
	})
}

// TestLoadCampaignAssumeUTXO_DuplicateWithinFileRefused: two entries in the
// SAME campaign file with the same height must be refused.
func TestLoadCampaignAssumeUTXO_DuplicateWithinFileRefused(t *testing.T) {
	fixture := mustWriteCampaignFixture(t, []map[string]any{
		{
			"height":           500,
			"blockhash":        "9999999999999999999999999999999999999999999999999999999999999999"[:64],
			"hash_serialized":  "1010101010101010101010101010101010101010101010101010101010101010"[:64],
			"m_chain_tx_count": 1,
		},
		{
			"height":           500, // duplicate height
			"blockhash":        "1212121212121212121212121212121212121212121212121212121212121212"[:64],
			"hash_serialized":  "1313131313131313131313131313131313131313131313131313131313131313"[:64],
			"m_chain_tx_count": 2,
		},
	})
	t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

	params := &ChainParams{Name: "mainnet", AssumeUTXO: &AssumeUTXOParams{}}
	if _, err := LoadCampaignAssumeUTXO(params); err == nil {
		t.Fatal("expected a duplicate-height-within-file error, got nil")
	}
}

// TestLoadCampaignAssumeUTXO_BadHexRefused: malformed hex length must be
// refused with a clear error, not silently truncated/zero-padded.
func TestLoadCampaignAssumeUTXO_BadHexRefused(t *testing.T) {
	fixture := mustWriteCampaignFixture(t, []map[string]any{
		{
			"height":           500,
			"blockhash":        "deadbeef", // way too short
			"hash_serialized":  "1010101010101010101010101010101010101010101010101010101010101010"[:64],
			"m_chain_tx_count": 1,
		},
	})
	t.Setenv(CampaignAssumeUTXOEnvVar, fixture)

	params := &ChainParams{Name: "mainnet", AssumeUTXO: &AssumeUTXOParams{}}
	if _, err := LoadCampaignAssumeUTXO(params); err == nil {
		t.Fatal("expected a bad-hex-length error, got nil")
	}
}

// TestLoadCampaignAssumeUTXO_MissingFileRefused: a path that does not exist
// must be a startup-fatal error, not a silent skip.
func TestLoadCampaignAssumeUTXO_MissingFileRefused(t *testing.T) {
	t.Setenv(CampaignAssumeUTXOEnvVar, filepath.Join(t.TempDir(), "does-not-exist.json"))
	params := &ChainParams{Name: "mainnet", AssumeUTXO: &AssumeUTXOParams{}}
	if _, err := LoadCampaignAssumeUTXO(params); err == nil {
		t.Fatal("expected an error for a missing campaign file, got nil")
	}
}
