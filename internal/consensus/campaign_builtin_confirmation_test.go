package consensus

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// campaign_builtin_confirmation_test.go — a HASHHOG_CAMPAIGN_ASSUMEUTXO entry
// whose commitment (height, blockhash, hash_serialized, m_chain_tx_count) is
// IDENTICAL to a built-in row is a confirmation, not a collision. A DIFFERENT
// entry at a built-in height is still refused.
//
// The R4 slice 910000-920000 was BLOCKED on this: the soak-910000 fixture was
// minted by dumping a Core clone at 910,000 and carries exactly the commitment
// Core hardcodes there (bitcoin-core/src/kernel/chainparams.cpp
// m_assumeutxo_data, mirrored in MainnetAssumeUTXOParams).

const (
	soak910kEntryPath  = "/home/work/hashhog/tools/boundary-blocks/soak-910000/campaign-entry.json"
	h910kBlockHash     = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
	h910kHashSerialzed = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
	h910kChainTxCount  = 1226586151
)

// freshMainnetParams returns a ChainParams whose AssumeUTXO is the REAL
// package-level mainnet table (so the real built-in 910000 row is what the
// campaign entry is compared against). LoadCampaignAssumeUTXO only swaps the
// pointer on this local params; the global table must stay untouched.
func freshMainnetParams() *ChainParams {
	return &ChainParams{Name: "mainnet", AssumeUTXO: &MainnetAssumeUTXOParams}
}

func countAtHeight(p *AssumeUTXOParams, h int32) int {
	n := 0
	for _, d := range p.Data {
		if d.Height == h {
			n++
		}
	}
	return n
}

func assertGlobal910kUntouched(t *testing.T) {
	t.Helper()
	g := MainnetAssumeUTXOParams.ForHeight(910000)
	if g == nil {
		t.Fatal("built-in 910000 row missing from MainnetAssumeUTXOParams")
	}
	if len(g.BaseTailHeaders) != 0 || g.Chainwork != nil {
		t.Fatal("the package-level built-in 910000 row was mutated in place")
	}
	if countAtHeight(&MainnetAssumeUTXOParams, 910000) != 1 {
		t.Fatal("package-level table gained a second 910000 row")
	}
}

// The REAL fixture range-runner.sh exports, against the REAL mainnet table.
func TestCampaignConfirmation_RealSoak910kFixtureAccepted(t *testing.T) {
	if _, err := os.Stat(soak910kEntryPath); err != nil {
		t.Skipf("real fixture not on disk: %v", err)
	}
	t.Setenv(CampaignAssumeUTXOEnvVar, soak910kEntryPath)
	params := freshMainnetParams()

	n, err := LoadCampaignAssumeUTXO(params)
	if err != nil {
		t.Fatalf("identical-to-built-in soak-910000 entry refused: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d entries, want 1", n)
	}
	if c := countAtHeight(params.AssumeUTXO, 910000); c != 1 {
		t.Fatalf("%d rows at 910000 after confirmation, want exactly 1", c)
	}
	d := params.AssumeUTXO.ForHeight(910000)
	if d.BlockHash.String() != h910kBlockHash || d.HashSerialized.String() != h910kHashSerialzed ||
		d.ChainTxCount != h910kChainTxCount {
		t.Fatalf("built-in commitment not kept: %s %s %d", d.BlockHash, d.HashSerialized, d.ChainTxCount)
	}
	// The boot path (activateSnapshotChainView) needs the band + chainwork;
	// the built-in row has neither, so the confirmation must fill them.
	if len(d.BaseTailHeaders) == 0 {
		t.Fatal("confirmation did not fill base_tail_headers into the 910000 row")
	}
	if d.BaseTailHeaders[len(d.BaseTailHeaders)-1].BlockHash() != d.BlockHash {
		t.Fatal("filled band does not end at the 910000 base")
	}
	if d.Chainwork == nil || d.Chainwork.Sign() <= 0 {
		t.Fatal("confirmation did not fill chainwork into the 910000 row")
	}
	if params.AssumeUTXO.ForBlockHash(d.BlockHash) != d {
		t.Fatal("ForBlockHash and ForHeight resolve different 910000 rows")
	}
	// Other built-in rows survive.
	for _, h := range []int32{840000, 880000, 935000} {
		if params.AssumeUTXO.ForHeight(h) == nil {
			t.Errorf("built-in height %d lost", h)
		}
	}
	assertGlobal910kUntouched(t)
}

func entry910k() map[string]any {
	return map[string]any{
		"height":           910000,
		"blockhash":        h910kBlockHash,
		"hash_serialized":  h910kHashSerialzed,
		"m_chain_tx_count": h910kChainTxCount,
	}
}

// Identical commitment without ancestry, in UPPERCASE hex: still the same
// commitment (hex is case-insensitive), accepted, nothing filled.
func TestCampaignConfirmation_IdenticalUppercaseAccepted(t *testing.T) {
	e := entry910k()
	e["blockhash"] = strings.ToUpper(h910kBlockHash)
	e["hash_serialized"] = strings.ToUpper(h910kHashSerialzed)
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{e}))
	params := freshMainnetParams()
	if _, err := LoadCampaignAssumeUTXO(params); err != nil {
		t.Fatalf("identical entry refused: %v", err)
	}
	if c := countAtHeight(params.AssumeUTXO, 910000); c != 1 {
		t.Fatalf("%d rows at 910000, want 1", c)
	}
	assertGlobal910kUntouched(t)
}

func TestCampaignConfirmation_DifferentHashSerializedRefused(t *testing.T) {
	e := entry910k()
	e["hash_serialized"] = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1569" // last nibble flipped
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{e}))
	params := freshMainnetParams()
	_, err := LoadCampaignAssumeUTXO(params)
	if err == nil {
		t.Fatal("a DIFFERENT hash_serialized at built-in height 910000 was accepted")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.AssumeUTXO != &MainnetAssumeUTXOParams {
		t.Fatal("params mutated on refusal")
	}
	assertGlobal910kUntouched(t)
}

func TestCampaignConfirmation_DifferentChainTxCountRefused(t *testing.T) {
	e := entry910k()
	e["m_chain_tx_count"] = h910kChainTxCount + 1
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{e}))
	if _, err := LoadCampaignAssumeUTXO(freshMainnetParams()); err == nil {
		t.Fatal("a DIFFERENT m_chain_tx_count at built-in height 910000 was accepted")
	}
}

func TestCampaignConfirmation_DifferentBlockhashSameHeightRefused(t *testing.T) {
	e := entry910k()
	e["blockhash"] = "1111111111111111111111111111111111111111111111111111111111111111"
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{e}))
	if _, err := LoadCampaignAssumeUTXO(freshMainnetParams()); err == nil {
		t.Fatal("a DIFFERENT blockhash at built-in height 910000 was accepted")
	}
}

// The built-in commitment at ANOTHER height is still a collision.
func TestCampaignConfirmation_BuiltinBlockhashOtherHeightRefused(t *testing.T) {
	e := entry910k()
	e["height"] = 910001
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{e}))
	if _, err := LoadCampaignAssumeUTXO(freshMainnetParams()); err == nil {
		t.Fatal("the built-in 910000 blockhash at height 910001 was accepted")
	}
}

// Supplemental ancestry that contradicts a value the row already pins refuses.
func TestCampaignConfirmation_ContradictingChainworkRefused(t *testing.T) {
	if _, err := os.Stat(soak910kEntryPath); err != nil {
		t.Skipf("real fixture not on disk: %v", err)
	}
	raw, err := os.ReadFile(soak910kEntryPath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	// First confirm once (fills chainwork), then confirm again against the
	// filled table with a different chainwork.
	t.Setenv(CampaignAssumeUTXOEnvVar, soak910kEntryPath)
	params := freshMainnetParams()
	if _, err := LoadCampaignAssumeUTXO(params); err != nil {
		t.Fatalf("first confirmation: %v", err)
	}
	entries[0]["chainwork"] = "00000000000000000000000000000000000000000000000000000000000000ff"
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, entries))
	before := params.AssumeUTXO
	if _, err := LoadCampaignAssumeUTXO(params); err == nil {
		t.Fatal("a chainwork contradicting the row's pinned chainwork was accepted")
	}
	if params.AssumeUTXO != before {
		t.Fatal("params mutated on refusal")
	}
	// Same entry with the agreeing chainwork is idempotent.
	t.Setenv(CampaignAssumeUTXOEnvVar, soak910kEntryPath)
	if _, err := LoadCampaignAssumeUTXO(params); err != nil {
		t.Fatalf("re-confirming with agreeing ancestry refused: %v", err)
	}
	assertGlobal910kUntouched(t)
}

// Regtest: an entry identical to a Core-parity row (299) is a confirmation;
// the effective table still holds exactly one 299 row.
func TestCampaignConfirmation_RegtestCoreParityIdenticalAccepted(t *testing.T) {
	ClearRegtestAssumeUTXO()
	t.Cleanup(ClearRegtestAssumeUTXO)
	var row AssumeUTXOData
	for _, d := range RegtestCoreParityAssumeUTXOData {
		if d.Height == 299 {
			row = d
		}
	}
	t.Setenv(CampaignAssumeUTXOEnvVar, mustWriteCampaignFixture(t, []map[string]any{{
		"height":           299,
		"blockhash":        row.BlockHash.String(),
		"hash_serialized":  row.HashSerialized.String(),
		"m_chain_tx_count": row.ChainTxCount,
	}}))
	params := &ChainParams{Name: "regtest"}
	if _, err := LoadCampaignAssumeUTXO(params); err != nil {
		t.Fatalf("identical-to-Core-parity regtest entry refused: %v", err)
	}
	eff := AssumeUTXOParamsForNetwork(params)
	if c := countAtHeight(eff, 299); c != 1 {
		t.Fatalf("%d rows at 299, want 1", c)
	}
	if len(eff.Data) != 3 {
		t.Fatalf("effective regtest table has %d rows, want 3", len(eff.Data))
	}
}
