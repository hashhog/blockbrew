package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/hashhog/blockbrew/internal/wire"
)

// CampaignAssumeUTXOEnvVar is the cross-impl (all 10 hashhog nodes share this
// one name) environment variable that points at an M2 boundary-campaign
// assumeutxo fixture. See receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md for the
// full design; the summary: read exactly once at startup, after network-
// params selection, and APPEND the file's entries to the running network's
// assumeutxo allowlist. Unset/empty is bit-identical to a build without this
// feature — LoadCampaignAssumeUTXO's only code path is a single os.Getenv.
const CampaignAssumeUTXOEnvVar = "HASHHOG_CAMPAIGN_ASSUMEUTXO"

// campaignAssumeUTXOEntry mirrors the shared campaign fixture schema
// (tools/campaign-assumeutxo/*.json, CAMPAIGN-SNAPSHOT-TABLE-SPEC.md). All
// hex is in Core DISPLAY order, exactly as Core's kernel/chainparams.cpp
// prints it — parseCampaignAssumeUTXO converts to blockbrew's internal byte
// order via wire.NewHash256FromHex, the same conversion mustParseHash and the
// mainnet/regtest tables above use.
//
// base_header/base_tail_headers/chainwork ARE consumed: they are what lets a
// -load-snapshot boot present the snapshot base as the active chain view (see
// AssumeUTXOData.BaseTailHeaders and HeaderIndex.GraftSnapshotBase). base_mtp
// is still parsed and discarded — blockbrew derives median-time-past from the
// grafted header band itself rather than from a pinned scalar.
type campaignAssumeUTXOEntry struct {
	Height          int32    `json:"height"`
	BlockHash       string   `json:"blockhash"`
	HashSerialized  string   `json:"hash_serialized"`
	ChainTxCount    uint64   `json:"m_chain_tx_count"`
	BaseMTP         *int64   `json:"base_mtp,omitempty"`
	BaseHeader      string   `json:"base_header,omitempty"`
	Chainwork       string   `json:"chainwork,omitempty"`
	BaseTailHeaders []string `json:"base_tail_headers,omitempty"`
}

// LoadCampaignAssumeUTXO implements the HASHHOG_CAMPAIGN_ASSUMEUTXO flag.
// Call exactly once at startup, immediately after params is resolved
// (MainnetParams()/Testnet4Params()/RegtestParams()/...) and before anything
// consults its AssumeUTXO data.
//
//   - Unset/empty HASHHOG_CAMPAIGN_ASSUMEUTXO: returns (0, nil) immediately.
//     This is the ONLY code path taken by default — a single os.Getenv, no
//     table copied or mutated, no file touched. Bit-identical to today.
//   - Set: reads and parses the file at that path (JSON array of entries per
//     the schema above), validates each entry (height > 0, valid 32-byte hex
//     for blockhash/hash_serialized, no duplicate height/blockhash WITHIN the
//     file), then refuses (non-nil error) if any entry's height or blockhash
//     collides with an entry already present in the network's EFFECTIVE
//     table (consensus.AssumeUTXOParamsForNetwork(params)) — campaign data
//     may never override a production/Core-parity entry. On success the
//     entries are appended: for regtest, via RegisterRegtestAssumeUTXO (the
//     existing runtime-registerable whitelist, so they show up merged with
//     the Core-parity 110/200/299 table through RegtestAssumeUTXOParams());
//     for every other network, params.AssumeUTXO is replaced with a new
//     *AssumeUTXOParams holding the built-in entries plus the campaign
//     entries (the built-in package-level table, e.g. MainnetAssumeUTXOParams,
//     is never mutated in place — only the ChainParams.AssumeUTXO pointer on
//     the caller's params is swapped).
//
// Returns the number of entries loaded (0 when unset) and logs the loud,
// greppable startup banner "[CAMPAIGN-ASSUMEUTXO] loaded N entries from
// <path> heights=[...]" on success, so tools/fleet-monitor.sh can alert if
// this ever fires against a production log.
func LoadCampaignAssumeUTXO(params *ChainParams) (int, error) {
	path := os.Getenv(CampaignAssumeUTXOEnvVar)
	if path == "" {
		return 0, nil
	}
	if params == nil {
		return 0, fmt.Errorf("%s=%q set but no chain params selected yet", CampaignAssumeUTXOEnvVar, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", CampaignAssumeUTXOEnvVar, path, err)
	}

	var rawEntries []campaignAssumeUTXOEntry
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return 0, fmt.Errorf("%s=%q: invalid JSON: %w", CampaignAssumeUTXOEnvVar, path, err)
	}
	if len(rawEntries) == 0 {
		return 0, fmt.Errorf("%s=%q: no entries", CampaignAssumeUTXOEnvVar, path)
	}

	entries, err := parseCampaignAssumeUTXOEntries(rawEntries)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", CampaignAssumeUTXOEnvVar, path, err)
	}

	// Refuse on collision with a built-in (non-campaign) entry: campaign data
	// may never override a production hash. Checked against the EFFECTIVE
	// table (Core-parity regtest entries included), not just the raw
	// params.AssumeUTXO field.
	existing := AssumeUTXOParamsForNetwork(params)
	if existing != nil {
		for _, e := range entries {
			if d := existing.ForHeight(e.Height); d != nil {
				return 0, fmt.Errorf("%s=%q: height %d collides with an existing assumeutxo entry",
					CampaignAssumeUTXOEnvVar, path, e.Height)
			}
			if d := existing.ForBlockHash(e.BlockHash); d != nil {
				return 0, fmt.Errorf("%s=%q: blockhash %s collides with an existing assumeutxo entry",
					CampaignAssumeUTXOEnvVar, path, e.BlockHash.String())
			}
		}
	}

	if params.Name == "regtest" {
		for _, e := range entries {
			RegisterRegtestAssumeUTXO(e)
		}
	} else {
		var builtin []AssumeUTXOData
		if existing != nil {
			builtin = existing.Data
		}
		merged := make([]AssumeUTXOData, 0, len(builtin)+len(entries))
		merged = append(merged, builtin...)
		merged = append(merged, entries...)
		params.AssumeUTXO = &AssumeUTXOParams{Data: merged}
	}

	heights := make([]int32, len(entries))
	for i, e := range entries {
		heights[i] = e.Height
	}
	log.Printf("[CAMPAIGN-ASSUMEUTXO] loaded %d entries from %s heights=%v", len(entries), path, heights)
	return len(entries), nil
}

// parseCampaignAssumeUTXOEntries validates and converts the raw JSON entries
// (display-order hex) into AssumeUTXOData (internal byte order). Pure
// function, no global state — the collision-with-built-in check lives in
// LoadCampaignAssumeUTXO since it needs the network's existing table.
func parseCampaignAssumeUTXOEntries(rawEntries []campaignAssumeUTXOEntry) ([]AssumeUTXOData, error) {
	entries := make([]AssumeUTXOData, 0, len(rawEntries))
	seenHeight := make(map[int32]bool, len(rawEntries))
	seenHash := make(map[wire.Hash256]bool, len(rawEntries))

	for i, re := range rawEntries {
		if re.Height <= 0 {
			return nil, fmt.Errorf("entry %d: height must be > 0, got %d", i, re.Height)
		}
		blockHash, err := wire.NewHash256FromHex(re.BlockHash)
		if err != nil {
			return nil, fmt.Errorf("entry %d: blockhash: %w", i, err)
		}
		hashSerialized, err := wire.NewHash256FromHex(re.HashSerialized)
		if err != nil {
			return nil, fmt.Errorf("entry %d: hash_serialized: %w", i, err)
		}
		if seenHeight[re.Height] {
			return nil, fmt.Errorf("entry %d: duplicate height %d within campaign file", i, re.Height)
		}
		if seenHash[blockHash] {
			return nil, fmt.Errorf("entry %d: duplicate blockhash within campaign file", i)
		}
		seenHeight[re.Height] = true
		seenHash[blockHash] = true

		// Optional snapshot-base ancestry. Validated structurally here
		// (well-formed hex, 80-byte headers, prev-hash linkage, last header
		// hashes to this entry's blockhash); proof-of-work is checked later,
		// in HeaderIndex.GraftSnapshotBase, which has the network's PowLimit.
		tail, err := parseCampaignBaseTail(re, blockHash)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}

		var chainwork *big.Int
		if re.Chainwork != "" {
			cw, ok := new(big.Int).SetString(strings.TrimPrefix(re.Chainwork, "0x"), 16)
			if !ok || cw.Sign() < 0 {
				return nil, fmt.Errorf("entry %d: chainwork: not a hex integer", i)
			}
			chainwork = cw
		}

		entries = append(entries, AssumeUTXOData{
			Height:          re.Height,
			HashSerialized:  hashSerialized,
			ChainTxCount:    re.ChainTxCount,
			BlockHash:       blockHash,
			BaseTailHeaders: tail,
			Chainwork:       chainwork,
		})
	}
	return entries, nil
}

// parseCampaignBaseTail decodes an entry's base-tail header band.
//
// The band is ASCENDING and its LAST header is the snapshot base's own header.
// When only `base_header` is supplied (the original spec's shape) the band is
// that single header. When both are supplied they must agree: `base_tail_headers`
// already ends with the base header, so a mismatch means the fixture is
// internally inconsistent and is refused rather than silently preferred one way.
//
// Structural invariants enforced (all of them, because this is consensus-
// critical input that will be spliced straight into the header index):
//   - every element is exactly 80 bytes of hex and deserialises;
//   - each header's PrevBlock equals the double-SHA256 of its predecessor;
//   - the last header hashes to the entry's declared blockhash;
//   - the band is no longer than the base height allows (heights stay >= 0).
//
// Returns nil (no error) when the entry carries no ancestry at all — legacy
// fixtures stay loadable, they just cannot present the snapshot tip.
func parseCampaignBaseTail(re campaignAssumeUTXOEntry, baseHash wire.Hash256) ([]wire.BlockHeader, error) {
	raw := re.BaseTailHeaders
	if len(raw) == 0 {
		if re.BaseHeader == "" {
			return nil, nil
		}
		raw = []string{re.BaseHeader}
	} else if re.BaseHeader != "" && !strings.EqualFold(raw[len(raw)-1], re.BaseHeader) {
		return nil, fmt.Errorf("base_header does not match the last base_tail_headers entry")
	}

	if int64(len(raw))-1 > int64(re.Height) {
		return nil, fmt.Errorf("base_tail_headers has %d entries but base height is only %d",
			len(raw), re.Height)
	}

	headers := make([]wire.BlockHeader, 0, len(raw))
	for i, h := range raw {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("base_tail_headers[%d]: %w", i, err)
		}
		if len(b) != 80 {
			return nil, fmt.Errorf("base_tail_headers[%d]: got %d bytes, want 80", i, len(b))
		}
		var hdr wire.BlockHeader
		if err := hdr.Deserialize(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("base_tail_headers[%d]: %w", i, err)
		}
		if i > 0 && hdr.PrevBlock != headers[i-1].BlockHash() {
			return nil, fmt.Errorf("base_tail_headers[%d]: prev-hash does not link to [%d]", i, i-1)
		}
		headers = append(headers, hdr)
	}

	if got := headers[len(headers)-1].BlockHash(); got != baseHash {
		return nil, fmt.Errorf("last base_tail_headers entry hashes to %s, not the entry blockhash %s",
			got.String(), baseHash.String())
	}
	return headers, nil
}
