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
	// params.AssumeUTXO field — by height AND by blockhash (a fixture that
	// puts a built-in blockhash at a different height is stale or wrong).
	//
	// The ONE non-refusal: an entry whose whole commitment — height,
	// blockhash, hash_serialized AND m_chain_tx_count — is IDENTICAL to the
	// existing row is not an override but a second source agreeing with the
	// first (Core keys an m_assumeutxo_data row by height+blockhash and checks
	// the snapshot against its hash_serialized; a byte-identical row adds no
	// new trust). R4's rung at 910,000 was minted by dumping a Core clone
	// there and came out equal to Core's own hardcoded anchor; refusing it
	// BLOCKED the slice with the best provenance of any rung. Such an entry
	// CONFIRMS the row: the commitment is kept, and only the supplemental
	// ancestry the row lacks (BaseTailHeaders, Chainwork — which the
	// -load-snapshot boot needs in activateSnapshotChainView and the built-in
	// rows never carry) is filled in. A contradiction of anything the row
	// already pins is still refused. Hashes are compared as parsed 32-byte
	// values, so hex case cannot matter.
	existing := AssumeUTXOParamsForNetwork(params)
	var fresh []AssumeUTXOData
	confirmed := make(map[int32]AssumeUTXOData) // height -> merged row
	var confirmedHeights []int32
	for _, e := range entries {
		var byHeight, byHash *AssumeUTXOData
		if existing != nil {
			byHeight = existing.ForHeight(e.Height)
			byHash = existing.ForBlockHash(e.BlockHash)
		}
		if byHeight == nil && byHash == nil {
			fresh = append(fresh, e)
			continue
		}
		if byHeight == nil {
			return 0, fmt.Errorf("%s=%q: blockhash %s collides with an existing assumeutxo entry at height %d",
				CampaignAssumeUTXOEnvVar, path, e.BlockHash.String(), byHash.Height)
		}
		if byHash != nil && byHash != byHeight {
			return 0, fmt.Errorf("%s=%q: blockhash %s collides with an existing assumeutxo entry at height %d",
				CampaignAssumeUTXOEnvVar, path, e.BlockHash.String(), byHash.Height)
		}
		if diff := commitmentDiff(byHeight, &e); diff != "" {
			return 0, fmt.Errorf("%s=%q: height %d collides with an existing assumeutxo entry (%s differ from the existing entry)",
				CampaignAssumeUTXOEnvVar, path, e.Height, diff)
		}
		merged, err := mergeCampaignConfirmation(*byHeight, e)
		if err != nil {
			return 0, fmt.Errorf("%s=%q: entry at height %d matches the existing commitment but %w",
				CampaignAssumeUTXOEnvVar, path, e.Height, err)
		}
		confirmed[e.Height] = merged
		confirmedHeights = append(confirmedHeights, e.Height)
	}

	if params.Name == "regtest" {
		// A confirmed row is registered too: RegtestAssumeUTXOParams lets a
		// registered row with an IDENTICAL commitment stand in for the
		// Core-parity row, so the filled ancestry is what consumers see.
		for _, e := range entries {
			if m, ok := confirmed[e.Height]; ok {
				RegisterRegtestAssumeUTXO(m)
			} else {
				RegisterRegtestAssumeUTXO(e)
			}
		}
	} else {
		var builtin []AssumeUTXOData
		if existing != nil {
			builtin = existing.Data
		}
		merged := make([]AssumeUTXOData, 0, len(builtin)+len(fresh))
		for _, b := range builtin {
			if m, ok := confirmed[b.Height]; ok {
				b = m // replace in place in the COPY; the built-in table is never mutated
			}
			merged = append(merged, b)
		}
		merged = append(merged, fresh...)
		params.AssumeUTXO = &AssumeUTXOParams{Data: merged}
	}
	for _, h := range confirmedHeights {
		m := confirmed[h]
		log.Printf("[CAMPAIGN-ASSUMEUTXO] entry height %d is IDENTICAL to the existing assumeutxo commitment "+
			"(blockhash, hash_serialized, m_chain_tx_count) -- accepted as a confirmation; commitment kept, "+
			"base_tail_headers=%d chainwork_set=%v", h, len(m.BaseTailHeaders), m.Chainwork != nil)
	}

	heights := make([]int32, len(entries))
	for i, e := range entries {
		heights[i] = e.Height
	}
	log.Printf("[CAMPAIGN-ASSUMEUTXO] loaded %d entries from %s heights=%v (confirming existing: %v)",
		len(entries), path, heights, confirmedHeights)
	return len(entries), nil
}

// commitmentDiff names the commitment fields (blockhash, hash_serialized,
// m_chain_tx_count) on which a campaign entry differs from the existing row at
// its height, or "" when the commitment is identical.
func commitmentDiff(row, e *AssumeUTXOData) string {
	var d []string
	if row.BlockHash != e.BlockHash {
		d = append(d, "blockhash")
	}
	if row.HashSerialized != e.HashSerialized {
		d = append(d, "hash_serialized")
	}
	if row.ChainTxCount != e.ChainTxCount {
		d = append(d, "m_chain_tx_count")
	}
	return strings.Join(d, "/")
}

// mergeCampaignConfirmation returns a COPY of row (whose commitment the caller
// has already proven identical to e's) with e's supplemental ancestry filling
// only the gaps: BaseTailHeaders and Chainwork. A value e supplies that
// differs from one the row already pins is a contradiction and refuses. The
// band itself was structurally verified by parseCampaignBaseTail (80-byte,
// linked, last header hashes to the blockhash); its proof-of-work is checked
// at graft time like any campaign band.
func mergeCampaignConfirmation(row, e AssumeUTXOData) (AssumeUTXOData, error) {
	if len(e.BaseTailHeaders) > 0 && len(row.BaseTailHeaders) > 0 {
		if len(e.BaseTailHeaders) != len(row.BaseTailHeaders) {
			return row, fmt.Errorf("its base_tail_headers contradict the existing row's band (length %d vs %d)",
				len(e.BaseTailHeaders), len(row.BaseTailHeaders))
		}
		for i := range e.BaseTailHeaders {
			if e.BaseTailHeaders[i] != row.BaseTailHeaders[i] {
				return row, fmt.Errorf("its base_tail_headers contradict the existing row's band (element %d)", i)
			}
		}
	}
	if e.Chainwork != nil && row.Chainwork != nil && e.Chainwork.Cmp(row.Chainwork) != 0 {
		return row, fmt.Errorf("its chainwork %s contradicts the existing row's chainwork %s",
			e.Chainwork.Text(16), row.Chainwork.Text(16))
	}
	if len(row.BaseTailHeaders) == 0 && len(e.BaseTailHeaders) > 0 {
		row.BaseTailHeaders = append([]wire.BlockHeader(nil), e.BaseTailHeaders...)
	}
	if row.Chainwork == nil && e.Chainwork != nil {
		row.Chainwork = new(big.Int).Set(e.Chainwork)
	}
	return row, nil
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
