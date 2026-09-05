package consensus

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// assumeutxo_graft_test.go — pins the -load-snapshot ACTIVE-CHAIN-VIEW fix.
//
// The defect: loadSnapshotFromFile promoted a snapshot in the DATABASE (coins,
// coins marker, chainstate pointer) but never placed the base block in the
// header index, so ChainManager.loadChainState could not resolve the saved tip
// to a *BlockNode and parked in pendingRecovery. With no peers at all the node
// read the snapshot, persisted it, re-read it on restart — and still answered
// genesis on getblockcount / getbestblockhash / getchainstates.
//
// Bitcoin Core cannot reach that state: ActivateSnapshot REFUSES a snapshot
// whose base header is not already in the headers chain
// (bitcoin-core/src/validation.cpp:5611-5616), so
// `snapshot_chainstate.m_chain.SetTip(*snapshot_start_block)`
// (validation.cpp:5917) always has a real block index entry to point at.
//
// Fixture: mainnet block 6299, the M2 boundary-campaign rung
// (tools/campaign-assumeutxo/rung-6299.json). Real header bytes, so the
// proof-of-work re-check inside GraftSnapshotBase is exercised for real.
const (
	rung6299Hash      = "0000000085292b3042abf1f35a48e42db1406537d4937986a42fa8d5b3250979"
	rung6299HashSer   = "e3e6c52fe422fa9085668ce14cb0079d6ec1e511b6c311773722294126535e68"
	rung6299Header    = "01000000a9da432167dafd144eec8132591e1653678b9897313bd617228405d20000000048b614cf433585962cc62f2b4e9a4c672a0f6effd86000d7f9dc9f2687d0c629b67fae49ffff001d3a46ca54"
	rung6299Chainwork = "0000000000000000000000000000000000000000000000000000189c189c189c"
)

// parseOneCampaignEntry runs the real JSON path (not a hand-built struct) so a
// schema change in the shared fixture format is caught here.
func parseOneCampaignEntry(t *testing.T, doc string) AssumeUTXOData {
	t.Helper()
	var raw []campaignAssumeUTXOEntry
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	entries, err := parseCampaignAssumeUTXOEntries(raw)
	if err != nil {
		t.Fatalf("parseCampaignAssumeUTXOEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	return entries[0]
}

func rung6299Doc(extra string) string {
	return `[{"height":6299,` +
		`"blockhash":"` + rung6299Hash + `",` +
		`"hash_serialized":"` + rung6299HashSer + `",` +
		`"m_chain_tx_count":6371,` +
		`"base_mtp":1236165740,` +
		`"base_header":"` + rung6299Header + `",` +
		`"chainwork":"` + rung6299Chainwork + `"` + extra + `}]`
}

// TestCampaignEntryCarriesBaseAncestry: base_header and chainwork used to be
// parsed and thrown away ("blockbrew's AssumeUTXOData has no slot for them").
// They are the snapshot base's identity and its cumulative work — without them
// the base cannot be placed in the header index at all.
func TestCampaignEntryCarriesBaseAncestry(t *testing.T) {
	e := parseOneCampaignEntry(t, rung6299Doc(""))

	if len(e.BaseTailHeaders) != 1 {
		t.Fatalf("base_header should yield a 1-header band, got %d", len(e.BaseTailHeaders))
	}
	want, _ := wire.NewHash256FromHex(rung6299Hash)
	if got := e.BaseTailHeaders[0].BlockHash(); got != want {
		t.Fatalf("band header hashes to %s, want %s", got.String(), want.String())
	}
	if e.Chainwork == nil {
		t.Fatal("chainwork was dropped")
	}
	if e.Chainwork.Text(16) != "189c189c189c" {
		t.Fatalf("chainwork = %s, want 189c189c189c", e.Chainwork.Text(16))
	}
}

// TestCampaignEntryRejectsInconsistentBand: a band whose last header does not
// hash to the declared blockhash is a broken fixture, not something to prefer
// one way over the other. This is consensus-critical input spliced straight
// into the header index.
func TestCampaignEntryRejectsInconsistentBand(t *testing.T) {
	// Same header, but declared under a different (real, mainnet) blockhash.
	doc := `[{"height":6299,` +
		`"blockhash":"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",` +
		`"hash_serialized":"` + rung6299HashSer + `",` +
		`"m_chain_tx_count":6371,` +
		`"base_header":"` + rung6299Header + `"}]`
	var raw []campaignAssumeUTXOEntry
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := parseCampaignAssumeUTXOEntries(raw); err == nil {
		t.Fatal("a band that does not hash to the entry blockhash must be refused")
	}
}

// TestGraftSnapshotBaseBecomesTheChainView is the regression: after grafting,
// the base is resolvable BY HASH (which is exactly what
// ChainManager.loadChainState does with the saved chainstate pointer) and is
// the index's best tip.
func TestGraftSnapshotBaseBecomesTheChainView(t *testing.T) {
	e := parseOneCampaignEntry(t, rung6299Doc(""))
	idx := NewHeaderIndex(MainnetParams())

	baseHash, _ := wire.NewHash256FromHex(rung6299Hash)
	if idx.GetNode(baseHash) != nil {
		t.Fatal("precondition: a fresh index must not know the snapshot base")
	}

	base, err := idx.GraftSnapshotBase(e.BaseTailHeaders, e.Height, e.Chainwork)
	if err != nil {
		t.Fatalf("GraftSnapshotBase: %v", err)
	}
	if base.Height != 6299 || base.Hash != baseHash {
		t.Fatalf("grafted node = %s@%d, want %s@6299", base.Hash.String(), base.Height, baseHash.String())
	}
	// The lookup loadChainState performs.
	if node := idx.GetNode(baseHash); node == nil || node.Height != 6299 {
		t.Fatal("snapshot base is not resolvable by hash after grafting")
	}
	if idx.BestHeight() != 6299 {
		t.Fatalf("best height = %d, want 6299", idx.BestHeight())
	}
	if tip := idx.BestTip(); tip == nil || tip.Hash != baseHash {
		t.Fatal("snapshot base did not become the best tip")
	}
	if sb := idx.SnapshotBase(); sb == nil || sb.Hash != baseHash {
		t.Fatal("snapshot base was not recorded on the index")
	}
	// The base is a DETACHED root: nothing links it to genesis, and it must not
	// pretend otherwise.
	if base.Parent != nil {
		t.Fatal("a one-header band's base must have no parent")
	}
	if base.GetAncestor(0) != nil {
		t.Fatal("GetAncestor below the band must return nil, not genesis")
	}
	// Second graft is a no-op returning the same node (restart re-graft).
	again, err := idx.GraftSnapshotBase(e.BaseTailHeaders, e.Height, e.Chainwork)
	if err != nil || again != base {
		t.Fatalf("re-graft should be idempotent, got node=%v err=%v", again, err)
	}
}

// TestGraftSnapshotBaseRejectsBadInput: the graft bypasses AddHeader's
// contextual gates by construction (their inputs live below the band), so the
// checks it DOES run are the only thing standing between a hostile fixture and
// the header index.
func TestGraftSnapshotBaseRejectsBadInput(t *testing.T) {
	e := parseOneCampaignEntry(t, rung6299Doc(""))
	work := e.Chainwork

	t.Run("no chainwork", func(t *testing.T) {
		idx := NewHeaderIndex(MainnetParams())
		if _, err := idx.GraftSnapshotBase(e.BaseTailHeaders, e.Height, nil); err == nil {
			t.Fatal("a grafted tip with unknowable cumulative work must be refused")
		}
	})

	t.Run("no headers", func(t *testing.T) {
		idx := NewHeaderIndex(MainnetParams())
		if _, err := idx.GraftSnapshotBase(nil, 6299, work); err == nil {
			t.Fatal("empty band must be refused")
		}
	})

	t.Run("band longer than the base height", func(t *testing.T) {
		idx := NewHeaderIndex(RegtestParams())
		if _, err := idx.GraftSnapshotBase(regtestBand(t, 2), 0, work); err == nil {
			t.Fatal("a band that would run below genesis must be refused")
		}
	})

	t.Run("unlinked band", func(t *testing.T) {
		idx := NewHeaderIndex(RegtestParams())
		band := regtestBand(t, 3)
		band[2].PrevBlock = wire.Hash256{} // no longer links to band[1]
		if _, err := idx.GraftSnapshotBase(band, 100, work); err == nil {
			t.Fatal("a band whose headers do not link must be refused")
		}
	})

	t.Run("bad proof of work", func(t *testing.T) {
		idx := NewHeaderIndex(MainnetParams())
		bad := []wire.BlockHeader{e.BaseTailHeaders[0]}
		bad[0].Nonce++ // hash no longer meets the target
		if _, err := idx.GraftSnapshotBase(bad, 6299, work); err == nil {
			t.Fatal("a header failing PoW must be refused")
		}
	})

	t.Run("chainwork too small for the band", func(t *testing.T) {
		idx := NewHeaderIndex(RegtestParams())
		if _, err := idx.GraftSnapshotBase(regtestBand(t, 4), 100, big.NewInt(1)); err == nil {
			t.Fatal("cumulative work smaller than the band's own work must be refused")
		}
	})
}

// regtestBand builds n linked headers that pass regtest proof-of-work, for the
// structural cases that do not need real mainnet bytes.
func regtestBand(t *testing.T, n int) []wire.BlockHeader {
	t.Helper()
	params := RegtestParams()
	band := make([]wire.BlockHeader, 0, n)
	for i := 0; i < n; i++ {
		hdr := wire.BlockHeader{
			Version:   1,
			Timestamp: uint32(1600000000 + i),
			Bits:      params.PowLimitBits,
		}
		if i > 0 {
			hdr.PrevBlock = band[i-1].BlockHash()
		}
		for hdr.Nonce = 0; hdr.Nonce < 1_000_000; hdr.Nonce++ {
			if CheckProofOfWork(hdr.BlockHash(), hdr.Bits, params.PowLimit) == nil {
				break
			}
		}
		if err := CheckProofOfWork(hdr.BlockHash(), hdr.Bits, params.PowLimit); err != nil {
			t.Fatalf("could not build a regtest header at index %d: %v", i, err)
		}
		band = append(band, hdr)
	}
	return band
}
