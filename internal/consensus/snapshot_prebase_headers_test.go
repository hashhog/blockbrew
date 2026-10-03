package consensus

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// snapshot_prebase_headers_test.go — a snapshot-booted node must not decide
// ancestor-dependent consensus values from the detached base-tail band.
//
// Core's ActivateSnapshot only runs with the full header chain already present
// (headers-first), so BIP-68's GetAncestor(nCoinHeight-1)->GetMedianTimePast()
// (consensus/tx_verify.cpp CalculateSequenceLocks) always sees 11 real
// headers. A campaign snapshot boot grafts only ~2,027 headers below the base;
// a coin ~2,020 blocks under the base needs headers ~2,030 below it. Two fleet
// nodes rejected valid mainnet blocks on exactly this:
//   - hotbuns 942168 (snapshot 940000, band 937974..940000, coin 937977)
//   - camlcoin 932256 (snapshot 930000, band 927974..930000, coin 927979)
// Both spend with nSequence 0x004013c7 (time lock 5063 * 512 s).

// window builds a linked chain of nodes with the given timestamps, heights
// first..first+len-1. When detachedFrom > first, nodes below detachedFrom are
// dropped and the node AT detachedFrom has no Parent — the grafted-band shape.
func window(first int32, ts []uint32, detachedFrom int32) []*BlockNode {
	var out []*BlockNode
	var parent *BlockNode
	for i, t := range ts {
		h := first + int32(i)
		if h < detachedFrom {
			continue
		}
		n := &BlockNode{Height: h, Parent: parent, Header: wire.BlockHeader{Timestamp: t}}
		out = append(out, n)
		parent = n
	}
	return out
}

func medianOf(ts []uint32) int64 {
	c := append([]uint32(nil), ts...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return int64(c[len(c)/2])
}

func TestBIP68CoinMTPFailsClosedOnPartialSnapshotWindow(t *testing.T) {
	const seq = 0x004013c7 // time-based, 5063 * 512 s
	cases := []struct {
		name        string
		coinHeight  int32
		bandLowest  int32
		coinWindow  []uint32 // timestamps coinHeight-11 .. coinHeight-1 (Core mainnet)
		blockWindow []uint32 // timestamps block-11 .. block-1
		coreCoinMTP int64
		partialMTP  int64 // what a partial-window median gives (the false reject)
	}{
		{
			name: "hotbuns-942168", coinHeight: 937977, bandLowest: 937974,
			coinWindow:  []uint32{1771849622, 1771850239, 1771852311, 1771853345, 1771853423, 1771853536, 1771854580, 1771854720, 1771855429, 1771855669, 1771857430},
			blockWindow: []uint32{1774443563, 1774443738, 1774444197, 1774444556, 1774445825, 1774446410, 1774446475, 1774446708, 1774446743, 1774448392, 1774449944},
			coreCoinMTP: 1771853536, partialMTP: 1771855669,
		},
		{
			name: "camlcoin-932256", coinHeight: 927979, bandLowest: 927974,
			coinWindow:  []uint32{1765801866, 1765802240, 1765802404, 1765802919, 1765803403, 1765804000, 1765807568, 1765807695, 1765808303, 1765808711, 1765809159},
			blockWindow: []uint32{1768395756, 1768395791, 1768396809, 1768397732, 1768398207, 1768398550, 1768398617, 1768398750, 1768400546, 1768400771, 1768401238},
			coreCoinMTP: 1765804000, partialMTP: 1765808303,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first := c.coinHeight - 11
			blockMTP := medianOf(c.blockWindow)
			tx := &wire.MsgTx{Version: 2, TxIn: []*wire.TxIn{{Sequence: seq}}}
			lockWith := func(coinMTP int64) bool {
				l := CalculateSequenceLocks(tx, []int32{c.coinHeight}, func(int32) int64 { return coinMTP })
				return EvaluateSequenceLocks(l, c.coinHeight+4000, blockMTP)
			}

			// Full window (Core's state): Core's number, and the block is valid.
			full := window(first, c.coinWindow, 0)
			anc := full[len(full)-1]
			got, err := bip68CoinMTP(anc, c.coinHeight-1)
			if err != nil || got != c.coreCoinMTP {
				t.Fatalf("full window: got %d err=%v, want Core's %d", got, err, c.coreCoinMTP)
			}
			if !lockWith(got) {
				t.Fatal("with Core's coin MTP the spend must satisfy its time lock")
			}

			// Band-shaped window: the old lookup's answer is the wrong number,
			// and it flips the verdict — that is the false reject.
			band := window(first, c.coinWindow, c.bandLowest)
			tip := band[len(band)-1]
			if old := tip.GetMedianTimePast(); old != c.partialMTP {
				t.Fatalf("partial-window median = %d, want the observed %d", old, c.partialMTP)
			}
			if lockWith(c.partialMTP) {
				t.Fatal("precondition: the partial-window MTP should reproduce the false reject")
			}
			// The fixed lookup refuses instead of answering.
			if v, err := bip68CoinMTP(tip, c.coinHeight-1); !errors.Is(err, ErrMissingAncestorHeader) {
				t.Fatalf("partial window must fail closed, got %d err=%v", v, err)
			}
			// An ancestor absent altogether: the old `return 0` satisfied every
			// time lock (fail-open). Now it is an error.
			if !lockWith(0) {
				t.Fatal("precondition: coin MTP 0 satisfies the lock (the fail-open the fix removes)")
			}
			if _, err := bip68CoinMTP(tip, c.bandLowest-1); !errors.Is(err, ErrMissingAncestorHeader) {
				t.Fatalf("missing ancestor must fail closed, got err=%v", err)
			}
		})
	}
}

// loadMainnetHeaders0to2030 reads real mainnet headers 0..2030 (from Core),
// which include the first retarget boundary (2016).
func loadMainnetHeaders0to2030(t *testing.T) []wire.BlockHeader {
	t.Helper()
	f, err := os.Open("testdata/mainnet_headers_0_2030.hex")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var out []wire.BlockHeader
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b, err := hex.DecodeString(sc.Text())
		if err != nil || len(b) != 80 {
			t.Fatalf("bad fixture line %d", len(out))
		}
		var h wire.BlockHeader
		if err := h.Deserialize(bytes.NewReader(b)); err != nil {
			t.Fatalf("deserialize %d: %v", len(out), err)
		}
		out = append(out, h)
	}
	if len(out) != 2031 {
		t.Fatalf("fixture has %d headers, want 2031", len(out))
	}
	if out[0].BlockHash() != MainnetParams().GenesisHash {
		t.Fatal("fixture does not start at genesis")
	}
	return out
}

func workThrough(hs []wire.BlockHeader) *big.Int {
	w := new(big.Int)
	for i := range hs {
		w.Add(w, CalcWork(hs[i].Bits))
	}
	return w
}

type mapHeaderSource map[wire.Hash256]*wire.BlockHeader

func (m mapHeaderSource) GetBlockHeader(h wire.Hash256) (*wire.BlockHeader, error) {
	if v, ok := m[h]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func TestSnapshotBandBackfillSplicesOntoGenesis(t *testing.T) {
	hs := loadMainnetHeaders0to2030(t)
	const baseH, bandLow = 2030, 2000
	work := workThrough(hs)

	idx := NewHeaderIndex(MainnetParams())
	base, err := idx.GraftSnapshotBase(hs[bandLow:], baseH, work)
	if err != nil {
		t.Fatalf("graft: %v", err)
	}
	if !idx.SnapshotHeadersPending() {
		t.Fatal("a detached band must hold block connection")
	}
	// Inside the band: fine. Across the root: fail closed.
	if _, err := base.GetMedianTimePastChecked(); err != nil {
		t.Fatalf("base MTP window lies inside the band: %v", err)
	}
	if _, err := bip68CoinMTP(base, 2004); !errors.Is(err, ErrMissingAncestorHeader) {
		t.Fatalf("coin MTP across the band root must fail closed, got %v", err)
	}
	// Retarget at 2016 needs height 0: fail closed rather than parent bits.
	n2015 := base.GetAncestor(2015)
	if err := idx.checkWorkAncestorsPresent(hs[2016], n2015, 2016); !errors.Is(err, ErrMissingAncestorHeader) {
		t.Fatalf("retarget without its period-start header must fail closed, got %v", err)
	}
	// Header acceptance on a band parent near the root: AddHeader's
	// time-too-old MTP would be a partial window.
	if _, err := base.GetAncestor(2003).GetMedianTimePastChecked(); !errors.Is(err, ErrMissingAncestorHeader) {
		t.Fatalf("parent MTP across the band root must fail closed, got %v", err)
	}

	// Backfill, in two batches, with a non-linking batch in between.
	if !idx.BackfillExpects(hs[1]) {
		t.Fatal("first backfill batch must be recognised")
	}
	loc, stop, ok := idx.BackfillRequest()
	if !ok || stop != hs[bandLow].BlockHash() || len(loc) == 0 || loc[0] != hs[0].BlockHash() {
		t.Fatalf("backfill request: ok=%v stop=%s loc=%d", ok, stop.String(), len(loc))
	}
	added, done, err := idx.AddBackfillHeaders(hs[1:1000])
	if err != nil || done || len(added) != 999 {
		t.Fatalf("batch 1: added=%d done=%v err=%v", len(added), done, err)
	}
	if _, _, err := idx.AddBackfillHeaders(hs[1500:1600]); !errors.Is(err, ErrBackfillHeader) {
		t.Fatalf("non-linking batch must be rejected, got %v", err)
	}
	if !idx.SnapshotHeadersPending() {
		t.Fatal("still pending mid-backfill")
	}
	added, done, err = idx.AddBackfillHeaders(hs[1000 : bandLow+1]) // ends with the band root
	if err != nil || !done || len(added) != 1000 {
		t.Fatalf("batch 2: added=%d done=%v err=%v", len(added), done, err)
	}
	if idx.SnapshotHeadersPending() {
		t.Fatal("splice must release block connection")
	}

	// Now every value is Core's.
	want := int64(0)
	{
		ts := make([]uint32, 0, 11)
		for h := 1994; h <= 2004; h++ {
			ts = append(ts, hs[h].Timestamp)
		}
		want = medianOf(ts)
	}
	if got, err := bip68CoinMTP(base, 2004); err != nil || got != want {
		t.Fatalf("coin MTP after splice = %d err=%v, want %d", got, err, want)
	}
	if g := base.GetAncestor(0); g == nil || g.Hash != hs[0].BlockHash() {
		t.Fatal("base must reach genesis after the splice")
	}
	if a := base.GetAncestor(1000); a == nil || a.Hash != hs[1000].BlockHash() {
		t.Fatal("GetAncestor through the spliced chain returned the wrong node")
	}
	if err := idx.checkWorkAncestorsPresent(hs[2016], base.GetAncestor(2015), 2016); err != nil {
		t.Fatalf("retarget after splice: %v", err)
	}
	if idx.BestTip() != base || base.TotalWork.Cmp(work) != 0 {
		t.Fatal("backfill must not move the best tip or its work")
	}

	// Restart: the persisted chain re-grafts LINKED (not detached).
	src := mapHeaderSource{}
	for i := range hs {
		src[hs[i].BlockHash()] = &hs[i]
	}
	idx2 := NewHeaderIndex(MainnetParams())
	n, err := idx2.HydrateSnapshotBaseFromDB(src, hs[baseH].BlockHash(), baseH, work)
	if err != nil || n != baseH {
		t.Fatalf("re-graft: n=%d err=%v", n, err)
	}
	if idx2.SnapshotHeadersPending() {
		t.Fatal("a fully persisted chain must re-graft linked to genesis")
	}
}

func TestSnapshotBandSpliceRejectsWrongChainwork(t *testing.T) {
	hs := loadMainnetHeaders0to2030(t)
	work := new(big.Int).Add(workThrough(hs), big.NewInt(1)) // the fixture lies by 1

	idx := NewHeaderIndex(MainnetParams())
	if _, err := idx.GraftSnapshotBase(hs[2000:], 2030, work); err != nil {
		t.Fatalf("graft: %v", err)
	}
	_, done, err := idx.AddBackfillHeaders(hs[1:2001])
	if done || !errors.Is(err, ErrBackfillHeader) {
		t.Fatalf("a band whose claimed work disagrees with genesis must not splice: done=%v err=%v", done, err)
	}
	if !idx.SnapshotHeadersPending() {
		t.Fatal("a refused splice must keep block connection held")
	}

	// Restart path, same lie.
	src := mapHeaderSource{}
	for i := range hs {
		src[hs[i].BlockHash()] = &hs[i]
	}
	idx2 := NewHeaderIndex(MainnetParams())
	if _, err := idx2.HydrateSnapshotBaseFromDB(src, hs[2030].BlockHash(), 2030, work); err == nil {
		t.Fatal("re-graft onto genesis with a wrong chainwork claim must be refused")
	}
}

func TestSnapshotBandBackfillRejectsBadHeader(t *testing.T) {
	hs := loadMainnetHeaders0to2030(t)
	idx := NewHeaderIndex(MainnetParams())
	if _, err := idx.GraftSnapshotBase(hs[2000:], 2030, workThrough(hs)); err != nil {
		t.Fatalf("graft: %v", err)
	}
	bad := append([]wire.BlockHeader(nil), hs[1:20]...)
	bad[10].Nonce ^= 1 // tampered: fails proof of work
	added, done, err := idx.AddBackfillHeaders(bad)
	if done || !errors.Is(err, ErrBackfillHeader) || len(added) != 10 {
		t.Fatalf("tampered backfill header: added=%d done=%v err=%v", len(added), done, err)
	}
}
