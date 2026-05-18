// Package rpc W141 ZMQ + REST + notification-scripts audit (DISCOVERY).
//
// Wave W141 (discovery only — no production code changes). See
// audit/w141_zmq_rest_notify.md for the full writeup of all 30 gates
// and 24 BUGs.
//
// Each test below pins down one audit gate. Most are structural xfails
// implemented as `t.Skip("BUG-N: ...")` with a small piece of evidence
// (a grep, an HTTP response shape, or a file existence check) that
// remains valid until the bug is fixed. A future fix wave converts the
// Skip into a real assertion — the bug ID per test name maps 1-1 to
// the audit doc.
//
// The 30 gates are split across 3 subsystems:
//   - A1..A10 — ZMQ publisher (cmd/blockbrew/zmqpub.go)
//   - B1..B10 — REST API (internal/rpc/rest.go)
//   - C1..C10 — notification scripts (cmd/blockbrew/* — none exist)
//
// Cross-refs:
//   - W124 BUG-10 absorbs C4/C5 (startup/shutdown notify hooks).
//   - W124 BUG-16 absorbs C1/C2/C3 (block/alert/wallet notify hooks).
//   - W133 G25/BUG-13 documents the missing BlockUntilSyncedToCurrentChain
//     on the BIP-157 index — same primitive REST gate B10 (BUG-18) needs.
package rpc

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// w141RepoRoot walks up from this file until it locates go.mod.
func w141RepoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(here)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate go.mod above test file")
	return ""
}

// w141Grep runs `grep -rn pattern paths...` from the repo root.
// Returns "" when grep exits 1 (no matches). Excludes *_test.go so audit
// files don't show up as consumers of the very identifier they audit.
func w141Grep(t *testing.T, pattern string, paths ...string) string {
	t.Helper()
	root := w141RepoRoot(t)
	args := append([]string{
		"-rn",
		"--include=*.go",
		"--exclude=*_test.go",
		pattern,
	}, paths...)
	cmd := exec.Command("grep", args...)
	cmd.Dir = root
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// w141ReadFile reads the named repo-relative file or fails the test.
func w141ReadFile(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(w141RepoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// ─────────────────────────────────────────────────────────────────────
// Subsystem A — ZMQ publisher (10 gates / 9 BUGs)
// ─────────────────────────────────────────────────────────────────────

// G_A1 — sanity: all 5 Core topic strings present.
func TestW141_A1_FiveZMQTopicStringsDeclared_PRESENT(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	for _, want := range []string{
		`zmqTopicHashBlock = "hashblock"`,
		`zmqTopicHashTx    = "hashtx"`,
		`zmqTopicRawBlock  = "rawblock"`,
		`zmqTopicRawTx     = "rawtx"`,
		`zmqTopicSequence  = "sequence"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing topic declaration: %q", want)
		}
	}
}

// G_A2 BUG-1 — hashblock bytes NOT reversed to display order on the wire.
func TestW141_A2_HashBlockNotReversed_BUG1(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	// Evidence: zmqpub.go currently passes hash[:] directly.
	if !strings.Contains(src, `p.sendTopic(zmqTopicHashBlock, p.cfg.HashBlock, hash[:])`) {
		t.Fatalf("BUG-1 may be fixed: hashblock send-site no longer uses hash[:]\n%s",
			"(scan rejects audit-stale assertion; re-audit byte order)")
	}
	if strings.Contains(src, "data[31") || strings.Contains(src, "reverseBytes") {
		t.Fatalf("BUG-1 may be fixed: zmqpub.go now contains byte-reversal logic")
	}
	t.Skip("BUG-1 (CDIV): cmd/blockbrew/zmqpub.go:222 publishes pubhashblock with " +
		"internal (little-endian) byte order; Core zmqpublishnotifier.cpp:210-219 " +
		"reverses bytes (data[31-i] = hash.begin()[i]) so the wire is display order. " +
		"Every external ZMQ subscriber against blockbrew sees a reversed 32-byte " +
		"hash vs every other Core-compatible node. Fix: copy into a 32-byte buffer " +
		"with reversed indexing before sendTopic.")
}

// G_A3 BUG-2 — hashtx bytes NOT reversed.
func TestW141_A3_HashTxNotReversed_BUG2(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	if !strings.Contains(src, `p.sendTopic(zmqTopicHashTx, p.cfg.HashTx, hash[:])`) {
		t.Fatalf("BUG-2 may be fixed: hashtx send-site no longer uses hash[:]")
	}
	t.Skip("BUG-2 (CDIV): cmd/blockbrew/zmqpub.go:256 publishes pubhashtx with " +
		"internal byte order; Core zmqpublishnotifier.cpp:221-230 reverses bytes. " +
		"Same impact pattern as BUG-1, on transactions. Fix: reverse into a stack " +
		"buffer before sendTopic.")
}

// G_A4 BUG-3 — sequence body hash bytes NOT reversed (block-connect path).
func TestW141_A4_SequenceBodyNotReversed_BUG3(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	// Block-connect path: copy hash directly into the body.
	if !strings.Contains(src, `copy(seqBody[:32], hash[:])`) {
		t.Fatalf("BUG-3 may be fixed: sequence(C) body no longer uses copy(seqBody[:32], hash[:])")
	}
	// Tx-accept path: same pattern.
	if !strings.Contains(src, `copy(body[:32], hash[:])`) {
		t.Fatalf("BUG-3 may be fixed: sequence(A) body no longer uses copy(body[:32], hash[:])")
	}
	t.Skip("BUG-3 (CDIV): cmd/blockbrew/zmqpub.go:235-237 (sequence(C)) and " +
		"269-273 (sequence(A)) copy hash[:] directly into the sequence body; Core " +
		"zmqpublishnotifier.cpp:256-265 (SendSequenceMsg) reverses bytes " +
		"(data[31-i] = hash.begin()[i]) before the 1-byte label. Wire-format " +
		"break for every external sequence consumer. Fix: reverse before write.")
}

// G_A5 BUG-4 — no sequence(D) / hashtx / rawtx on block disconnect.
func TestW141_A5_NoBlockDisconnectFanOut_BUG4(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/main.go")
	// The OnBlockDisconnected callback must NOT mention any zmq fan-out.
	idx := strings.Index(src, "SetOnBlockDisconnected(func(block")
	if idx < 0 {
		t.Fatalf("SetOnBlockDisconnected wire site moved; re-audit")
	}
	// Inspect the next ~3000 chars (callback body).
	region := src[idx:]
	if len(region) > 4000 {
		region = region[:4000]
	}
	if strings.Contains(region, "zmqPub.PublishBlockDisconnected") ||
		strings.Contains(region, "zmqPub.PublishTxAccepted") ||
		strings.Contains(region, "PublishTxConfirmedInBlock") {
		t.Fatalf("BUG-4 may be fixed: OnBlockDisconnected now has ZMQ fan-out\n%s", region)
	}
	t.Skip("BUG-4 (P1 MISSING): cmd/blockbrew/main.go:880-925 SetOnBlockDisconnected " +
		"has zero ZMQ fan-out. Core zmqnotificationinterface.cpp:198-211 emits hashtx/" +
		"rawtx for every tx in the disconnected block AND sequence(D) for the block " +
		"hash. External tools tracking reorgs via sequence(D) (electrs, mempool.space, " +
		"nbxplorer) silently desync on every reorg. Fix: add PublishBlockDisconnected " +
		"helper and wire it before the early returns.")
}

// G_A6 BUG-5 — no sequence(R) on mempool removal.
func TestW141_A6_NoMempoolRemovalFanOut_BUG5(t *testing.T) {
	// Look for ZMQ-side fan-out symbols only — NOT the mempool's own
	// MempoolRemovalReason enum (which is legitimately referenced in
	// internal/mempool/mempool.go without any ZMQ wiring).
	hits := w141Grep(t, "PublishTxRemoved\\|PublishMempoolRemoval\\|zmqSeqLabelTxRemove",
		"cmd/blockbrew/", "internal/mempool/", "internal/rpc/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		// zmqpub.go declares the 'R' label constant but never USES it;
		// the constant declaration alone isn't fan-out. Only count call
		// sites — heuristic: skip lines that look like a const decl.
		// (zmqpub.go's line: `zmqSeqLabelTxRemove        byte = 'R'`.)
		if strings.Contains(line, "byte = 'R'") || strings.Contains(line, "byte='R'") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("BUG-5 may be fixed: tx-removal fan-out hooks now exist:\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("BUG-5 (P1 MISSING): the zmqSeqLabelTxRemove='R' constant is declared " +
		"in cmd/blockbrew/zmqpub.go:35 but never used. No PublishTxRemoved helper " +
		"exists, no mempool removal site fires sequence(R). Core " +
		"zmqnotificationinterface.cpp:170-178 fires NotifyTransactionRemoval for " +
		"every non-block removal (expire, evict, replaced, conflict, sizelimit, " +
		"reorg) so subscribers see RBF / eviction events. Fix: add " +
		"PublishTxRemoved(tx, reason) with mempool_sequence parameter; wire it " +
		"from every removeSingleTxLocked(...) call site in internal/mempool.")
}

// G_A7 BUG-6 — no per-tx fan-out on block connect (Core fires hashtx/rawtx for each).
func TestW141_A7_NoPerTxFanOutOnBlockConnect_BUG6(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/main.go")
	// At the onBlockConnected hook (~line 1076), confirm there's a call to
	// zmqPub.PublishBlockConnected but NO loop over block.Transactions calling
	// per-tx publish.
	idx := strings.Index(src, "zmqPub.PublishBlockConnected(block, height)")
	if idx < 0 {
		t.Fatalf("PublishBlockConnected wire site moved; re-audit")
	}
	// Check immediate vicinity.
	region := src[idx:]
	if len(region) > 1500 {
		region = region[:1500]
	}
	// A future fix would add a tx loop near the block-connect callback.
	if strings.Contains(region, "PublishTxConfirmedInBlock") ||
		strings.Contains(region, "for _, tx := range block.Transactions") &&
			strings.Contains(region, "zmqPub.Publish") {
		t.Fatalf("BUG-6 may be fixed: per-tx ZMQ fan-out detected near block-connect")
	}
	t.Skip("BUG-6 (P1 MISSING): cmd/blockbrew/main.go:1076-1079 calls only " +
		"PublishBlockConnected; Core zmqnotificationinterface.cpp:180-196 also " +
		"iterates pblock->vtx and fires hashtx + rawtx for each confirmed tx. " +
		"Confirmation events never reach pubhashtx subscribers, so wallets " +
		"awaiting confirmation must fall back to RPC polling. Fix: in the " +
		"connect-block callback loop block.Transactions and call " +
		"PublishTxConfirmedInBlock(tx) (hashtx + rawtx only — no sequence(A), no " +
		"mempool_sequence bump).")
}

// G_A8 BUG-7 — no IBD gating on UpdatedBlockTip / PublishBlockConnected.
func TestW141_A8_NoIBDGating_BUG7(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	// Evidence: PublishBlockConnected should mention IsInIBD or fInitialDownload
	// before sending. Currently it only checks p.stopped.
	if strings.Contains(src, "IsInIBD") || strings.Contains(src, "InitialBlockDownload") ||
		strings.Contains(src, "fInitial") {
		t.Fatalf("BUG-7 may be fixed: zmqpub.go now references IBD state")
	}
	t.Skip("BUG-7 (P2 MISSING): cmd/blockbrew/zmqpub.go:216-246 fires for every " +
		"connected block including initial block download. Core " +
		"zmqnotificationinterface.cpp:151-159 (UpdatedBlockTip) short-circuits " +
		"if (fInitialDownload || pindexNew == pindexFork). During a fresh sync, " +
		"blockbrew floods slow subscribers; combined with BUG-8 (no HWM) the queue " +
		"grows unbounded. Fix: thread an IsInIBD() accessor from the chain " +
		"manager into the publisher; early-return when in IBD.")
}

// G_A9 BUG-8 — no -zmqpub<topic>hwm flags / no SNDHWM configuration.
func TestW141_A9_NoZMQHWMFlag_BUG8(t *testing.T) {
	hits := w141Grep(t, "zmqpubhashblockhwm\\|zmqpubhashtxhwm\\|zmqpubrawblockhwm\\|zmqpubrawtxhwm\\|zmqpubsequencehwm\\|OptionHWM\\|SetOption.*HWM",
		"cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("BUG-8 may be fixed: HWM CLI / SetOption present:\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("BUG-8 (P2 MISSING): no -zmqpub<topic>hwm flags and no SetOption(HWM) " +
		"call on any PUB socket. Core's DEFAULT_ZMQ_SNDHWM=1000 caps queue depth " +
		"per notifier (zmqabstractnotifier.h:22 + zmqnotificationinterface.cpp:69). " +
		"go-zeromq supports sock.SetOption(zmq4.OptionHWM, n) (zmq4@v0.17.0/pub.go:" +
		"96). At hwm=0 (Go default), a slow subscriber wedges memory growth on " +
		"the publisher. Fix: declare five hwm flags (default 1000); call " +
		"sock.SetOption(zmq4.OptionHWM, hwm) after zmq4.NewPub and before " +
		"sock.Listen.")
}

// G_A10 BUG-9 — no ZMQ_LINGER=0 on close.
func TestW141_A10_NoLingerOnClose_BUG9(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/zmqpub.go")
	// Evidence: Stop() should call SetOption("LINGER", 0) before Close(); it
	// currently does not (and zmq4 v0.17.0 doesn't even expose the option,
	// per audit doc).
	if strings.Contains(src, "LINGER") || strings.Contains(src, "Linger") {
		t.Fatalf("BUG-9 may be fixed: zmqpub.go now references LINGER")
	}
	t.Skip("BUG-9 (P3 MISSING): cmd/blockbrew/zmqpub.go:160-164 Stop() calls " +
		"ep.socket.Close() directly. Core zmqpublishnotifier.cpp:185-187 sets " +
		"ZMQ_LINGER=0 first so pending sends to disconnected subscribers don't " +
		"block shutdown. go-zeromq v0.17.0 does not currently expose a LINGER " +
		"option — file as a 'wontfix-pending-library-upstream' for now; document " +
		"in zmqpub.go so the requirement isn't lost if/when the binding adds it " +
		"(or when we migrate to czmq).")
}

// ─────────────────────────────────────────────────────────────────────
// Subsystem B — REST API (10 gates / 9 BUGs)
// ─────────────────────────────────────────────────────────────────────

// G_B1 — sanity: 10 currently-registered REST endpoints.
func TestW141_B1_RESTEndpointsRegistered_PRESENT(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	for _, want := range []string{
		`"/rest/block/"`,
		`"/rest/block/notxdetails/"`,
		`"/rest/tx/"`,
		`"/rest/headers/"`,
		`"/rest/blockhashbyheight/"`,
		`"/rest/chaininfo.json"`,
		`"/rest/mempool/info.json"`,
		`"/rest/mempool/contents.json"`,
		`"/rest/getutxos/"`,
		`"/rest/blockfilter/"`,
		`"/rest/blockfilterheaders/"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing REST registration: %q", want)
		}
	}
}

// G_B2 BUG-10 — three Core 27+ REST endpoints absent.
func TestW141_B2_MissingCoreRESTEndpoints_BUG10(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	for _, missing := range []string{
		`"/rest/blockpart/"`,
		`"/rest/spenttxouts/"`,
		`"/rest/deploymentinfo`,
	} {
		if strings.Contains(src, missing) {
			t.Fatalf("BUG-10 may be fixed: %s now registered", missing)
		}
	}
	t.Skip("BUG-10 (P2 MISSING): internal/rpc/rest.go RegisterRESTHandlers omits " +
		"three Core REST endpoints: /rest/blockpart/ (partial-block fetch, useful " +
		"for selective tx-range queries); /rest/spenttxouts/ (block undo data, " +
		"Core 27+); /rest/deploymentinfo/ (softfork deployment status). bitcoin-" +
		"core/src/rest.cpp:1141-1159 registers all three. Fix: add handlers; " +
		"spenttxouts + deploymentinfo can reuse existing RPC implementations the " +
		"way chaininfo reuses getblockchaininfo.")
}

// G_B3 BUG-11 — getutxos binary bitmap missing CompactSize prefix.
func TestW141_B3_GetutxosBitmapMissingCompactSize_BUG11(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	// Find the binary-write block.
	idx := strings.Index(src, "// Write bitmap")
	if idx < 0 {
		t.Fatalf("rest.go: 'Write bitmap' block missing; re-audit")
	}
	region := src[idx:]
	if len(region) > 400 {
		region = region[:400]
	}
	// The bug-state: bitmap is written via buf.Write(bitmap) with no
	// length-prefix in front. Confirm absence of a CompactSize-prefix path.
	if !strings.Contains(region, "buf.Write(bitmap)") {
		t.Fatalf("BUG-11 may be fixed: getutxos bitmap write pattern changed:\n%s", region)
	}
	if strings.Contains(region, "writeVarBytes(&buf, bitmap)") ||
		strings.Contains(region, "WriteCompactSize") {
		t.Fatalf("BUG-11 may be fixed: bitmap now has length prefix")
	}
	t.Skip("BUG-11 (CDIV): internal/rpc/rest.go:584-585 writes the getutxos bitmap " +
		"as raw bytes with no length prefix. Core rest.cpp:1039 serializes via " +
		"ssGetUTXOResponse << bitmap where bitmap is std::vector<unsigned char> — " +
		"Bitcoin's vector-serializer prepends a CompactSize. A BIP-64-compliant " +
		"binary client cannot parse blockbrew's response. Fix: use writeVarBytes " +
		"(rest.go:1157) which combines CompactSize length + bytes.")
}

// G_B4 BUG-12 — getutxos CCoin missing nTxVerDummy 4-byte zero prefix.
func TestW141_B4_GetutxosCCoinMissingNTxVerDummy_BUG12(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	idx := strings.Index(src, "// Write UTXOs")
	if idx < 0 {
		t.Fatalf("rest.go: 'Write UTXOs' block missing; re-audit")
	}
	region := src[idx:]
	if len(region) > 600 {
		region = region[:600]
	}
	// Bug-state: per-utxo write begins with Height, not 4 zero bytes.
	if strings.Contains(region, "nTxVerDummy") || strings.Contains(region, "writeUint32LE(&buf, 0)") {
		t.Fatalf("BUG-12 may be fixed: CCoin now has nTxVerDummy")
	}
	t.Skip("BUG-12 (CDIV): internal/rpc/rest.go:588-597 writes each CCoin as " +
		"<height:u32><value:i64><script:varbytes> — missing the 4-byte " +
		"nTxVerDummy=0 prefix Core writes per rest.cpp:64-67 (SERIALIZE_METHODS " +
		"reads/writes nTxVerDummy first). Every CCoin is offset by 4 bytes " +
		"vs Core. Binary clients fail to parse. Fix: write 4 zero bytes (use " +
		"writeUint32LE(&buf, 0)) before the height in the CCoin loop.")
}

// G_B5 BUG-13 — getutxos outer outs[] missing CompactSize count.
func TestW141_B5_GetutxosOutsVectorMissingCount_BUG13(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	idx := strings.Index(src, "// Write UTXOs")
	if idx < 0 {
		t.Fatalf("rest.go: 'Write UTXOs' anchor missing; re-audit")
	}
	region := src[max(0, idx-200):idx]
	// Bug-state: no CompactSize length emitted before the for-range over UTXOs.
	if strings.Contains(region, "writeVarBytes") && strings.Contains(region, "len(result.UTXOs)") {
		t.Fatalf("BUG-13 may be fixed: outer outs[] count prefix detected")
	}
	t.Skip("BUG-13 (CDIV): internal/rpc/rest.go:587-597 emits CCoins back-to-back " +
		"with no outer vector-count prefix. Core writes `outs` as " +
		"std::vector<CCoin>, which begins with a CompactSize element count. " +
		"Without the count, a client cannot know how many CCoins follow. Fix: " +
		"emit CompactSize(len(result.UTXOs)) between the bitmap write and the " +
		"CCoin loop.")
}

// G_B6 BUG-14 — getutxos value goes through float64 satoshi conversion.
func TestW141_B6_GetutxosValueGoesViaFloat64_BUG14(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	// Bug-state: RESTUTXOInfo.Value is float64 and binary write does
	// "int64(utxo.Value * 100_000_000)".
	if !strings.Contains(src, "Value        float64") &&
		!strings.Contains(src, "Value      float64") &&
		!strings.Contains(src, "Value float64") {
		t.Fatalf("BUG-14 may be fixed: RESTUTXOInfo.Value is no longer float64")
	}
	if !strings.Contains(src, "utxo.Value * 100_000_000") {
		t.Fatalf("BUG-14 may be fixed: getutxos no longer multiplies float by 100_000_000")
	}
	t.Skip("BUG-14 (P1 CDIV): internal/rpc/rest.go:592 computes valueSats := " +
		"int64(utxo.Value * 100_000_000) where utxo.Value is float64 BTC. " +
		"Round-trip is lossy: e.g. 10_000 sats → 0.0001 BTC → 9999.999... → int64 " +
		"truncates to 9999. Off-by-one in binary getutxos output for any non-" +
		"power-of-two satoshi amount. Core stores CAmount nValue int64 sats " +
		"throughout and never goes through float. Fix: keep RESTUTXOInfo.Value " +
		"as int64 satoshis; convert at the JSON boundary only.")
}

// G_B7 BUG-15 — /rest/headers/ only accepts deprecated /count/hash path form.
func TestW141_B7_RESTHeadersOnlyDeprecatedPath_BUG15(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	idx := strings.Index(src, "func (s *Server) handleRESTHeaders(")
	if idx < 0 {
		t.Fatalf("handleRESTHeaders missing; re-audit")
	}
	region := src[idx:]
	if len(region) > 1500 {
		region = region[:1500]
	}
	// Bug-state: only the path-size=2 form is accepted; modern path-size=1
	// with ?count= is rejected.
	if strings.Contains(region, `r.URL.Query().Get("count")`) ||
		strings.Contains(region, `r.URL.Query().Get(`+"`count`"+`)`) {
		t.Fatalf("BUG-15 may be fixed: modern query-parameter path now supported")
	}
	t.Skip("BUG-15 (P2 MISSING): internal/rpc/rest.go:309-313 requires path " +
		"format /rest/headers/<count>/<hash>.<ext> (deprecated). Core rest.cpp:" +
		"191-205 accepts BOTH that AND the modern /rest/headers/<hash>?count=<count> " +
		"(default 5). The modern form is what bitcoin-cli and most current REST " +
		"clients emit; blockbrew rejects them with HTTP 400. Fix: when path has " +
		"only one component, read count from r.URL.Query().Get(\"count\") with " +
		"default \"5\".")
}

// G_B8 BUG-16 — /rest/blockfilterheaders/ only accepts deprecated /type/count/hash form.
func TestW141_B8_RESTFilterHeadersOnlyDeprecatedPath_BUG16(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	idx := strings.Index(src, "func (s *Server) handleRESTBlockFilterHeaders(")
	if idx < 0 {
		t.Fatalf("handleRESTBlockFilterHeaders missing; re-audit")
	}
	region := src[idx:]
	if len(region) > 1800 {
		region = region[:1800]
	}
	// Bug-state: SplitN(path, "/", 3) and len(parts) != 3 rejects.
	if !strings.Contains(region, `SplitN(path, "/", 3)`) {
		t.Fatalf("BUG-16 may be fixed: filter-headers no longer hard-splits on 3")
	}
	if strings.Contains(region, `r.URL.Query().Get("count")`) {
		t.Fatalf("BUG-16 may be fixed: modern query-parameter path now supported")
	}
	t.Skip("BUG-16 (P2 MISSING): internal/rpc/rest.go:1027-1031 requires three " +
		"path components <filtertype>/<count>/<hash>.<ext> (deprecated). Core " +
		"rest.cpp:510-524 accepts BOTH that AND <filtertype>/<hash>?count=<count>. " +
		"Same shape as BUG-15. Fix: when path has two components, read count from " +
		"r.URL.Query().Get(\"count\") with default \"5\".")
}

// G_B9 BUG-17 — no warmup gating on REST handlers.
func TestW141_B9_RESTNoWarmupGating_BUG17(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	// Evidence: no warmup-related identifiers in rest.go.
	for _, marker := range []string{
		"isWarmingUp", "IsWarmingUp", "warmup", "Warmup",
		"RPCErrInWarmup", "checkWarmup",
	} {
		if strings.Contains(src, marker) {
			t.Fatalf("BUG-17 may be fixed: rest.go now references warmup state via %q", marker)
		}
	}
	t.Skip("BUG-17 (P2 MISSING): internal/rpc/rest.go handlers have no warmup " +
		"gate. Core rest.cpp:171-177 (CheckWarmup) is called first in every " +
		"REST handler and returns HTTP 503 with 'Service temporarily unavailable: " +
		"<state>' while RPCIsInWarmup. blockbrew has RPC-side warmup gating " +
		"(types.go:26 RPCErrInWarmup) but never applies it to REST. Pre-load " +
		"requests can nil-deref on chainMgr or return empty payloads. Fix: add " +
		"s.isWarmingUp() accessor; gate every REST handler at the top.")
}

// G_B10 BUG-18 — no BlockUntilSyncedToCurrentChain on filter REST.
func TestW141_B10_RESTFilterNoSyncWait_BUG18(t *testing.T) {
	src := w141ReadFile(t, "internal/rpc/rest.go")
	if strings.Contains(src, "BlockUntilSyncedToCurrentChain") {
		t.Fatalf("BUG-18 may be fixed: rest.go now calls BlockUntilSyncedToCurrentChain")
	}
	t.Skip("BUG-18 (P2 MISSING; cross-ref W133 G25/BUG-13): internal/rpc/rest.go " +
		"handleRESTBlockFilter (rest.go:924) and handleRESTBlockFilterHeaders " +
		"(rest.go:1020) read from BlockFilterIndex without first waiting for the " +
		"index to catch up to the current active chain. Core rest.cpp:563 calls " +
		"index->BlockUntilSyncedToCurrentChain() before per-block reads, blocking " +
		"the request until the index has caught up. Without this, a REST request " +
		"immediately after block-connect can return 'filter not found' until " +
		"the indexer thread catches up — flaky boundary semantics. Fix: add " +
		"BlockUntilSyncedToCurrentChain() to internal/storage.BlockFilterIndex " +
		"(blocking wait keyed on a chan signalled by the indexer worker); call " +
		"it before the per-height read in both REST filter handlers.")
}

// ─────────────────────────────────────────────────────────────────────
// Subsystem C — Notification scripts (10 gates / 6 BUGs)
//
// C1/C2/C3 absorb W124 BUG-16. C4/C5 absorb W124 BUG-10. The new W141
// findings BUG-19/20/21 are kept (one per hook) because each has a
// distinct fix path and Core-reference; BUG-22/23/24 are new.
// ─────────────────────────────────────────────────────────────────────

// G_C1 BUG-19 — no -blocknotify flag.
func TestW141_C1_NoBlockNotifyFlag_BUG19(t *testing.T) {
	hits := w141Grep(t, "blocknotify", "cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("BUG-19 may be fixed: blocknotify refs found:\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("BUG-19 (P2 MISSING; refines W124 BUG-16): no -blocknotify=<cmd> CLI " +
		"flag. Core init.cpp:498 declares it; init.cpp:2009-2018 wires it to " +
		"NotifyBlockTip on POST_INIT; the literal token <percent-s> in cmd is " +
		"replaced by block hash. Fix: add CLI flag; on NotifyBlockTip " +
		"(sync_state==POST_INIT only), substitute <percent-s> with the block " +
		"hash and spawn a detached goroutine running exec.Command(\"/bin/sh\", " +
		"\"-c\", cmd). DO NOT block the calling goroutine — Core uses " +
		"std::thread::detach(). See BUG-22.")
}

// G_C2 BUG-20 — no -alertnotify flag.
func TestW141_C2_NoAlertNotifyFlag_BUG20(t *testing.T) {
	hits := w141Grep(t, "alertnotify", "cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("BUG-20 may be fixed: alertnotify refs found:\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("BUG-20 (P2 MISSING; refines W124 BUG-16): no -alertnotify=<cmd> CLI " +
		"flag. Core init.cpp:485 declares it; node/kernel_notifications.cpp:30-47 " +
		"wires it to KernelNotifications::warningSet. blockbrew has no alert " +
		"subsystem at all — warnings are log.Printf only. Fix: add a Warning " +
		"subsystem (analog of Core warningSet); add CLI flag; on alert raise, " +
		"sanitize-and-quote the message (see BUG-23) before the <percent-s> " +
		"substitution; spawn a detached goroutine.")
}

// G_C3 BUG-21 — no -walletnotify flag.
func TestW141_C3_NoWalletNotifyFlag_BUG21(t *testing.T) {
	hits := w141Grep(t, "walletnotify", "cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("BUG-21 may be fixed: walletnotify refs found:\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("BUG-21 (P2 MISSING; refines W124 BUG-16): no -walletnotify=<cmd> CLI " +
		"flag. Core wallet/init.cpp:75 declares it; wallet/wallet.cpp:1480 + " +
		"3069 wire it to every tx-status change. Substitutions (token-form): " +
		"<percent-s>=TxID, <percent-w>=wallet-name, " +
		"<percent-b>=blockhash|unconfirmed, <percent-h>=height|-1. Fix: add CLI " +
		"flag to wallet config; on every wallet-tx update, replace all four " +
		"placeholders and spawn a detached goroutine. Document shell-escape " +
		"rules (BUG-22).")
}

// G_C4 — startupnotify (absorbed in W124 BUG-10; re-asserted here for shape).
func TestW141_C4_NoStartupNotifyFlag_ABSORBED(t *testing.T) {
	hits := w141Grep(t, "startupnotify", "cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("W141 C4 — startupnotify may be fixed (cross-ref W124 BUG-10):\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("W141 C4 (ABSORBED into W124 BUG-10): no -startupnotify=<cmd>. " +
		"Core init.cpp:738-745 declares + fires it after init complete. " +
		"Cross-ref cmd/blockbrew/w124_operator_test.go:" +
		"TestW124_G28_NoStartupShutdownNotifyHooks_BUG10.")
}

// G_C5 — shutdownnotify (absorbed in W124 BUG-10; re-asserted for shape).
func TestW141_C5_NoShutdownNotifyFlag_ABSORBED(t *testing.T) {
	hits := w141Grep(t, "shutdownnotify", "cmd/blockbrew/", "internal/")
	prod := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" || strings.Contains(line, "_test.go:") {
			continue
		}
		prod = append(prod, line)
	}
	if len(prod) > 0 {
		t.Fatalf("W141 C5 — shutdownnotify may be fixed (cross-ref W124 BUG-10):\n%s",
			strings.Join(prod, "\n"))
	}
	t.Skip("W141 C5 (ABSORBED into W124 BUG-10): no -shutdownnotify=<cmd>. " +
		"Core init.cpp:256-265 declares + fires it from ShutdownNotify (joins " +
		"threads synchronously). Cross-ref " +
		"TestW124_G28_NoStartupShutdownNotifyHooks_BUG10.")
}

// G_C6 — gate retained for shape; covered by C1..C5 once they're wired.
func TestW141_C6_NotifyDecoupled_DEFERRED(t *testing.T) {
	t.Skip("W141 C6 (DEFERRED): notify-script-decoupling — each hook must run " +
		"in its own detached goroutine so consensus is never blocked by a slow " +
		"or hung script (Core uses std::thread::detach throughout init.cpp + " +
		"kernel_notifications.cpp). No production code exists to gate yet; " +
		"will be a forward-regression when BUG-19/20/21 are landed.")
}

// G_C7 BUG-22 — doc gap: when hooks land, operator must be warned about
// shell evaluation of the substitution placeholder.
func TestW141_C7_DocGapShellInjection_BUG22(t *testing.T) {
	t.Skip("BUG-22 (DOC GAP, depends on BUG-19/20/21): when the three notify " +
		"hooks are added, the help-text (flag.StringVar usage strings) AND " +
		"README MUST warn: '<percent-s> substitution is literal text — " +
		"blockbrew uses /bin/sh -c <cmd>. Always single-quote <percent-s> in " +
		"your template, especially for -walletnotify and -alertnotify where " +
		"the substituted text can be attacker-controlled (subver, p2p " +
		"address, wallet name).' Skipping this warning at hook-introduction " +
		"time is how Bitcoin Core's own alertnotify CVE-class issues entered " +
		"the wild. Fix: when BUG-19/20/21 land, also land the doc warning + " +
		"a sanitiser (BUG-23).")
}

// G_C8 BUG-23 — once -alertnotify lands, message MUST be sanitised.
func TestW141_C8_AlertNotifySanitiseRequired_BUG23(t *testing.T) {
	t.Skip("BUG-23 (P2, depends on BUG-20): once -alertnotify is wired, the " +
		"alert message MUST be sanitised before <percent-s> substitution. " +
		"Core node/kernel_notifications.cpp:39-42: SanitizeString(strMessage) " +
		"strips non-SAFE_CHARS_USER_COMMENT characters; then wraps the result " +
		"in single quotes ('msg') before ReplaceAll. Without this pass, an " +
		"alert containing a backtick or $(cmd) enables RCE via /bin/sh -c " +
		"expansion. Fix: at fix-time for BUG-20, implement " +
		"sanitiseAlertMessage(msg) matching Core's SAFE_CHARS_USER_COMMENT " +
		"regex and apply before substitution.")
}

// G_C9 — walletnotify %w escaping doc (depends on BUG-21).
func TestW141_C9_WalletNotifyEscapeDoc_DEFERRED(t *testing.T) {
	t.Skip("W141 C9 (DEFERRED, depends on BUG-21): once -walletnotify is wired, " +
		"the help text must document Core wallet/init.cpp:75's escape rule for " +
		"%w (wallet name): '%w is NOT shell-quoted by the substitution — the " +
		"operator's template MUST quote it because wallet names can contain " +
		"single quotes and other shell metacharacters.' Cross-platform note: " +
		"%w is not supported on Windows (we're Linux-only, so moot).")
}

// G_C10 BUG-24 — sd_notify status string not escaped against newline injection.
func TestW141_C10_SDNotifyStatusNoNewlineEscape_BUG24(t *testing.T) {
	src := w141ReadFile(t, "cmd/blockbrew/notify.go")
	// Bug-state: notifyStatus concatenates raw.
	if !strings.Contains(src, `sdNotify("STATUS=" + status + "\n")`) {
		t.Fatalf("BUG-24 may be fixed: notifyStatus no longer raw-concatenates status")
	}
	if strings.Contains(src, "sanitizeSDStatus") || strings.Contains(src, "strings.ReplaceAll(status") {
		t.Fatalf("BUG-24 may be fixed: notify.go now sanitises status")
	}
	t.Skip("BUG-24 (P3 HARDENING): cmd/blockbrew/notify.go:72-74 notifyStatus " +
		"concatenates `status` directly into the sd_notify payload. systemd " +
		"parses every \\n as a directive boundary: a status containing " +
		"`foo\\nSTOPPING=1\\n` would tell systemd the daemon is shutting down. " +
		"Current callers pass curated internal strings (latent exposure), but " +
		"once peer-derived data (subver, IP, agent string) is plumbed in for " +
		"richer status, this closes the latency window. Fix: introduce a " +
		"sanitiseSDStatus helper that strips \\n/\\r/\\x00 before concat; apply " +
		"in notifyStatus, notifyReady, notifyStopping, and any future " +
		"sd-notify call site.")
}
