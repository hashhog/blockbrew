// Package main W124 operator-experience audit tests.
//
// Wave W124 (DISCOVERY only — no production code changes). Each test below is
// a structural xfail (t.Skip("BUG-N: ...")) documenting an operator-
// experience defect found by reading cmd/blockbrew/* against Bitcoin Core's
// init.cpp, logging.{cpp,h}, and the Interrupt/Shutdown semantics inside
// init.cpp.
//
// See audit/w124_operator_experience.md for the full writeup. The pattern
// matches the wave-level convention used by the existing W117/W121/W122
// audits in this tree (e.g. internal/p2p/w117_bip155_networks_test.go).
//
// All tests in this file are xfail: they describe the bug, hold a small
// piece of structural evidence (a grep or a file existence check) that
// remains valid until the bug is fixed, and then Skip. The lack of failure
// is what fix waves convert into a real assertion. See FIX-83 for the
// W122 pattern of activating an xfail by removing the Skip.
package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// w124RepoRoot walks up from the test file's location until it finds go.mod,
// returning the repo root path. Used by tests that grep production source
// for structural evidence of a bug.
func w124RepoRoot(t *testing.T) string {
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

// w124Grep runs `grep -rn pattern paths...` from the repo root, returning
// stdout. Bash for portability. Returns "" if grep finds nothing (exit 1
// is normal for "no matches"). Excludes all _test.go files so audit tests
// in cmd/blockbrew don't show up as "consumers" of the very identifier
// they're auditing.
func w124Grep(t *testing.T, pattern string, paths ...string) string {
	t.Helper()
	root := w124RepoRoot(t)
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

// ────────────────────────────────────────────────────────────────────────
// G3 — BUG-1: startup chainstate consistency probe is gated on
// OnSyncComplete, never runs on offline / no-peers nodes.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G3_ConsistencyProbeGatedOnSyncComplete_BUG1(t *testing.T) {
	// Structural pin: the only call site for VerifyChainstateConsistency
	// in cmd/blockbrew is inside the OnSyncComplete callback. If the node
	// never sees a fresh-headers exchange (e.g. network outage, no peers),
	// the probe never fires.
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	probeIdx := strings.Index(src, "VerifyChainstateConsistency(")
	if probeIdx < 0 {
		t.Fatalf("VerifyChainstateConsistency call site gone? audit stale")
	}
	// Walk back ~600 chars to find the enclosing OnSyncComplete + consistencyProbeOnce.Do.
	start := probeIdx - 800
	if start < 0 {
		start = 0
	}
	region := src[start:probeIdx]
	if !strings.Contains(region, "consistencyProbeOnce.Do") {
		t.Fatalf("VerifyChainstateConsistency call no longer gated by consistencyProbeOnce; pre-call region:\n%s",
			region)
	}
	if !strings.Contains(region, "OnSyncComplete") {
		t.Fatalf("VerifyChainstateConsistency call no longer inside OnSyncComplete; pre-call region:\n%s",
			region)
	}
	// Also confirm: no second synchronous call before peerMgr.Start().
	// That would mean the bug is being addressed.
	peerStartIdx := strings.Index(src, "peerMgr.Start()")
	if peerStartIdx > 0 && peerStartIdx < probeIdx {
		t.Fatalf("BUG-1 may be fixed: peerMgr.Start() at offset %d precedes VerifyChainstateConsistency at %d; "+
			"verify a synchronous early call was added before peerMgr.Start()", peerStartIdx, probeIdx)
	}
	t.Skip("BUG-1 (PARTIAL): VerifyChainstateConsistency is invoked only inside the " +
		"OnSyncComplete callback (main.go:1114-1127). A node that starts up disconnected " +
		"and never completes a header-sync exchange never runs the probe — silent " +
		"corruption window. Fix: also call the probe synchronously before peerMgr.Start().")
}

// ────────────────────────────────────────────────────────────────────────
// G9 — BUG-2: no interrupt plumbed through ChainManager; 30s watchdog can
// SIGKILL mid-reorg.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G9_NoInterruptInChainManager_BUG2(t *testing.T) {
	hits := w124Grep(t, "ctx\\.Done\\|ctx\\.Err\\|Interrupt", "internal/consensus/chainmanager.go")
	// Allow comments / docstrings that mention "interrupt" but no actual
	// context plumbing. The structural pin is: zero call to ctx.Done()
	// or ctx.Err() in the chain manager body.
	if strings.Contains(hits, "ctx.Done()") || strings.Contains(hits, "ctx.Err()") {
		t.Fatalf("chainmanager.go HAS ctx interrupt plumbing — bug may be fixed; verify:\n%s", hits)
	}
	t.Skip("BUG-2 (MISSING): internal/consensus/chainmanager.go has no ctx.Done() / " +
		"ctx.Err() / Interrupt plumbing. A deep reorg or slow ConnectBlock during " +
		"shutdown will hold the chain lock past the 30s watchdog at main.go:1544 — " +
		"watchdog fires os.Exit(1) mid-batch, Pebble batch is dropped, next startup " +
		"replays the consistency probe (best case) or wedges (worst case). Fix: thread " +
		"a context through ChainManager; check at the head of each ConnectBlock/" +
		"DisconnectBlock iteration; return ErrShutdownRequested on cancel.")
}

// ────────────────────────────────────────────────────────────────────────
// G10 — BUG-3: `stop` RPC does NOT stop the daemon.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G10_StopRPCDoesNotStopDaemon_BUG3(t *testing.T) {
	// Structural evidence: handleStop calls s.Stop() which only closes
	// the RPC HTTP server. There is no syscall.SIGTERM, no signal to the
	// process group, no close on a main-level shutdown channel.
	methodsBody, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "internal/rpc/methods.go"))
	if err != nil {
		t.Fatalf("read methods.go: %v", err)
	}
	mSrc := string(methodsBody)
	handleStopIdx := strings.Index(mSrc, "func (s *Server) handleStop()")
	if handleStopIdx < 0 {
		t.Fatalf("handleStop gone? audit stale")
	}
	// Function body sits in the ~250 chars after the declaration.
	endIdx := handleStopIdx + 500
	if endIdx > len(mSrc) {
		endIdx = len(mSrc)
	}
	handleStopBody := mSrc[handleStopIdx:endIdx]
	if !strings.Contains(handleStopBody, "s.Stop()") {
		t.Fatalf("handleStop no longer calls s.Stop(); body:\n%s", handleStopBody)
	}
	// Fail if the body now signals the process — bug may be fixed.
	if strings.Contains(handleStopBody, "syscall.SIGTERM") ||
		strings.Contains(handleStopBody, "os.Process") ||
		strings.Contains(handleStopBody, "syscall.Kill") {
		t.Fatalf("BUG-3 may be fixed: handleStop now signals the process:\n%s", handleStopBody)
	}

	serverBody, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "internal/rpc/server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	sSrc := string(serverBody)
	serverStopIdx := strings.Index(sSrc, "func (s *Server) Stop() error")
	if serverStopIdx < 0 {
		t.Fatalf("Server.Stop gone? audit stale")
	}
	serverStopEnd := serverStopIdx + 500
	if serverStopEnd > len(sSrc) {
		serverStopEnd = len(sSrc)
	}
	stopBody := sSrc[serverStopIdx:serverStopEnd]
	if strings.Contains(stopBody, "syscall.SIGTERM") || strings.Contains(stopBody, "syscall.Kill") {
		t.Fatalf("Server.Stop now signals the process — bug may be fixed:\n%s", stopBody)
	}
	t.Skip("BUG-3 (P0 MISSING): internal/rpc/methods.go:2159 handleStop() calls " +
		"s.Stop() which only stops the RPC HTTP listener (server.go:343 close(s.shutdown) " +
		"+ httpServer.Shutdown). The main goroutine sits at main.go:1526 blocked on " +
		"sigChan; no signal is delivered. After `bitcoin-cli stop` returns success the " +
		"RPC listener is gone but P2P + sync + mempool + wallet + ZMQ + chain manager " +
		"all keep running. This breaks every Core-playbook restart script. " +
		"Fix: handleStop must syscall.Kill(os.Getpid(), syscall.SIGTERM) so the main " +
		"signal handler runs the full shutdown sequence.")
}

// ────────────────────────────────────────────────────────────────────────
// G12 — BUG-4: SIGHUP handler gated on -logfile=<path>.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G12_SIGHUPGatedOnLogfile_BUG4(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	hupIdx := strings.Index(src, "signal.Notify(hupCh, syscall.SIGHUP)")
	if hupIdx < 0 {
		t.Fatalf("signal.Notify(hupCh, syscall.SIGHUP) gone? audit stale")
	}
	// Walk back ~600 chars; expect the enclosing guard `cfg.LogFile != ""`.
	preStart := hupIdx - 600
	if preStart < 0 {
		preStart = 0
	}
	preRegion := src[preStart:hupIdx]
	if !strings.Contains(preRegion, `cfg.LogFile != ""`) {
		t.Fatalf("BUG-4 may be fixed: SIGHUP no longer gated by cfg.LogFile guard; "+
			"pre-region:\n%s", preRegion)
	}
	t.Skip("BUG-4 (PARTIAL): SIGHUP handler at main.go:407 is gated on " +
		"`logHandle != nil && cfg.LogFile != \"\"`. When -logfile is unset (stderr " +
		"default), SIGHUP is not trapped; the Go runtime's default action is to " +
		"terminate the process — `kill -HUP $(cat blockbrew.pid)` for logrotate " +
		"will instead kill the daemon. Core (init.cpp:432 HandleSIGHUP) always " +
		"installs the handler. Fix: register SIGHUP unconditionally; logHandle.Reopen() " +
		"is already a no-op when path is empty (loglevel.go:212).")
}

// ────────────────────────────────────────────────────────────────────────
// G15 — BUG-5: -loglevel is a dead flag.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G15_LoglevelFlagIsDead_BUG5(t *testing.T) {
	// Count consumers of cfg.LogLevel across all production go files
	// (excluding _test.go). Expectation: zero non-declaration consumers.
	root := w124RepoRoot(t)
	hits := w124Grep(t, "LogLevel", "cmd/", "internal/")
	// Filter to non-test lines.
	prodLines := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		// Skip the declaration (struct field) and the flag.StringVar parse line.
		if strings.Contains(line, "main.go:") &&
			(strings.Contains(line, "LogLevel     string") ||
				strings.Contains(line, `flag.StringVar(&cfg.LogLevel`) ||
				strings.Contains(line, `--loglevel`)) {
			continue
		}
		prodLines = append(prodLines, line)
	}
	if len(prodLines) > 0 {
		t.Fatalf("BUG-5 may be fixed: found %d non-decl consumers of LogLevel:\n%s",
			len(prodLines), strings.Join(prodLines, "\n"))
	}
	// Sanity: confirm the flag IS declared (otherwise the test is stale).
	mainSrc, err := os.ReadFile(filepath.Join(root, "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(mainSrc), `flag.StringVar(&cfg.LogLevel, "loglevel"`) {
		t.Fatalf("flag declaration removed from main.go; audit is stale")
	}
	t.Skip("BUG-5 (P1 MISSING): cfg.LogLevel is declared (main.go:52), parsed via " +
		"`flag.StringVar(&cfg.LogLevel, \"loglevel\", \"info\", ...)` (main.go:462), " +
		"and documented in help (main.go:2127). It has ZERO production consumers — " +
		"every log call site uses stdlib log.Printf which has no notion of levels. " +
		"Setting -loglevel=error has no effect. Fix: either implement a level-aware " +
		"logger (slog wrapper) or delete the flag.")
}

// ────────────────────────────────────────────────────────────────────────
// G17 — BUG-6: no automatic log rotation (Core's ShrinkDebugFile).
// ────────────────────────────────────────────────────────────────────────

func TestW124_G17_NoLogShrinkOnStartup_BUG6(t *testing.T) {
	hits := w124Grep(t, "ShrinkDebugFile\\|MAX_LOG_FILE_SIZE\\|RECENT_DEBUG_HISTORY\\|shrinkdebugfile",
		"cmd/", "internal/")
	if strings.TrimSpace(hits) != "" {
		t.Fatalf("BUG-6 may be fixed: found references to log-shrink logic:\n%s", hits)
	}
	t.Skip("BUG-6 (MISSING): blockbrew has no ShrinkDebugFile equivalent. " +
		"Core (logging.cpp:514) trims debug.log to its last 10 MiB if the file " +
		"exceeds 11 MiB at startup. A long-running mainnet node with -logfile= " +
		"grows the logfile unboundedly until the disk fills. Fix: port Core's " +
		"algorithm (seek -10MiB from end, read into buffer, rewrite file with tail).")
}

// ────────────────────────────────────────────────────────────────────────
// G20 — BUG-7: wallet save is best-effort, no atomic-write guarantee in main.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G20_WalletSaveBestEffort_BUG7(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	// Look for the wallet save snippet pattern: `if err := w.Save(); err != nil {`
	// immediately followed by `log.Printf("Warning: wallet save failed: %v", err)`.
	walletSave := strings.Index(src, "w.Save(")
	if walletSave < 0 {
		t.Fatalf("wallet save call gone? audit stale")
	}
	region := src[walletSave:]
	if len(region) > 400 {
		region = region[:400]
	}
	if !strings.Contains(region, "Warning:") {
		t.Fatalf("wallet save no longer warn-on-error — bug may be fixed; verify:\n%s", region)
	}
	t.Skip("BUG-7 (PARTIAL): cmd/blockbrew/main.go:1603 calls w.Save() " +
		"and warn-logs on error — shutdown proceeds and the DB closes even if the " +
		"wallet write failed (ENOSPC, I/O error). Wallet.dat may be lost on next " +
		"startup; operator must restore from seed. Fix: surface wallet save failures " +
		"loudly (notifyStopping + non-zero exit at least); retry once to a sibling " +
		".new path. Mempool / fee-estimator best-effort is fine — wallet is not.")
}

// ────────────────────────────────────────────────────────────────────────
// G23 — BUG-8: ErrDiskFull declared but never raised.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G23_ErrDiskFullDeclaredNotUsed_BUG8(t *testing.T) {
	root := w124RepoRoot(t)
	// Parse internal/storage/flatfile.go AST and confirm ErrDiskFull is
	// declared. Then grep all production files for any use OTHER than the
	// declaration line.
	flatfilePath := filepath.Join(root, "internal/storage/flatfile.go")
	src, err := os.ReadFile(flatfilePath)
	if err != nil {
		t.Fatalf("read flatfile.go: %v", err)
	}
	if !strings.Contains(string(src), "ErrDiskFull") {
		t.Fatalf("ErrDiskFull no longer declared; audit stale")
	}
	// Grep across production .go files (exclude _test.go).
	hits := w124Grep(t, "ErrDiskFull", "internal/", "cmd/")
	uses := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		if strings.Contains(line, "flatfile.go") && strings.Contains(line, "ErrDiskFull       = errors.New") {
			continue // declaration
		}
		uses = append(uses, line)
	}
	if len(uses) > 0 {
		t.Fatalf("BUG-8 may be fixed: found %d ErrDiskFull consumers:\n%s",
			len(uses), strings.Join(uses, "\n"))
	}
	// Also sanity-check the AST so refactors that rename ErrDiskFull break the audit.
	fset := token.NewFileSet()
	if _, parseErr := parser.ParseFile(fset, flatfilePath, src, parser.SkipObjectResolution); parseErr != nil {
		t.Fatalf("parse flatfile.go: %v", parseErr)
	}
	t.Skip("BUG-8 (P2 MISSING): internal/storage/flatfile.go:178 declares " +
		"ErrDiskFull but no caller ever returns it. There is no preflight statfs " +
		"check before block writes — ENOSPC surfaces as opaque " +
		"`flatfile: write data failed: write ...: no space left on device` from " +
		"inside OnBlockConnected, after the chain manager committed the connect. " +
		"Core's CheckDiskSpace in blockstorage.cpp::FindNextBlockPos fails block- " +
		"download admission before the OS returns ENOSPC. Fix: statfs-based preflight " +
		"inside BlockStore.WriteBlock; return ErrDiskFull; abort block download.")
}

// ────────────────────────────────────────────────────────────────────────
// G25 — BUG-9: no rlimit adaptation for -maxconnections.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G25_NoMaxConnectionsRlimitAdaptation_BUG9(t *testing.T) {
	hits := w124Grep(t,
		"RLIMIT_NOFILE\\|setrlimit\\|getrlimit\\|FD_SETSIZE\\|Setrlimit\\|Getrlimit",
		"cmd/", "internal/")
	if strings.TrimSpace(hits) != "" {
		t.Fatalf("BUG-9 may be fixed: found rlimit references:\n%s", hits)
	}
	t.Skip("BUG-9 (P1 MISSING): blockbrew never queries or raises RLIMIT_NOFILE. " +
		"Default -maxinbound=117 + -maxoutbound=8 + pebble MaxOpenFiles=2000 + RPC " +
		"sockets routinely exhausts the standard `ulimit -n 1024`. Core (init.cpp:1044 " +
		"RaiseFileDescriptorLimit) raises rlimit, caps maxconnections to whatever the " +
		"OS allowed, and warns. Fix: at startup unix.Getrlimit(RLIMIT_NOFILE), " +
		"raise to maxconn + pebble.MaxOpenFiles + slack, cap user maxconn to allowed, " +
		"emit Core-compatible InitWarning.")
}

// ────────────────────────────────────────────────────────────────────────
// G28 — BUG-10: no -startupnotify / -shutdownnotify hooks.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G28_NoStartupShutdownNotifyHooks_BUG10(t *testing.T) {
	hits := w124Grep(t, "startupnotify\\|shutdownnotify", "cmd/", "internal/")
	if strings.TrimSpace(hits) != "" {
		t.Fatalf("BUG-10 may be fixed: found notify-hook references:\n%s", hits)
	}
	t.Skip("BUG-10 (MISSING): no -startupnotify / -shutdownnotify CLI flags. " +
		"Core init.cpp:529-530 declares both — operator workflow hook for paging, " +
		"service registration, etc. systemd notify (G27) partially covers this for " +
		"systemd hosts; not every deployment uses systemd. Fix: add both CLI flags, " +
		"trigger os/exec.Command at the same points Core does. Errors logged not fatal.")
}

// ────────────────────────────────────────────────────────────────────────
// G11 — BUG-11: Prometheus metrics bound on 0.0.0.0 by default.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_MetricsBindsOnAllInterfaces_BUG11(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, `"0.0.0.0:%d", cfg.MetricsPort`) {
		// Pattern may have been refactored — verify by checking for any
		// metricsAddr binding that isn't loopback.
		if strings.Contains(src, `metricsAddr := fmt.Sprintf("127.0.0.1`) {
			t.Fatalf("BUG-11 may be fixed: metricsAddr now bound on loopback")
		}
		t.Fatalf("metrics-bind pattern changed; re-audit (no 0.0.0.0 or 127.0.0.1 sprintf found)")
	}
	t.Skip("BUG-11 (P1): cmd/blockbrew/main.go:1436 binds Prometheus metrics on " +
		"`0.0.0.0:<port>` (default port 9332). Exposes bitcoin_blocks_total, " +
		"bitcoin_peers_connected, bitcoin_mempool_size to any host on the network " +
		"with no auth. Information disclosure. Fix: default to 127.0.0.1; add " +
		"-metricsbind=<addr> for explicit override (mirrors -rpcbind).")
}

// ────────────────────────────────────────────────────────────────────────
// G12_health — BUG-12: health endpoint bind failure not fatal.
// G13_metrics — BUG-13: metrics endpoint bind failure not fatal.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_HealthBindFailureNotFatal_BUG12(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	// Find the health endpoint handler function (skipping comments).
	// The pattern at main.go:~1467 is: healthMux.HandleFunc("/healthz", ...
	healthIdx := strings.Index(src, `healthMux.HandleFunc("/healthz"`)
	if healthIdx < 0 {
		t.Fatalf("/healthz handler gone? audit stale")
	}
	region := src[healthIdx:]
	if len(region) > 2000 {
		region = region[:2000]
	}
	if !strings.Contains(region, "go func()") || !strings.Contains(region, "http.ListenAndServe(healthAddr") {
		t.Fatalf("health-endpoint pattern changed; re-audit. region:\n%s", region)
	}
	t.Skip("BUG-12 (P2): main.go:1487 spawns the /healthz listener inside a " +
		"goroutine via http.ListenAndServe which only returns on error. Bind " +
		"failure is logged but does NOT abort startup. notifyReady (READY=1) fires " +
		"unconditionally — k8s pod marked ready then liveness probe hits unbound port " +
		"and gets ECONNREFUSED. Fix: net.Listen synchronously, then Serve in goroutine; " +
		"abort startup on bind failure. Mirror peermgr.go:414.")
}

func TestW124_G_MetricsBindFailureNotFatal_BUG13(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	metricsIdx := strings.Index(src, "metricsMux := http.NewServeMux()")
	if metricsIdx < 0 {
		t.Fatalf("metrics mux pattern gone? audit stale")
	}
	region := src[metricsIdx:]
	if len(region) > 2500 {
		region = region[:2500]
	}
	if !strings.Contains(region, "go func()") || !strings.Contains(region, "http.ListenAndServe(metricsAddr") {
		t.Fatalf("metrics-endpoint pattern changed; re-audit. region:\n%s", region)
	}
	t.Skip("BUG-13 (P2): same anti-pattern as BUG-12, applied to -metricsport. " +
		"main.go:1455 http.ListenAndServe inside goroutine; bind failure logged not " +
		"fatal. Daemon advertises READY=1 even when metrics never bound. Fix: same as " +
		"BUG-12 — net.Listen synchronously, Serve in goroutine, abort startup on error.")
}

// ────────────────────────────────────────────────────────────────────────
// G14 — BUG-14: no -rpcauth=<userpw> HMAC support.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_NoRPCAuthHMAC_BUG14(t *testing.T) {
	hits := w124Grep(t, "rpcauth\\|RPCAuth\\|RPCHmac\\|hmac.*rpc", "cmd/", "internal/rpc/")
	// Allow doc-string mentions only.
	prodHits := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		// Skip pure comment lines.
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+1:])
		// Find "n:" prefix (line number); skip it.
		colon := strings.Index(rest, ":")
		if colon < 0 {
			continue
		}
		body := strings.TrimSpace(rest[colon+1:])
		if strings.HasPrefix(body, "//") || strings.HasPrefix(body, "/*") || strings.HasPrefix(body, "*") {
			continue
		}
		prodHits = append(prodHits, line)
	}
	if len(prodHits) > 0 {
		t.Fatalf("BUG-14 may be fixed: rpcauth refs in production code:\n%s",
			strings.Join(prodHits, "\n"))
	}
	t.Skip("BUG-14 (P1 MISSING): no -rpcauth=<user>:<salt>$<hash> CLI flag. " +
		"Core supports HMAC-SHA256-stored RPC creds so the password never appears " +
		"in plaintext on disk. blockbrew only supports -rpcuser + -rpcpassword " +
		"(plaintext) plus the per-process cookie. Fix: parse repeatable -rpcauth " +
		"entries, check Basic Auth against salted HMAC in checkAuth.")
}

// ────────────────────────────────────────────────────────────────────────
// G15 — BUG-15: no -rpcallowip=<subnet> ACL.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_NoRPCAllowIPACL_BUG15(t *testing.T) {
	hits := w124Grep(t, "rpcallowip\\|AllowIP\\|allowed_ip\\|allowedNets", "cmd/", "internal/rpc/")
	prodHits := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		prodHits = append(prodHits, line)
	}
	if len(prodHits) > 0 {
		t.Fatalf("BUG-15 may be fixed: rpcallowip refs in production code:\n%s",
			strings.Join(prodHits, "\n"))
	}
	t.Skip("BUG-15 (P1 MISSING): no -rpcallowip CIDR ACL. RPC access is gated " +
		"only by Basic Auth — any host that can reach the -rpcbind socket can " +
		"brute-force credentials. Fix: parse repeatable -rpcallowip, build CIDR " +
		"list, gate checkAuth on r.RemoteAddr in allowed nets or loopback.")
}

// ────────────────────────────────────────────────────────────────────────
// G16 — BUG-16: no -blocknotify / -alertnotify / -walletnotify hooks.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_NoNotifyHooks_BUG16(t *testing.T) {
	hits := w124Grep(t, "blocknotify\\|alertnotify\\|walletnotify", "cmd/", "internal/")
	prodHits := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		prodHits = append(prodHits, line)
	}
	if len(prodHits) > 0 {
		t.Fatalf("BUG-16 may be fixed: notify-hook refs in production code:\n%s",
			strings.Join(prodHits, "\n"))
	}
	t.Skip("BUG-16 (P2 MISSING): no -blocknotify / -alertnotify / -walletnotify " +
		"CLI hooks. Core init.cpp:485,498 declares both blocknotify and alertnotify. " +
		"blockbrew has ZMQ pub (covers the what, not the workflow glue: needs a " +
		"subscriber). Fix: add CLI flags, fire os/exec.Command with percent-s substitution " +
		"at the matching Core points.")
}

// ────────────────────────────────────────────────────────────────────────
// G17 — BUG-17: no verifychain RPC / -checkblocks / -checklevel.
// ────────────────────────────────────────────────────────────────────────

func TestW124_G_NoVerifyChainRPC_BUG17(t *testing.T) {
	hits := w124Grep(t, "checkblocks\\|checklevel\\|verifychain", "cmd/", "internal/rpc/")
	prodHits := []string{}
	for _, line := range strings.Split(hits, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "_test.go:") {
			continue
		}
		prodHits = append(prodHits, line)
	}
	if len(prodHits) > 0 {
		t.Fatalf("BUG-17 may be fixed: verifychain refs in production code:\n%s",
			strings.Join(prodHits, "\n"))
	}
	t.Skip("BUG-17 (P2 MISSING): VerifyChainstateConsistency depth is hardcoded " +
		"to 200 (main.go:1115); no operator dial. Core has -checkblocks (default 6), " +
		"-checklevel (default 3), and the verifychain RPC. blockbrew has none. Fix: " +
		"add the three knobs, expose verifychain RPC backed by the existing engine.")
}
