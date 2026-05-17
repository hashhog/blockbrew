# W124 — Operator-Experience Audit (blockbrew)

**Wave**: W124 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Motivation**: Path A on May 17 restored haskoin + ouroboros after a four-day
silent outage. The fleet-monitor caught it; the nodes themselves did not. This
wave audits blockbrew's operator-experience surface against
`bitcoin-core/src/init.cpp`, `bitcoin-core/src/logging.{cpp,h}`, and the Core
`Interrupt()` / `Shutdown()` semantics (`init.cpp:268` / `init.cpp:288`;
the project's reference `src/shutdown.cpp` is the embedded notify/flush block
inside `init.cpp` — Core no longer has a standalone shutdown.cpp).

**Verdict**: **17 bugs / 30 gates**. PRESENT × 19, PARTIAL × 4, MISSING × 7.
The seven "additional findings" beyond the 30-gate set (BUG-11 through BUG-17)
are operator-experience defects discovered during the audit but outside the
standard W124 gate template — recorded as gates regardless because they each
have an xfail test attached.

Per Core reference: ALL of these are operability flaws, not consensus. They
are visible in production from operator-side: silent dead flags, logs we
cannot rotate, signals we cannot deliver, listeners that fall over without
fatal-erroring, RPC `stop` that doesn't stop the daemon, missing notify hooks.

The 30 gate xfail tests live in `cmd/blockbrew/w124_operator_test.go` and
`internal/rpc/w124_operator_test.go`. All xfails are `t.Skip("BUG-N: ...")`
which surface in `go test -v` output without breaking CI green.

## Gate verdict table (30)

| # | Gate | Status | Bug | Severity | Notes |
|---|------|--------|-----|----------|-------|
| G1 | Startup — datadir mkdir 0700 | **PRESENT** | — | — | `main.go:385` |
| G2 | Startup — pebble LOCK probe + stale-lock cleanup | **PRESENT** | — | — | `pebbledb.go:34` `removeStalePebbleLock` |
| G3 | Startup — chainstate consistency probe (walk back N blocks) | **PARTIAL** | BUG-1 | P1 | gated on `OnSyncComplete`; never runs on offline / no-peers nodes |
| G4 | Startup — `-loadsnapshot` AssumeUTXO loader | **PRESENT** | — | — | `main.go:785` (W102) |
| G5 | Shutdown — SIGINT + SIGTERM graceful | **PRESENT** | — | — | `main.go:1525` |
| G6 | Shutdown — 30s hard deadline watchdog | **PRESENT** | — | — | `main.go:1544` |
| G7 | Shutdown — second-signal escalation | **PRESENT** | — | — | `main.go:1554` |
| G8 | Shutdown — atomic chainstate (UTXO + tip) batch | **PRESENT** | — | — | `main.go:1622` |
| G9 | Shutdown — interrupt mid-reorg / long ConnectBlock | **MISSING** | BUG-2 | P1 | no `ctx.Done()` plumbed through `chainmanager.go`; 30s watchdog may SIGKILL mid-write on a deep reorg |
| G10 | Shutdown — `stop` RPC actually stops the daemon | **MISSING** | BUG-3 | **P0** | `handleStop()` calls `s.Stop()` (RPC HTTP only); main goroutine still blocks on `sigChan` — `stop` returns success and daemon stays up |
| G11 | Signals — PID file write + remove on shutdown | **PRESENT** | — | — | `pidfile.go` |
| G12 | Signals — SIGHUP reopen log file | **PARTIAL** | BUG-4 | P2 | only registered when `-logfile=<path>` set explicitly; Core reopens debug.log on SIGHUP regardless (`init.cpp:432 HandleSIGHUP`) |
| G13 | Signals — no SIGUSR1/SIGUSR2 mishandled | **PRESENT** | — | — | Go runtime ignores; we do not break this |
| G14 | Log format — timestamps + microseconds | **PRESENT** | — | — | `main.go:365` `log.Ldate | log.Ltime | log.Lmicroseconds` |
| G15 | Log format — severity levels (info/warn/error) | **MISSING** | BUG-5 | **P1** | `-loglevel` flag declared (`main.go:462`) and parsed into `cfg.LogLevel` (`main.go:52`), but **never consulted** by any code in the tree. Dead flag — `grep cfg.LogLevel` finds only the declaration. Bitcoin Core has `BCLog::Level::{Trace, Debug, Info, Warning, Error}` (`logging.h:60`). |
| G16 | Log categories — Core-compatible `-debug=<cat>` | **PRESENT** | — | — | `loglevel.go:31` mirrors `LOG_CATEGORIES_BY_STR` |
| G17 | Log rotation — automatic by size (Core `ShrinkDebugFile`) | **MISSING** | BUG-6 | P2 | Core trims debug.log when >11/10 × `RECENT_DEBUG_HISTORY_SIZE` (10 MiB) at startup (`logging.cpp:514`). blockbrew has no such mechanism — a logfile grown to GiB over months stays GiB until external rotation. |
| G18 | Log rotation — SIGHUP-friendly external rotation | **PARTIAL** | BUG-4 | (see G12) | works only if `-logfile=<path>` was set on the CLI |
| G19 | Persistence — mempool.dat (Core `-persistmempool`) | **PRESENT** | — | — | `main.go:1598` Dump on shutdown + `main.go:1008` Load on startup (matches Core MEMPOOL_DUMP_VERSION=2) |
| G20 | Persistence — wallet.dat (atomic write + reload) | **PARTIAL** | BUG-7 | P1 | `main.go:1603` `w.SaveToFile("")` is best-effort warn-on-error — no atomic rename + fsync guarantee surfaces in main; depends on wallet impl. |
| G21 | Persistence — blockfilterindex on disk survives restart | **PRESENT** | — | — | `blockfilterindex.go` W121 (BIP-157) |
| G22 | Disk growth — auto-prune to operator target | **PRESENT** | — | — | `main.go:728` `-prune=N` |
| G23 | Disk growth — preflight disk-space check before block write | **MISSING** | BUG-8 | P2 | `ErrDiskFull` is **declared but never used** (`flatfile.go:178`). No preflight `statfs` before block download / `WriteBlock`. ENOSPC propagates as opaque `flatfile: write data failed: ...`. Core does a `CheckDiskSpace` preflight in `blockstorage.cpp::FindNextBlockPos`. |
| G24 | Memory growth — heap soft cap (`GOMEMLIMIT`) | **PRESENT** | — | — | `main.go:296` 12 GiB soft cap if unset |
| G25 | FD usage — adapt `-maxconnections` to ulimit | **MISSING** | BUG-9 | P1 | Core (`init.cpp:1044 RaiseFileDescriptorLimit`) raises rlimit + caps maxconnections to whatever the OS allowed; blockbrew defaults `-maxinbound=117` blindly and lets FD exhaustion surface as connection failures mid-run. |
| G26 | Process supervision — `-daemon` (re-exec, setsid, detach stdio) | **PRESENT** | — | — | `daemon.go` |
| G27 | Process supervision — systemd READY=1 + STOPPING=1 + WATCHDOG | **PRESENT** | — | — | `notify.go` |
| G28 | Process supervision — `-startupnotify` / `-shutdownnotify` hook (Core `-startupnotify`, `-shutdownnotify`) | **MISSING** | BUG-10 | P2 | `init.cpp:529-530` declares both. blockbrew has neither. No way to fire an external alert when the daemon comes up / starts shutting down. |
| G29 | Conf parsing — `-conf=<file>` with `[main] / [test] / [testnet4] / [signet] / [regtest]` sections | **PRESENT** | — | — | `config.go` (Core-compat) |
| G30 | RPC `getblockchaininfo` IBD progress field | **PRESENT** | — | — | `methods.go:2979` `VerificationProgress` |

**Additional findings recorded as gates but not in the 30 above** — covered by
xfail tests:

| Gate | Status | Bug | Severity | Notes |
|---|---|---|---|---|
| RPC `0.0.0.0` metrics bind | bad | BUG-11 | P1 | `main.go:1436` Prometheus metrics bound on `0.0.0.0:9332` by default — exposes block height + peer count + mempool size to any host on the network with no auth. Core's `-prometheus` (when present in third-party builds) is loopback-only. |
| Health endpoint fail-on-bind | bad | BUG-12 | P2 | `main.go:1487` `http.ListenAndServe` inside goroutine; bind failure is logged but doesn't abort startup. Daemon advertises READY=1 even when `-healthport` could not be bound. |
| Metrics endpoint fail-on-bind | bad | BUG-13 | P2 | `main.go:1455` same as above for `-metricsport`. |
| `-rpcauth=<userpw>` (HMAC-SHA256) | bad | BUG-14 | P1 | Core supports `rpcauth=<user>:<hmac>` in `bitcoin.conf` so the password never appears in plaintext on disk. blockbrew supports only `-rpcuser` + `-rpcpassword`. Cookie auth works but is per-process — long-lived external clients still need a stable credential. |
| `-rpcallowip=<subnet>` ACL | bad | BUG-15 | P1 | Core gates RPC by source IP via `-rpcallowip`. blockbrew gates by Basic Auth only; if the operator binds to a non-loopback (e.g. for cross-host mainnet diff), there's no IP-level ACL. |
| `-blocknotify` / `-walletnotify` / `-alertnotify` hooks | bad | BUG-16 | P2 | `init.cpp:485,498` + walletnotify. blockbrew has ZMQ pub (`-zmqpub*`) but no `exec.Command`-driven notify path. ZMQ requires a subscriber; notify hooks are zero-dependency operator workflow glue. |
| RPC `verifychain` (`-checkblocks` / `-checklevel`) | bad | BUG-17 | P2 | Core has `verifychain` RPC + `-checkblocks` / `-checklevel` CLI to force a startup chainstate audit at operator-selected depth. blockbrew's `VerifyChainstateConsistency` walks 200 blocks unconditionally — no operator dial. |

## BUG-1 — startup consistency probe is gated on `OnSyncComplete`

**Severity**: P1 (silent corruption window on a stalled node)
**ID**: BLOCKBREW-W124-1
**Location**: `cmd/blockbrew/main.go:1114` (gate) / `internal/consensus/chainmanager.go:2111` (probe body)

`VerifyChainstateConsistency(200)` is invoked inside the `OnSyncComplete`
callback (`main.go:1114-1127`), which fires only when the header-sync loop
returns a non-empty header batch. For a node that:

- starts up disconnected from the internet (e.g. cold-spare, after a long
  shutdown, or during a fleet outage like May 13–17),
- has all outbound peers reject blockbrew's protocol version,
- runs without a single fresh-headers exchange,

the probe never fires. The May 1 2026 blockbrew h=938360 wedge and the
lunarblock Apr 28 wedge are exactly the failure mode the probe is meant to
catch — but if the node starts in a state where it cannot reach a peer with
fresh headers, the corruption is not detected at startup; the next attempt
to use the chain (RPC `getblock`, p2p service) trips on the missing UTXO and
the operator sees a confusing error long after restart.

**Fix shape**: also call `VerifyChainstateConsistency` synchronously
**before** the peer manager starts, so a corrupt persisted state is detected
and either auto-recovered or surfaced loudly within the first second of
process life, regardless of whether peers arrive.

**Test**: `TestW124_G3_ConsistencyProbeGatedOnSyncComplete_BUG1`.

## BUG-2 — no interrupt plumbed through `ChainManager.ReorgTo`

**Severity**: P1 (30s shutdown deadline may SIGKILL mid-batch)
**ID**: BLOCKBREW-W124-2
**Location**: `cmd/blockbrew/main.go:1542` (deadline) / `internal/consensus/chainmanager.go` (no `ctx`)

The shutdown sequence:

1. `main.go:1525` signal arrives.
2. `main.go:1544` starts a 30s `time.AfterFunc` watchdog.
3. `main.go:1567` builds a `ctx, cancel := context.WithTimeout(... 30s)` and
   immediately `defer cancel()` — but the ctx is **not** passed into any
   chain-manager call. It only logs.
4. If a deep reorg or a slow block connect is in flight (e.g. inside
   `chainMgr.ProcessSubmittedBlock`), the shutdown goroutine blocks waiting
   for the lock; the watchdog fires `os.Exit(1)` mid-batch, the Pebble batch
   is dropped, and the next startup re-runs the consistency probe (or worse,
   wedges).

`grep "ctx\.Done\|Interrupt\|ctx\.Err" internal/consensus/chainmanager.go`
returns **zero matches**. Core threads `m_interrupt_block` through
`ConnectTip` / `DisconnectTip` so a SIGTERM mid-reorg unwinds cleanly
(`validation.cpp::ConnectTip` checks the interrupt at each step).

**Fix shape**: thread a `context.Context` (or `<-chan struct{}` quit) through
`ChainManager`, check it at the head of each `ConnectBlock` /
`DisconnectBlock` iteration, and on detection return a sentinel
`ErrShutdownRequested` that the outer caller treats as a clean stop.

**Test**: `TestW124_G9_NoInterruptInChainManager_BUG2`.

## BUG-3 — `stop` RPC does not stop the daemon

**Severity**: **P0** (operator workflow lies — `bitcoin-cli stop` is the
standard fleet-restart primitive; if it returns success but the daemon stays
up, every restart script that uses it ends up double-launching the next
node or hanging on the kill-and-wait loop)
**ID**: BLOCKBREW-W124-3
**Location**: `internal/rpc/methods.go:2159` / `internal/rpc/server.go:343`

```go
// methods.go:2159
func (s *Server) handleStop() (interface{}, *RPCError) {
    go func() {
        time.Sleep(100 * time.Millisecond)
        s.Stop()                         // <-- only stops the RPC HTTP listener
    }()
    return "blockbrew server stopping", nil
}

// server.go:343
func (s *Server) Stop() error {
    close(s.shutdown)                    // <-- closes RPC shutdown chan only
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if s.httpServer != nil {
        return s.httpServer.Shutdown(ctx)
    }
    return nil
}
```

The main goroutine sits at `main.go:1526` blocked on
`sig := <-sigChan`. `s.Stop()` does not send a signal to the process group,
does not close any channel main is waiting on, and does not call
`os.Process.Signal(syscall.SIGTERM)`. After `handleStop()` returns, the RPC
listener is gone (so any follow-up RPC call hangs) but P2P, sync manager,
mempool, wallet, ZMQ publisher, and the chain manager all keep running.

**Reproduction**:

```bash
blockbrew &
PID=$!
bitcoin-cli -rpcport=$PORT stop
sleep 5
kill -0 $PID && echo "BUG: process still alive after stop RPC"
```

`tools/stop_mainnet.sh` works in production because it always falls through
to SIGTERM; nothing downstream of the meta-repo helpers caught this because
the helpers never trusted the RPC stop to actually stop the node. But every
script copied from Core's playbook (`bitcoin-cli stop && wait`) will hang
forever on blockbrew.

**Fix shape**: `handleStop` must send `syscall.SIGTERM` (or signal a global
shutdown channel observed by main). Two-line fix once the architecture
exposes a daemon-level shutdown handle.

**Test**: `TestW124_G10_StopRPCDoesNotStopDaemon_BUG3`.

## BUG-4 — SIGHUP handler is gated on `-logfile=<path>`

**Severity**: P2 (operator must restart the daemon to force-reopen the log
sink; precludes `logrotate` integration when running with default stderr +
systemd-journald)
**ID**: BLOCKBREW-W124-4
**Location**: `cmd/blockbrew/main.go:405`

```go
if logHandle != nil && cfg.LogFile != "" {
    hupCh := make(chan os.Signal, 1)
    signal.Notify(hupCh, syscall.SIGHUP)
    ...
}
```

Two consequences:

1. When `cfg.LogFile == ""` (stderr default), SIGHUP is delivered to the
   Go runtime which then **terminates the process** (default action for
   un-trapped SIGHUP). An operator firing `kill -HUP $(cat blockbrew.pid)`
   thinking they're rotating the journal will instead kill the node.
2. When the operator later adds `-logfile=...`, the behaviour silently
   changes from "kills daemon" to "reopens file" — surprising.

Core (`init.cpp:432`) always installs a SIGHUP handler that sets
`m_reopen_file = true`; the handler is a no-op when no logfile is configured
but it never lets the default action kill the daemon.

**Fix shape**: always install SIGHUP; route it to `logHandle.Reopen()` which
is already a no-op when `path == ""` (see `loglevel.go:212`).

**Test**: `TestW124_G12_SIGHUPGatedOnLogfile_BUG4`.

## BUG-5 — `-loglevel` is a dead flag

**Severity**: P1 (operator-visible feature claim; the flag appears in help,
in CLAUDE.md, and in test fixtures, but does nothing)
**ID**: BLOCKBREW-W124-5
**Location**: `cmd/blockbrew/main.go:52` (decl) / `main.go:462` (parse) /
`main.go:2127` (help)

```bash
$ grep -rn "cfg\.LogLevel\|LogLevel" cmd/ internal/
cmd/blockbrew/main_test.go:35:    LogLevel:     "info",
cmd/blockbrew/main.go:52:        LogLevel     string
cmd/blockbrew/main.go:462:       flag.StringVar(&cfg.LogLevel, "loglevel", "info", "Log level (debug, info, warn, error)")
```

Three references total: declare, parse, test fixture. **Zero consumers.**
Every log call site in the codebase goes through the stdlib `log` package
which has no notion of levels. Operator sets `-loglevel=error` and continues
to receive every `log.Printf` line.

The category-based `-debug=<cat>` flag (BUG-5's only saving grace) is wired
correctly via `IsDebugEnabled`, but level filtering (info vs debug vs warn)
is silently ignored.

**Fix shape**: either remove the flag (with a deprecation warning that maps
to `-debug=...`) or implement a real level-aware logger. Bitcoin Core's
`BCLog::Level` (`logging.h:60`) has 5 levels; the matching Go pattern is
`slog` (1.21+) or a 30-line wrapper.

**Test**: `TestW124_G15_LoglevelFlagIsDead_BUG5`.

## BUG-6 — no automatic log rotation (Core's `ShrinkDebugFile`)

**Severity**: P2 (long-running daemons fill disks; `-logfile=` users have no
auto-bound)
**ID**: BLOCKBREW-W124-6
**Location**: `cmd/blockbrew/loglevel.go:155` (no shrink call site) /
`bitcoin-core/src/logging.cpp:514` (reference)

Core trims debug.log to its last 10 MiB if it exceeds 11 MiB at startup
(`logging.cpp:514` `ShrinkDebugFile`). blockbrew has no such mechanism;
a 24/7 mainnet node with `-logfile=` and a busy debug category set can grow
the file unboundedly until the disk fills.

**Fix shape**: add a startup-time shrink (drop-in port of Core's algorithm:
seek to `RECENT_DEBUG_HISTORY_SIZE` from end, read into a buffer, rewrite the
file with that tail). Optional: also expose the threshold via
`-shrinkdebugfile=<MB>` to match Core.

**Test**: `TestW124_G17_NoLogShrinkOnStartup_BUG6`.

## BUG-7 — wallet save is best-effort, no atomic write surfaced in main

**Severity**: P1 (wallet corruption window if SIGKILL hits during shutdown
flush)
**ID**: BLOCKBREW-W124-7
**Location**: `cmd/blockbrew/main.go:1603`

```go
if w != nil {
    if err := w.SaveToFile(""); err != nil {
        log.Printf("Warning: wallet save failed: %v", err)
    }
    ...
}
```

The error is logged and discarded — shutdown proceeds and the DB closes.
If `w.SaveToFile` returns "no space left" or "I/O error", the wallet is
**lost** on next startup and the operator must restore from seed.

Mempool dump (`main.go:1598`) and fee estimator save (`main.go:1593`) follow
the same warn-and-continue pattern; for those it's tolerable (transient
state), but for wallet.dat it's a correctness issue.

**Fix shape**: wallet save errors should fail loud — surface via
`notifyStopping` so systemd marks the unit as Failed; optionally retry once
to a sibling `.new` path before giving up. Mempool/fee-estimator failures
are fine to warn.

**Test**: `TestW124_G20_WalletSaveBestEffort_BUG7`.

## BUG-8 — `ErrDiskFull` declared but never raised; no preflight check

**Severity**: P2 (operator gets cryptic error when ENOSPC hits mid-write)
**ID**: BLOCKBREW-W124-8
**Location**: `internal/storage/flatfile.go:178`

```go
var (
    ...
    ErrDiskFull       = errors.New("flatfile: disk full")   // <-- never used
    ...
)
```

`grep -rn ErrDiskFull internal/` returns one line: the declaration. Bitcoin
Core has `CheckDiskSpace` in `node/blockstorage.cpp::FindNextBlockPos` that
fails block-download admission long before the OS returns ENOSPC.

In blockbrew, the operator's first warning of a full disk is:

```
flatfile: write data failed: write /data/.../blk00219.dat: no space left on device
```

…dispatched from inside `OnBlockConnected`, after the chain manager already
committed the connect step. The on-disk state is now half-committed: chain
tip says height N+1, block body for N+1 is partially written, no
`flushchainstate` will have run (and we don't have that RPC anyway — see
also G8 atomic-batch which actually does the right thing on shutdown but
not mid-IBD).

**Fix shape**: add a `statfs`-based preflight inside `BlockStore.WriteBlock`
that returns `ErrDiskFull` when free space falls under a small reserve
(Core uses ~50 MiB). Wire the error up to abort block download until space
is reclaimed.

**Test**: `TestW124_G23_ErrDiskFullDeclaredNotUsed_BUG8`.

## BUG-9 — `-maxconnections` does not adapt to OS file-descriptor limit

**Severity**: P1 (FD exhaustion mid-run; operator sees cryptic accept
errors)
**ID**: BLOCKBREW-W124-9
**Location**: `cmd/blockbrew/main.go:458` (default) / `internal/p2p/peermgr.go`
(no rlimit interaction)

Defaults: `-maxoutbound=8` + `-maxinbound=117` = up to 125 P2P sockets, plus
Pebble's `MaxOpenFiles=2000` (`pebbledb.go:152`), plus RPC connections, plus
the listener fds, plus stdio. On a default `ulimit -n 1024` system this
silently exhausts FDs once IBD opens enough Pebble SSTs.

Bitcoin Core (`init.cpp:1044`):

```cpp
available_fds = RaiseFileDescriptorLimit(user_max_connection + max_private + min_required_fds);
available_fds = std::min(FD_SETSIZE, available_fds);
nMaxConnections = std::min(available_fds - min_required_fds, user_max_connection);
if (nMaxConnections < user_max_connection)
    InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), ...));
```

i.e. Core (1) attempts to raise `RLIMIT_NOFILE`, (2) caps `maxconnections`
to whatever the OS allowed, and (3) warns the operator. blockbrew skips all
three steps. The audit found zero references to `RLIMIT_NOFILE`, `setrlimit`,
`getrlimit`, or `FD_SETSIZE` in the entire tree:

```bash
$ grep -rln "ulimit\|RLIMIT_NOFILE\|setrlimit\|getrlimit\|FD_SETSIZE" internal/ cmd/
(no output)
```

**Fix shape**: at startup, query `unix.Getrlimit(RLIMIT_NOFILE)`, attempt to
raise it to a computed target (maxconn + pebble.MaxOpenFiles + RPC pool +
slack), cap `cfg.MaxInbound + cfg.MaxOutbound` to whatever the OS allowed,
and log a Core-compatible warning if the user value was reduced.

**Test**: `TestW124_G25_NoMaxConnectionsRlimitAdaptation_BUG9`.

## BUG-10 — no `-startupnotify` / `-shutdownnotify` operator hooks

**Severity**: P2 (operator workflow hook present in Core, absent here)
**ID**: BLOCKBREW-W124-10
**Location**: (not declared) / `bitcoin-core/src/init.cpp:529-530` (reference)

Core:

```cpp
argsman.AddArg("-startupnotify=<cmd>", "Execute command on startup.", ...);
argsman.AddArg("-shutdownnotify=<cmd>", "Execute command immediately before beginning shutdown. ...", ...);
```

The startupnotify hook fires after init completes (Core `init.cpp:740`);
shutdownnotify fires at the very beginning of `Interrupt()` (`init.cpp:256`).
Operator use cases: PagerDuty acknowledge on startup, paging out on
shutdown-in-progress, hooking external service-registration on/off events.

blockbrew has ZMQ pub for tx/block notifications but no daemon-lifecycle
hook. systemd notify (G27) partially covers this for systemd hosts; not
every deployment uses systemd.

**Fix shape**: add `-startupnotify` and `-shutdownnotify` CLI flags that
trigger `os/exec.Command` calls at the same points Core does. Errors should
not block startup or shutdown (best-effort).

**Test**: `TestW124_G28_NoStartupShutdownNotifyHooks_BUG10`.

## BUG-11 — Prometheus metrics bound on `0.0.0.0` by default

**Severity**: P1 (information disclosure: block height, peer count, mempool
size leak to any host on the network with no auth)
**ID**: BLOCKBREW-W124-11
**Location**: `cmd/blockbrew/main.go:1436`

```go
metricsAddr := fmt.Sprintf("0.0.0.0:%d", cfg.MetricsPort)
```

The metrics handler exposes:

- `bitcoin_blocks_total` (current block height — leaks IBD state)
- `bitcoin_peers_connected` (connected peer count)
- `bitcoin_mempool_size` (mempool tx count)

Default port `9332`. Anyone on the same LAN can `curl -s http://<host>:9332/metrics`
without auth. An attacker can use the height field to determine when the
node is fully synced (better target for further attacks) and peer count for
eclipse-attack reconnaissance.

**Fix shape**: bind to `127.0.0.1` by default; add `-metricsbind=<addr>` to
override (mirrors `-rpcbind`). Keep the unauthenticated handler — operator
who explicitly binds non-loopback owns the consequence.

**Test**: `TestW124_G_MetricsBindsOnAllInterfaces_BUG11`.

## BUG-12 / BUG-13 — health + metrics servers don't fail-startup on bind error

**Severity**: P2 (silent operator confusion: daemon claims READY=1 but
liveness probe gets ECONNREFUSED)
**ID**: BLOCKBREW-W124-12 / BLOCKBREW-W124-13
**Location**: `cmd/blockbrew/main.go:1487` (health) / `main.go:1455` (metrics)

```go
go func() {
    log.Printf("Health endpoint listening on %s (/healthz, /readyz)", healthAddr)
    if err := http.ListenAndServe(healthAddr, healthMux); err != nil {
        log.Printf("Health server error: %v", err)
    }
}()
```

The "listening on" line is logged **before** the bind succeeds.
`http.ListenAndServe` only returns when it fails (since it blocks on
success); the error is then logged but does not abort startup.
`notifyReady` (sent at `main.go:1501`, *after* this goroutine is spawned)
fires unconditionally — k8s thinks the pod is ready, then liveness probe
hits the unbound port and gets ECONNREFUSED on the very next iteration.

Same shape for the metrics endpoint at `main.go:1455`.

The P2P listener does this correctly (`peermgr.go:414` returns the bind
error synchronously from `peerMgr.Start()`). The RPC server also handles
it correctly (`server.go:310` validates the cert pair eagerly, but the
bind itself is still inside a goroutine — see also `server.go:322` —
actually the same anti-pattern, just with TLS validation moved out).

**Fix shape**: use `net.Listen` synchronously, then hand the listener to
`http.Server.Serve` in a goroutine. Mirror the pattern in `peermgr.go`.

**Tests**: `TestW124_G_HealthBindFailureNotFatal_BUG12`,
`TestW124_G_MetricsBindFailureNotFatal_BUG13`.

## BUG-14 — no `-rpcauth=<userpw>` (HMAC-SHA256) support

**Severity**: P1 (operator must store plaintext RPC password in conf file
or env var; Core has had `rpcauth=` since v0.12 specifically to avoid this)
**ID**: BLOCKBREW-W124-14
**Location**: `cmd/blockbrew/main.go:455-456` (only `-rpcuser` /
`-rpcpassword`)

Core's `rpcauth=<user>:<salt>$<hash>` stores only an HMAC-SHA256 of the
password; operator runs `share/rpcauth/rpcauth.py` to generate the line.
blockbrew has no HMAC path — only plaintext `-rpcuser` + `-rpcpassword`,
plus the per-process cookie (which works for local tools but not for
long-lived external clients that need a stable credential across restarts).

**Fix shape**: parse `-rpcauth=<user>:<salt>$<hash>` lines (repeatable),
check incoming Basic Auth against each entry's salted HMAC. ~50 LOC in
`server.go:checkAuth`.

**Test**: `TestW124_G_NoRPCAuthHMAC_BUG14`.

## BUG-15 — no `-rpcallowip=<subnet>` ACL

**Severity**: P1 (Core's standard IP-level ACL for cross-host RPC; missing
here means any host reachable by `-rpcbind=` can attempt Basic Auth
brute-force)
**ID**: BLOCKBREW-W124-15
**Location**: `internal/rpc/server.go:475-498` (checkAuth has no IP gate)

`grep -n "rpcallowip\|allowed_ip\|AllowIP" cmd/ internal/` returns no
matches. blockbrew's only RPC IP control is "what address is `-rpcbind`
bound to"; once you reach the socket you only have Basic Auth between you
and the RPC dispatch table.

For an operator running blockbrew on a multi-host network (e.g. consensus-
diff against a Core node on the same VPC), the safe pattern is
`-rpcbind=0.0.0.0:8332 -rpcallowip=10.0.0.0/8` — present in Core, absent
here.

**Fix shape**: add `-rpcallowip` as a repeatable flag, parse to a CIDR
list, gate `checkAuth` on `r.RemoteAddr` being in one of the allowed nets
or being loopback.

**Test**: `TestW124_G_NoRPCAllowIPACL_BUG15`.

## BUG-16 — no `-blocknotify` / `-walletnotify` / `-alertnotify` hooks

**Severity**: P2 (operator workflow shims present in Core since v0.6)
**ID**: BLOCKBREW-W124-16
**Location**: (not declared) / `bitcoin-core/src/init.cpp:485,498` (reference)

```cpp
// init.cpp:485
argsman.AddArg("-alertnotify=<cmd>", "Execute command when an alert is raised ...");
// init.cpp:498
argsman.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes ...");
// (walletnotify is declared in init.cpp:2200ish)
```

blockbrew has ZMQ pub (`-zmqpubhashblock`, `-zmqpubrawtx`, etc.) which
covers the *what* (real-time fan-out of events) but requires a subscriber
process. The notify-cmd path covers operator workflow glue: "ssh me when a
block lands at height N", "ping prometheus pushgateway with the tx hash",
"send PagerDuty an alert if validation flags an invalid block".

**Fix shape**: add `-blocknotify` (fires on `OnBlockConnected` with the
block hash via `%s` substitution), `-alertnotify` (fires on
`[CHAINSTATE-CORRUPTION]` log lines or other operator-visible alerts),
optionally `-walletnotify` (fires on wallet-relevant transactions).
Each is a single `os/exec.Command` per event; errors logged not returned.

**Test**: `TestW124_G_NoNotifyHooks_BUG16`.

## BUG-17 — no `verifychain` RPC / `-checkblocks` / `-checklevel`

**Severity**: P2 (operator has no way to force a deep startup audit;
`VerifyChainstateConsistency(200)` is the only level, hardcoded)
**ID**: BLOCKBREW-W124-17
**Location**: `cmd/blockbrew/main.go:1115` (hardcoded depth 200)

Core operator dial:

- `-checkblocks=<N>` — at startup, audit the last N blocks (default 6).
- `-checklevel=<L>` — depth of audit per block (0..4; default 3).
- `verifychain` RPC — same audit, on demand at runtime.

blockbrew runs only `VerifyChainstateConsistency(200)`, only at the
OnSyncComplete edge (cf. BUG-1), with no operator override. There is no
RPC entry point — the operator cannot say "I just SIGKILL'd the daemon
during a flush, please audit harder than usual on startup."

**Fix shape**: add `verifychain` RPC (handle has the same engine as the
startup probe, just operator-controlled), `-checkblocks=<N>` (override the
hardcoded 200), `-checklevel=<L>` (depth of per-block work; mirrors Core).

**Test**: `TestW124_G_NoVerifyChainRPC_BUG17`.

## Cross-impl notes

The W124 universe (operator-experience) is the natural follow-up to the
W123 silent-outage-recovery wave that motivated Path A on May 17. A few
patterns expected to recur fleet-wide based on initial scan:

- **"declared but never used" CLI flags** (BUG-5 `-loglevel`, BUG-8
  `ErrDiskFull`): the W124 cousin of the W117/W121 "dead helper" universal
  finding. Pattern: ergonomic surface implemented up to one inch from the
  call site, then the wire was never finished. Surface area for follow-up
  audits: `grep flag\\.StringVar.*&cfg\\.[A-Z]` then check each name has at
  least one non-test consumer.
- **"goroutine swallows bind failures"** (BUG-12, BUG-13): listener inside
  `go func()` block, error logged but startup proceeds — k8s + systemd
  notify both lie to the supervisor.
- **"RPC `stop` doesn't stop"** (BUG-3): may be unique to blockbrew but
  worth probing every impl. The harness `bitcoin-cli stop` is the
  fleet-restart contract — any impl that violates it breaks every Core-
  playbook script that's been copy-pasted into hashhog ops.
- **No FD-limit adaptation** (BUG-9): Go runtime doesn't raise rlimit
  automatically; every Go impl in the fleet (blockbrew + ouroboros's
  ferrous-utils Rust glue) is suspect.

## Test summary

xfail tests added in this audit:

| File | Tests |
|---|---|
| `cmd/blockbrew/w124_operator_test.go` | 14 |
| `internal/rpc/w124_operator_test.go` | 3 |

Total: **17 xfail tests** (one per bug). All marked `t.Skip("BUG-N: ...")`
so CI stays green; running `go test -v -run W124 ./...` enumerates each
gate with its current verdict.

## Audit budget

This wave is DISCOVERY only — no production code changes. Fix shapes are
sketched per-bug above but not landed. Each BUG-N is one independent
follow-up.
