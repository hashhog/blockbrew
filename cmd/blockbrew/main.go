package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"net/http"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/rpc"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

const (
	version    = "0.1.0"
	defaultDir = ".blockbrew"
)

// Config holds all application configuration.
type Config struct {
	DataDir      string
	Network      string
	ListenP2P    string
	ListenRPC    string
	RPCUser      string
	RPCPassword  string
	MaxOutbound  int
	MaxInbound   int
	NoListen     bool
	MinerAddress string
	WalletFile   string
	LogLevel     string
	TxIndex      bool
	MaxMempool   int64
	MinRelayFee  float64
	PrintVersion bool

	// MempoolFullRBF mirrors Bitcoin Core's `-mempoolfullrbf` switch (init.cpp).
	// True (the default; matches Core's DEFAULT_MEMPOOL_FULL_RBF=true since
	// v28) makes mempool replacement skip BIP-125 Rule 1 (opt-in signaling)
	// — every conflict is replaceable subject to Rules 3/4/5 and
	// ImprovesFeerateDiagram. False reinstates the legacy BIP-125 behaviour
	// that requires at least one conflicting tx (or any in-mempool ancestor)
	// to signal RBF. Surfaced through `getmempoolinfo.fullrbf` so the RPC
	// truth value reflects the runtime policy. W120 BUG-5 / FIX-68.
	MempoolFullRBF         bool
	MempoolFullRBFExplicit bool // true when the operator set -mempoolfullrbf= on the CLI/conf

	// Rest enables Bitcoin Core's REST HTTP surface
	// (`/rest/block/...`, `/rest/tx/...`, `/rest/chaininfo.json`, etc.) on
	// the same socket as the JSON-RPC server. Default false, matching
	// Bitcoin Core's `-rest=0` default (init.cpp). When true, the handlers
	// implemented in `internal/rpc/rest.go::RegisterRESTHandlers` are
	// mounted on the RPC mux at startup and serve unauthenticated GETs
	// under `/rest/`. JSON-RPC POST routes are unaffected and still
	// require auth. Mirrors Core: see `bitcoin-core/src/rest.cpp`
	// `uri_prefixes` and `init.cpp`'s `-rest` argspec.
	//
	// Pre-fix the `RPCConfig.RESTEnabled` field existed but no CLI flag
	// fed it, so the implemented REST handlers were unreachable in
	// production binaries (audit `_rest-api-cross-impl-audit-2026-05-06-part1.md`).
	Rest bool

	// RPCTLSCert / RPCTLSKey wire optional HTTPS termination for the
	// RPC + REST socket (W119 BUG / FIX-64). Both empty = legacy plain
	// HTTP (default; backward compat with operators fronting blockbrew
	// behind nginx/Tor for TLS). Both set = HTTPS via Go crypto/tls
	// ListenAndServeTLS. Exactly one set = startup error (refusing to
	// silently land on plaintext when the operator intended HTTPS).
	// Required for clearnet PayJoin per BIP-78 (HTTPS endpoint mandatory
	// outside of .onion). Reference: bitcoin-core/src/httpserver.cpp.
	RPCTLSCert string
	RPCTLSKey  string

	// Performance profiling
	PprofAddr       string
	ParallelScripts bool

	// Prometheus metrics
	MetricsPort int

	// Cache budget. -dbcache is in MiB and is split between the in-memory
	// UTXO cache (80%) and Pebble's block cache (20%). The skew toward the
	// UTXO cache follows W76-PHASE telemetry: ConnectBlock latency is
	// dominated by `first_avg` (UTXO read), so reducing UTXO cache misses
	// has more leverage than enlarging the LSM block cache.
	DBCache int

	// BIP-324 v2 transport opt-in. When true, both new outbound dials and
	// inbound classification negotiate the v2 (encrypted) transport with a
	// fall-through to v1 plaintext. Default ON since end-to-end interop
	// matrix shows blockbrew→ouroboros and ouroboros→blockbrew as v2/v2
	// (Phase C) and the cipher fix (`7351ce8`) plus libsecp256k1-cgo
	// EllSwift binding (`b3ac162`) make the in-process tests stable.
	// Bitcoin Core ≥26 defaults `-v2transport=1` since 2024; we match.
	//
	// Settable via `-bip324v2` CLI flag (`-bip324v2=false` to opt out) or
	// `BLOCKBREW_BIP324_V2` env var (`0` / `false` to opt out, `1` /
	// `true` to opt in).  CLI flag takes precedence when both are set.
	BIP324V2 bool

	// PeerBloomFilters controls advertisement of the BIP-111 NODE_BLOOM
	// service bit and is the gate for serving BIP-35 "mempool" requests.
	// Mirrors Bitcoin Core's `-peerbloomfilters` flag (see init.cpp:1104):
	// when true, NODE_BLOOM is OR'd into our advertised services in the
	// version handshake, and incoming "mempool" messages are honored.
	// When false, peers see no NODE_BLOOM bit and "mempool" requests are
	// silently ignored (Core disconnects; we simply drop, matching the
	// rest of blockbrew's permissive eviction policy).  Default false,
	// matching Core's DEFAULT_PEERBLOOMFILTERS=false (net_processing.h:44).
	PeerBloomFilters bool

	// Prune sets the auto-prune target in MiB for the blk*.dat / rev*.dat
	// directory. 0 (the default) disables pruning entirely (archive node).
	// Values 1..549 are rejected at flag-validation time: Bitcoin Core's
	// MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB is the floor below which
	// pruning would routinely drop data the node still needs to serve
	// over P2P inside the next compact-block window. Values >= 550 enable
	// automatic pruning: oldest blk/rev pairs whose contents are entirely
	// at heights tip - MIN_BLOCKS_TO_KEEP (288) or below are deleted to
	// keep the on-disk footprint near this target. Headers, the UTXO
	// set, and recent blocks are never pruned.
	//
	// Mirrors Bitcoin Core's `-prune=N` flag (init.cpp).
	Prune int64

	// Operational-parity flags. Each mirrors a Bitcoin Core CLI flag:
	//   -daemon          Run in the background after init (re-exec pattern).
	//   -pid=<file>      Write the daemon pid to <file> (default <datadir>/blockbrew.pid).
	//   -conf=<file>     Read additional options from a config file.
	//   -debug=<cat>     Enable verbose logging for the named category.
	//                    Repeatable / comma-separated. Categories follow Core
	//                    (`bitcoin-core/src/logging.cpp:LOG_CATEGORIES_BY_STR`).
	//   -printtoconsole  Force log output to stderr even when -logfile= is set.
	//   -logfile=<path>  Write log output to a file (SIGHUP reopens it).
	//   -reindex         Wipe chainstate and rebuild from blk*.dat. Currently
	//                    a *deferred* implementation: blockbrew honestly
	//                    refuses to start so the operator knows the support
	//                    is coming, instead of accepting the flag silently.
	//   -zmqpub*         ZMQ PUB endpoints, mirroring Core's `-zmqpub<topic>`.
	//   -rpcready-notify When run under systemd, send READY=1 once the RPC
	//                    server is bound. Defaults to ON so containerised
	//                    deployments work; set false to skip the syscall on
	//                    non-systemd hosts.
	//   -healthport=<n>  Bind a tiny HTTP /healthz endpoint for k8s-style
	//                    liveness/readiness probes. 0 disables.
	Daemon          bool
	PidFile         string
	ConfFile        string
	Debug           debugFlag // accumulator (repeatable, comma-OK)
	PrintToConsole  bool
	LogFile         string
	Reindex         bool
	ZMQPubHashBlock string
	ZMQPubHashTx    string
	ZMQPubRawBlock  string
	ZMQPubRawTx     string
	ZMQPubSequence  string
	RPCReadyNotify  bool
	HealthPort      int

	// LoadSnapshot is the path to a Bitcoin Core-format UTXO snapshot
	// (`utxo\xff` magic, VARINT-coded coins).  When non-empty and the
	// chainstate is fresh (height==0), blockbrew loads the snapshot
	// before starting the rest of the node.  Mirrors Core's
	// `-loadsnapshot=<path>`.  See bitcoin-core/src/node/utxo_snapshot.h
	// + src/rpc/blockchain.cpp loadtxoutset.
	LoadSnapshot string

	// BlockFilterIndex enables the BIP-157/158 compact-block-filter index.
	// When true, blockbrew builds and persists a basic-type GCS filter for
	// every connected block and rewinds the index on disconnect (BIP-157
	// Phase 1 + Phase 2). When false (the default — matches Bitcoin Core's
	// `-blockfilterindex=0`), the index is not registered, the
	// /rest/blockfilter and /rest/blockfilterheaders REST endpoints return
	// "Index is not enabled for filtertype basic", and getblockfilter
	// returns the same error.
	//
	// Mirrors Bitcoin Core's `-blockfilterindex=basic|0|1` flag (init.cpp).
	// We accept boolean only; "basic" is the only filter type defined and
	// the only one Core implements server-side.
	BlockFilterIndex bool

	// ASMap is the path to an ASMap binary file for AS-level peer bucketing
	// and eclipse-resistance diversity. When set, blockbrew loads and
	// validates the file (up to 8 MiB) at startup and uses the embedded
	// trie to map peer IPs to their Autonomous System Numbers. Peer
	// diversity is then enforced at the AS level rather than /16 subnet.
	// Mirrors Bitcoin Core's `-asmap=<file>` flag (init.cpp).
	// Leave empty (default) to use the legacy /16 subnet grouping.
	ASMap string

	// Connect pins the node to ONLY the listed <ip:port> peers and, while
	// non-empty, disables DNS-seed resolution AND the addrman/auto-outbound
	// dialing maintenance loop (full-relay, block-relay-only, feeler, and
	// the DNS-refresh trigger). Repeatable, mirroring Bitcoin Core's
	// `-connect=<ip:port>` (init.cpp: -connect implies -dnsseed=0 and turns
	// the automatic outbound connections off — the node connects to ONLY
	// the given peers). clearbit's reference is peer.zig:7009 (dedicated
	// connect branch skips dnsSeeds()) + peer.zig:7050 (outbound-fill gated
	// on connect_address==null). The pinned peers are dialed as manual
	// connections (capacity-cap-exempt, never auto-banned) and re-dialed if
	// they drop. Empty (default) = normal addrman + DNS-seed discovery.
	Connect connectFlag

	// NoDNSSeed independently suppresses DNS-seed resolution without
	// changing any other discovery behaviour (addrman/auto-outbound dialing
	// still runs and fixed seeds / gossip are still used). Mirrors Bitcoin
	// Core's `-dnsseed=0` / `-nodnsseed`, and clearbit's `--nodnsseed`
	// (sets dns_seed=false). Implied automatically when -connect is set.
	NoDNSSeed bool
}

// connectFlag implements flag.Value so `-connect=<ip:port>` may be repeated
// (and/or comma-separated), mirroring Bitcoin Core's repeatable `-connect`.
type connectFlag []string

func (c *connectFlag) String() string {
	if c == nil {
		return ""
	}
	return strings.Join(*c, ",")
}

func (c *connectFlag) Set(v string) error {
	// Accept comma-separated values in a single occurrence too.
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*c = append(*c, part)
		}
	}
	return nil
}

// debugFlag implements flag.Value so `-debug=` may be repeated and/or
// comma-separated, both forms supported by Bitcoin Core.
type debugFlag []string

func (d *debugFlag) String() string {
	if d == nil {
		return ""
	}
	return strings.Join(*d, ",")
}

func (d *debugFlag) Set(v string) error {
	*d = append(*d, v)
	return nil
}

// stdFlagSetter adapts a *flag.FlagSet to the FlagSetter interface used
// by applyConfigFlags. We need this thin shim so config-file tests can
// run without depending on the global flag.CommandLine state.
type stdFlagSetter struct{ fs *flag.FlagSet }

func (s stdFlagSetter) Set(name, value string) error {
	return s.fs.Set(name, value)
}

func (s stdFlagSetter) IsRegistered(name string) bool {
	return s.fs.Lookup(name) != nil
}

// Process-scoped handles for resources owned by main(). Stored as
// package-level vars so run() can wire them into shutdown without
// threading them through the function signature (which is already
// unwieldy). Initialised in main, consumed in run.
var (
	processPidFile *pidFileManager
	processLogFile *logFileHandle
)

// parseBIP324V2Env interprets the BLOCKBREW_BIP324_V2 env-var value as a
// tristate: "1"/"true" → enable, "0"/"false" → disable, anything else
// (including empty) → use `defaultOn`.  The defaultOn parameter is the
// compiled-in default for cases where the env var is unset or
// unrecognised.  Kept separate from parseFlags() so the propagation can
// be unit-tested without touching flag.Parse() globals.
func parseBIP324V2Env(v string, defaultOn bool) bool {
	if v == "" {
		return defaultOn
	}
	if v == "1" || strings.EqualFold(v, "true") {
		return true
	}
	if v == "0" || strings.EqualFold(v, "false") {
		return false
	}
	return defaultOn
}

// computeCacheSplit returns (utxoCacheBytes, pebbleBlockCacheBytes) for a
// given -dbcache value in MiB. Clamped to [4, 65536] MiB.
func computeCacheSplit(dbcacheMiB int) (utxoCacheBytes int64, pebbleBlockCacheBytes int64) {
	if dbcacheMiB < 4 {
		dbcacheMiB = 4
	}
	if dbcacheMiB > 65536 {
		dbcacheMiB = 65536
	}
	totalBytes := int64(dbcacheMiB) * 1024 * 1024
	utxoCacheBytes = totalBytes * 8 / 10
	pebbleBlockCacheBytes = totalBytes - utxoCacheBytes
	return
}

func main() {
	// Tune Go GC for large-heap IBD workloads. The default GOGC=100
	// causes excessive GC scanning of the multi-million-entry UTXO map.
	// GOGC=400 lets the heap grow 4x before triggering GC, dramatically
	// reducing GC CPU overhead. GOMEMLIMIT provides a safety net so the
	// runtime will still GC if memory approaches the limit.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(400)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(12 * 1024 * 1024 * 1024) // 12 GiB soft limit
	}

	// Check for subcommands first
	if len(os.Args) > 1 {
		if handleSubcommands(os.Args[1:]) {
			return
		}
	}

	cfg := parseFlags()

	if cfg.PrintVersion {
		fmt.Printf("blockbrew v%s\n", version)
		os.Exit(0)
	}

	// -reindex: HONEST DEFER. We currently track the work item in
	// CLAUDE.md and W?? notes; until the implementation lands, refusing
	// to start with a clear message is preferable to silently accepting
	// the flag and doing nothing (which would lie to the operator).
	// Match Bitcoin Core's user expectation: -reindex must rebuild the
	// chain from blk*.dat. Until we do that, exit non-zero.
	if cfg.Reindex {
		fmt.Fprintln(os.Stderr, "Error: -reindex is not yet implemented in blockbrew.")
		fmt.Fprintln(os.Stderr, "       The flat-file blk*.dat → Pebble chainstate rebuild path is in design.")
		fmt.Fprintln(os.Stderr, "       To force a full rebuild today, stop the node and remove the chaindata/ directory.")
		fmt.Fprintln(os.Stderr, "       Tracking: see meta-repo CLAUDE.md (W?? `-reindex implementation`).")
		os.Exit(1)
	}

	// -daemon: detach from the controlling terminal before initialising
	// the rest of the node. Done very early so the parent exits quickly
	// (start_mainnet.sh is still nohup'd for backward compat). The child
	// returns from daemonize() with daemonEnvFlag set; the parent exits.
	if cfg.Daemon {
		// Resolve pid path now so the parent can poll for it.
		pidPath := cfg.PidFile
		if pidPath == "" {
			pidPath = filepath.Join(cfg.DataDir, "blockbrew.pid")
		}
		daemonize(pidPath, pidWaitTimeoutDefault)
		// Only the child reaches here.
	}

	// Apply -debug categories (after potential daemon fork so the child
	// inherits the parsed list via its own flag.Parse — they're stored
	// on cfg.Debug already).
	accepted, warnings := applyDebugCategories(cfg.Debug)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "blockbrew: %s\n", w)
	}

	// Set up log destination. Default: stderr (matches existing behavior).
	// -logfile=<path>: writes go to file; SIGHUP reopens (rotation).
	// -printtoconsole: keep stderr ON even when -logfile is set (tee).
	logHandle, err := newLogFileHandle(cfg.LogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open log file %s: %v\n", cfg.LogFile, err)
		os.Exit(1)
	}
	if cfg.LogFile != "" {
		if cfg.PrintToConsole {
			log.SetOutput(io.MultiWriter(logHandle, os.Stderr))
		} else {
			log.SetOutput(logHandle)
		}
	}
	log.SetPrefix("[blockbrew] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("blockbrew v%s starting...", version)
	log.Printf("Network: %s", cfg.Network)
	log.Printf("Data directory: %s", cfg.DataDir)
	if cfg.BIP324V2 {
		log.Printf("BIP-324 v2 transport: ENABLED (outbound + inbound; v1 fall-through)")
	}
	if len(accepted) > 0 {
		cats, all := debugCategoriesSnapshot()
		if all {
			log.Printf("Debug logging: ALL categories enabled")
		} else {
			log.Printf("Debug logging: enabled categories: %v", cats)
		}
	}
	if cfg.LogFile != "" {
		log.Printf("Log file: %s (SIGHUP reopens)", cfg.LogFile)
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Write PID file. Even when -daemon was not used, exposing the pid
	// makes external tooling (start_mainnet.sh, systemd PIDFile=) work.
	pidMgr := newPidFileManager(cfg.PidFile, cfg.DataDir)
	if path, err := pidMgr.Write(); err != nil {
		log.Printf("WARNING: pid file write failed: %v", err)
	} else {
		log.Printf("PID file: %s (pid=%d)", path, os.Getpid())
	}

	// Stash for run()'s shutdown path.
	processPidFile = pidMgr
	processLogFile = logHandle

	// SIGHUP handler: reopen log file (if configured). Independent of
	// the SIGINT/SIGTERM shutdown handler installed in run() so log-rotation
	// signals never look like a shutdown request.
	if logHandle != nil && cfg.LogFile != "" {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		go func() {
			for range hupCh {
				log.Printf("SIGHUP received; reopening log file %s", cfg.LogFile)
				if err := logHandle.Reopen(); err != nil {
					log.Printf("logfile reopen error: %v", err)
				} else {
					log.Printf("log file reopened")
				}
			}
		}()
	}

	var chainParams *consensus.ChainParams
	switch cfg.Network {
	case "mainnet":
		chainParams = consensus.MainnetParams()
	case "testnet":
		chainParams = consensus.TestnetParams()
	case "regtest":
		chainParams = consensus.RegtestParams()
	case "signet":
		chainParams = consensus.SignetParams()
	case "testnet4":
		chainParams = consensus.Testnet4Params()
	default:
		log.Fatalf("Unknown network: %s", cfg.Network)
	}

	// Warn if RPC password is empty
	if cfg.RPCPassword == "" {
		log.Printf("WARNING: RPC password is empty, consider setting --rpcpassword for security")
	}

	if err := run(cfg, chainParams); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}

func parseFlags() *Config {
	cfg := &Config{}
	homeDir, _ := os.UserHomeDir()
	defaultDataDir := filepath.Join(homeDir, defaultDir)

	flag.StringVar(&cfg.DataDir, "datadir", defaultDataDir, "Data directory")
	flag.StringVar(&cfg.Network, "network", "mainnet", "Network (mainnet, testnet, regtest, signet)")
	flag.StringVar(&cfg.ListenP2P, "listen", "", "P2P listen address (default: based on network)")
	flag.StringVar(&cfg.ListenRPC, "rpcbind", "", "RPC listen address (default: based on network)")
	flag.StringVar(&cfg.RPCUser, "rpcuser", "blockbrew", "RPC username")
	flag.StringVar(&cfg.RPCPassword, "rpcpassword", "", "RPC password")
	flag.IntVar(&cfg.MaxOutbound, "maxoutbound", 8, "Maximum outbound connections")
	flag.IntVar(&cfg.MaxInbound, "maxinbound", 117, "Maximum inbound connections")
	flag.BoolVar(&cfg.NoListen, "nolisten", false, "Disable inbound P2P connections")
	flag.StringVar(&cfg.MinerAddress, "mineraddress", "", "Address for mining rewards")
	flag.StringVar(&cfg.WalletFile, "wallet", "wallet.dat", "Wallet file name")
	flag.StringVar(&cfg.LogLevel, "loglevel", "info", "Log level (debug, info, warn, error)")
	flag.BoolVar(&cfg.TxIndex, "txindex", false, "Enable transaction index")
	flag.BoolVar(&cfg.Rest, "rest", false, "Accept public REST requests on the JSON-RPC socket (Core parity: default off). When true, handlers under `/rest/` (block, tx, headers, blockhashbyheight, chaininfo, mempool/{info,contents}, getutxos) are mounted unauthenticated; JSON-RPC POST endpoints still require auth. Mirrors Bitcoin Core's `-rest=1`.")
	flag.StringVar(&cfg.RPCTLSCert, "rpc-tls-cert", "", "Path to a PEM-encoded x509 certificate for HTTPS-terminating the RPC + REST socket. Must be paired with -rpc-tls-key. Empty (default) = serve plain HTTP. Setting exactly one of cert/key is a startup error. Required for BIP-78 clearnet PayJoin endpoints (W119 / FIX-64).")
	flag.StringVar(&cfg.RPCTLSKey, "rpc-tls-key", "", "Path to a PEM-encoded private key paired with -rpc-tls-cert. Empty (default) = serve plain HTTP. See -rpc-tls-cert.")
	flag.Int64Var(&cfg.MaxMempool, "maxmempool", 300, "Maximum mempool size in MB")
	flag.Float64Var(&cfg.MinRelayFee, "minrelayfee", 0.00001, "Minimum relay fee (BTC/kvB)")
	flag.BoolVar(&cfg.MempoolFullRBF, "mempoolfullrbf", true, "Accept mempool replacements without BIP-125 opt-in signaling (Core v28+ default; DEFAULT_MEMPOOL_FULL_RBF=true). When true, Rule 1 is skipped — every conflict is replaceable subject to Rules 3/4/5 + ImprovesFeerateDiagram. When false (legacy), conflicts must signal (directly or via in-mempool ancestor) to be replaceable. The `getmempoolinfo.fullrbf` field reflects this setting. W120 BUG-5 / FIX-68.")
	flag.BoolVar(&cfg.PrintVersion, "version", false, "Print version and exit")
	flag.StringVar(&cfg.PprofAddr, "pprof", "", "pprof HTTP server address (e.g., localhost:6060)")
	flag.BoolVar(&cfg.ParallelScripts, "parallelscripts", true, "Enable parallel script validation")
	flag.IntVar(&cfg.MetricsPort, "metricsport", 9332, "Prometheus metrics port (0 to disable)")
	flag.IntVar(&cfg.DBCache, "dbcache", 2560, "Database cache size in MiB (split: 80% UTXO cache + 20% Pebble block cache; recommend 4096+ for active IBD)")
	flag.BoolVar(&cfg.BIP324V2, "bip324v2", true, "Enable BIP-324 v2 encrypted transport (outbound + inbound; v1 fall-through). Default ON; pass `-bip324v2=false` to opt out. Also settable via BLOCKBREW_BIP324_V2=0/1.")
	flag.BoolVar(&cfg.PeerBloomFilters, "peerbloomfilters", false, "Advertise NODE_BLOOM (BIP-111) and honor BIP-35 \"mempool\" requests. Default OFF, matching Bitcoin Core's DEFAULT_PEERBLOOMFILTERS=false. Pass `-peerbloomfilters=true` to opt in.")
	flag.Int64Var(&cfg.Prune, "prune", 0, "Auto-prune target in MiB for the blk*.dat directory. 0 = archive (no pruning, default). Must be >= 550 if non-zero (Bitcoin Core MIN_DISK_SPACE_FOR_BLOCK_FILES). Headers, UTXO set, and the last 288 blocks are never pruned.")
	// Operational-parity flags. Mirror Bitcoin Core init.cpp argspec.
	flag.BoolVar(&cfg.Daemon, "daemon", false, "Run in the background as a daemon (default: false). When true, blockbrew double-forks and detaches before init.")
	flag.StringVar(&cfg.PidFile, "pid", "", "Write the daemon pid to <file> (default: <datadir>/blockbrew.pid).")
	flag.StringVar(&cfg.ConfFile, "conf", "", "Path to a key=value config file. Defaults: <datadir>/blockbrew.conf, ~/.blockbrew/blockbrew.conf. CLI flags override config file.")
	flag.Var(&cfg.Debug, "debug", "Output debugging information for the named category. Repeatable / comma-separated. Categories: net, mempool, validation, rpc, ... (see Bitcoin Core LOG_CATEGORIES_BY_STR). Pass `-debug=all` for everything; `-debug=none` to clear; prefix with `-` to negate (e.g. `-debug=-net`).")
	flag.BoolVar(&cfg.PrintToConsole, "printtoconsole", false, "Send trace/debug info to console even when -logfile= is set (default: false). When -logfile is empty, output always goes to stderr regardless.")
	flag.StringVar(&cfg.LogFile, "logfile", "", "Specify the path of the log file. Empty = stderr. SIGHUP reopens the file (rotation-friendly).")
	flag.BoolVar(&cfg.Reindex, "reindex", false, "Wipe chainstate and rebuild from blk*.dat. NOT YET IMPLEMENTED — blockbrew refuses to start when this flag is set so silent no-ops never put the chainstate in a confused state.")
	flag.StringVar(&cfg.ZMQPubHashBlock, "zmqpubhashblock", "", "ZMQ endpoint to publish 32-byte block hashes on (e.g. tcp://127.0.0.1:28332).")
	flag.StringVar(&cfg.ZMQPubHashTx, "zmqpubhashtx", "", "ZMQ endpoint to publish 32-byte tx hashes on.")
	flag.StringVar(&cfg.ZMQPubRawBlock, "zmqpubrawblock", "", "ZMQ endpoint to publish raw serialised blocks on.")
	flag.StringVar(&cfg.ZMQPubRawTx, "zmqpubrawtx", "", "ZMQ endpoint to publish raw serialised txs on.")
	flag.StringVar(&cfg.ZMQPubSequence, "zmqpubsequence", "", "ZMQ endpoint for sequence notifications (block connect/disconnect, tx accept/remove).")
	flag.BoolVar(&cfg.RPCReadyNotify, "rpcready-notify", true, "On systemd hosts, send READY=1 to NOTIFY_SOCKET once RPC is bound. No-op when NOTIFY_SOCKET is unset.")
	flag.IntVar(&cfg.HealthPort, "healthport", 0, "If non-zero, bind a /healthz HTTP endpoint on 127.0.0.1:<port> for liveness/readiness probes. 0 disables.")
	flag.StringVar(&cfg.LoadSnapshot, "load-snapshot", "", "Load a Bitcoin Core-format UTXO snapshot (utxo\\xff magic) from <path> before starting the node. Only acted on when the chainstate is fresh (height==0); otherwise an error is logged and the snapshot is skipped. Mirrors Bitcoin Core's `-loadsnapshot=<path>`.")
	flag.BoolVar(&cfg.BlockFilterIndex, "blockfilterindex", false, "Maintain the BIP-157/158 basic compact-block-filter index. Default OFF (matches Bitcoin Core's `-blockfilterindex=0`). When ON, blockbrew populates the index on every connected block, rewinds it on disconnect (Phase 2 reorg-aware), and exposes the resulting filters via /rest/blockfilter, /rest/blockfilterheaders, and the getblockfilter RPC.")
	flag.StringVar(&cfg.ASMap, "asmap", "", "Path to an ASMap binary file for AS-level peer bucketing and eclipse-resistance diversity. When set, blockbrew loads the file (max 8 MiB), validates its trie, and uses it to map peer IPs to Autonomous System Numbers. Peer diversity is then enforced at the AS level rather than /16 subnet. Leave empty (default) to use legacy /16 grouping. Mirrors Bitcoin Core's `-asmap=<file>` (init.cpp).")
	flag.Var(&cfg.Connect, "connect", "Connect ONLY to the specified <ip:port> peer(s) and disable both DNS-seed resolution and addrman/auto-outbound dialing. Repeatable / comma-separated. Mirrors Bitcoin Core's `-connect=<ip:port>` (implies -dnsseed=0 and turns off automatic outbound connections). The pinned peers are dialed as manual connections and re-dialed if they drop. Empty (default) = normal peer discovery.")
	flag.BoolVar(&cfg.NoDNSSeed, "nodnsseed", false, "Disable DNS-seed resolution without otherwise changing peer discovery (addrman/auto-outbound dialing still runs). Mirrors Bitcoin Core's `-dnsseed=0` / `-nodnsseed`. Implied automatically when -connect is set.")
	flag.Parse()

	// Apply config file (CLI > config > default). Build the set of flags
	// the user provided on the command line so we don't overwrite them.
	cliSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { cliSet[f.Name] = true })

	// We need to pre-resolve the datadir to find the default config-file
	// path. The CLI value may already be set; the network suffix is
	// applied below after config merge so the datadir we search is the
	// raw user-supplied root (Core does the same).
	confDataDir := cfg.DataDir
	if confDataDir == "" {
		confDataDir = defaultDataDir
	}
	confPath, confExplicit := resolveConfigPath(cfg.ConfFile, confDataDir)
	if confPath != "" {
		entries, err := loadConfigFile(confPath, cfg.Network)
		if err != nil {
			if confExplicit {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			// Defaults search: file existed but failed to parse → warn
			// instead of fatal so a malformed default conf doesn't
			// brick the daemon.
			fmt.Fprintf(os.Stderr, "Warning: %v (continuing with CLI defaults)\n", err)
		} else {
			applyConfigFlags(stdFlagSetter{flag.CommandLine}, entries, cliSet,
				func(format string, args ...any) {
					fmt.Fprintf(os.Stderr, "blockbrew: "+format+"\n", args...)
				})
		}
	}

	// Validate -prune (Bitcoin Core init.cpp:524 / blockmanager_args.cpp:22):
	//   0      → off (archive, default)
	//   1      → manual mode: in prune mode but auto-prune does not fire;
	//            only the pruneblockchain RPC triggers a sweep.
	//   2..549 → rejected (below MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB)
	//   ≥550   → automatic prune target in MiB
	if cfg.Prune < 0 {
		fmt.Fprintln(os.Stderr, "Error: -prune must be >= 0")
		os.Exit(1)
	}
	if cfg.Prune > 1 && cfg.Prune < int64(storage.MinPruneTargetMiB) {
		fmt.Fprintf(os.Stderr,
			"Error: -prune target %d MiB is below the %d MiB floor (Bitcoin Core MIN_DISK_SPACE_FOR_BLOCK_FILES). Pass 0 to disable pruning, 1 for manual mode, or >= %d for automatic.\n",
			cfg.Prune, storage.MinPruneTargetMiB, storage.MinPruneTargetMiB)
		os.Exit(1)
	}

	// Env-var fallback: BLOCKBREW_BIP324_V2=0/1 overrides the compiled-in
	// default if the CLI flag wasn't explicitly set. CLI flag wins when
	// both are present (the env var is checked only if the user didn't
	// pass -bip324v2 on the command line — flag.Visit walks only flags
	// that were actually set).  Default is ON.
	cliBIP324V2Set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "bip324v2" {
			cliBIP324V2Set = true
		}
	})
	if !cliBIP324V2Set {
		cfg.BIP324V2 = parseBIP324V2Env(os.Getenv("BLOCKBREW_BIP324_V2"), true)
	}

	if cfg.ListenP2P == "" {
		cfg.ListenP2P = fmt.Sprintf(":%d", chainPortForNetwork(cfg.Network))
	}
	if cfg.ListenRPC == "" {
		cfg.ListenRPC = fmt.Sprintf("127.0.0.1:%d", rpcPortForNetwork(cfg.Network))
	}

	// For non-mainnet networks, create a subdirectory
	if cfg.Network != "mainnet" {
		cfg.DataDir = filepath.Join(cfg.DataDir, cfg.Network)
	}

	return cfg
}

func chainPortForNetwork(network string) uint16 {
	switch network {
	case "mainnet":
		return 8333
	case "testnet":
		return 18333
	case "testnet4":
		return 48333
	case "regtest":
		return 18444
	case "signet":
		return 38333
	default:
		return 8333
	}
}

func rpcPortForNetwork(network string) uint16 {
	switch network {
	case "mainnet":
		return 8332
	case "testnet":
		return 18332
	case "testnet4":
		return 48332
	case "regtest":
		return 18443
	case "signet":
		return 38332
	default:
		return 8332
	}
}

func networkMagic(params *consensus.ChainParams) uint32 {
	switch params.Name {
	case "mainnet":
		return p2p.MainnetMagic
	case "testnet3":
		return p2p.Testnet3Magic
	case "testnet4":
		return p2p.Testnet4Magic
	case "regtest":
		return p2p.RegtestMagic
	case "signet":
		return p2p.SignetMagic
	default:
		return p2p.MainnetMagic
	}
}

func networkToAddressNetwork(params *consensus.ChainParams) address.Network {
	switch params.Name {
	case "mainnet":
		return address.Mainnet
	case "testnet3":
		return address.Testnet
	case "testnet4":
		return address.Testnet
	case "regtest":
		return address.Regtest
	case "signet":
		return address.Testnet
	default:
		return address.Mainnet
	}
}

// chainStateAdapter implements mempool.ChainState on top of consensus.ChainManager.
// Lives in main to avoid an import cycle (mempool already depends on consensus,
// but we don't want consensus to depend on mempool).
type chainStateAdapter struct {
	cm *consensus.ChainManager
}

func newChainStateAdapter(cm *consensus.ChainManager) *chainStateAdapter {
	return &chainStateAdapter{cm: cm}
}

func (a *chainStateAdapter) TipHeight() int32 {
	_, h := a.cm.BestBlock()
	return h
}

func (a *chainStateAdapter) TipMTP() int64 {
	tip := a.cm.BestBlockNode()
	if tip == nil {
		return 0
	}
	return tip.GetMedianTimePast()
}

func (a *chainStateAdapter) MTPAtHeight(height int32) int64 {
	tip := a.cm.BestBlockNode()
	if tip == nil {
		return 0
	}
	anc := tip.GetAncestor(height)
	if anc == nil {
		return 0
	}
	return anc.GetMedianTimePast()
}

func run(cfg *Config, chainParams *consensus.ChainParams) error {
	// Startup consistency probe runs at most once per process (see
	// BUG-REPORT.md fix #3). OnSyncComplete fires on every header-sync
	// edge but the probe + DisconnectBlock loop is destructive and must
	// not be re-entered after the initial peel.
	var consistencyProbeOnce sync.Once

	// 0. Start pprof server if enabled
	if cfg.PprofAddr != "" {
		consensus.StartProfileServer(cfg.PprofAddr)
	}

	// 1. Open the database with the configured cache budget.
	utxoCacheBytes, pebbleBlockCacheBytes := computeCacheSplit(cfg.DBCache)
	dbPath := filepath.Join(cfg.DataDir, "chaindata")
	pebbleCfg := storage.DefaultPebbleDBConfig()
	pebbleCfg.BlockCacheSize = pebbleBlockCacheBytes
	db, err := storage.NewPebbleDBWithConfig(dbPath, pebbleCfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	chainDB := storage.NewChainDB(db)
	log.Printf("Database opened at %s (-dbcache=%d MiB → utxo_cache=%d MiB, pebble_block_cache=%d MiB)",
		dbPath, cfg.DBCache, utxoCacheBytes>>20, pebbleBlockCacheBytes>>20)

	// 1b. Open the flat-file block store (blk*.dat / rev*.dat) and
	// attach it to chainDB. New block bodies write here instead of
	// being inlined into the Pebble LSM. Existing "B"-prefixed blocks
	// remain readable via the GetBlock fallback (lazy migration).
	blocksDir := filepath.Join(cfg.DataDir, "blocks")
	blockStore, err := storage.NewBlockStore(blocksDir, networkMagic(chainParams), db)
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to open flat-file block store: %w", err)
	}
	chainDB.SetBlockStore(blockStore)
	log.Printf("Flat-file block store opened at %s (current file=blk%05d.dat)",
		blocksDir, blockStore.CurrentFile())

	// 1c. Initialize the auto-pruner. Disabled by default (cfg.Prune=0
	// → archive mode); enabled when the operator passes -prune=N for
	// N >= 550 MiB. The pruner does not start a background goroutine —
	// MaybePrune is invoked from the per-block OnBlockConnected hook so
	// pruning happens at most once per connected block (cheap when
	// usage is below target, since CalculateCurrentUsage is O(numFiles)).
	pruneCfg := storage.PruneConfig{}
	if cfg.Prune == 1 {
		pruneCfg.Manual = true
	} else if cfg.Prune > 1 {
		pruneCfg.TargetBytes = uint64(cfg.Prune) * 1024 * 1024
	}
	pruner := storage.NewPruner(pruneCfg, blockStore, chainDB)
	if pruner.IsEnabled() {
		if pruneCfg.Manual {
			log.Printf("Pruning enabled: manual mode (-prune=1); auto-prune off, pruneblockchain RPC required")
		} else {
			log.Printf("Pruning enabled: target=%d MiB (~%.1f GiB); MIN_BLOCKS_TO_KEEP=%d",
				cfg.Prune,
				float64(cfg.Prune)/1024.0,
				storage.MinBlocksToKeep,
			)
		}
	}

	// 2. Initialize the header index
	headerIndex := consensus.NewHeaderIndex(chainParams)
	log.Printf("Header index initialized with genesis: %s", chainParams.GenesisHash.String()[:16])

	// 3. Load persisted chain state
	chainState, err := chainDB.GetChainState()
	freshChainstate := false
	if err != nil {
		log.Printf("No existing chain state found, starting fresh")
		freshChainstate = true
		genesisHash := chainParams.GenesisBlock.Header.BlockHash()
		if err := chainDB.StoreBlock(genesisHash, chainParams.GenesisBlock); err != nil {
			log.Printf("Warning: failed to store genesis block: %v", err)
		}
		if err := chainDB.SetBlockHeight(0, genesisHash); err != nil {
			log.Printf("Warning: failed to set genesis height: %v", err)
		}
		if err := chainDB.SetChainState(&storage.ChainState{BestHash: genesisHash, BestHeight: 0}); err != nil {
			log.Printf("Warning: failed to set chain state: %v", err)
		}
	} else {
		log.Printf("Loaded chain state: height=%d hash=%s", chainState.BestHeight, chainState.BestHash.String())
		if chainState.BestHeight == 0 {
			freshChainstate = true
		}
	}

	// 3b. Rehydrate the header index from disk so a restart resumes from the
	// saved tip immediately, instead of re-downloading ~every header from peers
	// before ChainManager.loadChainState can restore the tip (the ~15-minute
	// "deferring recovery until headers are re-synced" penalty seen on every
	// restart). Must run BEFORE NewChainManager (which calls loadChainState).
	// No-op on a fresh or snapshot-only chainstate: no persisted height index
	// to walk, so it loads 0 headers and the node falls back to network sync.
	if chainState != nil && chainState.BestHeight > 0 {
		hStart := time.Now()
		loaded, herr := headerIndex.HydrateFromDB(chainDB, chainState.BestHash, chainState.BestHeight)
		if herr != nil {
			log.Printf("Header index hydration stopped early after %d headers: %v "+
				"(falling back to network header sync for the remainder)", loaded, herr)
		}
		log.Printf("Header index hydrated from disk: %d headers, tip now at height %d (%s)",
			loaded, headerIndex.BestHeight(), time.Since(hStart).Round(time.Millisecond))
	}

	// 4. Initialize UTXO set with the configured cache budget.
	utxoSet := consensus.NewUTXOSetWithMaxCache(chainDB, utxoCacheBytes)
	log.Printf("UTXO set initialized (cache_max=%d MiB)", utxoCacheBytes>>20)

	// 4b. -load-snapshot: import a Bitcoin Core-format UTXO snapshot
	// (utxo\xff magic) before the chain manager comes up.  Only acted
	// on when the chainstate is fresh — refusing in the general case
	// avoids accidentally clobbering an in-progress IBD.  Mirrors
	// Core's loadtxoutset RPC + -loadsnapshot CLI behaviour: the
	// snapshot file's blockhash MUST appear in the chain params'
	// AssumeUTXO table, and the loaded UTXO set's hash MUST match
	// the expected value before we accept it.
	if cfg.LoadSnapshot != "" {
		if !freshChainstate {
			log.Printf("WARNING: -load-snapshot=%q ignored: chainstate is not fresh (height>0). "+
				"To force a snapshot import, stop the node and remove %s.",
				cfg.LoadSnapshot, dbPath)
		} else {
			// Pass headerIndex for BUG-W102-05/06 (invalid-block + best-chain checks).
			// mempoolSize=0: mempool is always empty at startup (it's initialised
			// later at step 6); passing 0 satisfies the BUG-W102-07 guard without
			// needing a circular dependency on the mempool package here.
			if err := loadSnapshotFromFile(cfg.LoadSnapshot, chainDB, utxoSet, chainParams, headerIndex, 0); err != nil {
				return fmt.Errorf("load-snapshot %q: %w", cfg.LoadSnapshot, err)
			}
		}
	}

	// 5. Initialize chain manager
	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:          chainParams,
		HeaderIndex:     headerIndex,
		ChainDB:         chainDB,
		UTXOSet:         utxoSet,
		AssumeValidHash: chainParams.AssumeValidHash,
		ParallelScripts: cfg.ParallelScripts,
	})
	log.Printf("Chain manager initialized (parallel scripts: %v)", cfg.ParallelScripts)

	// Forward-declared so the chain → wallet connect/disconnect hooks
	// (installed below, before section 10a) can close over the multi-wallet
	// manager by reference. It is constructed later at section 10a; until then
	// the closures see nil and skip the wallet scan (no block connects before
	// the RPC server + manager are up). The legacy single-wallet `w` is also
	// declared up here for the same reason.
	//
	// feeEstimator and zmqPub are likewise forward-declared so the SINGLE
	// block-connect fan-out (the chainMgr.SetOnBlockConnected hook below) can
	// drive the full set of per-connect notifications — wallet scan, fee
	// estimator, mempool removal, ZMQ, prune — for EVERY connect path (locally
	// mined AND P2P), exactly once per block. They are assigned at their
	// original init sites further down; the hook closure reads them by
	// reference (nil-safe before assignment, but no block connects that early).
	var walletMgr *wallet.Manager
	var w *wallet.Wallet
	var feeEstimator *mempool.FeeEstimator
	var zmqPub *zmqPublisher

	// 6. Initialize mempool.
	//
	// -minrelayfee is a fee RATE in BTC/kvB; the mempool stores it as sat/kvB
	// (the unit every downstream consumer uses: the min-relay gate
	// `fee/vsize*1000`, and the dust threshold `spendingSize*MinRelayFeeRate/1000`
	// — see mempool.go:isDust / validateTransactionLocked). The conversion is
	// therefore BTC/kvB * COIN = sat/kvB. The default 0.00001 BTC/kvB maps to
	// 1000 sat/kvB, exactly Bitcoin Core's DEFAULT_MIN_RELAY_TX_FEE
	// (policy/policy.h). A stray extra `/1000` here previously produced 1
	// sat/kvB, collapsing the dust threshold to 0 (68*1/1000 == 0) so NO output
	// was ever dust — testmempoolaccept then accepted dust txns that default
	// Core rejects. Removing the `/1000` restores the genuine relay-policy floor.
	minRelayFeeRate := int64(cfg.MinRelayFee * 100_000_000) // BTC/kvB to sat/kvB
	mp := mempool.New(mempool.Config{
		MaxSize:         cfg.MaxMempool * 1_000_000,
		MinRelayFeeRate: minRelayFeeRate,
		MaxOrphanTxs:    100,
		ChainParams:     chainParams,
		ChainState:      newChainStateAdapter(chainMgr),
		// W120 BUG-5 / FIX-68: wire -mempoolfullrbf through to the mempool
		// so BIP-125 Rule 1 is conditional on the operator's switch instead
		// of unconditionally enforced. Default-true at the CLI matches Core
		// DEFAULT_MEMPOOL_FULL_RBF; Explicit=true so mempool.New does not
		// overwrite the flag with its own default.
		MempoolFullRBF:         cfg.MempoolFullRBF,
		MempoolFullRBFExplicit: true,
	}, utxoSet)
	log.Printf("Mempool initialized (max %d MB, fullrbf=%v)", cfg.MaxMempool, cfg.MempoolFullRBF)

	// 6a. Optional secondary indexes. Constructed before the chain → index
	// hooks below so the OnBlockConnected / OnBlockDisconnected fan-out can
	// reference them. Currently registers:
	//
	//   - blockfilterindex (BIP-157/158 basic) when -blockfilterindex is set.
	//
	// Mirrors Bitcoin Core's `-blockfilterindex=<basic>` flag. Default OFF
	// (`-blockfilterindex=0` in init.cpp). When OFF, the IndexManager is
	// still constructed (so RPC handlers see a non-nil but empty manager
	// and can return Core's "Index is not enabled" error string verbatim
	// instead of a generic "internal error").
	indexManager := storage.NewIndexManager(chainDB)
	var blockFilterIndex *storage.BlockFilterIndex
	if cfg.BlockFilterIndex {
		blockFilterIndex = storage.NewBlockFilterIndex(chainDB.DB())
		if err := indexManager.RegisterIndex(blockFilterIndex); err != nil {
			return fmt.Errorf("blockfilterindex: register: %w", err)
		}
		// BIP-157/158: index the genesis block (height 0) on a fresh index.
		// Core's BaseIndex indexes every connected block starting at genesis;
		// the genesis filter header chains from the all-zero parent header.
		// blockbrew's connect hook skips height 0 (unspendable coinbase), so
		// without this the genesis filter row would be missing and the
		// height-1 filter header would chain from all-zero instead of from
		// the genesis filter header — making every BIP-157 header diverge
		// from Core. WriteGenesis is a no-op once the index is past genesis.
		genesisHash := chainParams.GenesisBlock.Header.BlockHash()
		if err := blockFilterIndex.WriteGenesis(chainParams.GenesisBlock, genesisHash); err != nil {
			return fmt.Errorf("blockfilterindex: write genesis filter: %w", err)
		}
		log.Printf("BIP-157/158 blockfilterindex enabled (best_height=%d)", blockFilterIndex.BestHeight())
	}

	// 6a-bis. Secondary-index startup catch-up. Mirrors Bitcoin Core's
	// BaseIndex::Sync / Rewind (index/base.cpp): on startup each enabled index
	// must be walked forward from its persisted best block to the active chain
	// tip — and rewound if it is ahead of the tip after an unclean exit.
	// blockbrew's live OnBlockConnected fan-out only fires for blocks connected
	// AFTER startup, so an index that fell behind the chainstate (a crash
	// between the chainstate flush and the index batch commit, or an index
	// enabled on an already-synced node) was never brought current. Run this
	// AFTER the chainstate + header-index load (NewChainManager above) and
	// BEFORE the P2P sync manager starts connecting new blocks, so the index
	// is consistent with the tip before live connects resume.
	if cfg.BlockFilterIndex {
		_, tipHeight := chainMgr.BestBlock()
		if err := indexManager.CatchUp(tipHeight, chainDB.GetBlockHashByHeight); err != nil {
			// Non-fatal, matching the live index hooks' posture: log loudly
			// and continue. A half-synced index will be advanced by the live
			// connect hook as new blocks arrive; the next restart re-runs this
			// catch-up from wherever it got to.
			log.Printf("WARNING: index catch-up did not complete: %v", err)
		}
	}

	// Pattern B closure (2026-05-05) — wire chain → mempool refill on
	// disconnect. ChainManager's DisconnectBlock fires this for every block
	// popped off the active tip (including each peel inside ReorgTo). The
	// helper at internal/mempool/mempool.go::BlockDisconnected re-adds
	// non-coinbase txs from the disconnected block via AddTransaction (which
	// runs the same checks as a freshly received tx, so policy-correct
	// against the new tip — matching Core's MaybeUpdateMempoolForReorg).
	// Stacks on top of Pattern Y closure 4e51e8b which made
	// submitblock-driven reorgs flow through ReorgTo at all.
	// See CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.
	//
	// Pattern C0 closure (2026-05-05) — when -txindex is enabled, also fan
	// the disconnect into chainDB.DeleteTxIndex per tx (including coinbase)
	// so the stored tx_id → block_hash mapping is reverted when its block
	// leaves the active chain. Mirrors Bitcoin Core's
	// BaseIndex::BlockDisconnected → CustomRemove fan-out for the txindex
	// (index/txindex.cpp). Symmetric with the SetOnBlockConnected handler
	// below: every tx written on connect is deleted on disconnect.
	//
	// BIP-157 Phase 2 (2026-05-06) — when -blockfilterindex is enabled,
	// also fan the disconnect into the BlockFilterIndex's batch-aware
	// rewind helper. When the disconnect is part of a ReorgTo, we ride
	// chainMgr.CurrentReorgBatch() so the filter-row deletion + state-row
	// rewind commit atomically with the consensus state. When the
	// disconnect is a standalone single-block tip-pop (rare; primarily
	// invalidateblock RPC), we open a private batch and commit it
	// immediately. Mirrors Bitcoin Core's
	// BaseIndex::BlockDisconnected → CustomRemove fan-out — Core also
	// composes the deletion + state-row write into a single CDBBatch.
	chainMgr.SetOnBlockDisconnected(func(block *wire.MsgBlock, height int32) {
		// Wallet UTXO ledger: reverse this block's credits so a reorg cannot
		// leave the ledger over-counting coins that no longer exist on the
		// active chain. Symmetric to the ScanBlock credit on the connect hook
		// above. Best-effort (see Wallet.UnscanBlock) — the connect-side scan
		// of the replacement chain re-credits everything still owned.
		if walletMgr != nil {
			walletMgr.UnscanBlock(block, height)
		}
		if w != nil {
			w.UnscanBlock(block, height)
		}
		mp.BlockDisconnected(block)
		if cfg.TxIndex && chainDB != nil {
			for _, tx := range block.Transactions {
				txid := tx.TxHash()
				if err := chainDB.DeleteTxIndex(txid); err != nil {
					log.Printf("txindex: delete %s on disconnect height=%d failed: %v",
						txid.String()[:16], height, err)
				}
			}
		}
		if blockFilterIndex != nil {
			blockHash := block.Header.BlockHash()
			if reorgBatch := chainMgr.CurrentReorgBatch(); reorgBatch != nil {
				// Mid-reorg: queue the filter rewind into the shared
				// pebble batch. ReorgTo's batch.Write() commits it
				// atomically with the consensus rewind. The post-Write
				// in-memory state mutation is deferred to ReorgTo's
				// own deferred dispatcher via CommitRevertState below;
				// however the simplest correct approach here is to
				// also publish the in-memory mutation now — if the
				// batch-Write fails later, the chain manager's error
				// path leaves the on-disk index pointing at the
				// pre-reorg tip, and the next process restart re-Init's
				// the index from disk. This window is consistent with
				// the consensus chain: cm.tipNode is also moved
				// in-memory before batch.Write commits, and the same
				// re-Init-from-disk semantics rescue both.
				prevHeight, prevHash, prevFilterHeader, err :=
					blockFilterIndex.RevertBlockBatch(reorgBatch, block, height, blockHash, nil)
				if err != nil {
					log.Printf("blockfilterindex: revert (batched) %s @ height=%d failed: %v",
						blockHash.String()[:16], height, err)
					return
				}
				blockFilterIndex.CommitRevertState(prevHeight, prevHash, prevFilterHeader)
			} else {
				// Outside reorg: open a private batch + commit
				// immediately (RevertBlock encapsulates this).
				if err := blockFilterIndex.RevertBlock(block, height, blockHash, nil); err != nil {
					log.Printf("blockfilterindex: revert %s @ height=%d failed: %v",
						blockHash.String()[:16], height, err)
				}
			}
		}
	})

	// Pattern C0 closure (2026-05-05) — wire chain → txindex on connect.
	// ChainManager's ConnectBlock fires this for every block successfully
	// connected to the active tip (including each replay inside ReorgTo).
	// Pre-fix, chainDB.WriteTxIndex was defined at
	// internal/storage/chaindb.go:332 with zero non-test callers, so
	// `getrawtransaction(<txid>)` returned "no such tx" even for confirmed
	// transactions on the active chain. Mirrors Bitcoin Core's
	// BaseIndex::BlockConnected → CustomAppend fan-out
	// (index/base.cpp + index/txindex.cpp).
	//
	// Stacks on top of:
	//   - 4e51e8b (Pattern Y): submitblock side-branch acceptance — the
	//     ProcessSubmittedBlock path that exercises this hook.
	//   - 72c23be (Pattern B): symmetric onBlockDisconnected hook used for
	//     the matching txindex revert on disconnect (above).
	//
	// Genesis is exempt — ConnectBlock returns early for height 0 and the
	// onBlockConnected fire is skipped (genesis coinbase is unspendable).
	// All non-genesis coinbases ARE indexed to match Core (`-txindex` in
	// Core covers every confirmed tx including coinbases).
	//
	// BIP-157 Phase 1 (Phase 2 lands here too via the same hook) — when
	// -blockfilterindex is enabled, fan the connect into the
	// BlockFilterIndex's batch-aware filter writer. Inside ReorgTo this
	// rides cm.reorgBatch so the post-fork-replay filters land
	// atomically with the consensus rewrite; outside reorg it commits a
	// private batch.
	// This connect hook is ALWAYS registered (not gated on -txindex /
	// -blockfilterindex) because it now ALSO drives the wallet UTXO ledger.
	// ChainManager.ConnectBlock fires it for EVERY block connected to the
	// active tip — locally mined (generatetoaddress → miner.GenerateBlocks →
	// chainMgr.ConnectBlock) AND P2P-received (SyncManager → chainMgr.
	// ConnectBlock), and once per replayed block inside ReorgTo. This is the
	// single choke point Bitcoin Core models as the BlockConnected
	// notification fan-out (validationinterface.cpp): wallet scan + txindex +
	// blockfilterindex all hang off it.
	//
	// Wallet wiring (this commit): the wallet had a complete UTXO ledger
	// (Wallet.ScanBlock credits wallet-script outputs + debits spent inputs,
	// maturity-aware GetBalance/ListUnspent/CreateTransactionWithTip, signer,
	// AcceptToMemoryPool), but ScanBlock was only ever called from the
	// SyncManager's own post-connect callback — NEVER from the mining /
	// ConnectBlock path. So generatetoaddress credited nothing, getbalance /
	// listunspent stayed 0 / [], and sendtoaddress failed "insufficient
	// funds". Scanning here closes that gap for every connect path. Scanning
	// the multi-wallet manager covers createwallet-loaded wallets (the path
	// getWalletForRPC / getbalance / listunspent / sendtoaddress resolve);
	// scanning the legacy single wallet covers the -wallet=<file> path.
	// Mirrors Core's CWallet::blockConnected.
	chainMgr.SetOnBlockConnected(func(block *wire.MsgBlock, height int32) {
		blockHash := block.Header.BlockHash()

		// Wallet UTXO ledger — scan BEFORE the index writes so a failing
		// index write cannot skip the wallet credit (the wallet scan is a
		// pure in-memory map mutation and cannot fail). Idempotent: re-adding
		// the same outpoint overwrites with identical data and deleting an
		// already-spent input is a no-op, so a double-scan (defensive) is
		// harmless.
		if walletMgr != nil {
			walletMgr.ScanBlock(block, height)
		}
		if w != nil {
			w.ScanBlock(block, height)
		}

		// Per-connect notification fan-out, moved here from the SyncManager's
		// own onBlockConnected callback so it fires on EVERY connect path —
		// crucially the locally mined (generatetoaddress) path, which never
		// reaches the SyncManager. This is what clears confirmed txs from the
		// mempool after a locally mined block (the pre-fix bug: a wallet-native
		// sendtoaddress tx stayed in getrawmempool forever once mined locally,
		// because mp.BlockConnected was only on the P2P path). Placed BEFORE the
		// index writes because the blockfilterindex arm can early-return.
		//
		// FIX-47 BUG-10 ordering preserved: FeeEstimator.ProcessBlock records
		// confirmed txids BEFORE mp.BlockConnected removes them, so the
		// OnTxEvicted → UnregisterTransaction callback is a safe no-op for
		// confirmed txs.
		if feeEstimator != nil {
			confirmedTxids := make([]wire.Hash256, 0, len(block.Transactions))
			for _, tx := range block.Transactions {
				confirmedTxids = append(confirmedTxids, tx.TxHash())
			}
			feeEstimator.ProcessBlock(height, confirmedTxids)
		}
		mp.BlockConnected(block)
		if zmqPub != nil {
			zmqPub.PublishBlockConnected(block, height)
		}
		if pruner.IsEnabled() {
			if _, err := pruner.MaybePrune(height); err != nil {
				log.Printf("prune: %v", err)
			}
		}

		if cfg.TxIndex && chainDB != nil {
			for _, tx := range block.Transactions {
				txid := tx.TxHash()
				if err := chainDB.WriteTxIndex(txid, blockHash); err != nil {
					log.Printf("txindex: write %s @ height=%d failed: %v",
						txid.String()[:16], height, err)
				}
			}
		}
		if blockFilterIndex != nil {
			if reorgBatch := chainMgr.CurrentReorgBatch(); reorgBatch != nil {
				if err := blockFilterIndex.WriteBlockBatch(reorgBatch, block, height, blockHash, nil); err != nil {
					log.Printf("blockfilterindex: write (batched) %s @ height=%d failed: %v",
						blockHash.String()[:16], height, err)
					return
				}
				blockFilterIndex.CommitWriteState(height, blockHash)
			} else {
				if err := blockFilterIndex.WriteBlock(block, height, blockHash, nil); err != nil {
					log.Printf("blockfilterindex: write %s @ height=%d failed: %v",
						blockHash.String()[:16], height, err)
				}
			}
		}
	})

	// 6b. Initialize fee estimator
	feeEstimator = mempool.NewFeeEstimator()
	if err := feeEstimator.Load(cfg.DataDir); err != nil {
		log.Printf("Warning: could not load fee estimates: %v", err)
	} else if feeEstimator.BestHeight() > 0 {
		log.Printf("Loaded fee estimates from disk (height %d)", feeEstimator.BestHeight())
	}
	// FIX-47 BUG-22: wire FeeEstimator.UnregisterTransaction into the mempool
	// eviction callback so txs removed for non-block reasons (RBF, size
	// eviction, expiry) are correctly removed from the estimator's tracking.
	// The callback fires from removeSingleTxLocked after the pool delete, so
	// it is safe to call UnregisterTransaction here (no re-entrancy risk).
	//
	// FIX-73 (W120 BUG-9): callback now carries a MemPoolRemovalReason.
	// The fee estimator does not yet differentiate reasons (Core's
	// CBlockPolicyEstimator::removeTx ignores the reason flag too — it just
	// drops the entry from bucketMap regardless), so we pass through here.
	// Future wallet wiring + ZMQ pubrawtx "R" prefix will read the reason.
	mp.OnTxEvicted = func(txHash wire.Hash256, _ mempool.MemPoolRemovalReason) {
		feeEstimator.UnregisterTransaction(txHash)
	}

	// 6c. Reload persisted mempool. Match Bitcoin Core's
	//     DEFAULT_MEMPOOL_EXPIRY = 336 hours (2 weeks).
	if res, err := mp.Load(cfg.DataDir, mempool.LoadOptions{MaxAge: 14 * 24 * time.Hour}); err != nil {
		log.Printf("Warning: mempool.dat reload failed: %v", err)
	} else if res != nil {
		log.Printf("Reloaded mempool.dat: %d read, %d accepted, %d failed, %d expired",
			res.Read, res.Accepted, res.Failed, res.Expired)
	}

	// 6d. ZMQ publisher (optional, off by default).  Mirrors Bitcoin
	// Core's `-zmqpub<topic>` flags.  Failures here are downgraded to
	// warnings: a misconfigured ZMQ socket must not stop the node from
	// validating consensus.
	zmqPub = newZMQPublisher(zmqPublisherConfig{
		HashBlock: cfg.ZMQPubHashBlock,
		HashTx:    cfg.ZMQPubHashTx,
		RawBlock:  cfg.ZMQPubRawBlock,
		RawTx:     cfg.ZMQPubRawTx,
		Sequence:  cfg.ZMQPubSequence,
	})
	if err := zmqPub.Start(); err != nil {
		log.Printf("WARNING: zmq publisher start failed: %v (continuing without ZMQ)", err)
		zmqPub.Stop()
		zmqPub = newZMQPublisher(zmqPublisherConfig{}) // disabled instance
	}

	// 7. Initialize peer manager
	listenAddr := cfg.ListenP2P
	if cfg.NoListen {
		listenAddr = ""
	}

	peerMgr := p2p.NewPeerManager(p2p.PeerManagerConfig{
		Network:     networkMagic(chainParams),
		ChainParams: chainParams,
		MaxOutbound: cfg.MaxOutbound,
		MaxInbound:  cfg.MaxInbound,
		ListenAddr:  listenAddr,
		UserAgent:   fmt.Sprintf("/blockbrew:%s/", version),
		BestHeightFunc: func() int32 {
			_, h := chainMgr.BestBlock()
			return h
		},
		PreferV2:                    cfg.BIP324V2,
		AdvertiseNodeBloom:          cfg.PeerBloomFilters,
		AdvertiseNodeNetworkLimited: cfg.Prune > 0,
		AdvertiseCompactFilters:     cfg.BlockFilterIndex,
	})

	// 8. Initialize wallet early so sync callbacks can reference it
	// (`w` is forward-declared near the chain manager init above so the
	// chain → wallet block-connect hook can close over it).

	// 9. Initialize sync manager (we use a pointer indirection to handle the circular reference)
	var syncMgr *p2p.SyncManager

	// Create the sync manager with callbacks that reference it via the variable.
	//
	// The per-connect notification fan-out (wallet scan + FeeEstimator.Process
	// + mp.BlockConnected + ZMQ + prune) USED to live here, but that meant it
	// only fired for P2P-downloaded blocks — locally mined blocks
	// (generatetoaddress → miner.GenerateBlocks → chainMgr.ConnectBlock) never
	// reach this SyncManager callback. The entire fan-out has been moved into
	// the single chainMgr.SetOnBlockConnected hook above, which fires for
	// EVERY connect path exactly once per block (Core's BlockConnected
	// notification model). The SyncManager invokes chainMgr.ConnectBlock for
	// each downloaded block, so that hook covers the P2P path too — leaving
	// this callback empty avoids double-firing (e.g. a double mp.chainHeight++
	// or double-credited wallet txHistory).
	onBlockConnected := func(block *wire.MsgBlock, height int32) {
		_ = block
		_ = height
	}
	syncMgr = p2p.NewSyncManager(p2p.SyncManagerConfig{
		ChainParams:  chainParams,
		HeaderIndex:  headerIndex,
		ChainDB:      chainDB,
		PeerManager:  nil, // Will be set below after peerMgr is created
		ChainManager: chainMgr,
		Pruner:       pruner,
		OnSyncComplete: func() {
			log.Printf("Header synchronization complete, starting block download")
			// Re-resolve the chain tip now that headers are available.
			// On startup the header index only has genesis, so the chain
			// manager's tip defaults to genesis even when the DB has a
			// higher tip. This call restores the correct tip so that
			// StartBlockDownload resumes from where we left off.
			chainMgr.ReloadChainState()

			// Startup chainstate consistency probe (BUG-REPORT.md fix #3).
			// MUST run at most once per process: OnSyncComplete fires on
			// every header-sync edge (peer reconnect, late-arriving
			// header batches), and DisconnectBlock deletes undo data on
			// every peel — so a re-probe after rollback would re-detect
			// the freshly-deleted undo as "corruption" and peel the
			// chain back unboundedly. The sync.Once gate prevents that.
			consistencyProbeOnce.Do(func() {
				res := chainMgr.VerifyChainstateConsistency(200)
				if res.RolledBackBlocks > 0 {
					log.Printf("[CHAINSTATE-RECOVERY] auto-rolled back %d blocks (tip %d -> %d) after consistency probe; "+
						"will re-fetch + re-apply on the next IBD pass",
						res.RolledBackBlocks, res.TipBefore, res.TipAfter)
				}
				if res.RollbackFailed {
					log.Printf("[CHAINSTATE-CORRUPTION] startup consistency probe detected unrecoverable state at "+
						"height %d. Operator action required: stop the node and remove %s/chaindata/ "+
						"to force a full re-sync. (-reindex is honest-deferred; see main.go:258.)",
						res.CorruptionAtHeight, cfg.DataDir)
				}
			})

			syncMgr.StartBlockDownload()
		},
		OnBlockConnected: onBlockConnected,
	})

	// Wire up sync manager listeners to peer manager
	syncListeners := syncMgr.CreatePeerListeners()

	// Wire mempool tx relay: accept incoming transactions via AcceptToMemoryPool
	// and relay them to peers on success.
	syncListeners.OnTx = func(peer *p2p.Peer, msg *p2p.MsgTx) {
		if err := mp.AcceptToMemoryPool(msg.Tx); err != nil {
			log.Printf("[mempool] Rejected tx from %s: %v", peer.Address(), err)
			return
		}
		txHash := msg.Tx.TxHash()
		wtxHash := msg.Tx.WTxHash()
		entry := mp.GetEntry(txHash)
		if entry != nil {
			peerMgr.RelayTransaction(txHash, wtxHash, entry.Fee, entry.Size, peer.Address())
			// FIX-47 BUG-21: wire FeeEstimator.RegisterTransaction so the tx
			// is tracked for fee estimation.  entry.FeeRate is in sat/vB
			// (same unit as FeeEstimator).  entry.Height is the chain height
			// at which the tx entered the mempool.
			feeEstimator.RegisterTransaction(txHash, entry.FeeRate, entry.Height)
		}
		// ZMQ fan-out: hashtx / rawtx / sequence(A). Cheap no-op
		// when no -zmqpub* endpoint is configured.
		zmqPub.PublishTxAccepted(msg.Tx)
		log.Printf("[mempool] Accepted tx %s from %s (fee: %d, size: %d)",
			txHash, peer.Address(), entry.Fee, entry.Size)
	}

	// BIP35 "mempool" handler: peer requests our mempool contents → respond
	// with one or more inv messages enumerating mempool txids.  Mirrors
	// Bitcoin Core's net_processing.cpp NetMsgType::MEMPOOL handler:
	//
	//     if (!(peer.m_our_services & NODE_BLOOM) &&
	//         !pfrom.HasPermission(NetPermissionFlags::Mempool))
	//         return;
	//
	// Gate: BIP-35 is gated on whether *we* advertise NODE_BLOOM (BIP-111),
	// not on the peer's fRelay bit (which is BIP-37 and controls only
	// whether we relay txs to that peer absent a bloom filter).  Core's
	// MEMPOOL handler does not check fRelay before sending the inv —
	// queueing a `m_send_mempool` flag that the next inv flush honors —
	// so we don't either.  blockbrew has no per-peer permission system
	// (no equivalent of Core's NetPermissionFlags::Mempool), so the only
	// gate is the local NODE_BLOOM advertisement controlled by
	// `-peerbloomfilters` (default true).  When the flag is off we
	// silently drop the request rather than disconnecting; Core
	// disconnects, but blockbrew's permissive eviction policy applies
	// elsewhere too.
	bloomEnabled := cfg.PeerBloomFilters
	syncListeners.OnMempool = func(peer *p2p.Peer, _ *p2p.MsgMempool) {
		if !bloomEnabled {
			return
		}
		invs := p2p.HandleMempoolRequest(peer, mp)
		for _, inv := range invs {
			peer.SendMessage(inv)
		}
	}

	// BIP-331 package-relay handlers.
	//
	// OnSendPackages: peer.go already records the bitfield on the Peer struct
	// (see Peer.PackageVersions). Nothing extra to do here.
	//
	// OnGetPkgTxns: peer wants the full transactions for a list of wtxids.
	// Look each up in the mempool and reply with a single pkgtxns. Missing
	// entries are silently skipped — the peer will treat the gap as a
	// partial response (BIP-331 §"pkgtxns").
	syncListeners.OnGetPkgTxns = func(peer *p2p.Peer, msg *p2p.MsgGetPkgTxns) {
		reply := &p2p.MsgPkgTxns{}
		for _, w := range msg.WTxIDs {
			if tx := mp.GetTxByWTxid(w); tx != nil {
				reply.Txs = append(reply.Txs, tx)
			}
		}
		// Even an empty reply is meaningful (peer learns we have none of them).
		peer.SendMessage(reply)
	}

	// OnPkgTxns: peer pushed a package. Feed it through AcceptPackage and let
	// the existing relay logic take over for any tx that was newly accepted.
	syncListeners.OnPkgTxns = func(peer *p2p.Peer, msg *p2p.MsgPkgTxns) {
		if len(msg.Txs) == 0 {
			return
		}
		result, err := mp.AcceptPackage(msg.Txs)
		if err != nil {
			log.Printf("[mempool] Rejected pkgtxns from %s: %v", peer.Address(), err)
			return
		}
		// Relay each tx that was newly accepted (skip already-in / failed).
		if result == nil {
			return
		}
		for _, txr := range result.TxResults {
			if !txr.Accepted || txr.AlreadyInMempool {
				continue
			}
			peerMgr.RelayTransaction(txr.TxID, txr.WTxID, txr.Fee, txr.VSize, peer.Address())
		}
	}

	// BIP-157 P2P handlers: getcfilters / getcfheaders / getcfcheckpt.
	//
	// These are only wired when -blockfilterindex is enabled. The handlers
	// mirror Bitcoin Core's net_processing.cpp:PrepareBlockFilterRequest +
	// ProcessGetCFilters / ProcessGetCFHeaders / ProcessGetCFCheckPt.
	//
	// Range limits: MAX_GETCFILTERS_SIZE=1000, MAX_GETCFHEADERS_SIZE=2000,
	// CFCHECKPT_INTERVAL=1000 (net_processing.cpp:176-180).
	//
	// FIX-74 (W121 BUG-6 + BUG-7 + BUG-8): the pre-fix handlers looked up
	// filters by raw height via blockFilterIndex.GetFilter(h), which returns
	// active-chain filters regardless of which fork the peer's stop_hash is
	// on. A peer providing an orphan/stale stop_hash got a signed-but-lying
	// response (DoS vector + privacy leak about the peer's fork interest).
	// The new helpers in internal/p2p/cfilter_handlers.go resolve stop_hash
	// → stop_index, walk stop_index.GetAncestor(h) for each requested height,
	// and verify the stored filter's BlockHash matches the ancestor's hash
	// before serving. Matches Core's PrepareBlockFilterRequest +
	// LookupFilterRange / LookupFilterHeader / GETCFCHECKPT loop.
	if blockFilterIndex != nil {
		// getcfilters: peer requests raw GCS-encoded filters for a height range.
		// Wire format: filter_type(1) || start_height(4 LE) || stop_hash(32).
		// Core: net_processing.cpp ProcessGetCFilters.
		syncListeners.OnGetCFilters = func(peer *p2p.Peer, msg *p2p.MsgGetCFilters) {
			p2p.HandleGetCFilters(peer, msg, headerIndex, blockFilterIndex)
		}

		// getcfheaders: peer requests filter headers for a height range.
		// Wire format: filter_type(1) || start_height(4 LE) || stop_hash(32).
		// Response: cfheaders containing prev_filter_header + list of filter hashes.
		// Core: net_processing.cpp ProcessGetCFHeaders.
		syncListeners.OnGetCFHeaders = func(peer *p2p.Peer, msg *p2p.MsgGetCFHeaders) {
			p2p.HandleGetCFHeaders(peer, msg, headerIndex, blockFilterIndex)
		}

		// getcfcheckpt: peer requests evenly-spaced filter header checkpoints.
		// One checkpoint per CFCHECKPT_INTERVAL (1000) blocks up to stop_hash.
		// Core: net_processing.cpp ProcessGetCFCheckPt.
		syncListeners.OnGetCFCheckpt = func(peer *p2p.Peer, msg *p2p.MsgGetCFCheckpt) {
			p2p.HandleGetCFCheckpt(peer, msg, headerIndex, blockFilterIndex)
		}
	}

	peerMgr = p2p.NewPeerManager(p2p.PeerManagerConfig{
		Network:     networkMagic(chainParams),
		ChainParams: chainParams,
		MaxOutbound: cfg.MaxOutbound,
		MaxInbound:  cfg.MaxInbound,
		ListenAddr:  listenAddr,
		UserAgent:   fmt.Sprintf("/blockbrew:%s/", version),
		BestHeightFunc: func() int32 {
			_, h := chainMgr.BestBlock()
			return h
		},
		Listeners: syncListeners,
		OnPeerConnected: func(p *p2p.Peer) {
			syncMgr.HandlePeerConnected(p)
		},
		OnPeerDisconnected: func(p *p2p.Peer) {
			syncMgr.HandlePeerDisconnected(p)
		},
		PreferV2:                    cfg.BIP324V2,
		AdvertiseNodeBloom:          cfg.PeerBloomFilters,
		AdvertiseNodeNetworkLimited: cfg.Prune > 0,
		// BIP-157: advertise NODE_COMPACT_FILTERS when blockfilterindex is
		// active. Mirrors Core's init.cpp g_local_services |= NODE_COMPACT_FILTERS.
		AdvertiseCompactFilters: cfg.BlockFilterIndex,
		ASMapFile:               cfg.ASMap,
		// -connect=<ip:port> peer-pinning (Core parity). When non-empty the
		// peer manager dials ONLY these peers and skips DNS-seed resolution
		// + the auto-outbound maintenance loop. -nodnsseed (or an implied
		// dnsseed=0 from -connect) suppresses DNS-seed resolution.
		ConnectPeers: cfg.Connect,
		NoDNSSeed:    cfg.NoDNSSeed,
	})

	// Wire the peer manager back into the sync manager (breaks circular dependency)
	syncMgr.SetPeerManager(peerMgr)

	// 9. Initialize mining template generator
	templateGen := mining.NewTemplateGenerator(chainParams, chainMgr, mp, headerIndex)

	// 10. Initialize wallet (optional)
	walletPath := filepath.Join(cfg.DataDir, cfg.WalletFile)
	walletCfg := wallet.WalletConfig{
		DataDir:     cfg.DataDir,
		Network:     networkToAddressNetwork(chainParams),
		ChainParams: chainParams,
	}
	if _, err := os.Stat(walletPath); err == nil {
		// Load existing wallet.
		//
		// NOTE: LoadFromFile takes the DATA DIR (it joins "wallet.dat" itself).
		// The previous code passed walletPath (<datadir>/wallet.dat), which made
		// LoadFromFile look for <datadir>/wallet.dat/wallet.dat — a path that
		// never exists — so EVERY restart silently "failed to load" and fell
		// through to an empty wallet, discarding all prior wallet state. That is
		// itself a restart-persistence data-loss bug; pass cfg.DataDir so the
		// on-disk wallet actually loads. LoadFromFile is now fault-tolerant: a
		// corrupt/partial primary file transparently recovers from wallet.dat.bak
		// and never aborts startup.
		loaded, loadErr := wallet.LoadFromFile(cfg.DataDir, "", walletCfg)
		if loadErr != nil {
			log.Printf("Warning: failed to load wallet from %s: %v (starting with empty wallet)", walletPath, loadErr)
			w = wallet.NewWallet(walletCfg)
		} else {
			w = loaded
			log.Printf("Wallet loaded from %s (last synced height %d)", walletPath, w.LastSyncedHeight())
		}
	} else {
		w = wallet.NewWallet(walletCfg)
		log.Printf("No wallet file found, starting with empty wallet")
	}

	// Wallet reconcile + durable-flush wiring (DATA-LOSS fix, sweep wa0fq5wtk).
	//
	// (a) RECONCILE on startup: bring the wallet UTXO ledger up to the chain
	//     tip by scanning the gap [last_synced_height+1, tip]. After an unclean
	//     restart the persisted ledger may trail the chainstate (the last few
	//     auto-flushed blocks, or — for a wallet that lost its in-memory state
	//     to a SIGKILL — a larger gap). Rescanning the gap re-credits/-debits
	//     any blocks the wallet missed so getbalance/listunspent match the chain
	//     before the live connect loop takes over. Mirrors Bitcoin Core's
	//     CWallet startup ScanForWalletTransactions from m_last_block_processed.
	// (b) AUTO-FLUSH: a background goroutine durably persists the wallet a few
	//     seconds after any mutation (getnewaddress / setlabel / send / per-block
	//     ScanBlock credit), so a SIGKILL/OOM/power-loss can no longer wipe every
	//     mutation since the last clean shutdown. StopAutoFlush (in the shutdown
	//     path below) does a final synchronous flush.
	if w != nil {
		_, tipHeight := chainMgr.BestBlock()
		startH := w.LastSyncedHeight() + 1
		if startH < 1 {
			startH = 1
		}
		if tipHeight >= startH {
			getBlock := func(height int32) (*wire.MsgBlock, bool) {
				hash, herr := chainDB.GetBlockHashByHeight(height)
				if herr != nil {
					return nil, false
				}
				blk, berr := chainDB.GetBlock(hash)
				if berr != nil || blk == nil {
					return nil, false
				}
				return blk, true
			}
			log.Printf("wallet reconcile: scanning gap [%d, %d] to chain tip", startH, tipHeight)
			scannedTo, rerr := w.Rescan(startH, tipHeight, getBlock)
			if rerr != nil {
				// ErrNoMasterKey simply means there's nothing to scan for (empty
				// wallet) — not fatal. Any other error is logged; the live
				// connect loop will still keep the wallet current going forward.
				log.Printf("wallet reconcile: %v (scanned to %d)", rerr, scannedTo)
			} else if scannedTo >= startH {
				log.Printf("wallet reconcile: ledger brought up to height %d", scannedTo)
			}
			if scannedTo > w.LastSyncedHeight() {
				w.SetLastSyncedHeight(scannedTo)
			} else {
				// Even an empty/master-less wallet should record that it has
				// observed the chain up to the tip so the next restart's gap
				// stays bounded.
				w.SetLastSyncedHeight(tipHeight)
			}
		}
		w.StartAutoFlush(wallet.DefaultAutoFlushInterval)
		log.Printf("wallet auto-flush started (interval %s)", wallet.DefaultAutoFlushInterval)
	}

	// 10a. Initialize the multi-wallet manager.
	//
	// Without this the RPC server's s.walletMgr stays nil and every
	// wallet-management RPC (createwallet / loadwallet / getnewaddress /
	// ...) short-circuits with -32603 "Wallet manager not available"
	// (createwallet) or falls through to the empty legacy wallet and
	// fails with "wallet is locked" (getnewaddress). The manager stores
	// wallets under <datadir>/wallets/<name>/ (Core's multi-wallet
	// layout) and is the path getWalletForRPC prefers when non-nil.
	walletMgr = wallet.NewManager(cfg.DataDir, networkToAddressNetwork(chainParams), chainParams)

	// 11. Initialize RPC server
	// Generate a cookie file so local tools can authenticate without an
	// explicit password (mirrors Bitcoin Core's .cookie mechanism).
	cookiePassword, err := rpc.GenerateCookie(cfg.DataDir)
	if err != nil {
		log.Printf("WARNING: could not write RPC cookie file: %v", err)
		cookiePassword = ""
	} else {
		log.Printf("RPC cookie written to %s/.cookie", cfg.DataDir)
	}

	rpcServer := rpc.NewServer(
		rpc.RPCConfig{
			ListenAddr: cfg.ListenRPC,
			Username:   cfg.RPCUser,
			Password:   cfg.RPCPassword,
			// Pattern C0 closure (2026-05-05): plumb -txindex through to the
			// RPC server so getrawtransaction's txindex lookup branch is
			// reachable. Pre-fix this field defaulted to false and the
			// handler short-circuited with "Use -txindex" even when the
			// flag was passed on the command line. See chainMgr.SetOnBlockConnected
			// wiring above (the storage-side counterpart).
			TxIndex: cfg.TxIndex,
			// REST surface (`/rest/...`). Off by default (Core parity).
			// See `internal/rpc/rest.go` for the handler set; the audit
			// at `_rest-api-cross-impl-audit-2026-05-06-part1.md` flagged
			// the missing CLI plumbing as RED-2 (P1 dead code).
			RESTEnabled: cfg.Rest,
			// Optional HTTPS termination (W119 / FIX-64). Both empty =
			// legacy plain HTTP. Both set = HTTPS via crypto/tls. Setting
			// exactly one of the two is rejected in Server.Start.
			TLSCertFile: cfg.RPCTLSCert,
			TLSKeyFile:  cfg.RPCTLSKey,
		},
		rpc.WithCookiePassword(cookiePassword),
		rpc.WithChainParams(chainParams),
		rpc.WithChainManager(chainMgr),
		rpc.WithHeaderIndex(headerIndex),
		rpc.WithChainDB(chainDB),
		rpc.WithMempool(mp),
		rpc.WithFeeEstimator(feeEstimator),
		rpc.WithPeerManager(peerMgr),
		rpc.WithSyncManager(syncMgr),
		rpc.WithTemplateGenerator(templateGen),
		rpc.WithWallet(w),
		rpc.WithWalletManager(walletMgr),
		rpc.WithPruner(pruner),
		rpc.WithDataDir(cfg.DataDir),
		// IndexManager carries optional secondary indexes (BIP-157
		// blockfilterindex when -blockfilterindex=1, etc.). Always
		// passed; RPC handlers gate on whether the requested index is
		// registered. See section 6a above.
		rpc.WithIndexManager(indexManager),
	)

	// 12. Start all services
	log.Printf("Starting services...")

	if err := peerMgr.Start(); err != nil {
		return fmt.Errorf("peer manager start failed: %w", err)
	}
	if !cfg.NoListen {
		log.Printf("P2P network listening on %s", cfg.ListenP2P)
	} else {
		log.Printf("P2P network started (no inbound connections)")
	}

	syncMgr.Start()
	log.Printf("Sync manager started")

	// Periodic orphan expiry driver (W103 BUG-22 fix).
	//
	// Bitcoin Core calls LimitOrphans inside every AddTx / AddAnnouncer, so
	// orphans older than ORPHAN_TX_EXPIRE_TIME (20 min) are evicted as a
	// side-effect of the next incoming tx.  blockbrew's mempool has
	// ExpireOrphans() but it was never called from production code until this
	// fix.  We approximate Core's continuous sweep with a once-per-minute
	// timer — cheap enough to be negligible and tight enough that orphans are
	// evicted well within the 20-minute window.
	//
	// Interval: p2p.OrphanExpireDriverInterval (1 min).
	// Constant: mempool.OrphanTxExpireTime (20 min) — see mempool/mempool.go.
	orphanExpireQuit := make(chan struct{})
	go func() {
		orphanExpireTicker := time.NewTicker(p2p.OrphanExpireDriverInterval)
		defer orphanExpireTicker.Stop()
		for {
			select {
			case <-orphanExpireTicker.C:
				mp.ExpireOrphans()
			case <-orphanExpireQuit:
				return
			}
		}
	}()

	if err := rpcServer.Start(); err != nil {
		return fmt.Errorf("RPC server start failed: %w", err)
	}
	log.Printf("RPC server listening on %s", cfg.ListenRPC)

	// Start Prometheus metrics server
	if cfg.MetricsPort > 0 {
		metricsAddr := fmt.Sprintf("0.0.0.0:%d", cfg.MetricsPort)
		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			_, height := chainMgr.BestBlock()
			outbound, inbound := peerMgr.PeerCount()
			peers := outbound + inbound
			mempoolSize := mp.Count()

			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			fmt.Fprintf(w, "# HELP bitcoin_blocks_total Current block height\n")
			fmt.Fprintf(w, "# TYPE bitcoin_blocks_total gauge\n")
			fmt.Fprintf(w, "bitcoin_blocks_total %d\n", height)
			fmt.Fprintf(w, "# HELP bitcoin_peers_connected Number of connected peers\n")
			fmt.Fprintf(w, "# TYPE bitcoin_peers_connected gauge\n")
			fmt.Fprintf(w, "bitcoin_peers_connected %d\n", peers)
			fmt.Fprintf(w, "# HELP bitcoin_mempool_size Mempool transaction count\n")
			fmt.Fprintf(w, "# TYPE bitcoin_mempool_size gauge\n")
			fmt.Fprintf(w, "bitcoin_mempool_size %d\n", mempoolSize)
		})
		go func() {
			log.Printf("Prometheus metrics server listening on %s", metricsAddr)
			if err := http.ListenAndServe(metricsAddr, metricsMux); err != nil {
				log.Printf("Metrics server error: %v", err)
			}
		}()
	}

	// Health endpoint (k8s-style liveness/readiness probes). Bound on
	// 127.0.0.1 to avoid exposing internal state externally without an
	// auth layer. Disabled when -healthport=0.
	if cfg.HealthPort > 0 {
		healthAddr := fmt.Sprintf("127.0.0.1:%d", cfg.HealthPort)
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			// Liveness: if we can answer, we're alive. Readiness is gated
			// on chain initialization being far enough along to answer
			// RPCs — equivalent to Core's `getblockchaininfo` returning.
			_, height := chainMgr.BestBlock()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "ok height=%d\n", height)
		})
		healthMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			outbound, inbound := peerMgr.PeerCount()
			if outbound+inbound == 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintln(w, "not ready: no peers connected yet")
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "ready")
		})
		go func() {
			log.Printf("Health endpoint listening on %s (/healthz, /readyz)", healthAddr)
			if err := http.ListenAndServe(healthAddr, healthMux); err != nil {
				log.Printf("Health server error: %v", err)
			}
		}()
	}

	// systemd notify-ready (Type=notify integration). Cheap no-op when
	// NOTIFY_SOCKET is unset (i.e. not run under systemd).  We send
	// READY=1 *after* the RPC server is bound so external tooling
	// (start_mainnet.sh, deployment health checks) can rely on the
	// notification meaning "RPC will accept calls now".
	if cfg.RPCReadyNotify {
		notifyReady(fmt.Sprintf("blockbrew v%s ready, RPC on %s", version, cfg.ListenRPC))
	}

	// systemd watchdog: ping at half the configured interval. Disabled
	// when WATCHDOG_USEC is unset.
	if interval := watchdogInterval(); interval > 0 {
		log.Printf("systemd watchdog: pinging every %s", interval)
		ticker := time.NewTicker(interval)
		go func() {
			for range ticker.C {
				notifyWatchdog()
			}
		}()
	}

	log.Printf("blockbrew v%s started successfully", version)

	// 13. Wait for shutdown signal. Catches both SIGINT (Ctrl-C) and SIGTERM
	// (systemd, kill, rolling restarts). Previously only the first signal was
	// handled and the shutdown sequence ran on the main goroutine with no hard
	// deadline, so any blocked goroutine (P2P listener accept loop, DB
	// compaction, UTXO flush) would hang indefinitely and force an external
	// SIGKILL to escalate.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	if sig == syscall.SIGTERM {
		log.Printf("received SIGTERM, beginning graceful shutdown")
	} else {
		log.Printf("received SIGINT, beginning graceful shutdown")
	}

	// systemd: report STOPPING=1 so TimeoutStopSec doesn't tick down
	// against a node mid-flush.
	notifyStopping()

	// 14. Hard 30-second deadline watchdog. If graceful shutdown has not
	// completed by then we best-effort close the DB and os.Exit(1). This
	// guarantees the process never hangs longer than 30s after a signal,
	// matching Bitcoin Core's init.cpp shutdown semantics (StartShutdown +
	// bounded thread join).
	shutdownDone := make(chan struct{})
	const shutdownDeadline = 30 * time.Second
	watchdog := time.AfterFunc(shutdownDeadline, func() {
		log.Printf("shutdown deadline (%s) exceeded, forcing exit", shutdownDeadline)
		// Best-effort DB close so we don't leave the LSM in a corrupt state.
		// We ignore errors — we're about to die anyway.
		_ = db.Close()
		log.Printf("exit (forced)")
		os.Exit(1)
	})

	// Second signal escalates immediately.
	go func() {
		s, ok := <-sigChan
		if !ok {
			return
		}
		log.Printf("received second signal %s, forcing exit", s)
		_ = db.Close()
		os.Exit(1)
	}()

	// Cancel contexts and stop long-running goroutines in reverse startup
	// order, each phase logged so operators can see where shutdown is stuck
	// if it ever does exceed the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
	defer cancel()
	_ = ctx

	go func() {
		defer close(shutdownDone)

		// Stop background goroutines first.
		close(orphanExpireQuit)

		// Stop RPC first so no new client requests start mid-shutdown.
		if err := rpcServer.Stop(); err != nil {
			log.Printf("Warning: RPC server stop error: %v", err)
		}
		log.Printf("RPC server stopped")
		rpc.DeleteCookie(cfg.DataDir)

		// Stop P2P: sync manager (block/header download loop) then peer
		// manager (listener + all peer goroutines).
		log.Printf("stopping P2P")
		syncMgr.Stop()
		log.Printf("Sync manager stopped")
		peerMgr.Stop()
		log.Printf("Peer manager stopped")

		// Save auxiliary state.
		if err := feeEstimator.Save(cfg.DataDir); err != nil {
			log.Printf("Warning: fee estimates save failed: %v", err)
		} else {
			log.Printf("Fee estimates saved")
		}
		if err := mp.Dump(cfg.DataDir); err != nil {
			log.Printf("Warning: mempool.dat dump failed: %v", err)
		} else {
			log.Printf("mempool.dat saved (%d txs)", mp.Count())
		}
		if w != nil {
			// Stop the auto-flusher (does a final synchronous flush of any
			// pending mutations) then force one more durable save so the clean
			// shutdown is guaranteed persisted even if nothing was dirty.
			w.StopAutoFlush()
			if err := w.SaveToFile(""); err != nil {
				log.Printf("Warning: wallet save failed: %v", err)
			} else {
				log.Printf("Wallet saved")
			}
		}

		// Flush chainstate atomically: UTXO set + chain-tip pointer in a
		// single Pebble batch with Sync. Pre-2026-05-02 these were two
		// separate writes (utxoSet.Flush() then chainDB.SetChainState()),
		// which left a SIGKILL-during-shutdown window where the persisted
		// UTXO cache could land *ahead* of the persisted chain tip — the
		// exact corruption pattern observed in the May 1 blockbrew
		// h=938360 wedge (and lunarblock's Apr 28 h=938344 wedge).  After
		// this fix there is no on-disk state where UTXOs reflect height
		// N+M but chain_tip still says height N.
		bestHash, bestHeight := chainMgr.BestBlock()
		log.Printf("flushing chainstate atomically at height %d", bestHeight)
		shutBatch := chainDB.NewBatch()
		if err := utxoSet.FlushBatch(shutBatch); err != nil {
			log.Printf("Warning: UTXO flush-batch failed: %v", err)
		}
		if bestHeight > 0 {
			chainDB.SetChainStateBatch(shutBatch, &storage.ChainState{
				BestHash:   bestHash,
				BestHeight: bestHeight,
			})
		}
		if err := shutBatch.Write(); err != nil {
			log.Printf("Warning: atomic chainstate-flush batch failed: %v", err)
		} else {
			log.Printf("Chainstate flushed atomically (UTXO + tip) at height %d", bestHeight)
		}

		// Flush + close the flat-file block store BEFORE the Pebble DB.
		// BlockStore.Close persists its state (current file num/pos and
		// per-file BlockFileInfo) into the same Pebble DB, so the DB
		// must still be open at this point.
		if err := blockStore.Close(); err != nil {
			log.Printf("Warning: block store close failed: %v", err)
		} else {
			log.Printf("Block store flushed")
		}

		log.Printf("closing DB")
		if err := db.Close(); err != nil {
			log.Printf("Warning: database close failed: %v", err)
		}
		log.Printf("Database closed")

		// Stop ZMQ publisher (drains pending sends, closes sockets).
		zmqPub.Stop()
		log.Printf("ZMQ publisher stopped")

		// Remove pid file last so external monitors can still observe
		// the file during the shutdown window.
		if processPidFile != nil {
			if err := processPidFile.Remove(); err != nil {
				log.Printf("Warning: pid file remove failed: %v", err)
			}
		}
		// Close log file last so any post-shutdown log lines still land.
		if processLogFile != nil {
			_ = processLogFile.Close()
		}
	}()

	<-shutdownDone
	if !watchdog.Stop() {
		// AfterFunc already fired concurrently; it will os.Exit(1) for us.
		// Park the main goroutine so we don't race it.
		select {}
	}
	log.Printf("blockbrew shutdown complete")
	log.Printf("exit")
	os.Exit(0)
	return nil
}

// handleSubcommands handles CLI subcommands. Returns true if a subcommand was handled.
func handleSubcommands(args []string) bool {
	if len(args) == 0 {
		return false
	}

	switch args[0] {
	case "version":
		fmt.Printf("blockbrew v%s\n", version)
		return true
	case "wallet":
		handleWalletCommand(args[1:])
		return true
	case "import-blocks":
		handleImportBlocks(args[1:])
		return true
	case "help":
		printHelp()
		return true
	}
	return false
}

func handleWalletCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: blockbrew wallet <create|import|info>")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  create    Generate a new wallet with a random mnemonic")
		fmt.Println("  import    Import an existing wallet from a mnemonic")
		fmt.Println("  info      Display wallet information (requires running node)")
		return
	}

	switch args[0] {
	case "create":
		mnemonic, err := wallet.GenerateMnemonic()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating mnemonic: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("New wallet mnemonic (WRITE THIS DOWN AND KEEP SECURE):")
		fmt.Println()
		fmt.Println(mnemonic)
		fmt.Println()
		fmt.Println("WARNING: If you lose this mnemonic, you lose access to your funds!")
		fmt.Println("Store this in a safe place and never share it with anyone.")

	case "import":
		fmt.Print("Enter mnemonic: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		mnemonic := strings.TrimSpace(scanner.Text())

		if !wallet.ValidateMnemonic(mnemonic) {
			fmt.Fprintln(os.Stderr, "Invalid mnemonic. Please check your words and try again.")
			os.Exit(1)
		}
		fmt.Println("Mnemonic validated successfully!")
		fmt.Println("Wallet will be created on next node start with --wallet flag.")

	case "info":
		fmt.Println("Wallet info requires a running node.")
		fmt.Println("Use RPC: curl --user blockbrew:password --data-binary '{\"method\":\"getwalletinfo\"}' http://127.0.0.1:<rpcport>/")

	default:
		fmt.Fprintf(os.Stderr, "Unknown wallet command: %s\n", args[0])
		fmt.Println("Usage: blockbrew wallet <create|import|info>")
		os.Exit(1)
	}
}

// handleImportBlocks reads framed blocks from stdin and connects them.
// Frame format: [4 bytes height LE] [4 bytes size LE] [size bytes raw block]
func handleImportBlocks(args []string) {
	log.SetPrefix("[blockbrew] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Parse flags for import-blocks subcommand
	fs := flag.NewFlagSet("import-blocks", flag.ExitOnError)
	homeDir, _ := os.UserHomeDir()
	defaultDataDir := filepath.Join(homeDir, defaultDir)

	dataDir := fs.String("datadir", defaultDataDir, "Data directory")
	network := fs.String("network", "mainnet", "Network (mainnet, testnet, regtest, signet, testnet4)")
	parallelScripts := fs.Bool("parallelscripts", true, "Enable parallel script validation")
	fs.Parse(args)

	var chainParams *consensus.ChainParams
	switch *network {
	case "mainnet":
		chainParams = consensus.MainnetParams()
	case "testnet":
		chainParams = consensus.TestnetParams()
	case "regtest":
		chainParams = consensus.RegtestParams()
	case "signet":
		chainParams = consensus.SignetParams()
	case "testnet4":
		chainParams = consensus.Testnet4Params()
	default:
		log.Fatalf("Unknown network: %s", *network)
	}

	// For non-mainnet networks, create a subdirectory
	actualDataDir := *dataDir
	if *network != "mainnet" {
		actualDataDir = filepath.Join(*dataDir, *network)
	}

	if err := os.MkdirAll(actualDataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	log.Printf("import-blocks: network=%s datadir=%s", *network, actualDataDir)

	// Open database
	dbPath := filepath.Join(actualDataDir, "chaindata")
	db, err := storage.NewPebbleDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	chainDB := storage.NewChainDB(db)

	// Open flat-file block store and attach (new blocks land in blk*.dat).
	blocksDir := filepath.Join(actualDataDir, "blocks")
	blockStore, err := storage.NewBlockStore(blocksDir, networkMagic(chainParams), db)
	if err != nil {
		log.Fatalf("Failed to open flat-file block store: %v", err)
	}
	defer blockStore.Close()
	chainDB.SetBlockStore(blockStore)

	// Initialize header index
	headerIndex := consensus.NewHeaderIndex(chainParams)

	// Load persisted chain state
	chainState, err := chainDB.GetChainState()
	if err != nil {
		log.Printf("No existing chain state found, starting fresh")
		genesisHash := chainParams.GenesisBlock.Header.BlockHash()
		if err := chainDB.StoreBlock(genesisHash, chainParams.GenesisBlock); err != nil {
			log.Printf("Warning: failed to store genesis block: %v", err)
		}
		if err := chainDB.SetBlockHeight(0, genesisHash); err != nil {
			log.Printf("Warning: failed to set genesis height: %v", err)
		}
		if err := chainDB.SetChainState(&storage.ChainState{BestHash: genesisHash, BestHeight: 0}); err != nil {
			log.Printf("Warning: failed to set chain state: %v", err)
		}
	} else {
		log.Printf("Loaded chain state: height=%d hash=%s", chainState.BestHeight, chainState.BestHash.String())
	}

	// Initialize UTXO set and chain manager
	utxoSet := consensus.NewUTXOSet(chainDB)
	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:          chainParams,
		HeaderIndex:     headerIndex,
		ChainDB:         chainDB,
		UTXOSet:         utxoSet,
		AssumeValidHash: chainParams.AssumeValidHash,
		ParallelScripts: *parallelScripts,
	})

	_, tipHeight := chainMgr.BestBlock()
	log.Printf("Chain tip at height %d, starting import from stdin", tipHeight)

	// Read framed blocks from stdin
	reader := bufio.NewReaderSize(os.Stdin, 4*1024*1024) // 4MB buffer
	frameBuf := make([]byte, 8)
	imported := 0
	skipped := 0
	startTime := time.Now()
	lastLogTime := startTime

	for {
		// Read frame header: [4 bytes height LE] [4 bytes size LE]
		_, err := io.ReadFull(reader, frameBuf)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Error reading frame header: %v", err)
		}

		frameHeight := int32(binary.LittleEndian.Uint32(frameBuf[0:4]))
		frameSize := binary.LittleEndian.Uint32(frameBuf[4:8])

		if frameSize == 0 || frameSize > 4*1024*1024 { // 4MB max block
			log.Fatalf("Invalid frame size %d at height %d", frameSize, frameHeight)
		}

		// Read block data
		blockData := make([]byte, frameSize)
		_, err = io.ReadFull(reader, blockData)
		if err != nil {
			log.Fatalf("Error reading block data at height %d: %v", frameHeight, err)
		}

		// Skip blocks we already have
		if frameHeight <= tipHeight {
			skipped++
			continue
		}

		// Deserialize the block
		var block wire.MsgBlock
		blockReader := bytes.NewReader(blockData)
		if err := block.Deserialize(blockReader); err != nil {
			log.Fatalf("Error deserializing block at height %d: %v", frameHeight, err)
		}

		// Add header to header index (required by ConnectBlock).
		// minPowChecked=true: this is the import/replay path loading blocks
		// from a trusted flat-file; the chain's work has already been validated.
		_, err = headerIndex.AddHeader(block.Header, true)
		if err != nil && err != consensus.ErrDuplicateHeader {
			log.Fatalf("Error adding header at height %d: %v", frameHeight, err)
		}

		// Connect the block
		if err := chainMgr.ConnectBlock(&block); err != nil {
			log.Fatalf("Error connecting block at height %d: %v", frameHeight, err)
		}

		imported++

		// Log progress periodically
		now := time.Now()
		if now.Sub(lastLogTime) >= 10*time.Second || imported%10000 == 0 {
			elapsed := now.Sub(startTime).Seconds()
			rate := float64(imported) / elapsed
			log.Printf("import-blocks: height=%d imported=%d skipped=%d rate=%.1f blk/s",
				frameHeight, imported, skipped, rate)
			lastLogTime = now
		}
	}

	// Final flush
	if err := utxoSet.Flush(); err != nil {
		log.Printf("Warning: UTXO flush failed: %v", err)
	}

	elapsed := time.Since(startTime).Seconds()
	rate := float64(imported) / elapsed
	log.Printf("import-blocks complete: imported=%d skipped=%d elapsed=%.1fs rate=%.1f blk/s",
		imported, skipped, elapsed, rate)
}

// loadSnapshotFromFile imports a Bitcoin Core-format UTXO snapshot
// (`utxo\xff` magic, VARINT-coded coins) into the active chainstate
// database.  Mirrors Bitcoin Core's ActivateSnapshot + loadtxoutset RPC
// + -loadsnapshot CLI behaviour.
//
// Guard order (mirrors Core validation.cpp:5588–5883):
//  1. Open file, parse metadata header.
//  2. Verify AssumeUTXO params exist (network supports snapshot loading).
//  3. BUG-W102-07: mempool must be empty before activation.
//  4. AssumeUTXO table lookup by snapshot BlockHash (BUG-W102-15: must occur
//     BEFORE any coin is deserialised, to avoid UTXOSet pollution on error).
//  5. BUG-W102-14: cross-check file metadata height against table entry height.
//  6. BUG-W102-05: base block must not be marked BLOCK_FAILED_VALID.
//  7. BUG-W102-06: base block must be on the best header chain.
//  8. Deserialise coins with per-coin guards (BUG-W102-01..03) + EOF check (04).
//  9. Recompute HASH_SERIALIZED and compare against table entry.
// 10. Flush, promote chainstate.
//
// Reference: bitcoin-core/src/validation.cpp ActivateSnapshot:5588,
// PopulateAndValidateSnapshot:5754.
func loadSnapshotFromFile(
	path string,
	chainDB *storage.ChainDB,
	utxoSet *consensus.UTXOSet,
	params *consensus.ChainParams,
	headerIndex *consensus.HeaderIndex,
	mempoolSize int,
) error {
	log.Printf("[snapshot] loading Core-format UTXO snapshot from %s", path)

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 8*1024*1024)

	// --- Step 1: parse metadata header (network magic, block hash, coin count).
	sr, err := consensus.NewSnapshotReader(reader)
	if err != nil {
		return fmt.Errorf("snapshot header: %w", err)
	}
	meta := sr.Metadata()

	// Verify network magic.
	if meta.NetworkMagic != params.NetworkMagic {
		return consensus.ErrNetworkMismatch
	}

	// --- Step 2: verify network supports AssumeUTXO.
	if params.AssumeUTXO == nil {
		return fmt.Errorf("network %q has no AssumeUTXO params; snapshot loading not supported", params.Name)
	}

	// --- Step 3 (BUG-W102-07): mempool must be empty before activation.
	// Core ActivateSnapshot:5627-5630 — "Can't activate a snapshot when mempool not empty".
	if mempoolSize > 0 {
		return fmt.Errorf("%w: %d transactions pending", consensus.ErrMempoolNotEmpty, mempoolSize)
	}

	// --- Step 4 (BUG-W102-15): AssumeUTXO table lookup BEFORE coin deserialisation.
	// Core ActivateSnapshot:5600-5608 — looks up the table entry first; only
	// calls PopulateAndValidateSnapshot after a successful lookup. Without this
	// guard the UTXOSet gets polluted with up to 165M untrusted coins before the
	// lookup fails with ErrUnknownSnapshotHeight.
	expected := params.AssumeUTXO.ForBlockHash(meta.BlockHash)
	if expected == nil {
		return fmt.Errorf("snapshot block hash %s not recognised in AssumeUTXO params",
			meta.BlockHash.String())
	}

	// --- Step 5 (BUG-W102-14): cross-check file metadata height vs table entry.
	// The metadata header does not contain a height field — height comes from the
	// table entry located via ForBlockHash.  If the snapshot was created at a
	// different height than the one in our table (or the file was spliced), we
	// catch it here before spending time on coin I/O.
	// (SnapshotMetadata contains BlockHash but not a standalone height; the table
	// entry height IS the authoritative source. The cross-check confirms
	// ForBlockHash and ForHeight agree on the same entry.)
	if byHeight := params.AssumeUTXO.ForHeight(expected.Height); byHeight == nil ||
		byHeight.BlockHash != expected.BlockHash {
		return fmt.Errorf("%w: table entry at height %d has unexpected block hash",
			consensus.ErrSnapshotHeightMismatch, expected.Height)
	}

	// --- Step 6 (BUG-W102-05): base block must not be BLOCK_FAILED_VALID.
	// Core ActivateSnapshot:5618-5621 — rejects snapshots whose base block was
	// explicitly invalidated (nStatus & BLOCK_FAILED_VALID).
	if headerIndex != nil {
		baseNode := headerIndex.GetNode(meta.BlockHash)
		if baseNode != nil && baseNode.Status.IsInvalid() {
			return fmt.Errorf("%w: %s", consensus.ErrSnapshotBaseBlockInvalid,
				meta.BlockHash.String())
		}

		// --- Step 7 (BUG-W102-06): base block must be on the best header chain.
		// Core ActivateSnapshot:5622-5625 — m_best_header->GetAncestor(height) == base block.
		bestTip := headerIndex.BestTip()
		if bestTip != nil {
			ancestor := bestTip.GetAncestor(expected.Height)
			if ancestor != nil && ancestor.Hash != meta.BlockHash {
				return fmt.Errorf("%w: best-header ancestor at height %d is %s, snapshot base is %s",
					consensus.ErrSnapshotBaseBlockNotOnBestChain,
					expected.Height, ancestor.Hash.String(), meta.BlockHash.String())
			}
		}
	}

	// --- Step 8: deserialise coins with per-coin guards + EOF check.
	// BUG-W102-01..04 are enforced inside LoadSnapshotCoins.
	loaded, stats, err := consensus.LoadSnapshotCoins(sr, chainDB, expected.Height)
	if err != nil {
		return fmt.Errorf("LoadSnapshotCoins: %w", err)
	}

	// --- Step 9: recompute HASH_SERIALIZED and compare against table entry.
	//
	// Use ComputeHashSerialized (HashWriter::GetHash = SHA256d over
	// uncompressed TxOutSer records, validation.cpp:5912-5914) — same
	// flavour Bitcoin Core's `loadtxoutset` RPC validates against, and
	// the same flavour produced by `dumptxoutset`'s txoutset_hash field
	// + tools/compute-snapshot-hash.py + every other hashhog impl
	// (lunarblock src/utxo.lua, hotbuns src/consensus/utxoHash.ts, etc).
	computed, _, err := consensus.ComputeHashSerialized(loaded)
	if err != nil {
		return fmt.Errorf("ComputeHashSerialized: %w", err)
	}
	if computed != expected.HashSerialized {
		return fmt.Errorf("snapshot UTXO hash mismatch: expected %s, got %s",
			expected.HashSerialized.String(), computed.String())
	}

	// --- Step 10: flush and promote chainstate.
	//
	// LoadSnapshotCoins deliberately defers the flush so that the
	// post-flush cache eviction (utxoset.go:299) doesn't run before
	// ComputeHashSerialized has had a chance to walk the in-memory
	// cache.  Calling Flush here accepts the eviction that follows;
	// we no longer need the cache populated since the coins are now
	// durable in chainDB and the active utxoSet (which shares the
	// same chainDB) will read them on demand.
	if err := loaded.Flush(); err != nil {
		return fmt.Errorf("flush snapshot UTXOs: %w", err)
	}

	// Promote the snapshot to the active chainstate by recording the
	// base block as the chain tip + height mapping.  Subsequent IBD
	// will continue from this point.
	if err := chainDB.SetChainState(&storage.ChainState{
		BestHash:   stats.BlockHash,
		BestHeight: expected.Height,
	}); err != nil {
		return fmt.Errorf("SetChainState: %w", err)
	}
	if err := chainDB.SetBlockHeight(expected.Height, stats.BlockHash); err != nil {
		return fmt.Errorf("SetBlockHeight: %w", err)
	}

	// Replace the in-memory utxoSet caller's contents by re-reading
	// from the database.  We don't have a direct "swap" API; instead,
	// the snapshot's UTXOSet (`loaded`) now shares the same backing
	// chainDB as the active utxoSet, so subsequent GetUTXO calls on
	// utxoSet will hit the newly-persisted coins via the database.
	_ = utxoSet // placeholder: shared chainDB, no extra wiring needed

	log.Printf("[snapshot] loaded %d coins; tip=%s height=%d hash_serialized=%s",
		stats.CoinsLoaded, stats.BlockHash.String(), expected.Height, computed.String())
	return nil
}

func printHelp() {
	fmt.Printf("blockbrew v%s - A Bitcoin full node in Go\n\n", version)
	fmt.Println("Usage: blockbrew [options] [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version          Print version and exit")
	fmt.Println("  wallet           Wallet management commands")
	fmt.Println("  import-blocks    Import blocks from stdin (framed format)")
	fmt.Println("  help             Print this help message")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --datadir       Data directory (default: ~/.blockbrew)")
	fmt.Println("  --network       Network: mainnet, testnet, regtest, signet (default: mainnet)")
	fmt.Println("  --listen        P2P listen address (default: based on network)")
	fmt.Println("  --rpcbind       RPC listen address (default: based on network)")
	fmt.Println("  --rpcuser       RPC username (default: blockbrew)")
	fmt.Println("  --rpcpassword   RPC password")
	fmt.Println("  --maxoutbound   Maximum outbound connections (default: 8)")
	fmt.Println("  --maxinbound    Maximum inbound connections (default: 117)")
	fmt.Println("  --nolisten      Disable inbound P2P connections")
	fmt.Println("  --mineraddress  Address for mining rewards")
	fmt.Println("  --wallet        Wallet file name (default: wallet.dat)")
	fmt.Println("  --loglevel      Log level: debug, info, warn, error (default: info)")
	fmt.Println("  --txindex       Enable transaction index")
	fmt.Println("  --maxmempool    Maximum mempool size in MB (default: 300)")
	fmt.Println("  --minrelayfee   Minimum relay fee in BTC/kvB (default: 0.00001)")
	fmt.Println("  --version       Print version and exit")
	fmt.Println("  --pprof         pprof HTTP server address (e.g., localhost:6060)")
	fmt.Println("  --parallelscripts  Enable parallel script validation (default: true)")
	fmt.Println("  --bip324v2      Enable BIP-324 v2 encrypted transport (default: true)")
	fmt.Println("                  Pass -bip324v2=false to opt out. Also via env:")
	fmt.Println("                  BLOCKBREW_BIP324_V2=0 (off) or =1 (on; default)")
	fmt.Println("  --prune=N       Auto-prune target in MiB (default: 0 = archive)")
	fmt.Println("                  N must be 0 or >= 550 (Bitcoin Core MIN_DISK_SPACE)")
	fmt.Println("                  Headers, UTXO set, and last 288 blocks never pruned")
	fmt.Println()
	fmt.Println("Operational flags (Bitcoin Core compat):")
	fmt.Println("  --daemon            Detach into background after init")
	fmt.Println("  --pid=<file>        PID file path (default: <datadir>/blockbrew.pid)")
	fmt.Println("  --conf=<file>       Read additional options from a key=value config file")
	fmt.Println("                      Default search: <datadir>/blockbrew.conf,")
	fmt.Println("                      ~/.blockbrew/blockbrew.conf. CLI > conf > defaults.")
	fmt.Println("  --debug=<cat>       Enable debug logging (repeatable / comma-separated)")
	fmt.Println("                      Categories: net, mempool, validation, rpc, ...")
	fmt.Println("                      `all` enables every category; `none` clears.")
	fmt.Println("  --printtoconsole    Tee log file to stderr even when -logfile is set")
	fmt.Println("  --logfile=<path>    Write logs to file (SIGHUP reopens for log rotation)")
	fmt.Println("  --reindex           NOT YET IMPLEMENTED (refuses to start; tracking)")
	fmt.Println("  --zmqpubhashblock   ZMQ PUB endpoint for 32-byte block hashes")
	fmt.Println("  --zmqpubhashtx      ZMQ PUB endpoint for 32-byte tx hashes")
	fmt.Println("  --zmqpubrawblock    ZMQ PUB endpoint for serialised blocks")
	fmt.Println("  --zmqpubrawtx       ZMQ PUB endpoint for serialised txs")
	fmt.Println("  --zmqpubsequence    ZMQ PUB endpoint for sequence notifications")
	fmt.Println("  --rpcready-notify   systemd READY=1 once RPC is bound (default: true)")
	fmt.Println("  --healthport=N      Bind /healthz on 127.0.0.1:N (k8s probes; 0 disables)")
	fmt.Println("  --load-snapshot=<path>  Bitcoin Core-format UTXO snapshot to load at boot")
	fmt.Println("                          (utxo\\xff magic). Mirrors Core's -loadsnapshot.")
	fmt.Println("                          Only acted on when chainstate is fresh (height==0).")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  blockbrew                                           Start node on mainnet")
	fmt.Println("  blockbrew --network regtest                         Start node on regtest")
	fmt.Println("  blockbrew wallet create                             Generate new wallet")
	fmt.Println("  blockbrew import-blocks --network mainnet < blocks  Import blocks from stdin")
	fmt.Println("  blockbrew --load-snapshot=utxo.dat                  Load Core-format UTXO snapshot at boot")
	fmt.Println("  blockbrew --version                                 Print version")
}
