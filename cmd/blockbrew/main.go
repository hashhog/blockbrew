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

	// Performance profiling
	PprofAddr       string
	ParallelScripts bool

	// Prometheus metrics
	MetricsPort int
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

	log.SetPrefix("[blockbrew] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("blockbrew v%s starting...", version)
	log.Printf("Network: %s", cfg.Network)
	log.Printf("Data directory: %s", cfg.DataDir)

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
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
	flag.Int64Var(&cfg.MaxMempool, "maxmempool", 300, "Maximum mempool size in MB")
	flag.Float64Var(&cfg.MinRelayFee, "minrelayfee", 0.00001, "Minimum relay fee (BTC/kvB)")
	flag.BoolVar(&cfg.PrintVersion, "version", false, "Print version and exit")
	flag.StringVar(&cfg.PprofAddr, "pprof", "", "pprof HTTP server address (e.g., localhost:6060)")
	flag.BoolVar(&cfg.ParallelScripts, "parallelscripts", true, "Enable parallel script validation")
	flag.IntVar(&cfg.MetricsPort, "metricsport", 9332, "Prometheus metrics port (0 to disable)")
	flag.Parse()

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

func run(cfg *Config, chainParams *consensus.ChainParams) error {
	// 0. Start pprof server if enabled
	if cfg.PprofAddr != "" {
		consensus.StartProfileServer(cfg.PprofAddr)
	}

	// 1. Open the database
	dbPath := filepath.Join(cfg.DataDir, "chaindata")
	db, err := storage.NewPebbleDB(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	chainDB := storage.NewChainDB(db)
	log.Printf("Database opened at %s", dbPath)

	// 2. Initialize the header index
	headerIndex := consensus.NewHeaderIndex(chainParams)
	log.Printf("Header index initialized with genesis: %s", chainParams.GenesisHash.String()[:16])

	// 3. Load persisted chain state
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
		log.Printf("Loaded chain state: height=%d hash=%s", chainState.BestHeight, chainState.BestHash.String()[:16])
	}

	// 4. Initialize UTXO set
	utxoSet := consensus.NewUTXOSet(chainDB)
	log.Printf("UTXO set initialized")

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

	// 6. Initialize mempool
	minRelayFeeRate := int64(cfg.MinRelayFee * 100_000_000 / 1000) // BTC/kvB to sat/kvB
	mp := mempool.New(mempool.Config{
		MaxSize:         cfg.MaxMempool * 1_000_000,
		MinRelayFeeRate: minRelayFeeRate,
		MaxOrphanTxs:    100,
		ChainParams:     chainParams,
	}, utxoSet)
	log.Printf("Mempool initialized (max %d MB)", cfg.MaxMempool)

	// 6b. Initialize fee estimator
	feeEstimator := mempool.NewFeeEstimator()
	if err := feeEstimator.Load(cfg.DataDir); err != nil {
		log.Printf("Warning: could not load fee estimates: %v", err)
	} else if feeEstimator.BestHeight() > 0 {
		log.Printf("Loaded fee estimates from disk (height %d)", feeEstimator.BestHeight())
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
	})

	// 8. Initialize wallet early so sync callbacks can reference it
	var w *wallet.Wallet

	// 9. Initialize sync manager (we use a pointer indirection to handle the circular reference)
	var syncMgr *p2p.SyncManager

	// Create the sync manager with callbacks that reference it via the variable
	onBlockConnected := func(block *wire.MsgBlock, height int32) {
		if w != nil {
			w.ScanBlock(block, height)
		}
		mp.BlockConnected(block)
	}
	syncMgr = p2p.NewSyncManager(p2p.SyncManagerConfig{
		ChainParams:  chainParams,
		HeaderIndex:  headerIndex,
		ChainDB:      chainDB,
		PeerManager:  nil, // Will be set below after peerMgr is created
		ChainManager: chainMgr,
		OnSyncComplete: func() {
			log.Printf("Header synchronization complete, starting block download")
			// Re-resolve the chain tip now that headers are available.
			// On startup the header index only has genesis, so the chain
			// manager's tip defaults to genesis even when the DB has a
			// higher tip. This call restores the correct tip so that
			// StartBlockDownload resumes from where we left off.
			chainMgr.ReloadChainState()
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
		entry := mp.GetEntry(txHash)
		if entry != nil {
			peerMgr.RelayTransaction(txHash, entry.Fee, entry.Size, peer.Address())
		}
		log.Printf("[mempool] Accepted tx %s from %s (fee: %d, size: %d)",
			txHash, peer.Address(), entry.Fee, entry.Size)
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
		// Load existing wallet
		loaded, loadErr := wallet.LoadFromFile(walletPath, "", walletCfg)
		if loadErr != nil {
			log.Printf("Warning: failed to load wallet from %s: %v (starting with empty wallet)", walletPath, loadErr)
			w = wallet.NewWallet(walletCfg)
		} else {
			w = loaded
			log.Printf("Wallet loaded from %s", walletPath)
		}
	} else {
		w = wallet.NewWallet(walletCfg)
		log.Printf("No wallet file found, starting with empty wallet")
	}

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

	log.Printf("blockbrew v%s started successfully", version)

	// 13. Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal %s, shutting down...", sig)

	// 14. Graceful shutdown in reverse order
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := rpcServer.Stop(); err != nil {
		log.Printf("Warning: RPC server stop error: %v", err)
	}
	log.Printf("RPC server stopped")
	rpc.DeleteCookie(cfg.DataDir)

	syncMgr.Stop()
	log.Printf("Sync manager stopped")

	peerMgr.Stop()
	log.Printf("Peer manager stopped")

	// Save fee estimates
	if err := feeEstimator.Save(cfg.DataDir); err != nil {
		log.Printf("Warning: fee estimates save failed: %v", err)
	} else {
		log.Printf("Fee estimates saved")
	}

	// Save wallet state
	if w != nil {
		if err := w.SaveToFile(""); err != nil {
			log.Printf("Warning: wallet save failed: %v", err)
		} else {
			log.Printf("Wallet saved")
		}
	}

	if err := utxoSet.Flush(); err != nil {
		log.Printf("Warning: UTXO flush failed: %v", err)
	}
	log.Printf("UTXO set flushed")

	// Persist chain state AFTER UTXO flush for crash consistency
	bestHash, bestHeight := chainMgr.BestBlock()
	if bestHeight > 0 {
		if err := chainDB.SetChainState(&storage.ChainState{
			BestHash:   bestHash,
			BestHeight: bestHeight,
		}); err != nil {
			log.Printf("Warning: chain state save failed: %v", err)
		} else {
			log.Printf("Chain state saved at height %d", bestHeight)
		}
	}

	if err := db.Close(); err != nil {
		log.Printf("Warning: database close failed: %v", err)
	}
	log.Printf("Database closed")

	_ = ctx
	log.Printf("blockbrew shutdown complete")
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
	case "import-utxo":
		handleImportUTXO(args[1:])
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
		log.Printf("Loaded chain state: height=%d hash=%s", chainState.BestHeight, chainState.BestHash.String()[:16])
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

		// Add header to header index (required by ConnectBlock)
		_, err = headerIndex.AddHeader(block.Header)
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

// handleImportUTXO loads a UTXO snapshot from an HDOG file into the chainstate database.
// HDOG format:
//
//	Header (52 bytes): Magic "HDOG" (4) + Version uint32 LE (4) + BlockHash (32 LE) + Height uint32 LE (4) + UTXOCount uint64 LE (8)
//	Per UTXO: TxID (32 LE) + Vout uint32 LE (4) + Amount int64 LE (8) + HeightCB uint32 LE (4) + ScriptLen uint16 LE (2) + Script (N)
func handleImportUTXO(args []string) {
	log.SetPrefix("[blockbrew] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	fs := flag.NewFlagSet("import-utxo", flag.ExitOnError)
	homeDir, _ := os.UserHomeDir()
	defaultDataDir := filepath.Join(homeDir, defaultDir)

	dataDir := fs.String("datadir", defaultDataDir, "Data directory")
	network := fs.String("network", "mainnet", "Network (mainnet, testnet, regtest, signet, testnet4)")
	filePath := fs.String("file", "", "Path to HDOG snapshot file (required)")
	batchSize := fs.Int("batchsize", 100000, "Number of UTXOs per write batch")
	fs.Parse(args)

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: -file is required")
		fmt.Fprintln(os.Stderr, "Usage: blockbrew import-utxo -file <path> [-datadir <dir>] [-network <net>]")
		os.Exit(1)
	}

	// Resolve data directory
	actualDataDir := *dataDir
	if *network != "mainnet" {
		actualDataDir = filepath.Join(*dataDir, *network)
	}
	if err := os.MkdirAll(actualDataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	log.Printf("import-utxo: network=%s datadir=%s file=%s", *network, actualDataDir, *filePath)

	// Open snapshot file
	f, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("Failed to open snapshot file: %v", err)
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 8*1024*1024) // 8MB read buffer

	// --- Parse HDOG header (52 bytes) ---
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		log.Fatalf("Failed to read magic: %v", err)
	}
	if string(magic[:]) != "HDOG" {
		log.Fatalf("Invalid magic: %q (expected \"HDOG\")", magic)
	}

	var hdrVersion uint32
	if err := binary.Read(reader, binary.LittleEndian, &hdrVersion); err != nil {
		log.Fatalf("Failed to read version: %v", err)
	}
	if hdrVersion != 1 {
		log.Fatalf("Unsupported HDOG version: %d (expected 1)", hdrVersion)
	}

	var blockHash wire.Hash256
	if _, err := io.ReadFull(reader, blockHash[:]); err != nil {
		log.Fatalf("Failed to read block hash: %v", err)
	}

	var blockHeight uint32
	if err := binary.Read(reader, binary.LittleEndian, &blockHeight); err != nil {
		log.Fatalf("Failed to read block height: %v", err)
	}

	var utxoCount uint64
	if err := binary.Read(reader, binary.LittleEndian, &utxoCount); err != nil {
		log.Fatalf("Failed to read UTXO count: %v", err)
	}

	log.Printf("HDOG header: version=%d height=%d utxos=%d block=%s",
		hdrVersion, blockHeight, utxoCount, blockHash.String())

	// --- Open database (delete and recreate for clean import) ---
	dbPath := filepath.Join(actualDataDir, "chaindata")
	if _, statErr := os.Stat(dbPath); statErr == nil {
		log.Printf("Removing existing chaindata directory for clean import...")
		if err := os.RemoveAll(dbPath); err != nil {
			log.Fatalf("Failed to remove existing chaindata: %v", err)
		}
		log.Printf("Existing chaindata removed")
	}
	db, err := storage.NewPebbleDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// --- Stream UTXOs into database ---
	batch := db.NewBatch()
	startTime := time.Now()
	lastLogTime := startTime

	// Pre-allocate read buffer for fixed-size UTXO fields:
	// TxID(32) + Vout(4) + Amount(8) + HeightCB(4) + ScriptLen(2) = 50 bytes
	fixedBuf := make([]byte, 50)

	for i := uint64(0); i < utxoCount; i++ {
		// Read fixed-size fields in one call
		if _, err := io.ReadFull(reader, fixedBuf); err != nil {
			log.Fatalf("Failed to read UTXO %d: %v", i, err)
		}

		// Parse fields from buffer (all little-endian)
		// txid: fixedBuf[0:32]
		vout := binary.LittleEndian.Uint32(fixedBuf[32:36])
		amount := int64(binary.LittleEndian.Uint64(fixedBuf[36:44]))
		heightCB := binary.LittleEndian.Uint32(fixedBuf[44:48])
		scriptLen := binary.LittleEndian.Uint16(fixedBuf[48:50])

		// Read Script
		script := make([]byte, scriptLen)
		if scriptLen > 0 {
			if _, err := io.ReadFull(reader, script); err != nil {
				log.Fatalf("Failed to read script at UTXO %d: %v", i, err)
			}
		}

		// Construct DB key: "U" + txid (32 bytes) + vout (4 bytes BE)
		keyCopy := make([]byte, 1+32+4)
		keyCopy[0] = 'U'
		copy(keyCopy[1:33], fixedBuf[0:32])
		binary.BigEndian.PutUint32(keyCopy[33:], vout)

		// Construct DB value using the same serialization as consensus.SerializeUTXOEntry:
		//   varint(height << 1 | coinbase) + varint(amount) + varint(compressed_script_len) + compressed_script
		height := int32(heightCB >> 1)
		isCoinbase := (heightCB & 1) == 1

		entry := &consensus.UTXOEntry{
			Amount:     amount,
			PkScript:   script,
			Height:     height,
			IsCoinbase: isCoinbase,
		}
		value := consensus.SerializeUTXOEntry(entry)

		batch.Put(keyCopy, value)

		// Flush batch every batchSize entries
		if (i+1)%uint64(*batchSize) == 0 {
			if err := batch.Write(); err != nil {
				log.Fatalf("Batch write failed at UTXO %d: %v", i, err)
			}
			batch.Reset()
		}

		// Log progress every 1M UTXOs
		if (i+1)%1_000_000 == 0 {
			now := time.Now()
			elapsed := now.Sub(startTime).Seconds()
			rate := float64(i+1) / elapsed
			pct := float64(i+1) * 100 / float64(utxoCount)
			sinceLog := now.Sub(lastLogTime).Seconds()
			log.Printf("import-utxo: %d / %d (%.2f%%) %.0f utxo/s [%.1fs since last log, %.1fs total]",
				i+1, utxoCount, pct, rate, sinceLog, elapsed)
			lastLogTime = now
		}
	}

	// Flush remaining batch
	if batch.Len() > 0 {
		if err := batch.Write(); err != nil {
			log.Fatalf("Final batch write failed: %v", err)
		}
	}

	// --- Set chain state ---
	chainDB := storage.NewChainDB(db)
	chainState := &storage.ChainState{
		BestHash:   blockHash,
		BestHeight: int32(blockHeight),
	}
	if err := chainDB.SetChainState(chainState); err != nil {
		log.Fatalf("Failed to set chain state: %v", err)
	}

	// Also set the height -> hash mapping for the snapshot block
	if err := chainDB.SetBlockHeight(int32(blockHeight), blockHash); err != nil {
		log.Fatalf("Failed to set block height mapping: %v", err)
	}

	elapsed := time.Since(startTime).Seconds()
	rate := float64(utxoCount) / elapsed
	log.Printf("import-utxo complete: %d UTXOs imported in %.1fs (%.0f utxo/s)", utxoCount, elapsed, rate)
	log.Printf("Chain tip set to height=%d hash=%s", blockHeight, blockHash.String())
}

func printHelp() {
	fmt.Printf("blockbrew v%s - A Bitcoin full node in Go\n\n", version)
	fmt.Println("Usage: blockbrew [options] [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version          Print version and exit")
	fmt.Println("  wallet           Wallet management commands")
	fmt.Println("  import-blocks    Import blocks from stdin (framed format)")
	fmt.Println("  import-utxo      Import UTXO snapshot from HDOG file")
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
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  blockbrew                                           Start node on mainnet")
	fmt.Println("  blockbrew --network regtest                         Start node on regtest")
	fmt.Println("  blockbrew wallet create                             Generate new wallet")
	fmt.Println("  blockbrew import-blocks --network mainnet < blocks  Import blocks from stdin")
	fmt.Println("  blockbrew import-utxo -file snapshot.hdog           Import UTXO snapshot")
	fmt.Println("  blockbrew --version                                 Print version")
}
