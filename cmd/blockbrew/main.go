package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
}

func main() {
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
	flag.StringVar(&cfg.ListenRPC, "rpcbind", "127.0.0.1:8332", "RPC listen address")
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
	flag.Parse()

	if cfg.ListenP2P == "" {
		cfg.ListenP2P = fmt.Sprintf(":%d", chainPortForNetwork(cfg.Network))
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
			syncMgr.StartBlockDownload()
		},
		OnBlockConnected: onBlockConnected,
	})

	// Wire up sync manager listeners to peer manager
	syncListeners := syncMgr.CreatePeerListeners()
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
	rpcServer := rpc.NewServer(
		rpc.RPCConfig{
			ListenAddr: cfg.ListenRPC,
			Username:   cfg.RPCUser,
			Password:   cfg.RPCPassword,
		},
		rpc.WithChainParams(chainParams),
		rpc.WithChainManager(chainMgr),
		rpc.WithHeaderIndex(headerIndex),
		rpc.WithChainDB(chainDB),
		rpc.WithMempool(mp),
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

	syncMgr.Stop()
	log.Printf("Sync manager stopped")

	peerMgr.Stop()
	log.Printf("Peer manager stopped")

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
		fmt.Println("Use RPC: curl --user blockbrew:password --data-binary '{\"method\":\"getwalletinfo\"}' http://127.0.0.1:8332/")

	default:
		fmt.Fprintf(os.Stderr, "Unknown wallet command: %s\n", args[0])
		fmt.Println("Usage: blockbrew wallet <create|import|info>")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf("blockbrew v%s - A Bitcoin full node in Go\n\n", version)
	fmt.Println("Usage: blockbrew [options] [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version       Print version and exit")
	fmt.Println("  wallet        Wallet management commands")
	fmt.Println("  help          Print this help message")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --datadir       Data directory (default: ~/.blockbrew)")
	fmt.Println("  --network       Network: mainnet, testnet, regtest, signet (default: mainnet)")
	fmt.Println("  --listen        P2P listen address (default: based on network)")
	fmt.Println("  --rpcbind       RPC listen address (default: 127.0.0.1:8332)")
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
	fmt.Println("  blockbrew                          Start node on mainnet")
	fmt.Println("  blockbrew --network regtest        Start node on regtest")
	fmt.Println("  blockbrew wallet create            Generate new wallet")
	fmt.Println("  blockbrew --version                Print version")
}
