package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// RPCConfig configures the RPC server.
type RPCConfig struct {
	ListenAddr  string // e.g., "127.0.0.1:8332"
	Username    string // Basic auth username
	Password    string // Basic auth password
	TxIndex     bool   // Whether txindex is enabled
	RESTEnabled bool   // Whether REST API is enabled
}

// Server is the JSON-RPC server.
type Server struct {
	config       RPCConfig
	chainParams  *consensus.ChainParams
	chainMgr     *consensus.ChainManager
	headerIndex  *consensus.HeaderIndex
	chainDB      *storage.ChainDB
	mempool      *mempool.Mempool
	feeEstimator *mempool.FeeEstimator
	peerMgr      *p2p.PeerManager
	syncMgr      *p2p.SyncManager
	templateGen  *mining.TemplateGenerator
	wallet       *wallet.Wallet         // single wallet (legacy support)
	walletMgr    *wallet.Manager        // multi-wallet manager
	indexManager *storage.IndexManager
	pruner       *storage.Pruner        // BIP-?? auto-prune state; nil = archive
	dataDir      string                 // Filesystem root for mempool.dat etc.
	httpServer   *http.Server

	cookiePassword string // hex-encoded cookie secret (empty if unused)

	mu        sync.RWMutex
	startTime time.Time
	shutdown  chan struct{}

	// blockSubmissionPaused gates inbound block acceptance during the
	// `dumptxoutset rollback` rewind→dump→replay dance. Mirrors Bitcoin
	// Core's NetworkDisable RAII wrapper around TemporaryRollback in
	// rpc/blockchain.cpp::dumptxoutset. Peers stay connected; only block
	// acceptance is gated. Atomic so the P2P HandleBlock path can read
	// without lock contention.
	blockSubmissionPaused atomic.Bool
}

// networkDisable is the NetworkDisable equivalent: returns a closure
// that MUST be called (defer-style) to restore acceptance. Mirrors
// Core's NetworkDisable around TemporaryRollback in
// rpc/blockchain.cpp::dumptxoutset.
func (s *Server) networkDisable() func() {
	s.blockSubmissionPaused.Store(true)
	return func() {
		s.blockSubmissionPaused.Store(false)
	}
}

// IsBlockSubmissionPaused reports whether inbound block acceptance is
// currently gated by an active dumptxoutset rollback. Hot-path read.
func (s *Server) IsBlockSubmissionPaused() bool {
	return s.blockSubmissionPaused.Load()
}

// ServerOption is a functional option for configuring the server.
type ServerOption func(*Server)

// WithChainParams sets the chain parameters.
func WithChainParams(params *consensus.ChainParams) ServerOption {
	return func(s *Server) {
		s.chainParams = params
	}
}

// WithChainManager sets the chain manager.
func WithChainManager(cm *consensus.ChainManager) ServerOption {
	return func(s *Server) {
		s.chainMgr = cm
	}
}

// WithHeaderIndex sets the header index.
func WithHeaderIndex(idx *consensus.HeaderIndex) ServerOption {
	return func(s *Server) {
		s.headerIndex = idx
	}
}

// WithChainDB sets the chain database.
func WithChainDB(db *storage.ChainDB) ServerOption {
	return func(s *Server) {
		s.chainDB = db
	}
}

// WithMempool sets the mempool.
func WithMempool(mp *mempool.Mempool) ServerOption {
	return func(s *Server) {
		s.mempool = mp
	}
}

// WithFeeEstimator sets the fee estimator.
func WithFeeEstimator(fe *mempool.FeeEstimator) ServerOption {
	return func(s *Server) {
		s.feeEstimator = fe
	}
}

// WithPeerManager sets the peer manager.
func WithPeerManager(pm *p2p.PeerManager) ServerOption {
	return func(s *Server) {
		s.peerMgr = pm
	}
}

// WithSyncManager sets the sync manager.
func WithSyncManager(sm *p2p.SyncManager) ServerOption {
	return func(s *Server) {
		s.syncMgr = sm
	}
}

// WithTemplateGenerator sets the block template generator.
func WithTemplateGenerator(tg *mining.TemplateGenerator) ServerOption {
	return func(s *Server) {
		s.templateGen = tg
	}
}

// WithWallet sets the wallet (legacy, single wallet mode).
func WithWallet(w *wallet.Wallet) ServerOption {
	return func(s *Server) {
		s.wallet = w
	}
}

// WithWalletManager sets the multi-wallet manager.
func WithWalletManager(wm *wallet.Manager) ServerOption {
	return func(s *Server) {
		s.walletMgr = wm
	}
}

// WithIndexManager sets the index manager.
func WithIndexManager(im *storage.IndexManager) ServerOption {
	return func(s *Server) {
		s.indexManager = im
	}
}

// WithPruner attaches the auto-prune state so getblockchaininfo can
// report `pruned`, `pruneheight`, and `automatic_pruning` accurately.
// nil pruner = archive node (the default).
func WithPruner(p *storage.Pruner) ServerOption {
	return func(s *Server) {
		s.pruner = p
	}
}

// WithCookiePassword stores the pre-generated cookie password in the server
// so that checkAuth can accept "__cookie__" credentials.
func WithCookiePassword(password string) ServerOption {
	return func(s *Server) {
		s.cookiePassword = password
	}
}

// WithDataDir sets the data directory used by RPCs that read or write files
// (e.g. dumpmempool / loadmempool).
func WithDataDir(dir string) ServerOption {
	return func(s *Server) {
		s.dataDir = dir
	}
}

// NewServer creates a new RPC server with the given configuration.
func NewServer(config RPCConfig, opts ...ServerOption) *Server {
	s := &Server{
		config:    config,
		startTime: time.Now(),
		shutdown:  make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// GenerateCookie generates a 32-byte random cookie, writes
// "__cookie__:<hex>" to {datadir}/.cookie with permissions 0600, and
// returns the hex-encoded password.  The cookie lets local tools
// authenticate without a user-supplied password, matching Bitcoin Core
// behaviour.
func GenerateCookie(datadir string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cookie: failed to generate random bytes: %w", err)
	}
	password := hex.EncodeToString(raw)
	cookiePath := filepath.Join(datadir, ".cookie")
	content := "__cookie__:" + password
	if err := os.WriteFile(cookiePath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("cookie: failed to write %s: %w", cookiePath, err)
	}
	return password, nil
}

// DeleteCookie removes the .cookie file from datadir.  Call on clean
// shutdown so stale cookies are not left on disk.
func DeleteCookie(datadir string) {
	cookiePath := filepath.Join(datadir, ".cookie")
	if err := os.Remove(cookiePath); err != nil && !os.IsNotExist(err) {
		log.Printf("RPC: warning: failed to remove cookie file %s: %v", cookiePath, err)
	}
}

// Start begins listening for RPC requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register REST API handlers if enabled
	if s.config.RESTEnabled {
		s.RegisterRESTHandlers(mux)
		log.Printf("REST API enabled")
	}

	// Register JSON-RPC handler (must be after REST to not override /rest/ paths)
	mux.HandleFunc("/", s.handleRPC)

	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("RPC server error: %v", err)
		}
	}()

	log.Printf("RPC server listening on %s", s.config.ListenAddr)
	return nil
}

// Stop gracefully shuts down the RPC server.
func (s *Server) Stop() error {
	close(s.shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleRPC processes incoming JSON-RPC requests.
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check basic auth
	if !s.checkAuth(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="blockbrew"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Apply a per-request timeout so RPC calls don't hang indefinitely
	// when ConnectBlock holds the chain manager write lock during IBD.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Extract wallet name from URL path if present
	// URL pattern: /wallet/<walletname>
	walletName := s.extractWalletName(r.URL.Path)

	// Parse the request body
	var req RPCRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		s.sendError(w, nil, RPCErrParseError, "Parse error")
		return
	}

	// Check if context already expired before dispatching
	if ctx.Err() != nil {
		s.sendError(w, req.ID, RPCErrMisc, "Request timeout")
		return
	}

	// Dispatch to the appropriate handler with wallet context
	result, rpcErr := s.dispatch(req.Method, req.Params, walletName)
	if rpcErr != nil {
		s.sendResponse(w, RPCResponse{Error: rpcErr, ID: req.ID})
		return
	}
	s.sendResponse(w, RPCResponse{Result: result, ID: req.ID})
}

// rpcChainName returns the Bitcoin Core–canonical chain ID for RPC responses.
//
// blockbrew's ChainParams.Name uses the internal identifiers "mainnet",
// "testnet3", "testnet4", "regtest", "signet". Bitcoin Core's
// getblockchaininfo returns the shorter CBaseChainParams strings ("main",
// "test", "regtest", "signet", "testnet4"). Consensus-diff and other
// Core-compatible clients expect the Core values, so we translate at the
// RPC boundary without touching the internal name (which is still used
// for logging, peer messages, and config lookup).
func (s *Server) rpcChainName() string {
	if s.chainParams == nil {
		return "main"
	}
	switch s.chainParams.Name {
	case "mainnet":
		return "main"
	case "testnet", "testnet3":
		return "test"
	default:
		// regtest, signet, testnet4 — Core uses these identifiers verbatim.
		return s.chainParams.Name
	}
}

// extractWalletName extracts wallet name from URL path.
// Returns empty string if no wallet specified or path is "/".
func (s *Server) extractWalletName(path string) string {
	// Path format: /wallet/<walletname>
	const walletPrefix = "/wallet/"
	if len(path) > len(walletPrefix) && path[:len(walletPrefix)] == walletPrefix {
		return path[len(walletPrefix):]
	}
	return ""
}

// getWalletForRPC returns the wallet to use for wallet-related RPC calls.
// If walletName is specified, returns that specific wallet.
// If walletName is empty and only one wallet is loaded, returns that wallet.
// If walletName is empty and multiple wallets are loaded, returns an error.
func (s *Server) getWalletForRPC(walletName string) (*wallet.Wallet, *RPCError) {
	// Multi-wallet mode
	if s.walletMgr != nil {
		if walletName != "" {
			w, err := s.walletMgr.GetWallet(walletName)
			if err != nil {
				return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Requested wallet does not exist or is not loaded"}
			}
			return w, nil
		}
		// No wallet specified, try to get default
		w, err := s.walletMgr.GetDefaultWallet()
		if err != nil {
			if err == wallet.ErrMultipleWalletsNamed {
				return nil, &RPCError{Code: RPCErrWalletNotSpecified, Message: "Wallet file not specified (multiple wallets loaded)"}
			}
			return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "No wallet loaded"}
		}
		return w, nil
	}

	// Legacy single-wallet mode
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}
	return s.wallet, nil
}

// checkAuth verifies basic authentication.
// It accepts two credential pairs:
//  1. The configured rpcuser/rpcpassword (explicit credentials).
//  2. The "__cookie__" username with the generated cookie password
//     (used by local tools that read the .cookie file).
func (s *Server) checkAuth(r *http.Request) bool {
	// If no credentials are configured at all, allow every request.
	if s.config.Username == "" && s.config.Password == "" && s.cookiePassword == "" {
		return true
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}

	// Cookie auth: username must be literally "__cookie__".
	if user == "__cookie__" && s.cookiePassword != "" {
		return pass == s.cookiePassword
	}

	// Explicit rpcuser/rpcpassword auth.
	return user == s.config.Username && pass == s.config.Password
}

// sendResponse writes a JSON-RPC response.
func (s *Server) sendResponse(w http.ResponseWriter, resp RPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("RPC: failed to encode response: %v", err)
	}
}

// sendError writes a JSON-RPC error response.
func (s *Server) sendError(w http.ResponseWriter, id interface{}, code int, message string) {
	s.sendResponse(w, RPCResponse{
		Error: &RPCError{Code: code, Message: message},
		ID:    id,
	})
}

// dispatch routes method names to handlers.
// walletName is the wallet name from URL path (empty if not specified).
func (s *Server) dispatch(method string, params json.RawMessage, walletName string) (interface{}, *RPCError) {
	switch method {
	// Blockchain RPCs
	case "getblockchaininfo":
		return s.handleGetBlockchainInfo()
	case "getsyncstate":
		return s.handleGetSyncState()
	case "getblock":
		return s.handleGetBlock(params)
	case "getblockhash":
		return s.handleGetBlockHash(params)
	case "getblockcount":
		return s.handleGetBlockCount()
	case "getbestblockhash":
		return s.handleGetBestBlockHash()
	case "getblockheader":
		return s.handleGetBlockHeader(params)
	case "getdifficulty":
		return s.handleGetDifficulty()
	case "getchaintips":
		return s.handleGetChainTips()
	case "getdeploymentinfo":
		return s.handleGetDeploymentInfo(params)
	case "gettxout":
		return s.handleGetTxOut(params)
	case "getindexinfo":
		return s.handleGetIndexInfo()
	case "getblockfilter":
		return s.handleGetBlockFilter(params)

	// Chain management RPCs
	case "invalidateblock":
		return s.handleInvalidateBlock(params)
	case "reconsiderblock":
		return s.handleReconsiderBlock(params)
	case "preciousblock":
		return s.handlePreciousBlock(params)

	// Transaction RPCs
	case "decodescript":
		return s.handleDecodeScript(params)
	case "getrawtransaction":
		return s.handleGetRawTransaction(params)
	case "sendrawtransaction":
		return s.handleSendRawTransaction(params)
	case "decoderawtransaction":
		return s.handleDecodeRawTransaction(params)
	case "createrawtransaction":
		return s.handleCreateRawTransaction(params)
	case "signrawtransactionwithwallet":
		return s.handleSignRawTransactionWithWallet(params, walletName)

	// Mempool RPCs
	case "getmempoolinfo":
		return s.handleGetMempoolInfo()
	case "getrawmempool":
		return s.handleGetRawMempool(params)
	case "submitpackage":
		return s.handleSubmitPackage(params)
	case "testmempoolaccept":
		return s.handleTestMempoolAccept(params)
	case "getmempoolentry":
		return s.handleGetMempoolEntry(params)
	case "getmempoolancestors":
		return s.handleGetMempoolAncestors(params)
	case "getmempooldescendants":
		return s.handleGetMempoolDescendants(params)
	case "savemempool", "dumpmempool":
		return s.handleDumpMempool(params)
	case "loadmempool":
		return s.handleLoadMempool(params)

	// Network RPCs
	case "getpeerinfo":
		return s.handleGetPeerInfo()
	case "getconnectioncount":
		return s.handleGetConnectionCount()
	case "getnetworkinfo":
		return s.handleGetNetworkInfo()
	case "addnode":
		return s.handleAddNode(params)
	case "disconnectnode":
		return s.handleDisconnectNode(params)
	case "listbanned":
		return s.handleListBanned()
	case "setban":
		return s.handleSetBan(params)
	case "clearbanned":
		return s.handleClearBanned()

	// Mining RPCs
	case "getblocktemplate":
		return s.handleGetBlockTemplate(params)
	case "submitblock":
		return s.handleSubmitBlock(params)
	case "submitblockbatch":
		return s.handleSubmitBlockBatch(params)
	case "getmininginfo":
		return s.handleGetMiningInfo()
	case "generatetoaddress":
		return s.handleGenerateToAddress(params)
	case "generatetodescriptor":
		return s.handleGenerateToDescriptor(params)
	case "generateblock":
		return s.handleGenerateBlock(params)
	case "generate":
		return s.handleGenerate(params)

	// Fee estimation RPCs
	case "estimatesmartfee":
		return s.handleEstimateSmartFee(params)
	case "estimaterawfee":
		return s.handleEstimateRawFee(params)

	// Wallet management RPCs (don't require a specific wallet)
	case "createwallet":
		return s.handleCreateWallet(params)
	case "loadwallet":
		return s.handleLoadWallet(params)
	case "unloadwallet":
		return s.handleUnloadWallet(params, walletName)
	case "listwallets":
		return s.handleListWallets()
	case "listwalletdir":
		return s.handleListWalletDir()
	case "backupwallet":
		return s.handleBackupWallet(params, walletName)

	// Wallet RPCs (require wallet context)
	case "getnewaddress":
		return s.handleGetNewAddressWithWallet(walletName)
	case "getbalance":
		return s.handleGetBalanceWithWallet(walletName)
	case "listunspent":
		return s.handleListUnspentWithWallet(walletName)
	case "sendtoaddress":
		return s.handleSendToAddressWithWallet(params, walletName)
	case "encryptwallet":
		return s.handleEncryptWalletWithWallet(params, walletName)
	case "walletpassphrase":
		return s.handleWalletPassphraseWithWallet(params, walletName)
	case "walletlock":
		return s.handleWalletLockWithWallet(walletName)
	case "listtransactions":
		return s.handleListTransactionsWithWallet(params, walletName)
	case "getwalletinfo":
		return s.handleGetWalletInfoWithWallet(walletName)
	case "setlabel":
		return s.handleSetLabelWithWallet(params, walletName)
	case "listlabels":
		return s.handleListLabelsWithWallet(params, walletName)
	case "getaddressesbylabel":
		return s.handleGetAddressesByLabelWithWallet(params, walletName)
	case "getaddressinfo":
		return s.handleGetAddressInfoWithWallet(params, walletName)

	// PSBT RPCs
	case "createpsbt":
		return s.handleCreatePSBT(params)
	case "decodepsbt":
		return s.handleDecodePSBT(params)
	case "combinepsbt":
		return s.handleCombinePSBT(params)
	case "finalizepsbt":
		return s.handleFinalizePSBT(params)
	case "converttopsbt":
		return s.handleConvertToPSBT(params)
	case "walletprocesspsbt":
		return s.handleWalletProcessPSBTWithWallet(params, walletName)
	case "analyzepsbt":
		return s.handleAnalyzePSBT(params)
	case "joinpsbts":
		return s.handleJoinPSBTs(params)
	case "utxoupdatepsbt":
		return s.handleUTXOUpdatePSBT(params)

	// Control RPCs
	case "stop":
		return s.handleStop()
	case "uptime":
		return s.handleUptime()
	case "getinfo":
		return s.handleGetInfo()
	case "help":
		return s.handleHelp(params)
	case "verifymessage":
		return s.handleVerifyMessage(params)
	case "signmessage":
		return s.handleSignMessage(params, walletName)
	case "signmessagewithprivkey":
		return s.handleSignMessageWithPrivKey(params)

	// Descriptor RPCs
	case "getdescriptorinfo":
		return s.handleGetDescriptorInfo(params)
	case "deriveaddresses":
		return s.handleDeriveAddresses(params)

	// AssumeUTXO RPCs
	case "dumptxoutset":
		return s.handleDumpTxOutSet(params)
	case "loadtxoutset":
		return s.handleLoadTxOutSet(params)
	case "getchainstates":
		return s.handleGetChainStates()

	// Wave-47b P2 RPCs
	case "gettxoutsetinfo":
		return s.handleGetTxOutSetInfo(params)
	case "getnetworkhashps":
		return s.handleGetNetworkHashPS(params)
	case "gettxoutproof":
		return s.handleGetTxOutProof(params)
	case "verifytxoutproof":
		return s.handleVerifyTxOutProof(params)
	case "getrpcinfo":
		return s.handleGetRPCInfo(params)

	default:
		return nil, &RPCError{Code: RPCErrMethodNotFound, Message: fmt.Sprintf("Method not found: %s", method)}
	}
}
