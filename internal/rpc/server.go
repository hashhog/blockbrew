package rpc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
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

	// TLS termination (W119 BUG / FIX-64). When both TLSCertFile and
	// TLSKeyFile are non-empty the server uses ListenAndServeTLS so the
	// JSON-RPC and REST endpoints are served over HTTPS instead of plain
	// HTTP. When neither is set the legacy plaintext path is preserved
	// (backward compat with existing operators/tools that already front
	// blockbrew with nginx/Tor for TLS termination). Setting exactly one
	// of the two is a startup error — see Server.Start. Closes W119
	// universal "RPC plaintext fleet-wide" finding and is required for
	// clearnet PayJoin per BIP-78 §"Protocol" (HTTPS endpoint mandatory
	// outside of .onion). Reference: bitcoin-core/src/httpserver.cpp.
	TLSCertFile string
	TLSKeyFile  string
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
	wallet       *wallet.Wallet  // single wallet (legacy support)
	walletMgr    *wallet.Manager // multi-wallet manager
	indexManager *storage.IndexManager
	pruner       *storage.Pruner // BIP-?? auto-prune state; nil = archive
	dataDir      string          // Filesystem root for mempool.dat etc.
	httpServer   *http.Server

	cookiePassword string // hex-encoded cookie secret (empty if unused)

	// blockFetchPeers is the test seam for getblockfrompeer. In production
	// it is nil and the handler falls back to s.peerMgr.ConnectedPeers()
	// (the exact same source getpeerinfo enumerates, so peer_id matches the
	// id an operator sees there). Tests inject a deterministic peer list so
	// the genuine getdata send can be captured without a live network.
	blockFetchPeers fetchPeerLister

	mu        sync.RWMutex
	startTime time.Time
	shutdown  chan struct{}

	// snapshotActivation records the live AssumeUTXO snapshot activation (Core
	// ChainstateManager's second chainstate). nil while no snapshot is loaded;
	// set once handleLoadTxOutSet has activated a snapshot + driven the
	// background validator. Read by handleGetChainStates to surface
	// validated/snapshot_blockhash. Guarded by snapshotMu so the loadtxoutset
	// handler can record the activation on the SAME Server the getter reads —
	// mirrors Core where ActivateSnapshot installs the chainstate into the
	// long-lived ChainstateManager that getchainstates later inspects.
	// snapshotBaseHashHex is the snapshot base block hash (display hex), cached
	// alongside so getchainstates can emit snapshot_blockhash without a relock
	// of the chainstate internals.
	snapshotMu          sync.RWMutex
	snapshotActivation  *consensus.SnapshotActivation
	snapshotBaseHashHex string

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
//
// When both RPCConfig.TLSCertFile and RPCConfig.TLSKeyFile are non-empty
// the server is served over HTTPS via ListenAndServeTLS. When neither is
// set the legacy plaintext HTTP path is used (backward compat). Setting
// exactly one of the two — cert without key or vice versa — is rejected
// here with a clear error so an operator never silently lands on plaintext
// when they intended HTTPS. See RPCConfig docstring and W119 / FIX-64.
func (s *Server) Start() error {
	// Validate TLS arg pair before binding the socket so the daemon does
	// not transiently expose plain HTTP on the configured port when the
	// operator's intent was HTTPS but they typoed/forgot one of the two
	// flags. Both empty is fine (HTTP); both set is fine (HTTPS); exactly
	// one set is the misconfiguration we want to catch.
	certSet := s.config.TLSCertFile != ""
	keySet := s.config.TLSKeyFile != ""
	if certSet != keySet {
		return fmt.Errorf(
			"rpc: TLS misconfiguration: --rpc-tls-cert and --rpc-tls-key must both be set or both empty (cert=%q key=%q)",
			s.config.TLSCertFile, s.config.TLSKeyFile,
		)
	}

	mux := http.NewServeMux()

	// Register REST API handlers if enabled
	if s.config.RESTEnabled {
		s.RegisterRESTHandlers(mux)
		log.Printf("REST API enabled")
	}

	// Register BIP-78 PayJoin receiver route (W119 BUG-2 / FIX-65). The
	// route is always registered so a remote sender hitting /payjoin gets
	// a proper BIP-78 JSON error body when the receiver isn't ready
	// (e.g. no wallet loaded) rather than the JSON-RPC `Method not found`
	// envelope. Must be registered BEFORE the catch-all "/" so the more
	// specific path wins.
	mux.HandleFunc(payjoinPath, s.handlePayjoin)

	// Register JSON-RPC handler (must be after REST and PayJoin to not
	// override their explicit paths).
	mux.HandleFunc("/", s.handleRPC)

	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	tlsEnabled := certSet && keySet
	if tlsEnabled {
		// Validate the cert/key pair eagerly so a typo in the path or a
		// PEM-decoding failure surfaces synchronously, before Start
		// returns. Otherwise the error would only appear in the goroutine
		// log and the daemon would look "up" while serving nothing.
		if _, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil {
			return fmt.Errorf("rpc: TLS keypair load failed (cert=%q key=%q): %w", s.config.TLSCertFile, s.config.TLSKeyFile, err)
		}
		// Modern, conservative defaults: TLS 1.2 minimum, standard cipher
		// suites selected by the Go runtime. We don't pin a cipher list —
		// Go's defaults track upstream changes and we want HTTPS RPC to
		// stay current without code edits per release.
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	go func() {
		var err error
		if tlsEnabled {
			err = s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != http.ErrServerClosed {
			log.Printf("RPC server error: %v", err)
		}
	}()

	if tlsEnabled {
		log.Printf("RPC server listening on https://%s (TLS cert=%s)", s.config.ListenAddr, s.config.TLSCertFile)
	} else {
		log.Printf("RPC server listening on %s", s.config.ListenAddr)
	}
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
	case "getchaintxstats":
		return s.handleGetChainTxStats(params)
	case "getblockstats":
		return s.handleGetBlockStats(params)
	case "getdeploymentinfo":
		return s.handleGetDeploymentInfo(params)
	case "gettxout":
		return s.handleGetTxOut(params)
	case "getindexinfo":
		return s.handleGetIndexInfo(params)
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
	case "signrawtransactionwithkey":
		return s.handleSignRawTransactionWithKey(params)

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
	case "getorphantxs":
		return s.handleGetOrphanTxs(params)
	case "gettxspendingprevout":
		return s.handleGetTxSpendingPrevout(params)
	case "savemempool", "dumpmempool":
		return s.handleDumpMempool(params)
	case "loadmempool":
		return s.handleLoadMempool(params)
	// Prioritisation RPCs (W120 BUG-10 / FIX-72). Mirrors Core
	// src/rpc/mining.cpp::prioritisetransaction +
	// src/rpc/mining.cpp::getprioritisedtransactions. The mempool delta
	// participates in RBF Rule 3 (rbf.cpp::PaysMoreThanConflicts uses
	// GetModifiedFee) and in getmempoolentry's `modifiedfee` field.
	case "prioritisetransaction":
		return s.handlePrioritiseTransaction(params)
	case "getprioritisedtransactions":
		return s.handleGetPrioritisedTransactions(params)

	// Network RPCs
	case "getpeerinfo":
		return s.handleGetPeerInfo()
	case "getblockfrompeer":
		return s.handleGetBlockFromPeer(params)
	case "getconnectioncount":
		return s.handleGetConnectionCount()
	case "getnetworkinfo":
		return s.handleGetNetworkInfo()
	case "setnetworkactive":
		return s.handleSetNetworkActive(params)
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
	case "getnodeaddresses":
		return s.handleGetNodeAddresses(params)
	case "getaddrmaninfo":
		return s.handleGetAddrmanInfo(params)
	case "getmemoryinfo":
		return s.handleGetMemoryInfo(params)
	case "getaddednodeinfo":
		return s.handleGetAddedNodeInfo(params)
	case "addpeeraddress":
		return s.handleAddPeerAddress(params)

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
	case "gettransaction":
		return s.handleGetTransactionWithWallet(params, walletName)
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
	case "getbalances":
		return s.handleGetBalances(walletName)
	case "lockunspent":
		return s.handleLockUnspent(params, walletName)
	case "listlockunspent":
		return s.handleListLockUnspent(walletName)
	case "walletcreatefundedpsbt":
		return s.handleWalletCreateFundedPSBT(params, walletName)
	case "fundrawtransaction":
		return s.handleFundRawTransaction(params, walletName)

	// Wallet rescan + key import. rescanblockchain rebuilds the wallet's UTXO
	// ledger + history from existing chain blocks (the wallet half of recovery,
	// distinct from the chain-level scantxoutset); importprivkey adds a foreign
	// key + rescans to credit its funds.
	// Reference: bitcoin-core/src/wallet/rpc/transactions.cpp::rescanblockchain,
	// bitcoin-core/src/wallet/rpc/backup.cpp::importprivkey.
	case "rescanblockchain":
		return s.handleRescanBlockchain(params, walletName)
	case "importprivkey":
		return s.handleImportPrivKey(params, walletName)
	// importdescriptors is Core's ONLY remaining watch-only import path
	// (importaddress/importpubkey/importmulti are removed in v31.99 and stay
	// -32601 here, Core-faithfully).
	// Reference: bitcoin-core/src/wallet/rpc/backup.cpp::importdescriptors.
	case "importdescriptors":
		return s.handleImportDescriptors(params, walletName)
	case "dumpprivkey":
		return s.handleDumpPrivKey(params, walletName)
	// Seed-words export (W161 BUG-15/17 funds-loss fix). Non-Core extension
	// (companion of createwallet's mnemonic restore param); unlock-gated like
	// Core's listdescriptors private=true / legacy dumpwallet hdseed line.
	// Reference: bitcoin-core/src/wallet/rpc/backup.cpp::listdescriptors.
	case "getmnemonic":
		return s.handleGetMnemonic(walletName)

	// Fee-bumping RPCs (FIX-61 / W118 BUG-2). bumpfee broadcasts the
	// replacement; psbtbumpfee returns a PSBT for offline signing.
	// Reference: bitcoin-core/src/wallet/rpc/feebumper.cpp; BIP-125.
	case "bumpfee":
		return s.handleBumpFee(params, walletName)
	case "psbtbumpfee":
		return s.handlePSBTBumpFee(params, walletName)

	// PayJoin sender RPCs (FIX-66 / W119 BUG-4). getpayjoinrequest builds
	// + signs the Original PSBT (caller drives transport); sendpayjoinrequest
	// runs the full sender flow including G10-G15 anti-snoop + G22 fallback.
	// Reference: bips/bip-0078.mediawiki; internal/wallet/payjoin_sender.go.
	case "getpayjoinrequest":
		return s.handleGetPayjoinRequest(params, walletName)
	case "sendpayjoinrequest":
		return s.handleSendPayjoinRequest(params, walletName)

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

	case "scantxoutset":
		return s.handleScanTxOutSet(params)
	case "scanblocks":
		return s.handleScanBlocks(params)

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

	case "validateaddress":
		return s.handleValidateAddress(params)

	case "createmultisig":
		return s.handleCreateMultisig(params)

	default:
		return nil, &RPCError{Code: RPCErrMethodNotFound, Message: fmt.Sprintf("Method not found: %s", method)}
	}
}
