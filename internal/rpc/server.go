package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/storage"
)

// RPCConfig configures the RPC server.
type RPCConfig struct {
	ListenAddr string // e.g., "127.0.0.1:8332"
	Username   string // Basic auth username
	Password   string // Basic auth password
}

// Server is the JSON-RPC server.
type Server struct {
	config      RPCConfig
	chainParams *consensus.ChainParams
	chainMgr    *consensus.ChainManager
	headerIndex *consensus.HeaderIndex
	chainDB     *storage.ChainDB
	mempool     *mempool.Mempool
	peerMgr     *p2p.PeerManager
	syncMgr     *p2p.SyncManager
	templateGen *mining.TemplateGenerator
	httpServer  *http.Server

	mu        sync.RWMutex
	startTime time.Time
	shutdown  chan struct{}
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

// Start begins listening for RPC requests.
func (s *Server) Start() error {
	mux := http.NewServeMux()
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

	// Parse the request body
	var req RPCRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		s.sendError(w, nil, RPCErrParseError, "Parse error")
		return
	}

	// Dispatch to the appropriate handler
	result, rpcErr := s.dispatch(req.Method, req.Params)
	if rpcErr != nil {
		s.sendResponse(w, RPCResponse{Error: rpcErr, ID: req.ID})
		return
	}
	s.sendResponse(w, RPCResponse{Result: result, ID: req.ID})
}

// checkAuth verifies basic authentication.
func (s *Server) checkAuth(r *http.Request) bool {
	// If no auth configured, allow all requests
	if s.config.Username == "" && s.config.Password == "" {
		return true
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}

	return user == s.config.Username && pass == s.config.Password
}

// sendResponse writes a JSON-RPC response.
func (s *Server) sendResponse(w http.ResponseWriter, resp RPCResponse) {
	w.Header().Set("Content-Type", "application/json")
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
func (s *Server) dispatch(method string, params json.RawMessage) (interface{}, *RPCError) {
	switch method {
	// Blockchain RPCs
	case "getblockchaininfo":
		return s.handleGetBlockchainInfo()
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

	// Transaction RPCs
	case "getrawtransaction":
		return s.handleGetRawTransaction(params)
	case "sendrawtransaction":
		return s.handleSendRawTransaction(params)
	case "decoderawtransaction":
		return s.handleDecodeRawTransaction(params)

	// Mempool RPCs
	case "getmempoolinfo":
		return s.handleGetMempoolInfo()
	case "getrawmempool":
		return s.handleGetRawMempool(params)

	// Network RPCs
	case "getpeerinfo":
		return s.handleGetPeerInfo()
	case "getconnectioncount":
		return s.handleGetConnectionCount()
	case "getnetworkinfo":
		return s.handleGetNetworkInfo()
	case "addnode":
		return s.handleAddNode(params)

	// Mining RPCs
	case "getblocktemplate":
		return s.handleGetBlockTemplate(params)
	case "submitblock":
		return s.handleSubmitBlock(params)

	// Fee estimation RPCs
	case "estimatesmartfee":
		return s.handleEstimateSmartFee(params)

	// Control RPCs
	case "stop":
		return s.handleStop()
	case "uptime":
		return s.handleUptime()
	case "getinfo":
		return s.handleGetInfo()

	default:
		return nil, &RPCError{Code: RPCErrMethodNotFound, Message: fmt.Sprintf("Method not found: %s", method)}
	}
}
