package rpc

import "encoding/json"

// JSON-RPC error codes (from Bitcoin Core).
const (
	RPCErrParseError         = -32700 // Invalid JSON was received
	RPCErrInvalidRequest     = -32600 // The JSON sent is not a valid Request object
	RPCErrMethodNotFound     = -32601 // The method does not exist
	RPCErrInvalidParams      = -32602 // Invalid method parameter(s)
	RPCErrInternal           = -32603 // Internal JSON-RPC error
	RPCErrBlockNotFound      = -5     // Block not found
	RPCErrTxNotFound         = -5     // Transaction not found
	RPCErrWalletError        = -4     // Unspecified wallet error
	RPCErrWalletNotFound     = -18    // Wallet not loaded
	RPCErrWalletNotSpecified = -19    // Multiple wallets loaded, must specify which
	RPCErrWalletAlreadyLoaded = -35   // Wallet is already loaded
	RPCErrDeserialization      = -22    // Error parsing or validating structure in raw format
	RPCErrVerify               = -25    // Error during verification
	RPCErrInWarmup             = -28    // Client still warming up
	RPCErrClientNodeNotConnected = -29  // Node not found/connected
	RPCErrClientP2PDisabled      = -9   // P2P networking is disabled
	RPCErrWallet               = -4     // Wallet error (general)
	RPCErrMisc                 = -1     // Miscellaneous error
)

// RPCRequest is a JSON-RPC request.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// RPCResponse is a JSON-RPC response.
type RPCResponse struct {
	Result interface{} `json:"result"`
	Error  *RPCError   `json:"error"`
	ID     interface{} `json:"id"`
}

// RPCError is a JSON-RPC error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return e.Message
}

// SyncStateResult is the JSON response for the getsyncstate RPC (W70).
// See spec/getsyncstate.md for field semantics and invariants. SHOULD
// fields are *int64 / *float64 / *string so they can serialize to JSON
// null when the node can't produce them (blockbrew produces all of them).
type SyncStateResult struct {
	TipHeight             int32    `json:"tip_height"`
	TipHash               string   `json:"tip_hash"`
	BestHeaderHeight      int32    `json:"best_header_height"`
	BestHeaderHash        string   `json:"best_header_hash"`
	InitialBlockDownload  bool     `json:"initial_block_download"`
	NumPeers              int      `json:"num_peers"`
	VerificationProgress  *float64 `json:"verification_progress"`
	BlocksInFlight        *int     `json:"blocks_in_flight"`
	BlocksPendingConnect  *int     `json:"blocks_pending_connect"`
	LastBlockReceivedTime *int64   `json:"last_block_received_time"`
	Chain                 *string  `json:"chain"`
	ProtocolVersion       *int     `json:"protocol_version"`
}

// BlockchainInfo represents the result of getblockchaininfo.
type BlockchainInfo struct {
	Chain                string                     `json:"chain"`
	Blocks               int32                      `json:"blocks"`
	Headers              int32                      `json:"headers"`
	BestBlockHash        string                     `json:"bestblockhash"`
	Difficulty           float64                    `json:"difficulty"`
	MedianTime           int64                      `json:"mediantime"`
	VerificationProgress float64                    `json:"verificationprogress"`
	InitialBlockDownload bool                       `json:"initialblockdownload"`
	Pruned               bool                       `json:"pruned"`
	// PruneHeight is the lowest-height block whose body is still on disk.
	// Only emitted when pruned=true; matches Bitcoin Core's
	// rpc/blockchain.cpp getblockchaininfo behavior. omitempty so archive
	// nodes don't include the key, also matching Core.
	PruneHeight int32 `json:"pruneheight,omitempty"`
	// AutomaticPruning is true when the node will automatically delete
	// old block files to stay under -prune target. Always true when
	// pruned=true in our implementation (we don't expose `-prune=1`
	// manual-only mode).
	AutomaticPruning bool `json:"automatic_pruning,omitempty"`
	// PruneTargetSize is the configured -prune target in bytes (NOT
	// MiB — Core converts MiB to bytes here). Only emitted when
	// automatic_pruning=true. omitempty otherwise.
	PruneTargetSize uint64 `json:"prune_target_size,omitempty"`
	// Softforks mirrors getdeploymentinfo.deployments: both RPCs read from the
	// same buildDeploymentMap helper so their data is always consistent.
	Softforks            map[string]DeploymentEntry `json:"softforks"`
}

// BlockResult represents a block in RPC responses.
type BlockResult struct {
	Hash          string        `json:"hash"`
	Confirmations int32         `json:"confirmations"`
	Size          int           `json:"size"`
	Weight        int           `json:"weight"`
	Height        int32         `json:"height"`
	Version       int32         `json:"version"`
	VersionHex    string        `json:"versionHex"`
	MerkleRoot    string        `json:"merkleroot"`
	Tx            []interface{} `json:"tx"`
	Time          uint32        `json:"time"`
	MedianTime    int64         `json:"mediantime"`
	Nonce         uint32        `json:"nonce"`
	Bits          string        `json:"bits"`
	Difficulty    float64       `json:"difficulty"`
	ChainWork     string        `json:"chainwork,omitempty"`
	NTx           int           `json:"nTx"`
	PreviousHash  string        `json:"previousblockhash,omitempty"`
	NextHash      string        `json:"nextblockhash,omitempty"`
}

// BlockHeaderResult represents a block header in RPC responses.
type BlockHeaderResult struct {
	Hash          string  `json:"hash"`
	Confirmations int32   `json:"confirmations"`
	Height        int32   `json:"height"`
	Version       int32   `json:"version"`
	VersionHex    string  `json:"versionHex"`
	MerkleRoot    string  `json:"merkleroot"`
	Time          uint32  `json:"time"`
	MedianTime    int64   `json:"mediantime"`
	Nonce         uint32  `json:"nonce"`
	Bits          string  `json:"bits"`
	Difficulty    float64 `json:"difficulty"`
	ChainWork     string  `json:"chainwork,omitempty"`
	NTx           int     `json:"nTx"`
	PreviousHash  string  `json:"previousblockhash,omitempty"`
	NextHash      string  `json:"nextblockhash,omitempty"`
}

// TxResult represents a transaction in RPC responses (verbose mode).
type TxResult struct {
	TxID          string       `json:"txid"`
	Hash          string       `json:"hash"`
	Version       int32        `json:"version"`
	Size          int          `json:"size"`
	VSize         int          `json:"vsize"`
	Weight        int          `json:"weight"`
	LockTime      uint32       `json:"locktime"`
	Vin           []VinResult  `json:"vin"`
	Vout          []VoutResult `json:"vout"`
	Hex           string       `json:"hex,omitempty"`
	BlockHash     string       `json:"blockhash,omitempty"`
	Confirmations int32        `json:"confirmations,omitempty"`
	BlockTime     uint32       `json:"blocktime,omitempty"`
	Time          uint32       `json:"time,omitempty"`
}

// VinResult represents a transaction input in RPC responses.
type VinResult struct {
	TxID        string   `json:"txid,omitempty"`
	Vout        uint32   `json:"vout,omitempty"`
	ScriptSig   *Script  `json:"scriptSig,omitempty"`
	TxInWitness []string `json:"txinwitness,omitempty"`
	Sequence    uint32   `json:"sequence"`
	Coinbase    string   `json:"coinbase,omitempty"`
}

// VoutResult represents a transaction output in RPC responses.
type VoutResult struct {
	Value        float64      `json:"value"`
	N            int          `json:"n"`
	ScriptPubKey ScriptPubKey `json:"scriptPubKey"`
}

// Script represents a script in RPC responses.
type Script struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

// ScriptPubKey represents an output script in RPC responses.
type ScriptPubKey struct {
	Asm     string `json:"asm"`
	Hex     string `json:"hex"`
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
}

// MempoolInfo represents the result of getmempoolinfo.
type MempoolInfo struct {
	Loaded             bool    `json:"loaded"`
	Size               int     `json:"size"`
	Bytes              int64   `json:"bytes"`
	Usage              int64   `json:"usage"`
	TotalFee           float64 `json:"total_fee"`
	MaxMempool         int64   `json:"maxmempool"`
	MempoolMinFee      float64 `json:"mempoolminfee"`
	MinRelayTxFee      float64 `json:"minrelaytxfee"`
	IncrementalRelayFee float64 `json:"incrementalrelayfee"`
	UnbroadcastCount   int     `json:"unbroadcastcount"`
	FullRBF            bool    `json:"fullrbf"`
}

// MempoolEntry represents a mempool entry (verbose getrawmempool).
type MempoolEntry struct {
	VSize            int64    `json:"vsize"`
	Weight           int64    `json:"weight"`
	Fee              float64  `json:"fee"`
	ModifiedFee      float64  `json:"modifiedfee"`
	Time             int64    `json:"time"`
	Height           int32    `json:"height"`
	DescendantCount  int      `json:"descendantcount"`
	DescendantSize   int64    `json:"descendantsize"`
	DescendantFees   float64  `json:"descendantfees"`
	AncestorCount    int      `json:"ancestorcount"`
	AncestorSize     int64    `json:"ancestorsize"`
	AncestorFees     float64  `json:"ancestorfees"`
	WTxID            string   `json:"wtxid"`
	Depends          []string `json:"depends"`
	SpentBy          []string `json:"spentby"`
	Unbroadcast      bool     `json:"unbroadcast"`
}

// PeerInfo represents peer information in RPC responses.
type PeerInfo struct {
	ID             int      `json:"id"`
	Addr           string   `json:"addr"`
	Network        string   `json:"network"`
	Services       string   `json:"services"`
	ServicesNames  []string `json:"servicesnames"`
	RelayTxes      bool     `json:"relaytxes"`
	LastSend       int64    `json:"lastsend"`
	LastRecv       int64    `json:"lastrecv"`
	BytesSent      uint64   `json:"bytessent"`
	BytesRecv      uint64   `json:"bytesrecv"`
	ConnTime       int64    `json:"conntime"`
	TimeOffset     int64    `json:"timeoffset"`
	PingTime       float64  `json:"pingtime"`
	Version        int32    `json:"version"`
	SubVer         string   `json:"subver"`
	Inbound        bool     `json:"inbound"`
	BIP152HBTo     bool     `json:"bip152_hb_to"`
	BIP152HBFrom   bool     `json:"bip152_hb_from"`
	StartHeight    int32    `json:"startingheight"`
	SyncedHeaders  int32    `json:"synced_headers"`
	SyncedBlocks   int32    `json:"synced_blocks"`
	Inflight       []int    `json:"inflight"`
	ConnectionType string   `json:"connection_type"`
}

// NetworkInfo represents the result of getnetworkinfo.
type NetworkInfo struct {
	Version            int32          `json:"version"`
	SubVersion         string         `json:"subversion"`
	ProtocolVersion    int32          `json:"protocolversion"`
	LocalServices      string         `json:"localservices"`
	LocalServicesNames []string       `json:"localservicesnames"`
	LocalRelay         bool           `json:"localrelay"`
	TimeOffset         int64          `json:"timeoffset"`
	NetworkActive      bool           `json:"networkactive"`
	Connections        int            `json:"connections"`
	ConnectionsIn      int            `json:"connections_in"`
	ConnectionsOut     int            `json:"connections_out"`
	Networks           []NetworkEntry `json:"networks"`
	RelayFee           float64        `json:"relayfee"`
	IncrementalFee     float64        `json:"incrementalfee"`
	LocalAddresses     []interface{}  `json:"localaddresses"`
	Warnings           string         `json:"warnings"`
}

// NetworkEntry represents a network in getnetworkinfo.
type NetworkEntry struct {
	Name                     string `json:"name"`
	Limited                  bool   `json:"limited"`
	Reachable                bool   `json:"reachable"`
	Proxy                    string `json:"proxy"`
	ProxyRandomizeCredentials bool  `json:"proxy_randomize_credentials"`
}

// SmartFeeResult represents the result of estimatesmartfee.
type SmartFeeResult struct {
	FeeRate float64  `json:"feerate,omitempty"`
	Errors  []string `json:"errors,omitempty"`
	Blocks  int      `json:"blocks"`
}

// ChainTip represents a chain tip (for getchaintips).
type ChainTip struct {
	Height    int32  `json:"height"`
	Hash      string `json:"hash"`
	BranchLen int32  `json:"branchlen"`
	Status    string `json:"status"`
}

// WalletInfo represents the result of getwalletinfo.
type WalletInfo struct {
	WalletName            string  `json:"walletname"`
	WalletVersion         int     `json:"walletversion"`
	Format                string  `json:"format,omitempty"`
	Balance               float64 `json:"balance"`
	UnconfirmedBalance    float64 `json:"unconfirmed_balance"`
	TxCount               int     `json:"txcount"`
	KeypoolSize           int     `json:"keypoolsize"`
	KeypoolSizeHDInternal int     `json:"keypoolsize_hd_internal,omitempty"`
	UnlockedUntil         *int64  `json:"unlocked_until,omitempty"`
	PayTxFee              float64 `json:"paytxfee"`
	PrivateKeysEnabled    bool    `json:"private_keys_enabled"`
	AvoidReuse            bool    `json:"avoid_reuse"`
	Scanning              bool    `json:"scanning"`
	Descriptors           bool    `json:"descriptors"`
	ExternalSigner        bool    `json:"external_signer"`
	Blank                 bool    `json:"blank"`
	Locked                bool    `json:"-"` // Internal use, not serialized
}

// ListUnspentResult represents an unspent output for listunspent.
type ListUnspentResult struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	Address       string  `json:"address"`
	Label         string  `json:"label,omitempty"`
	Amount        float64 `json:"amount"`
	Confirmations int32   `json:"confirmations"`
	Spendable     bool    `json:"spendable"`
	Solvable      bool    `json:"solvable"`
	Safe          bool    `json:"safe"`
}

// ListTransactionsResult represents a wallet transaction for listtransactions.
type ListTransactionsResult struct {
	Address       string  `json:"address"`
	Category      string  `json:"category"` // "send", "receive"
	Amount        float64 `json:"amount"`
	Fee           float64 `json:"fee,omitempty"`
	Confirmations int32   `json:"confirmations"`
	TxID          string  `json:"txid"`
	Time          int64   `json:"time"`
	BlockHeight   int32   `json:"blockheight,omitempty"`
}

// TxOutResult represents the result of gettxout.
type TxOutResult struct {
	BestBlock     string       `json:"bestblock"`
	Confirmations int32        `json:"confirmations"`
	Value         float64      `json:"value"`
	ScriptPubKey  ScriptPubKey `json:"scriptPubKey"`
	Coinbase      bool         `json:"coinbase"`
}

// MiningInfo represents the result of getmininginfo.
type MiningInfo struct {
	Blocks       int32   `json:"blocks"`
	Difficulty   float64 `json:"difficulty"`
	NetworkHash  float64 `json:"networkhashps"`
	PooledTx     int     `json:"pooledtx"`
	Chain        string  `json:"chain"`
}

// DecodeScriptResult represents the result of decodescript.
type DecodeScriptResult struct {
	Asm  string `json:"asm"`
	Type string `json:"type"`
	P2SH string `json:"p2sh,omitempty"`
}

// BlockTemplateResult represents the result of getblocktemplate.
type BlockTemplateResult struct {
	Version                  int32                 `json:"version"`
	PreviousBlockHash        string                `json:"previousblockhash"`
	Transactions             []BlockTemplateTx     `json:"transactions"`
	CoinbaseAux              map[string]string     `json:"coinbaseaux"`
	CoinbaseValue            int64                 `json:"coinbasevalue"`
	Target                   string                `json:"target"`
	MinTime                  int64                 `json:"mintime"`
	Mutable                  []string              `json:"mutable"`
	NonceRange               string                `json:"noncerange"`
	SigOpLimit               int64                 `json:"sigoplimit"`
	SizeLimit                int64                 `json:"sizelimit"`
	WeightLimit              int64                 `json:"weightlimit"`
	CurTime                  int64                 `json:"curtime"`
	Bits                     string                `json:"bits"`
	Height                   int32                 `json:"height"`
	DefaultWitnessCommitment string                `json:"default_witness_commitment,omitempty"`
}

// BlockTemplateTx represents a transaction in the block template.
type BlockTemplateTx struct {
	Data    string   `json:"data"`
	TxID    string   `json:"txid"`
	Hash    string   `json:"hash"`
	Depends []int    `json:"depends"`
	Fee     int64    `json:"fee"`
	SigOps  int64    `json:"sigops"`
	Weight  int64    `json:"weight"`
}

// BannedInfo represents a banned peer in RPC responses.
type BannedInfo struct {
	Address     string `json:"address"`
	BanCreated  int64  `json:"ban_created"`
	BannedUntil int64  `json:"banned_until"`
	BanReason   string `json:"ban_reason,omitempty"`
}

// AddressInfoResult represents the result of getaddressinfo.
type AddressInfoResult struct {
	Address      string `json:"address"`
	ScriptPubKey string `json:"scriptPubKey,omitempty"`
	IsMine       bool   `json:"ismine"`
	IsWatchOnly  bool   `json:"iswatchonly"`
	Solvable     bool   `json:"solvable"`
	Label        string `json:"label,omitempty"`
	Labels       []struct {
		Name    string `json:"name"`
		Purpose string `json:"purpose"`
	} `json:"labels,omitempty"`
}

// AddressByLabelResult represents an address in getaddressesbylabel response.
type AddressByLabelResult struct {
	Purpose string `json:"purpose"`
}

// SubmitPackageResult is the result of the submitpackage RPC.
type SubmitPackageResult struct {
	PackageMsg           string                           `json:"package_msg"`
	TxResults            map[string]*SubmitPackageTxResult `json:"tx-results"`
	ReplacedTransactions []string                         `json:"replaced-transactions,omitempty"`
}

// SubmitPackageTxResult is the per-transaction result in submitpackage.
type SubmitPackageTxResult struct {
	TxID              string   `json:"txid"`
	WTxID             string   `json:"wtxid,omitempty"`
	VSize             int64    `json:"vsize,omitempty"`
	Fees              *TxFees  `json:"fees,omitempty"`
	Error             string   `json:"error,omitempty"`
	EffectiveFeerate  float64  `json:"effective-feerate,omitempty"`
	EffectiveIncludes []string `json:"effective-includes,omitempty"`
}

// TxFees represents fees for a transaction in submitpackage results.
type TxFees struct {
	Base float64 `json:"base"`
}

// DescriptorInfoResult represents the result of getdescriptorinfo.
type DescriptorInfoResult struct {
	Descriptor     string `json:"descriptor"`
	Checksum       string `json:"checksum"`
	IsRange        bool   `json:"isrange"`
	IsSolvable     bool   `json:"issolvable"`
	HasPrivateKeys bool   `json:"hasprivatekeys"`
}

// DeriveAddressesResult represents the result of deriveaddresses.
// It's just a list of strings, but we define this for documentation.
type DeriveAddressesResult []string

// GenerateBlockResult represents the result of generateblock.
type GenerateBlockResult struct {
	Hash string `json:"hash"`
	Hex  string `json:"hex,omitempty"`
}

// CreateWalletResult represents the result of createwallet.
type CreateWalletResult struct {
	Name     string   `json:"name"`
	Warnings []string `json:"warnings,omitempty"`
}

// LoadWalletResult represents the result of loadwallet.
type LoadWalletResult struct {
	Name     string   `json:"name"`
	Warnings []string `json:"warnings,omitempty"`
}

// UnloadWalletResult represents the result of unloadwallet.
type UnloadWalletResult struct {
	Warnings []string `json:"warnings,omitempty"`
}

// WalletDirEntry represents a wallet in listwalletdir.
type WalletDirEntry struct {
	Name     string   `json:"name"`
	Warnings []string `json:"warnings,omitempty"`
}

// ListWalletDirResult represents the result of listwalletdir.
type ListWalletDirResult struct {
	Wallets []WalletDirEntry `json:"wallets"`
}

// BIP9Stats contains statistics about the current signaling period for a BIP9 deployment.
type BIP9StatsResult struct {
	Period    int32 `json:"period"`
	Threshold int32 `json:"threshold,omitempty"`
	Elapsed   int32 `json:"elapsed"`
	Count     int32 `json:"count"`
	Possible  *bool `json:"possible,omitempty"`
}

// BIP9Info contains BIP9 deployment state information.
type BIP9Info struct {
	Bit                 *int             `json:"bit,omitempty"`
	StartTime           int64            `json:"start_time"`
	Timeout             int64            `json:"timeout"`
	MinActivationHeight int32            `json:"min_activation_height"`
	Status              string           `json:"status"`
	Since               int32            `json:"since"`
	StatusNext          string           `json:"status_next"`
	Statistics          *BIP9StatsResult `json:"statistics,omitempty"`
	Signalling          string           `json:"signalling,omitempty"`
}

// DeploymentEntry represents a single deployment in getdeploymentinfo.
type DeploymentEntry struct {
	Type   string    `json:"type"`
	Height *int32    `json:"height,omitempty"`
	Active bool      `json:"active"`
	BIP9   *BIP9Info `json:"bip9,omitempty"`
}

// DeploymentInfoResult represents the result of getdeploymentinfo.
type DeploymentInfoResult struct {
	Hash        string                     `json:"hash"`
	Height      int32                      `json:"height"`
	Deployments map[string]DeploymentEntry `json:"deployments"`
}

