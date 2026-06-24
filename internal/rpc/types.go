package rpc

import (
	"encoding/json"
	"strconv"
)

// JSON-RPC error codes (from Bitcoin Core).
const (
	RPCErrParseError             = -32700 // Invalid JSON was received
	RPCErrInvalidRequest         = -32600 // The JSON sent is not a valid Request object
	RPCErrMethodNotFound         = -32601 // The method does not exist
	RPCErrInvalidParams          = -32602 // Invalid method parameter(s)
	RPCErrInternal               = -32603 // Internal JSON-RPC error
	RPCErrTypeError              = -3     // Unexpected type was passed as parameter
	RPCErrInvalidAddressOrKey    = -5     // Invalid address or key
	RPCErrInvalidParameter       = -8     // Invalid, missing or duplicate parameter
	RPCErrBlockNotFound          = -5     // Block not found
	RPCErrTxNotFound             = -5     // Transaction not found
	RPCErrWalletError            = -4     // Unspecified wallet error
	RPCErrWalletNotFound         = -18    // Wallet not loaded
	RPCErrWalletNotSpecified     = -19    // Multiple wallets loaded, must specify which
	RPCErrWalletAlreadyLoaded    = -35    // Wallet is already loaded
	RPCErrDeserialization        = -22    // Error parsing or validating structure in raw format
	RPCErrVerify                 = -25    // Error during verification
	RPCErrInWarmup               = -28    // Client still warming up
	RPCErrClientNodeNotConnected = -29    // Node to disconnect not found in connected nodes
	RPCErrClientP2PDisabled      = -31    // No valid connection manager instance found (Core protocol.h:64)

	// P2P peer/ban-management error codes (Bitcoin Core protocol.h:60-63).
	// These map operator addnode/setban bad-input cases to the exact Core
	// JSON-RPC error codes so operator scripts can distinguish a duplicate
	// add / stale remove / malformed IP from a generic parameter error.
	RPCErrClientNodeAlreadyAdded  = -23 // Node is already added (addnode "add" dup)
	RPCErrClientNodeNotAdded      = -24 // Node has not been added before (addnode "remove")
	RPCErrClientInvalidIPOrSubnet = -30 // Invalid IP/Subnet (setban)
	RPCErrWallet                  = -4  // Wallet error (general)
	RPCErrMisc                    = -1  // Miscellaneous error

	// Wallet encryption-state error codes (Bitcoin Core protocol.h).
	RPCErrWalletUnlockNeeded        = -13 // Enter the wallet passphrase with walletpassphrase first
	RPCErrWalletPassphraseIncorrect = -14 // Passphrase entered was incorrect
	RPCErrWalletWrongEncState       = -15 // Wrong wallet encryption state
	RPCErrWalletEncryptionFailed    = -16 // Failed to encrypt the wallet
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
	Chain                string            `json:"chain"`
	Blocks               int32             `json:"blocks"`
	Headers              int32             `json:"headers"`
	BestBlockHash        string            `json:"bestblockhash"`
	Bits                 string            `json:"bits"`
	Target               string            `json:"target"`
	Difficulty           BitcoinDifficulty `json:"difficulty"`
	Time                 uint32            `json:"time"`
	MedianTime           int64             `json:"mediantime"`
	VerificationProgress float64           `json:"verificationprogress"`
	InitialBlockDownload bool              `json:"initialblockdownload"`
	ChainWork            string            `json:"chainwork"`
	SizeOnDisk           int64             `json:"size_on_disk"`
	Pruned               bool              `json:"pruned"`
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
	// Warnings is an ARRAY of strings in Core v31.99 (node::GetWarningsForRpc
	// returns a UniValue array; rpc/blockchain.cpp:1499). blockbrew previously
	// emitted a bare string. NOTE: softforks was REMOVED from getblockchaininfo
	// in Core v31.99 — it now lives ONLY in getdeploymentinfo
	// (blockchain.cpp:1499 getdeploymentinfo helper), so getblockchaininfo emits
	// no softforks key.
	Warnings []string `json:"warnings"`
}

// BlockResult represents a block in RPC responses.
//
// Field order mirrors Bitcoin Core's blockToJSON / blockheaderToJSON pushKV
// order (rpc/blockchain.cpp:154,202) EXACTLY, because the byte-diff harness
// checks field-emission order: hash, confirmations, height, version,
// versionHex, merkleroot, time, mediantime, nonce, bits, target, difficulty,
// chainwork, nTx, previousblockhash, nextblockhash, then the block-only tail
// strippedsize, size, weight, coinbase_tx, tx. Go marshals struct fields in
// declaration order, so the declaration order IS the wire order.
type BlockResult struct {
	Hash          string            `json:"hash"`
	Confirmations int32             `json:"confirmations"`
	Height        int32             `json:"height"`
	Version       int32             `json:"version"`
	VersionHex    string            `json:"versionHex"`
	MerkleRoot    string            `json:"merkleroot"`
	Time          uint32            `json:"time"`
	MedianTime    int64             `json:"mediantime"`
	Nonce         uint32            `json:"nonce"`
	Bits          string            `json:"bits"`
	Target        string            `json:"target"`
	Difficulty    BitcoinDifficulty `json:"difficulty"`
	ChainWork     string            `json:"chainwork"`
	NTx           int               `json:"nTx"`
	PreviousHash  string            `json:"previousblockhash,omitempty"`
	NextHash      string            `json:"nextblockhash,omitempty"`
	// Block-only tail (blockToJSON adds these after the header fields).
	StrippedSize int           `json:"strippedsize"`
	Size         int           `json:"size"`
	Weight       int           `json:"weight"`
	CoinbaseTx   interface{}   `json:"coinbase_tx,omitempty"`
	Tx           []interface{} `json:"tx"`
}

// BitcoinDifficulty is a float64 that serialises to JSON using 16
// significant digits (matching Bitcoin Core's UniValue::setFloat which
// uses std::ostringstream << std::setprecision(16)).  This ensures that
// values like 53911173001054.59 are not collapsed to the shortest
// round-trip representation (53911173001054.586) that Go's json.Marshal
// would otherwise produce.
type BitcoinDifficulty float64

// MarshalJSON emits the difficulty using the same precision as Core.
func (d BitcoinDifficulty) MarshalJSON() ([]byte, error) {
	s := strconv.FormatFloat(float64(d), 'g', 16, 64)
	return []byte(s), nil
}

// BlockHeaderResult represents a block header in RPC responses.
type BlockHeaderResult struct {
	Hash          string            `json:"hash"`
	Confirmations int32             `json:"confirmations"`
	Height        int32             `json:"height"`
	Version       int32             `json:"version"`
	VersionHex    string            `json:"versionHex"`
	MerkleRoot    string            `json:"merkleroot"`
	Time          uint32            `json:"time"`
	MedianTime    int64             `json:"mediantime"`
	Nonce         uint32            `json:"nonce"`
	Bits          string            `json:"bits"`
	Target        string            `json:"target,omitempty"`
	Difficulty    BitcoinDifficulty `json:"difficulty"`
	ChainWork     string            `json:"chainwork,omitempty"`
	NTx           int               `json:"nTx"`
	PreviousHash  string            `json:"previousblockhash,omitempty"`
	NextHash      string            `json:"nextblockhash,omitempty"`
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
	Loaded              bool    `json:"loaded"`
	Size                int     `json:"size"`
	Bytes               int64   `json:"bytes"`
	Usage               int64   `json:"usage"`
	TotalFee            float64 `json:"total_fee"`
	MaxMempool          int64   `json:"maxmempool"`
	MempoolMinFee       float64 `json:"mempoolminfee"`
	MinRelayTxFee       float64 `json:"minrelaytxfee"`
	IncrementalRelayFee float64 `json:"incrementalrelayfee"`
	UnbroadcastCount    int     `json:"unbroadcastcount"`
	FullRBF             bool    `json:"fullrbf"`
	// Core v31.99 added five fields after fullrbf (rpc/mempool.cpp:1059-1063,
	// MempoolInfoToJSON pushKV order). Emitted in Core's order, after fullrbf.
	PermitBareMultisig bool  `json:"permitbaremultisig"`
	MaxDataCarrierSize int64 `json:"maxdatacarriersize"`
	LimitClusterCount  int64 `json:"limitclustercount"`
	LimitClusterSize   int64 `json:"limitclustersize"`
	Optimal            bool  `json:"optimal"`
}

// MempoolEntry represents a mempool entry (verbose getrawmempool).
type MempoolEntry struct {
	VSize           int64    `json:"vsize"`
	Weight          int64    `json:"weight"`
	Fee             float64  `json:"fee"`
	ModifiedFee     float64  `json:"modifiedfee"`
	Time            int64    `json:"time"`
	Height          int32    `json:"height"`
	DescendantCount int      `json:"descendantcount"`
	DescendantSize  int64    `json:"descendantsize"`
	DescendantFees  float64  `json:"descendantfees"`
	AncestorCount   int      `json:"ancestorcount"`
	AncestorSize    int64    `json:"ancestorsize"`
	AncestorFees    float64  `json:"ancestorfees"`
	WTxID           string   `json:"wtxid"`
	Depends         []string `json:"depends"`
	SpentBy         []string `json:"spentby"`
	Unbroadcast     bool     `json:"unbroadcast"`
	// BIP125Replaceable mirrors Core's `bip125-replaceable` field on
	// `getmempoolentry` / `getrawmempool verbose=true`. Boolean (not the
	// {"yes","no","unknown"} string used in wallet RPCs because the entry
	// is by construction known-in-mempool). Computed by walking the tx +
	// unconfirmed mempool ancestors per BIP-125 §"Signaling implementation"
	// and short-circuiting to true when `-mempoolfullrbf=1` is in force.
	// W120 BUG-1 / FIX-68. Reference:
	// `bitcoin-core/src/rpc/mempool.cpp::MempoolEntryToJSON`.
	BIP125Replaceable bool `json:"bip125-replaceable"`
}

// PeerInfo represents peer information in RPC responses.
type PeerInfo struct {
	ID                    int              `json:"id"`
	Addr                  string           `json:"addr"`
	Network               string           `json:"network"`
	Services              string           `json:"services"`
	ServicesNames         []string         `json:"servicesnames"`
	RelayTxes             bool             `json:"relaytxes"`
	// LastInvSequence (Core m_last_inv_seq) and InvToSend (Core m_inv_to_send)
	// are emitted immediately after relaytxes and before lastsend, matching
	// Core v31.99 getpeerinfo wire order (rpc/net.cpp:243-244). blockbrew does
	// not track either value at the manager layer, so both are emitted as 0 —
	// the same convention as addr_processed/addr_rate_limited.
	LastInvSequence       int64            `json:"last_inv_sequence"`
	InvToSend             int64            `json:"inv_to_send"`
	LastSend              int64            `json:"lastsend"`
	LastRecv              int64            `json:"lastrecv"`
	LastTransaction       int64            `json:"last_transaction"`
	LastBlock             int64            `json:"last_block"`
	BytesSent             uint64           `json:"bytessent"`
	BytesRecv             uint64           `json:"bytesrecv"`
	ConnTime              int64            `json:"conntime"`
	TimeOffset            int64            `json:"timeoffset"`
	PingTime              float64          `json:"pingtime"`
	MinPing               float64          `json:"minping"`
	Version               int32            `json:"version"`
	SubVer                string           `json:"subver"`
	Inbound               bool             `json:"inbound"`
	BIP152HBTo            bool             `json:"bip152_hb_to"`
	BIP152HBFrom          bool             `json:"bip152_hb_from"`
	// Core v31.99 getpeerinfo no longer emits `startingheight` — rpc/net.cpp
	// pushes presynced_headers directly after bip152_hb_from. The legacy
	// m_starting_height was dropped from RPC output, so the field is omitted
	// here to match Core's wire shape exactly.
	PreSyncedHeaders      int32            `json:"presynced_headers"`
	SyncedHeaders         int32            `json:"synced_headers"`
	SyncedBlocks          int32            `json:"synced_blocks"`
	Inflight              []int            `json:"inflight"`
	AddrRelayEnabled      bool             `json:"addr_relay_enabled"`
	AddrProcessed         int64            `json:"addr_processed"`
	AddrRateLimited       int64            `json:"addr_rate_limited"`
	Permissions           []string         `json:"permissions"`
	MinFeeFilter          float64          `json:"minfeefilter"`
	BytesSentPerMsg       map[string]int64 `json:"bytessent_per_msg"`
	BytesRecvPerMsg       map[string]int64 `json:"bytesrecv_per_msg"`
	ConnectionType        string           `json:"connection_type"`
	TransportProtocolType string           `json:"transport_protocol_type"`
	SessionID             string           `json:"session_id"`
	// MappedAS is the Autonomous System Number for the peer's IP address,
	// derived from the loaded asmap file (0 when asmap is disabled or the
	// IP is not in the trie). Mirrors Core rpc/net.cpp:236 "mapped_as".
	MappedAS uint32 `json:"mapped_as,omitempty"`
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
	// Warnings is an ARRAY of strings in Core v31.99 (node::GetWarningsForRpc;
	// rpc/net.cpp). blockbrew previously emitted a bare string.
	Warnings []string `json:"warnings"`
}

// NetworkEntry represents a network in getnetworkinfo.
type NetworkEntry struct {
	Name                      string `json:"name"`
	Limited                   bool   `json:"limited"`
	Reachable                 bool   `json:"reachable"`
	Proxy                     string `json:"proxy"`
	ProxyRandomizeCredentials bool   `json:"proxy_randomize_credentials"`
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
// Field shape + sign conventions mirror Bitcoin Core's ListTransactions
// (src/wallet/rpc/transactions.cpp): "amount" is NEGATIVE for the "send"
// category and positive for receive/generate/immature; "fee" is NEGATIVE and
// present only on "send"; "generated"=true marks a coinbase credit.
type ListTransactionsResult struct {
	Address  string  `json:"address"`
	Category string  `json:"category"` // send / receive / generate / immature
	Amount   float64 `json:"amount"`
	// Vout is the index of the output (send/receive) this entry refers to,
	// matching Core's per-COutputEntry "vout".
	Vout uint32 `json:"vout"`
	// Fee is negative and only present on "send" entries (omitempty drops it
	// for receive/coinbase), matching Core's `ValueFromAmount(-nFee)`.
	Fee float64 `json:"fee,omitempty"`
	// Generated is true only for coinbase credits (Core only emits the key
	// when the tx is coinbase, so it is omitted otherwise).
	Generated     bool   `json:"generated,omitempty"`
	Confirmations int32  `json:"confirmations"`
	BlockHash     string `json:"blockhash,omitempty"`
	BlockTime     int64  `json:"blocktime,omitempty"`
	TxID          string `json:"txid"`
	Time          int64  `json:"time"`
	BlockHeight   int32  `json:"blockheight,omitempty"`
	// BIP125Replaceable mirrors Core's `bip125-replaceable` field on
	// `listtransactions` / `gettransaction` / `listsinceblock`. String,
	// one of {"yes","no","unknown"} (Core uses an enum: REPLACEABLE_BIP125
	// / NOT_REPLACEABLE / UNKNOWN — wallet/util:WalletTxToJSON converts to
	// these three strings). "unknown" means the txid is not in our mempool
	// (e.g. already confirmed) so we cannot walk ancestors any more. W120
	// BUG-7 / FIX-68. Reference:
	// `bitcoin-core/src/wallet/rpc/util.cpp::WalletTxToJSON`.
	BIP125Replaceable string `json:"bip125-replaceable"`
}

// GetTransactionResult is the gettransaction reply, mirroring Bitcoin Core's
// src/wallet/rpc/transactions.cpp::gettransaction. "amount" is the net effect
// on the wallet (nNet - nFee): negative for a spend, positive for a receive.
// "fee" is present (negative) only for transactions the wallet sent.
type GetTransactionResult struct {
	Amount        float64                `json:"amount"`
	Fee           float64                `json:"fee,omitempty"`
	Confirmations int32                  `json:"confirmations"`
	Generated     bool                   `json:"generated,omitempty"`
	BlockHash     string                 `json:"blockhash,omitempty"`
	BlockHeight   int32                  `json:"blockheight,omitempty"`
	BlockTime     int64                  `json:"blocktime,omitempty"`
	TxID          string                 `json:"txid"`
	Time          int64                  `json:"time"`
	TimeReceived  int64                  `json:"timereceived"`
	Details       []GetTransactionDetail `json:"details"`
	Hex           string                 `json:"hex"`
}

// GetTransactionDetail is one entry of gettransaction.details[], mirroring the
// per-COutputEntry objects Core renders via ListTransactions(fLong=false).
type GetTransactionDetail struct {
	Address  string  `json:"address"`
	Category string  `json:"category"` // send / receive / generate / immature
	Amount   float64 `json:"amount"`   // negative for "send"
	Vout     uint32  `json:"vout"`
	Fee      float64 `json:"fee,omitempty"` // negative, send only
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
// MiningInfoNext is the "next" sub-object in getmininginfo (Core 31.99).
type MiningInfoNext struct {
	Height     int32             `json:"height"`
	Bits       string            `json:"bits"`
	Difficulty BitcoinDifficulty `json:"difficulty"`
	Target     string            `json:"target"`
}

type MiningInfo struct {
	Blocks        int32             `json:"blocks"`
	Bits          string            `json:"bits"`
	Difficulty    BitcoinDifficulty `json:"difficulty"`
	Target        string            `json:"target"`
	NetworkHash   float64           `json:"networkhashps"`
	PooledTx      int               `json:"pooledtx"`
	BlockMinTxFee float64           `json:"blockmintxfee"`
	Chain         string            `json:"chain"`
	Next          MiningInfoNext    `json:"next"`
	// Warnings is an ARRAY of strings in Core v31.99 (rpc/mining.cpp:494).
	Warnings []string `json:"warnings"`
}

// DecodeScriptResult represents the result of decodescript.
type DecodeScriptResult struct {
	Asm  string `json:"asm"`
	Type string `json:"type"`
	P2SH string `json:"p2sh,omitempty"`
}

// BlockTemplateResult represents the result of getblocktemplate.
type BlockTemplateResult struct {
	Version                  int32             `json:"version"`
	Rules                    []string          `json:"rules"`
	Vbavailable              map[string]int    `json:"vbavailable"`
	Vbrequired               int               `json:"vbrequired"`
	PreviousBlockHash        string            `json:"previousblockhash"`
	Transactions             []BlockTemplateTx `json:"transactions"`
	CoinbaseAux              map[string]string `json:"coinbaseaux"`
	CoinbaseValue            int64             `json:"coinbasevalue"`
	Target                   string            `json:"target"`
	MinTime                  int64             `json:"mintime"`
	Mutable                  []string          `json:"mutable"`
	NonceRange               string            `json:"noncerange"`
	SigOpLimit               int64             `json:"sigoplimit"`
	SizeLimit                int64             `json:"sizelimit"`
	WeightLimit              int64             `json:"weightlimit"`
	CurTime                  int64             `json:"curtime"`
	Bits                     string            `json:"bits"`
	Height                   int32             `json:"height"`
	DefaultWitnessCommitment string            `json:"default_witness_commitment,omitempty"`
}

// BlockTemplateTx represents a transaction in the block template.
type BlockTemplateTx struct {
	Data    string `json:"data"`
	TxID    string `json:"txid"`
	Hash    string `json:"hash"`
	Depends []int  `json:"depends"`
	Fee     int64  `json:"fee"`
	SigOps  int64  `json:"sigops"`
	Weight  int64  `json:"weight"`
}

// BannedInfo represents a banned peer in RPC responses.
type BannedInfo struct {
	Address     string `json:"address"`
	BanCreated  int64  `json:"ban_created"`
	BannedUntil int64  `json:"banned_until"`
	BanReason   string `json:"ban_reason,omitempty"`
}

// AddressInfoResult represents the result of getaddressinfo, mirroring the
// Core v31.99 shape (bitcoin-core/src/wallet/rpc/addresses.cpp:368-513):
// labels is a PLAIN ARRAY OF LABEL-NAME STRINGS (addresses.cpp:503-508 — the
// {name,purpose} object form was removed), the top-level `label` field no
// longer exists, and iswatchonly is DEPRECATED + hardcoded false
// (addresses.cpp:383,478) — an imported watch-only descriptor address shows
// as ismine=true instead.
type AddressInfoResult struct {
	Address      string `json:"address"`
	ScriptPubKey string `json:"scriptPubKey"`
	IsMine       bool   `json:"ismine"`
	Solvable     bool   `json:"solvable"`
	// Desc / ParentDesc: the output descriptor for this address and the
	// wallet descriptor it came from (addresses.cpp:455-460, 470-476).
	Desc       string `json:"desc,omitempty"`
	ParentDesc string `json:"parent_desc,omitempty"`
	// IsWatchOnly is deprecated and always false (Core addresses.cpp:383,478).
	IsWatchOnly    bool   `json:"iswatchonly"`
	IsScript       bool   `json:"isscript"`
	IsWitness      bool   `json:"iswitness"`
	WitnessVersion *int   `json:"witness_version,omitempty"`
	WitnessProgram string `json:"witness_program,omitempty"`
	IsChange       bool   `json:"ischange"`
	// Timestamp is the descriptor-import creation time (addresses.cpp:485).
	Timestamp int64    `json:"timestamp,omitempty"`
	HDKeyPath string   `json:"hdkeypath,omitempty"`
	Labels    []string `json:"labels"`
}

// AddressByLabelResult represents an address in getaddressesbylabel response.
type AddressByLabelResult struct {
	Purpose string `json:"purpose"`
}

// SubmitPackageResult is the result of the submitpackage RPC.
type SubmitPackageResult struct {
	PackageMsg           string                            `json:"package_msg"`
	TxResults            map[string]*SubmitPackageTxResult `json:"tx-results"`
	ReplacedTransactions []string                          `json:"replaced-transactions,omitempty"`
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
//
// Mnemonic is a non-Core extension (Core's createwallet returns only
// name+warnings, bitcoin-core/src/wallet/rpc/wallet.cpp): it carries the
// freshly GENERATED BIP-39 recovery phrase exactly once, at creation, so the
// user can write the words down (W161 BUG-15/17 funds-loss fix; same
// convention as btcd/lnd). It is omitted when the caller supplied their own
// mnemonic (restore path) and for blank / watch-only wallets. The phrase is
// also persisted in the wallet file and retrievable later via the
// unlock-gated getmnemonic RPC.
type CreateWalletResult struct {
	Name     string   `json:"name"`
	Mnemonic string   `json:"mnemonic,omitempty"`
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
