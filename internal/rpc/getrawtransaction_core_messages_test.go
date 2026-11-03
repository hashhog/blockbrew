package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/storage"
)

// Core v31.1 rpc/rawtransaction.cpp:287,300,321-329: the not-found messages
// all end ". Use gettransaction for wallet transactions." and ParseHashV is
// called with the names "parameter 1" / "parameter 3", not "txid"/"blockhash".
const grtHint = ". Use gettransaction for wallet transactions."

func TestGetRawTransactionCoreMessages(t *testing.T) {
	const absent = "00000000000000000000000000000000000000000000000000000000000000ff"
	p := consensus.RegtestParams()
	genesis := p.GenesisBlock
	genesisHash := genesis.Header.BlockHash()

	build := func(txindex bool) *Server {
		idx := consensus.NewHeaderIndex(p)
		db := storage.NewChainDB(storage.NewMemDB())
		if err := db.StoreBlock(genesisHash, genesis); err != nil {
			t.Fatal(err)
		}
		cm := consensus.NewChainManager(consensus.ChainManagerConfig{Params: p, HeaderIndex: idx, ChainDB: db})
		mp := mempool.New(mempool.Config{MaxSize: 10_000_000, MinRelayFeeRate: 1000}, nil)
		return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", TxIndex: txindex},
			WithChainParams(p), WithHeaderIndex(idx), WithChainManager(cm),
			WithChainDB(db), WithMempool(mp))
	}

	call := func(s *Server, params ...interface{}) *RPCResponse {
		return testRPCRequest(t, s.handleRPC, "getrawtransaction", params, "", "")
	}

	t.Run("unknown-no-txindex", func(t *testing.T) {
		cblExpectError(t, call(build(false), absent), RPCErrTxNotFound,
			"No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries"+grtHint)
	})
	t.Run("unknown-txindex", func(t *testing.T) {
		cblExpectError(t, call(build(true), absent), RPCErrTxNotFound,
			"No such mempool or blockchain transaction"+grtHint)
	})
	t.Run("not-in-given-block", func(t *testing.T) {
		cblExpectError(t, call(build(false), absent, false, genesisHash.String()), RPCErrTxNotFound,
			"No such transaction found in the provided block"+grtHint)
	})
	t.Run("short-txid", func(t *testing.T) {
		cblExpectError(t, call(build(false), "00"), RPCErrInvalidParameter,
			"parameter 1 must be of length 64 (not 2, for '00')")
	})
	t.Run("short-blockhash", func(t *testing.T) {
		cblExpectError(t, call(build(false), absent, false, "00"), RPCErrInvalidParameter,
			"parameter 3 must be of length 64 (not 2, for '00')")
	})
}
