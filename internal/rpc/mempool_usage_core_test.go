package rpc

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// getmempoolinfo "usage" is Core's CTxMemPool::DynamicMemoryUsage
// (txmempool.cpp:778), the quantity -maxmempool limits. The expected values
// are what Core v31.1 regtest reported for the same transaction shapes in
// the warden_invalidated_submit group of tools/core-regtest:
//
//	maturity/tip100-info   one 1-in/1-out P2WPKH spend   usage 1176
//	usage/usage-drained    the pool emptied again         usage 64
//	usage/usage-2in2out    one 2-in/2-out P2WPKH spend    usage 1624
//
// blockbrew reported the transactions' vsize sum there (110, 0, 220).

// p2wpkhSpend builds a tx with n P2WPKH-style inputs (empty scriptSig,
// witness = 72-byte signature + 33-byte pubkey) and m P2WPKH outputs.
func p2wpkhSpend(tag byte, n, m int) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for i := 0; i < n; i++ {
		var prev wire.Hash256
		prev[0] = tag
		prev[1] = byte(i)
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prev, Index: 0},
			Witness:          [][]byte{make([]byte, 72), make([]byte, 33)},
			Sequence:         0xfffffffd,
		})
	}
	for i := 0; i < m; i++ {
		script := make([]byte, 22)
		script[0], script[1] = 0x00, 0x14
		script[2] = byte(i)
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 1000, PkScript: script})
	}
	return tx
}

func mempoolInfoUsage(t *testing.T, server *Server) int64 {
	t.Helper()
	result, rpcErr := server.handleGetMempoolInfo()
	if rpcErr != nil {
		t.Fatalf("getmempoolinfo: %v", rpcErr)
	}
	info, ok := result.(*MempoolInfo)
	if !ok {
		t.Fatalf("getmempoolinfo returned %T", result)
	}
	return info.Usage
}

func TestGetMempoolInfoUsageIsCoreDynamicMemoryUsage(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))

	if got := mempoolInfoUsage(t, server); got != 0 {
		t.Fatalf("empty pool usage = %d, want 0", got)
	}

	one := p2wpkhSpend(0x01, 1, 1)
	mempool.InjectTestEntry(mp, &mempool.TxEntry{Tx: one, TxHash: one.TxHash(), Fee: 1000, Size: 110, Time: time.Now()})
	if got := mempoolInfoUsage(t, server); got != 1176 {
		t.Fatalf("1-in/1-out P2WPKH usage = %d, want Core's 1176", got)
	}

	// Removing the last entry clears txns_randomized but keeps its
	// capacity: Core still charges MallocUsage(1 * 40) = 64.
	mp.RemoveTransaction(one.TxHash())
	if got := mempoolInfoUsage(t, server); got != 64 {
		t.Fatalf("drained pool usage = %d, want Core's 64", got)
	}

	two := p2wpkhSpend(0x02, 2, 2)
	mempool.InjectTestEntry(mp, &mempool.TxEntry{Tx: two, TxHash: two.TxHash(), Fee: 1000, Size: 220, Time: time.Now()})
	if got := mempoolInfoUsage(t, server); got != 1624 {
		t.Fatalf("2-in/2-out P2WPKH usage = %d, want Core's 1624", got)
	}
}
