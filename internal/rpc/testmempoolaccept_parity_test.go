package rpc

// testmempoolaccept false-accept parity test.
//
// handleTestMempoolAccept is a read-only (dry-run) twin of the real mempool
// accept path (mempool.AddTransactionFrom). It historically drifted and
// FALSE-ACCEPTED five classes of transaction that both Bitcoin Core and
// blockbrew's own AddTransaction reject. This test crafts one transaction per
// class and asserts the dry-run now returns allowed=false with the exact Core
// reject token:
//
//	non-final                          -> "non-final"
//	tx-size-small (CVE-2017-12842)     -> "tx-size-small"
//	per-tx sigops > 16000              -> "bad-txns-too-many-sigops"
//	nonstandard-inputs (legacy sigops) -> "bad-txns-nonstandard-inputs"
//	immature coinbase spend            -> "bad-txns-premature-spend-of-coinbase"
//
// Each case builds its own Mempool with an in-memory UTXO view (so inputs
// resolve) and a fake ChainState (so tip height / MTP drive the context-
// sensitive gates), then drives the RPC handler directly.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// tmaFakeChainState is a minimal mempool.ChainState fake: fixed tip height and
// MTP so IsFinalTx (nextHeight = tip+1) and coinbase maturity (spendHeight =
// tip+1) are deterministic.
type tmaFakeChainState struct {
	height int32
	mtp    int64
}

func (f *tmaFakeChainState) TipHeight() int32        { return f.height }
func (f *tmaFakeChainState) TipMTP() int64           { return f.mtp }
func (f *tmaFakeChainState) MTPAtHeight(int32) int64 { return f.mtp }

// tmaP2WPKHScript returns a standard, non-dust-shaped P2WPKH scriptPubKey.
func tmaP2WPKHScript(seed byte) []byte {
	s := make([]byte, 22)
	s[0] = 0x00 // OP_0
	s[1] = 0x14 // push 20
	for i := 2; i < 22; i++ {
		s[i] = seed + byte(i)
	}
	return s
}

// checksigScript returns a script of n OP_CHECKSIG bytes. Used as a prevout
// scriptPubKey to drive the BIP54 legacy-sigop gate, which counts prevout
// scriptPubKey sigops. It is not used as a scriptSig: a scriptSig that is not
// push-only (or is over 1,650 bytes) is refused by IsStandardTx before any
// sigop is counted (Core policy/policy.cpp:117-133).
func checksigScript(n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = 0xac // OP_CHECKSIG
	}
	return s
}

// bareMultisig1of3 is a standard bare 1-of-3 CHECKMULTISIG scriptPubKey. Its
// legacy (inaccurate) sigop count is 20 (MAX_PUBKEYS_PER_MULTISIG), and an
// output's scriptPubKey counts toward the per-tx sigop cost.
func bareMultisig1of3(seed byte) []byte {
	s := []byte{0x51} // OP_1
	for k := 0; k < 3; k++ {
		s = append(s, 0x21, 0x02)
		for i := 0; i < 32; i++ {
			s = append(s, seed+byte(k*32+i))
		}
	}
	return append(s, 0x53, 0xae) // OP_3 OP_CHECKMULTISIG
}

func txToHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("serialize tx: %v", err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// runTMA drives handleTestMempoolAccept for a single raw-tx hex and returns the
// single result.
func runTMA(t *testing.T, srv *Server, txHex string) *TestMempoolAcceptResult {
	t.Helper()
	params, err := json.Marshal([]interface{}{[]interface{}{txHex}})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	res, rpcErr := srv.handleTestMempoolAccept(json.RawMessage(params))
	if rpcErr != nil {
		t.Fatalf("handleTestMempoolAccept RPC error: %+v", rpcErr)
	}
	arr, ok := res.([]*TestMempoolAcceptResult)
	if !ok {
		t.Fatalf("result type %T, want []*TestMempoolAcceptResult", res)
	}
	if len(arr) != 1 {
		t.Fatalf("got %d results, want 1", len(arr))
	}
	return arr[0]
}

func TestTestMempoolAccept_FalseAcceptClasses(t *testing.T) {
	const tipHeight = int32(200) // nextHeight = 201

	cases := []struct {
		name       string
		build      func(t *testing.T) (txHex string, mp *mempool.Mempool)
		wantReason string
	}{
		{
			name:       "non-final",
			wantReason: "non-final",
			build: func(t *testing.T) (string, *mempool.Mempool) {
				// LockTime is a future block height (1000 > nextHeight 201) and the
				// single input is NOT finalized (sequence != 0xFFFFFFFF) -> IsFinalTx
				// returns false. Context-free, so no UTXO is needed to reach it.
				tx := &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
						Sequence:         0xFFFFFFFE, // not final
					}},
					TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x10)}},
					LockTime: 1000,
				}
				cfg := mempool.DefaultConfig()
				cfg.ChainState = &tmaFakeChainState{height: tipHeight, mtp: 1_600_000_000}
				mp := mempool.New(cfg, consensus.NewInMemoryUTXOView())
				return txToHex(t, tx), mp
			},
		},
		{
			name:       "tx-size-small",
			wantReason: "tx-size-small",
			build: func(t *testing.T) (string, *mempool.Mempool) {
				// 1 input + 1 tiny output -> non-witness serialization < 65 bytes.
				// tx-size-small runs before output-standardness and input lookup, so
				// the (unspendable) output and missing input are irrelevant.
				tx := &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x02}, Index: 0},
						Sequence:         0xFFFFFFFF,
					}},
					TxOut:    []*wire.TxOut{{Value: 0, PkScript: []byte{0x6a}}}, // OP_RETURN
					LockTime: 0,
				}
				cfg := mempool.DefaultConfig()
				cfg.ChainState = &tmaFakeChainState{height: tipHeight, mtp: 1_600_000_000}
				mp := mempool.New(cfg, consensus.NewInMemoryUTXOView())
				txHex := txToHex(t, tx)
				if l := len(txHex) / 2; l >= mempool.MinStandardTxNonWitnessSize {
					t.Fatalf("setup: tx is %d bytes, need < %d to trigger tx-size-small",
						l, mempool.MinStandardTxNonWitnessSize)
				}
				return txHex, mp
			},
		},
		{
			name:       "too-many-sigops",
			wantReason: "bad-txns-too-many-sigops",
			build: func(t *testing.T) (string, *mempool.Mempool) {
				// 201 bare 1-of-3 multisig outputs -> legacy sigops 201*20 =
				// 4020, scaled x4 = 16080 > MAX_STANDARD_TX_SIGOPS_COST (16000).
				// The scriptSig is empty (push-only), so IsStandardTx passes and
				// the sigop cost is what refuses it, as in Core.
				prevOut := wire.OutPoint{Hash: wire.Hash256{0x03}, Index: 0}
				tx := &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: prevOut,
						Sequence:         0xFFFFFFFF,
					}},
					LockTime: 0,
				}
				for i := 0; i < 201; i++ {
					tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 1_000, PkScript: bareMultisig1of3(byte(i))})
				}
				view := consensus.NewInMemoryUTXOView()
				view.AddUTXO(prevOut, &consensus.UTXOEntry{
					Amount:   1_000_000,
					PkScript: tmaP2WPKHScript(0x31), // non-P2SH prevout
					Height:   10,
				})
				cfg := mempool.DefaultConfig()
				cfg.ChainState = &tmaFakeChainState{height: tipHeight, mtp: 1_600_000_000}
				mp := mempool.New(cfg, view)
				return txToHex(t, tx), mp
			},
		},
		{
			name:       "nonstandard-inputs-legacy-sigops",
			wantReason: "bad-txns-nonstandard-inputs",
			build: func(t *testing.T) (string, *mempool.Mempool) {
				// The prevout scriptPubKey is 3000 OP_CHECKSIG -> legacy input
				// sigops 3000 > MAX_TX_LEGACY_SIGOPS (2500) =>
				// bad-txns-nonstandard-inputs. Prevout scriptPubKeys do not count
				// toward the per-tx sigop cost, so the too-many-sigops gate stays
				// silent (this class is reached, not shadowed). Core refuses such
				// a prevout with the same reason (AreInputsStandard). The
				// scriptSig is empty (push-only), so IsStandardTx passes.
				prevOut := wire.OutPoint{Hash: wire.Hash256{0x04}, Index: 0}
				tx := &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: prevOut,
						Sequence:         0xFFFFFFFF,
					}},
					TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x40)}},
					LockTime: 0,
				}
				view := consensus.NewInMemoryUTXOView()
				view.AddUTXO(prevOut, &consensus.UTXOEntry{
					Amount:   100_000,
					PkScript: checksigScript(3000),
					Height:   10,
				})
				cfg := mempool.DefaultConfig()
				cfg.ChainState = &tmaFakeChainState{height: tipHeight, mtp: 1_600_000_000}
				mp := mempool.New(cfg, view)
				return txToHex(t, tx), mp
			},
		},
		{
			name:       "immature-coinbase",
			wantReason: "bad-txns-premature-spend-of-coinbase",
			build: func(t *testing.T) (string, *mempool.Mempool) {
				// Spends a coinbase UTXO confirmed at height 150; spendHeight is
				// tip+1 = 201, depth = 51 < COINBASE_MATURITY (100).
				prevOut := wire.OutPoint{Hash: wire.Hash256{0x05}, Index: 0}
				tx := &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: prevOut,
						Sequence:         0xFFFFFFFF,
					}},
					TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x50)}},
					LockTime: 0,
				}
				view := consensus.NewInMemoryUTXOView()
				view.AddUTXO(prevOut, &consensus.UTXOEntry{
					Amount:     100_000,
					PkScript:   tmaP2WPKHScript(0x51),
					Height:     150,
					IsCoinbase: true,
				})
				cfg := mempool.DefaultConfig()
				cfg.ChainState = &tmaFakeChainState{height: tipHeight, mtp: 1_600_000_000}
				mp := mempool.New(cfg, view)
				return txToHex(t, tx), mp
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txHex, mp := tc.build(t)
			srv := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))
			r := runTMA(t, srv, txHex)
			if r.Allowed {
				t.Fatalf("%s: allowed=true, want false (reason should be %q)", tc.name, tc.wantReason)
			}
			if r.RejectReason != tc.wantReason {
				t.Fatalf("%s: reject-reason = %q, want %q", tc.name, r.RejectReason, tc.wantReason)
			}
		})
	}
}
