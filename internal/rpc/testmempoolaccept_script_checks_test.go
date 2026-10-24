package rpc

// testmempoolaccept script checks.
//
// Core's testmempoolaccept runs the full MemPoolAccept, so PolicyScriptChecks
// (validation.cpp) refuses a transaction whose signature does not verify:
// allowed=false, reject-reason "mempool-script-verify-flag-failed (<script
// error>)" and reject-details "<reason>, input N of <txid> (wtxid <wtxid>),
// spending <prevtxid>:<n>". blockbrew's dry-run never evaluated scripts, so an
// invalid-signature parent was reported allowed with fees and vsize (core-regtest
// seed_submitpackage/invalid-sig-parent/accept). In a multi-transaction call
// Core leaves the members after the first failure unvalidated: only txid and
// wtxid (rpc/mempool.cpp exit_early / m_tx_results).

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

const tmaNullFailReason = "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"

// tmaP2PKFixture is a mempool whose UTXO view holds P2PK outputs of one key.
type tmaP2PKFixture struct {
	key  *crypto.PrivateKey
	pk   []byte
	view *consensus.InMemoryUTXOView
}

func newTMAP2PKFixture(t *testing.T) *tmaP2PKFixture {
	t.Helper()
	key, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := key.PubKey().SerializeCompressed()
	pk := append(append([]byte{byte(len(pub))}, pub...), 0xac) // <pub> OP_CHECKSIG
	return &tmaP2PKFixture{key: key, pk: pk, view: consensus.NewInMemoryUTXOView()}
}

// fund adds a confirmed P2PK coin and returns its outpoint.
func (f *tmaP2PKFixture) fund(seed byte) wire.OutPoint {
	op := wire.OutPoint{Hash: wire.Hash256{seed, 0xb0}, Index: 0}
	f.view.AddUTXO(op, &consensus.UTXOEntry{Amount: 100_000, PkScript: f.pk, Height: 10})
	return op
}

// spend builds a tx spending op to one P2WPKH output (1000 sat fee). With
// validSig false the signature is a well-formed low-S DER signature over the
// wrong message, so CHECKSIG fails and NULLFAIL (a STANDARD flag) turns the
// failure into SCRIPT_ERR_SIG_NULLFAIL, the case Core's regtest scenario hits.
func (f *tmaP2PKFixture) spend(t *testing.T, op wire.OutPoint, value int64, outSeed byte, validSig bool) *wire.MsgTx {
	t.Helper()
	tx := &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: value, PkScript: tmaP2WPKHScript(outSeed)}},
		LockTime: 0,
	}
	var msg [32]byte
	if validSig {
		h, err := script.CalcSignatureHash(f.pk, script.SigHashAll, tx, 0)
		if err != nil {
			t.Fatalf("sighash: %v", err)
		}
		msg = h
	} else {
		msg[0] = 0x42
	}
	sig, err := crypto.SignECDSA(f.key, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig = append(sig, byte(script.SigHashAll))
	tx.TxIn[0].SignatureScript = append([]byte{byte(len(sig))}, sig...)
	return tx
}

func (f *tmaP2PKFixture) server() *Server {
	cfg := mempool.DefaultConfig()
	// Regtest, as in the core-regtest scenario: segwit is active from the
	// start, so the STANDARD flags carry NULLFAIL.
	cfg.ChainParams = consensus.RegtestParams()
	cfg.ChainState = &tmaFakeChainState{height: 200, mtp: 1_600_000_000}
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mempool.New(cfg, f.view)))
}

// runTMAMulti drives handleTestMempoolAccept and returns each result as the
// JSON object a client sees, so absent keys are checked, not zero values.
func runTMAMulti(t *testing.T, srv *Server, txs ...*wire.MsgTx) []map[string]interface{} {
	t.Helper()
	hexes := make([]interface{}, len(txs))
	for i, tx := range txs {
		hexes[i] = txToHex(t, tx)
	}
	params, err := json.Marshal([]interface{}{hexes})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	res, rpcErr := srv.handleTestMempoolAccept(json.RawMessage(params))
	if rpcErr != nil {
		t.Fatalf("handleTestMempoolAccept RPC error: %+v", rpcErr)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var out []map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal result %s: %v", raw, err)
	}
	if len(out) != len(txs) {
		t.Fatalf("got %d results, want %d: %s", len(out), len(txs), raw)
	}
	return out
}

func tmaNullFailDetails(tx *wire.MsgTx) string {
	op := tx.TxIn[0].PreviousOutPoint
	return fmt.Sprintf("%s, input 0 of %s (wtxid %s), spending %s:%d",
		tmaNullFailReason, tx.TxHash().String(), tx.WTxHash().String(), op.Hash.String(), op.Index)
}

func assertScriptReject(t *testing.T, got map[string]interface{}, tx *wire.MsgTx) {
	t.Helper()
	if got["allowed"] != false {
		t.Fatalf("allowed = %v, want false: %v", got["allowed"], got)
	}
	if got["reject-reason"] != tmaNullFailReason {
		t.Fatalf("reject-reason = %q, want %q", got["reject-reason"], tmaNullFailReason)
	}
	if want := tmaNullFailDetails(tx); got["reject-details"] != want {
		t.Fatalf("reject-details = %q, want %q", got["reject-details"], want)
	}
	for _, k := range []string{"fees", "vsize"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s present on a refused tx: %v", k, got)
		}
	}
}

func TestTestMempoolAccept_InvalidSignatureRefused(t *testing.T) {
	f := newTMAP2PKFixture(t)
	tx := f.spend(t, f.fund(0x01), 99_000, 0x10, false)
	got := runTMAMulti(t, f.server(), tx)
	assertScriptReject(t, got[0], tx)
}

// Control: the same shape with a valid signature passes, so the refusal above
// is the signature and not some other gate the fixture trips.
func TestTestMempoolAccept_ValidSignatureAllowed(t *testing.T) {
	f := newTMAP2PKFixture(t)
	tx := f.spend(t, f.fund(0x02), 99_000, 0x10, true)
	got := runTMAMulti(t, f.server(), tx)[0]
	if got["allowed"] != true {
		t.Fatalf("valid tx refused: %v", got)
	}
	if _, ok := got["reject-details"]; ok {
		t.Fatalf("reject-details on an allowed tx: %v", got)
	}
}

// seed_submitpackage/invalid-sig-parent/accept: the parent fails its script
// check, the child is left unvalidated (txid and wtxid only).
func TestTestMempoolAccept_PackageInvalidSigParent(t *testing.T) {
	f := newTMAP2PKFixture(t)
	parent := f.spend(t, f.fund(0x03), 99_000, 0x10, false)
	child := &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 0}, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: 98_000, PkScript: tmaP2WPKHScript(0x20)}},
		LockTime: 0,
	}
	got := runTMAMulti(t, f.server(), parent, child)
	assertScriptReject(t, got[0], parent)
	want := map[string]interface{}{"txid": child.TxHash().String(), "wtxid": child.WTxHash().String()}
	if len(got[1]) != len(want) || got[1]["txid"] != want["txid"] || got[1]["wtxid"] != want["wtxid"] {
		t.Fatalf("member after the failure = %v, want only %v", got[1], want)
	}
}

// Control: two valid independent members are both evaluated; the early exit
// only follows a failure.
func TestTestMempoolAccept_PackageValidMembersAllEvaluated(t *testing.T) {
	f := newTMAP2PKFixture(t)
	a := f.spend(t, f.fund(0x04), 99_000, 0x10, true)
	b := f.spend(t, f.fund(0x05), 99_000, 0x11, true)
	got := runTMAMulti(t, f.server(), a, b)
	for i, r := range got {
		if r["allowed"] != true {
			t.Fatalf("member %d refused: %v", i, r)
		}
	}
}

// A valid member before an invalid one keeps its result; the invalid one is
// refused with its own txid in the details (Core PolicyScriptChecks loop keeps
// the earlier successes in m_tx_results).
func TestTestMempoolAccept_PackageInvalidSigSecondMember(t *testing.T) {
	f := newTMAP2PKFixture(t)
	a := f.spend(t, f.fund(0x06), 99_000, 0x10, true)
	b := f.spend(t, f.fund(0x07), 99_000, 0x11, false)
	got := runTMAMulti(t, f.server(), a, b)
	if got[0]["allowed"] != true {
		t.Fatalf("valid first member refused: %v", got[0])
	}
	assertScriptReject(t, got[1], b)
}
