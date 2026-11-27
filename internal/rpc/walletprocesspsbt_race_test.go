package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// walletprocesspsbt must sign with the wallet named by the request URL, and
// only that wallet.
//
// Core (src/wallet/rpc/spend.cpp walletprocesspsbt) resolves the wallet once
// per request with GetWalletForJSONRPCRequest (src/wallet/rpc/util.cpp) and
// hands that CWallet to FillPSBT. Nothing is shared between requests, so two
// concurrent calls on /wallet/A and /wallet/B can never see each other's
// wallet.
//
// blockbrew's handleWalletProcessPSBTWithWallet used to swap the shared
// s.wallet field to the resolved wallet (no lock) and restore it in a defer,
// while handleWalletProcessPSBT re-read s.wallet for the nil check, the UTXO
// fill and the signer. Overlapping A and B calls could therefore sign an
// A-scoped request with B's keys (or fail with "Wallet not loaded" when a
// concurrent defer had restored nil).
//
// Fixture: wallets A and B, each owning one P2WPKH coin. Every request carries
// the same two-input PSBT spending A's coin (input 0) and B's coin (input 1),
// with witness_utxo attached, so the only thing that decides which input gets
// a signature is the wallet the handler signs with. An A-scoped reply must
// sign input 0 and leave input 1 bare; a B-scoped reply the reverse.

const wppRaceCalls = 200

func wppWalletRequest(t *testing.T, s *Server, walletName, method string, params interface{}) *RPCResponse {
	t.Helper()
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Errorf("marshal params: %v", err)
		return nil
	}
	body, err := json.Marshal(RPCRequest{JSONRPC: "1.0", ID: "test", Method: method, Params: paramsJSON})
	if err != nil {
		t.Errorf("marshal request: %v", err)
		return nil
	}
	req := httptest.NewRequest(http.MethodPost, "/wallet/"+walletName, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	var resp RPCResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Errorf("decode response (%s on /wallet/%s): %v", method, walletName, err)
		return nil
	}
	return &resp
}

// wppOwnedOutput gives the named wallet a fresh P2WPKH address and returns the
// TxOut paying it.
func wppOwnedOutput(t *testing.T, mgr *wallet.Manager, name string, value int64) *wire.TxOut {
	t.Helper()
	w, err := mgr.GetWallet(name)
	if err != nil {
		t.Fatalf("GetWallet(%s): %v", name, err)
	}
	addr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress(%s): %v", name, err)
	}
	decoded, err := address.DecodeAddress(addr, address.Regtest)
	if err != nil {
		t.Fatalf("DecodeAddress(%s): %v", addr, err)
	}
	return &wire.TxOut{Value: value, PkScript: decoded.ScriptPubKey()}
}

func TestWalletProcessPSBTUsesRequestWallet(t *testing.T) {
	params := consensus.RegtestParams()
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, params)
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithWalletManager(mgr),
	)
	for _, name := range []string{"A", "B"} {
		if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{name}, "", ""); resp.Error != nil {
			t.Fatalf("createwallet %s: %+v", name, resp.Error)
		}
	}

	coinA := wppOwnedOutput(t, mgr, "A", 1_0000_0000)
	coinB := wppOwnedOutput(t, mgr, "B", 2_0000_0000)

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xa1}, Index: 0}, Sequence: 0xfffffffd},
			{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xb1}, Index: 0}, Sequence: 0xfffffffd},
		},
		TxOut: []*wire.TxOut{{Value: 2_9999_0000, PkScript: []byte{0x51}}},
	}
	p, err := wallet.NewPSBT(tx)
	if err != nil {
		t.Fatalf("NewPSBT: %v", err)
	}
	p.Inputs[0].WitnessUTXO = coinA
	p.Inputs[1].WitnessUTXO = coinB
	psbtB64, err := p.EncodeBase64()
	if err != nil {
		t.Fatalf("EncodeBase64: %v", err)
	}

	// ownIdx/otherIdx: the input the request's wallet owns / does not own.
	check := func(walletName string, ownIdx, otherIdx int) error {
		resp := wppWalletRequest(t, s, walletName, "walletprocesspsbt", []interface{}{psbtB64})
		if resp == nil {
			return fmt.Errorf("/wallet/%s: no response", walletName)
		}
		if resp.Error != nil {
			return fmt.Errorf("/wallet/%s: error %+v", walletName, resp.Error)
		}
		res, ok := resp.Result.(map[string]interface{})
		if !ok {
			return fmt.Errorf("/wallet/%s: result type %T, want object", walletName, resp.Result)
		}
		out, _ := res["psbt"].(string)
		got, err := wallet.DecodePSBTBase64(out)
		if err != nil {
			return fmt.Errorf("/wallet/%s: decode returned psbt: %v", walletName, err)
		}
		signed := func(i int) bool {
			in := got.Inputs[i]
			return len(in.PartialSigs) > 0 || len(in.FinalScriptWitness) > 0 || len(in.FinalScriptSig) > 0
		}
		if signed(otherIdx) {
			return fmt.Errorf("/wallet/%s reply carries a signature for input %d, which only the other wallet owns", walletName, otherIdx)
		}
		if !signed(ownIdx) {
			return fmt.Errorf("/wallet/%s reply left its own input %d unsigned", walletName, ownIdx)
		}
		return nil
	}

	// Sequential control: each wallet alone signs exactly its own input.
	if err := check("A", 0, 1); err != nil {
		t.Fatalf("sequential control: %v", err)
	}
	if err := check("B", 1, 0); err != nil {
		t.Fatalf("sequential control: %v", err)
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		fails  []string
		start  = make(chan struct{})
		counts = map[string]int{}
	)
	for i := 0; i < wppRaceCalls; i++ {
		name, own, other := "A", 0, 1
		if i%2 == 1 {
			name, own, other = "B", 1, 0
		}
		wg.Add(1)
		go func(name string, own, other int) {
			defer wg.Done()
			<-start
			err := check(name, own, other)
			mu.Lock()
			defer mu.Unlock()
			counts[name]++
			if err != nil {
				fails = append(fails, err.Error())
			}
		}(name, own, other)
	}
	close(start)
	wg.Wait()

	if counts["A"]+counts["B"] != wppRaceCalls {
		t.Fatalf("ran %d calls, want %d", counts["A"]+counts["B"], wppRaceCalls)
	}
	if len(fails) > 0 {
		max := len(fails)
		if max > 5 {
			max = 5
		}
		t.Fatalf("%d of %d concurrent walletprocesspsbt calls used the wrong wallet; first %d:\n%v",
			len(fails), wppRaceCalls, max, fails[:max])
	}
}
