package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// detKey returns a deterministic non-zero private key for the test.
func detKey(seed byte) *bbcrypto.PrivateKey {
	b := make([]byte, 32)
	b[31] = seed
	b[0] = 0x01 // ensure non-trivial / valid scalar
	return bbcrypto.PrivateKeyFromBytes(b)
}

// p2wpkhScript builds a native P2WPKH scriptPubKey: OP_0 <20-byte hash160(pubkey)>.
func p2wpkhScript(pub *bbcrypto.PublicKey) []byte {
	h := bbcrypto.Hash160(pub.SerializeCompressed())
	out := make([]byte, 0, 22)
	out = append(out, 0x00, 0x14)
	out = append(out, h[:]...)
	return out
}

// callSRTWK marshals args, invokes the handler, and decodes the result.
func callSRTWK(t *testing.T, args []interface{}) *SignRawTransactionResult {
	t.Helper()
	s := &Server{} // chainParams nil -> getNetwork() == Mainnet, no disk/wallet needed
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	res, rpcErr := s.handleSignRawTransactionWithKey(raw)
	if rpcErr != nil {
		t.Fatalf("handleSignRawTransactionWithKey RPC error: %d %s", rpcErr.Code, rpcErr.Message)
	}
	out, ok := res.(*SignRawTransactionResult)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	return out
}

// buildSpendTx builds an unsigned 1-or-2-input tx spending the given prevouts
// (all-zero output script OP_TRUE) and returns the tx plus its hex.
func buildSpendTx(prevHashes []wire.Hash256, vouts []uint32) (*wire.MsgTx, string) {
	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	for i := range prevHashes {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevHashes[i], Index: vouts[i]},
			Sequence:         0xffffffff,
		})
	}
	tx.TxOut = []*wire.TxOut{{Value: 90_000, PkScript: []byte{0x51}}} // OP_TRUE
	var buf bytes.Buffer
	_ = tx.Serialize(&buf)
	return tx, hex.EncodeToString(buf.Bytes())
}

// TestSignRawTransactionWithKey_P2WPKHComplete is the focused functional test:
// a raw tx spends a P2WPKH output whose key is provided via WIF; the prevtx
// (scriptPubKey + amount) is supplied. We assert complete:true and — the
// important part — re-decode the signed hex and run the produced witness
// through blockbrew's OWN script verifier against the prevout scriptPubKey,
// proving the signature is genuine over the correct BIP-143 sighash.
func TestSignRawTransactionWithKey_P2WPKHComplete(t *testing.T) {
	priv := detKey(0x11)
	pub := priv.PubKey()
	spk := p2wpkhScript(pub)

	const amountSat int64 = 100_000
	const amountBTC = 0.001 // == 100_000 sat

	// Deterministic, non-zero prevout hash so it isn't mistaken for an
	// empty/coinbase-style outpoint.
	var prevHash wire.Hash256
	for i := range prevHash {
		prevHash[i] = byte(i + 1)
	}
	const vout uint32 = 0

	_, txHex := buildSpendTx([]wire.Hash256{prevHash}, []uint32{vout})

	wif := wallet.EncodeWIF(priv, address.Mainnet, true)

	prevtx := map[string]interface{}{
		"txid":         prevHash.String(),
		"vout":         vout,
		"scriptPubKey": hex.EncodeToString(spk),
		"amount":       amountBTC,
	}

	res := callSRTWK(t, []interface{}{
		txHex,
		[]interface{}{wif},
		[]interface{}{prevtx},
	})

	if !res.Complete {
		t.Fatalf("expected complete:true, got complete:false errors=%+v", res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("expected no errors on full sign, got %+v", res.Errors)
	}

	// (b) Decode the signed tx and run it through blockbrew's own verifier.
	signedBytes, err := hex.DecodeString(res.Hex)
	if err != nil {
		t.Fatalf("signed hex decode: %v", err)
	}
	signed := &wire.MsgTx{}
	if err := signed.Deserialize(bytes.NewReader(signedBytes)); err != nil {
		t.Fatalf("signed tx deserialize: %v", err)
	}
	if len(signed.TxIn[0].Witness) == 0 {
		t.Fatalf("expected a non-empty witness after signing")
	}

	prevOut := &wire.TxOut{Value: amountSat, PkScript: spk}
	flags := script.ScriptVerifyP2SH | script.ScriptVerifyWitness | script.ScriptVerifyStrictEncoding | script.ScriptVerifyLowS
	if err := script.VerifyScript(signed.TxIn[0].SignatureScript, spk,
		signed, 0, flags, amountSat, []*wire.TxOut{prevOut}); err != nil {
		t.Fatalf("VerifyScript on signrawtransactionwithkey P2WPKH output: %v", err)
	}
}

// TestSignRawTransactionWithKey_MissingKeyIncomplete asserts that an input
// for which NO key was supplied leaves complete:false and produces an
// errors[] entry of the Core TransactionError shape ({txid, vout, scriptSig,
// sequence, error}), while the input we DO have a key for is still signed.
func TestSignRawTransactionWithKey_MissingKeyIncomplete(t *testing.T) {
	have := detKey(0x21) // we supply this key
	miss := detKey(0x22) // we deliberately do NOT supply this one

	spkHave := p2wpkhScript(have.PubKey())
	spkMiss := p2wpkhScript(miss.PubKey())

	var h0, h1 wire.Hash256
	for i := range h0 {
		h0[i] = byte(0x10 + i)
		h1[i] = byte(0x40 + i)
	}

	_, txHex := buildSpendTx([]wire.Hash256{h0, h1}, []uint32{0, 1})

	wif := wallet.EncodeWIF(have, address.Mainnet, true)

	prevtxs := []interface{}{
		map[string]interface{}{
			"txid": h0.String(), "vout": uint32(0),
			"scriptPubKey": hex.EncodeToString(spkHave), "amount": 0.001,
		},
		map[string]interface{}{
			"txid": h1.String(), "vout": uint32(1),
			"scriptPubKey": hex.EncodeToString(spkMiss), "amount": 0.002,
		},
	}

	res := callSRTWK(t, []interface{}{
		txHex,
		[]interface{}{wif}, // only the key for input 0
		prevtxs,
	})

	if res.Complete {
		t.Fatalf("expected complete:false when a key is missing")
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected exactly 1 error entry, got %d: %+v", len(res.Errors), res.Errors)
	}
	e := res.Errors[0]
	if e.TxID != h1.String() || e.Vout != 1 {
		t.Fatalf("error entry points at wrong input: %s:%d", e.TxID, e.Vout)
	}
	if e.Error == "" {
		t.Fatalf("error entry missing error string")
	}
	if e.Sequence != 0xffffffff {
		t.Fatalf("error entry sequence = %d, want 0xffffffff", e.Sequence)
	}

	// The input we DID have a key for must verify through the own verifier,
	// proving the partial-sign signed the signable input genuinely.
	signedBytes, err := hex.DecodeString(res.Hex)
	if err != nil {
		t.Fatalf("signed hex decode: %v", err)
	}
	signed := &wire.MsgTx{}
	if err := signed.Deserialize(bytes.NewReader(signedBytes)); err != nil {
		t.Fatalf("signed tx deserialize: %v", err)
	}
	prevOut0 := &wire.TxOut{Value: 100_000, PkScript: spkHave}
	prevOut1 := &wire.TxOut{Value: 200_000, PkScript: spkMiss}
	flags := script.ScriptVerifyP2SH | script.ScriptVerifyWitness | script.ScriptVerifyStrictEncoding | script.ScriptVerifyLowS
	if err := script.VerifyScript(signed.TxIn[0].SignatureScript, spkHave,
		signed, 0, flags, 100_000, []*wire.TxOut{prevOut0, prevOut1}); err != nil {
		t.Fatalf("VerifyScript on the signable (input 0) P2WPKH output: %v", err)
	}
}
