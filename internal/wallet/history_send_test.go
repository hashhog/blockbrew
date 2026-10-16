package wallet

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// A wallet spend is committed to the wallet (inputs removed from the UTXO
// set, as rpc.commitWalletSend does) BEFORE the spending tx is mined. The
// block-connect scan must still attribute the debit, otherwise history gets no
// "send" entry (Core: CachedTxGetDebit works from the wallet's own txs, not
// from the live UTXO set).
func TestScanBlockRecordsSendAfterInputsCommitted(t *testing.T) {
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	})
	w.CreateFromMnemonic(testMnemonic, "")

	recv, _ := w.NewAddress()
	recvAddr, _ := address.DecodeAddress(recv, address.Mainnet)
	change, _ := w.NewChangeAddress()
	changeAddr, _ := address.DecodeAddress(change, address.Mainnet)
	foreign, _ := address.DecodeAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address.Mainnet)

	fund := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5000000000, PkScript: recvAddr.ScriptPubKey()}},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 1}, Transactions: []*wire.MsgTx{fund}}, 1)

	spend := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fund.TxHash(), Index: 0}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{
			{Value: 1000000000, PkScript: foreign.ScriptPubKey()},
			{Value: 3999990000, PkScript: changeAddr.ScriptPubKey()},
		},
	}
	// What sendtoaddress does at commit time.
	w.RemoveUTXO(spend.TxIn[0].PreviousOutPoint)

	coinbase2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5000000001, PkScript: recvAddr.ScriptPubKey()}},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 2}, Transactions: []*wire.MsgTx{coinbase2, spend}}, 2)

	var got *WalletTx
	for _, h := range w.GetHistory() {
		if h.TxHash == spend.TxHash() {
			got = h
		}
	}
	if got == nil {
		t.Fatal("no history entry for the wallet's own spend")
	}
	if !got.IsFromMe || got.Fee != 10000 {
		t.Fatalf("IsFromMe=%v Fee=%d, want true / 10000", got.IsFromMe, got.Fee)
	}
	sends := 0
	for _, d := range got.Details {
		if d.Category == "send" {
			sends++
			if d.Amount != 1000000000 {
				t.Errorf("send amount = %d, want 1000000000", d.Amount)
			}
		}
	}
	if sends != 1 {
		t.Fatalf("send details = %d, want 1 (change excluded)", sends)
	}
}
