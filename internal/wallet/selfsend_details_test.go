package wallet

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// detailsFor funds a wallet, mines a spend with the given outputs and returns
// the spend's history entry plus the wallet's balance afterwards.
func detailsFor(t *testing.T, toSelf bool) (*WalletTx, int64) {
	t.Helper()
	w := NewWallet(WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	})
	w.CreateFromMnemonic(testMnemonic, "")

	recv, _ := w.NewAddress()
	recvAddr, _ := address.DecodeAddress(recv, address.Mainnet)
	second, _ := w.NewAddress()
	secondAddr, _ := address.DecodeAddress(second, address.Mainnet)
	change, _ := w.NewChangeAddress()
	changeAddr, _ := address.DecodeAddress(change, address.Mainnet)
	foreign, _ := address.DecodeAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address.Mainnet)

	fund := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 5000000000, PkScript: recvAddr.ScriptPubKey()}},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 1}, Transactions: []*wire.MsgTx{fund}}, 1)

	dest := foreign.ScriptPubKey()
	if toSelf {
		dest = secondAddr.ScriptPubKey()
	}
	spend := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fund.TxHash(), Index: 0}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{
			{Value: 100000000, PkScript: dest},
			{Value: 3999990000, PkScript: changeAddr.ScriptPubKey()},
		},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 2}, Transactions: []*wire.MsgTx{spend}}, 2)
	for _, h := range w.GetHistory() {
		if h.TxHash == spend.TxHash() {
			confirmed, _ := w.GetBalance()
			return h, confirmed
		}
	}
	t.Fatal("no history entry for the spend")
	return nil, 0
}

// Core CachedTxGetAmounts: when the wallet paid (debit > 0) every non-change
// output is a "send" line, and every owned output is ALSO a "receive" line,
// so a send-to-self shows receive +X and send -X, change is in neither.
func TestSelfSendDetailsListReceiveAndSendNotChange(t *testing.T) {
	h, bal := detailsFor(t, true)
	var sends, recvs []WalletTxDetail
	for _, d := range h.Details {
		switch d.Category {
		case "send":
			sends = append(sends, d)
		case "receive":
			recvs = append(recvs, d)
		}
	}
	if len(h.Details) != 2 || len(sends) != 1 || len(recvs) != 1 {
		t.Fatalf("details = %+v, want exactly one send and one receive", h.Details)
	}
	if sends[0].Amount != 100000000 || recvs[0].Amount != 100000000 || sends[0].Vout != 0 || recvs[0].Vout != 0 {
		t.Errorf("send=%+v receive=%+v, want both 1 BTC on vout 0", sends[0], recvs[0])
	}
	// Balance must be unaffected by detail bookkeeping: 40 BTC change + 1 BTC self-paid.
	if bal != 3999990000+100000000 {
		t.Errorf("balance = %d, want %d", bal, 3999990000+100000000)
	}
}

// Control: a send to a foreign address is unchanged (one send, no receive).
func TestForeignSendDetailsUnchanged(t *testing.T) {
	h, bal := detailsFor(t, false)
	if len(h.Details) != 1 || h.Details[0].Category != "send" || h.Details[0].Amount != 100000000 {
		t.Fatalf("details = %+v, want one send of 1 BTC", h.Details)
	}
	if bal != 3999990000 {
		t.Errorf("balance = %d, want 3999990000", bal)
	}
}
