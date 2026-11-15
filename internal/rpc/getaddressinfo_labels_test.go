package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// getaddressinfo "labels" for a fresh getnewaddress address.
//
// Core v31.1 getaddressinfo (src/wallet/rpc/addresses.cpp) pushes the label
// of FindAddressBookEntry(dest) (allow_change=false, wallet.cpp). getnewaddress
// goes through CWallet::GetNewDestination, which always calls
// SetAddressBook(dest, label, AddressPurpose::RECEIVE), label "" by default.
// So a fresh receive address reports labels [""]; a change address (no
// address-book entry) and a foreign address report []. blockbrew returned []
// for the fresh receive address.

func labelsTestServer(t *testing.T) (*Server, *wallet.Wallet) {
	t.Helper()
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, consensus.RegtestParams())
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWalletManager(mgr),
	)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"w"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	w, err := mgr.GetWallet("w")
	if err != nil {
		t.Fatalf("GetWallet: %v", err)
	}
	return s, w
}

func addrInfoLabels(t *testing.T, s *Server, addr string) []interface{} {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, "getaddressinfo", []interface{}{addr}, "", "")
	if resp.Error != nil {
		t.Fatalf("getaddressinfo %s: %+v", addr, resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("getaddressinfo result type %T", resp.Result)
	}
	labels, ok := m["labels"].([]interface{})
	if !ok {
		t.Fatalf("labels = %#v, want an array", m["labels"])
	}
	return labels
}

func newAddressRPC(t *testing.T, s *Server) string {
	t.Helper()
	resp := testRPCRequest(t, s.handleRPC, "getnewaddress", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getnewaddress: %+v", resp.Error)
	}
	addr, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("getnewaddress result %T", resp.Result)
	}
	return addr
}

func TestGetAddressInfoLabels_NewAddressHasEmptyLabel(t *testing.T) {
	s, _ := labelsTestServer(t)
	labels := addrInfoLabels(t, s, newAddressRPC(t, s))
	if len(labels) != 1 || labels[0] != "" {
		t.Fatalf("labels = %#v, want [\"\"] (Core: getnewaddress writes an address-book entry with label \"\")", labels)
	}
}

// Controls: no address-book entry means [].
func TestGetAddressInfoLabels_ChangeAddressHasNone(t *testing.T) {
	s, w := labelsTestServer(t)
	change, err := w.NewChangeAddress()
	if err != nil {
		t.Fatalf("NewChangeAddress: %v", err)
	}
	if labels := addrInfoLabels(t, s, change); len(labels) != 0 {
		t.Fatalf("change labels = %#v, want [] (Core FindAddressBookEntry allow_change=false)", labels)
	}
}

func TestGetAddressInfoLabels_ForeignAddressHasNone(t *testing.T) {
	s, _ := labelsTestServer(t)
	if labels := addrInfoLabels(t, s, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"); len(labels) != 0 {
		t.Fatalf("foreign labels = %#v, want []", labels)
	}
}

func TestGetAddressInfoLabels_SetLabelIsListed(t *testing.T) {
	s, _ := labelsTestServer(t)
	addr := newAddressRPC(t, s)
	if resp := testRPCRequest(t, s.handleRPC, "setlabel", []interface{}{addr, "tabby"}, "", ""); resp.Error != nil {
		t.Fatalf("setlabel: %+v", resp.Error)
	}
	if labels := addrInfoLabels(t, s, addr); len(labels) != 1 || labels[0] != "tabby" {
		t.Fatalf("labels = %#v, want [\"tabby\"]", labels)
	}
}
