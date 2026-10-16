package wallet

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
)

// getdescriptorinfo must re-emit extended keys with the active network's
// version bytes: tpub on regtest/testnet, xpub on mainnet.
func TestGetDescriptorInfoExtendedKeyNetworkEncoding(t *testing.T) {
	master, err := NewMasterKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		net    address.Network
		prefix string
	}{
		{address.Mainnet, "xpub"},
		{address.Testnet, "tpub"},
		{address.Regtest, "tpub"},
	} {
		key := master.PublicKey().Serialize(tc.net)
		if !strings.HasPrefix(key, tc.prefix) {
			t.Fatalf("setup: %s lacks %s", key, tc.prefix)
		}
		info, err := GetDescriptorInfo("wpkh("+key+"/0/*)", tc.net)
		if err != nil {
			t.Fatalf("net %v: %v", tc.net, err)
		}
		want := "wpkh(" + key + "/0/*)#"
		if !strings.HasPrefix(info.Descriptor, want) {
			t.Errorf("net %v: descriptor %q, want prefix %q", tc.net, info.Descriptor, want)
		}
	}
}
