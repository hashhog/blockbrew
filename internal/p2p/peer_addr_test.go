package p2p

import (
	"net"
	"testing"
)

// Core getpeerinfo emits addrbind (the local socket address of the
// connection, rpc/net.cpp:229) and addrlocal (the address the peer reports
// seeing us at, taken from its version message addr_recv, net_processing.cpp
// SetAddrLocal(addrMe)).
func TestPeerAddrBindAndAddrLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	raw := NewInboundPeer(srv, PeerConfig{Network: MainnetMagic, ProtocolVersion: ProtocolVersion})
	// Resolved through an interface so this file also compiles (and fails by
	// name) on a base commit that lacks the accessors.
	p, ok := interface{}(raw).(interface {
		AddrBind() string
		AddrLocalString() string
	})
	if !ok {
		t.Fatal("Peer lacks AddrBind/AddrLocalString accessors for getpeerinfo addrbind/addrlocal")
	}
	if got, want := p.AddrBind(), ln.Addr().String(); got != want {
		t.Errorf("AddrBind = %q, want %q", got, want)
	}
	if got := p.AddrLocalString(); got != "" {
		t.Errorf("AddrLocal before version = %q, want empty", got)
	}

	raw.mu.Lock()
	raw.peerVersion = &MsgVersion{AddrRecv: NetAddress{IP: net.ParseIP("127.0.0.1"), Port: 18444}}
	raw.mu.Unlock()
	if got, want := p.AddrLocalString(), "127.0.0.1:18444"; got != want {
		t.Errorf("AddrLocal = %q, want %q", got, want)
	}

	// An unspecified addr_recv (0.0.0.0:0) is not valid; Core leaves it empty.
	raw.mu.Lock()
	raw.peerVersion = &MsgVersion{AddrRecv: NetAddress{IP: net.IPv4zero, Port: 0}}
	raw.mu.Unlock()
	if got := p.AddrLocalString(); got != "" {
		t.Errorf("AddrLocal for 0.0.0.0:0 = %q, want empty", got)
	}
}
