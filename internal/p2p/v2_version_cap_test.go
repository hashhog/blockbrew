package p2p

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// v2VersionAttack drives the initiator side of a BIP-324 handshake against an
// inbound NegotiateTransport, up to and including the garbage terminator, then
// sends only the encrypted 3-byte length of the version packet (value
// `length`) and nothing else. It returns the number of bytes the process
// allocated between that length going out and `settle` elapsing (or the
// victim returning, whichever is first), and whether the victim returned.
//
// Bitcoin Core (net.cpp V2Transport::ProcessReceivedPacketBytes) rejects any
// length over MAX_CONTENTS_LEN in the VERSION state exactly as in APP, and
// grows the receive buffer by at most MAX_RESERVE_AHEAD (256 KiB) beyond the
// bytes actually received, so a peer cannot make it reserve memory it has
// not paid for in bandwidth.
func v2VersionAttack(t *testing.T, length uint32, settle time.Duration) (allocated uint64, returned bool, victimErr error) {
	t.Helper()
	attackerConn, victimConn := net.Pipe()
	defer attackerConn.Close()
	defer victimConn.Close()

	type result struct {
		tr  Transport
		err error
	}
	victimCh := make(chan result, 1)
	go func() {
		tr, err := NegotiateTransport(victimConn, MainnetMagic, false /* inbound */, true)
		victimCh <- result{tr, err}
	}()

	attacker, err := NewBIP324Cipher()
	if err != nil {
		t.Fatalf("attacker cipher: %v", err)
	}
	ourPub := attacker.GetOurPubKey()
	attackerConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := attackerConn.Write(ourPub[:]); err != nil {
		t.Fatalf("send pubkey: %v", err)
	}
	theirPubBytes := make([]byte, EllSwiftPubKeySize)
	if _, err := io.ReadFull(attackerConn, theirPubBytes); err != nil {
		t.Fatalf("read victim pubkey: %v", err)
	}
	var theirPub crypto.EllSwiftPubKey
	copy(theirPub[:], theirPubBytes)
	if err := attacker.InitializeWithMagic(theirPub, true, MainnetMagic); err != nil {
		t.Fatalf("attacker init: %v", err)
	}
	// Drain the victim's garbage, terminator and version packet so its send
	// goroutine never blocks on the synchronous pipe.
	go func() { _, _ = io.Copy(io.Discard, attackerConn) }()

	// Zero-length garbage: the terminator alone.
	term := attacker.GetSendGarbageTerminator()
	if _, err := attackerConn.Write(term[:]); err != nil {
		t.Fatalf("send terminator: %v", err)
	}

	// Encrypted length only, using the attacker's real length cipher so the
	// victim decrypts exactly `length`.
	plain := [LengthLen]byte{byte(length), byte(length >> 8), byte(length >> 16)}
	var enc [LengthLen]byte
	attacker.sendLCipher.Crypt(plain[:], enc[:])

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if _, err := attackerConn.Write(enc[:]); err != nil {
		t.Fatalf("send encrypted length: %v", err)
	}

	select {
	case r := <-victimCh:
		returned, victimErr = true, r.err
		if r.tr != nil {
			r.tr.Close()
		}
	case <-time.After(settle):
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, returned, victimErr
}

// TestV2VersionPacketLengthCapped: an encrypted version-packet length of
// 0xFFFFFF (16 MiB) is over the 4 MB packet cap, so the inbound handshake must
// fail at once without reserving the claimed size. Before the fix blockbrew
// applied the cap only in the APP state, allocated ~16 MiB from the
// attacker-chosen length and sat in io.ReadFull waiting for it.
func TestV2VersionPacketLengthCapped(t *testing.T) {
	allocated, returned, err := v2VersionAttack(t, 0xFFFFFF, 2*time.Second)
	if !returned {
		t.Errorf("handshake still waiting 2s after an over-cap version length; want it rejected")
	} else if err == nil {
		t.Errorf("handshake accepted an over-cap version length")
	}
	if allocated >= 1<<20 {
		t.Errorf("allocated %d bytes for a 3-byte over-cap length; want < 1 MiB", allocated)
	}
}

// TestV2VersionPacketAllocatesIncrementally: a version length that is under
// the cap (3,000,000) but whose body never arrives must not make the node
// reserve the full claimed size up front. Core reserves at most
// MAX_RESERVE_AHEAD (256 KiB) beyond what it has received.
func TestV2VersionPacketAllocatesIncrementally(t *testing.T) {
	allocated, returned, err := v2VersionAttack(t, 3_000_000, 500*time.Millisecond)
	if returned {
		t.Fatalf("handshake returned (err=%v) with no version body sent; want it waiting", err)
	}
	if allocated >= 1<<20 {
		t.Errorf("allocated %d bytes for an unpaid 3,000,000-byte version length; want < 1 MiB", allocated)
	}
}

// TestV2VersionPacketMultiChunkAccepted: a genuine version packet whose
// contents span several 256 KiB growth steps (600,000 bytes, under the cap)
// must still be read in full and decrypt, so the incremental read keeps
// byte-exact framing. A framing slip would fail the AEAD tag here.
func TestV2VersionPacketMultiChunkAccepted(t *testing.T) {
	attackerConn, victimConn := net.Pipe()
	defer attackerConn.Close()
	defer victimConn.Close()

	type result struct {
		tr  Transport
		err error
	}
	victimCh := make(chan result, 1)
	go func() {
		tr, err := NegotiateTransport(victimConn, MainnetMagic, false, true)
		victimCh <- result{tr, err}
	}()

	peer, err := NewBIP324Cipher()
	if err != nil {
		t.Fatalf("peer cipher: %v", err)
	}
	ourPub := peer.GetOurPubKey()
	attackerConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := attackerConn.Write(ourPub[:]); err != nil {
		t.Fatalf("send pubkey: %v", err)
	}
	theirPubBytes := make([]byte, EllSwiftPubKeySize)
	if _, err := io.ReadFull(attackerConn, theirPubBytes); err != nil {
		t.Fatalf("read victim pubkey: %v", err)
	}
	var theirPub crypto.EllSwiftPubKey
	copy(theirPub[:], theirPubBytes)
	if err := peer.InitializeWithMagic(theirPub, true, MainnetMagic); err != nil {
		t.Fatalf("peer init: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, attackerConn) }()

	garbage := []byte("some-garbage")
	contents := make([]byte, 600_000)
	for i := range contents {
		contents[i] = byte(i * 7)
	}
	pkt, err := peer.Encrypt(contents, garbage, false)
	if err != nil {
		t.Fatalf("encrypt version: %v", err)
	}
	term := peer.GetSendGarbageTerminator()
	wire := append(append(append([]byte{}, garbage...), term[:]...), pkt...)
	go func() { _, _ = attackerConn.Write(wire) }()

	select {
	case r := <-victimCh:
		if r.err != nil {
			t.Fatalf("valid 600,000-byte version packet rejected: %v", r.err)
		}
		if !r.tr.IsEncrypted() {
			t.Fatalf("want a v2 transport")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("handshake did not complete for a valid 600,000-byte version packet")
	}
}
