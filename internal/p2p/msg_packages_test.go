package p2p

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestSendPackagesRoundTrip(t *testing.T) {
	in := &MsgSendPackages{Versions: PackageRelayVersionAncestor}
	var buf bytes.Buffer
	if err := in.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if buf.Len() != 8 {
		t.Fatalf("expected 8-byte payload, got %d", buf.Len())
	}
	out := &MsgSendPackages{}
	if err := out.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if out.Versions != in.Versions {
		t.Fatalf("versions mismatch: got %#x want %#x", out.Versions, in.Versions)
	}
	if in.Command() != "sendpackages" {
		t.Fatalf("command = %q", in.Command())
	}
}

func TestGetPkgTxnsRoundTrip(t *testing.T) {
	in := &MsgGetPkgTxns{
		WTxIDs: make([]wire.Hash256, 3),
	}
	in.WTxIDs[0][0] = 0x11
	in.WTxIDs[1][1] = 0x22
	in.WTxIDs[2][31] = 0x33

	var buf bytes.Buffer
	if err := in.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	out := &MsgGetPkgTxns{}
	if err := out.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(out.WTxIDs) != len(in.WTxIDs) {
		t.Fatalf("count mismatch: %d vs %d", len(out.WTxIDs), len(in.WTxIDs))
	}
	for i := range in.WTxIDs {
		if out.WTxIDs[i] != in.WTxIDs[i] {
			t.Fatalf("wtxid[%d] mismatch", i)
		}
	}
}

func TestGetPkgTxnsRejectsOversize(t *testing.T) {
	// Forge a payload claiming 26 wtxids — exceeds MaxGetPkgTxnsCount.
	var buf bytes.Buffer
	if err := wire.WriteCompactSize(&buf, MaxGetPkgTxnsCount+1); err != nil {
		t.Fatal(err)
	}
	out := &MsgGetPkgTxns{}
	err := out.Deserialize(&buf)
	if !errors.Is(err, ErrTooManyPkgTxns) {
		t.Fatalf("expected ErrTooManyPkgTxns, got %v", err)
	}
}

func TestPkgTxnsRoundTrip(t *testing.T) {
	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 5000, PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03}}},
	}
	tx2 := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x77}, Index: 1},
			SignatureScript:  []byte{0x52},
			Sequence:         0xFFFFFFFE,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{0xAA}}},
	}
	in := &MsgPkgTxns{Txs: []*wire.MsgTx{tx1, tx2}}

	var buf bytes.Buffer
	if err := in.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	out := &MsgPkgTxns{}
	if err := out.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(out.Txs) != 2 {
		t.Fatalf("expected 2 txs, got %d", len(out.Txs))
	}
	if out.Txs[0].TxHash() != tx1.TxHash() {
		t.Fatalf("tx0 hash mismatch")
	}
	if out.Txs[1].TxHash() != tx2.TxHash() {
		t.Fatalf("tx1 hash mismatch")
	}
}

// TestMakeMessageBIP331 ensures the global message factory recognises the new
// commands, so the read loop can dispatch them.
func TestMakeMessageBIP331(t *testing.T) {
	for _, cmd := range []string{"sendpackages", "getpkgtxns", "pkgtxns"} {
		msg, err := makeMessage(cmd)
		if err != nil {
			t.Fatalf("makeMessage(%q): %v", cmd, err)
		}
		if msg.Command() != cmd {
			t.Fatalf("makeMessage(%q): got %q", cmd, msg.Command())
		}
	}
}
