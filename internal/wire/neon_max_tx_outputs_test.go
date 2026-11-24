package wire

import (
	"bytes"
	"strings"
	"testing"
)

// Bitcoin Core has no per-transaction output-count cap at deserialization:
// the vout vector is read with ReadCompactSize (MAX_SIZE = 0x02000000) and
// the only consensus bound is the block/tx weight limit (4,000,000 WU, i.e.
// a stripped size of at most 1,000,000 bytes). A minimal output is 9 bytes
// (8-byte value + 1-byte empty scriptPubKey length), so a consensus-valid
// transaction can carry roughly 111,100 outputs. These tests pin that a
// transaction with more than 100,000 such outputs deserializes.

// neonMTOTx builds a 1-input transaction with n zero-value empty-script
// outputs. The input has an empty scriptSig (41 bytes, the minimum).
func neonMTOTx(n int) *MsgTx {
	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Hash: Hash256{0x01}, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut:    make([]*TxOut, n),
		LockTime: 0,
	}
	for i := range tx.TxOut {
		tx.TxOut[i] = &TxOut{Value: 0, PkScript: nil}
	}
	return tx
}

func neonMTORoundTrip(t *testing.T, n int) {
	t.Helper()
	tx := neonMTOTx(n)
	var buf bytes.Buffer
	if err := tx.SerializeNoWitness(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// 4 version + 1 vin count + 41 input + 5 vout count + 9n + 4 locktime.
	if want := 55 + 9*n; buf.Len() != want {
		t.Fatalf("serialized size %d, want %d", buf.Len(), want)
	}
	// Stays within the consensus tx size limit (stripped size * 4 <= 4M WU).
	if buf.Len()*4 > 4_000_000 {
		t.Fatalf("test tx is not consensus-sized: %d bytes", buf.Len())
	}
	raw := buf.Bytes()

	var got MsgTx
	if err := got.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("Deserialize of consensus-valid %d-output tx failed: %v", n, err)
	}
	if len(got.TxOut) != n {
		t.Fatalf("Deserialize: got %d outputs, want %d", len(got.TxOut), n)
	}
	if got.TxHash() != tx.TxHash() {
		t.Fatalf("Deserialize: txid mismatch")
	}

	var got2 MsgTx
	if err := got2.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DeserializeNoWitness of consensus-valid %d-output tx failed: %v", n, err)
	}
	if len(got2.TxOut) != n {
		t.Fatalf("DeserializeNoWitness: got %d outputs, want %d", len(got2.TxOut), n)
	}
}

func TestNeonMaxTxOutputs100001Deserialize(t *testing.T) {
	neonMTORoundTrip(t, 100_001)
}

// 111,105 is the largest output count for which a 1-input, empty-script,
// non-witness transaction still fits the 1,000,000-byte stripped-size limit:
// 55 + 9*111,105 = 1,000,000 bytes exactly (Core CheckTransaction's
// bad-txns-oversize bound is GetSerializeSize(NO_WITNESS)*4 > 4,000,000).
func TestNeonMaxTxOutputsConsensusMaxDeserialize(t *testing.T) {
	n := (1_000_000 - 55) / 9 // 111,105
	neonMTORoundTrip(t, n)
}

// Control: the DoS bound still exists. A tx that declares far more outputs
// than any 4 MB message could carry is refused on the count alone, before any
// output is read.
func TestNeonMaxTxOutputsDoSBoundStillRejects(t *testing.T) {
	var buf bytes.Buffer
	// version
	buf.Write([]byte{1, 0, 0, 0})
	// 1 input with empty scriptSig
	buf.WriteByte(1)
	buf.Write(make([]byte, 36))
	buf.WriteByte(0)
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	// vout count = 0x01000000 (16,777,216) as a canonical 0xfe CompactSize,
	// below MAX_SIZE so only the output-count bound can refuse it.
	buf.Write([]byte{0xfe, 0x00, 0x00, 0x00, 0x01})
	// no outputs follow

	for name, fn := range map[string]func(*MsgTx) error{
		"Deserialize": func(tx *MsgTx) error {
			return tx.Deserialize(bytes.NewReader(buf.Bytes()))
		},
		"DeserializeNoWitness": func(tx *MsgTx) error {
			return tx.DeserializeNoWitness(bytes.NewReader(buf.Bytes()))
		},
	} {
		var tx MsgTx
		err := fn(&tx)
		if err == nil {
			t.Fatalf("%s: accepted a tx declaring 16,777,216 outputs with none present", name)
		}
		if !strings.Contains(err.Error(), "output count") {
			t.Fatalf("%s: want the output-count bound to refuse it, got: %v", name, err)
		}
	}
}
