package wire

// Security finding H1: the deserializer sized slices from the count a peer
// declares, before reading a single element. A ~70-byte tx whose first input
// declares 4,000,000 witness items made Go allocate a 4,000,000-entry [][]byte
// (~92 MiB) and only then hit EOF. The TxIn, TxOut and block-transaction
// slices had the same shape (100,000 pointers, ~0.8 MiB each).
//
// Core grows these vectors in bounded steps as data actually arrives
// (serialize.h:674-675, MAX_VECTOR_ALLOCATE), so a peer has to send X bytes to
// make it allocate ~X bytes. TestSecurityWitnessAlloc_H1 pins that property,
// and pins that nothing which parsed before stops parsing: the count limits
// are unchanged, MaxWitnessItems-sized stacks of empty items still parse, a
// 32 MB item still parses, and every case round-trips byte-identically.

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// h1AllocDuring returns the heap bytes allocated while f runs.
func h1AllocDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// h1SegwitPrefix is version | marker | flag | 1 input (empty scriptSig) |
// 1 output (0 value, empty script). The witness section follows.
func h1SegwitPrefix() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, int32(2))
	b.Write([]byte{0x00, 0x01})
	b.WriteByte(0x01)
	b.Write(make([]byte, 32))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	b.WriteByte(0x00)
	binary.Write(&b, binary.LittleEndian, uint32(0xffffffff))
	b.WriteByte(0x01)
	binary.Write(&b, binary.LittleEndian, int64(0))
	b.WriteByte(0x00)
	return b.Bytes()
}

// h1WitnessTx builds a full segwit tx whose single input carries the given
// witness stack.
func h1WitnessTx(t *testing.T, count int, item []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(h1SegwitPrefix())
	if err := WriteCompactSize(&b, uint64(count)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		if err := WriteVarBytes(&b, item); err != nil {
			t.Fatal(err)
		}
	}
	binary.Write(&b, binary.LittleEndian, uint32(0)) // locktime
	return b.Bytes()
}

func h1RoundTrip(t *testing.T, raw []byte) *MsgTx {
	t.Helper()
	var tx MsgTx
	r := bytes.NewReader(raw)
	if err := tx.Deserialize(r); err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("%d trailing bytes left unread", r.Len())
	}
	var out bytes.Buffer
	if err := tx.Serialize(&out); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Equal(out.Bytes(), raw) {
		t.Fatalf("round trip differs: %d bytes in, %d bytes out", len(raw), out.Len())
	}
	return &tx
}

func TestSecurityWitnessAlloc_H1(t *testing.T) {
	const budget = 8 << 20 // 8 MiB

	t.Run("declared_4M_witness_items_then_EOF", func(t *testing.T) {
		var b bytes.Buffer
		b.Write(h1SegwitPrefix())
		if err := WriteCompactSize(&b, MaxWitnessItems); err != nil {
			t.Fatal(err)
		}
		raw := b.Bytes() // EOF: no witness item follows
		var err error
		n := h1AllocDuring(func() {
			var tx MsgTx
			err = tx.Deserialize(bytes.NewReader(raw))
		})
		if err == nil {
			t.Fatal("truncated tx declaring 4,000,000 witness items parsed without error")
		}
		if n >= budget {
			t.Fatalf("%d-byte tx declaring %d witness items allocated %d bytes (%.1f MiB) before failing; want < 8 MiB",
				len(raw), MaxWitnessItems, n, float64(n)/(1<<20))
		}
	})

	// The same defence on the other peer-sized makes. Each declared count is
	// the maximum the limits allow, followed by EOF; 64 KiB is far below the
	// 0.8 MiB a full-count pointer slice costs.
	const smallBudget = 64 << 10
	countCases := []struct {
		name  string
		raw   func() []byte
		parse func([]byte) error
	}{
		{"declared_100k_inputs_then_EOF", func() []byte {
			var b bytes.Buffer
			binary.Write(&b, binary.LittleEndian, int32(2))
			WriteCompactSize(&b, MaxTxInputs)
			return b.Bytes()
		}, func(raw []byte) error { var tx MsgTx; return tx.Deserialize(bytes.NewReader(raw)) }},
		{"declared_100k_inputs_then_EOF_nowitness", func() []byte {
			var b bytes.Buffer
			binary.Write(&b, binary.LittleEndian, int32(2))
			WriteCompactSize(&b, MaxTxInputs)
			return b.Bytes()
		}, func(raw []byte) error { var tx MsgTx; return tx.DeserializeNoWitness(bytes.NewReader(raw)) }},
		{"declared_100k_outputs_then_EOF", func() []byte {
			var b bytes.Buffer
			binary.Write(&b, binary.LittleEndian, int32(2))
			b.WriteByte(0x00) // vin count 0 => read as segwit marker
			b.WriteByte(0x01) // flag
			b.WriteByte(0x01)
			b.Write(make([]byte, 36))
			b.WriteByte(0x00)
			binary.Write(&b, binary.LittleEndian, uint32(0))
			WriteCompactSize(&b, MaxTxOutputs)
			return b.Bytes()
		}, func(raw []byte) error { var tx MsgTx; return tx.Deserialize(bytes.NewReader(raw)) }},
		{"declared_100k_outputs_then_EOF_nowitness", func() []byte {
			var b bytes.Buffer
			binary.Write(&b, binary.LittleEndian, int32(2))
			b.WriteByte(0x01)
			b.Write(make([]byte, 36))
			b.WriteByte(0x00)
			binary.Write(&b, binary.LittleEndian, uint32(0))
			WriteCompactSize(&b, MaxTxOutputs)
			return b.Bytes()
		}, func(raw []byte) error { var tx MsgTx; return tx.DeserializeNoWitness(bytes.NewReader(raw)) }},
		{"block_declared_100k_txs_then_EOF", func() []byte {
			var b bytes.Buffer
			b.Write(make([]byte, 80)) // header
			WriteCompactSize(&b, MaxBlockTransactions)
			return b.Bytes()
		}, func(raw []byte) error { var blk MsgBlock; return blk.Deserialize(bytes.NewReader(raw)) }},
	}
	for _, c := range countCases {
		t.Run(c.name, func(t *testing.T) {
			raw := c.raw()
			var err error
			n := h1AllocDuring(func() { err = c.parse(raw) })
			if err == nil {
				t.Fatal("truncated message parsed without error")
			}
			if n >= smallBudget {
				t.Fatalf("%d-byte message allocated %d bytes before failing; want < 64 KiB", len(raw), n)
			}
		})
	}

	// Nothing that parses today may stop parsing.
	t.Run("3999900_empty_items_parse_and_round_trip", func(t *testing.T) {
		tx := h1RoundTrip(t, h1WitnessTx(t, 3_999_900, nil))
		if got := len(tx.TxIn[0].Witness); got != 3_999_900 {
			t.Fatalf("witness items = %d, want 3999900", got)
		}
	})
	t.Run("MaxWitnessItems_empty_items_parse_and_round_trip", func(t *testing.T) {
		tx := h1RoundTrip(t, h1WitnessTx(t, MaxWitnessItems, nil))
		if got := len(tx.TxIn[0].Witness); got != MaxWitnessItems {
			t.Fatalf("witness items = %d, want %d", got, MaxWitnessItems)
		}
	})
	t.Run("MaxWitnessItems_plus_one_still_rejected", func(t *testing.T) {
		var b bytes.Buffer
		b.Write(h1SegwitPrefix())
		WriteCompactSize(&b, MaxWitnessItems+1)
		var tx MsgTx
		if err := tx.Deserialize(bytes.NewReader(b.Bytes())); err == nil {
			t.Fatal("witness count above MaxWitnessItems was accepted")
		}
	})
	t.Run("mainnet_761249_shape_500003_items", func(t *testing.T) {
		tx := h1RoundTrip(t, h1WitnessTx(t, 500_003, []byte{0x01}))
		if got := len(tx.TxIn[0].Witness); got != 500_003 {
			t.Fatalf("witness items = %d, want 500003", got)
		}
	})
	t.Run("single_32MB_item_parses_and_round_trips", func(t *testing.T) {
		item := bytes.Repeat([]byte{0xab}, MaxCompactSize)
		tx := h1RoundTrip(t, h1WitnessTx(t, 1, item))
		if !bytes.Equal(tx.TxIn[0].Witness[0], item) {
			t.Fatal("32 MB witness item changed in decode")
		}
	})
	t.Run("many_inputs_outputs_and_txs_round_trip", func(t *testing.T) {
		// Counts well above any initial capacity, so the append path is
		// exercised for every slice.
		mk := func(ins, outs int) *MsgTx {
			tx := &MsgTx{Version: 2}
			for i := 0; i < ins; i++ {
				tx.TxIn = append(tx.TxIn, &TxIn{
					PreviousOutPoint: OutPoint{Index: uint32(i)},
					Sequence:         uint32(i),
					Witness:          [][]byte{{byte(i)}, {}, {byte(i >> 8), 0x02}},
				})
			}
			for i := 0; i < outs; i++ {
				tx.TxOut = append(tx.TxOut, &TxOut{Value: int64(i), PkScript: []byte{byte(i)}})
			}
			return tx
		}
		tx := mk(3000, 2500)
		var raw bytes.Buffer
		if err := tx.Serialize(&raw); err != nil {
			t.Fatal(err)
		}
		got := h1RoundTrip(t, raw.Bytes())
		if len(got.TxIn) != 3000 || len(got.TxOut) != 2500 {
			t.Fatalf("ins/outs = %d/%d, want 3000/2500", len(got.TxIn), len(got.TxOut))
		}
		var nw bytes.Buffer
		if err := tx.SerializeNoWitness(&nw); err != nil {
			t.Fatal(err)
		}
		var tnw MsgTx
		if err := tnw.DeserializeNoWitness(bytes.NewReader(nw.Bytes())); err != nil {
			t.Fatal(err)
		}
		if len(tnw.TxIn) != 3000 || len(tnw.TxOut) != 2500 {
			t.Fatalf("nowitness ins/outs = %d/%d", len(tnw.TxIn), len(tnw.TxOut))
		}

		blk := &MsgBlock{}
		for i := 0; i < 2100; i++ {
			blk.Transactions = append(blk.Transactions, mk(1, 1))
		}
		var braw bytes.Buffer
		if err := blk.Serialize(&braw); err != nil {
			t.Fatal(err)
		}
		var b2 MsgBlock
		if err := b2.Deserialize(bytes.NewReader(braw.Bytes())); err != nil {
			t.Fatal(err)
		}
		var bout bytes.Buffer
		if err := b2.Serialize(&bout); err != nil {
			t.Fatal(err)
		}
		if len(b2.Transactions) != 2100 || !bytes.Equal(bout.Bytes(), braw.Bytes()) {
			t.Fatalf("block round trip: %d txs, equal=%v", len(b2.Transactions), bytes.Equal(bout.Bytes(), braw.Bytes()))
		}
	})
}
