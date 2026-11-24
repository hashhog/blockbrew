package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// A coin whose scriptPubKey is exactly MAX_SCRIPT_SIZE (10,000) bytes is
// spendable (interpreter.cpp fails only size() > MAX_SCRIPT_SIZE) and is kept
// in the coins view (coins.cpp drops only IsUnspendable(), i.e. more than
// 10,000 bytes). CompressScript stores a non-template script behind a 1-byte
// tag, so the record holds 10,001 compressed bytes; DeserializeUTXOEntry
// compared that with 10,000 and refused the coin as "script too large". Any
// read of the flushed coin (a spend after a restart or a cache eviction,
// gettxout) then latched AbortNode in readCoin. Core bounds the RAW script
// length (compressor.h ScriptCompression::Unser).

// coinTestScript builds a bare script of exactly n bytes that leaves OP_1 on
// the stack (the night-1 R3 trigger shape for n = 10,000).
func coinTestScript(n int) []byte {
	s := []byte{0x51} // OP_1
	for n-len(s) >= 77+1 {
		s = append(s, 75)
		s = append(s, bytes.Repeat([]byte{0x01}, 75)...)
		s = append(s, 0x75) // OP_DROP
	}
	if rest := n - len(s) - 2; rest > 0 {
		push := rest
		if push > 75 {
			push = 75
		}
		s = append(s, byte(push))
		s = append(s, bytes.Repeat([]byte{0x01}, push)...)
		s = append(s, 0x75)
	}
	for len(s) < n {
		s = append(s, 0x61) // OP_NOP
	}
	return s
}

// readBackFlushedCoin adds a coin with the given script, flushes it to the
// coins DB, and reads it back through a FRESH UTXOSet on the same database
// (an empty cache, as after a restart), so the read goes through readCoin and
// DeserializeUTXOEntry.
func readBackFlushedCoin(t *testing.T, script []byte) (*UTXOEntry, bool) {
	t.Helper()
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)

	chainDB := storage.NewChainDB(storage.NewMemDB())
	op := wire.OutPoint{Hash: wire.Hash256{0xc0, 0x1d}, Index: 0}
	set := NewUTXOSet(chainDB)
	set.AddUTXO(op, &UTXOEntry{Amount: 99_000, PkScript: script, Height: 102})
	if err := set.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if IsAborted() {
		t.Fatalf("precondition: node aborted during the flush: %v", AbortReason())
	}

	restarted := NewUTXOSet(chainDB)
	got := restarted.GetUTXO(op)
	return got, IsAborted()
}

// TestCoinsDBReadsBackMaxScriptSizeCoin is the repro for the coins-DB variant.
func TestCoinsDBReadsBackMaxScriptSizeCoin(t *testing.T) {
	script := coinTestScript(MaxScriptSize)
	got, aborted := readBackFlushedCoin(t, script)
	if aborted {
		t.Fatalf("reading a flushed 10,000-byte (MAX_SCRIPT_SIZE) scriptPubKey coin latched AbortNode: %v", AbortReason())
	}
	if got == nil {
		t.Fatalf("flushed 10,000-byte scriptPubKey coin is missing after a cold read")
	}
	if !bytes.Equal(got.PkScript, script) || got.Amount != 99_000 || got.Height != 102 {
		t.Fatalf("10,000-byte scriptPubKey coin read back wrong: %d-byte script, amount %d, height %d",
			len(got.PkScript), got.Amount, got.Height)
	}
}

// Control: a 9,999-byte scriptPubKey coin always read back.
func TestCoinsDBReadsBackMaxScriptSizeMinusOneCoin(t *testing.T) {
	script := coinTestScript(MaxScriptSize - 1)
	got, aborted := readBackFlushedCoin(t, script)
	if aborted || got == nil || !bytes.Equal(got.PkScript, script) {
		t.Fatalf("9,999-byte scriptPubKey coin: got %v aborted=%v", got != nil, aborted)
	}
}

// The record codec on its own, both edges: 10,000 raw bytes decode, 10,001 do
// not. A coin longer than MAX_SCRIPT_SIZE is unspendable and never added to
// the set (IsUnspendable), so such a record can only be corruption.
func TestUTXOEntryCodecScriptLengthBound(t *testing.T) {
	ok := coinTestScript(MaxScriptSize)
	got, err := DeserializeUTXOEntry(SerializeUTXOEntry(&UTXOEntry{Amount: 1, PkScript: ok, Height: 1}))
	if err != nil {
		t.Fatalf("UTXO record with a 10,000-byte (MAX_SCRIPT_SIZE) scriptPubKey does not decode: %v", err)
	}
	if !bytes.Equal(got.PkScript, ok) {
		t.Fatalf("10,000-byte scriptPubKey did not round-trip through the UTXO record")
	}
	over := coinTestScript(MaxScriptSize + 1)
	if _, err := DeserializeUTXOEntry(SerializeUTXOEntry(&UTXOEntry{Amount: 1, PkScript: over, Height: 1})); err == nil {
		t.Fatalf("UTXO record with a 10,001-byte scriptPubKey decoded; want a refusal")
	}
}
