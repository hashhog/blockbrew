package storage

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// A scriptPubKey of exactly MAX_SCRIPT_SIZE (10,000) bytes is spendable:
// Core's interpreter fails only script.size() > MAX_SCRIPT_SIZE
// (interpreter.cpp), and coins.cpp drops only IsUnspendable() outputs (more
// than 10,000 bytes). So a block may spend such a coin, its undo record holds
// the coin, and a reorg past that block must be able to read the record back.
//
// The compressed undo encoding stores a non-template script behind a 1-byte
// type tag, so a 10,000-byte script is 10,001 bytes on disk. The decoder
// compared that compressed length with 10,000 and refused the record, so the
// block could never be disconnected. Core bounds the RAW script length
// (compressor.h ScriptCompression::Unser: nSize - nSpecialScripts >
// MAX_SCRIPT_SIZE).

// maxSizeScript builds a bare script of exactly n bytes (n >= 3) that leaves
// OP_1 on the stack: OP_1, then 75-byte pushes each followed by OP_DROP, a
// final shorter push + OP_DROP, and OP_NOP padding. It is the night-1 R3
// trigger shape (OP_1 + 129x(PUSH75 OP_DROP) + PUSH63 OP_DROP + OP_NOP for
// n = 10,000).
func maxSizeScript(n int) []byte {
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

func undoWithScript(script []byte) *BlockUndo {
	return &BlockUndo{TxUndos: []TxUndo{{SpentCoins: []SpentCoin{{
		TxOut:  wire.TxOut{Value: 99_000, PkScript: script},
		Height: 102,
	}}}}}
}

func TestMaxSizeScriptHelperShape(t *testing.T) {
	for _, n := range []int{9_999, 10_000, 10_001} {
		if got := len(maxSizeScript(n)); got != n {
			t.Fatalf("maxSizeScript(%d) has %d bytes", n, got)
		}
	}
}

// TestBlockUndoRoundTripsMaxScriptSizeCoin is the repro: the undo record of a
// block that spent a 10,000-byte scriptPubKey must decode to the same coin.
func TestBlockUndoRoundTripsMaxScriptSizeCoin(t *testing.T) {
	script := maxSizeScript(10_000)
	got, err := DeserializeBlockUndo(undoWithScript(script).Serialize())
	if err != nil {
		t.Fatalf("undo record of a spent 10,000-byte (MAX_SCRIPT_SIZE) scriptPubKey does not decode: %v", err)
	}
	if !bytes.Equal(got.TxUndos[0].SpentCoins[0].TxOut.PkScript, script) {
		t.Fatalf("10,000-byte scriptPubKey did not round-trip through the undo record")
	}
}

// Control: one byte shorter always decoded.
func TestBlockUndoRoundTripsMaxScriptSizeMinusOneCoin(t *testing.T) {
	script := maxSizeScript(9_999)
	got, err := DeserializeBlockUndo(undoWithScript(script).Serialize())
	if err != nil {
		t.Fatalf("9,999-byte scriptPubKey undo record: %v", err)
	}
	if !bytes.Equal(got.TxUndos[0].SpentCoins[0].TxOut.PkScript, script) {
		t.Fatalf("9,999-byte scriptPubKey did not round-trip")
	}
}

// Negative control: a record whose raw script is longer than MAX_SCRIPT_SIZE
// cannot come from a block (such a coin is unspendable and never enters the
// coins view), so the decoder still refuses it as corrupt.
func TestBlockUndoRefusesOverMaxScriptSizeCoin(t *testing.T) {
	if _, err := DeserializeBlockUndo(undoWithScript(maxSizeScript(10_001)).Serialize()); err == nil {
		t.Fatalf("undo record holding a 10,001-byte scriptPubKey decoded; want a refusal")
	}
}
