package consensus

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// A block whose coinbase carries more than 100,000 minimal (9-byte) outputs is
// consensus-valid in Bitcoin Core as long as the block's stripped size stays
// within MAX_BLOCK_WEIGHT/WITNESS_SCALE_FACTOR (CheckBlock "bad-blk-length").
// Core's deserializer has no output-count cap below MAX_SIZE. These tests feed
// such a block through the wire round trip and CheckBlockSanity.

// neonMTOBlock builds a regtest block whose only transaction is a coinbase
// with n zero-value empty-script outputs, and mines it.
//
// Stripped size: 80 header + 1 tx count + 4 version + 1 vin count +
// 43 coinbase input (36 prevout + 1 len + 2 scriptSig + 4 sequence) +
// 5 vout count + 9n + 4 locktime = 138 + 9n bytes.
func neonMTOBlock(t *testing.T, params *ChainParams, n int) *wire.MsgBlock {
	t.Helper()
	cb := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
			SignatureScript:  []byte{0x51, 0x51},
			Sequence:         0xffffffff,
		}},
		TxOut: make([]*wire.TxOut, n),
	}
	for i := range cb.TxOut {
		cb.TxOut[i] = &wire.TxOut{Value: 0}
	}
	blk := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x20000000,
			PrevBlock:  params.GenesisHash,
			MerkleRoot: CalcMerkleRoot([]wire.Hash256{cb.TxHash()}),
			Timestamp:  uint32(time.Now().Unix()),
			Bits:       params.PowLimitBits,
		},
		Transactions: []*wire.MsgTx{cb},
	}
	for nonce := uint32(0); ; nonce++ {
		blk.Header.Nonce = nonce
		if CheckProofOfWork(blk.Header.BlockHash(), blk.Header.Bits, params.PowLimit) == nil {
			break
		}
	}
	return blk
}

func neonMTOWireRoundTrip(t *testing.T, blk *wire.MsgBlock, wantSize int) *wire.MsgBlock {
	t.Helper()
	var buf bytes.Buffer
	if err := blk.Serialize(&buf); err != nil {
		t.Fatalf("serialize block: %v", err)
	}
	if buf.Len() != wantSize {
		t.Fatalf("serialized block size %d, want %d", buf.Len(), wantSize)
	}
	var got wire.MsgBlock
	if err := got.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("block Deserialize failed for a %d-byte block with a %d-output coinbase: %v",
			buf.Len(), len(blk.Transactions[0].TxOut), err)
	}
	if got.Header.BlockHash() != blk.Header.BlockHash() {
		t.Fatalf("block hash changed across the round trip")
	}
	return &got
}

func TestNeonMaxTxOutputsBlock100001Outputs(t *testing.T) {
	params := RegtestParams()
	const n = 100_001
	blk := neonMTOBlock(t, params, n)
	got := neonMTOWireRoundTrip(t, blk, 138+9*n)
	if err := CheckBlockSanity(got, params.PowLimit); err != nil {
		t.Fatalf("CheckBlockSanity rejected a consensus-valid block: %v", err)
	}
}

// The largest such block that still fits: 138 + 9*111,095 = 999,993 bytes.
func TestNeonMaxTxOutputsBlockConsensusMax(t *testing.T) {
	params := RegtestParams()
	const n = (1_000_000 - 138) / 9 // 111,095
	blk := neonMTOBlock(t, params, n)
	got := neonMTOWireRoundTrip(t, blk, 138+9*n)
	if w := CalcStrippedBlockWeight(got); w > MaxBlockWeight {
		t.Fatalf("test block is not consensus-sized: stripped weight %d", w)
	}
	if err := CheckBlockSanity(got, params.PowLimit); err != nil {
		t.Fatalf("CheckBlockSanity rejected a consensus-valid block: %v", err)
	}
}

// Control: one more output pushes the block to 1,000,002 bytes stripped. It
// must still deserialize (the wire layer is not the consensus bound) and then
// be rejected by the size gate, exactly like Core's bad-blk-length.
func TestNeonMaxTxOutputsBlockOneOverRejectedBySizeGate(t *testing.T) {
	params := RegtestParams()
	const n = (1_000_000-138)/9 + 1 // 111,096
	blk := neonMTOBlock(t, params, n)
	got := neonMTOWireRoundTrip(t, blk, 138+9*n)
	err := CheckBlockSanity(got, params.PowLimit)
	if !errors.Is(err, ErrBlockLengthTooHigh) {
		t.Fatalf("want ErrBlockLengthTooHigh (bad-blk-length), got: %v", err)
	}
}
