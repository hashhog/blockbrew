package consensus

import (
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// makeCoinbaseOnlyBlockWithPkScript builds a single-transaction (coinbase-only)
// block whose coinbase has one output with the supplied scriptPubKey. The merkle
// root is set correctly so the block passes CheckBlockSanity's merkle gate; PoW
// and the future-time gate are skipped via skipPOW when the block is checked.
func makeCoinbaseOnlyBlockWithPkScript(pkScript []byte) *wire.MsgBlock {
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00}, // 4-byte, height-ish push
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: pkScript}},
	}
	root, _ := CalcMerkleRootMutation([]wire.Hash256{coinbase.TxHash()})
	return &wire.MsgBlock{
		Header:       wire.BlockHeader{MerkleRoot: root},
		Transactions: []*wire.MsgTx{coinbase},
	}
}

// repeatByte returns a scriptPubKey of n copies of op (used to synthesize an
// exact legacy sigop count in the coinbase output).
func repeatByte(op byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = op
	}
	return b
}

// TestCoinbaseSigOpsCountedInBlockCap is the regression test for the BOTH-PATH
// consensus fork where a COINBASE-ONLY block with excessive coinbase sigops was
// accepted on both submitblock and P2P. The block-sigops cap in ConnectBlock's
// first-pass loop was misplaced inside the non-coinbase branch: the coinbase
// branch accumulated the coinbase's sigops then `continue`d before the cap
// check, and CheckBlockSanity had no sigops gate at all. Core catches this in
// CheckBlock (validation.cpp:3971-3977, "bad-blk-sigops"), which sums the LEGACY
// sigop count over EVERY tx INCLUDING the coinbase. The fix adds that same
// context-free cap to CheckBlockSanity, so it runs on every path.
func TestCoinbaseSigOpsCountedInBlockCap(t *testing.T) {
	powLimit := new(big.Int).Lsh(big.NewInt(1), 255) // irrelevant; PoW skipped

	tests := []struct {
		name       string
		pkScript   []byte
		wantReject bool
		// documents the legacy sigop cost (legacy count × WitnessScaleFactor)
		wantCost int
	}{
		{
			// The adversarial witness: 1001 bare OP_CHECKMULTISIG.
			// legacy (inaccurate) = 1001 × 20 = 20020; × 4 = 80080 > 80000.
			name:       "coinbase 1001x OP_CHECKMULTISIG rejects (80080)",
			pkScript:   repeatByte(script.OP_CHECKMULTISIG, 1001),
			wantReject: true,
			wantCost:   80080,
		},
		{
			// Boundary just over: 20001 OP_CHECKSIG → 20001 × 4 = 80004 > 80000.
			name:       "coinbase 20001x OP_CHECKSIG rejects (80004)",
			pkScript:   repeatByte(script.OP_CHECKSIG, 20001),
			wantReject: true,
			wantCost:   80004,
		},
		{
			// Boundary at the limit: 20000 OP_CHECKSIG → 20000 × 4 = 80000, not > 80000.
			name:       "coinbase 20000x OP_CHECKSIG accepts (80000, at limit)",
			pkScript:   repeatByte(script.OP_CHECKSIG, 20000),
			wantReject: false,
			wantCost:   80000,
		},
		{
			// Normal coinbase output — must not false-reject.
			name:       "normal coinbase-only block accepts",
			pkScript:   []byte{0x51 /* OP_1 */, script.OP_CHECKSIG}, // 1 sigop × 4 = 4
			wantReject: false,
			wantCost:   4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := makeCoinbaseOnlyBlockWithPkScript(tc.pkScript)

			// Confirm our test vector actually produces the intended cost so a
			// counting-logic change can't silently defang the boundary asserts.
			legacy := 0
			for _, txOut := range block.Transactions[0].TxOut {
				legacy += CountSigOpsInaccurate(txOut.PkScript)
			}
			for _, txIn := range block.Transactions[0].TxIn {
				legacy += CountSigOpsInaccurate(txIn.SignatureScript)
			}
			if got := legacy * WitnessScaleFactor; got != tc.wantCost {
				t.Fatalf("vector cost = %d, want %d", got, tc.wantCost)
			}

			err := CheckBlockSanity(block, powLimit, true) // skipPOW=true
			if tc.wantReject {
				if err == nil {
					t.Fatalf("CheckBlockSanity accepted a block with %d sigops cost (> %d); expected bad-blk-sigops rejection",
						tc.wantCost, MaxBlockSigOpsCost)
				}
				if !errors.Is(err, ErrSigOpsCostTooHigh) {
					t.Fatalf("rejected with wrong error: %v (want ErrSigOpsCostTooHigh)", err)
				}
			} else if err != nil {
				t.Fatalf("CheckBlockSanity rejected a valid block (%d sigops cost ≤ %d): %v",
					tc.wantCost, MaxBlockSigOpsCost, err)
			}
		})
	}
}
