package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// submitpackage and multi-transaction testmempoolaccept decode every member
// with Core's DecodeHexTx (rpc/mempool.cpp:332, :1381), the same decoder as
// sendrawtransaction: a decoding that leaves bytes unread is a -22. Before
// the fix both package paths called MsgTx.Deserialize, which stops after the
// transaction and ignores what follows, so a member with a trailing byte was
// accepted for validation.

// strictDecodeSpendOf is a segwit tx spending tx's output 0.
func strictDecodeSpendOf(t *testing.T, hexTx string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexTx)
	if err != nil {
		t.Fatal(err)
	}
	parent := &wire.MsgTx{}
	if err := parent.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	child := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 0},
			Sequence:         0xfffffffd,
			Witness:          [][]byte{bytes.Repeat([]byte{8}, 64)},
		}},
		TxOut: []*wire.TxOut{{Value: 500, PkScript: append([]byte{0x00, 0x14}, make([]byte, 20)...)}},
	}
	var b bytes.Buffer
	if err := child.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

func TestPackageStrictDecode_SubmitPackageTrailingByte(t *testing.T) {
	parent := strictDecodeSegwitTx(t)
	child := strictDecodeSpendOf(t, parent)
	requireDecode22(t, "submitpackage", []interface{}{[]string{parent, child + "00"}})
	requireDecode22(t, "submitpackage", []interface{}{[]string{parent + "00", child}})
}

func TestPackageStrictDecode_TestMempoolAcceptPackageTrailingByte(t *testing.T) {
	parent := strictDecodeSegwitTx(t)
	child := strictDecodeSpendOf(t, parent)
	requireDecode22(t, "testmempoolaccept", []interface{}{[]string{parent, child + "00"}})
	requireDecode22(t, "testmempoolaccept", []interface{}{[]string{parent + "00", child}})
}

// Control: the same two members without the trailing byte decode, so the
// answer is not a -22 (the members then fail validation, which is fine).
func TestPackageStrictDecode_Controls(t *testing.T) {
	server := w125TestServer(t)
	parent := strictDecodeSegwitTx(t)
	child := strictDecodeSpendOf(t, parent)
	for _, method := range []string{"submitpackage", "testmempoolaccept"} {
		resp := testRPCRequest(t, server.handleRPC, method, []interface{}{[]string{parent, child}}, "", "")
		if resp.Error != nil && resp.Error.Code == RPCErrDeserialization {
			t.Fatalf("%s: well-formed package answered -22: %s", method, resp.Error.Message)
		}
	}
}
