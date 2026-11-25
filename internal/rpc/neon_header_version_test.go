package rpc

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// submitheader / submitblock must refuse a header whose nVersion breaks the
// buried BIP34/66/65 gates, before indexing it.
//
// Core: AcceptBlockHeader -> ContextualCheckBlockHeader rejects
// "bad-version(0x%08x)" (validation.cpp:4112-4118). submitheader turns that
// into JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason())
// (rpc/mining.cpp:1138-1144). On regtest BIP34/65/66 are active at height 1.

func neonHVHeader(t *testing.T, parent *consensus.BlockNode, version int32, tag byte) wire.BlockHeader {
	t.Helper()
	h := wire.BlockHeader{
		Version:    version,
		PrevBlock:  parent.Hash,
		MerkleRoot: wire.Hash256{0x4e, 0x48, 0x56, tag},
		Timestamp:  parent.Header.Timestamp + 600,
		Bits:       0x207fffff,
	}
	target := consensus.CompactToBig(h.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		h.Nonce = i
		if consensus.HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return h
		}
	}
	t.Fatalf("could not mine header")
	return h
}

func neonHVSubmitHeader(t *testing.T, s *Server, h wire.BlockHeader) (interface{}, *RPCError) {
	t.Helper()
	var w byteWriter
	if err := h.Serialize(&w); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]interface{}{hex.EncodeToString(w.bytes)})
	if err != nil {
		t.Fatal(err)
	}
	return s.handleSubmitHeader(raw)
}

func TestNeonHeaderVersionSubmitHeaderRejectsBadVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int32
		want    string
	}{
		{"v1", 1, "bad-version(0x00000001)"},
		{"v3", 3, "bad-version(0x00000003)"},
		{"neg1", -1, "bad-version(0xffffffff)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newSubmitBlockRig(t, 2)
			tipNode := rig.tips[len(rig.tips)-1]
			hdr := neonHVHeader(t, tipNode, tc.version, 1)

			res, rpcErr := neonHVSubmitHeader(t, rig.server, hdr)
			if rpcErr == nil {
				t.Fatalf("submitheader(version %d) = %v, want RPC_VERIFY_ERROR %q", tc.version, res, tc.want)
			}
			if rpcErr.Code != RPCErrVerify || rpcErr.Message != tc.want {
				t.Fatalf("submitheader(version %d) = {%d %q}, want {%d %q}",
					tc.version, rpcErr.Code, rpcErr.Message, RPCErrVerify, tc.want)
			}
			if rig.idx.GetNode(hdr.BlockHash()) != nil {
				t.Fatalf("bad-version header was indexed")
			}
		})
	}

	// Control: a version-4 header on the same tip is accepted (null).
	rig := newSubmitBlockRig(t, 2)
	tipNode := rig.tips[len(rig.tips)-1]
	good := neonHVHeader(t, tipNode, 4, 2)
	if res, rpcErr := neonHVSubmitHeader(t, rig.server, good); rpcErr != nil || res != nil {
		t.Fatalf("control: submitheader(version 4) = %v %+v, want null", res, rpcErr)
	}
	if rig.idx.GetNode(good.BlockHash()) == nil {
		t.Fatalf("control: version-4 header not indexed")
	}
}

// submitblock: Core rejects the header in AcceptBlockHeader, so the block's
// header never enters the index. The answer stays bad-version(0x...).
func TestNeonHeaderVersionSubmitBlockDoesNotIndexBadVersion(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	tipNode := rig.tips[len(rig.tips)-1]
	tipBefore, hBefore := rig.cm.BestBlock()

	blk := buildRegtestBlock(t, rig.params, tipNode)
	blk.Header.Version = 1
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); ; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock: RPC error %+v", rpcErr)
	}
	if got, _ := res.(string); got != "bad-version(0x00000001)" {
		t.Fatalf("submitblock(version 1) = %v, want \"bad-version(0x00000001)\"", res)
	}
	if rig.idx.GetNode(blk.Header.BlockHash()) != nil {
		t.Fatalf("submitblock indexed the bad-version header (Core rejects it in AcceptBlockHeader)")
	}
	if tip, h := rig.cm.BestBlock(); tip != tipBefore || h != hBefore {
		t.Fatalf("tip moved")
	}
}
