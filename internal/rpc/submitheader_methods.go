package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// handleSubmitHeader implements the submitheader RPC.
//
//	submitheader "hexdata"
//
// Faithful port of bitcoin-core/src/rpc/mining.cpp submitheader() (:1108-1146).
// Decodes the given hexdata as an 80-byte block header and submits it as a
// candidate chain tip if valid. Throws when the header is invalid.
//
// Core semantics (byte-for-byte error parity):
//
//	DecodeHexBlockHeader fails  -> RPC_DESERIALIZATION_ERROR (-22)
//	                               "Block header decode failed"
//	parent (prevblock) unknown  -> RPC_VERIFY_ERROR          (-25)
//	                               "Must submit previous header (<prevhash>) first"
//	                               where <prevhash> is the big-endian DISPLAY hex
//	                               (Core's h.hashPrevBlock.GetHex()).
//	PoW / contextual failure    -> RPC_VERIFY_ERROR          (-25) reject reason
//	success / already-known     -> JSON null
//
// This REUSES blockbrew's existing headers-first validation + block index store
// (HeaderIndex.GetNode for the parent lookup, HeaderIndex.AddHeader for the real
// PoW + contextual validation and index insertion). No parallel validator is
// introduced — the path is identical to the one submitblock and P2P header sync
// drive (minPowChecked=false, the external-caller convention; AddHeader enforces
// the MinimumChainWork gate itself, mirroring Core validation.cpp:4229).
func (s *Server) handleSubmitHeader(params json.RawMessage) (result interface{}, rpcErr *RPCError) {
	// Recover from any panic during header decode/processing so a malformed
	// submitheader cannot crash the node (DoS vector), mirroring the
	// defer/recover guard on handleSubmitBlock.
	defer func() {
		if r := recover(); r != nil {
			result = nil
			rpcErr = &RPCError{Code: RPCErrDeserialization, Message: "Block header decode failed"}
		}
	}()

	// --- Param plumbing -----------------------------------------------------
	// Core: request.params[0].get_str(). A missing/non-string first arg is an
	// invalid-parameter error (-32602), distinct from a decode failure.
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hexdata parameter"}
	}
	hexStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "hexdata must be a string"}
	}

	// --- Step 1: decode the hex-encoded 80-byte header ----------------------
	// Core: DecodeHexBlockHeader(h, ...). Bad hex, wrong length, or trailing
	// bytes -> RPC_DESERIALIZATION_ERROR (-22) "Block header decode failed".
	header, err := decodeHexBlockHeader(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Block header decode failed"}
	}

	if s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Header index not available"}
	}

	// --- Step 2: parent-known check -----------------------------------------
	// Core: LOCK(cs_main); if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock))
	// throw RPC_VERIFY_ERROR "Must submit previous header (<prevhash>) first".
	// HeaderIndex is blockbrew's block-index analog; GetNode is LookupBlockIndex.
	// header.PrevBlock.String() renders the big-endian display hex, matching
	// Core's uint256::GetHex() byte-reversal exactly.
	if s.headerIndex.GetNode(header.PrevBlock) == nil {
		return nil, &RPCError{
			Code:    RPCErrVerify,
			Message: "Must submit previous header (" + header.PrevBlock.String() + ") first",
		}
	}

	// --- Step 3: run the header through the real validation path ------------
	// Core: chainman.ProcessNewBlockHeaders({{h}}, min_pow_checked=true, state).
	// blockbrew's equivalent is HeaderIndex.AddHeader, which performs the same
	// CheckProofOfWork + ContextualCheckBlockHeader (bad-diffbits / time-too-old /
	// timewarp / time-too-new) + checkpoint gates and inserts the validated
	// header into the index.
	//
	// minPowChecked=true: Core's submitheader passes min_pow_checked=true to
	// ProcessNewBlockHeaders (mining.cpp), so the MinimumChainWork gate is
	// SKIPPED for this trusted local-RPC submission — a low-work but otherwise
	// valid header is accepted (null), matching Core. Passing false here would
	// reject it with "too-little-chainwork", diverging from Core on mainnet/
	// testnet4 (regtest MinimumChainWork==0 masks the difference). PoW +
	// contextual checks still run regardless.
	if _, err := s.headerIndex.AddHeader(*header, true); err != nil {
		// Idempotency: a header already in the index is a no-op that returns
		// null, matching Core's ProcessNewBlockHeaders (AcceptBlockHeader returns
		// the existing index entry without error for a known header).
		if errors.Is(err, consensus.ErrDuplicateHeader) {
			return nil, nil
		}
		// All other failures are validation failures -> RPC_VERIFY_ERROR (-25)
		// with the Core reject reason string.
		return nil, &RPCError{Code: RPCErrVerify, Message: headerRejectReason(err)}
	}

	// Success: header accepted into the index -> JSON null.
	return nil, nil
}

// decodeHexBlockHeader decodes a hex string into an 80-byte block header,
// mirroring Bitcoin Core's DecodeHexBlockHeader (rpc/blockchain.cpp). It fails
// on invalid hex, a payload that is not exactly 80 bytes, or any trailing bytes
// beyond the header — all of which Core surfaces as a single "Block header
// decode failed" deserialization error.
func decodeHexBlockHeader(hexStr string) (*wire.BlockHeader, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(raw) != 80 {
		return nil, errors.New("block header is not 80 bytes")
	}
	var h wire.BlockHeader
	r := bytes.NewReader(raw)
	if err := h.Deserialize(r); err != nil {
		return nil, err
	}
	// A well-formed 80-byte header leaves no trailing bytes; Core's
	// DecodeHexBlockHeader rejects extra data via ssData.empty().
	if r.Len() != 0 {
		return nil, errors.New("extra data after block header")
	}
	return &h, nil
}

// headerRejectReason maps a HeaderIndex.AddHeader validation error to the
// canonical Bitcoin Core reject-reason string surfaced by
// ProcessNewBlockHeaders -> state.GetRejectReason(). The header-level sentinels
// are mapped explicitly (AddHeader wraps CheckProofOfWork failures as
// ErrInvalidPoW, which bip22ResultString does not recognise), then it falls
// back to bip22ResultString for any other error so the two paths stay
// consistent without a parallel mapping table.
func headerRejectReason(err error) string {
	switch {
	case errors.Is(err, consensus.ErrInvalidPoW):
		// Core CheckProofOfWork failure -> "high-hash".
		return "high-hash"
	case errors.Is(err, consensus.ErrBadDifficulty):
		return "bad-diffbits"
	case errors.Is(err, consensus.ErrTimestampTooEarly):
		return "time-too-old"
	case errors.Is(err, consensus.ErrTimestampTooFarFuture):
		return "time-too-new"
	case errors.Is(err, consensus.ErrTimeWarpAttack):
		return "time-timewarp-attack"
	case errors.Is(err, consensus.ErrTooLittleChainwork):
		return "too-little-chainwork"
	case errors.Is(err, consensus.ErrCheckpointMismatch):
		return "checkpoint mismatch"
	case errors.Is(err, consensus.ErrForkBeforeCheckpoint):
		return "bad-fork-prior-to-checkpoint"
	default:
		// bip22ResultString already maps the broader set of validation
		// sentinels to canonical short strings (and "rejected" otherwise).
		return bip22ResultString(err)
	}
}
