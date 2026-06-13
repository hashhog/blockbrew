package rpc

import (
	"encoding/hex"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wire"
)

// parseHashV parses a txid/blockhash argument the way Bitcoin Core's
// ParseHashV does (bitcoin-core/src/rpc/util.cpp:117). A MALFORMED hash —
// wrong length, or right length but non-hexadecimal — is rejected at the
// parse boundary with RPC_INVALID_PARAMETER (-8) and a Core-style message,
// BEFORE any chain/mempool lookup is attempted.
//
//   - wrong length:  "<name> must be of length 64 (not N, for '<hex>')"
//   - right length, non-hex: "<name> must be hexadecimal string (not '<hex>')"
//
// A well-formed 64-hex hash that simply is not found is NOT this function's
// concern — that stays a handler-level -5 (RPC_INVALID_ADDRESS_OR_KEY) or a
// null result (gettxout), exactly as in Core.
//
// name is the argument name used in the error message ("txid", "blockhash"),
// mirroring Core's ParseHashV(v, name).
func parseHashV(s string, name string) (wire.Hash256, *RPCError) {
	var h wire.Hash256
	const expectedLen = 64 // uint256::size()*2
	if len(s) != expectedLen {
		return h, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("%s must be of length %d (not %d, for '%s')", name, expectedLen, len(s), s),
		}
	}
	if _, err := hex.DecodeString(s); err != nil {
		return h, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("%s must be hexadecimal string (not '%s')", name, s),
		}
	}
	// Length-64 valid hex: delegate to the canonical (reversing) parser.
	hh, err := wire.NewHash256FromHex(s)
	if err != nil {
		// Should be unreachable given the checks above, but stay defensive
		// and keep Core's malformed-hash error code rather than leaking a
		// generic one.
		return h, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: fmt.Sprintf("%s must be hexadecimal string (not '%s')", name, s),
		}
	}
	return hh, nil
}
