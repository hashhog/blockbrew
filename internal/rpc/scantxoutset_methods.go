// scantxoutset_methods.go — RPC handler for scantxoutset
//
// Reference: Bitcoin Core src/rpc/blockchain.cpp::scantxoutset.
//
// Scans the current UTXO set for outputs whose scriptPubKey matches one of the
// supplied scan objects. This is the building block for wallet recovery: a
// restored wallet can derive its scriptPubKeys and locate its coins without a
// full rescan of the block files.
//
// Supported scan objects (minimal subset of Core's descriptor language):
//
//	addr(<address>)         — outputs paying to <address>'s scriptPubKey
//	raw(<scriptPubKey-hex>) — outputs whose scriptPubKey equals these bytes
//	pkh(<pubkey-hex>)       — P2PKH for the given pubkey      (bonus)
//	wpkh(<pubkey-hex>)      — P2WPKH for the given pubkey      (bonus)
//	tr(<x-only-pubkey-hex>) — P2TR for the given x-only pubkey (bonus)
//
// xpub/range descriptors are out of scope (a follow-up). The "abort" and
// "status" actions return a success stub since this scan is synchronous and
// never leaves a background job running.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// scanTxOutUnspent is one matched UTXO in the scantxoutset result.
type scanTxOutUnspent struct {
	TxID         string    `json:"txid"`
	Vout         uint32    `json:"vout"`
	ScriptPubKey string    `json:"scriptPubKey"`
	Desc         string    `json:"desc"`
	Amount       btcAmount `json:"amount"`
	Coinbase     bool      `json:"coinbase"`
	Height       int32     `json:"height"`
}

// scanTxOutSetResult is the result of scantxoutset "start".
type scanTxOutSetResult struct {
	Success     bool               `json:"success"`
	TxOuts      uint64             `json:"txouts"`
	Height      int32              `json:"height"`
	BestBlock   string             `json:"bestblock"`
	Unspents    []scanTxOutUnspent `json:"unspents"`
	TotalAmount btcAmount          `json:"total_amount"`
}

func (s *Server) handleScanTxOutSet(params json.RawMessage) (interface{}, *RPCError) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing action parameter"}
	}

	var action string
	if err := json.Unmarshal(args[0], &action); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid action parameter"}
	}

	switch action {
	case "status":
		// No background scan ever runs (this scan is synchronous), so there
		// is never anything in progress. Core returns null in that case.
		return nil, nil
	case "abort":
		// Nothing to abort; report no-scan-was-running.
		return false, nil
	case "start":
		return s.scanTxOutSetStart(args)
	default:
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: fmt.Sprintf("Invalid action '%s'", action),
		}
	}
}

func (s *Server) scanTxOutSetStart(args []json.RawMessage) (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}
	if len(args) < 2 {
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: "scanobjects argument is required for the start action",
		}
	}

	var scanObjects []json.RawMessage
	if err := json.Unmarshal(args[1], &scanObjects); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "scanobjects must be an array"}
	}

	// Build the set of target scripts (the "needles"), keyed by hex so we can
	// match in O(1) and report the originating descriptor in the output.
	needles := make(map[string]string) // scriptPubKey-hex -> descriptor string
	for _, raw := range scanObjects {
		spk, desc, rerr := s.parseScanObject(raw)
		if rerr != nil {
			return nil, rerr
		}
		needles[hex.EncodeToString(spk)] = desc
	}

	utxoSet := s.chainMgr.UTXOSet()
	if utxoSet == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "UTXO set not available"}
	}
	us, ok := utxoSet.(*consensus.UTXOSet)
	if !ok {
		return nil, &RPCError{Code: RPCErrInternal, Message: "UTXO set type not supported for scanning"}
	}

	tipHash, tipHeight := s.chainMgr.BestBlock()

	result := &scanTxOutSetResult{
		Success:   true,
		Height:    tipHeight,
		BestBlock: tipHash.String(),
		Unspents:  []scanTxOutUnspent{},
	}
	var total int64

	count, err := us.ScanUTXOs(func(outpoint wire.OutPoint, entry *consensus.UTXOEntry) bool {
		spkHex := hex.EncodeToString(entry.PkScript)
		desc, matched := needles[spkHex]
		if !matched {
			return true
		}
		result.Unspents = append(result.Unspents, scanTxOutUnspent{
			TxID:         outpoint.Hash.String(),
			Vout:         outpoint.Index,
			ScriptPubKey: spkHex,
			Desc:         desc,
			Amount:       btcAmount(entry.Amount),
			Coinbase:     entry.IsCoinbase,
			Height:       entry.Height,
		})
		total += entry.Amount
		return true
	})
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("UTXO scan failed: %v", err)}
	}

	result.TxOuts = count
	result.TotalAmount = btcAmount(total)
	return result, nil
}

// parseScanObject parses a single scan object into its target scriptPubKey and
// a canonical descriptor string. The scan object may be a bare string
// ("addr(...)", "raw(...)", ...) or an object {"desc": "..."} (the optional
// "range" key is accepted and ignored for non-range descriptors).
func (s *Server) parseScanObject(raw json.RawMessage) ([]byte, string, *RPCError) {
	var descStr string
	// Try a bare string first.
	if err := json.Unmarshal(raw, &descStr); err != nil {
		// Fall back to the object form {"desc": "..."}.
		var obj struct {
			Desc string `json:"desc"`
		}
		if err2 := json.Unmarshal(raw, &obj); err2 != nil || obj.Desc == "" {
			return nil, "", &RPCError{
				Code:    RPCErrInvalidParams,
				Message: "Scan object must be a descriptor string or {\"desc\":...} object",
			}
		}
		descStr = obj.Desc
	}

	// Strip any descriptor checksum suffix ("#xxxxxxxx").
	if i := strings.IndexByte(descStr, '#'); i >= 0 {
		descStr = descStr[:i]
	}
	descStr = strings.TrimSpace(descStr)

	inner, ok := extractDescArg(descStr, "addr")
	if ok {
		addr, derr := address.DecodeAddress(inner, s.getNetwork())
		if derr != nil {
			return nil, "", &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid address in addr() descriptor: %v", derr),
			}
		}
		spk := addr.ScriptPubKey()
		if len(spk) == 0 {
			return nil, "", &RPCError{Code: RPCErrInvalidParams, Message: "Unsupported address type"}
		}
		return spk, descStr, nil
	}

	if inner, ok := extractDescArg(descStr, "raw"); ok {
		spk, herr := hex.DecodeString(inner)
		if herr != nil || len(spk) == 0 {
			return nil, "", &RPCError{
				Code:    RPCErrInvalidParams,
				Message: "raw() descriptor requires a non-empty hex script",
			}
		}
		return spk, descStr, nil
	}

	// Bonus single-key descriptors: pkh(), wpkh(), tr().
	if inner, ok := extractDescArg(descStr, "pkh"); ok {
		pub, herr := hex.DecodeString(inner)
		if herr != nil || (len(pub) != 33 && len(pub) != 65) {
			return nil, "", &RPCError{Code: RPCErrInvalidParams, Message: "pkh() requires a 33- or 65-byte pubkey hex"}
		}
		h160 := crypto.Hash160(pub)
		spk := address.NewP2PKHAddress(h160, s.getNetwork()).ScriptPubKey()
		return spk, descStr, nil
	}
	if inner, ok := extractDescArg(descStr, "wpkh"); ok {
		pub, herr := hex.DecodeString(inner)
		if herr != nil || len(pub) != 33 {
			return nil, "", &RPCError{Code: RPCErrInvalidParams, Message: "wpkh() requires a 33-byte compressed pubkey hex"}
		}
		h160 := crypto.Hash160(pub)
		spk := address.NewP2WPKHAddress(h160, s.getNetwork()).ScriptPubKey()
		return spk, descStr, nil
	}
	if inner, ok := extractDescArg(descStr, "tr"); ok {
		pub, herr := hex.DecodeString(inner)
		if herr != nil || len(pub) != 32 {
			return nil, "", &RPCError{Code: RPCErrInvalidParams, Message: "tr() requires a 32-byte x-only pubkey hex"}
		}
		var xonly [32]byte
		copy(xonly[:], pub)
		spk := address.NewP2TRAddress(xonly, s.getNetwork()).ScriptPubKey()
		return spk, descStr, nil
	}

	return nil, "", &RPCError{
		Code: RPCErrInvalidParams,
		Message: fmt.Sprintf(
			"Unsupported scan object %q (supported: addr(), raw(), pkh(), wpkh(), tr())", descStr),
	}
}

// extractDescArg returns the inner argument of a single-function descriptor of
// the form name(<arg>). It returns ("", false) when descStr is not a call to
// name with a single balanced-paren argument.
func extractDescArg(descStr, name string) (string, bool) {
	prefix := name + "("
	if !strings.HasPrefix(descStr, prefix) || !strings.HasSuffix(descStr, ")") {
		return "", false
	}
	inner := descStr[len(prefix) : len(descStr)-1]
	return strings.TrimSpace(inner), true
}
