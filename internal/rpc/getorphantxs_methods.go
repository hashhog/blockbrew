package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
)

// handleGetOrphanTxs implements the `getorphantxs` JSON-RPC method, mirroring
// Bitcoin Core's rpc/mempool.cpp::getorphantxs (added in Core v28; marked
// EXPERIMENTAL — "this call may be changed in future releases"). It shows the
// transactions currently parked in the tx orphanage (txs received with one or
// more missing parents, awaiting their inputs).
//
// Arg: optional `verbosity`, integer, default 0. Valid values are 0, 1, 2.
// Core parses it with ParseVerbosity(..., allow_bool=false), so a BOOLEAN
// argument is rejected (not coerced to 0/1) — unlike the verbose RPCs.
//
//   - verbosity 0: a JSON array of txid strings (one per orphan). Core uses the
//     non-witness txid (orphan.tx->GetHash()), so we do the same: tx.TxHash().
//   - verbosity 1: a JSON array of objects with tx details — txid, wtxid, bytes
//     (the full BIP144 witness-serialized size), vsize (BIP141 virtual size),
//     weight (BIP141 weight) and from (the array of announcing peers). Mirrors
//     OrphanToJSON + OrphanDescription in rpc/mempool.cpp.
//   - verbosity 2: the verbosity-1 object PLUS a `hex` field holding the
//     serialized, hex-encoded transaction. Mirrors Core's verbosity-2 arm,
//     which appends o.pushKV("hex", EncodeHexTx(*orphan.tx)).
//
// Invalid verbosity (outside 0..2) -> RPC_INVALID_PARAMETER (-8) with Core's
// message "Invalid verbosity value <n>".
//
// from array: Core emits numeric peer ids (orphan.announcers, a std::set<NodeId>
// populated by AddTx/AddAnnouncer). blockbrew tracks a single announcer per
// orphan as a peer *address string* (orphanEntry.fromPeer, recorded by
// AddTransactionFrom from the P2P tx handler — see RemoveOrphansForPeer /
// txorphanage.cpp::EraseForPeer). So `from` is a 1-element array of the
// announcing peer's address when known, and an empty array for
// locally-originated / RPC / reorg-re-added orphans (fromPeer==""). This is a
// best-effort rendering of the same concept; see from_peer_source.
func (s *Server) handleGetOrphanTxs(params json.RawMessage) (interface{}, *RPCError) {
	// Default verbosity 0. Core parses this with
	// ParseVerbosity(request.params[0], default_verbosity=0, allow_bool=false):
	// the argument is an integer, and a BOOLEAN argument is REJECTED with a type
	// error (it is NOT silently mapped to 0/1, unlike the verbose RPCs that pass
	// allow_bool=true). We mirror that: integer (or stringified integer) only;
	// a bool argument errors.
	verbosity := 0
	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil && len(args) >= 1 {
			switch v := args[0].(type) {
			case float64:
				verbosity = int(v)
			case bool:
				// Core's ParseVerbosity(allow_bool=false) throws RPC_TYPE_ERROR
				// for a boolean argument rather than coercing it to 0/1
				// (rpc/util.cpp:88). Mirror the exact code (-3) and message.
				return nil, &RPCError{
					Code:    RPCErrTypeError,
					Message: "Verbosity was boolean but only integer allowed",
				}
			case string:
				// Tolerate a stringified integer (e.g. CLI passes "2").
				switch v {
				case "0":
					verbosity = 0
				case "1":
					verbosity = 1
				case "2":
					verbosity = 2
				default:
					return nil, &RPCError{
						Code:    RPCErrInvalidParameter,
						Message: "Invalid verbosity value " + v,
					}
				}
			}
		}
	}

	if verbosity < 0 || verbosity > 2 {
		return nil, &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: "Invalid verbosity value " + strconv.Itoa(verbosity),
		}
	}

	ret := make([]interface{}, 0)
	if s.mempool == nil {
		return ret, nil
	}

	orphans := s.mempool.GetOrphanTransactions()

	switch verbosity {
	case 0:
		for _, orphan := range orphans {
			ret = append(ret, orphan.Tx.TxHash().String())
		}
	case 1:
		for _, orphan := range orphans {
			ret = append(ret, orphanToJSON(orphan))
		}
	case 2:
		for _, orphan := range orphans {
			o := orphanToJSON(orphan)
			var buf bytes.Buffer
			if err := orphan.Tx.Serialize(&buf); err != nil {
				return nil, &RPCError{
					Code:    RPCErrInternal,
					Message: "Failed to serialize orphan transaction: " + err.Error(),
				}
			}
			o["hex"] = hex.EncodeToString(buf.Bytes())
			ret = append(ret, o)
		}
	}

	return ret, nil
}

// orphanToJSON renders a single orphan-pool entry as the verbosity-1 object,
// matching Bitcoin Core rpc/mempool.cpp::OrphanToJSON. bytes = full witness
// serialized size (ComputeTotalSize / GetSerializeSize(TX_WITH_WITNESS)); vsize
// = (weight+3)/4 (the same idiom getmempoolentry/testmempoolaccept use here);
// weight = BIP141 transaction weight. `from` is the announcing-peer array.
func orphanToJSON(orphan mempool.OrphanTxInfo) map[string]interface{} {
	tx := orphan.Tx

	var buf bytes.Buffer
	_ = tx.Serialize(&buf)
	totalSize := buf.Len()

	weight := consensus.CalcTxWeight(tx)
	vsize := (weight + 3) / 4

	from := make([]interface{}, 0, len(orphan.Announcers))
	for _, peer := range orphan.Announcers {
		from = append(from, peer)
	}

	return map[string]interface{}{
		"txid":   tx.TxHash().String(),
		"wtxid":  tx.WTxHash().String(),
		"bytes":  totalSize,
		"vsize":  vsize,
		"weight": weight,
		"from":   from,
	}
}
