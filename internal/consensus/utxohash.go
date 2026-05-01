// utxohash.go: Core-compatible UTXO set hashing.
//
// Implements two flavors used by Bitcoin Core (kernel/coinstats.cpp):
//
//   - HASH_SERIALIZED: stream every (outpoint, code, value, scriptPubKey)
//     through SHA256 in a fixed iteration order, then take the SHA256d of the
//     stream. This is what `dumptxoutset` reports as `txoutset_hash` and what
//     `loadtxoutset` validates against `assumeutxo`'s pinned `hash_serialized`
//     value. Spec: bitcoin-core/src/validation.cpp:5912-5914.
//
//   - MUHASH3072: feed the same per-coin record through MuHash3072.Insert
//     (the multiset hash from internal/crypto/muhash.go). Iteration-order
//     independent — so this is the right primitive for an incremental UTXO
//     commitment that updates per block. Not yet wired into block connect
//     here, but exposed so the rest of the codebase can use it.
//
// Both flavors share the byte layout from coinstats.cpp:46:
//
//	TxOutSer(ss, outpoint, coin) {
//	    ss << outpoint;                                     // 32B txid LE + 4B index LE
//	    ss << uint32_t((coin.nHeight << 1) + coin.fCoinBase); // 4B LE; NOT a varint.
//	    ss << coin.out;                                     // 8B nValue LE + CompactSize len + script bytes
//	}
//
// IMPORTANT: TxOutSer is the *uncompressed* form. It does NOT use Core's
// TxOutCompression (which `dumptxoutset` uses on disk). Mixing the two would
// produce a different digest and break assumeutxo validation.

package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// WriteTxOutSer writes the per-coin record from coinstats.cpp::TxOutSer.
// The reference layout is documented at the top of this file.
func WriteTxOutSer(w io.Writer, outpoint wire.OutPoint, entry *UTXOEntry) error {
	// outpoint: 32B hash || 4B vout (LE)
	if err := outpoint.Serialize(w); err != nil {
		return err
	}
	// code = (height << 1) | coinbase, written as uint32 LE (NOT varint).
	code := (uint32(entry.Height) << 1)
	if entry.IsCoinbase {
		code |= 1
	}
	var buf4 [4]byte
	binary.LittleEndian.PutUint32(buf4[:], code)
	if _, err := w.Write(buf4[:]); err != nil {
		return err
	}
	// nValue: int64 LE.
	var buf8 [8]byte
	binary.LittleEndian.PutUint64(buf8[:], uint64(entry.Amount))
	if _, err := w.Write(buf8[:]); err != nil {
		return err
	}
	// scriptPubKey: CompactSize length + raw bytes.
	if err := wire.WriteCompactSize(w, uint64(len(entry.PkScript))); err != nil {
		return err
	}
	if _, err := w.Write(entry.PkScript); err != nil {
		return err
	}
	return nil
}

// txOutSerBytes is a small helper that returns the TxOutSer encoding as a
// fresh byte slice (used by MuHash where we need the input as a contiguous
// span).
func txOutSerBytes(outpoint wire.OutPoint, entry *UTXOEntry) []byte {
	var buf bytes.Buffer
	// Conservative pre-size: outpoint 36 + code 4 + amount 8 + len varint 5 + script.
	buf.Grow(36 + 4 + 8 + 5 + len(entry.PkScript))
	_ = WriteTxOutSer(&buf, outpoint, entry)
	return buf.Bytes()
}

// collectAndSortCacheCoins extracts (outpoint, entry) pairs from a UTXOSet's
// cache and returns them sorted by (txid, vout) ascending. Iteration over
// utxoSet.cache must happen under the read lock; we lift that into here so
// callers don't have to.
//
// Note: this only iterates the IN-MEMORY cache, matching the existing
// snapshot-write path in WriteSnapshot/ComputeUTXOHash. A production Core
// implementation walks the chainstate DB cursor; we'll switch to that once
// the snapshot writer does too. This is therefore safe to use AFTER a
// LoadSnapshot (which puts every coin into the cache) but does not yet
// produce a correct digest mid-IBD when the UTXO set has spilled to disk.
func collectAndSortCacheCoins(utxoSet *UTXOSet) []sortedCoin {
	utxoSet.mu.RLock()
	defer utxoSet.mu.RUnlock()
	out := make([]sortedCoin, 0, len(utxoSet.cache))
	for op, entry := range utxoSet.cache {
		if entry == nil {
			continue
		}
		out = append(out, sortedCoin{outpoint: op, entry: entry})
	}
	sort.Slice(out, func(i, j int) bool {
		// Compare txid byte-for-byte (internal byte order).
		for k := 0; k < 32; k++ {
			if out[i].outpoint.Hash[k] != out[j].outpoint.Hash[k] {
				return out[i].outpoint.Hash[k] < out[j].outpoint.Hash[k]
			}
		}
		return out[i].outpoint.Index < out[j].outpoint.Index
	})
	return out
}

type sortedCoin struct {
	outpoint wire.OutPoint
	entry    *UTXOEntry
}

// ComputeHashSerialized computes Core's HASH_SERIALIZED over the given
// UTXOSet's cache. This is the value compared against
// AssumeUTXOData.HashSerialized in loadtxoutset.
//
// Returns the digest, the number of coins iterated, and an error.
func ComputeHashSerialized(utxoSet *UTXOSet) (wire.Hash256, uint64, error) {
	coins := collectAndSortCacheCoins(utxoSet)

	h := sha256.New()
	for _, c := range coins {
		if err := WriteTxOutSer(h, c.outpoint, c.entry); err != nil {
			return wire.Hash256{}, 0, err
		}
	}
	// HashWriter::GetHash() = SHA256d. Single SHA256 first, then SHA256 again.
	first := h.Sum(nil)
	second := sha256.Sum256(first)
	var out wire.Hash256
	copy(out[:], second[:])
	return out, uint64(len(coins)), nil
}

// ComputeMuHashUTXO computes Core's MUHASH3072 over the given UTXOSet's cache.
// Since MuHash is order-invariant we don't strictly need to sort, but we keep
// the sort for parity with ComputeHashSerialized — makes test reproductions
// against trace dumps simpler.
func ComputeMuHashUTXO(utxoSet *UTXOSet) (wire.Hash256, uint64, error) {
	coins := collectAndSortCacheCoins(utxoSet)

	mh := crypto.NewMuHash3072()
	for _, c := range coins {
		mh.Insert(txOutSerBytes(c.outpoint, c.entry))
	}
	digest := mh.Finalize()
	var out wire.Hash256
	copy(out[:], digest[:])
	return out, uint64(len(coins)), nil
}
