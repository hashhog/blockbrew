// Persistence for the mempool, byte-compatible with Bitcoin Core's
// mempool.dat (src/node/mempool_persist.cpp).
//
// File layout (Core MEMPOOL_DUMP_VERSION = 2):
//
//   0..7    uint64le  version  (always 2)
//   8       compact-size  always 0x08
//   9..16   8 bytes   XOR obfuscation key (zeroed = no obfuscation)
//   17..    XOR-obfuscated payload, byte at file offset p XOR'd with
//           key[p % 8] when key is nonzero. The payload is:
//             uint64le  count
//             count *   { TX_WITH_WITNESS, int64le time, int64le feeDelta }
//             compact-size N + N * { 32B txid, int64le amount }   (mapDeltas)
//             compact-size M + M *   32B txid                     (unbroadcast)
//
// For maximum compatibility with peers loading the file we always emit a
// zero key (obfuscation off). Reading tolerates either form.
//
// mapDeltas persistence (FIX-76 — closes the brief-error in FIX-72 dc8e1a0,
// where the original commit message claimed "delta lost on restart matches
// Core". Core actually persists per
// bitcoin-core/src/node/mempool_persist.cpp:101 (DumpMempool's
// `file << mapDeltas` after the per-entry loop) and :128-132 (LoadMempool's
// `PrioritiseTransaction(txid, delta)` over the tail block). Mirror:
//
//   - Dump: per-entry feeDelta is the entry's `mapDeltas[hash]` value (zero
//     if no delta is set). After the per-entry loop, txids in `mapDeltas`
//     that are NOT also in `pool` are emitted in the standalone tail block.
//     This matches Core's `mapDeltas.erase(i.tx->GetHash())` step at
//     mempool_persist.cpp:200 so a single delta is never double-counted.
//   - Load: read the tail block, feed each (txid, amount) into
//     PrioritiseTransaction. Per-entry feeDelta also rides back through
//     PrioritiseTransaction so the same `mapDeltas` shape is restored.
//
// Backward-compat: a v2 file with no tail block (truncated, or written by
// an older blockbrew) loads cleanly — EOF when reading the deltaCount
// compact-size is treated as zero deltas. This is intentional symmetry
// with Core's LoadMempool which catches the deserialize exception and
// returns success on partial files (mempool_persist.cpp:144-147).

package mempool

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Mempool dump filename, matching Bitcoin Core convention.
const mempoolDatFile = "mempool.dat"

// Bitcoin Core's MEMPOOL_DUMP_VERSION values.
const (
	mempoolDumpVersionNoXorKey uint64 = 1
	mempoolDumpVersion         uint64 = 2
)

// ErrMempoolDatVersion is returned when the file's version field is unrecognised.
var ErrMempoolDatVersion = errors.New("unrecognised mempool.dat version")

// xorReader wraps a Reader and XORs every byte read with key[pos % 8],
// where pos is the absolute file offset. Caller must initialise pos to the
// file offset of the first byte that should be obfuscated.
type xorReader struct {
	r   io.Reader
	key [8]byte
	pos int64
}

func (x *xorReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	if x.allZero() {
		x.pos += int64(n)
		return n, err
	}
	for i := 0; i < n; i++ {
		p[i] ^= x.key[x.pos%8]
		x.pos++
	}
	return n, err
}

func (x *xorReader) allZero() bool {
	for _, b := range x.key {
		if b != 0 {
			return false
		}
	}
	return true
}

// xorWriter is the symmetric counterpart used during dump.
type xorWriter struct {
	w   io.Writer
	key [8]byte
	pos int64
}

func (x *xorWriter) Write(p []byte) (int, error) {
	if x.allZero() {
		n, err := x.w.Write(p)
		x.pos += int64(n)
		return n, err
	}
	buf := make([]byte, len(p))
	for i := 0; i < len(p); i++ {
		buf[i] = p[i] ^ x.key[(x.pos+int64(i))%8]
	}
	n, err := x.w.Write(buf)
	x.pos += int64(n)
	return n, err
}

func (x *xorWriter) allZero() bool {
	for _, b := range x.key {
		if b != 0 {
			return false
		}
	}
	return true
}

// MempoolPath returns the canonical mempool.dat path under the data dir.
func MempoolPath(dataDir string) string {
	return filepath.Join(dataDir, mempoolDatFile)
}

// Dump writes the mempool to <dataDir>/mempool.dat in Bitcoin Core
// MEMPOOL_DUMP_VERSION=2 format. The file is written atomically via a
// .new sibling that is renamed on success.
//
// The XOR obfuscation key is left zero (no obfuscation), which Core treats as
// a valid v2 file (`Obfuscation::operator bool()` returns false when the key
// is zero, so reads/writes pass through unmodified).
func (mp *Mempool) Dump(dataDir string) error {
	finalPath := MempoolPath(dataDir)
	tmpPath := finalPath + ".new"

	f, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("mempool dump: open %s: %w", tmpPath, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()

	// Header: version (8 bytes) + compact-size(8) + 8-byte key. Header is
	// not obfuscated regardless of key contents.
	if err := wire.WriteUint64LE(f, mempoolDumpVersion); err != nil {
		return fmt.Errorf("mempool dump: write version: %w", err)
	}
	var key [8]byte // zero = obfuscation disabled
	if err := wire.WriteCompactSize(f, uint64(len(key))); err != nil {
		return fmt.Errorf("mempool dump: write key length: %w", err)
	}
	if _, err := f.Write(key[:]); err != nil {
		return fmt.Errorf("mempool dump: write key: %w", err)
	}

	// Snapshot the pool + mapDeltas under the lock, then release before
	// writing tx data. Per-entry feeDelta is the entry's `mapDeltas[hash]`
	// value (zero if no delta is set) — this matches Core's per-tx
	// `nFeeDelta` write at mempool_persist.cpp:199. Deltas for txids NOT
	// in the pool are tracked separately and emitted in the standalone
	// tail block below; Core does the same via the `mapDeltas.erase()`
	// step at mempool_persist.cpp:200.
	mp.mu.RLock()
	count := uint64(len(mp.pool))
	type snap struct {
		tx       *wire.MsgTx
		timeUnix int64
		feeDelta int64
	}
	snaps := make([]snap, 0, count)
	for _, e := range mp.pool {
		snaps = append(snaps, snap{
			tx:       e.Tx,
			timeUnix: e.Time.Unix(),
			feeDelta: mp.mapDeltas[e.TxHash],
		})
	}
	// Standalone tail block: copy mapDeltas entries whose txid is NOT in
	// the pool. These are operator prioritisations issued before broadcast,
	// or for txids that have been evicted but whose delta the operator
	// wants to apply if they ever return. Mirrors Core's mapDeltas
	// post-erase set (mempool_persist.cpp:200-203).
	type tailDelta struct {
		txid   wire.Hash256
		amount int64
	}
	tailDeltas := make([]tailDelta, 0)
	for txid, amount := range mp.mapDeltas {
		if _, inPool := mp.pool[txid]; inPool {
			continue
		}
		tailDeltas = append(tailDeltas, tailDelta{txid: txid, amount: amount})
	}
	mp.mu.RUnlock()

	// Stable order for the tail-block deltas eases regression diffs.
	sort.Slice(tailDeltas, func(i, j int) bool {
		return bytes.Compare(tailDeltas[i].txid[:], tailDeltas[j].txid[:]) < 0
	})

	// Stable order eases regression diffs and matches how Core's infoAll
	// produces a deterministic-ish list (insertion order).
	sort.Slice(snaps, func(i, j int) bool {
		hi := snaps[i].tx.TxHash()
		hj := snaps[j].tx.TxHash()
		return bytes.Compare(hi[:], hj[:]) < 0
	})

	xw := &xorWriter{w: f, key: key, pos: 17}

	// Payload: count + per-tx records.
	if err := wire.WriteUint64LE(xw, uint64(len(snaps))); err != nil {
		return fmt.Errorf("mempool dump: write count: %w", err)
	}
	for _, s := range snaps {
		if err := s.tx.Serialize(xw); err != nil {
			return fmt.Errorf("mempool dump: write tx: %w", err)
		}
		if err := wire.WriteInt64LE(xw, s.timeUnix); err != nil {
			return fmt.Errorf("mempool dump: write time: %w", err)
		}
		if err := wire.WriteInt64LE(xw, s.feeDelta); err != nil {
			return fmt.Errorf("mempool dump: write feeDelta: %w", err)
		}
	}

	// mapDeltas tail block: emit (txid, amount) for every delta whose txid
	// is NOT in the per-entry list above (those rode along in the per-entry
	// nFeeDelta slot). Mirrors mempool_persist.cpp:203 `file << mapDeltas`.
	if err := wire.WriteCompactSize(xw, uint64(len(tailDeltas))); err != nil {
		return fmt.Errorf("mempool dump: write mapDeltas count: %w", err)
	}
	for _, d := range tailDeltas {
		td := d.txid // local copy: Serialize takes a pointer
		if err := td.Serialize(xw); err != nil {
			return fmt.Errorf("mempool dump: write mapDeltas txid: %w", err)
		}
		if err := wire.WriteInt64LE(xw, d.amount); err != nil {
			return fmt.Errorf("mempool dump: write mapDeltas amount: %w", err)
		}
	}
	// Unbroadcast set: still zero — blockbrew does not yet track an
	// unbroadcast set (out of scope for FIX-76).
	if err := wire.WriteCompactSize(xw, 0); err != nil {
		return fmt.Errorf("mempool dump: write unbroadcast: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("mempool dump: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mempool dump: close: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("mempool dump: rename: %w", err)
	}
	return nil
}

// LoadResult summarises the outcome of a Load call.
type LoadResult struct {
	// Read is the number of transactions that were decoded from the file.
	Read int
	// Accepted is the number that were re-added to the mempool.
	Accepted int
	// Failed is the number rejected by AcceptToMemoryPool.
	Failed int
	// Expired is the number skipped because their on-disk age exceeded MaxAge.
	Expired int
}

// LoadOptions tunes Load behaviour.
type LoadOptions struct {
	// MaxAge skips entries whose stored timestamp is older than now-MaxAge.
	// Zero disables the check.
	MaxAge time.Duration
}

// Load reads <dataDir>/mempool.dat (Core MEMPOOL_DUMP_VERSION = 1 or 2) and
// re-adds each transaction via AcceptToMemoryPool. Missing files return a nil
// result and a nil error so callers can treat "no dump on disk" as a no-op.
func (mp *Mempool) Load(dataDir string, opts LoadOptions) (*LoadResult, error) {
	path := MempoolPath(dataDir)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("mempool load: open %s: %w", path, err)
	}
	defer f.Close()

	version, err := wire.ReadUint64LE(f)
	if err != nil {
		return nil, fmt.Errorf("mempool load: read version: %w", err)
	}
	var key [8]byte
	headerEnd := int64(8)
	switch version {
	case mempoolDumpVersionNoXorKey:
		// No obfuscation key in the file; payload starts immediately.
	case mempoolDumpVersion:
		klen, err := wire.ReadCompactSize(f)
		if err != nil {
			return nil, fmt.Errorf("mempool load: read key length: %w", err)
		}
		if klen != 8 {
			return nil, fmt.Errorf("mempool load: bad key length %d", klen)
		}
		if _, err := io.ReadFull(f, key[:]); err != nil {
			return nil, fmt.Errorf("mempool load: read key: %w", err)
		}
		headerEnd = 8 + 1 + 8
	default:
		return nil, fmt.Errorf("%w: %d", ErrMempoolDatVersion, version)
	}

	xr := &xorReader{r: f, key: key, pos: headerEnd}

	count, err := wire.ReadUint64LE(xr)
	if err != nil {
		return nil, fmt.Errorf("mempool load: read count: %w", err)
	}
	// Cap to a sane upper bound; Core's mempool default size is 300k tx,
	// so 10x that is more than enough headroom.
	const maxLoadCount = 3_000_000
	if count > maxLoadCount {
		return nil, fmt.Errorf("mempool load: count %d exceeds %d", count, maxLoadCount)
	}

	now := time.Now()
	res := &LoadResult{}
	for i := uint64(0); i < count; i++ {
		tx := &wire.MsgTx{}
		if err := tx.Deserialize(xr); err != nil {
			return nil, fmt.Errorf("mempool load: tx %d: %w", i, err)
		}
		nTime, err := wire.ReadInt64LE(xr)
		if err != nil {
			return nil, fmt.Errorf("mempool load: tx %d time: %w", i, err)
		}
		nFeeDelta, err := wire.ReadInt64LE(xr)
		if err != nil {
			return nil, fmt.Errorf("mempool load: tx %d feeDelta: %w", i, err)
		}
		res.Read++

		if opts.MaxAge > 0 {
			age := now.Sub(time.Unix(nTime, 0))
			if age > opts.MaxAge {
				res.Expired++
				continue
			}
		}
		// Re-prioritise BEFORE attempting acceptance so the delta is
		// present at admission time (matching Core's
		// `apply_fee_delta_priority` ordering at mempool_persist.cpp:100-
		// 102 — PrioritiseTransaction runs before AcceptToMemoryPool for
		// the same entry). If acceptance later fails the delta still
		// sits in mapDeltas waiting for the tx to arrive via another
		// path; Core has the same property.
		if nFeeDelta != 0 {
			mp.PrioritiseTransaction(tx.TxHash(), nFeeDelta)
		}
		if err := mp.AcceptToMemoryPool(tx); err != nil {
			res.Failed++
			continue
		}
		res.Accepted++
	}

	// mapDeltas tail block — txids that had a delta applied but were NOT
	// in the per-entry list. Feed each back through PrioritiseTransaction
	// (Core's path: mempool_persist.cpp:128-132 ApplyDelta loop).
	deltaCount, err := wire.ReadCompactSize(xr)
	if err != nil {
		// EOF here is OK on partial files / pre-FIX-76 dumps — the txs we
		// already accepted stand, and there are simply no standalone
		// deltas to restore. Mirrors Core's catch-block tolerance at
		// mempool_persist.cpp:144-147.
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		return res, fmt.Errorf("mempool load: read mapDeltas: %w", err)
	}
	for i := uint64(0); i < deltaCount; i++ {
		var txid wire.Hash256
		if err := txid.Deserialize(xr); err != nil {
			return res, fmt.Errorf("mempool load: mapDeltas[%d] txid: %w", i, err)
		}
		amount, err := wire.ReadInt64LE(xr)
		if err != nil {
			return res, fmt.Errorf("mempool load: mapDeltas[%d] amount: %w", i, err)
		}
		if amount != 0 {
			mp.PrioritiseTransaction(txid, amount)
		}
	}
	unbroadcastCount, err := wire.ReadCompactSize(xr)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		return res, fmt.Errorf("mempool load: read unbroadcast: %w", err)
	}
	for i := uint64(0); i < unbroadcastCount; i++ {
		var txid wire.Hash256
		if err := txid.Deserialize(xr); err != nil {
			return res, fmt.Errorf("mempool load: unbroadcast[%d]: %w", i, err)
		}
	}
	return res, nil
}
