// PayJoin per-session state — TTL, replay cache, in-flight outpoint tracker.
//
// Closes W119 BUG-9 / BUG-10 (G18 / G19 / G30). The BIP-78 spec
// (§"Receiver's per-session state") lists three responsibilities for the
// receiver between handing out a proposal and observing it on the wire:
//
//   1. TTL on offered proposals (G18). After PayjoinSessionTTL elapses,
//      the cached entry is dropped and any retry from the sender is
//      treated as a fresh proposal. Bounded memory is the goal — a
//      stale offer that the sender never broadcast SHOULD NOT pin a
//      UTXO forever.
//
//   2. Outpoint tracker for concurrent offers (G19). Two distinct
//      sender requests that select the same receiver UTXO would create
//      a self-double-spend if both senders broadcast their respective
//      proposals. We track every receiver UTXO that has an in-flight
//      offer; once an in-flight offer expires or is "completed" (the
//      sender's tx hits our mempool), the outpoint is released for
//      re-use.
//
//   3. Replay cache keyed on sha256(Original PSBT bytes) (G30). When
//      the same Original PSBT is POSTed twice (sender retry, network
//      hiccup), the receiver MUST return the EXACT SAME proposal so
//      the sender's anti-snoop validators see the same signed bytes.
//      Without replay protection the receiver would re-run selection
//      and could pick a different UTXO on the retry, producing a
//      structurally different proposal — and worse, locking TWO
//      receiver UTXOs in the outpoint tracker for what is logically
//      one offer.
//
// State is held in a single struct (payjoinSessionStore) attached to
// the Wallet. The mutex is held briefly for each lookup/insert; the
// store itself uses lazy expiry (entries past TTL are pruned on the
// next access) so we don't need a background goroutine. A future
// hardening can add a tick-driven prune for long-lived nodes serving
// many merchants.
//
// Memory bound: each session entry is ~100 bytes (sha256 + outpoint
// list + timestamp + proposal base64). With PayjoinSessionTTL=10
// minutes and a generous 100 proposals/sec receiver, the cap is
// ~6 MB of state — well below any sensible budget.
//
// Reference: bips/bip-0078.mediawiki §"Receiver's per-session state";
// payjoin.org Rust crate `payjoin::receiver::SessionStore`.

package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// PayjoinSessionTTL caps how long a previously-offered proposal stays
// in the replay/outpoint cache. Per BIP-78 §"Receiver's per-session
// state" the receiver SHOULD pick a value that exceeds typical sender
// retry windows but bounds memory. 10 minutes matches the payjoin.org
// reference implementation default.
const PayjoinSessionTTL = 10 * time.Minute

// payjoinPSBTID returns the canonical identifier for an Original PSBT:
// hex(sha256(base64-bytes-after-TrimSpace)). Keyed on the wire-form
// bytes (not the decoded PSBT struct) because the spec defines replay
// based on what the sender sent, not on a canonicalised re-encoding.
//
// Why sha256-of-base64 rather than sha256-of-PSBT-raw: the BIP-78 spec
// says "the same Original PSBT" without further clarification, and the
// reference implementations key on the request body string. Two senders
// who somehow produced byte-equal base64 strings will collide; this is
// vanishingly unlikely (the PSBT carries per-input WitnessUTXO and the
// sender's input nonces).
func payjoinPSBTID(base64Body string) string {
	sum := sha256.Sum256([]byte(base64Body))
	return hex.EncodeToString(sum[:])
}

// payjoinSessionEntry tracks one in-flight PayJoin offer.
type payjoinSessionEntry struct {
	// psbtID is the sha256 hex of the Original PSBT base64 body.
	psbtID string

	// expiresAt is the wall-clock time after which this entry is
	// pruned on next access. Lazy expiry; no background sweep.
	expiresAt time.Time

	// receiverOutpoints lists the receiver-wallet UTXO outpoints that
	// the proposal pinned. Released back to the free pool on prune.
	// One entry per proposal — typically 1 outpoint, but the design
	// allows for future UIH-aware selection that picks 2+.
	receiverOutpoints []wire.OutPoint

	// proposalBase64 is the EXACT bytes we returned on the first call
	// for this psbtID. Replay re-emits this verbatim so the sender's
	// anti-snoop validators see byte-stable input.
	proposalBase64 string
}

// payjoinSessionStore is the wallet-level state container.
//
// We keep two indexes:
//   - byID: psbtID → entry, for G30 replay lookup.
//   - reservedOutpoints: outpoint → struct{}, for G19 double-spend
//     guard during UTXO selection.
//
// Both are protected by a single mutex; PayJoin throughput is low
// (merchant flows are tens per minute at most), so contention is a
// non-issue compared to clarity.
type payjoinSessionStore struct {
	mu                sync.Mutex
	byID              map[string]*payjoinSessionEntry
	reservedOutpoints map[wire.OutPoint]struct{}

	// nowFn is overridable for tests (G18 TTL expiry test sets it to
	// a fake clock so the test doesn't sleep 10 minutes). Production
	// uses time.Now.
	nowFn func() time.Time

	// ttl is the per-entry lifetime. Settable for tests; production
	// uses PayjoinSessionTTL.
	ttl time.Duration
}

// newPayjoinSessionStore constructs a fresh store with the production
// defaults. The wallet creates one at construction time.
func newPayjoinSessionStore() *payjoinSessionStore {
	return &payjoinSessionStore{
		byID:              make(map[string]*payjoinSessionEntry),
		reservedOutpoints: make(map[wire.OutPoint]struct{}),
		nowFn:             time.Now,
		ttl:               PayjoinSessionTTL,
	}
}

// pruneExpiredLocked drops every entry whose expiresAt is in the past.
// Released outpoints are removed from reservedOutpoints so a future
// proposal CAN re-use them. Caller MUST hold s.mu.
func (s *payjoinSessionStore) pruneExpiredLocked(now time.Time) {
	for id, ent := range s.byID {
		if !now.After(ent.expiresAt) {
			continue
		}
		for _, op := range ent.receiverOutpoints {
			delete(s.reservedOutpoints, op)
		}
		delete(s.byID, id)
	}
}

// lookupReplay returns the cached proposal for psbtID, if any. Used by
// G30: a sender retrying the same Original PSBT MUST receive the same
// proposal back. Returns ("", false) on cache miss.
func (s *payjoinSessionStore) lookupReplay(psbtID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.nowFn())
	ent, ok := s.byID[psbtID]
	if !ok {
		return "", false
	}
	return ent.proposalBase64, true
}

// reserveOutpoints attempts to reserve `outpoints` for an in-flight
// proposal. Returns false if ANY of them is already reserved (G19
// double-spend guard). On success the caller is committed to storing
// a session entry via storeSession; if it doesn't, the outpoints will
// leak until next prune cycle (10 min worst case).
//
// We require the caller to pass psbtID and proposalBase64 in the same
// call so the reservation is atomic with the entry creation.
func (s *payjoinSessionStore) storeSession(
	psbtID string,
	outpoints []wire.OutPoint,
	proposalBase64 string,
) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	s.pruneExpiredLocked(now)
	// G19: refuse if ANY outpoint is already reserved by another live
	// session. Don't reserve any if one collides — atomic all-or-none.
	for _, op := range outpoints {
		if _, taken := s.reservedOutpoints[op]; taken {
			return false
		}
	}
	for _, op := range outpoints {
		s.reservedOutpoints[op] = struct{}{}
	}
	s.byID[psbtID] = &payjoinSessionEntry{
		psbtID:            psbtID,
		expiresAt:         now.Add(s.ttl),
		receiverOutpoints: append([]wire.OutPoint(nil), outpoints...),
		proposalBase64:    proposalBase64,
	}
	return true
}

// isReserved reports whether the given outpoint is currently held by
// any live session. Used by the selection path (payjoinScanLocked) to
// skip already-pinned UTXOs.
func (s *payjoinSessionStore) isReserved(op wire.OutPoint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.nowFn())
	_, taken := s.reservedOutpoints[op]
	return taken
}

// activeSessions returns the count of live entries — used by tests to
// assert TTL expiry actually pruned the store.
func (s *payjoinSessionStore) activeSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.nowFn())
	return len(s.byID)
}

// getPayjoinSessions returns the wallet's PayJoin session store,
// lazy-initialising it for wallets constructed outside NewWallet (legacy
// tests, programmatic struct-literal construction). Callers MUST NOT
// hold w.mu when invoking this — the store has its own mutex and we
// don't want to invert lock order.
func (w *Wallet) getPayjoinSessions() *payjoinSessionStore {
	w.mu.Lock()
	if w.payjoinSessions == nil {
		w.payjoinSessions = newPayjoinSessionStore()
	}
	s := w.payjoinSessions
	w.mu.Unlock()
	return s
}
