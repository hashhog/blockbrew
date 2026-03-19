// Package p2p implements BIP330 Erlay transaction reconciliation protocol.
// Erlay reduces transaction relay bandwidth by ~40% using set reconciliation
// instead of flooding every transaction to every peer.
package p2p

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP330 Erlay protocol constants.
const (
	// TxReconciliationVersion is the supported Erlay protocol version.
	TxReconciliationVersion uint32 = 1

	// ReconciliationInterval is the time between reconciliation rounds.
	ReconciliationInterval = 2 * time.Second

	// FloodOutboundPeers is the number of outbound peers to flood txs to.
	// Other peers use reconciliation for bandwidth savings.
	FloodOutboundPeers = 8

	// MaxReconciliationCapacity is the maximum sketch capacity.
	MaxReconciliationCapacity = 256

	// DefaultReconciliationCapacity is the default sketch capacity.
	DefaultReconciliationCapacity = 32

	// MinReconciliationVersion is the minimum supported version.
	MinReconciliationVersion = 1
)

// Erlay-related errors.
var (
	ErrErlayNotSupported     = errors.New("erlay not supported by peer")
	ErrErlayNotNegotiated    = errors.New("erlay not yet negotiated")
	ErrErlayAlreadyRegistered = errors.New("erlay already registered for peer")
	ErrInvalidErlayVersion   = errors.New("invalid erlay version")
	ErrReconciliationFailed  = errors.New("reconciliation failed")
)

// MsgSendTxRcncl is the "sendtxrcncl" message for Erlay negotiation.
// Sent after version handshake, before verack to signal Erlay support.
type MsgSendTxRcncl struct {
	Version uint32 // Protocol version (1)
	Salt    uint64 // 64-bit random salt for short ID computation
}

// Command returns the protocol command string for the message.
func (m *MsgSendTxRcncl) Command() string { return "sendtxrcncl" }

// Serialize writes the sendtxrcncl message to w.
func (m *MsgSendTxRcncl) Serialize(w io.Writer) error {
	if err := wire.WriteUint32LE(w, m.Version); err != nil {
		return err
	}
	return wire.WriteUint64LE(w, m.Salt)
}

// Deserialize reads the sendtxrcncl message from r.
func (m *MsgSendTxRcncl) Deserialize(r io.Reader) error {
	var err error
	m.Version, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	m.Salt, err = wire.ReadUint64LE(r)
	return err
}

// MsgReqReconcil is the "reqreconcil" message requesting a reconciliation round.
// Sent by the initiator (outbound connection) to start reconciliation.
type MsgReqReconcil struct {
	SetSize uint16 // Number of transactions in our set to reconcile
}

// Command returns the protocol command string for the message.
func (m *MsgReqReconcil) Command() string { return "reqreconcil" }

// Serialize writes the reqreconcil message to w.
func (m *MsgReqReconcil) Serialize(w io.Writer) error {
	return wire.WriteUint16LE(w, m.SetSize)
}

// Deserialize reads the reqreconcil message from r.
func (m *MsgReqReconcil) Deserialize(r io.Reader) error {
	var err error
	m.SetSize, err = wire.ReadUint16LE(r)
	return err
}

// MsgSketch is the "sketch" message containing a minisketch for reconciliation.
// Sent by the responder (inbound connection) in response to reqreconcil.
type MsgSketch struct {
	SketchData []byte // Serialized minisketch
}

// Command returns the protocol command string for the message.
func (m *MsgSketch) Command() string { return "sketch" }

// Serialize writes the sketch message to w.
func (m *MsgSketch) Serialize(w io.Writer) error {
	return wire.WriteVarBytes(w, m.SketchData)
}

// Deserialize reads the sketch message from r.
func (m *MsgSketch) Deserialize(r io.Reader) error {
	var err error
	// Max sketch size: 256 capacity * 4 bytes = 1024 bytes
	m.SketchData, err = wire.ReadVarBytes(r, 1024)
	return err
}

// MsgReconcilDiff is the "reconcildiff" message sent after decoding the sketch.
// Contains the short IDs of transactions the sender needs.
type MsgReconcilDiff struct {
	Success       bool     // Whether decoding succeeded
	AskShortIDs   []uint32 // Short IDs of transactions we need from peer
}

// Command returns the protocol command string for the message.
func (m *MsgReconcilDiff) Command() string { return "reconcildiff" }

// Serialize writes the reconcildiff message to w.
func (m *MsgReconcilDiff) Serialize(w io.Writer) error {
	var success uint8
	if m.Success {
		success = 1
	}
	if err := wire.WriteUint8(w, success); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.AskShortIDs))); err != nil {
		return err
	}
	for _, shortID := range m.AskShortIDs {
		if err := wire.WriteUint32LE(w, shortID); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the reconcildiff message from r.
func (m *MsgReconcilDiff) Deserialize(r io.Reader) error {
	success, err := wire.ReadUint8(r)
	if err != nil {
		return err
	}
	m.Success = success != 0

	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxReconciliationCapacity {
		return ErrTooManyInvVects
	}

	m.AskShortIDs = make([]uint32, count)
	for i := range m.AskShortIDs {
		m.AskShortIDs[i], err = wire.ReadUint32LE(r)
		if err != nil {
			return err
		}
	}
	return nil
}

// ReconciliationRole defines whether a peer is the initiator or responder.
type ReconciliationRole int

const (
	// RoleInitiator initiates reconciliation (typically outbound connection).
	RoleInitiator ReconciliationRole = iota
	// RoleResponder responds to reconciliation requests (typically inbound).
	RoleResponder
)

// TxReconciliationState holds the reconciliation state for a single peer.
type TxReconciliationState struct {
	// Role determines who initiates reconciliation
	Role ReconciliationRole

	// Salt keys for short ID computation (derived from both peers' salts)
	K0, K1 uint64

	// LocalSalt is our salt sent in sendtxrcncl
	LocalSalt uint64

	// RemoteSalt is peer's salt from their sendtxrcncl
	RemoteSalt uint64

	// NegotiatedVersion is the minimum of our and peer's versions
	NegotiatedVersion uint32

	// LocalSet contains short IDs of transactions we want to reconcile
	LocalSet map[uint32]wire.Hash256

	// LastReconciliation is when we last reconciled with this peer
	LastReconciliation time.Time

	// PendingSketch is our sketch awaiting a response
	PendingSketch *crypto.Minisketch32

	mu sync.Mutex
}

// NewTxReconciliationState creates a new reconciliation state for a peer.
func NewTxReconciliationState(role ReconciliationRole, localSalt, remoteSalt uint64, version uint32) *TxReconciliationState {
	k0, k1 := crypto.ComputeErlaySalt(localSalt, remoteSalt)
	return &TxReconciliationState{
		Role:               role,
		K0:                 k0,
		K1:                 k1,
		LocalSalt:          localSalt,
		RemoteSalt:         remoteSalt,
		NegotiatedVersion:  version,
		LocalSet:           make(map[uint32]wire.Hash256),
		LastReconciliation: time.Now(),
	}
}

// ComputeShortID computes the 32-bit short ID for a transaction.
func (s *TxReconciliationState) ComputeShortID(wtxid wire.Hash256) uint32 {
	return crypto.ErlayShortID(s.K0, s.K1, wtxid[:])
}

// AddTransaction adds a transaction to the local set for reconciliation.
func (s *TxReconciliationState) AddTransaction(wtxid wire.Hash256) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shortID := s.ComputeShortID(wtxid)
	s.LocalSet[shortID] = wtxid
}

// RemoveTransaction removes a transaction from the local set.
func (s *TxReconciliationState) RemoveTransaction(wtxid wire.Hash256) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shortID := s.ComputeShortID(wtxid)
	delete(s.LocalSet, shortID)
}

// BuildSketch creates a minisketch of the local transaction set.
func (s *TxReconciliationState) BuildSketch(capacity int) *crypto.Minisketch32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	sketch := crypto.NewMinisketch32(capacity)
	for shortID := range s.LocalSet {
		sketch.Add(shortID)
	}
	return sketch
}

// SetSize returns the number of transactions in the local set.
func (s *TxReconciliationState) SetSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.LocalSet)
}

// Clear clears the local transaction set.
func (s *TxReconciliationState) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LocalSet = make(map[uint32]wire.Hash256)
}

// TxReconciliationTracker manages reconciliation state across all peers.
type TxReconciliationTracker struct {
	mu sync.RWMutex

	// preRegistered holds salts for peers that haven't completed registration yet
	preRegistered map[string]uint64 // addr -> local salt

	// registered holds fully registered peer states
	registered map[string]*TxReconciliationState // addr -> state

	// floodPeers is the set of outbound peers we flood transactions to
	floodPeers map[string]bool

	// reconcilePeers is the set of peers we reconcile with
	reconcilePeers map[string]bool

	// outboundCount tracks how many outbound flood peers we have
	outboundCount int
}

// NewTxReconciliationTracker creates a new reconciliation tracker.
func NewTxReconciliationTracker() *TxReconciliationTracker {
	return &TxReconciliationTracker{
		preRegistered:  make(map[string]uint64),
		registered:     make(map[string]*TxReconciliationState),
		floodPeers:     make(map[string]bool),
		reconcilePeers: make(map[string]bool),
	}
}

// PreRegisterPeer generates a salt and pre-registers a peer for Erlay.
// Called before sending sendtxrcncl. Returns the salt to send.
func (t *TxReconciliationTracker) PreRegisterPeer(addr string) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if already pre-registered or registered
	if _, exists := t.preRegistered[addr]; exists {
		return 0, ErrErlayAlreadyRegistered
	}
	if _, exists := t.registered[addr]; exists {
		return 0, ErrErlayAlreadyRegistered
	}

	// Generate random salt
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return 0, err
	}
	salt := binary.LittleEndian.Uint64(buf[:])

	t.preRegistered[addr] = salt
	return salt, nil
}

// RegisterPeer completes registration when we receive peer's sendtxrcncl.
// Returns the negotiated version and role.
func (t *TxReconciliationTracker) RegisterPeer(addr string, remoteSalt uint64, remoteVersion uint32, isInbound bool) (*TxReconciliationState, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Validate version
	if remoteVersion < MinReconciliationVersion {
		return nil, ErrInvalidErlayVersion
	}

	// Get our pre-registered salt
	localSalt, exists := t.preRegistered[addr]
	if !exists {
		return nil, ErrErlayNotNegotiated
	}
	delete(t.preRegistered, addr)

	// Check if already registered (shouldn't happen but be safe)
	if _, exists := t.registered[addr]; exists {
		return nil, ErrErlayAlreadyRegistered
	}

	// Determine role and negotiated version
	var role ReconciliationRole
	if isInbound {
		role = RoleResponder
	} else {
		role = RoleInitiator
	}

	version := TxReconciliationVersion
	if remoteVersion < version {
		version = remoteVersion
	}

	// Create state
	state := NewTxReconciliationState(role, localSalt, remoteSalt, version)
	t.registered[addr] = state

	// Decide flood vs reconcile
	// Flood to first FloodOutboundPeers outbound peers, reconcile with rest
	if !isInbound && t.outboundCount < FloodOutboundPeers {
		t.floodPeers[addr] = true
		t.outboundCount++
	} else {
		t.reconcilePeers[addr] = true
	}

	return state, nil
}

// ForgetPeer removes a peer from the tracker.
func (t *TxReconciliationTracker) ForgetPeer(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.preRegistered, addr)
	delete(t.registered, addr)

	if t.floodPeers[addr] {
		delete(t.floodPeers, addr)
		t.outboundCount--
	}
	delete(t.reconcilePeers, addr)
}

// GetState returns the reconciliation state for a peer.
func (t *TxReconciliationTracker) GetState(addr string) *TxReconciliationState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.registered[addr]
}

// IsRegistered returns true if the peer is registered for reconciliation.
func (t *TxReconciliationTracker) IsRegistered(addr string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, exists := t.registered[addr]
	return exists
}

// IsFloodPeer returns true if we should flood transactions to this peer.
func (t *TxReconciliationTracker) IsFloodPeer(addr string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.floodPeers[addr]
}

// IsReconcilePeer returns true if we should reconcile with this peer.
func (t *TxReconciliationTracker) IsReconcilePeer(addr string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.reconcilePeers[addr]
}

// GetReconcilePeers returns addresses of all reconcile peers.
func (t *TxReconciliationTracker) GetReconcilePeers() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peers := make([]string, 0, len(t.reconcilePeers))
	for addr := range t.reconcilePeers {
		peers = append(peers, addr)
	}
	return peers
}

// AddTransactionToAll adds a transaction to all registered peers' local sets.
func (t *TxReconciliationTracker) AddTransactionToAll(wtxid wire.Hash256) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, state := range t.registered {
		state.AddTransaction(wtxid)
	}
}

// RemoveTransactionFromAll removes a transaction from all peers' local sets.
func (t *TxReconciliationTracker) RemoveTransactionFromAll(wtxid wire.Hash256) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, state := range t.registered {
		state.RemoveTransaction(wtxid)
	}
}

// ErlayReconciler handles the reconciliation loop for a peer.
type ErlayReconciler struct {
	tracker *TxReconciliationTracker
	peer    *Peer

	// Callbacks
	onRequestTx func(wtxid wire.Hash256)        // Called when we need a tx from peer
	onSendTx    func(wtxid wire.Hash256) bool   // Called to send a tx to peer

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewErlayReconciler creates a new reconciler for a peer.
func NewErlayReconciler(tracker *TxReconciliationTracker, peer *Peer) *ErlayReconciler {
	return &ErlayReconciler{
		tracker: tracker,
		peer:    peer,
		quit:    make(chan struct{}),
	}
}

// SetCallbacks sets the callbacks for requesting and sending transactions.
func (r *ErlayReconciler) SetCallbacks(onRequestTx func(wire.Hash256), onSendTx func(wire.Hash256) bool) {
	r.onRequestTx = onRequestTx
	r.onSendTx = onSendTx
}

// Start begins the reconciliation loop (only for initiator role).
func (r *ErlayReconciler) Start() {
	state := r.tracker.GetState(r.peer.Address())
	if state == nil || state.Role != RoleInitiator {
		return // Only initiators run the loop
	}

	r.wg.Add(1)
	go r.reconciliationLoop()
}

// Stop stops the reconciliation loop.
func (r *ErlayReconciler) Stop() {
	close(r.quit)
	r.wg.Wait()
}

// reconciliationLoop periodically initiates reconciliation with the peer.
func (r *ErlayReconciler) reconciliationLoop() {
	defer r.wg.Done()

	// Stagger initial reconciliation randomly to avoid thundering herd
	jitter := time.Duration(binary.LittleEndian.Uint32(make([]byte, 4))) % ReconciliationInterval
	time.Sleep(jitter)

	ticker := time.NewTicker(ReconciliationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.initiateReconciliation()
		case <-r.quit:
			return
		}
	}
}

// initiateReconciliation starts a reconciliation round with the peer.
func (r *ErlayReconciler) initiateReconciliation() {
	state := r.tracker.GetState(r.peer.Address())
	if state == nil {
		return
	}

	state.mu.Lock()
	setSize := len(state.LocalSet)
	state.mu.Unlock()

	if setSize == 0 {
		return // Nothing to reconcile
	}

	// Build our sketch
	capacity := DefaultReconciliationCapacity
	if setSize > capacity {
		capacity = setSize + 10 // Add margin
	}
	if capacity > MaxReconciliationCapacity {
		capacity = MaxReconciliationCapacity
	}

	sketch := state.BuildSketch(capacity)

	state.mu.Lock()
	state.PendingSketch = sketch
	state.mu.Unlock()

	// Send reqreconcil
	msg := &MsgReqReconcil{SetSize: uint16(setSize)}
	r.peer.SendMessage(msg)

	log.Printf("erlay: initiated reconciliation with %s (set_size=%d)", r.peer.Address(), setSize)
}

// HandleSketch processes a sketch message from the peer (as initiator).
func (r *ErlayReconciler) HandleSketch(msg *MsgSketch) {
	state := r.tracker.GetState(r.peer.Address())
	if state == nil || state.Role != RoleInitiator {
		return
	}

	state.mu.Lock()
	localSketch := state.PendingSketch
	state.PendingSketch = nil
	localSet := make(map[uint32]wire.Hash256, len(state.LocalSet))
	for k, v := range state.LocalSet {
		localSet[k] = v
	}
	state.mu.Unlock()

	if localSketch == nil {
		log.Printf("erlay: received unexpected sketch from %s", r.peer.Address())
		return
	}

	// Deserialize peer's sketch
	peerSketch := crypto.NewMinisketch32(localSketch.Capacity())
	if err := peerSketch.Deserialize(msg.SketchData); err != nil {
		log.Printf("erlay: failed to deserialize sketch from %s: %v", r.peer.Address(), err)
		r.sendReconcilDiff(false, nil)
		return
	}

	// Compute symmetric difference: local XOR remote
	diffSketch := localSketch.Clone()
	if err := diffSketch.Merge(peerSketch); err != nil {
		log.Printf("erlay: failed to merge sketches: %v", err)
		r.sendReconcilDiff(false, nil)
		return
	}

	// Build list of candidates (all short IDs from both sets)
	candidates := make([]uint32, 0, len(localSet)+peerSketch.Capacity())
	for shortID := range localSet {
		candidates = append(candidates, shortID)
	}

	// Try to decode the difference
	diffIDs, err := diffSketch.DecodeWithHint(candidates)
	if err != nil {
		log.Printf("erlay: failed to decode sketch difference with %s: %v", r.peer.Address(), err)
		r.sendReconcilDiff(false, nil)
		return
	}

	// Separate: which IDs do we need (in diff but not in local), which does peer need (in diff and in local)
	weNeed := make([]uint32, 0)
	for _, shortID := range diffIDs {
		if _, inLocal := localSet[shortID]; !inLocal {
			weNeed = append(weNeed, shortID)
		}
	}

	// Send reconcildiff with the short IDs we need
	r.sendReconcilDiff(true, weNeed)

	// Clear reconciled transactions from local set
	state.mu.Lock()
	state.LastReconciliation = time.Now()
	state.mu.Unlock()

	log.Printf("erlay: reconciliation with %s succeeded, need %d txs", r.peer.Address(), len(weNeed))
}

// HandleReqReconcil processes a reconciliation request (as responder).
func (r *ErlayReconciler) HandleReqReconcil(msg *MsgReqReconcil) {
	state := r.tracker.GetState(r.peer.Address())
	if state == nil || state.Role != RoleResponder {
		log.Printf("erlay: received reqreconcil but not a responder for %s", r.peer.Address())
		return
	}

	// Estimate capacity: max of our set size and peer's set size, plus margin
	ourSize := state.SetSize()
	capacity := int(msg.SetSize)
	if ourSize > capacity {
		capacity = ourSize
	}
	capacity += 10 // Safety margin

	if capacity > MaxReconciliationCapacity {
		capacity = MaxReconciliationCapacity
	}

	// Build and send our sketch
	sketch := state.BuildSketch(capacity)
	sketchData := sketch.Serialize()

	r.peer.SendMessage(&MsgSketch{SketchData: sketchData})

	log.Printf("erlay: sent sketch to %s (capacity=%d)", r.peer.Address(), capacity)
}

// HandleReconcilDiff processes the result of reconciliation (as responder).
func (r *ErlayReconciler) HandleReconcilDiff(msg *MsgReconcilDiff) {
	state := r.tracker.GetState(r.peer.Address())
	if state == nil {
		return
	}

	if !msg.Success {
		log.Printf("erlay: reconciliation with %s failed, falling back to inv", r.peer.Address())
		// TODO: Fall back to full inv flooding for this round
		return
	}

	// Peer is asking for these short IDs - send the corresponding transactions
	state.mu.Lock()
	for _, shortID := range msg.AskShortIDs {
		if wtxid, ok := state.LocalSet[shortID]; ok {
			if r.onSendTx != nil {
				r.onSendTx(wtxid)
			}
		}
	}
	state.LastReconciliation = time.Now()
	state.mu.Unlock()

	log.Printf("erlay: peer %s requested %d txs", r.peer.Address(), len(msg.AskShortIDs))
}

// sendReconcilDiff sends the reconciliation diff result.
func (r *ErlayReconciler) sendReconcilDiff(success bool, askShortIDs []uint32) {
	msg := &MsgReconcilDiff{
		Success:     success,
		AskShortIDs: askShortIDs,
	}
	r.peer.SendMessage(msg)
}
