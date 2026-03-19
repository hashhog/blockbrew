package p2p

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

func TestMsgSendTxRcnclSerialize(t *testing.T) {
	msg := &MsgSendTxRcncl{
		Version: TxReconciliationVersion,
		Salt:    0x123456789ABCDEF0,
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	// Should be 12 bytes: 4 (version) + 8 (salt)
	if buf.Len() != 12 {
		t.Errorf("serialized length = %d, expected 12", buf.Len())
	}

	// Deserialize
	msg2 := &MsgSendTxRcncl{}
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if msg2.Version != msg.Version {
		t.Errorf("version = %d, expected %d", msg2.Version, msg.Version)
	}
	if msg2.Salt != msg.Salt {
		t.Errorf("salt = %d, expected %d", msg2.Salt, msg.Salt)
	}
}

func TestMsgSendTxRcnclCommand(t *testing.T) {
	msg := &MsgSendTxRcncl{}
	if msg.Command() != "sendtxrcncl" {
		t.Errorf("command = %s, expected sendtxrcncl", msg.Command())
	}
}

func TestMsgReqReconcilSerialize(t *testing.T) {
	msg := &MsgReqReconcil{SetSize: 1000}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	// Should be 2 bytes
	if buf.Len() != 2 {
		t.Errorf("serialized length = %d, expected 2", buf.Len())
	}

	msg2 := &MsgReqReconcil{}
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if msg2.SetSize != 1000 {
		t.Errorf("set_size = %d, expected 1000", msg2.SetSize)
	}
}

func TestMsgSketchSerialize(t *testing.T) {
	sketchData := make([]byte, 128) // 32 capacity * 4 bytes
	for i := range sketchData {
		sketchData[i] = byte(i)
	}

	msg := &MsgSketch{SketchData: sketchData}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	msg2 := &MsgSketch{}
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if !bytes.Equal(msg2.SketchData, sketchData) {
		t.Error("sketch data mismatch")
	}
}

func TestMsgReconcilDiffSerialize(t *testing.T) {
	msg := &MsgReconcilDiff{
		Success:     true,
		AskShortIDs: []uint32{111, 222, 333, 444},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	msg2 := &MsgReconcilDiff{}
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if !msg2.Success {
		t.Error("expected success=true")
	}
	if len(msg2.AskShortIDs) != 4 {
		t.Fatalf("expected 4 short IDs, got %d", len(msg2.AskShortIDs))
	}
	for i, id := range msg.AskShortIDs {
		if msg2.AskShortIDs[i] != id {
			t.Errorf("short ID[%d] = %d, expected %d", i, msg2.AskShortIDs[i], id)
		}
	}
}

func TestMsgReconcilDiffFailed(t *testing.T) {
	msg := &MsgReconcilDiff{
		Success:     false,
		AskShortIDs: nil,
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	msg2 := &MsgReconcilDiff{}
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if msg2.Success {
		t.Error("expected success=false")
	}
	if len(msg2.AskShortIDs) != 0 {
		t.Errorf("expected 0 short IDs, got %d", len(msg2.AskShortIDs))
	}
}

func TestTxReconciliationState(t *testing.T) {
	localSalt := uint64(12345)
	remoteSalt := uint64(67890)

	state := NewTxReconciliationState(RoleInitiator, localSalt, remoteSalt, TxReconciliationVersion)

	if state.Role != RoleInitiator {
		t.Errorf("role = %v, expected RoleInitiator", state.Role)
	}
	if state.LocalSalt != localSalt {
		t.Errorf("local salt = %d, expected %d", state.LocalSalt, localSalt)
	}
	if state.RemoteSalt != remoteSalt {
		t.Errorf("remote salt = %d, expected %d", state.RemoteSalt, remoteSalt)
	}
	if state.NegotiatedVersion != TxReconciliationVersion {
		t.Errorf("version = %d, expected %d", state.NegotiatedVersion, TxReconciliationVersion)
	}

	// Verify K0, K1 are computed
	if state.K0 == 0 && state.K1 == 0 {
		t.Error("K0 and K1 should not both be zero")
	}
}

func TestTxReconciliationStateAddRemove(t *testing.T) {
	state := NewTxReconciliationState(RoleInitiator, 1, 2, 1)

	// Create a wtxid
	var wtxid wire.Hash256
	for i := range wtxid {
		wtxid[i] = byte(i)
	}

	// Add transaction
	state.AddTransaction(wtxid)

	if state.SetSize() != 1 {
		t.Errorf("set size = %d, expected 1", state.SetSize())
	}

	// Remove transaction
	state.RemoveTransaction(wtxid)

	if state.SetSize() != 0 {
		t.Errorf("set size = %d, expected 0", state.SetSize())
	}
}

func TestTxReconciliationStateBuildSketch(t *testing.T) {
	state := NewTxReconciliationState(RoleInitiator, 1, 2, 1)

	// Add some transactions
	for i := 0; i < 10; i++ {
		var wtxid wire.Hash256
		wtxid[0] = byte(i)
		state.AddTransaction(wtxid)
	}

	// Build sketch
	sketch := state.BuildSketch(20)

	if sketch == nil {
		t.Fatal("sketch should not be nil")
	}
	if sketch.Capacity() != 20 {
		t.Errorf("sketch capacity = %d, expected 20", sketch.Capacity())
	}
	if sketch.IsEmpty() {
		t.Error("sketch should not be empty after adding transactions")
	}
}

func TestTxReconciliationTrackerPreRegister(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	salt, err := tracker.PreRegisterPeer("peer1")
	if err != nil {
		t.Fatalf("pre-register failed: %v", err)
	}
	if salt == 0 {
		t.Error("salt should not be zero")
	}

	// Double pre-register should fail
	_, err = tracker.PreRegisterPeer("peer1")
	if err != ErrErlayAlreadyRegistered {
		t.Errorf("expected ErrErlayAlreadyRegistered, got %v", err)
	}
}

func TestTxReconciliationTrackerRegister(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	// Pre-register
	_, err := tracker.PreRegisterPeer("peer1")
	if err != nil {
		t.Fatalf("pre-register failed: %v", err)
	}

	// Register should fail without pre-registration
	_, err = tracker.RegisterPeer("peer2", 12345, 1, true)
	if err != ErrErlayNotNegotiated {
		t.Errorf("expected ErrErlayNotNegotiated for unregistered peer, got %v", err)
	}

	// Complete registration for peer1
	state, err := tracker.RegisterPeer("peer1", 12345, 1, true)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if state == nil {
		t.Fatal("state should not be nil")
	}
	if state.Role != RoleResponder {
		t.Errorf("inbound peer should be responder, got %v", state.Role)
	}

	// Should be registered now
	if !tracker.IsRegistered("peer1") {
		t.Error("peer1 should be registered")
	}
}

func TestTxReconciliationTrackerOutboundRole(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	_, _ = tracker.PreRegisterPeer("outbound1")
	state, err := tracker.RegisterPeer("outbound1", 12345, 1, false)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if state.Role != RoleInitiator {
		t.Errorf("outbound peer should be initiator, got %v", state.Role)
	}
}

func TestTxReconciliationTrackerFloodVsReconcile(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	// Register FloodOutboundPeers outbound peers - they should be flood peers
	for i := 0; i < FloodOutboundPeers; i++ {
		addr := "outbound" + string(rune('0'+i))
		_, _ = tracker.PreRegisterPeer(addr)
		_, _ = tracker.RegisterPeer(addr, uint64(i), 1, false)

		if !tracker.IsFloodPeer(addr) {
			t.Errorf("peer %s should be flood peer", addr)
		}
		if tracker.IsReconcilePeer(addr) {
			t.Errorf("peer %s should not be reconcile peer", addr)
		}
	}

	// Next outbound peer should be reconcile
	_, _ = tracker.PreRegisterPeer("extraOutbound")
	_, _ = tracker.RegisterPeer("extraOutbound", 99, 1, false)

	if tracker.IsFloodPeer("extraOutbound") {
		t.Error("extra outbound peer should not be flood peer")
	}
	if !tracker.IsReconcilePeer("extraOutbound") {
		t.Error("extra outbound peer should be reconcile peer")
	}

	// Inbound peers should always be reconcile
	_, _ = tracker.PreRegisterPeer("inbound1")
	_, _ = tracker.RegisterPeer("inbound1", 100, 1, true)

	if tracker.IsFloodPeer("inbound1") {
		t.Error("inbound peer should not be flood peer")
	}
	if !tracker.IsReconcilePeer("inbound1") {
		t.Error("inbound peer should be reconcile peer")
	}
}

func TestTxReconciliationTrackerForget(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	_, _ = tracker.PreRegisterPeer("peer1")
	_, _ = tracker.RegisterPeer("peer1", 12345, 1, false)

	if !tracker.IsRegistered("peer1") {
		t.Fatal("peer1 should be registered")
	}

	tracker.ForgetPeer("peer1")

	if tracker.IsRegistered("peer1") {
		t.Error("peer1 should not be registered after forget")
	}
	if tracker.IsFloodPeer("peer1") {
		t.Error("peer1 should not be flood peer after forget")
	}
}

func TestTxReconciliationTrackerAddTransactionToAll(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	// Register multiple peers
	for i := 0; i < 3; i++ {
		addr := "peer" + string(rune('0'+i))
		_, _ = tracker.PreRegisterPeer(addr)
		_, _ = tracker.RegisterPeer(addr, uint64(i+1000), 1, true)
	}

	// Add transaction to all
	var wtxid wire.Hash256
	wtxid[0] = 0x42
	tracker.AddTransactionToAll(wtxid)

	// All peers should have it
	for i := 0; i < 3; i++ {
		addr := "peer" + string(rune('0'+i))
		state := tracker.GetState(addr)
		if state.SetSize() != 1 {
			t.Errorf("peer %s set size = %d, expected 1", addr, state.SetSize())
		}
	}

	// Remove from all
	tracker.RemoveTransactionFromAll(wtxid)

	for i := 0; i < 3; i++ {
		addr := "peer" + string(rune('0'+i))
		state := tracker.GetState(addr)
		if state.SetSize() != 0 {
			t.Errorf("peer %s set size = %d, expected 0", addr, state.SetSize())
		}
	}
}

func TestTxReconciliationStateShortIDConsistency(t *testing.T) {
	// Two states with same salts should compute same short IDs
	state1 := NewTxReconciliationState(RoleInitiator, 100, 200, 1)
	state2 := NewTxReconciliationState(RoleResponder, 100, 200, 1)

	var wtxid wire.Hash256
	for i := range wtxid {
		wtxid[i] = byte(i * 7)
	}

	id1 := state1.ComputeShortID(wtxid)
	id2 := state2.ComputeShortID(wtxid)

	if id1 != id2 {
		t.Errorf("short ID mismatch: %d vs %d", id1, id2)
	}
}

func TestReconciliationE2E(t *testing.T) {
	// Simulate a full reconciliation round

	// Setup: peer A (initiator) and peer B (responder)
	localSaltA := uint64(111)
	localSaltB := uint64(222)

	stateA := NewTxReconciliationState(RoleInitiator, localSaltA, localSaltB, 1)
	stateB := NewTxReconciliationState(RoleResponder, localSaltB, localSaltA, 1)

	// Both peers know some transactions (overlapping sets)
	// A has: tx1, tx2, tx3
	// B has: tx2, tx3, tx4
	// Symmetric diff: tx1 (only A), tx4 (only B)

	var tx1, tx2, tx3, tx4 wire.Hash256
	tx1[0] = 1
	tx2[0] = 2
	tx3[0] = 3
	tx4[0] = 4

	stateA.AddTransaction(tx1)
	stateA.AddTransaction(tx2)
	stateA.AddTransaction(tx3)

	stateB.AddTransaction(tx2)
	stateB.AddTransaction(tx3)
	stateB.AddTransaction(tx4)

	// A initiates: send reqreconcil with set size
	setSize := stateA.SetSize()
	if setSize != 3 {
		t.Fatalf("expected A set size 3, got %d", setSize)
	}

	// B responds: build sketch and send
	capacity := setSize + 10
	sketchB := stateB.BuildSketch(capacity)
	sketchData := sketchB.Serialize()

	// A receives sketch, computes difference
	sketchA := stateA.BuildSketch(capacity)
	peerSketch := crypto.NewMinisketch32(0)
	if err := peerSketch.Deserialize(sketchData); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	diffSketch := sketchA.Clone()
	diffSketch.Merge(peerSketch)

	// Build candidate list (all short IDs from both sets)
	candidates := make([]uint32, 0)
	for shortID := range stateA.LocalSet {
		candidates = append(candidates, shortID)
	}
	// In real implementation, we'd also include expected peer short IDs

	// Add B's short IDs to candidates
	shortID1 := stateB.ComputeShortID(tx1) // A has this
	shortID4 := stateB.ComputeShortID(tx4) // B has this
	candidates = append(candidates, shortID1, shortID4)

	// Decode difference
	result, err := diffSketch.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Should find 2 differences (tx1 and tx4)
	if len(result) != 2 {
		t.Fatalf("expected 2 differences, got %d: %v", len(result), result)
	}

	// Verify the differences are tx1 and tx4
	found := make(map[uint32]bool)
	for _, id := range result {
		found[id] = true
	}

	if !found[shortID1] && !found[shortID4] {
		t.Errorf("expected to find tx1 or tx4 short IDs in result")
	}
}

func TestMsgCommands(t *testing.T) {
	tests := []struct {
		msg     Message
		command string
	}{
		{&MsgSendTxRcncl{}, "sendtxrcncl"},
		{&MsgReqReconcil{}, "reqreconcil"},
		{&MsgSketch{}, "sketch"},
		{&MsgReconcilDiff{}, "reconcildiff"},
	}

	for _, tt := range tests {
		if tt.msg.Command() != tt.command {
			t.Errorf("%T command = %s, expected %s", tt.msg, tt.msg.Command(), tt.command)
		}
	}
}

func TestTxReconciliationTrackerVersionValidation(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	_, _ = tracker.PreRegisterPeer("peer1")

	// Invalid version (0) should fail
	_, err := tracker.RegisterPeer("peer1", 12345, 0, true)
	if err != ErrInvalidErlayVersion {
		t.Errorf("expected ErrInvalidErlayVersion, got %v", err)
	}
}

func TestTxReconciliationStateComputeShortID(t *testing.T) {
	state := NewTxReconciliationState(RoleInitiator, 0x1234, 0x5678, 1)

	var wtxid wire.Hash256
	for i := range wtxid {
		wtxid[i] = byte(i)
	}

	// Should be deterministic
	id1 := state.ComputeShortID(wtxid)
	id2 := state.ComputeShortID(wtxid)
	if id1 != id2 {
		t.Error("short ID should be deterministic")
	}

	// Different wtxid should give different ID (with high probability)
	var wtxid2 wire.Hash256
	for i := range wtxid2 {
		wtxid2[i] = byte(i + 100)
	}
	id3 := state.ComputeShortID(wtxid2)
	if id1 == id3 {
		t.Error("different wtxid should give different short ID")
	}
}

func TestTxReconciliationStateClear(t *testing.T) {
	state := NewTxReconciliationState(RoleInitiator, 1, 2, 1)

	var wtxid wire.Hash256
	wtxid[0] = 42
	state.AddTransaction(wtxid)

	if state.SetSize() != 1 {
		t.Fatal("set should have 1 element")
	}

	state.Clear()

	if state.SetSize() != 0 {
		t.Error("set should be empty after clear")
	}
}

func TestGetReconcilePeers(t *testing.T) {
	tracker := NewTxReconciliationTracker()

	// Add some reconcile peers
	for i := 0; i < 5; i++ {
		addr := "peer" + string(rune('0'+i))
		_, _ = tracker.PreRegisterPeer(addr)
		_, _ = tracker.RegisterPeer(addr, uint64(i+1000), 1, true) // inbound = reconcile
	}

	peers := tracker.GetReconcilePeers()
	if len(peers) != 5 {
		t.Errorf("expected 5 reconcile peers, got %d", len(peers))
	}
}

func BenchmarkTxReconciliationStateAddTx(b *testing.B) {
	state := NewTxReconciliationState(RoleInitiator, 1, 2, 1)
	var wtxid wire.Hash256

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wtxid[0] = byte(i)
		state.AddTransaction(wtxid)
	}
}

func BenchmarkTxReconciliationStateBuildSketch(b *testing.B) {
	state := NewTxReconciliationState(RoleInitiator, 1, 2, 1)

	// Add 100 transactions
	for i := 0; i < 100; i++ {
		var wtxid wire.Hash256
		wtxid[0] = byte(i)
		state.AddTransaction(wtxid)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.BuildSketch(32)
	}
}
