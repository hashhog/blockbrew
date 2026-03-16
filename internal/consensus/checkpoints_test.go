package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestNewCheckpointData(t *testing.T) {
	checkpoints := []Checkpoint{
		{100, mustParseHash("0000000000000000000000000000000000000000000000000000000000000100")},
		{200, mustParseHash("0000000000000000000000000000000000000000000000000000000000000200")},
		{300, mustParseHash("0000000000000000000000000000000000000000000000000000000000000300")},
	}

	cd := NewCheckpointData(checkpoints)

	if cd == nil {
		t.Fatal("checkpoint data should not be nil")
	}

	if len(cd.Checkpoints) != 3 {
		t.Errorf("expected 3 checkpoints, got %d", len(cd.Checkpoints))
	}

	// Verify byHeight map was populated
	for _, cp := range checkpoints {
		hash, ok := cd.GetCheckpointByHeight(cp.Height)
		if !ok {
			t.Errorf("checkpoint at height %d not found", cp.Height)
		}
		if hash != cp.Hash {
			t.Errorf("checkpoint hash mismatch at height %d", cp.Height)
		}
	}

	// Verify last checkpoint is the highest
	lastCP := cd.GetLastCheckpoint()
	if lastCP == nil {
		t.Fatal("last checkpoint should not be nil")
	}
	if lastCP.Height != 300 {
		t.Errorf("last checkpoint height = %d, want 300", lastCP.Height)
	}
}

func TestCheckpointDataEmpty(t *testing.T) {
	cd := NewCheckpointData(nil)

	if !cd.IsEmpty() {
		t.Error("checkpoint data with nil should be empty")
	}

	// Should handle nil gracefully
	if cd.GetLastCheckpoint() != nil {
		t.Error("last checkpoint should be nil for empty data")
	}

	hash, ok := cd.GetCheckpointByHeight(100)
	if ok {
		t.Error("should not find checkpoint in empty data")
	}
	if !hash.IsZero() {
		t.Error("hash should be zero for not found")
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	expectedHash := mustParseHash("0000000000000000000000000000000000000000000000000000000000000100")
	wrongHash := mustParseHash("0000000000000000000000000000000000000000000000000000000000000999")

	checkpoints := []Checkpoint{
		{100, expectedHash},
	}
	cd := NewCheckpointData(checkpoints)

	tests := []struct {
		name      string
		height    int32
		hash      wire.Hash256
		wantErr   error
	}{
		{
			name:    "matching checkpoint",
			height:  100,
			hash:    expectedHash,
			wantErr: nil,
		},
		{
			name:    "mismatched checkpoint",
			height:  100,
			hash:    wrongHash,
			wantErr: ErrCheckpointMismatch,
		},
		{
			name:    "no checkpoint at height",
			height:  50,
			hash:    wrongHash,
			wantErr: nil, // No checkpoint at this height, so no error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCheckpoint(cd, tt.height, tt.hash)
			if err != tt.wantErr {
				t.Errorf("VerifyCheckpoint() error = %v, want %v", err, tt.wantErr)
			}
		})
	}

	// Test with nil checkpoint data
	err := VerifyCheckpoint(nil, 100, wrongHash)
	if err != nil {
		t.Errorf("VerifyCheckpoint with nil data should return nil, got %v", err)
	}
}

func TestCheckForkBeforeLastCheckpoint(t *testing.T) {
	checkpoints := []Checkpoint{
		{100, mustParseHash("0000000000000000000000000000000000000000000000000000000000000100")},
		{200, mustParseHash("0000000000000000000000000000000000000000000000000000000000000200")},
	}
	cd := NewCheckpointData(checkpoints)

	tests := []struct {
		name    string
		height  int32
		isFork  bool
		wantErr error
	}{
		{
			name:    "header above checkpoint not a fork",
			height:  250,
			isFork:  false,
			wantErr: nil,
		},
		{
			name:    "header above checkpoint is a fork (ok - fork after checkpoint)",
			height:  250,
			isFork:  true,
			wantErr: nil,
		},
		{
			name:    "header at checkpoint not a fork",
			height:  200,
			isFork:  false,
			wantErr: nil,
		},
		{
			name:    "header at checkpoint is a fork (rejected)",
			height:  200,
			isFork:  true,
			wantErr: ErrForkBeforeCheckpoint,
		},
		{
			name:    "header below checkpoint not a fork",
			height:  150,
			isFork:  false,
			wantErr: nil,
		},
		{
			name:    "header below checkpoint is a fork (rejected)",
			height:  150,
			isFork:  true,
			wantErr: ErrForkBeforeCheckpoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckForkBeforeLastCheckpoint(cd, tt.height, tt.isFork)
			if err != tt.wantErr {
				t.Errorf("CheckForkBeforeLastCheckpoint() error = %v, want %v", err, tt.wantErr)
			}
		})
	}

	// Test with nil/empty checkpoint data
	err := CheckForkBeforeLastCheckpoint(nil, 100, true)
	if err != nil {
		t.Errorf("CheckForkBeforeLastCheckpoint with nil data should return nil, got %v", err)
	}

	emptyCD := NewCheckpointData(nil)
	err = CheckForkBeforeLastCheckpoint(emptyCD, 100, true)
	if err != nil {
		t.Errorf("CheckForkBeforeLastCheckpoint with empty data should return nil, got %v", err)
	}
}

func TestGetCheckpointsForNetwork(t *testing.T) {
	tests := []struct {
		network        string
		expectNonEmpty bool
		expectLastCP   int32 // Expected last checkpoint height, 0 if empty
	}{
		{"mainnet", true, 295000},
		{"testnet3", true, 546},
		{"testnet4", false, 0},
		{"signet", false, 0},
		{"regtest", false, 0},
		{"unknown", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			cd := GetCheckpointsForNetwork(tt.network)

			if tt.expectNonEmpty && cd.IsEmpty() {
				t.Errorf("expected non-empty checkpoints for %s", tt.network)
			}
			if !tt.expectNonEmpty && !cd.IsEmpty() {
				t.Errorf("expected empty checkpoints for %s", tt.network)
			}

			if tt.expectLastCP > 0 {
				lastCP := cd.GetLastCheckpoint()
				if lastCP == nil {
					t.Errorf("expected last checkpoint for %s", tt.network)
				} else if lastCP.Height != tt.expectLastCP {
					t.Errorf("last checkpoint height = %d, want %d", lastCP.Height, tt.expectLastCP)
				}
			}
		})
	}
}

func TestMainnetCheckpointsAreValid(t *testing.T) {
	// Verify all mainnet checkpoints have valid hashes
	for _, cp := range MainnetCheckpoints {
		if cp.Height <= 0 {
			t.Errorf("checkpoint height %d should be positive", cp.Height)
		}
		if cp.Hash.IsZero() {
			t.Errorf("checkpoint at height %d has zero hash", cp.Height)
		}
	}

	// Verify checkpoints are in ascending order
	for i := 1; i < len(MainnetCheckpoints); i++ {
		if MainnetCheckpoints[i].Height <= MainnetCheckpoints[i-1].Height {
			t.Errorf("checkpoints not in ascending order at index %d", i)
		}
	}
}

func TestHeaderIndexCheckpointIntegration(t *testing.T) {
	// Test that HeaderIndex properly uses checkpoint data
	params := MainnetParams()
	idx := NewHeaderIndex(params)

	// Should have checkpoint data loaded
	cd := idx.GetCheckpointData()
	if cd == nil {
		t.Fatal("mainnet should have checkpoint data")
	}

	if cd.IsEmpty() {
		t.Error("mainnet checkpoint data should not be empty")
	}

	// GetLastCheckpoint should work
	lastCP := idx.GetLastCheckpoint()
	if lastCP == nil {
		t.Fatal("mainnet should have a last checkpoint")
	}
	if lastCP.Height != 295000 {
		t.Errorf("last checkpoint height = %d, want 295000", lastCP.Height)
	}
}

func TestRegtestNoCheckpoints(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	cd := idx.GetCheckpointData()
	if cd == nil {
		t.Fatal("checkpoint data should not be nil (but can be empty)")
	}

	if !cd.IsEmpty() {
		t.Error("regtest should have no checkpoints")
	}

	if idx.GetLastCheckpoint() != nil {
		t.Error("regtest should have no last checkpoint")
	}
}

func TestCheckpointForkRejectionInHeaderIndex(t *testing.T) {
	// Create a custom test scenario using regtest with fake checkpoints
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build a chain of 5 headers
	nodes := make([]*BlockNode, 6)
	nodes[0] = idx.genesis
	prevNode := idx.genesis

	for i := 1; i <= 5; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		nodes[i] = node
		prevNode = node
	}

	// Manually inject a checkpoint at height 3 to test fork rejection
	fakeCheckpoint := Checkpoint{
		Height: 3,
		Hash:   nodes[3].Hash,
	}
	idx.checkpointData = NewCheckpointData([]Checkpoint{fakeCheckpoint})

	// Now try to create a fork at height 2 (before checkpoint)
	// This should fail because it would fork before the checkpoint
	forkHeader := createTestHeader(
		nodes[1].Hash, // Fork from height 1
		nodes[1].Header.Timestamp+700, // Different timestamp
		uint32(999), // Different nonce for different hash
	)

	_, err := idx.AddHeader(forkHeader)
	if err != ErrForkBeforeCheckpoint {
		t.Errorf("expected ErrForkBeforeCheckpoint, got %v", err)
	}

	// But extending the main chain should still work
	extendHeader := createTestHeader(
		nodes[5].Hash,
		nodes[5].Header.Timestamp+600,
		uint32(6),
	)
	_, err = idx.AddHeader(extendHeader)
	if err != nil {
		t.Errorf("extending main chain should work, got error: %v", err)
	}

	// And forking after the checkpoint should also work
	// Fork from height 4 (after checkpoint at 3)
	afterCheckpointFork := createTestHeader(
		nodes[4].Hash, // Fork from height 4
		nodes[4].Header.Timestamp+700,
		uint32(1000),
	)
	_, err = idx.AddHeader(afterCheckpointFork)
	if err != nil {
		t.Errorf("fork after checkpoint should work, got error: %v", err)
	}
}

func TestCheckpointMismatchRejection(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	// Build 3 headers
	nodes := make([]*BlockNode, 4)
	nodes[0] = idx.genesis
	prevNode := idx.genesis

	for i := 1; i <= 3; i++ {
		header := createTestHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		nodes[i] = node
		prevNode = node
	}

	// Set a checkpoint at height 4 with a specific hash
	expectedHash := mustParseHash("0000000000000000000000000000000000000000000000000000000000004444")
	idx.checkpointData = NewCheckpointData([]Checkpoint{
		{4, expectedHash},
	})

	// Try to add a header at height 4 that doesn't match the checkpoint
	badHeader := createTestHeader(
		nodes[3].Hash,
		nodes[3].Header.Timestamp+600,
		uint32(4),
	)

	// The hash of badHeader almost certainly won't match expectedHash
	_, err := idx.AddHeader(badHeader)
	if err != ErrCheckpointMismatch {
		t.Errorf("expected ErrCheckpointMismatch, got %v", err)
	}
}
