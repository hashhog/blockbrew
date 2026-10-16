package storage

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestSnapshotBaseRecordWithoutChainwork: a snapshot whose assumeutxo entry
// carries no base-tail headers has no detached band and no known base work,
// but its base must still be recorded — the startup consistency probe reads
// the height as the floor of the body-less range. It used to be refused
// ("nil chainwork"), so such datadirs had no record at all.
func TestSnapshotBaseRecordWithoutChainwork(t *testing.T) {
	db := NewChainDB(NewMemDB())
	hash := wire.Hash256{0xab}
	if err := db.SetSnapshotBase(&SnapshotBase{Hash: hash, Height: 299}); err != nil {
		t.Fatalf("SetSnapshotBase without chainwork: %v", err)
	}
	sb, err := db.GetSnapshotBase()
	if err != nil {
		t.Fatalf("GetSnapshotBase: %v", err)
	}
	if sb.Hash != hash || sb.Height != 299 {
		t.Fatalf("round trip: got %s@%d", sb.Hash.String(), sb.Height)
	}
	if sb.Chainwork == nil || sb.Chainwork.Sign() != 0 {
		t.Fatalf("no-band record must read back zero (non-nil) chainwork, got %v", sb.Chainwork)
	}

	// A band record keeps its work.
	work := big.NewInt(0x1234567)
	if err := db.SetSnapshotBase(&SnapshotBase{Hash: hash, Height: 299, Chainwork: work}); err != nil {
		t.Fatalf("SetSnapshotBase with chainwork: %v", err)
	}
	if sb, err = db.GetSnapshotBase(); err != nil || sb.Chainwork.Cmp(work) != 0 {
		t.Fatalf("band record round trip: %+v err=%v", sb, err)
	}

	if err := db.SetSnapshotBase(nil); err == nil {
		t.Fatal("nil record must still be refused")
	}
}
