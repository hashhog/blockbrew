package storage

import (
	"bytes"
	"os"
	"testing"
)

// rolloverStore writes 200-byte blocks into 1000-byte files until the store
// has rolled over at least three times.
func rolloverStore(t *testing.T) *BlockStore {
	t.Helper()
	bs, err := NewBlockStore(t.TempDir(), testMagic, NewMemDB())
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	bs.mu.Lock()
	bs.maxFileSize = 1000
	bs.mu.Unlock()
	for i := 0; bs.CurrentFile() < 3; i++ {
		if _, err := bs.WriteBlock(bytes.Repeat([]byte{byte(i)}, 200), uint32(i), 1609459200+uint64(i)); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}
	return bs
}

// TestBlockStoreCloseSyncsOnlyTheCurrentFile: every block write is already
// fsynced, so Close must not fsync every finished block file again (one
// fsync per file was 18 s on the saturated mainnet disk).
//
// Negative control: with Flush looping flushFile over every file (the
// 985c117 behaviour) Close makes 4 fsyncs here and the test fails.
func TestBlockStoreCloseSyncsOnlyTheCurrentFile(t *testing.T) {
	bs := rolloverStore(t)
	before := bs.fileSyncs.Load()
	if err := bs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := bs.fileSyncs.Load() - before; n != 1 {
		t.Fatalf("Close made %d block-file fsyncs with %d files, want 1 (the current file)", n, bs.CurrentFile()+1)
	}
	for i := int32(0); i < bs.CurrentFile(); i++ {
		st, err := os.Stat(bs.blockFilename(i))
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != int64(bs.fileInfo[i].Size) {
			t.Fatalf("finished file %d is %d bytes, want its used size %d", i, st.Size(), bs.fileInfo[i].Size)
		}
	}
}

// A finished file whose finalizing truncation was lost (pre-allocated tail
// still there, as after a crash on a datadir written by the old order) is
// finalized by Close.
//
// Negative control: with the finishedFileNeedsFinalize step removed from
// Flush, file 1 keeps its tail and the test fails.
func TestBlockStoreCloseFinalizesAnOversizedFinishedFile(t *testing.T) {
	bs := rolloverStore(t)
	want := int64(bs.fileInfo[1].Size)
	if err := os.Truncate(bs.blockFilename(1), 16<<20); err != nil {
		t.Fatal(err)
	}
	if err := bs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, err := os.Stat(bs.blockFilename(1))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != want {
		t.Fatalf("finished file 1 is %d bytes after Close, want %d", st.Size(), want)
	}
}
