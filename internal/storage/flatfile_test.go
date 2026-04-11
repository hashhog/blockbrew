package storage

import (
	"bytes"
	"os"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

const testMagic = uint32(0xD9B4BEF9) // mainnet magic

func TestFlatFilePos(t *testing.T) {
	t.Run("IsNull", func(t *testing.T) {
		nullPos := FlatFilePos{FileNum: -1, Pos: 0}
		if !nullPos.IsNull() {
			t.Error("expected IsNull to return true for FileNum -1")
		}

		validPos := FlatFilePos{FileNum: 0, Pos: 100}
		if validPos.IsNull() {
			t.Error("expected IsNull to return false for FileNum 0")
		}
	})

	t.Run("Serialization", func(t *testing.T) {
		pos := FlatFilePos{FileNum: 5, Pos: 12345}

		var buf bytes.Buffer
		if err := pos.Serialize(&buf); err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		var pos2 FlatFilePos
		if err := pos2.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("Deserialize failed: %v", err)
		}

		if pos != pos2 {
			t.Errorf("round-trip failed: got %v, want %v", pos2, pos)
		}
	})
}

func TestBlockFileInfo(t *testing.T) {
	t.Run("AddBlock", func(t *testing.T) {
		fi := BlockFileInfo{}

		// Add first block
		fi.AddBlock(100, 1609459200) // height 100, time Jan 1 2021
		if fi.NumBlocks != 1 {
			t.Errorf("NumBlocks = %d, want 1", fi.NumBlocks)
		}
		if fi.HeightFirst != 100 || fi.HeightLast != 100 {
			t.Errorf("Heights = %d..%d, want 100..100", fi.HeightFirst, fi.HeightLast)
		}

		// Add second block at higher height
		fi.AddBlock(200, 1609459300)
		if fi.NumBlocks != 2 {
			t.Errorf("NumBlocks = %d, want 2", fi.NumBlocks)
		}
		if fi.HeightFirst != 100 || fi.HeightLast != 200 {
			t.Errorf("Heights = %d..%d, want 100..200", fi.HeightFirst, fi.HeightLast)
		}

		// Add block at lower height (out of order)
		fi.AddBlock(50, 1609459100)
		if fi.NumBlocks != 3 {
			t.Errorf("NumBlocks = %d, want 3", fi.NumBlocks)
		}
		if fi.HeightFirst != 50 || fi.HeightLast != 200 {
			t.Errorf("Heights = %d..%d, want 50..200", fi.HeightFirst, fi.HeightLast)
		}
		if fi.TimeFirst != 1609459100 {
			t.Errorf("TimeFirst = %d, want 1609459100", fi.TimeFirst)
		}
	})

	t.Run("Serialization", func(t *testing.T) {
		fi := BlockFileInfo{
			NumBlocks:   10,
			Size:        1000000,
			UndoSize:    50000,
			HeightFirst: 100,
			HeightLast:  200,
			TimeFirst:   1609459200,
			TimeLast:    1609459300,
		}

		var buf bytes.Buffer
		if err := fi.Serialize(&buf); err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		fi2, err := DeserializeBlockFileInfo(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("Deserialize failed: %v", err)
		}

		if *fi2 != fi {
			t.Errorf("round-trip failed: got %+v, want %+v", fi2, fi)
		}
	})
}

func TestBlockStore(t *testing.T) {
	tmpDir := t.TempDir()

	// Create in-memory DB for index
	db := NewMemDB()
	defer db.Close()

	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}
	defer bs.Close()

	t.Run("WriteAndReadBlock", func(t *testing.T) {
		blockData := []byte("test block data 12345")
		height := uint32(100)
		blockTime := uint64(1609459200)

		pos, err := bs.WriteBlock(blockData, height, blockTime)
		if err != nil {
			t.Fatalf("WriteBlock failed: %v", err)
		}

		if pos.IsNull() {
			t.Fatal("WriteBlock returned null position")
		}
		if pos.FileNum != 0 {
			t.Errorf("FileNum = %d, want 0", pos.FileNum)
		}
		if pos.Pos != StorageHeaderSize {
			t.Errorf("Pos = %d, want %d", pos.Pos, StorageHeaderSize)
		}

		// Read it back
		data, err := bs.ReadBlock(pos)
		if err != nil {
			t.Fatalf("ReadBlock failed: %v", err)
		}

		if !bytes.Equal(data, blockData) {
			t.Errorf("ReadBlock returned %q, want %q", data, blockData)
		}
	})

	t.Run("WriteMultipleBlocks", func(t *testing.T) {
		var positions []FlatFilePos
		for i := 0; i < 5; i++ {
			blockData := bytes.Repeat([]byte{byte(i)}, 1000)
			pos, err := bs.WriteBlock(blockData, uint32(200+i), 1609459200+uint64(i)*100)
			if err != nil {
				t.Fatalf("WriteBlock %d failed: %v", i, err)
			}
			positions = append(positions, pos)
		}

		// Read all back
		for i, pos := range positions {
			data, err := bs.ReadBlock(pos)
			if err != nil {
				t.Fatalf("ReadBlock %d failed: %v", i, err)
			}
			expected := bytes.Repeat([]byte{byte(i)}, 1000)
			if !bytes.Equal(data, expected) {
				t.Errorf("ReadBlock %d: data mismatch", i)
			}
		}
	})

	t.Run("FileInfo", func(t *testing.T) {
		fi := bs.GetFileInfo(0)
		if fi == nil {
			t.Fatal("GetFileInfo returned nil")
		}
		if fi.NumBlocks == 0 {
			t.Error("NumBlocks = 0, expected > 0")
		}
		if fi.Size == 0 {
			t.Error("Size = 0, expected > 0")
		}
	})

	t.Run("BadMagic", func(t *testing.T) {
		// Write with wrong magic
		filename := bs.blockFilename(999)
		file, err := os.Create(filename)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		// Write wrong magic
		file.Write([]byte{0x00, 0x00, 0x00, 0x00})
		// Write size
		file.Write([]byte{0x04, 0x00, 0x00, 0x00})
		// Write data
		file.Write([]byte("test"))
		file.Close()

		// Try to read
		_, err = bs.ReadBlock(FlatFilePos{FileNum: 999, Pos: 8})
		if err != ErrBadMagic {
			t.Errorf("expected ErrBadMagic, got %v", err)
		}

		os.Remove(filename)
	})
}

func TestBlockStoreUndo(t *testing.T) {
	tmpDir := t.TempDir()

	db := NewMemDB()
	defer db.Close()

	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}
	defer bs.Close()

	// Write a block first to create file info
	blockData := []byte("test block")
	_, err = bs.WriteBlock(blockData, 100, 1609459200)
	if err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	t.Run("WriteAndReadUndo", func(t *testing.T) {
		undoData := []byte("undo data for block")
		pos, err := bs.WriteUndo(0, undoData)
		if err != nil {
			t.Fatalf("WriteUndo failed: %v", err)
		}

		if pos.IsNull() {
			t.Fatal("WriteUndo returned null position")
		}
		if pos.FileNum != 0 {
			t.Errorf("FileNum = %d, want 0", pos.FileNum)
		}

		// Read it back
		data, err := bs.ReadUndo(pos)
		if err != nil {
			t.Fatalf("ReadUndo failed: %v", err)
		}

		if !bytes.Equal(data, undoData) {
			t.Errorf("ReadUndo returned %q, want %q", data, undoData)
		}
	})

	t.Run("UndoFileCreated", func(t *testing.T) {
		undoFile := bs.undoFilename(0)
		if _, err := os.Stat(undoFile); os.IsNotExist(err) {
			t.Error("undo file was not created")
		}
	})
}

func TestBlockStoreIndex(t *testing.T) {
	tmpDir := t.TempDir()

	db := NewMemDB()
	defer db.Close()

	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}
	defer bs.Close()

	// Create a test hash
	hash := wire.DoubleHashB([]byte("test block hash"))

	t.Run("WriteAndIndexBlock", func(t *testing.T) {
		blockData := []byte("indexed block data")
		pos, err := bs.WriteAndIndexBlock(hash, blockData, 500, 1609459200)
		if err != nil {
			t.Fatalf("WriteAndIndexBlock failed: %v", err)
		}

		if !bs.HasBlock(hash) {
			t.Error("HasBlock returned false")
		}

		// Read by hash
		data, err := bs.ReadBlockByHash(hash)
		if err != nil {
			t.Fatalf("ReadBlockByHash failed: %v", err)
		}

		if !bytes.Equal(data, blockData) {
			t.Errorf("ReadBlockByHash returned wrong data")
		}

		// Get position
		pos2, err := bs.GetBlockPos(hash)
		if err != nil {
			t.Fatalf("GetBlockPos failed: %v", err)
		}

		if pos != pos2 {
			t.Errorf("GetBlockPos = %v, want %v", pos2, pos)
		}
	})

	t.Run("WriteAndIndexUndo", func(t *testing.T) {
		undoData := []byte("indexed undo data")
		pos, err := bs.WriteAndIndexUndo(hash, 0, undoData)
		if err != nil {
			t.Fatalf("WriteAndIndexUndo failed: %v", err)
		}

		if !bs.HasUndo(hash) {
			t.Error("HasUndo returned false")
		}

		// Read by hash
		data, err := bs.ReadUndoByHash(hash)
		if err != nil {
			t.Fatalf("ReadUndoByHash failed: %v", err)
		}

		if !bytes.Equal(data, undoData) {
			t.Errorf("ReadUndoByHash returned wrong data")
		}

		// Get position
		pos2, err := bs.GetUndoPos(hash)
		if err != nil {
			t.Fatalf("GetUndoPos failed: %v", err)
		}

		if pos != pos2 {
			t.Errorf("GetUndoPos = %v, want %v", pos2, pos)
		}
	})

	t.Run("NonExistentHash", func(t *testing.T) {
		unknownHash := wire.DoubleHashB([]byte("unknown"))

		if bs.HasBlock(unknownHash) {
			t.Error("HasBlock returned true for unknown hash")
		}

		_, err := bs.ReadBlockByHash(unknownHash)
		if err != ErrNotFound {
			t.Errorf("ReadBlockByHash: expected ErrNotFound, got %v", err)
		}
	})

	t.Run("DeleteIndex", func(t *testing.T) {
		if err := bs.DeleteBlockIndex(hash); err != nil {
			t.Fatalf("DeleteBlockIndex failed: %v", err)
		}

		if bs.HasBlock(hash) {
			t.Error("HasBlock returned true after delete")
		}

		if err := bs.DeleteUndoIndex(hash); err != nil {
			t.Fatalf("DeleteUndoIndex failed: %v", err)
		}

		if bs.HasUndo(hash) {
			t.Error("HasUndo returned true after delete")
		}
	})
}

func TestBlockStoreFileRollover(t *testing.T) {
	tmpDir := t.TempDir()

	db := NewMemDB()
	defer db.Close()

	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}
	defer bs.Close()

	// Override max file size for testing
	bs.mu.Lock()
	bs.maxFileSize = 1000 // 1KB max for testing
	bs.mu.Unlock()

	// Write blocks until we roll over to a new file
	var fileNums []int32
	for i := 0; i < 10; i++ {
		blockData := bytes.Repeat([]byte{byte(i)}, 200) // 200 bytes each
		pos, err := bs.WriteBlock(blockData, uint32(i), 1609459200+uint64(i)*100)
		if err != nil {
			t.Fatalf("WriteBlock %d failed: %v", i, err)
		}
		fileNums = append(fileNums, pos.FileNum)
	}

	// Should have written to multiple files
	maxFile := int32(0)
	for _, fn := range fileNums {
		if fn > maxFile {
			maxFile = fn
		}
	}

	if maxFile == 0 {
		t.Error("expected file rollover to new file, but all blocks in file 0")
	}

	// Verify both files exist
	for i := int32(0); i <= maxFile; i++ {
		filename := bs.blockFilename(i)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Errorf("file %d does not exist", i)
		}
	}
}

func TestBlockStorePersistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create block store and write some data
	db := NewMemDB()

	bs, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}

	hash := wire.DoubleHashB([]byte("persistent block"))
	blockData := []byte("persistent block data")
	pos, err := bs.WriteAndIndexBlock(hash, blockData, 1000, 1609459200)
	if err != nil {
		t.Fatalf("WriteAndIndexBlock failed: %v", err)
	}

	// Flush to ensure state is saved
	if err := bs.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Verify state was saved
	stateData, err := db.Get(flatFileStateKey)
	if err != nil {
		t.Fatalf("Failed to get state key: %v", err)
	}
	if stateData == nil {
		t.Fatal("State data is nil after flush")
	}
	t.Logf("State data: %x (len=%d)", stateData, len(stateData))

	// Close (which also flushes)
	bs.Close()

	// Reopen with same db
	bs2, err := NewBlockStore(tmpDir, testMagic, db)
	if err != nil {
		t.Fatalf("NewBlockStore (reopen) failed: %v", err)
	}
	// Do not defer bs2.Close() here — it must be closed before db.Close().
	// See explicit bs2.Close() + db.Close() at end of test.

	// Current file should be preserved
	if bs2.CurrentFile() != pos.FileNum {
		t.Errorf("CurrentFile = %d, want %d", bs2.CurrentFile(), pos.FileNum)
	}

	// Should be able to read by hash
	data, err := bs2.ReadBlockByHash(hash)
	if err != nil {
		t.Fatalf("ReadBlockByHash after reopen failed: %v", err)
	}

	if !bytes.Equal(data, blockData) {
		t.Error("data mismatch after reopen")
	}

	// File info should be preserved
	fi := bs2.GetFileInfo(0)
	if fi == nil {
		t.Fatal("GetFileInfo returned nil after reopen")
	}
	if fi.NumBlocks == 0 {
		t.Error("NumBlocks = 0 after reopen")
	}

	// Close bs2 before closing db: bs2.Close() flushes state to db,
	// so db must still be open when bs2.Close() runs.
	bs2.Close()
	db.Close()
}

func TestBlockStoreNoDB(t *testing.T) {
	tmpDir := t.TempDir()

	// Create block store without DB (index won't be persisted)
	bs, err := NewBlockStore(tmpDir, testMagic, nil)
	if err != nil {
		t.Fatalf("NewBlockStore failed: %v", err)
	}
	defer bs.Close()

	// Write a block
	blockData := []byte("test block without index")
	pos, err := bs.WriteBlock(blockData, 100, 1609459200)
	if err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	// Can still read by position
	data, err := bs.ReadBlock(pos)
	if err != nil {
		t.Fatalf("ReadBlock failed: %v", err)
	}

	if !bytes.Equal(data, blockData) {
		t.Error("data mismatch")
	}

	// HasBlock always returns false without DB
	hash := wire.DoubleHashB([]byte("test"))
	if bs.HasBlock(hash) {
		t.Error("HasBlock should return false without DB")
	}
}
