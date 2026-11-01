package p2p

import (
	"fmt"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP37 bloom filter constants.
const (
	// MaxFilterLoadHashFuncs is the maximum number of hash functions in a filter.
	MaxFilterLoadHashFuncs = 50

	// MaxFilterLoadFilterSize is the maximum filter size in bytes (36,000).
	MaxFilterLoadFilterSize = 36000

	// BloomUpdateNone indicates the filter should not be updated with matched outputs.
	BloomUpdateNone uint8 = 0

	// BloomUpdateAll indicates the filter should be updated with all matched outputs.
	BloomUpdateAll uint8 = 1

	// BloomUpdateP2PubkeyOnly indicates the filter should be updated only for
	// pay-to-pubkey or multisig outputs.
	BloomUpdateP2PubkeyOnly uint8 = 2

	// MaxMerkleBlockHashes is the most hashes a merkleblock can carry inside
	// a MaxPayloadSize message (32 bytes each): 125,000.
	MaxMerkleBlockHashes = MaxPayloadSize / 32

	// merkleBlockHashAllocStep caps the initial hash-slice capacity; the
	// slice grows only as hashes are actually read.
	merkleBlockHashAllocStep = 4096
)

// MsgFilterLoad is the "filterload" message (BIP37) that sets a bloom filter
// on the connection. Legacy SPV message; modern nodes use BIP157/158 instead.
type MsgFilterLoad struct {
	Filter    []byte // The bloom filter data
	HashFuncs uint32 // Number of hash functions
	Tweak     uint32 // Random value to add to seed
	Flags     uint8  // Bloom update flags
}

// Command returns the protocol command string for the message.
func (m *MsgFilterLoad) Command() string { return "filterload" }

// Serialize writes the filterload message to w.
func (m *MsgFilterLoad) Serialize(w io.Writer) error {
	if err := wire.WriteVarBytes(w, m.Filter); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(w, m.HashFuncs); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(w, m.Tweak); err != nil {
		return err
	}
	return wire.WriteUint8(w, m.Flags)
}

// Deserialize reads the filterload message from r.
func (m *MsgFilterLoad) Deserialize(r io.Reader) error {
	var err error
	m.Filter, err = wire.ReadVarBytes(r, MaxFilterLoadFilterSize)
	if err != nil {
		return err
	}
	m.HashFuncs, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	if m.HashFuncs > MaxFilterLoadHashFuncs {
		return fmt.Errorf("p2p: filterload hash funcs %d exceeds max %d", m.HashFuncs, MaxFilterLoadHashFuncs)
	}
	m.Tweak, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	m.Flags, err = wire.ReadUint8(r)
	return err
}

// MsgFilterAdd is the "filteradd" message (BIP37) that adds data to the
// peer's current bloom filter.
type MsgFilterAdd struct {
	Data []byte // Element to add to the filter (max 520 bytes)
}

// MaxFilterAddDataSize is the maximum size of data that can be added to a filter.
const MaxFilterAddDataSize = 520

// Command returns the protocol command string for the message.
func (m *MsgFilterAdd) Command() string { return "filteradd" }

// Serialize writes the filteradd message to w.
func (m *MsgFilterAdd) Serialize(w io.Writer) error {
	return wire.WriteVarBytes(w, m.Data)
}

// Deserialize reads the filteradd message from r.
func (m *MsgFilterAdd) Deserialize(r io.Reader) error {
	var err error
	m.Data, err = wire.ReadVarBytes(r, MaxFilterAddDataSize)
	return err
}

// MsgFilterClear is the "filterclear" message (BIP37) that removes the
// bloom filter from the connection.
type MsgFilterClear struct{}

// Command returns the protocol command string for the message.
func (m *MsgFilterClear) Command() string { return "filterclear" }

// Serialize writes the filterclear message to w (no payload).
func (m *MsgFilterClear) Serialize(w io.Writer) error { return nil }

// Deserialize reads the filterclear message from r (no payload).
func (m *MsgFilterClear) Deserialize(r io.Reader) error { return nil }

// MsgMerkleBlock is the "merkleblock" message (BIP37) containing a filtered
// block using a merkle branch to prove inclusion of matching transactions.
type MsgMerkleBlock struct {
	Header       wire.BlockHeader // Block header
	TxCount      uint32           // Total transactions in block
	Hashes       []wire.Hash256   // Transaction hashes in partial merkle tree
	Flags        []byte           // Bit flags for partial merkle tree
}

// Command returns the protocol command string for the message.
func (m *MsgMerkleBlock) Command() string { return "merkleblock" }

// Serialize writes the merkleblock message to w.
func (m *MsgMerkleBlock) Serialize(w io.Writer) error {
	if err := m.Header.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(w, m.TxCount); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.Hashes))); err != nil {
		return err
	}
	for _, hash := range m.Hashes {
		if err := hash.Serialize(w); err != nil {
			return err
		}
	}
	return wire.WriteVarBytes(w, m.Flags)
}

// Deserialize reads the merkleblock message from r.
func (m *MsgMerkleBlock) Deserialize(r io.Reader) error {
	if err := m.Header.Deserialize(r); err != nil {
		return err
	}
	var err error
	m.TxCount, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	hashCount, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	// Never size the hash vector from the peer's counts alone: TxCount is
	// attacker-chosen too, so 2*TxCount+1 let an 89-byte payload reserve
	// 1 GiB (security audit C1). Bound by what a message can carry and by
	// the bytes actually left, then grow as hashes arrive, like Core's
	// MAX_VECTOR_ALLOCATE-stepped vector Unserialize (serialize.h).
	if hashCount > MaxMerkleBlockHashes {
		return fmt.Errorf("p2p: merkleblock hash count %d exceeds %d", hashCount, MaxMerkleBlockHashes)
	}
	if hashCount > uint64(m.TxCount)*2+1 {
		return fmt.Errorf("p2p: merkleblock hash count %d too large", hashCount)
	}
	if n, ok := remainingBytes(r); ok && hashCount*32 > n {
		return fmt.Errorf("p2p: merkleblock hash count %d exceeds remaining payload (%d bytes)", hashCount, n)
	}
	m.Hashes = make([]wire.Hash256, 0, min(hashCount, merkleBlockHashAllocStep))
	for i := uint64(0); i < hashCount; i++ {
		var h wire.Hash256
		if err := h.Deserialize(r); err != nil {
			return err
		}
		m.Hashes = append(m.Hashes, h)
	}

	flagLen, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if flagLen > MaxPayloadSize {
		return fmt.Errorf("p2p: merkleblock flags length %d exceeds %d", flagLen, MaxPayloadSize)
	}
	if n, ok := remainingBytes(r); ok && flagLen > n {
		return fmt.Errorf("p2p: merkleblock flags length %d exceeds remaining payload (%d bytes)", flagLen, n)
	}
	if flagLen == 0 {
		m.Flags = nil
		return nil
	}
	// ReadAll over a LimitReader grows with the bytes delivered rather than
	// reserving flagLen up front.
	m.Flags, err = io.ReadAll(io.LimitReader(r, int64(flagLen)))
	if err != nil {
		return err
	}
	if uint64(len(m.Flags)) != flagLen {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// remainingBytes reports how many unread bytes r holds, when r can say
// (bytes.Reader, bytes.Buffer — what ReadMessage and the v2 transport pass).
func remainingBytes(r io.Reader) (uint64, bool) {
	if l, ok := r.(interface{ Len() int }); ok {
		return uint64(l.Len()), true
	}
	return 0, false
}
