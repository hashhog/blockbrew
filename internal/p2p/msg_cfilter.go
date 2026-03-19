package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP157 compact block filter constants.
const (
	// FilterTypeBasic is the basic filter type (BIP158).
	FilterTypeBasic uint8 = 0

	// MaxCFiltersPerRequest is the maximum number of filters in a single getcfilters request.
	MaxCFiltersPerRequest = 1000

	// MaxCFHeadersPerRequest is the maximum number of filter headers per getcfheaders request.
	MaxCFHeadersPerRequest = 2000

	// MaxCFCheckptPerRequest is the maximum number of checkpoints per getcfcheckpt response.
	// One checkpoint per 1000 blocks.
	MaxCFCheckptPerRequest = 1000
)

// MsgGetCFilters is the "getcfilters" message (BIP157) requesting compact block
// filters for a range of blocks.
type MsgGetCFilters struct {
	FilterType  uint8        // Filter type (0 = basic)
	StartHeight uint32       // Start block height
	StopHash    wire.Hash256 // Hash of the last block in the range
}

// Command returns the protocol command string for the message.
func (m *MsgGetCFilters) Command() string { return "getcfilters" }

// Serialize writes the getcfilters message to w.
func (m *MsgGetCFilters) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(w, m.StartHeight); err != nil {
		return err
	}
	return m.StopHash.Serialize(w)
}

// Deserialize reads the getcfilters message from r.
func (m *MsgGetCFilters) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	m.StartHeight, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	return m.StopHash.Deserialize(r)
}

// MsgCFilter is the "cfilter" message (BIP157) containing a compact block filter.
type MsgCFilter struct {
	FilterType uint8        // Filter type (0 = basic)
	BlockHash  wire.Hash256 // Block hash the filter applies to
	Filter     []byte       // The encoded filter data
}

// Command returns the protocol command string for the message.
func (m *MsgCFilter) Command() string { return "cfilter" }

// Serialize writes the cfilter message to w.
func (m *MsgCFilter) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	if err := m.BlockHash.Serialize(w); err != nil {
		return err
	}
	return wire.WriteVarBytes(w, m.Filter)
}

// Deserialize reads the cfilter message from r.
func (m *MsgCFilter) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	if err := m.BlockHash.Deserialize(r); err != nil {
		return err
	}
	m.Filter, err = wire.ReadVarBytes(r, 1<<20) // Max 1MB filter
	return err
}

// MsgGetCFHeaders is the "getcfheaders" message (BIP157) requesting compact
// block filter headers for a range of blocks.
type MsgGetCFHeaders struct {
	FilterType  uint8        // Filter type (0 = basic)
	StartHeight uint32       // Start block height
	StopHash    wire.Hash256 // Hash of the last block in the range
}

// Command returns the protocol command string for the message.
func (m *MsgGetCFHeaders) Command() string { return "getcfheaders" }

// Serialize writes the getcfheaders message to w.
func (m *MsgGetCFHeaders) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(w, m.StartHeight); err != nil {
		return err
	}
	return m.StopHash.Serialize(w)
}

// Deserialize reads the getcfheaders message from r.
func (m *MsgGetCFHeaders) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	m.StartHeight, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	return m.StopHash.Deserialize(r)
}

// MsgCFHeaders is the "cfheaders" message (BIP157) containing compact block
// filter headers.
type MsgCFHeaders struct {
	FilterType       uint8          // Filter type (0 = basic)
	StopHash         wire.Hash256   // Hash of the last block in the range
	PrevFilterHeader wire.Hash256   // Filter header of the block before StartHeight
	FilterHashes     []wire.Hash256 // Filter hashes for each block in the range
}

// Command returns the protocol command string for the message.
func (m *MsgCFHeaders) Command() string { return "cfheaders" }

// Serialize writes the cfheaders message to w.
func (m *MsgCFHeaders) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	if err := m.StopHash.Serialize(w); err != nil {
		return err
	}
	if err := m.PrevFilterHeader.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.FilterHashes))); err != nil {
		return err
	}
	for _, hash := range m.FilterHashes {
		if err := hash.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the cfheaders message from r.
func (m *MsgCFHeaders) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	if err := m.StopHash.Deserialize(r); err != nil {
		return err
	}
	if err := m.PrevFilterHeader.Deserialize(r); err != nil {
		return err
	}
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxCFHeadersPerRequest {
		return ErrTooManyHeaders
	}
	m.FilterHashes = make([]wire.Hash256, count)
	for i := range m.FilterHashes {
		if err := m.FilterHashes[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}

// MsgGetCFCheckpt is the "getcfcheckpt" message (BIP157) requesting evenly
// spaced compact block filter headers (one per 1000 blocks).
type MsgGetCFCheckpt struct {
	FilterType uint8        // Filter type (0 = basic)
	StopHash   wire.Hash256 // Hash of the last block
}

// Command returns the protocol command string for the message.
func (m *MsgGetCFCheckpt) Command() string { return "getcfcheckpt" }

// Serialize writes the getcfcheckpt message to w.
func (m *MsgGetCFCheckpt) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	return m.StopHash.Serialize(w)
}

// Deserialize reads the getcfcheckpt message from r.
func (m *MsgGetCFCheckpt) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	return m.StopHash.Deserialize(r)
}

// MsgCFCheckpt is the "cfcheckpt" message (BIP157) containing evenly spaced
// compact block filter headers.
type MsgCFCheckpt struct {
	FilterType    uint8          // Filter type (0 = basic)
	StopHash      wire.Hash256   // Hash of the last block
	FilterHeaders []wire.Hash256 // Filter headers at every 1000th block
}

// Command returns the protocol command string for the message.
func (m *MsgCFCheckpt) Command() string { return "cfcheckpt" }

// Serialize writes the cfcheckpt message to w.
func (m *MsgCFCheckpt) Serialize(w io.Writer) error {
	if err := wire.WriteUint8(w, m.FilterType); err != nil {
		return err
	}
	if err := m.StopHash.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.FilterHeaders))); err != nil {
		return err
	}
	for _, hash := range m.FilterHeaders {
		if err := hash.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the cfcheckpt message from r.
func (m *MsgCFCheckpt) Deserialize(r io.Reader) error {
	var err error
	m.FilterType, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}
	if err := m.StopHash.Deserialize(r); err != nil {
		return err
	}
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxCFCheckptPerRequest {
		return ErrTooManyHeaders
	}
	m.FilterHeaders = make([]wire.Hash256, count)
	for i := range m.FilterHeaders {
		if err := m.FilterHeaders[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}
