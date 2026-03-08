package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgHeaders is the "headers" message containing block headers.
type MsgHeaders struct {
	Headers []wire.BlockHeader // Up to 2,000 headers
}

// Command returns the protocol command string for the message.
func (m *MsgHeaders) Command() string { return "headers" }

// Serialize writes the headers message to w.
// Each header is 80 bytes + a CompactSize tx count (always 0 in headers message).
func (m *MsgHeaders) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(len(m.Headers))); err != nil {
		return err
	}
	for _, hdr := range m.Headers {
		if err := hdr.Serialize(w); err != nil {
			return err
		}
		// Transaction count is always 0 in headers message
		if err := wire.WriteCompactSize(w, 0); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the headers message from r.
func (m *MsgHeaders) Deserialize(r io.Reader) error {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxHeaders {
		return ErrTooManyHeaders
	}
	m.Headers = make([]wire.BlockHeader, count)
	for i := range m.Headers {
		if err := m.Headers[i].Deserialize(r); err != nil {
			return err
		}
		// Read and discard the transaction count (should be 0)
		_, err := wire.ReadCompactSize(r)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddHeader adds a block header to the message.
func (m *MsgHeaders) AddHeader(hdr wire.BlockHeader) error {
	if len(m.Headers) >= MaxHeaders {
		return ErrTooManyHeaders
	}
	m.Headers = append(m.Headers, hdr)
	return nil
}
