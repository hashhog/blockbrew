package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxCompactSize is the maximum value allowed for a CompactSize integer (32 MB).
const MaxCompactSize = 0x02000000

// ErrCompactSizeTooLarge is returned when a CompactSize value exceeds MaxCompactSize.
var ErrCompactSizeTooLarge = errors.New("compact size too large")

// ReadCompactSizeUnchecked reads a CompactSize-encoded integer without any upper
// bound check. This is needed for fields like BIP155 service flags which are
// valid uint64 values that may exceed MaxCompactSize.
func ReadCompactSizeUnchecked(r io.Reader) (uint64, error) {
	first, err := ReadUint8(r)
	if err != nil {
		return 0, err
	}

	switch first {
	case 0xFD:
		v, err := ReadUint16LE(r)
		if err != nil {
			return 0, err
		}
		return uint64(v), nil
	case 0xFE:
		v, err := ReadUint32LE(r)
		if err != nil {
			return 0, err
		}
		return uint64(v), nil
	case 0xFF:
		return ReadUint64LE(r)
	default:
		return uint64(first), nil
	}
}

// WriteUint8 writes a uint8 to the writer.
func WriteUint8(w io.Writer, v uint8) error {
	_, err := w.Write([]byte{v})
	return err
}

// WriteUint16LE writes a uint16 in little-endian order to the writer.
func WriteUint16LE(w io.Writer, v uint16) error {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

// WriteUint32LE writes a uint32 in little-endian order to the writer.
func WriteUint32LE(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

// WriteUint64LE writes a uint64 in little-endian order to the writer.
func WriteUint64LE(w io.Writer, v uint64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

// WriteInt32LE writes an int32 in little-endian order to the writer.
func WriteInt32LE(w io.Writer, v int32) error {
	return WriteUint32LE(w, uint32(v))
}

// WriteInt64LE writes an int64 in little-endian order to the writer.
func WriteInt64LE(w io.Writer, v int64) error {
	return WriteUint64LE(w, uint64(v))
}

// WriteBytes writes a byte slice to the writer.
func WriteBytes(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

// WriteCompactSize writes a CompactSize-encoded integer to the writer.
// Encoding rules:
//   - 0x00–0xFC: 1 byte, value as-is
//   - 0xFD–0xFFFF: 0xFD prefix + 2-byte LE uint16
//   - 0x10000–0xFFFFFFFF: 0xFE prefix + 4-byte LE uint32
//   - 0x100000000–0xFFFFFFFFFFFFFFFF: 0xFF prefix + 8-byte LE uint64
func WriteCompactSize(w io.Writer, val uint64) error {
	switch {
	case val < 0xFD:
		return WriteUint8(w, uint8(val))
	case val <= 0xFFFF:
		if err := WriteUint8(w, 0xFD); err != nil {
			return err
		}
		return WriteUint16LE(w, uint16(val))
	case val <= 0xFFFFFFFF:
		if err := WriteUint8(w, 0xFE); err != nil {
			return err
		}
		return WriteUint32LE(w, uint32(val))
	default:
		if err := WriteUint8(w, 0xFF); err != nil {
			return err
		}
		return WriteUint64LE(w, val)
	}
}

// WriteVarBytes writes a byte slice with a CompactSize length prefix.
func WriteVarBytes(w io.Writer, b []byte) error {
	if err := WriteCompactSize(w, uint64(len(b))); err != nil {
		return err
	}
	return WriteBytes(w, b)
}

// WriteVarString writes a string with a CompactSize length prefix.
func WriteVarString(w io.Writer, s string) error {
	return WriteVarBytes(w, []byte(s))
}

// ReadUint8 reads a uint8 from the reader.
func ReadUint8(r io.Reader) (uint8, error) {
	var buf [1]byte
	_, err := io.ReadFull(r, buf[:])
	return buf[0], err
}

// ReadUint16LE reads a uint16 in little-endian order from the reader.
func ReadUint16LE(r io.Reader) (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(buf[:]), nil
}

// ReadUint32LE reads a uint32 in little-endian order from the reader.
func ReadUint32LE(r io.Reader) (uint32, error) {
	var buf [4]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// ReadUint64LE reads a uint64 in little-endian order from the reader.
func ReadUint64LE(r io.Reader) (uint64, error) {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// ReadInt32LE reads an int32 in little-endian order from the reader.
func ReadInt32LE(r io.Reader) (int32, error) {
	v, err := ReadUint32LE(r)
	return int32(v), err
}

// ReadInt64LE reads an int64 in little-endian order from the reader.
func ReadInt64LE(r io.Reader) (int64, error) {
	v, err := ReadUint64LE(r)
	return int64(v), err
}

// ReadBytes reads exactly n bytes from the reader.
func ReadBytes(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadCompactSize reads a CompactSize-encoded integer from the reader.
// Returns an error if the value exceeds MaxCompactSize.
func ReadCompactSize(r io.Reader) (uint64, error) {
	first, err := ReadUint8(r)
	if err != nil {
		return 0, err
	}

	var val uint64
	switch first {
	case 0xFD:
		v, err := ReadUint16LE(r)
		if err != nil {
			return 0, err
		}
		val = uint64(v)
	case 0xFE:
		v, err := ReadUint32LE(r)
		if err != nil {
			return 0, err
		}
		val = uint64(v)
	case 0xFF:
		v, err := ReadUint64LE(r)
		if err != nil {
			return 0, err
		}
		val = v
	default:
		val = uint64(first)
	}

	if val > MaxCompactSize {
		return 0, ErrCompactSizeTooLarge
	}
	return val, nil
}

// ReadVarBytes reads a byte slice with a CompactSize length prefix.
// maxSize limits the maximum number of bytes that can be read.
func ReadVarBytes(r io.Reader, maxSize uint64) ([]byte, error) {
	length, err := ReadCompactSize(r)
	if err != nil {
		return nil, err
	}
	if length > maxSize {
		return nil, ErrCompactSizeTooLarge
	}
	if length == 0 {
		return nil, nil
	}
	return ReadBytes(r, int(length))
}

// ReadVarString reads a string with a CompactSize length prefix.
// maxSize limits the maximum number of bytes that can be read.
func ReadVarString(r io.Reader, maxSize uint64) (string, error) {
	b, err := ReadVarBytes(r, maxSize)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
