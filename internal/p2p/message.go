// Package p2p implements Bitcoin peer-to-peer networking.
package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

const (
	// MessageHeaderSize is the size of a Bitcoin P2P message header in bytes.
	MessageHeaderSize = 24

	// MaxPayloadSize is the maximum allowed message payload (32 MB).
	MaxPayloadSize = 32 * 1024 * 1024

	// CommandSize is the fixed size of the command field in bytes.
	CommandSize = 12
)

// Network magic values.
const (
	MainnetMagic  uint32 = 0xD9B4BEF9
	Testnet3Magic uint32 = 0x0709110B
	Testnet4Magic uint32 = 0x283F161C
	RegtestMagic  uint32 = 0xDAB5BFFA
	SignetMagic   uint32 = 0x40CF030A
)

// Errors for message parsing.
var (
	ErrBadMagic         = errors.New("p2p: bad network magic")
	ErrBadChecksum      = errors.New("p2p: bad message checksum")
	ErrPayloadTooLarge  = errors.New("p2p: payload too large")
	ErrUnknownCommand   = errors.New("p2p: unknown command")
	ErrInvalidCommand   = errors.New("p2p: invalid command string")
	ErrTooManyInvVects  = errors.New("p2p: too many inventory vectors")
	ErrTooManyHeaders   = errors.New("p2p: too many headers")
	ErrTooManyAddresses = errors.New("p2p: too many addresses")
	ErrTooManyLocators  = errors.New("p2p: too many block locators")
)

// NonFatalMessageError indicates a deserialization failure for a non-critical
// message where the TCP stream remains valid (payload was fully consumed and
// checksum verified). The peer connection should NOT be killed for this error.
type NonFatalMessageError struct {
	Command string
	Err     error
}

func (e *NonFatalMessageError) Error() string {
	return fmt.Sprintf("deserialize %s (non-fatal): %v", e.Command, e.Err)
}

func (e *NonFatalMessageError) Unwrap() error {
	return e.Err
}

// IsNonFatalMessageError returns true if err is a NonFatalMessageError.
func IsNonFatalMessageError(err error) bool {
	var nfe *NonFatalMessageError
	return errors.As(err, &nfe)
}

// Maximum counts for various message fields.
const (
	MaxInvVects     = 50000
	MaxHeaders      = 2000
	MaxAddresses    = 1000
	MaxBlockLocators = 101
)

// MessageHeader represents a Bitcoin P2P message header.
type MessageHeader struct {
	Magic    uint32
	Command  [CommandSize]byte
	Length   uint32
	Checksum [4]byte
}

// CommandString returns the command as a string, trimmed of null bytes.
func (h *MessageHeader) CommandString() string {
	// Find the first null byte
	end := 0
	for i := 0; i < CommandSize; i++ {
		if h.Command[i] == 0 {
			break
		}
		end = i + 1
	}
	return string(h.Command[:end])
}

// Message is the interface all P2P messages implement.
type Message interface {
	Command() string
	Serialize(w io.Writer) error
	Deserialize(r io.Reader) error
}

// WriteMessageHeader writes a message header to w.
func WriteMessageHeader(w io.Writer, magic uint32, command string, payload []byte) error {
	// Write magic
	if err := wire.WriteUint32LE(w, magic); err != nil {
		return err
	}

	// Write command (null-padded to 12 bytes)
	var cmdBytes [CommandSize]byte
	copy(cmdBytes[:], command)
	if err := wire.WriteBytes(w, cmdBytes[:]); err != nil {
		return err
	}

	// Write payload length
	if err := wire.WriteUint32LE(w, uint32(len(payload))); err != nil {
		return err
	}

	// Write checksum (first 4 bytes of DoubleSHA256)
	checksum := crypto.DoubleSHA256(payload)
	return wire.WriteBytes(w, checksum[:4])
}

// ReadMessageHeader reads and parses a message header from r.
func ReadMessageHeader(r io.Reader) (*MessageHeader, error) {
	var h MessageHeader
	var err error

	h.Magic, err = wire.ReadUint32LE(r)
	if err != nil {
		return nil, err
	}

	cmdBytes, err := wire.ReadBytes(r, CommandSize)
	if err != nil {
		return nil, err
	}
	copy(h.Command[:], cmdBytes)

	h.Length, err = wire.ReadUint32LE(r)
	if err != nil {
		return nil, err
	}

	checksumBytes, err := wire.ReadBytes(r, 4)
	if err != nil {
		return nil, err
	}
	copy(h.Checksum[:], checksumBytes)

	return &h, nil
}

// WriteMessage writes a complete message (header + payload) to w.
func WriteMessage(w io.Writer, magic uint32, msg Message) error {
	// Serialize payload to buffer
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		return fmt.Errorf("serialize payload: %w", err)
	}
	payload := buf.Bytes()

	// Check payload size
	if len(payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	// Write header
	if err := WriteMessageHeader(w, magic, msg.Command(), payload); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write payload
	if err := wire.WriteBytes(w, payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// ReadMessage reads a complete message from r, validates checksum, returns the Message.
// Deserialization errors for non-critical messages (e.g., addrv2) are logged and
// the message is skipped rather than killing the connection, since the payload
// was fully consumed and the stream remains valid.
func ReadMessage(r io.Reader, magic uint32) (Message, error) {
	// Read header
	h, err := ReadMessageHeader(r)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Verify magic
	if h.Magic != magic {
		return nil, ErrBadMagic
	}

	// Enforce max payload size
	if h.Length > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	// Read payload
	payload, err := wire.ReadBytes(r, int(h.Length))
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Verify checksum
	checksum := crypto.DoubleSHA256(payload)
	if !bytes.Equal(checksum[:4], h.Checksum[:]) {
		return nil, ErrBadChecksum
	}

	// Create appropriate message type
	cmd := h.CommandString()
	msg, err := makeMessage(cmd)
	if err != nil {
		// Unknown command — not fatal, skip the message.
		// The payload was fully consumed so the stream is still aligned.
		return nil, &NonFatalMessageError{Command: cmd, Err: err}
	}

	// Deserialize payload
	if err := msg.Deserialize(bytes.NewReader(payload)); err != nil {
		// The payload was fully read and checksum-verified, so the TCP stream
		// is still properly aligned. For non-critical messages (addr, addrv2,
		// inv, etc.), a deserialization failure should not kill the connection.
		// Only fail for messages critical to the sync pipeline.
		if isNonCriticalMessage(cmd) {
			return nil, &NonFatalMessageError{Command: cmd, Err: err}
		}
		return nil, fmt.Errorf("deserialize %s: %w", cmd, err)
	}

	return msg, nil
}

// isNonCriticalMessage returns true for message types where a deserialization
// failure should not kill the peer connection. These messages are informational
// and not required for block sync.
func isNonCriticalMessage(cmd string) bool {
	switch cmd {
	case "addr", "addrv2", "inv", "feefilter", "sendcmpct", "sendheaders",
		"sendaddrv2", "wtxidrelay", "sendtxrcncl", "ping", "pong",
		"filterload", "filteradd", "filterclear", "merkleblock",
		"cmpctblock", "getblocktxn", "blocktxn",
		"getcfilters", "cfilter", "getcfheaders", "cfheaders",
		"getcfcheckpt", "cfcheckpt":
		return true
	default:
		return false
	}
}

// makeMessage creates a new empty message for the given command string.
func makeMessage(command string) (Message, error) {
	switch command {
	case "version":
		return &MsgVersion{}, nil
	case "verack":
		return &MsgVerAck{}, nil
	case "ping":
		return &MsgPing{}, nil
	case "pong":
		return &MsgPong{}, nil
	case "getaddr":
		return &MsgGetAddr{}, nil
	case "addr":
		return &MsgAddr{}, nil
	case "inv":
		return &MsgInv{}, nil
	case "getdata":
		return &MsgGetData{}, nil
	case "notfound":
		return &MsgNotFound{}, nil
	case "getblocks":
		return &MsgGetBlocks{}, nil
	case "getheaders":
		return &MsgGetHeaders{}, nil
	case "headers":
		return &MsgHeaders{}, nil
	case "block":
		return &MsgBlock{}, nil
	case "tx":
		return &MsgTx{}, nil
	case "sendheaders":
		return &MsgSendHeaders{}, nil
	case "sendcmpct":
		return &MsgSendCmpct{}, nil
	case "feefilter":
		return &MsgFeeFilter{}, nil
	case "mempool":
		return &MsgMempool{}, nil
	case "wtxidrelay":
		return &MsgWTxidRelay{}, nil
	case "cmpctblock":
		return &MsgCmpctBlock{}, nil
	case "getblocktxn":
		return &MsgGetBlockTxn{}, nil
	case "blocktxn":
		return &MsgBlockTxn{}, nil
	case "sendaddrv2":
		return &MsgSendAddrv2{}, nil
	case "addrv2":
		return &MsgAddrv2{}, nil
	// BIP330 Erlay messages
	case "sendtxrcncl":
		return &MsgSendTxRcncl{}, nil
	case "reqreconcil":
		return &MsgReqReconcil{}, nil
	case "sketch":
		return &MsgSketch{}, nil
	case "reconcildiff":
		return &MsgReconcilDiff{}, nil
	// BIP37 bloom filter messages
	case "filterload":
		return &MsgFilterLoad{}, nil
	case "filteradd":
		return &MsgFilterAdd{}, nil
	case "filterclear":
		return &MsgFilterClear{}, nil
	case "merkleblock":
		return &MsgMerkleBlock{}, nil
	// BIP157/158 compact block filter messages
	case "getcfilters":
		return &MsgGetCFilters{}, nil
	case "cfilter":
		return &MsgCFilter{}, nil
	case "getcfheaders":
		return &MsgGetCFHeaders{}, nil
	case "cfheaders":
		return &MsgCFHeaders{}, nil
	case "getcfcheckpt":
		return &MsgGetCFCheckpt{}, nil
	case "cfcheckpt":
		return &MsgCFCheckpt{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownCommand, command)
	}
}
