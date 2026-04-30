package p2p

import (
	"errors"
	"fmt"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP-331 message limits.
const (
	// MaxPackageVersionsBytes is the maximum number of bytes in a sendpackages
	// versions field. Currently always 8 (single uint64 bitfield) per BIP-331.
	MaxPackageVersionsBytes = 8

	// MaxGetPkgTxnsCount is the maximum number of wtxids that may be requested
	// in a single getpkgtxns. Mirrors Bitcoin Core's MAX_PACKAGE_COUNT (25).
	MaxGetPkgTxnsCount = 25

	// MaxPkgTxnsCount is the maximum number of transactions in a pkgtxns.
	MaxPkgTxnsCount = MaxGetPkgTxnsCount

	// PackageRelayVersionAncestor is bit 0 of the sendpackages versions
	// bitfield: "ancestor packages" support (BIP-331 §"sendpackages").
	PackageRelayVersionAncestor uint64 = 1 << 0
)

// Errors specific to BIP-331 package-relay decoding.
var (
	ErrTooManyPackageVersions = errors.New("sendpackages: versions field too large")
	ErrTooManyPkgTxns         = errors.New("getpkgtxns / pkgtxns: too many transactions")
)

// MsgSendPackages is the BIP-331 "sendpackages" message. Sent during the
// version handshake (after version, before verack) by peers that wish to
// negotiate package relay. The Versions field is a bitfield indicating which
// package-relay variants the sender supports (bit 0 = ancestor packages).
type MsgSendPackages struct {
	Versions uint64
}

// Command returns the protocol command string for the message.
func (m *MsgSendPackages) Command() string { return "sendpackages" }

// Serialize writes the sendpackages message to w.
func (m *MsgSendPackages) Serialize(w io.Writer) error {
	return wire.WriteUint64LE(w, m.Versions)
}

// Deserialize reads the sendpackages message from r.
func (m *MsgSendPackages) Deserialize(r io.Reader) error {
	v, err := wire.ReadUint64LE(r)
	if err != nil {
		return err
	}
	m.Versions = v
	return nil
}

// MsgGetPkgTxns is the BIP-331 "getpkgtxns" message: a request for the full
// transaction data of a package, identified by its constituent wtxids.
type MsgGetPkgTxns struct {
	WTxIDs []wire.Hash256
}

// Command returns the protocol command string for the message.
func (m *MsgGetPkgTxns) Command() string { return "getpkgtxns" }

// Serialize writes the getpkgtxns message to w.
func (m *MsgGetPkgTxns) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(len(m.WTxIDs))); err != nil {
		return err
	}
	for i := range m.WTxIDs {
		if err := m.WTxIDs[i].Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the getpkgtxns message from r.
func (m *MsgGetPkgTxns) Deserialize(r io.Reader) error {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxGetPkgTxnsCount {
		return fmt.Errorf("%w: %d > %d", ErrTooManyPkgTxns, count, MaxGetPkgTxnsCount)
	}
	m.WTxIDs = make([]wire.Hash256, count)
	for i := range m.WTxIDs {
		if err := m.WTxIDs[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}

// MsgPkgTxns is the BIP-331 "pkgtxns" message: the transaction data for a
// package previously requested via getpkgtxns. Each tx is serialized in the
// canonical BIP-144 segwit format (TX_WITH_WITNESS).
type MsgPkgTxns struct {
	Txs []*wire.MsgTx
}

// Command returns the protocol command string for the message.
func (m *MsgPkgTxns) Command() string { return "pkgtxns" }

// Serialize writes the pkgtxns message to w.
func (m *MsgPkgTxns) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(len(m.Txs))); err != nil {
		return err
	}
	for _, tx := range m.Txs {
		if tx == nil {
			tx = &wire.MsgTx{}
		}
		if err := tx.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the pkgtxns message from r.
func (m *MsgPkgTxns) Deserialize(r io.Reader) error {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxPkgTxnsCount {
		return fmt.Errorf("%w: %d > %d", ErrTooManyPkgTxns, count, MaxPkgTxnsCount)
	}
	m.Txs = make([]*wire.MsgTx, count)
	for i := range m.Txs {
		tx := &wire.MsgTx{}
		if err := tx.Deserialize(r); err != nil {
			return err
		}
		m.Txs[i] = tx
	}
	return nil
}
