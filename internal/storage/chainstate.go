package storage

import (
	"bytes"
	"errors"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ChainState holds the persisted chain state.
type ChainState struct {
	BestHash   wire.Hash256
	BestHeight int32
}

// Serialize writes the chain state to a byte slice.
func (cs *ChainState) Serialize() []byte {
	buf := new(bytes.Buffer)
	cs.BestHash.Serialize(buf)
	wire.WriteInt32LE(buf, cs.BestHeight)
	return buf.Bytes()
}

// DeserializeChainState reads a chain state from a byte slice.
func DeserializeChainState(data []byte) (*ChainState, error) {
	if len(data) < 36 {
		return nil, errors.New("chain state data too short")
	}

	r := bytes.NewReader(data)
	cs := &ChainState{}

	if err := cs.BestHash.Deserialize(r); err != nil {
		return nil, err
	}

	var err error
	cs.BestHeight, err = wire.ReadInt32LE(r)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return cs, nil
}
