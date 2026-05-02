package mining

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// TestChainManagerSatisfiesUTXOViewProvider documents that the production
// ChainManager wires automatically into NewTemplateGenerator's UTXO source.
func TestChainManagerSatisfiesUTXOViewProvider(t *testing.T) {
	var _ UTXOViewProvider = (*consensus.ChainManager)(nil)
}
