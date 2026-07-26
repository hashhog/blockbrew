// Package mempool implements the transaction memory pool.
package mempool

import (
	"errors"
	"math/bits"
	"sort"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// MaxClusterCount is the maximum number of transactions allowed in a cluster.
// Matches Bitcoin Core's DEFAULT_CLUSTER_LIMIT (src/policy/policy.h:72), which
// is handed to TxGraph as max_cluster_count (txmempool.cpp:180) and compared
// with a STRICT ">" in TxGraphImpl (txgraph.cpp:2059):
//
//	if (total_count > m_max_cluster_count || total_size > m_max_cluster_size)
//
// so a 64-transaction cluster is accepted and a 65th transaction is rejected.
const MaxClusterCount = 64

// MaxClusterSize is a legacy alias for MaxClusterCount. Despite the name it has
// always been a transaction COUNT, never a byte or weight size. Retained so
// existing callers keep compiling; new code should name what it means —
// MaxClusterCount for the count cap, MaxClusterSizeWeight for the size cap.
const MaxClusterSize = MaxClusterCount

// MaxClusterSizeWeight is the maximum total size of a cluster, in WEIGHT units.
// Core derives it in two steps:
//
//	kernel/mempool_limits.h:22  cluster_size_vbytes = DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1'000
//	txmempool.cpp:181           max_cluster_size    = cluster_size_vbytes * WITNESS_SCALE_FACTOR
//
// = 101 * 1000 * 4 = 404_000 weight units.
//
// The per-transaction quantity summed into this total is the UNROUNDED
// sigop-adjusted weight: txmempool.cpp:1017 feeds
// GetSigOpsAdjustedWeight(GetTransactionWeight(tx), sigops_cost, nBytesPerSigOp)
// straight into TxGraph. It is NOT ceil(weight/4) vbytes. Summing per-tx
// ceilinged vbytes against 101_000 would be systematically STRICTER than Core
// (because Σ⌈wᵢ/4⌉ ≥ (Σwᵢ)/4, always in the same direction) — up to 48 vB of
// spurious slack over a 64-transaction cluster. Do not "port" this limit by
// swapping the constant while still rounding per transaction.
const MaxClusterSizeWeight int64 = DefaultClusterSizeLimitKvB * vbytesPerKvB * consensus.WitnessScaleFactor

// ErrClusterTooLarge is returned when a transaction would push its cluster past
// either cluster limit — the transaction count (MaxClusterCount) or the total
// sigop-adjusted weight (MaxClusterSizeWeight).
//
// Core signals both with a single reject token, "too-large-cluster", and an
// EMPTY debug string (validation.cpp:1024, :1116, :1343, :1521). The sentinel
// text is therefore exactly that token, and it is deliberately never wrapped
// with detail so the surfaced reason stays byte-identical to Core's.
var ErrClusterTooLarge = errors.New("too-large-cluster")

// ============================================================================
// FeeFrac - Precise fee/size fraction for feerate comparison
// ============================================================================

// FeeFrac represents a fee and size pair for precise feerate comparisons.
// This avoids floating point issues by using cross-multiplication.
type FeeFrac struct {
	Fee  int64
	Size int32
}

// IsEmpty returns true if the FeeFrac is empty (zero size).
func (f FeeFrac) IsEmpty() bool {
	return f.Size == 0
}

// Add adds another FeeFrac to this one.
func (f FeeFrac) Add(other FeeFrac) FeeFrac {
	return FeeFrac{
		Fee:  f.Fee + other.Fee,
		Size: f.Size + other.Size,
	}
}

// Sub subtracts another FeeFrac from this one.
func (f FeeFrac) Sub(other FeeFrac) FeeFrac {
	return FeeFrac{
		Fee:  f.Fee - other.Fee,
		Size: f.Size - other.Size,
	}
}

// Compare returns:
//
//	-1 if f < other (f has lower feerate)
//	 0 if f == other (equal feerates)
//	 1 if f > other (f has higher feerate)
//
// Uses cross-multiplication to avoid floating point: fee1/size1 vs fee2/size2
// becomes fee1*size2 vs fee2*size1.
func (f FeeFrac) Compare(other FeeFrac) int {
	// Handle zero-size cases
	if f.Size == 0 && other.Size == 0 {
		return 0
	}
	if f.Size == 0 {
		return -1 // Empty is less than non-empty
	}
	if other.Size == 0 {
		return 1 // Non-empty is greater than empty
	}

	// Cross-multiply to compare: f.Fee/f.Size vs other.Fee/other.Size
	// => f.Fee * other.Size vs other.Fee * f.Size
	lhs := f.Fee * int64(other.Size)
	rhs := other.Fee * int64(f.Size)

	if lhs < rhs {
		return -1
	}
	if lhs > rhs {
		return 1
	}
	return 0
}

// FeeRate returns the feerate as sat/vB (floating point, for display only).
func (f FeeFrac) FeeRate() float64 {
	if f.Size == 0 {
		return 0
	}
	return float64(f.Fee) / float64(f.Size)
}

// ============================================================================
// BitSet - Efficient set operations for transaction indices
// ============================================================================

// BitSet is a fixed-size bit set for efficient set operations.
// Supports up to 128 elements (2 uint64s). This is more than sufficient for MaxClusterSize=64.
type BitSet struct {
	bits [2]uint64
}

// Set sets the bit at position i.
func (b *BitSet) Set(i int) {
	if i < 64 {
		b.bits[0] |= 1 << uint(i)
	} else if i < 128 {
		b.bits[1] |= 1 << uint(i-64)
	}
}

// Reset clears the bit at position i.
func (b *BitSet) Reset(i int) {
	if i < 64 {
		b.bits[0] &^= 1 << uint(i)
	} else if i < 128 {
		b.bits[1] &^= 1 << uint(i-64)
	}
}

// Has returns true if the bit at position i is set.
func (b *BitSet) Has(i int) bool {
	if i < 64 {
		return (b.bits[0] & (1 << uint(i))) != 0
	}
	if i < 128 {
		return (b.bits[1] & (1 << uint(i-64))) != 0
	}
	return false
}

// Count returns the number of set bits.
func (b BitSet) Count() int {
	return bits.OnesCount64(b.bits[0]) + bits.OnesCount64(b.bits[1])
}

// Any returns true if any bit is set.
func (b BitSet) Any() bool {
	return b.bits[0] != 0 || b.bits[1] != 0
}

// None returns true if no bits are set.
func (b BitSet) None() bool {
	return b.bits[0] == 0 && b.bits[1] == 0
}

// First returns the index of the first set bit, or -1 if none.
func (b BitSet) First() int {
	if b.bits[0] != 0 {
		return bits.TrailingZeros64(b.bits[0])
	}
	if b.bits[1] != 0 {
		return 64 + bits.TrailingZeros64(b.bits[1])
	}
	return -1
}

// Union returns the union of two sets.
func (b BitSet) Union(other BitSet) BitSet {
	return BitSet{
		bits: [2]uint64{b.bits[0] | other.bits[0], b.bits[1] | other.bits[1]},
	}
}

// Intersection returns the intersection of two sets.
func (b BitSet) Intersection(other BitSet) BitSet {
	return BitSet{
		bits: [2]uint64{b.bits[0] & other.bits[0], b.bits[1] & other.bits[1]},
	}
}

// Difference returns b - other (elements in b but not in other).
func (b BitSet) Difference(other BitSet) BitSet {
	return BitSet{
		bits: [2]uint64{b.bits[0] &^ other.bits[0], b.bits[1] &^ other.bits[1]},
	}
}

// IsSubsetOf returns true if b is a subset of other.
func (b BitSet) IsSubsetOf(other BitSet) bool {
	return (b.bits[0] & ^other.bits[0]) == 0 && (b.bits[1] & ^other.bits[1]) == 0
}

// Overlaps returns true if b and other share any elements.
func (b BitSet) Overlaps(other BitSet) bool {
	return (b.bits[0]&other.bits[0]) != 0 || (b.bits[1]&other.bits[1]) != 0
}

// Equal returns true if two sets are identical.
func (b BitSet) Equal(other BitSet) bool {
	return b.bits[0] == other.bits[0] && b.bits[1] == other.bits[1]
}

// Clone returns a copy of the set.
func (b BitSet) Clone() BitSet {
	return BitSet{bits: [2]uint64{b.bits[0], b.bits[1]}}
}

// ForEach calls fn for each set bit.
func (b BitSet) ForEach(fn func(int)) {
	for i := 0; i < 64; i++ {
		if b.bits[0]&(1<<uint(i)) != 0 {
			fn(i)
		}
	}
	for i := 0; i < 64; i++ {
		if b.bits[1]&(1<<uint(i)) != 0 {
			fn(i + 64)
		}
	}
}

// Elements returns a slice of all set bit indices.
func (b BitSet) Elements() []int {
	var result []int
	b.ForEach(func(i int) {
		result = append(result, i)
	})
	return result
}

// Singleton creates a set with only position i set.
func Singleton(i int) BitSet {
	var b BitSet
	b.Set(i)
	return b
}

// ============================================================================
// DepGraph - Dependency graph for a cluster
// ============================================================================

// DepGraphEntry holds information about a single transaction in the graph.
type DepGraphEntry struct {
	Feerate     FeeFrac // Fee and size of this transaction
	Ancestors   BitSet  // All ancestors (including self)
	Descendants BitSet  // All descendants (including self)
}

// DepGraph represents a dependency graph for a set of transactions.
// It tracks ancestors and descendants for each transaction, enabling
// efficient set operations during linearization.
type DepGraph struct {
	entries []DepGraphEntry
	used    BitSet // Which positions are active
}

// NewDepGraph creates a new empty dependency graph.
func NewDepGraph() *DepGraph {
	return &DepGraph{
		entries: make([]DepGraphEntry, 0, MaxClusterSize),
	}
}

// TxCount returns the number of transactions in the graph.
func (g *DepGraph) TxCount() int {
	return g.used.Count()
}

// Positions returns the set of used positions.
func (g *DepGraph) Positions() BitSet {
	return g.used
}

// PositionRange returns the size of the entries array.
func (g *DepGraph) PositionRange() int {
	return len(g.entries)
}

// FeeRate returns the feerate of transaction at position i.
func (g *DepGraph) FeeRate(i int) FeeFrac {
	return g.entries[i].Feerate
}

// SetFeeRate updates the feerate of transaction at position i.
func (g *DepGraph) SetFeeRate(i int, fr FeeFrac) {
	g.entries[i].Feerate = fr
}

// Ancestors returns the ancestor set of transaction i (including i).
func (g *DepGraph) Ancestors(i int) BitSet {
	return g.entries[i].Ancestors
}

// Descendants returns the descendant set of transaction i (including i).
func (g *DepGraph) Descendants(i int) BitSet {
	return g.entries[i].Descendants
}

// AddTransaction adds a new transaction to the graph and returns its index.
func (g *DepGraph) AddTransaction(fr FeeFrac) int {
	// Find first available position
	for i := 0; i < len(g.entries); i++ {
		if !g.used.Has(i) {
			g.entries[i] = DepGraphEntry{
				Feerate:     fr,
				Ancestors:   Singleton(i),
				Descendants: Singleton(i),
			}
			g.used.Set(i)
			return i
		}
	}

	// No available position, append new entry
	idx := len(g.entries)
	if idx >= MaxClusterSize {
		return -1 // Cluster too large
	}
	g.entries = append(g.entries, DepGraphEntry{
		Feerate:     fr,
		Ancestors:   Singleton(idx),
		Descendants: Singleton(idx),
	})
	g.used.Set(idx)
	return idx
}

// AddDependencies adds parent->child dependencies.
// After this call, child's ancestors include all ancestors of parents,
// and parents' descendants include all descendants of child.
func (g *DepGraph) AddDependencies(parents BitSet, child int) {
	if !g.used.Has(child) {
		return
	}

	// Compute ancestors of parents that are not already ancestors of child
	var parAnc BitSet
	diff := parents.Difference(g.Ancestors(child))
	diff.ForEach(func(par int) {
		if g.used.Has(par) {
			parAnc = parAnc.Union(g.Ancestors(par))
		}
	})
	parAnc = parAnc.Difference(g.Ancestors(child))

	if parAnc.None() {
		return
	}

	// To each ancestor of parent, add descendants of child
	childDesc := g.entries[child].Descendants
	parAnc.ForEach(func(anc int) {
		g.entries[anc].Descendants = g.entries[anc].Descendants.Union(childDesc)
	})

	// To each descendant of child, add those ancestors
	childDesc.ForEach(func(desc int) {
		g.entries[desc].Ancestors = g.entries[desc].Ancestors.Union(parAnc)
	})
}

// RemoveTransactions removes the specified transactions from the graph.
func (g *DepGraph) RemoveTransactions(del BitSet) {
	// Before removing, compute the direct parents of each transaction that had
	// a deleted transaction in its ancestor set. These are the transactions whose
	// transitive ancestor sets may change after the removal.
	//
	// We must use GetReducedParents BEFORE removing from g.used, since
	// GetReducedParents relies on g.entries[i].Ancestors being correct.
	type parentRecord struct {
		directParents BitSet
	}
	affected := make(map[int]parentRecord)
	remaining := g.used.Difference(del)
	remaining.ForEach(func(i int) {
		// If any ancestor of i is being deleted, i's ancestor set needs rebuilding.
		if !g.entries[i].Ancestors.Intersection(del).None() {
			affected[i] = parentRecord{directParents: g.GetReducedParents(i)}
		}
	})

	g.used = remaining

	// For transactions with no deleted ancestors, just strip the deleted bits.
	for i := 0; i < len(g.entries); i++ {
		if g.used.Has(i) {
			if _, needsRebuild := affected[i]; !needsRebuild {
				g.entries[i].Ancestors = g.entries[i].Ancestors.Intersection(g.used)
				g.entries[i].Descendants = g.entries[i].Descendants.Intersection(g.used)
			}
		}
	}

	// For affected transactions, recompute ancestors from direct parents.
	// We need a topological order (ancestors before descendants). The simplest
	// approach: iterate until stable (propagate in dependency order).
	if len(affected) > 0 {
		// Reset ancestor sets for affected nodes to just themselves, then rebuild.
		for i := range affected {
			g.entries[i].Ancestors = Singleton(i)
		}
		// Also strip deleted bits from direct parents of affected nodes.
		for i, rec := range affected {
			cleanParents := rec.directParents.Intersection(g.used)
			affected[i] = parentRecord{directParents: cleanParents}
		}
		// Re-propagate ancestors in topological order (repeat until stable).
		changed := true
		for changed {
			changed = false
			for i, rec := range affected {
				rec.directParents.ForEach(func(par int) {
					if !g.used.Has(par) {
						return
					}
					newAnc := g.entries[par].Ancestors
					before := g.entries[i].Ancestors
					g.entries[i].Ancestors = g.entries[i].Ancestors.Union(newAnc)
					if !g.entries[i].Ancestors.Equal(before) {
						changed = true
					}
				})
			}
		}
		// Rebuild descendants for all nodes from ancestors.
		// Reset descendants of all remaining nodes to just themselves.
		for i := 0; i < len(g.entries); i++ {
			if g.used.Has(i) {
				g.entries[i].Descendants = Singleton(i)
			}
		}
		// For each node, add it to all its ancestors' descendant sets.
		for i := 0; i < len(g.entries); i++ {
			if !g.used.Has(i) {
				continue
			}
			anc := g.entries[i].Ancestors
			anc.Reset(i) // skip self
			anc.ForEach(func(a int) {
				g.entries[a].Descendants = g.entries[a].Descendants.Union(Singleton(i))
			})
		}
	}
}

// GetReducedParents returns the minimal set of parents whose ancestors
// together equal all of i's ancestors.
func (g *DepGraph) GetReducedParents(i int) BitSet {
	parents := g.Ancestors(i)
	parents.Reset(i)

	parents.ForEach(func(parent int) {
		if parents.Has(parent) {
			// Remove ancestors of this parent (except parent itself)
			toRemove := g.Ancestors(parent)
			toRemove.Reset(parent)
			parents = parents.Difference(toRemove)
		}
	})

	return parents
}

// GetReducedChildren returns the minimal set of children whose descendants
// together equal all of i's descendants.
func (g *DepGraph) GetReducedChildren(i int) BitSet {
	children := g.Descendants(i)
	children.Reset(i)

	children.ForEach(func(child int) {
		if children.Has(child) {
			// Remove descendants of this child (except child itself)
			toRemove := g.Descendants(child)
			toRemove.Reset(child)
			children = children.Difference(toRemove)
		}
	})

	return children
}

// AggregateFeeFrac computes the total fee and size of a set of transactions.
func (g *DepGraph) AggregateFeeFrac(set BitSet) FeeFrac {
	var result FeeFrac
	set.ForEach(func(i int) {
		result = result.Add(g.entries[i].Feerate)
	})
	return result
}

// GetConnectedComponent returns the connected component containing tx within todo.
func (g *DepGraph) GetConnectedComponent(todo BitSet, tx int) BitSet {
	if !todo.Has(tx) {
		return BitSet{}
	}

	toAdd := Singleton(tx)
	var result BitSet

	for toAdd.Any() {
		old := result
		toAdd.ForEach(func(add int) {
			result = result.Union(g.Descendants(add))
			result = result.Union(g.Ancestors(add))
		})
		result = result.Intersection(todo)
		toAdd = result.Difference(old)
	}

	return result
}

// ComponentAfterRemoval returns the connected component that would contain
// seeds if every position outside survivors were removed from the graph.
// Read-only: it does not touch the graph.
//
// It deliberately does NOT reuse GetConnectedComponent. That walks the
// TRANSITIVE Ancestors/Descendants sets, which still contain the to-be-removed
// transactions' closure, so for a chain A → R → B with R removed it would union
// A and B into one component. RemoveTransactions rebuilds each survivor's
// ancestor set from its GetReducedParents edges (cluster.go RemoveTransactions),
// which leaves A and B genuinely disconnected, and splitCluster then puts them
// in different clusters. Walking the same reduced-parent edges here reproduces
// the post-removal component exactly, so a probe built on this agrees with the
// mutating gate that runs after the removal actually happens.
func (g *DepGraph) ComponentAfterRemoval(survivors BitSet, seeds []int) BitSet {
	// Undirected adjacency over direct (reduced-parent) edges, restricted to
	// survivors. Bounded by MaxClusterCount positions.
	adj := make(map[int]BitSet, survivors.Count())
	survivors.ForEach(func(i int) {
		parents := g.GetReducedParents(i).Intersection(survivors)
		if parents.None() {
			return
		}
		child := adj[i]
		adj[i] = child.Union(parents)
		parents.ForEach(func(p int) {
			pEdges := adj[p]
			pEdges.Set(i)
			adj[p] = pEdges
		})
	})

	var frontier BitSet
	for _, s := range seeds {
		if survivors.Has(s) {
			frontier.Set(s)
		}
	}

	var result BitSet
	for frontier.Any() {
		result = result.Union(frontier)
		var next BitSet
		frontier.ForEach(func(i int) {
			next = next.Union(adj[i])
		})
		frontier = next.Intersection(survivors).Difference(result)
	}
	return result
}

// FindConnectedComponent finds a connected component within todo.
func (g *DepGraph) FindConnectedComponent(todo BitSet) BitSet {
	if todo.None() {
		return todo
	}
	return g.GetConnectedComponent(todo, todo.First())
}

// IsConnected returns true if the subset forms a connected component.
func (g *DepGraph) IsConnected(subset BitSet) bool {
	return g.FindConnectedComponent(subset).Equal(subset)
}

// ============================================================================
// SetInfo - A set of transactions with aggregate feerate
// ============================================================================

// SetInfo represents a set of transactions and their aggregate feerate.
type SetInfo struct {
	Transactions BitSet
	Feerate      FeeFrac
}

// NewSetInfo creates a SetInfo for a single transaction.
func NewSetInfo(g *DepGraph, pos int) SetInfo {
	return SetInfo{
		Transactions: Singleton(pos),
		Feerate:      g.FeeRate(pos),
	}
}

// NewSetInfoFromSet creates a SetInfo for a set of transactions.
func NewSetInfoFromSet(g *DepGraph, set BitSet) SetInfo {
	return SetInfo{
		Transactions: set,
		Feerate:      g.AggregateFeeFrac(set),
	}
}

// Add adds a transaction to this SetInfo.
func (s *SetInfo) Add(g *DepGraph, pos int) {
	if s.Transactions.Has(pos) {
		return
	}
	s.Transactions.Set(pos)
	s.Feerate = s.Feerate.Add(g.FeeRate(pos))
}

// Merge merges another SetInfo into this one (no overlap allowed).
func (s *SetInfo) Merge(other SetInfo) {
	s.Transactions = s.Transactions.Union(other.Transactions)
	s.Feerate = s.Feerate.Add(other.Feerate)
}

// Sub subtracts a subset from this SetInfo.
func (s *SetInfo) Sub(other SetInfo) {
	s.Transactions = s.Transactions.Difference(other.Transactions)
	s.Feerate = s.Feerate.Sub(other.Feerate)
}

// ============================================================================
// Chunk - A chunk in the linearization
// ============================================================================

// Chunk represents a group of transactions that form a unit in the linearization.
// Chunks have monotonically decreasing feerates in a valid linearization.
type Chunk struct {
	Txs     []int   // Transaction indices in this chunk
	FeeRate FeeFrac // Aggregate fee/size of chunk
}

// ============================================================================
// Cluster - A connected component of transactions
// ============================================================================

// Cluster represents a connected component of transactions in the mempool.
// Transactions in a cluster are related through spending relationships.
type Cluster struct {
	ID           uint64              // Unique cluster ID
	Transactions map[wire.Hash256]int // txid -> index in depgraph
	DepGraph     *DepGraph           // Dependency graph for this cluster
	Linearization []int              // Current linearization (indices)
	Chunks       []Chunk             // Chunked linearization
	dirty        bool                // True if linearization needs recomputing
}

// NewCluster creates a new empty cluster.
func NewCluster(id uint64) *Cluster {
	return &Cluster{
		ID:           id,
		Transactions: make(map[wire.Hash256]int),
		DepGraph:     NewDepGraph(),
		dirty:        true,
	}
}

// Size returns the number of transactions in the cluster.
func (c *Cluster) Size() int {
	return len(c.Transactions)
}

// AddTransaction adds a transaction to the cluster.
// parents is the set of parent indices already in the cluster.
func (c *Cluster) AddTransaction(txHash wire.Hash256, fr FeeFrac, parents []int) (int, error) {
	if len(c.Transactions) >= MaxClusterSize {
		return -1, ErrClusterTooLarge
	}

	idx := c.DepGraph.AddTransaction(fr)
	if idx < 0 {
		return -1, ErrClusterTooLarge
	}

	c.Transactions[txHash] = idx

	// Add dependencies
	var parentSet BitSet
	for _, p := range parents {
		parentSet.Set(p)
	}
	c.DepGraph.AddDependencies(parentSet, idx)

	c.dirty = true
	return idx, nil
}

// RemoveTransaction removes a transaction from the cluster.
// Returns true if the cluster should be split.
func (c *Cluster) RemoveTransaction(txHash wire.Hash256) bool {
	idx, ok := c.Transactions[txHash]
	if !ok {
		return false
	}

	delete(c.Transactions, txHash)
	c.DepGraph.RemoveTransactions(Singleton(idx))
	c.dirty = true

	// Check if cluster needs splitting
	return c.DepGraph.TxCount() > 0 && !c.DepGraph.IsConnected(c.DepGraph.Positions())
}

// GetLinearization returns the current linearization, recomputing if necessary.
func (c *Cluster) GetLinearization() []int {
	if c.dirty {
		c.recomputeLinearization()
	}
	return c.Linearization
}

// GetChunks returns the chunked linearization.
func (c *Cluster) GetChunks() []Chunk {
	if c.dirty {
		c.recomputeLinearization()
	}
	return c.Chunks
}

// recomputeLinearization computes an optimal linearization using the chunking algorithm.
func (c *Cluster) recomputeLinearization() {
	if c.DepGraph.TxCount() == 0 {
		c.Linearization = nil
		c.Chunks = nil
		c.dirty = false
		return
	}

	// Use the greedy chunking algorithm:
	// 1. Find the highest-feerate topologically valid subset
	// 2. Make it a chunk
	// 3. Repeat until all transactions are placed

	remaining := c.DepGraph.Positions()
	var linearization []int
	var chunks []Chunk

	for remaining.Any() {
		// Find the best chunk: highest feerate subset where all ancestors are in subset
		bestChunk := c.findBestChunk(remaining)

		// Add to linearization in topological order within the chunk
		topoOrder := c.topologicalSort(bestChunk)
		linearization = append(linearization, topoOrder...)

		// Create chunk
		chunks = append(chunks, Chunk{
			Txs:     topoOrder,
			FeeRate: c.DepGraph.AggregateFeeFrac(bestChunk),
		})

		remaining = remaining.Difference(bestChunk)
	}

	c.Linearization = linearization
	c.Chunks = chunks
	c.dirty = false
}

// findBestChunk finds the highest-feerate topologically valid subset.
// A topologically valid subset contains all ancestors of any transaction in it.
func (c *Cluster) findBestChunk(remaining BitSet) BitSet {
	// For each transaction, compute its ancestor set within remaining
	// The best chunk is the one with highest aggregate feerate

	var bestSet BitSet
	var bestRate FeeFrac
	haveBest := false

	remaining.ForEach(func(i int) {
		// Candidate chunk: ancestors of i that are in remaining
		candidate := c.DepGraph.Ancestors(i).Intersection(remaining)

		// Compute aggregate feerate
		rate := c.DepGraph.AggregateFeeFrac(candidate)

		// Keep if better
		if !haveBest || rate.Compare(bestRate) > 0 {
			bestSet = candidate
			bestRate = rate
			haveBest = true
		}
	})

	return bestSet
}

// topologicalSort returns transactions in topological order (parents before children).
func (c *Cluster) topologicalSort(set BitSet) []int {
	elements := set.Elements()

	// Sort by ancestor count (fewer ancestors = earlier in order)
	sort.Slice(elements, func(i, j int) bool {
		ancI := c.DepGraph.Ancestors(elements[i]).Intersection(set).Count()
		ancJ := c.DepGraph.Ancestors(elements[j]).Intersection(set).Count()
		if ancI != ancJ {
			return ancI < ancJ
		}
		// Tie-break by index
		return elements[i] < elements[j]
	})

	return elements
}

// WorstChunkFeeRate returns the feerate of the lowest-feerate chunk.
func (c *Cluster) WorstChunkFeeRate() FeeFrac {
	chunks := c.GetChunks()
	if len(chunks) == 0 {
		return FeeFrac{}
	}
	return chunks[len(chunks)-1].FeeRate
}

// BestChunkFeeRate returns the feerate of the highest-feerate chunk.
func (c *Cluster) BestChunkFeeRate() FeeFrac {
	chunks := c.GetChunks()
	if len(chunks) == 0 {
		return FeeFrac{}
	}
	return chunks[0].FeeRate
}

// ============================================================================
// Linearization comparison using feerate diagrams
// ============================================================================

// FeerateDiagram represents a feerate diagram for comparing linearizations.
// It consists of (cumulative_size, cumulative_fee) points.
type FeerateDiagram struct {
	Points [][2]int64 // [size, fee] pairs
}

// NewFeerateDiagram creates a feerate diagram from chunks.
func NewFeerateDiagram(chunks []Chunk) FeerateDiagram {
	points := make([][2]int64, 0, len(chunks)+1)
	points = append(points, [2]int64{0, 0}) // Origin

	var cumSize, cumFee int64
	for _, chunk := range chunks {
		cumSize += int64(chunk.FeeRate.Size)
		cumFee += chunk.FeeRate.Fee
		points = append(points, [2]int64{cumSize, cumFee})
	}

	return FeerateDiagram{Points: points}
}

// Compare compares two feerate diagrams.
// Returns:
//
//	 1 if d is strictly better than other
//	-1 if other is strictly better than d
//	 0 if they are equivalent or incomparable
func (d FeerateDiagram) Compare(other FeerateDiagram) int {
	// A diagram is better if it has at least as much fee at every size point
	// and strictly more fee at at least one point.

	// Merge the size points and compare
	i, j := 0, 0
	dBetter, otherBetter := false, false

	for i < len(d.Points) || j < len(other.Points) {
		var size int64
		var dFee, otherFee int64

		if i >= len(d.Points) {
			size = other.Points[j][0]
		} else if j >= len(other.Points) {
			size = d.Points[i][0]
		} else if d.Points[i][0] <= other.Points[j][0] {
			size = d.Points[i][0]
		} else {
			size = other.Points[j][0]
		}

		// Interpolate d's fee at this size
		dFee = d.feeAtSize(size)
		otherFee = other.feeAtSize(size)

		if dFee > otherFee {
			dBetter = true
		}
		if otherFee > dFee {
			otherBetter = true
		}

		// Advance indices
		if i < len(d.Points) && d.Points[i][0] == size {
			i++
		}
		if j < len(other.Points) && other.Points[j][0] == size {
			j++
		}
	}

	if dBetter && !otherBetter {
		return 1
	}
	if otherBetter && !dBetter {
		return -1
	}
	return 0
}

// feeAtSize returns the fee at a given cumulative size using linear interpolation.
func (d FeerateDiagram) feeAtSize(size int64) int64 {
	if len(d.Points) == 0 {
		return 0
	}

	// Find the segment containing this size
	for i := 1; i < len(d.Points); i++ {
		if d.Points[i][0] >= size {
			// Interpolate between points[i-1] and points[i]
			prevSize := d.Points[i-1][0]
			prevFee := d.Points[i-1][1]
			curSize := d.Points[i][0]
			curFee := d.Points[i][1]

			if curSize == prevSize {
				return curFee
			}

			// Linear interpolation
			return prevFee + (curFee-prevFee)*(size-prevSize)/(curSize-prevSize)
		}
	}

	// Beyond the last point
	return d.Points[len(d.Points)-1][1]
}

// ============================================================================
// ClusterManager - Manages transaction clusters in the mempool
// ============================================================================

// ClusterManager tracks clusters and provides cluster-based operations.
type ClusterManager struct {
	clusters    map[uint64]*Cluster     // clusterID -> Cluster
	txToCluster map[wire.Hash256]uint64 // txid -> clusterID
	// txAdjWeight is the per-transaction quantity Core sums into a cluster's
	// size: max(tx_weight, sigops_cost * DEFAULT_BYTES_PER_SIGOP), in WEIGHT
	// units, unrounded (policy.cpp:390 GetSigOpsAdjustedWeight, as passed to
	// TxGraph at txmempool.cpp:1017). Kept alongside txToCluster rather than
	// inside Cluster so it survives merges and splits, which move transactions
	// between clusters but never change a transaction's own contribution.
	txAdjWeight   map[wire.Hash256]int64
	nextClusterID uint64
}

// NewClusterManager creates a new cluster manager.
func NewClusterManager() *ClusterManager {
	return &ClusterManager{
		clusters:      make(map[uint64]*Cluster),
		txToCluster:   make(map[wire.Hash256]uint64),
		txAdjWeight:   make(map[wire.Hash256]int64),
		nextClusterID: 1,
	}
}

// clusterAdjWeight returns the total sigop-adjusted weight of a cluster: the
// plain sum of its members' contributions, with NO per-transaction division and
// NO per-transaction rounding. Mirrors TxGraph's Cluster::GetTotalTxSize()
// accumulation (txgraph.cpp:2051).
func (cm *ClusterManager) clusterAdjWeight(c *Cluster) int64 {
	var total int64
	for txHash := range c.Transactions {
		total += cm.txAdjWeight[txHash]
	}
	return total
}

// ClusterSizeWeight returns the total sigop-adjusted weight, in weight units,
// of the cluster containing txHash, or 0 if the transaction is not clustered.
// Exposed for tests and diagnostics; the live gate uses clusterAdjWeight.
func (cm *ClusterManager) ClusterSizeWeight(txHash wire.Hash256) int64 {
	c := cm.GetCluster(txHash)
	if c == nil {
		return 0
	}
	return cm.clusterAdjWeight(c)
}

// ProspectiveCluster returns the (count, weight) the cluster containing a
// candidate transaction WOULD have if that candidate were admitted, without
// touching a single byte of ClusterManager state.
//
// adjWeight is the candidate's own sigop-adjusted weight contribution;
// parentTxids are its in-mempool parents. removals is the set of transactions
// the caller will evict as part of the SAME atomic change — the RBF conflicts
// and their in-mempool descendants — or nil when there are none.
//
// Core models exactly this with a ChangeSet: ReplacementChecks stages the
// conflicts for removal (validation.cpp:1019) and stages the candidate for
// addition (validation.cpp:927), both against TxGraph's STAGING level, and
// CheckMemPoolPolicyLimits then asks IsOversized(Level::TOP)
// (txmempool.cpp:1072-1080). The removals are therefore already discounted when
// the limit is evaluated; a probe that ignored them would reject ordinary
// replacements into a near-full cluster that Core accepts.
func (cm *ClusterManager) ProspectiveCluster(adjWeight int64, parentTxids []wire.Hash256, removals map[wire.Hash256]bool) (int, int64) {
	// Group the candidate's surviving in-mempool parents by current cluster.
	// A cluster with no resolvable parent index still registers (with a nil
	// index list): txToCluster pointing at a cluster that does not list the
	// transaction is a bookkeeping bug, and the conservative reading — the
	// whole cluster merges in — is the one the mutating gate has always taken.
	parentIndices := make(map[uint64][]int)
	for _, parentTxid := range parentTxids {
		if removals[parentTxid] {
			// The parent is leaving with the same change, so it cannot anchor
			// the candidate to its cluster. (Core rejects this shape outright
			// as "bad-txns-spends-conflicting-tx", validation.cpp:1358.)
			continue
		}
		clusterID, ok := cm.txToCluster[parentTxid]
		if !ok {
			continue
		}
		cluster := cm.clusters[clusterID]
		if cluster == nil {
			// Stale txToCluster entry — never deref nil.
			continue
		}
		idxs := parentIndices[clusterID]
		if idx, ok := cluster.Transactions[parentTxid]; ok {
			idxs = append(idxs, idx)
		}
		parentIndices[clusterID] = idxs
	}

	totalCount := 1          // the candidate itself
	totalWeight := adjWeight // the candidate's own contribution

	for clusterID, idxs := range parentIndices {
		cluster := cm.clusters[clusterID]

		// Fast path — nothing in this cluster is being removed, so the whole
		// cluster merges in. This is every non-RBF admission.
		survivors, anyRemoved := cm.survivingPositions(cluster, removals)
		if !anyRemoved {
			totalCount += cluster.Size()
			totalWeight += cm.clusterAdjWeight(cluster)
			continue
		}

		// Something in this cluster is going away, which may disconnect it.
		// Only the component the candidate actually re-anchors to counts, and
		// that component is defined over DIRECT edges — the same reduced-parent
		// edges DepGraph.RemoveTransactions rebuilds from and splitCluster then
		// walks — so this reproduces the post-eviction cluster exactly.
		//
		// With no resolvable anchor (the bookkeeping bug above) fall back to
		// every survivor, which is the largest the component can be.
		component := survivors
		if len(idxs) > 0 {
			component = cluster.DepGraph.ComponentAfterRemoval(survivors, idxs)
		}
		for txHash, idx := range cluster.Transactions {
			if component.Has(idx) {
				totalCount++
				totalWeight += cm.txAdjWeight[txHash]
			}
		}
	}

	return totalCount, totalWeight
}

// CheckLimits is the READ-ONLY cluster gate. It reports whether admitting a
// candidate would breach either Core cluster limit — the transaction count
// (MaxClusterCount) or the total sigop-adjusted weight (MaxClusterSizeWeight) —
// using Core's strict ">" on each axis (txgraph.cpp:2059). It mutates nothing.
//
// This exists so the rejection decision can be made BEFORE any mempool state is
// destroyed. Core's ordering is load-bearing, not incidental:
// AcceptSingleTransactionInternal runs ReplacementChecks, then
// CheckMemPoolPolicyLimits and `return Failure` (validation.cpp:1341-1345), and
// only then FinalizeSubpackage (validation.cpp:1393) — and FinalizeSubpackage is
// the ONLY place conflicting transactions are actually removed from the pool
// (validation.cpp:1198-1238). Deciding after the eviction instead turns a
// cluster-limit rejection into a free eviction primitive: the attacker's
// transaction is rejected, pays nothing, and the transactions it "replaced" are
// gone anyway.
//
// See ProspectiveCluster for the meaning of the arguments.
func (cm *ClusterManager) CheckLimits(adjWeight int64, parentTxids []wire.Hash256, removals map[wire.Hash256]bool) error {
	count, weight := cm.ProspectiveCluster(adjWeight, parentTxids, removals)
	if count > MaxClusterCount || weight > MaxClusterSizeWeight {
		return ErrClusterTooLarge
	}
	return nil
}

// survivingPositions returns the cluster's depgraph positions minus the
// positions of any member listed in removals, plus whether anything was
// actually dropped. Read-only.
func (cm *ClusterManager) survivingPositions(c *Cluster, removals map[wire.Hash256]bool) (BitSet, bool) {
	survivors := c.DepGraph.Positions()
	if len(removals) == 0 {
		return survivors, false
	}
	anyRemoved := false
	for txHash, idx := range c.Transactions {
		if removals[txHash] {
			survivors.Reset(idx)
			anyRemoved = true
		}
	}
	return survivors, anyRemoved
}

// AddTransaction adds a transaction to the appropriate cluster(s).
// If the transaction has parents in multiple clusters, those clusters are merged.
// parentTxids are the mempool transaction IDs that this transaction depends on.
// Returns the cluster the transaction was added to.
// adjWeight is the transaction's own contribution to its cluster's size, in
// WEIGHT units: max(tx_weight, sigops_cost * DEFAULT_BYTES_PER_SIGOP). See
// MaxClusterSizeWeight for why this must not be pre-divided into vbytes.
//
// This is the MUTATING gate: it still enforces both limits before committing
// anything, but by the time a caller reaches it the pool may already have been
// changed. Callers that evict conflicts must run CheckLimits first — see the
// comment there.
func (cm *ClusterManager) AddTransaction(txHash wire.Hash256, fee int64, size int32, adjWeight int64, parentTxids []wire.Hash256) (*Cluster, error) {
	// Find which clusters the parents are in
	parentClusters := make(map[uint64]bool)
	parentIndices := make(map[uint64][]int) // clusterID -> parent indices in that cluster

	for _, parentTxid := range parentTxids {
		if clusterID, ok := cm.txToCluster[parentTxid]; ok {
			cluster := cm.clusters[clusterID]
			if cluster == nil {
				// Stale txToCluster entry: the cluster was removed/merged
				// without this mapping being updated. Skip — never deref nil.
				continue
			}
			parentClusters[clusterID] = true
			if idx, ok := cluster.Transactions[parentTxid]; ok {
				parentIndices[clusterID] = append(parentIndices[clusterID], idx)
			}
		}
	}

	// ---------------------------------------------------------------------
	// Cluster limit gate. Runs BEFORE any mutation.
	//
	// When a transaction joins several parent clusters they are merged into
	// one, so the resulting cluster is the union of every parent cluster plus
	// the candidate. Clusters are disjoint (txToCluster is a function), so the
	// union's count and weight are plain sums over the distinct parent
	// cluster IDs.
	//
	// Core's comparison is STRICT ">" on both axes (txgraph.cpp:2059), applied
	// to the would-be merged group before it is committed. Evaluating it here,
	// ahead of mergeClusters, is what makes a rejection side-effect free: the
	// previous ordering merged first and checked after, and returned the error
	// without rolling back, so a single rejected transaction permanently fused
	// its parents' clusters and inflated every later cluster check. It also
	// guarantees the adds below cannot overflow Cluster.AddTransaction.
	//
	// The rule itself lives in CheckLimits so there is exactly one definition
	// of it. No removals are passed: by the time this runs, any conflicts the
	// caller intended to evict are already gone from the ClusterManager.
	// ---------------------------------------------------------------------
	if err := cm.CheckLimits(adjWeight, parentTxids, nil); err != nil {
		return nil, err
	}

	var targetCluster *Cluster

	if len(parentClusters) == 0 {
		// No parents in mempool - create new cluster
		targetCluster = NewCluster(cm.nextClusterID)
		cm.clusters[cm.nextClusterID] = targetCluster
		cm.nextClusterID++
	} else if len(parentClusters) == 1 {
		// Single parent cluster - add to it
		for clusterID := range parentClusters {
			targetCluster = cm.clusters[clusterID]
		}
	} else {
		// Multiple parent clusters - merge them
		targetCluster = cm.mergeClusters(parentClusters)
		// Recompute parent indices after merge
		parentIndices = make(map[uint64][]int)
		for _, parentTxid := range parentTxids {
			if idx, ok := targetCluster.Transactions[parentTxid]; ok {
				parentIndices[targetCluster.ID] = append(parentIndices[targetCluster.ID], idx)
			}
		}
	}

	// Add the transaction. The gate above already proved there is room, so
	// this cannot fail on a limit; a non-nil error here is a bookkeeping bug.
	fr := FeeFrac{Fee: fee, Size: size}
	allParentIndices := parentIndices[targetCluster.ID]
	_, err := targetCluster.AddTransaction(txHash, fr, allParentIndices)
	if err != nil {
		return nil, err
	}

	cm.txToCluster[txHash] = targetCluster.ID
	cm.txAdjWeight[txHash] = adjWeight
	return targetCluster, nil
}

// mergeClusters merges multiple clusters into one.
func (cm *ClusterManager) mergeClusters(clusterIDs map[uint64]bool) *Cluster {
	// Find the largest cluster to be the base
	var largestID uint64
	var largestSize int
	for id := range clusterIDs {
		if cm.clusters[id].Size() > largestSize {
			largestSize = cm.clusters[id].Size()
			largestID = id
		}
	}

	targetCluster := cm.clusters[largestID]

	// Merge other clusters into the target
	for id := range clusterIDs {
		if id == largestID {
			continue
		}

		srcCluster := cm.clusters[id]

		// We need to rebuild the target cluster's depgraph to include src transactions
		// This is a simplified merge - in practice we'd preserve the structure better
		for txHash, srcIdx := range srcCluster.Transactions {
			fr := srcCluster.DepGraph.FeeRate(srcIdx)

			// Find parents that are already in target
			srcAncestors := srcCluster.DepGraph.Ancestors(srcIdx)
			srcAncestors.Reset(srcIdx)

			var parentIndices []int
			srcAncestors.ForEach(func(ancIdx int) {
				// Find the txHash of this ancestor
				for ancestorHash, idx := range srcCluster.Transactions {
					if idx == ancIdx {
						if targetIdx, ok := targetCluster.Transactions[ancestorHash]; ok {
							parentIndices = append(parentIndices, targetIdx)
						}
					}
				}
			})

			idx, _ := targetCluster.AddTransaction(txHash, fr, parentIndices)
			if idx >= 0 {
				cm.txToCluster[txHash] = targetCluster.ID
			} else {
				// Unreachable now that AddTransaction gates the merged group
				// before calling mergeClusters, but kept defensively: the tx
				// did not fit into the target cluster, so drop its stale
				// mapping so it does not dangle when the source cluster is
				// deleted below (a dangling entry nil-derefs AddTransaction).
				delete(cm.txToCluster, txHash)
				delete(cm.txAdjWeight, txHash)
			}
		}

		// Remove the merged cluster
		delete(cm.clusters, id)
	}

	return targetCluster
}

// RemoveTransaction removes a transaction from its cluster.
// If removal causes the cluster to split, new clusters are created.
func (cm *ClusterManager) RemoveTransaction(txHash wire.Hash256) {
	clusterID, ok := cm.txToCluster[txHash]
	if !ok {
		return
	}

	delete(cm.txToCluster, txHash)
	delete(cm.txAdjWeight, txHash)
	cluster := cm.clusters[clusterID]

	needsSplit := cluster.RemoveTransaction(txHash)

	if cluster.Size() == 0 {
		delete(cm.clusters, clusterID)
		return
	}

	if needsSplit {
		cm.splitCluster(clusterID)
	}
}

// splitCluster splits a disconnected cluster into separate connected clusters.
func (cm *ClusterManager) splitCluster(clusterID uint64) {
	cluster := cm.clusters[clusterID]
	remaining := cluster.DepGraph.Positions()

	if remaining.None() {
		return
	}

	// Find first connected component - this stays in the original cluster
	firstComponent := cluster.DepGraph.FindConnectedComponent(remaining)
	remaining = remaining.Difference(firstComponent)

	// If there's nothing remaining, cluster is already connected
	if remaining.None() {
		return
	}

	// Build txHash -> idx reverse map for the original cluster
	idxToHash := make(map[int]wire.Hash256)
	for txHash, idx := range cluster.Transactions {
		idxToHash[idx] = txHash
	}

	// Extract transactions not in the first component
	for remaining.Any() {
		component := cluster.DepGraph.FindConnectedComponent(remaining)

		// Create new cluster for this component
		newCluster := NewCluster(cm.nextClusterID)
		cm.clusters[cm.nextClusterID] = newCluster
		cm.nextClusterID++

		// Move transactions to new cluster
		component.ForEach(func(idx int) {
			txHash := idxToHash[idx]
			fr := cluster.DepGraph.FeeRate(idx)

			// Find parent indices in the new cluster
			parents := cluster.DepGraph.GetReducedParents(idx).Intersection(component)
			var parentIndices []int
			parents.ForEach(func(pIdx int) {
				pHash := idxToHash[pIdx]
				if newIdx, ok := newCluster.Transactions[pHash]; ok {
					parentIndices = append(parentIndices, newIdx)
				}
			})

			newIdx, _ := newCluster.AddTransaction(txHash, fr, parentIndices)
			if newIdx >= 0 {
				cm.txToCluster[txHash] = newCluster.ID
			}

			// Remove from original cluster
			delete(cluster.Transactions, txHash)
		})

		// Remove from original depgraph
		cluster.DepGraph.RemoveTransactions(component)
		cluster.dirty = true

		remaining = remaining.Difference(component)
	}
}

// GetCluster returns the cluster containing the given transaction.
func (cm *ClusterManager) GetCluster(txHash wire.Hash256) *Cluster {
	if clusterID, ok := cm.txToCluster[txHash]; ok {
		return cm.clusters[clusterID]
	}
	return nil
}

// GetAllClusters returns all clusters.
func (cm *ClusterManager) GetAllClusters() []*Cluster {
	result := make([]*Cluster, 0, len(cm.clusters))
	for _, c := range cm.clusters {
		result = append(result, c)
	}
	return result
}

// CountDistinctClusters counts how many distinct clusters contain the given transactions.
func (cm *ClusterManager) CountDistinctClusters(txids []wire.Hash256) int {
	seen := make(map[uint64]bool)
	for _, txid := range txids {
		if clusterID, ok := cm.txToCluster[txid]; ok {
			seen[clusterID] = true
		}
	}
	return len(seen)
}

// Clear removes all clusters.
func (cm *ClusterManager) Clear() {
	cm.clusters = make(map[uint64]*Cluster)
	cm.txToCluster = make(map[wire.Hash256]uint64)
	cm.txAdjWeight = make(map[wire.Hash256]int64)
}

// ============================================================================
// Cluster-based mining selection
// ============================================================================

// MiningChunk represents a chunk selected for mining.
type MiningChunk struct {
	Cluster  *Cluster
	ChunkIdx int
	Chunk    Chunk
	FeeRate  FeeFrac
}

// GetChunksForMining returns all chunks from all clusters, sorted by feerate (highest first).
// This enables optimal block template construction.
func (cm *ClusterManager) GetChunksForMining() []MiningChunk {
	var allChunks []MiningChunk

	for _, cluster := range cm.clusters {
		chunks := cluster.GetChunks()
		for i, chunk := range chunks {
			allChunks = append(allChunks, MiningChunk{
				Cluster:  cluster,
				ChunkIdx: i,
				Chunk:    chunk,
				FeeRate:  chunk.FeeRate,
			})
		}
	}

	// Sort by feerate descending
	sort.Slice(allChunks, func(i, j int) bool {
		return allChunks[i].FeeRate.Compare(allChunks[j].FeeRate) > 0
	})

	return allChunks
}

// GetWorstChunkForEviction returns the worst (lowest feerate) chunk across all clusters.
// Used for mempool eviction when the mempool is full.
func (cm *ClusterManager) GetWorstChunkForEviction() (*Cluster, *Chunk) {
	var worstCluster *Cluster
	var worstChunk *Chunk
	var worstRate FeeFrac
	first := true

	for _, cluster := range cm.clusters {
		chunks := cluster.GetChunks()
		if len(chunks) == 0 {
			continue
		}

		// Last chunk is the worst (lowest feerate)
		lastChunk := &chunks[len(chunks)-1]
		if first || lastChunk.FeeRate.Compare(worstRate) < 0 {
			worstCluster = cluster
			worstChunk = lastChunk
			worstRate = lastChunk.FeeRate
			first = false
		}
	}

	return worstCluster, worstChunk
}
