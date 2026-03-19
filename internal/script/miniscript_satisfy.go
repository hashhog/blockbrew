// Package script implements the Bitcoin Script interpreter.
// This file implements Miniscript satisfaction - computing witness data.
package script

import (
	"bytes"
	"errors"
)

// Availability indicates whether a satisfaction/dissatisfaction is available.
type Availability int

const (
	AvailNo    Availability = iota // Not available
	AvailYes                       // Definitely available
	AvailMaybe                     // Might be available at signing time
)

// SatisfactionContext provides the information needed to satisfy a miniscript.
type SatisfactionContext struct {
	// Sign returns a signature for the given public key.
	// Returns the signature bytes and availability.
	Sign func(pubkey []byte) ([]byte, Availability)

	// SatSHA256 returns the preimage for a SHA256 hash.
	SatSHA256 func(hash []byte) ([]byte, Availability)

	// SatHASH256 returns the preimage for a HASH256 hash.
	SatHASH256 func(hash []byte) ([]byte, Availability)

	// SatRIPEMD160 returns the preimage for a RIPEMD160 hash.
	SatRIPEMD160 func(hash []byte) ([]byte, Availability)

	// SatHASH160 returns the preimage for a HASH160 hash.
	SatHASH160 func(hash []byte) ([]byte, Availability)

	// CheckOlder returns true if the relative timelock is satisfied.
	CheckOlder func(n uint32) bool

	// CheckAfter returns true if the absolute timelock is satisfied.
	CheckAfter func(n uint32) bool
}

// InputStack represents a potential witness stack.
type InputStack struct {
	Available Availability // Whether this stack is available
	HasSig    bool         // Whether this stack contains a signature
	Malleable bool         // Whether this stack is malleable
	NonCanon  bool         // Whether this stack is non-canonical
	Size      int          // Total serialized size
	Stack     [][]byte     // The actual stack elements
}

// NewInputStack creates a new empty valid input stack.
func NewInputStack() *InputStack {
	return &InputStack{
		Available: AvailYes,
		Stack:     [][]byte{},
	}
}

// NewInputStackWithElement creates an input stack with one element.
func NewInputStackWithElement(elem []byte) *InputStack {
	size := len(elem)
	if size <= 75 {
		size++ // 1-byte push
	} else if size <= 255 {
		size += 2 // OP_PUSHDATA1
	} else {
		size += 3 // OP_PUSHDATA2
	}
	return &InputStack{
		Available: AvailYes,
		Size:      size,
		Stack:     [][]byte{elem},
	}
}

// Invalid returns an invalid input stack.
func InvalidStack() *InputStack {
	return &InputStack{
		Available: AvailNo,
	}
}

// SetAvailable sets the availability.
func (s *InputStack) SetAvailable(avail Availability) *InputStack {
	s.Available = avail
	if avail == AvailNo {
		s.Stack = nil
		s.Size = 0
		s.HasSig = false
		s.Malleable = false
		s.NonCanon = false
	}
	return s
}

// SetWithSig marks this stack as containing a signature.
func (s *InputStack) SetWithSig() *InputStack {
	s.HasSig = true
	return s
}

// SetMalleable marks this stack as malleable.
func (s *InputStack) SetMalleable() *InputStack {
	s.Malleable = true
	return s
}

// SetNonCanon marks this stack as non-canonical.
func (s *InputStack) SetNonCanon() *InputStack {
	s.NonCanon = true
	return s
}

// Concat concatenates two input stacks.
func (s *InputStack) Concat(other *InputStack) *InputStack {
	if s.Available == AvailNo || other.Available == AvailNo {
		return InvalidStack()
	}

	result := &InputStack{
		Available: s.Available,
		HasSig:    s.HasSig || other.HasSig,
		Malleable: s.Malleable || other.Malleable,
		NonCanon:  s.NonCanon || other.NonCanon,
		Size:      s.Size + other.Size,
		Stack:     append(append([][]byte{}, s.Stack...), other.Stack...),
	}

	if other.Available == AvailMaybe {
		result.Available = AvailMaybe
	}

	return result
}

// Choose picks the better of two input stacks.
func Choose(a, b *InputStack) *InputStack {
	// If only one is available, pick the other
	if a.Available == AvailNo {
		return b
	}
	if b.Available == AvailNo {
		return a
	}

	// If only one requires a signature, prefer the other
	if !a.HasSig && b.HasSig {
		return a
	}
	if !b.HasSig && a.HasSig {
		return b
	}

	// If neither requires a signature, result is malleable
	if !a.HasSig && !b.HasSig {
		a.Malleable = true
		b.Malleable = true
	} else {
		// Both have signatures - prefer non-malleable
		if b.Malleable && !a.Malleable {
			return a
		}
		if a.Malleable && !b.Malleable {
			return b
		}
	}

	// Prefer YES over MAYBE
	if a.Available == AvailYes && b.Available != AvailYes {
		return a
	}
	if b.Available == AvailYes && a.Available != AvailYes {
		return b
	}

	// Between same availability, pick smaller for YES, larger for MAYBE
	if a.Available == AvailYes {
		if a.Size <= b.Size {
			return a
		}
		return b
	}
	// MAYBE - pick larger (more conservative estimate)
	if a.Size >= b.Size {
		return a
	}
	return b
}

// InputResult holds both satisfaction and dissatisfaction for a node.
type InputResult struct {
	Sat  *InputStack
	Nsat *InputStack
}

// Satisfy computes the witness stack to satisfy this miniscript.
func (n *MiniscriptNode) Satisfy(ctx *SatisfactionContext) ([][]byte, error) {
	result := n.produceInput(ctx)
	if result.Sat.Available == AvailNo {
		return nil, ErrMiniscriptNoSatisfaction
	}
	return result.Sat.Stack, nil
}

// produceInput recursively computes satisfaction/dissatisfaction for this node.
func (n *MiniscriptNode) produceInput(ctx *SatisfactionContext) *InputResult {
	// Compute results for all children first
	var subResults []*InputResult
	for _, sub := range n.Subs {
		subResults = append(subResults, sub.produceInput(ctx))
	}

	return n.computeInputResult(ctx, subResults)
}

// computeInputResult computes the input result for this node given child results.
func (n *MiniscriptNode) computeInputResult(ctx *SatisfactionContext, subRes []*InputResult) *InputResult {
	// Common stack elements
	zero := NewInputStackWithElement([]byte{})
	one := NewInputStackWithElement([]byte{0x01})
	zero32 := NewInputStackWithElement(make([]byte, 32))
	zero32.SetMalleable()

	switch n.Fragment {
	case FragJust0:
		return &InputResult{
			Sat:  InvalidStack(),
			Nsat: NewInputStack(),
		}

	case FragJust1:
		return &InputResult{
			Sat:  NewInputStack(),
			Nsat: InvalidStack(),
		}

	case FragPkK:
		var sig []byte
		avail := AvailNo
		if ctx.Sign != nil {
			sig, avail = ctx.Sign(n.Keys[0])
		}
		sat := NewInputStackWithElement(sig)
		sat.SetWithSig()
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: zero,
		}

	case FragPkH:
		var sig []byte
		avail := AvailNo
		if ctx.Sign != nil {
			sig, avail = ctx.Sign(n.Keys[0])
		}
		key := n.Keys[0]
		keySat := NewInputStackWithElement(key)
		sigSat := NewInputStackWithElement(sig)
		sigSat.SetWithSig()
		sigSat.SetAvailable(avail)
		return &InputResult{
			Sat:  sigSat.Concat(keySat),
			Nsat: zero.Concat(keySat),
		}

	case FragOlder:
		avail := AvailNo
		if ctx.CheckOlder != nil && ctx.CheckOlder(n.K) {
			avail = AvailYes
		}
		sat := NewInputStack()
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: InvalidStack(),
		}

	case FragAfter:
		avail := AvailNo
		if ctx.CheckAfter != nil && ctx.CheckAfter(n.K) {
			avail = AvailYes
		}
		sat := NewInputStack()
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: InvalidStack(),
		}

	case FragSHA256:
		var preimage []byte
		avail := AvailNo
		if ctx.SatSHA256 != nil {
			preimage, avail = ctx.SatSHA256(n.Data)
		}
		sat := NewInputStackWithElement(preimage)
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: zero32,
		}

	case FragHASH256:
		var preimage []byte
		avail := AvailNo
		if ctx.SatHASH256 != nil {
			preimage, avail = ctx.SatHASH256(n.Data)
		}
		sat := NewInputStackWithElement(preimage)
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: zero32,
		}

	case FragRIPEMD160:
		var preimage []byte
		avail := AvailNo
		if ctx.SatRIPEMD160 != nil {
			preimage, avail = ctx.SatRIPEMD160(n.Data)
		}
		sat := NewInputStackWithElement(preimage)
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: zero32,
		}

	case FragHASH160:
		var preimage []byte
		avail := AvailNo
		if ctx.SatHASH160 != nil {
			preimage, avail = ctx.SatHASH160(n.Data)
		}
		sat := NewInputStackWithElement(preimage)
		sat.SetAvailable(avail)
		return &InputResult{
			Sat:  sat,
			Nsat: zero32,
		}

	case FragWrapA, FragWrapS, FragWrapC, FragWrapN:
		return subRes[0]

	case FragWrapD:
		x := subRes[0]
		return &InputResult{
			Sat:  x.Sat.Concat(one),
			Nsat: zero,
		}

	case FragWrapV:
		x := subRes[0]
		return &InputResult{
			Sat:  x.Sat,
			Nsat: InvalidStack(),
		}

	case FragWrapJ:
		x := subRes[0]
		nsat := zero.SetMalleable()
		if x.Nsat.Available != AvailNo && !x.Nsat.HasSig {
			// Dissatisfaction exists but isn't secured by sig
			nsat.SetMalleable()
		}
		return &InputResult{
			Sat:  x.Sat,
			Nsat: nsat,
		}

	case FragAndV:
		x, y := subRes[0], subRes[1]
		// Satisfaction: sat(Y) sat(X)
		sat := y.Sat.Concat(x.Sat)
		// Dissatisfaction: nsat(Y) sat(X) - but mark as non-canon
		nsat := y.Nsat.Concat(x.Sat)
		nsat.SetNonCanon()
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragAndB:
		x, y := subRes[0], subRes[1]
		// Satisfaction: sat(Y) sat(X)
		sat := y.Sat.Concat(x.Sat)
		// Dissatisfaction options:
		// 1. nsat(Y) nsat(X) - canonical
		// 2. sat(Y) nsat(X) - malleable
		// 3. nsat(Y) sat(X) - malleable
		nsat1 := y.Nsat.Concat(x.Nsat)
		nsat2 := y.Sat.Concat(x.Nsat)
		nsat2.SetMalleable().SetNonCanon()
		nsat3 := y.Nsat.Concat(x.Sat)
		nsat3.SetMalleable().SetNonCanon()
		nsat := Choose(nsat1, Choose(nsat2, nsat3))
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragOrB:
		x, z := subRes[0], subRes[1]
		// Satisfaction options:
		// 1. nsat(Z) sat(X)
		// 2. sat(Z) nsat(X)
		// 3. sat(Z) sat(X) - malleable (overcomplete)
		sat1 := z.Nsat.Concat(x.Sat)
		sat2 := z.Sat.Concat(x.Nsat)
		sat3 := z.Sat.Concat(x.Sat)
		sat3.SetMalleable().SetNonCanon()
		sat := Choose(sat1, Choose(sat2, sat3))
		// Dissatisfaction: nsat(Z) nsat(X)
		nsat := z.Nsat.Concat(x.Nsat)
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragOrC:
		x, z := subRes[0], subRes[1]
		// Satisfaction options:
		// 1. sat(X)
		// 2. sat(Z) nsat(X)
		sat := Choose(x.Sat, z.Sat.Concat(x.Nsat))
		return &InputResult{
			Sat:  sat,
			Nsat: InvalidStack(), // V type cannot be dissatisfied
		}

	case FragOrD:
		x, z := subRes[0], subRes[1]
		// Satisfaction options:
		// 1. sat(X)
		// 2. sat(Z) nsat(X)
		sat := Choose(x.Sat, z.Sat.Concat(x.Nsat))
		// Dissatisfaction: nsat(Z) nsat(X)
		nsat := z.Nsat.Concat(x.Nsat)
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragOrI:
		x, z := subRes[0], subRes[1]
		// Satisfaction options:
		// 1. sat(X) 1
		// 2. sat(Z) 0
		sat1 := x.Sat.Concat(one)
		sat2 := z.Sat.Concat(zero)
		sat := Choose(sat1, sat2)
		// Dissatisfaction options:
		// 1. nsat(X) 1
		// 2. nsat(Z) 0
		nsat1 := x.Nsat.Concat(one)
		nsat2 := z.Nsat.Concat(zero)
		nsat := Choose(nsat1, nsat2)
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragAndOr:
		x, y, z := subRes[0], subRes[1], subRes[2]
		// Satisfaction options:
		// 1. sat(Y) sat(X)
		// 2. sat(Z) nsat(X)
		sat1 := y.Sat.Concat(x.Sat)
		sat2 := z.Sat.Concat(x.Nsat)
		sat := Choose(sat1, sat2)
		// Dissatisfaction options:
		// 1. nsat(Z) nsat(X)
		// 2. nsat(Y) sat(X) - non-canon
		nsat1 := z.Nsat.Concat(x.Nsat)
		nsat2 := y.Nsat.Concat(x.Sat)
		nsat2.SetNonCanon()
		nsat := Choose(nsat1, nsat2)
		return &InputResult{
			Sat:  sat,
			Nsat: nsat,
		}

	case FragMulti:
		// Multi: k signatures from n keys
		// Dynamic programming approach
		nKeys := len(n.Keys)
		k := int(n.K)

		// sats[j] = best stack for j signatures
		sats := make([]*InputStack, k+1)
		sats[0] = zero // Dummy element for CHECKMULTISIG bug

		for i := 0; i < nKeys; i++ {
			var sig []byte
			avail := AvailNo
			if ctx.Sign != nil {
				sig, avail = ctx.Sign(n.Keys[i])
			}
			sigStack := NewInputStackWithElement(sig)
			sigStack.SetWithSig()
			sigStack.SetAvailable(avail)

			// Update from back to front
			newSats := make([]*InputStack, k+1)
			newSats[0] = sats[0]
			for j := 1; j <= min(i+1, k); j++ {
				// Option 1: don't use this key's signature
				opt1 := sats[j]
				// Option 2: use this key's signature
				var opt2 *InputStack
				if j > 0 && sats[j-1] != nil {
					opt2 = sats[j-1].Concat(sigStack)
				}
				newSats[j] = Choose(opt1, opt2)
			}
			sats = newSats
		}

		// Dissatisfaction: k+1 empty elements
		nsat := zero
		for i := 0; i < k; i++ {
			nsat = nsat.Concat(zero)
		}

		return &InputResult{
			Sat:  sats[k],
			Nsat: nsat,
		}

	case FragMultiA:
		// multi_a: signatures in reverse key order
		nKeys := len(n.Keys)
		k := int(n.K)

		// sats[j] = best stack for j signatures
		sats := make([]*InputStack, k+1)
		sats[0] = NewInputStack()

		for i := 0; i < nKeys; i++ {
			// Get signature for key in reverse order
			keyIdx := nKeys - 1 - i
			var sig []byte
			avail := AvailNo
			if ctx.Sign != nil {
				sig, avail = ctx.Sign(n.Keys[keyIdx])
			}
			sigStack := NewInputStackWithElement(sig)
			sigStack.SetWithSig()
			sigStack.SetAvailable(avail)

			newSats := make([]*InputStack, k+1)
			// No signature for this key
			newSats[0] = sats[0].Concat(zero)

			for j := 1; j <= min(i+1, k); j++ {
				// Option 1: don't use this key's signature
				opt1 := sats[j]
				if opt1 != nil {
					opt1 = opt1.Concat(zero)
				}
				// Option 2: use this key's signature
				var opt2 *InputStack
				if sats[j-1] != nil {
					opt2 = sats[j-1].Concat(sigStack)
				}
				newSats[j] = Choose(opt1, opt2)
			}
			sats = newSats
		}

		// Dissatisfaction: n empty elements
		nsat := sats[0]

		return &InputResult{
			Sat:  sats[k],
			Nsat: nsat,
		}

	case FragThresh:
		// thresh: k of n subexpressions
		k := int(n.K)
		nSubs := len(n.Subs)

		// sats[j] = best stack for j satisfactions
		sats := make([]*InputStack, k+1)
		sats[0] = NewInputStack()

		for i := 0; i < nSubs; i++ {
			res := subRes[nSubs-1-i] // Process in reverse

			newSats := make([]*InputStack, k+1)
			// 0 satisfactions: add dissatisfaction
			newSats[0] = sats[0].Concat(res.Nsat)

			for j := 1; j <= min(i+1, k); j++ {
				// Option 1: dissatisfy this sub
				opt1 := sats[j]
				if opt1 != nil {
					opt1 = opt1.Concat(res.Nsat)
				}
				// Option 2: satisfy this sub
				var opt2 *InputStack
				if sats[j-1] != nil {
					opt2 = sats[j-1].Concat(res.Sat)
				}
				newSats[j] = Choose(opt1, opt2)
			}
			sats = newSats
		}

		// Dissatisfaction: all subs dissatisfied
		nsat := InvalidStack()
		for j := 0; j <= k; j++ {
			if j != k && sats[j] != nil {
				candidate := sats[j]
				if j != 0 {
					candidate.SetMalleable().SetNonCanon()
				}
				nsat = Choose(nsat, candidate)
			}
		}

		return &InputResult{
			Sat:  sats[k],
			Nsat: nsat,
		}
	}

	return &InputResult{
		Sat:  InvalidStack(),
		Nsat: InvalidStack(),
	}
}

// min returns the minimum of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetRequiredKeys returns all public keys that need signatures.
func (n *MiniscriptNode) GetRequiredKeys() [][]byte {
	var keys [][]byte

	var collect func(*MiniscriptNode)
	collect = func(node *MiniscriptNode) {
		switch node.Fragment {
		case FragPkK, FragPkH:
			keys = append(keys, node.Keys...)
		case FragMulti, FragMultiA:
			keys = append(keys, node.Keys...)
		}
		for _, sub := range node.Subs {
			collect(sub)
		}
	}
	collect(n)

	return keys
}

// GetRequiredHashes returns all hashes that need preimages.
type RequiredHash struct {
	HashType string // "sha256", "hash256", "ripemd160", "hash160"
	Hash     []byte
}

func (n *MiniscriptNode) GetRequiredHashes() []RequiredHash {
	var hashes []RequiredHash

	var collect func(*MiniscriptNode)
	collect = func(node *MiniscriptNode) {
		switch node.Fragment {
		case FragSHA256:
			hashes = append(hashes, RequiredHash{HashType: "sha256", Hash: node.Data})
		case FragHASH256:
			hashes = append(hashes, RequiredHash{HashType: "hash256", Hash: node.Data})
		case FragRIPEMD160:
			hashes = append(hashes, RequiredHash{HashType: "ripemd160", Hash: node.Data})
		case FragHASH160:
			hashes = append(hashes, RequiredHash{HashType: "hash160", Hash: node.Data})
		}
		for _, sub := range node.Subs {
			collect(sub)
		}
	}
	collect(n)

	return hashes
}

// GetTimelocks returns all timelocks in the miniscript.
type Timelock struct {
	IsAbsolute bool   // true for CLTV, false for CSV
	IsTime     bool   // true for time-based, false for block-based
	Value      uint32
}

func (n *MiniscriptNode) GetTimelocks() []Timelock {
	var timelocks []Timelock

	var collect func(*MiniscriptNode)
	collect = func(node *MiniscriptNode) {
		switch node.Fragment {
		case FragAfter:
			timelocks = append(timelocks, Timelock{
				IsAbsolute: true,
				IsTime:     node.K >= 500000000,
				Value:      node.K,
			})
		case FragOlder:
			timelocks = append(timelocks, Timelock{
				IsAbsolute: false,
				IsTime:     node.K&(1<<22) != 0,
				Value:      node.K,
			})
		}
		for _, sub := range node.Subs {
			collect(sub)
		}
	}
	collect(n)

	return timelocks
}

// CreateSatisfactionContext creates a satisfaction context from maps.
func CreateSatisfactionContext(
	signatures map[string][]byte, // pubkey hex -> signature
	preimages map[string][]byte, // hash hex -> preimage
	checkOlder func(uint32) bool,
	checkAfter func(uint32) bool,
) *SatisfactionContext {
	return &SatisfactionContext{
		Sign: func(pubkey []byte) ([]byte, Availability) {
			key := bytesToHex(pubkey)
			if sig, ok := signatures[key]; ok {
				return sig, AvailYes
			}
			return nil, AvailNo
		},
		SatSHA256: func(hash []byte) ([]byte, Availability) {
			key := bytesToHex(hash)
			if pre, ok := preimages[key]; ok {
				return pre, AvailYes
			}
			return nil, AvailNo
		},
		SatHASH256: func(hash []byte) ([]byte, Availability) {
			key := bytesToHex(hash)
			if pre, ok := preimages[key]; ok {
				return pre, AvailYes
			}
			return nil, AvailNo
		},
		SatRIPEMD160: func(hash []byte) ([]byte, Availability) {
			key := bytesToHex(hash)
			if pre, ok := preimages[key]; ok {
				return pre, AvailYes
			}
			return nil, AvailNo
		},
		SatHASH160: func(hash []byte) ([]byte, Availability) {
			key := bytesToHex(hash)
			if pre, ok := preimages[key]; ok {
				return pre, AvailYes
			}
			return nil, AvailNo
		},
		CheckOlder: checkOlder,
		CheckAfter: checkAfter,
	}
}

// bytesToHex converts bytes to lowercase hex string.
func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// CanSatisfy returns true if a valid satisfaction exists with the given context.
func (n *MiniscriptNode) CanSatisfy(ctx *SatisfactionContext) bool {
	result := n.produceInput(ctx)
	return result.Sat.Available != AvailNo
}

// EstimateWitnessSize estimates the witness size for satisfying this miniscript.
func (n *MiniscriptNode) EstimateWitnessSize(ctx *SatisfactionContext) (int, error) {
	result := n.produceInput(ctx)
	if result.Sat.Available == AvailNo {
		return 0, ErrMiniscriptNoSatisfaction
	}
	return result.Sat.Size, nil
}

// SerializeWitness serializes the witness stack for inclusion in a transaction.
func SerializeWitness(stack [][]byte) []byte {
	var buf bytes.Buffer

	// Write number of items
	writeVarInt(&buf, uint64(len(stack)))

	// Write each item
	for _, item := range stack {
		writeVarInt(&buf, uint64(len(item)))
		buf.Write(item)
	}

	return buf.Bytes()
}

// writeVarInt writes a variable-length integer.
func writeVarInt(buf *bytes.Buffer, n uint64) {
	if n < 0xfd {
		buf.WriteByte(byte(n))
	} else if n <= 0xffff {
		buf.WriteByte(0xfd)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
	} else if n <= 0xffffffff {
		buf.WriteByte(0xfe)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 24))
	} else {
		buf.WriteByte(0xff)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 24))
		buf.WriteByte(byte(n >> 32))
		buf.WriteByte(byte(n >> 40))
		buf.WriteByte(byte(n >> 48))
		buf.WriteByte(byte(n >> 56))
	}
}

// Dissatisfy computes a dissatisfaction witness for this miniscript.
func (n *MiniscriptNode) Dissatisfy(ctx *SatisfactionContext) ([][]byte, error) {
	result := n.produceInput(ctx)
	if result.Nsat.Available == AvailNo {
		return nil, errors.New("no dissatisfaction available")
	}
	return result.Nsat.Stack, nil
}
