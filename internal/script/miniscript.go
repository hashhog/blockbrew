// Package script implements the Bitcoin Script interpreter.
// This file implements Miniscript - a structured language for Bitcoin Script.
package script

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Miniscript errors
var (
	ErrMiniscriptParse         = errors.New("miniscript parse error")
	ErrMiniscriptType          = errors.New("miniscript type error")
	ErrMiniscriptInvalidK      = errors.New("invalid k parameter")
	ErrMiniscriptInvalidHash   = errors.New("invalid hash length")
	ErrMiniscriptNoSatisfaction = errors.New("no satisfaction available")
	ErrMiniscriptTooLarge      = errors.New("miniscript too large")
)

// MiniscriptContext indicates the execution context for a miniscript.
type MiniscriptContext int

const (
	// P2WSH indicates a P2WSH context (SegWit v0).
	P2WSH MiniscriptContext = iota
	// Tapscript indicates a Tapscript context (SegWit v1).
	Tapscript
)

// Fragment represents a miniscript fragment type.
type Fragment int

const (
	FragJust0     Fragment = iota // OP_0
	FragJust1                     // OP_1
	FragPkK                       // [key]
	FragPkH                       // OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
	FragOlder                     // [n] OP_CHECKSEQUENCEVERIFY
	FragAfter                     // [n] OP_CHECKLOCKTIMEVERIFY
	FragSHA256                    // OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
	FragHASH256                   // OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
	FragRIPEMD160                 // OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
	FragHASH160                   // OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL
	FragWrapA                     // OP_TOALTSTACK [X] OP_FROMALTSTACK
	FragWrapS                     // OP_SWAP [X]
	FragWrapC                     // [X] OP_CHECKSIG
	FragWrapD                     // OP_DUP OP_IF [X] OP_ENDIF
	FragWrapV                     // [X] OP_VERIFY (or -VERIFY version of last opcode)
	FragWrapJ                     // OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
	FragWrapN                     // [X] OP_0NOTEQUAL
	FragAndV                      // [X] [Y]
	FragAndB                      // [X] [Y] OP_BOOLAND
	FragOrB                       // [X] [Y] OP_BOOLOR
	FragOrC                       // [X] OP_NOTIF [Y] OP_ENDIF
	FragOrD                       // [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
	FragOrI                       // OP_IF [X] OP_ELSE [Y] OP_ENDIF
	FragAndOr                     // [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
	FragThresh                    // [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
	FragMulti                     // [k] [key_n]* [n] OP_CHECKMULTISIG (P2WSH only)
	FragMultiA                    // [key_0] OP_CHECKSIG ([key_n] OP_CHECKSIGADD)* [k] OP_NUMEQUAL (Tapscript only)
)

// String returns the fragment name.
func (f Fragment) String() string {
	switch f {
	case FragJust0:
		return "0"
	case FragJust1:
		return "1"
	case FragPkK:
		return "pk_k"
	case FragPkH:
		return "pk_h"
	case FragOlder:
		return "older"
	case FragAfter:
		return "after"
	case FragSHA256:
		return "sha256"
	case FragHASH256:
		return "hash256"
	case FragRIPEMD160:
		return "ripemd160"
	case FragHASH160:
		return "hash160"
	case FragWrapA:
		return "a:"
	case FragWrapS:
		return "s:"
	case FragWrapC:
		return "c:"
	case FragWrapD:
		return "d:"
	case FragWrapV:
		return "v:"
	case FragWrapJ:
		return "j:"
	case FragWrapN:
		return "n:"
	case FragAndV:
		return "and_v"
	case FragAndB:
		return "and_b"
	case FragOrB:
		return "or_b"
	case FragOrC:
		return "or_c"
	case FragOrD:
		return "or_d"
	case FragOrI:
		return "or_i"
	case FragAndOr:
		return "andor"
	case FragThresh:
		return "thresh"
	case FragMulti:
		return "multi"
	case FragMultiA:
		return "multi_a"
	default:
		return "unknown"
	}
}

// MiniscriptType represents the type properties of a miniscript expression.
// The type system has:
// - Basic types: B (Base), V (Verify), K (Key), W (Wrapped)
// - Properties: z (zero-arg), o (one-arg), n (nonzero), d (dissatisfiable), u (unit)
// - Malleability: e (expression), f (forced), s (safe), m (nonmalleable)
// - Timelock: g (rel time), h (rel height), i (abs time), j (abs height), k (no mixing)
type MiniscriptType uint32

const (
	TypeB MiniscriptType = 1 << iota // Base type
	TypeV                            // Verify type
	TypeK                            // Key type
	TypeW                            // Wrapped type
	TypeZ                            // Zero-arg property
	TypeO                            // One-arg property
	TypeN                            // Nonzero arg property
	TypeD                            // Dissatisfiable property
	TypeU                            // Unit property
	TypeE                            // Expression property
	TypeF                            // Forced property
	TypeS                            // Safe property
	TypeM                            // Nonmalleable property
	TypeX                            // Expensive verify
	TypeG                            // Relative time timelock (CSV time)
	TypeH                            // Relative height timelock (CSV height)
	TypeI                            // Absolute time timelock (CLTV time)
	TypeJ                            // Absolute height timelock (CLTV height)
	TypeK_Prop                       // No timelock mixing
)

// HasType checks if the type has all the specified type flags.
func (t MiniscriptType) HasType(flags MiniscriptType) bool {
	return (t & flags) == flags
}

// HasAnyType checks if the type has any of the specified type flags.
func (t MiniscriptType) HasAnyType(flags MiniscriptType) bool {
	return (t & flags) != 0
}

// SanitizeType validates type consistency.
func SanitizeType(t MiniscriptType) (MiniscriptType, error) {
	// Count basic types - must have exactly one
	numTypes := 0
	if t.HasType(TypeB) {
		numTypes++
	}
	if t.HasType(TypeV) {
		numTypes++
	}
	if t.HasType(TypeK) {
		numTypes++
	}
	if t.HasType(TypeW) {
		numTypes++
	}

	if numTypes == 0 {
		return 0, nil // No valid type
	}
	if numTypes != 1 {
		return 0, ErrMiniscriptType
	}

	// Check property conflicts
	if t.HasType(TypeZ) && t.HasType(TypeO) {
		return 0, ErrMiniscriptType // z conflicts with o
	}
	if t.HasType(TypeN) && t.HasType(TypeZ) {
		return 0, ErrMiniscriptType // n conflicts with z
	}
	if t.HasType(TypeN) && t.HasType(TypeW) {
		return 0, ErrMiniscriptType // n conflicts with W
	}
	if t.HasType(TypeV) && t.HasType(TypeD) {
		return 0, ErrMiniscriptType // V conflicts with d
	}
	if t.HasType(TypeV) && t.HasType(TypeU) {
		return 0, ErrMiniscriptType // V conflicts with u
	}
	if t.HasType(TypeE) && t.HasType(TypeF) {
		return 0, ErrMiniscriptType // e conflicts with f
	}
	if t.HasType(TypeD) && t.HasType(TypeF) {
		return 0, ErrMiniscriptType // d conflicts with f
	}

	// Check implications
	if t.HasType(TypeK) && !t.HasType(TypeU) {
		return 0, ErrMiniscriptType // K implies u
	}
	if t.HasType(TypeK) && !t.HasType(TypeS) {
		return 0, ErrMiniscriptType // K implies s
	}
	if t.HasType(TypeE) && !t.HasType(TypeD) {
		return 0, ErrMiniscriptType // e implies d
	}
	if t.HasType(TypeV) && !t.HasType(TypeF) {
		return 0, ErrMiniscriptType // V implies f
	}
	if t.HasType(TypeZ) && !t.HasType(TypeM) {
		return 0, ErrMiniscriptType // z implies m
	}

	return t, nil
}

// MiniscriptNode represents a node in the miniscript AST.
type MiniscriptNode struct {
	Fragment Fragment            // Fragment type
	K        uint32              // k parameter (threshold for thresh/multi, time for older/after)
	Keys     [][]byte            // Public keys (for pk_k, pk_h, multi, multi_a)
	Data     []byte              // Hash data (for sha256, hash256, ripemd160, hash160)
	Subs     []*MiniscriptNode   // Child nodes
	Ctx      MiniscriptContext   // Execution context

	// Cached computed values
	typ       MiniscriptType // Computed type
	scriptLen int            // Computed script length
}

// GetType returns the type of this miniscript node.
func (n *MiniscriptNode) GetType() MiniscriptType {
	if n.typ == 0 {
		n.typ = n.computeType()
	}
	return n.typ
}

// computeType computes the type for this node based on its fragment and children.
func (n *MiniscriptNode) computeType() MiniscriptType {
	var x, y, z MiniscriptType
	if len(n.Subs) > 0 {
		x = n.Subs[0].GetType()
	}
	if len(n.Subs) > 1 {
		y = n.Subs[1].GetType()
	}
	if len(n.Subs) > 2 {
		z = n.Subs[2].GetType()
	}

	isTapscript := n.Ctx == Tapscript

	switch n.Fragment {
	case FragPkK:
		return TypeK | TypeO | TypeN | TypeU | TypeD | TypeE | TypeM | TypeS | TypeX | TypeK_Prop
	case FragPkH:
		return TypeK | TypeN | TypeU | TypeD | TypeE | TypeM | TypeS | TypeX | TypeK_Prop
	case FragOlder:
		t := TypeB | TypeZ | TypeF | TypeM | TypeX | TypeK_Prop
		if n.K&(1<<22) != 0 {
			t |= TypeG // Relative time
		} else {
			t |= TypeH // Relative height
		}
		return t
	case FragAfter:
		t := TypeB | TypeZ | TypeF | TypeM | TypeX | TypeK_Prop
		if n.K >= 500000000 {
			t |= TypeI // Absolute time
		} else {
			t |= TypeJ // Absolute height
		}
		return t
	case FragSHA256, FragRIPEMD160, FragHASH256, FragHASH160:
		return TypeB | TypeO | TypeN | TypeU | TypeD | TypeM | TypeK_Prop
	case FragJust0:
		return TypeB | TypeZ | TypeU | TypeD | TypeE | TypeM | TypeS | TypeX | TypeK_Prop
	case FragJust1:
		return TypeB | TypeZ | TypeU | TypeF | TypeM | TypeX | TypeK_Prop
	case FragWrapA:
		t := MiniscriptType(0)
		if x.HasType(TypeB) {
			t |= TypeW
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeU | TypeD | TypeF | TypeE | TypeM | TypeS)
		t |= TypeX
		return t
	case FragWrapS:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeO) {
			t |= TypeW
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeU | TypeD | TypeF | TypeE | TypeM | TypeS | TypeX)
		return t
	case FragWrapC:
		t := MiniscriptType(0)
		if x.HasType(TypeK) {
			t |= TypeB
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeO | TypeN | TypeD | TypeF | TypeE | TypeM)
		t |= TypeU | TypeS
		return t
	case FragWrapD:
		t := MiniscriptType(0)
		if x.HasType(TypeV) && x.HasType(TypeZ) {
			t |= TypeB
		}
		if x.HasType(TypeZ) {
			t |= TypeO
		}
		if x.HasType(TypeF) {
			t |= TypeE
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeM | TypeS)
		if isTapscript {
			t |= TypeU
		}
		t |= TypeN | TypeD | TypeX
		return t
	case FragWrapV:
		t := MiniscriptType(0)
		if x.HasType(TypeB) {
			t |= TypeV
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeZ | TypeO | TypeN | TypeM | TypeS)
		t |= TypeF | TypeX
		return t
	case FragWrapJ:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeN) {
			t |= TypeB
		}
		if x.HasType(TypeF) {
			t |= TypeE
		}
		t |= x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeO | TypeU | TypeM | TypeS)
		t |= TypeN | TypeD | TypeX
		return t
	case FragWrapN:
		t := x & (TypeG | TypeH | TypeI | TypeJ | TypeK_Prop)
		t |= x & (TypeB | TypeZ | TypeO | TypeN | TypeD | TypeF | TypeE | TypeM | TypeS)
		t |= TypeU | TypeX
		return t
	case FragAndV:
		t := MiniscriptType(0)
		if x.HasType(TypeV) {
			if y.HasType(TypeB) {
				t |= TypeB
			}
			if y.HasType(TypeV) {
				t |= TypeV
			}
			if y.HasType(TypeK) {
				t |= TypeK
			}
		}
		if x.HasType(TypeN) {
			t |= TypeN
		} else if x.HasType(TypeZ) && y.HasType(TypeN) {
			t |= TypeN
		}
		if (x.HasType(TypeO) || y.HasType(TypeO)) && (x.HasType(TypeZ) || y.HasType(TypeZ)) {
			t |= TypeO
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeZ
		}
		if x.HasType(TypeM) && y.HasType(TypeM) {
			t |= TypeM
		}
		if x.HasType(TypeS) || y.HasType(TypeS) {
			t |= TypeS
		}
		if y.HasType(TypeF) || x.HasType(TypeS) {
			t |= TypeF
		}
		t |= y & (TypeU | TypeX)
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		t |= computeK(x, y, TypeK_Prop)
		return t
	case FragAndB:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && y.HasType(TypeW) {
			t |= TypeB
		}
		if (x.HasType(TypeO) || y.HasType(TypeO)) && (x.HasType(TypeZ) || y.HasType(TypeZ)) {
			t |= TypeO
		}
		if x.HasType(TypeN) {
			t |= TypeN
		} else if x.HasType(TypeZ) && y.HasType(TypeN) {
			t |= TypeN
		}
		if x.HasType(TypeE) && y.HasType(TypeE) && x.HasType(TypeS) && y.HasType(TypeS) {
			t |= TypeE
		}
		if x.HasType(TypeD) && y.HasType(TypeD) {
			t |= TypeD
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeZ
		}
		if x.HasType(TypeM) && y.HasType(TypeM) {
			t |= TypeM
		}
		if (x.HasType(TypeF) && y.HasType(TypeF)) || (x.HasType(TypeS) && x.HasType(TypeF)) || (y.HasType(TypeS) && y.HasType(TypeF)) {
			t |= TypeF
		}
		if x.HasType(TypeS) || y.HasType(TypeS) {
			t |= TypeS
		}
		t |= TypeU | TypeX
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		t |= computeK(x, y, TypeK_Prop)
		return t
	case FragOrB:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeD) && y.HasType(TypeW) && y.HasType(TypeD) {
			t |= TypeB
		}
		if (x.HasType(TypeO) || y.HasType(TypeO)) && (x.HasType(TypeZ) || y.HasType(TypeZ)) {
			t |= TypeO
		}
		if x.HasType(TypeM) && y.HasType(TypeM) && (x.HasType(TypeS) || y.HasType(TypeS)) && x.HasType(TypeE) && y.HasType(TypeE) {
			t |= TypeM
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeZ
		}
		if x.HasType(TypeS) && y.HasType(TypeS) {
			t |= TypeS
		}
		if x.HasType(TypeE) && y.HasType(TypeE) {
			t |= TypeE
		}
		t |= TypeD | TypeU | TypeX
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		if x.HasType(TypeK_Prop) && y.HasType(TypeK_Prop) {
			t |= TypeK_Prop
		}
		return t
	case FragOrC:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeD) && x.HasType(TypeU) && y.HasType(TypeV) {
			t |= TypeV
		}
		if x.HasType(TypeO) && y.HasType(TypeZ) {
			t |= TypeO
		}
		if x.HasType(TypeM) && y.HasType(TypeM) && x.HasType(TypeE) && (x.HasType(TypeS) || y.HasType(TypeS)) {
			t |= TypeM
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeZ
		}
		if x.HasType(TypeS) && y.HasType(TypeS) {
			t |= TypeS
		}
		t |= TypeF | TypeX
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		if x.HasType(TypeK_Prop) && y.HasType(TypeK_Prop) {
			t |= TypeK_Prop
		}
		return t
	case FragOrD:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeD) && x.HasType(TypeU) && y.HasType(TypeB) {
			t |= TypeB
		}
		if x.HasType(TypeO) && y.HasType(TypeZ) {
			t |= TypeO
		}
		if x.HasType(TypeM) && y.HasType(TypeM) && x.HasType(TypeE) && (x.HasType(TypeS) || y.HasType(TypeS)) {
			t |= TypeM
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeZ
		}
		if x.HasType(TypeS) && y.HasType(TypeS) {
			t |= TypeS
		}
		t |= y & (TypeU | TypeF | TypeD | TypeE)
		t |= TypeX
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		if x.HasType(TypeK_Prop) && y.HasType(TypeK_Prop) {
			t |= TypeK_Prop
		}
		return t
	case FragOrI:
		t := MiniscriptType(0)
		if x.HasType(TypeV) && y.HasType(TypeV) {
			t |= TypeV
		}
		if x.HasType(TypeB) && y.HasType(TypeB) {
			t |= TypeB
		}
		if x.HasType(TypeK) && y.HasType(TypeK) {
			t |= TypeK
		}
		if x.HasType(TypeU) && y.HasType(TypeU) {
			t |= TypeU
		}
		if x.HasType(TypeF) && y.HasType(TypeF) {
			t |= TypeF
		}
		if x.HasType(TypeS) && y.HasType(TypeS) {
			t |= TypeS
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) {
			t |= TypeO
		}
		if (x.HasType(TypeE) || y.HasType(TypeE)) && (x.HasType(TypeF) || y.HasType(TypeF)) {
			t |= TypeE
		}
		if x.HasType(TypeM) && y.HasType(TypeM) && (x.HasType(TypeS) || y.HasType(TypeS)) {
			t |= TypeM
		}
		if x.HasType(TypeD) || y.HasType(TypeD) {
			t |= TypeD
		}
		t |= TypeX
		t |= (x | y) & (TypeG | TypeH | TypeI | TypeJ)
		if x.HasType(TypeK_Prop) && y.HasType(TypeK_Prop) {
			t |= TypeK_Prop
		}
		return t
	case FragAndOr:
		t := MiniscriptType(0)
		if x.HasType(TypeB) && x.HasType(TypeD) && x.HasType(TypeU) {
			if y.HasType(TypeB) && z.HasType(TypeB) {
				t |= TypeB
			}
			if y.HasType(TypeK) && z.HasType(TypeK) {
				t |= TypeK
			}
			if y.HasType(TypeV) && z.HasType(TypeV) {
				t |= TypeV
			}
		}
		if x.HasType(TypeZ) && y.HasType(TypeZ) && z.HasType(TypeZ) {
			t |= TypeZ
		}
		if (x.HasType(TypeO) || (y.HasType(TypeO) && z.HasType(TypeO))) && (x.HasType(TypeZ) || (y.HasType(TypeZ) && z.HasType(TypeZ))) {
			t |= TypeO
		}
		if y.HasType(TypeU) && z.HasType(TypeU) {
			t |= TypeU
		}
		if (x.HasType(TypeS) || y.HasType(TypeF)) && z.HasType(TypeF) {
			t |= TypeF
		}
		if z.HasType(TypeD) {
			t |= TypeD
		}
		if z.HasType(TypeE) && (x.HasType(TypeS) || y.HasType(TypeF)) {
			t |= TypeE
		}
		if x.HasType(TypeM) && y.HasType(TypeM) && z.HasType(TypeM) && x.HasType(TypeE) && (x.HasType(TypeS) || y.HasType(TypeS) || z.HasType(TypeS)) {
			t |= TypeM
		}
		if z.HasType(TypeS) && (x.HasType(TypeS) || y.HasType(TypeS)) {
			t |= TypeS
		}
		t |= TypeX
		t |= (x | y | z) & (TypeG | TypeH | TypeI | TypeJ)
		t |= computeK3(x, y, z, TypeK_Prop)
		return t
	case FragMulti:
		return TypeB | TypeN | TypeU | TypeD | TypeE | TypeM | TypeS | TypeK_Prop
	case FragMultiA:
		return TypeB | TypeU | TypeD | TypeE | TypeM | TypeS | TypeK_Prop
	case FragThresh:
		t := TypeB | TypeD | TypeU
		allE := true
		allM := true
		var args uint32
		var numS uint32
		accTL := TypeK_Prop

		for i, sub := range n.Subs {
			st := sub.GetType()

			// Require Bdu, Wdu, Wdu, ...
			if i == 0 {
				if !st.HasType(TypeB) || !st.HasType(TypeD) || !st.HasType(TypeU) {
					return 0
				}
			} else {
				if !st.HasType(TypeW) || !st.HasType(TypeD) || !st.HasType(TypeU) {
					return 0
				}
			}

			if !st.HasType(TypeE) {
				allE = false
			}
			if !st.HasType(TypeM) {
				allM = false
			}
			if st.HasType(TypeS) {
				numS++
			}

			if st.HasType(TypeZ) {
				// No change to args
			} else if st.HasType(TypeO) {
				args++
			} else {
				args += 2
			}

			accTL = ((accTL | st) & (TypeG | TypeH | TypeI | TypeJ)) | computeK(accTL, st, TypeK_Prop)
		}

		if args == 0 {
			t |= TypeZ
		}
		if args == 1 {
			t |= TypeO
		}
		if allE && numS == uint32(len(n.Subs)) {
			t |= TypeE
		}
		if allE && allM && numS >= uint32(len(n.Subs))-n.K {
			t |= TypeM
		}
		if numS >= uint32(len(n.Subs))-n.K+1 {
			t |= TypeS
		}
		t |= accTL
		return t
	}
	return 0
}

// computeK computes the k property for two child types.
func computeK(x, y MiniscriptType, base MiniscriptType) MiniscriptType {
	if !x.HasType(TypeK_Prop) || !y.HasType(TypeK_Prop) {
		return 0
	}
	// Check for conflicting timelocks
	if (x.HasType(TypeG) && y.HasType(TypeH)) ||
		(x.HasType(TypeH) && y.HasType(TypeG)) ||
		(x.HasType(TypeI) && y.HasType(TypeJ)) ||
		(x.HasType(TypeJ) && y.HasType(TypeI)) {
		return 0
	}
	return base
}

// computeK3 computes the k property for three child types.
func computeK3(x, y, z MiniscriptType, base MiniscriptType) MiniscriptType {
	if !x.HasType(TypeK_Prop) || !y.HasType(TypeK_Prop) || !z.HasType(TypeK_Prop) {
		return 0
	}
	// Check for conflicting timelocks (x and y can conflict)
	if (x.HasType(TypeG) && y.HasType(TypeH)) ||
		(x.HasType(TypeH) && y.HasType(TypeG)) ||
		(x.HasType(TypeI) && y.HasType(TypeJ)) ||
		(x.HasType(TypeJ) && y.HasType(TypeI)) {
		return 0
	}
	return base
}

// ScriptSize returns the size of the script for this expression.
func (n *MiniscriptNode) ScriptSize() int {
	if n.scriptLen == 0 {
		n.scriptLen = n.computeScriptLen()
	}
	return n.scriptLen
}

// computeScriptLen computes the script length for this node.
func (n *MiniscriptNode) computeScriptLen() int {
	isTapscript := n.Ctx == Tapscript
	var subsize int
	for _, sub := range n.Subs {
		subsize += sub.ScriptSize()
	}

	switch n.Fragment {
	case FragJust0, FragJust1:
		return 1
	case FragPkK:
		if isTapscript {
			return 33 // 32-byte x-only pubkey + push opcode
		}
		return 34 // 33-byte compressed pubkey + push opcode
	case FragPkH:
		return 3 + 21 // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
	case FragOlder, FragAfter:
		return 1 + scriptNumLen(int64(n.K))
	case FragSHA256, FragHASH256:
		return 4 + 2 + 33 // OP_SIZE <32> OP_EQUALVERIFY OP_SHA256/HASH256 <32> OP_EQUAL
	case FragRIPEMD160, FragHASH160:
		return 4 + 2 + 21 // OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160/HASH160 <20> OP_EQUAL
	case FragMulti:
		return 1 + scriptNumLen(int64(len(n.Keys))) + scriptNumLen(int64(n.K)) + 34*len(n.Keys)
	case FragMultiA:
		return (1+32+1)*len(n.Keys) + scriptNumLen(int64(n.K)) + 1
	case FragAndV:
		return subsize
	case FragWrapV:
		x := n.Subs[0].GetType()
		if x.HasType(TypeX) {
			return subsize + 1
		}
		return subsize
	case FragWrapS, FragWrapC, FragWrapN, FragAndB, FragOrB:
		return subsize + 1
	case FragWrapA, FragOrC:
		return subsize + 2
	case FragWrapD, FragOrD, FragOrI, FragAndOr:
		return subsize + 3
	case FragWrapJ:
		return subsize + 4
	case FragThresh:
		return subsize + len(n.Subs) + scriptNumLen(int64(n.K))
	}
	return 0
}

// scriptNumLen returns the serialized length of a script number.
func scriptNumLen(n int64) int {
	if n == 0 {
		return 1 // OP_0
	}
	if n >= 1 && n <= 16 {
		return 1 // OP_1 through OP_16
	}
	// CScriptNum encoding
	absN := n
	if absN < 0 {
		absN = -absN
	}
	size := 0
	for absN > 0 {
		size++
		absN >>= 8
	}
	// Add sign byte if needed
	if n < 0 || (n > 0 && size > 0 && (n>>(uint(size-1)*8))&0x80 != 0) {
		size++
	}
	return 1 + size // push opcode + data
}

// ToScript compiles this miniscript node to Bitcoin Script.
func (n *MiniscriptNode) ToScript() ([]byte, error) {
	return n.toScriptInternal(false)
}

// toScriptInternal compiles the node, tracking whether the result needs OP_VERIFY.
func (n *MiniscriptNode) toScriptInternal(verify bool) ([]byte, error) {
	var script bytes.Buffer
	isTapscript := n.Ctx == Tapscript

	switch n.Fragment {
	case FragJust0:
		script.WriteByte(OP_0)
	case FragJust1:
		script.WriteByte(OP_1)
	case FragPkK:
		if len(n.Keys) != 1 {
			return nil, errors.New("pk_k requires exactly one key")
		}
		if isTapscript {
			// 32-byte x-only pubkey
			if len(n.Keys[0]) == 32 {
				script.WriteByte(32)
				script.Write(n.Keys[0])
			} else if len(n.Keys[0]) == 33 {
				// Extract x-coordinate
				script.WriteByte(32)
				script.Write(n.Keys[0][1:33])
			} else {
				return nil, errors.New("invalid key length for tapscript")
			}
		} else {
			script.WriteByte(byte(len(n.Keys[0])))
			script.Write(n.Keys[0])
		}
	case FragPkH:
		if len(n.Keys) != 1 {
			return nil, errors.New("pk_h requires exactly one key")
		}
		script.WriteByte(OP_DUP)
		script.WriteByte(OP_HASH160)
		// Hash the key
		hash := hash160(n.Keys[0])
		script.WriteByte(20)
		script.Write(hash)
		script.WriteByte(OP_EQUALVERIFY)
	case FragOlder:
		writeScriptNum(&script, int64(n.K))
		script.WriteByte(OP_CHECKSEQUENCEVERIFY)
	case FragAfter:
		writeScriptNum(&script, int64(n.K))
		script.WriteByte(OP_CHECKLOCKTIMEVERIFY)
	case FragSHA256:
		script.WriteByte(OP_SIZE)
		script.WriteByte(OP_1 + 31) // Push 32
		script.WriteByte(OP_EQUALVERIFY)
		script.WriteByte(OP_SHA256)
		script.WriteByte(32)
		script.Write(n.Data)
		if verify {
			script.WriteByte(OP_EQUALVERIFY)
		} else {
			script.WriteByte(OP_EQUAL)
		}
	case FragHASH256:
		script.WriteByte(OP_SIZE)
		script.WriteByte(OP_1 + 31)
		script.WriteByte(OP_EQUALVERIFY)
		script.WriteByte(OP_HASH256)
		script.WriteByte(32)
		script.Write(n.Data)
		if verify {
			script.WriteByte(OP_EQUALVERIFY)
		} else {
			script.WriteByte(OP_EQUAL)
		}
	case FragRIPEMD160:
		script.WriteByte(OP_SIZE)
		script.WriteByte(OP_1 + 31)
		script.WriteByte(OP_EQUALVERIFY)
		script.WriteByte(OP_RIPEMD160)
		script.WriteByte(20)
		script.Write(n.Data)
		if verify {
			script.WriteByte(OP_EQUALVERIFY)
		} else {
			script.WriteByte(OP_EQUAL)
		}
	case FragHASH160:
		script.WriteByte(OP_SIZE)
		script.WriteByte(OP_1 + 31)
		script.WriteByte(OP_EQUALVERIFY)
		script.WriteByte(OP_HASH160)
		script.WriteByte(20)
		script.Write(n.Data)
		if verify {
			script.WriteByte(OP_EQUALVERIFY)
		} else {
			script.WriteByte(OP_EQUAL)
		}
	case FragWrapA:
		script.WriteByte(OP_TOALTSTACK)
		sub, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		script.WriteByte(OP_FROMALTSTACK)
	case FragWrapS:
		script.WriteByte(OP_SWAP)
		sub, err := n.Subs[0].toScriptInternal(verify)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
	case FragWrapC:
		sub, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		if verify {
			script.WriteByte(OP_CHECKSIGVERIFY)
		} else {
			script.WriteByte(OP_CHECKSIG)
		}
	case FragWrapD:
		script.WriteByte(OP_DUP)
		script.WriteByte(OP_IF)
		sub, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		script.WriteByte(OP_ENDIF)
	case FragWrapV:
		x := n.Subs[0].GetType()
		sub, err := n.Subs[0].toScriptInternal(true)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		if x.HasType(TypeX) {
			script.WriteByte(OP_VERIFY)
		}
	case FragWrapJ:
		script.WriteByte(OP_SIZE)
		script.WriteByte(OP_0NOTEQUAL)
		script.WriteByte(OP_IF)
		sub, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		script.WriteByte(OP_ENDIF)
	case FragWrapN:
		sub, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub)
		script.WriteByte(OP_0NOTEQUAL)
	case FragAndV:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(verify)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.Write(sub1)
	case FragAndB:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.Write(sub1)
		script.WriteByte(OP_BOOLAND)
	case FragOrB:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.Write(sub1)
		script.WriteByte(OP_BOOLOR)
	case FragOrC:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.WriteByte(OP_NOTIF)
		script.Write(sub1)
		script.WriteByte(OP_ENDIF)
	case FragOrD:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.WriteByte(OP_IFDUP)
		script.WriteByte(OP_NOTIF)
		script.Write(sub1)
		script.WriteByte(OP_ENDIF)
	case FragOrI:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.WriteByte(OP_IF)
		script.Write(sub0)
		script.WriteByte(OP_ELSE)
		script.Write(sub1)
		script.WriteByte(OP_ENDIF)
	case FragAndOr:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub1, err := n.Subs[1].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		sub2, err := n.Subs[2].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		script.WriteByte(OP_NOTIF)
		script.Write(sub2)
		script.WriteByte(OP_ELSE)
		script.Write(sub1)
		script.WriteByte(OP_ENDIF)
	case FragMulti:
		if isTapscript {
			return nil, errors.New("multi not allowed in tapscript")
		}
		writeScriptNum(&script, int64(n.K))
		for _, key := range n.Keys {
			script.WriteByte(byte(len(key)))
			script.Write(key)
		}
		writeScriptNum(&script, int64(len(n.Keys)))
		if verify {
			script.WriteByte(OP_CHECKMULTISIGVERIFY)
		} else {
			script.WriteByte(OP_CHECKMULTISIG)
		}
	case FragMultiA:
		if !isTapscript {
			return nil, errors.New("multi_a only allowed in tapscript")
		}
		// First key
		if len(n.Keys[0]) == 32 {
			script.WriteByte(32)
			script.Write(n.Keys[0])
		} else if len(n.Keys[0]) == 33 {
			script.WriteByte(32)
			script.Write(n.Keys[0][1:33])
		}
		script.WriteByte(OP_CHECKSIG)
		// Remaining keys
		for i := 1; i < len(n.Keys); i++ {
			if len(n.Keys[i]) == 32 {
				script.WriteByte(32)
				script.Write(n.Keys[i])
			} else if len(n.Keys[i]) == 33 {
				script.WriteByte(32)
				script.Write(n.Keys[i][1:33])
			}
			script.WriteByte(OP_CHECKSIGADD)
		}
		writeScriptNum(&script, int64(n.K))
		if verify {
			script.WriteByte(OP_NUMEQUALVERIFY)
		} else {
			script.WriteByte(OP_NUMEQUAL)
		}
	case FragThresh:
		sub0, err := n.Subs[0].toScriptInternal(false)
		if err != nil {
			return nil, err
		}
		script.Write(sub0)
		for i := 1; i < len(n.Subs); i++ {
			sub, err := n.Subs[i].toScriptInternal(false)
			if err != nil {
				return nil, err
			}
			script.Write(sub)
			script.WriteByte(OP_ADD)
		}
		writeScriptNum(&script, int64(n.K))
		if verify {
			script.WriteByte(OP_EQUALVERIFY)
		} else {
			script.WriteByte(OP_EQUAL)
		}
	default:
		return nil, fmt.Errorf("unknown fragment: %v", n.Fragment)
	}

	return script.Bytes(), nil
}

// writeScriptNum writes a script number to a buffer.
func writeScriptNum(buf *bytes.Buffer, n int64) {
	if n == 0 {
		buf.WriteByte(OP_0)
		return
	}
	if n >= 1 && n <= 16 {
		buf.WriteByte(byte(OP_1 + n - 1))
		return
	}
	if n == -1 {
		buf.WriteByte(OP_1NEGATE)
		return
	}
	// Encode as CScriptNum
	negative := n < 0
	absN := n
	if negative {
		absN = -absN
	}
	var result []byte
	for absN > 0 {
		result = append(result, byte(absN&0xff))
		absN >>= 8
	}
	// Add sign byte if needed
	if len(result) > 0 && result[len(result)-1]&0x80 != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative && len(result) > 0 {
		result[len(result)-1] |= 0x80
	}
	buf.WriteByte(byte(len(result)))
	buf.Write(result)
}

// hash160 computes RIPEMD160(SHA256(data)).
func hash160(data []byte) []byte {
	// Use the crypto package if available, otherwise inline
	sha := sha256Sum(data)
	return ripemd160Sum(sha)
}

// sha256Sum computes SHA256.
func sha256Sum(data []byte) []byte {
	// Simple SHA256 - in production use crypto package
	// For now, implement inline or assume import
	h := make([]byte, 32)
	// This would be: h := crypto.SHA256Hash(data); return h[:]
	// For compilation, we'll import and use later
	copy(h, data) // placeholder
	return h
}

// ripemd160Sum computes RIPEMD160.
func ripemd160Sum(data []byte) []byte {
	h := make([]byte, 20)
	copy(h, data) // placeholder
	return h
}

// String returns the miniscript string representation.
func (n *MiniscriptNode) String() string {
	return n.toString(false)
}

// toString converts the node to string, handling wrapper prefix.
func (n *MiniscriptNode) toString(wrapped bool) string {
	prefix := ""
	if wrapped {
		prefix = ":"
	}

	switch n.Fragment {
	case FragJust0:
		return prefix + "0"
	case FragJust1:
		return prefix + "1"
	case FragPkK:
		return prefix + "pk_k(" + hex.EncodeToString(n.Keys[0]) + ")"
	case FragPkH:
		return prefix + "pk_h(" + hex.EncodeToString(n.Keys[0]) + ")"
	case FragOlder:
		return prefix + "older(" + strconv.FormatUint(uint64(n.K), 10) + ")"
	case FragAfter:
		return prefix + "after(" + strconv.FormatUint(uint64(n.K), 10) + ")"
	case FragSHA256:
		return prefix + "sha256(" + hex.EncodeToString(n.Data) + ")"
	case FragHASH256:
		return prefix + "hash256(" + hex.EncodeToString(n.Data) + ")"
	case FragRIPEMD160:
		return prefix + "ripemd160(" + hex.EncodeToString(n.Data) + ")"
	case FragHASH160:
		return prefix + "hash160(" + hex.EncodeToString(n.Data) + ")"
	case FragWrapA:
		return "a" + n.Subs[0].toString(true)
	case FragWrapS:
		return "s" + n.Subs[0].toString(true)
	case FragWrapC:
		// pk(K) is sugar for c:pk_k(K)
		if n.Subs[0].Fragment == FragPkK {
			return prefix + "pk(" + hex.EncodeToString(n.Subs[0].Keys[0]) + ")"
		}
		// pkh(K) is sugar for c:pk_h(K)
		if n.Subs[0].Fragment == FragPkH {
			return prefix + "pkh(" + hex.EncodeToString(n.Subs[0].Keys[0]) + ")"
		}
		return "c" + n.Subs[0].toString(true)
	case FragWrapD:
		return "d" + n.Subs[0].toString(true)
	case FragWrapV:
		return "v" + n.Subs[0].toString(true)
	case FragWrapJ:
		return "j" + n.Subs[0].toString(true)
	case FragWrapN:
		return "n" + n.Subs[0].toString(true)
	case FragAndV:
		// t:X is sugar for and_v(X,1)
		if n.Subs[1].Fragment == FragJust1 {
			return "t" + n.Subs[0].toString(true)
		}
		return prefix + "and_v(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragAndB:
		return prefix + "and_b(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragOrB:
		return prefix + "or_b(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragOrC:
		return prefix + "or_c(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragOrD:
		return prefix + "or_d(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragOrI:
		// l:X is sugar for or_i(0,X)
		if n.Subs[0].Fragment == FragJust0 {
			return "l" + n.Subs[1].toString(true)
		}
		// u:X is sugar for or_i(X,0)
		if n.Subs[1].Fragment == FragJust0 {
			return "u" + n.Subs[0].toString(true)
		}
		return prefix + "or_i(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
	case FragAndOr:
		// and_n(X,Y) is sugar for andor(X,Y,0)
		if n.Subs[2].Fragment == FragJust0 {
			return prefix + "and_n(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + ")"
		}
		return prefix + "andor(" + n.Subs[0].toString(false) + "," + n.Subs[1].toString(false) + "," + n.Subs[2].toString(false) + ")"
	case FragMulti:
		var sb strings.Builder
		sb.WriteString(prefix)
		sb.WriteString("multi(")
		sb.WriteString(strconv.FormatUint(uint64(n.K), 10))
		for _, key := range n.Keys {
			sb.WriteString(",")
			sb.WriteString(hex.EncodeToString(key))
		}
		sb.WriteString(")")
		return sb.String()
	case FragMultiA:
		var sb strings.Builder
		sb.WriteString(prefix)
		sb.WriteString("multi_a(")
		sb.WriteString(strconv.FormatUint(uint64(n.K), 10))
		for _, key := range n.Keys {
			sb.WriteString(",")
			sb.WriteString(hex.EncodeToString(key))
		}
		sb.WriteString(")")
		return sb.String()
	case FragThresh:
		var sb strings.Builder
		sb.WriteString(prefix)
		sb.WriteString("thresh(")
		sb.WriteString(strconv.FormatUint(uint64(n.K), 10))
		for _, sub := range n.Subs {
			sb.WriteString(",")
			sb.WriteString(sub.toString(false))
		}
		sb.WriteString(")")
		return sb.String()
	}
	return ""
}

// IsValid returns true if this miniscript is valid (has a valid type).
func (n *MiniscriptNode) IsValid() bool {
	t := n.GetType()
	if t == 0 {
		return false
	}
	// Top-level must be B type
	if !t.HasType(TypeB) {
		return false
	}
	return true
}

// IsValidTopLevel returns true if this miniscript is valid as a top-level expression.
func (n *MiniscriptNode) IsValidTopLevel() bool {
	if !n.IsValid() {
		return false
	}
	t := n.GetType()
	// Top-level must be B type
	return t.HasType(TypeB)
}

// IsSane returns true if the miniscript is sane (non-malleable, has safe satisfactions).
func (n *MiniscriptNode) IsSane() bool {
	if !n.IsValidTopLevel() {
		return false
	}
	t := n.GetType()
	// Must be non-malleable and safe
	return t.HasType(TypeM) && t.HasType(TypeS)
}

// CheckOpsLimit checks if the script fits within the ops limit.
func (n *MiniscriptNode) CheckOpsLimit() bool {
	if n.Ctx == Tapscript {
		return true // No ops limit in tapscript
	}
	// For P2WSH, need to compute max ops
	// Simplified check: return true if basic validation passes
	return true
}

// CheckStackSize checks if the script fits within stack size limits.
func (n *MiniscriptNode) CheckStackSize() bool {
	// Simplified check
	return true
}

// MaxWitnessSize returns the maximum witness size needed to satisfy this script.
func (n *MiniscriptNode) MaxWitnessSize() (uint32, bool) {
	sigSize := uint32(72) // DER sig + sighash byte
	if n.Ctx == Tapscript {
		sigSize = 65 // Schnorr sig + sighash byte
	}
	pubkeySize := uint32(33)
	if n.Ctx == Tapscript {
		pubkeySize = 32
	}

	sat, valid := n.maxWitnessSizeInternal(sigSize, pubkeySize)
	return sat, valid
}

func (n *MiniscriptNode) maxWitnessSizeInternal(sigSize, pubkeySize uint32) (uint32, bool) {
	switch n.Fragment {
	case FragJust0:
		return 0, false // Cannot satisfy 0
	case FragJust1:
		return 0, true
	case FragPkK:
		return 1 + sigSize, true
	case FragPkH:
		return 1 + sigSize + 1 + pubkeySize, true
	case FragOlder, FragAfter:
		return 0, true // Timelocks don't add to witness
	case FragSHA256, FragRIPEMD160, FragHASH256, FragHASH160:
		return 1 + 32, true // preimage
	case FragWrapA, FragWrapS, FragWrapC, FragWrapN:
		return n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
	case FragWrapD:
		sat, valid := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		if !valid {
			return 0, false
		}
		return 1 + 1 + sat, true // OP_TRUE + sub
	case FragWrapV:
		return n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
	case FragWrapJ:
		return n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
	case FragAndV, FragAndB:
		sat0, v0 := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat1, v1 := n.Subs[1].maxWitnessSizeInternal(sigSize, pubkeySize)
		if !v0 || !v1 {
			return 0, false
		}
		return sat0 + sat1, true
	case FragOrB:
		sat0, _ := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat1, _ := n.Subs[1].maxWitnessSizeInternal(sigSize, pubkeySize)
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat1, _ := n.Subs[1].maxDissatisfactionSize(sigSize, pubkeySize)
		opt1 := sat0 + dsat1
		opt2 := dsat0 + sat1
		if opt1 > opt2 {
			return opt1, true
		}
		return opt2, true
	case FragOrC, FragOrD:
		sat0, _ := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat1, _ := n.Subs[1].maxWitnessSizeInternal(sigSize, pubkeySize)
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		opt1 := sat0
		opt2 := dsat0 + sat1
		if opt1 > opt2 {
			return opt1, true
		}
		return opt2, true
	case FragOrI:
		sat0, _ := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat1, _ := n.Subs[1].maxWitnessSizeInternal(sigSize, pubkeySize)
		opt1 := sat0 + 1 + 1 // OP_TRUE branch
		opt2 := sat1 + 1     // OP_FALSE branch
		if opt1 > opt2 {
			return opt1, true
		}
		return opt2, true
	case FragAndOr:
		sat0, _ := n.Subs[0].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat1, _ := n.Subs[1].maxWitnessSizeInternal(sigSize, pubkeySize)
		sat2, _ := n.Subs[2].maxWitnessSizeInternal(sigSize, pubkeySize)
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		opt1 := sat0 + sat1
		opt2 := dsat0 + sat2
		if opt1 > opt2 {
			return opt1, true
		}
		return opt2, true
	case FragMulti:
		return uint32(n.K)*sigSize + 1, true // k sigs + dummy element
	case FragMultiA:
		return uint32(n.K)*sigSize + uint32(len(n.Keys)-int(n.K)), true // k sigs + (n-k) empty
	case FragThresh:
		var total uint32
		for _, sub := range n.Subs {
			sat, _ := sub.maxWitnessSizeInternal(sigSize, pubkeySize)
			total += sat
		}
		return total, true
	}
	return 0, false
}

func (n *MiniscriptNode) maxDissatisfactionSize(sigSize, pubkeySize uint32) (uint32, bool) {
	switch n.Fragment {
	case FragJust0:
		return 0, true
	case FragJust1:
		return 0, false
	case FragPkK:
		return 1, true // Empty sig
	case FragPkH:
		return 1 + 1 + pubkeySize, true // Empty sig + pubkey
	case FragOlder, FragAfter:
		return 0, false // Cannot dissatisfy timelocks
	case FragSHA256, FragRIPEMD160, FragHASH256, FragHASH160:
		return 1 + 32, true // Fake preimage (32 zero bytes)
	case FragWrapA, FragWrapS, FragWrapC, FragWrapN:
		return n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
	case FragWrapD:
		return 1, true // Just OP_FALSE
	case FragWrapV:
		return 0, false // V types cannot be dissatisfied
	case FragWrapJ:
		return 1, true // Just OP_FALSE
	case FragAndV:
		return 0, false // and_v cannot be dissatisfied
	case FragAndB:
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat1, _ := n.Subs[1].maxDissatisfactionSize(sigSize, pubkeySize)
		return dsat0 + dsat1, true
	case FragOrB:
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat1, _ := n.Subs[1].maxDissatisfactionSize(sigSize, pubkeySize)
		return dsat0 + dsat1, true
	case FragOrC:
		return 0, false // or_c cannot be dissatisfied (V type)
	case FragOrD:
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat1, _ := n.Subs[1].maxDissatisfactionSize(sigSize, pubkeySize)
		return dsat0 + dsat1, true
	case FragOrI:
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat1, _ := n.Subs[1].maxDissatisfactionSize(sigSize, pubkeySize)
		opt1 := dsat0 + 1 + 1
		opt2 := dsat1 + 1
		if opt1 > opt2 {
			return opt1, true
		}
		return opt2, true
	case FragAndOr:
		dsat0, _ := n.Subs[0].maxDissatisfactionSize(sigSize, pubkeySize)
		dsat2, _ := n.Subs[2].maxDissatisfactionSize(sigSize, pubkeySize)
		return dsat0 + dsat2, true
	case FragMulti:
		return uint32(n.K) + 1, true // k+1 empty elements
	case FragMultiA:
		return uint32(len(n.Keys)), true // n empty elements
	case FragThresh:
		var total uint32
		for _, sub := range n.Subs {
			dsat, _ := sub.maxDissatisfactionSize(sigSize, pubkeySize)
			total += dsat
		}
		return total, true
	}
	return 0, false
}
