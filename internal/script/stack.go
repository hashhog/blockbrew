package script

import (
	"errors"
)

// Stack errors
var (
	ErrStackUnderflow   = errors.New("stack underflow")
	ErrStackOverflow    = errors.New("stack overflow")
	ErrInvalidStackOp   = errors.New("invalid stack operation")
	ErrScriptNumOverflow = errors.New("script number overflow")
)

// Stack represents the Bitcoin Script execution stack.
type Stack struct {
	items [][]byte
}

// NewStack creates a new empty stack.
func NewStack() *Stack {
	return &Stack{
		items: make([][]byte, 0),
	}
}

// Push adds an item to the top of the stack.
func (s *Stack) Push(item []byte) {
	// Make a copy to avoid external modification
	cp := make([]byte, len(item))
	copy(cp, item)
	s.items = append(s.items, cp)
}

// Pop removes and returns the top item from the stack.
func (s *Stack) Pop() ([]byte, error) {
	if len(s.items) == 0 {
		return nil, ErrStackUnderflow
	}
	item := s.items[len(s.items)-1]
	s.items = s.items[:len(s.items)-1]
	return item, nil
}

// Peek returns the top item without removing it.
func (s *Stack) Peek() ([]byte, error) {
	if len(s.items) == 0 {
		return nil, ErrStackUnderflow
	}
	return s.items[len(s.items)-1], nil
}

// PeekAt returns the item at index i from the top (0 = top).
func (s *Stack) PeekAt(i int) ([]byte, error) {
	if i < 0 || i >= len(s.items) {
		return nil, ErrStackUnderflow
	}
	return s.items[len(s.items)-1-i], nil
}

// Size returns the number of items on the stack.
func (s *Stack) Size() int {
	return len(s.items)
}

// IsEmpty returns true if the stack is empty.
func (s *Stack) IsEmpty() bool {
	return len(s.items) == 0
}

// PopInt pops the top item and decodes it as a script number.
// maxLen is the maximum byte length allowed (typically 4 for most operations).
func (s *Stack) PopInt(maxLen int) (int64, error) {
	item, err := s.Pop()
	if err != nil {
		return 0, err
	}
	return ScriptNumDeserialize(item, maxLen)
}

// PushInt encodes an integer as a script number and pushes it.
func (s *Stack) PushInt(n int64) {
	s.Push(ScriptNumSerialize(n))
}

// PopBool pops the top item and interprets it as a boolean.
func (s *Stack) PopBool() (bool, error) {
	item, err := s.Pop()
	if err != nil {
		return false, err
	}
	return CastToBool(item), nil
}

// PushBool pushes a boolean value onto the stack.
func (s *Stack) PushBool(b bool) {
	if b {
		s.Push([]byte{1})
	} else {
		s.Push([]byte{})
	}
}

// SwapTop swaps the top two items on the stack.
func (s *Stack) SwapTop() error {
	if len(s.items) < 2 {
		return ErrStackUnderflow
	}
	n := len(s.items)
	s.items[n-1], s.items[n-2] = s.items[n-2], s.items[n-1]
	return nil
}

// RemoveAt removes and returns the item at index i from the top (0 = top).
func (s *Stack) RemoveAt(i int) ([]byte, error) {
	if i < 0 || i >= len(s.items) {
		return nil, ErrStackUnderflow
	}
	idx := len(s.items) - 1 - i
	item := s.items[idx]
	s.items = append(s.items[:idx], s.items[idx+1:]...)
	return item, nil
}

// Copy returns a copy of the stack.
func (s *Stack) Copy() *Stack {
	cp := &Stack{
		items: make([][]byte, len(s.items)),
	}
	for i, item := range s.items {
		cp.items[i] = make([]byte, len(item))
		copy(cp.items[i], item)
	}
	return cp
}

// Items returns all stack items (bottom to top).
func (s *Stack) Items() [][]byte {
	return s.items
}

// SetItems replaces all stack items.
func (s *Stack) SetItems(items [][]byte) {
	s.items = make([][]byte, len(items))
	for i, item := range items {
		s.items[i] = make([]byte, len(item))
		copy(s.items[i], item)
	}
}

// ScriptNumSerialize serializes an int64 to Bitcoin's script number format.
// Script numbers are little-endian with a sign bit in the MSB of the last byte.
// Zero is represented as an empty byte slice.
func ScriptNumSerialize(n int64) []byte {
	if n == 0 {
		return []byte{}
	}

	negative := n < 0
	if negative {
		n = -n
	}

	// Serialize to little-endian bytes
	var result []byte
	for n > 0 {
		result = append(result, byte(n&0xff))
		n >>= 8
	}

	// If the MSB has the sign bit set, we need an extra byte
	if result[len(result)-1]&0x80 != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative {
		result[len(result)-1] |= 0x80
	}

	return result
}

// ScriptNumDeserialize deserializes a script number from bytes to int64.
// maxLen limits the maximum byte length (typically 4 bytes).
func ScriptNumDeserialize(b []byte, maxLen int) (int64, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if len(b) > maxLen {
		return 0, ErrScriptNumOverflow
	}

	// Check for minimal encoding (no unnecessary leading zero bytes)
	// Unless the byte before it has its high bit set
	if len(b) > 1 {
		if b[len(b)-1] == 0x00 && b[len(b)-2]&0x80 == 0 {
			return 0, ErrScriptNumOverflow
		}
		if b[len(b)-1] == 0x80 && b[len(b)-2]&0x80 == 0 {
			return 0, ErrScriptNumOverflow
		}
	}

	// Read little-endian value
	var result int64
	for i := len(b) - 1; i >= 0; i-- {
		result <<= 8
		result |= int64(b[i])
	}

	// Handle sign bit
	if b[len(b)-1]&0x80 != 0 {
		// Clear the sign bit and negate
		mask := int64(0x80) << (8 * (len(b) - 1))
		result = -(result & ^mask)
	}

	return result, nil
}

// CastToBool interprets a byte slice as a boolean per Bitcoin rules.
// Empty slice is false, all zeros (except 0x80 "negative zero") are false.
func CastToBool(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			// Negative zero is still false
			if i == len(b)-1 && b[i] == 0x80 {
				return false
			}
			return true
		}
	}
	return false
}
