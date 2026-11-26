package script

// conditionStack is the IF/NOTIF/ELSE/ENDIF branch state, kept the way
// Bitcoin Core's ConditionStack keeps it (src/script/interpreter.cpp:273-318).
//
// Only two facts about the implied stack of branch values are observable:
// its size (for ENDIF/ELSE balance) and whether it holds any false value
// (whether the current opcode executes). Entries above the first false one
// can never be observed, because they are popped before it. So the stack is
// stored as its size plus the position of its first false entry, and every
// operation is O(1). A []bool scanned before every opcode made a tapscript
// leaf with d nested IFs cost O(d^2); tapscript has no opcode or nesting
// limit, so that was seconds per standard-size transaction.
type conditionStack struct {
	size int // number of entries in the implied stack
	// falseAt is 1 + the index of the first false entry, or 0 when every
	// entry is true. The 1-based encoding makes the zero value an empty,
	// all-true stack, so an Engine literal needs no initialisation.
	falseAt int
}

func (c *conditionStack) reset() { *c = conditionStack{} }

func (c *conditionStack) empty() bool { return c.size == 0 }

// allTrue reports whether no entry is false, i.e. the current opcode executes.
func (c *conditionStack) allTrue() bool { return c.falseAt == 0 }

func (c *conditionStack) push(v bool) {
	if !v && c.falseAt == 0 {
		c.falseAt = c.size + 1
	}
	c.size++
}

// pop removes the top entry. The caller checks empty() first.
func (c *conditionStack) pop() {
	if c.falseAt == c.size {
		// Popping the first false entry leaves only true ones.
		c.falseAt = 0
	}
	c.size--
}

// toggleTop flips the top entry (OP_ELSE). The caller checks empty() first.
// Flipping matters only when no false entry sits below the top; otherwise
// the top is unobservable and nothing changes, the same rule as the old
// "flip only if the parent is executing" guard.
func (c *conditionStack) toggleTop() {
	switch c.falseAt {
	case 0:
		c.falseAt = c.size // the top becomes the first false entry
	case c.size:
		c.falseAt = 0 // the top was the first false entry
	}
}
