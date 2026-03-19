// Package script implements the Bitcoin Script interpreter.
// This file implements the Miniscript parser.
package script

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseMiniscript parses a miniscript string into an AST.
func ParseMiniscript(s string, ctx MiniscriptContext) (*MiniscriptNode, error) {
	p := &miniscriptParser{
		input: s,
		pos:   0,
		ctx:   ctx,
	}
	node, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.input) {
		return nil, fmt.Errorf("%w: unexpected character at position %d", ErrMiniscriptParse, p.pos)
	}

	// Validate types
	if !node.IsValid() {
		return nil, ErrMiniscriptType
	}

	return node, nil
}

// miniscriptParser is a recursive descent parser for miniscript.
type miniscriptParser struct {
	input string
	pos   int
	ctx   MiniscriptContext
}

// peek returns the current character without advancing.
func (p *miniscriptParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

// advance moves to the next character.
func (p *miniscriptParser) advance() {
	if p.pos < len(p.input) {
		p.pos++
	}
}

// expect consumes the expected character or returns an error.
func (p *miniscriptParser) expect(c byte) error {
	if p.peek() != c {
		return fmt.Errorf("%w: expected '%c' at position %d, got '%c'", ErrMiniscriptParse, c, p.pos, p.peek())
	}
	p.advance()
	return nil
}

// skipWhitespace skips any whitespace characters.
func (p *miniscriptParser) skipWhitespace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t' || p.input[p.pos] == '\n') {
		p.pos++
	}
}

// parseExpr parses a miniscript expression.
func (p *miniscriptParser) parseExpr() (*MiniscriptNode, error) {
	p.skipWhitespace()

	// Check for wrapper prefixes
	if p.pos < len(p.input) {
		switch p.peek() {
		case 'a':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapA, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 's':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapS, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'c':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapC, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'd':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapD, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'v':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapV, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'j':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapJ, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'n':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{Fragment: FragWrapN, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}, nil
			}
		case 'l':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				// l:X is sugar for or_i(0,X)
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{
					Fragment: FragOrI,
					Subs:     []*MiniscriptNode{{Fragment: FragJust0, Ctx: p.ctx}, sub},
					Ctx:      p.ctx,
				}, nil
			}
		case 'u':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				// u:X is sugar for or_i(X,0)
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{
					Fragment: FragOrI,
					Subs:     []*MiniscriptNode{sub, {Fragment: FragJust0, Ctx: p.ctx}},
					Ctx:      p.ctx,
				}, nil
			}
		case 't':
			if p.pos+1 < len(p.input) && p.input[p.pos+1] == ':' {
				// t:X is sugar for and_v(X,1)
				p.pos += 2
				sub, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &MiniscriptNode{
					Fragment: FragAndV,
					Subs:     []*MiniscriptNode{sub, {Fragment: FragJust1, Ctx: p.ctx}},
					Ctx:      p.ctx,
				}, nil
			}
		case '0':
			p.advance()
			return &MiniscriptNode{Fragment: FragJust0, Ctx: p.ctx}, nil
		case '1':
			p.advance()
			return &MiniscriptNode{Fragment: FragJust1, Ctx: p.ctx}, nil
		}
	}

	// Parse function name
	name := p.parseIdent()
	if name == "" {
		return nil, fmt.Errorf("%w: expected identifier at position %d", ErrMiniscriptParse, p.pos)
	}

	return p.parseFunction(name)
}

// parseIdent parses an identifier.
func (p *miniscriptParser) parseIdent() string {
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (p.pos > start && c >= '0' && c <= '9') {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

// parseFunction parses a function call.
func (p *miniscriptParser) parseFunction(name string) (*MiniscriptNode, error) {
	// Handle special case: just 0 or 1 without parens
	if name == "0" {
		return &MiniscriptNode{Fragment: FragJust0, Ctx: p.ctx}, nil
	}
	if name == "1" {
		return &MiniscriptNode{Fragment: FragJust1, Ctx: p.ctx}, nil
	}

	if err := p.expect('('); err != nil {
		return nil, err
	}

	var node *MiniscriptNode
	var err error

	switch name {
	case "pk":
		// pk(KEY) is sugar for c:pk_k(KEY)
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		inner := &MiniscriptNode{Fragment: FragPkK, Keys: [][]byte{key}, Ctx: p.ctx}
		return &MiniscriptNode{Fragment: FragWrapC, Subs: []*MiniscriptNode{inner}, Ctx: p.ctx}, nil

	case "pkh":
		// pkh(KEY) is sugar for c:pk_h(KEY)
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		inner := &MiniscriptNode{Fragment: FragPkH, Keys: [][]byte{key}, Ctx: p.ctx}
		return &MiniscriptNode{Fragment: FragWrapC, Subs: []*MiniscriptNode{inner}, Ctx: p.ctx}, nil

	case "pk_k":
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragPkK, Keys: [][]byte{key}, Ctx: p.ctx}

	case "pk_h":
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragPkH, Keys: [][]byte{key}, Ctx: p.ctx}

	case "older":
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		if k < 1 || k >= 0x80000000 {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragOlder, K: uint32(k), Ctx: p.ctx}

	case "after":
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		if k < 1 || k >= 0x80000000 {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragAfter, K: uint32(k), Ctx: p.ctx}

	case "sha256":
		hash, err := p.parseHash(32)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragSHA256, Data: hash, Ctx: p.ctx}

	case "hash256":
		hash, err := p.parseHash(32)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragHASH256, Data: hash, Ctx: p.ctx}

	case "ripemd160":
		hash, err := p.parseHash(20)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragRIPEMD160, Data: hash, Ctx: p.ctx}

	case "hash160":
		hash, err := p.parseHash(20)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragHASH160, Data: hash, Ctx: p.ctx}

	case "and_v":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragAndV, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "and_b":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragAndB, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "and_n":
		// and_n(X,Y) is sugar for andor(X,Y,0)
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{
			Fragment: FragAndOr,
			Subs:     []*MiniscriptNode{sub0, sub1, {Fragment: FragJust0, Ctx: p.ctx}},
			Ctx:      p.ctx,
		}

	case "or_b":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragOrB, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "or_c":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragOrC, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "or_d":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragOrD, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "or_i":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragOrI, Subs: []*MiniscriptNode{sub0, sub1}, Ctx: p.ctx}

	case "andor":
		sub0, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub2, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragAndOr, Subs: []*MiniscriptNode{sub0, sub1, sub2}, Ctx: p.ctx}

	case "thresh":
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		var subs []*MiniscriptNode
		for p.peek() == ',' {
			p.advance()
			sub, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			subs = append(subs, sub)
		}
		if k < 1 || k > uint64(len(subs)) {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragThresh, K: uint32(k), Subs: subs, Ctx: p.ctx}

	case "multi":
		if p.ctx == Tapscript {
			return nil, errors.New("multi not allowed in tapscript context")
		}
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		var keys [][]byte
		for p.peek() == ',' {
			p.advance()
			key, err := p.parseKey()
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
		if k < 1 || k > uint64(len(keys)) || len(keys) > 20 {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragMulti, K: uint32(k), Keys: keys, Ctx: p.ctx}

	case "multi_a":
		if p.ctx != Tapscript {
			return nil, errors.New("multi_a only allowed in tapscript context")
		}
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		var keys [][]byte
		for p.peek() == ',' {
			p.advance()
			key, err := p.parseKey()
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
		if k < 1 || k > uint64(len(keys)) {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragMultiA, K: uint32(k), Keys: keys, Ctx: p.ctx}

	default:
		return nil, fmt.Errorf("%w: unknown function '%s'", ErrMiniscriptParse, name)
	}

	if err != nil {
		return nil, err
	}
	if err := p.expect(')'); err != nil {
		return nil, err
	}

	return node, nil
}

// parseKey parses a public key (hex encoded).
func (p *miniscriptParser) parseKey() ([]byte, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			p.pos++
		} else {
			break
		}
	}
	hexStr := p.input[start:p.pos]
	if len(hexStr) == 0 {
		return nil, fmt.Errorf("%w: expected hex key at position %d", ErrMiniscriptParse, p.pos)
	}
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex key: %v", ErrMiniscriptParse, err)
	}
	// Validate key length
	if len(key) != 32 && len(key) != 33 && len(key) != 65 {
		return nil, fmt.Errorf("%w: invalid key length %d", ErrMiniscriptParse, len(key))
	}
	return key, nil
}

// parseNumber parses a decimal number.
func (p *miniscriptParser) parseNumber() (uint64, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c >= '0' && c <= '9' {
			p.pos++
		} else {
			break
		}
	}
	numStr := p.input[start:p.pos]
	if len(numStr) == 0 {
		return 0, fmt.Errorf("%w: expected number at position %d", ErrMiniscriptParse, p.pos)
	}
	n, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid number: %v", ErrMiniscriptParse, err)
	}
	return n, nil
}

// parseHash parses a hex hash of expected length.
func (p *miniscriptParser) parseHash(expectedLen int) ([]byte, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			p.pos++
		} else {
			break
		}
	}
	hexStr := p.input[start:p.pos]
	hash, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex hash: %v", ErrMiniscriptParse, err)
	}
	if len(hash) != expectedLen {
		return nil, fmt.Errorf("%w: expected %d byte hash, got %d", ErrMiniscriptInvalidHash, expectedLen, len(hash))
	}
	return hash, nil
}

// CompilePolicy compiles a spending policy into miniscript.
// Policy language: and(A,B), or(A,B), thresh(k,A,B,C), pk(KEY), after(n), older(n), sha256(H)
func CompilePolicy(policy string, ctx MiniscriptContext) (*MiniscriptNode, error) {
	p := &policyParser{
		input: policy,
		pos:   0,
		ctx:   ctx,
	}
	node, err := p.parsePolicy()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.input) {
		return nil, fmt.Errorf("%w: unexpected character at position %d", ErrMiniscriptParse, p.pos)
	}
	return node, nil
}

// policyParser parses spending policies.
type policyParser struct {
	input string
	pos   int
	ctx   MiniscriptContext
}

func (p *policyParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *policyParser) advance() {
	if p.pos < len(p.input) {
		p.pos++
	}
}

func (p *policyParser) expect(c byte) error {
	if p.peek() != c {
		return fmt.Errorf("%w: expected '%c' at position %d", ErrMiniscriptParse, c, p.pos)
	}
	p.advance()
	return nil
}

func (p *policyParser) skipWhitespace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t' || p.input[p.pos] == '\n') {
		p.pos++
	}
}

func (p *policyParser) parseIdent() string {
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (p.pos > start && c >= '0' && c <= '9') {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *policyParser) parseNumber() (uint64, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}
	if start == p.pos {
		return 0, fmt.Errorf("%w: expected number", ErrMiniscriptParse)
	}
	return strconv.ParseUint(p.input[start:p.pos], 10, 64)
}

func (p *policyParser) parseKey() ([]byte, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			p.pos++
		} else {
			break
		}
	}
	hexStr := p.input[start:p.pos]
	return hex.DecodeString(hexStr)
}

func (p *policyParser) parseHash(size int) ([]byte, error) {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			p.pos++
		} else {
			break
		}
	}
	hexStr := p.input[start:p.pos]
	hash, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(hash) != size {
		return nil, ErrMiniscriptInvalidHash
	}
	return hash, nil
}

func (p *policyParser) parsePolicy() (*MiniscriptNode, error) {
	p.skipWhitespace()

	name := p.parseIdent()
	if name == "" {
		return nil, fmt.Errorf("%w: expected policy function", ErrMiniscriptParse)
	}

	if err := p.expect('('); err != nil {
		return nil, err
	}

	var node *MiniscriptNode

	switch name {
	case "pk":
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		// pk(K) compiles to c:pk_k(K)
		inner := &MiniscriptNode{Fragment: FragPkK, Keys: [][]byte{key}, Ctx: p.ctx}
		node = &MiniscriptNode{Fragment: FragWrapC, Subs: []*MiniscriptNode{inner}, Ctx: p.ctx}

	case "pkh":
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		// pkh(K) compiles to c:pk_h(K)
		inner := &MiniscriptNode{Fragment: FragPkH, Keys: [][]byte{key}, Ctx: p.ctx}
		node = &MiniscriptNode{Fragment: FragWrapC, Subs: []*MiniscriptNode{inner}, Ctx: p.ctx}

	case "after":
		n, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragAfter, K: uint32(n), Ctx: p.ctx}

	case "older":
		n, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragOlder, K: uint32(n), Ctx: p.ctx}

	case "sha256":
		hash, err := p.parseHash(32)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragSHA256, Data: hash, Ctx: p.ctx}

	case "hash256":
		hash, err := p.parseHash(32)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragHASH256, Data: hash, Ctx: p.ctx}

	case "ripemd160":
		hash, err := p.parseHash(20)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragRIPEMD160, Data: hash, Ctx: p.ctx}

	case "hash160":
		hash, err := p.parseHash(20)
		if err != nil {
			return nil, err
		}
		node = &MiniscriptNode{Fragment: FragHASH160, Data: hash, Ctx: p.ctx}

	case "and":
		// and(A,B) compiles to and_v(A,B) or and_b(A,B) depending on types
		sub0, err := p.parsePolicy()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parsePolicy()
		if err != nil {
			return nil, err
		}
		// Choose compilation based on types
		// Simple strategy: use and_b with wrapped subs
		// and_b(X,Y) requires B for X and W for Y
		// Wrap second sub with s: to make it W
		wrappedSub1 := &MiniscriptNode{Fragment: FragWrapS, Subs: []*MiniscriptNode{sub1}, Ctx: p.ctx}
		node = &MiniscriptNode{Fragment: FragAndB, Subs: []*MiniscriptNode{sub0, wrappedSub1}, Ctx: p.ctx}

	case "or":
		// or(A,B) compiles to or_d(A,B) or or_b(A,B)
		sub0, err := p.parsePolicy()
		if err != nil {
			return nil, err
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		sub1, err := p.parsePolicy()
		if err != nil {
			return nil, err
		}
		// Use or_d for simplicity (works when X is Bdu and Y is B)
		// May need to wrap subs
		wrappedSub1 := &MiniscriptNode{Fragment: FragWrapS, Subs: []*MiniscriptNode{sub1}, Ctx: p.ctx}
		node = &MiniscriptNode{Fragment: FragOrB, Subs: []*MiniscriptNode{sub0, wrappedSub1}, Ctx: p.ctx}

	case "thresh":
		k, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		var subs []*MiniscriptNode
		for p.peek() == ',' {
			p.advance()
			sub, err := p.parsePolicy()
			if err != nil {
				return nil, err
			}
			// First sub needs to be B, rest need to be W
			if len(subs) > 0 {
				sub = &MiniscriptNode{Fragment: FragWrapS, Subs: []*MiniscriptNode{sub}, Ctx: p.ctx}
			}
			subs = append(subs, sub)
		}
		if k < 1 || k > uint64(len(subs)) {
			return nil, ErrMiniscriptInvalidK
		}
		node = &MiniscriptNode{Fragment: FragThresh, K: uint32(k), Subs: subs, Ctx: p.ctx}

	default:
		return nil, fmt.Errorf("%w: unknown policy '%s'", ErrMiniscriptParse, name)
	}

	if err := p.expect(')'); err != nil {
		return nil, err
	}

	return node, nil
}

// MiniscriptFromScript attempts to parse a Bitcoin Script back into miniscript.
// This is a reverse operation and may not always succeed.
func MiniscriptFromScript(script []byte, ctx MiniscriptContext) (*MiniscriptNode, error) {
	// This is a complex operation - decompose the script into opcodes and
	// attempt to match known miniscript patterns.
	// For now, return an error indicating this is not implemented.
	return nil, errors.New("miniscript decompilation not yet implemented")
}

// ValidateMiniscript performs comprehensive validation of a miniscript.
func ValidateMiniscript(ms string, ctx MiniscriptContext) error {
	node, err := ParseMiniscript(ms, ctx)
	if err != nil {
		return err
	}

	// Check type validity
	if !node.IsValidTopLevel() {
		return errors.New("invalid top-level type")
	}

	// Check script size limits
	size := node.ScriptSize()
	if ctx == P2WSH && size > MaxScriptSize {
		return ErrMiniscriptTooLarge
	}

	// Check ops limit
	if !node.CheckOpsLimit() {
		return errors.New("exceeds ops limit")
	}

	// Check stack size
	if !node.CheckStackSize() {
		return errors.New("exceeds stack size limit")
	}

	return nil
}

// AnalyzeMiniscript returns analysis information about a miniscript.
type MiniscriptAnalysis struct {
	ScriptSize      int
	MaxWitnessSize  uint32
	RequiresSig     bool
	HasTimeLock     bool
	AbsoluteTime    bool  // Has CLTV with time
	AbsoluteHeight  bool  // Has CLTV with height
	RelativeTime    bool  // Has CSV with time
	RelativeHeight  bool  // Has CSV with height
	IsSane          bool
	IsNonMalleable  bool
}

// Analyze returns analysis information about this miniscript.
func (n *MiniscriptNode) Analyze() *MiniscriptAnalysis {
	t := n.GetType()
	maxWit, _ := n.MaxWitnessSize()

	return &MiniscriptAnalysis{
		ScriptSize:      n.ScriptSize(),
		MaxWitnessSize:  maxWit,
		RequiresSig:     t.HasType(TypeS),
		HasTimeLock:     t.HasAnyType(TypeG | TypeH | TypeI | TypeJ),
		AbsoluteTime:    t.HasType(TypeI),
		AbsoluteHeight:  t.HasType(TypeJ),
		RelativeTime:    t.HasType(TypeG),
		RelativeHeight:  t.HasType(TypeH),
		IsSane:          n.IsSane(),
		IsNonMalleable:  t.HasType(TypeM),
	}
}

// FormatMiniscript formats a miniscript with optional syntax highlighting.
func FormatMiniscript(ms string, indent int) string {
	// Simple formatter that adds newlines and indentation for readability
	var sb strings.Builder
	level := 0
	indentStr := strings.Repeat("  ", indent)

	for i := 0; i < len(ms); i++ {
		c := ms[i]
		switch c {
		case '(':
			sb.WriteByte(c)
			level++
			if level <= 2 {
				sb.WriteByte('\n')
				sb.WriteString(strings.Repeat(indentStr, level))
			}
		case ')':
			level--
			if level < 2 {
				sb.WriteByte('\n')
				sb.WriteString(strings.Repeat(indentStr, level))
			}
			sb.WriteByte(c)
		case ',':
			sb.WriteByte(c)
			if level <= 2 {
				sb.WriteByte('\n')
				sb.WriteString(strings.Repeat(indentStr, level))
			}
		default:
			sb.WriteByte(c)
		}
	}

	return sb.String()
}
