package rpc

import (
	"bytes"
	"encoding/json"
)

// omap is an insertion-ordered JSON object. Go's encoding/json marshals
// map[string]T with keys sorted alphabetically, which diverges from Bitcoin
// Core's UniValue (a VOBJ preserves pushKV insertion order). For RPC results
// that must be BYTE-IDENTICAL to Core v31.99 — where field-emission order is
// part of the contract the byte-diff harness checks — we build the object as
// an omap and emit it in the exact pushKV order Core uses.
//
// Use Set to append a key in Core's pushKV order. MarshalJSON then emits the
// pairs in that order. Set overwrites an existing key's value IN PLACE (so the
// position is preserved) — this mirrors UniValue::pushKV's "replace if present,
// else append" only for the in-place case; new keys always append. Callers
// that need Core's exact order simply Set in that order.
type omap struct {
	keys   []string
	values map[string]any
}

// newOMap returns an empty ordered object.
func newOMap() *omap {
	return &omap{values: make(map[string]any)}
}

// Set appends key→val in insertion order, or updates an existing key in place.
func (o *omap) Set(key string, val any) *omap {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = val
	return o
}

// Delete removes a key (and its value) from the object, preserving the order
// of the remaining keys. No-op if the key is absent.
func (o *omap) Delete(key string) *omap {
	if _, ok := o.values[key]; !ok {
		return o
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
	return o
}

// Has reports whether the key is present.
func (o *omap) Has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// Get returns the value stored for key (nil, false if absent).
func (o *omap) Get(key string) (any, bool) {
	v, ok := o.values[key]
	return v, ok
}

// MarshalJSON emits the object with keys in insertion order, matching Core's
// UniValue VOBJ serialization. Encoding of each value uses the standard library
// (so nested omaps, structs, slices, and BitcoinDifficulty/btcAmount all render
// exactly as elsewhere).
func (o *omap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(o.values[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
