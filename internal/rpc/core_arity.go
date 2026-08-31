package rpc

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Dispatcher arity check — Core rpc/util.cpp:644 -> IsValidNumArgs (:733).
//
// Core validates argument COUNT centrally, before any handler runs:
//
//	if (GET_HELP || !IsValidNumArgs(request.params.size())) throw HelpResult{...}
//	IsValidNumArgs = num_required <= n && n <= num_declared
//
// and the violation surfaces as error -1 carrying the method's help text.
//
// No implementation in this fleet had that check: handlers decline to police
// argument count on the grounds that the dispatcher owns it, and no dispatcher
// owned it. The operator probe found savemempool accepting a surplus argument
// in 10 of 10 implementations and clearbanned in 9 of 10 (2026-08-31).
//
// The table is DERIVED FROM CORE by tools/core-arity.py, which reads
// `help <method>` (whose signature line parenthesises optional arguments),
// rather than hand-written once per implementation. It was validated by calling
// Core with declared+1 arguments on nine read-only methods: all nine returned
// -1, as the table predicts.
//
// COVERAGE: 87 of the 103 operator-subset methods. A method ABSENT from the
// table is NOT checked — deliberately. Treating an unknown method as zero-arg
// would reject calls Core accepts, a worse failure than the one being fixed.

//go:embed core-arity.json
var coreArityJSON []byte

type coreArityEntry struct {
	Required int    `json:"required"`
	Declared int    `json:"declared"`
	Sig      string `json:"sig"`
}

var coreArity = func() map[string]coreArityEntry {
	m := map[string]coreArityEntry{}
	if err := json.Unmarshal(coreArityJSON, &m); err != nil {
		// A corrupt embedded table must not silently disable the check.
		panic(fmt.Sprintf("core-arity.json failed to parse: %v", err))
	}
	return m
}()

// checkCoreArity rejects a call whose positional argument count Core would
// refuse. Returns nil when the call is acceptable, or the method is not in the
// table, or params are not a positional array.
func checkCoreArity(method string, params json.RawMessage) *RPCError {
	a, known := coreArity[method]
	if !known {
		return nil // fail OPEN — see COVERAGE above
	}
	if len(params) == 0 {
		if 0 < a.Required {
			return &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf(
				"%s takes %s argument(s), got 0", method, arityRange(a))}
		}
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil {
		return nil // named/object params: not this check's business
	}
	if len(arr) < a.Required || len(arr) > a.Declared {
		return &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf(
			"%s takes %s argument(s), got %d", method, arityRange(a), len(arr))}
	}
	return nil
}

func arityRange(a coreArityEntry) string {
	if a.Required == a.Declared {
		return fmt.Sprintf("%d", a.Declared)
	}
	return fmt.Sprintf("%d to %d", a.Required, a.Declared)
}
