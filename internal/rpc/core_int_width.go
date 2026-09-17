package rpc

// Core's UniValue::getInt<T>() at the RPC argument boundary.
//
// getInt runs std::from_chars INTO THE DESTINATION WIDTH
// (bitcoin-core/src/univalue/include/univalue.h), so the width check lives
// inside the CONVERSION and fires BEFORE the handler's own domain test:
//
//	out of width / fractional -> RPC_MISC_ERROR (-1) "JSON integer out of range"
//	converts, violates range  -> that handler's own error (-8, -5, ...)
//
// Go makes getting this wrong easy and silent. `int32(f)` for a float64
// outside int32's range is IMPLEMENTATION-DEFINED (spec: "the behavior is
// undefined" for a value not representable in the destination), so
// `getblockhash 4294967296` did not merely answer the wrong code -- it ran
// the height domain test against whatever the truncation produced.
//
// Encoding/json hands numbers back as float64, so the fractional check is
// also load-bearing: Core rejects 1.5 here, it does not truncate it.
func coreGetInt32(v float64) (int32, *RPCError) {
	if v != float64(int64(v)) || v < -2147483648 || v > 2147483647 {
		return 0, &RPCError{Code: RPCErrMiscError, Message: "JSON integer out of range"}
	}
	return int32(v), nil
}

// coreGetIntArg is coreGetInt32 for a handler that wants a plain int.
func coreGetIntArg(v float64) (int, *RPCError) {
	n, rpcErr := coreGetInt32(v)
	if rpcErr != nil {
		return 0, rpcErr
	}
	return int(n), nil
}

// parseRPCInt32 reads a JSON-RPC numeric argument the way Core's
// UniValue::getInt<int> does: a non-number is RPC_TYPE_ERROR (-3)
// "JSON value of type X is not of expected type number"; a number that
// is fractional or outside int32 is RPC_MISC_ERROR (-1) "JSON integer
// out of range". json.Unmarshal into interface{} yields float64 for
// every JSON number.
func parseRPCInt32(v interface{}) (int32, *RPCError) {
	f, ok := v.(float64)
	if !ok {
		return 0, &RPCError{
			Code:    RPCErrTypeError,
			Message: "JSON value of type " + jsonTypeName(v) + " is not of expected type number",
		}
	}
	return coreGetInt32(f)
}
