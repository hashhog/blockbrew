package script

import "testing"

// Core's ScriptErrorString (script/script_error.cpp) text, which Core puts in
// "mempool-script-verify-flag-failed (<text>)" reject reasons.
func TestCoreErrorString(t *testing.T) {
	cases := map[ErrorCode]string{
		ErrCodeSigNullFail:       "Signature must be zero for failed CHECK(MULTI)SIG operation",
		ErrCodeEvalFalse:         "Script evaluated without error but finished with a false/empty top stack element",
		ErrCodeSigDER:            "Non-canonical DER signature",
		ErrCodeScriptNum:         "Script number overflowed or is non-minimally encoded",
		ErrCodeSigFindAndDelete:  "Signature is found in scriptCode",
		ErrCodeUnknownError:      "unknown error",
		ErrCodeWitnessPubKeyType: "Using non-compressed keys in segwit",
	}
	for code, want := range cases {
		if got := CoreErrorString(code); got != want {
			t.Errorf("CoreErrorString(%s) = %q, want %q", code, got, want)
		}
	}
	// Every Core code has its own text; only UNKNOWN_ERROR says "unknown error".
	for c := ErrCodeEvalFalse; c < ErrCodeInternal; c++ {
		if got := CoreErrorString(c); got == "" || got == "unknown error" {
			t.Errorf("CoreErrorString(%s) = %q, want Core's text", c, got)
		}
	}
}
