package script

// coreErrorStrings is Core's ScriptErrorString (script/script_error.cpp), the
// text Core puts inside "mempool-script-verify-flag-failed (<text>)" and
// "block-script-verify-flag-failed (<text>)" reject reasons.
var coreErrorStrings = [numErrorCodes]string{
	ErrCodeOK:                                 "No error",
	ErrCodeUnknownError:                       "unknown error",
	ErrCodeEvalFalse:                          "Script evaluated without error but finished with a false/empty top stack element",
	ErrCodeOpReturn:                           "OP_RETURN was encountered",
	ErrCodeScriptNum:                          "Script number overflowed or is non-minimally encoded",
	ErrCodeScriptSize:                         "Script is too big",
	ErrCodePushSize:                           "Push value size limit exceeded",
	ErrCodeOpCount:                            "Operation limit exceeded",
	ErrCodeStackSize:                          "Stack size limit exceeded",
	ErrCodeSigCount:                           "Signature count negative or greater than pubkey count",
	ErrCodePubKeyCount:                        "Pubkey count negative or limit exceeded",
	ErrCodeVerify:                             "Script failed an OP_VERIFY operation",
	ErrCodeEqualVerify:                        "Script failed an OP_EQUALVERIFY operation",
	ErrCodeCheckMultiSigVerify:                "Script failed an OP_CHECKMULTISIGVERIFY operation",
	ErrCodeCheckSigVerify:                     "Script failed an OP_CHECKSIGVERIFY operation",
	ErrCodeNumEqualVerify:                     "Script failed an OP_NUMEQUALVERIFY operation",
	ErrCodeBadOpcode:                          "Opcode missing or not understood",
	ErrCodeDisabledOpcode:                     "Attempted to use a disabled opcode",
	ErrCodeInvalidStackOperation:              "Operation not valid with the current stack size",
	ErrCodeInvalidAltstackOperation:           "Operation not valid with the current altstack size",
	ErrCodeUnbalancedConditional:              "Invalid OP_IF construction",
	ErrCodeNegativeLocktime:                   "Negative locktime",
	ErrCodeUnsatisfiedLocktime:                "Locktime requirement not satisfied",
	ErrCodeSigHashType:                        "Signature hash type missing or not understood",
	ErrCodeSigDER:                             "Non-canonical DER signature",
	ErrCodeMinimalData:                        "Data push larger than necessary",
	ErrCodeSigPushOnly:                        "Only push operators allowed in signatures",
	ErrCodeSigHighS:                           "Non-canonical signature: S value is unnecessarily high",
	ErrCodeSigNullDummy:                       "Dummy CHECKMULTISIG argument must be zero",
	ErrCodePubKeyType:                         "Public key is neither compressed or uncompressed",
	ErrCodeCleanStack:                         "Stack size must be exactly one after execution",
	ErrCodeMinimalIf:                          "OP_IF/NOTIF argument must be minimal",
	ErrCodeSigNullFail:                        "Signature must be zero for failed CHECK(MULTI)SIG operation",
	ErrCodeDiscourageUpgradableNops:           "NOPx reserved for soft-fork upgrades",
	ErrCodeDiscourageUpgradableWitnessProgram: "Witness version reserved for soft-fork upgrades",
	ErrCodeDiscourageUpgradableTaprootVersion: "Taproot version reserved for soft-fork upgrades",
	ErrCodeDiscourageOpSuccess:                "OP_SUCCESSx reserved for soft-fork upgrades",
	ErrCodeDiscourageUpgradablePubKeyType:     "Public key version reserved for soft-fork upgrades",
	ErrCodeWitnessProgramWrongLength:          "Witness program has incorrect length",
	ErrCodeWitnessProgramWitnessEmpty:         "Witness program was passed an empty witness",
	ErrCodeWitnessProgramMismatch:             "Witness program hash mismatch",
	ErrCodeWitnessMalleated:                   "Witness requires empty scriptSig",
	ErrCodeWitnessMalleatedP2SH:               "Witness requires only-redeemscript scriptSig",
	ErrCodeWitnessUnexpected:                  "Witness provided for non-witness script",
	ErrCodeWitnessPubKeyType:                  "Using non-compressed keys in segwit",
	ErrCodeSchnorrSigSize:                     "Invalid Schnorr signature size",
	ErrCodeSchnorrSigHashType:                 "Invalid Schnorr signature hash type",
	ErrCodeSchnorrSig:                         "Invalid Schnorr signature",
	ErrCodeTaprootWrongControlSize:            "Invalid Taproot control block size",
	ErrCodeTapscriptValidationWeight:          "Too much signature validation relative to witness weight",
	ErrCodeTapscriptCheckMultiSig:             "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
	ErrCodeTapscriptMinimalIf:                 "OP_IF/NOTIF argument must be minimal in tapscript",
	ErrCodeTapscriptEmptyPubKey:               "Empty public key in tapscript",
	ErrCodeOpCodeSeparator:                    "Using OP_CODESEPARATOR in non-witness script",
	ErrCodeSigFindAndDelete:                   "Signature is found in scriptCode",
}

// CoreErrorString returns Core's ScriptErrorString text for code. Codes Core
// has no text for (ErrCodeInternal, out of range) read "unknown error", as
// Core's own fallthrough does.
func CoreErrorString(code ErrorCode) string {
	if code >= 0 && code < numErrorCodes && coreErrorStrings[code] != "" {
		return coreErrorStrings[code]
	}
	return "unknown error"
}
