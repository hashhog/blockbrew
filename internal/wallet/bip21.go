// Package wallet — BIP-21 (bitcoin: URI) parser.
//
// BIP-21 spec: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
//
// Format: bitcoin:<address>?<query>
//
// Query parameters:
//   - amount=<decimal BTC>      — exact amount in BTC (canonical decimal)
//   - label=<percent-encoded>   — UTF-8 label
//   - message=<percent-encoded> — UTF-8 message
//   - lightning=<BOLT-11>       — extension (Lightning fallback)
//   - pj=<URL>                  — BIP-78 PayJoin endpoint
//   - pjos=0|1                  — BIP-78 output substitution (default 1)
//   - req-<X>=...               — MUST reject entire URI if unknown
//   - other unprefixed keys     — ignore (forward-compat) but capture in Extras
//
// Keys are case-insensitive per RFC 3986. Values are percent-decoded.

package wallet

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hashhog/blockbrew/internal/address"
)

// Bip21URI is the structured form of a parsed bitcoin: URI.
//
// Optional fields use pointers so the caller can distinguish "absent" from
// "present with zero value" (e.g. amount=0.0 is valid and not the same as no
// amount).
type Bip21URI struct {
	// Address is the decoded BIP-21 target address. Always populated on a
	// successful parse — the bare bitcoin:<address> form is valid.
	Address *address.Address

	// AddressString preserves the address exactly as it appeared in the URI
	// (case-preserved for base58, lowercased for bech32 by the caller's input).
	AddressString string

	// Amount is the exact payment amount in satoshis. Nil if absent.
	// Per BIP-21 the wire format is decimal BTC; we convert to satoshis using
	// a fixed-point parser (no float rounding).
	Amount *int64

	// Label, Message: percent-decoded UTF-8. Nil if absent.
	Label   *string
	Message *string

	// Lightning is the BOLT-11 invoice from a `lightning=` parameter.
	Lightning *string

	// PJ is the BIP-78 PayJoin endpoint URL.
	PJ *string

	// PJOS is the BIP-78 disableoutputsubstitution flag (`pjos=0` → false,
	// `pjos=1` → true). Per BIP-78 the default when `pj=` is present is
	// `pjos=0` (output substitution allowed); callers should treat nil as
	// "unspecified" and apply the default in context.
	PJOS *bool

	// Extras captures unrecognized unprefixed parameters for forward-compat
	// (per BIP-21, unknown non-`req-` keys MUST be ignored — we retain them
	// for diagnostics but consumers should not require them).
	Extras map[string]string
}

// Error sentinels — callers can errors.Is() against these.
//
// The package-level ErrInvalidAddress (defined in wallet.go) is the general
// wallet-side address-rejection error; here we use a BIP-21-scoped sentinel
// (ErrBip21InvalidAddress) so callers can distinguish "URI parsing failed
// because the address was wrong" from "wallet-side address validation rejected
// it during a send / signing path".
var (
	ErrWrongScheme          = errors.New("bip21: scheme is not bitcoin:")
	ErrBip21InvalidAddress  = errors.New("bip21: invalid address")
	ErrWrongNetwork         = errors.New("bip21: address belongs to wrong network")
	ErrInvalidAmount        = errors.New("bip21: invalid amount")
	ErrMalformedQuery       = errors.New("bip21: malformed query string")
	ErrUnknownRequiredParam = errors.New("bip21: unknown required parameter")
)

// unknownRequiredParamErr wraps ErrUnknownRequiredParam with the offending key
// so callers can surface it. Use errors.Is(err, ErrUnknownRequiredParam) to
// match, and errors.As() with *UnknownRequiredParamError to extract the key.
type UnknownRequiredParamError struct {
	Key string
}

func (e *UnknownRequiredParamError) Error() string {
	return fmt.Sprintf("bip21: unknown required parameter: %s", e.Key)
}

func (e *UnknownRequiredParamError) Is(target error) bool {
	return target == ErrUnknownRequiredParam
}

// satoshisPerBTC is the canonical 1 BTC = 10^8 satoshis.
const satoshisPerBTC = int64(100_000_000)

// maxMoneyBTC is 21 million BTC; BIP-21 amounts above this are invalid.
const maxMoneyBTC = int64(21_000_000)

// ParseBIP21 parses a BIP-21 bitcoin: URI string.
//
// `network` is the expected network for address-membership checking. Pass
// `address.Mainnet` (etc.). A successful parse guarantees:
//   - input.Scheme is "bitcoin" (case-insensitive)
//   - the address decodes and belongs to `network`
//   - no `req-` parameter is unknown
//
// Returns one of the sentinel errors above; for unknown required params the
// returned error is an *UnknownRequiredParamError that satisfies
// errors.Is(err, ErrUnknownRequiredParam).
func ParseBIP21(input string, network address.Network) (*Bip21URI, error) {
	// Scheme — BIP-21 fixes `bitcoin:`. RFC 3986 says schemes are
	// case-insensitive; the colon is mandatory. We do NOT accept the
	// `//` authority form; bitcoin: is opaque-style.
	const scheme = "bitcoin:"
	if len(input) < len(scheme) || !strings.EqualFold(input[:len(scheme)], scheme) {
		return nil, ErrWrongScheme
	}
	rest := input[len(scheme):]

	// Trim a single leading "//" if some over-eager UI inserted one.
	// Bitcoin Core's GUIUtil::parseBitcoinURI also tolerates this.
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
	}

	// Split address from query.
	var addrPart, queryPart string
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		addrPart = rest[:idx]
		queryPart = rest[idx+1:]
	} else {
		addrPart = rest
	}

	// Strip any fragment from the address part (BIP-21 doesn't define one,
	// but RFC 3986 reserves '#'; treat anything after as fragment, ignored).
	if idx := strings.IndexByte(addrPart, '#'); idx >= 0 {
		addrPart = addrPart[:idx]
	}

	if addrPart == "" {
		return nil, ErrBip21InvalidAddress
	}

	// Percent-decode the address part (some encoders escape characters that
	// don't need it). Bech32 / base58 alphabets are ASCII so this is safe.
	decodedAddrStr, err := percentDecode(addrPart)
	if err != nil {
		return nil, ErrBip21InvalidAddress
	}

	// Address parsing: try the requested network; address.DecodeAddress
	// reports ErrNetworkMismatch when the decoded prefix targets another
	// network, which we translate into ErrWrongNetwork.
	addr, addrErr := address.DecodeAddress(decodedAddrStr, network)
	if addrErr != nil {
		if errors.Is(addrErr, address.ErrNetworkMismatch) {
			return nil, ErrWrongNetwork
		}
		// To distinguish "valid address, wrong network" from "junk", we
		// retry parsing with each other network — if any of them accept
		// it we know it was a network mismatch the upstream missed.
		for _, alt := range []address.Network{address.Mainnet, address.Testnet, address.Regtest, address.Signet} {
			if alt == network {
				continue
			}
			if _, e := address.DecodeAddress(decodedAddrStr, alt); e == nil {
				return nil, ErrWrongNetwork
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrBip21InvalidAddress, addrErr)
	}

	out := &Bip21URI{
		Address:       addr,
		AddressString: decodedAddrStr,
		Extras:        map[string]string{},
	}

	if queryPart == "" {
		return out, nil
	}

	// Split &-separated key=value pairs.
	for _, kv := range strings.Split(queryPart, "&") {
		if kv == "" {
			// "&&" or trailing "&" — tolerate, skip.
			continue
		}
		eq := strings.IndexByte(kv, '=')
		var rawKey, rawVal string
		if eq < 0 {
			rawKey = kv
			rawVal = ""
		} else {
			rawKey = kv[:eq]
			rawVal = kv[eq+1:]
		}

		// Keys are case-insensitive (RFC 3986); BIP-21 examples are all
		// lower-case but we accept any case for parameter names. The
		// `req-` prefix and the `lightning` value, however, are matched
		// case-insensitively too — that's the only way "case-insensitive
		// keys" is meaningful.
		keyDecoded, err := percentDecode(rawKey)
		if err != nil {
			return nil, fmt.Errorf("%w: bad key: %v", ErrMalformedQuery, err)
		}
		key := strings.ToLower(keyDecoded)

		val, err := percentDecode(rawVal)
		if err != nil {
			return nil, fmt.Errorf("%w: bad value for %q: %v", ErrMalformedQuery, key, err)
		}

		// Handle `req-` first — any unknown req- key fails the whole URI.
		if strings.HasPrefix(key, "req-") {
			suffix := key[len("req-"):]
			// Recognized req-prefixed keys (none yet in BIP-21 base; if
			// future extensions add some they'd be enumerated here).
			switch suffix {
			default:
				return nil, &UnknownRequiredParamError{Key: key}
			}
		}

		switch key {
		case "amount":
			sats, err := parseBTCAmount(val)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidAmount, err)
			}
			out.Amount = &sats

		case "label":
			s := val
			out.Label = &s

		case "message":
			s := val
			out.Message = &s

		case "lightning":
			s := val
			out.Lightning = &s

		case "pj":
			s := val
			out.PJ = &s

		case "pjos":
			// BIP-78: pjos=0 → output substitution disabled-flag false
			// (i.e. substitution allowed); pjos=1 → disabled.
			switch val {
			case "0":
				b := false
				out.PJOS = &b
			case "1":
				b := true
				out.PJOS = &b
			default:
				return nil, fmt.Errorf("%w: pjos must be 0 or 1, got %q", ErrMalformedQuery, val)
			}

		default:
			// Unknown unprefixed key — per BIP-21 we MUST ignore it (i.e.
			// not fail), but we capture it in Extras for diagnostics /
			// forward-compat handlers.
			out.Extras[key] = val
		}
	}

	return out, nil
}

// parseBTCAmount converts a decimal-BTC string to int64 satoshis using
// fixed-point arithmetic (no float). Accepts up to 8 fractional digits,
// rejects negatives, scientific notation, and overflow past MAX_MONEY.
func parseBTCAmount(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty amount")
	}
	// Reject leading sign — BIP-21 amounts are non-negative.
	if s[0] == '-' || s[0] == '+' {
		return 0, fmt.Errorf("amount must be non-negative: %q", s)
	}
	// Reject scientific notation; canonical form is plain decimal.
	if strings.ContainsAny(s, "eE") {
		return 0, fmt.Errorf("scientific notation not allowed: %q", s)
	}

	// Split integer.fractional.
	var intPart, fracPart string
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart = s[:dot]
		fracPart = s[dot+1:]
		if strings.ContainsRune(fracPart, '.') {
			return 0, fmt.Errorf("multiple decimal points: %q", s)
		}
	} else {
		intPart = s
	}

	// Empty integer part is allowed only when fractional present
	// (".5" → 0.5 BTC), but we require at least one digit somewhere.
	if intPart == "" && fracPart == "" {
		return 0, fmt.Errorf("amount has no digits: %q", s)
	}
	if intPart == "" {
		intPart = "0"
	}

	// Parse integer BTC.
	intBTC, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad integer part %q: %w", intPart, err)
	}
	if intBTC < 0 {
		return 0, fmt.Errorf("amount must be non-negative: %q", s)
	}
	if intBTC > maxMoneyBTC {
		return 0, fmt.Errorf("amount exceeds MAX_MONEY: %q", s)
	}

	// Fractional → pad/truncate to exactly 8 digits.
	// BIP-21: more than 8 fractional digits is invalid (precision exceeds
	// satoshi). We reject rather than silently truncate.
	if len(fracPart) > 8 {
		// Allow trailing zeros past 8 places — they don't add precision.
		if strings.Trim(fracPart[8:], "0") != "" {
			return 0, fmt.Errorf("amount precision exceeds 1 satoshi: %q", s)
		}
		fracPart = fracPart[:8]
	}
	// All-digits check on the fractional part.
	for _, c := range fracPart {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit in fractional part: %q", s)
		}
	}
	// Pad to 8 digits.
	if len(fracPart) < 8 {
		fracPart = fracPart + strings.Repeat("0", 8-len(fracPart))
	}

	var fracSats int64
	if fracPart != "" {
		fracSats, err = strconv.ParseInt(fracPart, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("bad fractional part: %w", err)
		}
	}

	// intBTC * 1e8 + fracSats — guard against overflow.
	if intBTC > math.MaxInt64/satoshisPerBTC {
		return 0, fmt.Errorf("amount overflow: %q", s)
	}
	sats := intBTC*satoshisPerBTC + fracSats
	if sats < 0 {
		return 0, fmt.Errorf("amount overflow: %q", s)
	}
	if sats > maxMoneyBTC*satoshisPerBTC {
		return 0, fmt.Errorf("amount exceeds MAX_MONEY: %q", s)
	}
	return sats, nil
}

// percentDecode handles RFC 3986 percent-encoding. Returns an error on
// malformed escapes (`%` without two hex digits, non-hex chars).
// '+' is NOT treated as space — BIP-21 uses RFC 3986 URI rules, not
// application/x-www-form-urlencoded. (Bitcoin Core matches this; see
// `qt/guiutil.cpp::parseBitcoinURI`.)
func percentDecode(s string) (string, error) {
	if !strings.ContainsRune(s, '%') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated percent-escape at offset %d", i)
		}
		hi, ok1 := hexDigit(s[i+1])
		lo, ok2 := hexDigit(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("bad percent-escape %q at offset %d", s[i:i+3], i)
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
