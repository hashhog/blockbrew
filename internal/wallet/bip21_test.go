// BIP-21 URI parser tests.
//
// Vectors borrowed from the BIP-21 spec
// (https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki#examples)
// plus blockbrew-specific cases covering BIP-78 (`pj`, `pjos`) and the
// W119 audit gates G28 / G29.

package wallet

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
)

// Mainnet addresses known to round-trip in internal/address/address_test.go.
const (
	mainnetP2PKHAddr  = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	mainnetP2WPKHAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	mainnetP2TRAddr   = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
)

// ── Basic structural parses ────────────────────────────────────────────────

func TestParseBIP21_BareAddress(t *testing.T) {
	u, err := ParseBIP21("bitcoin:"+mainnetP2PKHAddr, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.AddressString != mainnetP2PKHAddr {
		t.Errorf("AddressString = %q, want %q", u.AddressString, mainnetP2PKHAddr)
	}
	if u.Address == nil {
		t.Fatal("Address is nil")
	}
	if u.Address.Type != address.P2PKH {
		t.Errorf("address Type = %v, want P2PKH", u.Address.Type)
	}
	if u.Amount != nil || u.Label != nil || u.Message != nil ||
		u.Lightning != nil || u.PJ != nil || u.PJOS != nil {
		t.Errorf("optional fields should be nil for bare URI: %+v", u)
	}
}

func TestParseBIP21_EmptyQueryStillValid(t *testing.T) {
	// "bitcoin:<addr>?" with empty query string should still parse.
	u, err := ParseBIP21("bitcoin:"+mainnetP2WPKHAddr+"?", address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Amount != nil {
		t.Errorf("Amount should be nil, got %d", *u.Amount)
	}
}

// ── Standard params with Go-native types ───────────────────────────────────

func TestParseBIP21_AllStandardParams(t *testing.T) {
	// Spec sample 3: amount, label, message.
	uri := "bitcoin:" + mainnetP2PKHAddr +
		"?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Amount == nil {
		t.Fatal("Amount should be set")
	}
	if got, want := *u.Amount, int64(50)*satoshisPerBTC; got != want {
		t.Errorf("Amount = %d sats, want %d", got, want)
	}
	if u.Label == nil || *u.Label != "Luke-Jr" {
		t.Errorf("Label = %v, want %q", u.Label, "Luke-Jr")
	}
	if u.Message == nil || *u.Message != "Donation for project xyz" {
		t.Errorf("Message = %v, want %q", u.Message, "Donation for project xyz")
	}
}

// ── Spec test vectors (BIP-21 §Examples) ───────────────────────────────────

func TestParseBIP21_SpecVectors(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		// expected fields; pointer-typed → nil means "absent"
		wantAmount  *int64
		wantLabel   *string
		wantMessage *string
	}{
		{
			name: "just address",
			uri:  "bitcoin:" + mainnetP2PKHAddr,
		},
		{
			name:      "address with label",
			uri:       "bitcoin:" + mainnetP2PKHAddr + "?label=Luke-Jr",
			wantLabel: ptrString("Luke-Jr"),
		},
		{
			name:        "request 20.30 BTC to single address",
			uri:         "bitcoin:" + mainnetP2PKHAddr + "?amount=20.3&label=Luke-Jr",
			wantAmount:  ptrInt64(int64(20)*satoshisPerBTC + 30_000_000),
			wantLabel:   ptrString("Luke-Jr"),
		},
		{
			name: "request 50 BTC with message",
			uri: "bitcoin:" + mainnetP2PKHAddr +
				"?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
			wantAmount:  ptrInt64(int64(50) * satoshisPerBTC),
			wantLabel:   ptrString("Luke-Jr"),
			wantMessage: ptrString("Donation for project xyz"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ParseBIP21(tc.uri, address.Mainnet)
			if err != nil {
				t.Fatalf("ParseBIP21(%q) error: %v", tc.uri, err)
			}
			if !int64Eq(u.Amount, tc.wantAmount) {
				t.Errorf("Amount = %v, want %v", deref64(u.Amount), deref64(tc.wantAmount))
			}
			if !strEq(u.Label, tc.wantLabel) {
				t.Errorf("Label = %v, want %v", derefStr(u.Label), derefStr(tc.wantLabel))
			}
			if !strEq(u.Message, tc.wantMessage) {
				t.Errorf("Message = %v, want %v", derefStr(u.Message), derefStr(tc.wantMessage))
			}
		})
	}
}

// ── Percent-decoded label/message ──────────────────────────────────────────

func TestParseBIP21_PercentDecode(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr +
		"?label=Caf%C3%A9&message=hello%20world%21"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Label == nil || *u.Label != "Café" {
		t.Errorf("Label = %v, want %q", derefStr(u.Label), "Café")
	}
	if u.Message == nil || *u.Message != "hello world!" {
		t.Errorf("Message = %v, want %q", derefStr(u.Message), "hello world!")
	}
}

func TestParseBIP21_PercentDecodeMalformed(t *testing.T) {
	// Truncated and non-hex escapes → ErrMalformedQuery.
	cases := []string{
		"bitcoin:" + mainnetP2PKHAddr + "?label=bad%X1",
		"bitcoin:" + mainnetP2PKHAddr + "?label=truncated%2",
	}
	for _, uri := range cases {
		_, err := ParseBIP21(uri, address.Mainnet)
		if !errors.Is(err, ErrMalformedQuery) {
			t.Errorf("ParseBIP21(%q) err=%v, want ErrMalformedQuery", uri, err)
		}
	}
}

// ── req-<X> handling ───────────────────────────────────────────────────────

func TestParseBIP21_UnknownReqParam(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr + "?req-frobnicate=42"
	_, err := ParseBIP21(uri, address.Mainnet)
	if !errors.Is(err, ErrUnknownRequiredParam) {
		t.Fatalf("err = %v, want ErrUnknownRequiredParam", err)
	}
	var typed *UnknownRequiredParamError
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *UnknownRequiredParamError", err)
	}
	if typed.Key != "req-frobnicate" {
		t.Errorf("Key = %q, want req-frobnicate", typed.Key)
	}
}

func TestParseBIP21_UnknownUnprefixedGoesToExtras(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr + "?somefutureparam=42&amount=1"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := u.Extras["somefutureparam"]; got != "42" {
		t.Errorf("Extras[somefutureparam] = %q, want 42", got)
	}
	// Amount must still be parsed alongside extras.
	if u.Amount == nil || *u.Amount != satoshisPerBTC {
		t.Errorf("Amount = %v, want 1 BTC", deref64(u.Amount))
	}
}

// ── Invalid address / wrong-network / bad scheme ──────────────────────────

func TestParseBIP21_InvalidAddress(t *testing.T) {
	uri := "bitcoin:notarealaddress?amount=1"
	_, err := ParseBIP21(uri, address.Mainnet)
	if !errors.Is(err, ErrBip21InvalidAddress) {
		t.Errorf("err = %v, want ErrBip21InvalidAddress", err)
	}
}

func TestParseBIP21_WrongNetwork(t *testing.T) {
	// Mainnet P2PKH address fed to a Testnet parser → ErrWrongNetwork.
	uri := "bitcoin:" + mainnetP2PKHAddr
	_, err := ParseBIP21(uri, address.Testnet)
	if !errors.Is(err, ErrWrongNetwork) {
		t.Errorf("err = %v, want ErrWrongNetwork", err)
	}
}

func TestParseBIP21_WrongScheme(t *testing.T) {
	cases := []string{
		"http://example.com",
		"lightning:lnbc1...",
		"",
		"bitcoin",   // no colon
		"bitcoin//", // wrong delimiter, no colon either
	}
	for _, uri := range cases {
		_, err := ParseBIP21(uri, address.Mainnet)
		if !errors.Is(err, ErrWrongScheme) {
			t.Errorf("ParseBIP21(%q) err = %v, want ErrWrongScheme", uri, err)
		}
	}
}

// ── BIP-78 pj / pjos extraction ────────────────────────────────────────────

func TestParseBIP21_PJExtracted(t *testing.T) {
	pjURL := "https://example.com/payjoin"
	encoded := "https%3A%2F%2Fexample.com%2Fpayjoin"
	uri := "bitcoin:" + mainnetP2PKHAddr + "?amount=0.01&pj=" + encoded
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.PJ == nil || *u.PJ != pjURL {
		t.Errorf("PJ = %v, want %q", derefStr(u.PJ), pjURL)
	}
}

func TestParseBIP21_PJOSValues(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"0", false},
		{"1", true},
	}
	for _, tc := range cases {
		t.Run("pjos="+tc.val, func(t *testing.T) {
			uri := "bitcoin:" + mainnetP2PKHAddr + "?pj=https%3A%2F%2Fexample.com&pjos=" + tc.val
			u, err := ParseBIP21(uri, address.Mainnet)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u.PJOS == nil {
				t.Fatal("PJOS should be set")
			}
			if *u.PJOS != tc.want {
				t.Errorf("PJOS = %v, want %v", *u.PJOS, tc.want)
			}
		})
	}
}

func TestParseBIP21_PJOSInvalid(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr + "?pjos=2"
	_, err := ParseBIP21(uri, address.Mainnet)
	if !errors.Is(err, ErrMalformedQuery) {
		t.Errorf("err = %v, want ErrMalformedQuery", err)
	}
}

// ── Case-insensitive keys ───────────────────────────────────────────────

func TestParseBIP21_CaseInsensitiveKeys(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr + "?AMOUNT=2&Label=mixed&PJ=https%3A%2F%2Fexample.com"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Amount == nil || *u.Amount != 2*satoshisPerBTC {
		t.Errorf("Amount = %v, want 2 BTC", deref64(u.Amount))
	}
	if u.Label == nil || *u.Label != "mixed" {
		t.Errorf("Label = %v, want mixed", derefStr(u.Label))
	}
	if u.PJ == nil || *u.PJ != "https://example.com" {
		t.Errorf("PJ = %v, want https://example.com", derefStr(u.PJ))
	}
}

func TestParseBIP21_CaseInsensitiveScheme(t *testing.T) {
	cases := []string{
		"Bitcoin:" + mainnetP2PKHAddr,
		"BITCOIN:" + mainnetP2PKHAddr,
		"BiTcOiN:" + mainnetP2PKHAddr,
	}
	for _, uri := range cases {
		if _, err := ParseBIP21(uri, address.Mainnet); err != nil {
			t.Errorf("ParseBIP21(%q) err = %v, want nil", uri, err)
		}
	}
}

// ── Amount edge cases (fixed-point precision) ──────────────────────────────

func TestParseBIP21_AmountPrecision(t *testing.T) {
	cases := []struct {
		amount string
		want   int64 // sats
		ok     bool
	}{
		{"0", 0, true},
		{"0.0", 0, true},
		{"1", satoshisPerBTC, true},
		{"0.00000001", 1, true},       // 1 sat
		{"0.1", 10_000_000, true},     // 0.1 BTC = 10M sat
		{".5", 50_000_000, true},      // leading-dot form
		{"20.3", 2_030_000_000, true}, // BIP-21 vector
		// trailing zeros past 8 places are ok — they don't add precision
		{"1.000000000", satoshisPerBTC, true},
		// too much precision → reject
		{"0.000000001", 0, false},
		// negatives
		{"-1", 0, false},
		// scientific notation
		{"1e8", 0, false},
		// multiple dots
		{"1.2.3", 0, false},
		// empty
		{"", 0, false},
		// over MAX_MONEY
		{"21000001", 0, false},
		// exactly MAX_MONEY is ok
		{"21000000", maxMoneyBTC * satoshisPerBTC, true},
	}
	for _, tc := range cases {
		t.Run(tc.amount, func(t *testing.T) {
			got, err := parseBTCAmount(tc.amount)
			if tc.ok {
				if err != nil {
					t.Errorf("parseBTCAmount(%q) err = %v, want nil", tc.amount, err)
					return
				}
				if got != tc.want {
					t.Errorf("parseBTCAmount(%q) = %d, want %d", tc.amount, got, tc.want)
				}
			} else if err == nil {
				t.Errorf("parseBTCAmount(%q) = %d, want error", tc.amount, got)
			}
		})
	}
}

func TestParseBIP21_AmountInvalid(t *testing.T) {
	cases := []string{
		"bitcoin:" + mainnetP2PKHAddr + "?amount=abc",
		"bitcoin:" + mainnetP2PKHAddr + "?amount=-1",
		"bitcoin:" + mainnetP2PKHAddr + "?amount=1e8",
		"bitcoin:" + mainnetP2PKHAddr + "?amount=99999999",
	}
	for _, uri := range cases {
		_, err := ParseBIP21(uri, address.Mainnet)
		if !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("ParseBIP21(%q) err = %v, want ErrInvalidAmount", uri, err)
		}
	}
}

// ── Lightning fallback ─────────────────────────────────────────────────────

func TestParseBIP21_Lightning(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr +
		"?amount=0.001&lightning=lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpdw3jhxapqd9h8vmmfvdjscqzpgxqyz5vqsp5usyc4lk9chsfp53kvcnvq456ganh60d89reykdngsmtj6yw3nhvq9qyyssqjm6zs9k9bw2j6h2zb6h5gz5kj0qj6lpcuv0z2u3v54hcl9wxq57yz63jw7tg6h84n6h2lxgwc2c8h9xls79zyc2zhxrcfh3rdwg6lqkccz4q"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Lightning == nil || !strings.HasPrefix(*u.Lightning, "lnbc") {
		t.Errorf("Lightning = %v, want BOLT-11 starting with lnbc", derefStr(u.Lightning))
	}
}

// ── Misc structural ────────────────────────────────────────────────────────

func TestParseBIP21_TolerateExtraAmpersands(t *testing.T) {
	uri := "bitcoin:" + mainnetP2PKHAddr + "?amount=1&&label=x&"
	u, err := ParseBIP21(uri, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Amount == nil || *u.Amount != satoshisPerBTC {
		t.Errorf("Amount = %v, want 1 BTC", deref64(u.Amount))
	}
	if u.Label == nil || *u.Label != "x" {
		t.Errorf("Label = %v, want x", derefStr(u.Label))
	}
}

func TestParseBIP21_TolerateDoubleSlash(t *testing.T) {
	// Some UIs emit `bitcoin://addr...`; tolerate.
	u, err := ParseBIP21("bitcoin://"+mainnetP2PKHAddr, address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.AddressString != mainnetP2PKHAddr {
		t.Errorf("AddressString = %q, want %q", u.AddressString, mainnetP2PKHAddr)
	}
}

func TestParseBIP21_FragmentIgnored(t *testing.T) {
	u, err := ParseBIP21("bitcoin:"+mainnetP2WPKHAddr+"#someanchor", address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.AddressString != mainnetP2WPKHAddr {
		t.Errorf("AddressString = %q, want %q", u.AddressString, mainnetP2WPKHAddr)
	}
}

func TestParseBIP21_TaprootAddress(t *testing.T) {
	u, err := ParseBIP21("bitcoin:"+mainnetP2TRAddr+"?amount=0.001", address.Mainnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Address.Type != address.P2TR {
		t.Errorf("Type = %v, want P2TR", u.Address.Type)
	}
	if u.Amount == nil || *u.Amount != 100_000 {
		t.Errorf("Amount = %v, want 100_000 sats", deref64(u.Amount))
	}
}

// ── Pointer helpers used by the table-driven tests above ─────────────────

func ptrString(s string) *string { return &s }
func ptrInt64(v int64) *int64    { return &v }

func int64Eq(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func strEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func deref64(p *int64) interface{} {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func derefStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
