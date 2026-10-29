package main

import (
	"fmt"
	"strings"
)

const (
	satPerBTC = 100_000_000
	// maxMoneySat is Core's MAX_MONEY (consensus/amount.h).
	maxMoneySat = 21_000_000 * satPerBTC
	// highTxFeePerKB is Core's HIGH_TX_FEE_PER_KB (wallet/wallet.h): COIN/100.
	highTxFeePerKB = satPerBTC / 100
)

// parseMoney is Core's ParseMoney (util/moneystr.cpp): an unsigned decimal
// BTC amount with at most 8 decimal places, surrounding whitespace trimmed,
// inside 0..MAX_MONEY. No sign, exponent, inner space or trailing junk.
func parseMoney(s string) (int64, bool) {
	if strings.IndexByte(s, 0) >= 0 {
		return 0, false
	}
	s = strings.Trim(s, " \f\n\r\t\v")
	if s == "" {
		return 0, false
	}
	whole := ""
	var units int64
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			i++
			for mult := int64(satPerBTC / 10); i < len(s) && s[i] >= '0' && s[i] <= '9' && mult > 0; i++ {
				units += mult * int64(s[i]-'0')
				mult /= 10
			}
			break
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		whole += string(c)
	}
	if i < len(s) || len(whole) > 10 {
		return 0, false
	}
	var w int64
	for _, c := range whole {
		w = w*10 + int64(c-'0')
	}
	v := w*satPerBTC + units
	if v < 0 || v > maxMoneySat {
		return 0, false
	}
	return v, true
}

// parseFallbackFee checks -fallbackfee the way Core's wallet load does
// (wallet/wallet.cpp): an unparsable amount is an error, a value above
// HIGH_TX_FEE_PER_KB is kept with a warning. Returns sat/kvB.
func parseFallbackFee(raw string) (int64, string, error) {
	v, ok := parseMoney(raw)
	if !ok {
		return 0, "", fmt.Errorf("Invalid amount for -fallbackfee=<amount>: '%s'", raw)
	}
	if v > highTxFeePerKB {
		return v, "-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available.", nil
	}
	return v, "", nil
}
