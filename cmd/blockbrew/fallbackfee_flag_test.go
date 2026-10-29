package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The startup tests run parseFlags() in a child copy of the test binary,
// because a bad -fallbackfee must exit the process and parseFlags uses the
// global flag.CommandLine.
const fallbackFeeChildEnv = "BLOCKBREW_FALLBACKFEE_CHILD_ARGS"

func TestFallbackFeeStartupChild(t *testing.T) {
	raw := os.Getenv(fallbackFeeChildEnv)
	if raw == "" {
		t.Skip("helper for the TestFallbackFeeStartup_* tests")
	}
	os.Args = append([]string{"blockbrew"}, strings.Split(raw, "\x1f")...)
	flag.CommandLine = flag.NewFlagSet("blockbrew", flag.ExitOnError)
	cfg := parseFlags()
	if f := reflect.ValueOf(cfg).Elem().FieldByName("FallbackFee"); f.IsValid() {
		fmt.Printf("FALLBACKFEE=%v\n", f.Interface())
	}
	os.Exit(0)
}

// runFallbackFeeStartup runs parseFlags with args (plus a temp datadir and,
// if conf is non-empty, a blockbrew.conf holding it) and returns the exit
// code and combined output.
func runFallbackFeeStartup(t *testing.T, conf string, args ...string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	base := []string{"-network=regtest", "-datadir=" + dir}
	if conf != "" {
		confPath := filepath.Join(dir, "blockbrew.conf")
		if err := os.WriteFile(confPath, []byte(conf+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base = append(base, "-conf="+confPath)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFallbackFeeStartupChild$")
	cmd.Env = append(os.Environ(), fallbackFeeChildEnv+"="+strings.Join(append(base, args...), "\x1f"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), out.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, out.String()
}

// Core wallet.cpp: ParseMoney failure => "Invalid amount for
// -fallbackfee=<amount>: '<raw>'" and the wallet refuses to load.
func TestFallbackFeeStartup_InvalidRefusesLikeCore(t *testing.T) {
	for _, v := range []string{
		"-0.0001",     // sign
		"+0.0001",     // sign
		"0.000000001", // 9 decimal places
		"1e-4",        // scientific notation
		"21000000.01", // above MAX_MONEY
		"99999999999", // whole part too long
		"0.0001x",     // trailing junk
		"0. 0001",     // internal space
		"abc",         // non-digit
		"",            // empty
		"   ",         // empty after trim
	} {
		code, out := runFallbackFeeStartup(t, "", "-fallbackfee="+v)
		want := fmt.Sprintf("Invalid amount for -fallbackfee=<amount>: '%s'", v)
		if code == 0 || !strings.Contains(out, want) {
			t.Errorf("-fallbackfee=%q: exit %d, output %q; want non-zero exit and %q", v, code, out, want)
		}
	}
}

func TestFallbackFeeStartup_InvalidInConfFileRefuses(t *testing.T) {
	code, out := runFallbackFeeStartup(t, "fallbackfee=-1")
	want := "Invalid amount for -fallbackfee=<amount>: '-1'"
	if code == 0 || !strings.Contains(out, want) {
		t.Fatalf("conf fallbackfee=-1: exit %d, output %q; want non-zero exit and %q", code, out, want)
	}
}

func TestFallbackFeeStartup_ValidAccepted(t *testing.T) {
	for v, want := range map[string]float64{
		"0":          0,
		"0.0002":     0.0002,
		" 0.0002 ":   0.0002, // Core trims surrounding whitespace
		".0001":      0.0001,
		"1.":         1,
		"0.00000001": 0.00000001,
		"21000000":   21000000,
	} {
		code, out := runFallbackFeeStartup(t, "", "-fallbackfee="+v)
		if code != 0 {
			t.Errorf("-fallbackfee=%q: exit %d, output %q; want accepted", v, code, out)
			continue
		}
		i := strings.Index(out, "FALLBACKFEE=")
		if i < 0 {
			t.Errorf("-fallbackfee=%q: no FALLBACKFEE in output %q", v, out)
			continue
		}
		got, err := strconv.ParseFloat(strings.Fields(out[i+len("FALLBACKFEE="):])[0], 64)
		if err != nil || got != want {
			t.Errorf("-fallbackfee=%q: got %v (%v), want %v", v, got, err, want)
		}
	}
}

// Above HIGH_TX_FEE_PER_KB (0.01 BTC/kvB) Core keeps the value and warns.
func TestFallbackFeeStartup_HighWarnsNotRejected(t *testing.T) {
	code, out := runFallbackFeeStartup(t, "", "-fallbackfee=0.02")
	if code != 0 || !strings.Contains(out, "-fallbackfee is set very high!") {
		t.Fatalf("-fallbackfee=0.02: exit %d, output %q; want accepted with a 'set very high' warning", code, out)
	}
	if code, out := runFallbackFeeStartup(t, "", "-fallbackfee=0.01"); code != 0 || strings.Contains(out, "very high") {
		t.Fatalf("-fallbackfee=0.01: exit %d, output %q; want accepted without warning", code, out)
	}
}
