package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigStreamSimple(t *testing.T) {
	in := `# top-level comment
rpcuser=foo
rpcpassword = bar
# blank line below

datadir=/tmp/x
-network=mainnet
`
	out, err := parseConfigStream(strings.NewReader(in), "")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := map[string]string{
		"rpcuser":     "foo",
		"rpcpassword": "bar",
		"datadir":     "/tmp/x",
		"network":     "mainnet",
	}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("key %q: got %q, want %q", k, out[k], v)
		}
	}
}

func TestParseConfigStreamSections(t *testing.T) {
	in := `rpcuser=globaluser
[main]
rpcuser=mainuser
rpcpassword=mainpass
[test]
rpcuser=testuser
[regtest]
rpcuser=regtestuser
`
	tests := []struct {
		network  string
		wantUser string
	}{
		{"mainnet", "mainuser"},
		{"testnet", "testuser"},
		{"regtest", "regtestuser"},
		{"unknownnet", "globaluser"},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			out, err := parseConfigStream(strings.NewReader(in), tt.network)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if got := out["rpcuser"]; got != tt.wantUser {
				t.Errorf("network=%s rpcuser=%q want %q", tt.network, got, tt.wantUser)
			}
		})
	}
}

func TestParseConfigStreamMalformed(t *testing.T) {
	cases := []string{
		"key without equals\n",
		"=missingkey\n",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := parseConfigStream(strings.NewReader(c), ""); err == nil {
				t.Errorf("expected error for %q", c)
			}
		})
	}
}

func TestLoadConfigFileMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := loadConfigFile(filepath.Join(dir, "does-not-exist.conf"), "mainnet")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var cfErr *configFileError
	if !errors.As(err, &cfErr) {
		t.Errorf("expected configFileError, got %T", err)
	}
}

func TestResolveConfigPathExplicit(t *testing.T) {
	path, explicit := resolveConfigPath("/etc/foo.conf", "/var/data")
	if !explicit {
		t.Error("expected explicit=true")
	}
	if path != "/etc/foo.conf" {
		t.Errorf("got %q, want /etc/foo.conf", path)
	}
}

func TestResolveConfigPathDataDir(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "blockbrew.conf")
	if err := os.WriteFile(confPath, []byte("rpcuser=x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path, explicit := resolveConfigPath("", dir)
	if explicit {
		t.Error("expected explicit=false")
	}
	if path != confPath {
		t.Errorf("got %q, want %q", path, confPath)
	}
}

// fakeFlagSetter implements FlagSetter without depending on flag.FlagSet.
type fakeFlagSetter struct {
	registered map[string]bool
	got        map[string]string
}

func (f *fakeFlagSetter) Set(name, val string) error {
	if f.got == nil {
		f.got = map[string]string{}
	}
	if !f.registered[name] {
		return errors.New("not registered")
	}
	f.got[name] = val
	return nil
}

func (f *fakeFlagSetter) IsRegistered(name string) bool { return f.registered[name] }

func TestApplyConfigFlagsRespectsCliPrecedence(t *testing.T) {
	fs := &fakeFlagSetter{registered: map[string]bool{"rpcuser": true, "rpcpassword": true}}
	cfg := map[string]string{
		"rpcuser":     "fromconf",
		"rpcpassword": "fromconf",
		"unknown":     "ignored",
	}
	cliSet := map[string]bool{"rpcuser": true}
	var warnings []string
	applyConfigFlags(fs, cfg, cliSet, func(format string, args ...any) {
		warnings = append(warnings, format)
	})
	if _, ok := fs.got["rpcuser"]; ok {
		t.Error("CLI-set flag was overridden by config")
	}
	if fs.got["rpcpassword"] != "fromconf" {
		t.Errorf("rpcpassword not applied from config; got %q", fs.got["rpcpassword"])
	}
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning for unknown key, got %d: %v", len(warnings), warnings)
	}
}
