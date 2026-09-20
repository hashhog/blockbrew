package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestPrintHelpDocumentsSnapshotRSSBound is the operator-facing control for
// the 2026-09-20 open question: peak RSS during -load-snapshot was 6.57 GB
// against a 2.01 GB UTXO cache (~3×). That is a bound, not a budget. An
// operator sizing a machine from -dbcache would under-provision on the
// documented fast-boot path. printHelp (`blockbrew help`) must say so.
func TestPrintHelpDocumentsSnapshotRSSBound(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	printHelp()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "-dbcache") {
		t.Errorf("printHelp omits -dbcache, so an operator reading `blockbrew help` cannot size RAM")
	}
	low := strings.ToLower(text)
	if !strings.Contains(low, "rss") {
		t.Errorf("printHelp does not mention RSS")
	}
	if !hasThreeX(text) {
		t.Errorf("printHelp does not mention the ~3× peak-RSS / UTXO-cache bound")
	}
	if !strings.Contains(low, "load-snapshot") {
		t.Errorf("printHelp does not tie the RSS bound to -load-snapshot")
	}
	if t.Failed() {
		t.Fatalf("BEFORE: `blockbrew help` does not tell operators that peak RSS during -load-snapshot is ~3× the UTXO cache (a bound, not a budget). got:\n%s", text)
	}
}

// TestDbcacheFlagUsageDocumentsSnapshotRSSBound covers the other help
// surface: `blockbrew -h` prints flag.IntVar / flag.StringVar usage.
// Source-grep is the behavioral check: those strings are what PrintDefaults
// emits. Compile-red is not the control — the flags already exist at the
// parent; they just do not warn about the 3× bound.
func TestDbcacheFlagUsageDocumentsSnapshotRSSBound(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`flag.IntVar(&cfg.DBCache, "dbcache", 2560, dbcacheFlagHelp)`)) {
		t.Error(`-dbcache is not wired to dbcacheFlagHelp; -h would not show the RSS bound`)
	}
	if !bytes.Contains(src, []byte(`flag.StringVar(&cfg.LoadSnapshot, "load-snapshot", "", loadSnapshotFlagHelp)`)) {
		t.Error(`-load-snapshot is not wired to loadSnapshotFlagHelp; -h would not show the RSS bound`)
	}

	db := constLine(src, "dbcacheFlagHelp")
	if db == "" {
		t.Error("const dbcacheFlagHelp is missing")
	}
	load := constLine(src, "loadSnapshotFlagHelp")
	if load == "" {
		t.Error("const loadSnapshotFlagHelp is missing")
	}

	check := func(name, snippet string) {
		t.Helper()
		if snippet == "" {
			return
		}
		low := strings.ToLower(snippet)
		if !strings.Contains(low, "rss") {
			t.Errorf("%s usage does not mention RSS: %s", name, snippet)
		}
		if !hasThreeX(snippet) {
			t.Errorf("%s usage does not mention the ~3x bound: %s", name, snippet)
		}
	}
	check("-dbcache", db)
	check("-load-snapshot", load)
	if t.Failed() {
		t.Fatalf("-h usage for -dbcache / -load-snapshot does not tell operators peak RSS is ~3x the UTXO cache")
	}
}

func hasThreeX(s string) bool {
	return strings.Contains(s, "3×") || strings.Contains(s, "3x") || strings.Contains(s, "~3")
}

func constLine(src []byte, name string) string {
	sig := []byte("const " + name + " = ")
	i := bytes.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := bytes.IndexByte(rest, '\n'); j > 0 {
		return string(rest[:j])
	}
	return string(rest)
}
