package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// configFileError lets callers distinguish "file not present" (a soft fail
// when -conf was not explicitly set) from a real parse error (always fatal).
type configFileError struct {
	path string
	err  error
}

func (e *configFileError) Error() string {
	return fmt.Sprintf("config file %s: %v", e.path, e.err)
}

// loadConfigFile parses a Bitcoin Core-style key=value configuration file
// and returns the resulting map of canonical flag-name → string value.
//
// Format mirrors `bitcoin-core/src/util/settings.cpp` ReadConfigStream:
//
//   - Blank lines and lines whose first non-whitespace char is '#' are skipped.
//   - Lines must contain '=' to be valid; "key" alone (no '=') is rejected.
//   - Whitespace around key and value is trimmed.
//   - Network sections like `[main]`, `[test]`, `[regtest]`, `[signet]`
//     are recognised as scope markers; keys inside a section are namespaced
//     with `<section>.<key>`. We currently apply only keys in the "global"
//     scope (no section) and the section matching the active network.
//   - Leading "-" on a key is accepted and stripped so users can paste
//     either `-rpcuser=foo` or `rpcuser=foo`.
//   - Inline comments (`# …` after a value) are NOT supported; Core
//     treats them as part of the value, so we do too.
//
// network is the active network name ("mainnet", "testnet", etc); pass
// the empty string to apply only the global scope.  Returns the merged
// flag map; later entries override earlier ones, matching Core.
func loadConfigFile(path string, network string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &configFileError{path: path, err: err}
	}
	defer f.Close()
	return parseConfigStream(f, network)
}

// sectionForNetwork returns the [section] header name that applies to a
// given network argument.  Bitcoin Core uses `[main]`, `[test]`, `[testnet4]`,
// `[signet]`, `[regtest]` — see chainparamsbase.cpp:CBaseChainParams. Empty
// network → empty section name (only the global scope applies).
func sectionForNetwork(network string) string {
	switch network {
	case "mainnet":
		return "main"
	case "testnet":
		return "test"
	case "testnet4":
		return "testnet4"
	case "signet":
		return "signet"
	case "regtest":
		return "regtest"
	default:
		return ""
	}
}

// parseConfigStream is the testable inner of loadConfigFile — it operates
// on an io.Reader so tests can drive it without touching the filesystem.
func parseConfigStream(r io.Reader, network string) (map[string]string, error) {
	out := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	currentSection := ""
	activeSection := sectionForNetwork(network)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Section header: [name]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		// Skip lines outside the active scope.
		if currentSection != "" && currentSection != activeSection {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key=value, got %q", lineNum, line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNum)
		}
		key = strings.TrimPrefix(key, "-")
		out[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// FlagSetter is the subset of *flag.FlagSet that applyConfigFlags uses.
// Defined as an interface so tests can substitute a fake without needing
// to construct a real *flag.FlagSet.
type FlagSetter interface {
	// Set updates the named flag's value, returning an error if the
	// flag does not exist or the value is invalid.
	Set(name, value string) error
	// IsRegistered returns true if a flag with the given name is known
	// to the underlying FlagSet.
	IsRegistered(name string) bool
}

// applyConfigFlags walks the map produced by loadConfigFile and Sets each
// recognised flag on the provided FlagSetter, but ONLY for flags the user
// did not already specify on the command line.  Bitcoin Core's precedence
// is CLI > config file > defaults, and we match that here by skipping any
// flag found in cliSet.
//
// Unknown keys are silently ignored — Core warns, we just log.  Repeated
// keys are not specially handled (the map already collapsed them to the
// last seen value, which is what Core does too).
func applyConfigFlags(fs FlagSetter, cfg map[string]string, cliSet map[string]bool, logFn func(string, ...any)) {
	for k, v := range cfg {
		if cliSet[k] {
			continue
		}
		if !fs.IsRegistered(k) {
			if logFn != nil {
				logFn("config: ignoring unknown key %q", k)
			}
			continue
		}
		if err := fs.Set(k, v); err != nil {
			if logFn != nil {
				logFn("config: invalid value for %q: %v", k, err)
			}
		}
	}
}

// resolveConfigPath returns the config-file path to load, in priority order:
//  1. The explicit -conf=<path> if provided (returned as-is).
//  2. <datadir>/blockbrew.conf if present.
//  3. ~/.blockbrew/blockbrew.conf if present.
//
// Returns ("", false) if no config file was requested and none of the
// default search locations contain one.  When the user explicitly set
// -conf the path is returned even if the file does not exist, so the
// caller can produce a fatal error.
func resolveConfigPath(explicit string, datadir string) (path string, explicitlySet bool) {
	if explicit != "" {
		return explicit, true
	}
	candidates := []string{}
	if datadir != "" {
		candidates = append(candidates, filepath.Join(datadir, "blockbrew.conf"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, defaultDir, "blockbrew.conf"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, false
		}
	}
	return "", false
}
