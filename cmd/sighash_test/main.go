// Command sighash_test runs the Bitcoin Core sighash test vectors against
// the blockbrew CalcSignatureHash implementation.
//
// Test vector file: sighash.json from Bitcoin Core
// Format: [raw_transaction_hex, script_hex, input_index, hash_type, expected_sighash_hex]
//
// NOTE: The blockbrew CalcSignatureHash function accepts SigHashType as a byte,
// then writes uint32(hashType) when appending the hash type to the serialized
// transaction. The Bitcoin Core test vectors use full 32-bit hash type values
// where the upper bytes are nonzero and significant. This means the blockbrew
// implementation will produce incorrect sighash values for test vectors where
// the hash type does not fit in a single byte (i.e., the upper 24 bits are
// nonzero). This harness reports those mismatches.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <sighash.json>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	var testCases []json.RawMessage
	if err := json.Unmarshal(data, &testCases); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	passed := 0
	failed := 0
	skipped := 0
	errors := 0

	for i, raw := range testCases {
		// Each entry is an array. The first entry is a comment (single-element string array).
		var entry []json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing entry: %v\n", i, err)
			errors++
			continue
		}

		// Skip comment entries (single-element arrays or arrays that don't have 5 elements)
		if len(entry) != 5 {
			skipped++
			continue
		}

		var rawTxHex string
		var scriptHex string
		var inputIndex int
		var hashType int32
		var expectedHashHex string

		if err := json.Unmarshal(entry[0], &rawTxHex); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing raw_tx: %v\n", i, err)
			errors++
			continue
		}
		if err := json.Unmarshal(entry[1], &scriptHex); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing script: %v\n", i, err)
			errors++
			continue
		}
		if err := json.Unmarshal(entry[2], &inputIndex); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing input_index: %v\n", i, err)
			errors++
			continue
		}
		if err := json.Unmarshal(entry[3], &hashType); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing hash_type: %v\n", i, err)
			errors++
			continue
		}
		if err := json.Unmarshal(entry[4], &expectedHashHex); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error parsing expected_hash: %v\n", i, err)
			errors++
			continue
		}

		// Decode raw transaction
		txBytes, err := hex.DecodeString(rawTxHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error decoding tx hex: %v\n", i, err)
			errors++
			continue
		}

		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error deserializing tx: %v\n", i, err)
			errors++
			continue
		}

		// Decode script
		scriptBytes, err := hex.DecodeString(scriptHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error decoding script hex: %v\n", i, err)
			errors++
			continue
		}

		// Decode expected hash (Bitcoin Core stores hashes in reversed byte order)
		expectedHash, err := hex.DecodeString(expectedHashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test %d: error decoding expected hash: %v\n", i, err)
			errors++
			continue
		}
		// Reverse to get natural byte order
		for left, right := 0, len(expectedHash)-1; left < right; left, right = left+1, right-1 {
			expectedHash[left], expectedHash[right] = expectedHash[right], expectedHash[left]
		}

		sht := script.SigHashType(hashType)

		result, err := script.CalcSignatureHash(scriptBytes, sht, &tx, inputIndex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test %d: CalcSignatureHash error: %v\n", i, err)
			errors++
			continue
		}

		if bytes.Equal(result[:], expectedHash) {
			passed++
		} else {
			failed++
			fmt.Printf("FAIL test %d: hashType=0x%08x (byte=0x%02x) idx=%d\n",
				i, uint32(hashType), byte(hashType), inputIndex)
			fmt.Printf("  expected: %s\n", expectedHashHex)
			fmt.Printf("  got:      %x\n", result[:])
		}
	}

	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Passed:  %d\n", passed)
	fmt.Printf("Failed:  %d\n", failed)
	fmt.Printf("Errors:  %d\n", errors)
	fmt.Printf("Skipped: %d\n", skipped)
	fmt.Printf("Total:   %d\n", passed+failed+errors+skipped)
}
