package p2p

// ASMap (Autonomous System Map) subsystem
//
// Implements the bit-packed binary trie interpreter that maps IP address
// prefixes to Autonomous System Numbers (ASNs). Mirrors Bitcoin Core's
// src/util/asmap.h / asmap.cpp line-for-line.
//
// The asmap file is a bit-packed format where the entire trie is treated as a
// continuous sequence of bits without byte alignment. Bits are stored in bytes
// using little-endian bit ordering (LSB first). IP address bits are consumed
// MSB first (network byte order).
//
// Four instruction types encode the trie:
//   RETURN  [0]      — leaf: return constant ASN
//   JUMP    [1,0]    — branch: if next IP bit == 1, skip N bits; else fall through
//   MATCH   [1,1,0]  — multi-bit compare: if pattern matches, continue; else return default
//   DEFAULT [1,1,1]  — set fallback ASN and continue

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"os"
)

// MaxAsmapFileSize is the maximum allowed asmap file size (8 MiB).
// Mirrors Bitcoin Core src/init.cpp MAX_ASMAP_FILESIZE.
const MaxAsmapFileSize = 8 * 1024 * 1024

// asmapInvalid signals a decoding error or invalid data within DecodeBits.
const asmapInvalid = uint32(0xFFFFFFFF)

// Instruction opcodes — same encoding as Core.
const (
	instrRETURN  = 0
	instrJUMP    = 1
	instrMATCH   = 2
	instrDEFAULT = 3
)

// Type encoding bit-sizes: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
var typeBitSizes = []uint8{0, 0, 1}

// ASN encoding: minval=1, bit_sizes=[15,16,...,24]
var asnBitSizes = []uint8{15, 16, 17, 18, 19, 20, 21, 22, 23, 24}

// MATCH argument: minval=2, bit_sizes=[1,2,...,8]
var matchBitSizes = []uint8{1, 2, 3, 4, 5, 6, 7, 8}

// JUMP offset: minval=17, bit_sizes=[5,6,...,30]
var jumpBitSizes = []uint8{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

// consumeBitLE reads the bit at bitpos from data using little-endian bit order
// (LSB first within each byte). Used for asmap bytecode.
func consumeBitLE(bitpos *int, data []byte) bool {
	b := int(*bitpos)
	bit := (data[b/8] >> (uint(b) % 8)) & 1
	*bitpos++
	return bit == 1
}

// consumeBitBE reads the bit at bitpos from data using big-endian bit order
// (MSB first within each byte). Used for IP address bits.
func consumeBitBE(bitpos *uint8, data []byte) bool {
	b := int(*bitpos)
	bit := (data[b/8] >> (7 - uint(b)%8)) & 1
	*bitpos++
	return bit == 1
}

// decodeBits is the variable-length integer decoder.
// Mirrors Core's DecodeBits() exactly.
//
// The encoding for minval=100, bit_sizes=[4,2,2,3]:
//   x in [100..115]: [0] + [4-bit BE encoding of (x-100)]
//   x in [116..119]: [1,0] + [2-bit BE encoding of (x-116)]
//   x in [120..123]: [1,1,0] + [2-bit BE encoding of (x-120)]
//   x in [124..131]: [1,1,1] + [3-bit BE encoding of (x-124)]
func decodeBits(bitpos *int, data []byte, minval uint32, bitSizes []uint8) uint32 {
	val := minval
	endBit := len(data) * 8
	for i, sz := range bitSizes {
		// Read continuation bit (unless last class — last class has no continuation bit)
		var contBit bool
		if i+1 != len(bitSizes) {
			if *bitpos >= endBit {
				break // Reached EOF in exponent
			}
			contBit = consumeBitLE(bitpos, data)
		} else {
			contBit = false // last class
		}
		if contBit {
			// Not in this class: skip its range and continue
			val += 1 << sz
		} else {
			// In this class: read sz-bit big-endian position within class
			for b := uint8(0); b < sz; b++ {
				if *bitpos >= endBit {
					return asmapInvalid // Reached EOF in mantissa
				}
				bit := consumeBitLE(bitpos, data)
				if bit {
					val += 1 << (sz - 1 - b)
				}
			}
			return val
		}
	}
	return asmapInvalid // Reached EOF in exponent
}

func decodeType(bitpos *int, data []byte) uint32 {
	return decodeBits(bitpos, data, 0, typeBitSizes)
}

func decodeASN(bitpos *int, data []byte) uint32 {
	return decodeBits(bitpos, data, 1, asnBitSizes)
}

func decodeMatch(bitpos *int, data []byte) uint32 {
	return decodeBits(bitpos, data, 2, matchBitSizes)
}

func decodeJump(bitpos *int, data []byte) uint32 {
	return decodeBits(bitpos, data, 17, jumpBitSizes)
}

// Interpret executes the ASMap bytecode trie for a 16-byte IPv6 address.
// Returns the matching ASN (0 = no match / unmapped).
// Mirrors Bitcoin Core's Interpret() line-for-line.
//
// ip must be a 16-byte slice (net.IP.To16()). IPv4-mapped addresses are passed
// as-is (::ffff:a.b.c.d), which is consistent with Core's IPv6-128-bit treatment.
func Interpret(asmap []byte, ip [16]byte) uint32 {
	pos := 0
	endpos := len(asmap) * 8
	var ipBit uint8
	ipBitsEnd := uint8(128)
	var defaultASN uint32

	for pos < endpos {
		opcode := decodeType(&pos, asmap)
		switch opcode {
		case instrRETURN:
			asn := decodeASN(&pos, asmap)
			if asn == asmapInvalid {
				// ASN straddles EOF — should have been caught by sanity check
				return 0
			}
			return asn

		case instrJUMP:
			jump := decodeJump(&pos, asmap)
			if jump == asmapInvalid {
				return 0
			}
			if ipBit == ipBitsEnd {
				return 0 // No IP bits left
			}
			if int64(jump) >= int64(endpos-pos) {
				return 0 // Jump past EOF
			}
			if consumeBitBE(&ipBit, ip[:]) {
				pos += int(jump) // bit=1: jump to right subtree
			}
			// bit=0: fall through to left subtree

		case instrMATCH:
			match := decodeMatch(&pos, asmap)
			if match == asmapInvalid {
				return 0
			}
			matchlen := bits.Len32(match) - 1 // bit_width(match) - 1
			if int(ipBitsEnd-ipBit) < matchlen {
				return 0 // Not enough IP bits
			}
			for bit := 0; bit < matchlen; bit++ {
				ipbitval := consumeBitBE(&ipBit, ip[:])
				expected := ((match >> uint(matchlen-1-bit)) & 1) == 1
				if ipbitval != expected {
					return defaultASN // Pattern mismatch
				}
			}
			// Pattern matched — continue

		case instrDEFAULT:
			asn := decodeASN(&pos, asmap)
			if asn == asmapInvalid {
				return 0
			}
			defaultASN = asn

		default:
			// opcode == asmapInvalid (straddles EOF)
			return 0
		}
	}
	// Reached EOF without RETURN — should have been caught by SanityCheckAsmap
	return 0
}

// SanityCheckAsmap validates the entire asmap bytecode by simulating all
// possible execution paths, checking well-formedness and proper termination.
// bits is the number of IP address bits the trie is expected to consume (128
// for standard IPv6/IPv4-mapped use). Mirrors Core's SanityCheckAsmap().
func SanityCheckAsmap(asmap []byte, bitsLeft int) bool {
	pos := 0
	endpos := len(asmap) * 8
	type jumpEntry struct {
		offset int
		bits   int
	}
	jumps := make([]jumpEntry, 0, bitsLeft)
	prevOpcode := instrJUMP
	hadIncompleteMatch := false

	for pos != endpos {
		// Check that no queued jump has been passed
		if len(jumps) > 0 && pos >= jumps[len(jumps)-1].offset {
			return false
		}

		opcode := decodeType(&pos, asmap)
		switch opcode {
		case instrRETURN:
			// RETURN immediately after DEFAULT is wasteful (could be combined)
			if prevOpcode == instrDEFAULT {
				return false
			}
			asn := decodeASN(&pos, asmap)
			if asn == asmapInvalid {
				return false
			}
			if len(jumps) == 0 {
				// Final RETURN: check padding
				if endpos-pos > 7 {
					return false // Excessive padding
				}
				for pos != endpos {
					if consumeBitLE(&pos, asmap) {
						return false // Nonzero padding bit
					}
				}
				return true
			}
			// Continue at the queued jump target
			last := jumps[len(jumps)-1]
			if pos != last.offset {
				return false // Unreachable code between RETURN and jump target
			}
			bitsLeft = last.bits
			jumps = jumps[:len(jumps)-1]
			prevOpcode = instrJUMP

		case instrJUMP:
			jump := decodeJump(&pos, asmap)
			if jump == asmapInvalid {
				return false
			}
			if int64(jump) > int64(endpos-pos) {
				return false // Jump out of range
			}
			if bitsLeft == 0 {
				return false // Consuming bits past end of input
			}
			bitsLeft--
			jumpOffset := pos + int(jump)
			if len(jumps) > 0 && jumpOffset >= jumps[len(jumps)-1].offset {
				return false // Intersecting jumps
			}
			jumps = append(jumps, jumpEntry{jumpOffset, bitsLeft})
			prevOpcode = instrJUMP

		case instrMATCH:
			match := decodeMatch(&pos, asmap)
			if match == asmapInvalid {
				return false
			}
			matchlen := bits.Len32(match) - 1
			if prevOpcode != instrMATCH {
				hadIncompleteMatch = false
			}
			// Within a sequence of MATCHes, at most one may be < 8 bits
			if matchlen < 8 && hadIncompleteMatch {
				return false
			}
			hadIncompleteMatch = (matchlen < 8)
			if bitsLeft < matchlen {
				return false // Consuming bits past end of input
			}
			bitsLeft -= matchlen
			prevOpcode = instrMATCH

		case instrDEFAULT:
			// Two successive DEFAULTs could be combined into one
			if prevOpcode == instrDEFAULT {
				return false
			}
			asn := decodeASN(&pos, asmap)
			if asn == asmapInvalid {
				return false
			}
			prevOpcode = instrDEFAULT

		default:
			// opcode == asmapInvalid (straddles EOF)
			return false
		}
	}
	return false // Reached EOF without a RETURN instruction
}

// CheckStandardAsmap validates asmap data for standard 128-bit (IPv6) use.
// Returns true if SanityCheckAsmap passes for 128 bits. Mirrors Core's
// CheckStandardAsmap().
func CheckStandardAsmap(data []byte) bool {
	return SanityCheckAsmap(data, 128)
}

// LoadAsmap reads an asmap file from disk, enforces MaxAsmapFileSize, validates
// it with CheckStandardAsmap, and returns the raw bytes. Returns an error if
// the file cannot be read, exceeds the size limit, or fails validation.
// Mirrors Core's DecodeAsmap().
func LoadAsmap(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("asmap: stat %s: %w", path, err)
	}
	if fi.Size() > MaxAsmapFileSize {
		return nil, fmt.Errorf("asmap: file %s is %d bytes, exceeds MaxAsmapFileSize=%d", path, fi.Size(), MaxAsmapFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("asmap: read %s: %w", path, err)
	}
	if !CheckStandardAsmap(data) {
		return nil, fmt.Errorf("asmap: sanity check failed for %s — file may be corrupt or not an asmap binary", path)
	}
	return data, nil
}

// AsmapVersion computes a compact hex fingerprint of the asmap data for
// logging. Returns the first 8 hex chars of SHA256(data), or "" for empty
// input. Mirrors the intent of Core's AsmapVersion() (SHA256d checksum).
func AsmapVersion(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])[:8]
}

// GetMappedAS returns the ASN for the given IP by interpreting the asmap trie.
// ip must be a valid net.IP (v4 or v6). Returns 0 when asmap is nil/empty or
// when the IP has no entry in the trie. Mirrors Core's
// NetGroupManager::GetMappedAS().
func GetMappedAS(asmap []byte, ip net.IP) uint32 {
	if len(asmap) == 0 || ip == nil {
		return 0
	}
	ip16 := ip.To16()
	if ip16 == nil || len(ip16) != 16 {
		return 0
	}
	var key [16]byte
	copy(key[:], ip16)
	return Interpret(asmap, key)
}

// GetGroup returns the network-group bytes for eclipse-resistance bucketing.
// When asmap is loaded, returns [6, asn_byte0, asn_byte1, asn_byte2, asn_byte3]
// where 6 = NET_IPV6. When asmap is empty, falls back to the /16 prefix key
// returned as a string (unchanged legacy behaviour). The caller uses the ASN
// form for AddrMan bucket diversification (FIX-51). Mirrors Core's
// NetGroupManager::GetGroup().
//
// Note: this is not yet wired into AddrMan bucket hashing (deferred to FIX-51).
// It is used by GetMappedASForPeer for the getpeerinfo mapped_as field.
func GetGroup(asmap []byte, ip net.IP) []byte {
	if len(asmap) > 0 {
		asn := GetMappedAS(asmap, ip)
		if asn != 0 {
			// [NET_IPV6=6, asn as big-endian 4 bytes]
			return []byte{6, byte(asn >> 24), byte(asn >> 16), byte(asn >> 8), byte(asn)}
		}
	}
	// Fallback: /16 subnet prefix (IPv4) or first 4 bytes (IPv6)
	ipv4 := ip.To4()
	if ipv4 != nil {
		return []byte{4, ipv4[0], ipv4[1]}
	}
	ip16 := ip.To16()
	if ip16 != nil && len(ip16) >= 4 {
		return ip16[:4]
	}
	return nil
}
