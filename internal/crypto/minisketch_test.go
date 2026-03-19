package crypto

import (
	"bytes"
	"testing"
)

func TestMinisketch32Basic(t *testing.T) {
	// Test basic add and empty check
	sketch := NewMinisketch32(10)
	if !sketch.IsEmpty() {
		t.Error("new sketch should be empty")
	}

	sketch.Add(1)
	if sketch.IsEmpty() {
		t.Error("sketch should not be empty after add")
	}

	// Adding same element twice should cancel out (XOR property)
	sketch.Add(1)
	if !sketch.IsEmpty() {
		t.Error("adding same element twice should result in empty sketch")
	}
}

func TestMinisketch32SerializeDeserialize(t *testing.T) {
	sketch := NewMinisketch32(8)
	sketch.Add(100)
	sketch.Add(200)
	sketch.Add(300)

	data := sketch.Serialize()

	// Deserialize into new sketch
	sketch2 := NewMinisketch32(0)
	if err := sketch2.Deserialize(data); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	// Compare syndromes
	if len(sketch.syndromes) != len(sketch2.syndromes) {
		t.Errorf("syndrome count mismatch: %d vs %d", len(sketch.syndromes), len(sketch2.syndromes))
	}

	for i := range sketch.syndromes {
		if sketch.syndromes[i] != sketch2.syndromes[i] {
			t.Errorf("syndrome[%d] mismatch: %d vs %d", i, sketch.syndromes[i], sketch2.syndromes[i])
		}
	}
}

func TestMinisketch32Merge(t *testing.T) {
	// Set A = {1, 2, 3}
	sketchA := NewMinisketch32(10)
	sketchA.Add(1)
	sketchA.Add(2)
	sketchA.Add(3)

	// Set B = {2, 3, 4}
	sketchB := NewMinisketch32(10)
	sketchB.Add(2)
	sketchB.Add(3)
	sketchB.Add(4)

	// Merge: A XOR B = {1, 4} (symmetric difference)
	sketchA.Merge(sketchB)

	// Verify the symmetric difference sketch
	// Elements 2 and 3 should cancel out

	// Build a verification sketch with just 1 and 4
	expected := NewMinisketch32(10)
	expected.Add(1)
	expected.Add(4)

	// Syndromes should match
	for i := range sketchA.syndromes {
		if sketchA.syndromes[i] != expected.syndromes[i] {
			t.Errorf("merged syndrome[%d] = %d, expected %d", i, sketchA.syndromes[i], expected.syndromes[i])
		}
	}
}

func TestMinisketch32DecodeWithHint(t *testing.T) {
	// Set A = {1, 2, 3}
	sketchA := NewMinisketch32(10)
	sketchA.Add(1)
	sketchA.Add(2)
	sketchA.Add(3)

	// Set B = {2, 3, 4}
	sketchB := NewMinisketch32(10)
	sketchB.Add(2)
	sketchB.Add(3)
	sketchB.Add(4)

	// Compute symmetric difference
	diff := sketchA.Clone()
	diff.Merge(sketchB)

	// Decode with hint - provide all possible candidates
	candidates := []uint32{1, 2, 3, 4, 5, 6, 7, 8}
	result, err := diff.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Should find elements 1 and 4
	if len(result) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(result))
	}

	found := make(map[uint32]bool)
	for _, v := range result {
		found[v] = true
	}

	if !found[1] || !found[4] {
		t.Errorf("expected elements {1, 4}, got %v", result)
	}
}

func TestMinisketch32EmptyDifference(t *testing.T) {
	// Two identical sets should have empty difference
	sketchA := NewMinisketch32(10)
	sketchA.Add(1)
	sketchA.Add(2)
	sketchA.Add(3)

	sketchB := NewMinisketch32(10)
	sketchB.Add(1)
	sketchB.Add(2)
	sketchB.Add(3)

	diff := sketchA.Clone()
	diff.Merge(sketchB)

	if !diff.IsEmpty() {
		t.Error("symmetric difference of identical sets should be empty")
	}

	result, err := diff.DecodeWithHint([]uint32{1, 2, 3})
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestMinisketch32Clone(t *testing.T) {
	sketch := NewMinisketch32(5)
	sketch.Add(100)
	sketch.Add(200)

	clone := sketch.Clone()

	// Modify original
	sketch.Add(300)

	// Clone should be unaffected
	if len(clone.syndromes) != 5 {
		t.Error("clone capacity changed")
	}

	// Original and clone should now differ
	differ := false
	for i := range sketch.syndromes {
		if sketch.syndromes[i] != clone.syndromes[i] {
			differ = true
			break
		}
	}
	if !differ {
		t.Error("clone should be independent from original")
	}
}

func TestGF32Arithmetic(t *testing.T) {
	// Test multiplication identity
	if gf32Mul(1, 1) != 1 {
		t.Error("1 * 1 should be 1")
	}

	// Test multiplication by zero
	if gf32Mul(12345, 0) != 0 {
		t.Error("x * 0 should be 0")
	}

	// Test inverse: a * a^-1 = 1
	a := uint64(12345)
	aInv := gf32Inv(a)
	product := gf32Mul(a, aInv)
	if product != 1 {
		t.Errorf("a * a^-1 = %d, expected 1", product)
	}

	// Test another inverse
	b := uint64(0xDEADBEEF)
	bInv := gf32Inv(b)
	product = gf32Mul(b, bInv)
	if product != 1 {
		t.Errorf("b * b^-1 = %d, expected 1", product)
	}

	// Test division: a / b * b = a
	c := gf32Div(a, b)
	result := gf32Mul(c, b)
	if result != a&0xFFFFFFFF {
		t.Errorf("(a/b)*b = %d, expected %d", result, a)
	}
}

func TestErlaySalt(t *testing.T) {
	// Test salt computation is deterministic
	salt1 := uint64(0x1234567890ABCDEF)
	salt2 := uint64(0xFEDCBA0987654321)

	k0a, k1a := ComputeErlaySalt(salt1, salt2)
	k0b, k1b := ComputeErlaySalt(salt2, salt1) // Order reversed

	// Should produce same result regardless of order
	if k0a != k0b || k1a != k1b {
		t.Error("salt computation should be symmetric")
	}

	// Should produce non-zero keys
	if k0a == 0 && k1a == 0 {
		t.Error("salt computation should produce non-zero keys")
	}
}

func TestErlayShortID(t *testing.T) {
	k0, k1 := ComputeErlaySalt(0x1234, 0x5678)

	// Create a fake wtxid
	wtxid := make([]byte, 32)
	for i := range wtxid {
		wtxid[i] = byte(i)
	}

	// Compute short ID
	shortID := ErlayShortID(k0, k1, wtxid)

	// Should be deterministic
	shortID2 := ErlayShortID(k0, k1, wtxid)
	if shortID != shortID2 {
		t.Error("short ID should be deterministic")
	}

	// Different wtxid should produce different short ID (with high probability)
	wtxid2 := make([]byte, 32)
	for i := range wtxid2 {
		wtxid2[i] = byte(i + 100)
	}
	shortID3 := ErlayShortID(k0, k1, wtxid2)
	if shortID == shortID3 {
		t.Error("different wtxid should produce different short ID")
	}
}

func TestSipHash24(t *testing.T) {
	// Test vector from the SipHash paper
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)

	// Empty message
	h := siphash24Keys(k0, k1, []byte{})
	// Note: We don't have the exact expected value, just verify it runs

	// With a message
	msg := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	h = siphash24Keys(k0, k1, msg)
	if h == 0 {
		t.Error("siphash should produce non-zero result for non-trivial input")
	}

	// Same input should give same result
	h2 := siphash24Keys(k0, k1, msg)
	if h != h2 {
		t.Error("siphash should be deterministic")
	}
}

func TestMinisketch32SerializedSize(t *testing.T) {
	sketch := NewMinisketch32(16)
	expected := 16 * 4 // 16 syndromes * 4 bytes each
	if sketch.SerializedSize() != expected {
		t.Errorf("serialized size = %d, expected %d", sketch.SerializedSize(), expected)
	}
}

func TestMinisketch32FP(t *testing.T) {
	// Test the false-positive based constructor
	sketch := NewMinisketch32FP(10, 16)

	// Should have at least enough capacity for 10 elements + FP margin
	if sketch.Capacity() < 10 {
		t.Errorf("capacity should be at least 10, got %d", sketch.Capacity())
	}
}

func TestMinisketch32InvalidDeserialize(t *testing.T) {
	sketch := NewMinisketch32(8)

	// Invalid size (not multiple of 4)
	err := sketch.Deserialize([]byte{1, 2, 3})
	if err != ErrInvalidSketchSize {
		t.Errorf("expected ErrInvalidSketchSize, got %v", err)
	}
}

func TestMinisketch32SingleElement(t *testing.T) {
	// Test decode with single element
	sketch := NewMinisketch32(5)
	sketch.Add(42)

	candidates := []uint32{1, 2, 42, 100, 200}
	result, err := sketch.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(result) != 1 || result[0] != 42 {
		t.Errorf("expected [42], got %v", result)
	}
}

func TestMinisketch32ThreeElements(t *testing.T) {
	// Set A = {1, 2, 3, 4, 5}
	sketchA := NewMinisketch32(10)
	sketchA.Add(1)
	sketchA.Add(2)
	sketchA.Add(3)
	sketchA.Add(4)
	sketchA.Add(5)

	// Set B = {3, 4, 5, 6, 7}
	sketchB := NewMinisketch32(10)
	sketchB.Add(3)
	sketchB.Add(4)
	sketchB.Add(5)
	sketchB.Add(6)
	sketchB.Add(7)

	// Symmetric difference = {1, 2, 6, 7}
	diff := sketchA.Clone()
	diff.Merge(sketchB)

	candidates := []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	result, err := diff.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(result) != 4 {
		t.Fatalf("expected 4 elements, got %d: %v", len(result), result)
	}

	found := make(map[uint32]bool)
	for _, v := range result {
		found[v] = true
	}

	for _, expected := range []uint32{1, 2, 6, 7} {
		if !found[expected] {
			t.Errorf("expected element %d in result", expected)
		}
	}
}

func BenchmarkMinisketch32Add(b *testing.B) {
	sketch := NewMinisketch32(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sketch.Add(uint32(i))
	}
}

func BenchmarkMinisketch32Merge(b *testing.B) {
	sketch1 := NewMinisketch32(32)
	sketch2 := NewMinisketch32(32)
	for i := 0; i < 100; i++ {
		sketch1.Add(uint32(i))
		sketch2.Add(uint32(i + 50))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := sketch1.Clone()
		s.Merge(sketch2)
	}
}

func BenchmarkErlayShortID(b *testing.B) {
	k0, k1 := ComputeErlaySalt(12345, 67890)
	wtxid := make([]byte, 32)
	for i := range wtxid {
		wtxid[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ErlayShortID(k0, k1, wtxid)
	}
}

func BenchmarkGF32Mul(b *testing.B) {
	a := uint64(0x12345678)
	c := uint64(0x87654321)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gf32Mul(a, c)
	}
}

func BenchmarkGF32Inv(b *testing.B) {
	a := uint64(0x12345678)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gf32Inv(a)
	}
}

func TestMinisketch32Roundtrip(t *testing.T) {
	// Test serialize/deserialize preserves sketch behavior
	original := NewMinisketch32(8)
	original.Add(111)
	original.Add(222)
	original.Add(333)

	data := original.Serialize()

	restored := NewMinisketch32(0)
	if err := restored.Deserialize(data); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	// Both should decode to same result
	candidates := []uint32{111, 222, 333, 444}

	result1, err := original.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode original failed: %v", err)
	}

	result2, err := restored.DecodeWithHint(candidates)
	if err != nil {
		t.Fatalf("decode restored failed: %v", err)
	}

	if len(result1) != len(result2) {
		t.Fatalf("results have different lengths: %d vs %d", len(result1), len(result2))
	}

	// Results should match (same elements)
	found1 := make(map[uint32]bool)
	found2 := make(map[uint32]bool)
	for _, v := range result1 {
		found1[v] = true
	}
	for _, v := range result2 {
		found2[v] = true
	}

	for k := range found1 {
		if !found2[k] {
			t.Errorf("element %d in original but not restored", k)
		}
	}
	for k := range found2 {
		if !found1[k] {
			t.Errorf("element %d in restored but not original", k)
		}
	}
}

func TestSaltComputation(t *testing.T) {
	// Verify the tagged hash structure
	// The salt should be computed as:
	// SHA256(SHA256("Tx Relay Salting") || SHA256("Tx Relay Salting") || min(s1,s2) || max(s1,s2))

	salt1 := uint64(100)
	salt2 := uint64(200)

	k0a, k1a := ComputeErlaySalt(salt1, salt2)
	k0b, k1b := ComputeErlaySalt(salt2, salt1)

	// Must be order-independent
	if k0a != k0b || k1a != k1b {
		t.Errorf("salt computation must be order independent")
	}

	// Same salts should produce same result
	k0c, k1c := ComputeErlaySalt(salt1, salt2)
	if k0a != k0c || k1a != k1c {
		t.Errorf("salt computation must be deterministic")
	}
}

func TestMinisketch32ZeroElement(t *testing.T) {
	// Zero is the identity element and should be skipped
	sketch := NewMinisketch32(5)
	sketch.Add(0)

	if !sketch.IsEmpty() {
		t.Error("adding zero should not affect the sketch")
	}
}

func TestSerializedDataMatches(t *testing.T) {
	// Create two sketches with same content
	sketch1 := NewMinisketch32(4)
	sketch1.Add(1)
	sketch1.Add(2)

	sketch2 := NewMinisketch32(4)
	sketch2.Add(1)
	sketch2.Add(2)

	data1 := sketch1.Serialize()
	data2 := sketch2.Serialize()

	if !bytes.Equal(data1, data2) {
		t.Error("identical sketches should serialize identically")
	}
}
