package clock

import (
	"testing"
	"time"
)

func TestMockPinsAndResets(t *testing.T) {
	defer SetMock(0)
	SetMock(1_700_000_000)
	if Unix() != 1_700_000_000 {
		t.Fatalf("mocked Unix = %d", Unix())
	}
	SetMock(0)
	if d := time.Now().Unix() - Unix(); d < -1 || d > 1 {
		t.Fatalf("unmocked clock off wall clock by %d", d)
	}
}
