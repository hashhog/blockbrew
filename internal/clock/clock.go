// Package clock is blockbrew's NodeClock: wall-clock time that the
// regtest-only setmocktime RPC can pin, as Bitcoin Core's SetMockTime does.
package clock

import (
	"sync/atomic"
	"time"
)

var mockUnix atomic.Int64 // seconds since epoch; 0 = not mocked

// SetMock pins the clock to sec seconds since the epoch; 0 restores the wall
// clock (Core: SetMockTime(0)).
func SetMock(sec int64) { mockUnix.Store(sec) }

// Mock returns the pinned time, or 0 when unpinned.
func Mock() int64 { return mockUnix.Load() }

// Now returns the mocked time when pinned, else time.Now().
func Now() time.Time {
	if m := mockUnix.Load(); m != 0 {
		return time.Unix(m, 0)
	}
	return time.Now()
}

// Unix is Now().Unix().
func Unix() int64 { return Now().Unix() }
