package consensus

import (
	"log"
	"net/http"
	"net/http/pprof"
	"runtime"
	"time"
)

// Timeouts for the node's side HTTP listeners (metrics, pprof). Without them
// a client that half-sends a request holds an fd and a goroutine forever
// (security audit 2026-10-30, H3/M2).
const (
	SideHTTPReadHeaderTimeout = 5 * time.Second
	SideHTTPReadTimeout       = 10 * time.Second
	SideHTTPWriteTimeout      = 10 * time.Second
	SideHTTPIdleTimeout       = 30 * time.Second

	// pprof streams CPU profiles and traces for ?seconds=N (default 30), and
	// net/http/pprof refuses any N at or above the server's WriteTimeout, so
	// the pprof server gets a longer write window than the metrics server.
	pprofWriteTimeout = 120 * time.Second
)

// NewSideHTTPServer returns an http.Server for addr with the side-listener
// timeouts applied.
func NewSideHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: SideHTTPReadHeaderTimeout,
		ReadTimeout:       SideHTTPReadTimeout,
		WriteTimeout:      SideHTTPWriteTimeout,
		IdleTimeout:       SideHTTPIdleTimeout,
	}
}

// profileMux serves the pprof handlers on a dedicated mux, so nothing else
// registered on http.DefaultServeMux is exposed through the pprof port.
func profileMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// StartProfileServer starts the pprof HTTP server on the given address.
// Access profiles at:
//   - http://addr/debug/pprof/              - index of available profiles
//   - http://addr/debug/pprof/heap          - heap profile
//   - http://addr/debug/pprof/goroutine     - goroutine profile
//   - http://addr/debug/pprof/profile?seconds=30 - CPU profile
//   - http://addr/debug/pprof/trace?seconds=5    - execution trace
func StartProfileServer(addr string) {
	srv := NewSideHTTPServer(addr, profileMux())
	srv.WriteTimeout = pprofWriteTimeout
	go func() {
		log.Printf("pprof server listening on %s", addr)
		log.Printf("  CPU profile: go tool pprof http://%s/debug/pprof/profile?seconds=30", addr)
		log.Printf("  Heap profile: go tool pprof http://%s/debug/pprof/heap", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("pprof server error: %v", err)
		}
	}()
}

// RuntimeMetrics contains current Go runtime statistics.
type RuntimeMetrics struct {
	Alloc         uint64 // Bytes allocated and still in use
	TotalAlloc    uint64 // Bytes allocated (ever)
	Sys           uint64 // Bytes obtained from system
	NumGC         uint32 // Number of GC cycles
	NumGoroutines int    // Current number of goroutines
	HeapObjects   uint64 // Number of allocated heap objects
	HeapInuse     uint64 // Bytes in in-use heap spans
	StackInuse    uint64 // Bytes in stack spans
}

// GetRuntimeMetrics reads current runtime statistics.
func GetRuntimeMetrics() RuntimeMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return RuntimeMetrics{
		Alloc:         m.Alloc,
		TotalAlloc:    m.TotalAlloc,
		Sys:           m.Sys,
		NumGC:         m.NumGC,
		NumGoroutines: runtime.NumGoroutine(),
		HeapObjects:   m.HeapObjects,
		HeapInuse:     m.HeapInuse,
		StackInuse:    m.StackInuse,
	}
}

// LogRuntimeMetrics logs current runtime memory and goroutine statistics.
func LogRuntimeMetrics() {
	m := GetRuntimeMetrics()
	log.Printf("Memory: Alloc=%dMB TotalAlloc=%dMB Sys=%dMB NumGC=%d",
		m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	log.Printf("Heap: Objects=%d InUse=%dMB Stack=%dMB Goroutines=%d",
		m.HeapObjects, m.HeapInuse/1024/1024, m.StackInuse/1024/1024, m.NumGoroutines)
}

// PerformanceStats collects performance-related statistics.
type PerformanceStats struct {
	RuntimeMetrics RuntimeMetrics
	UTXOCacheStats UTXOCacheStats
}

// GetPerformanceStats collects all performance statistics.
func GetPerformanceStats(utxoSet *UTXOSet) PerformanceStats {
	stats := PerformanceStats{
		RuntimeMetrics: GetRuntimeMetrics(),
	}
	if utxoSet != nil {
		stats.UTXOCacheStats = utxoSet.Stats()
	}
	return stats
}
