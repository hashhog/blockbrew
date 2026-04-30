package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// sdNotify sends a status payload to systemd's notify socket if NOTIFY_SOCKET
// is set. Returns true if the message was successfully sent.  Mirrors the
// behaviour of `systemd-notify --status=` and the
// `coreos/go-systemd/daemon.SdNotify` helper, but implemented inline so we
// don't depend on an external library.
//
// The payload is a newline-separated list of `KEY=VALUE` lines:
//   - READY=1                  service has finished initialisation
//   - STATUS=<text>            free-form status string
//   - STOPPING=1               graceful shutdown begun
//   - WATCHDOG=1               watchdog ping (only if WATCHDOG_USEC set)
//
// We intentionally allow the caller to pass the full multi-line string so
// they can combine READY=1 with STATUS=... in a single send (matches
// systemd's documented behaviour: each datagram is parsed atomically).
func sdNotify(state string) (bool, error) {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return false, nil
	}
	// systemd uses unix datagram sockets. Path may be either an
	// absolute filesystem path or, if it starts with '@', an abstract
	// socket whose name is the rest of the string with a leading NUL.
	addr := &net.UnixAddr{Net: "unixgram"}
	if strings.HasPrefix(socketPath, "@") {
		addr.Name = "\x00" + socketPath[1:]
	} else {
		addr.Name = socketPath
	}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return false, fmt.Errorf("dial notify socket: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("write notify socket: %w", err)
	}
	return true, nil
}

// notifyReady sends READY=1 + STATUS=<msg> to systemd. Convenience
// wrapper around sdNotify; logs on failure but does not return error
// (the node is still functional even without sd_notify).
func notifyReady(status string) {
	payload := "READY=1\nSTATUS=" + status + "\n"
	ok, err := sdNotify(payload)
	if err != nil {
		// Don't spam: NOTIFY_SOCKET unset is the common case.
		return
	}
	if ok {
		// Logged at the call site so the line ordering with the
		// surrounding "started successfully" message is preserved.
		_ = err
	}
}

// notifyStatus sends STATUS=<msg> to systemd. Used for periodic IBD
// progress updates (height, peer count) so `systemctl status blockbrew`
// shows useful info.
func notifyStatus(status string) {
	_, _ = sdNotify("STATUS=" + status + "\n")
}

// notifyStopping signals graceful shutdown to systemd so it stops
// counting against TimeoutStopSec.
func notifyStopping() {
	_, _ = sdNotify("STOPPING=1\nSTATUS=shutting down\n")
}

// watchdogInterval reads WATCHDOG_USEC from systemd and returns half
// of that as the recommended ping interval. Returns zero if the var
// is unset or invalid (no watchdog configured).
func watchdogInterval() time.Duration {
	v := os.Getenv("WATCHDOG_USEC")
	if v == "" {
		return 0
	}
	usec, err := strconv.ParseInt(v, 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	// systemd recommends pinging at half the configured interval so
	// missed pings don't trigger a false-positive restart.
	return time.Duration(usec) * time.Microsecond / 2
}

// notifyWatchdog sends a single WATCHDOG=1 ping. Cheap; safe to call
// from a ticker goroutine.
func notifyWatchdog() {
	_, _ = sdNotify("WATCHDOG=1\n")
}
