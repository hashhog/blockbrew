package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// daemonEnvFlag is the env-var marker we set on the child process to tell
// it "you're the detached daemon, don't try to fork again".  Mirrors the
// established re-exec pattern used by Caddy, Docker, and other Go
// daemons. We can't use the C `daemon(3)` call because the Go runtime
// has already started threads by main().
const daemonEnvFlag = "BLOCKBREW_DAEMONIZED"

// daemonize forks the current process into the background and returns
// from the parent immediately (the parent exits 0).  The child re-execs
// itself with the same argv but with daemonEnvFlag set so it knows to
// continue main() rather than re-fork.  The parent waits up to
// `pidWaitTimeout` for the child to write `pidPath` so it can be sure
// the child got far enough to be useful before exiting; on timeout the
// parent still exits 0 (matching Core, which also doesn't block on full
// init) but emits a warning to stderr.
//
// pidPath may be empty, in which case the parent exits as soon as the
// child is started — matching Bitcoin Core's `-daemon -pid=` behaviour.
//
// This function returns only in the child (with daemonEnvFlag set).
// The parent calls os.Exit before returning.
func daemonize(pidPath string, pidWaitTimeout time.Duration) {
	if os.Getenv(daemonEnvFlag) == "1" {
		// We are the child. Detach from controlling terminal so signals
		// to the parent's TTY don't kill us, and redirect std fds to
		// /dev/null so we don't write to a possibly-closed parent stdout.
		if err := detachStdio(); err != nil {
			// Non-fatal — we can run with whatever fds we inherited.
			fmt.Fprintf(os.Stderr, "blockbrew: warning: detachStdio: %v\n", err)
		}
		// Become a session leader so we're not killed by SIGHUP when the
		// parent's TTY closes.
		if _, err := syscall.Setsid(); err != nil {
			// Already a session leader (or kernel disallowed): ignore.
			_ = err
		}
		return
	}

	// We are the parent. Build argv from os.Args[0] (the resolved
	// binary path) and inherit args verbatim.  We cannot rely on
	// os.Executable() because it may resolve to a different path
	// after exec on some platforms (Linux is fine, but we want
	// reproducible behaviour cross-platform).
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = os.Args[0]
	}

	// Strip -daemon so the child doesn't recurse if the env var is
	// somehow lost. The leading flag could be `-daemon`, `--daemon`,
	// or `-daemon=true` etc; just match the prefix.
	args := stripDaemonFlag(os.Args[1:])

	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), daemonEnvFlag+"=1")
	// We deliberately do NOT inherit stdin; the parent's stdin may be
	// a terminal that closes on parent exit. stdout/stderr are routed
	// through detachStdio in the child.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// Place child in its own session so it survives parent exit.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "blockbrew: failed to start daemon child: %v\n", err)
		os.Exit(1)
	}

	// Optionally wait for the pid file to appear so callers downstream
	// of `blockbrew -daemon` (e.g. `start_mainnet.sh`) can immediately
	// look up the pid. Best-effort; on timeout we still exit 0 since
	// the child is alive and starting up.
	if pidPath != "" && pidWaitTimeout > 0 {
		deadline := time.Now().Add(pidWaitTimeout)
		for time.Now().Before(deadline) {
			if pid, err := readPidFile(pidPath); err == nil && pid == cmd.Process.Pid {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	fmt.Fprintf(os.Stdout, "Blockbrew daemon started (pid=%d)\n", cmd.Process.Pid)
	os.Exit(0)
}

// detachStdio replaces the calling process's stdin/stdout/stderr with
// `/dev/null`, matching the convention `daemon(3)` follows. Errors are
// returned but only the first one — we attempt all three regardless.
func detachStdio() error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	// We deliberately DO NOT close `null` here; Dup2-equivalent calls
	// below replace fds 0/1/2 with copies of `null`, then we close `null`.
	defer null.Close()

	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())
	stderrFd := int(os.Stderr.Fd())
	nullFd := int(null.Fd())

	// On Linux Dup3 is the cleanest, but Dup2 is portable enough.
	if err := syscall.Dup2(nullFd, stdinFd); err != nil {
		return err
	}
	if err := syscall.Dup2(nullFd, stdoutFd); err != nil {
		return err
	}
	if err := syscall.Dup2(nullFd, stderrFd); err != nil {
		return err
	}
	return nil
}

// stripDaemonFlag returns args with any token whose name (after stripping
// leading dashes) equals "daemon" removed. Recognises both
// "-daemon" / "--daemon" (boolean) and "-daemon=true" / "-daemon=false".
// We unconditionally strip the flag from the child's argv to defend
// against a runaway re-fork chain in case the env var was clobbered.
func stripDaemonFlag(args []string) []string {
	out := make([]string, 0, len(args))
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		// "-daemon=value" form: keep nothing.
		if a == "-daemon" || a == "--daemon" {
			continue
		}
		if hasDaemonPrefix(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func hasDaemonPrefix(a string) bool {
	for _, p := range []string{"-daemon=", "--daemon="} {
		if len(a) >= len(p) && a[:len(p)] == p {
			return true
		}
	}
	return false
}

// pidWaitTimeoutDefault is exposed so tests can shorten the parent wait
// without redefining the function signature.
var pidWaitTimeoutDefault = 5 * time.Second

// pidString is a tiny helper used by callers that want to log the
// child's pid before the file is written.
func pidString(pid int) string { return strconv.Itoa(pid) }
