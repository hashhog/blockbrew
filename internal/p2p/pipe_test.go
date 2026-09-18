package p2p

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// pipeHandshakeBudget is the explicit wait for net.Pipe handshake fixtures
// and for tests that must observe an async side-effect (listener, ping
// latency, disconnect). It is a backstop, not a sleep: the pipe unblocks
// on Close, and the waiter returns as soon as the condition is true.
const pipeHandshakeBudget = 15 * time.Second

// pipeClosed reports the expected error when the far end of a net.Pipe
// hangs up. Handshake fixtures must treat this as success after version
// and verack have been exchanged; failing the test on it is a race
// against Peer.Disconnect.
func pipeClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return pipeClosed(op.Err)
	}
	return false
}

// writePipeMessage writes msg and treats a hangup as success: the peer
// may Disconnect as soon as it has parsed our verack header, which
// races a trailing payload write on net.Pipe.
func writePipeMessage(conn net.Conn, magic uint32, msg Message) error {
	err := WriteMessage(conn, magic, msg)
	if pipeClosed(err) {
		return nil
	}
	return err
}

// pipeSession is a concurrent reader on one end of a net.Pipe.
// net.Pipe is synchronous and full-duplex: if both ends Write without a
// reader, both block forever. The reader must run for the lifetime of
// the fixture, with no read deadline — Close is what unblocks it.
type pipeSession struct {
	msgs <-chan Message
	done <-chan error
}

func servePipe(conn net.Conn, magic uint32) *pipeSession {
	msgs := make(chan Message, 64)
	done := make(chan error, 1)
	go func() {
		defer close(msgs)
		for {
			msg, err := ReadMessage(conn, magic)
			if err != nil {
				if pipeClosed(err) {
					done <- nil
				} else {
					done <- err
				}
				return
			}
			select {
			case msgs <- msg:
			default:
				// Buffer full: keep reading so the far writeHandler
				// cannot deadlock. Handshake waiters see the first
				// few messages, which is all they need.
			}
		}
	}()
	return &pipeSession{msgs: msgs, done: done}
}

func (s *pipeSession) waitMessage(timeout time.Duration, match func(Message) bool) (Message, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case msg, ok := <-s.msgs:
			if !ok {
				return nil, errors.New("pipe closed before expected message")
			}
			if match(msg) {
				return msg, nil
			}
		case <-timer.C:
			return nil, errors.New("timeout waiting for pipe message")
		}
	}
}

func (s *pipeSession) waitClose(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-s.done:
		return err
	case <-timer.C:
		return errors.New("timeout waiting for pipe close")
	}
}

func waitUntil(t *testing.T, timeout time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if pred() {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("condition not met within %s", timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
