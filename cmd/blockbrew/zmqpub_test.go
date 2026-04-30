package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-zeromq/zmq4"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestZMQPublisherDisabledIsNoop verifies the pub no-ops when no flags are set.
func TestZMQPublisherDisabledIsNoop(t *testing.T) {
	pub := newZMQPublisher(zmqPublisherConfig{})
	if err := pub.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	pub.PublishBlockConnected(&wire.MsgBlock{}, 0)
	pub.PublishTxAccepted(&wire.MsgTx{})
	pub.Stop()
	pub.Stop() // idempotent
}

func TestNormalizeZMQAddr(t *testing.T) {
	cases := []struct {
		in    string
		out   string
		isErr bool
	}{
		{"tcp://127.0.0.1:28332", "tcp://127.0.0.1:28332", false},
		{"ipc:///tmp/blockbrew.zmq", "ipc:///tmp/blockbrew.zmq", false},
		{"127.0.0.1:28332", "tcp://127.0.0.1:28332", false},
		{"", "", true},
		{"badformat", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeZMQAddr(c.in)
			if c.isErr && err == nil {
				t.Errorf("%q: expected error, got %q", c.in, got)
			}
			if !c.isErr && err != nil {
				t.Errorf("%q: unexpected error: %v", c.in, err)
			}
			if !c.isErr && got != c.out {
				t.Errorf("%q -> %q, want %q", c.in, got, c.out)
			}
		})
	}
}

// TestZMQPublishHashBlockEndToEnd binds a real PUB socket, connects a
// SUB consumer, fires a block-connect, and verifies the consumer
// receives the topic + 32-byte hash. Skipped under -short.
func TestZMQPublishHashBlockEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping zmq end-to-end test in -short mode")
	}
	port, err := pickEphemeralPort()
	if err != nil {
		t.Fatalf("pickEphemeralPort: %v", err)
	}
	addr := "tcp://127.0.0.1:" + strconv.Itoa(port)
	pub := newZMQPublisher(zmqPublisherConfig{HashBlock: addr})
	if err := pub.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pub.Stop()

	// SUB consumer.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sub := zmq4.NewSub(ctx)
	if err := sub.Dial(addr); err != nil {
		t.Fatalf("sub dial: %v", err)
	}
	defer sub.Close()
	if err := sub.SetOption(zmq4.OptionSubscribe, "hashblock"); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Publishers need a moment for the subscription handshake.
	time.Sleep(100 * time.Millisecond)

	// Send a block. We construct a minimal MsgBlock; the hash is whatever
	// BlockHash() returns for a zero header — fine for this test.
	block := &wire.MsgBlock{}

	var got zmq4.Msg
	var wg sync.WaitGroup
	wg.Add(1)
	gotCh := make(chan zmq4.Msg, 1)
	go func() {
		defer wg.Done()
		// Retry recv a few times: ZMQ subscription propagation is async.
		for i := 0; i < 20; i++ {
			pub.PublishBlockConnected(block, 1)
			m, err := sub.Recv()
			if err == nil {
				gotCh <- m
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	select {
	case got = <-gotCh:
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for hashblock message")
	}
	wg.Wait()

	if len(got.Frames) != 3 {
		t.Fatalf("expected 3 frames (topic, body, seq); got %d", len(got.Frames))
	}
	if string(got.Frames[0]) != "hashblock" {
		t.Errorf("frame 0 = %q, want %q", got.Frames[0], "hashblock")
	}
	if len(got.Frames[1]) != 32 {
		t.Errorf("frame 1 length = %d, want 32 (block hash)", len(got.Frames[1]))
	}
	if len(got.Frames[2]) != 4 {
		t.Errorf("frame 2 length = %d, want 4 (LE u32 sequence)", len(got.Frames[2]))
	}
}

func pickEphemeralPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr := l.Addr().String()
	_, p, _ := strings.Cut(addr, ":")
	return strconv.Atoi(p)
}
