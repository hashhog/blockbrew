package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/clock"
	"github.com/hashhog/blockbrew/internal/consensus"
)

func TestSetMockTimeRegtest(t *testing.T) {
	defer clock.SetMock(0)
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithChainParams(consensus.RegtestParams()))

	res, rerr := s.dispatch("setmocktime", json.RawMessage(`[1700000000]`), "")
	if rerr != nil || res != nil {
		t.Fatalf("setmocktime: res=%v err=%+v (Core returns null)", res, rerr)
	}
	if got := clock.Unix(); got != 1700000000 {
		t.Fatalf("clock = %d, want 1700000000", got)
	}
	if _, rerr = s.dispatch("setmocktime", json.RawMessage(`[-1]`), ""); rerr == nil || rerr.Code != RPCErrInvalidParameter {
		t.Fatalf("negative: %+v, want -8", rerr)
	}
	if _, rerr = s.dispatch("setmocktime", json.RawMessage(`[]`), ""); rerr == nil || rerr.Code != RPCErrInvalidParameter {
		t.Fatalf("missing arg: %+v, want -8", rerr)
	}
	if _, rerr = s.dispatch("setmocktime", json.RawMessage(`[0]`), ""); rerr != nil {
		t.Fatalf("reset: %+v", rerr)
	}
	if clock.Mock() != 0 {
		t.Fatalf("mock not cleared")
	}
}

func TestSetMockTimeRefusedOutsideRegtest(t *testing.T) {
	defer clock.SetMock(0)
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithChainParams(consensus.MainnetParams()))
	_, rerr := s.dispatch("setmocktime", json.RawMessage(`[1700000000]`), "")
	if rerr == nil || rerr.Code != RPCErrMisc {
		t.Fatalf("mainnet: %+v, want -1", rerr)
	}
	if clock.Mock() != 0 {
		t.Fatalf("mainnet setmocktime changed the clock")
	}
}
