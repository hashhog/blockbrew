package main

import (
	"reflect"
	"testing"
)

func TestStripDaemonFlag(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		out  []string
	}{
		{"no daemon", []string{"-network", "mainnet"}, []string{"-network", "mainnet"}},
		{"plain -daemon", []string{"-daemon", "-rpcuser=x"}, []string{"-rpcuser=x"}},
		{"plain --daemon", []string{"--daemon", "-rpcuser=x"}, []string{"-rpcuser=x"}},
		{"-daemon=true", []string{"-daemon=true", "-rpcuser=x"}, []string{"-rpcuser=x"}},
		{"--daemon=false", []string{"--daemon=false", "-rpcuser=x"}, []string{"-rpcuser=x"}},
		{"keep similar", []string{"-daemonize=1"}, []string{"-daemonize=1"}}, // not -daemon
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripDaemonFlag(c.in)
			if !reflect.DeepEqual(got, c.out) {
				t.Errorf("stripDaemonFlag(%v) = %v, want %v", c.in, got, c.out)
			}
		})
	}
}

func TestHasDaemonPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"-daemon=true", true},
		{"--daemon=false", true},
		{"-daemon", false},  // exact match handled separately
		{"-daemonize", false}, // unrelated flag
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := hasDaemonPrefix(c.in); got != c.want {
				t.Errorf("hasDaemonPrefix(%q) = %v want %v", c.in, got, c.want)
			}
		})
	}
}
