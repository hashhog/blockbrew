package main

import "testing"

func TestParseExternalIP(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port uint16
		err  bool
	}{
		{"1.2.3.4", "1.2.3.4", 0, false},
		{"1.2.3.4:8455", "1.2.3.4", 8455, false},
		{"2001:db8::1", "2001:db8::1", 0, false},
		{"[2001:db8::1]", "2001:db8::1", 0, false},
		{"[2001:db8::1]:8455", "2001:db8::1", 8455, false},
		{"example.com", "", 0, true},
		{"1.2.3.4:0", "", 0, true},
		{"1.2.3.4:99999", "", 0, true},
	}
	for _, c := range cases {
		ip, port, err := parseExternalIP(c.in)
		if (err != nil) != c.err {
			t.Errorf("%q: err=%v, want err=%v", c.in, err, c.err)
			continue
		}
		if !c.err && (ip.String() != c.ip || port != c.port) {
			t.Errorf("%q: got %s:%d, want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}
