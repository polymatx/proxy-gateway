package proxyproto

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func mustTrusted(t *testing.T, spec string) []*net.IPNet {
	t.Helper()
	n, err := ParseTrusted(spec)
	if err != nil {
		t.Fatalf("ParseTrusted(%q): %v", spec, err)
	}
	return n
}

// serve wires a listener on loopback and returns its address plus a stop func.
func serve(t *testing.T, trusted []*net.IPNet, handle func(net.Conn)) (string, func()) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := NewListener(inner, trusted)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return inner.Addr().String(), func() { inner.Close(); <-done }
}

// The whole point: a header from a trusted peer names the real client.
func TestV1HeaderFromTrustedPeerIsHonoured(t *testing.T) {
	type result struct {
		ip   string
		body string
	}
	results := make(chan result, 1)

	addr, stop := serve(t, mustTrusted(t, "127.0.0.1"), func(c net.Conn) {
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		ip, _ := RealClientIPFromContext(WithConn(context.Background(), c))
		results <- result{ip: ip, body: strings.TrimSpace(line)}
	})
	defer stop()

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	io.WriteString(client, "PROXY TCP4 198.51.100.7 10.0.0.1 51234 31000\r\nCONNECT example.com:443\n")

	select {
	case r := <-results:
		if r.ip != "198.51.100.7" {
			t.Errorf("client ip = %q, want 198.51.100.7", r.ip)
		}
		if r.body != "CONNECT example.com:443" {
			t.Errorf("stream after header = %q; the header must be consumed and nothing else", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}

// A header from anyone else is an assertion we have no reason to believe.
// Honouring it would let any client forge its own address in traffic_logs.
func TestHeaderFromUntrustedPeerIsIgnored(t *testing.T) {
	type result struct {
		ip   string
		body string
	}
	results := make(chan result, 1)

	// Trust a network the loopback client is not in.
	addr, stop := serve(t, mustTrusted(t, "203.0.113.0/24"), func(c net.Conn) {
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		ip, _ := RealClientIPFromContext(WithConn(context.Background(), c))
		results <- result{ip: ip, body: strings.TrimSpace(line)}
	})
	defer stop()

	client, _ := net.Dial("tcp", addr)
	defer client.Close()
	io.WriteString(client, "PROXY TCP4 198.51.100.7 10.0.0.1 51234 31000\r\n")

	select {
	case r := <-results:
		if r.ip != "" {
			t.Errorf("forged header was honoured: got client ip %q, want none", r.ip)
		}
		if !strings.HasPrefix(r.body, "PROXY ") {
			t.Errorf("stream was modified for an untrusted peer: %q", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}

// Deployable before the relay is switched over: no header must behave exactly
// as today.
func TestNoHeaderPassesThroughUntouched(t *testing.T) {
	bodies := make(chan string, 1)
	addr, stop := serve(t, mustTrusted(t, "127.0.0.1"), func(c net.Conn) {
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		bodies <- strings.TrimSpace(line)
	})
	defer stop()

	client, _ := net.Dial("tcp", addr)
	defer client.Close()
	io.WriteString(client, "CONNECT example.com:443\n")

	select {
	case got := <-bodies:
		if got != "CONNECT example.com:443" {
			t.Errorf("stream = %q, want it untouched", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}

func TestParseV1(t *testing.T) {
	for _, tc := range []struct {
		name, header, wantIP string
		wantErr              bool
	}{
		{name: "tcp4", header: "PROXY TCP4 198.51.100.7 10.0.0.1 5 6\r\n", wantIP: "198.51.100.7"},
		{name: "tcp6", header: "PROXY TCP6 2001:db8::1 2001:db8::2 5 6\r\n", wantIP: "2001:db8::1"},
		{name: "unknown yields no address", header: "PROXY UNKNOWN\r\n"},
		{name: "family mismatch", header: "PROXY TCP4 2001:db8::1 10.0.0.1 5 6\r\n", wantErr: true},
		{name: "bad source ip", header: "PROXY TCP4 not-an-ip 10.0.0.1 5 6\r\n", wantErr: true},
		{name: "bad port", header: "PROXY TCP4 198.51.100.7 10.0.0.1 99999 6\r\n", wantErr: true},
		{name: "too few fields", header: "PROXY TCP4 198.51.100.7\r\n", wantErr: true},
		{name: "bare LF", header: "PROXY TCP4 198.51.100.7 10.0.0.1 5 6\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := parseV1(bufio.NewReader(strings.NewReader(tc.header)))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got addr %v", addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantIP == "" {
				if addr != nil {
					t.Fatalf("expected no address, got %v", addr)
				}
				return
			}
			host, _, _ := net.SplitHostPort(addr.String())
			if host != tc.wantIP {
				t.Fatalf("ip = %q, want %q", host, tc.wantIP)
			}
		})
	}
}

// A v2 header must be refused outright: skipping it would leave its binary
// body in the stream and corrupt the request that follows.
func TestV2HeaderIsRefused(t *testing.T) {
	errs := make(chan error, 1)
	addr, stop := serve(t, mustTrusted(t, "127.0.0.1"), func(c net.Conn) {
		defer c.Close()
		_, err := c.Read(make([]byte, 16))
		errs <- err
	})
	defer stop()

	client, _ := net.Dial("tcp", addr)
	defer client.Close()
	client.Write(append(append([]byte{}, v2Magic...), 0x21, 0x11, 0x00, 0x0C))

	select {
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "v1 only") {
			t.Fatalf("expected a v2 refusal, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}

func TestParseTrusted(t *testing.T) {
	nets, err := ParseTrusted(" 2.28.225.3 , 10.0.0.0/8 ,, 2001:db8::1 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d networks, want 3", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("2.28.225.3")) || nets[0].Contains(net.ParseIP("2.28.225.4")) {
		t.Error("a bare address should match only itself")
	}
	if !nets[1].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("CIDR should match inside its range")
	}
	if _, err := ParseTrusted("nonsense"); err == nil {
		t.Error("expected an error for a non-address")
	}
}
