// Package proxyproto recovers the real client address from HAProxy's PROXY
// protocol header.
//
// Customer traffic reaches the gateway through the relay, which until now
// forwarded raw TCP: every request therefore arrived with the relay's address,
// and traffic_logs recorded 2.28.225.3 for essentially every row. That makes
// abuse tracing impossible and would make any future per-customer IP allowlist
// match every customer at once.
//
// The header is only ever read from peers named in the trusted list. A header
// is an assertion about who the client is, so honouring one from an arbitrary
// peer would let anyone connecting to the node port forge their own address in
// the logs -- worse than having no address at all.
package proxyproto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	v1Prefix = []byte("PROXY ")
	// The v2 header opens with this fixed 12-byte block.
	v2Magic = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

const (
	// A peer that has connected but sent nothing is not held up for long: the
	// header is the very first thing HAProxy writes.
	headerReadTimeout = 5 * time.Second
	// The v1 grammar caps the line at 107 bytes plus CRLF.
	maxV1Header = 108
)

// ParseTrusted turns a comma-separated list of IPs and CIDRs into networks.
// A bare address is treated as a single-host network.
func ParseTrusted(spec string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("not an IP or CIDR: %q", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// Listener wraps connections from trusted peers so their PROXY header is
// consumed before the HTTP server sees the stream.
type Listener struct {
	net.Listener
	trusted []*net.IPNet
}

func NewListener(inner net.Listener, trusted []*net.IPNet) *Listener {
	return &Listener{Listener: inner, trusted: trusted}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.isTrusted(c.RemoteAddr()) {
		return c, nil
	}
	// Deliberately not parsed here: Accept must not block on one slow peer.
	// The header is consumed on the first read instead.
	return &Conn{Conn: c, r: bufio.NewReader(c)}, nil
}

func (l *Listener) isTrusted(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range l.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Conn is a connection from a trusted peer. Its PROXY header, if any, is read
// lazily on the first Read.
type Conn struct {
	net.Conn
	r        *bufio.Reader
	once     sync.Once
	realAddr net.Addr
	parseErr error
}

// RealClientIP is the address the trusted peer vouched for, or "" when no
// header was sent. Call it once the request has been read -- by then the header
// has been consumed.
func (c *Conn) RealClientIP() string {
	if c.realAddr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(c.realAddr.String())
	if err != nil {
		return c.realAddr.String()
	}
	return host
}

func (c *Conn) Read(p []byte) (int, error) {
	c.consumeHeader()
	if c.parseErr != nil {
		return 0, c.parseErr
	}
	return c.r.Read(p)
}

// RemoteAddr reports the client the header named, falling back to the peer.
// Note the HTTP server captures this before any read, so handlers should use
// RealClientIP via the request context rather than r.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	if c.realAddr != nil {
		return c.realAddr
	}
	return c.Conn.RemoteAddr()
}

func (c *Conn) consumeHeader() {
	c.once.Do(func() {
		_ = c.Conn.SetReadDeadline(time.Now().Add(headerReadTimeout))
		defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()

		prefix, err := c.r.Peek(len(v1Prefix))
		if err != nil {
			// Nothing arrived, or the peer hung up. Not an error in itself:
			// leave the stream untouched and let the server deal with it.
			return
		}

		if bytes.Equal(prefix, v1Prefix) {
			c.realAddr, c.parseErr = parseV1(c.r)
			return
		}

		if magic, err := c.r.Peek(len(v2Magic)); err == nil && bytes.Equal(magic, v2Magic) {
			// Refused rather than skipped: silently ignoring a v2 header would
			// leave its binary body in the stream and corrupt the request.
			c.parseErr = errors.New("proxyproto: v2 header received, this build speaks v1 only")
			return
		}

		// No header. Expected while the relay has not been switched over yet,
		// and for anything reaching the node port directly.
	})
}

// parseV1 reads one line of the form
//
//	PROXY TCP4 <src ip> <dst ip> <src port> <dst port>\r\n
//
// Returns a nil address for "PROXY UNKNOWN", which the spec allows when the
// sender cannot determine the origin.
func parseV1(r *bufio.Reader) (net.Addr, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("proxyproto: reading v1 header: %w", err)
	}
	if len(line) > maxV1Header {
		return nil, fmt.Errorf("proxyproto: v1 header too long (%d bytes)", len(line))
	}
	if !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("proxyproto: v1 header not CRLF-terminated")
	}

	fields := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("proxyproto: malformed v1 header %q", line)
	}

	switch fields[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
	default:
		return nil, fmt.Errorf("proxyproto: unsupported v1 protocol %q", fields[1])
	}

	if len(fields) != 6 {
		return nil, fmt.Errorf("proxyproto: v1 header wants 6 fields, got %d", len(fields))
	}

	srcIP := net.ParseIP(fields[2])
	if srcIP == nil {
		return nil, fmt.Errorf("proxyproto: bad source address %q", fields[2])
	}
	isV4 := srcIP.To4() != nil
	if (fields[1] == "TCP4") != isV4 {
		return nil, fmt.Errorf("proxyproto: %s header carries a %s address", fields[1], addrFamily(isV4))
	}
	srcPort, err := strconv.Atoi(fields[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		return nil, fmt.Errorf("proxyproto: bad source port %q", fields[4])
	}

	return &net.TCPAddr{IP: srcIP, Port: srcPort}, nil
}

func addrFamily(isV4 bool) string {
	if isV4 {
		return "v4"
	}
	return "v6"
}

type ctxKey struct{}

// WithConn stashes the connection so a handler can ask for the real client
// address later, once the header has actually been read.
func WithConn(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*Conn); ok {
		return context.WithValue(ctx, ctxKey{}, pc)
	}
	return ctx
}

// RealClientIPFromContext returns the address a trusted peer vouched for, and
// whether there was one.
func RealClientIPFromContext(ctx context.Context) (string, bool) {
	pc, ok := ctx.Value(ctxKey{}).(*Conn)
	if !ok {
		return "", false
	}
	ip := pc.RealClientIP()
	return ip, ip != ""
}
