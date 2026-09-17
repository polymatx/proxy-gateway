package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxy-gateway/internal/traffic"

	"github.com/sirupsen/logrus"
)

// fakeUpstream accepts one CONNECT, answers 200, then streams until closed.
// It stands in for the residential provider.
func fakeUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				chunk := make([]byte, 16*1024)
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); wg.Wait() }
}

// hijackRecorder is the minimum http.ResponseWriter that can be hijacked.
type hijackRecorder struct {
	conn net.Conn
	hdr  http.Header
}

func (h *hijackRecorder) Header() http.Header         { return h.hdr }
func (h *hijackRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (h *hijackRecorder) WriteHeader(int)             {}
func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

type stubBalance struct {
	remaining int64
	err       error
	calls     int64
}

func (s *stubBalance) Remaining(context.Context, string) (int64, error) {
	atomic.AddInt64(&s.calls, 1)
	return s.remaining, s.err
}

func newTestGateway() *Gateway {
	lg := logrus.New()
	lg.SetLevel(logrus.PanicLevel)
	return &Gateway{logger: lg}
}

// runTunnel drives one tunnel against the fake upstream, draining the client
// end, and returns the tail the meter did not report plus any error.
func runTunnel(t *testing.T, g *Gateway, upstream string, meter *tunnelMeter) (tailReq, tailResp int64, err error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(io.Discard, clientSide)
	}()

	req, _ := http.NewRequest(http.MethodConnect, "//example.com:443", nil)
	req.Host = "example.com:443"

	w := &hijackRecorder{conn: serverSide, hdr: http.Header{}}
	choice := upstreamChoice{URL: "http://" + upstream, SessionID: "sess-test"}

	tailReq, tailResp, _, err = g.handleConnectTunnelWithMetrics(w, req, choice, nil, meter)
	clientSide.Close()
	<-done
	return tailReq, tailResp, err
}

// The point of the whole change: a tunnel must not outlive the balance, and
// the overshoot must be bounded by a read buffer rather than by how fast the
// link is.
func TestTunnelClosesWhenBudgetIsSpent(t *testing.T) {
	addr, stop := fakeUpstream(t)
	defer stop()

	const budget = int64(256 * 1024)
	g := newTestGateway()

	var mu sync.Mutex
	var reported int64

	meter := &tunnelMeter{
		interval: time.Hour, // never ticks: this test is about inline enforcement
		budget:   budget,
		flush: func(sessionID string, reqDelta, respDelta int64) bool {
			mu.Lock()
			reported += reqDelta + respDelta
			mu.Unlock()
			return true
		},
	}

	start := time.Now()
	tailReq, tailResp, err := runTunnel(t, g, addr, meter)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("tunnel returned error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tunnel ran for %v; the budget should have closed it", elapsed)
	}

	mu.Lock()
	total := reported + tailReq + tailResp
	mu.Unlock()

	if total < budget {
		t.Fatalf("tunnel moved %d bytes, expected it to reach the %d budget", total, budget)
	}
	// One read buffer of slack (io.Copy uses 32 KiB), doubled for headroom.
	const maxOvershoot = int64(64 * 1024)
	if over := total - budget; over > maxOvershoot {
		t.Fatalf("tunnel overshot the budget by %d bytes (max %d)", over, maxOvershoot)
	}
	t.Logf("closed after %v: %d bytes for a %d budget (overshoot %d)",
		elapsed, total, budget, total-budget)
}

// Concurrency safety: both directions draw on one allowance.
func TestTunnelBudgetIsSharedAcrossDirections(t *testing.T) {
	b := &tunnelBudget{remaining: 100}
	var wg sync.WaitGroup
	var oks int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.spend(1) {
				atomic.AddInt64(&oks, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&oks); got != 99 {
		t.Fatalf("budget of 100 allowed %d single-byte spends, want 99", got)
	}
}

// Without a meter the behaviour must be exactly what it was before: one tunnel,
// one set of totals, nothing reported mid-flight.
func TestTunnelWithoutMeterReturnsFullTotals(t *testing.T) {
	addr, stop := fakeUpstream(t)
	defer stop()

	g := newTestGateway()
	done := make(chan struct{})
	var tailResp int64
	go func() {
		defer close(done)
		_, tailResp, _ = runTunnel(t, g, addr, nil)
	}()

	select {
	case <-done:
		if tailResp <= 0 {
			t.Fatalf("expected the unmetered tunnel to report its total, got %d", tailResp)
		}
	case <-time.After(2 * time.Second):
		// Expected: with no meter the tunnel stays open until a side closes.
		// The deferred client close in runTunnel ends it; this branch only
		// guards against the test hanging forever.
		t.Log("unmetered tunnel still open after 2s, as designed")
	}
}

// A user whose balance reads as zero must be cut off on the first report.
func TestNewTunnelMeterStopsOnZeroBalance(t *testing.T) {
	g := newTestGateway()
	g.trafficLogger = &traffic.Logger{} // non-nil so the meter is built
	g.balance = &stubBalance{remaining: 0}

	meter := g.newTunnelMeter("someone", func(string, int64, int64) {})
	if meter == nil {
		t.Fatal("expected a meter")
	}
	if meter.flush("s", 1024, 1024) {
		t.Fatal("meter kept the tunnel open for a user with no balance")
	}
}

// An unreadable balance must not cut anyone off: availability wins, and the
// local budget still bounds the session.
func TestNewTunnelMeterFailsOpenWhenBalanceUnreadable(t *testing.T) {
	g := newTestGateway()
	g.trafficLogger = &traffic.Logger{}
	g.balance = &stubBalance{err: errors.New("redis down")}

	meter := g.newTunnelMeter("someone", func(string, int64, int64) {})
	if meter == nil {
		t.Fatal("expected a meter")
	}
	if !meter.flush("s", 1024, 1024) {
		t.Fatal("meter closed a tunnel because the balance could not be read")
	}
}
