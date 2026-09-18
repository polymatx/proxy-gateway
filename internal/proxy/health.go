package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Health tracks which upstream providers are worth sending traffic to.
//
// Detection is passive: real requests already tell us whether a provider is
// answering, and a request only counts as failed once the gateway has exhausted
// its retries, so a provider that is merely flaky does not get marked down.
// Probing is active but narrow -- only providers already believed to be down
// are probed, which is what lets one come back without a customer request
// having to discover it. A healthy provider is never probed, so health checking
// costs no upstream traffic in the steady state.
//
// Thresholds mirror the relay's HAProxy backend (fall 3 / rise 2) so the two
// layers behave alike.
type Health struct {
	mu     sync.RWMutex
	state  map[string]*providerState
	logger *logrus.Logger

	failThreshold int
	riseThreshold int
	probeTarget   string
	probeTimeout  time.Duration
}

type providerState struct {
	healthy       bool
	consecFail    int
	consecSuccess int
	since         time.Time
}

type HealthConfig struct {
	FailThreshold int
	RiseThreshold int
	ProbeTarget   string
	ProbeTimeout  time.Duration
}

func NewHealth(cfg HealthConfig, logger *logrus.Logger) *Health {
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = 3
	}
	if cfg.RiseThreshold <= 0 {
		cfg.RiseThreshold = 2
	}
	if cfg.ProbeTarget == "" {
		cfg.ProbeTarget = "www.google.com:443"
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}
	return &Health{
		state:         make(map[string]*providerState),
		logger:        logger,
		failThreshold: cfg.FailThreshold,
		riseThreshold: cfg.RiseThreshold,
		probeTarget:   cfg.ProbeTarget,
		probeTimeout:  cfg.ProbeTimeout,
	}
}

// entry returns the state for a slug, creating it healthy. An unknown provider
// is assumed good: refusing traffic to something we have simply never tried
// would take a working provider out on deployment.
func (h *Health) entry(slug string) *providerState {
	if s, ok := h.state[slug]; ok {
		return s
	}
	s := &providerState{healthy: true, since: time.Now()}
	h.state[slug] = s
	return s
}

// RecordSuccess is called when a request completed through this provider.
func (h *Health) RecordSuccess(slug string) {
	if slug == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.entry(slug)
	s.consecFail = 0
	if s.healthy {
		return
	}
	s.consecSuccess++
	if s.consecSuccess >= h.riseThreshold {
		s.healthy = true
		s.consecSuccess = 0
		s.since = time.Now()
		h.logger.WithField("proxy_slug", slug).Info("Upstream provider is healthy again")
	}
}

// RecordFailure is called when a request could not be served by this provider
// after the gateway's own retries.
func (h *Health) RecordFailure(slug string) {
	if slug == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.entry(slug)
	s.consecSuccess = 0
	if !s.healthy {
		return
	}
	s.consecFail++
	if s.consecFail >= h.failThreshold {
		s.healthy = false
		s.consecFail = 0
		s.since = time.Now()
		h.logger.WithField("proxy_slug", slug).Warn("Upstream provider marked unhealthy; traffic will avoid it")
	}
}

func (h *Health) IsHealthy(slug string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s, ok := h.state[slug]; ok {
		return s.healthy
	}
	return true
}

// Snapshot is what /health reports.
func (h *Health) Snapshot() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]bool, len(h.state))
	for slug, s := range h.state {
		out[slug] = s.healthy
	}
	return out
}

func (h *Health) unhealthySlugs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	for slug, s := range h.state {
		if !s.healthy {
			out = append(out, slug)
		}
	}
	return out
}

// RunProbes re-tests providers currently believed to be down, until ctx ends.
// Healthy providers are deliberately left alone: real traffic is already a
// better signal than a synthetic one, and probing them would spend upstream
// allowance to learn what we already know.
func (h *Health) RunProbes(ctx context.Context, provider *ProxyProvider, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, slug := range h.unhealthySlugs() {
				p := provider.GetProxyBySlug(slug)
				if p == nil {
					continue // removed from the database while down
				}
				if err := h.probe(p); err != nil {
					h.logger.WithError(err).WithField("proxy_slug", slug).Debug("Health probe still failing")
					continue
				}
				h.RecordSuccess(slug)
			}
		}
	}
}

// probe opens a CONNECT tunnel and closes it without transferring anything, so
// it costs a handshake rather than traffic.
func (h *Health) probe(p *ProxyData) error {
	proxyURL, err := url.Parse(p.BuildProxyURL("", "", 1))
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	conn, err := net.DialTimeout("tcp", proxyURL.Host, h.probeTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(h.probeTimeout))

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: h.probeTarget},
		Host:   h.probeTarget,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		pw, _ := proxyURL.User.Password()
		req.SetBasicAuth(proxyURL.User.Username(), pw)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(conn); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream rejected probe CONNECT: %d", resp.StatusCode)
	}
	return nil
}
