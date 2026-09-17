package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"proxy-gateway/internal/traffic"

	"github.com/sirupsen/logrus"
)

type Gateway struct {
	provider  *ProxyProvider
	validator interface {
		ValidateIP(r *http.Request) bool
		GetClientIP(r *http.Request) string
		ValidateRequest(r *http.Request) (bool, string)
		SendProxyAuthRequired(w http.ResponseWriter)
	}
	logger        *logrus.Logger
	baseTransport *http.Transport
	trafficLogger *traffic.Logger
	balance       BalanceReader
	meterInterval time.Duration
}

// UnlimitedRemaining mirrors auth.UnlimitedRemaining: the value a BalanceReader
// returns when it has nothing authoritative to report and the caller should
// carry on regardless.
const UnlimitedRemaining = int64(math.MaxInt64)

// BalanceReader reports how many bytes a user still has to spend. The auth
// package's BalanceChecker satisfies it; it is declared here so the proxy
// package does not depend on auth.
type BalanceReader interface {
	Remaining(ctx context.Context, username string) (int64, error)
}

func NewGateway(provider *ProxyProvider, validator interface {
	ValidateIP(r *http.Request) bool
	GetClientIP(r *http.Request) string
	ValidateRequest(r *http.Request) (bool, string)
	SendProxyAuthRequired(w http.ResponseWriter)
}, logger *logrus.Logger) *Gateway {
	baseTransport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,

		// No timeouts - pure bridge mode
		TLSHandshakeTimeout:   0,
		ResponseHeaderTimeout: 0,
		ExpectContinueTimeout: 0,

		DisableKeepAlives:  false,
		DisableCompression: false,
		ForceAttemptHTTP2:  true,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: false,
			MinVersion:             tls.VersionTLS12,
		},

		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &Gateway{
		provider:      provider,
		validator:     validator,
		logger:        logger,
		baseTransport: baseTransport,
	}
}

func (g *Gateway) SetTrafficLogger(tl *traffic.Logger) {
	g.trafficLogger = tl
}

// SetBalanceChecker enables mid-tunnel metering. Without it a CONNECT tunnel is
// only checked against the balance when it opens, and nothing stops a user with
// an empty account from transferring indefinitely inside a single tunnel.
func (g *Gateway) SetBalanceChecker(b BalanceReader) {
	g.balance = b
}

// SetMeterInterval sets how often an open tunnel reports the bytes it has moved
// and is re-checked against the balance. Zero keeps the default.
func (g *Gateway) SetMeterInterval(d time.Duration) {
	if d > 0 {
		g.meterInterval = d
	}
}

func (g *Gateway) tunnelMeterInterval() time.Duration {
	if g.meterInterval > 0 {
		return g.meterInterval
	}
	return defaultMeterInterval
}

func (g *Gateway) createTransport(proxyURLString string) (*http.Transport, error) {
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	transport := g.baseTransport.Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	return transport, nil
}

func (g *Gateway) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := g.validator.GetClientIP(r)
	g.logger.WithFields(logrus.Fields{
		"client_ip": clientIP,
		"method":    r.Method,
		"url":       r.URL.String(),
		"host":      r.Host,
	}).Debug("Incoming HTTP request")

	if valid, reason := g.validator.ValidateRequest(r); !valid {
		g.logger.WithFields(logrus.Fields{
			"client_ip": clientIP,
			"reason":    reason,
		}).Warn("Request validation failed")

		switch reason {
		case "Invalid proxy credentials":
			g.validator.SendProxyAuthRequired(w)
		case "Insufficient balance":
			http.Error(w, "Insufficient balance - please top up your account", http.StatusPaymentRequired)
		default:
			http.Error(w, "Access Denied", http.StatusForbidden)
		}
		return
	}

	// Extract country, session_id, duration, username, and whether to use global proxy
	username, country, sessionID, duration, useGlobal := g.extractProxyParams(r)

	// Generate session ID if not provided (for non-sticky requests)
	generatedSession := false
	if sessionID == "" {
		sessionID = g.generateSessionID()
		generatedSession = true
	}

	// Get proxy for session (sticky if session provided, random if generated)
	// useGlobal=true when no -country- is specified, useGlobal=false when country is specified
	var proxyData *ProxyData
	if generatedSession {
		// No stickiness needed for generated sessions
		if useGlobal {
			proxyData = g.provider.GetRandomGlobalProxy()
		} else {
			proxyData = g.provider.GetRandomNonGlobalProxy()
		}
	} else {
		// Use session-aware selection for sticky sessions
		proxyData = g.provider.GetProxyForSession(r.Context(), username, country, sessionID, duration, useGlobal)
	}
	if proxyData == nil {
		proxyType := "non-global"
		if useGlobal {
			proxyType = "global"
		}
		g.logger.WithField("proxy_type", proxyType).Error("No proxies available")
		http.Error(w, "No proxies available", http.StatusServiceUnavailable)
		return
	}

	// Build the actual proxy URL using the template
	// For global proxies, don't pass country; for non-global, use the specified country
	proxyURL := proxyData.BuildProxyURL(country, sessionID, duration)

	g.logger.WithFields(logrus.Fields{
		"proxy_slug":  proxyData.Slug,
		"target_host": r.Host,
		"country":     country,
		"session_id":  sessionID,
	}).Debug("Forwarding HTTP request")

	requestBytes := r.ContentLength
	if requestBytes < 0 {
		requestBytes = 0
	}
	requestBytes += g.estimateHeaderSize(r.Header)

	responseBytes, statusCode, err := g.forwardRequestWithMetrics(w, r, proxyURL)
	if err != nil {
		g.logger.WithFields(logrus.Fields{
			"error":       err.Error(),
			"proxy_slug":  proxyData.Slug,
			"target_url":  r.URL.String(),
			"target_host": r.Host,
		}).Error("Failed to forward request")
		http.Error(w, "Proxy Error", http.StatusBadGateway)
		return
	}

	// Log traffic
	if g.trafficLogger != nil && username != "" {
		g.trafficLogger.Log(traffic.TrafficLogRequest{
			Username:      username,
			RequestBytes:  requestBytes,
			ResponseBytes: responseBytes,
			TargetHost:    r.Host,
			TargetMethod:  r.Method,
			ProxySlug:     proxyData.Slug,
			Country:       country,
			SessionID:     sessionID,
			Duration:      duration,
			StatusCode:    statusCode,
			ClientIP:      clientIP,
		})
	}
}

func (g *Gateway) HandleConnect(w http.ResponseWriter, r *http.Request) {
	clientIP := g.validator.GetClientIP(r)
	g.logger.WithFields(logrus.Fields{
		"client_ip": clientIP,
		"method":    r.Method,
		"host":      r.Host,
	}).Debug("Incoming CONNECT request")

	if valid, reason := g.validator.ValidateRequest(r); !valid {
		g.logger.WithFields(logrus.Fields{
			"client_ip": clientIP,
			"reason":    reason,
		}).Warn("CONNECT validation failed")

		switch reason {
		case "Invalid proxy credentials":
			g.validator.SendProxyAuthRequired(w)
		case "Insufficient balance":
			http.Error(w, "Insufficient balance - please top up your account", http.StatusPaymentRequired)
		default:
			http.Error(w, "Access Denied", http.StatusForbidden)
		}
		return
	}

	username, country, sessionID, duration, useGlobal := g.extractProxyParams(r)

	// Generate session ID if not provided (for non-sticky requests)
	generatedSession := false
	if sessionID == "" {
		sessionID = g.generateSessionID()
		generatedSession = true
	}

	// Get proxy for session (sticky if session provided, random if generated)
	// useGlobal=true when no -country- is specified, useGlobal=false when country is specified
	var proxyData *ProxyData
	if generatedSession {
		// No stickiness needed for generated sessions
		if useGlobal {
			proxyData = g.provider.GetRandomGlobalProxy()
		} else {
			proxyData = g.provider.GetRandomNonGlobalProxy()
		}
	} else {
		// Use session-aware selection for sticky sessions
		proxyData = g.provider.GetProxyForSession(r.Context(), username, country, sessionID, duration, useGlobal)
	}
	if proxyData == nil {
		proxyType := "non-global"
		if useGlobal {
			proxyType = "global"
		}
		g.logger.WithField("proxy_type", proxyType).Error("No proxies available for CONNECT")
		http.Error(w, "No proxies available", http.StatusServiceUnavailable)
		return
	}

	// Build the actual proxy URL using the template
	choice := upstreamChoice{URL: proxyData.BuildProxyURL(country, sessionID, duration), SessionID: sessionID}

	// Nobody asked for a generated session to stick, so a retry may take a
	// fresh exit node instead of the one that just refused us. A client that
	// supplied its own session ID keeps it, even at the cost of a 502.
	var rotate func() upstreamChoice
	if generatedSession {
		rotate = func() upstreamChoice {
			sid := g.generateSessionID()
			return upstreamChoice{URL: proxyData.BuildProxyURL(country, sid, duration), SessionID: sid}
		}
	}

	g.logger.WithFields(logrus.Fields{
		"target":     r.Host,
		"proxy_slug": proxyData.Slug,
	}).Debug("Handling CONNECT request")

	// One slice of a tunnel's traffic. A short tunnel produces a single row on
	// close, exactly as before; a long one produces a row per metering
	// interval, so the worker can deduct it while the tunnel is still open.
	logSlice := func(sessionID string, reqBytes, respBytes int64) {
		if g.trafficLogger == nil || username == "" || (reqBytes <= 0 && respBytes <= 0) {
			return
		}
		g.trafficLogger.Log(traffic.TrafficLogRequest{
			Username:      username,
			RequestBytes:  reqBytes,
			ResponseBytes: respBytes,
			TargetHost:    r.Host,
			TargetMethod:  "CONNECT",
			ProxySlug:     proxyData.Slug,
			Country:       country,
			SessionID:     sessionID,
			Duration:      duration,
			StatusCode:    200,
			ClientIP:      clientIP,
		})
	}

	requestBytes, responseBytes, used, err := g.handleConnectTunnelWithMetrics(w, r, choice, rotate, g.newTunnelMeter(username, logSlice))
	if err != nil {
		g.logger.WithError(err).Error("Failed to handle CONNECT")
		http.Error(w, "Proxy Error", http.StatusBadGateway)
		return
	}

	// Whatever the meter did not already report.
	logSlice(used.SessionID, requestBytes, responseBytes)
}

// newTunnelMeter builds the meter for one CONNECT tunnel: it reports traffic as
// it happens and closes the tunnel once the account is spent.
//
// The budget is the balance read when the tunnel opens, spent down locally so
// enforcement is immediate rather than waiting for the worker to catch up. The
// balance is also re-read on each report, which is what stops several
// concurrent tunnels from each spending the same allowance.
func (g *Gateway) newTunnelMeter(username string, logSlice func(sessionID string, reqBytes, respBytes int64)) *tunnelMeter {
	if g.trafficLogger == nil || username == "" {
		return nil
	}

	var (
		capped bool
		budget int64
	)
	if g.balance != nil {
		ctx, cancel := context.WithTimeout(context.Background(), balanceReadTimeout)
		remaining, err := g.balance.Remaining(ctx, username)
		cancel()
		switch {
		case err != nil:
			g.logger.WithError(err).WithField("username", username).
				Warn("Could not read balance for tunnel budget, tunnel will not be capped")
		case remaining >= UnlimitedRemaining:
			// The checker could not reach anything authoritative and told us to
			// carry on; capping at MaxInt64 would be pointless bookkeeping.
		default:
			capped, budget = true, remaining
		}
	}

	return &tunnelMeter{
		interval: g.tunnelMeterInterval(),
		capped:   capped,
		budget:   budget,
		flush: func(sessionID string, reqDelta, respDelta int64) bool {
			logSlice(sessionID, reqDelta, respDelta)

			if g.balance == nil {
				return true
			}

			// The budget itself is enforced per read; this second check is what
			// keeps several concurrent tunnels from each spending the same
			// allowance, once the worker has deducted the slices above.
			// Normally a Redis hit on the entry the worker just wrote.
			ctx, cancel := context.WithTimeout(context.Background(), balanceReadTimeout)
			remaining, err := g.balance.Remaining(ctx, username)
			cancel()
			if err != nil {
				// Unreadable balance keeps the tunnel open; the local budget
				// still bounds it.
				return true
			}
			return remaining > 0
		},
	}
}

// extractProxyParams extracts username, country, session_id, duration and whether to use global proxy
// useGlobal is true when no -country- parameter is provided
func (g *Gateway) extractProxyParams(r *http.Request) (username, country, sessionID string, duration int, useGlobal bool) {
	username = ""
	country = ""
	sessionID = ""
	duration = 5
	useGlobal = true // Default to global when no country specified

	proxyAuth := r.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		proxyAuth = r.Header.Get("Authorization")
	}

	if proxyAuth == "" {
		return
	}

	parts := strings.SplitN(proxyAuth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) < 1 {
		return
	}

	usernameStr := credentials[0]
	username, country, sessionID, duration, useGlobal = g.parseUsernameFormat(usernameStr)
	return
}

// parseUsernameFormat parses: {username}-country-{country}-session-{session_id}-sessTime-{duration}
// Returns useGlobal=true when no -country- is present, useGlobal=false when country is specified
func (g *Gateway) parseUsernameFormat(usernameStr string) (username, country, sessionID string, duration int, useGlobal bool) {
	country = ""
	sessionID = ""
	duration = 5
	useGlobal = true // Default: no country = use global proxy

	countryIdx := strings.Index(usernameStr, "-country-")
	if countryIdx == -1 {
		// No -country- parameter: parse for -session- directly
		username = usernameStr
		sessionIdx := strings.Index(usernameStr, "-session-")
		if sessionIdx != -1 {
			username = usernameStr[:sessionIdx]
			afterSession := usernameStr[sessionIdx+9:]
			sessTimeIdx := strings.Index(afterSession, "-sessTime-")
			if sessTimeIdx == -1 {
				sessionID = afterSession
			} else {
				sessionID = afterSession[:sessTimeIdx]
				durationStr := afterSession[sessTimeIdx+10:]
				if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
					duration = d
				}
			}
		} else {
			// Check for -sessTime- without session
			sessTimeIdx := strings.Index(usernameStr, "-sessTime-")
			if sessTimeIdx != -1 {
				username = usernameStr[:sessTimeIdx]
				durationStr := usernameStr[sessTimeIdx+10:]
				if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
					duration = d
				}
			}
		}
		return // useGlobal remains true
	}

	// Country is specified: use non-global proxy
	useGlobal = false
	username = usernameStr[:countryIdx]
	afterCountry := usernameStr[countryIdx+9:]

	sessionIdx := strings.Index(afterCountry, "-session-")
	if sessionIdx == -1 {
		sessTimeIdx := strings.Index(afterCountry, "-sessTime-")
		if sessTimeIdx == -1 {
			country = afterCountry
		} else {
			country = afterCountry[:sessTimeIdx]
			durationStr := afterCountry[sessTimeIdx+10:]
			if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
				duration = d
			}
		}
		return
	}

	country = afterCountry[:sessionIdx]
	afterSession := afterCountry[sessionIdx+9:]

	sessTimeIdx := strings.Index(afterSession, "-sessTime-")
	if sessTimeIdx == -1 {
		sessionID = afterSession
	} else {
		sessionID = afterSession[:sessTimeIdx]
		durationStr := afterSession[sessTimeIdx+10:]
		if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
			duration = d
		}
	}

	return
}

func (g *Gateway) generateSessionID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var result strings.Builder
	result.Grow(10)
	for i := 0; i < 10; i++ {
		result.WriteByte(charset[rand.Intn(len(charset))])
	}
	return result.String()
}

func (g *Gateway) estimateHeaderSize(headers http.Header) int64 {
	var size int64
	for key, values := range headers {
		for _, value := range values {
			size += int64(len(key) + len(value) + 4)
		}
	}
	return size
}

func (g *Gateway) forwardRequestWithMetrics(w http.ResponseWriter, r *http.Request, proxyURLString string) (responseBytes int64, statusCode int, err error) {
	transport, err := g.createTransport(proxyURLString)
	if err != nil {
		return 0, 0, err
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // No timeout - bridge mode
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		if r.URL.Scheme != "" {
			scheme = r.URL.Scheme
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		targetURL = scheme + "://" + host + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %v", err)
	}

	for key, values := range r.Header {
		if key != "Proxy-Authorization" && key != "Proxy-Connection" {
			req.Header[key] = values
		}
	}

	if r.ContentLength > 0 {
		req.ContentLength = r.ContentLength
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		w.Header()[key] = values
	}

	w.WriteHeader(resp.StatusCode)
	statusCode = resp.StatusCode

	cw := &countingWriter{w: w}
	_, err = io.Copy(cw, resp.Body)
	responseBytes = cw.bytes + g.estimateHeaderSize(resp.Header)

	return responseBytes, statusCode, err
}

type countingWriter struct {
	w     http.ResponseWriter
	bytes int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.bytes += int64(n)
	return n, err
}

// tunnelErr classifies a failure to establish the upstream CONNECT tunnel.
// A transient failure happens before a single byte has been written to the
// client, so the caller may retry it against the same upstream without any
// client-visible side effect.
type tunnelErr struct {
	err       error
	transient bool
}

func (e *tunnelErr) Error() string { return e.err.Error() }
func (e *tunnelErr) Unwrap() error { return e.err }

const (
	// The upstream residential provider drops a small share of CONNECT
	// handshakes mid-flight (EOF while reading its response). One or two
	// retries recover almost all of them; more only delays the 502.
	connectAttempts  = 3
	connectRetryBase = 100 * time.Millisecond

	// How often an open tunnel reports what it has moved and is re-checked
	// against the balance. This bounds how far a user can overshoot an empty
	// account: one interval's worth of transfer, not the whole session.
	defaultMeterInterval = 15 * time.Second

	// A balance read is a Redis GET, or a single indexed row when the cache
	// has expired; it must never hold a tunnel up.
	balanceReadTimeout = 3 * time.Second
)

// tunnelMeter is consulted while a CONNECT tunnel is open. flush receives the
// bytes moved since the previous call and reports whether the tunnel may stay
// open; returning false tears it down.
type tunnelMeter struct {
	interval time.Duration
	// budget is the hard ceiling, in bytes, for this tunnel, applied when
	// capped is set. It is enforced on every read rather than on the interval,
	// because a tick-based check lets a fast tunnel overshoot by
	// interval x throughput -- tens of megabytes of unpaid traffic. Enforced
	// inline, the overshoot is one read buffer.
	//
	// capped is separate from "budget > 0" on purpose: a budget of exactly zero
	// must still cap the tunnel (closing it on the first read), not wave it
	// through. The balance is re-read here rather than reused from validation,
	// so it can legitimately have reached zero in between.
	capped bool
	budget int64
	flush  func(sessionID string, reqDelta, respDelta int64) (keepOpen bool)
}

// errBudgetExhausted ends the copy that spends the last of the budget.
var errBudgetExhausted = errors.New("tunnel budget exhausted")

// tunnelBudget is the shared allowance both directions of one tunnel draw on.
type tunnelBudget struct {
	remaining int64 // atomic
}

func (b *tunnelBudget) spend(n int64) bool {
	return atomic.AddInt64(&b.remaining, -n) > 0
}

// dialUpstreamTunnel opens the upstream proxy connection and completes the
// CONNECT handshake for target. On success the returned reader must be used
// for upstream->client copying: it may already hold bytes read past the
// response headers.
func (g *Gateway) dialUpstreamTunnel(proxyURL *url.URL, target string) (net.Conn, *bufio.Reader, error) {
	// No timeout for dial - bridge mode
	upstreamConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		return nil, nil, &tunnelErr{fmt.Errorf("failed to connect to upstream proxy: %w", err), true}
	}

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := username + ":" + password
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	if err := connectReq.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		return nil, nil, &tunnelErr{fmt.Errorf("failed to write CONNECT: %w", err), true}
	}

	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		upstreamConn.Close()
		// Typically io.ErrUnexpectedEOF: the upstream accepted the TCP
		// connection and then dropped it. This is the case retries exist for.
		return nil, nil, &tunnelErr{fmt.Errorf("failed to read CONNECT response: %w", err), true}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		upstreamConn.Close()
		// 5xx is the provider having a bad moment; 407/403/4xx is a decision
		// about this request and will not change on a retry.
		return nil, nil, &tunnelErr{
			fmt.Errorf("upstream rejected CONNECT: %d %s", resp.StatusCode, strings.TrimSpace(string(body))),
			resp.StatusCode >= 500,
		}
	}
	resp.Body.Close() // a 2xx to CONNECT carries no body
	return upstreamConn, br, nil
}

// upstreamChoice is one concrete upstream URL together with the session ID
// baked into it, so the caller can log which session actually carried traffic.
type upstreamChoice struct {
	URL       string
	SessionID string
}

// handleConnectTunnelWithMetrics establishes the tunnel and pipes bytes.
// rotate, when non-nil, is consulted before each retry to pick a different
// upstream session: a request that was refused three times on one exit node
// is usually that node's problem, not a momentary blip, so knocking on the
// same door again rarely helps. Sticky sessions pass nil and keep their exit.
// meter, when non-nil, is ticked while the tunnel is open: it reports traffic
// as it happens and can close the tunnel when the account runs dry. The byte
// counts returned are only the tail the meter has not already reported, so the
// caller must not log the whole session again.
func (g *Gateway) handleConnectTunnelWithMetrics(w http.ResponseWriter, r *http.Request, choice upstreamChoice, rotate func() upstreamChoice, meter *tunnelMeter) (requestBytes, responseBytes int64, used upstreamChoice, err error) {
	var (
		upstreamConn net.Conn
		br           *bufio.Reader
	)
	for attempt := 1; ; attempt++ {
		proxyURL, perr := url.Parse(choice.URL)
		if perr != nil {
			return 0, 0, choice, fmt.Errorf("invalid proxy URL: %v", perr)
		}
		upstreamConn, br, err = g.dialUpstreamTunnel(proxyURL, r.Host)
		if err == nil {
			if attempt > 1 {
				g.logger.WithFields(logrus.Fields{"attempt": attempt, "target": r.Host, "rotated": rotate != nil}).Info("Upstream CONNECT succeeded after retry")
			}
			break
		}
		var te *tunnelErr
		if !errors.As(err, &te) || !te.transient || attempt >= connectAttempts || r.Context().Err() != nil {
			return 0, 0, choice, err
		}
		g.logger.WithError(err).WithFields(logrus.Fields{"attempt": attempt, "target": r.Host, "rotated": rotate != nil}).Warn("Upstream CONNECT failed, retrying")
		time.Sleep(connectRetryBase * time.Duration(1<<(attempt-1)))
		if rotate != nil {
			choice = rotate()
		}
	}
	defer upstreamConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return 0, 0, choice, fmt.Errorf("hijacking not supported")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return 0, 0, choice, fmt.Errorf("failed to hijack connection: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return 0, 0, choice, fmt.Errorf("failed to send 200: %v", err)
	}

	var reqBytes, respBytes int64
	errChan := make(chan error, 2)

	var budget *tunnelBudget
	if meter != nil && meter.capped {
		budget = &tunnelBudget{remaining: meter.budget}
	}

	go func() {
		_, err := io.Copy(upstreamConn, &countingReader{r: clientConn, bytes: &reqBytes, budget: budget})
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, &countingReader{r: br, bytes: &respBytes, budget: budget})
		errChan <- err
	}()

	if meter == nil {
		<-errChan
		return atomic.LoadInt64(&reqBytes), atomic.LoadInt64(&respBytes), choice, nil
	}

	// Everything reported to the meter is subtracted from the tail we hand
	// back, so a long session is billed once, in slices, rather than twice.
	var reportedReq, reportedResp int64
	ticker := time.NewTicker(meter.interval)
	defer ticker.Stop()

metering:
	for {
		select {
		case copyErr := <-errChan:
			if errors.Is(copyErr, errBudgetExhausted) {
				g.logger.WithFields(logrus.Fields{
					"target":     r.Host,
					"session_id": choice.SessionID,
				}).Info("Closing tunnel: traffic allowance spent")
			}
			break metering
		case <-ticker.C:
			nowReq := atomic.LoadInt64(&reqBytes)
			nowResp := atomic.LoadInt64(&respBytes)
			deltaReq, deltaResp := nowReq-reportedReq, nowResp-reportedResp
			if deltaReq <= 0 && deltaResp <= 0 {
				// Idle interval: nothing to bill and nothing new to decide on.
				continue
			}
			reportedReq, reportedResp = nowReq, nowResp
			if meter.flush(choice.SessionID, deltaReq, deltaResp) {
				continue
			}
			g.logger.WithFields(logrus.Fields{
				"target":     r.Host,
				"session_id": choice.SessionID,
			}).Info("Closing tunnel: account out of balance")
			// Closing both ends unblocks both copies; errChan is buffered so
			// neither goroutine leaks.
			upstreamConn.Close()
			clientConn.Close()
			break metering
		}
	}

	return atomic.LoadInt64(&reqBytes) - reportedReq, atomic.LoadInt64(&respBytes) - reportedResp, choice, nil
}

type countingReader struct {
	r      io.Reader
	bytes  *int64
	budget *tunnelBudget
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		atomic.AddInt64(cr.bytes, int64(n))
		if cr.budget != nil && !cr.budget.spend(int64(n)) && err == nil {
			// Return the bytes we did read: io.Copy writes them out before it
			// acts on the error, so nothing is lost on the way down.
			return n, errBudgetExhausted
		}
	}
	return n, err
}
