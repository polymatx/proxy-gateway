package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
	logger         *logrus.Logger
	transportCache map[string]*http.Transport
	transportMu    sync.RWMutex
	baseTransport  *http.Transport
	trafficLogger  *traffic.Logger
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
		provider:       provider,
		validator:      validator,
		logger:         logger,
		baseTransport:  baseTransport,
		transportCache: make(map[string]*http.Transport),
	}
}

func (g *Gateway) SetTrafficLogger(tl *traffic.Logger) {
	g.trafficLogger = tl
}

func (g *Gateway) getOrCreateTransport(proxyURLString string) (*http.Transport, error) {
	g.transportMu.RLock()
	if transport, exists := g.transportCache[proxyURLString]; exists {
		g.transportMu.RUnlock()
		return transport, nil
	}
	g.transportMu.RUnlock()

	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	g.transportMu.Lock()
	defer g.transportMu.Unlock()

	if transport, exists := g.transportCache[proxyURLString]; exists {
		return transport, nil
	}

	transport := g.baseTransport.Clone()
	transport.Proxy = http.ProxyURL(proxyURL)

	g.transportCache[proxyURLString] = transport

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

	// Extract country, session_id, duration and username from proxy authentication
	username, country, sessionID, duration := g.extractProxyParams(r)

	// Get random proxy from available proxies
	proxyData := g.provider.GetRandomProxy()
	if proxyData == nil {
		g.logger.Error("No proxies available")
		http.Error(w, "No proxies available", http.StatusServiceUnavailable)
		return
	}

	// Use provided session_id or generate one if not provided
	if sessionID == "" {
		sessionID = g.generateSessionID()
	}

	// Build the actual proxy URL using the template
	var finalCountry string
	if proxyData.IsGlobal {
		finalCountry = ""
	} else {
		finalCountry = country
	}
	proxyURL := proxyData.BuildProxyURL(finalCountry, sessionID, duration)

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
			"error":      err.Error(),
			"proxy_slug": proxyData.Slug,
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

	username, country, sessionID, duration := g.extractProxyParams(r)

	proxyData := g.provider.GetRandomProxy()
	if proxyData == nil {
		g.logger.Error("No proxies available for CONNECT")
		http.Error(w, "No proxies available", http.StatusServiceUnavailable)
		return
	}

	if sessionID == "" {
		sessionID = g.generateSessionID()
	}

	var finalCountry string
	if proxyData.IsGlobal {
		finalCountry = ""
	} else {
		finalCountry = country
	}
	proxyURL := proxyData.BuildProxyURL(finalCountry, sessionID, duration)

	g.logger.WithFields(logrus.Fields{
		"target":     r.Host,
		"proxy_slug": proxyData.Slug,
	}).Debug("Handling CONNECT request")

	requestBytes, responseBytes, err := g.handleConnectTunnelWithMetrics(w, r, proxyURL)
	if err != nil {
		g.logger.WithError(err).Error("Failed to handle CONNECT")
		http.Error(w, "Proxy Error", http.StatusBadGateway)
		return
	}

	// Log traffic for CONNECT
	if g.trafficLogger != nil && username != "" {
		g.trafficLogger.Log(traffic.TrafficLogRequest{
			Username:      username,
			RequestBytes:  requestBytes,
			ResponseBytes: responseBytes,
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
}

// extractProxyParams extracts username, country, session_id, and duration from proxy authentication
func (g *Gateway) extractProxyParams(r *http.Request) (username, country, sessionID string, duration int) {
	username = ""
	country = "US"
	sessionID = ""
	duration = 5

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
	username, country, sessionID, duration = g.parseUsernameFormat(usernameStr)
	return
}

// parseUsernameFormat parses: {username}-country-{country}-session-{session_id}-sessTime-{duration}
func (g *Gateway) parseUsernameFormat(usernameStr string) (username, country, sessionID string, duration int) {
	country = "US"
	sessionID = ""
	duration = 5

	countryIdx := strings.Index(usernameStr, "-country-")
	if countryIdx == -1 {
		username = usernameStr
		return
	}

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
	transport, err := g.getOrCreateTransport(proxyURLString)
	if err != nil {
		return 0, 0, err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // No timeout - bridge mode
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
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

func (g *Gateway) handleConnectTunnelWithMetrics(w http.ResponseWriter, r *http.Request, proxyURLString string) (requestBytes, responseBytes int64, err error) {
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid proxy URL: %v", err)
	}

	// No timeout for dial - bridge mode
	upstreamConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to connect to upstream proxy: %v", err)
	}
	defer upstreamConn.Close()

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: r.Host},
		Host:   r.Host,
		Header: make(http.Header),
	}

	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := username + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq.Header.Set("Proxy-Authorization", basicAuth)
	}

	if err := connectReq.Write(upstreamConn); err != nil {
		return 0, 0, fmt.Errorf("failed to write CONNECT: %v", err)
	}

	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read CONNECT response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, 0, fmt.Errorf("upstream rejected CONNECT: %d %s", resp.StatusCode, string(body))
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return 0, 0, fmt.Errorf("hijacking not supported")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to hijack connection: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return 0, 0, fmt.Errorf("failed to send 200: %v", err)
	}

	var reqBytes, respBytes int64
	errChan := make(chan error, 2)

	go func() {
		n, err := io.Copy(upstreamConn, &countingReader{r: clientConn, bytes: &reqBytes})
		_ = n
		errChan <- err
	}()

	go func() {
		n, err := io.Copy(clientConn, &countingReader{r: upstreamConn, bytes: &respBytes})
		_ = n
		errChan <- err
	}()

	<-errChan

	return atomic.LoadInt64(&reqBytes), atomic.LoadInt64(&respBytes), nil
}

type countingReader struct {
	r     io.Reader
	bytes *int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	atomic.AddInt64(cr.bytes, int64(n))
	return n, err
}
