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
	"time"

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
}

func NewGateway(provider *ProxyProvider, validator interface {
	ValidateIP(r *http.Request) bool
	GetClientIP(r *http.Request) string
	ValidateRequest(r *http.Request) (bool, string)
	SendProxyAuthRequired(w http.ResponseWriter)
}, timeout time.Duration, logger *logrus.Logger) *Gateway {
	baseTransport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,

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
	}).Info("Incoming HTTP request")

	if valid, reason := g.validator.ValidateRequest(r); !valid {
		g.logger.WithFields(logrus.Fields{
			"client_ip": clientIP,
			"reason":    reason,
		}).Warn("Request validation failed")

		if reason == "Invalid proxy credentials" {
			g.validator.SendProxyAuthRequired(w)
		} else {
			http.Error(w, "Access Denied", http.StatusForbidden)
		}
		return
	}

	// Extract country, session_id, and duration from proxy authentication
	country, sessionID, duration := g.extractProxyParams(r)

	// Get random proxy from available proxies
	proxyData := g.provider.GetRandomProxy()
	if proxyData == nil {
		g.logger.Error("No proxies available")
		http.Error(w, "No proxies available", http.StatusServiceUnavailable)
		return
	}

	g.logger.WithFields(logrus.Fields{
		"proxy_name":   proxyData.Name,
		"proxy_slug":   proxyData.Slug,
		"url_template": proxyData.URLTemplate,
	}).Info("Selected random proxy provider")

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
		"proxy_name":     proxyData.Name,
		"proxy_base_url": proxyData.BaseURL,
		"proxy_username": proxyData.Username,
		"proxy_port_min": proxyData.PortMin,
		"proxy_port_max": proxyData.PortMax,
		"url_template":   proxyData.URLTemplate,
		"proxy_full_url": proxyURL,
		"target":         r.URL.String(),
		"target_host":    r.Host,
		"target_method":  r.Method,
		"country":        country,
		"session_id":     sessionID,
		"duration":       duration,
		"content_length": r.ContentLength,
	}).Info("Forwarding HTTP request through proxy")

	if err := g.forwardRequest(w, r, proxyURL); err != nil {
		g.logger.WithFields(logrus.Fields{
			"error":      err.Error(),
			"proxy_slug": proxyData.Slug,
		}).Error("Failed to forward request")
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	g.logger.Info("Request forwarded successfully")
}

func (g *Gateway) HandleConnect(w http.ResponseWriter, r *http.Request) {
	clientIP := g.validator.GetClientIP(r)
	g.logger.WithFields(logrus.Fields{
		"client_ip": clientIP,
		"method":    r.Method,
		"host":      r.Host,
	}).Info("Incoming CONNECT request")

	if valid, reason := g.validator.ValidateRequest(r); !valid {
		g.logger.WithFields(logrus.Fields{
			"client_ip": clientIP,
			"reason":    reason,
		}).Warn("CONNECT validation failed")

		if reason == "Invalid proxy credentials" {
			g.validator.SendProxyAuthRequired(w)
		} else {
			http.Error(w, "Access Denied", http.StatusForbidden)
		}
		return
	}

	country, sessionID, duration := g.extractProxyParams(r)

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
		"target":         r.Host,
		"proxy_slug":     proxyData.Slug,
		"proxy_full_url": proxyURL,
		"duration":       duration,
	}).Info("Handling CONNECT request")

	if err := g.handleConnectTunnel(w, r, proxyURL); err != nil {
		g.logger.WithError(err).Error("Failed to handle CONNECT")
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}
}

// extractProxyParams extracts country, session_id, and duration from proxy authentication
// Format: {username}-country-{country}-session-{session_id}-sessTime-{duration}:{password}
func (g *Gateway) extractProxyParams(r *http.Request) (country, sessionID string, duration int) {
	// Default values
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
	country, sessionID, duration = g.parseUsernameFormat(usernameStr)
	return
}

// parseUsernameFormat parses the username format:
// {username}-country-{country}-session-{session_id}-sessTime-{duration}
func (g *Gateway) parseUsernameFormat(username string) (country, sessionID string, duration int) {
	country = "US"
	sessionID = ""
	duration = 5

	// Find -country-
	countryIdx := strings.Index(username, "-country-")
	if countryIdx == -1 {
		return
	}
	afterCountry := username[countryIdx+9:] // len("-country-") = 9

	// Find -session-
	sessionIdx := strings.Index(afterCountry, "-session-")
	if sessionIdx == -1 {
		// No session, rest might be country or country-sessTime-X
		sessTimeIdx := strings.Index(afterCountry, "-sessTime-")
		if sessTimeIdx == -1 {
			country = afterCountry
		} else {
			country = afterCountry[:sessTimeIdx]
			durationStr := afterCountry[sessTimeIdx+10:] // len("-sessTime-") = 10
			if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
				duration = d
			}
		}
		return
	}

	country = afterCountry[:sessionIdx]
	afterSession := afterCountry[sessionIdx+9:] // len("-session-") = 9

	// Find -sessTime-
	sessTimeIdx := strings.Index(afterSession, "-sessTime-")
	if sessTimeIdx == -1 {
		sessionID = afterSession
	} else {
		sessionID = afterSession[:sessTimeIdx]
		durationStr := afterSession[sessTimeIdx+10:] // len("-sessTime-") = 10
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

func (g *Gateway) forwardRequest(w http.ResponseWriter, r *http.Request, proxyURLString string) error {
	transport, err := g.getOrCreateTransport(proxyURLString)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0,
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
		return fmt.Errorf("failed to create request: %v", err)
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
		return fmt.Errorf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		w.Header()[key] = values
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	return err
}

func (g *Gateway) handleConnectTunnel(w http.ResponseWriter, r *http.Request, proxyURLString string) error {
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	upstreamConn, err := net.DialTimeout("tcp", proxyURL.Host, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to upstream proxy: %v", err)
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
		return fmt.Errorf("failed to write CONNECT: %v", err)
	}

	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upstream rejected CONNECT: %d %s", resp.StatusCode, string(body))
	}

	upstreamConn.SetDeadline(time.Time{})

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("hijacking not supported")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack connection: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("failed to send 200: %v", err)
	}

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstreamConn, clientConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, upstreamConn)
		errChan <- err
	}()

	<-errChan

	return nil
}
