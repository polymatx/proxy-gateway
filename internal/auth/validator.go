package auth

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
)

type AuthorizedIP struct {
	ID          int       `db:"id"`
	IP          string    `db:"ip"`
	Description string    `db:"description"`
	IsActive    bool      `db:"is_active"`
	CreatedAt   time.Time `db:"created_at"`
}

type User struct {
	ID        int       `db:"id"`
	Username  string    `db:"username"`
	Password  string    `db:"password"`
	IsActive  bool      `db:"is_active"`
	CreatedAt time.Time `db:"created_at"`
}

type IPValidator struct {
	pool           *pgxpool.Pool
	authorizedIPs  map[string]bool
	authorizedNets []*net.IPNet
	users          map[string]string // username -> password
	mu             sync.RWMutex
	logger         *logrus.Logger
}

func NewIPValidator(pool *pgxpool.Pool, logger *logrus.Logger) *IPValidator {
	return &IPValidator{
		pool:           pool,
		authorizedIPs:  make(map[string]bool),
		authorizedNets: make([]*net.IPNet, 0),
		users:          make(map[string]string),
		logger:         logger,
	}
}

func (v *IPValidator) LoadAuthorizedIPs() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := v.pool.Query(ctx, "SELECT id, ip, description, is_active, created_at FROM authorized_ips WHERE is_active = true")
	if err != nil {
		return err
	}
	defer rows.Close()

	newIPMap := make(map[string]bool)
	var newNets []*net.IPNet

	for rows.Next() {
		var doc AuthorizedIP
		if err := rows.Scan(&doc.ID, &doc.IP, &doc.Description, &doc.IsActive, &doc.CreatedAt); err != nil {
			return err
		}

		ip := strings.TrimSpace(doc.IP)
		if ip == "" {
			continue
		}

		if strings.Contains(ip, "/") {
			_, ipNet, err := net.ParseCIDR(ip)
			if err == nil {
				newNets = append(newNets, ipNet)
			}
		} else {
			newIPMap[ip] = true
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	v.mu.Lock()
	v.authorizedIPs = newIPMap
	v.authorizedNets = newNets
	v.mu.Unlock()

	return nil
}

func (v *IPValidator) LoadUsers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := v.pool.Query(ctx, "SELECT id, username, password, is_active, created_at FROM users WHERE is_active = true")
	if err != nil {
		return err
	}
	defer rows.Close()

	newUsers := make(map[string]string)

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.IsActive, &user.CreatedAt); err != nil {
			return err
		}
		newUsers[user.Username] = user.Password
	}

	if err := rows.Err(); err != nil {
		return err
	}

	v.mu.Lock()
	v.users = newUsers
	v.mu.Unlock()

	return nil
}

func (v *IPValidator) RefreshAuthorizedIPs() error {
	return v.LoadAuthorizedIPs()
}

func (v *IPValidator) RefreshUsers() error {
	return v.LoadUsers()
}

func (v *IPValidator) GetAuthorizedIPCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.authorizedIPs) + len(v.authorizedNets)
}

func (v *IPValidator) GetUserCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.users)
}

func (v *IPValidator) ValidateIP(r *http.Request) bool {
	clientIP := getClientIP(r)

	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.authorizedIPs[clientIP] {
		return true
	}

	ip := net.ParseIP(clientIP)
	if ip != nil {
		for _, ipNet := range v.authorizedNets {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func (v *IPValidator) ValidateProxyAuth(r *http.Request) bool {
	proxyAuth := r.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		proxyAuth = r.Header.Get("Authorization")
		if proxyAuth == "" {
			return false
		}
	}

	parts := strings.SplitN(proxyAuth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Format: {username}-country-{country}-session-{session_id}-sessTime-{duration}:{password}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) < 2 {
		return false
	}

	usernameStr := credentials[0]
	password := credentials[1]

	// Extract base username (everything before -country-)
	username := usernameStr
	if idx := strings.Index(usernameStr, "-country-"); idx != -1 {
		username = usernameStr[:idx]
	}

	v.mu.RLock()
	expectedPassword, exists := v.users[username]
	v.mu.RUnlock()

	return exists && expectedPassword == password
}

func (v *IPValidator) ValidateRequest(r *http.Request) (bool, string) {
	if !v.ValidateIP(r) {
		return false, "IP not authorized"
	}

	if !v.ValidateProxyAuth(r) {
		return false, "Invalid proxy credentials"
	}

	return true, "OK"
}

func getClientIP(r *http.Request) string {
	xoff := r.Header.Get("X-Original-Forwarded-For")
	if xoff != "" {
		ips := strings.Split(xoff, ",")
		ip := strings.TrimSpace(ips[0])
		if ip != "" && !isPrivateIP(ip) {
			return ip
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" && !isPrivateIP(ip) {
				return ip
			}
		}
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		ip := strings.TrimSpace(xri)
		if !isPrivateIP(ip) {
			return ip
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	if ip == "::1" {
		return "127.0.0.1"
	}

	return ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func (v *IPValidator) GetClientIP(r *http.Request) string {
	return getClientIP(r)
}

func (v *IPValidator) SendProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy Gateway\"")
	w.WriteHeader(http.StatusProxyAuthRequired)
	w.Write([]byte("Proxy Authentication Required"))
}
