package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProxyData struct {
	ID            int       `db:"id"`
	BaseURL       string    `db:"base_url"`
	Name          string    `db:"name"`
	Slug          string    `db:"slug"`
	Username      string    `db:"username"`
	Password      string    `db:"password"`
	URLTemplate   string    `db:"url_template"`
	PortMin       int       `db:"port_min"`
	PortMax       int       `db:"port_max"`
	IsVisible     bool      `db:"is_visible"`
	IsDisabled    bool      `db:"is_disabled"`
	IsGlobal      bool      `db:"is_global"`
	CountryFormat string    `db:"country_format"`
	CreatedAt     time.Time `db:"created_at"`
}

func (p *ProxyData) BuildProxyURL(country string, sessionID string, duration int) string {
	if p.URLTemplate == "" {
		return fmt.Sprintf("http://%s:%s@%s:%d", p.Username, p.Password, p.BaseURL, p.getPort())
	}

	if sessionID == "" {
		sessionID = fmt.Sprintf("%d", rand.Int63())
	}

	if country == "" && !p.IsGlobal {
		country = "US"
	}
	if duration == 0 {
		duration = 5
	}

	formattedCountry := p.formatCountry(country)

	url := p.URLTemplate
	url = strings.ReplaceAll(url, "{username}", p.Username)
	url = strings.ReplaceAll(url, "{password}", p.Password)
	url = strings.ReplaceAll(url, "{host}", p.BaseURL)
	url = strings.ReplaceAll(url, "{port}", fmt.Sprintf("%d", p.getPort()))
	url = strings.ReplaceAll(url, "{country}", formattedCountry)
	url = strings.ReplaceAll(url, "{session_id}", sessionID)
	url = strings.ReplaceAll(url, "{duration}", fmt.Sprintf("%d", duration))

	return "http://" + url
}

func (p *ProxyData) formatCountry(country string) string {
	switch p.CountryFormat {
	case "ISO":
		return strings.ToUpper(country)
	case "ISO_LOWERCASE":
		return strings.ToLower(country)
	case "FULL_NAME":
		return p.getCountryFullName(country)
	case "NO_SPACES":
		fullName := p.getCountryFullName(country)
		return strings.ReplaceAll(fullName, " ", "")
	default:
		return strings.ToUpper(country)
	}
}

func (p *ProxyData) getCountryFullName(isoCode string) string {
	country := countries.ByName(isoCode)
	if country == countries.Unknown {
		country = countries.ByName(strings.ToUpper(isoCode))
		if country == countries.Unknown {
			return "United States"
		}
	}
	return country.String()
}

func (p *ProxyData) getPort() int {
	if p.PortMin >= p.PortMax {
		return p.PortMin
	}
	return p.PortMin + rand.Intn(p.PortMax-p.PortMin+1)
}

type ProxyProvider struct {
	pool         *pgxpool.Pool
	proxies      []ProxyData
	proxyMap     map[string]*ProxyData
	mu           sync.RWMutex
	sessionCache *SessionCache
}

func NewProxyProvider(pool *pgxpool.Pool) *ProxyProvider {
	return &ProxyProvider{
		pool:     pool,
		proxyMap: make(map[string]*ProxyData),
	}
}

// SetSessionCache sets the Redis session cache for sticky sessions
func (p *ProxyProvider) SetSessionCache(cache *SessionCache) {
	p.sessionCache = cache
}

func (p *ProxyProvider) LoadProxies() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT id, base_url, name, slug, username, password, url_template,
		       port_min, port_max, is_visible, is_disabled, is_global,
		       COALESCE(country_format, 'ISO') as country_format, created_at
		FROM proxies
		WHERE is_visible = true AND is_disabled = false
	`

	rows, err := p.pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query proxies: %w", err)
	}
	defer rows.Close()

	var newProxies []ProxyData
	for rows.Next() {
		var proxy ProxyData
		err := rows.Scan(
			&proxy.ID, &proxy.BaseURL, &proxy.Name, &proxy.Slug,
			&proxy.Username, &proxy.Password, &proxy.URLTemplate,
			&proxy.PortMin, &proxy.PortMax, &proxy.IsVisible,
			&proxy.IsDisabled, &proxy.IsGlobal, &proxy.CountryFormat,
			&proxy.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to scan proxy row: %w", err)
		}
		newProxies = append(newProxies, proxy)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating proxy rows: %w", err)
	}

	newProxyMap := make(map[string]*ProxyData, len(newProxies))
	for i := range newProxies {
		if newProxies[i].Slug != "" {
			newProxyMap[newProxies[i].Slug] = &newProxies[i]
		}
	}

	p.mu.Lock()
	p.proxies = newProxies
	p.proxyMap = newProxyMap
	p.mu.Unlock()

	return nil
}

func (p *ProxyProvider) RefreshProxies() error {
	return p.LoadProxies()
}

func (p *ProxyProvider) GetProxyBySlug(slug string) *ProxyData {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxyMap[slug]
}

func (p *ProxyProvider) GetRandomProxy() *ProxyData {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.proxies) == 0 {
		return nil
	}

	idx := rand.Intn(len(p.proxies))
	return &p.proxies[idx]
}

// GetRandomGlobalProxy returns a random proxy where is_global = true
func (p *ProxyProvider) GetRandomGlobalProxy() *ProxyData {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var globalProxies []*ProxyData
	for i := range p.proxies {
		if p.proxies[i].IsGlobal {
			globalProxies = append(globalProxies, &p.proxies[i])
		}
	}

	if len(globalProxies) == 0 {
		return nil
	}

	return globalProxies[rand.Intn(len(globalProxies))]
}

// GetRandomNonGlobalProxy returns a random proxy where is_global = false
func (p *ProxyProvider) GetRandomNonGlobalProxy() *ProxyData {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var nonGlobalProxies []*ProxyData
	for i := range p.proxies {
		if !p.proxies[i].IsGlobal {
			nonGlobalProxies = append(nonGlobalProxies, &p.proxies[i])
		}
	}

	if len(nonGlobalProxies) == 0 {
		return nil
	}

	return nonGlobalProxies[rand.Intn(len(nonGlobalProxies))]
}

func (p *ProxyProvider) GetProxyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

func (p *ProxyProvider) GetAllProxies() []ProxyData {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]ProxyData(nil), p.proxies...)
}

// GetProxyForSession returns a proxy for the given session, ensuring stickiness
// If a session ID is provided and we have a cached proxy, return that proxy
// Otherwise, select a random proxy and cache it for future requests
// useGlobal determines whether to select from global (is_global=true) or non-global proxies
func (p *ProxyProvider) GetProxyForSession(ctx context.Context, username, country, sessionID string, durationMinutes int, useGlobal bool) *ProxyData {
	// If no session ID, just return random proxy based on global flag (no stickiness)
	if sessionID == "" {
		if useGlobal {
			return p.GetRandomGlobalProxy()
		}
		return p.GetRandomNonGlobalProxy()
	}

	// Try to get cached proxy for this session
	if p.sessionCache != nil {
		cachedSlug, err := p.sessionCache.GetProxySlug(ctx, username, country, sessionID, useGlobal)
		if err == nil && cachedSlug != "" {
			// Cache hit - return the same proxy
			if proxy := p.GetProxyBySlug(cachedSlug); proxy != nil {
				return proxy
			}
			// Cached proxy no longer exists, fall through to select new one
		}
	}

	// No cache or cache miss - select random proxy based on global flag
	var proxy *ProxyData
	if useGlobal {
		proxy = p.GetRandomGlobalProxy()
	} else {
		proxy = p.GetRandomNonGlobalProxy()
	}
	if proxy == nil {
		return nil
	}

	// Cache the selection for future requests with same session
	if p.sessionCache != nil && proxy.Slug != "" {
		_ = p.sessionCache.SetProxySlug(ctx, username, country, sessionID, proxy.Slug, durationMinutes, useGlobal)
	}

	return proxy
}
