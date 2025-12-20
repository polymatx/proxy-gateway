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
	pool     *pgxpool.Pool
	proxies  []ProxyData
	proxyMap map[string]*ProxyData
	mu       sync.RWMutex
}

func NewProxyProvider(pool *pgxpool.Pool) *ProxyProvider {
	return &ProxyProvider{
		pool:     pool,
		proxyMap: make(map[string]*ProxyData),
	}
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
