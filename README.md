# Proxy Gateway

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A high-performance HTTP/HTTPS proxy gateway written in Go. Authenticates clients via IP whitelist and username/password, then routes requests through upstream residential proxy providers with session and country support.

## Features

- **IP Whitelist Authentication** - Supports individual IPs and CIDR ranges
- **User Authentication** - Dynamic username/password from PostgreSQL
- **Random Proxy Selection** - Automatically selects from available proxy providers
- **Session Management** - Sticky sessions with configurable duration
- **Country Routing** - Route traffic through specific countries
- **HTTP/HTTPS Support** - Full support for both HTTP and CONNECT tunneling
- **Health Checks** - Built-in health endpoint for monitoring
- **Graceful Shutdown** - Clean connection handling on shutdown
- **Auto-Refresh** - Periodically reloads proxies and auth data from database

## Quick Start

### Using Docker

```bash
docker run -d \
  -p 8080:8080 \
  -e POSTGRES_URI="postgres://user:pass@host:5432/dbname" \
  ghcr.io/YOUR_USERNAME/proxy-gateway:latest
```

### Using Docker Compose

```yaml
version: '3.8'
services:
  proxy-gateway:
    image: ghcr.io/YOUR_USERNAME/proxy-gateway:latest
    ports:
      - "8080:8080"
    environment:
      - POSTGRES_URI=postgres://user:pass@postgres:5432/proxydb
      - LOG_LEVEL=info
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: proxydb
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Building from Source

```bash
git clone https://github.com/YOUR_USERNAME/proxy-gateway.git
cd proxy-gateway
go mod tidy
go build -o proxy-gateway cmd/main.go
./proxy-gateway
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `PORT` | Server listening port | `8080` |
| `POSTGRES_URI` | PostgreSQL connection string | **Required** |
| `PROXY_TIMEOUT` | Request timeout in seconds | `30` |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |

## Database Setup

### Schema

```sql
-- Users table for authentication
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Authorized IPs whitelist
CREATE TABLE authorized_ips (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Upstream proxy providers
CREATE TABLE proxies (
    id SERIAL PRIMARY KEY,
    base_url VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    url_template TEXT NOT NULL,
    port_min INTEGER NOT NULL,
    port_max INTEGER NOT NULL,
    is_visible BOOLEAN DEFAULT true,
    is_disabled BOOLEAN DEFAULT false,
    is_global BOOLEAN DEFAULT false,
    country_format VARCHAR(50) DEFAULT 'ISO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_authorized_ips_active ON authorized_ips(is_active);
CREATE INDEX idx_proxies_visible_disabled ON proxies(is_visible, is_disabled);
```

### Example Data

```sql
-- Add a user
INSERT INTO users (username, password) VALUES ('myuser', 'mysecretpass');

-- Add authorized IP
INSERT INTO authorized_ips (ip, description) VALUES ('203.0.113.50', 'Office IP');
INSERT INTO authorized_ips (ip, description) VALUES ('10.0.0.0/8', 'Internal network');

-- Add a proxy provider
INSERT INTO proxies (base_url, name, slug, username, password, url_template, port_min, port_max, country_format)
VALUES (
    'proxy.provider.com',
    'Example Provider',
    'example-provider',
    'provideruser',
    'providerpass',
    '{username}-country-{country}-session-{session_id}-sessTime-{duration}:{password}@{host}:{port}',
    10000,
    10100,
    'ISO'
);
```

## Usage

### Proxy URL Format

```
{username}-country-{COUNTRY}-session-{SESSION_ID}-sessTime-{DURATION}:{password}@gateway:port
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `username` | Your username from users table | Required |
| `password` | Your password from users table | Required |
| `COUNTRY` | ISO country code (US, GB, DE, etc.) | US |
| `SESSION_ID` | Sticky session identifier | Auto-generated |
| `DURATION` | Session duration in minutes | 5 |

### Examples

```bash
# Full format with all parameters
curl -x "myuser-country-US-session-abc123-sessTime-10:mypassword@localhost:8080" \
  https://api.example.com

# With country only
curl -x "myuser-country-DE:mypassword@localhost:8080" \
  https://httpbin.org/ip

# Minimal (uses defaults: country=US, session=random, duration=5)
curl -x "myuser:mypassword@localhost:8080" \
  https://httpbin.org/ip

# HTTPS request
curl -x "myuser-country-GB-session-xyz789-sessTime-15:mypassword@localhost:8080" \
  https://api.example.com/secure
```

### Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "proxy_count": 5,
  "authorized_ip_count": 10,
  "user_count": 3
}
```

## URL Template Placeholders

When configuring proxy providers, use these placeholders in `url_template`:

| Placeholder | Description |
|-------------|-------------|
| `{username}` | Proxy provider username |
| `{password}` | Proxy provider password |
| `{host}` | Proxy provider host (base_url) |
| `{port}` | Random port from port_min to port_max |
| `{country}` | Formatted country code |
| `{session_id}` | Session identifier |
| `{duration}` | Session duration |

### Country Format Options

Set `country_format` in the proxies table:

| Format | Example Input | Output |
|--------|---------------|--------|
| `ISO` | us | US |
| `ISO_LOWERCASE` | US | us |
| `FULL_NAME` | US | United States |
| `NO_SPACES` | US | UnitedStates |

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Client    │────▶│  Proxy Gateway  │────▶│ Upstream Proxies │
└─────────────┘     └─────────────────┘     └──────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  PostgreSQL   │
                    │  - users      │
                    │  - auth_ips   │
                    │  - proxies    │
                    └───────────────┘
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by [Polymatx](https://polymatx.dev)
