# Proxy Gateway

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A high-performance HTTP/HTTPS proxy gateway written in Go. Authenticates clients via IP whitelist and username/password, then routes requests through upstream residential proxy providers with session and country support.

## Features

- **IP Whitelist Authentication** - Supports individual IPs and CIDR ranges
- **User Authentication** - Dynamic username/password from PostgreSQL
- **Balance Checking** - Real-time balance verification via Redis cache
- **Traffic Logging** - Async traffic logging to Redis queue for processing
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
  -e REDIS_ADDR="localhost:6379" \
  -e ENABLE_TRAFFIC_LOGGING="true" \
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
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=
      - REDIS_DB=0
      - ENABLE_TRAFFIC_LOGGING=true
      - LOG_LEVEL=info
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: proxydb
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
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
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |
| `ENABLE_TRAFFIC_LOGGING` | Enable traffic logging and balance checking | `true` |
| `REDIS_ADDR` | Redis server address | `localhost:6379` |
| `REDIS_PASSWORD` | Redis password | `` |
| `REDIS_DB` | Redis database number | `0` |

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

-- User balances
CREATE TABLE balances (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    traffic_bytes BIGINT DEFAULT 0,
    used_bytes BIGINT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

-- Traffic logs
CREATE TABLE traffic_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    request_bytes BIGINT DEFAULT 0,
    response_bytes BIGINT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    target_host VARCHAR(255),
    target_method VARCHAR(10),
    proxy_slug VARCHAR(255),
    country VARCHAR(10),
    session_id VARCHAR(100),
    duration INTEGER,
    status_code INTEGER,
    client_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);
CREATE UNIQUE INDEX idx_balances_user_id ON balances(user_id);
CREATE INDEX idx_authorized_ips_active ON authorized_ips(is_active);
CREATE INDEX idx_proxies_visible_disabled ON proxies(is_visible, is_disabled);
CREATE INDEX idx_traffic_logs_user_id ON traffic_logs(user_id);
CREATE INDEX idx_traffic_logs_created_at ON traffic_logs(created_at);
```

### Example Data

```sql
-- Add a user
INSERT INTO users (username, password) VALUES ('myuser', 'mysecretpass');

-- Add balance (10GB)
INSERT INTO balances (user_id, traffic_bytes, used_bytes) VALUES (1, 10737418240, 0);

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
  "user_count": 3,
  "queue_length": 42
}
```

## Balance Checking

The gateway checks user balance before allowing requests:

1. **Redis Cache** - Balance is cached in Redis with key `balance:cache:{username}`
2. **Fail-Open** - If cache miss, request is allowed (balance synced by worker)
3. **HTTP 402** - If balance ≤ 0, returns "Payment Required"

### How It Works

```
Request → IP Check → Auth Check → Balance Check → Forward to Proxy
                                       │
                                       ├── Cache Hit & Balance > 0 → Allow
                                       ├── Cache Hit & Balance ≤ 0 → HTTP 402
                                       └── Cache Miss → Allow (fail-open)
```

The balance cache is updated by a separate worker service that:
1. Consumes traffic logs from Redis queue
2. Updates `used_bytes` in PostgreSQL
3. Updates `balance:cache:{username}` in Redis

## Traffic Logging

When `ENABLE_TRAFFIC_LOGGING=true`, the gateway logs all traffic to a Redis queue:

- **Queue Name**: `traffic:logs`
- **Format**: JSON with request/response bytes, target host, proxy used, etc.
- **Processing**: Consumed by a worker service for persistence

### Traffic Log Structure

```json
{
  "username": "myuser",
  "request_bytes": 1024,
  "response_bytes": 4096,
  "target_host": "api.example.com:443",
  "target_method": "CONNECT",
  "proxy_slug": "example-provider",
  "country": "US",
  "session_id": "abc123",
  "duration": 5,
  "status_code": 200,
  "client_ip": "203.0.113.50",
  "timestamp": 1703001234567
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
                    ┌───────┴───────┐
                    ▼               ▼
            ┌───────────────┐ ┌─────────────┐
            │  PostgreSQL   │ │    Redis    │
            │  - users      │ │  - traffic  │
            │  - balances   │ │    queue    │
            │  - auth_ips   │ │  - balance  │
            │  - proxies    │ │    cache    │
            └───────────────┘ └─────────────┘
                                    │
                                    ▼
                            ┌───────────────┐
                            │ Worker Service│
                            │ (luminaproxy- │
                            │     api)      │
                            └───────────────┘
```

## Error Responses

| HTTP Code | Reason |
|-----------|--------|
| 402 | Insufficient balance |
| 403 | IP not authorized |
| 407 | Invalid proxy credentials |
| 502 | Upstream proxy error |
| 503 | No proxies available |

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
