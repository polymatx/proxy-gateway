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
| `METER_INTERVAL_SECONDS` | How often an open tunnel reports traffic and re-checks the balance | `15` |
| `PROXY_PROTOCOL_FROM` | Comma-separated IPs/CIDRs whose PROXY protocol header is believed | `` (disabled) |

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

## Client Addresses

Traffic normally reaches the gateway through a TCP relay, which means the peer
address on every connection is the relay's, not the customer's. Set
`PROXY_PROTOCOL_FROM` to the relay's address and configure the relay to send a
PROXY protocol v1 header (`send-proxy` in HAProxy) to recover the real one.

Two things are deliberate:

- **A header is only believed from a listed peer.** It is an unverifiable claim
  about who the client is, so honouring one from an arbitrary peer would let
  anyone reaching the port forge their address in `traffic_logs`.
- **A missing header is not an error.** The gateway can therefore be deployed
  before the relay is switched over, and direct connections keep working.

When a header is present it wins over `X-Forwarded-For` and friends: this is a
forward proxy, so those headers are written by the very client being identified.

A v2 (binary) header is refused rather than skipped, since ignoring it would
leave its body in the stream and corrupt the request behind it.

## Balance Checking

The gateway checks a user's remaining traffic before a request is allowed, and
keeps checking while a CONNECT tunnel is open.

1. **Redis cache** - remaining bytes are cached as `balance:cache:{username}` (30s TTL)
2. **Read-through** - on a cache miss the `balances` table is consulted, which is
   authoritative, and the cache is repopulated. Concurrent misses for one user
   collapse into a single query.
3. **HTTP 402** - if nothing remains, the request is refused
4. **Fail-open only on outage** - if neither Redis nor PostgreSQL can be reached the
   request is allowed and logged loudly. That path is unmetered, by design: an
   unreachable database should not take the platform down.

### Long-lived tunnels

A CONNECT tunnel can stay open for hours, so checking only at the start would let
an empty account transfer indefinitely. Each tunnel is opened with a budget equal
to the balance at that moment:

- the budget is decremented on **every read**, so a tunnel stops within one read
  buffer of spending it - overshoot does not scale with link speed
- every `METER_INTERVAL_SECONDS` (default 15) the bytes moved so far are pushed to
  the traffic queue, so the worker deducts them while the tunnel is still open,
  and the balance is re-read - this is what stops several concurrent tunnels from
  each spending the same allowance
- a long session therefore produces several `traffic_logs` rows rather than one,
  each covering a distinct slice of the transfer

```
Request -> IP Check -> Auth Check -> Balance Check -> Tunnel opens with a budget
                                          |                     |
                                          |-- > 0 -> Allow      |-- every read: budget -= n, 0 -> close
                                          |-- <= 0 -> HTTP 402  |-- every interval: report slice, re-read balance
                                          `-- unreachable -> Allow (logged, unmetered)
```

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
