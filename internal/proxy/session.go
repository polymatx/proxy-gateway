package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	SessionCachePrefix = "session:proxy:"
)

// SessionCache manages session-to-proxy affinity using Redis
type SessionCache struct {
	redis  *redis.Client
	logger *logrus.Logger
}

// NewSessionCache creates a new Redis-backed session cache
func NewSessionCache(redisAddr, redisPassword string, redisDB int, logger *logrus.Logger) (*SessionCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPassword,
		DB:           redisDB,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis for session cache: %w", err)
	}

	return &SessionCache{
		redis:  rdb,
		logger: logger,
	}, nil
}

// buildCacheKey creates a unique cache key for session affinity
// Format: session:proxy:{username}:{country}:{sessionID}:{global|regional}
func (s *SessionCache) buildCacheKey(username, country, sessionID string, useGlobal bool) string {
	proxyType := "regional"
	if useGlobal {
		proxyType = "global"
	}
	return fmt.Sprintf("%s%s:%s:%s:%s", SessionCachePrefix, username, country, sessionID, proxyType)
}

// GetProxySlug retrieves the cached proxy slug for a session
// Returns empty string if no cache entry exists
func (s *SessionCache) GetProxySlug(ctx context.Context, username, country, sessionID string, useGlobal bool) (string, error) {
	if sessionID == "" {
		return "", nil // No session ID means no stickiness needed
	}

	key := s.buildCacheKey(username, country, sessionID, useGlobal)
	slug, err := s.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // Cache miss - not an error
	}
	if err != nil {
		return "", fmt.Errorf("failed to get session cache: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"session_id": sessionID,
		"proxy_slug": slug,
		"use_global": useGlobal,
		"cache_hit":  true,
	}).Debug("Session cache hit")

	return slug, nil
}

// SetProxySlug stores the proxy slug for a session with TTL matching sessTime exactly
// After sessTime expires, the same session ID will get a new proxy selection
func (s *SessionCache) SetProxySlug(ctx context.Context, username, country, sessionID, proxySlug string, durationMinutes int, useGlobal bool) error {
	if sessionID == "" || proxySlug == "" {
		return nil // Nothing to cache
	}

	key := s.buildCacheKey(username, country, sessionID, useGlobal)
	ttl := time.Duration(durationMinutes) * time.Minute

	err := s.redis.Set(ctx, key, proxySlug, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set session cache: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"session_id": sessionID,
		"proxy_slug": proxySlug,
		"use_global": useGlobal,
		"ttl":        ttl.String(),
	}).Debug("Session cache set")

	return nil
}

// Close closes the Redis connection
func (s *SessionCache) Close() error {
	return s.redis.Close()
}
