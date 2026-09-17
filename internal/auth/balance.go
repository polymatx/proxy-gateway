package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

const (
	BalanceCachePrefix = "balance:cache:"

	// Matches the TTL the traffic worker writes so both writers agree on how
	// long a cached balance stays valid.
	balanceCacheTTL = 30 * time.Second

	balanceQueryTimeout = 3 * time.Second
)

type BalanceChecker struct {
	redis  *redis.Client
	pool   *pgxpool.Pool
	group  singleflight.Group
	logger *logrus.Logger
}

func NewBalanceChecker(redisAddr, redisPassword string, redisDB int, pool *pgxpool.Pool, logger *logrus.Logger) (*BalanceChecker, error) {
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
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &BalanceChecker{
		redis:  rdb,
		pool:   pool,
		logger: logger,
	}, nil
}

// UnlimitedRemaining is returned when no authoritative figure can be obtained
// (no database configured, or the lookup failed). Callers treat it as "plenty",
// which preserves the fail-open behaviour: we would rather serve traffic we
// cannot meter than take the whole platform down.
const UnlimitedRemaining = int64(math.MaxInt64)

// HasBalance reports whether the user still has traffic left to spend.
func (b *BalanceChecker) HasBalance(ctx context.Context, username string) (bool, error) {
	remaining, err := b.Remaining(ctx, username)
	if err != nil {
		return false, err
	}
	return remaining > 0, nil
}

// Remaining reports how many bytes the user still has to spend.
//
// The Redis key is written by the traffic worker after each batch and expires
// after 30s, so it is absent whenever a user has been idle -- which is most of
// the time. Treating that absence as "allow" meant the balance was effectively
// unenforced outside sustained bursts, and a user with no allowance at all
// could keep pulling traffic. On a miss we consult the balances table, which
// is authoritative, and repopulate the cache from it.
func (b *BalanceChecker) Remaining(ctx context.Context, username string) (int64, error) {
	key := BalanceCachePrefix + username

	val, err := b.redis.Get(ctx, key).Result()
	switch {
	case err == nil:
		if remaining, convErr := strconv.ParseInt(val, 10, 64); convErr == nil {
			return remaining, nil
		}
		b.logger.WithField("username", username).
			Warn("Unparseable balance cache value, falling back to database")
	case errors.Is(err, redis.Nil):
		// Expected: the entry expired, or this user has simply been idle.
	default:
		b.logger.WithError(err).WithField("username", username).
			Warn("Balance cache unavailable, falling back to database")
	}

	return b.remainingFromDB(ctx, username, key)
}

// remainingFromDB is the authoritative check. Concurrent misses for the same
// user are collapsed into a single query so that a burst arriving after an idle
// period cannot stampede the database.
func (b *BalanceChecker) remainingFromDB(ctx context.Context, username, key string) (int64, error) {
	if b.pool == nil {
		// Nothing authoritative to consult; preserve availability.
		return UnlimitedRemaining, nil
	}

	v, err, _ := b.group.Do(username, func() (interface{}, error) {
		// Deliberately not derived from the request context: this result is
		// shared with every caller waiting on the same key, so one client
		// disconnecting must not cancel the lookup for the others.
		qctx, cancel := context.WithTimeout(context.Background(), balanceQueryTimeout)
		defer cancel()

		var remaining int64
		err := b.pool.QueryRow(qctx, `
			SELECT b.traffic_bytes - b.used_bytes
			FROM balances b
			JOIN users u ON u.id = b.user_id
			WHERE u.username = $1`, username).Scan(&remaining)

		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Provisioning creates a balances row alongside every user, so a
			// missing row means there is no allowance to spend.
			remaining = 0
		case err != nil:
			return nil, err
		}

		if remaining < 0 {
			remaining = 0
		}

		if cacheErr := b.redis.Set(qctx, key, remaining, balanceCacheTTL).Err(); cacheErr != nil {
			b.logger.WithError(cacheErr).WithField("username", username).
				Warn("Failed to repopulate balance cache")
		}
		return remaining, nil
	})

	if err != nil {
		// The database is the last line of defence. If it is unreachable we let
		// traffic through rather than halt the whole platform, but say so
		// loudly -- this path is unmetered.
		b.logger.WithError(err).WithField("username", username).
			Error("Balance lookup failed, allowing request unmetered")
		return UnlimitedRemaining, nil
	}

	return v.(int64), nil
}

func (b *BalanceChecker) Close() error {
	return b.redis.Close()
}
