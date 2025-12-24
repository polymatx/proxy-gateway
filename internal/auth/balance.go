package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	BalanceCachePrefix = "balance:cache:"
)

type BalanceChecker struct {
	redis  *redis.Client
	logger *logrus.Logger
}

func NewBalanceChecker(redisAddr, redisPassword string, redisDB int, logger *logrus.Logger) (*BalanceChecker, error) {
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
		logger: logger,
	}, nil
}

func (b *BalanceChecker) HasBalance(ctx context.Context, username string) (bool, error) {
	key := BalanceCachePrefix + username

	val, err := b.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		// No cache entry - allow request (fail-open)
		// The balance will be checked when synced from DB
		return true, nil
	}
	if err != nil {
		b.logger.WithError(err).Warn("Failed to check balance cache, allowing request")
		return true, nil
	}

	remaining, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return true, nil
	}

	return remaining > 0, nil
}

func (b *BalanceChecker) Close() error {
	return b.redis.Close()
}
