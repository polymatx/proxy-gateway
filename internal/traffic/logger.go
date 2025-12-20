package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	TrafficLogQueue = "traffic:logs"
)

type TrafficLogRequest struct {
	Username      string `json:"username"`
	RequestBytes  int64  `json:"request_bytes"`
	ResponseBytes int64  `json:"response_bytes"`
	TargetHost    string `json:"target_host"`
	TargetMethod  string `json:"target_method"`
	ProxySlug     string `json:"proxy_slug"`
	Country       string `json:"country"`
	SessionID     string `json:"session_id"`
	Duration      int    `json:"duration"`
	StatusCode    int    `json:"status_code"`
	ClientIP      string `json:"client_ip"`
	Timestamp     int64  `json:"timestamp"`
}

type Logger struct {
	redis      *redis.Client
	logger     *logrus.Logger
	buffer     []TrafficLogRequest
	bufferMu   sync.Mutex
	bufferSize int
	flushTick  *time.Ticker
	done       chan struct{}
	wg         sync.WaitGroup
}

func NewLogger(redisAddr, redisPassword string, redisDB int, logger *logrus.Logger) (*Logger, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPassword,
		DB:           redisDB,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	tl := &Logger{
		redis:      rdb,
		logger:     logger,
		buffer:     make([]TrafficLogRequest, 0, 200),
		bufferSize: 100,
		flushTick:  time.NewTicker(2 * time.Second),
		done:       make(chan struct{}),
	}

	tl.wg.Add(1)
	go tl.flushLoop()

	return tl, nil
}

func (l *Logger) flushLoop() {
	defer l.wg.Done()
	for {
		select {
		case <-l.flushTick.C:
			l.Flush()
		case <-l.done:
			l.Flush()
			return
		}
	}
}

func (l *Logger) Log(req TrafficLogRequest) {
	req.Timestamp = time.Now().UnixMilli()

	l.bufferMu.Lock()
	l.buffer = append(l.buffer, req)
	shouldFlush := len(l.buffer) >= l.bufferSize
	l.bufferMu.Unlock()

	if shouldFlush {
		go l.Flush()
	}
}

func (l *Logger) Flush() {
	l.bufferMu.Lock()
	if len(l.buffer) == 0 {
		l.bufferMu.Unlock()
		return
	}
	logs := make([]TrafficLogRequest, len(l.buffer))
	copy(logs, l.buffer)
	l.buffer = l.buffer[:0]
	l.bufferMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := l.redis.Pipeline()
	for _, log := range logs {
		data, err := json.Marshal(log)
		if err != nil {
			l.logger.WithError(err).Error("Failed to marshal traffic log")
			continue
		}
		pipe.RPush(ctx, TrafficLogQueue, data)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		l.logger.WithError(err).WithField("count", len(logs)).Error("Failed to push traffic logs to Redis")
		return
	}

	l.logger.WithField("count", len(logs)).Debug("Flushed traffic logs to Redis")
}

func (l *Logger) Close() {
	l.flushTick.Stop()
	close(l.done)
	l.wg.Wait()
	l.redis.Close()
}

func (l *Logger) GetQueueLength(ctx context.Context) (int64, error) {
	return l.redis.LLen(ctx, TrafficLogQueue).Result()
}
