package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"proxy-gateway/internal/auth"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/database"
	"proxy-gateway/internal/proxy"
	"proxy-gateway/internal/proxyproto"
	"proxy-gateway/internal/traffic"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	cfg := config.Load()
	logger.WithField("port", cfg.Port).Info("Starting Proxy Gateway (Bridge Mode)")

	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "warn", "warning":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	if cfg.PostgresURI == "" {
		logger.Fatal("POSTGRES_URI environment variable is required")
	}

	dbClient, err := database.NewClient(cfg.PostgresURI)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to PostgreSQL")
	}
	defer func() {
		if err := dbClient.Close(); err != nil {
			logger.WithError(err).Error("Failed to close database connection")
		}
	}()

	proxyProvider := proxy.NewProxyProvider(dbClient.GetPool())
	if err := proxyProvider.LoadProxies(); err != nil {
		logger.WithError(err).Fatal("Failed to load proxies")
	}
	logger.WithField("proxy_count", proxyProvider.GetProxyCount()).Info("Loaded proxies from database")

	// Initialize session cache for sticky sessions (uses Redis)
	sessionCache, err := proxy.NewSessionCache(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize session cache, sticky sessions disabled")
	} else {
		proxyProvider.SetSessionCache(sessionCache)
		defer sessionCache.Close()
		logger.Info("Session cache enabled for sticky sessions")
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := proxyProvider.RefreshProxies(); err != nil {
				logger.WithError(err).Error("Failed to refresh proxies")
			}
		}
	}()

	// Initialize balance checker (uses same Redis as traffic logger)
	var balanceChecker *auth.BalanceChecker
	if cfg.EnableTraffic {
		balanceChecker, err = auth.NewBalanceChecker(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, dbClient.GetPool(), logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize balance checker, balance checking disabled")
			balanceChecker = nil
		} else {
			defer balanceChecker.Close()
		}
	}

	ipValidator := auth.NewIPValidator(dbClient.GetPool(), logger, balanceChecker)
	if err := ipValidator.LoadAuthorizedIPs(); err != nil {
		logger.WithError(err).Fatal("Failed to load authorized IPs")
	}
	if err := ipValidator.LoadUsers(); err != nil {
		logger.WithError(err).Fatal("Failed to load users")
	}

	logger.WithFields(logrus.Fields{
		"authorized_ip_count":   ipValidator.GetAuthorizedIPCount(),
		"user_count":            ipValidator.GetUserCount(),
		"balance_check_enabled": balanceChecker != nil,
		"meter_interval":        cfg.MeterInterval.String(),
	}).Info("Authentication configured")

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := ipValidator.RefreshAuthorizedIPs(); err != nil {
				logger.WithError(err).Error("Failed to refresh authorized IPs")
			}
			if err := ipValidator.RefreshUsers(); err != nil {
				logger.WithError(err).Error("Failed to refresh users")
			}
		}
	}()

	var health *proxy.Health
	if cfg.HealthEnabled {
		health = proxy.NewHealth(proxy.HealthConfig{
			FailThreshold: cfg.HealthFallThreshold,
			RiseThreshold: cfg.HealthRiseThreshold,
			ProbeTarget:   cfg.HealthProbeTarget,
		}, logger)
		proxyProvider.SetHealth(health, logger)

		healthCtx, stopHealth := context.WithCancel(context.Background())
		defer stopHealth()
		go health.RunProbes(healthCtx, proxyProvider, cfg.HealthProbeInterval)

		logger.WithFields(logrus.Fields{
			"fall":           cfg.HealthFallThreshold,
			"rise":           cfg.HealthRiseThreshold,
			"probe_interval": cfg.HealthProbeInterval.String(),
			"probe_target":   cfg.HealthProbeTarget,
		}).Info("Provider health checking enabled")
	} else {
		logger.Warn("Provider health checking disabled; a failing upstream will keep receiving its share of traffic")
	}

	proxyGateway := proxy.NewGateway(proxyProvider, ipValidator, logger)
	proxyGateway.SetMeterInterval(cfg.MeterInterval)
	if health != nil {
		proxyGateway.SetHealth(health)
	}
	if balanceChecker != nil {
		// Guarded rather than passed unconditionally: a nil *BalanceChecker
		// stored in the interface would be non-nil to the gateway and panic on
		// first use.
		proxyGateway.SetBalanceChecker(balanceChecker)
	}

	// Initialize traffic logger with Redis
	var trafficLogger *traffic.Logger
	if cfg.EnableTraffic {
		trafficLogger, err = traffic.NewLogger(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize traffic logger")
		}
		proxyGateway.SetTrafficLogger(trafficLogger)
		logger.WithField("redis_addr", cfg.RedisAddr).Info("Traffic logging enabled")
	}

	router := mux.NewRouter()

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		proxyCount := proxyProvider.GetProxyCount()
		if proxyCount == 0 {
			http.Error(w, "No proxies available", http.StatusServiceUnavailable)
			return
		}

		var queueLen int64
		if trafficLogger != nil {
			queueLen, _ = trafficLogger.GetQueueLength(r.Context())
		}

		providers := "{}"
		if health != nil {
			if b, err := json.Marshal(health.Snapshot()); err == nil {
				providers = string(b)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","proxy_count":%d,"user_count":%d,"queue_length":%d,"providers":%s}`,
			proxyCount, ipValidator.GetUserCount(), queueLen, providers)
	}).Methods("GET")

	router.PathPrefix("/").HandlerFunc(proxyGateway.HandleHTTP)

	topLevelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			proxyGateway.HandleConnect(w, r)
		} else if r.URL.IsAbs() {
			// Proxy-mode HTTP request (e.g., GET http://example.com/)
			// Bypass mux to prevent URL modification
			proxyGateway.HandleHTTP(w, r)
		} else {
			// Direct request (e.g., GET /health)
			router.ServeHTTP(w, r)
		}
	})

	trustedProxies, err := proxyproto.ParseTrusted(cfg.ProxyProtocolFrom)
	if err != nil {
		logger.WithError(err).Fatal("Invalid PROXY_PROTOCOL_FROM")
	}

	listener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		logger.WithError(err).Fatal("Failed to listen")
	}

	server := &http.Server{
		Handler: topLevelHandler,
		// No timeouts - pure bridge mode
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	if len(trustedProxies) > 0 {
		// The header is read off the connection, so the handler has to reach
		// the connection to ask about it; ConnContext is the only hook that
		// runs early enough to make that possible.
		listener = proxyproto.NewListener(listener, trustedProxies)
		server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return proxyproto.WithConn(ctx, c)
		}
		logger.WithField("trusted", cfg.ProxyProtocolFrom).
			Info("PROXY protocol enabled; client addresses will come from trusted peers")
	} else {
		logger.Warn("PROXY_PROTOCOL_FROM not set; every request through the relay will be logged with the relay's address")
	}

	go func() {
		logger.WithField("port", cfg.Port).Info("Server starting (no timeouts)")
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.WithError(err).Fatal("Server failed to start")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down...")

	if trafficLogger != nil {
		trafficLogger.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server exited")
	}
}
