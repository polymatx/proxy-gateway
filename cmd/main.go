package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"proxy-gateway/internal/auth"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/database"
	"proxy-gateway/internal/proxy"
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
		balanceChecker, err = auth.NewBalanceChecker(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, logger)
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

	proxyGateway := proxy.NewGateway(proxyProvider, ipValidator, logger)

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

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","proxy_count":%d,"user_count":%d,"queue_length":%d}`,
			proxyCount, ipValidator.GetUserCount(), queueLen)
	}).Methods("GET")

	router.PathPrefix("/").HandlerFunc(proxyGateway.HandleHTTP)

	topLevelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			proxyGateway.HandleConnect(w, r)
		} else {
			router.ServeHTTP(w, r)
		}
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: topLevelHandler,
		// No timeouts - pure bridge mode
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	go func() {
		logger.WithField("port", cfg.Port).Info("Server starting (no timeouts)")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
