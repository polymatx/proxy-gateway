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
	logger.WithField("port", cfg.Port).Info("Starting Proxy Gateway")

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
			logger.Debug("Refreshing proxy list from database...")
			if err := proxyProvider.RefreshProxies(); err != nil {
				logger.WithError(err).Error("Failed to refresh proxies")
			} else {
				logger.WithField("proxy_count", proxyProvider.GetProxyCount()).Debug("Refreshed proxies")
			}
		}
	}()

	ipValidator := auth.NewIPValidator(dbClient.GetPool(), logger)
	if err := ipValidator.LoadAuthorizedIPs(); err != nil {
		logger.WithError(err).Fatal("Failed to load authorized IPs")
	}
	if err := ipValidator.LoadUsers(); err != nil {
		logger.WithError(err).Fatal("Failed to load users")
	}

	logger.WithFields(logrus.Fields{
		"authorized_ip_count": ipValidator.GetAuthorizedIPCount(),
		"user_count":          ipValidator.GetUserCount(),
	}).Info("Authentication configured")

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			logger.Debug("Refreshing authorized IPs and users from database...")
			if err := ipValidator.RefreshAuthorizedIPs(); err != nil {
				logger.WithError(err).Error("Failed to refresh authorized IPs")
			}
			if err := ipValidator.RefreshUsers(); err != nil {
				logger.WithError(err).Error("Failed to refresh users")
			}
			logger.WithFields(logrus.Fields{
				"authorized_ip_count": ipValidator.GetAuthorizedIPCount(),
				"user_count":          ipValidator.GetUserCount(),
			}).Debug("Refreshed authentication data")
		}
	}()

	gatewayTimeout := time.Duration(cfg.ProxyTimeout) * time.Second
	proxyGateway := proxy.NewGateway(proxyProvider, ipValidator, gatewayTimeout, logger)

	router := mux.NewRouter()

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		proxyCount := proxyProvider.GetProxyCount()
		if proxyCount == 0 {
			http.Error(w, "No proxies available", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"status":"healthy","proxy_count":%d,"authorized_ip_count":%d,"user_count":%d}`,
			proxyCount, ipValidator.GetAuthorizedIPCount(), ipValidator.GetUserCount())
		if _, err := w.Write([]byte(response)); err != nil {
			logger.WithError(err).Error("Failed to write health check response")
		}
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
		Addr:              ":" + cfg.Port,
		Handler:           topLevelHandler,
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
		MaxHeaderBytes:    0,
	}

	go func() {
		logger.WithField("port", cfg.Port).Info("Server starting")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.WithError(err).Fatal("Server failed to start")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server exited gracefully")
	}
}
