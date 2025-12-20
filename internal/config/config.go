package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port         string
	PostgresURI  string
	ProxyTimeout int
	LogLevel     string
}

func Load() *Config {
	timeout, _ := strconv.Atoi(getEnv("PROXY_TIMEOUT", "30"))

	return &Config{
		Port:         getEnv("PORT", "8080"),
		PostgresURI:  getEnv("POSTGRES_URI", ""),
		ProxyTimeout: timeout,
		LogLevel:     getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
