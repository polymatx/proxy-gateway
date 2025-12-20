package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port          string
	PostgresURI   string
	LogLevel      string
	EnableTraffic bool
	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

func Load() *Config {
	enableTraffic, _ := strconv.ParseBool(getEnv("ENABLE_TRAFFIC_LOGGING", "true"))
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))

	return &Config{
		Port:          getEnv("PORT", "8080"),
		PostgresURI:   getEnv("POSTGRES_URI", ""),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		EnableTraffic: enableTraffic,
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       redisDB,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
