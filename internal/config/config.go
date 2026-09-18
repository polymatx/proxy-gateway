package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port          string
	PostgresURI   string
	LogLevel      string
	EnableTraffic bool
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	// MeterInterval is how often an open CONNECT tunnel reports the bytes it
	// has moved and is re-checked against the user's balance.
	MeterInterval time.Duration
	// ProxyProtocolFrom lists the IPs and CIDRs whose PROXY protocol header is
	// believed. Empty disables the feature entirely. A header from anyone else
	// is ignored, because it is an unverifiable claim about who the client is.
	ProxyProtocolFrom string
}

func Load() *Config {
	enableTraffic, _ := strconv.ParseBool(getEnv("ENABLE_TRAFFIC_LOGGING", "true"))
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	meterSeconds, err := strconv.Atoi(getEnv("METER_INTERVAL_SECONDS", "15"))
	if err != nil || meterSeconds <= 0 {
		meterSeconds = 15
	}

	return &Config{
		Port:              getEnv("PORT", "8080"),
		PostgresURI:       getEnv("POSTGRES_URI", ""),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		EnableTraffic:     enableTraffic,
		RedisAddr:         getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:     getEnv("REDIS_PASSWORD", ""),
		RedisDB:           redisDB,
		MeterInterval:     time.Duration(meterSeconds) * time.Second,
		ProxyProtocolFrom: getEnv("PROXY_PROTOCOL_FROM", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
