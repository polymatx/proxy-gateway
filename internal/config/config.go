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
	// Health checking. Detection is passive, from real request outcomes;
	// probes only re-test providers already believed to be down, so a healthy
	// provider costs no upstream traffic.
	HealthEnabled       bool
	HealthProbeInterval time.Duration
	HealthProbeTarget   string
	HealthFallThreshold int
	HealthRiseThreshold int
}

func Load() *Config {
	enableTraffic, _ := strconv.ParseBool(getEnv("ENABLE_TRAFFIC_LOGGING", "true"))
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	meterSeconds, err := strconv.Atoi(getEnv("METER_INTERVAL_SECONDS", "15"))
	if err != nil || meterSeconds <= 0 {
		meterSeconds = 15
	}
	healthEnabled, _ := strconv.ParseBool(getEnv("HEALTH_CHECK_ENABLED", "true"))
	probeSeconds := atoiOr(getEnv("HEALTH_PROBE_INTERVAL_SECONDS", "30"), 30)
	// Named after HAProxy's fall/rise, and defaulted to match the relay's
	// backend, so the two layers agree on what "down" means.
	fall := atoiOr(getEnv("HEALTH_FALL", "3"), 3)
	rise := atoiOr(getEnv("HEALTH_RISE", "2"), 2)

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

		HealthEnabled:       healthEnabled,
		HealthProbeInterval: time.Duration(probeSeconds) * time.Second,
		HealthProbeTarget:   getEnv("HEALTH_PROBE_TARGET", "www.google.com:443"),
		HealthFallThreshold: fall,
		HealthRiseThreshold: rise,
	}
}

func atoiOr(raw string, fallback int) int {
	if v, err := strconv.Atoi(raw); err == nil && v > 0 {
		return v
	}
	return fallback
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
