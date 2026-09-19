package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the application configuration loaded from environment variables.
type Config struct {
	AppEnv            string
	Port              string
	FrontendURL       string
	LogLevel          string
	DatabaseURL       string
	DatabaseDirectURL string
	DBMaxConns        int
	DBMinConns        int
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration
	DBHealthTimeout   time.Duration
}

// Load loads configuration from environment variables with safe defaults.
func Load() (*Config, error) {
	maxConns, err := getEnvInt("DB_MAX_CONNS", 5)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_CONNS: %w", err)
	}

	minConns, err := getEnvInt("DB_MIN_CONNS", 0)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MIN_CONNS: %w", err)
	}

	maxConnLifetime, err := getEnvDuration("DB_MAX_CONN_LIFETIME", 30*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_CONN_LIFETIME: %w", err)
	}

	maxConnIdleTime, err := getEnvDuration("DB_MAX_CONN_IDLE_TIME", 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_CONN_IDLE_TIME: %w", err)
	}

	healthTimeout, err := getEnvDuration("DB_HEALTH_TIMEOUT", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_HEALTH_TIMEOUT: %w", err)
	}

	cfg := &Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		Port:              getEnv("PORT", "8080"),
		FrontendURL:       getEnv("FRONTEND_URL", "http://localhost:3000"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		DatabaseURL:       getEnv("DATABASE_URL", ""),
		DatabaseDirectURL: getEnv("DATABASE_DIRECT_URL", ""),
		DBMaxConns:        maxConns,
		DBMinConns:        minConns,
		DBMaxConnLifetime: maxConnLifetime,
		DBMaxConnIdleTime: maxConnIdleTime,
		DBHealthTimeout:   healthTimeout,
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation error: %w", err)
	}

	return cfg, nil
}

// Validate ensures all configuration fields conform to expected formats and ranges.
func (c *Config) Validate() error {
	switch c.AppEnv {
	case "development", "production", "test":
		// valid
	default:
		return fmt.Errorf("invalid APP_ENV '%s': must be development, production, or test", c.AppEnv)
	}

	portNum, err := strconv.Atoi(c.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid PORT '%s': must be an integer between 1 and 65535", c.Port)
	}

	if strings.TrimSpace(c.FrontendURL) == "" {
		return fmt.Errorf("FRONTEND_URL must not be empty")
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("invalid LOG_LEVEL '%s': must be debug, info, warn, or error", c.LogLevel)
	}

	if c.DBMaxConns < 1 {
		return fmt.Errorf("invalid DB_MAX_CONNS: must be an integer >= 1")
	}

	if c.DBMinConns < 0 {
		return fmt.Errorf("invalid DB_MIN_CONNS: must be an integer >= 0")
	}

	if c.DBMinConns > c.DBMaxConns {
		return fmt.Errorf("invalid DB_MIN_CONNS: cannot exceed DB_MAX_CONNS")
	}

	if c.DBMaxConnLifetime <= 0 {
		return fmt.Errorf("invalid DB_MAX_CONN_LIFETIME: must be positive duration")
	}

	if c.DBMaxConnIdleTime <= 0 {
		return fmt.Errorf("invalid DB_MAX_CONN_IDLE_TIME: must be positive duration")
	}

	if c.DBHealthTimeout <= 0 {
		return fmt.Errorf("invalid DB_HEALTH_TIMEOUT: must be positive duration")
	}

	if strings.TrimSpace(c.DatabaseURL) != "" {
		if err := validatePostgresURL(c.DatabaseURL); err != nil {
			return fmt.Errorf("invalid DATABASE_URL: malformed connection URL")
		}
	}

	if strings.TrimSpace(c.DatabaseDirectURL) != "" {
		if err := validatePostgresURL(c.DatabaseDirectURL); err != nil {
			return fmt.Errorf("invalid DATABASE_DIRECT_URL: malformed connection URL")
		}
	}

	return nil
}

// ValidateForAPI checks general validation and additionally ensures DATABASE_URL is present.
func (c *Config) ValidateForAPI() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}
	return nil
}

func validatePostgresURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("unsupported scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) (int, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := strconv.Atoi(strings.TrimSpace(valStr))
	if err != nil {
		return 0, fmt.Errorf("expected integer: %w", err)
	}
	return val, nil
}

func getEnvDuration(key string, defaultVal time.Duration) (time.Duration, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := time.ParseDuration(strings.TrimSpace(valStr))
	if err != nil {
		return 0, fmt.Errorf("expected duration (e.g. 30m, 5m, 2s): %w", err)
	}
	return val, nil
}
