package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the application configuration loaded from environment variables.
type Config struct {
	AppEnv      string
	Port        string
	FrontendURL string
	LogLevel    string
}

// Load loads configuration from environment variables with safe defaults.
func Load() (*Config, error) {
	cfg := &Config{
		AppEnv:      getEnv("APP_ENV", "development"),
		Port:        getEnv("PORT", "8080"),
		FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
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

	return nil
}

func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}
