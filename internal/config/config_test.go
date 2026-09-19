package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	// Clear any existing env vars for this test
	os.Unsetenv("APP_ENV")
	os.Unsetenv("PORT")
	os.Unsetenv("FRONTEND_URL")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("DATABASE_URL")
	os.Unsetenv("DATABASE_DIRECT_URL")
	os.Unsetenv("DB_MAX_CONNS")
	os.Unsetenv("DB_MIN_CONNS")
	os.Unsetenv("DB_MAX_CONN_LIFETIME")
	os.Unsetenv("DB_MAX_CONN_IDLE_TIME")
	os.Unsetenv("DB_HEALTH_TIMEOUT")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error loading defaults, got: %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Errorf("expected default AppEnv 'development', got '%s'", cfg.AppEnv)
	}
	if cfg.Port != "8080" {
		t.Errorf("expected default Port '8080', got '%s'", cfg.Port)
	}
	if cfg.FrontendURL != "http://localhost:3000" {
		t.Errorf("expected default FrontendURL 'http://localhost:3000', got '%s'", cfg.FrontendURL)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got '%s'", cfg.LogLevel)
	}
	if cfg.DatabaseURL != "" {
		t.Errorf("expected default DatabaseURL to be empty, got '%s'", cfg.DatabaseURL)
	}
	if cfg.DatabaseDirectURL != "" {
		t.Errorf("expected default DatabaseDirectURL to be empty, got '%s'", cfg.DatabaseDirectURL)
	}
	if cfg.DBMaxConns != 5 {
		t.Errorf("expected default DBMaxConns 5, got %d", cfg.DBMaxConns)
	}
	if cfg.DBMinConns != 0 {
		t.Errorf("expected default DBMinConns 0, got %d", cfg.DBMinConns)
	}
	if cfg.DBMaxConnLifetime != 30*time.Minute {
		t.Errorf("expected default DBMaxConnLifetime 30m, got %v", cfg.DBMaxConnLifetime)
	}
	if cfg.DBMaxConnIdleTime != 5*time.Minute {
		t.Errorf("expected default DBMaxConnIdleTime 5m, got %v", cfg.DBMaxConnIdleTime)
	}
	if cfg.DBHealthTimeout != 2*time.Second {
		t.Errorf("expected default DBHealthTimeout 2s, got %v", cfg.DBHealthTimeout)
	}
}

func TestConfig_Validation(t *testing.T) {
	validBaseConfig := func() Config {
		return Config{
			AppEnv:            "development",
			Port:              "8080",
			FrontendURL:       "http://localhost:3000",
			LogLevel:          "info",
			DatabaseURL:       "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
			DatabaseDirectURL: "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
			DBMaxConns:        5,
			DBMinConns:        0,
			DBMaxConnLifetime: 30 * time.Minute,
			DBMaxConnIdleTime: 5 * time.Minute,
			DBHealthTimeout:   2 * time.Second,
		}
	}

	tests := []struct {
		name        string
		modify      func(c *Config)
		expectError bool
		errContains string
	}{
		{
			name:        "valid configuration",
			modify:      func(c *Config) {},
			expectError: false,
		},
		{
			name: "valid postgresql scheme",
			modify: func(c *Config) {
				c.DatabaseURL = "postgresql://user:secret@localhost:5432/testdb"
			},
			expectError: false,
		},
		{
			name: "valid empty database URLs during general validation",
			modify: func(c *Config) {
				c.DatabaseURL = ""
				c.DatabaseDirectURL = ""
			},
			expectError: false,
		},
		{
			name: "invalid environment",
			modify: func(c *Config) {
				c.AppEnv = "staging_invalid"
			},
			expectError: true,
			errContains: "invalid APP_ENV",
		},
		{
			name: "invalid non-numeric port",
			modify: func(c *Config) {
				c.Port = "abc"
			},
			expectError: true,
			errContains: "invalid PORT",
		},
		{
			name: "invalid out-of-range port",
			modify: func(c *Config) {
				c.Port = "70000"
			},
			expectError: true,
			errContains: "invalid PORT",
		},
		{
			name: "empty frontend url",
			modify: func(c *Config) {
				c.FrontendURL = "   "
			},
			expectError: true,
			errContains: "FRONTEND_URL must not be empty",
		},
		{
			name: "invalid log level",
			modify: func(c *Config) {
				c.LogLevel = "verbose"
			},
			expectError: true,
			errContains: "invalid LOG_LEVEL",
		},
		{
			name: "invalid DB_MAX_CONNS zero",
			modify: func(c *Config) {
				c.DBMaxConns = 0
			},
			expectError: true,
			errContains: "DB_MAX_CONNS: must be an integer >= 1",
		},
		{
			name: "invalid DB_MIN_CONNS negative",
			modify: func(c *Config) {
				c.DBMinConns = -1
			},
			expectError: true,
			errContains: "DB_MIN_CONNS: must be an integer >= 0",
		},
		{
			name: "invalid DB_MIN_CONNS exceeds DB_MAX_CONNS",
			modify: func(c *Config) {
				c.DBMinConns = 10
				c.DBMaxConns = 5
			},
			expectError: true,
			errContains: "cannot exceed DB_MAX_CONNS",
		},
		{
			name: "invalid DB_MAX_CONN_LIFETIME zero",
			modify: func(c *Config) {
				c.DBMaxConnLifetime = 0
			},
			expectError: true,
			errContains: "DB_MAX_CONN_LIFETIME: must be positive duration",
		},
		{
			name: "invalid DB_MAX_CONN_IDLE_TIME zero",
			modify: func(c *Config) {
				c.DBMaxConnIdleTime = 0
			},
			expectError: true,
			errContains: "DB_MAX_CONN_IDLE_TIME: must be positive duration",
		},
		{
			name: "invalid DB_HEALTH_TIMEOUT zero",
			modify: func(c *Config) {
				c.DBHealthTimeout = 0
			},
			expectError: true,
			errContains: "DB_HEALTH_TIMEOUT: must be positive duration",
		},
		{
			name: "invalid DATABASE_URL scheme",
			modify: func(c *Config) {
				c.DatabaseURL = "mysql://user:pass@localhost:3306/db"
			},
			expectError: true,
			errContains: "invalid DATABASE_URL: malformed connection URL",
		},
		{
			name: "invalid DATABASE_URL missing host",
			modify: func(c *Config) {
				c.DatabaseURL = "postgres:///dbname"
			},
			expectError: true,
			errContains: "invalid DATABASE_URL: malformed connection URL",
		},
		{
			name: "invalid DATABASE_DIRECT_URL scheme",
			modify: func(c *Config) {
				c.DatabaseDirectURL = "http://localhost:5432"
			},
			expectError: true,
			errContains: "invalid DATABASE_DIRECT_URL: malformed connection URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(&cfg)
			err := cfg.Validate()
			if tt.expectError && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("expected no validation error, got: %v", err)
			}
			if tt.expectError && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errContains, err.Error())
				}
				// Verify secret was not leaked in error message
				if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "pass") {
					t.Errorf("error message must NOT leak credentials; got: %s", err.Error())
				}
			}
		})
	}
}

func TestConfig_ValidateForAPI(t *testing.T) {
	cfg := Config{
		AppEnv:            "development",
		Port:              "8080",
		FrontendURL:       "http://localhost:3000",
		LogLevel:          "info",
		DatabaseURL:       "", // missing
		DatabaseDirectURL: "", // optional for API
		DBMaxConns:        5,
		DBMinConns:        0,
		DBMaxConnLifetime: 30 * time.Minute,
		DBMaxConnIdleTime: 5 * time.Minute,
		DBHealthTimeout:   2 * time.Second,
	}

	err := cfg.ValidateForAPI()
	if err == nil {
		t.Fatalf("expected error when DATABASE_URL is empty, got nil")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL environment variable is required") {
		t.Errorf("expected required error, got: %v", err)
	}

	// Supply valid DATABASE_URL, leaving DATABASE_DIRECT_URL empty
	cfg.DatabaseURL = "postgres://user:secret@localhost:5432/testdb"
	err = cfg.ValidateForAPI()
	if err != nil {
		t.Errorf("expected ValidateForAPI to succeed without DATABASE_DIRECT_URL, got: %v", err)
	}
}
