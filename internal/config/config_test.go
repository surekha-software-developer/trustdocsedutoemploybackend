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
	if cfg.AuthSessionCookieName != "trustdocs_session" {
		t.Errorf("expected default AuthSessionCookieName 'trustdocs_session', got '%s'", cfg.AuthSessionCookieName)
	}
	if cfg.AuthSessionTTL != 24*time.Hour {
		t.Errorf("expected default AuthSessionTTL 24h, got %v", cfg.AuthSessionTTL)
	}
	if cfg.AuthCookieSameSite != "Lax" {
		t.Errorf("expected default AuthCookieSameSite 'Lax', got '%s'", cfg.AuthCookieSameSite)
	}
	if cfg.Argon2Memory != 64*1024 {
		t.Errorf("expected default Argon2Memory 65536, got %d", cfg.Argon2Memory)
	}
	if cfg.Argon2Iterations != 3 {
		t.Errorf("expected default Argon2Iterations 3, got %d", cfg.Argon2Iterations)
	}
	if cfg.Argon2Parallelism != 2 {
		t.Errorf("expected default Argon2Parallelism 2, got %d", cfg.Argon2Parallelism)
	}
	if cfg.RateLimitLoginAttempts != 5 {
		t.Errorf("expected default RateLimitLoginAttempts 5, got %d", cfg.RateLimitLoginAttempts)
	}
}

func TestConfig_Validation(t *testing.T) {
	validBaseConfig := func() Config {
		return Config{
			AppEnv:                    "development",
			Port:                      "8080",
			FrontendURL:               "http://localhost:3000",
			LogLevel:                  "info",
			DatabaseURL:               "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
			DatabaseDirectURL:         "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
			DBMaxConns:                5,
			DBMinConns:                0,
			DBMaxConnLifetime:         30 * time.Minute,
			DBMaxConnIdleTime:         5 * time.Minute,
			DBHealthTimeout:           2 * time.Second,
			AuthSessionCookieName:     "trustdocs_session",
			AuthSessionTTL:            24 * time.Hour,
			AuthCookieSecure:          false,
			AuthCookieSameSite:        "Lax",
			CSRFSecret:                "test-csrf-secret-minimum-32-bytes-long-key!",
			Argon2Memory:              64 * 1024,
			Argon2Iterations:          3,
			Argon2Parallelism:         2,
			Argon2SaltLength:          16,
			Argon2KeyLength:           32,
			RateLimitLoginAttempts:    5,
			RateLimitLoginWindow:      15 * time.Minute,
			RateLimitIPAttempts:       20,
			RateLimitIPWindow:         15 * time.Minute,
			RateLimitRegisterAttempts: 10,
			RateLimitRegisterWindow:   1 * time.Hour,
			TrustedProxies:            []string{"127.0.0.1"},
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
		{
			name: "empty auth session cookie name",
			modify: func(c *Config) {
				c.AuthSessionCookieName = "   "
			},
			expectError: true,
			errContains: "AUTH_SESSION_COOKIE_NAME must not be empty",
		},
		{
			name: "auth session cookie name with spaces",
			modify: func(c *Config) {
				c.AuthSessionCookieName = "trustdocs session"
			},
			expectError: true,
			errContains: "AUTH_SESSION_COOKIE_NAME contains invalid characters",
		},
		{
			name: "auth session cookie name with semicolon separator",
			modify: func(c *Config) {
				c.AuthSessionCookieName = "trustdocs;session"
			},
			expectError: true,
			errContains: "AUTH_SESSION_COOKIE_NAME contains invalid characters",
		},
		{
			name: "auth session cookie name with equals separator",
			modify: func(c *Config) {
				c.AuthSessionCookieName = "trustdocs=session"
			},
			expectError: true,
			errContains: "AUTH_SESSION_COOKIE_NAME contains invalid characters",
		},
		{
			name: "valid cookie name with hyphen and period",
			modify: func(c *Config) {
				c.AuthSessionCookieName = "trustdocs_session-v1.0"
			},
			expectError: false,
		},
		{
			name: "auth session TTL negative",
			modify: func(c *Config) {
				c.AuthSessionTTL = -1 * time.Hour
			},
			expectError: true,
			errContains: "AUTH_SESSION_TTL must be positive duration",
		},
		{
			name: "auth session TTL exceeds 30 days",
			modify: func(c *Config) {
				c.AuthSessionTTL = 31 * 24 * time.Hour
			},
			expectError: true,
			errContains: "AUTH_SESSION_TTL cannot exceed 30 days",
		},
		{
			name: "invalid auth cookie same site",
			modify: func(c *Config) {
				c.AuthCookieSameSite = "Invalid"
			},
			expectError: true,
			errContains: "invalid AUTH_COOKIE_SAME_SITE",
		},
		{
			name: "auth cookie SameSite None without Secure rejected",
			modify: func(c *Config) {
				c.AuthCookieSameSite = "None"
				c.AuthCookieSecure = false
			},
			expectError: true,
			errContains: "AUTH_COOKIE_SAME_SITE=None requires AUTH_COOKIE_SECURE=true",
		},
		{
			name: "auth cookie SameSite None with Secure accepted",
			modify: func(c *Config) {
				c.AuthCookieSameSite = "None"
				c.AuthCookieSecure = true
			},
			expectError: false,
		},
		{
			name: "production mode with insecure cookies rejected",
			modify: func(c *Config) {
				c.AppEnv = "production"
				c.CSRFSecret = "12345678901234567890123456789012"
				c.AuthCookieSecure = false
			},
			expectError: true,
			errContains: "AUTH_COOKIE_SECURE must be true in production",
		},
		{
			name: "production mode with secure cookies accepted",
			modify: func(c *Config) {
				c.AppEnv = "production"
				c.CSRFSecret = "12345678901234567890123456789012"
				c.AuthCookieSecure = true
			},
			expectError: false,
		},
		{
			name: "csrf secret too short in production",
			modify: func(c *Config) {
				c.AppEnv = "production"
				c.AuthCookieSecure = true
				c.CSRFSecret = "short"
			},
			expectError: true,
			errContains: "CSRF_SECRET is required and must be at least 32 bytes in production",
		},
		{
			name: "invalid argon2 memory too small",
			modify: func(c *Config) {
				c.Argon2Memory = 8192
			},
			expectError: true,
			errContains: "invalid ARGON2_MEMORY",
		},
		{
			name: "invalid argon2 iterations zero",
			modify: func(c *Config) {
				c.Argon2Iterations = 0
			},
			expectError: true,
			errContains: "invalid ARGON2_ITERATIONS",
		},
		{
			name: "invalid argon2 parallelism zero",
			modify: func(c *Config) {
				c.Argon2Parallelism = 0
			},
			expectError: true,
			errContains: "invalid ARGON2_PARALLELISM",
		},
		{
			name: "invalid rate limit login attempts zero",
			modify: func(c *Config) {
				c.RateLimitLoginAttempts = 0
			},
			expectError: true,
			errContains: "invalid RATE_LIMIT_LOGIN_ATTEMPTS",
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
		AppEnv:                    "development",
		Port:                      "8080",
		FrontendURL:               "http://localhost:3000",
		LogLevel:                  "info",
		DatabaseURL:               "", // missing
		DatabaseDirectURL:         "", // optional for API
		DBMaxConns:                5,
		DBMinConns:                0,
		DBMaxConnLifetime:         30 * time.Minute,
		DBMaxConnIdleTime:         5 * time.Minute,
		DBHealthTimeout:           2 * time.Second,
		AuthSessionCookieName:     "trustdocs_session",
		AuthSessionTTL:            24 * time.Hour,
		AuthCookieSecure:          false,
		AuthCookieSameSite:        "Lax",
		CSRFSecret:                "test-csrf-secret-minimum-32-bytes-long-key!",
		Argon2Memory:              64 * 1024,
		Argon2Iterations:          3,
		Argon2Parallelism:         2,
		Argon2SaltLength:          16,
		Argon2KeyLength:           32,
		RateLimitLoginAttempts:    5,
		RateLimitLoginWindow:      15 * time.Minute,
		RateLimitIPAttempts:       20,
		RateLimitIPWindow:         15 * time.Minute,
		RateLimitRegisterAttempts: 10,
		RateLimitRegisterWindow:   1 * time.Hour,
		TrustedProxies:            []string{"127.0.0.1"},
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
