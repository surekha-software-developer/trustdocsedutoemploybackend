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
	if cfg.R2PresignTTL != 5*time.Minute {
		t.Errorf("expected default R2PresignTTL 5m, got %v", cfg.R2PresignTTL)
	}
	if cfg.CertificateMaxFileSize != 10485760 {
		t.Errorf("expected default CertificateMaxFileSize 10485760, got %d", cfg.CertificateMaxFileSize)
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
			R2PresignTTL:              5 * time.Minute,
			CertificateMaxFileSize:    10485760,
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
			name: "invalid R2 presign TTL zero",
			modify: func(c *Config) {
				c.R2PresignTTL = 0
			},
			expectError: true,
			errContains: "invalid R2_PRESIGN_TTL",
		},
		{
			name: "invalid R2 presign TTL exceeds 5m",
			modify: func(c *Config) {
				c.R2PresignTTL = 10 * time.Minute
			},
			expectError: true,
			errContains: "invalid R2_PRESIGN_TTL",
		},
		{
			name: "invalid certificate max file size zero",
			modify: func(c *Config) {
				c.CertificateMaxFileSize = 0
			},
			expectError: true,
			errContains: "invalid CERTIFICATE_MAX_FILE_SIZE",
		},
		{
			name: "invalid certificate max file size exceeds 10 MiB",
			modify: func(c *Config) {
				c.CertificateMaxFileSize = 20 * 1024 * 1024
			},
			expectError: true,
			errContains: "invalid CERTIFICATE_MAX_FILE_SIZE",
		},
		{
			name: "invalid R2 endpoint without HTTPS",
			modify: func(c *Config) {
				c.R2Endpoint = "http://insecure-r2.local"
			},
			expectError: true,
			errContains: "invalid R2_ENDPOINT: must use HTTPS",
		},
		{
			name: "partial R2 configuration rejected",
			modify: func(c *Config) {
				c.R2BucketName = "my-bucket"
				// missing access key, secret key, account id
			},
			expectError: true,
			errContains: "incomplete R2 configuration: missing R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ACCOUNT_ID",
		},
		{
			name: "valid full R2 configuration in general validate",
			modify: func(c *Config) {
				c.R2BucketName = "my-bucket"
				c.R2AccessKeyID = "key123"
				c.R2SecretAccessKey = "secret123"
				c.R2AccountID = "acc123"
			},
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

	cfg.R2PresignTTL = 5 * time.Minute
	cfg.CertificateMaxFileSize = 10485760

	err := cfg.ValidateForAPI()
	if err == nil {
		t.Fatalf("expected error when DATABASE_URL is empty, got nil")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL environment variable is required") {
		t.Errorf("expected required error, got: %v", err)
	}

	// 2. Supply valid DATABASE_URL, but without R2 configuration -> must fail in real API environment
	cfg.DatabaseURL = "postgres://user:secret@localhost:5432/testdb"
	err = cfg.ValidateForAPI()
	if err == nil {
		t.Fatalf("expected error when R2 configuration is missing for API, got nil")
	}
	if !strings.Contains(err.Error(), "missing required R2 environment variables") {
		t.Errorf("expected missing R2 error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "R2_BUCKET_NAME") || !strings.Contains(err.Error(), "R2_ACCESS_KEY_ID") {
		t.Errorf("expected missing variable names in error, got: %v", err)
	}

	// 3. Partial R2 configuration -> must fail and identify only missing names
	cfg.R2BucketName = "test-bucket"
	cfg.R2AccessKeyID = "test-key"
	err = cfg.ValidateForAPI()
	if err == nil {
		t.Fatalf("expected error for partial R2 config, got nil")
	}
	if !strings.Contains(err.Error(), "R2_SECRET_ACCESS_KEY") {
		t.Errorf("expected R2_SECRET_ACCESS_KEY in missing vars, got: %v", err)
	}
	// Verify no credential values or secrets printed
	if strings.Contains(err.Error(), "test-key") || strings.Contains(err.Error(), "test-bucket") {
		t.Errorf("error must not print configuration values; got: %v", err)
	}

	// 4. Complete valid R2 configuration -> must succeed
	cfg.R2SecretAccessKey = "test-secret"
	cfg.R2AccountID = "0123456789abcdef"
	err = cfg.ValidateForAPI()
	if err != nil {
		t.Fatalf("expected ValidateForAPI to succeed with full R2 config, got: %v", err)
	}

	// 5. Alternate valid configuration using explicit R2_ENDPOINT instead of R2_ACCOUNT_ID
	cfg.R2AccountID = ""
	cfg.R2Endpoint = "https://custom-r2.endpoint.com"
	err = cfg.ValidateForAPI()
	if err != nil {
		t.Fatalf("expected ValidateForAPI to succeed with R2_ENDPOINT, got: %v", err)
	}
}

func validBaseTestConfig() *Config {
	return &Config{
		AppEnv:                          "development",
		Port:                            "8080",
		FrontendURL:                     "http://localhost:3000",
		LogLevel:                        "info",
		DatabaseURL:                     "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
		DatabaseDirectURL:               "postgres://user:secret@localhost:5432/testdb?sslmode=disable",
		DBMaxConns:                      5,
		DBMinConns:                      0,
		DBMaxConnLifetime:               30 * time.Minute,
		DBMaxConnIdleTime:               5 * time.Minute,
		DBHealthTimeout:                 2 * time.Second,
		AuthSessionCookieName:           "trustdocs_session",
		AuthSessionTTL:                  24 * time.Hour,
		AuthCookieSecure:                false,
		AuthCookieSameSite:              "Lax",
		CSRFSecret:                      "test-csrf-secret-minimum-32-bytes-long-key!",
		Argon2Memory:                    64 * 1024,
		Argon2Iterations:                3,
		Argon2Parallelism:               2,
		Argon2SaltLength:                16,
		Argon2KeyLength:                 32,
		RateLimitLoginAttempts:          5,
		RateLimitLoginWindow:            15 * time.Minute,
		RateLimitIPAttempts:             20,
		RateLimitIPWindow:               15 * time.Minute,
		RateLimitRegisterAttempts:       10,
		RateLimitRegisterWindow:         1 * time.Hour,
		TrustedProxies:                  []string{"127.0.0.1"},
		R2PresignTTL:                    5 * time.Minute,
		CertificateMaxFileSize:          10485760,
		BlockchainEnabled:               false,
		BlockchainChainID:               80002,
		BlockchainConfirmationsRequired: 2,
		BlockchainPollInterval:          5 * time.Second,
		BlockchainConfirmationTimeout:   5 * time.Minute,
		BlockchainRPCTimeout:            10 * time.Second,
		AnchoringWorkerEnabled:          false,
		AnchoringBatchSize:              100,
		AnchoringBatchLease:             60 * time.Second,
		AnchoringMaxRetries:             5,
		AnchoringFeeBumpPercentage:      15,
	}
}

func TestConfig_BlockchainDefaults(t *testing.T) {
	cfg := validBaseTestConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid default blockchain config, got: %v", err)
	}
}

func TestConfig_LegacyDisabledRemainsValid(t *testing.T) {
	cfg := validBaseTestConfig()
	// Zero out all Phase 5B fields as a legacy config would have
	cfg.BlockchainEnabled = false
	cfg.BlockchainChainID = 0
	cfg.BlockchainRPCURL = ""
	cfg.BlockchainAnchorContractAddress = ""
	cfg.BlockchainConfirmationsRequired = 0
	cfg.BlockchainPollInterval = 0
	cfg.BlockchainConfirmationTimeout = 0
	cfg.BlockchainRPCTimeout = 0
	cfg.BlockchainSignerPrivateKey = ""
	cfg.BlockchainSignerAddress = ""
	cfg.BlockchainExplorerTxURL = ""
	cfg.AnchoringWorkerEnabled = false
	cfg.AnchoringBatchSize = 0
	cfg.AnchoringBatchLease = 0
	cfg.AnchoringMaxRetries = 0
	cfg.AnchoringFeeBumpPercentage = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected legacy config with zeroed Phase 5B fields to remain valid, got: %v", err)
	}
}

func TestConfig_BlockchainValidationBounds(t *testing.T) {
	baseCfg := func() *Config {
		cfg := validBaseTestConfig()
		cfg.BlockchainEnabled = true
		cfg.BlockchainRPCURL = "https://rpc-amoy.polygon.technology"
		cfg.BlockchainAnchorContractAddress = "0x000000000000000000000000000000000000dEaD"
		return cfg
	}

	// 1. Invalid Chain ID
	cfg := baseCfg()
	cfg.BlockchainChainID = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CHAIN_ID") {
		t.Errorf("expected error for ChainID <= 0, got: %v", err)
	}

	cfg = baseCfg()
	cfg.BlockchainChainID = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CHAIN_ID") {
		t.Errorf("expected error for ChainID < 0, got: %v", err)
	}

	// 2. Invalid Confirmations Required
	cfg = baseCfg()
	cfg.BlockchainConfirmationsRequired = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CONFIRMATIONS_REQUIRED") {
		t.Errorf("expected error for confirmations < 1, got: %v", err)
	}
	cfg = baseCfg()
	cfg.BlockchainConfirmationsRequired = 101
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CONFIRMATIONS_REQUIRED") {
		t.Errorf("expected error for confirmations > 100, got: %v", err)
	}

	// 3. Invalid Poll Interval
	cfg = baseCfg()
	cfg.BlockchainPollInterval = 500 * time.Millisecond
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_POLL_INTERVAL") {
		t.Errorf("expected error for poll interval < 1s, got: %v", err)
	}
	cfg = baseCfg()
	cfg.BlockchainPollInterval = 6 * time.Minute
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_POLL_INTERVAL") {
		t.Errorf("expected error for poll interval > 5m, got: %v", err)
	}

	// 4. Invalid Confirmation Timeout
	cfg = baseCfg()
	cfg.BlockchainConfirmationTimeout = 5 * time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CONFIRMATION_TIMEOUT") {
		t.Errorf("expected error for timeout < 10s, got: %v", err)
	}
	cfg = baseCfg()
	cfg.BlockchainConfirmationTimeout = 31 * time.Minute
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_CONFIRMATION_TIMEOUT") {
		t.Errorf("expected error for timeout > 30m, got: %v", err)
	}

	// 5. Invalid RPC Timeout
	cfg = baseCfg()
	cfg.BlockchainRPCTimeout = 500 * time.Millisecond
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_RPC_TIMEOUT") {
		t.Errorf("expected error for rpc timeout < 1s, got: %v", err)
	}
	cfg = baseCfg()
	cfg.BlockchainRPCTimeout = 65 * time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_RPC_TIMEOUT") {
		t.Errorf("expected error for rpc timeout > 60s, got: %v", err)
	}

	// Operational bounds for Anchoring Worker (requires AnchoringWorkerEnabled=true, valid signer material)
	baseWorkerCfg := func() *Config {
		c := baseCfg()
		c.AnchoringWorkerEnabled = true
		c.BlockchainSignerPrivateKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		c.BlockchainSignerAddress = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"
		return c
	}

	// 6. Invalid Fee Bump Percentage
	cfg = baseWorkerCfg()
	cfg.AnchoringFeeBumpPercentage = 5
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_FEE_BUMP_PERCENTAGE") {
		t.Errorf("expected error for fee bump < 10, got: %v", err)
	}
	cfg = baseWorkerCfg()
	cfg.AnchoringFeeBumpPercentage = 101
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_FEE_BUMP_PERCENTAGE") {
		t.Errorf("expected error for fee bump > 100, got: %v", err)
	}

	// 7. Invalid Batch Size
	cfg = baseWorkerCfg()
	cfg.AnchoringBatchSize = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_BATCH_SIZE") {
		t.Errorf("expected error for batch size < 1, got: %v", err)
	}
	cfg = baseWorkerCfg()
	cfg.AnchoringBatchSize = 1001
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_BATCH_SIZE") {
		t.Errorf("expected error for batch size > 1000, got: %v", err)
	}

	// 8. Invalid Lease
	cfg = baseWorkerCfg()
	cfg.AnchoringBatchLease = 5 * time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_BATCH_LEASE") {
		t.Errorf("expected error for lease < 10s, got: %v", err)
	}
	cfg = baseWorkerCfg()
	cfg.AnchoringBatchLease = 15 * time.Minute
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_BATCH_LEASE") {
		t.Errorf("expected error for lease > 10m, got: %v", err)
	}

	// 9. Invalid Max Retries
	cfg = baseWorkerCfg()
	cfg.AnchoringMaxRetries = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_MAX_RETRIES") {
		t.Errorf("expected error for retries < 1, got: %v", err)
	}
	cfg = baseWorkerCfg()
	cfg.AnchoringMaxRetries = 25
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ANCHORING_MAX_RETRIES") {
		t.Errorf("expected error for retries > 20, got: %v", err)
	}
}

func TestConfig_BlockchainEnabledValidation(t *testing.T) {
	cfg := validBaseTestConfig()
	cfg.BlockchainEnabled = true

	// Missing RPC URL
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_RPC_URL") {
		t.Errorf("expected error for missing RPC URL when blockchain enabled, got: %v", err)
	}

	// Invalid RPC URL scheme
	cfg.BlockchainRPCURL = "ftp://rpc.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid BLOCKCHAIN_RPC_URL") {
		t.Errorf("expected error for invalid RPC URL scheme, got: %v", err)
	}

	cfg.BlockchainRPCURL = "https://rpc-amoy.polygon.technology"
	// Missing Contract Address
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS") {
		t.Errorf("expected error for missing contract address, got: %v", err)
	}

	// Invalid Contract Address format
	cfg.BlockchainAnchorContractAddress = "0x123invalid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS") {
		t.Errorf("expected error for invalid contract address hex, got: %v", err)
	}

	// Valid Contract Address
	cfg.BlockchainAnchorContractAddress = "0x000000000000000000000000000000000000dEaD"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid blockchain config, got: %v", err)
	}

	// Invalid Explorer Tx URL scheme
	cfg.BlockchainExplorerTxURL = "ftp://explorer.example.com/tx/"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid BLOCKCHAIN_EXPLORER_TX_URL") {
		t.Errorf("expected error for invalid explorer tx url, got: %v", err)
	}
	cfg.BlockchainExplorerTxURL = "https://amoy.polygonscan.com/tx/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid blockchain config with explorer URL, got: %v", err)
	}
}

func TestConfig_AnchoringWorkerEnabledValidation(t *testing.T) {
	cfg := validBaseTestConfig()
	cfg.BlockchainEnabled = false
	cfg.AnchoringWorkerEnabled = true

	// Worker enabled while blockchain disabled
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_ENABLED must be true when ANCHORING_WORKER_ENABLED is true") {
		t.Errorf("expected error when worker enabled but blockchain disabled, got: %v", err)
	}

	// Enable blockchain and supply valid blockchain settings
	cfg.BlockchainEnabled = true
	cfg.BlockchainRPCURL = "https://rpc-amoy.polygon.technology"
	cfg.BlockchainAnchorContractAddress = "0x000000000000000000000000000000000000dEaD"

	// Missing private key
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_SIGNER_PRIVATE_KEY") {
		t.Errorf("expected error for missing private key when worker enabled, got: %v", err)
	}

	// Invalid private key format
	cfg.BlockchainSignerPrivateKey = "not-a-hex-key"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid BLOCKCHAIN_SIGNER_PRIVATE_KEY") {
		t.Errorf("expected error for invalid private key format, got: %v", err)
	}

	cfg.BlockchainSignerPrivateKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Missing signer address
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BLOCKCHAIN_SIGNER_ADDRESS") {
		t.Errorf("expected error for missing signer address when worker enabled, got: %v", err)
	}

	// Invalid signer address format
	cfg.BlockchainSignerAddress = "0xinvalid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid BLOCKCHAIN_SIGNER_ADDRESS") {
		t.Errorf("expected error for invalid signer address format, got: %v", err)
	}

	cfg.BlockchainSignerAddress = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid worker config, got: %v", err)
	}
}

func TestConfig_CompleteEnabledConfiguration(t *testing.T) {
	cfg := validBaseTestConfig()
	cfg.BlockchainEnabled = true
	cfg.BlockchainChainID = 80002
	cfg.BlockchainRPCURL = "https://rpc-amoy.polygon.technology"
	cfg.BlockchainAnchorContractAddress = "0x000000000000000000000000000000000000dEaD"
	cfg.BlockchainConfirmationsRequired = 2
	cfg.BlockchainPollInterval = 5 * time.Second
	cfg.BlockchainConfirmationTimeout = 5 * time.Minute
	cfg.BlockchainRPCTimeout = 10 * time.Second
	cfg.BlockchainExplorerTxURL = "https://amoy.polygonscan.com/tx/"
	cfg.AnchoringWorkerEnabled = true
	cfg.AnchoringBatchSize = 100
	cfg.AnchoringBatchLease = 60 * time.Second
	cfg.AnchoringMaxRetries = 5
	cfg.AnchoringFeeBumpPercentage = 15
	cfg.BlockchainSignerPrivateKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.BlockchainSignerAddress = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected complete enabled configuration to succeed, got: %v", err)
	}
}

func TestConfig_SecretRedaction(t *testing.T) {
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	csrfSecret := "super-secret-csrf-token-32-chars-long"
	r2Secret := "my-r2-secret-access-key-12345"
	dbURL := "postgres://user:supersecretpass@db.example.com:5432/trustdocs"
	rpcURL := "https://amoy.polygon.technology/v1/super-secret-rpc-key-12345"

	cfg := &Config{
		AppEnv:                     "production",
		Port:                       "8080",
		FrontendURL:                "https://trustdocs.example.com",
		DatabaseURL:                dbURL,
		CSRFSecret:                 csrfSecret,
		R2SecretAccessKey:          r2Secret,
		BlockchainEnabled:          true,
		BlockchainChainID:          80002,
		BlockchainRPCURL:           rpcURL,
		BlockchainSignerPrivateKey: secretKey,
		BlockchainSignerAddress:    "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
	}

	strOutput := cfg.String()
	goStrOutput := cfg.GoString()

	// Verify that none of the secrets appear in String() or GoString()
	for _, out := range []string{strOutput, goStrOutput} {
		if strings.Contains(out, secretKey) {
			t.Errorf("private key leaked in string output: %s", out)
		}
		if strings.Contains(out, csrfSecret) {
			t.Errorf("csrf secret leaked in string output: %s", out)
		}
		if strings.Contains(out, r2Secret) {
			t.Errorf("r2 secret leaked in string output: %s", out)
		}
		if strings.Contains(out, "supersecretpass") {
			t.Errorf("database password leaked in string output: %s", out)
		}
		if strings.Contains(out, "super-secret-rpc-key-12345") {
			t.Errorf("rpc secret leaked in string output: %s", out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("expected [REDACTED] placeholder in string output: %s", out)
		}
	}
}
