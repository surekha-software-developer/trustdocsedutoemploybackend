package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
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

	// Phase 4A Authentication, Session & CSRF
	AuthSessionCookieName string
	AuthSessionTTL        time.Duration
	AuthCookieSecure      bool
	AuthCookieSameSite    string
	CSRFSecret            string

	// Argon2id Parameters
	Argon2Memory      uint32
	Argon2Iterations  uint32
	Argon2Parallelism uint8
	Argon2SaltLength  uint32
	Argon2KeyLength   uint32

	// Rate Limiting & Proxies
	RateLimitLoginAttempts    int
	RateLimitLoginWindow      time.Duration
	RateLimitIPAttempts       int
	RateLimitIPWindow         time.Duration
	RateLimitRegisterAttempts int
	RateLimitRegisterWindow   time.Duration
	TrustedProxies            []string

	// Phase 5A Cloudflare R2 Object Storage & Certificate File Configuration
	R2AccountID            string
	R2AccessKeyID          string
	R2SecretAccessKey      string
	R2BucketName           string
	R2Endpoint             string
	R2PresignTTL           time.Duration
	CertificateMaxFileSize int64

	// Phase 5B Blockchain & Merkle Anchoring Configuration
	BlockchainEnabled               bool
	BlockchainChainID               int64
	BlockchainRPCURL                string
	BlockchainAnchorContractAddress string
	BlockchainSignerPrivateKey      string // Redacted in String() and GoString()
	BlockchainSignerAddress         string
	BlockchainConfirmationsRequired int
	BlockchainPollInterval          time.Duration
	BlockchainConfirmationTimeout   time.Duration
	BlockchainRPCTimeout            time.Duration
	BlockchainExplorerTxURL         string
	AnchoringWorkerEnabled          bool
	AnchoringBatchSize              int
	AnchoringBatchLease             time.Duration
	AnchoringMaxRetries             int
	AnchoringFeeBumpPercentage      int
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

	sessionTTL, err := getEnvDuration("AUTH_SESSION_TTL", 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_SESSION_TTL: %w", err)
	}

	argon2Memory, err := getEnvUint32("ARGON2_MEMORY", 64*1024)
	if err != nil {
		return nil, fmt.Errorf("invalid ARGON2_MEMORY: %w", err)
	}

	argon2Iterations, err := getEnvUint32("ARGON2_ITERATIONS", 3)
	if err != nil {
		return nil, fmt.Errorf("invalid ARGON2_ITERATIONS: %w", err)
	}

	argon2Parallelism, err := getEnvUint8("ARGON2_PARALLELISM", 2)
	if err != nil {
		return nil, fmt.Errorf("invalid ARGON2_PARALLELISM: %w", err)
	}

	argon2SaltLength, err := getEnvUint32("ARGON2_SALT_LENGTH", 16)
	if err != nil {
		return nil, fmt.Errorf("invalid ARGON2_SALT_LENGTH: %w", err)
	}

	argon2KeyLength, err := getEnvUint32("ARGON2_KEY_LENGTH", 32)
	if err != nil {
		return nil, fmt.Errorf("invalid ARGON2_KEY_LENGTH: %w", err)
	}

	rateLimitLoginAttempts, err := getEnvInt("RATE_LIMIT_LOGIN_ATTEMPTS", 5)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_LOGIN_ATTEMPTS: %w", err)
	}

	rateLimitLoginWindow, err := getEnvDuration("RATE_LIMIT_LOGIN_WINDOW", 15*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_LOGIN_WINDOW: %w", err)
	}

	rateLimitIPAttempts, err := getEnvInt("RATE_LIMIT_IP_ATTEMPTS", 20)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_IP_ATTEMPTS: %w", err)
	}

	rateLimitIPWindow, err := getEnvDuration("RATE_LIMIT_IP_WINDOW", 15*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_IP_WINDOW: %w", err)
	}

	rateLimitRegisterAttempts, err := getEnvInt("RATE_LIMIT_REGISTER_ATTEMPTS", 10)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_REGISTER_ATTEMPTS: %w", err)
	}

	rateLimitRegisterWindow, err := getEnvDuration("RATE_LIMIT_REGISTER_WINDOW", 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_REGISTER_WINDOW: %w", err)
	}

	appEnv := getEnv("APP_ENV", "development")

	// In development/test, supply safe non-committed default for CSRFSecret if not provided; in production, require explicit secret
	defaultCSRFSecret := ""
	if appEnv == "development" || appEnv == "test" {
		defaultCSRFSecret = "dev-test-csrf-secret-must-be-at-least-32-bytes-long!"
	}

	// Default AuthCookieSecure to true in production, false otherwise
	defaultCookieSecure := false
	if appEnv == "production" {
		defaultCookieSecure = true
	}
	cookieSecure, err := getEnvBool("AUTH_COOKIE_SECURE", defaultCookieSecure)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_COOKIE_SECURE: %w", err)
	}

	r2PresignTTL, err := getEnvDuration("R2_PRESIGN_TTL", 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid R2_PRESIGN_TTL: %w", err)
	}

	certMaxFileSize, err := getEnvInt64("CERTIFICATE_MAX_FILE_SIZE", 10485760)
	if err != nil {
		return nil, fmt.Errorf("invalid CERTIFICATE_MAX_FILE_SIZE: %w", err)
	}

	blockchainEnabled, err := getEnvBool("BLOCKCHAIN_ENABLED", false)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_ENABLED: %w", err)
	}

	blockchainChainID, err := getEnvInt64("BLOCKCHAIN_CHAIN_ID", 80002)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_CHAIN_ID: %w", err)
	}

	blockchainConfirmationsRequired, err := getEnvInt("BLOCKCHAIN_CONFIRMATIONS_REQUIRED", 2)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_CONFIRMATIONS_REQUIRED: %w", err)
	}

	blockchainPollInterval, err := getEnvDuration("BLOCKCHAIN_POLL_INTERVAL", 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_POLL_INTERVAL: %w", err)
	}

	blockchainConfirmationTimeout, err := getEnvDuration("BLOCKCHAIN_CONFIRMATION_TIMEOUT", 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_CONFIRMATION_TIMEOUT: %w", err)
	}

	blockchainRPCTimeout, err := getEnvDuration("BLOCKCHAIN_RPC_TIMEOUT", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid BLOCKCHAIN_RPC_TIMEOUT: %w", err)
	}

	anchoringWorkerEnabled, err := getEnvBool("ANCHORING_WORKER_ENABLED", false)
	if err != nil {
		return nil, fmt.Errorf("invalid ANCHORING_WORKER_ENABLED: %w", err)
	}

	anchoringBatchSize, err := getEnvInt("ANCHORING_BATCH_SIZE", 100)
	if err != nil {
		return nil, fmt.Errorf("invalid ANCHORING_BATCH_SIZE: %w", err)
	}

	anchoringBatchLease, err := getEnvDuration("ANCHORING_BATCH_LEASE", 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid ANCHORING_BATCH_LEASE: %w", err)
	}

	anchoringMaxRetries, err := getEnvInt("ANCHORING_MAX_RETRIES", 5)
	if err != nil {
		return nil, fmt.Errorf("invalid ANCHORING_MAX_RETRIES: %w", err)
	}

	anchoringFeeBumpPercentage, err := getEnvInt("ANCHORING_FEE_BUMP_PERCENTAGE", 15)
	if err != nil {
		return nil, fmt.Errorf("invalid ANCHORING_FEE_BUMP_PERCENTAGE: %w", err)
	}

	trustedProxies := getEnvSlice("TRUSTED_PROXIES", []string{"127.0.0.1", "::1"})

	cfg := &Config{
		AppEnv:                          appEnv,
		Port:                            getEnv("PORT", "8080"),
		FrontendURL:                     getEnv("FRONTEND_URL", "http://localhost:3000"),
		LogLevel:                        getEnv("LOG_LEVEL", "info"),
		DatabaseURL:                     getEnv("DATABASE_URL", ""),
		DatabaseDirectURL:               getEnv("DATABASE_DIRECT_URL", ""),
		DBMaxConns:                      maxConns,
		DBMinConns:                      minConns,
		DBMaxConnLifetime:               maxConnLifetime,
		DBMaxConnIdleTime:               maxConnIdleTime,
		DBHealthTimeout:                 healthTimeout,
		AuthSessionCookieName:           getEnv("AUTH_SESSION_COOKIE_NAME", "trustdocs_session"),
		AuthSessionTTL:                  sessionTTL,
		AuthCookieSecure:                cookieSecure,
		AuthCookieSameSite:              getEnv("AUTH_COOKIE_SAME_SITE", "Lax"),
		CSRFSecret:                      getEnv("CSRF_SECRET", defaultCSRFSecret),
		Argon2Memory:                    argon2Memory,
		Argon2Iterations:                argon2Iterations,
		Argon2Parallelism:               argon2Parallelism,
		Argon2SaltLength:                argon2SaltLength,
		Argon2KeyLength:                 argon2KeyLength,
		RateLimitLoginAttempts:          rateLimitLoginAttempts,
		RateLimitLoginWindow:            rateLimitLoginWindow,
		RateLimitIPAttempts:             rateLimitIPAttempts,
		RateLimitIPWindow:               rateLimitIPWindow,
		RateLimitRegisterAttempts:       rateLimitRegisterAttempts,
		RateLimitRegisterWindow:         rateLimitRegisterWindow,
		TrustedProxies:                  trustedProxies,
		R2AccountID:                     getEnv("R2_ACCOUNT_ID", ""),
		R2AccessKeyID:                   getEnv("R2_ACCESS_KEY_ID", ""),
		R2SecretAccessKey:               getEnv("R2_SECRET_ACCESS_KEY", ""),
		R2BucketName:                    getEnv("R2_BUCKET_NAME", ""),
		R2Endpoint:                      getEnv("R2_ENDPOINT", ""),
		R2PresignTTL:                    r2PresignTTL,
		CertificateMaxFileSize:          certMaxFileSize,
		BlockchainEnabled:               blockchainEnabled,
		BlockchainChainID:               blockchainChainID,
		BlockchainRPCURL:                getEnv("BLOCKCHAIN_RPC_URL", ""),
		BlockchainAnchorContractAddress: getEnv("BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS", ""),
		BlockchainSignerPrivateKey:      getEnv("BLOCKCHAIN_SIGNER_PRIVATE_KEY", ""),
		BlockchainSignerAddress:         getEnv("BLOCKCHAIN_SIGNER_ADDRESS", ""),
		BlockchainConfirmationsRequired: blockchainConfirmationsRequired,
		BlockchainPollInterval:          blockchainPollInterval,
		BlockchainConfirmationTimeout:   blockchainConfirmationTimeout,
		BlockchainRPCTimeout:            blockchainRPCTimeout,
		BlockchainExplorerTxURL:         getEnv("BLOCKCHAIN_EXPLORER_TX_URL", ""),
		AnchoringWorkerEnabled:          anchoringWorkerEnabled,
		AnchoringBatchSize:              anchoringBatchSize,
		AnchoringBatchLease:             anchoringBatchLease,
		AnchoringMaxRetries:             anchoringMaxRetries,
		AnchoringFeeBumpPercentage:      anchoringFeeBumpPercentage,
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

	if strings.TrimSpace(c.AuthSessionCookieName) == "" {
		return fmt.Errorf("AUTH_SESSION_COOKIE_NAME must not be empty")
	}
	if !isValidCookieName(c.AuthSessionCookieName) {
		return fmt.Errorf("AUTH_SESSION_COOKIE_NAME contains invalid characters")
	}

	if c.AuthSessionTTL <= 0 {
		return fmt.Errorf("AUTH_SESSION_TTL must be positive duration")
	}
	if c.AuthSessionTTL > 30*24*time.Hour {
		return fmt.Errorf("AUTH_SESSION_TTL cannot exceed 30 days")
	}

	switch c.AuthCookieSameSite {
	case "Lax", "Strict", "None":
		// valid
	default:
		return fmt.Errorf("invalid AUTH_COOKIE_SAME_SITE '%s': must be Lax, Strict, or None", c.AuthCookieSameSite)
	}

	if c.AuthCookieSameSite == "None" && !c.AuthCookieSecure {
		return fmt.Errorf("AUTH_COOKIE_SAME_SITE=None requires AUTH_COOKIE_SECURE=true")
	}

	if c.AppEnv == "production" {
		if !c.AuthCookieSecure {
			return fmt.Errorf("AUTH_COOKIE_SECURE must be true in production")
		}
		if len(c.CSRFSecret) < 32 {
			return fmt.Errorf("CSRF_SECRET is required and must be at least 32 bytes in production")
		}
	} else if len(c.CSRFSecret) > 0 && len(c.CSRFSecret) < 32 {
		return fmt.Errorf("CSRF_SECRET must be at least 32 bytes")
	}

	if c.Argon2Memory < 16384 {
		return fmt.Errorf("invalid ARGON2_MEMORY: must be at least 16384 KiB (16 MB)")
	}

	if c.Argon2Iterations < 1 || c.Argon2Iterations > 10 {
		return fmt.Errorf("invalid ARGON2_ITERATIONS: must be between 1 and 10")
	}

	if c.Argon2Parallelism < 1 || c.Argon2Parallelism > 16 {
		return fmt.Errorf("invalid ARGON2_PARALLELISM: must be between 1 and 16")
	}

	if c.Argon2SaltLength < 16 {
		return fmt.Errorf("invalid ARGON2_SALT_LENGTH: must be at least 16 bytes")
	}

	if c.Argon2KeyLength < 32 {
		return fmt.Errorf("invalid ARGON2_KEY_LENGTH: must be at least 32 bytes")
	}

	if c.RateLimitLoginAttempts < 1 {
		return fmt.Errorf("invalid RATE_LIMIT_LOGIN_ATTEMPTS: must be >= 1")
	}

	if c.RateLimitLoginWindow <= 0 {
		return fmt.Errorf("invalid RATE_LIMIT_LOGIN_WINDOW: must be positive duration")
	}

	if c.RateLimitIPAttempts < 1 {
		return fmt.Errorf("invalid RATE_LIMIT_IP_ATTEMPTS: must be >= 1")
	}

	if c.RateLimitIPWindow <= 0 {
		return fmt.Errorf("invalid RATE_LIMIT_IP_WINDOW: must be positive duration")
	}

	if c.RateLimitRegisterAttempts < 1 {
		return fmt.Errorf("invalid RATE_LIMIT_REGISTER_ATTEMPTS: must be >= 1")
	}

	if c.RateLimitRegisterWindow <= 0 {
		return fmt.Errorf("invalid RATE_LIMIT_REGISTER_WINDOW: must be positive duration")
	}

	if c.R2PresignTTL <= 0 || c.R2PresignTTL > 5*time.Minute {
		return fmt.Errorf("invalid R2_PRESIGN_TTL: must be positive and not exceed 5m")
	}

	if c.CertificateMaxFileSize <= 0 || c.CertificateMaxFileSize > 10485760 {
		return fmt.Errorf("invalid CERTIFICATE_MAX_FILE_SIZE: must be between 1 and 10485760 bytes (10 MiB)")
	}

	if strings.TrimSpace(c.R2Endpoint) != "" && !strings.HasPrefix(strings.TrimSpace(c.R2Endpoint), "https://") {
		return fmt.Errorf("invalid R2_ENDPOINT: must use HTTPS")
	}

	// If partial R2 configuration is supplied, reject incomplete setup
	hasAnyR2 := strings.TrimSpace(c.R2AccountID) != "" ||
		strings.TrimSpace(c.R2AccessKeyID) != "" ||
		strings.TrimSpace(c.R2SecretAccessKey) != "" ||
		strings.TrimSpace(c.R2BucketName) != "" ||
		strings.TrimSpace(c.R2Endpoint) != ""

	if hasAnyR2 {
		var missing []string
		if strings.TrimSpace(c.R2BucketName) == "" {
			missing = append(missing, "R2_BUCKET_NAME")
		}
		if strings.TrimSpace(c.R2AccessKeyID) == "" {
			missing = append(missing, "R2_ACCESS_KEY_ID")
		}
		if strings.TrimSpace(c.R2SecretAccessKey) == "" {
			missing = append(missing, "R2_SECRET_ACCESS_KEY")
		}
		if strings.TrimSpace(c.R2AccountID) == "" && strings.TrimSpace(c.R2Endpoint) == "" {
			missing = append(missing, "R2_ACCOUNT_ID (or R2_ENDPOINT)")
		}
		if len(missing) > 0 {
			return fmt.Errorf("incomplete R2 configuration: missing %s", strings.Join(missing, ", "))
		}
	}

	// When ANCHORING_WORKER_ENABLED=true, require blockchain to be enabled
	if c.AnchoringWorkerEnabled && !c.BlockchainEnabled {
		return fmt.Errorf("BLOCKCHAIN_ENABLED must be true when ANCHORING_WORKER_ENABLED is true")
	}

	ethAddressRegex := regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	privateKeyRegex := regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)

	// When BLOCKCHAIN_ENABLED=true, require and validate blockchain settings
	if c.BlockchainEnabled {
		if c.BlockchainChainID <= 0 {
			return fmt.Errorf("invalid BLOCKCHAIN_CHAIN_ID: must be > 0")
		}

		if c.BlockchainConfirmationsRequired < 1 || c.BlockchainConfirmationsRequired > 100 {
			return fmt.Errorf("invalid BLOCKCHAIN_CONFIRMATIONS_REQUIRED: must be between 1 and 100")
		}

		if c.BlockchainPollInterval < time.Second || c.BlockchainPollInterval > 5*time.Minute {
			return fmt.Errorf("invalid BLOCKCHAIN_POLL_INTERVAL: must be between 1s and 5m")
		}

		if c.BlockchainConfirmationTimeout < 10*time.Second || c.BlockchainConfirmationTimeout > 30*time.Minute {
			return fmt.Errorf("invalid BLOCKCHAIN_CONFIRMATION_TIMEOUT: must be between 10s and 30m")
		}

		if c.BlockchainRPCTimeout < time.Second || c.BlockchainRPCTimeout > 60*time.Second {
			return fmt.Errorf("invalid BLOCKCHAIN_RPC_TIMEOUT: must be between 1s and 60s")
		}

		if strings.TrimSpace(c.BlockchainRPCURL) == "" {
			return fmt.Errorf("BLOCKCHAIN_RPC_URL is required when blockchain is enabled")
		}
		if !strings.HasPrefix(c.BlockchainRPCURL, "http://") && !strings.HasPrefix(c.BlockchainRPCURL, "https://") {
			return fmt.Errorf("invalid BLOCKCHAIN_RPC_URL: must start with http:// or https://")
		}
		if strings.TrimSpace(c.BlockchainAnchorContractAddress) == "" {
			return fmt.Errorf("BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS is required when blockchain is enabled")
		}
		if !ethAddressRegex.MatchString(strings.TrimSpace(c.BlockchainAnchorContractAddress)) {
			return fmt.Errorf("invalid BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS: must be 0x-prefixed 40-character hex address")
		}
	}

	// When ANCHORING_WORKER_ENABLED=true, require and validate worker operational settings
	if c.AnchoringWorkerEnabled {
		if c.AnchoringBatchSize < 1 || c.AnchoringBatchSize > 1000 {
			return fmt.Errorf("invalid ANCHORING_BATCH_SIZE: must be between 1 and 1000")
		}

		if c.AnchoringBatchLease < 10*time.Second || c.AnchoringBatchLease > 10*time.Minute {
			return fmt.Errorf("invalid ANCHORING_BATCH_LEASE: must be between 10s and 10m")
		}

		if c.AnchoringMaxRetries < 1 || c.AnchoringMaxRetries > 20 {
			return fmt.Errorf("invalid ANCHORING_MAX_RETRIES: must be between 1 and 20")
		}

		if c.AnchoringFeeBumpPercentage < 10 || c.AnchoringFeeBumpPercentage > 100 {
			return fmt.Errorf("invalid ANCHORING_FEE_BUMP_PERCENTAGE: must be between 10 and 100")
		}

		if strings.TrimSpace(c.BlockchainSignerPrivateKey) == "" {
			return fmt.Errorf("BLOCKCHAIN_SIGNER_PRIVATE_KEY is required when anchoring worker is enabled")
		}
		if !privateKeyRegex.MatchString(strings.TrimSpace(c.BlockchainSignerPrivateKey)) {
			return fmt.Errorf("invalid BLOCKCHAIN_SIGNER_PRIVATE_KEY: must be 64 hex characters (with optional 0x prefix)")
		}
		if strings.TrimSpace(c.BlockchainSignerAddress) == "" {
			return fmt.Errorf("BLOCKCHAIN_SIGNER_ADDRESS is required when anchoring worker is enabled")
		}
		if !ethAddressRegex.MatchString(strings.TrimSpace(c.BlockchainSignerAddress)) {
			return fmt.Errorf("invalid BLOCKCHAIN_SIGNER_ADDRESS: must be 0x-prefixed 40-character hex address")
		}
	}

	if strings.TrimSpace(c.BlockchainExplorerTxURL) != "" {
		if !strings.HasPrefix(c.BlockchainExplorerTxURL, "http://") && !strings.HasPrefix(c.BlockchainExplorerTxURL, "https://") {
			return fmt.Errorf("invalid BLOCKCHAIN_EXPLORER_TX_URL: must start with http:// or https://")
		}
	}

	return nil
}

// ValidateForAPI checks general validation, ensures DATABASE_URL is present, and ensures R2 configuration is complete.
func (c *Config) ValidateForAPI() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	var missingR2 []string
	if strings.TrimSpace(c.R2BucketName) == "" {
		missingR2 = append(missingR2, "R2_BUCKET_NAME")
	}
	if strings.TrimSpace(c.R2AccessKeyID) == "" {
		missingR2 = append(missingR2, "R2_ACCESS_KEY_ID")
	}
	if strings.TrimSpace(c.R2SecretAccessKey) == "" {
		missingR2 = append(missingR2, "R2_SECRET_ACCESS_KEY")
	}
	if strings.TrimSpace(c.R2AccountID) == "" && strings.TrimSpace(c.R2Endpoint) == "" {
		missingR2 = append(missingR2, "R2_ACCOUNT_ID (or R2_ENDPOINT)")
	}
	if len(missingR2) > 0 {
		return fmt.Errorf("missing required R2 environment variables: %s", strings.Join(missingR2, ", "))
	}

	if c.BlockchainEnabled {
		if strings.TrimSpace(c.BlockchainRPCURL) == "" {
			return fmt.Errorf("BLOCKCHAIN_RPC_URL is required when blockchain is enabled")
		}
		if strings.TrimSpace(c.BlockchainAnchorContractAddress) == "" {
			return fmt.Errorf("BLOCKCHAIN_ANCHOR_CONTRACT_ADDRESS is required when blockchain is enabled")
		}
	}

	return nil
}

// String implements fmt.Stringer with comprehensive secret redaction.
func (c *Config) String() string {
	return fmt.Sprintf("Config{AppEnv: %s, Port: %s, FrontendURL: %s, BlockchainEnabled: %t, ChainID: %d, RPCURL: [REDACTED], SignerAddress: %s, SignerPrivateKey: [REDACTED], CSRFSecret: [REDACTED], R2SecretAccessKey: [REDACTED], DatabaseURL: [REDACTED]}",
		c.AppEnv, c.Port, c.FrontendURL, c.BlockchainEnabled, c.BlockchainChainID, c.BlockchainSignerAddress)
}

// GoString implements fmt.GoStringer with comprehensive secret redaction.
func (c *Config) GoString() string {
	return c.String()
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

func getEnvInt64(key string, defaultVal int64) (int64, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
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

func getEnvUint32(key string, defaultVal uint32) (uint32, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := strconv.ParseUint(strings.TrimSpace(valStr), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("expected unsigned integer: %w", err)
	}
	return uint32(val), nil
}

func getEnvUint8(key string, defaultVal uint8) (uint8, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := strconv.ParseUint(strings.TrimSpace(valStr), 10, 8)
	if err != nil {
		return 0, fmt.Errorf("expected unsigned integer (1-255): %w", err)
	}
	return uint8(val), nil
}

func getEnvBool(key string, defaultVal bool) (bool, error) {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal, nil
	}
	val, err := strconv.ParseBool(strings.TrimSpace(valStr))
	if err != nil {
		return false, fmt.Errorf("expected boolean (true/false): %w", err)
	}
	return val, nil
}

func getEnvSlice(key string, defaultVal []string) []string {
	valStr := os.Getenv(key)
	if strings.TrimSpace(valStr) == "" {
		return defaultVal
	}
	parts := strings.Split(valStr, ",")
	results := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			results = append(results, trimmed)
		}
	}
	if len(results) == 0 {
		return defaultVal
	}
	return results
}

// isValidCookieName validates that a cookie name conforms to RFC 6265 / RFC 2616 token specification:
// non-empty, visible ASCII characters (33-126), strictly excluding separators and control characters.
func isValidCookieName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b <= 32 || b >= 127 {
			return false
		}
		switch b {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}
