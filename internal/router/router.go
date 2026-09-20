package router

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/certificates"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/health"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/organizations"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

// Option configures optional dependencies for SetupRouter.
type Option func(*options)

type options struct {
	storage storage.ObjectStorage
}

// WithObjectStorage explicitly injects an ObjectStorage implementation.
// router.go never creates, selects, or defaults to mock storage.
func WithObjectStorage(s storage.ObjectStorage) Option {
	return func(o *options) {
		o.storage = s
	}
}

// SetupRouter initializes the Gin engine with the deliberate middleware chain,
// custom error handlers (404, 405), trusted proxy configuration, and domain route registrations.
func SetupRouter(cfg *config.Config, logger *slog.Logger, dbPinger health.Pinger, opts ...Option) *gin.Engine {
	var opt options
	for _, fn := range opts {
		fn(&opt)
	}

	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()

	if len(cfg.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(cfg.TrustedProxies)
	}

	// Enable Method Not Allowed handling for custom 405 responses
	r.HandleMethodNotAllowed = true

	// Register global middleware in deliberate sequence:
	// 1. Request ID (generates/propagates trace ID)
	// 2. Recovery (catches panics and returns safe JSON 500)
	// 3. Structured Logging (records request metrics without sensitive data)
	// 4. CORS (restricts cross-origin requests to configured frontend URL)
	r.Use(middleware.RequestID())
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.Logging(logger))
	r.Use(middleware.CORS(cfg.FrontendURL))

	// Custom 404 Handler
	r.NoRoute(func(c *gin.Context) {
		core.SendError(
			c,
			http.StatusNotFound,
			core.ErrCodeNotFound,
			"The requested resource was not found",
		)
	})

	// Custom 405 Handler
	r.NoMethod(func(c *gin.Context) {
		core.SendError(
			c,
			http.StatusMethodNotAllowed,
			core.ErrCodeMethodNotAllowed,
			"The HTTP method is not allowed",
		)
	})

	// Initialize and register health domain module
	healthService := health.NewService(dbPinger, cfg.DBHealthTimeout, logger)
	healthHandler := health.NewHandler(healthService)
	health.RegisterRoutes(r, healthHandler)

	// Determine auth repository from database pool if available
	var authRepo auth.Repository
	if pool, ok := dbPinger.(*pgxpool.Pool); ok && pool != nil {
		authRepo = auth.NewPgxRepository(pool)
	}

	// Wire domain modules if database repository is available
	if authRepo != nil {
		pool, _ := dbPinger.(*pgxpool.Pool)
		orgRepo := organizations.NewPgxRepository(pool)
		orgService := organizations.NewService(orgRepo)
		orgHandler := organizations.NewHandler(orgService)

		rateLimiter := auth.NewMemoryRateLimiter(10000, nil)
		authService := auth.NewService(authRepo, cfg)
		authHandler := auth.NewHandler(authService, cfg, rateLimiter)

		originMw := middleware.ValidateOrigin(cfg.FrontendURL)
		jsonMw := middleware.RequireJSONContentType()
		rateLimitRegister := middleware.RateLimit(rateLimiter, cfg.RateLimitRegisterAttempts, cfg.RateLimitRegisterWindow)
		rateLimitLogin := middleware.RateLimit(rateLimiter, cfg.RateLimitIPAttempts, cfg.RateLimitIPWindow)
		rateLimitPublic := middleware.RateLimit(rateLimiter, 60, time.Minute)
		authMw := middleware.RequireAuth(authService, cfg)
		csrfMw := middleware.ValidateCSRF(authService, cfg)

		v1 := r.Group("/api/v1")
		auth.RegisterRoutes(v1, authHandler, originMw, jsonMw, rateLimitRegister, rateLimitLogin, authMw, csrfMw)
		organizations.RegisterRoutes(v1, orgHandler, authRepo, orgRepo, originMw, jsonMw, authMw, csrfMw, rateLimitPublic)

		// Wire certificate module ONLY if an explicit ObjectStorage dependency is provided.
		// Never fallback to mock storage; nil storage safely leaves the module unregistered in isolated tests.
		if opt.storage != nil {
			certRepo := certificates.NewPgxRepository(pool)
			certService := certificates.NewService(certRepo, opt.storage, cfg.CertificateMaxFileSize, cfg.R2PresignTTL, logger)
			certHandler := certificates.NewHandler(certService)
			certificates.RegisterRoutes(v1, certHandler, authRepo, orgRepo, originMw, jsonMw, authMw, csrfMw, rateLimitPublic)
		}
	}

	return r
}
