package router

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/health"
)

// SetupRouter initializes the Gin engine with the deliberate middleware chain,
// custom error handlers (404, 405), and domain route registrations.
func SetupRouter(cfg *config.Config, logger *slog.Logger, dbPinger health.Pinger) *gin.Engine {
	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()

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

	// Initialize and register domain modules
	healthService := health.NewService(dbPinger, cfg.DBHealthTimeout, logger)
	healthHandler := health.NewHandler(healthService)
	health.RegisterRoutes(r, healthHandler)

	return r
}
