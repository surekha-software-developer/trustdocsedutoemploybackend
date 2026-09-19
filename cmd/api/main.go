package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/database"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/router"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/server"
)

func main() {
	// 1. Load configuration from environment variables
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// 2. Initialize structured JSON logging
	logger := core.InitLogger(cfg.LogLevel)
	logger.Info("starting TrustDocs API service",
		slog.String("env", cfg.AppEnv),
		slog.String("port", cfg.Port),
		slog.String("frontend_url", cfg.FrontendURL),
	)

	// 3. Ensure DATABASE_URL is present for API runtime (DATABASE_DIRECT_URL is optional)
	if err := cfg.ValidateForAPI(); err != nil {
		logger.Error("configuration validation failed for API service",
			slog.String("error_code", "config_invalid"),
		)
		os.Exit(1)
	}

	// 4. Initialize PostgreSQL connection pool (pooled connection via DATABASE_URL)
	pool, err := database.NewPool(context.Background(), cfg)
	if err != nil {
		logger.Error("failed to create database pool",
			slog.String("dependency", "postgres"),
			slog.String("error_code", "pool_init_failed"),
		)
		os.Exit(1)
	}
	defer pool.Close()

	// 5. Initial connection ping
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = pool.Ping(pingCtx)
	pingCancel()
	if err != nil {
		if cfg.AppEnv == "production" {
			logger.Error("database ping failed on startup in production",
				slog.String("dependency", "postgres"),
				slog.String("error_code", "database_unavailable"),
			)
			os.Exit(1)
		}
		logger.Warn("database ping failed on startup; server starting in unready state",
			slog.String("dependency", "postgres"),
			slog.String("error_code", "database_unavailable"),
		)
	} else {
		logger.Info("database pool connection established")
	}

	// 6. Initialize router with database pinger dependency
	r := router.SetupRouter(cfg, logger, pool)

	// 7. Initialize HTTP server with timeouts
	srv := server.NewServer(cfg, r)

	// 8. Start HTTP server in a separate goroutine
	go func() {
		logger.Info("HTTP server listening", slog.String("addr", ":"+cfg.Port))
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server encountered fatal error", "error", err)
			os.Exit(1)
		}
	}()

	// 9. Graceful shutdown on OS interrupt/termination signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit

	logger.Info("shutdown signal received, draining active connections...", slog.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("TrustDocs API server exited cleanly")
}
