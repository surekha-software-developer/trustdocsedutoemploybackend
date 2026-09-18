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

	// 3. Initialize router and middleware chain
	r := router.SetupRouter(cfg, logger)

	// 4. Initialize HTTP server with timeouts
	srv := server.NewServer(cfg, r)

	// 5. Start HTTP server in a separate goroutine
	go func() {
		logger.Info("HTTP server listening", slog.String("addr", ":"+cfg.Port))
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server encountered fatal error", "error", err)
			os.Exit(1)
		}
	}()

	// 6. Graceful shutdown on OS interrupt/termination signals
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
