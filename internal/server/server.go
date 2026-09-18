package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
)

// Server wraps the standard http.Server with production-safe timeouts.
type Server struct {
	httpServer *http.Server
}

// NewServer constructs an HTTP Server configured with safe timeouts.
func NewServer(cfg *config.Config, handler http.Handler) *Server {
	addr := fmt.Sprintf(":%s", cfg.Port)

	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// Start begins listening and serving incoming HTTP requests.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
