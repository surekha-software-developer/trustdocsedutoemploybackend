package health

import (
	"context"
	"log/slog"
	"time"
)

// Pinger defines the interface required for database liveness/readiness probes.
// This matches the exact method signature of (*pgxpool.Pool).Ping.
type Pinger interface {
	Ping(ctx context.Context) error
}

// DependencyStatus represents the state of a single dependency.
type DependencyStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Service defines the interface for health and readiness checks.
type Service interface {
	CheckHealth() HealthData
	CheckReady(ctx context.Context) (ReadyData, bool)
}

// HealthData represents the payload returned by the /health endpoint.
type HealthData struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// ReadyData represents the payload returned by the /ready endpoint.
type ReadyData struct {
	Status       string             `json:"status"`
	Dependencies []DependencyStatus `json:"dependencies"`
}

type healthService struct {
	dbPinger      Pinger
	healthTimeout time.Duration
	logger        *slog.Logger
}

// NewService constructs a new health service.
func NewService(dbPinger Pinger, healthTimeout time.Duration, logger *slog.Logger) Service {
	return &healthService{
		dbPinger:      dbPinger,
		healthTimeout: healthTimeout,
		logger:        logger,
	}
}

func (s *healthService) CheckHealth() HealthData {
	return HealthData{
		Status:  "ok",
		Service: "trustdocs-api",
	}
}

func (s *healthService) CheckReady(ctx context.Context) (ReadyData, bool) {
	if s.dbPinger == nil {
		return ReadyData{
			Status: "not_ready",
			Dependencies: []DependencyStatus{
				{Name: "postgres", Status: "down"},
			},
		}, false
	}

	timeout := s.healthTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := s.dbPinger.Ping(timeoutCtx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn(
				"readiness probe failed",
				slog.String("dependency", "postgres"),
				slog.String("error_code", "database_unavailable"),
			)
		}
		return ReadyData{
			Status: "not_ready",
			Dependencies: []DependencyStatus{
				{Name: "postgres", Status: "down"},
			},
		}, false
	}

	return ReadyData{
		Status: "ready",
		Dependencies: []DependencyStatus{
			{Name: "postgres", Status: "up"},
		},
	}, true
}
