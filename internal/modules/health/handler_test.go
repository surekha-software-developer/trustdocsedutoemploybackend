package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type mockPinger struct {
	pingFunc func(ctx context.Context) error
}

func (m *mockPinger) Ping(ctx context.Context) error {
	if m.pingFunc != nil {
		return m.pingFunc(ctx)
	}
	return nil
}

func setupTestRouter(pinger Pinger, timeout time.Duration) *gin.Engine {
	r := gin.New()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	svc := NewService(pinger, timeout, logger)
	h := NewHandler(svc)
	RegisterRoutes(r, h)
	return r
}

func TestHealthEndpoint_IndependentOfDatabase(t *testing.T) {
	// 1. When pinger is nil
	r1 := setupTestRouter(nil, 2*time.Second)
	req1 := httptest.NewRequest(http.MethodGet, "/health", nil)
	w1 := httptest.NewRecorder()
	r1.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected status 200 with nil pinger, got %d", w1.Code)
	}

	// 2. When database is failing
	failingMock := &mockPinger{
		pingFunc: func(ctx context.Context) error {
			return errors.New("postgres connection refused")
		},
	}
	r2 := setupTestRouter(failingMock, 2*time.Second)
	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200 with failing pinger, got %d", w2.Code)
	}

	var resp struct {
		Success bool       `json:"success"`
		Data    HealthData `json:"data"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success to be true")
	}
	if resp.Data.Status != "ok" || resp.Data.Service != "trustdocs-api" {
		t.Errorf("unexpected health data: %+v", resp.Data)
	}
}

func TestReadyEndpoint_SuccessWhenDatabaseAvailable(t *testing.T) {
	healthyMock := &mockPinger{
		pingFunc: func(ctx context.Context) error {
			return nil
		},
	}
	r := setupTestRouter(healthyMock, 2*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp struct {
		Success bool      `json:"success"`
		Data    ReadyData `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success to be true")
	}
	if resp.Data.Status != "ready" {
		t.Errorf("expected status 'ready', got '%s'", resp.Data.Status)
	}
	if len(resp.Data.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(resp.Data.Dependencies))
	}
	if resp.Data.Dependencies[0].Name != "postgres" || resp.Data.Dependencies[0].Status != "up" {
		t.Errorf("expected postgres up, got: %+v", resp.Data.Dependencies[0])
	}
}

func TestReadyEndpoint_FailureWhenDatabaseUnavailable(t *testing.T) {
	failingMock := &mockPinger{
		pingFunc: func(ctx context.Context) error {
			return errors.New("connection reset by peer: secret-host:5432")
		},
	}
	r := setupTestRouter(failingMock, 2*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}

	bodyStr := w.Body.String()
	// Ensure raw error or sensitive connection info is not exposed in HTTP response
	if strings.Contains(bodyStr, "secret-host") || strings.Contains(bodyStr, "connection reset") {
		t.Errorf("response body must NOT expose raw database error; got: %s", bodyStr)
	}

	var resp struct {
		Success bool          `json:"success"`
		Error   core.AppError `json:"error"`
		Data    ReadyData     `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error.Code != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("expected error code 'DEPENDENCY_UNAVAILABLE', got '%s'", resp.Error.Code)
	}
	if resp.Data.Status != "not_ready" {
		t.Errorf("expected status 'not_ready', got '%s'", resp.Data.Status)
	}
	if len(resp.Data.Dependencies) != 1 || resp.Data.Dependencies[0].Status != "down" {
		t.Errorf("expected postgres down, got: %+v", resp.Data.Dependencies)
	}
}

func TestReadyEndpoint_TimeoutHandling(t *testing.T) {
	slowMock := &mockPinger{
		pingFunc: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	// Use very short timeout for test
	r := setupTestRouter(slowMock, 20*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 on timeout, got %d", w.Code)
	}

	var resp struct {
		Success bool      `json:"success"`
		Data    ReadyData `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data.Status != "not_ready" {
		t.Errorf("expected status 'not_ready', got '%s'", resp.Data.Status)
	}
	if resp.Data.Dependencies[0].Status != "down" {
		t.Errorf("expected postgres status 'down', got '%s'", resp.Data.Dependencies[0].Status)
	}
}

func TestReadyEndpoint_DynamicRecovery(t *testing.T) {
	var isHealthy int32 = 0 // 0 = failing, 1 = healthy

	mock := &mockPinger{
		pingFunc: func(ctx context.Context) error {
			if atomic.LoadInt32(&isHealthy) == 1 {
				return nil
			}
			return errors.New("simulated database outage")
		},
	}
	r := setupTestRouter(mock, 2*time.Second)

	// Probe 1: Database is down
	req1 := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected initial status 503, got %d", w1.Code)
	}

	// Recover database
	atomic.StoreInt32(&isHealthy, 1)

	// Probe 2: Next probe automatically succeeds without server restart
	req2 := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected recovered status 200, got %d", w2.Code)
	}
}
