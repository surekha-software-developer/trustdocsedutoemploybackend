package router

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func getTestSetup() (*config.Config, *slog.Logger) {
	cfg := &config.Config{
		AppEnv:      "test",
		Port:        "8080",
		FrontendURL: "http://localhost:3000",
		LogLevel:    "error",
	}
	// Discard logger output during tests
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return cfg, logger
}

func TestRouter_UnknownRouteReturns404(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent-route", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeNotFound {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeNotFound, resp.Error)
	}
	if resp.Error.Message != "The requested resource was not found" {
		t.Errorf("expected message 'The requested resource was not found', got '%s'", resp.Error.Message)
	}
}

func TestRouter_UnsupportedMethodReturns405(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	// /health only supports GET, so POST must return 405
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeMethodNotAllowed {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeMethodNotAllowed, resp.Error)
	}
	if resp.Error.Message != "The HTTP method is not allowed" {
		t.Errorf("expected message 'The HTTP method is not allowed', got '%s'", resp.Error.Message)
	}
}

func TestRouter_AllowedCORSPreflight(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 No Content for OPTIONS preflight, got %d", w.Code)
	}

	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "http://localhost:3000" {
		t.Errorf("expected Access-Control-Allow-Origin 'http://localhost:3000', got '%s'", allowOrigin)
	}

	allowMethods := w.Header().Get("Access-Control-Allow-Methods")
	if !strings.Contains(allowMethods, "GET") {
		t.Errorf("expected Access-Control-Allow-Methods to contain GET, got '%s'", allowMethods)
	}
}

func TestRouter_UnapprovedCORSOrigin(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "http://malicious-site.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for unapproved origin, got '%s'", allowOrigin)
	}
}

func TestRouter_RequestIDHeaderExists(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	reqID := w.Header().Get(middleware.RequestIDHeader)
	if reqID == "" {
		t.Errorf("expected %s header in response, got empty string", middleware.RequestIDHeader)
	}
}

func TestRouter_PanicRecoveryReturns500WithoutStackTrace(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger)

	// Add a test-only panicking route
	r.GET("/test-panic", func(c *gin.Context) {
		panic("simulated unexpected database crash or nil pointer")
	})

	req := httptest.NewRequest(http.MethodGet, "/test-panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	bodyStr := w.Body.String()
	if strings.Contains(bodyStr, "simulated unexpected") {
		t.Errorf("response body must NOT expose internal panic text; got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, ".go:") || strings.Contains(bodyStr, "goroutine") {
		t.Errorf("response body must NOT expose stack trace; got: %s", bodyStr)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeInternal {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeInternal, resp.Error)
	}
	if resp.Error.Message != "An unexpected error occurred" {
		t.Errorf("expected message 'An unexpected error occurred', got '%s'", resp.Error.Message)
	}
}
