package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRouter() *gin.Engine {
	r := gin.New()
	svc := NewService()
	h := NewHandler(svc)
	RegisterRoutes(r, h)
	return r
}

func TestHealthEndpoint(t *testing.T) {
	router := setupTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp struct {
		Success bool       `json:"success"`
		Data    HealthData `json:"data"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success to be true")
	}
	if resp.Data.Status != "ok" {
		t.Errorf("expected status 'ok', got '%s'", resp.Data.Status)
	}
	if resp.Data.Service != "trustdocs-api" {
		t.Errorf("expected service 'trustdocs-api', got '%s'", resp.Data.Service)
	}
}

func TestReadyEndpoint(t *testing.T) {
	router := setupTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

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
	if resp.Data.Dependencies == nil || len(resp.Data.Dependencies) != 0 {
		t.Errorf("expected empty dependencies slice, got %v", resp.Data.Dependencies)
	}
}
