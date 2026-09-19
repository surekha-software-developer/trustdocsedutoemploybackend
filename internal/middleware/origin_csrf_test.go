package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

type mockAuthServiceForMiddleware struct {
	auth.Service
	validCSRFToken string
}

func (m *mockAuthServiceForMiddleware) ValidateCSRFToken(rawToken, providedToken string) bool {
	return providedToken == m.validCSRFToken && rawToken != ""
}

func TestValidateOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	allowedOrigin := "http://localhost:3000"

	setup := func() *gin.Engine {
		r := gin.New()
		r.Use(ValidateOrigin(allowedOrigin))
		r.POST("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		r.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		return r
	}

	r := setup()

	// 1. POST with matching Origin -> 200
	req1, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req1.Header.Set("Origin", "http://localhost:3000")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for matching origin, got %d", w1.Code)
	}

	// 2. POST with untrusted Origin -> 403
	req2, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req2.Header.Set("Origin", "http://evil.com")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for untrusted origin, got %d", w2.Code)
	}

	// 3. POST with matching Referer when Origin missing -> 200
	req3, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req3.Header.Set("Referer", "http://localhost:3000/login")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for matching referer, got %d", w3.Code)
	}

	// 4. POST with untrusted Referer -> 403
	req4, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req4.Header.Set("Referer", "http://evil.com/phish")
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusForbidden {
		t.Errorf("expected 403 for untrusted referer, got %d", w4.Code)
	}

	// 5. GET request with untrusted origin is not blocked by ValidateOrigin -> 200
	req5, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req5.Header.Set("Origin", "http://evil.com")
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, req5)
	if w5.Code != http.StatusOK {
		t.Errorf("expected 200 for GET request, got %d", w5.Code)
	}
}

func TestRequireJSONContentType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireJSONContentType())
	r.POST("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// 1. application/json -> 200
	req1, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req1.Header.Set("Content-Type", "application/json; charset=utf-8")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for application/json, got %d", w1.Code)
	}

	// 2. text/html -> 400
	req2, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req2.Header.Set("Content-Type", "text/html")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for text/html, got %d", w2.Code)
	}

	// 3. application/x-www-form-urlencoded -> 400
	req3, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for form-urlencoded, got %d", w3.Code)
	}
}

func TestValidateCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
	}
	mockSvc := &mockAuthServiceForMiddleware{validCSRFToken: "valid-csrf-token"}

	r := gin.New()
	r.Use(ValidateCSRF(mockSvc, cfg))
	r.POST("/api/v1/auth/logout", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// 1. Cookie present + missing X-CSRF-Token -> 403
	req1, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req1.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "raw-session-token"})
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing CSRF token, got %d", w1.Code)
	}

	// 2. Cookie present + invalid X-CSRF-Token -> 403
	req2, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req2.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "raw-session-token"})
	req2.Header.Set("X-CSRF-Token", "wrong-csrf-token")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid CSRF token, got %d", w2.Code)
	}

	// 3. Cookie present + valid X-CSRF-Token -> 200
	req3, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req3.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "raw-session-token"})
	req3.Header.Set("X-CSRF-Token", "valid-csrf-token")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for valid CSRF token, got %d", w3.Code)
	}

	// 4. Cookie absent -> passes through (e.g. unauthenticated logout or requests without cookie) -> 200
	req4, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Errorf("expected 200 when session cookie is absent, got %d", w4.Code)
	}
}
