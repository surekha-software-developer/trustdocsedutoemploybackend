package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type mockLimiterForMiddleware struct {
	allowed    bool
	retryAfter time.Duration
	calls      int
}

func (m *mockLimiterForMiddleware) Allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	m.calls++
	return m.allowed, m.retryAfter
}

func TestRateLimitMiddleware_AllowedAndExceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 1. Allowed request
	limiter := &mockLimiterForMiddleware{allowed: true, retryAfter: 0}
	r := gin.New()
	r.Use(RateLimit(limiter, 5, 1*time.Minute))
	r.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. Exceeded limit -> 429 and Retry-After
	limiter.allowed = false
	limiter.retryAfter = 30 * time.Second

	wExceeded := httptest.NewRecorder()
	r.ServeHTTP(wExceeded, req)

	if wExceeded.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", wExceeded.Code)
	}
	retryAfter := wExceeded.Header().Get("Retry-After")
	if retryAfter != "30" {
		t.Errorf("expected Retry-After 30, got %s", retryAfter)
	}
	if !strings.Contains(wExceeded.Body.String(), ErrCodeRateLimitExceeded) {
		t.Errorf("expected body to contain %s", ErrCodeRateLimitExceeded)
	}
}

func TestRateLimitMiddleware_TrustedProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Configure trusted proxies to 127.0.0.1 only
	_ = r.SetTrustedProxies([]string{"127.0.0.1"})

	var capturedKey string
	recordKeyLimiter := &keyRecorderLimiter{onAllow: func(key string) {
		capturedKey = key
	}}

	r.Use(RateLimit(recordKeyLimiter, 10, 1*time.Minute))
	r.GET("/ip-test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Request from untrusted remote address with spoofed X-Forwarded-For header
	req, _ := http.NewRequest(http.MethodGet, "/ip-test", nil)
	req.RemoteAddr = "192.168.1.100:12345"             // untrusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.195") // spoofed client IP

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Since 192.168.1.100 is NOT a trusted proxy, Gin ignores X-Forwarded-For and uses 192.168.1.100
	if capturedKey != "ip:192.168.1.100" {
		t.Errorf("expected untrusted remote IP 'ip:192.168.1.100' to be used, got %s", capturedKey)
	}
}

type keyRecorderLimiter struct {
	onAllow func(key string)
}

func (k *keyRecorderLimiter) Allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	k.onAllow(key)
	return true, 0
}
