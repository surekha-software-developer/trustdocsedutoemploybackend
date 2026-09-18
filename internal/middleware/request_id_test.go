package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestIDMiddleware_GeneratesNewHeader(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())

	router.GET("/test", func(c *gin.Context) {
		reqID := GetRequestID(c)
		if reqID == "" {
			t.Errorf("expected request ID in context, got empty string")
		}
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	respHeader := w.Header().Get(RequestIDHeader)
	if respHeader == "" {
		t.Fatalf("expected %s header in response, got none", RequestIDHeader)
	}
	if len(respHeader) != 36 {
		t.Errorf("expected UUID v4 length of 36 chars, got '%s' (len %d)", respHeader, len(respHeader))
	}
}

func TestRequestIDMiddleware_PreservesExistingHeader(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())

	const customID = "custom-trace-id-12345"
	router.GET("/test", func(c *gin.Context) {
		reqID := GetRequestID(c)
		if reqID != customID {
			t.Errorf("expected context request ID '%s', got '%s'", customID, reqID)
		}
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, customID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	respHeader := w.Header().Get(RequestIDHeader)
	if respHeader != customID {
		t.Errorf("expected preserved header '%s', got '%s'", customID, respHeader)
	}
}
