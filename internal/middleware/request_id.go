package middleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// RequestIDHeader is the HTTP header key for tracing requests.
	RequestIDHeader = "X-Request-ID"

	// RequestIDContextKey is the context key for storing the request ID.
	RequestIDContextKey = "request_id"
)

type contextKey string

const requestIDKey contextKey = RequestIDContextKey

// RequestID returns a Gin middleware that ensures every request has a unique Request ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := strings.TrimSpace(c.GetHeader(RequestIDHeader))
		if reqID == "" {
			reqID = generateUUIDv4()
		}

		c.Header(RequestIDHeader, reqID)
		c.Set(RequestIDContextKey, reqID)

		// Also attach to the request's Go context
		ctx := context.WithValue(c.Request.Context(), requestIDKey, reqID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// GetRequestID extracts the request ID from a gin.Context.
func GetRequestID(c *gin.Context) string {
	if val, exists := c.Get(RequestIDContextKey); exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// generateUUIDv4 generates an RFC 4122 compliant UUID v4 using crypto/rand.
func generateUUIDv4() string {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		// Fallback to a timestamp-based pseudo random string if entropy fails
		return fmt.Sprintf("req-%d", timeNowNano())
	}

	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

var timeNowNano = func() int64 {
	return 0
}
