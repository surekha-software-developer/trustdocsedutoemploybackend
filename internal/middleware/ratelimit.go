package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

const (
	ErrCodeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
)

// RateLimit creates a middleware that enforces rate limiting on requests using the provided RateLimiter.
// Client IP is extracted via c.ClientIP(), which honors Gin's trusted proxy configuration.
// If the limit is exceeded, HTTP 429 is returned along with the standard Retry-After header in seconds.
func RateLimit(limiter auth.RateLimiter, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		key := auth.DeriveIPRateLimitKey(clientIP)

		allowed, retryAfter := limiter.Allow(key, limit, window)
		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", seconds))
			core.SendError(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.")
			c.Abort()
			return
		}

		c.Next()
	}
}
