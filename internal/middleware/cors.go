package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that strictly restricts allowed cross-origin requests
// to the configured frontend URL. Wildcards are prohibited to support credentialed workflows.
func CORS(allowedOrigin string) gin.HandlerFunc {
	cleanAllowedOrigin := strings.TrimRight(strings.TrimSpace(allowedOrigin), "/")

	return func(c *gin.Context) {
		origin := strings.TrimRight(strings.TrimSpace(c.GetHeader("Origin")), "/")

		// Check if incoming origin matches the approved frontend origin
		if origin != "" && origin == cleanAllowedOrigin {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-ID, X-CSRF-Token")
			c.Header("Access-Control-Max-Age", "86400")
		}

		// Handle preflight OPTIONS requests
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
