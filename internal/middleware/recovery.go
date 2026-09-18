package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Recovery returns a Gin middleware that recovers from any panics,
// logs the stack trace internally, and writes a safe, standardized JSON 500 response.
func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				reqID := GetRequestID(c)

				// Log internal panic and stack trace securely
				logger.Error("panic recovered in HTTP handler",
					slog.String("request_id", reqID),
					slog.Any("error", r),
					slog.String("stack", string(debug.Stack())),
					slog.String("path", c.Request.URL.Path),
					slog.String("method", c.Request.Method),
				)

				// Return standardized safe error without exposing internal details
				c.AbortWithStatusJSON(http.StatusInternalServerError, core.ErrorResponse{
					Success: false,
					Error: core.NewAppError(
						core.ErrCodeInternal,
						"An unexpected error occurred",
					),
				})
			}
		}()

		c.Next()
	}
}
