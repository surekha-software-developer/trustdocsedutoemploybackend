package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

// RequireAuth ensures that the request carries a valid, active session cookie.
// On success, populates "user", "session", and "user_id" in the Gin context.
func RequireAuth(svc auth.Service, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken, err := auth.GetSessionToken(c, cfg.AuthSessionCookieName)
		if err != nil || rawToken == "" {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		session, user, err := svc.GetSessionByToken(c.Request.Context(), rawToken)
		if err != nil {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Session expired or invalid")
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("session", session)
		c.Set("user_id", user.ID.String())

		c.Next()
	}
}
