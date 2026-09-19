package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

// ValidateOrigin returns a middleware that checks the Origin or Referer header on state-changing requests
// to prevent cross-site request forgery from untrusted domains.
func ValidateOrigin(allowedOrigin string) gin.HandlerFunc {
	cleanAllowedOrigin := strings.TrimRight(strings.TrimSpace(allowedOrigin), "/")

	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			origin := strings.TrimRight(strings.TrimSpace(c.GetHeader("Origin")), "/")
			if origin == "" {
				referer := c.GetHeader("Referer")
				if referer != "" {
					parsed, err := url.Parse(referer)
					if err == nil {
						origin = strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/")
					}
				}
			}

			// In browser environments, Origin/Referer must match configured frontend
			if origin != "" && origin != cleanAllowedOrigin {
				core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Cross-origin request rejected: untrusted origin")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RequireJSONContentType verifies that incoming state-changing requests specify application/json Content-Type.
func RequireJSONContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
			ct := c.ContentType()
			if !strings.HasPrefix(strings.ToLower(ct), "application/json") {
				core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Content-Type must be application/json")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// ValidateCSRF validates the session-bound X-CSRF-Token header on cookie-authenticated mutating requests.
func ValidateCSRF(svc auth.Service, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			rawToken, err := auth.GetSessionToken(c, cfg.AuthSessionCookieName)
			if err == nil && rawToken != "" {
				csrfHeader := c.GetHeader("X-CSRF-Token")
				if csrfHeader == "" || !svc.ValidateCSRFToken(rawToken, csrfHeader) {
					core.SendError(c, http.StatusForbidden, auth.ErrCodeCSRFInvalid, "Invalid or missing CSRF token")
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}
