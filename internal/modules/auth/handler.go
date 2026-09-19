package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/gin-gonic/gin"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

const (
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeCSRFInvalid        = "CSRF_TOKEN_INVALID"
	ErrCodeRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
)

// Handler handles HTTP requests for authentication and authorization.
type Handler struct {
	service Service
	cfg     *config.Config
	limiter RateLimiter
}

// NewHandler constructs a new auth Handler with an optional RateLimiter for account rate-limiting.
func NewHandler(service Service, cfg *config.Config, limiter RateLimiter) *Handler {
	return &Handler{
		service: service,
		cfg:     cfg,
		limiter: limiter,
	}
}

func parseClientIP(c *gin.Context) *netip.Addr {
	ipStr := c.ClientIP()
	if ipStr == "" {
		return nil
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil
	}
	return &addr
}

// Register handles POST /api/v1/auth/register.
// Always returns generic 200 OK for both new and duplicate valid registrations.
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	if err := req.SanitizeAndValidate(); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, err.Error())
		return
	}

	ip := parseClientIP(c)
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Register(c.Request.Context(), req, ip, userAgent)
	if err != nil {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Registration service error")
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// Login handles POST /api/v1/auth/login.
// Authenticates credentials, sets host-only session cookie on success, or returns generic 401 on failure.
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	if err := req.SanitizeAndValidate(); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, err.Error())
		return
	}

	// Enforce per-account-per-IP rate limiting to protect against targeted brute-force attacks
	// while preventing cross-IP denial-of-service against valid users
	if h.limiter != nil {
		clientIP := c.ClientIP()
		compoundKey := DeriveAccountIPRateLimitKey(h.cfg.CSRFSecret, req.Email, clientIP)
		allowed, retryAfter := h.limiter.Allow(compoundKey, h.cfg.RateLimitLoginAttempts, h.cfg.RateLimitLoginWindow)
		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", seconds))
			core.SendError(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.")
			return
		}
	}

	ip := parseClientIP(c)
	userAgent := c.Request.UserAgent()

	user, rawToken, err := h.service.Login(c.Request.Context(), req, ip, userAgent)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			core.SendError(c, http.StatusUnauthorized, ErrCodeInvalidCredentials, "Invalid email or password")
			return
		}
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Authentication service error")
		return
	}

	// Set Host-Only HttpOnly session cookie on successful login
	SetSessionCookie(c, rawToken, h.cfg)

	core.SendSuccess(c, http.StatusOK, gin.H{
		"user": user,
	})
}

// CSRF handles GET /api/v1/auth/csrf.
// Requires active session and returns session-bound HMAC CSRF token with Cache-Control: no-store.
func (h *Handler) CSRF(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Pragma", "no-cache")

	rawToken, err := GetSessionToken(c, h.cfg.AuthSessionCookieName)
	if err != nil {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}

	_, _, err = h.service.GetSessionByToken(c.Request.Context(), rawToken)
	if err != nil {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}

	csrfToken := h.service.GenerateCSRFToken(rawToken)
	core.SendSuccess(c, http.StatusOK, CSRFResponse{
		CSRFToken: csrfToken,
	})
}

// Logout handles POST /api/v1/auth/logout.
// Idempotently revokes the session and clears the cookie.
func (h *Handler) Logout(c *gin.Context) {
	rawToken, err := GetSessionToken(c, h.cfg.AuthSessionCookieName)
	if err == nil && rawToken != "" {
		ip := parseClientIP(c)
		userAgent := c.Request.UserAgent()
		_ = h.service.Logout(c.Request.Context(), rawToken, ip, userAgent)
	}

	// Always clear session cookie with matching attributes
	ClearSessionCookie(c, h.cfg)

	core.SendSuccess(c, http.StatusOK, MessageResponse{
		Message: "Logged out successfully",
	})
}

// Me handles GET /api/v1/auth/me.
// Returns current authenticated user and active organization memberships.
func (h *Handler) Me(c *gin.Context) {
	userVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}

	user, ok := userVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	resp, err := h.service.GetMe(c.Request.Context(), user.ID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			core.SendError(c, http.StatusNotFound, core.ErrCodeNotFound, "User not found")
			return
		}
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Failed to retrieve user profile")
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}
