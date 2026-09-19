package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
)

const csrfDomainPrefix = "csrf:v1:"

var (
	ErrSessionTokenNotFound = errors.New("session token not found in cookie")
	ErrInvalidSessionToken  = errors.New("invalid session token")
)

// GenerateSessionToken generates a cryptographically secure 32-byte raw token,
// encoded as a base64url string (43 characters, unpadded).
func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random session bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSessionToken computes a SHA-256 digest of the raw session token,
// returning a 64-character lowercase hex string for database storage/lookup.
func HashSessionToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ComputeCSRFToken generates a session-bound HMAC-SHA256 CSRF token with explicit domain separation:
// HMAC-SHA256(CSRF_SECRET, "csrf:v1:" + rawSessionToken), Base64URL-encoded without padding.
// Never exposes the raw session token.
func ComputeCSRFToken(csrfSecret string, rawSessionToken string) string {
	if csrfSecret == "" || rawSessionToken == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(csrfSecret))
	mac.Write([]byte(csrfDomainPrefix + rawSessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidateCSRFToken verifies that the provided CSRF token matches HMAC-SHA256(CSRF_SECRET, rawSessionToken).
// Comparison is executed using crypto/subtle.ConstantTimeCompare to mitigate timing attacks.
func ValidateCSRFToken(csrfSecret string, rawSessionToken string, providedToken string) bool {
	if csrfSecret == "" || rawSessionToken == "" || providedToken == "" {
		return false
	}
	expected := ComputeCSRFToken(csrfSecret, rawSessionToken)
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(providedToken)) == 1
}

// ParseSameSite translates configuration string to http.SameSite mode.
func ParseSameSite(sameSiteStr string) http.SameSite {
	switch strings.ToLower(sameSiteStr) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		fallthrough
	default:
		return http.SameSiteLaxMode
	}
}

// SetSessionCookie writes the Host-Only session cookie with Path=/api and HttpOnly=true.
func SetSessionCookie(c *gin.Context, rawToken string, cfg *config.Config) {
	sameSite := ParseSameSite(cfg.AuthCookieSameSite)
	cookie := &http.Cookie{
		Name:     cfg.AuthSessionCookieName,
		Value:    rawToken,
		Path:     "/api",
		Domain:   "", // Omitted for host-only cookie
		MaxAge:   int(cfg.AuthSessionTTL.Seconds()),
		Secure:   cfg.AuthCookieSecure,
		HttpOnly: true,
		SameSite: sameSite,
	}
	http.SetCookie(c.Writer, cookie)
}

// ClearSessionCookie clears the session cookie using identical attributes (Path, Domain, Secure, SameSite, HttpOnly)
// with MaxAge=-1 and an expired date (Jan 1, 1970).
func ClearSessionCookie(c *gin.Context, cfg *config.Config) {
	sameSite := ParseSameSite(cfg.AuthCookieSameSite)
	cookie := &http.Cookie{
		Name:     cfg.AuthSessionCookieName,
		Value:    "",
		Path:     "/api",
		Domain:   "", // Omitted for host-only cookie
		MaxAge:   -1,
		Expires:  time.Unix(0, 0), // Expired date for cross-browser deletion compatibility
		Secure:   cfg.AuthCookieSecure,
		HttpOnly: true,
		SameSite: sameSite,
	}
	http.SetCookie(c.Writer, cookie)
}

// GetSessionToken extracts the raw session token from the designated request cookie.
func GetSessionToken(c *gin.Context, cookieName string) (string, error) {
	cookie, err := c.Request.Cookie(cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", ErrSessionTokenNotFound
		}
		return "", err
	}
	val := strings.TrimSpace(cookie.Value)
	if val == "" {
		return "", ErrInvalidSessionToken
	}
	return val, nil
}
