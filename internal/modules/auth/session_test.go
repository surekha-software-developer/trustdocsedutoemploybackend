package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
)

func TestSessionTokenGeneration(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken failed: %v", err)
		}
		if len(token) != 43 {
			t.Errorf("expected 43-character base64url string, got %d chars: %s", len(token), token)
		}
		if tokens[token] {
			t.Fatalf("duplicate session token detected: %s", token)
		}
		tokens[token] = true
	}
}

func TestHashSessionToken(t *testing.T) {
	rawToken := "test-raw-session-token-12345"
	hash1 := HashSessionToken(rawToken)
	hash2 := HashSessionToken(rawToken)

	if hash1 != hash2 {
		t.Errorf("HashSessionToken must be deterministic: %s != %s", hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex string, got %d chars: %s", len(hash1), hash1)
	}

	diffToken := "test-raw-session-token-67890"
	diffHash := HashSessionToken(diffToken)
	if hash1 == diffHash {
		t.Errorf("hashes of different tokens must not collide")
	}
}

func TestCSRFTokenLifecycle(t *testing.T) {
	secret := "my-very-secret-csrf-key-min-32-chars-long!"
	rawToken := "sample-raw-session-token-val"

	csrfToken := ComputeCSRFToken(secret, rawToken)
	if csrfToken == "" {
		t.Fatalf("ComputeCSRFToken returned empty string")
	}
	if strings.Contains(csrfToken, rawToken) {
		t.Errorf("CSRF token must never reveal raw session token")
	}

	// Valid token verification
	if !ValidateCSRFToken(secret, rawToken, csrfToken) {
		t.Errorf("ValidateCSRFToken failed for valid token")
	}

	// Invalid token verification
	if ValidateCSRFToken(secret, rawToken, "invalid-token") {
		t.Errorf("ValidateCSRFToken should return false for invalid token")
	}

	// Wrong session token verification
	if ValidateCSRFToken(secret, "wrong-raw-session-token", csrfToken) {
		t.Errorf("ValidateCSRFToken should return false for mismatched raw session token")
	}

	// Wrong secret verification
	if ValidateCSRFToken("another-secret-at-least-32-chars-long!!", rawToken, csrfToken) {
		t.Errorf("ValidateCSRFToken should return false for mismatched secret")
	}

	// Empty inputs
	if ValidateCSRFToken("", rawToken, csrfToken) {
		t.Errorf("ValidateCSRFToken should return false for empty secret")
	}
	if ValidateCSRFToken(secret, "", csrfToken) {
		t.Errorf("ValidateCSRFToken should return false for empty session token")
	}
	if ValidateCSRFToken(secret, rawToken, "") {
		t.Errorf("ValidateCSRFToken should return false for empty provided token")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      true,
		AuthCookieSameSite:    "Lax",
	}

	// Test SetSessionCookie
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/test", nil)

	rawToken := "sample-raw-token"
	SetSessionCookie(c, rawToken, cfg)

	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	sc := cookies[0]
	if sc.Name != cfg.AuthSessionCookieName {
		t.Errorf("expected cookie name %s, got %s", cfg.AuthSessionCookieName, sc.Name)
	}
	if sc.Value != rawToken {
		t.Errorf("expected cookie value %s, got %s", rawToken, sc.Value)
	}
	if sc.Path != "/api" {
		t.Errorf("expected cookie path /api, got %s", sc.Path)
	}
	if sc.Domain != "" {
		t.Errorf("expected empty cookie domain for Host-only cookie, got %s", sc.Domain)
	}
	if !sc.HttpOnly {
		t.Errorf("expected HttpOnly to be true")
	}
	if !sc.Secure {
		t.Errorf("expected Secure to be true")
	}
	if sc.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite Lax, got %v", sc.SameSite)
	}
	if sc.MaxAge != int(cfg.AuthSessionTTL.Seconds()) {
		t.Errorf("expected MaxAge %d, got %d", int(cfg.AuthSessionTTL.Seconds()), sc.MaxAge)
	}

	// Test ClearSessionCookie
	wClear := httptest.NewRecorder()
	cClear, _ := gin.CreateTestContext(wClear)
	cClear.Request, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)

	ClearSessionCookie(cClear, cfg)

	respClear := wClear.Result()
	clearCookies := respClear.Cookies()
	if len(clearCookies) != 1 {
		t.Fatalf("expected 1 cookie on clear, got %d", len(clearCookies))
	}

	cc := clearCookies[0]
	if cc.Name != cfg.AuthSessionCookieName {
		t.Errorf("expected clear cookie name %s, got %s", cfg.AuthSessionCookieName, cc.Name)
	}
	if cc.Value != "" {
		t.Errorf("expected empty clear cookie value, got %s", cc.Value)
	}
	if cc.Path != "/api" {
		t.Errorf("expected clear cookie path /api, got %s", cc.Path)
	}
	if cc.Domain != "" {
		t.Errorf("expected empty clear cookie domain, got %s", cc.Domain)
	}
	if cc.MaxAge != -1 {
		t.Errorf("expected clear cookie MaxAge -1, got %d", cc.MaxAge)
	}
	if !cc.Expires.Equal(time.Unix(0, 0)) {
		t.Errorf("expected clear cookie Expires at Unix epoch, got %v", cc.Expires)
	}
	if !cc.HttpOnly {
		t.Errorf("expected clear cookie HttpOnly to be true")
	}
	if !cc.Secure {
		t.Errorf("expected clear cookie Secure to be true")
	}
	if cc.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected clear cookie SameSite Lax, got %v", cc.SameSite)
	}

	// Test GetSessionToken
	reqWithCookie, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqWithCookie.AddCookie(&http.Cookie{
		Name:  cfg.AuthSessionCookieName,
		Value: "extracted-token-value",
	})
	cGet, _ := gin.CreateTestContext(httptest.NewRecorder())
	cGet.Request = reqWithCookie

	extracted, err := GetSessionToken(cGet, cfg.AuthSessionCookieName)
	if err != nil {
		t.Fatalf("GetSessionToken failed: %v", err)
	}
	if extracted != "extracted-token-value" {
		t.Errorf("expected extracted token 'extracted-token-value', got '%s'", extracted)
	}

	// Test missing cookie
	reqNoCookie, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	cNoCookie, _ := gin.CreateTestContext(httptest.NewRecorder())
	cNoCookie.Request = reqNoCookie
	_, err = GetSessionToken(cNoCookie, cfg.AuthSessionCookieName)
	if err == nil {
		t.Errorf("expected error when cookie is missing")
	}
}

func TestHMAC_DomainSeparationCrossProtocolNonCollision(t *testing.T) {
	secret := "shared-csrf-and-rate-limit-secret-key-32-chars!"
	// Even with identical input, the outputs must be completely different because
	// ComputeCSRFToken prefixes with "csrf:v1:" and DeriveAccountRateLimitKey prefixes with "rate-limit:v1:".
	identicalInput := "target@example.com"

	csrfToken := ComputeCSRFToken(secret, identicalInput)
	rateLimitKey := DeriveAccountRateLimitKey(secret, identicalInput)

	if csrfToken == "" {
		t.Fatalf("expected non-empty csrfToken")
	}
	if rateLimitKey == "" {
		t.Fatalf("expected non-empty rateLimitKey")
	}

	// Cross-domain collision must be impossible
	if csrfToken == rateLimitKey {
		t.Fatalf("critical vulnerability: CSRF token and account rate limit key collided on identical input: %s", csrfToken)
	}

	// Verify that neither exposes the raw input in plaintext
	if strings.Contains(csrfToken, identicalInput) || strings.Contains(rateLimitKey, identicalInput) {
		t.Errorf("derived tokens/keys must never leak plaintext input")
	}
}
