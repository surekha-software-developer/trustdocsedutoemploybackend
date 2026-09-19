package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

func setupTestRouter(handler *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/api/v1")
	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/register", handler.Register)
		authGroup.POST("/login", handler.Login)
		authGroup.GET("/csrf", handler.CSRF)
		authGroup.POST("/logout", handler.Logout)

		// Mock auth middleware for /me testing
		authGroup.GET("/me", func(c *gin.Context) {
			val, exists := c.Request.Header["X-Test-User-ID"]
			if !exists || len(val) == 0 {
				core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
				c.Abort()
				return
			}
			var uUUID pgtype.UUID
			_ = uUUID.Scan(val[0])
			c.Set("user", db.User{
				ID:            uUUID,
				Email:         "testuser@example.com",
				FullName:      "Test User",
				IsActive:      true,
				IsSuperadmin:  false,
				EmailVerified: false,
			})
			c.Next()
		}, handler.Me)
	}

	return r
}

func TestHandler_Register(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          16384,
		Argon2Iterations:      1,
		Argon2Parallelism:     1,
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}
	svc := NewService(repo, cfg)
	h := NewHandler(svc, cfg, nil)
	router := setupTestRouter(h)

	// 1. Successful registration
	reqBody := `{"email":"new@example.com","password":"StrongPassword12345!","full_name":"New User"}`
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	// Check no session cookie set
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("registration must never set a session cookie")
	}

	// 2. Duplicate registration returns identical response
	wDup := httptest.NewRecorder()
	reqDup, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(reqBody))
	reqDup.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wDup, reqDup)

	if wDup.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for duplicate, got %d", wDup.Code)
	}
	if wDup.Body.String() != w.Body.String() {
		t.Errorf("duplicate registration response must be identical to new user registration")
	}

	// 3. Short password (< 15 runes) returns 400 BAD_REQUEST
	reqShort := `{"email":"short@example.com","password":"ShortPassword!","full_name":"User"}`
	wShort := httptest.NewRecorder()
	rShort, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(reqShort))
	rShort.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wShort, rShort)

	if wShort.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for short password, got %d", wShort.Code)
	}

	// 4. Malformed JSON returns 400
	wBad := httptest.NewRecorder()
	rBad, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString("invalid json"))
	rBad.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wBad, rBad)

	if wBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed json, got %d", wBad.Code)
	}
}

func TestHandler_Login(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          16384,
		Argon2Iterations:      1,
		Argon2Parallelism:     1,
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}
	svc := NewService(repo, cfg)
	h := NewHandler(svc, cfg, nil)
	router := setupTestRouter(h)

	// Setup user
	regBody := `{"email":"login@example.com","password":"ValidPassword12345!","full_name":"Login Tester"}`
	rReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	rReg.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	router.ServeHTTP(wReg, rReg)

	// 1. Successful Login
	loginBody := `{"email":"login@example.com","password":"ValidPassword12345!"}`
	rLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	rLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	router.ServeHTTP(wLogin, rLogin)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}

	cookies := wLogin.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 session cookie, got %d", len(cookies))
	}
	if cookies[0].Name != cfg.AuthSessionCookieName {
		t.Errorf("expected cookie name %s, got %s", cfg.AuthSessionCookieName, cookies[0].Name)
	}
	if !cookies[0].HttpOnly {
		t.Errorf("session cookie must be HttpOnly")
	}

	// 2. Failed Login: Wrong Password returns 401 INVALID_CREDENTIALS
	badLoginBody := `{"email":"login@example.com","password":"WrongPassword12345!"}`
	rBad, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(badLoginBody))
	rBad.Header.Set("Content-Type", "application/json")
	wBad := httptest.NewRecorder()
	router.ServeHTTP(wBad, rBad)

	if wBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", wBad.Code)
	}
	if !bytes.Contains(wBad.Body.Bytes(), []byte(ErrCodeInvalidCredentials)) {
		t.Errorf("expected error code %s in body: %s", ErrCodeInvalidCredentials, wBad.Body.String())
	}
	if len(wBad.Result().Cookies()) != 0 {
		t.Errorf("failed login must not set session cookie")
	}

	// 3. Failed Login: Unknown User returns identical 401 INVALID_CREDENTIALS
	unknownBody := `{"email":"nonexistent@example.com","password":"ValidPassword12345!"}`
	rUnk, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(unknownBody))
	rUnk.Header.Set("Content-Type", "application/json")
	wUnk := httptest.NewRecorder()
	router.ServeHTTP(wUnk, rUnk)

	if wUnk.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unknown user, got %d", wUnk.Code)
	}
	if !bytes.Contains(wUnk.Body.Bytes(), []byte(ErrCodeInvalidCredentials)) {
		t.Errorf("expected code %s for unknown user", ErrCodeInvalidCredentials)
	}
}

func TestHandler_CSRF_Endpoint(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          16384,
		Argon2Iterations:      1,
		Argon2Parallelism:     1,
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}
	svc := NewService(repo, cfg)
	h := NewHandler(svc, cfg, nil)
	router := setupTestRouter(h)

	// 1. Without session cookie: returns 401
	rNoCookie, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	wNoCookie := httptest.NewRecorder()
	router.ServeHTTP(wNoCookie, rNoCookie)

	if wNoCookie.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie, got %d", wNoCookie.Code)
	}

	// 2. Setup user and login to get valid cookie
	regBody := `{"email":"csrftest@example.com","password":"ValidPassword12345!","full_name":"CSRF Tester"}`
	rReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	rReg.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	router.ServeHTTP(wReg, rReg)

	loginBody := `{"email":"csrftest@example.com","password":"ValidPassword12345!"}`
	rLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	rLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	router.ServeHTTP(wLogin, rLogin)

	cookies := wLogin.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected cookie from login")
	}
	sessionCookie := cookies[0]

	// 3. With valid cookie: returns 200 OK, no-store headers, and valid csrf_token
	rCSRF, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	rCSRF.AddCookie(sessionCookie)
	wCSRF := httptest.NewRecorder()
	router.ServeHTTP(wCSRF, rCSRF)

	if wCSRF.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from csrf endpoint, got %d: %s", wCSRF.Code, wCSRF.Body.String())
	}

	cacheControl := wCSRF.Header().Get("Cache-Control")
	if !bytes.Contains([]byte(cacheControl), []byte("no-store")) {
		t.Errorf("expected Cache-Control: no-store, got %s", cacheControl)
	}

	var jsonResp struct {
		Success bool         `json:"success"`
		Data    CSRFResponse `json:"data"`
	}
	if err := json.Unmarshal(wCSRF.Body.Bytes(), &jsonResp); err != nil {
		t.Fatalf("failed to decode CSRF response: %v", err)
	}
	if jsonResp.Data.CSRFToken == "" {
		t.Errorf("expected non-empty csrf_token")
	}

	// Verify the token validates against raw session token
	if !svc.ValidateCSRFToken(sessionCookie.Value, jsonResp.Data.CSRFToken) {
		t.Errorf("returned CSRF token failed validation")
	}
}

func TestHandler_Logout(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          16384,
		Argon2Iterations:      1,
		Argon2Parallelism:     1,
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}
	svc := NewService(repo, cfg)
	h := NewHandler(svc, cfg, nil)
	router := setupTestRouter(h)

	// Call logout with cookie
	rLogout, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rLogout.AddCookie(&http.Cookie{
		Name:  cfg.AuthSessionCookieName,
		Value: "any-session-token",
	})
	wLogout := httptest.NewRecorder()
	router.ServeHTTP(wLogout, rLogout)

	if wLogout.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", wLogout.Code)
	}

	// Verify cookie cleared with MaxAge = -1
	cookies := wLogout.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 clear cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("expected MaxAge -1 on logout clear cookie, got %d", cookies[0].MaxAge)
	}
}

func TestHandler_Login_AccountRateLimiting(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                 "test",
		AuthSessionCookieName:  "trustdocs_session",
		AuthSessionTTL:         24 * time.Hour,
		AuthCookieSecure:       false,
		AuthCookieSameSite:     "Lax",
		CSRFSecret:             "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:           16384,
		Argon2Iterations:       1,
		Argon2Parallelism:      1,
		Argon2SaltLength:       16,
		Argon2KeyLength:        32,
		RateLimitLoginAttempts: 3,
		RateLimitLoginWindow:   10 * time.Minute,
	}
	limiter := NewMemoryRateLimiter(100, nil)
	svc := NewService(repo, cfg)
	h := NewHandler(svc, cfg, limiter)
	router := setupTestRouter(h)

	targetEmail := "victim@example.com"
	badReqBody := `{"email":"` + targetEmail + `","password":"WrongPassword12345!"}`

	// First 3 failed attempts: return 401 Unauthorized
	for i := 1; i <= 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(badReqBody))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i, w.Code)
		}
	}

	// 4th attempt: must return 429 Too Many Requests with integer Retry-After header
	req4, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(badReqBody))
	req4.Header.Set("Content-Type", "application/json")
	req4.RemoteAddr = "192.0.2.1:12345"
	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, req4)

	if w4.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 4: expected 429 Too Many Requests, got %d: %s", w4.Code, w4.Body.String())
	}

	retryAfter := w4.Header().Get("Retry-After")
	if retryAfter == "" || retryAfter == "0" {
		t.Errorf("expected positive integer Retry-After header, got '%s'", retryAfter)
	}

	var errResp core.ErrorResponse
	if err := json.Unmarshal(w4.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to unmarshal 429 response: %v", err)
	}
	if errResp.Error == nil || errResp.Error.Code != ErrCodeRateLimitExceeded {
		t.Errorf("expected error code %s, got %v", ErrCodeRateLimitExceeded, errResp.Error)
	}

	// 5. Different email from same IP is NOT blocked by account rate limit
	diffReqBody := `{"email":"different@example.com","password":"WrongPassword12345!"}`
	reqDiff, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(diffReqBody))
	reqDiff.Header.Set("Content-Type", "application/json")
	reqDiff.RemoteAddr = "192.0.2.1:12345"
	wDiff := httptest.NewRecorder()
	router.ServeHTTP(wDiff, reqDiff)

	if wDiff.Code != http.StatusUnauthorized {
		t.Errorf("expected different account to return 401 Unauthorized, got %d", wDiff.Code)
	}

	// 6. Same email from a DIFFERENT IP is NOT blocked (prevents DoS attack from locking out legitimate user)
	reqDiffIP, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(badReqBody))
	reqDiffIP.Header.Set("Content-Type", "application/json")
	reqDiffIP.RemoteAddr = "198.51.100.2:54321"
	wDiffIP := httptest.NewRecorder()
	router.ServeHTTP(wDiffIP, reqDiffIP)

	if wDiffIP.Code != http.StatusUnauthorized {
		t.Errorf("expected same account from different IP to return 401 Unauthorized, got %d", wDiffIP.Code)
	}
}
