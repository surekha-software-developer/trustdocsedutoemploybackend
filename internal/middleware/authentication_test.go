package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

type mockAuthServiceForAuthMiddleware struct {
	auth.Service
	failSession bool
	user        db.User
	session     db.AuthSession
}

func (m *mockAuthServiceForAuthMiddleware) GetSessionByToken(ctx context.Context, rawToken string) (db.AuthSession, db.User, error) {
	if m.failSession || rawToken == "" {
		return db.AuthSession{}, db.User{}, errors.New("invalid session")
	}
	return m.session, m.user, nil
}

func TestRequireAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
	}

	var userUUID pgtype.UUID
	_ = userUUID.Scan("00000000-0000-0000-0000-000000000001")
	testUser := db.User{
		ID:            userUUID,
		Email:         "authtest@example.com",
		FullName:      "Auth User",
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: true,
	}
	testSession := db.AuthSession{
		ID:     userUUID,
		UserID: userUUID,
	}

	mockSvc := &mockAuthServiceForAuthMiddleware{
		user:    testUser,
		session: testSession,
	}

	r := gin.New()
	r.Use(RequireAuth(mockSvc, cfg))
	r.GET("/protected", func(c *gin.Context) {
		user := c.MustGet("user").(db.User)
		c.JSON(http.StatusOK, gin.H{"email": user.Email})
	})

	// 1. Missing cookie -> 401
	req1, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing cookie, got %d", w1.Code)
	}

	// 2. Invalid session in cookie -> 401
	mockSvc.failSession = true
	req2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "expired-token"})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired/invalid session, got %d", w2.Code)
	}

	// 3. Valid session -> 200 OK and populated user context
	mockSvc.failSession = false
	req3, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req3.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "valid-token"})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 for valid session, got %d", w3.Code)
	}
}
