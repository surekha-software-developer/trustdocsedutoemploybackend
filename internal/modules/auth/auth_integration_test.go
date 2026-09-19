//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/health"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/router"
)

// testTracker tracks all database entity primary keys created during an integration test
// to guarantee clean, dependency-safe teardown after test execution without broad DELETE or TRUNCATE.
type testTracker struct {
	mu       sync.Mutex
	pool     *pgxpool.Pool
	userIDs  []pgtype.UUID
	orgIDs   []pgtype.UUID
	auditIDs []pgtype.UUID
}

func newTestTracker(pool *pgxpool.Pool) *testTracker {
	return &testTracker{
		pool:     pool,
		userIDs:  make([]pgtype.UUID, 0),
		orgIDs:   make([]pgtype.UUID, 0),
		auditIDs: make([]pgtype.UUID, 0),
	}
}

func (tr *testTracker) TrackUser(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.userIDs = append(tr.userIDs, id)
}

func (tr *testTracker) TrackOrg(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.orgIDs = append(tr.orgIDs, id)
}

func (tr *testTracker) TrackAuditID(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.auditIDs = append(tr.auditIDs, id)
}

// TrackAuditByTrace queries audit_logs for the unique user_agent trace string
// and records its primary key UUID. This captures audit records even when actor_user_id is NULL
// (e.g. failed login attempts for non-existent users).
func (tr *testTracker) TrackAuditByTrace(ctx context.Context, t *testing.T, traceID string) {
	t.Helper()
	rows, err := tr.pool.Query(ctx, "SELECT id FROM audit_logs WHERE user_agent = $1", traceID)
	if err != nil {
		t.Fatalf("failed to query audit log by trace ID: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("failed to scan audit log id: %v", err)
		}
		tr.TrackAuditID(id)
	}
}

// cleanup removes tracked records strictly in reverse foreign-key dependency order.
func (tr *testTracker) cleanup(t *testing.T) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Delete audit logs by tracked primary key UUIDs
	if len(tr.auditIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM audit_logs WHERE id = ANY($1)", tr.auditIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete audit_logs: %v", err)
		}
	}

	// 2. Delete organization memberships referencing tracked users or organizations
	if len(tr.userIDs) > 0 || len(tr.orgIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM organization_memberships WHERE user_id = ANY($1) OR organization_id = ANY($2)", tr.userIDs, tr.orgIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete organization_memberships: %v", err)
		}
	}

	// 3. Clear any organization reviewed_by_user_id references
	if len(tr.userIDs) > 0 {
		_, _ = tr.pool.Exec(ctx, "UPDATE organizations SET reviewed_by_user_id = NULL WHERE reviewed_by_user_id = ANY($1)", tr.userIDs)
	}

	// 4. Delete organizations by tracked primary key UUIDs
	if len(tr.orgIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM organizations WHERE id = ANY($1)", tr.orgIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete organizations: %v", err)
		}
	}

	// 5. Delete auth sessions for tracked users
	if len(tr.userIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM auth_sessions WHERE user_id = ANY($1)", tr.userIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete auth_sessions: %v", err)
		}
	}

	// 6. Delete auth identities for tracked users
	if len(tr.userIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM auth_identities WHERE user_id = ANY($1)", tr.userIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete auth_identities: %v", err)
		}
	}

	// 7. Delete users by tracked primary key UUIDs
	if len(tr.userIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM users WHERE id = ANY($1)", tr.userIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete users: %v", err)
		}
	}
}

// verifyRemoved verifies that all tracked records are absent from the test database.
func (tr *testTracker) verifyRemoved(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if len(tr.auditIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE id = ANY($1)", tr.auditIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d audit_logs rows still exist", count)
		}
	}

	if len(tr.userIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE id = ANY($1)", tr.userIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d users rows still exist", count)
		}
	}

	if len(tr.orgIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM organizations WHERE id = ANY($1)", tr.orgIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d organizations rows still exist", count)
		}
	}
}

// setupIntegrationTestDB validates all 9 security guards and initializes isolated database connection.
// Enforces single explicit cleanup order:
// 1. Test data cleanup while pool is open.
// 2. Verify tracked records were removed.
// 3. Close the pgx pool last.
func setupIntegrationTestDB(t *testing.T) (*pgxpool.Pool, *config.Config, *testTracker) {
	t.Helper()

	// Guard 1: Require TEST_DATABASE_DIRECT_URL
	testDBURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_DIRECT_URL"))
	if testDBURL == "" {
		t.Fatal("ABORT: TEST_DATABASE_DIRECT_URL environment variable is required for integration tests")
	}

	// Guard 2: Require DB_TARGET_ENV exactly equal to test
	targetEnv := os.Getenv("DB_TARGET_ENV")
	if targetEnv != "test" {
		t.Fatalf("ABORT: DB_TARGET_ENV must be exactly 'test', got '%s'", targetEnv)
	}

	// Guard 3: Reject execution if DATABASE_URL is present
	if strings.TrimSpace(os.Getenv("DATABASE_URL")) != "" {
		t.Fatal("ABORT: DATABASE_URL is present; integration tests must run isolated without DATABASE_URL")
	}

	// Guard 4: Reject execution if DATABASE_DIRECT_URL is present
	if strings.TrimSpace(os.Getenv("DATABASE_DIRECT_URL")) != "" {
		t.Fatal("ABORT: DATABASE_DIRECT_URL is present; integration tests must run isolated without DATABASE_DIRECT_URL")
	}

	// Guard 5: Connect using TEST_DATABASE_DIRECT_URL only
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolCfg, err := pgxpool.ParseConfig(testDBURL)
	if err != nil {
		t.Fatalf("ABORT: failed to parse test database connection config: %v", err)
	}
	poolCfg.MaxConns = 5
	poolCfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("ABORT: failed to connect to integration test database: %v", err)
	}

	// Guard 6 & 7: Execute SELECT current_database() and require trustdocs_schema_test
	var currentDB string
	if err := pool.QueryRow(ctx, "SELECT current_database()").Scan(&currentDB); err != nil {
		pool.Close()
		t.Fatalf("ABORT: failed to query current_database(): %v", err)
	}

	if currentDB != "trustdocs_schema_test" {
		pool.Close()
		t.Fatalf("ABORT: integration tests can only run against 'trustdocs_schema_test', connected to '%s'", currentDB)
	}

	tracker := newTestTracker(pool)

	// Single explicit teardown: cleanup -> verify -> close pool
	t.Cleanup(func() {
		tracker.cleanup(t)
		tracker.verifyRemoved(t)
		pool.Close()
	})

	cfg := &config.Config{
		AppEnv:                    "test",
		Port:                      "8080",
		FrontendURL:               "http://localhost:3000",
		LogLevel:                  "error",
		AuthSessionCookieName:     "trustdocs_session",
		AuthSessionTTL:            24 * time.Hour,
		AuthCookieSecure:          false,
		AuthCookieSameSite:        "Lax",
		CSRFSecret:                "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:              16384, // Lower memory for fast integration test execution
		Argon2Iterations:          1,
		Argon2Parallelism:         1,
		Argon2SaltLength:          16,
		Argon2KeyLength:           32,
		RateLimitLoginAttempts:    100, // Generous limits to avoid test throttling
		RateLimitLoginWindow:      15 * time.Minute,
		RateLimitIPAttempts:       100,
		RateLimitIPWindow:         15 * time.Minute,
		RateLimitRegisterAttempts: 100,
		RateLimitRegisterWindow:   1 * time.Hour,
		TrustedProxies:            []string{"127.0.0.1"},
	}

	return pool, cfg, tracker
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// canonicalRegistrationNumber generates a cryptographically random, trimmed, uppercase registration number
// complying strictly with the chk_organizations_reg_canonical constraint: registration_number = UPPER(BTRIM(registration_number)).
func canonicalRegistrationNumber(prefix string, nBytes int) string {
	return strings.ToUpper(strings.TrimSpace(prefix + randomHex(nBytes)))
}

func setupTestRouter(cfg *config.Config, pool *pgxpool.Pool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return router.SetupRouter(cfg, logger, pool)
}

// findCookieByName asserts that cookies is non-empty, finds the cookie with the given name,
// and fails immediately with a descriptive fatal error if not found.
func findCookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	if len(cookies) == 0 {
		t.Fatalf("expected cookies in HTTP response, got none")
	}
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("expected cookie %q not found in HTTP response (%d cookies present)", name, len(cookies))
	return nil
}

// ----------------------------------------------------------------------------
// Test 1: New registration creates 1 user, 1 identity, 1 audit entry, 0 sessions
// ----------------------------------------------------------------------------
func TestIntegration_NewRegistration_CreatesRecordsAtomically(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_reg_%s@example.com", randomHex(8))
	traceID := "test-trace-" + randomHex(12)

	body := fmt.Sprintf(`{"email":"%s","password":"ValidPassword12345!","full_name":"Integration User"}`, email)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", cfg.FrontendURL)
	req.Header.Set("User-Agent", traceID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on registration, got %d: %s", w.Code, w.Body.String())
	}

	// Verify no session cookie set
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("registration must never set a session cookie")
	}

	ctx := context.Background()

	// Query created user
	var userID pgtype.UUID
	var isSuperadmin, emailVerified bool
	err := pool.QueryRow(ctx, "SELECT id, is_superadmin, email_verified FROM users WHERE email = $1", email).Scan(&userID, &isSuperadmin, &emailVerified)
	if err != nil {
		t.Fatalf("failed to query created user from database: %v", err)
	}
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// Verify 1 identity
	var identCount int
	var identityType, identifier string
	err = pool.QueryRow(ctx, "SELECT count(*), coalesce(max(identity_type), ''), coalesce(max(identifier), '') FROM auth_identities WHERE user_id = $1 GROUP BY ()", userID).Scan(&identCount, &identityType, &identifier)
	if err != nil || identCount != 1 {
		t.Errorf("expected exactly 1 auth identity, got %d (err: %v)", identCount, err)
	}
	if identityType != "EMAIL_PASSWORD" || identifier != email {
		t.Errorf("expected identity EMAIL_PASSWORD for %s, got %s for %s", email, identityType, identifier)
	}

	// Verify 1 USER_REGISTER audit log
	var auditCount int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE actor_user_id = $1 AND action = 'USER_REGISTER'", userID).Scan(&auditCount)
	if err != nil || auditCount != 1 {
		t.Errorf("expected exactly 1 USER_REGISTER audit log, got %d", auditCount)
	}

	// Verify 0 sessions
	var sessionCount int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE user_id = $1", userID).Scan(&sessionCount)
	if err != nil || sessionCount != 0 {
		t.Errorf("expected 0 auth sessions for new registration, got %d", sessionCount)
	}
}

// ----------------------------------------------------------------------------
// Test 2: Duplicate registration returns same generic response, no duplicate records
// ----------------------------------------------------------------------------
func TestIntegration_DuplicateRegistration_AntiEnumeration(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_dup_%s@example.com", randomHex(8))
	traceID1 := "test-trace-" + randomHex(12)
	traceID2 := "test-trace-" + randomHex(12)

	body1 := fmt.Sprintf(`{"email":"%s","password":"ValidPassword12345!","full_name":"Original User"}`, email)
	req1, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Origin", cfg.FrontendURL)
	req1.Header.Set("User-Agent", traceID1)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", w1.Code)
	}

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID1)

	// Second registration with identical email
	body2 := fmt.Sprintf(`{"email":"%s","password":"AnotherValidPassword123!","full_name":"Duplicate User"}`, email)
	req2, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", cfg.FrontendURL)
	req2.Header.Set("User-Agent", traceID2)

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	tracker.TrackAuditByTrace(ctx, t, traceID2)

	// Responses must be strictly identical
	if w2.Code != http.StatusOK {
		t.Fatalf("duplicate registration should return 200 OK, got %d", w2.Code)
	}
	if w1.Body.String() != w2.Body.String() {
		t.Errorf("duplicate registration response leaked enumeration info: %s != %s", w1.Body.String(), w2.Body.String())
	}

	// Verify no duplicate user created in database
	var userCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE email = $1", email).Scan(&userCount)
	if userCount != 1 {
		t.Errorf("expected exactly 1 user record, got %d", userCount)
	}
}

// ----------------------------------------------------------------------------
// Test 3: Registration transaction rollback leaves no orphan records
// ----------------------------------------------------------------------------
func TestIntegration_RegistrationTransactionRollback(t *testing.T) {
	pool, _, _ := setupIntegrationTestDB(t)

	repo := auth.NewPgxRepository(pool)
	ctx := context.Background()

	email := fmt.Sprintf("test_rollback_%s@example.com", randomHex(8))

	userParams := db.CreateUserParams{
		Email:         email,
		FullName:      "Rollback Test User",
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: false,
	}

	// Invalid identity type to trigger database CHECK constraint violation
	identityParams := db.CreateAuthIdentityParams{
		IdentityType:   "INVALID_UNSUPPORTED_TYPE",
		Identifier:     email,
		CredentialHash: pgtype.Text{String: "some-hash", Valid: true},
		Metadata:       []byte("{}"),
	}

	auditParams := db.CreateAuditLogParams{
		Action:       "USER_REGISTER",
		ResourceType: "user",
		Payload:      []byte("{}"),
	}

	// Must fail and roll back transaction
	_, err := repo.CreateUserAndIdentityWithAudit(ctx, userParams, identityParams, auditParams)
	if err == nil {
		t.Fatalf("expected error on invalid identity type constraint violation")
	}

	// Confirm user was NOT saved in database
	var userCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE email = $1", email).Scan(&userCount)
	if userCount != 0 {
		t.Errorf("expected 0 users after rollback, found %d", userCount)
	}
}

// ----------------------------------------------------------------------------
// Test 4: Successful login creates session and LOGIN_SUCCESS audit atomically
// Stores only SHA-256 session token hash, never raw token
// ----------------------------------------------------------------------------
func TestIntegration_Login_Success_AtomicSessionAndAudit(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_login_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	regTraceID := "test-trace-" + randomHex(12)
	loginTraceID := "test-trace-" + randomHex(12)

	// Register
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Login Tester"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", regTraceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)
	if wReg.Code != http.StatusOK {
		t.Fatalf("registration failed: %d", wReg.Code)
	}

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, regTraceID)

	// Login
	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, email, password)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", loginTraceID)

	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	tracker.TrackAuditByTrace(ctx, t, loginTraceID)

	// Check session cookie
	cookies := wLogin.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 session cookie, got %d", len(cookies))
	}
	sessionCookie := findCookieByName(t, cookies, cfg.AuthSessionCookieName)
	rawSessionToken := sessionCookie.Value
	if rawSessionToken == "" {
		t.Fatalf("session cookie value is empty")
	}

	// Verify database session row
	var tokenHash string
	var sessionID pgtype.UUID
	err := pool.QueryRow(ctx, "SELECT id, token_hash FROM auth_sessions WHERE user_id = $1", userID).Scan(&sessionID, &tokenHash)
	if err != nil {
		t.Fatalf("failed to query auth_session from database: %v", err)
	}

	// Must be 64-char hex string (SHA-256)
	if len(tokenHash) != 64 {
		t.Errorf("expected 64-char hex token_hash, got %d chars: %s", len(tokenHash), tokenHash)
	}
	// Raw token must NEVER equal or appear in token_hash
	if tokenHash == rawSessionToken || strings.Contains(tokenHash, rawSessionToken) {
		t.Errorf("raw session token was stored directly in database!")
	}

	// Verify LOGIN_SUCCESS audit entry
	var successCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE actor_user_id = $1 AND action = 'LOGIN_SUCCESS'", userID).Scan(&successCount)
	if successCount != 1 {
		t.Errorf("expected 1 LOGIN_SUCCESS audit log, got %d", successCount)
	}
}

// ----------------------------------------------------------------------------
// Test 5: Failed login returns identical generic error, no session, no PII in audit
// ----------------------------------------------------------------------------
func TestIntegration_Login_Failed_NoSessionAndPIIProtection(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_fail_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	regTraceID := "test-trace-" + randomHex(12)
	wrongPassTraceID := "test-trace-" + randomHex(12)
	unknownTraceID := "test-trace-" + randomHex(12)

	// Register user
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Fail Tester"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", regTraceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, regTraceID)

	// 1. Wrong password attempt
	wrongPassBody := fmt.Sprintf(`{"email":"%s","password":"WrongPassword12345!","portal_context":"app"}`, email)
	reqWrong, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(wrongPassBody))
	reqWrong.Header.Set("Content-Type", "application/json")
	reqWrong.Header.Set("Origin", cfg.FrontendURL)
	reqWrong.Header.Set("User-Agent", wrongPassTraceID)
	wWrong := httptest.NewRecorder()
	r.ServeHTTP(wWrong, reqWrong)
	tracker.TrackAuditByTrace(ctx, t, wrongPassTraceID)

	if wWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password, got %d", wWrong.Code)
	}

	// 2. Unknown email attempt
	unknownEmail := fmt.Sprintf("nonexistent_%s@example.com", randomHex(8))
	unknownBody := fmt.Sprintf(`{"email":"%s","password":"ValidPassword12345!","portal_context":"app"}`, unknownEmail)
	reqUnk, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(unknownBody))
	reqUnk.Header.Set("Content-Type", "application/json")
	reqUnk.Header.Set("Origin", cfg.FrontendURL)
	reqUnk.Header.Set("User-Agent", unknownTraceID)
	wUnk := httptest.NewRecorder()
	r.ServeHTTP(wUnk, reqUnk)
	tracker.TrackAuditByTrace(ctx, t, unknownTraceID)

	if wUnk.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unknown email, got %d", wUnk.Code)
	}

	// Both failures must return identical error responses
	if wWrong.Body.String() != wUnk.Body.String() {
		t.Errorf("error responses differed between wrong password and unknown user: %s != %s", wWrong.Body.String(), wUnk.Body.String())
	}

	// Zero sessions created
	var sessionCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE user_id = $1", userID).Scan(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("expected 0 sessions after failed logins, got %d", sessionCount)
	}

	// Check audit log payloads for PII
	rows, err := pool.Query(ctx, "SELECT payload FROM audit_logs WHERE user_agent IN ($1, $2)", wrongPassTraceID, unknownTraceID)
	if err != nil {
		t.Fatalf("failed to query failed login audit logs: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var payload []byte
		_ = rows.Scan(&payload)
		payloadStr := string(payload)
		if strings.Contains(payloadStr, email) || strings.Contains(payloadStr, unknownEmail) ||
			strings.Contains(payloadStr, password) || strings.Contains(payloadStr, "WrongPassword") {
			t.Errorf("failed login audit log contained plain PII: %s", payloadStr)
		}
	}
}

// ----------------------------------------------------------------------------
// Test 6: Authenticated /me across 5 session states
// ----------------------------------------------------------------------------
func TestIntegration_AuthMe_SessionStates(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_me_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	traceID := "test-trace-" + randomHex(12)

	// Register & Login
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Profile User"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, email, password)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	sessionCookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)

	var sessionID pgtype.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM auth_sessions WHERE user_id = $1", userID).Scan(&sessionID); err != nil {
		t.Fatalf("failed to query auth_session ID: %v", err)
	}

	// 1. Valid session -> 200 OK
	reqMe, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.AddCookie(sessionCookie)
	wMe := httptest.NewRecorder()
	r.ServeHTTP(wMe, reqMe)
	if wMe.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /me with valid session, got %d: %s", wMe.Code, wMe.Body.String())
	}

	// 2. Missing cookie -> 401
	reqMissing, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing session cookie, got %d", wMissing.Code)
	}

	// 3. Invalid token string -> 401
	reqInvalid, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqInvalid.AddCookie(&http.Cookie{Name: cfg.AuthSessionCookieName, Value: "invalid-bogus-token"})
	wInvalid := httptest.NewRecorder()
	r.ServeHTTP(wInvalid, reqInvalid)
	if wInvalid.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid session cookie, got %d", wInvalid.Code)
	}

	// 4. Expired session in database -> 401
	// Atomically shift created_at and expires_at into the past so that:
	// created_at < expires_at < NOW(), satisfying chk_auth_sessions_expiry (expires_at > created_at).
	_, err := pool.Exec(ctx, "UPDATE auth_sessions SET created_at = NOW() - INTERVAL '2 hours', expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1", sessionID)
	if err != nil {
		t.Fatalf("failed to update session expiry: %v", err)
	}
	reqExpired, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqExpired.AddCookie(sessionCookie)
	wExpired := httptest.NewRecorder()
	r.ServeHTTP(wExpired, reqExpired)
	if wExpired.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired session, got %d", wExpired.Code)
	}

	// Reset session with future expiry, then mark revoked.
	// Note: created_at was shifted to NOW() - INTERVAL '2 hours',
	// so setting expires_at = NOW() + INTERVAL '24 hours' and revoked_at = NOW()
	// satisfies both chk_auth_sessions_expiry (expires_at > created_at)
	// and chk_auth_sessions_revocation (revoked_at >= created_at).
	_, err = pool.Exec(ctx, "UPDATE auth_sessions SET expires_at = NOW() + INTERVAL '24 hours', revoked_at = NOW() WHERE id = $1", sessionID)
	if err != nil {
		t.Fatalf("failed to update session revocation: %v", err)
	}

	// 5. Revoked session in database -> 401
	reqRevoked, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqRevoked.AddCookie(sessionCookie)
	wRevoked := httptest.NewRecorder()
	r.ServeHTTP(wRevoked, reqRevoked)
	if wRevoked.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked session, got %d", wRevoked.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 7: CSRF token distribution, no-store headers, and mutation validation
// ----------------------------------------------------------------------------
func TestIntegration_CSRF_Lifecycle(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_csrf_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	traceID := "test-trace-" + randomHex(12)

	// Register & Login
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"CSRF User"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, email, password)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	sessionCookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)

	// 1. GET /api/v1/auth/csrf with valid cookie
	reqCSRF, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqCSRF.AddCookie(sessionCookie)
	wCSRF := httptest.NewRecorder()
	r.ServeHTTP(wCSRF, reqCSRF)

	if wCSRF.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /csrf, got %d", wCSRF.Code)
	}

	cacheControl := wCSRF.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("expected Cache-Control: no-store, got '%s'", cacheControl)
	}

	var csrfResp struct {
		Data auth.CSRFResponse `json:"data"`
	}
	if err := json.Unmarshal(wCSRF.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("failed to decode CSRF response: %v", err)
	}
	csrfToken := csrfResp.Data.CSRFToken
	if csrfToken == "" {
		t.Fatalf("expected non-empty CSRF token")
	}
	// Token must differ from raw session cookie
	if csrfToken == sessionCookie.Value {
		t.Errorf("CSRF token must not expose raw session cookie")
	}

	// 2. Mutation with valid X-CSRF-Token -> 200 OK
	reqLogoutValid, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogoutValid.Header.Set("Origin", cfg.FrontendURL)
	reqLogoutValid.Header.Set("X-CSRF-Token", csrfToken)
	reqLogoutValid.Header.Set("User-Agent", traceID)
	reqLogoutValid.AddCookie(sessionCookie)
	wLogoutValid := httptest.NewRecorder()
	r.ServeHTTP(wLogoutValid, reqLogoutValid)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogoutValid.Code != http.StatusOK {
		t.Errorf("expected 200 OK for logout with valid CSRF token, got %d: %s", wLogoutValid.Code, wLogoutValid.Body.String())
	}

	// 3. Login again with a fresh request/body to test missing and invalid CSRF tokens
	wLogin2 := httptest.NewRecorder()
	reqLogin2, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin2.Header.Set("Content-Type", "application/json")
	reqLogin2.Header.Set("Origin", cfg.FrontendURL)
	reqLogin2.Header.Set("User-Agent", traceID)
	r.ServeHTTP(wLogin2, reqLogin2)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogin2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from second login, got %d: %s", wLogin2.Code, wLogin2.Body.String())
	}
	sessionCookie2 := findCookieByName(t, wLogin2.Result().Cookies(), cfg.AuthSessionCookieName)

	// Mutation with missing X-CSRF-Token -> 403 CSRF_TOKEN_INVALID
	reqLogoutMissing, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogoutMissing.Header.Set("Origin", cfg.FrontendURL)
	reqLogoutMissing.AddCookie(sessionCookie2)
	wLogoutMissing := httptest.NewRecorder()
	r.ServeHTTP(wLogoutMissing, reqLogoutMissing)

	if wLogoutMissing.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for missing CSRF token, got %d", wLogoutMissing.Code)
	}
	if !strings.Contains(wLogoutMissing.Body.String(), "CSRF_TOKEN_INVALID") {
		t.Errorf("expected code CSRF_TOKEN_INVALID, got %s", wLogoutMissing.Body.String())
	}

	// Mutation with invalid X-CSRF-Token -> 403 CSRF_TOKEN_INVALID
	reqLogoutBad, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogoutBad.Header.Set("Origin", cfg.FrontendURL)
	reqLogoutBad.Header.Set("X-CSRF-Token", "forged-invalid-csrf-token")
	reqLogoutBad.AddCookie(sessionCookie2)
	wLogoutBad := httptest.NewRecorder()
	r.ServeHTTP(wLogoutBad, reqLogoutBad)

	if wLogoutBad.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for invalid CSRF token, got %d", wLogoutBad.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 8: Logout revokes session, clears cookie, and repeated logout is idempotent
// ----------------------------------------------------------------------------
func TestIntegration_Logout_RevocationAndIdempotency(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_logout_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	traceID := "test-trace-" + randomHex(12)

	// Register & Login
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Logout User"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, email, password)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	sessionCookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)

	// Fetch CSRF token
	reqCSRF, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqCSRF.AddCookie(sessionCookie)
	wCSRF := httptest.NewRecorder()
	r.ServeHTTP(wCSRF, reqCSRF)
	var csrfResp struct {
		Data auth.CSRFResponse `json:"data"`
	}
	_ = json.Unmarshal(wCSRF.Body.Bytes(), &csrfResp)

	// Logout
	reqLogout, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogout.Header.Set("Origin", cfg.FrontendURL)
	reqLogout.Header.Set("X-CSRF-Token", csrfResp.Data.CSRFToken)
	reqLogout.Header.Set("User-Agent", traceID)
	reqLogout.AddCookie(sessionCookie)

	wLogout := httptest.NewRecorder()
	r.ServeHTTP(wLogout, reqLogout)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogout.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", wLogout.Code)
	}

	// Verify cookie cleared with MaxAge = -1 and expired Unix epoch
	clearCookies := wLogout.Result().Cookies()
	if len(clearCookies) != 1 {
		t.Fatalf("expected 1 clear cookie, got %d", len(clearCookies))
	}
	clearCookie := findCookieByName(t, clearCookies, cfg.AuthSessionCookieName)
	if clearCookie.MaxAge != -1 || clearCookie.Value != "" {
		t.Errorf("expected MaxAge -1 and empty value on logout clear cookie, got MaxAge=%d, Val='%s'", clearCookie.MaxAge, clearCookie.Value)
	}

	// Verify session marked revoked in database
	var revokedAt pgtype.Timestamptz
	err := pool.QueryRow(ctx, "SELECT revoked_at FROM auth_sessions WHERE user_id = $1", userID).Scan(&revokedAt)
	if err != nil || !revokedAt.Valid {
		t.Errorf("expected session to be marked revoked in database, got valid=%v", revokedAt.Valid)
	}

	// Calling logout again is idempotent
	reqLogoutRepeat, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogoutRepeat.Header.Set("Origin", cfg.FrontendURL)
	reqLogoutRepeat.Header.Set("X-CSRF-Token", csrfResp.Data.CSRFToken)
	reqLogoutRepeat.Header.Set("User-Agent", traceID)
	reqLogoutRepeat.AddCookie(sessionCookie)

	wLogoutRepeat := httptest.NewRecorder()
	r.ServeHTTP(wLogoutRepeat, reqLogoutRepeat)
	if wLogoutRepeat.Code != http.StatusOK {
		t.Errorf("repeated logout should succeed idempotently, got %d", wLogoutRepeat.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 9: Portal isolation (normal user vs superadmin in app vs admin contexts)
// ----------------------------------------------------------------------------
func TestIntegration_PortalIsolation(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	normalEmail := fmt.Sprintf("test_norm_%s@example.com", randomHex(8))
	adminEmail := fmt.Sprintf("test_admin_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	traceID := "test-trace-" + randomHex(12)

	ctx := context.Background()

	// 1. Create normal user
	regBodyNorm := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Normal User"}`, normalEmail, password)
	reqNorm, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBodyNorm))
	reqNorm.Header.Set("Content-Type", "application/json")
	reqNorm.Header.Set("Origin", cfg.FrontendURL)
	reqNorm.Header.Set("User-Agent", traceID)
	wNorm := httptest.NewRecorder()
	r.ServeHTTP(wNorm, reqNorm)

	var normalUserID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", normalEmail).Scan(&normalUserID)
	tracker.TrackUser(normalUserID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// 2. Create superadmin user (register then promote via UPDATE users SET is_superadmin=true)
	regBodyAdmin := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Super Admin"}`, adminEmail, password)
	reqAdmin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBodyAdmin))
	reqAdmin.Header.Set("Content-Type", "application/json")
	reqAdmin.Header.Set("Origin", cfg.FrontendURL)
	reqAdmin.Header.Set("User-Agent", traceID)
	wAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdmin, reqAdmin)

	var adminUserID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", adminEmail).Scan(&adminUserID)
	tracker.TrackUser(adminUserID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	_, err := pool.Exec(ctx, "UPDATE users SET is_superadmin = true WHERE id = $1", adminUserID)
	if err != nil {
		t.Fatalf("failed to promote test user to superadmin: %v", err)
	}

	// A. Normal user logging into portal_context="admin" -> rejected with 401 INVALID_CREDENTIALS
	bodyNormAdmin := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"admin"}`, normalEmail, password)
	reqNA, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(bodyNormAdmin))
	reqNA.Header.Set("Content-Type", "application/json")
	reqNA.Header.Set("Origin", cfg.FrontendURL)
	reqNA.Header.Set("User-Agent", traceID)
	wNA := httptest.NewRecorder()
	r.ServeHTTP(wNA, reqNA)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wNA.Code != http.StatusUnauthorized {
		t.Errorf("normal user with admin portal context must be rejected with 401, got %d", wNA.Code)
	}

	// B. Superadmin logging into portal_context="app" -> rejected with 401 INVALID_CREDENTIALS
	bodyAdminApp := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, adminEmail, password)
	reqAA, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(bodyAdminApp))
	reqAA.Header.Set("Content-Type", "application/json")
	reqAA.Header.Set("Origin", cfg.FrontendURL)
	reqAA.Header.Set("User-Agent", traceID)
	wAA := httptest.NewRecorder()
	r.ServeHTTP(wAA, reqAA)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wAA.Code != http.StatusUnauthorized {
		t.Errorf("superadmin user with app portal context must be rejected with 401, got %d", wAA.Code)
	}

	// C. Normal user logging into portal_context="app" -> succeeds
	bodyNormApp := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, normalEmail, password)
	reqNormApp, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(bodyNormApp))
	reqNormApp.Header.Set("Content-Type", "application/json")
	reqNormApp.Header.Set("Origin", cfg.FrontendURL)
	reqNormApp.Header.Set("User-Agent", traceID)
	wNormApp := httptest.NewRecorder()
	r.ServeHTTP(wNormApp, reqNormApp)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wNormApp.Code != http.StatusOK {
		t.Fatalf("normal user with app portal context must authenticate, got %d", wNormApp.Code)
	}

	// D. Superadmin user logging into portal_context="admin" -> succeeds
	bodyAdminAdmin := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"admin"}`, adminEmail, password)
	reqAdminAdmin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(bodyAdminAdmin))
	reqAdminAdmin.Header.Set("Content-Type", "application/json")
	reqAdminAdmin.Header.Set("Origin", cfg.FrontendURL)
	reqAdminAdmin.Header.Set("User-Agent", traceID)
	wAdminAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdminAdmin, reqAdminAdmin)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wAdminAdmin.Code != http.StatusOK {
		t.Fatalf("superadmin user with admin portal context must authenticate, got %d", wAdminAdmin.Code)
	}

	// E. Route guard test: RequireSuperadmin vs RequireNonSuperadmin
	normalCookie := findCookieByName(t, wNormApp.Result().Cookies(), cfg.AuthSessionCookieName)
	adminCookie := findCookieByName(t, wAdminAdmin.Result().Cookies(), cfg.AuthSessionCookieName)

	authRepo := auth.NewPgxRepository(pool)
	authSvc := auth.NewService(authRepo, cfg)

	testRouter := gin.New()
	testRouter.Use(middleware.RequireAuth(authSvc, cfg))
	testRouter.GET("/admin-only", middleware.RequireSuperadmin(), func(c *gin.Context) {
		core.SendSuccess(c, http.StatusOK, gin.H{"access": "granted"})
	})
	testRouter.GET("/app-only", middleware.RequireNonSuperadmin(), func(c *gin.Context) {
		core.SendSuccess(c, http.StatusOK, gin.H{"access": "granted"})
	})

	// Normal user on admin route -> 403
	reqCheck1, _ := http.NewRequest(http.MethodGet, "/admin-only", nil)
	reqCheck1.AddCookie(normalCookie)
	wCheck1 := httptest.NewRecorder()
	testRouter.ServeHTTP(wCheck1, reqCheck1)
	if wCheck1.Code != http.StatusForbidden {
		t.Errorf("expected 403 for normal user on superadmin route, got %d", wCheck1.Code)
	}

	// Superadmin on non-superadmin route -> 403
	reqCheck2, _ := http.NewRequest(http.MethodGet, "/app-only", nil)
	reqCheck2.AddCookie(adminCookie)
	wCheck2 := httptest.NewRecorder()
	testRouter.ServeHTTP(wCheck2, reqCheck2)
	if wCheck2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for superadmin user on app route, got %d", wCheck2.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 10: Organization RBAC (functional roles and cross-tenant isolation)
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationRBAC(t *testing.T) {
	pool, _, tracker := setupIntegrationTestDB(t)
	queries := db.New(pool)
	ctx := context.Background()

	// 1. Create Organization A (UNIVERSITY) and Organization B (COMPANY)
	orgA, err := queries.CreateOrganization(ctx, db.CreateOrganizationParams{
		OrgType:            "UNIVERSITY",
		LegalName:          "Test Apex University " + randomHex(4),
		TradeName:          pgtype.Text{String: "Apex Uni", Valid: true},
		CountryCode:        "US",
		RegistrationNumber: canonicalRegistrationNumber("UNIV-", 6),
		OfficialDomain:     fmt.Sprintf("apex-%s.edu", randomHex(4)),
	})
	if err != nil {
		t.Fatalf("failed to create organization A: %v", err)
	}
	tracker.TrackOrg(orgA.ID)

	orgB, err := queries.CreateOrganization(ctx, db.CreateOrganizationParams{
		OrgType:            "COMPANY",
		LegalName:          "Test Vertex Corp " + randomHex(4),
		TradeName:          pgtype.Text{String: "Vertex", Valid: true},
		CountryCode:        "US",
		RegistrationNumber: canonicalRegistrationNumber("CORP-", 6),
		OfficialDomain:     fmt.Sprintf("vertex-%s.com", randomHex(4)),
	})
	if err != nil {
		t.Fatalf("failed to create organization B: %v", err)
	}
	tracker.TrackOrg(orgB.ID)

	// 2. Create User A (UNIVERSITY_ADMIN) and User B (UNIVERSITY_ISSUER) in Org A
	userA, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:         fmt.Sprintf("admin_%s@apex.edu", randomHex(6)),
		FullName:      "University Admin",
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("failed to create user A: %v", err)
	}
	tracker.TrackUser(userA.ID)

	userB, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:         fmt.Sprintf("issuer_%s@apex.edu", randomHex(6)),
		FullName:      "University Issuer",
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("failed to create user B: %v", err)
	}
	tracker.TrackUser(userB.ID)

	// Memberships in Org A
	_, err = queries.CreateMembership(ctx, db.CreateMembershipParams{
		OrganizationID: orgA.ID,
		UserID:         userA.ID,
		Role:           "UNIVERSITY_ADMIN",
		IsActive:       true,
	})
	if err != nil {
		t.Fatalf("failed to create membership for user A: %v", err)
	}

	_, err = queries.CreateMembership(ctx, db.CreateMembershipParams{
		OrganizationID: orgA.ID,
		UserID:         userB.ID,
		Role:           "UNIVERSITY_ISSUER",
		IsActive:       true,
	})
	if err != nil {
		t.Fatalf("failed to create membership for user B: %v", err)
	}

	repo := auth.NewPgxRepository(pool)
	testRouter := gin.New()

	// Mock user session context for testing RBAC route guards
	testRouter.GET("/orgs/:org_id/admin-action", func(c *gin.Context) {
		mockUser := c.GetHeader("X-Test-Mock-User")
		if mockUser == "A" {
			c.Set("user", userA)
		} else if mockUser == "B" {
			c.Set("user", userB)
		}
		c.Next()
	}, middleware.RequireOrgRole(repo, "UNIVERSITY_ADMIN"), func(c *gin.Context) {
		core.SendSuccess(c, http.StatusOK, gin.H{"status": "admin_granted"})
	})

	// User A has UNIVERSITY_ADMIN in Org A -> succeeds
	reqA, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/orgs/%s/admin-action", orgA.ID), nil)
	reqA.Header.Set("X-Test-Mock-User", "A")
	wA := httptest.NewRecorder()
	testRouter.ServeHTTP(wA, reqA)
	if wA.Code != http.StatusOK {
		t.Errorf("expected 200 OK for UNIVERSITY_ADMIN on admin action, got %d", wA.Code)
	}

	// User B has UNIVERSITY_ISSUER in Org A -> fails with 403 Forbidden
	reqB, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/orgs/%s/admin-action", orgA.ID), nil)
	reqB.Header.Set("X-Test-Mock-User", "B")
	wB := httptest.NewRecorder()
	testRouter.ServeHTTP(wB, reqB)
	if wB.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for UNIVERSITY_ISSUER on admin action, got %d", wB.Code)
	}

	// User A attempts access to Org B (cross-tenant attack) -> fails with 403 Forbidden
	reqCross, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/orgs/%s/admin-action", orgB.ID), nil)
	reqCross.Header.Set("X-Test-Mock-User", "A")
	wCross := httptest.NewRecorder()
	testRouter.ServeHTTP(wCross, reqCross)
	if wCross.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on cross-organization access, got %d", wCross.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 11: Audit log secrecy: no plaintext emails, passwords, tokens, hashes in payloads
// ----------------------------------------------------------------------------
func TestIntegration_AuditLog_PIIExclusion(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	email := fmt.Sprintf("test_audit_%s@example.com", randomHex(8))
	password := "SecretPass12345!"
	traceID := "test-trace-" + randomHex(12)

	// Register
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Audit User"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	ctx := context.Background()
	var userID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	tracker.TrackUser(userID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// Login
	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, email, password)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	sessionCookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)
	rawToken := sessionCookie.Value

	// Inspect all audit rows created for this user
	rows, err := pool.Query(ctx, "SELECT action, resource_type, payload FROM audit_logs WHERE actor_user_id = $1", userID)
	if err != nil {
		t.Fatalf("failed to query audit logs: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var action, resType string
		var payload []byte
		_ = rows.Scan(&action, &resType, &payload)
		payloadStr := string(payload)

		// Assert zero credentials, tokens, or passwords
		forbiddenStrings := []string{email, password, rawToken}
		for _, forbidden := range forbiddenStrings {
			if forbidden != "" && strings.Contains(payloadStr, forbidden) {
				t.Errorf("audit log payload for action '%s' leaked forbidden secret/PII '%s': %s", action, forbidden, payloadStr)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Test 12: Regression: /health remains 200, /ready returns 200 with postgres dependency
// ----------------------------------------------------------------------------
func TestIntegration_Regression_HealthAndReady(t *testing.T) {
	pool, cfg, _ := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)

	// 1. /health
	reqHealth, _ := http.NewRequest(http.MethodGet, "/health", nil)
	wHealth := httptest.NewRecorder()
	r.ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /health, got %d: %s", wHealth.Code, wHealth.Body.String())
	}

	var healthResp struct {
		Success bool              `json:"success"`
		Data    health.HealthData `json:"data"`
	}
	if err := json.Unmarshal(wHealth.Body.Bytes(), &healthResp); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if !healthResp.Success || healthResp.Data.Status != "ok" {
		t.Errorf("unexpected health data: %+v", healthResp)
	}

	// 2. /ready: Assert exact existing readiness contract
	reqReady, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	wReady := httptest.NewRecorder()
	r.ServeHTTP(wReady, reqReady)

	if wReady.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /ready, got %d: %s", wReady.Code, wReady.Body.String())
	}

	var readyResp struct {
		Success bool             `json:"success"`
		Data    health.ReadyData `json:"data"`
	}
	if err := json.Unmarshal(wReady.Body.Bytes(), &readyResp); err != nil {
		t.Fatalf("failed to decode ready response: %v", err)
	}

	if !readyResp.Success {
		t.Errorf("expected ready success to be true")
	}
	if readyResp.Data.Status != "ready" {
		t.Errorf("expected data.status to be 'ready', got '%s'", readyResp.Data.Status)
	}
	if len(readyResp.Data.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(readyResp.Data.Dependencies))
	}
	dep := readyResp.Data.Dependencies[0]
	if dep.Name != "postgres" || dep.Status != "up" {
		t.Errorf("expected postgres: up, got %s: %s", dep.Name, dep.Status)
	}
}
