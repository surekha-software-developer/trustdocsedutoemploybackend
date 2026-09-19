//go:build integration

package organizations_test

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
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/organizations"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/router"
)

// testTracker tracks exact primary key UUIDs for all entity types created during integration test execution
// to ensure dependency-safe, leak-free teardown without TRUNCATE, DROP, migrations, or broad DELETE statements.
type testTracker struct {
	mu              sync.Mutex
	pool            *pgxpool.Pool
	userIDs         []pgtype.UUID
	authIdentityIDs []pgtype.UUID
	sessionIDs      []pgtype.UUID
	orgIDs          []pgtype.UUID
	membershipIDs   []pgtype.UUID
	auditIDs        []pgtype.UUID
}

func newTestTracker(pool *pgxpool.Pool) *testTracker {
	return &testTracker{
		pool:            pool,
		userIDs:         make([]pgtype.UUID, 0),
		authIdentityIDs: make([]pgtype.UUID, 0),
		sessionIDs:      make([]pgtype.UUID, 0),
		orgIDs:          make([]pgtype.UUID, 0),
		membershipIDs:   make([]pgtype.UUID, 0),
		auditIDs:        make([]pgtype.UUID, 0),
	}
}

func deduplicateUUIDs(ids []pgtype.UUID) []pgtype.UUID {
	seen := make(map[[16]byte]bool, len(ids))
	result := make([]pgtype.UUID, 0, len(ids))
	for _, id := range ids {
		if !id.Valid {
			continue
		}
		if !seen[id.Bytes] {
			seen[id.Bytes] = true
			result = append(result, id)
		}
	}
	return result
}

func (tr *testTracker) TrackUser(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.userIDs = append(tr.userIDs, id)
}

func (tr *testTracker) TrackAuthIdentity(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.authIdentityIDs = append(tr.authIdentityIDs, id)
}

func (tr *testTracker) TrackSession(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.sessionIDs = append(tr.sessionIDs, id)
}

func (tr *testTracker) TrackOrg(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.orgIDs = append(tr.orgIDs, id)
}

func (tr *testTracker) TrackMembership(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.membershipIDs = append(tr.membershipIDs, id)
}

func (tr *testTracker) TrackAuditID(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.auditIDs = append(tr.auditIDs, id)
}

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

func (tr *testTracker) cleanup(t *testing.T) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Prior to deletion, discover any uncaptured exact primary keys associated with tracked users or organizations
	if len(tr.userIDs) > 0 {
		rowsAI, err := tr.pool.Query(ctx, "SELECT id FROM auth_identities WHERE user_id = ANY($1)", tr.userIDs)
		if err == nil {
			for rowsAI.Next() {
				var id pgtype.UUID
				if err := rowsAI.Scan(&id); err == nil {
					tr.authIdentityIDs = append(tr.authIdentityIDs, id)
				}
			}
			rowsAI.Close()
		}

		rowsS, err := tr.pool.Query(ctx, "SELECT id FROM auth_sessions WHERE user_id = ANY($1)", tr.userIDs)
		if err == nil {
			for rowsS.Next() {
				var id pgtype.UUID
				if err := rowsS.Scan(&id); err == nil {
					tr.sessionIDs = append(tr.sessionIDs, id)
				}
			}
			rowsS.Close()
		}

		rowsMU, err := tr.pool.Query(ctx, "SELECT id FROM organization_memberships WHERE user_id = ANY($1)", tr.userIDs)
		if err == nil {
			for rowsMU.Next() {
				var id pgtype.UUID
				if err := rowsMU.Scan(&id); err == nil {
					tr.membershipIDs = append(tr.membershipIDs, id)
				}
			}
			rowsMU.Close()
		}

		rowsAU, err := tr.pool.Query(ctx, "SELECT id FROM audit_logs WHERE actor_user_id = ANY($1)", tr.userIDs)
		if err == nil {
			for rowsAU.Next() {
				var id pgtype.UUID
				if err := rowsAU.Scan(&id); err == nil {
					tr.auditIDs = append(tr.auditIDs, id)
				}
			}
			rowsAU.Close()
		}
	}

	if len(tr.orgIDs) > 0 {
		rowsMO, err := tr.pool.Query(ctx, "SELECT id FROM organization_memberships WHERE organization_id = ANY($1)", tr.orgIDs)
		if err == nil {
			for rowsMO.Next() {
				var id pgtype.UUID
				if err := rowsMO.Scan(&id); err == nil {
					tr.membershipIDs = append(tr.membershipIDs, id)
				}
			}
			rowsMO.Close()
		}

		rowsAO, err := tr.pool.Query(ctx, "SELECT id FROM audit_logs WHERE target_organization_id = ANY($1)", tr.orgIDs)
		if err == nil {
			for rowsAO.Next() {
				var id pgtype.UUID
				if err := rowsAO.Scan(&id); err == nil {
					tr.auditIDs = append(tr.auditIDs, id)
				}
			}
			rowsAO.Close()
		}
	}

	// Deduplicate all tracked primary key slices
	tr.auditIDs = deduplicateUUIDs(tr.auditIDs)
	tr.membershipIDs = deduplicateUUIDs(tr.membershipIDs)
	tr.orgIDs = deduplicateUUIDs(tr.orgIDs)
	tr.sessionIDs = deduplicateUUIDs(tr.sessionIDs)
	tr.authIdentityIDs = deduplicateUUIDs(tr.authIdentityIDs)
	tr.userIDs = deduplicateUUIDs(tr.userIDs)

	// Execute exact primary key deletions in reverse foreign-key dependency order:
	// 1. DELETE FROM audit_logs WHERE id = ANY($1)
	if len(tr.auditIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM audit_logs WHERE id = ANY($1)", tr.auditIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete audit_logs: %v", err)
		}
	}

	// 2. DELETE FROM organization_memberships WHERE id = ANY($1)
	if len(tr.membershipIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM organization_memberships WHERE id = ANY($1)", tr.membershipIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete organization_memberships: %v", err)
		}
	}

	// 3. DELETE FROM organizations WHERE id = ANY($1)
	if len(tr.orgIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM organizations WHERE id = ANY($1)", tr.orgIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete organizations: %v", err)
		}
	}

	// 4. DELETE FROM auth_sessions WHERE id = ANY($1)
	if len(tr.sessionIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM auth_sessions WHERE id = ANY($1)", tr.sessionIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete auth_sessions: %v", err)
		}
	}

	// 5. DELETE FROM auth_identities WHERE id = ANY($1)
	if len(tr.authIdentityIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM auth_identities WHERE id = ANY($1)", tr.authIdentityIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete auth_identities: %v", err)
		}
	}

	// 6. DELETE FROM users WHERE id = ANY($1)
	if len(tr.userIDs) > 0 {
		_, err := tr.pool.Exec(ctx, "DELETE FROM users WHERE id = ANY($1)", tr.userIDs)
		if err != nil {
			t.Errorf("cleanup: failed to delete users: %v", err)
		}
	}
}

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

	if len(tr.membershipIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM organization_memberships WHERE id = ANY($1)", tr.membershipIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d organization_memberships rows still exist", count)
		}
	}

	if len(tr.orgIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM organizations WHERE id = ANY($1)", tr.orgIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d organizations rows still exist", count)
		}
	}

	if len(tr.sessionIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE id = ANY($1)", tr.sessionIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d auth_sessions rows still exist", count)
		}
	}

	if len(tr.authIdentityIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM auth_identities WHERE id = ANY($1)", tr.authIdentityIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d auth_identities rows still exist", count)
		}
	}

	if len(tr.userIDs) > 0 {
		var count int
		_ = tr.pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE id = ANY($1)", tr.userIDs).Scan(&count)
		if count != 0 {
			t.Errorf("cleanup verification failed: %d users rows still exist", count)
		}
	}
}

// setupIntegrationTestDB validates all 10 security guards and initializes an isolated database connection.
func setupIntegrationTestDB(t *testing.T) (*pgxpool.Pool, *config.Config, *testTracker) {
	t.Helper()

	// Guard 1: Require TEST_DATABASE_DIRECT_URL
	testDBURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_DIRECT_URL"))
	if testDBURL == "" {
		t.Fatal("ABORT: TEST_DATABASE_DIRECT_URL environment variable is required for integration tests")
	}

	// Guard 2: Require DB_TARGET_ENV exactly equal to "test"
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
	// Guard 6: Conservative max connection count
	poolCfg.MaxConns = 5
	poolCfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("ABORT: failed to connect to integration test database: %v", err)
	}

	// Guard 7 & 8: Execute SELECT current_database() and require trustdocs_schema_test
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
		Argon2Memory:              16384,
		Argon2Iterations:          1,
		Argon2Parallelism:         1,
		Argon2SaltLength:          16,
		Argon2KeyLength:           32,
		RateLimitLoginAttempts:    100,
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

func canonicalRegistrationNumber(prefix string, nBytes int) string {
	return strings.ToUpper(strings.TrimSpace(prefix + randomHex(nBytes)))
}

func canonicalDomain(prefix string) string {
	return fmt.Sprintf("%s-%s.edu", prefix, randomHex(6))
}

func setupTestRouter(cfg *config.Config, pool *pgxpool.Pool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return router.SetupRouter(cfg, logger, pool)
}

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

type authenticatedSession struct {
	User      db.User
	Cookie    *http.Cookie
	CSRFToken string
	UserAgent string
}

// createAndLoginUser registers, verifies, logs in a user, fetches CSRF token, and returns authenticated session.
func createAndLoginUser(t *testing.T, r *gin.Engine, pool *pgxpool.Pool, cfg *config.Config, tracker *testTracker, isSuperadmin bool) *authenticatedSession {
	t.Helper()
	ctx := context.Background()

	email := fmt.Sprintf("user_%s@example.com", randomHex(8))
	password := "ValidPassword12345!"
	traceID := "trace-" + randomHex(12)

	// 1. Register
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Test User"}`, email, password)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)
	if wReg.Code != http.StatusOK {
		t.Fatalf("registration failed: %d: %s", wReg.Code, wReg.Body.String())
	}

	var user db.User
	err := pool.QueryRow(ctx, "SELECT id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at FROM users WHERE email = $1", email).Scan(
		&user.ID, &user.Email, &user.FullName, &user.IsActive, &user.IsSuperadmin, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		t.Fatalf("failed to query created user: %v", err)
	}
	tracker.TrackUser(user.ID)

	// Capture exact primary key for created auth identity
	var identityID pgtype.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM auth_identities WHERE user_id = $1", user.ID).Scan(&identityID); err != nil {
		t.Fatalf("failed to query created auth identity: %v", err)
	}
	tracker.TrackAuthIdentity(identityID)

	tracker.TrackAuditByTrace(ctx, t, traceID)

	if isSuperadmin {
		_, err = pool.Exec(ctx, "UPDATE users SET is_superadmin = TRUE WHERE id = $1", user.ID)
		if err != nil {
			t.Fatalf("failed to elevate user to superadmin: %v", err)
		}
		user.IsSuperadmin = true
	}

	// 2. Login
	portalCtx := "app"
	if isSuperadmin {
		portalCtx = "admin"
	}
	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"%s"}`, email, password, portalCtx)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", wLogin.Code, wLogin.Body.String())
	}
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// Capture exact primary key for created auth session
	var sessionID pgtype.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM auth_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", user.ID).Scan(&sessionID); err != nil {
		t.Fatalf("failed to query created auth session: %v", err)
	}
	tracker.TrackSession(sessionID)

	cookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)

	// 3. Fetch CSRF token
	reqCSRF, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqCSRF.AddCookie(cookie)
	wCSRF := httptest.NewRecorder()
	r.ServeHTTP(wCSRF, reqCSRF)
	if wCSRF.Code != http.StatusOK {
		t.Fatalf("csrf fetch failed: %d: %s", wCSRF.Code, wCSRF.Body.String())
	}

	var csrfResp struct {
		Data auth.CSRFResponse `json:"data"`
	}
	if err := json.Unmarshal(wCSRF.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("failed to parse CSRF response: %v", err)
	}
	if csrfResp.Data.CSRFToken == "" {
		t.Fatalf("expected non-empty CSRF token")
	}

	return &authenticatedSession{
		User:      user,
		Cookie:    cookie,
		CSRFToken: csrfResp.Data.CSRFToken,
		UserAgent: traceID,
	}
}

func parseUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("failed to parse UUID string %q: %v", s, err)
	}
	return u
}

// ----------------------------------------------------------------------------
// Test 1: Atomic organization onboarding application submission (University & Company)
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationApplication_AtomicCreation(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	// 1. Submit UNIVERSITY application
	applicant := createAndLoginUser(t, r, pool, cfg, tracker, false)
	domainUni := canonicalDomain("uni")
	regNumUni := canonicalRegistrationNumber("REG-UNI-", 6)

	applyPayload := fmt.Sprintf(`{
		"org_type": "UNIVERSITY",
		"legal_name": "Test University Global",
		"country_code": "US",
		"registration_number": "%s",
		"official_domain": "%s"
	}`, regNumUni, domainUni)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(applyPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", cfg.FrontendURL)
	req.Header.Set("X-CSRF-Token", applicant.CSRFToken)
	req.Header.Set("User-Agent", applicant.UserAgent)
	req.AddCookie(applicant.Cookie)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	tracker.TrackAuditByTrace(ctx, t, applicant.UserAgent)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on organization application, got %d: %s", w.Code, w.Body.String())
	}

	var submitResp struct {
		Success bool                                      `json:"success"`
		Data    organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &submitResp); err != nil {
		t.Fatalf("failed to parse submission response: %v", err)
	}

	orgIDUni := parseUUID(t, submitResp.Data.Organization.ID)
	tracker.TrackOrg(orgIDUni)
	memIDUni := parseUUID(t, submitResp.Data.Membership.ID)
	tracker.TrackMembership(memIDUni)

	if submitResp.Data.Organization.VerificationStatus != "PENDING" {
		t.Errorf("expected PENDING status, got %s", submitResp.Data.Organization.VerificationStatus)
	}
	if submitResp.Data.Membership.IsActive != false {
		t.Errorf("expected membership to be inactive (false), got true")
	}
	if submitResp.Data.Membership.Role != "UNIVERSITY_ADMIN" {
		t.Errorf("expected UNIVERSITY_ADMIN role, got %s", submitResp.Data.Membership.Role)
	}

	// Verify database record
	var orgCount, memCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM organizations WHERE id = $1 AND verification_status = 'PENDING'", orgIDUni).Scan(&orgCount)
	if orgCount != 1 {
		t.Errorf("expected 1 PENDING organization in database, found %d", orgCount)
	}

	_ = pool.QueryRow(ctx, "SELECT count(*) FROM organization_memberships WHERE organization_id = $1 AND user_id = $2 AND role = 'UNIVERSITY_ADMIN' AND is_active = FALSE", orgIDUni, applicant.User.ID).Scan(&memCount)
	if memCount != 1 {
		t.Errorf("expected 1 inactive UNIVERSITY_ADMIN membership in database, found %d", memCount)
	}

	// 2. Submit COMPANY application with second user
	applicant2 := createAndLoginUser(t, r, pool, cfg, tracker, false)
	domainCo := canonicalDomain("techco")
	regNumCo := canonicalRegistrationNumber("REG-CO-", 6)

	applyPayloadCo := fmt.Sprintf(`{
		"org_type": "COMPANY",
		"legal_name": "Test Technology Corporation",
		"country_code": "US",
		"registration_number": "%s",
		"official_domain": "%s"
	}`, regNumCo, domainCo)

	reqCo, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(applyPayloadCo))
	reqCo.Header.Set("Content-Type", "application/json")
	reqCo.Header.Set("Origin", cfg.FrontendURL)
	reqCo.Header.Set("X-CSRF-Token", applicant2.CSRFToken)
	reqCo.Header.Set("User-Agent", applicant2.UserAgent)
	reqCo.AddCookie(applicant2.Cookie)

	wCo := httptest.NewRecorder()
	r.ServeHTTP(wCo, reqCo)
	tracker.TrackAuditByTrace(ctx, t, applicant2.UserAgent)

	if wCo.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on company application, got %d: %s", wCo.Code, wCo.Body.String())
	}

	var submitRespCo struct {
		Success bool                                      `json:"success"`
		Data    organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wCo.Body.Bytes(), &submitRespCo); err != nil {
		t.Fatalf("failed to parse company submission response: %v", err)
	}
	orgIDCo := parseUUID(t, submitRespCo.Data.Organization.ID)
	tracker.TrackOrg(orgIDCo)
	memIDCo := parseUUID(t, submitRespCo.Data.Membership.ID)
	tracker.TrackMembership(memIDCo)

	if submitRespCo.Data.Membership.Role != "COMPANY_ADMIN" {
		t.Errorf("expected COMPANY_ADMIN role, got %s", submitRespCo.Data.Membership.Role)
	}
	if submitRespCo.Data.Membership.IsActive != false {
		t.Errorf("expected company admin membership to be inactive")
	}
}

// ----------------------------------------------------------------------------
// Test 2: Conflict handling and transaction rollback
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationApplication_ConflictAndRollback(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	user1 := createAndLoginUser(t, r, pool, cfg, tracker, false)
	user2 := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("conflict-test")
	regNum := canonicalRegistrationNumber("CONF-REG-", 6)

	// First application succeeds
	body1 := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"Original Org","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	req1, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Origin", cfg.FrontendURL)
	req1.Header.Set("X-CSRF-Token", user1.CSRFToken)
	req1.Header.Set("User-Agent", user1.UserAgent)
	req1.AddCookie(user1.Cookie)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	tracker.TrackAuditByTrace(ctx, t, user1.UserAgent)

	if w1.Code != http.StatusCreated {
		t.Fatalf("first application failed: %d: %s", w1.Code, w1.Body.String())
	}
	var res1 struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, res1.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, res1.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// Second application with identical domain by user2 must return 409 ORGANIZATION_ALREADY_EXISTS
	body2 := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"Duplicate Domain Org","country_code":"US","registration_number":"%s","official_domain":"%s"}`, canonicalRegistrationNumber("DIFF-REG-", 6), domain)
	req2, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", cfg.FrontendURL)
	req2.Header.Set("X-CSRF-Token", user2.CSRFToken)
	req2.Header.Set("User-Agent", user2.UserAgent)
	req2.AddCookie(user2.Cookie)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	tracker.TrackAuditByTrace(ctx, t, user2.UserAgent)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on duplicate domain, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "ORGANIZATION_ALREADY_EXISTS") {
		t.Errorf("expected ORGANIZATION_ALREADY_EXISTS code, got: %s", w2.Body.String())
	}
	// Verify user1's identity is not revealed
	if strings.Contains(w2.Body.String(), user1.User.Email) || strings.Contains(w2.Body.String(), "Original Org") {
		t.Errorf("error response leaked previous applicant data")
	}

	// Verify no partial membership was created for user2
	var user2Memberships int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM organization_memberships WHERE user_id = $1", user2.User.ID).Scan(&user2Memberships)
	if user2Memberships != 0 {
		t.Errorf("failed transaction left orphan membership for user2: count=%d", user2Memberships)
	}
}

// ----------------------------------------------------------------------------
// Test 3: /mine includes inactive pending application & decision reason on rejection
// ----------------------------------------------------------------------------
func TestIntegration_Mine_IncludesInactivePendingApplication(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	user := createAndLoginUser(t, r, pool, cfg, tracker, false)
	domain := canonicalDomain("mine-test")
	regNum := canonicalRegistrationNumber("MINE-REG-", 6)

	// Apply
	body := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"My Pending University","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	reqApply, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	reqApply.Header.Set("Content-Type", "application/json")
	reqApply.Header.Set("Origin", cfg.FrontendURL)
	reqApply.Header.Set("X-CSRF-Token", user.CSRFToken)
	reqApply.Header.Set("User-Agent", user.UserAgent)
	reqApply.AddCookie(user.Cookie)
	wApply := httptest.NewRecorder()
	r.ServeHTTP(wApply, reqApply)
	tracker.TrackAuditByTrace(ctx, t, user.UserAgent)

	var resApply struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wApply.Body.Bytes(), &resApply); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, resApply.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, resApply.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// Call GET /api/v1/organizations/mine
	reqMine, _ := http.NewRequest(http.MethodGet, "/api/v1/organizations/mine", nil)
	reqMine.AddCookie(user.Cookie)
	wMine := httptest.NewRecorder()
	r.ServeHTTP(wMine, reqMine)

	if wMine.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /mine, got %d: %s", wMine.Code, wMine.Body.String())
	}

	var mineResp struct {
		Success bool                                   `json:"success"`
		Data    []organizations.MyOrganizationResponse `json:"data"`
	}
	if err := json.Unmarshal(wMine.Body.Bytes(), &mineResp); err != nil {
		t.Fatalf("failed to parse /mine response: %v", err)
	}

	if len(mineResp.Data) == 0 {
		t.Fatalf("expected at least 1 organization in /mine, got 0")
	}

	found := false
	for _, o := range mineResp.Data {
		if o.ID == resApply.Data.Organization.ID {
			found = true
			if o.VerificationStatus != "PENDING" {
				t.Errorf("expected PENDING, got %s", o.VerificationStatus)
			}
			if o.MyIsActive != false {
				t.Errorf("expected my_is_active to be false")
			}
			if o.DecisionReason != nil {
				t.Errorf("decision_reason must be nil for PENDING application")
			}
		}
	}
	if !found {
		t.Errorf("created organization not found in /mine response")
	}
}

// ----------------------------------------------------------------------------
// Test 4: Admin application listing, dossier query, and privacy projections
// ----------------------------------------------------------------------------
func TestIntegration_AdminApplicationDossier(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)
	applicant := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("dossier-test")
	regNum := canonicalRegistrationNumber("DOS-REG-", 6)

	// Applicant submits
	body := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"Dossier University","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	reqApply, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	reqApply.Header.Set("Content-Type", "application/json")
	reqApply.Header.Set("Origin", cfg.FrontendURL)
	reqApply.Header.Set("X-CSRF-Token", applicant.CSRFToken)
	reqApply.Header.Set("User-Agent", applicant.UserAgent)
	reqApply.AddCookie(applicant.Cookie)
	wApply := httptest.NewRecorder()
	r.ServeHTTP(wApply, reqApply)
	tracker.TrackAuditByTrace(ctx, t, applicant.UserAgent)

	var resApply struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wApply.Body.Bytes(), &resApply); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, resApply.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, resApply.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// 1. Superadmin lists applications via GET /api/v1/admin/organizations
	reqList, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/organizations", nil)
	reqList.AddCookie(admin.Cookie)
	wList := httptest.NewRecorder()
	r.ServeHTTP(wList, reqList)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/admin/organizations, got %d: %s", wList.Code, wList.Body.String())
	}

	var listResp struct {
		Success bool                                 `json:"success"`
		Data    []organizations.AdminDossierResponse `json:"data"`
	}
	if err := json.Unmarshal(wList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode admin applications list: %v", err)
	}
	if len(listResp.Data) == 0 {
		t.Fatalf("expected at least 1 application in admin list, got 0")
	}

	// 2. Superadmin requests exact dossier via GET /api/v1/admin/organizations/:organization_id
	reqDos, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID, nil)
	reqDos.AddCookie(admin.Cookie)
	wDos := httptest.NewRecorder()
	r.ServeHTTP(wDos, reqDos)

	if wDos.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from admin dossier, got %d: %s", wDos.Code, wDos.Body.String())
	}

	var dosResp struct {
		Success bool                               `json:"success"`
		Data    organizations.AdminDossierResponse `json:"data"`
	}
	if err := json.Unmarshal(wDos.Body.Bytes(), &dosResp); err != nil {
		t.Fatalf("failed to parse admin dossier: %v", err)
	}

	if dosResp.Data.Applicant.Email != applicant.User.Email {
		t.Errorf("expected applicant email %s, got %s", applicant.User.Email, dosResp.Data.Applicant.Email)
	}
	if dosResp.Data.Applicant.Role != "UNIVERSITY_ADMIN" {
		t.Errorf("expected role UNIVERSITY_ADMIN, got %s", dosResp.Data.Applicant.Role)
	}

	// Assert sensitive security hashes are completely absent
	bodyStr := wDos.Body.String()
	if strings.Contains(bodyStr, "credential_hash") || strings.Contains(bodyStr, "token_hash") {
		t.Errorf("dossier exposed credential or session hashes!")
	}

	// 3. Regular non-admin user receives 403 on GET /api/v1/admin/organizations
	reqListForbidden, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/organizations", nil)
	reqListForbidden.AddCookie(applicant.Cookie)
	wListForbidden := httptest.NewRecorder()
	r.ServeHTTP(wListForbidden, reqListForbidden)
	if wListForbidden.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-admin on admin applications list, got %d", wListForbidden.Code)
	}

	// 4. Regular non-admin user receives 403 on GET /api/v1/admin/organizations/:organization_id
	reqDosForbidden, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID, nil)
	reqDosForbidden.AddCookie(applicant.Cookie)
	wDosForbidden := httptest.NewRecorder()
	r.ServeHTTP(wDosForbidden, reqDosForbidden)
	if wDosForbidden.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-admin on admin dossier, got %d", wDosForbidden.Code)
	}

	// 5. Missing organization returns 404 ORGANIZATION_NOT_FOUND
	reqMissing, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/organizations/00000000-0000-0000-0000-000000000000", nil)
	reqMissing.AddCookie(admin.Cookie)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing organization, got %d", wMissing.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 5: In-transaction row locking prevents concurrent review races
// ----------------------------------------------------------------------------
func TestIntegration_OrgReview_InTransactionLocking(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin1 := createAndLoginUser(t, r, pool, cfg, tracker, true)
	admin2 := createAndLoginUser(t, r, pool, cfg, tracker, true)
	applicant := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("lock-race-test")
	regNum := canonicalRegistrationNumber("LOCK-REG-", 6)

	// Submit application
	body := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"Concurrent Review Uni","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	reqApply, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	reqApply.Header.Set("Content-Type", "application/json")
	reqApply.Header.Set("Origin", cfg.FrontendURL)
	reqApply.Header.Set("X-CSRF-Token", applicant.CSRFToken)
	reqApply.Header.Set("User-Agent", applicant.UserAgent)
	reqApply.AddCookie(applicant.Cookie)
	wApply := httptest.NewRecorder()
	r.ServeHTTP(wApply, reqApply)
	tracker.TrackAuditByTrace(ctx, t, applicant.UserAgent)

	var resApply struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wApply.Body.Bytes(), &resApply); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, resApply.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, resApply.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// Concurrently attempt review from two superadmins
	type result struct {
		code int
		body string
	}
	resChan := make(chan result, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		reqApprove, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/approve", bytes.NewBufferString(`{"reason":"Reviewed"}`))
		reqApprove.Header.Set("Content-Type", "application/json")
		reqApprove.Header.Set("Origin", cfg.FrontendURL)
		reqApprove.Header.Set("X-CSRF-Token", admin1.CSRFToken)
		reqApprove.Header.Set("User-Agent", admin1.UserAgent)
		reqApprove.AddCookie(admin1.Cookie)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, reqApprove)
		resChan <- result{code: w.Code, body: w.Body.String()}
	}()

	go func() {
		defer wg.Done()
		reqReject, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/reject", bytes.NewBufferString(`{"decision_reason":"Denied due to review","reason_code":"INELIGIBLE_ORGANIZATION"}`))
		reqReject.Header.Set("Content-Type", "application/json")
		reqReject.Header.Set("Origin", cfg.FrontendURL)
		reqReject.Header.Set("X-CSRF-Token", admin2.CSRFToken)
		reqReject.Header.Set("User-Agent", admin2.UserAgent)
		reqReject.AddCookie(admin2.Cookie)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, reqReject)
		resChan <- result{code: w.Code, body: w.Body.String()}
	}()

	wg.Wait()
	close(resChan)

	tracker.TrackAuditByTrace(ctx, t, admin1.UserAgent)
	tracker.TrackAuditByTrace(ctx, t, admin2.UserAgent)

	var successCount, conflictCount int
	for res := range resChan {
		if res.code == http.StatusOK {
			successCount++
		} else if res.code == http.StatusConflict {
			conflictCount++
			if !strings.Contains(res.body, "ORGANIZATION_NOT_PENDING") {
				t.Errorf("expected ORGANIZATION_NOT_PENDING error on concurrent conflict, got: %s", res.body)
			}
		} else {
			t.Errorf("unexpected status code in race test: %d: %s", res.code, res.body)
		}
	}

	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("expected exactly 1 success (200) and 1 conflict (409), got %d successes and %d conflicts", successCount, conflictCount)
	}
}

// ----------------------------------------------------------------------------
// Test 6: Approval activates only exact applicant membership
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationApproval_ActivatesExactMembership(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)
	applicant := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("approve-test")
	regNum := canonicalRegistrationNumber("APP-REG-", 6)

	// Apply
	body := fmt.Sprintf(`{"org_type":"UNIVERSITY","legal_name":"Approval Uni","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	reqApply, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	reqApply.Header.Set("Content-Type", "application/json")
	reqApply.Header.Set("Origin", cfg.FrontendURL)
	reqApply.Header.Set("X-CSRF-Token", applicant.CSRFToken)
	reqApply.Header.Set("User-Agent", applicant.UserAgent)
	reqApply.AddCookie(applicant.Cookie)
	wApply := httptest.NewRecorder()
	r.ServeHTTP(wApply, reqApply)
	tracker.TrackAuditByTrace(ctx, t, applicant.UserAgent)

	var resApply struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wApply.Body.Bytes(), &resApply); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, resApply.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, resApply.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// Create secondary unrelated pending organization with inactive membership to verify isolation
	unrelatedApplicant := createAndLoginUser(t, r, pool, cfg, tracker, false)
	domainUnrelated := canonicalDomain("unrelated-test")
	regNumUnrelated := canonicalRegistrationNumber("UNREL-REG-", 6)
	var unrelatedOrgID pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status) VALUES ('UNIVERSITY', 'Unrelated Org', 'US', $1, $2, 'PENDING') RETURNING id", regNumUnrelated, domainUnrelated).Scan(&unrelatedOrgID)
	if err != nil {
		t.Fatalf("failed to insert unrelated org: %v", err)
	}
	tracker.TrackOrg(unrelatedOrgID)

	var unrelatedMemID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ADMIN', FALSE) RETURNING id", unrelatedOrgID, unrelatedApplicant.User.ID).Scan(&unrelatedMemID)
	if err != nil {
		t.Fatalf("failed to insert unrelated membership: %v", err)
	}
	tracker.TrackMembership(unrelatedMemID)

	// Approve target organization
	reqApprove, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/approve", bytes.NewBufferString(`{"reason":"Accredited"}`))
	reqApprove.Header.Set("Content-Type", "application/json")
	reqApprove.Header.Set("Origin", cfg.FrontendURL)
	reqApprove.Header.Set("X-CSRF-Token", admin.CSRFToken)
	reqApprove.Header.Set("User-Agent", admin.UserAgent)
	reqApprove.AddCookie(admin.Cookie)
	wApprove := httptest.NewRecorder()
	r.ServeHTTP(wApprove, reqApprove)
	tracker.TrackAuditByTrace(ctx, t, admin.UserAgent)

	if wApprove.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from approve, got %d: %s", wApprove.Code, wApprove.Body.String())
	}

	// Verify database state: status = VERIFIED, is_active = TRUE
	var status string
	var reviewerID pgtype.UUID
	_ = pool.QueryRow(ctx, "SELECT verification_status, reviewed_by_user_id FROM organizations WHERE id = $1", orgID).Scan(&status, &reviewerID)
	if status != "VERIFIED" {
		t.Errorf("expected VERIFIED, got %s", status)
	}
	if reviewerID != admin.User.ID {
		t.Errorf("expected reviewer_id %v, got %v", admin.User.ID, reviewerID)
	}

	var isActive bool
	_ = pool.QueryRow(ctx, "SELECT is_active FROM organization_memberships WHERE id = $1", memID).Scan(&isActive)
	if !isActive {
		t.Errorf("expected target membership to be active (true)")
	}

	// Verify unrelated membership remains inactive
	var unrelatedIsActive bool
	_ = pool.QueryRow(ctx, "SELECT is_active FROM organization_memberships WHERE id = $1", unrelatedMemID).Scan(&unrelatedIsActive)
	if unrelatedIsActive {
		t.Errorf("unrelated membership must remain inactive (false)!")
	}
}

// ----------------------------------------------------------------------------
// Test 7: Rejection leaves membership inactive, records reason_code in audit
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationRejection(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)
	applicant := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("reject-test")
	regNum := canonicalRegistrationNumber("REJ-REG-", 6)

	// Apply
	body := fmt.Sprintf(`{"org_type":"COMPANY","legal_name":"Rejection Co","country_code":"US","registration_number":"%s","official_domain":"%s"}`, regNum, domain)
	reqApply, _ := http.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewBufferString(body))
	reqApply.Header.Set("Content-Type", "application/json")
	reqApply.Header.Set("Origin", cfg.FrontendURL)
	reqApply.Header.Set("X-CSRF-Token", applicant.CSRFToken)
	reqApply.Header.Set("User-Agent", applicant.UserAgent)
	reqApply.AddCookie(applicant.Cookie)
	wApply := httptest.NewRecorder()
	r.ServeHTTP(wApply, reqApply)
	tracker.TrackAuditByTrace(ctx, t, applicant.UserAgent)

	var resApply struct {
		Data organizations.ApplicantSubmissionResponse `json:"data"`
	}
	if err := json.Unmarshal(wApply.Body.Bytes(), &resApply); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	orgID := parseUUID(t, resApply.Data.Organization.ID)
	tracker.TrackOrg(orgID)
	memID := parseUUID(t, resApply.Data.Membership.ID)
	tracker.TrackMembership(memID)

	// 1. Invalid reason_code returns 400 Bad Request
	reqInvalidCode, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/reject", bytes.NewBufferString(`{"decision_reason":"Valid reason here.","reason_code":"UNKNOWN_CODE"}`))
	reqInvalidCode.Header.Set("Content-Type", "application/json")
	reqInvalidCode.Header.Set("Origin", cfg.FrontendURL)
	reqInvalidCode.Header.Set("X-CSRF-Token", admin.CSRFToken)
	reqInvalidCode.Header.Set("User-Agent", admin.UserAgent)
	reqInvalidCode.AddCookie(admin.Cookie)
	wInvalidCode := httptest.NewRecorder()
	r.ServeHTTP(wInvalidCode, reqInvalidCode)
	if wInvalidCode.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid reason_code, got %d", wInvalidCode.Code)
	}

	// 2. Empty decision_reason returns 400 Bad Request
	reqEmptyReason, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/reject", bytes.NewBufferString(`{"decision_reason":"","reason_code":"REGISTRATION_NOT_VERIFIED"}`))
	reqEmptyReason.Header.Set("Content-Type", "application/json")
	reqEmptyReason.Header.Set("Origin", cfg.FrontendURL)
	reqEmptyReason.Header.Set("X-CSRF-Token", admin.CSRFToken)
	reqEmptyReason.Header.Set("User-Agent", admin.UserAgent)
	reqEmptyReason.AddCookie(admin.Cookie)
	wEmptyReason := httptest.NewRecorder()
	r.ServeHTTP(wEmptyReason, reqEmptyReason)
	if wEmptyReason.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for empty decision_reason, got %d", wEmptyReason.Code)
	}

	// 3. Reject with valid payload
	rejectBody := `{"decision_reason":"Business entity could not be verified in state corporate database.","reason_code":"REGISTRATION_NOT_VERIFIED"}`
	reqReject, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/reject", bytes.NewBufferString(rejectBody))
	reqReject.Header.Set("Content-Type", "application/json")
	reqReject.Header.Set("Origin", cfg.FrontendURL)
	reqReject.Header.Set("X-CSRF-Token", admin.CSRFToken)
	reqReject.Header.Set("User-Agent", admin.UserAgent)
	reqReject.AddCookie(admin.Cookie)
	wReject := httptest.NewRecorder()
	r.ServeHTTP(wReject, reqReject)
	tracker.TrackAuditByTrace(ctx, t, admin.UserAgent)

	if wReject.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from reject, got %d: %s", wReject.Code, wReject.Body.String())
	}

	// Verify database: status = REJECTED, is_active = FALSE
	var status, decisionReason string
	_ = pool.QueryRow(ctx, "SELECT verification_status, decision_reason FROM organizations WHERE id = $1", orgID).Scan(&status, &decisionReason)
	if status != "REJECTED" {
		t.Errorf("expected REJECTED, got %s", status)
	}
	if !strings.Contains(decisionReason, "Business entity could not be verified") {
		t.Errorf("expected decision reason in organization, got %s", decisionReason)
	}

	var isActive bool
	_ = pool.QueryRow(ctx, "SELECT is_active FROM organization_memberships WHERE id = $1", memID).Scan(&isActive)
	if isActive {
		t.Errorf("expected membership to remain inactive (false) upon rejection")
	}

	// Verify audit payload contains reason_code and NOT free-text reason
	var auditPayload []byte
	err := pool.QueryRow(ctx, "SELECT payload FROM audit_logs WHERE target_organization_id = $1 AND action = 'ORGANIZATION_REJECTED'", orgID).Scan(&auditPayload)
	if err != nil {
		t.Fatalf("failed to query rejection audit log: %v", err)
	}

	var pMap map[string]interface{}
	_ = json.Unmarshal(auditPayload, &pMap)
	if pMap["reason_code"] != "REGISTRATION_NOT_VERIFIED" {
		t.Errorf("expected reason_code REGISTRATION_NOT_VERIFIED in audit, got %v", pMap["reason_code"])
	}
	if _, exists := pMap["decision_reason"]; exists {
		t.Errorf("free-text decision_reason must NEVER enter audit JSON")
	}

	// 4. Repeated reject returns 409 ORGANIZATION_NOT_PENDING
	reqReject2, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/organizations/"+resApply.Data.Organization.ID+"/reject", bytes.NewBufferString(rejectBody))
	reqReject2.Header.Set("Content-Type", "application/json")
	reqReject2.Header.Set("Origin", cfg.FrontendURL)
	reqReject2.Header.Set("X-CSRF-Token", admin.CSRFToken)
	reqReject2.Header.Set("User-Agent", admin.UserAgent)
	reqReject2.AddCookie(admin.Cookie)
	wReject2 := httptest.NewRecorder()
	r.ServeHTTP(wReject2, reqReject2)
	if wReject2.Code != http.StatusConflict {
		t.Errorf("expected 409 on second reject, got %d", wReject2.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 8: Superadmin self-review prohibited
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationSelfReviewProhibited(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	superUser := createAndLoginUser(t, r, pool, cfg, tracker, true)

	domain := canonicalDomain("self-test")
	regNum := canonicalRegistrationNumber("SELF-REG-", 6)

	// Create controlled fixture directly in DB where applicant is superUser
	var orgID pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status) VALUES ('UNIVERSITY', 'Self Uni', 'US', $1, $2, 'PENDING') RETURNING id", regNum, domain).Scan(&orgID)
	if err != nil {
		t.Fatalf("failed to insert fixture org: %v", err)
	}
	tracker.TrackOrg(orgID)

	var memID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ADMIN', FALSE) RETURNING id", orgID, superUser.User.ID).Scan(&memID)
	if err != nil {
		t.Fatalf("failed to insert fixture membership: %v", err)
	}
	tracker.TrackMembership(memID)

	// 1. Attempt approval by self -> 403 ORGANIZATION_SELF_REVIEW_PROHIBITED
	reqApprove, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/admin/organizations/%s/approve", orgID.String()), bytes.NewBufferString(`{"reason":"Approve myself"}`))
	reqApprove.Header.Set("Content-Type", "application/json")
	reqApprove.Header.Set("Origin", cfg.FrontendURL)
	reqApprove.Header.Set("X-CSRF-Token", superUser.CSRFToken)
	reqApprove.Header.Set("User-Agent", superUser.UserAgent)
	reqApprove.AddCookie(superUser.Cookie)
	wApprove := httptest.NewRecorder()
	r.ServeHTTP(wApprove, reqApprove)

	if wApprove.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on self-review approve, got %d: %s", wApprove.Code, wApprove.Body.String())
	}
	if !strings.Contains(wApprove.Body.String(), "ORGANIZATION_SELF_REVIEW_PROHIBITED") {
		t.Errorf("expected ORGANIZATION_SELF_REVIEW_PROHIBITED error, got: %s", wApprove.Body.String())
	}

	// 2. Attempt rejection by self -> 403 ORGANIZATION_SELF_REVIEW_PROHIBITED
	reqReject, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/admin/organizations/%s/reject", orgID.String()), bytes.NewBufferString(`{"decision_reason":"Reject myself","reason_code":"INELIGIBLE_ORGANIZATION"}`))
	reqReject.Header.Set("Content-Type", "application/json")
	reqReject.Header.Set("Origin", cfg.FrontendURL)
	reqReject.Header.Set("X-CSRF-Token", superUser.CSRFToken)
	reqReject.Header.Set("User-Agent", superUser.UserAgent)
	reqReject.AddCookie(superUser.Cookie)
	wReject := httptest.NewRecorder()
	r.ServeHTTP(wReject, reqReject)

	if wReject.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on self-review reject, got %d: %s", wReject.Code, wReject.Body.String())
	}
	if !strings.Contains(wReject.Body.String(), "ORGANIZATION_SELF_REVIEW_PROHIBITED") {
		t.Errorf("expected ORGANIZATION_SELF_REVIEW_PROHIBITED error, got: %s", wReject.Body.String())
	}

	// Verify organization remains PENDING
	var status string
	_ = pool.QueryRow(ctx, "SELECT verification_status FROM organizations WHERE id = $1", orgID).Scan(&status)
	if status != "PENDING" {
		t.Errorf("organization must remain PENDING after self-review attempt, got %s", status)
	}

	// Verify membership remains inactive
	var isActive bool
	_ = pool.QueryRow(ctx, "SELECT is_active FROM organization_memberships WHERE id = $1", memID).Scan(&isActive)
	if isActive {
		t.Errorf("membership must remain inactive (false) after self-review attempt")
	}

	// Verify no approval/rejection audit record was added
	var auditCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE target_organization_id = $1", orgID).Scan(&auditCount)
	if auditCount != 0 {
		t.Errorf("expected 0 audit logs for self-review attempt, found %d", auditCount)
	}
}

// ----------------------------------------------------------------------------
// Test 9: Tenant operations strictly require VERIFIED status
// ----------------------------------------------------------------------------
func TestIntegration_TenantOperations_RequireVerified(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	user := createAndLoginUser(t, r, pool, cfg, tracker, false)
	domain := canonicalDomain("tenant-ops-test")
	regNum := canonicalRegistrationNumber("TEN-REG-", 6)

	// 1. Create fixture org in PENDING status with membership
	var orgID pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status) VALUES ('UNIVERSITY', 'Pending Tenant Uni', 'US', $1, $2, 'PENDING') RETURNING id", regNum, domain).Scan(&orgID)
	if err != nil {
		t.Fatalf("failed to insert org fixture: %v", err)
	}
	tracker.TrackOrg(orgID)

	var memID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ADMIN', TRUE) RETURNING id", orgID, user.User.ID).Scan(&memID)
	if err != nil {
		t.Fatalf("failed to insert membership: %v", err)
	}
	tracker.TrackMembership(memID)

	// Attempt tenant profile GET -> must return 403 ORGANIZATION_NOT_ACTIVE
	reqProfile, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), nil)
	reqProfile.AddCookie(user.Cookie)
	wProfile := httptest.NewRecorder()
	r.ServeHTTP(wProfile, reqProfile)

	if wProfile.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tenant profile on unverified org, got %d: %s", wProfile.Code, wProfile.Body.String())
	}
	if !strings.Contains(wProfile.Body.String(), "ORGANIZATION_NOT_ACTIVE") {
		t.Errorf("expected code ORGANIZATION_NOT_ACTIVE, got: %s", wProfile.Body.String())
	}

	// 2. Missing/non-existent organization returns non-leaking 403 FORBIDDEN
	reqMissing, _ := http.NewRequest(http.MethodGet, "/api/v1/organizations/00000000-0000-0000-0000-000000000000", nil)
	reqMissing.AddCookie(user.Cookie)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusForbidden {
		t.Errorf("expected non-leaking 403 for missing organization, got %d", wMissing.Code)
	}

	// 3. Transition org to VERIFIED with reviewer
	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)
	_, err = pool.Exec(ctx, "UPDATE organizations SET verification_status = 'VERIFIED', reviewed_by_user_id = $1, reviewed_at = NOW() WHERE id = $2", admin.User.ID, orgID)
	if err != nil {
		t.Fatalf("failed to update org to VERIFIED: %v", err)
	}

	// Fresh tenant profile GET on VERIFIED org with active membership -> 200 OK
	reqProfile2, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), nil)
	reqProfile2.AddCookie(user.Cookie)
	wProfile2 := httptest.NewRecorder()
	r.ServeHTTP(wProfile2, reqProfile2)
	if wProfile2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant profile on VERIFIED org, got %d: %s", wProfile2.Code, wProfile2.Body.String())
	}

	// 4. Inactive membership on VERIFIED org returns 403 FORBIDDEN
	_, err = pool.Exec(ctx, "UPDATE organization_memberships SET is_active = FALSE WHERE id = $1", memID)
	if err != nil {
		t.Fatalf("failed to set membership inactive: %v", err)
	}
	reqProfile3, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), nil)
	reqProfile3.AddCookie(user.Cookie)
	wProfile3 := httptest.NewRecorder()
	r.ServeHTTP(wProfile3, reqProfile3)
	if wProfile3.Code != http.StatusForbidden {
		t.Errorf("expected 403 for inactive member, got %d", wProfile3.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 10: Verified profile update allows trade_name only
// ----------------------------------------------------------------------------
func TestIntegration_VerifiedProfileUpdate(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)
	user := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("profile-update-test")
	regNum := canonicalRegistrationNumber("PROF-REG-", 6)

	// Create VERIFIED organization with active admin membership
	var orgID pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at) VALUES ('UNIVERSITY', 'Verified University', 'US', $1, $2, 'VERIFIED', $3, NOW()) RETURNING id", regNum, domain, admin.User.ID).Scan(&orgID)
	if err != nil {
		t.Fatalf("failed to insert verified org fixture: %v", err)
	}
	tracker.TrackOrg(orgID)

	var memID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ADMIN', TRUE) RETURNING id", orgID, user.User.ID).Scan(&memID)
	if err != nil {
		t.Fatalf("failed to insert membership: %v", err)
	}
	tracker.TrackMembership(memID)

	// 1. Update trade_name successfully
	patchBody := `{"trade_name":"New Brand Trade Name"}`
	reqPatch, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), bytes.NewBufferString(patchBody))
	reqPatch.Header.Set("Content-Type", "application/json")
	reqPatch.Header.Set("Origin", cfg.FrontendURL)
	reqPatch.Header.Set("X-CSRF-Token", user.CSRFToken)
	reqPatch.Header.Set("User-Agent", user.UserAgent)
	reqPatch.AddCookie(user.Cookie)

	wPatch := httptest.NewRecorder()
	r.ServeHTTP(wPatch, reqPatch)
	tracker.TrackAuditByTrace(ctx, t, user.UserAgent)

	if wPatch.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from profile update, got %d: %s", wPatch.Code, wPatch.Body.String())
	}

	var tradeName string
	_ = pool.QueryRow(ctx, "SELECT coalesce(trade_name, '') FROM organizations WHERE id = $1", orgID).Scan(&tradeName)
	if tradeName != "New Brand Trade Name" {
		t.Errorf("expected trade_name 'New Brand Trade Name', got '%s'", tradeName)
	}

	// 2. Verify immutable fields cannot be updated
	patchImmutable := `{"trade_name":"Second Brand","official_domain":"malicious.edu","legal_name":"Hacked Name"}`
	reqImmutable, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), bytes.NewBufferString(patchImmutable))
	reqImmutable.Header.Set("Content-Type", "application/json")
	reqImmutable.Header.Set("Origin", cfg.FrontendURL)
	reqImmutable.Header.Set("X-CSRF-Token", user.CSRFToken)
	reqImmutable.Header.Set("User-Agent", user.UserAgent)
	reqImmutable.AddCookie(user.Cookie)

	wImmutable := httptest.NewRecorder()
	r.ServeHTTP(wImmutable, reqImmutable)
	tracker.TrackAuditByTrace(ctx, t, user.UserAgent)

	if wImmutable.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from partial update, got %d", wImmutable.Code)
	}

	var currentLegalName, currentDomain string
	_ = pool.QueryRow(ctx, "SELECT legal_name, official_domain FROM organizations WHERE id = $1", orgID).Scan(&currentLegalName, &currentDomain)
	if currentLegalName != "Verified University" {
		t.Errorf("immutable legal_name was modified: %s", currentLegalName)
	}
	if currentDomain != domain {
		t.Errorf("immutable official_domain was modified: %s", currentDomain)
	}

	// 3. Cross-organization access is forbidden
	unrelatedUser := createAndLoginUser(t, r, pool, cfg, tracker, false)
	reqCross, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/organizations/%s", orgID.String()), bytes.NewBufferString(`{"trade_name":"Cross Org Attack"}`))
	reqCross.Header.Set("Content-Type", "application/json")
	reqCross.Header.Set("Origin", cfg.FrontendURL)
	reqCross.Header.Set("X-CSRF-Token", unrelatedUser.CSRFToken)
	reqCross.Header.Set("User-Agent", unrelatedUser.UserAgent)
	reqCross.AddCookie(unrelatedUser.Cookie)
	wCross := httptest.NewRecorder()
	r.ServeHTTP(wCross, reqCross)

	if wCross.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on cross-org update, got %d", wCross.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 11: Member listing scope, pagination, and no-store headers
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationMemberListing(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	adminReviewer := createAndLoginUser(t, r, pool, cfg, tracker, true)
	orgAdmin := createAndLoginUser(t, r, pool, cfg, tracker, false)

	domain := canonicalDomain("members-list-test")
	regNum := canonicalRegistrationNumber("MEM-REG-", 6)

	// Create verified organization
	var orgID pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at) VALUES ('UNIVERSITY', 'Members Test Uni', 'US', $1, $2, 'VERIFIED', $3, NOW()) RETURNING id", regNum, domain, adminReviewer.User.ID).Scan(&orgID)
	if err != nil {
		t.Fatalf("failed to insert org: %v", err)
	}
	tracker.TrackOrg(orgID)

	var memAdminID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ADMIN', TRUE) RETURNING id", orgID, orgAdmin.User.ID).Scan(&memAdminID)
	if err != nil {
		t.Fatalf("failed to insert admin membership: %v", err)
	}
	tracker.TrackMembership(memAdminID)

	// Add second member (issuer)
	staffUser := createAndLoginUser(t, r, pool, cfg, tracker, false)
	var memStaffID pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organization_memberships (organization_id, user_id, role, is_active) VALUES ($1, $2, 'UNIVERSITY_ISSUER', TRUE) RETURNING id", orgID, staffUser.User.ID).Scan(&memStaffID)
	if err != nil {
		t.Fatalf("failed to insert issuer membership: %v", err)
	}
	tracker.TrackMembership(memStaffID)

	// 1. Request members list as verified org admin
	reqMembers, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s/members", orgID.String()), nil)
	reqMembers.AddCookie(orgAdmin.Cookie)
	wMembers := httptest.NewRecorder()
	r.ServeHTTP(wMembers, reqMembers)

	if wMembers.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from members list, got %d: %s", wMembers.Code, wMembers.Body.String())
	}

	// Assert Cache-Control: no-store and Pragma: no-cache
	if wMembers.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %s", wMembers.Header().Get("Cache-Control"))
	}
	if wMembers.Header().Get("Pragma") != "no-cache" {
		t.Errorf("expected Pragma: no-cache, got %s", wMembers.Header().Get("Pragma"))
	}

	var mResp struct {
		Success bool                           `json:"success"`
		Data    []organizations.MemberResponse `json:"data"`
	}
	if err := json.Unmarshal(wMembers.Body.Bytes(), &mResp); err != nil {
		t.Fatalf("failed to decode members response: %v", err)
	}
	if len(mResp.Data) != 2 {
		t.Fatalf("expected 2 members in list, got %d", len(mResp.Data))
	}

	// 2. Filter by allowlisted role
	reqRoleFilter, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s/members?role=UNIVERSITY_ISSUER", orgID.String()), nil)
	reqRoleFilter.AddCookie(orgAdmin.Cookie)
	wRoleFilter := httptest.NewRecorder()
	r.ServeHTTP(wRoleFilter, reqRoleFilter)
	if wRoleFilter.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with role filter, got %d", wRoleFilter.Code)
	}

	var mRoleResp struct {
		Success bool                           `json:"success"`
		Data    []organizations.MemberResponse `json:"data"`
	}
	if err := json.Unmarshal(wRoleFilter.Body.Bytes(), &mRoleResp); err != nil {
		t.Fatalf("failed to decode role-filtered members response: %v", err)
	}
	if len(mRoleResp.Data) != 1 {
		t.Errorf("expected 1 member with UNIVERSITY_ISSUER role, got %d", len(mRoleResp.Data))
	} else if mRoleResp.Data[0].Role != "UNIVERSITY_ISSUER" {
		t.Errorf("expected role UNIVERSITY_ISSUER, got %s", mRoleResp.Data[0].Role)
	}

	// 3. Invalid role filter returns 400 Bad Request
	reqInvalidRole, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s/members?role=INVALID_ROLE", orgID.String()), nil)
	reqInvalidRole.AddCookie(orgAdmin.Cookie)
	wInvalidRole := httptest.NewRecorder()
	r.ServeHTTP(wInvalidRole, reqInvalidRole)
	if wInvalidRole.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid role filter, got %d", wInvalidRole.Code)
	}

	// 4. Cross-organization access is forbidden
	unrelatedUser := createAndLoginUser(t, r, pool, cfg, tracker, false)
	reqCross, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/organizations/%s/members", orgID.String()), nil)
	reqCross.AddCookie(unrelatedUser.Cookie)
	wCross := httptest.NewRecorder()
	r.ServeHTTP(wCross, reqCross)
	if wCross.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for cross-org member listing, got %d", wCross.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 12: Public directory discovery strictly exposes safe verified fields & tests rate limiting
// ----------------------------------------------------------------------------
func TestIntegration_PublicVerifiedOrganizationDiscovery(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	admin := createAndLoginUser(t, r, pool, cfg, tracker, true)

	// 1. Insert VERIFIED organization
	domainV := canonicalDomain("public-verified-test")
	regNumV := canonicalRegistrationNumber("PUB-VER-", 6)
	var orgIDVerified pgtype.UUID
	err := pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at) VALUES ('UNIVERSITY', 'Public Verified Uni', 'US', $1, $2, 'VERIFIED', $3, NOW()) RETURNING id", regNumV, domainV, admin.User.ID).Scan(&orgIDVerified)
	if err != nil {
		t.Fatalf("failed to insert verified org: %v", err)
	}
	tracker.TrackOrg(orgIDVerified)

	// 2. Insert PENDING organization
	domainP := canonicalDomain("public-pending-test")
	regNumP := canonicalRegistrationNumber("PUB-PEND-", 6)
	var orgIDPending pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status) VALUES ('UNIVERSITY', 'Public Pending Uni', 'US', $1, $2, 'PENDING') RETURNING id", regNumP, domainP).Scan(&orgIDPending)
	if err != nil {
		t.Fatalf("failed to insert pending org: %v", err)
	}
	tracker.TrackOrg(orgIDPending)

	// 3. Insert REJECTED organization
	domainR := canonicalDomain("public-rejected-test")
	regNumR := canonicalRegistrationNumber("PUB-REJ-", 6)
	var orgIDRejected pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason) VALUES ('COMPANY', 'Public Rejected Co', 'US', $1, $2, 'REJECTED', $3, NOW(), 'Business entity documentation rejected') RETURNING id", regNumR, domainR, admin.User.ID).Scan(&orgIDRejected)
	if err != nil {
		t.Fatalf("failed to insert rejected org: %v", err)
	}
	tracker.TrackOrg(orgIDRejected)

	// 4. Insert SUSPENDED organization
	domainS := canonicalDomain("public-suspended-test")
	regNumS := canonicalRegistrationNumber("PUB-SUSP-", 6)
	var orgIDSuspended pgtype.UUID
	err = pool.QueryRow(ctx, "INSERT INTO organizations (org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason) VALUES ('UNIVERSITY', 'Public Suspended Uni', 'US', $1, $2, 'SUSPENDED', $3, NOW(), 'Suspended due to compliance audit') RETURNING id", regNumS, domainS, admin.User.ID).Scan(&orgIDSuspended)
	if err != nil {
		t.Fatalf("failed to insert suspended org: %v", err)
	}
	tracker.TrackOrg(orgIDSuspended)

	// Request public listing
	reqList, _ := http.NewRequest(http.MethodGet, "/api/v1/public/verified-organizations", nil)
	wList := httptest.NewRecorder()
	r.ServeHTTP(wList, reqList)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from public verified list, got %d: %s", wList.Code, wList.Body.String())
	}

	bodyList := wList.Body.String()
	if !strings.Contains(bodyList, domainV) {
		t.Errorf("expected verified domain %s in public list", domainV)
	}
	if strings.Contains(bodyList, domainP) {
		t.Errorf("pending domain %s must NOT appear in public verified list", domainP)
	}
	if strings.Contains(bodyList, domainR) {
		t.Errorf("rejected domain %s must NOT appear in public verified list", domainR)
	}
	if strings.Contains(bodyList, domainS) {
		t.Errorf("suspended domain %s must NOT appear in public verified list", domainS)
	}

	// Verify safe fields only: no registration number, no reviewer
	if strings.Contains(bodyList, regNumV) {
		t.Errorf("public list must NOT expose registration numbers!")
	}
	if strings.Contains(bodyList, admin.User.ID.String()) {
		t.Errorf("public list must NOT expose reviewer IDs!")
	}

	// Public single lookup for VERIFIED org -> 200
	reqSingle, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/public/organizations/%s", orgIDVerified.String()), nil)
	wSingle := httptest.NewRecorder()
	r.ServeHTTP(wSingle, reqSingle)
	if wSingle.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from public lookup, got %d", wSingle.Code)
	}

	// Public single lookup for PENDING org -> uniform 404 (no enumeration leakage)
	reqPending, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/public/organizations/%s", orgIDPending.String()), nil)
	wPending := httptest.NewRecorder()
	r.ServeHTTP(wPending, reqPending)
	if wPending.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unverified organization lookup, got %d", wPending.Code)
	}

	// Public single lookup for REJECTED org -> uniform 404
	reqRejected, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/public/organizations/%s", orgIDRejected.String()), nil)
	wRejected := httptest.NewRecorder()
	r.ServeHTTP(wRejected, reqRejected)
	if wRejected.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for rejected organization lookup, got %d", wRejected.Code)
	}

	// Public single lookup for SUSPENDED org -> uniform 404
	reqSuspended, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/public/organizations/%s", orgIDSuspended.String()), nil)
	wSuspended := httptest.NewRecorder()
	r.ServeHTTP(wSuspended, reqSuspended)
	if wSuspended.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for suspended organization lookup, got %d", wSuspended.Code)
	}

	// Public single lookup for NON-EXISTENT org -> uniform 404
	reqNonExistent, _ := http.NewRequest(http.MethodGet, "/api/v1/public/organizations/00000000-0000-0000-0000-000000000000", nil)
	wNonExistent := httptest.NewRecorder()
	r.ServeHTTP(wNonExistent, reqNonExistent)
	if wNonExistent.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent organization lookup, got %d", wNonExistent.Code)
	}

	if wPending.Body.String() != wNonExistent.Body.String() {
		t.Errorf("public 404 responses leaked existence details: %s != %s", wPending.Body.String(), wNonExistent.Body.String())
	}
	if wRejected.Body.String() != wNonExistent.Body.String() {
		t.Errorf("public 404 responses leaked existence details for rejected org: %s != %s", wRejected.Body.String(), wNonExistent.Body.String())
	}
	if wSuspended.Body.String() != wNonExistent.Body.String() {
		t.Errorf("public 404 responses leaked existence details for suspended org: %s != %s", wSuspended.Body.String(), wNonExistent.Body.String())
	}

	// 4. Rate Limiting Verification on public endpoints (limit is 60 requests per minute per IP)
	rateTestIP := "198.51.100.77:4321"
	for i := 0; i < 60; i++ {
		reqRate, _ := http.NewRequest(http.MethodGet, "/api/v1/public/verified-organizations", nil)
		reqRate.RemoteAddr = rateTestIP
		wRate := httptest.NewRecorder()
		r.ServeHTTP(wRate, reqRate)
		if wRate.Code != http.StatusOK {
			t.Fatalf("request %d under rate limit failed unexpectedly: %d", i+1, wRate.Code)
		}
	}

	// 61st request from same IP must be rate limited (429 Too Many Requests)
	reqExceeded, _ := http.NewRequest(http.MethodGet, "/api/v1/public/verified-organizations", nil)
	reqExceeded.RemoteAddr = rateTestIP
	wExceeded := httptest.NewRecorder()
	r.ServeHTTP(wExceeded, reqExceeded)
	if wExceeded.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on 61st request, got %d", wExceeded.Code)
	}
	if wExceeded.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}

	// A different IP is not rate limited
	reqOtherIP, _ := http.NewRequest(http.MethodGet, "/api/v1/public/verified-organizations", nil)
	reqOtherIP.RemoteAddr = "198.51.100.88:4321"
	wOtherIP := httptest.NewRecorder()
	r.ServeHTTP(wOtherIP, reqOtherIP)
	if wOtherIP.Code != http.StatusOK {
		t.Errorf("expected 200 OK for distinct client IP, got %d", wOtherIP.Code)
	}
}

// ----------------------------------------------------------------------------
// Test 13: Regression test ensuring health, ready, and full Phase 4A auth lifecycle
// ----------------------------------------------------------------------------
func TestIntegration_OrganizationRegression(t *testing.T) {
	pool, cfg, tracker := setupIntegrationTestDB(t)
	r := setupTestRouter(cfg, pool)
	ctx := context.Background()

	// 1. GET /health -> 200
	reqH, _ := http.NewRequest(http.MethodGet, "/health", nil)
	wH := httptest.NewRecorder()
	r.ServeHTTP(wH, reqH)
	if wH.Code != http.StatusOK {
		t.Errorf("expected 200 for /health, got %d", wH.Code)
	}

	// 2. GET /ready -> 200 (database pool is up)
	reqR, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	wR := httptest.NewRecorder()
	r.ServeHTTP(wR, reqR)
	if wR.Code != http.StatusOK {
		t.Errorf("expected 200 for /ready, got %d: %s", wR.Code, wR.Body.String())
	}

	// 3. Phase 4A authentication foundation lifecycle regression:
	// Register -> Login -> CSRF -> /auth/me -> Logout -> /auth/me revoked
	regEmail := fmt.Sprintf("reg_%s@example.com", randomHex(8))
	regPassword := "RegressionPass12345!"
	traceID := "trace-reg-" + randomHex(12)

	// 3a. Register
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s","full_name":"Regression User"}`, regEmail, regPassword)
	reqReg, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)
	if wReg.Code != http.StatusOK {
		t.Fatalf("regression register failed: %d: %s", wReg.Code, wReg.Body.String())
	}

	var regUser db.User
	err := pool.QueryRow(ctx, "SELECT id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at FROM users WHERE email = $1", regEmail).Scan(
		&regUser.ID, &regUser.Email, &regUser.FullName, &regUser.IsActive, &regUser.IsSuperadmin, &regUser.EmailVerified, &regUser.CreatedAt, &regUser.UpdatedAt, &regUser.DeletedAt,
	)
	if err != nil {
		t.Fatalf("failed to query created user: %v", err)
	}
	tracker.TrackUser(regUser.ID)

	var regIdentityID pgtype.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM auth_identities WHERE user_id = $1", regUser.ID).Scan(&regIdentityID); err != nil {
		t.Fatalf("failed to query created auth identity: %v", err)
	}
	tracker.TrackAuthIdentity(regIdentityID)
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// 3b. Login
	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s","portal_context":"app"}`, regEmail, regPassword)
	reqLogin, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("Origin", cfg.FrontendURL)
	reqLogin.Header.Set("User-Agent", traceID)
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("regression login failed: %d: %s", wLogin.Code, wLogin.Body.String())
	}
	tracker.TrackAuditByTrace(ctx, t, traceID)

	var regSessionID pgtype.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM auth_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", regUser.ID).Scan(&regSessionID); err != nil {
		t.Fatalf("failed to query created auth session: %v", err)
	}
	tracker.TrackSession(regSessionID)

	cookie := findCookieByName(t, wLogin.Result().Cookies(), cfg.AuthSessionCookieName)

	// 3c. Fetch CSRF token
	reqCSRF, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqCSRF.AddCookie(cookie)
	wCSRF := httptest.NewRecorder()
	r.ServeHTTP(wCSRF, reqCSRF)
	if wCSRF.Code != http.StatusOK {
		t.Fatalf("regression csrf fetch failed: %d: %s", wCSRF.Code, wCSRF.Body.String())
	}

	var csrfResp struct {
		Data auth.CSRFResponse `json:"data"`
	}
	if err := json.Unmarshal(wCSRF.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("failed to parse CSRF response: %v", err)
	}

	// 3d. Authenticated GET /api/v1/auth/me succeeds 200 OK
	reqMe, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.AddCookie(cookie)
	wMe := httptest.NewRecorder()
	r.ServeHTTP(wMe, reqMe)
	if wMe.Code != http.StatusOK {
		t.Fatalf("regression /auth/me failed: %d: %s", wMe.Code, wMe.Body.String())
	}

	// 3e. Authenticated POST /api/v1/auth/logout with CSRF
	reqLogout, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogout.Header.Set("Origin", cfg.FrontendURL)
	reqLogout.Header.Set("X-CSRF-Token", csrfResp.Data.CSRFToken)
	reqLogout.Header.Set("User-Agent", traceID)
	reqLogout.AddCookie(cookie)
	wLogout := httptest.NewRecorder()
	r.ServeHTTP(wLogout, reqLogout)
	if wLogout.Code != http.StatusOK {
		t.Fatalf("regression logout failed: %d: %s", wLogout.Code, wLogout.Body.String())
	}
	tracker.TrackAuditByTrace(ctx, t, traceID)

	// 3f. Request /auth/me with revoked cookie returns 401 Unauthorized
	reqMeAfterLogout, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMeAfterLogout.AddCookie(cookie)
	wMeAfterLogout := httptest.NewRecorder()
	r.ServeHTTP(wMeAfterLogout, reqMeAfterLogout)
	if wMeAfterLogout.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized after logout, got %d", wMeAfterLogout.Code)
	}
}
