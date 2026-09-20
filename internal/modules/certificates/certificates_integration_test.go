//go:build integration

package certificates_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/certificates"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/router"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

// testIntegrationPassword satisfies the Phase 4A password policy:
// minimum 15 Unicode code points (MinPasswordRunes = 15) and maximum 256 UTF-8 bytes.
// Used uniformly across test user creation, registration requests, and authentication logins.
const testIntegrationPassword = "TestIntegrationPassword123!"

// testTracker tracks exact primary key UUIDs for all entity types created during integration test execution
// to ensure dependency-safe, leak-free teardown without TRUNCATE, DROP, migrations down, or broad DELETE statements.
// Also registers per-test unique identifiers (emails, domains, public IDs, traces) upfront so that even if an
// assertion aborts early via t.Fatalf, teardown discovers and deletes the created rows by exact primary key.
type testTracker struct {
	mu                   sync.Mutex
	pool                 *pgxpool.Pool
	userIDs              []pgtype.UUID
	authIdentityIDs      []pgtype.UUID
	sessionIDs           []pgtype.UUID
	orgIDs               []pgtype.UUID
	membershipIDs        []pgtype.UUID
	certIDs              []pgtype.UUID
	auditIDs             []pgtype.UUID
	storageKeys          []string
	trackedEmails        []string
	trackedOrgDomains    []string
	trackedCertPublicIDs []string
	traces               []string
	mockStorage          *storage.MockStorage
}

func newTestTracker(pool *pgxpool.Pool, mockStore *storage.MockStorage) *testTracker {
	return &testTracker{
		pool:                 pool,
		mockStorage:          mockStore,
		userIDs:              make([]pgtype.UUID, 0),
		authIdentityIDs:      make([]pgtype.UUID, 0),
		sessionIDs:           make([]pgtype.UUID, 0),
		orgIDs:               make([]pgtype.UUID, 0),
		membershipIDs:        make([]pgtype.UUID, 0),
		certIDs:              make([]pgtype.UUID, 0),
		auditIDs:             make([]pgtype.UUID, 0),
		storageKeys:          make([]string, 0),
		trackedEmails:        make([]string, 0),
		trackedOrgDomains:    make([]string, 0),
		trackedCertPublicIDs: make([]string, 0),
		traces:               make([]string, 0),
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

func (tr *testTracker) TrackEmail(email string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if strings.TrimSpace(email) != "" {
		tr.trackedEmails = append(tr.trackedEmails, strings.TrimSpace(email))
	}
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

func (tr *testTracker) TrackOrgDomain(domain string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if strings.TrimSpace(domain) != "" {
		tr.trackedOrgDomains = append(tr.trackedOrgDomains, strings.TrimSpace(domain))
	}
}

func (tr *testTracker) TrackMembership(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.membershipIDs = append(tr.membershipIDs, id)
}

func (tr *testTracker) TrackCert(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.certIDs = append(tr.certIDs, id)
}

func (tr *testTracker) TrackCertPublicID(pubID string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if strings.TrimSpace(pubID) != "" {
		tr.trackedCertPublicIDs = append(tr.trackedCertPublicIDs, strings.TrimSpace(pubID))
	}
}

func (tr *testTracker) TrackAuditID(id pgtype.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.auditIDs = append(tr.auditIDs, id)
}

func (tr *testTracker) TrackTrace(trace string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if strings.TrimSpace(trace) != "" {
		tr.traces = append(tr.traces, strings.TrimSpace(trace))
	}
}

func (tr *testTracker) TrackStorageKey(key string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if strings.TrimSpace(key) != "" {
		tr.storageKeys = append(tr.storageKeys, key)
	}
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

// verifyZeroRows asserts that zero rows remain in the database for every tracked UUID before commit.
// Returns false if any verification query fails or if any residual rows exist, preventing an invalid commit.
func (tr *testTracker) verifyZeroRows(ctx context.Context, t *testing.T, tx pgx.Tx) bool {
	t.Helper()
	passed := true

	checkZero := func(tableName string, ids []pgtype.UUID) {
		if len(ids) == 0 {
			return
		}
		var count int
		query := fmt.Sprintf("SELECT count(*) FROM %s WHERE id = ANY($1)", tableName)
		if err := tx.QueryRow(ctx, query, ids).Scan(&count); err != nil {
			t.Errorf("cleanup verification query failed on %s: %v", tableName, err)
			passed = false
			return
		}
		if count != 0 {
			t.Errorf("cleanup verification failed: %d %s rows still exist", count, tableName)
			passed = false
		}
	}

	checkZero("audit_logs", tr.auditIDs)
	checkZero("certificates", tr.certIDs)
	checkZero("organization_memberships", tr.membershipIDs)
	checkZero("organizations", tr.orgIDs)
	checkZero("auth_sessions", tr.sessionIDs)
	checkZero("auth_identities", tr.authIdentityIDs)
	checkZero("users", tr.userIDs)

	return passed
}

// cleanup executes exact-ID reverse foreign-key order teardown in a single atomic transaction.
// Pre-discovers exact primary keys from upfront tracked identifiers so that tests aborting early
// are fully cleaned up without leaving residual users, identities, or audit rows.
// Does NOT mutate organizations into constraint-invalid intermediate states (e.g. reviewed_by_user_id = NULL).
// Deletes organizations before users, satisfying ON DELETE RESTRICT cleanly.
func (tr *testTracker) cleanup(t *testing.T) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 0a. Discover uncaptured exact primary keys from tracked email identifiers
	if len(tr.trackedEmails) > 0 {
		rowsUE, err := tr.pool.Query(ctx, "SELECT id FROM users WHERE email = ANY($1)", tr.trackedEmails)
		if err == nil {
			for rowsUE.Next() {
				var id pgtype.UUID
				if err := rowsUE.Scan(&id); err == nil {
					tr.userIDs = append(tr.userIDs, id)
				}
			}
			rowsUE.Close()
		}
	}

	// 0b. Discover uncaptured exact primary keys from tracked organization domains
	if len(tr.trackedOrgDomains) > 0 {
		rowsOE, err := tr.pool.Query(ctx, "SELECT id FROM organizations WHERE official_domain = ANY($1)", tr.trackedOrgDomains)
		if err == nil {
			for rowsOE.Next() {
				var id pgtype.UUID
				if err := rowsOE.Scan(&id); err == nil {
					tr.orgIDs = append(tr.orgIDs, id)
				}
			}
			rowsOE.Close()
		}
	}

	// 0c. Discover uncaptured exact primary keys from tracked certificate public IDs
	if len(tr.trackedCertPublicIDs) > 0 {
		rowsCE, err := tr.pool.Query(ctx, "SELECT id FROM certificates WHERE public_id = ANY($1)", tr.trackedCertPublicIDs)
		if err == nil {
			for rowsCE.Next() {
				var id pgtype.UUID
				if err := rowsCE.Scan(&id); err == nil {
					tr.certIDs = append(tr.certIDs, id)
				}
			}
			rowsCE.Close()
		}
	}

	// 0d. Discover uncaptured exact primary keys from tracked user agent traces
	for _, trace := range tr.traces {
		rowsAT, err := tr.pool.Query(ctx, "SELECT id FROM audit_logs WHERE user_agent = $1", trace)
		if err == nil {
			for rowsAT.Next() {
				var id pgtype.UUID
				if err := rowsAT.Scan(&id); err == nil {
					tr.auditIDs = append(tr.auditIDs, id)
				}
			}
			rowsAT.Close()
		}
	}

	// 0e. Prior to deletion, discover uncaptured exact primary keys associated with tracked users
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

		rowsCU, err := tr.pool.Query(ctx, "SELECT id FROM certificates WHERE recipient_user_id = ANY($1) OR created_by_user_id = ANY($1)", tr.userIDs)
		if err == nil {
			for rowsCU.Next() {
				var id pgtype.UUID
				if err := rowsCU.Scan(&id); err == nil {
					tr.certIDs = append(tr.certIDs, id)
				}
			}
			rowsCU.Close()
		}
	}

	// 0f. Prior to deletion, discover uncaptured exact primary keys associated with tracked organizations
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

		rowsCO, err := tr.pool.Query(ctx, "SELECT id FROM certificates WHERE organization_id = ANY($1)", tr.orgIDs)
		if err == nil {
			for rowsCO.Next() {
				var id pgtype.UUID
				if err := rowsCO.Scan(&id); err == nil {
					tr.certIDs = append(tr.certIDs, id)
				}
			}
			rowsCO.Close()
		}
	}

	// 0g. Prior to deletion, discover uncaptured replacement lineage certificates and certificate audit logs
	if len(tr.certIDs) > 0 {
		rowsCL, err := tr.pool.Query(ctx, "SELECT replaced_by_certificate_id, replaces_certificate_id FROM certificates WHERE id = ANY($1)", tr.certIDs)
		if err == nil {
			for rowsCL.Next() {
				var repBy, rep pgtype.UUID
				if err := rowsCL.Scan(&repBy, &rep); err == nil {
					if repBy.Valid {
						tr.certIDs = append(tr.certIDs, repBy)
					}
					if rep.Valid {
						tr.certIDs = append(tr.certIDs, rep)
					}
				}
			}
			rowsCL.Close()
		}

		rowsAC, err := tr.pool.Query(ctx, "SELECT id FROM audit_logs WHERE resource_id = ANY($1)", tr.certIDs)
		if err == nil {
			for rowsAC.Next() {
				var id pgtype.UUID
				if err := rowsAC.Scan(&id); err == nil {
					tr.auditIDs = append(tr.auditIDs, id)
				}
			}
			rowsAC.Close()
		}
	}

	// Deduplicate tracked collections
	tr.auditIDs = deduplicateUUIDs(tr.auditIDs)
	tr.certIDs = deduplicateUUIDs(tr.certIDs)
	tr.membershipIDs = deduplicateUUIDs(tr.membershipIDs)
	tr.orgIDs = deduplicateUUIDs(tr.orgIDs)
	tr.sessionIDs = deduplicateUUIDs(tr.sessionIDs)
	tr.authIdentityIDs = deduplicateUUIDs(tr.authIdentityIDs)
	tr.userIDs = deduplicateUUIDs(tr.userIDs)

	// Execute teardown in a single atomic transaction
	tx, err := tr.pool.Begin(ctx)
	if err != nil {
		t.Errorf("cleanup: failed to begin cleanup transaction: %v", err)
		return
	}
	defer tx.Rollback(ctx)

	rollback := func(step string, err error) {
		_ = tx.Rollback(ctx)
		t.Errorf("cleanup: failed at %s: %v", step, err)
	}

	execStep := func(step string, query string, args ...any) bool {
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			rollback(step, err)
			return false
		}
		return true
	}

	// Step 1: DELETE audit_logs by exact tracked UUIDs
	if len(tr.auditIDs) > 0 {
		if !execStep("audit_logs", "DELETE FROM audit_logs WHERE id = ANY($1)", tr.auditIDs) {
			return
		}
	}

	// Step 2: Neutralize self-referencing replacement lineage on tracked certificates
	// Clears bidirectional foreign keys so ON DELETE RESTRICT does not block certificate deletion
	if len(tr.certIDs) > 0 {
		// Step 2a: Break outward replacement references by transitioning tracked REPLACED rows to REVOKED
		// with replaced_by_certificate_id = NULL. This strictly satisfies chk_certificates_status_consistency
		// while removing the foreign-key reference to the replacement certificate.
		if !execStep("neutralize_replaced_certificates", `
			UPDATE certificates
			SET status = 'REVOKED',
			    replaced_by_certificate_id = NULL
			WHERE id = ANY($1) AND status = 'REPLACED'
		`, tr.certIDs) {
			return
		}

		// Step 2b: Break inward replacement references by clearing replaces_certificate_id on tracked replacement certificates.
		// For ISSUED/REVOKED rows, replaces_certificate_id = NULL is fully valid under chk_certificates_status_consistency.
		if !execStep("neutralize_replaces_certificates", `
			UPDATE certificates
			SET replaces_certificate_id = NULL
			WHERE id = ANY($1) AND replaces_certificate_id IS NOT NULL
		`, tr.certIDs) {
			return
		}

		// Step 3: DELETE certificates by exact tracked UUIDs
		if !execStep("certificates", "DELETE FROM certificates WHERE id = ANY($1)", tr.certIDs) {
			return
		}
	}

	// Step 4: DELETE organization_memberships by exact tracked UUIDs
	if len(tr.membershipIDs) > 0 {
		if !execStep("organization_memberships", "DELETE FROM organization_memberships WHERE id = ANY($1)", tr.membershipIDs) {
			return
		}
	}

	// Step 5: DELETE organizations by exact tracked UUIDs
	// Deleting organizations before reviewer users cleanly satisfies ON DELETE RESTRICT on users
	// without violating chk_organizations_status_consistency by nullifying reviewed_by_user_id.
	if len(tr.orgIDs) > 0 {
		if !execStep("organizations", "DELETE FROM organizations WHERE id = ANY($1)", tr.orgIDs) {
			return
		}
	}

	// Step 6: DELETE auth_sessions by exact tracked UUIDs
	if len(tr.sessionIDs) > 0 {
		if !execStep("auth_sessions", "DELETE FROM auth_sessions WHERE id = ANY($1)", tr.sessionIDs) {
			return
		}
	}

	// Step 7: DELETE auth_identities by exact tracked UUIDs
	if len(tr.authIdentityIDs) > 0 {
		if !execStep("auth_identities", "DELETE FROM auth_identities WHERE id = ANY($1)", tr.authIdentityIDs) {
			return
		}
	}

	// Step 8: DELETE users by exact tracked UUIDs
	if len(tr.userIDs) > 0 {
		if !execStep("users", "DELETE FROM users WHERE id = ANY($1)", tr.userIDs) {
			return
		}
	}

	// Step 9: Verify zero rows remain for every exact tracked UUID before commit
	if !tr.verifyZeroRows(ctx, t, tx) {
		_ = tx.Rollback(ctx)
		return
	}

	// Step 10: Commit atomic teardown
	if err := tx.Commit(ctx); err != nil {
		_ = tx.Rollback(ctx)
		t.Errorf("cleanup: failed to commit cleanup transaction: %v", err)
		return
	}

	// Reset tracked collections after successful commit
	tr.auditIDs = nil
	tr.certIDs = nil
	tr.membershipIDs = nil
	tr.orgIDs = nil
	tr.sessionIDs = nil
	tr.authIdentityIDs = nil
	tr.userIDs = nil
	tr.trackedEmails = nil
	tr.trackedOrgDomains = nil
	tr.trackedCertPublicIDs = nil
	tr.traces = nil

	// Step 11: Clean up in-memory mock storage objects
	if tr.mockStorage != nil {
		for _, key := range tr.storageKeys {
			_ = tr.mockStorage.DeleteObject(ctx, key)
		}
		tr.storageKeys = nil
	}
}

// setupIntegrationTestDB validates all 11 security guards and initializes an isolated database connection.
func setupIntegrationTestDB(t *testing.T) (*pgxpool.Pool, *config.Config, *testTracker, *storage.MockStorage) {
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

	// Guard 9: Verify migration schema: verify certificates and audit_logs tables exist
	var certTableExists bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'certificates')").Scan(&certTableExists); err != nil || !certTableExists {
		pool.Close()
		t.Fatalf("ABORT: certificates table missing from test database; please run migration 000002 up")
	}

	// Explicitly construct and inject MockStorage (zero Cloudflare calls, zero R2 construction)
	mockStorage := storage.NewMockStorage()
	tracker := newTestTracker(pool, mockStorage)

	// Single explicit teardown: cleanup -> verify in tx -> close pool
	t.Cleanup(func() {
		tracker.cleanup(t)
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
		RateLimitIPAttempts:       200,
		RateLimitIPWindow:         15 * time.Minute,
		RateLimitRegisterAttempts: 100,
		RateLimitRegisterWindow:   1 * time.Hour,
		TrustedProxies:            []string{"127.0.0.1"},
		CertificateMaxFileSize:    10485760, // 10 MB
		R2PresignTTL:              5 * time.Minute,
	}

	return pool, cfg, tracker, mockStorage
}

func setupIntegrationRouter(cfg *config.Config, pool *pgxpool.Pool, mockStore storage.ObjectStorage) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return router.SetupRouter(cfg, logger, pool, router.WithObjectStorage(mockStore))
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}
	return hex.EncodeToString(b)
}

// testPublicID creates a canonical uppercase public identifier satisfying ^TD-CERT-[A-Z0-9]{16,32}$
func testPublicID(t *testing.T) string {
	t.Helper()
	return "TD-CERT-" + strings.ToUpper(randomHex(t, 12))
}

// createTestUser creates a test user adhering strictly to migration 000001 schema:
// - users table columns: email, full_name, is_superadmin, is_active, email_verified (no role column on users)
// - creates corresponding auth_identities row with EMAIL_PASSWORD identity_type and canonical identifier
// - registers identifiers with testTracker upfront for robust teardown discovery
// - hashes testIntegrationPassword satisfying Phase 4A password policy
func createTestUser(ctx context.Context, t *testing.T, pool *pgxpool.Pool, cfg *config.Config, tracker *testTracker, role string) (pgtype.UUID, string) {
	t.Helper()
	email := fmt.Sprintf("test-%s@example.com", randomHex(t, 8))
	tracker.TrackEmail(email)

	isSuper := (role == "SUPERADMIN")
	var userID pgtype.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO users (email, full_name, is_superadmin, is_active, email_verified)
		VALUES ($1, $2, $3, true, true)
		RETURNING id
	`, email, "Test User "+email, isSuper).Scan(&userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	tracker.TrackUser(userID)

	// Create valid auth_identities row with configured Argon2id parameters
	argonParams := auth.Argon2Params{
		Memory:      cfg.Argon2Memory,
		Iterations:  cfg.Argon2Iterations,
		Parallelism: cfg.Argon2Parallelism,
		SaltLength:  cfg.Argon2SaltLength,
		KeyLength:   cfg.Argon2KeyLength,
	}
	hashedPassword, err := auth.HashPassword(testIntegrationPassword, argonParams)
	if err != nil {
		t.Fatalf("failed to hash password for test user: %v", err)
	}

	var identityID pgtype.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO auth_identities (user_id, identity_type, identifier, credential_hash)
		VALUES ($1, 'EMAIL_PASSWORD', $2, $3)
		RETURNING id
	`, userID, email, hashedPassword).Scan(&identityID)
	if err != nil {
		t.Fatalf("failed to create test user auth identity: %v", err)
	}
	tracker.TrackAuthIdentity(identityID)

	return userID, email
}

// createTestOrg creates a verified or pending organization and assigns the creator to organization_memberships.
// Strictly adheres to migration 000001:
// - organizations columns: org_type, legal_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at
// - satisfies chk_organizations_status_consistency
// - role is modeled in organization_memberships (UNIVERSITY_ADMIN or COMPANY_ADMIN)
func createTestOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tracker *testTracker, creatorID pgtype.UUID, orgType, status string) pgtype.UUID {
	t.Helper()
	regNo := strings.ToUpper(fmt.Sprintf("REG-%s", randomHex(t, 6)))
	domain := strings.ToLower(fmt.Sprintf("%s.edu", randomHex(t, 6)))
	tracker.TrackOrgDomain(domain)

	var orgID pgtype.UUID
	var err error
	if status == "VERIFIED" {
		err = pool.QueryRow(ctx, `
			INSERT INTO organizations (legal_name, org_type, registration_number, country_code, official_domain, verification_status, reviewed_by_user_id, reviewed_at)
			VALUES ($1, $2, $3, 'US', $4, 'VERIFIED', $5, NOW())
			RETURNING id
		`, "Test Org "+domain, orgType, regNo, domain, creatorID).Scan(&orgID)
	} else if status == "PENDING" {
		err = pool.QueryRow(ctx, `
			INSERT INTO organizations (legal_name, org_type, registration_number, country_code, official_domain, verification_status)
			VALUES ($1, $2, $3, 'US', $4, 'PENDING')
			RETURNING id
		`, "Test Org "+domain, orgType, regNo, domain).Scan(&orgID)
	} else {
		err = pool.QueryRow(ctx, `
			INSERT INTO organizations (legal_name, org_type, registration_number, country_code, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason)
			VALUES ($1, $2, $3, 'US', $4, $5, $6, NOW(), 'Test reason')
			RETURNING id
		`, "Test Org "+domain, orgType, regNo, domain, status, creatorID).Scan(&orgID)
	}
	if err != nil {
		t.Fatalf("failed to create test org: %v", err)
	}
	tracker.TrackOrg(orgID)

	// Add membership
	memRole := "UNIVERSITY_ADMIN"
	if orgType == "COMPANY" {
		memRole = "COMPANY_ADMIN"
	}
	var memID pgtype.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO organization_memberships (organization_id, user_id, role, is_active)
		VALUES ($1, $2, $3, true)
		RETURNING id
	`, orgID, creatorID, memRole).Scan(&memID)
	if err != nil {
		t.Fatalf("failed to add org membership: %v", err)
	}
	tracker.TrackMembership(memID)

	return orgID
}

func createAuthenticatedSession(t *testing.T, r *gin.Engine, pool *pgxpool.Pool, tracker *testTracker, email, password string) (*http.Cookie, string) {
	t.Helper()
	// Perform login request
	loginBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed with status %d: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "trustdocs_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("trustdocs_session cookie not found in login response")
	}

	// Fetch CSRF token
	reqCSRF := httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reqCSRF.AddCookie(sessionCookie)
	wCSRF := httptest.NewRecorder()
	r.ServeHTTP(wCSRF, reqCSRF)

	if wCSRF.Code != http.StatusOK {
		t.Fatalf("csrf request failed with status %d: %s", wCSRF.Code, wCSRF.Body.String())
	}

	var csrfResp struct {
		Success bool `json:"success"`
		Data    struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wCSRF.Body.Bytes(), &csrfResp); err != nil || csrfResp.Data.CSRFToken == "" {
		t.Fatalf("failed to decode csrf token from response: %v", err)
	}

	return sessionCookie, csrfResp.Data.CSRFToken
}

func generateValidPDF(sizeBytes int) []byte {
	if sizeBytes < 15 {
		sizeBytes = 15
	}
	data := make([]byte, sizeBytes)
	copy(data, "%PDF-1.4\n")
	copy(data[len(data)-6:], "\n%%EOF")
	return data
}

// ============================================================================
// Scenarios 1 - 6: Certificate Draft Creation, Constraints & Snapshots
// ============================================================================
func TestIntegration_CertificateDraft_CreationAndValidation(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, adminEmail := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	sessionCookie, csrfToken := createAuthenticatedSession(t, r, pool, tracker, adminEmail, testIntegrationPassword)

	orgStr := certificates.UUIDToString(orgID)

	// Scenario 2: Valid draft creation with snapshot
	validDraftReq := fmt.Sprintf(`{
		"recipient_user_id": "%s",
		"recipient_name": "Alice Smith",
		"recipient_email": "%s",
		"title": "Bachelor of Science in Computer Science",
		"degree_type": "BACHELOR",
		"graduation_date": "2026-05-15",
		"issue_date": "2026-05-20"
	}`, certificates.UUIDToString(studentID), studentEmail)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates", strings.NewReader(validDraftReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(sessionCookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for valid draft, got %d: %s", w.Code, w.Body.String())
	}

	var createResp struct {
		Success bool                             `json:"success"`
		Data    certificates.CertificateResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode create draft response: %v", err)
	}

	certUUID := certificates.StringToUUID(createResp.Data.ID)
	tracker.TrackCert(certUUID)

	// Scenario 3: Recipient email/UUID correspondence
	if createResp.Data.RecipientEmail != studentEmail {
		t.Errorf("expected recipient email %s, got %s", studentEmail, createResp.Data.RecipientEmail)
	}
	if createResp.Data.Status != "DRAFT" {
		t.Errorf("expected DRAFT status, got %s", createResp.Data.Status)
	}

	// Scenario 4: Academic date ordering constraint (issue_date < graduation_date must fail)
	badDateReq := fmt.Sprintf(`{
		"recipient_user_id": "%s",
		"recipient_name": "Alice Smith",
		"recipient_email": "%s",
		"title": "Degree",
		"degree_type": "BACHELOR",
		"graduation_date": "2026-06-01",
		"issue_date": "2026-05-01"
	}`, certificates.UUIDToString(studentID), studentEmail)

	reqBadDate := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates", strings.NewReader(badDateReq))
	reqBadDate.Header.Set("Content-Type", "application/json")
	reqBadDate.Header.Set("X-CSRF-Token", csrfToken)
	reqBadDate.AddCookie(sessionCookie)
	wBadDate := httptest.NewRecorder()
	r.ServeHTTP(wBadDate, reqBadDate)

	if wBadDate.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for issue_date < graduation_date, got %d", wBadDate.Code)
	}

	// Scenario 5: Future issue-date rejection (issue_date > 30 days in future)
	futureIssueDate := time.Now().AddDate(0, 2, 0).Format("2006-01-02")
	futureReq := fmt.Sprintf(`{
		"recipient_user_id": "%s",
		"recipient_name": "Alice Smith",
		"recipient_email": "%s",
		"title": "Degree",
		"degree_type": "BACHELOR",
		"graduation_date": "2026-01-01",
		"issue_date": "%s"
	}`, certificates.UUIDToString(studentID), studentEmail, futureIssueDate)

	reqFuture := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates", strings.NewReader(futureReq))
	reqFuture.Header.Set("Content-Type", "application/json")
	reqFuture.Header.Set("X-CSRF-Token", csrfToken)
	reqFuture.AddCookie(sessionCookie)
	wFuture := httptest.NewRecorder()
	r.ServeHTTP(wFuture, reqFuture)

	if wFuture.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for far-future issue date, got %d", wFuture.Code)
	}
}

// ============================================================================
// Scenarios 7 - 14: PDF Upload, Size Limits, Hashing, Compensation & Cleanup
// ============================================================================
func TestIntegration_CertificateFile_UploadValidation(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, adminEmail := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	sessionCookie, csrfToken := createAuthenticatedSession(t, r, pool, tracker, adminEmail, testIntegrationPassword)

	// Create test draft
	var certID pgtype.UUID
	pubID := testPublicID(t)
	tracker.TrackCertPublicID(pubID)
	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, created_by_user_id
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science', 'BACHELOR', '2026-05-15', '2026-05-20', 'DRAFT', $5
		) RETURNING id
	`, pubID, orgID, studentID, studentEmail, adminID).Scan(&certID)
	if err != nil {
		t.Fatalf("failed to insert test draft certificate: %v", err)
	}
	tracker.TrackCert(certID)

	uploadURL := fmt.Sprintf("/api/v1/organizations/%s/certificates/%s/file", certificates.UUIDToString(orgID), certificates.UUIDToString(certID))

	// Scenario 7: Valid PDF upload and exact SHA-256 persistence
	pdfContent := generateValidPDF(1024)
	expectedHashBytes := sha256.Sum256(pdfContent)
	expectedHash := hex.EncodeToString(expectedHashBytes[:])

	bodyBuf := &bytes.Buffer{}
	mpWriter := multipart.NewWriter(bodyBuf)
	part, _ := mpWriter.CreateFormFile("file", "diploma.pdf")
	_, _ = part.Write(pdfContent)
	mpWriter.Close()

	reqUpload := httptest.NewRequest(http.MethodPost, uploadURL, bodyBuf)
	reqUpload.Header.Set("Content-Type", mpWriter.FormDataContentType())
	reqUpload.Header.Set("X-CSRF-Token", csrfToken)
	reqUpload.AddCookie(sessionCookie)
	wUpload := httptest.NewRecorder()
	r.ServeHTTP(wUpload, reqUpload)

	if wUpload.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid PDF upload, got %d: %s", wUpload.Code, wUpload.Body.String())
	}

	// Verify document hash in DB
	var dbHash, dbStorageKey string
	var dbFileSize int64
	err = pool.QueryRow(ctx, "SELECT document_hash, file_storage_key, file_size FROM certificates WHERE id = $1", certID).Scan(&dbHash, &dbStorageKey, &dbFileSize)
	if err != nil {
		t.Fatalf("failed to query certificate file fields: %v", err)
	}

	if dbHash != expectedHash {
		t.Errorf("document hash mismatch: expected %s, got %s", expectedHash, dbHash)
	}
	if dbFileSize != 1024 {
		t.Errorf("file size mismatch: expected 1024, got %d", dbFileSize)
	}
	tracker.TrackStorageKey(dbStorageKey)

	// Scenario 11: Invalid %PDF- magic bytes rejected
	badMagicBuf := &bytes.Buffer{}
	badWriter := multipart.NewWriter(badMagicBuf)
	badPart, _ := badWriter.CreateFormFile("file", "fake.pdf")
	_, _ = badPart.Write([]byte("NOT_A_PDF_DOCUMENT"))
	badWriter.Close()

	reqBadMagic := httptest.NewRequest(http.MethodPost, uploadURL, badMagicBuf)
	reqBadMagic.Header.Set("Content-Type", badWriter.FormDataContentType())
	reqBadMagic.Header.Set("X-CSRF-Token", csrfToken)
	reqBadMagic.AddCookie(sessionCookie)
	wBadMagic := httptest.NewRecorder()
	r.ServeHTTP(wBadMagic, reqBadMagic)

	if wBadMagic.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid magic bytes, got %d", wBadMagic.Code)
	}
}

// ============================================================================
// Scenarios 15 - 19: Soft Deletion, Issuance, Concurrency & Document Hash Conflicts
// ============================================================================
func TestIntegration_Certificate_IssuanceAndConflicts(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, adminEmail := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	sessionCookie, csrfToken := createAuthenticatedSession(t, r, pool, tracker, adminEmail, testIntegrationPassword)

	// Create and attach file to draft
	var certID pgtype.UUID
	pubID := testPublicID(t)
	tracker.TrackCertPublicID(pubID)
	docHash := randomHex(t, 32)
	storageKey := fmt.Sprintf("certificates/%s/%s/%s.pdf", certificates.UUIDToString(orgID), randomHex(t, 16), docHash)
	tracker.TrackStorageKey(storageKey)
	_ = mockStorage.PutObject(ctx, storageKey, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science', 'BACHELOR', '2026-05-15', '2026-05-20', 'DRAFT',
			$5, 'cert.pdf', 15, 'application/pdf', $6, $7
		) RETURNING id
	`, pubID, orgID, studentID, studentEmail, storageKey, docHash, adminID).Scan(&certID)
	if err != nil {
		t.Fatalf("failed to insert draft certificate: %v", err)
	}
	tracker.TrackCert(certID)

	issueURL := fmt.Sprintf("/api/v1/organizations/%s/certificates/%s/issue", certificates.UUIDToString(orgID), certificates.UUIDToString(certID))

	// Scenario 16: Issue certificate successfully
	reqIssue := httptest.NewRequest(http.MethodPost, issueURL, nil)
	reqIssue.Header.Set("X-CSRF-Token", csrfToken)
	reqIssue.AddCookie(sessionCookie)
	wIssue := httptest.NewRecorder()
	r.ServeHTTP(wIssue, reqIssue)

	if wIssue.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on certificate issuance, got %d: %s", wIssue.Code, wIssue.Body.String())
	}

	// Scenario 18: Immutability - issuing an already issued certificate returns conflict
	reqDuplicateIssue := httptest.NewRequest(http.MethodPost, issueURL, nil)
	reqDuplicateIssue.Header.Set("X-CSRF-Token", csrfToken)
	reqDuplicateIssue.AddCookie(sessionCookie)
	wDup := httptest.NewRecorder()
	r.ServeHTTP(wDup, reqDuplicateIssue)

	if wDup.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for re-issuance of finalized certificate, got %d", wDup.Code)
	}

	// Scenario 19: Duplicate document hash conflict on a second certificate
	var secondCertID pgtype.UUID
	pubID2 := testPublicID(t)
	tracker.TrackCertPublicID(pubID2)
	err = pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, created_by_user_id
		) VALUES (
			$1, $2, $3, 'Student Two', $4,
			'Master of Science', 'MASTER', '2026-05-15', '2026-05-20', 'DRAFT', $5
		) RETURNING id
	`, pubID2, orgID, studentID, studentEmail, adminID).Scan(&secondCertID)
	if err != nil {
		t.Fatalf("failed to insert second certificate: %v", err)
	}
	tracker.TrackCert(secondCertID)

	// Attempt to attach the same document hash to second certificate
	repo := certificates.NewPgxRepository(pool)
	conflict, err := repo.CheckDocumentHashConflict(ctx, docHash)
	if err != nil {
		t.Fatalf("failed to check document hash conflict: %v", err)
	}
	if !conflict {
		t.Errorf("expected document hash conflict for already issued hash, got false")
	}
}

// ============================================================================
// Scenarios 22 - 26: Student Passport & Download Authorization Policies
// ============================================================================
func TestIntegration_StudentPassport_AndDownloadPolicies(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, _ := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	studentCookie, _ := createAuthenticatedSession(t, r, pool, tracker, studentEmail, testIntegrationPassword)

	// Create ISSUED and REVOKED certificates for student
	var issuedCertID, revokedCertID pgtype.UUID
	pubID1 := testPublicID(t)
	tracker.TrackCertPublicID(pubID1)
	docHash1 := randomHex(t, 32)
	key1 := fmt.Sprintf("certificates/%s/issued.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(key1)
	_ = mockStorage.PutObject(ctx, key1, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Arts', 'BACHELOR', '2026-05-15', '2026-05-20', 'ISSUED',
			$5, 'issued.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW()
		) RETURNING id
	`, pubID1, orgID, studentID, studentEmail, key1, docHash1, adminID).Scan(&issuedCertID)
	if err != nil {
		t.Fatalf("failed to insert issued certificate: %v", err)
	}
	tracker.TrackCert(issuedCertID)

	pubID2 := testPublicID(t)
	tracker.TrackCertPublicID(pubID2)
	docHash2 := randomHex(t, 32)
	key2 := fmt.Sprintf("certificates/%s/revoked.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(key2)
	_ = mockStorage.PutObject(ctx, key2, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	err = pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at, revoked_by_user_id, revoked_at,
			revocation_reason_code, revocation_reason
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Certificate of Study', 'BACHELOR', '2026-05-15', '2026-05-20', 'REVOKED',
			$5, 'revoked.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW(), $7, NOW(),
			'ACADEMIC_MISCONDUCT', 'Revoked due to honor code violation'
		) RETURNING id
	`, pubID2, orgID, studentID, studentEmail, key2, docHash2, adminID).Scan(&revokedCertID)
	if err != nil {
		t.Fatalf("failed to insert revoked certificate: %v", err)
	}
	tracker.TrackCert(revokedCertID)

	// Scenario 22: Student passport lists own certificates
	reqPassport := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/mine", nil)
	reqPassport.AddCookie(studentCookie)
	wPassport := httptest.NewRecorder()
	r.ServeHTTP(wPassport, reqPassport)

	if wPassport.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for student passport, got %d: %s", wPassport.Code, wPassport.Body.String())
	}

	// Scenario 24: Student download of ISSUED certificate returns download URL
	reqDownIssued := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/"+certificates.UUIDToString(issuedCertID)+"/download", nil)
	reqDownIssued.AddCookie(studentCookie)
	wDownIssued := httptest.NewRecorder()
	r.ServeHTTP(wDownIssued, reqDownIssued)

	if wDownIssued.Code != http.StatusOK {
		t.Errorf("expected 200 OK for student downloading ISSUED cert, got %d: %s", wDownIssued.Code, wDownIssued.Body.String())
	}

	// Scenario 25: Student download of REVOKED certificate returns 410 Gone with status metadata
	reqDownRevoked := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/"+certificates.UUIDToString(revokedCertID)+"/download", nil)
	reqDownRevoked.AddCookie(studentCookie)
	wDownRevoked := httptest.NewRecorder()
	r.ServeHTTP(wDownRevoked, reqDownRevoked)

	if wDownRevoked.Code != http.StatusGone {
		t.Errorf("expected 410 Gone for student downloading REVOKED cert, got %d: %s", wDownRevoked.Code, wDownRevoked.Body.String())
	}
	if wDownRevoked.Header().Get("X-Certificate-Status") != "REVOKED" {
		t.Errorf("expected X-Certificate-Status header to be REVOKED")
	}
}

// ============================================================================
// Scenarios 29 - 34: Atomic Certificate Replacement Lineage
// ============================================================================
func TestIntegration_Certificate_ReplacementLineage(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, adminEmail := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	sessionCookie, csrfToken := createAuthenticatedSession(t, r, pool, tracker, adminEmail, testIntegrationPassword)

	// 1. Create original ISSUED certificate
	var oldCertID pgtype.UUID
	pubIDOld := testPublicID(t)
	tracker.TrackCertPublicID(pubIDOld)
	docHashOld := randomHex(t, 32)
	keyOld := fmt.Sprintf("certificates/%s/old.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(keyOld)
	_ = mockStorage.PutObject(ctx, keyOld, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science', 'BACHELOR', '2026-05-15', '2026-05-20', 'ISSUED',
			$5, 'old.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW()
		) RETURNING id
	`, pubIDOld, orgID, studentID, studentEmail, keyOld, docHashOld, adminID).Scan(&oldCertID)
	if err != nil {
		t.Fatalf("failed to insert old issued certificate: %v", err)
	}
	tracker.TrackCert(oldCertID)

	// 2. Create new DRAFT certificate for replacement with distinct hash
	var newCertID pgtype.UUID
	pubIDNew := testPublicID(t)
	tracker.TrackCertPublicID(pubIDNew)
	docHashNew := randomHex(t, 32)
	keyNew := fmt.Sprintf("certificates/%s/new.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(keyNew)
	_ = mockStorage.PutObject(ctx, keyNew, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	err = pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science (Corrected)', 'BACHELOR', '2026-05-15', '2026-05-20', 'DRAFT',
			$5, 'new.pdf', 15, 'application/pdf', $6, $7
		) RETURNING id
	`, pubIDNew, orgID, studentID, studentEmail, keyNew, docHashNew, adminID).Scan(&newCertID)
	if err != nil {
		t.Fatalf("failed to insert new draft certificate: %v", err)
	}
	tracker.TrackCert(newCertID)

	// Scenario 29: Perform atomic certificate replacement
	newCertUUIDStr := certificates.UUIDToString(newCertID)
	if newCertUUIDStr == "" {
		t.Fatalf("expected non-empty replacement certificate UUID")
	}

	replaceURL := fmt.Sprintf("/api/v1/organizations/%s/certificates/%s/replace", certificates.UUIDToString(orgID), certificates.UUIDToString(oldCertID))
	replaceBody := fmt.Sprintf(`{
		"replacement_certificate_id": "%s",
		"reason_code": "ADMINISTRATIVE_CORRECTION",
		"reason": "Corrected typographical error in honors title"
	}`, newCertUUIDStr)

	reqReplace := httptest.NewRequest(http.MethodPost, replaceURL, strings.NewReader(replaceBody))
	reqReplace.Header.Set("Content-Type", "application/json")
	reqReplace.Header.Set("Origin", cfg.FrontendURL)
	reqReplace.Header.Set("X-CSRF-Token", csrfToken)
	reqReplace.AddCookie(sessionCookie)
	wReplace := httptest.NewRecorder()
	r.ServeHTTP(wReplace, reqReplace)

	if wReplace.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on certificate replacement, got %d: %s", wReplace.Code, wReplace.Body.String())
	}

	// Verify bidirectional lineage in database
	var oldStatus string
	var oldReplacedBy pgtype.UUID
	err = pool.QueryRow(ctx, "SELECT status, replaced_by_certificate_id FROM certificates WHERE id = $1", oldCertID).Scan(&oldStatus, &oldReplacedBy)
	if err != nil {
		t.Fatalf("failed to query old certificate status: %v", err)
	}

	if oldStatus != "REPLACED" {
		t.Errorf("expected old certificate status to be REPLACED, got %s", oldStatus)
	}
	if !certificates.UUIDEqual(oldReplacedBy, newCertID) {
		t.Errorf("expected old certificate replaced_by_certificate_id to match new certificate ID")
	}

	var newStatus string
	var newReplaces pgtype.UUID
	err = pool.QueryRow(ctx, "SELECT status, replaces_certificate_id FROM certificates WHERE id = $1", newCertID).Scan(&newStatus, &newReplaces)
	if err != nil {
		t.Fatalf("failed to query new certificate status: %v", err)
	}

	if newStatus != "ISSUED" {
		t.Errorf("expected new certificate status to be ISSUED, got %s", newStatus)
	}
	if !certificates.UUIDEqual(newReplaces, oldCertID) {
		t.Errorf("expected new certificate replaces_certificate_id to match old certificate ID")
	}

	// Scenario 33: Self-replacement rejection
	reqSelfReplace := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/organizations/%s/certificates/%s/replace", certificates.UUIDToString(orgID), newCertUUIDStr), strings.NewReader(fmt.Sprintf(`{
		"replacement_certificate_id": "%s",
		"reason_code": "ADMINISTRATIVE_CORRECTION",
		"reason": "Self replacement attempted"
	}`, newCertUUIDStr)))
	reqSelfReplace.Header.Set("Content-Type", "application/json")
	reqSelfReplace.Header.Set("Origin", cfg.FrontendURL)
	reqSelfReplace.Header.Set("X-CSRF-Token", csrfToken)
	reqSelfReplace.AddCookie(sessionCookie)
	wSelf := httptest.NewRecorder()
	r.ServeHTTP(wSelf, reqSelfReplace)

	if wSelf.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-replacement, got %d", wSelf.Code)
	}
}

// TestIntegration_Certificate_ReplacementLineage_Cleanup validates that testTracker.cleanup
// safely resolves bidirectional replacement lineage cycles (REPLACED -> ISSUED) without
// violating chk_certificates_status_consistency or foreign-key restrictions, and confirms
// that both certificates are completely deleted from the database.
func TestIntegration_Certificate_ReplacementLineage_Cleanup(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	ctx := context.Background()

	adminID, _ := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	// 1. Create original REPLACED certificate and replacement ISSUED certificate with bidirectional lineage
	pubIDOld := testPublicID(t)
	tracker.TrackCertPublicID(pubIDOld)
	docHashOld := randomHex(t, 32)
	keyOld := fmt.Sprintf("certificates/%s/cleanup-old.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(keyOld)
	_ = mockStorage.PutObject(ctx, keyOld, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	pubIDNew := testPublicID(t)
	tracker.TrackCertPublicID(pubIDNew)
	docHashNew := randomHex(t, 32)
	keyNew := fmt.Sprintf("certificates/%s/cleanup-new.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(keyNew)
	_ = mockStorage.PutObject(ctx, keyNew, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	// First insert replacement certificate as ISSUED (without replaces link yet)
	var newCertID pgtype.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science (Replacement)', 'BACHELOR', '2026-05-15', '2026-05-20', 'ISSUED',
			$5, 'cleanup-new.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW()
		) RETURNING id
	`, pubIDNew, orgID, studentID, studentEmail, keyNew, docHashNew, adminID).Scan(&newCertID)
	if err != nil {
		t.Fatalf("failed to insert replacement certificate: %v", err)
	}
	tracker.TrackCert(newCertID)

	// Insert original certificate as REPLACED pointing to newCertID
	var oldCertID pgtype.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at, revoked_by_user_id, revoked_at,
			revocation_reason_code, revocation_reason, replaced_by_certificate_id
		) VALUES (
			$1, $2, $3, 'Student Name', $4,
			'Bachelor of Science (Original)', 'BACHELOR', '2026-05-15', '2026-05-20', 'REPLACED',
			$5, 'cleanup-old.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW(), $7, NOW(),
			'ADMINISTRATIVE_CORRECTION', 'Cleanup test replacement cycle', $8
		) RETURNING id
	`, pubIDOld, orgID, studentID, studentEmail, keyOld, docHashOld, adminID, newCertID).Scan(&oldCertID)
	if err != nil {
		t.Fatalf("failed to insert original replaced certificate: %v", err)
	}
	tracker.TrackCert(oldCertID)

	// Link replacement back to original to form the bidirectional cycle
	_, err = pool.Exec(ctx, "UPDATE certificates SET replaces_certificate_id = $1 WHERE id = $2", oldCertID, newCertID)
	if err != nil {
		t.Fatalf("failed to link bidirectional replacement lineage: %v", err)
	}

	// Verify both exist with exact statuses and bidirectional lineage
	var oldStatus, newStatus string
	var oldRepBy, newRep pgtype.UUID
	err = pool.QueryRow(ctx, "SELECT status, replaced_by_certificate_id FROM certificates WHERE id = $1", oldCertID).Scan(&oldStatus, &oldRepBy)
	if err != nil || oldStatus != "REPLACED" || !certificates.UUIDEqual(oldRepBy, newCertID) {
		t.Fatalf("precondition failed: original certificate not in valid REPLACED state: status=%s, repBy=%v, err=%v", oldStatus, oldRepBy, err)
	}
	err = pool.QueryRow(ctx, "SELECT status, replaces_certificate_id FROM certificates WHERE id = $1", newCertID).Scan(&newStatus, &newRep)
	if err != nil || newStatus != "ISSUED" || !certificates.UUIDEqual(newRep, oldCertID) {
		t.Fatalf("precondition failed: replacement certificate not in valid ISSUED state: status=%s, rep=%v, err=%v", newStatus, newRep, err)
	}

	// 2. Execute tracker.cleanup explicitly
	tracker.cleanup(t)

	// 3. Assert both exact certificate IDs are absent in the database afterward
	var remainingOld, remainingNew int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM certificates WHERE id = $1", oldCertID).Scan(&remainingOld)
	if err != nil {
		t.Errorf("failed to query remaining original certificate: %v", err)
	}
	if remainingOld != 0 {
		t.Errorf("cleanup failed: original certificate %s still exists in database", certificates.UUIDToString(oldCertID))
	}

	err = pool.QueryRow(ctx, "SELECT count(*) FROM certificates WHERE id = $1", newCertID).Scan(&remainingNew)
	if err != nil {
		t.Errorf("failed to query remaining replacement certificate: %v", err)
	}
	if remainingNew != 0 {
		t.Errorf("cleanup failed: replacement certificate %s still exists in database", certificates.UUIDToString(newCertID))
	}
}

// ============================================================================
// Scenarios 35 - 38: Public Verification, Privacy Masking & Rate Limiting
// ============================================================================
func TestIntegration_PublicVerification_PrivacyAndRateLimit(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	adminID, _ := createTestUser(ctx, t, pool, cfg, tracker, "UNIVERSITY_ADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, adminID, "UNIVERSITY", "VERIFIED")
	studentID, studentEmail := createTestUser(ctx, t, pool, cfg, tracker, "STUDENT")

	pubID := testPublicID(t)
	tracker.TrackCertPublicID(pubID)
	docHash := randomHex(t, 32)
	storageKey := fmt.Sprintf("certificates/%s/public_test.pdf", certificates.UUIDToString(orgID))
	tracker.TrackStorageKey(storageKey)
	_ = mockStorage.PutObject(ctx, storageKey, bytes.NewReader([]byte("%PDF-1.4\n%%EOF")), 15, "application/pdf")

	var certID pgtype.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO certificates (
			public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
			title, degree_type, graduation_date, issue_date, status, file_storage_key,
			file_name, file_size, file_mime_type, document_hash, created_by_user_id,
			issued_by_user_id, issued_at
		) VALUES (
			$1, $2, $3, 'Jane Elizabeth Doe', $4,
			'Bachelor of Science', 'BACHELOR', '2026-05-15', '2026-05-20', 'ISSUED',
			$5, 'diploma.pdf', 15, 'application/pdf', $6, $7,
			$7, NOW()
		) RETURNING id
	`, pubID, orgID, studentID, studentEmail, storageKey, docHash, adminID).Scan(&certID)
	if err != nil {
		t.Fatalf("failed to insert public test certificate: %v", err)
	}
	tracker.TrackCert(certID)

	// Scenario 35 & 36: Public verification privacy: masked recipient, no storage key or PII
	reqVerify := httptest.NewRequest(http.MethodGet, "/api/v1/public/certificates/"+pubID, nil)
	reqVerify.RemoteAddr = "198.51.100.1:12345"
	wVerify := httptest.NewRecorder()
	r.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for public verification, got %d: %s", wVerify.Code, wVerify.Body.String())
	}

	bodyStr := wVerify.Body.String()
	// Must contain masked name
	if !strings.Contains(bodyStr, "J*** E******** D**") {
		t.Errorf("expected masked recipient name in public response, got: %s", bodyStr)
	}
	// Must strictly omit sensitive data
	prohibitedSubstrings := []string{
		studentEmail,
		certificates.UUIDToString(studentID),
		certificates.UUIDToString(adminID),
		storageKey,
		"diploma.pdf",
	}
	for _, p := range prohibitedSubstrings {
		if strings.Contains(bodyStr, p) {
			t.Errorf("public response leaked sensitive data %q: %s", p, bodyStr)
		}
	}

	// Scenario 37: Uniform 404 for missing certificate
	reqMissing := httptest.NewRequest(http.MethodGet, "/api/v1/public/certificates/TD-CERT-NONEXISTENT1234567890", nil)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing public certificate, got %d", wMissing.Code)
	}

	// Scenario 38: Rate limiting on public endpoint (60 allowed per window)
	clientIP := "203.0.113.50:54321"
	limitHit := false
	for i := 0; i < 65; i++ {
		reqLim := httptest.NewRequest(http.MethodGet, "/api/v1/public/certificates/"+pubID, nil)
		reqLim.RemoteAddr = clientIP
		wLim := httptest.NewRecorder()
		r.ServeHTTP(wLim, reqLim)

		if i >= 60 && wLim.Code == http.StatusTooManyRequests {
			limitHit = true
			if wLim.Header().Get("Retry-After") == "" {
				t.Errorf("expected Retry-After header on 429 response")
			}
			break
		}
	}
	if !limitHit {
		t.Errorf("expected rate limiter to return 429 after 60 requests")
	}

	// Alternate IP remains unblocked
	reqAlt := httptest.NewRequest(http.MethodGet, "/api/v1/public/certificates/"+pubID, nil)
	reqAlt.RemoteAddr = "203.0.113.99:54321"
	wAlt := httptest.NewRecorder()
	r.ServeHTTP(wAlt, reqAlt)
	if wAlt.Code != http.StatusOK {
		t.Errorf("expected alternate IP to remain unblocked, got status %d", wAlt.Code)
	}
}

// ============================================================================
// Scenarios 39 - 42: Regressions (Auth, Organization, Health Endpoints)
// ============================================================================
func TestIntegration_Phase4_Regressions_AndHealth(t *testing.T) {
	pool, cfg, tracker, mockStorage := setupIntegrationTestDB(t)
	r := setupIntegrationRouter(cfg, pool, mockStorage)
	ctx := context.Background()

	// Scenario 41: /health remains independent
	reqH := httptest.NewRequest(http.MethodGet, "/health", nil)
	wH := httptest.NewRecorder()
	r.ServeHTTP(wH, reqH)
	if wH.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /health, got %d", wH.Code)
	}

	// Scenario 42: /ready reports postgres up
	reqR := httptest.NewRequest(http.MethodGet, "/ready", nil)
	wR := httptest.NewRecorder()
	r.ServeHTTP(wR, reqR)
	if wR.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /ready, got %d", wR.Code)
	}

	// Scenario 39: Phase 4A Auth regression: register -> login -> csrf -> me -> logout
	userEmail := fmt.Sprintf("reg-%s@example.com", randomHex(t, 6))
	traceID := "trace-reg-" + randomHex(t, 8)
	tracker.TrackEmail(userEmail)
	tracker.TrackTrace(traceID)

	regBody := fmt.Sprintf(`{
		"email": "%s",
		"password": "%s",
		"full_name": "Regression User"
	}`, userEmail, testIntegrationPassword)

	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(regBody))
	reqReg.Header.Set("Content-Type", "application/json")
	reqReg.Header.Set("Origin", cfg.FrontendURL)
	reqReg.Header.Set("User-Agent", traceID)
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	if wReg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for auth registration, got %d: %s", wReg.Code, wReg.Body.String())
	}

	var regResp struct {
		Success bool `json:"success"`
		Data    struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wReg.Body.Bytes(), &regResp); err != nil {
		t.Fatalf("failed to decode registration response: %v", err)
	}
	if !regResp.Success || regResp.Data.Message != "If this email address is eligible, a registration confirmation has been processed." {
		t.Fatalf("unexpected registration response payload: %s", wReg.Body.String())
	}

	// Track created user
	var regUserID pgtype.UUID
	err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", userEmail).Scan(&regUserID)
	if err != nil {
		t.Fatalf("failed to query registered user: %v", err)
	}
	tracker.TrackUser(regUserID)

	// Activate user for login
	_, err = pool.Exec(ctx, "UPDATE users SET email_verified = true, is_active = true WHERE id = $1", regUserID)
	if err != nil {
		t.Fatalf("failed to activate registered user: %v", err)
	}

	loginCookie, csrfToken := createAuthenticatedSession(t, r, pool, tracker, userEmail, testIntegrationPassword)

	// Query /api/v1/auth/me
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.AddCookie(loginCookie)
	wMe := httptest.NewRecorder()
	r.ServeHTTP(wMe, reqMe)
	if wMe.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /auth/me, got %d: %s", wMe.Code, wMe.Body.String())
	}

	// Logout
	reqLogout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogout.Header.Set("X-CSRF-Token", csrfToken)
	reqLogout.AddCookie(loginCookie)
	wLogout := httptest.NewRecorder()
	r.ServeHTTP(wLogout, reqLogout)
	if wLogout.Code != http.StatusOK {
		t.Errorf("expected 200 OK for logout, got %d: %s", wLogout.Code, wLogout.Body.String())
	}

	// Scenario 40: Phase 4B Organization regression
	superadminID, _ := createTestUser(ctx, t, pool, cfg, tracker, "SUPERADMIN")
	orgID := createTestOrg(ctx, t, pool, tracker, superadminID, "COMPANY", "VERIFIED")

	var verifiedStatus string
	err = pool.QueryRow(ctx, "SELECT verification_status FROM organizations WHERE id = $1", orgID).Scan(&verifiedStatus)
	if err != nil {
		t.Fatalf("failed to query organization verification status: %v", err)
	}
	if verifiedStatus != "VERIFIED" {
		t.Errorf("expected organization status VERIFIED, got %s", verifiedStatus)
	}
}
