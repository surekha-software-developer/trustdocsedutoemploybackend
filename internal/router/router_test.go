package router

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/anchoring"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/certificates"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/organizations"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func getTestSetup() (*config.Config, *slog.Logger) {
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
		RateLimitLoginAttempts:    5,
		RateLimitLoginWindow:      15 * time.Minute,
		RateLimitIPAttempts:       20,
		RateLimitIPWindow:         15 * time.Minute,
		RateLimitRegisterAttempts: 10,
		RateLimitRegisterWindow:   1 * time.Hour,
		TrustedProxies:            []string{"127.0.0.1"},
	}
	// Discard logger output during tests
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return cfg, logger
}

func TestRouter_UnknownRouteReturns404(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent-route", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeNotFound {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeNotFound, resp.Error)
	}
	if resp.Error.Message != "The requested resource was not found" {
		t.Errorf("expected message 'The requested resource was not found', got '%s'", resp.Error.Message)
	}
}

func TestRouter_UnsupportedMethodReturns405(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	// /health only supports GET, so POST must return 405
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeMethodNotAllowed {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeMethodNotAllowed, resp.Error)
	}
	if resp.Error.Message != "The HTTP method is not allowed" {
		t.Errorf("expected message 'The HTTP method is not allowed', got '%s'", resp.Error.Message)
	}
}

func TestRouter_AllowedCORSPreflight(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 No Content for OPTIONS preflight, got %d", w.Code)
	}

	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "http://localhost:3000" {
		t.Errorf("expected Access-Control-Allow-Origin 'http://localhost:3000', got '%s'", allowOrigin)
	}

	allowMethods := w.Header().Get("Access-Control-Allow-Methods")
	if !strings.Contains(allowMethods, "GET") {
		t.Errorf("expected Access-Control-Allow-Methods to contain GET, got '%s'", allowMethods)
	}
}

func TestRouter_UnapprovedCORSOrigin(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "http://malicious-site.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for unapproved origin, got '%s'", allowOrigin)
	}
}

func TestRouter_RequestIDHeaderExists(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	reqID := w.Header().Get(middleware.RequestIDHeader)
	if reqID == "" {
		t.Errorf("expected %s header in response, got empty string", middleware.RequestIDHeader)
	}
}

func TestRouter_PanicRecoveryReturns500WithoutStackTrace(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	// Add a test-only panicking route
	r.GET("/test-panic", func(c *gin.Context) {
		panic("simulated unexpected database crash or nil pointer")
	})

	req := httptest.NewRequest(http.MethodGet, "/test-panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	bodyStr := w.Body.String()
	if strings.Contains(bodyStr, "simulated unexpected") {
		t.Errorf("response body must NOT expose internal panic text; got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, ".go:") || strings.Contains(bodyStr, "goroutine") {
		t.Errorf("response body must NOT expose stack trace; got: %s", bodyStr)
	}

	var resp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false")
	}
	if resp.Error == nil || resp.Error.Code != core.ErrCodeInternal {
		t.Errorf("expected error code '%s', got '%v'", core.ErrCodeInternal, resp.Error)
	}
	if resp.Error.Message != "An unexpected error occurred" {
		t.Errorf("expected message 'An unexpected error occurred', got '%s'", resp.Error.Message)
	}
}

func TestRouter_HealthAndReadyEndpoints(t *testing.T) {
	cfg, logger := getTestSetup()
	r := SetupRouter(cfg, logger, nil)

	// Test GET /health
	reqH := httptest.NewRequest(http.MethodGet, "/health", nil)
	wH := httptest.NewRecorder()
	r.ServeHTTP(wH, reqH)
	if wH.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /health, got %d", wH.Code)
	}

	// Test GET /ready with nil pinger returns 503 DEPENDENCY_UNAVAILABLE
	reqR := httptest.NewRequest(http.MethodGet, "/ready", nil)
	wR := httptest.NewRecorder()
	r.ServeHTTP(wR, reqR)
	if wR.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable for /ready without DB, got %d", wR.Code)
	}
}

type mockAuthRepoForRouter struct {
	auth.Repository
}

func (m *mockAuthRepoForRouter) GetMembership(ctx context.Context, orgID, userID pgtype.UUID) (db.OrganizationMembership, error) {
	return db.OrganizationMembership{IsActive: true, Role: "UNIVERSITY_ADMIN"}, nil
}

type mockOrgRepoForRouter struct {
	organizations.Repository
}

func (m *mockOrgRepoForRouter) GetOrganizationByID(ctx context.Context, id pgtype.UUID) (db.Organization, error) {
	return db.Organization{VerificationStatus: "VERIFIED"}, nil
}

func TestRouter_OrganizationRoutesRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")

	mockAuth := &mockAuthRepoForRouter{}
	mockOrg := &mockOrgRepoForRouter{}
	h := organizations.NewHandler(organizations.NewService(mockOrg))

	noop := func(c *gin.Context) { c.Next() }
	organizations.RegisterRoutes(v1, h, mockAuth, mockOrg, noop, noop, noop, noop, noop)

	routes := r.Routes()
	expectedRoutes := []string{
		"POST /api/v1/organizations",
		"GET /api/v1/organizations/mine",
		"GET /api/v1/organizations/:organization_id",
		"PATCH /api/v1/organizations/:organization_id",
		"GET /api/v1/organizations/:organization_id/members",
		"GET /api/v1/admin/organizations",
		"GET /api/v1/admin/organizations/:organization_id",
		"POST /api/v1/admin/organizations/:organization_id/approve",
		"POST /api/v1/admin/organizations/:organization_id/reject",
		"GET /api/v1/public/verified-organizations",
		"GET /api/v1/public/organizations/:organization_id",
	}

	foundRoutes := make(map[string]bool)
	for _, route := range routes {
		key := route.Method + " " + route.Path
		foundRoutes[key] = true
	}

	for _, expected := range expectedRoutes {
		if !foundRoutes[expected] {
			t.Errorf("expected route %s not found in registered routes", expected)
		}
	}
}

func TestRouter_CertificateRoutesRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")

	mockAuth := &mockAuthRepoForRouter{}
	mockOrg := &mockOrgRepoForRouter{}
	mockStorage := storage.NewMockStorage()
	svc := certificates.NewService(nil, mockStorage, 10485760, 5*time.Minute, nil)
	h := certificates.NewHandler(svc)

	noop := func(c *gin.Context) { c.Next() }
	certificates.RegisterRoutes(v1, h, mockAuth, mockOrg, noop, noop, noop, noop, noop)

	routes := r.Routes()
	expectedRoutes := []string{
		"POST /api/v1/organizations/:organization_id/certificates",
		"PATCH /api/v1/organizations/:organization_id/certificates/:certificate_id",
		"POST /api/v1/organizations/:organization_id/certificates/:certificate_id/file",
		"POST /api/v1/organizations/:organization_id/certificates/:certificate_id/issue",
		"GET /api/v1/organizations/:organization_id/certificates",
		"GET /api/v1/organizations/:organization_id/certificates/:certificate_id",
		"DELETE /api/v1/organizations/:organization_id/certificates/:certificate_id",
		"POST /api/v1/organizations/:organization_id/certificates/:certificate_id/revoke",
		"POST /api/v1/organizations/:organization_id/certificates/:certificate_id/replace",
		"GET /api/v1/certificates/mine",
		"GET /api/v1/certificates/mine/:certificate_id",
		"GET /api/v1/certificates/:certificate_id/download",
		"GET /api/v1/public/certificates/:public_id",
	}

	foundRoutes := make(map[string]bool)
	for _, route := range routes {
		key := route.Method + " " + route.Path
		foundRoutes[key] = true
	}

	for _, expected := range expectedRoutes {
		if !foundRoutes[expected] {
			t.Errorf("expected route %s not found in registered routes", expected)
		}
	}
}

func TestRouter_StorageComposition_NoMockFallback(t *testing.T) {
	cfg, logger := getTestSetup()
	// Setup router without storage option
	r := SetupRouter(cfg, logger, nil)

	routes := r.Routes()
	for _, route := range routes {
		if strings.Contains(route.Path, "/certificates") {
			t.Errorf("expected no certificate routes when storage option is omitted, found: %s %s", route.Method, route.Path)
		}
	}
}

func TestRouter_StorageComposition_ExplicitMockInjection(t *testing.T) {
	cfg, logger := getTestSetup()
	mockStorage := storage.NewMockStorage()

	// Explicit injection of mock storage
	opt := WithObjectStorage(mockStorage)
	var optApplied options
	opt(&optApplied)

	if optApplied.storage == nil {
		t.Fatalf("expected WithObjectStorage to set storage dependency")
	}

	// In test mode without DB pool, router still initializes health/errors safely
	r := SetupRouter(cfg, logger, nil, WithObjectStorage(mockStorage))
	if r == nil {
		t.Fatalf("expected non-nil router")
	}
}

type mockAnchoringRepoForRouter struct{}

var _ anchoring.Repository = (*mockAnchoringRepoForRouter)(nil)

func (m *mockAnchoringRepoForRouter) FindEligibleCertificates(ctx context.Context, limit int32) ([]anchoring.EligibleCertificate, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) CreateBatchWithCertificates(
	ctx context.Context,
	canonicalBatchID string,
	treeAlgo string,
	treeVer int32,
	leafVer string,
	proofVer string,
	leaves []anchoring.LeafData,
	root string,
) (*db.MerkleBatch, error) {
	return &db.MerkleBatch{}, nil
}

func (m *mockAnchoringRepoForRouter) GetBatchByID(ctx context.Context, id pgtype.UUID) (*db.MerkleBatch, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetBatchByCanonicalID(ctx context.Context, canonicalID string) (*db.MerkleBatch, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetBatchByNumber(ctx context.Context, batchNumber int64) (*db.MerkleBatch, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) ListBatches(ctx context.Context, limit int32, offset int32) ([]db.MerkleBatch, error) {
	return []db.MerkleBatch{}, nil
}

func (m *mockAnchoringRepoForRouter) CountBatches(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockAnchoringRepoForRouter) ClaimNextReadyBatch(ctx context.Context, claimedBy string, leaseSeconds int32, chainID int64, contractAddress string) (*db.MerkleBatch, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) ExtendBatchClaim(ctx context.Context, batchID pgtype.UUID, claimedBy string, leaseSeconds int32) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) ResetExpiredBatchClaim(ctx context.Context, batchID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkBatchSubmitted(ctx context.Context, batchID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkBatchConfirmed(ctx context.Context, batchID pgtype.UUID, blockNumber int64, blockHash string, confirmationCount int32) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkBatchFailed(ctx context.Context, batchID pgtype.UUID, failureStage string, failureCode string, failureDetailCode string) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) SetAuthoritativeTransaction(ctx context.Context, batchID pgtype.UUID, txID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) ReserveSignerNonce(ctx context.Context, batchID pgtype.UUID, chainID int64, signerAddress string, nonce int64) (*db.SignerNonceReservation, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetHighestNonceBySigner(ctx context.Context, chainID int64, signerAddress string) (int64, error) {
	return 0, nil
}

func (m *mockAnchoringRepoForRouter) GetActiveNonceReservation(ctx context.Context, batchID pgtype.UUID) (*db.SignerNonceReservation, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) CommitNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) ReleaseNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) CreateBlockchainTransaction(ctx context.Context, arg db.CreateBlockchainTransactionParams) (*db.BlockchainTransaction, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetActiveTransactionByReservationID(ctx context.Context, reservationID pgtype.UUID) (*db.BlockchainTransaction, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetAuthoritativeTransactionForBatch(ctx context.Context, batchID pgtype.UUID) (*db.BlockchainTransaction, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) ListTransactionsByBatchID(ctx context.Context, batchID pgtype.UUID) ([]db.BlockchainTransaction, error) {
	return []db.BlockchainTransaction{}, nil
}

func (m *mockAnchoringRepoForRouter) MarkTransactionBroadcast(ctx context.Context, txID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkTransactionMined(ctx context.Context, txID pgtype.UUID, blockNumber int64, blockHash string, gasUsed int64) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkTransactionReplaced(ctx context.Context, txID pgtype.UUID) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) MarkTransactionFailed(ctx context.Context, txID pgtype.UUID, failureCode string, failureDetailCode string) error {
	return nil
}

func (m *mockAnchoringRepoForRouter) GetBatchCertificateByPublicID(ctx context.Context, publicID string) (*db.BatchCertificate, error) {
	return nil, nil
}

func (m *mockAnchoringRepoForRouter) GetProofNodesByBatchCertID(ctx context.Context, batchCertID pgtype.UUID) ([]db.GetProofNodesByBatchCertIDRow, error) {
	return []db.GetProofNodesByBatchCertIDRow{}, nil
}

func (m *mockAnchoringRepoForRouter) GetCertificateByPublicID(ctx context.Context, publicID string) (*anchoring.CertificateRow, error) {
	return nil, nil
}

func TestRouter_AnchoringPublicRouteRegistered(t *testing.T) {
	cfg, logger := getTestSetup()
	mockRepo := &mockAnchoringRepoForRouter{}
	anchorSvc := anchoring.NewService(mockRepo, 10, logger)

	r := SetupRouter(cfg, logger, nil, WithAnchoringService(anchorSvc))
	if r == nil {
		t.Fatalf("expected non-nil router")
	}

	found := false
	for _, route := range r.Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/v1/public/certificates/verify-proof" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected POST /api/v1/public/certificates/verify-proof to be registered")
	}
}
