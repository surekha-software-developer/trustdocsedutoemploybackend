package anchoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRouter(handler *Handler) *gin.Engine {
	r := gin.New()
	v1 := r.Group("/api/v1")
	RegisterRoutes(v1, handler, nil, nil, nil, nil, func(c *gin.Context) {})
	return r
}

func TestHandler_VerifyProof_Success(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(2)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	batchResp, err := svc.CreateBatch(t.Context(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	target := certs[0]
	proofData, _ := svc.GetBatchProofForCertificate(t.Context(), target.PublicID)

	handler := NewHandler(svc, newTestLogger())
	router := setupTestRouter(handler)

	reqBody, _ := json.Marshal(VerifyProofRequest{
		PublicID:     target.PublicID,
		DocumentHash: target.DocumentHash.String,
		MerkleRoot:   *batchResp.MerkleRoot,
		Proof:        proofData.Proof,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/certificates/verify-proof", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Assert Cache-Control: no-store
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("expected Cache-Control: no-store header, got '%s'", cc)
	}

	var jsonResp struct {
		Success bool                `json:"success"`
		Data    VerifyProofResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jsonResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !jsonResp.Success || !jsonResp.Data.MathematicalProofValid {
		t.Errorf("expected valid mathematical proof response, got %+v", jsonResp)
	}
}

func TestHandler_VerifyProof_InvalidJSON(t *testing.T) {
	svc := NewService(NewMockRepository(), 10, newTestLogger())
	handler := NewHandler(svc, newTestLogger())
	router := setupTestRouter(handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/certificates/verify-proof", strings.NewReader("invalid-json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResp core.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Success || errResp.Error == nil || errResp.Error.Code != core.ErrCodeBadRequest {
		t.Errorf("expected BAD_REQUEST error, got %+v", errResp)
	}
}

func TestHandler_VerifyProof_ProofDepthExceeded(t *testing.T) {
	svc := NewService(NewMockRepository(), 10, newTestLogger())
	handler := NewHandler(svc, newTestLogger())
	router := setupTestRouter(handler)

	deepProof := make([]string, 25)
	for i := range deepProof {
		deepProof[i] = "0x" + strings.Repeat("0", 64)
	}

	reqBody, _ := json.Marshal(VerifyProofRequest{
		PublicID:     "TD-CERT-A1B2C3D4E5F60718",
		DocumentHash: strings.Repeat("a", 64),
		MerkleRoot:   "0x" + strings.Repeat("b", 64),
		Proof:        deepProof,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/certificates/verify-proof", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var errResp core.ErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error == nil || errResp.Error.Code != core.ErrCodeProofDepthExceeded {
		t.Errorf("expected PROOF_DEPTH_EXCEEDED, got %+v", errResp)
	}
}

func TestHandler_Admin_BatchEndpoints(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(3)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	handler := NewHandler(svc, newTestLogger())

	// Set up router with admin routes enabled
	r := gin.New()
	v1 := r.Group("/api/v1")
	RegisterRoutes(v1, handler, nil, nil, func(c *gin.Context) { c.Next() }, nil, func(c *gin.Context) {})

	// 1. CreateBatch
	w := httptest.NewRecorder()
	createBody, _ := json.Marshal(CreateBatchRequest{BatchSize: 10})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/anchoring/batches", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d (body: %s)", w.Code, w.Body.String())
	}

	var createResp struct {
		Success bool          `json:"success"`
		Data    BatchResponse `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	batchID := createResp.Data.ID

	// 2. GetBatch
	wGet := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/admin/anchoring/batches/%s", batchID), nil)
	r.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", wGet.Code)
	}

	// 3. GetBatch Not Found
	wNotFound := httptest.NewRecorder()
	reqNotFound := httptest.NewRequest(http.MethodGet, "/api/v1/admin/anchoring/batches/00000000-0000-0000-0000-000000000000", nil)
	r.ServeHTTP(wNotFound, reqNotFound)
	if wNotFound.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent batch, got %d", wNotFound.Code)
	}

	// 4. ListBatches
	wList := httptest.NewRecorder()
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/admin/anchoring/batches?limit=10&offset=0", nil)
	r.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", wList.Code)
	}
}
