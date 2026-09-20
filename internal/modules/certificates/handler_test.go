package certificates

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/organizations"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestHandler() (*Handler, *MockRepository, *storage.MockStorage) {
	repo := NewMockRepository()
	mockStorage := storage.NewMockStorage()
	svc := NewService(repo, mockStorage, 10485760, 5*time.Minute, nil)
	svc.SetSleeper(func(d time.Duration) {})
	h := NewHandler(svc)
	return h, repo, mockStorage
}

func TestHandler_CreateDraft(t *testing.T) {
	h, repo, _ := setupTestHandler()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000002")

	repo.AddUser(db.User{
		ID:       studentID,
		Email:    "student@university.edu",
		FullName: "Student Name",
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: StringToUUID("10000000-0000-0000-0000-000000000003")})
		c.Next()
	})
	r.POST("/organizations/:organization_id/certificates", h.CreateDraft)

	reqBody := CreateCertificateDraftRequest{
		RecipientUserID: UUIDToString(studentID),
		RecipientName:   "Student Name",
		RecipientEmail:  "student@university.edu",
		Title:           "Bachelor of Science",
		DegreeType:      "BACHELOR",
		GraduationDate:  "2026-05-15",
		IssueDate:       "2026-05-20",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/organizations/"+UUIDToString(orgID)+"/certificates", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var resp core.SuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success to be true")
	}
}

func TestHandler_UploadMultipartWithoutJSONRequirement(t *testing.T) {
	h, repo, _ := setupTestHandler()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-TEST1234",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: StringToUUID("10000000-0000-0000-0000-000000000003")})
		c.Next()
	})
	r.POST("/organizations/:organization_id/certificates/:certificate_id/file", h.UploadCertificateFile)

	// Create multipart form payload
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "diploma.pdf")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write([]byte("%PDF-1.4\nvalid content"))
	writer.Close()

	req := httptest.NewRequest(
		http.MethodPost,
		"/organizations/"+UUIDToString(orgID)+"/certificates/"+UUIDToString(certID)+"/file",
		&buf,
	)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK for multipart upload, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_PublicVerificationEndpoint(t *testing.T) {
	h, repo, _ := setupTestHandler()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	repo.AddOrganization(db.Organization{
		ID:             orgID,
		LegalName:      "Tech Institute",
		OfficialDomain: "tech.edu",
		CountryCode:    "US",
	})

	certID := StringToUUID("20000000-0000-0000-0000-000000000001")
	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-PUB9999",
		OrganizationID: orgID,
		Status:         "ISSUED",
		Title:          "Master of Computer Science",
		DegreeType:     "MASTER",
		RecipientName:  "Jane Marie Doe",
		DocumentHash:   pgtype.Text{String: "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", Valid: true},
		GraduationDate: pgtype.Date{Time: time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC), Valid: true},
		IssueDate:      pgtype.Date{Time: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC), Valid: true},
	})

	r := gin.New()
	r.GET("/public/certificates/:public_id", h.VerifyPublicCertificate)

	// 1. Success verification
	req := httptest.NewRequest(http.MethodGet, "/public/certificates/TD-CERT-PUB9999", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp core.SuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify absence of sensitive PII in response body
	bodyStr := w.Body.String()
	if strings.Contains(bodyStr, "recipient_email") || strings.Contains(bodyStr, "Jane Marie Doe") {
		t.Errorf("public response contains PII: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "J*** M**** D**") {
		t.Errorf("public response missing masked name: %s", bodyStr)
	}

	// 2. Non-existent returns 404
	req404 := httptest.NewRequest(http.MethodGet, "/public/certificates/TD-CERT-UNKNOWN", nil)
	w404 := httptest.NewRecorder()
	r.ServeHTTP(w404, req404)

	if w404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for unknown certificate, got %d", w404.Code)
	}
}

func TestHandler_DownloadStudentDeniedRevoked(t *testing.T) {
	h, repo, mockStorage := setupTestHandler()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	mockStorage.PutObject(context.Background(), "cert-key", strings.NewReader("dummy pdf bytes"), 15, "application/pdf")

	repo.AddCertificate(db.Certificate{
		ID:                   certID,
		PublicID:             "TD-CERT-REV1234",
		OrganizationID:       orgID,
		RecipientUserID:      studentID,
		Status:               "REVOKED",
		FileStorageKey:       pgtype.Text{String: "cert-key", Valid: true},
		RevocationReasonCode: pgtype.Text{String: RevocationReasonAcademicMisconduct, Valid: true},
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: studentID})
		c.Next()
	})
	r.GET("/certificates/:certificate_id/download", h.DownloadCertificate)

	req := httptest.NewRequest(http.MethodGet, "/certificates/"+UUIDToString(certID)+"/download", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Student must receive 410 Gone with status metadata
	if w.Code != http.StatusGone {
		t.Fatalf("expected status 410 Gone for revoked certificate, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Certificate-Status") != "REVOKED" {
		t.Errorf("expected X-Certificate-Status header to be REVOKED")
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode 410 response: %v", err)
	}
	errObj := errResp["error"].(map[string]interface{})
	if errObj["code"] != "CERTIFICATE_REVOKED" {
		t.Errorf("expected error code CERTIFICATE_REVOKED, got %v", errObj["code"])
	}
}

type mockAuthRepoForHandler struct {
	auth.Repository
}

func (m *mockAuthRepoForHandler) GetMembership(ctx context.Context, orgID, userID pgtype.UUID) (db.OrganizationMembership, error) {
	return db.OrganizationMembership{IsActive: true, Role: "UNIVERSITY_ADMIN"}, nil
}

type mockOrgRepoForHandler struct {
	organizations.Repository
}

func (m *mockOrgRepoForHandler) GetOrganizationByID(ctx context.Context, id pgtype.UUID) (db.Organization, error) {
	return db.Organization{VerificationStatus: "VERIFIED"}, nil
}

func TestHandler_MiddlewareAttachment_AndContentTypeEnforcement(t *testing.T) {
	h, repo, mockStorage := setupTestHandler()

	mockAuth := &mockAuthRepoForHandler{}
	mockOrg := &mockOrgRepoForHandler{}

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	certID := StringToUUID("20000000-0000-0000-0000-000000000002")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000003")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-ISSUE-1",
		OrganizationID: orgID,
		Status:         "DRAFT",
		FileStorageKey: pgtype.Text{String: "certificates/org/cert/hash.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Valid: true},
		Title:          "Bachelor",
		DegreeType:     "BACHELOR",
		GraduationDate: pgtype.Date{Time: time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC), Valid: true},
		IssueDate:      pgtype.Date{Time: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC), Valid: true},
	})
	_ = mockStorage.PutObject(context.Background(), "certificates/org/cert/hash.pdf", strings.NewReader("%PDF-1.4"), 8, "application/pdf")

	r := gin.New()
	v1 := r.Group("/api/v1")

	// Middleware simulation: pass authenticated user
	mockAuthContext := func(c *gin.Context) {
		c.Set("user", db.User{ID: actorID})
		c.Next()
	}
	noop := func(c *gin.Context) { c.Next() }
	realJSONMw := middleware.RequireJSONContentType()

	// Register with real RequireJSONContentType and mock repositories
	RegisterRoutes(v1, h, mockAuth, mockOrg, noop, realJSONMw, mockAuthContext, noop, noop)

	orgStr := UUIDToString(orgID)
	certStr := UUIDToString(certID)

	// 1. GET requests work without Content-Type
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+orgStr+"/certificates", nil)
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Errorf("GET certificates failed without Content-Type, got code %d: %s", wGet.Code, wGet.Body.String())
	}

	// 2. DELETE draft works without Content-Type
	// Add a draft for deletion
	draftDeleteID := StringToUUID("20000000-0000-0000-0000-000000000099")
	repo.AddCertificate(db.Certificate{
		ID:             draftDeleteID,
		PublicID:       "TD-CERT-DEL-1",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/organizations/"+orgStr+"/certificates/"+UUIDToString(draftDeleteID), nil)
	wDel := httptest.NewRecorder()
	r.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Errorf("DELETE draft failed without Content-Type, got code %d: %s", wDel.Code, wDel.Body.String())
	}

	// 3. POST issue works without Content-Type (bodyless request)
	reqIssue := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates/"+certStr+"/issue", nil)
	wIssue := httptest.NewRecorder()
	r.ServeHTTP(wIssue, reqIssue)
	if wIssue.Code != http.StatusOK {
		t.Errorf("POST issue failed without Content-Type, got code %d: %s", wIssue.Code, wIssue.Body.String())
	}

	// 4. Multipart upload works with multipart/form-data (without application/json)
	draftUploadID := StringToUUID("20000000-0000-0000-0000-000000000088")
	repo.AddCertificate(db.Certificate{
		ID:             draftUploadID,
		PublicID:       "TD-CERT-UP-1",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	part, _ := writer.CreateFormFile("file", "upload.pdf")
	_, _ = part.Write([]byte("%PDF-1.4\nuploaded content"))
	writer.Close()

	reqUpload := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates/"+UUIDToString(draftUploadID)+"/file", bodyBuf)
	reqUpload.Header.Set("Content-Type", writer.FormDataContentType())
	wUpload := httptest.NewRecorder()
	r.ServeHTTP(wUpload, reqUpload)
	if wUpload.Code != http.StatusOK {
		t.Errorf("Multipart upload failed with form-data Content-Type, got code %d: %s", wUpload.Code, wUpload.Body.String())
	}

	// 5. JSON-body endpoints reject incorrect Content-Type (e.g. text/plain or missing)
	// CreateDraft
	reqBadCreate := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates", strings.NewReader(`{}`))
	reqBadCreate.Header.Set("Content-Type", "text/plain")
	wBadCreate := httptest.NewRecorder()
	r.ServeHTTP(wBadCreate, reqBadCreate)
	if wBadCreate.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for CreateDraft without application/json, got %d", wBadCreate.Code)
	}

	// UpdateDraft
	reqBadPatch := httptest.NewRequest(http.MethodPatch, "/api/v1/organizations/"+orgStr+"/certificates/"+certStr, strings.NewReader(`{}`))
	reqBadPatch.Header.Set("Content-Type", "text/plain")
	wBadPatch := httptest.NewRecorder()
	r.ServeHTTP(wBadPatch, reqBadPatch)
	if wBadPatch.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for UpdateDraft without application/json, got %d", wBadPatch.Code)
	}

	// Revoke
	reqBadRevoke := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates/"+certStr+"/revoke", strings.NewReader(`{}`))
	reqBadRevoke.Header.Set("Content-Type", "text/plain")
	wBadRevoke := httptest.NewRecorder()
	r.ServeHTTP(wBadRevoke, reqBadRevoke)
	if wBadRevoke.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for Revoke without application/json, got %d", wBadRevoke.Code)
	}

	// Replace
	reqBadReplace := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgStr+"/certificates/"+certStr+"/replace", strings.NewReader(`{}`))
	reqBadReplace.Header.Set("Content-Type", "text/plain")
	wBadReplace := httptest.NewRecorder()
	r.ServeHTTP(wBadReplace, reqBadReplace)
	if wBadReplace.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for Replace without application/json, got %d", wBadReplace.Code)
	}

	// 6. Verify single response write on all endpoints (no duplicate headers or writes)
	recorders := []*httptest.ResponseRecorder{wGet, wDel, wIssue, wUpload, wBadCreate, wBadPatch, wBadRevoke, wBadReplace}
	for i, rec := range recorders {
		if rec.Flushed {
			t.Errorf("recorder %d prematurely flushed", i)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Errorf("recorder %d response is not valid single JSON payload: %s", i, rec.Body.String())
		}
	}
}

func TestHandler_UploadBoundary_Audit(t *testing.T) {
	repo := NewMockRepository()
	mockStorage := storage.NewMockStorage()
	maxSize := int64(1000) // Configured 1000-byte test maximum
	svc := NewService(repo, mockStorage, maxSize, 5*time.Minute, nil)
	svc.SetSleeper(func(d time.Duration) {})
	h := NewHandler(svc)

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-LIMIT-1",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: actorID})
		c.Next()
	})
	r.POST("/organizations/:organization_id/certificates/:certificate_id/file", h.UploadCertificateFile)

	targetURL := "/organizations/" + UUIDToString(orgID) + "/certificates/" + UUIDToString(certID) + "/file"

	// 1. Exactly maximum-sized valid PDF (1000 bytes) accepted
	exactBytes := make([]byte, maxSize)
	copy(exactBytes, "%PDF-1.4\n")
	copy(exactBytes[len(exactBytes)-6:], "\n%%EOF")

	buf1 := &bytes.Buffer{}
	w1 := multipart.NewWriter(buf1)
	part1, _ := w1.CreateFormFile("file", "exact.pdf")
	_, _ = part1.Write(exactBytes)
	w1.Close()

	req1 := httptest.NewRequest(http.MethodPost, targetURL, buf1)
	req1.Header.Set("Content-Type", w1.FormDataContentType())
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200 OK for exactly maximum-sized PDF, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// 2. Exactly one byte over maximum (1001 bytes) rejected with 413
	overBytes := make([]byte, maxSize+1)
	copy(overBytes, "%PDF-1.4\n")
	copy(overBytes[len(overBytes)-6:], "\n%%EOF")

	buf2 := &bytes.Buffer{}
	w2 := multipart.NewWriter(buf2)
	part2, _ := w2.CreateFormFile("file", "over.pdf")
	_, _ = part2.Write(overBytes)
	w2.Close()

	req2 := httptest.NewRequest(http.MethodPost, targetURL, buf2)
	req2.Header.Set("Content-Type", w2.FormDataContentType())
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Request Entity Too Large for max+1 bytes, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// 3. Multipart request overhead does not count as PDF bytes:
	// Total request is ~1300 bytes (1000 byte PDF + ~300 bytes of headers/fields), PDF is exactly 1000 bytes.
	buf3 := &bytes.Buffer{}
	w3 := multipart.NewWriter(buf3)
	_ = w3.WriteField("extra_header", strings.Repeat("A", 200))
	part3, _ := w3.CreateFormFile("file", "with_overhead.pdf")
	_, _ = part3.Write(exactBytes)
	w3.Close()

	req3 := httptest.NewRequest(http.MethodPost, targetURL, buf3)
	req3.Header.Set("Content-Type", w3.FormDataContentType())
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 OK when multipart overhead is present but PDF <= max, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// 4a. Oversized non-file multipart fields exceeding envelope allowance independently (tested with small PDF):
	// Even though total serialized body (~66,000 bytes) is below handler total cap (maxSize + MultipartEnvelopeAllowance = 66,536 bytes),
	// non-file fields independently exceed MultipartEnvelopeAllowance (65,536 bytes) and must be rejected with 413.
	buf4a := &bytes.Buffer{}
	w4a := multipart.NewWriter(buf4a)
	_ = w4a.WriteField("huge_field", strings.Repeat("X", int(MultipartEnvelopeAllowance+100)))
	part4a, _ := w4a.CreateFormFile("file", "small.pdf")
	_, _ = part4a.Write([]byte("%PDF-1.4\n%%EOF"))
	w4a.Close()

	req4a := httptest.NewRequest(http.MethodPost, targetURL, buf4a)
	req4a.Header.Set("Content-Type", w4a.FormDataContentType())
	rec4a := httptest.NewRecorder()
	r.ServeHTTP(rec4a, req4a)
	if rec4a.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 when non-file multipart fields exceed envelope allowance, got %d: %s", rec4a.Code, rec4a.Body.String())
	}

	// 4b. Serialized multipart request genuinely exceeding handler total cap (maxSize + MultipartEnvelopeAllowance):
	// Combines maximum-sized PDF (1000 bytes) with non-file fields/overhead exceeding allowance.
	buf4b := &bytes.Buffer{}
	w4b := multipart.NewWriter(buf4b)
	_ = w4b.WriteField("huge_field", strings.Repeat("X", int(MultipartEnvelopeAllowance+100)))
	part4b, _ := w4b.CreateFormFile("file", "exact.pdf")
	_, _ = part4b.Write(exactBytes)
	w4b.Close()

	if int64(buf4b.Len()) <= maxSize+MultipartEnvelopeAllowance {
		t.Fatalf("constructed body length %d must exceed total cap %d", buf4b.Len(), maxSize+MultipartEnvelopeAllowance)
	}

	req4b := httptest.NewRequest(http.MethodPost, targetURL, buf4b)
	req4b.Header.Set("Content-Type", w4b.FormDataContentType())
	rec4b := httptest.NewRecorder()
	r.ServeHTTP(rec4b, req4b)
	if rec4b.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 when total multipart request exceeds total cap, got %d: %s", rec4b.Code, rec4b.Body.String())
	}

	// 5. Truncated multipart body returns 400 Bad Request
	truncatedBody := bytes.NewReader([]byte("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"trunc.pdf\"\r\n\r\n%PDF-1.4"))
	req5 := httptest.NewRequest(http.MethodPost, targetURL, truncatedBody)
	req5.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	rec5 := httptest.NewRecorder()
	r.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for truncated multipart body, got %d: %s", rec5.Code, rec5.Body.String())
	}
}

func TestHandler_IssueCertificate_StatusConflicts(t *testing.T) {
	h, repo, _ := setupTestHandler()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-ISSUE00000001",
		OrganizationID: orgID,
		Status:         "DRAFT",
		FileStorageKey: pgtype.Text{String: "certificates/org/cert/test.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Valid: true},
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: actorID})
		c.Next()
	})
	r.POST("/organizations/:organization_id/certificates/:certificate_id/issue", h.IssueCertificate)

	// 1. DRAFT -> ISSUED: returns 200 OK
	url := "/organizations/" + UUIDToString(orgID) + "/certificates/" + UUIDToString(certID) + "/issue"
	req1 := httptest.NewRequest(http.MethodPost, url, nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid issuance, got %d: %s", w1.Code, w1.Body.String())
	}

	// 2. ISSUED -> issue: returns 409 Conflict
	req2 := httptest.NewRequest(http.MethodPost, url, nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for re-issuance of ISSUED certificate, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. REVOKED -> issue: returns 409 Conflict
	revokedCertID := StringToUUID("20000000-0000-0000-0000-000000000002")
	repo.AddCertificate(db.Certificate{
		ID:             revokedCertID,
		PublicID:       "TD-CERT-REVOKED0000000001",
		OrganizationID: orgID,
		Status:         "REVOKED",
		FileStorageKey: pgtype.Text{String: "key2.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "hash2", Valid: true},
	})
	urlRevoked := "/organizations/" + UUIDToString(orgID) + "/certificates/" + UUIDToString(revokedCertID) + "/issue"
	req3 := httptest.NewRequest(http.MethodPost, urlRevoked, nil)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for issuance of REVOKED certificate, got %d: %s", w3.Code, w3.Body.String())
	}

	// 4. REPLACED -> issue: returns 409 Conflict
	replacedCertID := StringToUUID("20000000-0000-0000-0000-000000000003")
	repo.AddCertificate(db.Certificate{
		ID:             replacedCertID,
		PublicID:       "TD-CERT-REPLACED000000001",
		OrganizationID: orgID,
		Status:         "REPLACED",
		FileStorageKey: pgtype.Text{String: "key3.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "hash3", Valid: true},
	})
	urlReplaced := "/organizations/" + UUIDToString(orgID) + "/certificates/" + UUIDToString(replacedCertID) + "/issue"
	req4 := httptest.NewRequest(http.MethodPost, urlReplaced, nil)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for issuance of REPLACED certificate, got %d: %s", w4.Code, w4.Body.String())
	}

	// 5. Malformed input (invalid UUID): returns 400 Bad Request
	urlBad := "/organizations/invalid-org-uuid/certificates/" + UUIDToString(certID) + "/issue"
	req5 := httptest.NewRequest(http.MethodPost, urlBad, nil)
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, req5)
	if w5.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for malformed UUID, got %d: %s", w5.Code, w5.Body.String())
	}
}

func TestHandler_DownloadCertificate_Policies(t *testing.T) {
	h, repo, mockStorage := setupTestHandler()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	issuerID := StringToUUID("10000000-0000-0000-0000-000000000002")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000003")

	certKey := "certificates/org/cert/hash.pdf"
	_ = mockStorage.PutObject(ctx, certKey, strings.NewReader("sample pdf"), 10, "application/pdf")

	// 1. REVOKED certificate
	revokedID := StringToUUID("20000000-0000-0000-0000-000000000001")
	repo.AddCertificate(db.Certificate{
		ID:                   revokedID,
		PublicID:             "TD-CERT-REVOKED0000000001",
		OrganizationID:       orgID,
		RecipientUserID:      studentID,
		Status:               "REVOKED",
		FileStorageKey:       pgtype.Text{String: certKey, Valid: true},
		FileName:             pgtype.Text{String: "revoked.pdf", Valid: true},
		RevocationReasonCode: pgtype.Text{String: "ACADEMIC_MISCONDUCT", Valid: true},
		RevokedAt:            pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	})

	// 2. REPLACED certificate with replacement draft
	replacementID := StringToUUID("20000000-0000-0000-0000-000000000003")
	replacementPubID := "TD-CERT-REPLACE0000000001"
	repo.AddCertificate(db.Certificate{
		ID:              replacementID,
		PublicID:        replacementPubID,
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "ISSUED",
		FileStorageKey:  pgtype.Text{String: certKey, Valid: true},
	})

	replacedID := StringToUUID("20000000-0000-0000-0000-000000000002")
	repo.AddCertificate(db.Certificate{
		ID:                      replacedID,
		PublicID:                "TD-CERT-REPLACED000000001",
		OrganizationID:          orgID,
		RecipientUserID:         studentID,
		Status:                  "REPLACED",
		FileStorageKey:          pgtype.Text{String: certKey, Valid: true},
		FileName:                pgtype.Text{String: "replaced.pdf", Valid: true},
		RevocationReasonCode:    pgtype.Text{String: "ADMINISTRATIVE_CORRECTION", Valid: true},
		RevokedAt:               pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		ReplacedByCertificateID: replacementID,
	})

	r := gin.New()
	var currentActor pgtype.UUID
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: currentActor})
		c.Next()
	})
	r.GET("/certificates/:certificate_id/download", h.DownloadCertificate)

	// A. Student download REVOKED -> returns 410 Gone with status metadata
	currentActor = studentID
	reqRev := httptest.NewRequest(http.MethodGet, "/certificates/"+UUIDToString(revokedID)+"/download", nil)
	wRev := httptest.NewRecorder()
	r.ServeHTTP(wRev, reqRev)
	if wRev.Code != http.StatusGone {
		t.Errorf("expected 410 Gone for student download of REVOKED, got %d: %s", wRev.Code, wRev.Body.String())
	}
	if wRev.Header().Get("X-Certificate-Status") != "REVOKED" {
		t.Errorf("expected X-Certificate-Status REVOKED, got %s", wRev.Header().Get("X-Certificate-Status"))
	}

	// B. Student download REPLACED -> returns 410 Gone with replaced_by_public_id metadata
	reqRep := httptest.NewRequest(http.MethodGet, "/certificates/"+UUIDToString(replacedID)+"/download", nil)
	wRep := httptest.NewRecorder()
	r.ServeHTTP(wRep, reqRep)
	if wRep.Code != http.StatusGone {
		t.Errorf("expected 410 Gone for student download of REPLACED, got %d: %s", wRep.Code, wRep.Body.String())
	}
	if wRep.Header().Get("X-Certificate-Status") != "REPLACED" {
		t.Errorf("expected X-Certificate-Status REPLACED, got %s", wRep.Header().Get("X-Certificate-Status"))
	}
	var repBody struct {
		Success bool `json:"success"`
		Error   struct {
			Code    string                            `json:"code"`
			Details CertificateStatusMetadataResponse `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(wRep.Body.Bytes(), &repBody); err != nil {
		t.Fatalf("failed to decode 410 response: %v", err)
	}
	if repBody.Error.Details.ReplacedByPublicID == nil || *repBody.Error.Details.ReplacedByPublicID != replacementPubID {
		t.Errorf("expected replaced_by_public_id %s, got %v", replacementPubID, repBody.Error.Details.ReplacedByPublicID)
	}

	// C. Issuer audit download REVOKED -> returns 200 OK with presigned URL
	currentActor = issuerID
	reqIssuerRev := httptest.NewRequest(http.MethodGet, "/certificates/"+UUIDToString(revokedID)+"/download?organization_id="+UUIDToString(orgID), nil)
	wIssuerRev := httptest.NewRecorder()
	r.ServeHTTP(wIssuerRev, reqIssuerRev)
	if wIssuerRev.Code != http.StatusOK {
		t.Errorf("expected 200 OK for issuer audit download of REVOKED, got %d: %s", wIssuerRev.Code, wIssuerRev.Body.String())
	}
	if wIssuerRev.Header().Get("X-Certificate-Status") != "REVOKED" {
		t.Errorf("expected X-Certificate-Status REVOKED on issuer download")
	}

	// D. Issuer audit download REPLACED -> returns 200 OK with presigned URL
	reqIssuerRep := httptest.NewRequest(http.MethodGet, "/certificates/"+UUIDToString(replacedID)+"/download?organization_id="+UUIDToString(orgID), nil)
	wIssuerRep := httptest.NewRecorder()
	r.ServeHTTP(wIssuerRep, reqIssuerRep)
	if wIssuerRep.Code != http.StatusOK {
		t.Errorf("expected 200 OK for issuer audit download of REPLACED, got %d: %s", wIssuerRep.Code, wIssuerRep.Body.String())
	}
	if wIssuerRep.Header().Get("X-Certificate-Status") != "REPLACED" {
		t.Errorf("expected X-Certificate-Status REPLACED on issuer download")
	}

	// E. Malformed UUID input -> returns 400 Bad Request
	reqBad := httptest.NewRequest(http.MethodGet, "/certificates/not-a-valid-uuid/download", nil)
	wBad := httptest.NewRecorder()
	r.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for malformed certificate ID, got %d: %s", wBad.Code, wBad.Body.String())
	}
}
