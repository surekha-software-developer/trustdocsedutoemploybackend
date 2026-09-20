package certificates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

func setupTestService() (*Service, *MockRepository, *storage.MockStorage) {
	repo := NewMockRepository()
	mockStorage := storage.NewMockStorage()
	svc := NewService(repo, mockStorage, 10485760, 5*time.Minute, nil)
	// Inject zero-delay sleeper for tests
	svc.SetSleeper(func(d time.Duration) {})
	return svc, repo, mockStorage
}

func TestService_CreateDraft(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000003")

	repo.AddUser(db.User{
		ID:       studentID,
		Email:    "alice@student.edu",
		FullName: "Alice Student",
	})

	// 1. Success
	req := CreateCertificateDraftRequest{
		RecipientUserID: UUIDToString(studentID),
		RecipientName:   "Alice Student",
		RecipientEmail:  "alice@student.edu",
		Title:           "Bachelor of Science",
		DegreeType:      "BACHELOR",
		GraduationDate:  "2026-05-15",
		IssueDate:       "2026-05-20",
	}

	resp, err := svc.CreateDraft(ctx, orgID, actorID, req)
	if err != nil {
		t.Fatalf("expected create draft to succeed, got: %v", err)
	}
	if resp.Status != "DRAFT" {
		t.Errorf("expected status DRAFT, got %s", resp.Status)
	}
	if !strings.HasPrefix(resp.PublicID, "TD-CERT-") {
		t.Errorf("expected public ID with prefix TD-CERT-, got %s", resp.PublicID)
	}

	// 2. Recipient email mismatch
	reqBadEmail := req
	reqBadEmail.RecipientEmail = "different@student.edu"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqBadEmail)
	if err == nil {
		t.Fatalf("expected error for recipient email mismatch, got nil")
	}

	// 3. Non-existent recipient
	reqBadUser := req
	reqBadUser.RecipientUserID = "99999999-9999-9999-9999-999999999999"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqBadUser)
	if err == nil {
		t.Fatalf("expected error for non-existent recipient, got nil")
	}
}

func TestService_CreateDraft_DateValidation(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	fixedNow := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return fixedNow })

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000003")

	repo.AddUser(db.User{
		ID:       studentID,
		Email:    "alice@student.edu",
		FullName: "Alice Student",
	})

	baseReq := CreateCertificateDraftRequest{
		RecipientUserID: UUIDToString(studentID),
		RecipientName:   "Alice Student",
		RecipientEmail:  "alice@student.edu",
		Title:           "Bachelor of Science",
		DegreeType:      "BACHELOR",
	}

	// 1. Today accepted
	reqToday := baseReq
	reqToday.GraduationDate = "2026-09-01"
	reqToday.IssueDate = "2026-09-20"
	resp, err := svc.CreateDraft(ctx, orgID, actorID, reqToday)
	if err != nil {
		t.Fatalf("expected today issue date to be accepted, got: %v", err)
	}
	if resp.IssueDate != "2026-09-20" {
		t.Errorf("expected issue date 2026-09-20, got %s", resp.IssueDate)
	}

	// 2. Past accepted when academic ordering is valid
	reqPast := baseReq
	reqPast.GraduationDate = "2026-05-15"
	reqPast.IssueDate = "2026-05-20"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqPast)
	if err != nil {
		t.Fatalf("expected past valid academic dates to be accepted, got: %v", err)
	}

	// 3. Tomorrow rejected
	reqTomorrow := baseReq
	reqTomorrow.GraduationDate = "2026-09-01"
	reqTomorrow.IssueDate = "2026-09-21"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqTomorrow)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeFutureIssueDate {
		t.Fatalf("expected ErrCodeFutureIssueDate for tomorrow, got: %v", err)
	}

	// 4. Far-future rejected
	reqFarFuture := baseReq
	reqFarFuture.GraduationDate = "2026-09-01"
	reqFarFuture.IssueDate = "2026-11-20"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqFarFuture)
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeFutureIssueDate {
		t.Fatalf("expected ErrCodeFutureIssueDate for far future, got: %v", err)
	}

	// 5. Graduation date after issue date rejected
	reqGradAfterIssue := baseReq
	reqGradAfterIssue.GraduationDate = "2026-09-15"
	reqGradAfterIssue.IssueDate = "2026-09-10"
	_, err = svc.CreateDraft(ctx, orgID, actorID, reqGradAfterIssue)
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeInvalidAcademicDates {
		t.Fatalf("expected ErrCodeInvalidAcademicDates for graduation_date > issue_date, got: %v", err)
	}
}

func TestService_UpdateDraft_DateValidation(t *testing.T) {
	fixedNow := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")

	todayStr := "2026-09-20"
	pastStr := "2026-06-01"
	tomorrowStr := "2026-09-21"
	farFutureStr := "2026-12-01"
	gradStr := "2026-08-01"
	issueStr := "2026-07-01"

	tests := []struct {
		name              string
		initialGradDate   time.Time
		initialIssueDate  time.Time
		req               UpdateCertificateDraftRequest
		expectedErrCode   string
		expectedIssueDate string
	}{
		{
			name:              "today accepted",
			initialGradDate:   time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
			initialIssueDate:  time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			req:               UpdateCertificateDraftRequest{IssueDate: &todayStr},
			expectedIssueDate: "2026-09-20",
		},
		{
			name:              "past accepted",
			initialGradDate:   time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
			initialIssueDate:  time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			req:               UpdateCertificateDraftRequest{IssueDate: &pastStr},
			expectedIssueDate: "2026-06-01",
		},
		{
			name:             "tomorrow rejected",
			initialGradDate:  time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
			initialIssueDate: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			req:              UpdateCertificateDraftRequest{IssueDate: &tomorrowStr},
			expectedErrCode:  core.ErrCodeFutureIssueDate,
		},
		{
			name:             "far future rejected",
			initialGradDate:  time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
			initialIssueDate: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			req:              UpdateCertificateDraftRequest{IssueDate: &farFutureStr},
			expectedErrCode:  core.ErrCodeFutureIssueDate,
		},
		{
			name:             "graduation date after issue date rejected",
			initialGradDate:  time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
			initialIssueDate: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			req: UpdateCertificateDraftRequest{
				GraduationDate: &gradStr,
				IssueDate:      &issueStr,
			},
			expectedErrCode: core.ErrCodeInvalidAcademicDates,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, _ := setupTestService()
			svc.SetNowFunc(func() time.Time { return fixedNow })
			ctx := context.Background()

			certID := StringToUUID("20000000-0000-0000-0000-000000000001")
			repo.AddCertificate(db.Certificate{
				ID:             certID,
				PublicID:       "TD-CERT-1111222233334444",
				OrganizationID: orgID,
				Status:         "DRAFT",
				GraduationDate: pgtype.Date{Time: tc.initialGradDate, Valid: true},
				IssueDate:      pgtype.Date{Time: tc.initialIssueDate, Valid: true},
			})

			resp, err := svc.UpdateDraft(ctx, certID, orgID, actorID, tc.req)
			if tc.expectedErrCode != "" {
				if err == nil {
					t.Fatalf("expected error %s, got nil", tc.expectedErrCode)
				}
				var appErr *core.AppError
				if !errors.As(err, &appErr) || appErr.Code != tc.expectedErrCode {
					t.Fatalf("expected error code %s, got: %v", tc.expectedErrCode, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if tc.expectedIssueDate != "" && resp.IssueDate != tc.expectedIssueDate {
					t.Errorf("expected issue date %s, got %s", tc.expectedIssueDate, resp.IssueDate)
				}
			}
		})
	}
}

func TestService_UploadCertificateFile(t *testing.T) {
	svc, repo, mockStorage := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-1111222233334444",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})

	validPDF := []byte("%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

	// 1. Success upload
	resp, err := svc.UploadCertificateFile(ctx, certID, orgID, actorID, "diploma.pdf", bytes.NewReader(validPDF), int64(len(validPDF)), "application/pdf")
	if err != nil {
		t.Fatalf("expected upload to succeed, got: %v", err)
	}
	if resp.FileStorageKey == nil || !strings.HasPrefix(*resp.FileStorageKey, "certificates/") {
		t.Errorf("expected valid storage key, got %v", resp.FileStorageKey)
	}
	if resp.DocumentHash == nil || len(*resp.DocumentHash) != 64 {
		t.Errorf("expected 64-char hex document hash, got %v", resp.DocumentHash)
	}

	// Verify object exists in storage
	if !mockStorage.HasObject(*resp.FileStorageKey) {
		t.Fatalf("expected object to exist in mock storage at key %s", *resp.FileStorageKey)
	}

	// 2. Invalid magic bytes
	invalidPDF := []byte("%PNG-1.2 not a pdf file")
	_, err = svc.UploadCertificateFile(ctx, certID, orgID, actorID, "fake.pdf", bytes.NewReader(invalidPDF), int64(len(invalidPDF)), "application/pdf")
	if err == nil {
		t.Fatalf("expected error for invalid magic bytes, got nil")
	}

	// 3. Oversized upload (>10 MiB)
	oversized := make([]byte, 10485761)
	copy(oversized[:5], "%PDF-")
	_, err = svc.UploadCertificateFile(ctx, certID, orgID, actorID, "huge.pdf", bytes.NewReader(oversized), int64(len(oversized)), "application/pdf")
	if err == nil {
		t.Fatalf("expected error for oversized file, got nil")
	}

	// 4. Empty upload
	_, err = svc.UploadCertificateFile(ctx, certID, orgID, actorID, "empty.pdf", bytes.NewReader([]byte{}), 0, "application/pdf")
	if err == nil {
		t.Fatalf("expected error for empty file, got nil")
	}
}

func TestService_UploadCompensationOnDBFailure(t *testing.T) {
	svc, repo, mockStorage := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-1111222233334444",
		OrganizationID: orgID,
		Status:         "DRAFT",
	})

	validPDF := []byte("%PDF-1.4 valid pdf content")

	// Inject DB Attach failure
	repo.FailAttachTx = errors.New("simulated DB disk failure")

	deleteCalled := false
	prevDeleteCount := mockStorage.DeleteCount

	_, err := svc.UploadCertificateFile(ctx, certID, orgID, actorID, "doc.pdf", bytes.NewReader(validPDF), int64(len(validPDF)), "application/pdf")
	if err == nil {
		t.Fatalf("expected error from DB attach failure, got nil")
	}

	if mockStorage.DeleteCount > prevDeleteCount {
		deleteCalled = true
	}

	if !deleteCalled {
		t.Fatalf("expected compensation DeleteObject to be called on storage when DB attach fails")
	}
}

func TestService_IssueCertificate(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	// 1. Missing file -> issue must fail
	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-1111222233334444",
		OrganizationID: orgID,
		Status:         "DRAFT",
		IssueDate:      pgtype.Date{Time: time.Now().Add(-24 * time.Hour), Valid: true},
	})

	_, err := svc.IssueCertificate(ctx, certID, orgID, actorID)
	if err == nil {
		t.Fatalf("expected error when certificate has no attached file, got nil")
	}

	// 2. Attach file and retry -> succeeds
	cert := repo.certificates[UUIDToString(certID)]
	cert.FileStorageKey = pgtype.Text{String: "certificates/org/cert/hash.pdf", Valid: true}
	cert.DocumentHash = pgtype.Text{String: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Valid: true}
	repo.certificates[UUIDToString(certID)] = cert

	resp, err := svc.IssueCertificate(ctx, certID, orgID, actorID)
	if err != nil {
		t.Fatalf("expected issue to succeed, got: %v", err)
	}
	if resp.Status != "ISSUED" {
		t.Errorf("expected status ISSUED, got %s", resp.Status)
	}

	// 3. Issue already issued -> conflict (ISSUED -> issue conflict)
	_, err = svc.IssueCertificate(ctx, certID, orgID, actorID)
	if err == nil {
		t.Fatalf("expected error when re-issuing already issued certificate, got nil")
	}
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeCertificateAlreadyIssued {
		t.Errorf("expected ErrCodeCertificateAlreadyIssued, got %v", err)
	}

	// 4. Issue revoked certificate -> conflict (REVOKED -> issue conflict)
	revokedCertID := StringToUUID("20000000-0000-0000-0000-000000000002")
	repo.AddCertificate(db.Certificate{
		ID:             revokedCertID,
		PublicID:       "TD-CERT-1111222233334445",
		OrganizationID: orgID,
		Status:         "REVOKED",
		FileStorageKey: pgtype.Text{String: "key.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "hash2", Valid: true},
	})
	_, err = svc.IssueCertificate(ctx, revokedCertID, orgID, actorID)
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeCertificateStateConflict {
		t.Errorf("expected ErrCodeCertificateStateConflict, got %v", err)
	}

	// 5. Issue replaced certificate -> conflict (REPLACED -> issue conflict)
	replacedCertID := StringToUUID("20000000-0000-0000-0000-000000000003")
	repo.AddCertificate(db.Certificate{
		ID:             replacedCertID,
		PublicID:       "TD-CERT-1111222233334446",
		OrganizationID: orgID,
		Status:         "REPLACED",
		FileStorageKey: pgtype.Text{String: "key3.pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: "hash3", Valid: true},
	})
	_, err = svc.IssueCertificate(ctx, replacedCertID, orgID, actorID)
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeCertificateStateConflict {
		t.Errorf("expected ErrCodeCertificateStateConflict, got %v", err)
	}
}

func TestService_RevokeCertificate(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-1111222233334444",
		OrganizationID: orgID,
		Status:         "ISSUED",
		FileStorageKey: pgtype.Text{String: "key", Valid: true},
		DocumentHash:   pgtype.Text{String: "hash", Valid: true},
	})

	// 1. Invalid reason code
	reqBad := RevokeCertificateRequest{
		ReasonCode: "INVALID_REASON",
		Reason:     "Discovered issue.",
	}
	_, err := svc.RevokeCertificate(ctx, certID, orgID, actorID, reqBad)
	if err == nil {
		t.Fatalf("expected error for invalid reason code, got nil")
	}

	// 2. Valid revocation
	reqGood := RevokeCertificateRequest{
		ReasonCode: RevocationReasonAcademicMisconduct,
		Reason:     "Confirmed student misconduct in thesis.",
	}
	resp, err := svc.RevokeCertificate(ctx, certID, orgID, actorID, reqGood)
	if err != nil {
		t.Fatalf("expected revoke to succeed, got: %v", err)
	}
	if resp.Status != "REVOKED" {
		t.Errorf("expected status REVOKED, got %s", resp.Status)
	}

	// 3. Re-revocation fails
	_, err = svc.RevokeCertificate(ctx, certID, orgID, actorID, reqGood)
	if err == nil {
		t.Fatalf("expected error when revoking already revoked certificate, got nil")
	}
}

func TestService_ReplaceCertificate(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000003")

	oldCertID := StringToUUID("20000000-0000-0000-0000-000000000001")
	newCertID := StringToUUID("20000000-0000-0000-0000-000000000002")

	repo.AddCertificate(db.Certificate{
		ID:              oldCertID,
		PublicID:        "TD-CERT-OLD11111111",
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "ISSUED",
		DocumentHash:    pgtype.Text{String: "1111111111111111111111111111111111111111111111111111111111111111", Valid: true},
		FileStorageKey:  pgtype.Text{String: "old-key", Valid: true},
	})

	repo.AddCertificate(db.Certificate{
		ID:              newCertID,
		PublicID:        "TD-CERT-NEW22222222",
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "DRAFT",
		DocumentHash:    pgtype.Text{String: "2222222222222222222222222222222222222222222222222222222222222222", Valid: true},
		FileStorageKey:  pgtype.Text{String: "new-key", Valid: true},
	})

	// 1. Success replacement
	req := ReplaceCertificateRequest{
		ReplacementCertificateID: UUIDToString(newCertID),
		ReasonCode:               RevocationReasonAdministrativeCorrection,
		Reason:                   "Corrected major title typo.",
	}

	oldResp, newResp, err := svc.ReplaceCertificate(ctx, oldCertID, orgID, actorID, req)
	if err != nil {
		t.Fatalf("expected replacement to succeed, got: %v", err)
	}
	if oldResp.Status != "REPLACED" {
		t.Errorf("expected old certificate status REPLACED, got %s", oldResp.Status)
	}
	if newResp.Status != "ISSUED" {
		t.Errorf("expected new certificate status ISSUED, got %s", newResp.Status)
	}
	if oldResp.ReplacedByCertificateID == nil || *oldResp.ReplacedByCertificateID != UUIDToString(newCertID) {
		t.Errorf("expected replaced_by_certificate_id to be set to newCertID")
	}
	if newResp.ReplacesCertificateID == nil || *newResp.ReplacesCertificateID != UUIDToString(oldCertID) {
		t.Errorf("expected replaces_certificate_id to be set to oldCertID")
	}

	// 2. Self-replacement rejection
	reqSelf := ReplaceCertificateRequest{
		ReplacementCertificateID: UUIDToString(oldCertID),
		ReasonCode:               RevocationReasonAdministrativeCorrection,
		Reason:                   "Self replacement test.",
	}
	_, _, err = svc.ReplaceCertificate(ctx, oldCertID, orgID, actorID, reqSelf)
	if err == nil {
		t.Fatalf("expected error for self replacement, got nil")
	}
}

func TestService_DownloadCertificatePolicy(t *testing.T) {
	svc, repo, mockStorage := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	studentID := StringToUUID("10000000-0000-0000-0000-000000000003")

	certKey := "certificates/org/cert/hash.pdf"
	mockStorage.PutObject(ctx, certKey, strings.NewReader("dummy pdf bytes"), 15, "application/pdf")

	// 1. DRAFT certificate
	draftID := StringToUUID("20000000-0000-0000-0000-000000000001")
	repo.AddCertificate(db.Certificate{
		ID:              draftID,
		PublicID:        "TD-CERT-DRAFT000000000001",
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "DRAFT",
		FileStorageKey:  pgtype.Text{String: certKey, Valid: true},
	})

	// Issuer can download draft preview
	resIssuer, err := svc.DownloadCertificate(ctx, draftID, actorID, true, &orgID)
	if err != nil {
		t.Fatalf("expected issuer to download draft, got: %v", err)
	}
	if resIssuer.PresignedURL == "" {
		t.Errorf("expected presigned URL for issuer draft download")
	}

	// Student receives 404 for draft
	_, err = svc.DownloadCertificate(ctx, draftID, studentID, false, nil)
	if err == nil {
		t.Fatalf("expected 404 error for student downloading draft, got nil")
	}

	// 2. ISSUED certificate
	issuedID := StringToUUID("20000000-0000-0000-0000-000000000002")
	repo.AddCertificate(db.Certificate{
		ID:              issuedID,
		PublicID:        "TD-CERT-ISSUED00000000001",
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "ISSUED",
		FileStorageKey:  pgtype.Text{String: certKey, Valid: true},
	})

	// Both issuer and student can download issued certificate
	resStudent, err := svc.DownloadCertificate(ctx, issuedID, studentID, false, nil)
	if err != nil {
		t.Fatalf("expected student to download issued certificate, got: %v", err)
	}
	if resStudent.PresignedURL == "" {
		t.Errorf("expected presigned URL for student issued download")
	}

	// 3. REVOKED certificate
	revokedID := StringToUUID("20000000-0000-0000-0000-000000000003")
	repo.AddCertificate(db.Certificate{
		ID:                   revokedID,
		PublicID:             "TD-CERT-REVOKED0000000001",
		OrganizationID:       orgID,
		RecipientUserID:      studentID,
		Status:               "REVOKED",
		FileStorageKey:       pgtype.Text{String: certKey, Valid: true},
		RevocationReasonCode: pgtype.Text{String: RevocationReasonIdentityFraud, Valid: true},
	})

	// Student is denied (receives DeniedResponse with status REVOKED)
	resRevStudent, err := svc.DownloadCertificate(ctx, revokedID, studentID, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resRevStudent.DeniedResponse == nil || resRevStudent.DeniedResponse.Status != "REVOKED" {
		t.Errorf("expected DeniedResponse with status REVOKED for student")
	}

	// Issuer audit access is allowed and contains header
	resRevIssuer, err := svc.DownloadCertificate(ctx, revokedID, actorID, true, &orgID)
	if err != nil {
		t.Fatalf("expected issuer audit download for revoked certificate, got: %v", err)
	}
	if resRevIssuer.Headers["X-Certificate-Status"] != "REVOKED" {
		t.Errorf("expected X-Certificate-Status header to be REVOKED")
	}

	// 4. REPLACED certificate with replacement certificate in repo
	replacedID := StringToUUID("20000000-0000-0000-0000-000000000004")
	replacementID := StringToUUID("20000000-0000-0000-0000-000000000005")
	replacementPubID := "TD-CERT-REPLACE0000000001"

	repo.AddCertificate(db.Certificate{
		ID:              replacementID,
		PublicID:        replacementPubID,
		OrganizationID:  orgID,
		RecipientUserID: studentID,
		Status:          "ISSUED",
		FileStorageKey:  pgtype.Text{String: certKey, Valid: true},
	})

	repo.AddCertificate(db.Certificate{
		ID:                      replacedID,
		PublicID:                "TD-CERT-REPLACED000000001",
		OrganizationID:          orgID,
		RecipientUserID:         studentID,
		Status:                  "REPLACED",
		FileStorageKey:          pgtype.Text{String: certKey, Valid: true},
		RevocationReasonCode:    pgtype.Text{String: RevocationReasonAdministrativeCorrection, Valid: true},
		ReplacedByCertificateID: replacementID,
	})

	// Student is denied (receives DeniedResponse with status REPLACED and replaced_by_public_id metadata)
	resRepStudent, err := svc.DownloadCertificate(ctx, replacedID, studentID, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resRepStudent.DeniedResponse == nil || resRepStudent.DeniedResponse.Status != "REPLACED" {
		t.Errorf("expected DeniedResponse with status REPLACED for student")
	}
	if resRepStudent.DeniedResponse.ReplacedByPublicID == nil || *resRepStudent.DeniedResponse.ReplacedByPublicID != replacementPubID {
		t.Errorf("expected ReplacedByPublicID %s, got %v", replacementPubID, resRepStudent.DeniedResponse.ReplacedByPublicID)
	}

	// Issuer audit access is allowed for REPLACED certificate
	resRepIssuer, err := svc.DownloadCertificate(ctx, replacedID, actorID, true, &orgID)
	if err != nil {
		t.Fatalf("expected issuer audit download for replaced certificate, got: %v", err)
	}
	if resRepIssuer.Headers["X-Certificate-Status"] != "REPLACED" {
		t.Errorf("expected X-Certificate-Status header to be REPLACED")
	}
	if resRepIssuer.PresignedURL == "" {
		t.Errorf("expected presigned URL for issuer replaced download")
	}

	// 5. Inconsistent replacement lineage -> returns ErrCodeInternal
	inconsistentID := StringToUUID("20000000-0000-0000-0000-000000000006")
	missingReplacementID := StringToUUID("20000000-0000-0000-0000-000000000007")
	repo.AddCertificate(db.Certificate{
		ID:                      inconsistentID,
		PublicID:                "TD-CERT-INCONSISTENT0001",
		OrganizationID:          orgID,
		RecipientUserID:         studentID,
		Status:                  "REPLACED",
		FileStorageKey:          pgtype.Text{String: certKey, Valid: true},
		ReplacedByCertificateID: missingReplacementID, // missing from repo
	})

	_, err = svc.DownloadCertificate(ctx, inconsistentID, studentID, false, nil)
	if err == nil {
		t.Fatalf("expected error for inconsistent replacement lineage, got nil")
	}
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeInternal {
		t.Errorf("expected ErrCodeInternal for inconsistent replacement lineage, got: %v", err)
	}
}

func TestService_VerifyPublicCertificate(t *testing.T) {
	svc, repo, _ := setupTestService()
	ctx := context.Background()

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	repo.AddOrganization(db.Organization{
		ID:             orgID,
		LegalName:      "State University",
		OfficialDomain: "state.edu",
		CountryCode:    "US",
	})

	certID := StringToUUID("20000000-0000-0000-0000-000000000001")
	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-PUB12345678",
		OrganizationID: orgID,
		Status:         "ISSUED",
		Title:          "Bachelor of Science in Engineering",
		DegreeType:     "BACHELOR",
		RecipientName:  "Jane Marie Doe",
		DocumentHash:   pgtype.Text{String: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Valid: true},
		GraduationDate: pgtype.Date{Time: time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC), Valid: true},
		IssueDate:      pgtype.Date{Time: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC), Valid: true},
	})

	// 1. Success verification
	pubResp, err := svc.VerifyPublicCertificate(ctx, "TD-CERT-PUB12345678")
	if err != nil {
		t.Fatalf("expected public verification to succeed, got: %v", err)
	}
	if pubResp.MaskedRecipientName != "J*** M**** D**" {
		t.Errorf("expected masked recipient name J*** M**** D**, got %s", pubResp.MaskedRecipientName)
	}
	if pubResp.IssuerOrganizationName != "State University" {
		t.Errorf("expected State University, got %s", pubResp.IssuerOrganizationName)
	}

	// 2. Non-existent public ID
	_, err = svc.VerifyPublicCertificate(ctx, "TD-CERT-NONEXISTENT")
	if err == nil {
		t.Fatalf("expected error for non-existent certificate, got nil")
	}
}

func TestService_BuildCertificateStorageKey(t *testing.T) {
	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	certID := StringToUUID("20000000-0000-0000-0000-000000000002")
	validHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// 1. Correct deterministic format and UUID canonical formatting
	key, err := BuildCertificateStorageKey(orgID, certID, validHash)
	if err != nil {
		t.Fatalf("expected valid key generation, got: %v", err)
	}
	expectedKey := "certificates/10000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000002/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.pdf"
	if key != expectedKey {
		t.Fatalf("expected key %q, got %q", expectedKey, key)
	}

	// 2. Lowercase SHA-256 requirement: uppercase must be rejected
	upperHash := strings.ToUpper(validHash)
	_, err = BuildCertificateStorageKey(orgID, certID, upperHash)
	if err == nil {
		t.Errorf("expected error for uppercase document hash, got nil")
	}

	// 3. Invalid hash length or non-hex characters rejected
	_, err = BuildCertificateStorageKey(orgID, certID, "short-hash")
	if err == nil {
		t.Errorf("expected error for short document hash, got nil")
	}
	nonHex := strings.Repeat("z", 64)
	_, err = BuildCertificateStorageKey(orgID, certID, nonHex)
	if err == nil {
		t.Errorf("expected error for non-hex document hash, got nil")
	}

	// 4. Invalid UUIDs rejected
	invalidUUID := pgtype.UUID{Valid: false}
	_, err = BuildCertificateStorageKey(invalidUUID, certID, validHash)
	if err == nil {
		t.Errorf("expected error for invalid organization UUID, got nil")
	}
	_, err = BuildCertificateStorageKey(orgID, invalidUUID, validHash)
	if err == nil {
		t.Errorf("expected error for invalid certificate UUID, got nil")
	}

	// 5. No recipient PII or original filename appears in the key
	piiElements := []string{"Jane", "Doe", "jane@example.com", "diploma.pdf", "student", "12345"}
	for _, pii := range piiElements {
		if strings.Contains(key, pii) {
			t.Errorf("storage key leaked PII or filename %q: %s", pii, key)
		}
	}

	// 6. Complete key is never returned in HTTP DTOs
	certResp := CertificateResponse{
		ID:             UUIDToString(certID),
		PublicID:       "TD-CERT-TEST",
		OrganizationID: UUIDToString(orgID),
		Title:          "Degree",
		FileStorageKey: &key,
	}
	data, err := json.Marshal(certResp)
	if err != nil {
		t.Fatalf("failed to marshal CertificateResponse: %v", err)
	}
	if strings.Contains(string(data), "file_storage_key") || strings.Contains(string(data), "certificates/") {
		t.Errorf("CertificateResponse JSON leaked internal storage key: %s", string(data))
	}
}

func TestService_PostCommitCleanup_Lifecycle(t *testing.T) {
	repo := NewMockRepository()
	mockStorage := storage.NewMockStorage()
	svc := NewService(repo, mockStorage, 10485760, 5*time.Minute, nil)

	var sleepCalls []time.Duration
	svc.SetSleeper(func(d time.Duration) {
		sleepCalls = append(sleepCalls, d)
	})

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")

	oldStorageKey := "certificates/10000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000001/oldhash11111111111111111111111111111111111111111111111111111111111.pdf"
	_ = mockStorage.PutObject(context.Background(), oldStorageKey, bytes.NewReader([]byte("%PDF-old")), 8, "application/pdf")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-OLD-FILE",
		OrganizationID: orgID,
		Status:         "DRAFT",
		FileStorageKey: pgtype.Text{String: oldStorageKey, Valid: true},
		DocumentHash:   pgtype.Text{String: "oldhash11111111111111111111111111111111111111111111111111111111111", Valid: true},
	})

	// 1. Re-uploading file to draft cleans up superseded object synchronously post-commit
	validPDF := []byte("%PDF-1.4\n%new file content\n%%EOF")
	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := svc.UploadCertificateFile(reqCtx, certID, orgID, actorID, "new.pdf", bytes.NewReader(validPDF), int64(len(validPDF)), "application/pdf")
	if err != nil {
		t.Fatalf("expected upload to succeed, got: %v", err)
	}

	// Old file must be purged from mock storage
	if mockStorage.HasObject(oldStorageKey) {
		t.Errorf("expected old storage key to be deleted post-commit")
	}
	// New file must exist
	if resp.DocumentHash == nil {
		t.Fatalf("expected document hash on response")
	}

	// 2. Cleanup uses its own dedicated context:
	// Verify cleanup completes independently of caller request lifecycle
	oldStorageKey2 := "certificates/10000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000001/oldhash22222222222222222222222222222222222222222222222222222222222.pdf"
	_ = mockStorage.PutObject(context.Background(), oldStorageKey2, bytes.NewReader([]byte("%PDF-old2")), 9, "application/pdf")

	c2 := repo.certificates[UUIDToString(certID)]
	c2.FileStorageKey = pgtype.Text{String: oldStorageKey2, Valid: true}
	repo.certificates[UUIDToString(certID)] = c2

	// cleanupStorageObjectWithRetry uses its own dedicated context, so it succeeds despite any external lifecycle
	svc.cleanupStorageObjectWithRetry(oldStorageKey2, certID, orgID)
	if mockStorage.HasObject(oldStorageKey2) {
		t.Errorf("expected old object to be deleted using independent bounded context")
	}

	// 3. Retry count and sleeper invocations on storage deletion failure
	failKey := "certificates/10000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000001/failkey33333333333333333333333333333333333333333333333333333333333.pdf"
	mockStorage.FailDelete = errors.New("simulated R2 503 Service Unavailable")
	sleepCalls = nil

	svc.cleanupStorageObjectWithRetry(failKey, certID, orgID)

	// Exactly 3 attempts with 2 sleep intervals (100ms, 200ms)
	if len(sleepCalls) != 2 {
		t.Errorf("expected exactly 2 retry sleep calls, got %d", len(sleepCalls))
	}
	mockStorage.FailDelete = nil

	// 4. No cleanup before commit: when DB attach fails, old file is NOT purged
	_ = mockStorage.PutObject(context.Background(), oldStorageKey, bytes.NewReader([]byte("%PDF-old")), 8, "application/pdf")
	c3 := repo.certificates[UUIDToString(certID)]
	c3.FileStorageKey = pgtype.Text{String: oldStorageKey, Valid: true}
	repo.certificates[UUIDToString(certID)] = c3

	repo.FailAttachTx = errors.New("simulated DB constraint failure")
	_, err = svc.UploadCertificateFile(context.Background(), certID, orgID, actorID, "fail.pdf", bytes.NewReader(validPDF), int64(len(validPDF)), "application/pdf")
	if err == nil {
		t.Fatalf("expected upload to fail on DB error, got nil")
	}
	// Old file must still be present because commit failed
	if !mockStorage.HasObject(oldStorageKey) {
		t.Errorf("old storage key was deleted before DB commit succeeded")
	}
	repo.FailAttachTx = nil
}

func TestService_DraftSoftDeletion_Semantics(t *testing.T) {
	repo := NewMockRepository()
	mockStorage := storage.NewMockStorage()
	svc := NewService(repo, mockStorage, 10485760, 5*time.Minute, nil)

	orgID := StringToUUID("10000000-0000-0000-0000-000000000001")
	otherOrgID := StringToUUID("10000000-0000-0000-0000-000000000099")
	actorID := StringToUUID("10000000-0000-0000-0000-000000000002")
	certID := StringToUUID("20000000-0000-0000-0000-000000000001")
	issuedCertID := StringToUUID("20000000-0000-0000-0000-000000000002")

	storageKey := "certificates/10000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000001/draftfile111111111111111111111111111111111111111111111111111111111.pdf"
	_ = mockStorage.PutObject(context.Background(), storageKey, bytes.NewReader([]byte("%PDF-draft")), 10, "application/pdf")

	repo.AddCertificate(db.Certificate{
		ID:             certID,
		PublicID:       "TD-CERT-DRAFT-1",
		OrganizationID: orgID,
		Status:         "DRAFT",
		FileStorageKey: pgtype.Text{String: storageKey, Valid: true},
	})
	repo.AddCertificate(db.Certificate{
		ID:             issuedCertID,
		PublicID:       "TD-CERT-ISSUED-1",
		OrganizationID: orgID,
		Status:         "ISSUED",
	})

	// 1. Cross-tenant deletion rejected
	err := svc.DeleteDraft(context.Background(), certID, otherOrgID, actorID)
	if err == nil {
		t.Fatalf("expected cross-tenant deletion to fail, got nil")
	}

	// 2. Non-DRAFT deletion rejected
	err = svc.DeleteDraft(context.Background(), issuedCertID, orgID, actorID)
	if err == nil {
		t.Fatalf("expected non-DRAFT deletion to fail, got nil")
	}

	// 3. Storage cleanup begins only after commit: if DB commit fails, storage is retained
	repo.FailDeleteTx = errors.New("simulated DB error")
	err = svc.DeleteDraft(context.Background(), certID, orgID, actorID)
	if err == nil {
		t.Fatalf("expected failure when DB fails, got nil")
	}
	if !mockStorage.HasObject(storageKey) {
		t.Errorf("storage object was deleted before DB commit succeeded")
	}
	repo.FailDeleteTx = nil

	// 4. Successful soft-deletion:
	err = svc.DeleteDraft(context.Background(), certID, orgID, actorID)
	if err != nil {
		t.Fatalf("expected successful soft deletion, got: %v", err)
	}

	// Assert row is retained in database with deleted_at set
	retainedCert, ok := repo.certificates[UUIDToString(certID)]
	if !ok {
		t.Fatalf("expected certificate row to be retained, but row was physically deleted")
	}
	if !retainedCert.DeletedAt.Valid {
		t.Errorf("expected deleted_at to be valid and set on soft-deleted draft")
	}

	// Assert storage object is purged post-commit
	if mockStorage.HasObject(storageKey) {
		t.Errorf("expected storage object to be purged after soft-deletion commit")
	}

	// 5. Repeated deletion must be safe and return not found
	err = svc.DeleteDraft(context.Background(), certID, orgID, actorID)
	if err == nil {
		t.Fatalf("expected repeated deletion to fail with not found, got nil")
	}
}
