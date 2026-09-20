package certificates

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

func TestCreateCertificateDraftRequest_ValidationAndCanonicalization(t *testing.T) {
	// 1. Valid request canonicalization
	validReq := CreateCertificateDraftRequest{
		RecipientUserID: "  10000000-0000-0000-0000-000000000001  ",
		RecipientName:   "  Jane Doe  ",
		RecipientEmail:  "  Jane.Doe@University.Edu  ",
		Title:           "  Bachelor of Science in Computer Science  ",
		DegreeType:      "  bachelor  ",
		GraduationDate:  "2026-05-15",
		IssueDate:       "2026-05-20",
	}

	err := validReq.ValidateAndCanonicalize()
	if err != nil {
		t.Fatalf("expected valid request to succeed, got: %v", err)
	}
	if validReq.RecipientUserID != "10000000-0000-0000-0000-000000000001" {
		t.Errorf("expected trimmed recipient user ID, got %s", validReq.RecipientUserID)
	}
	if validReq.RecipientName != "Jane Doe" {
		t.Errorf("expected trimmed recipient name, got %s", validReq.RecipientName)
	}
	if validReq.RecipientEmail != "jane.doe@university.edu" {
		t.Errorf("expected lowercase canonical email, got %s", validReq.RecipientEmail)
	}
	if validReq.DegreeType != "BACHELOR" {
		t.Errorf("expected uppercase canonical degree type, got %s", validReq.DegreeType)
	}
	if validReq.Title != "Bachelor of Science in Computer Science" {
		t.Errorf("expected trimmed title, got %s", validReq.Title)
	}

	// 2. Missing required fields
	reqMissing := CreateCertificateDraftRequest{}
	if err := reqMissing.ValidateAndCanonicalize(); err == nil {
		t.Errorf("expected error for empty request, got nil")
	}

	// 3. Invalid email format
	reqBadEmail := validReq
	reqBadEmail.RecipientEmail = "not-an-email"
	if err := reqBadEmail.ValidateAndCanonicalize(); err == nil {
		t.Errorf("expected error for invalid email, got nil")
	}

	// 4. Invalid degree type
	reqBadDegree := validReq
	reqBadDegree.DegreeType = "INVALID_DEGREE"
	err = reqBadDegree.ValidateAndCanonicalize()
	if err == nil || err.Code != core.ErrCodeInvalidDegreeType {
		t.Errorf("expected ErrCodeInvalidDegreeType, got %v", err)
	}

	// 5. Academic date ordering (issue_date < graduation_date must fail)
	reqBadDates := validReq
	reqBadDates.GraduationDate = "2026-06-01"
	reqBadDates.IssueDate = "2026-05-01"
	err = reqBadDates.ValidateAndCanonicalize()
	if err == nil || err.Code != core.ErrCodeInvalidAcademicDates {
		t.Errorf("expected ErrCodeInvalidAcademicDates, got %v", err)
	}

	// 6. Invalid date format
	reqBadDateFormat := validReq
	reqBadDateFormat.GraduationDate = "05/15/2026"
	if err := reqBadDateFormat.ValidateAndCanonicalize(); err == nil {
		t.Errorf("expected error for bad date format, got nil")
	}

	// 7. Optional fields canonicalization (empty strings converted to nil)
	emptyStr := "   "
	validReq.StudentIDNumber = &emptyStr
	validReq.Major = &emptyStr
	validReq.GradeOrHonors = &emptyStr
	if err := validReq.ValidateAndCanonicalize(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validReq.StudentIDNumber != nil {
		t.Errorf("expected empty student_id_number to become nil, got %v", validReq.StudentIDNumber)
	}
	if validReq.Major != nil {
		t.Errorf("expected empty major to become nil, got %v", validReq.Major)
	}
	if validReq.GradeOrHonors != nil {
		t.Errorf("expected empty grade_or_honors to become nil, got %v", validReq.GradeOrHonors)
	}
}

func TestCreateCertificateDraftRequest_FutureIssueDate(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Past issue date -> valid
	pastReq := CreateCertificateDraftRequest{IssueDate: "2026-05-15"}
	if err := pastReq.ValidateFutureIssueDate(now); err != nil {
		t.Errorf("expected past date to be valid, got %v", err)
	}

	// Same-day (today) issue date -> valid
	todayReq := CreateCertificateDraftRequest{IssueDate: "2026-06-01"}
	if err := todayReq.ValidateFutureIssueDate(now); err != nil {
		t.Errorf("expected same-day date to be valid, got %v", err)
	}

	// Tomorrow issue date -> rejected
	tomorrowReq := CreateCertificateDraftRequest{IssueDate: "2026-06-02"}
	err := tomorrowReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeFutureIssueDate {
		t.Errorf("expected ErrCodeFutureIssueDate for tomorrow, got %v", err)
	}

	// Far-future issue date -> rejected
	farFutureReq := CreateCertificateDraftRequest{IssueDate: "2026-12-31"}
	err = farFutureReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeFutureIssueDate {
		t.Errorf("expected ErrCodeFutureIssueDate for far future, got %v", err)
	}

	// Malformed date -> rejected with BadRequest
	malformedReq := CreateCertificateDraftRequest{IssueDate: "not-a-date"}
	err = malformedReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeBadRequest {
		t.Errorf("expected ErrCodeBadRequest for malformed date, got %v", err)
	}
}

func TestUpdateCertificateDraftRequest_FutureIssueDate(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Nil issue date -> valid (no-op)
	nilReq := UpdateCertificateDraftRequest{IssueDate: nil}
	if err := nilReq.ValidateFutureIssueDate(now); err != nil {
		t.Errorf("expected nil issue date to be valid, got %v", err)
	}

	// Past issue date -> valid
	pastStr := "2026-05-15"
	pastReq := UpdateCertificateDraftRequest{IssueDate: &pastStr}
	if err := pastReq.ValidateFutureIssueDate(now); err != nil {
		t.Errorf("expected past date to be valid, got %v", err)
	}

	// Same-day (today) issue date -> valid
	todayStr := "2026-06-01"
	todayReq := UpdateCertificateDraftRequest{IssueDate: &todayStr}
	if err := todayReq.ValidateFutureIssueDate(now); err != nil {
		t.Errorf("expected same-day date to be valid, got %v", err)
	}

	// Tomorrow issue date -> rejected
	tomorrowStr := "2026-06-02"
	tomorrowReq := UpdateCertificateDraftRequest{IssueDate: &tomorrowStr}
	err := tomorrowReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeFutureIssueDate {
		t.Errorf("expected ErrCodeFutureIssueDate for tomorrow, got %v", err)
	}

	// Far-future issue date -> rejected
	farFutureStr := "2026-12-31"
	farFutureReq := UpdateCertificateDraftRequest{IssueDate: &farFutureStr}
	err = farFutureReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeFutureIssueDate {
		t.Errorf("expected ErrCodeFutureIssueDate for far future, got %v", err)
	}

	// Malformed date -> rejected with BadRequest
	malformedStr := "invalid-date"
	malformedReq := UpdateCertificateDraftRequest{IssueDate: &malformedStr}
	err = malformedReq.ValidateFutureIssueDate(now)
	if err == nil || err.Code != core.ErrCodeBadRequest {
		t.Errorf("expected ErrCodeBadRequest for malformed date, got %v", err)
	}
}

func TestUpdateCertificateDraftRequest_ValidationAndCanonicalization(t *testing.T) {
	// 1. Partial update canonicalization
	name := "  John Smith  "
	email := "  John.Smith@Uni.Edu  "
	deg := "  master  "
	updateReq := UpdateCertificateDraftRequest{
		RecipientName:  &name,
		RecipientEmail: &email,
		DegreeType:     &deg,
	}

	if err := updateReq.ValidateAndCanonicalize(); err != nil {
		t.Fatalf("expected valid partial update, got: %v", err)
	}
	if *updateReq.RecipientName != "John Smith" {
		t.Errorf("expected trimmed name, got %s", *updateReq.RecipientName)
	}
	if *updateReq.RecipientEmail != "john.smith@uni.edu" {
		t.Errorf("expected lowercase canonical email, got %s", *updateReq.RecipientEmail)
	}
	if *updateReq.DegreeType != "MASTER" {
		t.Errorf("expected uppercase canonical degree type, got %s", *updateReq.DegreeType)
	}

	// 2. Invalid degree type
	badDeg := "INVALID"
	badReq := UpdateCertificateDraftRequest{DegreeType: &badDeg}
	if err := badReq.ValidateAndCanonicalize(); err == nil || err.Code != core.ErrCodeInvalidDegreeType {
		t.Errorf("expected ErrCodeInvalidDegreeType, got %v", err)
	}

	// 3. Date ordering in update
	grad := "2026-06-15"
	iss := "2026-05-01"
	badDateReq := UpdateCertificateDraftRequest{
		GraduationDate: &grad,
		IssueDate:      &iss,
	}
	if err := badDateReq.ValidateAndCanonicalize(); err == nil || err.Code != core.ErrCodeInvalidAcademicDates {
		t.Errorf("expected ErrCodeInvalidAcademicDates, got %v", err)
	}
}

func TestRevokeAndReplaceRequests_Validation(t *testing.T) {
	// 1. Valid revoke request
	validRevoke := RevokeCertificateRequest{
		ReasonCode: "ACADEMIC_MISCONDUCT",
		Reason:     "Discovered plagiarism in final thesis project.",
	}
	if err := validRevoke.Validate(); err != nil {
		t.Fatalf("expected valid revoke, got %v", err)
	}

	// 2. Invalid reason code
	badCodeRevoke := RevokeCertificateRequest{
		ReasonCode: "INVALID_CODE",
		Reason:     "Valid reason text explanation.",
	}
	err := badCodeRevoke.Validate()
	if err == nil || err.Code != core.ErrCodeInvalidRevocationReasonCode {
		t.Errorf("expected ErrCodeInvalidRevocationReasonCode, got %v", err)
	}

	// 3. Too short reason
	shortReasonRevoke := RevokeCertificateRequest{
		ReasonCode: "ISSUED_IN_ERROR",
		Reason:     "no",
	}
	err = shortReasonRevoke.Validate()
	if err == nil || err.Code != core.ErrCodeRevocationReasonRequired {
		t.Errorf("expected ErrCodeRevocationReasonRequired, got %v", err)
	}

	// 4. Valid replace request
	validReplace := ReplaceCertificateRequest{
		ReplacementCertificateID: "10000000-0000-0000-0000-000000000002",
		ReasonCode:               "ADMINISTRATIVE_CORRECTION",
		Reason:                   "Typo in major name on diploma.",
	}
	if err := validReplace.Validate(); err != nil {
		t.Fatalf("expected valid replace, got %v", err)
	}

	// 5. Missing replacement ID
	missingIDReplace := ReplaceCertificateRequest{
		ReasonCode: "ADMINISTRATIVE_CORRECTION",
		Reason:     "Typo correction.",
	}
	if err := missingIDReplace.Validate(); err == nil {
		t.Errorf("expected error for missing replacement_certificate_id, got nil")
	}
}

func TestSanitizePaginationParams(t *testing.T) {
	tests := []struct {
		name      string
		inPage    int
		inLimit   int
		wantPage  int
		wantLimit int
	}{
		{"defaults on zeros", 0, 0, 1, 20},
		{"defaults on negatives", -5, -10, 1, 20},
		{"clamps maximum limit to 50", 1, 100, 1, 50},
		{"preserves valid values", 3, 25, 3, 25},
		{"minimum limit", 2, 1, 2, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotP, gotL := SanitizePaginationParams(tc.inPage, tc.inLimit)
			if gotP != tc.wantPage || gotL != tc.wantLimit {
				t.Errorf("SanitizePaginationParams(%d, %d) = (%d, %d), want (%d, %d)",
					tc.inPage, tc.inLimit, gotP, gotL, tc.wantPage, tc.wantLimit)
			}
		})
	}
}

func TestMaskRecipientName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Jane Doe", "J*** D**"},
		{"Alexander", "A********"},
		{"A B C", "A B C"},
		{"Mary Jane Watson", "M*** J*** W*****"},
		{"  Jane   Doe  ", "J*** D**"},
		{"José María", "J*** M****"},
		{"A", "A"},
		{"", "***"},
		{"   ", "***"},
		{"Li", "L*"},
		{"Émile Zola", "É**** Z***"},
	}

	for _, tc := range tests {
		got := MaskRecipientName(tc.input)
		if got != tc.want {
			t.Errorf("MaskRecipientName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPublicCertificateResponse_SecretAndPIIExclusion(t *testing.T) {
	major := "Computer Science"
	resp := PublicCertificateResponse{
		PublicID:                 "TD-CERT-A1B2C3D4E5F60718",
		Status:                   "ISSUED",
		Title:                    "Bachelor of Science",
		DegreeType:               "BACHELOR",
		Major:                    &major,
		GraduationDate:           "2026-05-15",
		IssueDate:                "2026-05-20",
		DocumentHash:             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		IssuerOrganizationName:   "State University",
		IssuerOrganizationDomain: "state.edu",
		IssuerCountryCode:        "US",
		MaskedRecipientName:      MaskRecipientName("Jane Doe"),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal PublicCertificateResponse: %v", err)
	}

	jsonStr := string(data)

	// Verify absence of sensitive keywords
	prohibitedSubstrings := []string{
		"recipient_email",
		"recipient_user_id",
		"student_id_number",
		"file_storage_key",
		"file_name",
		"Jane Doe",
		"created_by_user_id",
		"issued_by_user_id",
	}

	for _, prohibited := range prohibitedSubstrings {
		if strings.Contains(jsonStr, prohibited) {
			t.Errorf("PublicCertificateResponse JSON contains prohibited field or PII %q: %s", prohibited, jsonStr)
		}
	}

	// Verify presence of masked recipient name
	if !strings.Contains(jsonStr, "J*** D**") {
		t.Errorf("PublicCertificateResponse JSON missing masked recipient name: %s", jsonStr)
	}
}
