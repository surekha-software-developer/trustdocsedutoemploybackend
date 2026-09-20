package certificates

import (
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Allowed degree types matching check constraint chk_certificates_degree_type_enum
var AllowedDegreeTypes = map[string]bool{
	"BACHELOR":    true,
	"MASTER":      true,
	"DOCTORATE":   true,
	"DIPLOMA":     true,
	"ASSOCIATE":   true,
	"CERTIFICATE": true,
}

// Allowed certificate statuses matching check constraint chk_certificates_status
var AllowedStatuses = map[string]bool{
	"DRAFT":    true,
	"ISSUED":   true,
	"REVOKED":  true,
	"REPLACED": true,
}

// Allowed revocation reason codes
const (
	RevocationReasonIssuedInError            = "ISSUED_IN_ERROR"
	RevocationReasonAcademicMisconduct       = "ACADEMIC_MISCONDUCT"
	RevocationReasonIdentityFraud            = "IDENTITY_FRAUD"
	RevocationReasonAdministrativeCorrection = "ADMINISTRATIVE_CORRECTION"
	RevocationReasonCourseRequirementUnmet   = "COURSE_REQUIREMENT_UNMET"
	RevocationReasonRevocationByRequest      = "REVOCATION_BY_REQUEST"
	RevocationReasonOther                    = "OTHER"
)

var AllowedRevocationReasonCodes = map[string]bool{
	RevocationReasonIssuedInError:            true,
	RevocationReasonAcademicMisconduct:       true,
	RevocationReasonIdentityFraud:            true,
	RevocationReasonAdministrativeCorrection: true,
	RevocationReasonCourseRequirementUnmet:   true,
	RevocationReasonRevocationByRequest:      true,
	RevocationReasonOther:                    true,
}

// CreateCertificateDraftRequest defines payload to create a new unissued draft certificate.
type CreateCertificateDraftRequest struct {
	RecipientUserID string  `json:"recipient_user_id"`
	RecipientName   string  `json:"recipient_name"`
	RecipientEmail  string  `json:"recipient_email"`
	StudentIDNumber *string `json:"student_id_number,omitempty"`
	Title           string  `json:"title"`
	DegreeType      string  `json:"degree_type"`
	Major           *string `json:"major,omitempty"`
	GradeOrHonors   *string `json:"grade_or_honors,omitempty"`
	GraduationDate  string  `json:"graduation_date"`
	IssueDate       string  `json:"issue_date"`
}

// ValidateAndCanonicalize sanitizes and validates input data strictly according to schema constraints.
func (r *CreateCertificateDraftRequest) ValidateAndCanonicalize() *core.AppError {
	r.RecipientUserID = strings.TrimSpace(r.RecipientUserID)
	if r.RecipientUserID == "" {
		return core.NewAppError(core.ErrCodeBadRequest, "recipient_user_id is required")
	}

	r.RecipientName = strings.TrimSpace(r.RecipientName)
	if l := utf8.RuneCountInString(r.RecipientName); l < 1 || l > 255 {
		return core.NewAppError(core.ErrCodeBadRequest, "recipient_name must be between 1 and 255 characters")
	}

	r.RecipientEmail = strings.ToLower(strings.TrimSpace(r.RecipientEmail))
	if r.RecipientEmail == "" || !ValidateEmailHelper(r.RecipientEmail) {
		return core.NewAppError(core.ErrCodeBadRequest, "recipient_email must be a valid email address")
	}

	if r.StudentIDNumber != nil {
		sid := strings.TrimSpace(*r.StudentIDNumber)
		if sid == "" {
			r.StudentIDNumber = nil
		} else {
			if utf8.RuneCountInString(sid) > 100 {
				return core.NewAppError(core.ErrCodeBadRequest, "student_id_number cannot exceed 100 characters")
			}
			r.StudentIDNumber = &sid
		}
	}

	r.Title = strings.TrimSpace(r.Title)
	if l := utf8.RuneCountInString(r.Title); l < 1 || l > 255 {
		return core.NewAppError(core.ErrCodeBadRequest, "title must be between 1 and 255 characters")
	}

	r.DegreeType = strings.ToUpper(strings.TrimSpace(r.DegreeType))
	if !AllowedDegreeTypes[r.DegreeType] {
		return core.NewAppError(core.ErrCodeInvalidDegreeType, fmt.Sprintf("degree_type must be one of: BACHELOR, MASTER, DOCTORATE, DIPLOMA, ASSOCIATE, CERTIFICATE"))
	}

	if r.Major != nil {
		m := strings.TrimSpace(*r.Major)
		if m == "" {
			r.Major = nil
		} else {
			if utf8.RuneCountInString(m) > 255 {
				return core.NewAppError(core.ErrCodeBadRequest, "major cannot exceed 255 characters")
			}
			r.Major = &m
		}
	}

	if r.GradeOrHonors != nil {
		g := strings.TrimSpace(*r.GradeOrHonors)
		if g == "" {
			r.GradeOrHonors = nil
		} else {
			if utf8.RuneCountInString(g) > 100 {
				return core.NewAppError(core.ErrCodeBadRequest, "grade_or_honors cannot exceed 100 characters")
			}
			r.GradeOrHonors = &g
		}
	}

	r.GraduationDate = strings.TrimSpace(r.GraduationDate)
	gradTime, err := time.Parse("2006-01-02", r.GraduationDate)
	if err != nil {
		return core.NewAppError(core.ErrCodeBadRequest, "graduation_date must be in YYYY-MM-DD format")
	}

	r.IssueDate = strings.TrimSpace(r.IssueDate)
	issueTime, err := time.Parse("2006-01-02", r.IssueDate)
	if err != nil {
		return core.NewAppError(core.ErrCodeBadRequest, "issue_date must be in YYYY-MM-DD format")
	}

	if issueTime.Before(gradTime) {
		return core.NewAppError(core.ErrCodeInvalidAcademicDates, "issue_date must be on or after graduation_date")
	}

	return nil
}

// ValidateFutureIssueDate validates that the certificate issue_date is not later than the current UTC calendar date.
func ValidateFutureIssueDate(issueDateStr string, now time.Time) *core.AppError {
	issueTime, err := time.Parse("2006-01-02", strings.TrimSpace(issueDateStr))
	if err != nil {
		return core.NewAppError(core.ErrCodeBadRequest, "issue_date must be in YYYY-MM-DD format")
	}

	nowUTC := now.UTC()
	todayUTC := time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), 0, 0, 0, 0, time.UTC)
	if issueTime.After(todayUTC) {
		return core.NewAppError(core.ErrCodeFutureIssueDate, "Certificate issue_date cannot be in the future")
	}

	return nil
}

// ValidateFutureIssueDate validates that the certificate issue_date is not later than current UTC calendar date.
func (r *CreateCertificateDraftRequest) ValidateFutureIssueDate(now time.Time) *core.AppError {
	return ValidateFutureIssueDate(r.IssueDate, now)
}

// UpdateCertificateDraftRequest defines payload to update an unissued draft certificate.
type UpdateCertificateDraftRequest struct {
	RecipientUserID *string `json:"recipient_user_id,omitempty"`
	RecipientName   *string `json:"recipient_name,omitempty"`
	RecipientEmail  *string `json:"recipient_email,omitempty"`
	StudentIDNumber *string `json:"student_id_number,omitempty"`
	Title           *string `json:"title,omitempty"`
	DegreeType      *string `json:"degree_type,omitempty"`
	Major           *string `json:"major,omitempty"`
	GradeOrHonors   *string `json:"grade_or_honors,omitempty"`
	GraduationDate  *string `json:"graduation_date,omitempty"`
	IssueDate       *string `json:"issue_date,omitempty"`
}

// ValidateAndCanonicalize sanitizes and validates the optional draft update fields.
func (r *UpdateCertificateDraftRequest) ValidateAndCanonicalize() *core.AppError {
	if r.RecipientUserID != nil {
		uid := strings.TrimSpace(*r.RecipientUserID)
		if uid == "" {
			return core.NewAppError(core.ErrCodeBadRequest, "recipient_user_id cannot be empty")
		}
		r.RecipientUserID = &uid
	}

	if r.RecipientName != nil {
		name := strings.TrimSpace(*r.RecipientName)
		if l := utf8.RuneCountInString(name); l < 1 || l > 255 {
			return core.NewAppError(core.ErrCodeBadRequest, "recipient_name must be between 1 and 255 characters")
		}
		r.RecipientName = &name
	}

	if r.RecipientEmail != nil {
		email := strings.ToLower(strings.TrimSpace(*r.RecipientEmail))
		if email == "" || !ValidateEmailHelper(email) {
			return core.NewAppError(core.ErrCodeBadRequest, "recipient_email must be a valid email address")
		}
		r.RecipientEmail = &email
	}

	if r.StudentIDNumber != nil {
		sid := strings.TrimSpace(*r.StudentIDNumber)
		if sid == "" {
			r.StudentIDNumber = nil
		} else {
			if utf8.RuneCountInString(sid) > 100 {
				return core.NewAppError(core.ErrCodeBadRequest, "student_id_number cannot exceed 100 characters")
			}
			r.StudentIDNumber = &sid
		}
	}

	if r.Title != nil {
		title := strings.TrimSpace(*r.Title)
		if l := utf8.RuneCountInString(title); l < 1 || l > 255 {
			return core.NewAppError(core.ErrCodeBadRequest, "title must be between 1 and 255 characters")
		}
		r.Title = &title
	}

	if r.DegreeType != nil {
		deg := strings.ToUpper(strings.TrimSpace(*r.DegreeType))
		if !AllowedDegreeTypes[deg] {
			return core.NewAppError(core.ErrCodeInvalidDegreeType, "degree_type must be one of: BACHELOR, MASTER, DOCTORATE, DIPLOMA, ASSOCIATE, CERTIFICATE")
		}
		r.DegreeType = &deg
	}

	if r.Major != nil {
		m := strings.TrimSpace(*r.Major)
		if m == "" {
			r.Major = nil
		} else {
			if utf8.RuneCountInString(m) > 255 {
				return core.NewAppError(core.ErrCodeBadRequest, "major cannot exceed 255 characters")
			}
			r.Major = &m
		}
	}

	if r.GradeOrHonors != nil {
		g := strings.TrimSpace(*r.GradeOrHonors)
		if g == "" {
			r.GradeOrHonors = nil
		} else {
			if utf8.RuneCountInString(g) > 100 {
				return core.NewAppError(core.ErrCodeBadRequest, "grade_or_honors cannot exceed 100 characters")
			}
			r.GradeOrHonors = &g
		}
	}

	var gradTime, issueTime time.Time
	var hasGrad, hasIssue bool

	if r.GraduationDate != nil {
		gd := strings.TrimSpace(*r.GraduationDate)
		t, err := time.Parse("2006-01-02", gd)
		if err != nil {
			return core.NewAppError(core.ErrCodeBadRequest, "graduation_date must be in YYYY-MM-DD format")
		}
		r.GraduationDate = &gd
		gradTime = t
		hasGrad = true
	}

	if r.IssueDate != nil {
		id := strings.TrimSpace(*r.IssueDate)
		t, err := time.Parse("2006-01-02", id)
		if err != nil {
			return core.NewAppError(core.ErrCodeBadRequest, "issue_date must be in YYYY-MM-DD format")
		}
		r.IssueDate = &id
		issueTime = t
		hasIssue = true
	}

	if hasGrad && hasIssue && issueTime.Before(gradTime) {
		return core.NewAppError(core.ErrCodeInvalidAcademicDates, "issue_date must be on or after graduation_date")
	}

	return nil
}

// ValidateFutureIssueDate validates that the certificate issue_date is not later than the current UTC calendar date if provided.
func (r *UpdateCertificateDraftRequest) ValidateFutureIssueDate(now time.Time) *core.AppError {
	if r.IssueDate == nil {
		return nil
	}
	return ValidateFutureIssueDate(*r.IssueDate, now)
}

// RevokeCertificateRequest defines payload to revoke an issued certificate.
type RevokeCertificateRequest struct {
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

// Validate ensures non-empty reason and allowlisted reason code.
func (r *RevokeCertificateRequest) Validate() *core.AppError {
	r.ReasonCode = strings.TrimSpace(r.ReasonCode)
	if !AllowedRevocationReasonCodes[r.ReasonCode] {
		return core.NewAppError(core.ErrCodeInvalidRevocationReasonCode, fmt.Sprintf("reason_code must be one of: %s, %s, %s, %s, %s, %s, %s",
			RevocationReasonIssuedInError, RevocationReasonAcademicMisconduct, RevocationReasonIdentityFraud,
			RevocationReasonAdministrativeCorrection, RevocationReasonCourseRequirementUnmet,
			RevocationReasonRevocationByRequest, RevocationReasonOther))
	}

	r.Reason = strings.TrimSpace(r.Reason)
	if l := utf8.RuneCountInString(r.Reason); l < 5 || l > 1000 {
		return core.NewAppError(core.ErrCodeRevocationReasonRequired, "reason must be between 5 and 1000 characters")
	}

	return nil
}

// ReplaceCertificateRequest defines payload to mark an issued certificate as replaced by a new certificate draft.
type ReplaceCertificateRequest struct {
	ReplacementCertificateID string `json:"replacement_certificate_id"`
	ReasonCode               string `json:"reason_code"`
	Reason                   string `json:"reason"`
}

// Validate validates replacement parameters.
func (r *ReplaceCertificateRequest) Validate() *core.AppError {
	r.ReplacementCertificateID = strings.TrimSpace(r.ReplacementCertificateID)
	if r.ReplacementCertificateID == "" {
		return core.NewAppError(core.ErrCodeBadRequest, "replacement_certificate_id is required")
	}

	r.ReasonCode = strings.TrimSpace(r.ReasonCode)
	if !AllowedRevocationReasonCodes[r.ReasonCode] {
		return core.NewAppError(core.ErrCodeInvalidRevocationReasonCode, fmt.Sprintf("reason_code must be one of: %s, %s, %s, %s, %s, %s, %s",
			RevocationReasonIssuedInError, RevocationReasonAcademicMisconduct, RevocationReasonIdentityFraud,
			RevocationReasonAdministrativeCorrection, RevocationReasonCourseRequirementUnmet,
			RevocationReasonRevocationByRequest, RevocationReasonOther))
	}

	r.Reason = strings.TrimSpace(r.Reason)
	if l := utf8.RuneCountInString(r.Reason); l < 5 || l > 1000 {
		return core.NewAppError(core.ErrCodeRevocationReasonRequired, "reason must be between 5 and 1000 characters")
	}

	return nil
}

// SanitizePaginationParams ensures page defaults to 1 and limit is clamped to [1, 50] with default 20.
func SanitizePaginationParams(page, limit int) (int, int) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	} else if limit > 50 {
		limit = 50
	}
	return page, limit
}

// ValidateEmailHelper parses and verifies standard email format.
func ValidateEmailHelper(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
