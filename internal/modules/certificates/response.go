package certificates

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// CertificateResponse represents full issuer-facing certificate details.
type CertificateResponse struct {
	ID                      string  `json:"id"`
	PublicID                string  `json:"public_id"`
	OrganizationID          string  `json:"organization_id"`
	RecipientUserID         string  `json:"recipient_user_id"`
	RecipientName           string  `json:"recipient_name"`
	RecipientEmail          string  `json:"recipient_email"`
	StudentIDNumber         *string `json:"student_id_number,omitempty"`
	Title                   string  `json:"title"`
	DegreeType              string  `json:"degree_type"`
	Major                   *string `json:"major,omitempty"`
	GradeOrHonors           *string `json:"grade_or_honors,omitempty"`
	GraduationDate          string  `json:"graduation_date"`
	IssueDate               string  `json:"issue_date"`
	Status                  string  `json:"status"`
	FileStorageKey          *string `json:"-"`
	FileName                *string `json:"file_name,omitempty"`
	FileSize                *int64  `json:"file_size,omitempty"`
	FileMimeType            *string `json:"file_mime_type,omitempty"`
	DocumentHash            *string `json:"document_hash,omitempty"`
	CreatedByUserID         string  `json:"created_by_user_id"`
	CreatedAt               string  `json:"created_at"`
	UpdatedAt               string  `json:"updated_at"`
	IssuedByUserID          *string `json:"issued_by_user_id,omitempty"`
	IssuedAt                *string `json:"issued_at,omitempty"`
	RevokedByUserID         *string `json:"revoked_by_user_id,omitempty"`
	RevokedAt               *string `json:"revoked_at,omitempty"`
	RevocationReasonCode    *string `json:"revocation_reason_code,omitempty"`
	RevocationReason        *string `json:"revocation_reason,omitempty"`
	ReplacedByCertificateID *string `json:"replaced_by_certificate_id,omitempty"`
	ReplacesCertificateID   *string `json:"replaces_certificate_id,omitempty"`
}

// StudentCertificateResponse represents certificate details displayed in the student's Career Trust Passport.
type StudentCertificateResponse struct {
	ID                    string  `json:"id"`
	PublicID              string  `json:"public_id"`
	OrganizationID        string  `json:"organization_id"`
	OrganizationLegalName string  `json:"organization_legal_name"`
	OrganizationDomain    string  `json:"organization_domain"`
	RecipientName         string  `json:"recipient_name"`
	StudentIDNumber       *string `json:"student_id_number,omitempty"`
	Title                 string  `json:"title"`
	DegreeType            string  `json:"degree_type"`
	Major                 *string `json:"major,omitempty"`
	GradeOrHonors         *string `json:"grade_or_honors,omitempty"`
	GraduationDate        string  `json:"graduation_date"`
	IssueDate             string  `json:"issue_date"`
	Status                string  `json:"status"`
	FileName              *string `json:"file_name,omitempty"`
	FileSize              *int64  `json:"file_size,omitempty"`
	DocumentHash          *string `json:"document_hash,omitempty"`
	IssuedAt              *string `json:"issued_at,omitempty"`
	RevokedAt             *string `json:"revoked_at,omitempty"`
	RevocationReasonCode  *string `json:"revocation_reason_code,omitempty"`
	ReplacedByPublicID    *string `json:"replaced_by_public_id,omitempty"`
}

// PublicCertificateResponse represents safe, privacy-preserving public verification projection.
// It strictly excludes student email, student account UUID, internal issuer UUIDs, storage keys, and raw recipient names.
type PublicCertificateResponse struct {
	PublicID                 string  `json:"public_id"`
	Status                   string  `json:"status"`
	Title                    string  `json:"title"`
	DegreeType               string  `json:"degree_type"`
	Major                    *string `json:"major,omitempty"`
	GraduationDate           string  `json:"graduation_date"`
	IssueDate                string  `json:"issue_date"`
	DocumentHash             string  `json:"document_hash"`
	IssuerOrganizationName   string  `json:"issuer_organization_name"`
	IssuerOrganizationDomain string  `json:"issuer_organization_domain"`
	IssuerCountryCode        string  `json:"issuer_country_code"`
	MaskedRecipientName      string  `json:"masked_recipient_name"`
	RevocationReasonCode     *string `json:"revocation_reason_code,omitempty"`
	RevokedAt                *string `json:"revoked_at,omitempty"`
	ReplacedByPublicID       *string `json:"replaced_by_public_id,omitempty"`
}

// CertificateStatusMetadataResponse is returned when student download is denied for REVOKED or REPLACED certificates.
type CertificateStatusMetadataResponse struct {
	CertificateID        string  `json:"certificate_id"`
	PublicID             string  `json:"public_id"`
	Status               string  `json:"status"`
	RevocationReasonCode *string `json:"revocation_reason_code,omitempty"`
	RevokedAt            *string `json:"revoked_at,omitempty"`
	ReplacedByPublicID   *string `json:"replaced_by_public_id,omitempty"`
	Message              string  `json:"message"`
}

// PaginationResponse represents standard pagination metadata envelope.
type PaginationResponse struct {
	Page         int   `json:"page"`
	Limit        int   `json:"limit"`
	TotalRecords int64 `json:"total_records"`
	TotalPages   int   `json:"total_pages"`
}

// MaskRecipientName masks recipient name for public projection while preserving initial letters per name token.
// Handles Unicode runes, multi-token names, repeated spaces, and edge cases.
// Examples:
// - "Jane Doe" -> "J*** D**"
// - "Alexander" -> "A********"
// - "A B C" -> "A B C"
// - "Mary Jane Watson" -> "M*** J*** W*****"
// - "" -> "***"
func MaskRecipientName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "***"
	}

	words := strings.Fields(trimmed)
	if len(words) == 0 {
		return "***"
	}

	maskedWords := make([]string, 0, len(words))
	for _, word := range words {
		runes := []rune(word)
		if len(runes) <= 1 {
			maskedWords = append(maskedWords, string(runes))
		} else {
			masked := string(runes[0]) + strings.Repeat("*", len(runes)-1)
			maskedWords = append(maskedWords, masked)
		}
	}

	return strings.Join(maskedWords, " ")
}

// FormatDateString helper formats time.Time to YYYY-MM-DD string.
func FormatDateString(t time.Time) string {
	return t.Format("2006-01-02")
}

// UUIDToString formats pgtype.UUID as a standard canonical lowercase UUID string.
func UUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	src := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", src[0:4], src[4:6], src[6:8], src[8:10], src[10:16])
}

// StringToUUID parses a string into a pgtype.UUID.
func StringToUUID(s string) pgtype.UUID {
	var u pgtype.UUID
	if err := u.Scan(strings.TrimSpace(s)); err != nil {
		return pgtype.UUID{Valid: false}
	}
	return u
}

// UUIDEqual compares two pgtype.UUID instances.
func UUIDEqual(a, b pgtype.UUID) bool {
	if !a.Valid && !b.Valid {
		return true
	}
	if a.Valid != b.Valid {
		return false
	}
	return bytes.Equal(a.Bytes[:], b.Bytes[:])
}
