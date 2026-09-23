package core

import "fmt"

// Standard Error Codes used across the TrustDocs platform.
const (
	ErrCodeNotFound         = "NOT_FOUND"
	ErrCodeMethodNotAllowed = "METHOD_NOT_ALLOWED"
	ErrCodeInternal         = "INTERNAL_ERROR"
	ErrCodeBadRequest       = "BAD_REQUEST"
	ErrCodeUnauthorized     = "UNAUTHORIZED"
	ErrCodeForbidden        = "FORBIDDEN"

	// Phase 4B Organization Domain Error Codes
	ErrCodeOrganizationNotFound                     = "ORGANIZATION_NOT_FOUND"
	ErrCodeOrganizationAlreadyExists                = "ORGANIZATION_ALREADY_EXISTS"
	ErrCodeOrganizationNotPending                   = "ORGANIZATION_NOT_PENDING"
	ErrCodeOrganizationNotActive                    = "ORGANIZATION_NOT_ACTIVE"
	ErrCodeOrganizationSelfReviewProhibited         = "ORGANIZATION_SELF_REVIEW_PROHIBITED"
	ErrCodeOrganizationMembershipIntegrityViolation = "ORGANIZATION_MEMBERSHIP_INTEGRITY_VIOLATION"
	ErrCodeInvalidMembershipState                   = "INVALID_MEMBERSHIP_STATE"
	ErrCodeInvalidMembershipRole                    = "INVALID_MEMBERSHIP_ROLE"
	ErrCodeInvalidReasonCode                        = "INVALID_REASON_CODE"
	ErrCodeDecisionReasonRequired                   = "DECISION_REASON_REQUIRED"
	ErrCodeInvalidFilterParam                       = "INVALID_FILTER_PARAM"
	ErrCodeConflict                                 = "CONFLICT"

	// Phase 5A Certificate Domain Error Codes
	ErrCodeCertificateNotFound         = "CERTIFICATE_NOT_FOUND"
	ErrCodeCertificateNotDraft         = "CERTIFICATE_NOT_DRAFT"
	ErrCodeCertificateAlreadyIssued    = "CERTIFICATE_ALREADY_ISSUED"
	ErrCodeCertificateRevoked          = "CERTIFICATE_REVOKED"
	ErrCodeCertificateReplaced         = "CERTIFICATE_REPLACED"
	ErrCodeCertificateStateConflict    = "CERTIFICATE_STATE_CONFLICT"
	ErrCodeCertificateFileRequired     = "CERTIFICATE_FILE_REQUIRED"
	ErrCodeDuplicateDocumentHash       = "DUPLICATE_DOCUMENT_HASH"
	ErrCodeRecipientNotFound           = "RECIPIENT_NOT_FOUND"
	ErrCodeRecipientMismatch           = "RECIPIENT_MISMATCH"
	ErrCodeInvalidDegreeType           = "INVALID_DEGREE_TYPE"
	ErrCodeInvalidAcademicDates        = "INVALID_ACADEMIC_DATES"
	ErrCodeFutureIssueDate             = "FUTURE_ISSUE_DATE"
	ErrCodeInvalidRevocationReasonCode = "INVALID_REVOCATION_REASON_CODE"
	ErrCodeRevocationReasonRequired    = "REVOCATION_REASON_REQUIRED"
	ErrCodeSelfReplacementProhibited   = "SELF_REPLACEMENT_PROHIBITED"
	ErrCodeFileTooLarge                = "FILE_TOO_LARGE"
	ErrCodeInvalidFileFormat           = "INVALID_FILE_FORMAT"

	// Phase 5B Anchoring Domain Error Codes
	ErrCodeProofInvalid           = "PROOF_INVALID"
	ErrCodeProofDepthExceeded     = "PROOF_DEPTH_EXCEEDED"
	ErrCodeBatchNotFound          = "BATCH_NOT_FOUND"
	ErrCodeBatchNotReady          = "BATCH_NOT_READY"
	ErrCodeBatchAlreadyAnchored   = "BATCH_ALREADY_ANCHORED"
	ErrCodeBatchEmpty             = "BATCH_EMPTY"
	ErrCodeAnchorNotConfirmed     = "ANCHOR_NOT_CONFIRMED"
	ErrCodeBlockchainUnavailable  = "BLOCKCHAIN_UNAVAILABLE"
	ErrCodeTxReconstructionFailed = "TX_RECONSTRUCTION_FAILED"
	ErrCodeReorgDetected          = "REORG_DETECTED"
	ErrCodeNonceDriftDetected     = "NONCE_DRIFT_DETECTED"
)

// AppError represents a structured application error returned in API responses.
type AppError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// NewAppError constructs a new AppError with code, message, and optional details.
func NewAppError(code, message string, details ...interface{}) *AppError {
	err := &AppError{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 {
		err.Details = details[0]
	}
	return err
}
