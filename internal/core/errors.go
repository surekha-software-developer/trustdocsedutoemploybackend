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
