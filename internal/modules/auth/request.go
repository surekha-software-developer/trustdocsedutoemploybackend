package auth

import (
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidEmail         = errors.New("invalid email address format")
	ErrFullNameRequired     = errors.New("full name is required (1-100 characters)")
	ErrPasswordRequired     = errors.New("password is required")
	ErrInvalidPortalContext = errors.New("invalid portal context (must be 'app' or 'admin')")
)

// Valid portal contexts for client login intent.
var validPortalContexts = map[string]bool{
	"":      true,
	"app":   true,
	"admin": true,
}

// RegisterRequest defines the input payload for user registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

// SanitizeAndValidate canonicalizes email and verifies input constraints according to NIST/OWASP password guidelines.
func (r *RegisterRequest) SanitizeAndValidate() error {
	r.Email = strings.TrimSpace(strings.ToLower(r.Email))
	if r.Email == "" || len(r.Email) > 255 {
		return ErrInvalidEmail
	}
	if _, err := mail.ParseAddress(r.Email); err != nil || !strings.Contains(r.Email, ".") {
		return ErrInvalidEmail
	}

	r.FullName = strings.TrimSpace(r.FullName)
	nameLen := utf8.RuneCountInString(r.FullName)
	if nameLen < 1 || nameLen > 100 {
		return ErrFullNameRequired
	}

	if r.Password == "" {
		return ErrPasswordRequired
	}

	return ValidatePasswordPolicy(r.Password)
}

// LoginRequest defines the input payload for credential authentication.
type LoginRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	PortalContext string `json:"portal_context"`
}

// SanitizeAndValidate validates input structure without leaking password policy or account existence.
func (r *LoginRequest) SanitizeAndValidate() error {
	r.Email = strings.TrimSpace(strings.ToLower(r.Email))
	if r.Email == "" || len(r.Email) > 255 {
		return ErrInvalidEmail
	}
	if _, err := mail.ParseAddress(r.Email); err != nil || !strings.Contains(r.Email, ".") {
		return ErrInvalidEmail
	}

	if r.Password == "" {
		return ErrPasswordRequired
	}
	if len([]byte(r.Password)) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}

	r.PortalContext = strings.ToLower(strings.TrimSpace(r.PortalContext))
	if !validPortalContexts[r.PortalContext] {
		return ErrInvalidPortalContext
	}

	return nil
}
