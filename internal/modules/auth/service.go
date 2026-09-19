package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrSessionExpired     = errors.New("session expired or revoked")
	ErrUserNotFound       = errors.New("user not found")
)

// Service defines business operations for authentication and RBAC workflows.
type Service interface {
	Register(ctx context.Context, req RegisterRequest, ip *netip.Addr, userAgent string) (MessageResponse, error)
	Login(ctx context.Context, req LoginRequest, ip *netip.Addr, userAgent string) (UserResponse, string, error)
	Logout(ctx context.Context, rawSessionToken string, ip *netip.Addr, userAgent string) error
	GetMe(ctx context.Context, userID pgtype.UUID) (AuthMeResponse, error)
	GetSessionByToken(ctx context.Context, rawSessionToken string) (db.AuthSession, db.User, error)
	GenerateCSRFToken(rawSessionToken string) string
	ValidateCSRFToken(rawSessionToken string, providedToken string) bool
	GetConfig() *config.Config
	GetDummyHash() string
}

type authService struct {
	repo            Repository
	cfg             *config.Config
	dummyArgon2Hash string
}

// NewService constructs a new auth service and initializes a configured dummy Argon2id hash
// using the exact parameters from cfg to ensure timing equalization matches real password verification.
func NewService(repo Repository, cfg *config.Config) Service {
	argonParams := Argon2Params{
		Memory:      cfg.Argon2Memory,
		Iterations:  cfg.Argon2Iterations,
		Parallelism: cfg.Argon2Parallelism,
		SaltLength:  cfg.Argon2SaltLength,
		KeyLength:   cfg.Argon2KeyLength,
	}
	dummyHash := GenerateDummyHash(argonParams)
	return &authService{
		repo:            repo,
		cfg:             cfg,
		dummyArgon2Hash: dummyHash,
	}
}

func (s *authService) GetConfig() *config.Config {
	return s.cfg
}

func (s *authService) GetDummyHash() string {
	return s.dummyArgon2Hash
}

// Register creates a new user, authentication identity, and audit record in a single transaction.
// Implements anti-enumeration: both new and duplicate email registrations return identical generic
// 200 OK responses with zero session cookies set.
func (s *authService) Register(ctx context.Context, req RegisterRequest, ip *netip.Addr, userAgent string) (MessageResponse, error) {
	genericResponse := MessageResponse{
		Message: "If this email address is eligible, a registration confirmation has been processed.",
	}

	argonParams := Argon2Params{
		Memory:      s.cfg.Argon2Memory,
		Iterations:  s.cfg.Argon2Iterations,
		Parallelism: s.cfg.Argon2Parallelism,
		SaltLength:  s.cfg.Argon2SaltLength,
		KeyLength:   s.cfg.Argon2KeyLength,
	}

	// Always compute Argon2id hash upfront so timing is equalized for new and duplicate registrations
	hashedPassword, err := HashPassword(req.Password, argonParams)
	if err != nil {
		return MessageResponse{}, err
	}

	userParams := db.CreateUserParams{
		Email:         req.Email,
		FullName:      req.FullName,
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: false,
	}

	identityParams := db.CreateAuthIdentityParams{
		IdentityType:   "EMAIL_PASSWORD",
		Identifier:     req.Email,
		CredentialHash: pgtype.Text{String: hashedPassword, Valid: true},
		Metadata:       []byte("{}"),
	}

	auditPayload, _ := json.Marshal(map[string]interface{}{
		"identity_type": "EMAIL_PASSWORD",
	})

	auditParams := db.CreateAuditLogParams{
		Action:       "USER_REGISTER",
		ResourceType: "user",
		Payload:      auditPayload,
		IpAddress:    ip,
		UserAgent:    pgtype.Text{String: userAgent, Valid: userAgent != ""},
	}

	_, err = s.repo.CreateUserAndIdentityWithAudit(ctx, userParams, identityParams, auditParams)
	if err != nil {
		// Detect duplicate email / unique constraint violation
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "unique") || strings.Contains(errStr, "duplicate") {
			// Anti-enumeration: return identical success response without error
			return genericResponse, nil
		}
		return MessageResponse{}, fmt.Errorf("registration failed: %w", err)
	}

	return genericResponse, nil
}

// Login validates user credentials, checks portal context, and creates a session atomically with audit.
// Implements timing equalization and anti-enumeration: all failure modes return ErrInvalidCredentials.
func (s *authService) Login(ctx context.Context, req LoginRequest, ip *netip.Addr, userAgent string) (UserResponse, string, error) {
	// 1. Fetch user by canonical lowercase email
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// User does not exist: run dummy Argon2id verification with configured parameters to equalize response timing
		_, _ = VerifyPassword(req.Password, s.dummyArgon2Hash)
		s.recordFailedLoginAudit(ctx, pgtype.UUID{}, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}

	// 2. Fetch credential identity
	identity, err := s.repo.GetAuthIdentityForVerification(ctx, "EMAIL_PASSWORD", req.Email)
	if err != nil {
		_, _ = VerifyPassword(req.Password, s.dummyArgon2Hash)
		s.recordFailedLoginAudit(ctx, user.ID, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}

	// 3. Verify password against stored hash
	valid, err := VerifyPassword(req.Password, identity.CredentialHash.String)
	if err != nil || !valid {
		s.recordFailedLoginAudit(ctx, user.ID, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}

	// 4. Check user status (active and not soft-deleted)
	if !user.IsActive || user.DeletedAt.Valid {
		s.recordFailedLoginAudit(ctx, user.ID, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}

	// 5. Enforce portal context match (untrusted client intent check)
	if req.PortalContext == "admin" && !user.IsSuperadmin {
		s.recordFailedLoginAudit(ctx, user.ID, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}
	if req.PortalContext == "app" && user.IsSuperadmin {
		s.recordFailedLoginAudit(ctx, user.ID, ip, userAgent)
		return UserResponse{}, "", ErrInvalidCredentials
	}

	// 6. Generate cryptographically secure session token
	rawSessionToken, err := GenerateSessionToken()
	if err != nil {
		return UserResponse{}, "", fmt.Errorf("session token generation failed: %w", err)
	}
	tokenHash := HashSessionToken(rawSessionToken)

	now := time.Now().UTC()
	expiresAt := now.Add(s.cfg.AuthSessionTTL)

	sessionParams := db.CreateAuthSessionParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		UserAgent: pgtype.Text{String: userAgent, Valid: userAgent != ""},
		IpAddress: ip,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}

	auditPayload, _ := json.Marshal(map[string]interface{}{
		"portal_context": req.PortalContext,
	})

	auditParams := db.CreateAuditLogParams{
		ActorUserID:  user.ID,
		Action:       "LOGIN_SUCCESS",
		ResourceType: "auth_session",
		Payload:      auditPayload,
		IpAddress:    ip,
		UserAgent:    pgtype.Text{String: userAgent, Valid: userAgent != ""},
	}

	// 7. Atomically create session and audit log
	_, err = s.repo.CreateSessionAndSuccessAudit(ctx, sessionParams, auditParams)
	if err != nil {
		return UserResponse{}, "", fmt.Errorf("session creation transaction failed: %w", err)
	}

	userResp := UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		FullName:      user.FullName,
		IsSuperadmin:  user.IsSuperadmin,
		EmailVerified: user.EmailVerified,
	}

	return userResp, rawSessionToken, nil
}

// recordFailedLoginAudit writes a LOGIN_FAILURE audit entry without altering public response
// and strictly without PII (zero emails, passwords, or tokens).
func (s *authService) recordFailedLoginAudit(ctx context.Context, userID pgtype.UUID, ip *netip.Addr, userAgent string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"reason": "INVALID_CREDENTIALS",
	})
	auditParams := db.CreateAuditLogParams{
		ActorUserID:  userID,
		Action:       "LOGIN_FAILURE",
		ResourceType: "auth_session",
		Payload:      payload,
		IpAddress:    ip,
		UserAgent:    pgtype.Text{String: userAgent, Valid: userAgent != ""},
	}
	// Audit write errors do not alter authentication response
	_, _ = s.repo.CreateAuditLog(ctx, auditParams)
}

// Logout revokes the session in the database if present. Always succeeds idempotently.
func (s *authService) Logout(ctx context.Context, rawSessionToken string, ip *netip.Addr, userAgent string) error {
	if rawSessionToken == "" {
		return nil
	}

	tokenHash := HashSessionToken(rawSessionToken)
	session, err := s.repo.GetAuthSessionByHash(ctx, tokenHash)
	if err == nil {
		_ = s.repo.RevokeAuthSession(ctx, session.ID)

		payload, _ := json.Marshal(map[string]interface{}{
			"action": "LOGOUT",
		})
		_, _ = s.repo.CreateAuditLog(ctx, db.CreateAuditLogParams{
			ActorUserID:  session.UserID,
			Action:       "LOGOUT",
			ResourceType: "auth_session",
			ResourceID:   session.ID,
			Payload:      payload,
			IpAddress:    ip,
			UserAgent:    pgtype.Text{String: userAgent, Valid: userAgent != ""},
		})
	}

	return nil
}

// GetMe retrieves the authenticated user's profile and active organization memberships.
func (s *authService) GetMe(ctx context.Context, userID pgtype.UUID) (AuthMeResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return AuthMeResponse{}, ErrUserNotFound
	}

	memberships, err := s.repo.ListMembershipsByUserID(ctx, userID)
	if err != nil {
		return AuthMeResponse{}, fmt.Errorf("failed to query memberships: %w", err)
	}

	membershipResponses := make([]MembershipResponse, 0, len(memberships))
	for _, m := range memberships {
		membershipResponses = append(membershipResponses, MembershipResponse{
			OrganizationID:        m.OrganizationID.String(),
			Role:                  m.Role,
			OrganizationLegalName: m.OrganizationLegalName,
			OrganizationType:      m.OrganizationType,
			OrganizationStatus:    m.OrganizationStatus,
		})
	}

	return AuthMeResponse{
		User: UserResponse{
			ID:            user.ID.String(),
			Email:         user.Email,
			FullName:      user.FullName,
			IsSuperadmin:  user.IsSuperadmin,
			EmailVerified: user.EmailVerified,
		},
		Memberships: membershipResponses,
	}, nil
}

// GetSessionByToken finds and validates an active, unrevoked session and its associated active user.
func (s *authService) GetSessionByToken(ctx context.Context, rawSessionToken string) (db.AuthSession, db.User, error) {
	tokenHash := HashSessionToken(rawSessionToken)
	session, err := s.repo.GetAuthSessionByHash(ctx, tokenHash)
	if err != nil {
		return db.AuthSession{}, db.User{}, ErrSessionExpired
	}

	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil || !user.IsActive || user.DeletedAt.Valid {
		return db.AuthSession{}, db.User{}, ErrSessionExpired
	}

	return session, user, nil
}

// GenerateCSRFToken generates a session-bound HMAC-SHA256 CSRF token.
func (s *authService) GenerateCSRFToken(rawSessionToken string) string {
	return ComputeCSRFToken(s.cfg.CSRFSecret, rawSessionToken)
}

// ValidateCSRFToken validates the incoming CSRF token against the raw session token.
func (s *authService) ValidateCSRFToken(rawSessionToken string, providedToken string) bool {
	return ValidateCSRFToken(s.cfg.CSRFSecret, rawSessionToken, providedToken)
}
