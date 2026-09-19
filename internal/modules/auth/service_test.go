package auth

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/config"
)

func newTestService(repo Repository) Service {
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          16384, // Lower for fast unit tests
		Argon2Iterations:      1,
		Argon2Parallelism:     1,
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}
	return NewService(repo, cfg)
}

func TestRegister_AntiEnumeration_NewAndDuplicate(t *testing.T) {
	repo := newMockRepository()
	svc := newTestService(repo)
	ctx := context.Background()
	ip, _ := netip.ParseAddr("127.0.0.1")

	req1 := RegisterRequest{
		Email:    "newuser@example.com",
		Password: "ValidPassword12345!",
		FullName: "First User",
	}

	// 1. Initial registration
	resp1, err := svc.Register(ctx, req1, &ip, "TestAgent")
	if err != nil {
		t.Fatalf("Register failed for new user: %v", err)
	}

	// 2. Duplicate registration with same email
	req2 := RegisterRequest{
		Email:    "newuser@example.com",
		Password: "AnotherValidPassword123!",
		FullName: "Duplicate User",
	}
	resp2, err := svc.Register(ctx, req2, &ip, "TestAgent")
	if err != nil {
		t.Fatalf("Register failed for duplicate user: %v", err)
	}

	// Both responses must be strictly identical
	if resp1.Message != resp2.Message {
		t.Errorf("expected identical messages for new and duplicate registrations: %s != %s", resp1.Message, resp2.Message)
	}

	// Verify no plain password or email in audit logs
	for _, log := range repo.AuditLogs {
		payloadStr := string(log.Payload)
		if strings.Contains(payloadStr, "ValidPassword") || strings.Contains(payloadStr, "newuser@example.com") {
			t.Errorf("audit log payload contains PII or secret: %s", payloadStr)
		}
	}
}

func TestRegister_TransactionRollbackOnIdentityFailure(t *testing.T) {
	repo := newMockRepository()
	repo.FailRegistrationIdentity = true
	svc := newTestService(repo)
	ctx := context.Background()

	req := RegisterRequest{
		Email:    "rollback@example.com",
		Password: "ValidPassword12345!",
		FullName: "Rollback User",
	}

	_, err := svc.Register(ctx, req, nil, "")
	if err == nil {
		t.Fatalf("expected error when identity creation fails")
	}

	// Verify user was NOT saved (transaction rolled back)
	if _, exists := repo.Users["rollback@example.com"]; exists {
		t.Errorf("user was persisted despite identity transaction failure")
	}
}

func TestRegister_TransactionRollbackOnAuditFailure(t *testing.T) {
	repo := newMockRepository()
	repo.FailRegistrationAudit = true
	svc := newTestService(repo)
	ctx := context.Background()

	req := RegisterRequest{
		Email:    "auditrollback@example.com",
		Password: "ValidPassword12345!",
		FullName: "Rollback User",
	}

	_, err := svc.Register(ctx, req, nil, "")
	if err == nil {
		t.Fatalf("expected error when audit log creation fails")
	}

	// Verify user was NOT saved
	if _, exists := repo.Users["auditrollback@example.com"]; exists {
		t.Errorf("user was persisted despite audit transaction failure")
	}
}

func TestLogin_SuccessAndAntiEnumeration(t *testing.T) {
	repo := newMockRepository()
	svc := newTestService(repo)
	ctx := context.Background()
	ip, _ := netip.ParseAddr("127.0.0.1")

	// Register user
	regReq := RegisterRequest{
		Email:    "loginuser@example.com",
		Password: "ValidPassword12345!",
		FullName: "Login User",
	}
	_, err := svc.Register(ctx, regReq, &ip, "TestAgent")
	if err != nil {
		t.Fatalf("setup registration failed: %v", err)
	}

	// 1. Successful login
	loginReq := LoginRequest{
		Email:    "loginuser@example.com",
		Password: "ValidPassword12345!",
	}
	userResp, rawToken, err := svc.Login(ctx, loginReq, &ip, "TestAgent")
	if err != nil {
		t.Fatalf("Login failed for valid credentials: %v", err)
	}
	if userResp.Email != "loginuser@example.com" {
		t.Errorf("expected email loginuser@example.com, got %s", userResp.Email)
	}
	if len(rawToken) != 43 {
		t.Errorf("expected 43-character raw session token, got %d", len(rawToken))
	}

	// Verify session was persisted by hash ONLY
	tokenHash := HashSessionToken(rawToken)
	sess, exists := repo.Sessions[tokenHash]
	if !exists {
		t.Fatalf("session not found in repository under token hash")
	}
	if sess.TokenHash != tokenHash {
		t.Errorf("expected session token hash %s, got %s", tokenHash, sess.TokenHash)
	}

	// Verify audit logs have NO credentials or raw token
	for _, l := range repo.AuditLogs {
		if strings.Contains(string(l.Payload), rawToken) || strings.Contains(string(l.Payload), "ValidPassword") {
			t.Errorf("audit log leaked raw session token or password")
		}
	}

	// 2. Failure: Unknown email
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:    "unknown@example.com",
		Password: "ValidPassword12345!",
	}, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for unknown email, got %v", err)
	}

	// 3. Failure: Wrong password
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:    "loginuser@example.com",
		Password: "WrongPassword12345!",
	}, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}

	// 4. Failure: Inactive user
	u := repo.Users["loginuser@example.com"]
	u.IsActive = false
	repo.Users["loginuser@example.com"] = u
	_, _, err = svc.Login(ctx, loginReq, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for inactive user, got %v", err)
	}

	// 5. Failure: Soft-deleted user
	u.IsActive = true
	u.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	repo.Users["loginuser@example.com"] = u
	_, _, err = svc.Login(ctx, loginReq, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for deleted user, got %v", err)
	}

	// 6. Failure: Portal context mismatch
	// Normal user with portal_context="admin" must receive generic ErrInvalidCredentials
	u.DeletedAt = pgtype.Timestamptz{Valid: false}
	u.IsSuperadmin = false
	repo.Users["loginuser@example.com"] = u
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:         "loginuser@example.com",
		Password:      "ValidPassword12345!",
		PortalContext: "admin",
	}, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for normal user with admin portal context, got %v", err)
	}

	// Superadmin with portal_context="app" must receive generic ErrInvalidCredentials
	u.IsSuperadmin = true
	repo.Users["loginuser@example.com"] = u
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:         "loginuser@example.com",
		Password:      "ValidPassword12345!",
		PortalContext: "app",
	}, &ip, "TestAgent")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for superadmin with app portal context, got %v", err)
	}

	// Superadmin with portal_context="admin" succeeds
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:         "loginuser@example.com",
		Password:      "ValidPassword12345!",
		PortalContext: "admin",
	}, &ip, "TestAgent")
	if err != nil {
		t.Errorf("expected superadmin with admin portal context to authenticate, got %v", err)
	}

	// Normal user with portal_context="app" succeeds
	u.IsSuperadmin = false
	repo.Users["loginuser@example.com"] = u
	_, _, err = svc.Login(ctx, LoginRequest{
		Email:         "loginuser@example.com",
		Password:      "ValidPassword12345!",
		PortalContext: "app",
	}, &ip, "TestAgent")
	if err != nil {
		t.Errorf("expected normal user with app portal context to authenticate, got %v", err)
	}
}

func TestLogin_TransactionRollbackOnAuditFailure(t *testing.T) {
	repo := newMockRepository()
	svc := newTestService(repo)
	ctx := context.Background()

	// Register
	_, _ = svc.Register(ctx, RegisterRequest{
		Email:    "sessionrollback@example.com",
		Password: "ValidPassword12345!",
		FullName: "Rollback User",
	}, nil, "")

	// Set audit failure
	repo.FailLoginSessionAudit = true

	_, _, err := svc.Login(ctx, LoginRequest{
		Email:    "sessionrollback@example.com",
		Password: "ValidPassword12345!",
	}, nil, "")

	if err == nil {
		t.Fatalf("expected error when login session audit fails")
	}

	// Verify no session was persisted
	if len(repo.Sessions) != 0 {
		t.Errorf("session was persisted despite transaction failure")
	}
}

func TestLogout_Idempotency(t *testing.T) {
	repo := newMockRepository()
	svc := newTestService(repo)
	ctx := context.Background()

	// 1. Logout with empty token succeeds
	if err := svc.Logout(ctx, "", nil, ""); err != nil {
		t.Errorf("logout with empty token should succeed: %v", err)
	}

	// 2. Logout with non-existent token succeeds
	if err := svc.Logout(ctx, "non-existent-token", nil, ""); err != nil {
		t.Errorf("logout with non-existent token should succeed: %v", err)
	}

	// 3. Setup user, login, then logout
	_, _ = svc.Register(ctx, RegisterRequest{
		Email:    "logout@example.com",
		Password: "ValidPassword12345!",
		FullName: "Logout User",
	}, nil, "")

	_, token, _ := svc.Login(ctx, LoginRequest{
		Email:    "logout@example.com",
		Password: "ValidPassword12345!",
	}, nil, "")

	tokenHash := HashSessionToken(token)
	if _, exists := repo.Sessions[tokenHash]; !exists {
		t.Fatalf("session should exist before logout")
	}

	// Revoke
	if err := svc.Logout(ctx, token, nil, ""); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	// Session is now revoked in mock
	sess := repo.Sessions[tokenHash]
	if !sess.RevokedAt.Valid {
		t.Errorf("session should be marked revoked")
	}

	// Calling logout again on revoked session still succeeds idempotently
	if err := svc.Logout(ctx, token, nil, ""); err != nil {
		t.Errorf("repeated logout should succeed: %v", err)
	}
}

func TestGetMe(t *testing.T) {
	repo := newMockRepository()
	svc := newTestService(repo)
	ctx := context.Background()

	var uUUID, orgUUID pgtype.UUID
	_ = uUUID.Scan("00000000-0000-0000-0000-000000000001")
	_ = orgUUID.Scan("22222222-2222-2222-2222-222222222222")

	repo.UsersByID[uUUID.String()] = db.User{
		ID:            uUUID,
		Email:         "me@example.com",
		FullName:      "Me User",
		IsActive:      true,
		IsSuperadmin:  false,
		EmailVerified: true,
	}

	repo.Memberships[uUUID.String()] = []db.ListMembershipsByUserIDRow{
		{
			OrganizationID:        orgUUID,
			Role:                  "ADMIN",
			OrganizationLegalName: "Test University",
			OrganizationType:      "INSTITUTE",
			OrganizationStatus:    "VERIFIED",
		},
	}

	me, err := svc.GetMe(ctx, uUUID)
	if err != nil {
		t.Fatalf("GetMe failed: %v", err)
	}

	if me.User.Email != "me@example.com" {
		t.Errorf("expected email me@example.com, got %s", me.User.Email)
	}
	if len(me.Memberships) != 1 {
		t.Fatalf("expected 1 membership, got %d", len(me.Memberships))
	}
	if me.Memberships[0].Role != "ADMIN" {
		t.Errorf("expected role ADMIN, got %s", me.Memberships[0].Role)
	}
}

func TestService_ConfiguredArgon2ParameterParity(t *testing.T) {
	repo := newMockRepository()
	cfg := &config.Config{
		AppEnv:                "test",
		AuthSessionCookieName: "trustdocs_session",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieSecure:      false,
		AuthCookieSameSite:    "Lax",
		CSRFSecret:            "test-csrf-secret-must-be-at-least-32-bytes-long!",
		Argon2Memory:          20480, // Custom memory parameter
		Argon2Iterations:      2,     // Custom iterations
		Argon2Parallelism:     3,     // Custom parallelism
		Argon2SaltLength:      16,
		Argon2KeyLength:       32,
	}

	svc := NewService(repo, cfg)
	dummyHash := svc.GetDummyHash()

	expectedPrefix := "$argon2id$v=19$m=20480,t=2,p=3$"
	if !strings.HasPrefix(dummyHash, expectedPrefix) {
		t.Errorf("expected service dummy hash prefix %s matching configured parameters, got %s", expectedPrefix, dummyHash)
	}
}
