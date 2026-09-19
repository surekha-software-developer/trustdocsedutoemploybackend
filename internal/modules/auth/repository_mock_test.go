package auth

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

var (
	errMockTxRollback = errors.New("simulated transaction failure")
)

// Ensure mockRepository implements Repository interface at compile time.
var _ Repository = (*mockRepository)(nil)

// mockRepository provides an in-memory test double of Repository for isolated unit testing.
// Excluded from production binaries by residing exclusively in this *_test.go file.
type mockRepository struct {
	mu sync.Mutex

	Users       map[string]db.User
	UsersByID   map[string]db.User
	Identities  map[string]db.AuthIdentity
	Sessions    map[string]db.AuthSession
	Memberships map[string][]db.ListMembershipsByUserIDRow
	AuditLogs   []db.AuditLog

	// Test hooks to simulate transactional failures
	FailRegistrationIdentity bool
	FailRegistrationAudit    bool
	FailLoginSessionAudit    bool
	FailCreateUser           bool
	FailGetMembership        bool
	CustomMembership         *db.OrganizationMembership
}

// newMockRepository constructs an empty, initialized mockRepository for tests.
func newMockRepository() *mockRepository {
	return &mockRepository{
		Users:       make(map[string]db.User),
		UsersByID:   make(map[string]db.User),
		Identities:  make(map[string]db.AuthIdentity),
		Sessions:    make(map[string]db.AuthSession),
		Memberships: make(map[string][]db.ListMembershipsByUserIDRow),
		AuditLogs:   make([]db.AuditLog, 0),
	}
}

func (m *mockRepository) CreateUserAndIdentityWithAudit(
	ctx context.Context,
	userParams db.CreateUserParams,
	identityParams db.CreateAuthIdentityParams,
	auditParams db.CreateAuditLogParams,
) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailCreateUser {
		return db.User{}, errMockTxRollback
	}

	if _, exists := m.Users[userParams.Email]; exists {
		return db.User{}, errors.New("unique violation: user email already exists")
	}

	var userUUID pgtype.UUID
	_ = userUUID.Scan("00000000-0000-0000-0000-000000000001")

	u := db.User{
		ID:            userUUID,
		Email:         userParams.Email,
		FullName:      userParams.FullName,
		IsActive:      userParams.IsActive,
		IsSuperadmin:  userParams.IsSuperadmin,
		EmailVerified: userParams.EmailVerified,
	}

	if m.FailRegistrationIdentity {
		return db.User{}, errMockTxRollback
	}

	identKey := identityParams.IdentityType + ":" + identityParams.Identifier
	ident := db.AuthIdentity{
		ID:             userUUID,
		UserID:         userUUID,
		IdentityType:   identityParams.IdentityType,
		Identifier:     identityParams.Identifier,
		CredentialHash: identityParams.CredentialHash,
	}

	if m.FailRegistrationAudit {
		return db.User{}, errMockTxRollback
	}

	audit := db.AuditLog{
		ActorUserID:  userUUID,
		Action:       auditParams.Action,
		ResourceType: auditParams.ResourceType,
		ResourceID:   userUUID,
		Payload:      auditParams.Payload,
	}

	m.Users[userParams.Email] = u
	m.UsersByID[userUUID.String()] = u
	m.Identities[identKey] = ident
	m.AuditLogs = append(m.AuditLogs, audit)

	return u, nil
}

func (m *mockRepository) CreateSessionAndSuccessAudit(
	ctx context.Context,
	sessionParams db.CreateAuthSessionParams,
	auditParams db.CreateAuditLogParams,
) (db.CreateAuthSessionRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var sessionUUID pgtype.UUID
	_ = sessionUUID.Scan("11111111-1111-1111-1111-111111111111")

	if m.FailLoginSessionAudit {
		return db.CreateAuthSessionRow{}, errMockTxRollback
	}

	row := db.CreateAuthSessionRow{
		ID:        sessionUUID,
		UserID:    sessionParams.UserID,
		UserAgent: sessionParams.UserAgent,
		IpAddress: sessionParams.IpAddress,
		ExpiresAt: sessionParams.ExpiresAt,
	}

	m.Sessions[sessionParams.TokenHash] = db.AuthSession{
		ID:        sessionUUID,
		UserID:    sessionParams.UserID,
		TokenHash: sessionParams.TokenHash,
		UserAgent: sessionParams.UserAgent,
		IpAddress: sessionParams.IpAddress,
		ExpiresAt: sessionParams.ExpiresAt,
	}

	m.AuditLogs = append(m.AuditLogs, db.AuditLog{
		ActorUserID:  sessionParams.UserID,
		Action:       auditParams.Action,
		ResourceType: auditParams.ResourceType,
		ResourceID:   sessionUUID,
		Payload:      auditParams.Payload,
	})

	return row, nil
}

func (m *mockRepository) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, exists := m.Users[email]
	if !exists {
		return db.User{}, errors.New("no rows in result set")
	}
	return u, nil
}

func (m *mockRepository) GetAuthIdentityForVerification(ctx context.Context, identityType string, identifier string) (db.AuthIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	identKey := identityType + ":" + identifier
	ident, exists := m.Identities[identKey]
	if !exists {
		return db.AuthIdentity{}, errors.New("no rows in result set")
	}
	return ident, nil
}

func (m *mockRepository) CreateAuditLog(ctx context.Context, auditParams db.CreateAuditLogParams) (db.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	audit := db.AuditLog{
		ActorUserID:  auditParams.ActorUserID,
		Action:       auditParams.Action,
		ResourceType: auditParams.ResourceType,
		ResourceID:   auditParams.ResourceID,
		Payload:      auditParams.Payload,
	}
	m.AuditLogs = append(m.AuditLogs, audit)
	return audit, nil
}

func (m *mockRepository) GetAuthSessionByHash(ctx context.Context, tokenHash string) (db.AuthSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.Sessions[tokenHash]
	if !exists {
		return db.AuthSession{}, errors.New("no rows in result set")
	}
	if sess.RevokedAt.Valid {
		return db.AuthSession{}, errors.New("session is revoked")
	}
	return sess, nil
}

func (m *mockRepository) RevokeAuthSession(ctx context.Context, sessionID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, sess := range m.Sessions {
		if sess.ID == sessionID {
			sess.RevokedAt = pgtype.Timestamptz{Valid: true}
			m.Sessions[k] = sess
			return nil
		}
	}
	return nil
}

func (m *mockRepository) GetUserByID(ctx context.Context, userID pgtype.UUID) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, exists := m.UsersByID[userID.String()]
	if !exists {
		return db.User{}, errors.New("no rows in result set")
	}
	return u, nil
}

func (m *mockRepository) ListMembershipsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListMembershipsByUserIDRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.Memberships[userID.String()], nil
}

func (m *mockRepository) GetMembership(ctx context.Context, orgID pgtype.UUID, userID pgtype.UUID) (db.OrganizationMembership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailGetMembership {
		return db.OrganizationMembership{}, errors.New("no rows in result set")
	}
	if m.CustomMembership != nil {
		return *m.CustomMembership, nil
	}

	return db.OrganizationMembership{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           "ADMIN",
		IsActive:       true,
	}, nil
}
