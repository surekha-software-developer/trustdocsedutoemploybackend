package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

// Repository defines the data access contract for authentication and RBAC operations.
type Repository interface {
	CreateUserAndIdentityWithAudit(
		ctx context.Context,
		userParams db.CreateUserParams,
		identityParams db.CreateAuthIdentityParams,
		auditParams db.CreateAuditLogParams,
	) (db.User, error)

	CreateSessionAndSuccessAudit(
		ctx context.Context,
		sessionParams db.CreateAuthSessionParams,
		auditParams db.CreateAuditLogParams,
	) (db.CreateAuthSessionRow, error)

	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetAuthIdentityForVerification(ctx context.Context, identityType string, identifier string) (db.AuthIdentity, error)
	CreateAuditLog(ctx context.Context, auditParams db.CreateAuditLogParams) (db.AuditLog, error)
	GetAuthSessionByHash(ctx context.Context, tokenHash string) (db.AuthSession, error)
	RevokeAuthSession(ctx context.Context, sessionID pgtype.UUID) error
	GetUserByID(ctx context.Context, userID pgtype.UUID) (db.User, error)
	ListMembershipsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListMembershipsByUserIDRow, error)
	GetMembership(ctx context.Context, orgID pgtype.UUID, userID pgtype.UUID) (db.OrganizationMembership, error)
}

// PgxRepository implements Repository using pgxpool.Pool and sqlc queries with explicit transactions.
type PgxRepository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewPgxRepository constructs a new PgxRepository.
func NewPgxRepository(pool *pgxpool.Pool) *PgxRepository {
	return &PgxRepository{
		pool:    pool,
		queries: db.New(pool),
	}
}

// CreateUserAndIdentityWithAudit executes user creation, password identity creation, and initial audit log
// atomically in a single database transaction.
func (r *PgxRepository) CreateUserAndIdentityWithAudit(
	ctx context.Context,
	userParams db.CreateUserParams,
	identityParams db.CreateAuthIdentityParams,
	auditParams db.CreateAuditLogParams,
) (db.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.User{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	user, err := qtx.CreateUser(ctx, userParams)
	if err != nil {
		return db.User{}, err
	}

	identityParams.UserID = user.ID
	_, err = qtx.CreateAuthIdentity(ctx, identityParams)
	if err != nil {
		return db.User{}, err
	}

	auditParams.ActorUserID = user.ID
	auditParams.ResourceID = user.ID
	_, err = qtx.CreateAuditLog(ctx, auditParams)
	if err != nil {
		return db.User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.User{}, err
	}

	return user, nil
}

// CreateSessionAndSuccessAudit executes session creation and LOGIN_SUCCESS audit log atomically
// in a single transaction.
func (r *PgxRepository) CreateSessionAndSuccessAudit(
	ctx context.Context,
	sessionParams db.CreateAuthSessionParams,
	auditParams db.CreateAuditLogParams,
) (db.CreateAuthSessionRow, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.CreateAuthSessionRow{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	session, err := qtx.CreateAuthSession(ctx, sessionParams)
	if err != nil {
		return db.CreateAuthSessionRow{}, err
	}

	auditParams.ResourceID = session.ID
	_, err = qtx.CreateAuditLog(ctx, auditParams)
	if err != nil {
		return db.CreateAuthSessionRow{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.CreateAuthSessionRow{}, err
	}

	return session, nil
}

func (r *PgxRepository) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	return r.queries.GetUserByEmail(ctx, email)
}

func (r *PgxRepository) GetAuthIdentityForVerification(ctx context.Context, identityType string, identifier string) (db.AuthIdentity, error) {
	return r.queries.GetAuthIdentityForVerification(ctx, db.GetAuthIdentityForVerificationParams{
		IdentityType: identityType,
		Identifier:   identifier,
	})
}

func (r *PgxRepository) CreateAuditLog(ctx context.Context, auditParams db.CreateAuditLogParams) (db.AuditLog, error) {
	return r.queries.CreateAuditLog(ctx, auditParams)
}

func (r *PgxRepository) GetAuthSessionByHash(ctx context.Context, tokenHash string) (db.AuthSession, error) {
	return r.queries.GetAuthSessionByHash(ctx, tokenHash)
}

func (r *PgxRepository) RevokeAuthSession(ctx context.Context, sessionID pgtype.UUID) error {
	return r.queries.RevokeAuthSession(ctx, sessionID)
}

func (r *PgxRepository) GetUserByID(ctx context.Context, userID pgtype.UUID) (db.User, error) {
	return r.queries.GetUserByID(ctx, userID)
}

func (r *PgxRepository) ListMembershipsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListMembershipsByUserIDRow, error) {
	return r.queries.ListMembershipsByUserID(ctx, userID)
}

func (r *PgxRepository) GetMembership(ctx context.Context, orgID pgtype.UUID, userID pgtype.UUID) (db.OrganizationMembership, error) {
	return r.queries.GetMembership(ctx, db.GetMembershipParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
}
