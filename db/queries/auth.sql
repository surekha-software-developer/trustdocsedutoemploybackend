-- Provider Subject/Identifier Semantics:
-- For EMAIL_PASSWORD: identifier is the user's normalized canonical lowercase email address.
-- For GOOGLE_OAUTH: identifier is the immutable Google OAuth Subject ID ('sub' claim).

-- name: GetAuthIdentityForVerification :one
-- Strictly internal query for password verification service; selects credential_hash.
SELECT id, user_id, identity_type, identifier, credential_hash, metadata, created_at, updated_at
FROM auth_identities
WHERE identity_type = $1 AND identifier = $2;

-- name: ListUserAuthIdentities :many
-- Public query for user profile/security settings; credential_hash is deliberately excluded.
SELECT id, user_id, identity_type, identifier, created_at, updated_at
FROM auth_identities
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: CreateAuthIdentity :one
INSERT INTO auth_identities (
    user_id, identity_type, identifier, credential_hash, metadata
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id, user_id, identity_type, identifier, created_at, updated_at;

-- name: CreateAuthSession :one
INSERT INTO auth_sessions (
    user_id, token_hash, user_agent, ip_address, expires_at
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id, user_id, user_agent, ip_address, expires_at, created_at;

-- name: GetAuthSessionByHash :one
SELECT id, user_id, token_hash, user_agent, ip_address, expires_at, revoked_at, created_at
FROM auth_sessions
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW();

-- name: ListUserSessions :many
-- Excludes token_hash to prevent secret token leakage in session management views.
SELECT id, user_id, user_agent, ip_address, expires_at, revoked_at, created_at
FROM auth_sessions
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: RevokeAuthSession :exec
UPDATE auth_sessions
SET revoked_at = NOW()
WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserSessions :exec
UPDATE auth_sessions
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredAndRevokedSessions :exec
DELETE FROM auth_sessions
WHERE expires_at < NOW() OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '30 days');
