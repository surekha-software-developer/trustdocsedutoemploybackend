-- name: GetUserByID :one
SELECT id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at
FROM users
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at
FROM users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL;

-- name: CreateUser :one
INSERT INTO users (
    email, full_name, is_active, is_superadmin, email_verified
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at;

-- name: UpdateUser :one
UPDATE users
SET
    full_name = $2,
    email_verified = $3,
    is_active = $4,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at;

-- name: SoftDeleteUser :exec
UPDATE users
SET
    deleted_at = NOW(),
    is_active = FALSE,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: RestoreUser :one
UPDATE users
SET
    deleted_at = NULL,
    is_active = TRUE,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NOT NULL
RETURNING id, email, full_name, is_active, is_superadmin, email_verified, created_at, updated_at, deleted_at;
