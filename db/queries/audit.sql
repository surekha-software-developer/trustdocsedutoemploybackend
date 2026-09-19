-- name: CreateAuditLog :one
-- Immutable append-only audit event record.
INSERT INTO audit_logs (
    actor_user_id, target_organization_id, action, resource_type, resource_id, payload, ip_address, user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING id, actor_user_id, target_organization_id, action, resource_type, resource_id, payload, ip_address, user_agent, created_at;

-- name: ListAuditLogsByOrg :many
SELECT id, actor_user_id, target_organization_id, action, resource_type, resource_id, payload, ip_address, user_agent, created_at
FROM audit_logs
WHERE target_organization_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByActor :many
SELECT id, actor_user_id, target_organization_id, action, resource_type, resource_id, payload, ip_address, user_agent, created_at
FROM audit_logs
WHERE actor_user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
