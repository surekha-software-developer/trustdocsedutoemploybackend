BEGIN;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS organization_memberships;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS auth_identities;
DROP TABLE IF EXISTS users;

COMMIT;
