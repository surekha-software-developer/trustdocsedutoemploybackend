BEGIN;

-- ============================================================================
-- 1. USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_superadmin BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_users_email_canonical CHECK (email = LOWER(BTRIM(email))),
    CONSTRAINT chk_users_email_sanity CHECK (
        position('@' IN email) > 1 AND
        position('.' IN email) > position('@' IN email) + 1
    )
);

-- Global case-insensitive email uniqueness (including soft-deleted accounts)
CREATE UNIQUE INDEX idx_users_email_lower ON users (LOWER(email));

-- ============================================================================
-- 2. AUTH IDENTITIES TABLE (Decoupled Authentication Methods)
-- ============================================================================
CREATE TABLE auth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255) NOT NULL,
    credential_hash VARCHAR(255) NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_auth_identities_type CHECK (
        identity_type IN ('EMAIL_PASSWORD', 'GOOGLE_OAUTH')
    ),
    CONSTRAINT chk_auth_identities_canonical CHECK (
        (identity_type = 'EMAIL_PASSWORD' AND identifier = LOWER(BTRIM(identifier))) OR
        (identity_type != 'EMAIL_PASSWORD')
    ),
    CONSTRAINT chk_auth_identities_credential CHECK (
        (identity_type = 'EMAIL_PASSWORD' AND credential_hash IS NOT NULL) OR
        (identity_type = 'GOOGLE_OAUTH' AND credential_hash IS NULL)
    ),
    CONSTRAINT uq_auth_identities_type_identifier UNIQUE (identity_type, identifier)
);

CREATE INDEX idx_auth_identities_user_id ON auth_identities (user_id);
CREATE UNIQUE INDEX idx_auth_identities_email_lower ON auth_identities (LOWER(identifier))
    WHERE identity_type = 'EMAIL_PASSWORD';

-- ============================================================================
-- 3. AUTH SESSIONS TABLE (Hashed Refresh Tokens)
-- ============================================================================
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NULL,
    ip_address INET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_auth_sessions_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_auth_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_auth_sessions_revocation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX idx_auth_sessions_user_id ON auth_sessions (user_id);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions (expires_at);

-- ============================================================================
-- 4. ORGANIZATIONS TABLE (Universities & Companies)
-- ============================================================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_type VARCHAR(50) NOT NULL,
    legal_name VARCHAR(255) NOT NULL,
    trade_name VARCHAR(255) NULL,
    country_code CHAR(2) NOT NULL,
    registration_number VARCHAR(100) NOT NULL,
    official_domain VARCHAR(255) NOT NULL,
    verification_status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    reviewed_by_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    reviewed_at TIMESTAMPTZ NULL,
    decision_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_organizations_type CHECK (org_type IN ('UNIVERSITY', 'COMPANY')),
    CONSTRAINT chk_organizations_status CHECK (
        verification_status IN ('PENDING', 'VERIFIED', 'REJECTED', 'SUSPENDED')
    ),
    CONSTRAINT chk_organizations_country_canonical CHECK (
        country_code = UPPER(BTRIM(country_code)) AND country_code ~ '^[A-Z]{2}$'
    ),
    CONSTRAINT chk_organizations_reg_canonical CHECK (
        registration_number = UPPER(BTRIM(registration_number))
    ),
    CONSTRAINT chk_organizations_domain_canonical CHECK (
        official_domain = LOWER(BTRIM(official_domain)) AND
        official_domain !~ '[:/\\?#]'
    ),
    CONSTRAINT chk_organizations_status_consistency CHECK (
        (verification_status = 'PENDING' AND reviewed_by_user_id IS NULL AND reviewed_at IS NULL AND decision_reason IS NULL) OR
        (verification_status = 'VERIFIED' AND reviewed_by_user_id IS NOT NULL AND reviewed_at IS NOT NULL) OR
        (verification_status IN ('REJECTED', 'SUSPENDED') AND reviewed_by_user_id IS NOT NULL AND reviewed_at IS NOT NULL AND decision_reason IS NOT NULL)
    ),
    CONSTRAINT uq_organizations_country_registration UNIQUE (country_code, registration_number)
);

CREATE UNIQUE INDEX idx_organizations_domain_lower ON organizations (LOWER(official_domain))
    WHERE deleted_at IS NULL;
CREATE INDEX idx_organizations_status ON organizations (verification_status);

-- ============================================================================
-- 5. ORGANIZATION MEMBERSHIPS TABLE (Tenancy & Functional RBAC)
-- ============================================================================
CREATE TABLE organization_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_org_memberships_role CHECK (
        role IN ('UNIVERSITY_ADMIN', 'UNIVERSITY_ISSUER', 'COMPANY_ADMIN', 'COMPANY_VERIFIER')
    ),
    CONSTRAINT uq_org_memberships_org_user UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_org_memberships_user_id ON organization_memberships (user_id);
CREATE INDEX idx_org_memberships_org_id ON organization_memberships (organization_id);

-- ============================================================================
-- 6. AUDIT LOGS TABLE (Application-Level Append-Only Compliance Trail)
-- ============================================================================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_organization_id UUID NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID NOT NULL,
    payload JSONB NULL,
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_org_created ON audit_logs (target_organization_id, created_at DESC);
CREATE INDEX idx_audit_logs_actor_created ON audit_logs (actor_user_id, created_at DESC);

COMMIT;
