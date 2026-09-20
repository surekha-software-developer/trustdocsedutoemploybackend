# TrustDocs Education to Employment - Backend

The core REST API backend service for the TrustDocs education-to-employment verification platform.

---

## Overview

TrustDocs connects verified university education with verified employment. This backend service powers tamper-evident digital certificate verification, scoped consent-based QR verification, and the Continuous Identity Chain across hiring milestones.

---

## Current Status: Phase 5A — Academic Certificate Issuance, Verification & R2 Storage Foundation Verified

- **Language / Runtime**: Go `1.26.1`
- **Module Path**: `github.com/surekha-software-developer/trustdocsedutoemploybackend`
- **HTTP Web Framework**: Gin (`v1.12.0`)
- **Database Driver & Pooling**: `pgx/v5` (`github.com/jackc/pgx/v5` & `github.com/jackc/pgx/v5/pgxpool`)
- **Migration Engine**: `golang-migrate` (`github.com/golang-migrate/migrate/v4`) using `pgx/v5` driver
- **Code Generation**: `sqlc` (`v1.28.0`) targeting PostgreSQL `pgx/v5`
- **Password Hashing**: Argon2id (`golang.org/x/crypto/argon2`) with CSPRNG salts, PHC format, and constant-time verification
- **Password Policy**: NIST/OWASP-aligned Phase 4A policy (15 Unicode code-point minimum, 256 UTF-8 byte maximum, Unicode/emojis/spaces allowed, zero arbitrary composition rules, no silent truncation)
- **Session Management**: Cryptographically secure 32-byte CSPRNG session tokens, SHA-256 hash-only storage, Host-Only cookies (`Path=/api`, `HttpOnly=true`, `SameSite=Lax`)
- **CSRF Defense**: Session-bound `HMAC-SHA256(CSRF_SECRET, "csrf:v1:" + rawSessionToken)` tokens with domain separation, strict Origin/Referer allowlist validation, `Content-Type: application/json` enforcement, and `Cache-Control: no-store` on distribution
- **Anti-Enumeration**: Generic 200 OK on `/register` (identical for new and duplicate registrations); uniform 401 `INVALID_CREDENTIALS` on all login failures with dummy Argon2id timing equalization; uniform 403 on missing protected tenants; uniform 404 on unverified or non-existent public organizations; uniform 404 on unissued certificate drafts or non-existent certificates
- **Rate Limiting**: Sliding-window in-memory rate limiter with bounded memory, LRU eviction, integer `Retry-After` header on 429, domain-separated HMAC account keys (`"rate-limit:v1:"`), per-account-per-IP tracking, independent per-IP limits, and public directory / public verification throttling (60 requests/minute/IP)
- **Multi-Tenant RBAC & Portal Isolation**: Route middleware guards (`RequireAuth`, `RequireSuperadmin`, `RequireNonSuperadmin`, `RequireOrgMembership`, `RequireOrgRole`)
- **Cloudflare R2 Object Storage**: S3-compatible private object storage for certificate PDF blobs, SHA-256 content addressing, zero recipient PII in storage keys, short-lived presigned download URLs (maximum 5 minutes), and automatic upload compensation and deletion cleanup
- **Document Integrity & Tamper-Evidence**: Strict 10 MiB file limits, `application/pdf` MIME validation, `%PDF-` magic-byte inspection, SHA-256 hexadecimal hashing, and partial unique index guaranteeing document hash uniqueness across all finalized certificates
- **Public Verification Privacy**: Masked recipient name algorithm (`Jane Doe` -> `J*** D**`), complete omission of student emails, IDs, and storage paths, and public rate limiting (60 requests/minute/IP)
- **Structured Logging & Audit**: Native `log/slog` JSON output and append-only database audit logs excluding all PII, emails, passwords, tokens, secret hashes, and free-text review comments
- **Verification Milestones**:
  - **Phase 3A**: Neon PostgreSQL infrastructure & dual-connection foundation completed.
  - **Phase 3B**: MVP authentication and organizations schema completed.
  - **Phase 4A**: Backend authentication, rate limiting, and multi-tenant RBAC foundation completed and verified (100% pass across all unit tests and 12 database integration tests).
  - **Phase 4B**: Organization onboarding, superadmin review & dossier, approval/rejection lifecycle, initial admin membership activation, verified organization access, member listing, and public discovery completed and verified (100% pass across all unit tests and 13 database integration tests).
  - **Phase 5A**: Academic certificate lifecycle (`DRAFT`, `ISSUED`, `REVOKED`, `REPLACED`), university issuer certificate management, PDF upload validation & SHA-256 hashing, Cloudflare R2 private object storage integration, short-lived presigned download URLs, status-dependent download authorization rules, student Career Trust Passport endpoints, public certificate verification with masked recipient name, replacement lineage and atomic concurrency controls, migration 000002, and comprehensive unit and database integration test suites completed and verified.
  - **Deferred**: Blockchain / Merkle tree cryptographic batch anchoring (Phase 5B), consent-scoped QR verification tokens & employer verification logs (Phase 6), member invitations and membership mutation, rejection appeal/reapplication, and employment credential verification with Continuous Identity Chain (Phase 7+).

---

## Architecture

The backend follows a scalable, **modular-monolith** architecture. Each domain module encapsulates its own business logic, HTTP handlers, routes, and data access layers.

### Directory Structure

```text
trustdocsedutoemploybackend/
├── cmd/
│   ├── api/
│   │   └── main.go                  # API entry point, pgxpool lifecycle & graceful shutdown
│   └── migrate/
│       ├── main.go                  # Dedicated migration runner CLI (requires DATABASE_DIRECT_URL)
│       └── main_test.go             # Migration safety & command unit tests
├── db/
│   ├── migrations/
│   │   ├── 000001_create_mvp_auth_and_organizations.up.sql   # Phase 3B MVP schema
│   │   ├── 000001_create_mvp_auth_and_organizations.down.sql # Phase 3B teardown
│   │   ├── 000002_create_certificates_schema.up.sql         # Phase 5A certificates schema
│   │   └── 000002_create_certificates_schema.down.sql       # Phase 5A certificates teardown
│   ├── queries/
│   │   ├── audit.sql                # sqlc query definitions for audit logs
│   │   ├── auth.sql                 # sqlc query definitions for sessions & identities
│   │   ├── certificates.sql         # sqlc query definitions for academic certificates
│   │   ├── memberships.sql          # sqlc query definitions for organization memberships
│   │   ├── organizations.sql        # sqlc query definitions for organizations
│   │   └── users.sql                # sqlc query definitions for users
│   └── sqlc/
│       ├── audit.sql.go             # Generated Go models & methods for audit logs
│       ├── auth.sql.go              # Generated Go models & methods for auth
│       ├── certificates.sql.go      # Generated Go models & methods for certificates
│       ├── db.go                    # Generated DBTX interface & factory
│       ├── memberships.sql.go       # Generated Go models & methods for memberships
│       ├── models.go                # Generated Go domain struct models
│       ├── organizations.sql.go     # Generated Go models & methods for organizations
│       └── users.sql.go             # Generated Go models & methods for users
├── internal/
│   ├── config/
│   │   ├── config.go                # Process environment variable loader & validation
│   │   └── config_test.go           # Configuration & pool option unit tests
│   ├── core/
│   │   ├── errors.go                # Standard API error codes & AppError types
│   │   ├── logger.go                # Structured slog JSON logger
│   │   ├── response.go              # Consistent Success/Error JSON envelope responders
│   │   └── response_test.go         # Response envelope unit tests
│   ├── database/
│   │   ├── postgres.go              # pgxpool factory with compile-time health.Pinger assertion
│   │   └── schema_test.go           # Migration file syntax & safety unit tests
│   ├── middleware/
│   │   ├── authentication.go        # Session token verification & context injector
│   │   ├── authentication_test.go   # Authentication middleware tests
│   │   ├── authorization.go         # RBAC route guards (Superadmin, Org Membership, Org Role)
│   │   ├── authorization_test.go    # Authorization middleware tests
│   │   ├── cors.go                  # Restricted cross-origin protection
│   │   ├── logging.go               # Structured request logging excluding secrets
│   │   ├── origin_csrf.go           # Origin/Referer & session-bound HMAC CSRF validation
│   │   ├── origin_csrf_test.go      # Origin & CSRF middleware tests
│   │   ├── ratelimit.go             # IP and account sliding-window rate limiters
│   │   ├── ratelimit_test.go        # Rate limiting middleware tests
│   │   ├── recovery.go              # Safe panic recovery with sanitized JSON 500
│   │   ├── request_id.go            # RFC 4122 UUID v4 request ID tracing
│   │   └── request_id_test.go       # Request ID tests
│   ├── modules/
│   │   ├── auth/
│   │   │   ├── auth_integration_test.go # Isolated database integration test suite (Phase 4A)
│   │   │   ├── handler.go           # HTTP handlers for register, login, csrf, logout, me
│   │   │   ├── handler_test.go      # Auth HTTP handler unit tests
│   │   │   ├── password.go          # Argon2id hashing & NIST password policy validation
│   │   │   ├── password_test.go     # Password hashing & policy tests
│   │   │   ├── ratelimit.go         # Bounded sliding-window memory store with LRU eviction
│   │   │   ├── ratelimit_test.go    # Rate limiter store tests
│   │   │   ├── repository.go        # Auth data access interface & pgxpool implementation
│   │   │   ├── repository_mock_test.go # Mock repository for isolated service testing
│   │   │   ├── request.go           # Input payload DTOs & canonical sanitization
│   │   │   ├── response.go          # Auth response DTOs
│   │   │   ├── routes.go            # Auth route registration
│   │   │   ├── service.go           # Auth business logic, timing equalization & audit
│   │   │   ├── service_test.go      # Auth domain service unit tests
│   │   │   ├── session.go           # CSPRNG session token generator & cookie helpers
│   │   │   └── session_test.go      # Session helper tests
│   │   ├── certificates/
│   │   │   ├── certificates_integration_test.go # Guarded database integration test suite (Phase 5A)
│   │   │   ├── dto_test.go          # Certificate DTO validation & masking unit tests
│   │   │   ├── handler.go           # HTTP handlers for certificate CRUD, upload, issue, download
│   │   │   ├── handler_test.go      # Certificate HTTP handler unit tests
│   │   │   ├── repository.go        # Certificate repository interface & pgx queries
│   │   │   ├── repository_mock_test.go # Mock repository for isolated certificate testing
│   │   │   ├── request.go           # Certificate request DTOs & sanitization
│   │   │   ├── response.go          # Certificate response DTOs, masking & projection
│   │   │   ├── routes.go            # Certificate route registration with middleware chains
│   │   │   ├── service.go           # Core certificate lifecycle business logic & compensation
│   │   │   └── service_test.go      # Certificate domain service unit tests
│   │   ├── health/
│   │   │   ├── handler.go           # /health and dynamic /ready HTTP handlers
│   │   │   ├── handler_test.go      # Health unit tests (200, 503, timeout, recovery)
│   │   │   ├── routes.go            # Health route registration
│   │   │   └── service.go           # Health domain service (Ping(ctx) with timeout)
│   │   └── organizations/
│   │       ├── handler.go           # HTTP handlers for application, review, profile, discovery
│   │       ├── handler_test.go      # Organization HTTP handler unit tests
│   │       ├── organizations_integration_test.go # Guarded database integration test suite (Phase 4B)
│   │       ├── repository.go        # Organization data access interface & pgxpool queries
│   │       ├── repository_mock_test.go # Mock repository for isolated service testing
│   │       ├── request.go           # Request DTOs, uppercase/lowercase canonical sanitization
│   │       ├── response.go          # Response DTOs & privacy projections
│   │       ├── routes.go            # Route registration (public, applicant, tenant, admin)
│   │       ├── service.go           # Core business logic, row-locking review & audit
│   │       └── service_test.go      # Organization domain service unit tests
│   ├── router/
│   │   ├── router.go                # Gin engine setup, middleware chain & route mounting
│   │   └── router_test.go           # 404, 405, CORS, and recovery tests
│   ├── server/
│   │   └── server.go                # HTTP server with safe timeouts
│   └── storage/
│       ├── mock.go                  # Thread-safe in-memory ObjectStorage mock for testing
│       ├── r2.go                    # Cloudflare R2 implementation via AWS SDK v2
│       ├── storage.go               # ObjectStorage interface & standard storage errors
│       └── storage_test.go          # Storage unit tests (R2 construction, TTL validation)
├── sqlc.yaml                        # sqlc configuration for PostgreSQL pgx/v5
├── .env.example                     # Environment variable reference template
├── .gitignore                       # Git ignore rules
├── go.mod                           # Go module declaration
├── go.sum                           # Dependency checksums
└── README.md                        # Project documentation
```

---

## Configuration & Environment Variables

> [!IMPORTANT]
> **Configuration Source**: Third-party environment file loaders (such as `godotenv`) are deliberately excluded. Configuration is read strictly from **process environment variables** or safe default fallbacks. The application does **not** automatically parse a `.env` file at runtime.
>
> Use `.env.example` as a variable reference when deploying or configuring local shell environments.

| Variable | Description | Default | Supported Values |
|---|---|---|---|
| `APP_ENV` | Application environment | `development` | `development`, `production`, `test` |
| `PORT` | HTTP server listening port | `8080` | `1024-65535` |
| `FRONTEND_URL` | Allowed origin for CORS | `http://localhost:3000` | Full URL (e.g. `http://localhost:3000`) |
| `LOG_LEVEL` | Logging verbosity | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | Neon pooled connection string (PgBouncer) | `""` | `postgres://` or `postgresql://` URL (Required for `cmd/api`) |
| `DATABASE_DIRECT_URL` | Neon direct compute connection string | `""` | `postgres://` or `postgresql://` URL (Required for `cmd/migrate`) |
| `DB_MAX_CONNS` | Maximum open connections in pgxpool | `5` | Integer `>= 1` |
| `DB_MIN_CONNS` | Minimum idle connections in pgxpool | `0` | Integer `>= 0` and `<= DB_MAX_CONNS` |
| `DB_MAX_CONN_LIFETIME` | Maximum lifetime of a pooled connection | `30m` | Go duration string (e.g. `30m`, `1h`) |
| `DB_MAX_CONN_IDLE_TIME` | Maximum idle time before recycling | `5m` | Go duration string (e.g. `5m`, `10m`) |
| `DB_HEALTH_TIMEOUT` | Database readiness probe timeout | `2s` | Go duration string (e.g. `2s`, `5s`) |
| `AUTH_SESSION_COOKIE_NAME` | Name of Host-Only session cookie | `trustdocs_session` | Non-empty string |
| `AUTH_SESSION_TTL` | Lifespan of active user sessions | `24h` | Positive duration string (e.g. `24h`, `12h`) |
| `AUTH_COOKIE_SECURE` | Enforce Secure flag on cookies | `true` (prod), `false` (dev/test) | `true`, `false` |
| `AUTH_COOKIE_SAME_SITE` | SameSite attribute for session cookie | `Lax` | `Lax`, `Strict`, `None` |
| `CSRF_SECRET` | Secret key for session-bound HMAC CSRF | `""` (dev fallback) | At least 32 random bytes in production |
| `ARGON2_MEMORY` | Argon2id memory parameter in KiB | `65536` (64 MB) | Unsigned integer `>= 16384` |
| `ARGON2_ITERATIONS` | Argon2id time cost (iterations) | `3` | Integer `1-10` |
| `ARGON2_PARALLELISM` | Argon2id thread lanes | `2` | Integer `1-16` |
| `ARGON2_SALT_LENGTH` | Argon2id salt length in bytes | `16` | Integer `>= 16` |
| `ARGON2_KEY_LENGTH` | Argon2id derived key length in bytes | `32` | Integer `>= 32` |
| `RATE_LIMIT_LOGIN_ATTEMPTS` | Maximum login attempts per window | `5` | Integer `>= 1` |
| `RATE_LIMIT_LOGIN_WINDOW` | Login rate-limit window duration | `15m` | Positive duration string |
| `RATE_LIMIT_IP_ATTEMPTS` | Maximum IP requests per window | `20` | Integer `>= 1` |
| `RATE_LIMIT_IP_WINDOW` | IP rate-limit window duration | `15m` | Positive duration string |
| `RATE_LIMIT_REGISTER_ATTEMPTS` | Maximum register attempts per window | `10` | Integer `>= 1` |
| `RATE_LIMIT_REGISTER_WINDOW` | Register rate-limit window duration | `1h` | Positive duration string |
| `TRUSTED_PROXIES` | Comma-separated trusted upstream proxies | `127.0.0.1,::1` | Comma-separated IP/CIDR strings |
| `R2_ACCOUNT_ID` | Cloudflare account ID for R2 endpoint | `""` | Non-empty hex string (required for API unless `R2_ENDPOINT` set) |
| `R2_ACCESS_KEY_ID` | Cloudflare R2 S3 API access key ID | `""` | Non-empty string (required for `cmd/api`) |
| `R2_SECRET_ACCESS_KEY` | Cloudflare R2 S3 API secret access key | `""` | Non-empty string (required for `cmd/api`) |
| `R2_BUCKET_NAME` | Cloudflare R2 private bucket name | `""` | Non-empty string (required for `cmd/api`) |
| `R2_ENDPOINT` | Explicit S3 HTTPS endpoint override | `""` | HTTPS URL (e.g. `https://<account_id>.r2.cloudflarestorage.com`) |
| `R2_PRESIGN_TTL` | Presigned download URL lifespan | `5m` | Positive duration string `<= 5m` |
| `CERTIFICATE_MAX_FILE_SIZE` | Maximum certificate PDF upload size | `10485760` (10 MiB) | Positive integer between `1` and `10485760` bytes |

### Connection Separation: Pooled API vs. Direct Migrations

- **API Service (`cmd/api`)**: Uses `DATABASE_URL` to connect to Neon through PgBouncer (transaction pooling mode). `DATABASE_DIRECT_URL` is **not** required for `cmd/api`.
- **Migration Runner (`cmd/migrate`)**: Requires `DATABASE_DIRECT_URL` to connect directly to the PostgreSQL compute instance. `cmd/migrate` **never** falls back to `DATABASE_URL`. If `DATABASE_DIRECT_URL` is absent, `cmd/migrate` aborts immediately.
- **Secrecy**: Connection strings and credentials are never logged, printed, or exposed in errors or HTTP responses.

### Cloudflare R2 Object Storage Configuration & Validation

The API server (`cmd/api`) validates object storage configuration at startup via `cfg.ValidateForAPI()`:
- **Full Configuration Enforcement**: If any R2 variable is set, `R2_BUCKET_NAME`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and either `R2_ACCOUNT_ID` or `R2_ENDPOINT` are strictly required. Partial setups trigger a startup validation error.
- **HTTPS Enforcement**: Any custom `R2_ENDPOINT` must strictly start with `https://`. Plain HTTP endpoints are rejected.
- **Presigned URL TTL Cap**: `R2_PRESIGN_TTL` is validated to ensure it is positive and does not exceed **5 minutes** (`MaxPresignTTL = 5 * time.Minute`). Requests attempting longer TTLs are rejected at startup.
- **File Size Ceiling**: `CERTIFICATE_MAX_FILE_SIZE` defaults to `10485760` bytes (10 MiB) and cannot exceed this ceiling.

---

## Database Schema & Migrations

### Phase 3 MVP Schema Overview

The database schema (`db/migrations/000001_create_mvp_auth_and_organizations.up.sql`) establishes the core multi-tenant entity foundation:

1. **`users`**: UUID primary key, canonical lowercase trimmed email (`chk_users_email_canonical`), full name, `is_active`, `is_superadmin`, `email_verified`, timestamps.
2. **`auth_identities`**: `user_id` foreign key, authentication provider (`LOCAL`, `GOOGLE`, `MICROSOFT`), provider subject, Argon2id `password_hash`.
3. **`auth_sessions`**: UUID primary key, `user_id` foreign key, `token_hash` (SHA-256 hex string), `portal_context` (`app`, `admin`), client IP, user agent, timestamps. Enforces:
   - `chk_auth_sessions_expiry CHECK (expires_at > created_at)`
   - `chk_auth_sessions_revocation CHECK (revoked_at IS NULL OR revoked_at >= created_at)`
4. **`organizations`**: UUID primary key, `org_type` (`UNIVERSITY`, `COMPANY`), `legal_name`, `trade_name`, `country_code` (ISO 3166-1 alpha-2 uppercase), `registration_number` (canonical uppercase trimmed), `official_domain` (canonical lowercase trimmed), `verification_status` (`PENDING`, `VERIFIED`, `REJECTED`, `SUSPENDED`), and review audit fields. Enforces:
   - `chk_organizations_reg_canonical CHECK (registration_number = UPPER(BTRIM(registration_number)))`
   - `chk_organizations_domain_canonical CHECK (official_domain = LOWER(BTRIM(official_domain)) AND official_domain !~ '[:/\\?#]')`
   - `chk_organizations_status_consistency CHECK (...)`
5. **`organization_memberships`**: Multi-tenant RBAC tenancy table linking `organization_id` and `user_id` with roles (`UNIVERSITY_ADMIN`, `UNIVERSITY_ISSUER`, `COMPANY_ADMIN`, `COMPANY_VERIFIER`), `is_active` flag, and unique constraint `(organization_id, user_id)`.
6. **`audit_logs`**: Append-only compliance trail recording `actor_user_id`, `target_organization_id`, `action`, `resource_type`, `resource_id`, sanitized `payload` (JSONB), `ip_address`, and `user_agent`.

### Phase 5A Academic Certificates Schema Overview

Migration 000002 (`db/migrations/000002_create_certificates_schema.up.sql`) establishes the tamper-evident digital certificates schema:

1. **`certificates`**:
   - **Identifiers**: UUID `id` primary key, `public_id` formatted as `^TD-CERT-[A-Z0-9]{16,32}$` (`uq_certificates_public_id`), `organization_id` (foreign key to `organizations` with `ON DELETE RESTRICT`), and `recipient_user_id` (foreign key to `users` with `ON DELETE RESTRICT`).
   - **Recipient Snapshot**: `recipient_name` (canonical non-empty), `recipient_email` (canonical lowercase), optional `student_id_number`.
   - **Academic Details**: `title`, `degree_type` (`BACHELOR`, `MASTER`, `DOCTORATE`, `DIPLOMA`, `ASSOCIATE`, `CERTIFICATE`), optional `major`, optional `grade_or_honors`, `graduation_date`, and `issue_date`.
   - **Storage & Integrity**: `file_storage_key` (`VARCHAR(512)`), `file_name` (`VARCHAR(255)`), `file_size` (`BIGINT`), `file_mime_type` (`VARCHAR(100)`), and `document_hash` (`CHAR(64)` lowercase SHA-256 hex).
   - **Lifecycle Attribution**: `created_by_user_id`, `created_at`, `updated_at`, `issued_by_user_id`, `issued_at`, `revoked_by_user_id`, `revoked_at`, `revocation_reason_code`, `revocation_reason`.
   - **Replacement Lineage**: `replaced_by_certificate_id` (foreign key to `certificates`), `replaces_certificate_id` (foreign key to `certificates`).
   - **Soft Deletion**: `deleted_at` (`TIMESTAMPTZ`, permitted only when `status = 'DRAFT'`).
2. **Schema Invariant Constraints**:
   - `chk_certificates_status`: `status IN ('DRAFT', 'ISSUED', 'REVOKED', 'REPLACED')`.
   - `chk_certificates_public_id_format`: Enforces canonical format `^TD-CERT-[A-Z0-9]{16,32}$`.
   - `chk_certificates_academic_dates`: Enforces `issue_date >= graduation_date`, `issued_at >= created_at`, and `revoked_at >= issued_at`.
   - `chk_certificates_file_consistency`: All 5 file fields (`file_storage_key`, `file_name`, `file_size`, `file_mime_type`, `document_hash`) must be NULL together, or all populated together with `file_size > 0 AND file_size <= 10485760 AND file_mime_type = 'application/pdf'`.
   - `chk_certificates_status_consistency`:
     - `DRAFT`: Unissued, unrevoked, replacement pointers NULL.
     - `ISSUED`: `issued_at`, `issued_by_user_id`, `document_hash`, and `file_storage_key` NOT NULL; unrevoked; `replaced_by_certificate_id` NULL; `deleted_at` NULL.
     - `REVOKED`: Finalized fields NOT NULL; `revoked_at`, `revoked_by_user_id`, `revocation_reason_code`, and `revocation_reason` NOT NULL; `replaced_by_certificate_id` NULL; `deleted_at` NULL.
     - `REPLACED`: Finalized and revocation fields NOT NULL; `replaced_by_certificate_id` NOT NULL; `deleted_at` NULL.
   - `chk_certificates_no_self_replacement`: Prohibits self-replacement (`replaced_by_certificate_id != id` and `replaces_certificate_id != id`).
   - `chk_certificates_no_direct_cycle`: Prohibits direct circular replacement (`replaced_by_certificate_id != replaces_certificate_id`).
3. **Indexes**:
   - `idx_certificates_document_hash_finalized`: Partial unique index on `document_hash` for `status IN ('ISSUED', 'REVOKED', 'REPLACED') AND deleted_at IS NULL`. Prevents duplicate document bytes across finalized certificates.
   - `idx_certificates_replaced_by`: Unique partial index on `replaced_by_certificate_id` (enforces strict 1-to-1 replacement).
   - `idx_certificates_replaces`: Unique partial index on `replaces_certificate_id` (enforces strict 1-to-1 replacement).
   - `idx_certificates_org_status`: Multi-tenant composite query index on `(organization_id, status, created_at DESC)`.
   - `idx_certificates_recipient`: Recipient composite query index on `(recipient_user_id, status, created_at DESC)`.
   - `idx_certificates_public_id`: Unique public lookup index on `public_id`.

### Migration Conventions & Transaction Rules

The migration CLI (`cmd/migrate`) uses `golang-migrate/migrate/v4` with the `pgx/v5` driver:

1. **Transactional Migrations**: Standard schema changes (tables, columns, foreign keys, check constraints) are wrapped in explicit transaction blocks:
   ```sql
   BEGIN;
   -- transactional statements
   COMMIT;
   ```
2. **Non-Transactional Migrations**: Operations that cannot run inside a PostgreSQL transaction block (such as `CREATE INDEX CONCURRENTLY`) must be isolated in dedicated migration files without `BEGIN`/`COMMIT`.
3. **Advisory Locking**: `cmd/migrate` uses PostgreSQL advisory locks to prevent concurrent migration runner collisions.
4. **Direct Compute Connection**: Migrations must only be executed against direct PostgreSQL compute (`DATABASE_DIRECT_URL`), never through a transaction-pooling connection proxy.

### Migration Commands

```bash
# Set direct compute connection string
$env:DATABASE_DIRECT_URL="postgres://user:password@ep-sample.example.neon.tech/neondb?sslmode=require"

# Apply all pending migrations (000001 and 000002)
go run ./cmd/migrate up

# Roll back the single most recent migration (000002)
go run ./cmd/migrate down 1

# Check current schema version and dirty state
go run ./cmd/migrate version

# Force a specific version if recovering from a dirty state
go run ./cmd/migrate force 2
```

### sqlc Code Generation

SQL queries in `db/queries/` (`audit.sql`, `auth.sql`, `certificates.sql`, `memberships.sql`, `organizations.sql`, `users.sql`) are compiled into type-safe Go code using `sqlc`:

```bash
# Regenerate Go code from SQL definitions
sqlc generate
```

Configuration is maintained in `sqlc.yaml` targeting PostgreSQL with `pgx/v5` engine and parameter overriding.

---

## Authentication, Security & RBAC Specifications (Phase 4A)

### 1. NIST/OWASP-Aligned Password Policy
- **Minimum Length**: 15 Unicode code points (`utf8.RuneCountInString >= 15`).
- **Maximum Length**: 256 UTF-8 bytes (`len([]byte) <= 256`) as explicit resource control before Argon2id derivation.
- **Rules**: Zero composition rules (no mandatory uppercase, numbers, or special symbols). Unicode characters, emojis, and spaces are fully permitted. Passwords are never silently truncated.
- **Hashing**: Argon2id (`m=65536` KiB, `t=3`, `p=2`, salt=16 bytes, key=32 bytes) with standard PHC string representation and constant-time verification.

### 2. Session Management & Cookie Security
- **Token Generation**: 32 bytes of cryptographically secure random data (`crypto/rand`), Base64URL-encoded (43 characters).
- **Storage**: Only the SHA-256 hex digest (`token_hash`, 64 characters) is stored in the database. Raw tokens are never persisted.
- **Cookie Security**: Emitted as a Host-Only cookie (`Path=/api`, `HttpOnly=true`, `SameSite=Lax`, `Secure` in production). Cookies are cleared with `MaxAge=-1` and Unix epoch expiration on logout.

### 3. Exact CSRF Token Lifecycle
- **Distribution** (`GET /api/v1/auth/csrf`): Requires an active, authenticated session cookie. Computes `HMAC-SHA256(CSRF_SECRET, "csrf:v1:" + rawSessionToken)` and returns the Base64URL token with `Cache-Control: no-store, no-cache, must-revalidate`.
- **Validation**: State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) with session cookies require the `X-CSRF-Token` header. Validation uses `crypto/subtle.ConstantTimeCompare`. Missing or invalid tokens return `403 CSRF_TOKEN_INVALID`.
- **Origin Protection**: Mutating requests enforce Origin/Referer allowlist matching against `FRONTEND_URL`.
- **Content-Type Protection**: Body-bearing endpoints enforce `Content-Type: application/json` (except multipart file uploads, which enforce RFC 2046 multipart boundaries).

### 4. Anti-Enumeration Protections
- **Registration**: `/register` returns an identical generic `200 OK` response for both new and duplicate email registrations.
- **Login**: All authentication failures (unknown email, incorrect password, inactive user) return uniform `401 INVALID_CREDENTIALS`. If a user is not found, a dummy Argon2id hash is computed against a fixed baseline salt to equalize response timing.

### 5. In-Memory Rate Limiting
- **Dual Limits**: Independent per-IP limit (`RATE_LIMIT_IP_ATTEMPTS`) plus compound per-account-per-IP limit (`RATE_LIMIT_LOGIN_ATTEMPTS`).
- **Key Privacy**: Account rate-limit keys are derived via `HMAC-SHA256(CSRF_SECRET, "rate-limit:v1:" + canonicalEmail)`, preventing plaintext email storage in memory and avoiding cross-IP user lockouts.
- **Bounded Store**: Sliding-window limiter with bounded capacity (10,000 entries) and LRU eviction under memory pressure. Emits positive integer `Retry-After` header on `429 Too Many Requests`.

### 6. Portal Isolation & Multi-Tenant RBAC
- **Portal Isolation**: Validates `portal_context` (`app` vs `admin`) on login. Superadmins cannot access the non-superadmin application portal (`RequireNonSuperadmin`), and non-superadmin users cannot access the admin portal (`RequireSuperadmin`).
- **Organization RBAC**: Route guards `RequireOrgMembership` and `RequireOrgRole` verify active organization tenancy and role permissions (`UNIVERSITY_ADMIN`, `UNIVERSITY_ISSUER`, `COMPANY_ADMIN`, `COMPANY_VERIFIER`).

### 7. Append-Only Audit Logging
- Security-relevant actions (`REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`) are recorded in `audit_logs`.
- Payloads strictly exclude all sensitive data: zero passwords, tokens, hashes, or emails appear in audit records.

---

## Organization Management & Tenancy Specifications (Phase 4B)

Phase 4B implements the organization onboarding lifecycle, TrustDocs superadmin verification and review, tenant access controls, member listing, and public discovery.

### 1. Organization Onboarding Lifecycle

```text
Applicant Submits Application (POST /api/v1/organizations)
        │
        ▼
Database Transaction:
  ├── INSERT INTO organizations (status = 'PENDING')
  ├── INSERT INTO organization_memberships (is_active = false, role = OrgType_ADMIN)
  └── INSERT INTO audit_logs (action = 'ORGANIZATION_APPLICATION_SUBMITTED')
        │
        ▼
Applicant views status via GET /api/v1/organizations/mine (status: 'PENDING', my_is_active: false)
        │
        ▼
TrustDocs Superadmin Review (GET /api/v1/admin/organizations/:organization_id)
        │
        ├───────────────────────────────────────────────┐
        ▼                                               ▼
[APPROVE]                                       [REJECT]
POST /api/v1/admin/organizations/:organization_id/approve    POST /api/v1/admin/organizations/:organization_id/reject
  ├── SELECT ... FOR UPDATE (row lock)            ├── SELECT ... FOR UPDATE (row lock)
  ├── UPDATE organizations                        ├── UPDATE organizations
  │     SET verification_status = 'VERIFIED',     │     SET verification_status = 'REJECTED',
  │         reviewed_by_user_id = admin,          │         reviewed_by_user_id = admin,
  │         reviewed_at = NOW(),                  │         reviewed_at = NOW(),
  │         decision_reason = NULL                │         decision_reason = reason
  ├── UPDATE organization_memberships             ├── Membership remains is_active = false
  │     SET is_active = true                      └── INSERT INTO audit_logs
  │   WHERE org_id = id AND user_id = applicant         (payload includes allowlisted reason_code;
  └── INSERT INTO audit_logs                            free-text reason & applicant PII excluded)
        (action = 'ORGANIZATION_APPROVED')              │
        │                                               ▼
        ▼                                       Tenant Operations Forbidden (403)
Tenant Operations Enabled                       Applicant views decision_reason via /api/v1/organizations/mine
(GET/PATCH /api/v1/organizations/:organization_id, members list)
```

### 2. Transaction Guarantees & Concurrency Control
- **Atomic Creation**: Organization record, inactive initial administrator membership, and submission audit trail are created within a single database transaction. If uniqueness conflicts occur (e.g. duplicate country code + registration number, or duplicate domain), the entire transaction rolls back cleanly with zero orphaned rows.
- **Row-Level Review Locking**: Superadmin review endpoints execute `SELECT ... FOR UPDATE` on the target organization row inside an explicit transaction.
- **Strict Single-Decision Guarantee**: Organization status is evaluated while holding the row lock. Concurrent review requests for the same organization resolve with exactly one successful review decision (`200 OK`) and immediate conflict rejection (`409 Conflict`, error code `ORGANIZATION_NOT_PENDING`) for all subsequent or racing requests.
- **Exact Membership Activation**: Approval activates only the exact initial applicant membership tied to the organization. Unrelated or existing memberships are untouched.
- **Co-Transactional Audit Trail**: Review audit logs are inserted within the same database transaction that updates organization status and membership state, ensuring audit trail immutability and consistency.

### 3. Organization Status Rules & Schema Consistency
The database enforces strict state consistency via check constraint `chk_organizations_status_consistency`:
- **`PENDING`**:
  - `reviewed_by_user_id IS NULL`
  - `reviewed_at IS NULL`
  - `decision_reason IS NULL`
- **`VERIFIED`**:
  - `reviewed_by_user_id IS NOT NULL` (references valid reviewer user)
  - `reviewed_at IS NOT NULL`
- **`REJECTED`**:
  - `reviewed_by_user_id IS NOT NULL`
  - `reviewed_at IS NOT NULL`
  - `decision_reason IS NOT NULL` (mandatory non-empty justification)
- **`SUSPENDED`**:
  - `reviewed_by_user_id IS NOT NULL`
  - `reviewed_at IS NOT NULL`
  - `decision_reason IS NOT NULL`

### 4. Functional RBAC Roles
Organization memberships link authenticated users to organizations with specific functional roles matching the organization type (`chk_org_memberships_role`):
- **University Roles**:
  - `UNIVERSITY_ADMIN`: Tenant administrator; manages organization profile, views member directory, and creates/issues certificates.
  - `UNIVERSITY_ISSUER`: Academic credential issuer; creates drafts, uploads certificate PDFs, issues, revokes, and replaces certificates.
- **Company Roles**:
  - `COMPANY_ADMIN`: Tenant administrator; manages organization profile and views member directory.
  - `COMPANY_VERIFIER`: Employment credential verifier (assigned for subsequent verification phases).

### 5. Multi-Tenant Security & Route Guards
- **Two-Condition Tenancy Requirement**: Accessing tenant operations (`GET /api/v1/organizations/:organization_id`, `PATCH /api/v1/organizations/:organization_id`, `GET /api/v1/organizations/:organization_id/members`) strictly requires **both**:
  1. The target organization must have `verification_status = 'VERIFIED'`.
  2. The authenticated user must possess an **active** membership (`is_active = true`) in that specific organization.
- **Non-Verified Organization Rejection**: Requests for `PENDING`, `REJECTED`, or `SUSPENDED` organizations reject tenant access with `403 Forbidden` and error code `ORGANIZATION_NOT_ACTIVE`.
- **Anti-Enumeration Tenant Boundary**: Accessing a non-existent, deleted, or unauthorized organization ID returns a uniform `403 Forbidden` (`FORBIDDEN`), preventing external attackers or non-members from mapping valid tenant UUIDs.
- **Strict Mutation Bounds**: Tenant profile updates (`PATCH /api/v1/organizations/:organization_id`) are restricted in SQL to `verification_status = 'VERIFIED' AND deleted_at IS NULL`. Immutable identity attributes (`legal_name`, `official_domain`, `country_code`, `registration_number`, `org_type`) cannot be modified through the API; only `trade_name` is mutable.

### 6. Superadmin Review & Privacy Boundaries
- **Anti-Self-Review Enforcement**: Superadmins are prohibited from approving or rejecting organization applications where they are the applicant. Self-review attempts return `403 Forbidden` with error code `ORGANIZATION_SELF_REVIEW_PROHIBITED`, preserving independence of accreditation.
- **Review Precondition**: Only organizations in `PENDING` status may be reviewed.
- **Allowlisted Rejection Codes**: Rejection requires an allowlisted `reason_code`:
  - `INELIGIBLE_ORGANIZATION`
  - `REGISTRATION_NOT_VERIFIED`
  - `DOMAIN_MISMATCH`
  - `DUPLICATE_APPLICATION`
  - `FRAUDULENT_SUBMISSION`
  - `INCOMPLETE_DOCUMENTATION`
- **Audit Privacy Boundary**: While `decision_reason` is stored in the organization table for tenant notification, free-text decision reasons and applicant PII are strictly excluded from audit log JSON payloads and structured logs. Audit logs store only the allowlisted `reason_code`.

### 7. Member Directory Listing
- **Access Guard**: Restricted to verified organization administrators (`RequireOrgRole("UNIVERSITY_ADMIN", "COMPANY_ADMIN")`).
- **Pagination**: Default page 1 (minimum 1), default limit 20 (minimum 1, maximum 50). Limits exceeding 50 are safely clamped to 50.
- **Role Filtering**: Optional `?role=` query parameter accepts only schema-valid roles matching the organization type (`UNIVERSITY_ADMIN`, `UNIVERSITY_ISSUER`, `COMPANY_ADMIN`, `COMPANY_VERIFIER`). Invalid role values return `400 Bad Request` (`INVALID_FILTER_PARAM`).
- **Anti-Enumeration**: Partial-email and substring searches are rejected; users cannot probe for directory email presence.
- **Cache Invalidation**: Responses enforce HTTP headers `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache`.
- **Phase 4B Scope**: Member listing is read-only. Member invitations, role mutations, and member revocations are deferred to future stages.

### 8. Public Verified Organization Discovery
- **Public Directory Scope**: `GET /api/v1/public/verified-organizations` exposes only organizations with `verification_status = 'VERIFIED'` and `deleted_at IS NULL`. Organizations in `PENDING`, `REJECTED`, or `SUSPENDED` states never appear.
- **Minimal Safe Projection**: Public responses include only:
  - `id`
  - `org_type`
  - `legal_name`
  - `trade_name`
  - `country_code`
  - `official_domain`
- **Data Privacy Guarantee**: Registration numbers, reviewer user IDs, review timestamps, decision reasons, applicant details, member lists, and audit metadata are completely omitted from public directory responses.
- **Uniform 404 Response**: `GET /api/v1/public/organizations/:organization_id` returns an identical uniform `404 Not Found` response for non-existent organizations and organizations in `PENDING`, `REJECTED`, or `SUSPENDED` status, preventing public enumeration of pending or rejected applicants.
- **Public Rate Limiting**: All public discovery endpoints are protected by an in-memory sliding-window rate limiter enforcing a strict ceiling of **60 requests per minute per client IP**. Requests exceeding this threshold receive `429 Too Many Requests` with an integer `Retry-After` header and sanitized error code `RATE_LIMIT_EXCEEDED`.

---

## Academic Certificate Issuance & Cloudflare R2 Storage Specifications (Phase 5A)

Phase 5A establishes the tamper-evident digital certificate lifecycle, university issuance workflows, Cloudflare R2 private object storage integration, short-lived presigned download URLs, student Career Trust Passport access, public verification with masked recipient privacy, and atomic replacement lineage.

### 1. Certificate Lifecycle State Machine

```text
       [ University Issuer ]
       POST /organizations/:org_id/certificates
                 │
                 ▼
            ┌─────────┐
            │  DRAFT  │ ◄─── (File Upload / Update / Soft Delete)
            └─────────┘
                 │
                 │ POST /organizations/:org_id/certificates/:cert_id/issue
                 │ (Requires valid PDF file attached; enforces SHA-256 uniqueness)
                 ▼
            ┌─────────┐
            │ ISSUED  │ ───► Student Career Trust Passport & Public Verification Active
            └─────────┘
                 │
         ┌───────┴────────────────────────────────┐
         │                                        │
         │ POST .../:cert_id/revoke               │ POST .../:cert_id/replace
         │ (Academic / Admin Revocation)          │ (Atomic Replacement with new DRAFT)
         ▼                                        ▼
   ┌───────────┐                            ┌───────────┐
   │  REVOKED  │                            │ REPLACED  │ ───► References replacement
   └───────────┘                            └───────────┘      certificate public ID
```

The database and domain service enforce strict state transitions across all 4 lifecycle states:

- **`DRAFT`**:
  - Created by authorized university personnel (`UNIVERSITY_ADMIN` or `UNIVERSITY_ISSUER`).
  - Mutable attributes (`recipient_name`, `recipient_email`, `student_id_number`, `title`, `degree_type`, `major`, `grade_or_honors`, `graduation_date`, `issue_date`).
  - Document file can be attached or re-uploaded.
  - Can be soft-deleted (`DELETE /organizations/:org_id/certificates/:cert_id`), which asynchronously cleans up any attached R2 storage object.
  - Strictly hidden from the student recipient: student requests receive a uniform `404 Not Found` (`CERTIFICATE_NOT_FOUND`).
  - Prohibited from public verification: public queries receive a uniform `404 Not Found`.
- **`ISSUED`**:
  - Finalized, immutable academic credential.
  - Requires an attached PDF document with computed SHA-256 hash before issuance can occur.
  - Enforces cryptographic document hash uniqueness via `idx_certificates_document_hash_finalized`.
  - Immutable: cannot be updated, soft-deleted, or re-uploaded. Re-issuing returns `409 Conflict` (`CERTIFICATE_ALREADY_ISSUED`).
  - Visible in student Career Trust Passport (`GET /api/v1/certificates/mine`).
  - Available for student download (returns `200 OK` with short-lived presigned download URL).
  - Verifiable on public directory (`GET /api/v1/public/certificates/:public_id`) with masked recipient name.
- **`REVOKED`**:
  - Revoked by university issuer (`POST .../:cert_id/revoke`) with mandatory `reason_code` and `reason` text.
  - Immutable: cannot be edited, deleted, or re-issued.
  - Retained permanently in database for compliance and non-repudiation audit trails.
  - Student download returns `410 Gone` with `X-Certificate-Status: REVOKED` and JSON status metadata (`CERTIFICATE_REVOKED`).
  - University issuer retains audit download access (returns `200 OK` with presigned URL and `X-Certificate-Status: REVOKED` header).
  - Public verification reflects `status = "REVOKED"` along with allowlisted `revocation_reason_code` and UTC `revoked_at`.
- **`REPLACED`**:
  - Superseded by an updated replacement certificate via atomic transaction (`POST .../:cert_id/replace`).
  - Mandatory replacement lineage recorded: `old.replaced_by_certificate_id = new.id` and `new.replaces_certificate_id = old.id`.
  - Student download returns `410 Gone` with `X-Certificate-Status: REPLACED`, JSON status metadata (`CERTIFICATE_REPLACED`), and `replaced_by_public_id`.
  - University issuer retains audit download access (returns `200 OK` with presigned URL and `X-Replaced-By: <public_id>` header).
  - Public verification reflects `status = "REPLACED"`, `revocation_reason_code`, UTC `revoked_at`, and `replaced_by_public_id`.

### 2. Document Upload Validation & Cryptographic Hashing

Document file uploads (`POST /api/v1/organizations/:organization_id/certificates/:certificate_id/file`) adhere to strict integrity controls:

- **10 MiB File Size Limit**: Controlled by `CERTIFICATE_MAX_FILE_SIZE` (default `10485760` bytes). Requests declaring or streaming more than 10 MiB are rejected with `413 Request Entity Too Large` (`FILE_TOO_LARGE`).
- **Multipart Boundary Handling**: Configures `MultipartEnvelopeAllowance = 262144` bytes (256 KiB) to accommodate multipart MIME boundaries and headers without allowing the inner document payload to exceed the 10 MiB limit.
- **Bounded Stream Consumption**: Uses `io.LimitedReader` capped at `maxFileSize + 1` to detect payload overflow deterministically without exhausting server memory.
- **MIME & Magic-Byte Validation**:
  - Upload requests enforce `Content-Type: multipart/form-data` with valid boundary delimiter.
  - The first 5 bytes of the file stream are inspected and must match the exact PDF magic bytes: `%PDF-`. Files failing this check are rejected with `400 Bad Request` (`INVALID_FILE_FORMAT`).
  - Persisted `file_mime_type` is strictly recorded as `application/pdf`.
- **SHA-256 Cryptographic Hashing**:
  - A cryptographic SHA-256 hash is computed concurrently during the upload stream copy via `io.MultiWriter`.
  - Stored as a canonical 64-character lowercase hexadecimal string (`CHAR(64)`).
  - Before attaching, the hash is checked against all finalized certificates (`CheckDocumentHashConflict`). If another issued, revoked, or replaced certificate already uses this hash, the upload is rejected with `409 Conflict` (`DUPLICATE_DOCUMENT_HASH`).
- **Object Key Scheme**:
  ```text
  certificates/{organization_id}/{certificate_id}/{document_hash}.pdf
  ```
  This key layout is completely devoid of recipient PII, names, emails, or user-provided filenames.
- **Upload Compensation**: If the database transaction attaching the file metadata fails, the newly uploaded object is immediately deleted from R2 storage via a bounded background context (`compensateNewUpload`) to prevent orphan storage leaks.

### 3. Cloudflare R2 Private Storage & Presigned URLs

- **Private Storage Isolation**: Certificate blobs are stored in a private Cloudflare R2 bucket accessed via AWS SDK Go v2 S3 client. Direct public access to the bucket is completely disabled.
- **Short-Lived Presigned URLs**: File downloads generate presigned GET URLs with a strict maximum expiration of **5 minutes** (`MaxPresignTTL = 5 * time.Minute`, controlled by `R2_PRESIGN_TTL`).
- **Cache-Control Defense**: Download responses emit `Cache-Control: private, no-store` to prevent intermediary proxy or browser caching of sensitive academic credentials.

### 4. Download Authorization Rules Matrix

Download requests (`GET /api/v1/certificates/:certificate_id/download`) enforce status-dependent authorization based on actor identity:

| Certificate Status | Caller Persona | HTTP Status | URL Returned? | Response Headers | Response Body / Metadata |
|---|---|---|---|---|---|
| `DRAFT` | University Issuer (`?organization_id=...`) | `200 OK` | Yes (Presigned) | `Cache-Control: private, no-store` | `{"download_url": "...", "file_name": "..."}` |
| `DRAFT` | Student Recipient | `404 Not Found` | No | — | Generic `CERTIFICATE_NOT_FOUND` (Draft hidden) |
| `ISSUED` | University Issuer (`?organization_id=...`) | `200 OK` | Yes (Presigned) | `Cache-Control: private, no-store` | `{"download_url": "...", "file_name": "..."}` |
| `ISSUED` | Student Recipient | `200 OK` | Yes (Presigned) | `Cache-Control: private, no-store` | `{"download_url": "...", "file_name": "..."}` |
| `REVOKED` | University Issuer (`?organization_id=...`) | `200 OK` | Yes (Presigned) | `Cache-Control: private, no-store`<br>`X-Certificate-Status: REVOKED` | `{"download_url": "...", "file_name": "..."}` |
| `REVOKED` | Student Recipient | `410 Gone` | No | `X-Certificate-Status: REVOKED` | `{"code": "CERTIFICATE_REVOKED", "details": {"status": "REVOKED", "revocation_reason_code": "...", "revoked_at": "..."}}` |
| `REPLACED` | University Issuer (`?organization_id=...`) | `200 OK` | Yes (Presigned) | `Cache-Control: private, no-store`<br>`X-Certificate-Status: REPLACED`<br>`X-Replaced-By: <public_id>` | `{"download_url": "...", "file_name": "..."}` |
| `REPLACED` | Student Recipient | `410 Gone` | No | `X-Certificate-Status: REPLACED` | `{"code": "CERTIFICATE_REPLACED", "details": {"status": "REPLACED", "revocation_reason_code": "...", "revoked_at": "...", "replaced_by_public_id": "..."}}` |
| Any | Unauthenticated / Unauthorized | `401` / `404` | No | — | Uniform anti-enumeration boundary |

### 5. Atomic Certificate Replacement & Lineage Guarantees

When an issued certificate must be replaced (e.g., due to an administrative name correction or typographical error in degree honors), `POST /api/v1/organizations/:organization_id/certificates/:certificate_id/replace` executes an atomic replacement:

1. **Prerequisites**:
   - The original certificate must have `status = 'ISSUED'`.
   - The replacement certificate must exist in the same organization, have `status = 'DRAFT'`, and already have a valid PDF document attached (`file_storage_key` and `document_hash` populated).
2. **Row Locking**: The original certificate row is locked via `SELECT ... FOR UPDATE` inside an explicit database transaction.
3. **Atomic State Transition**:
   - The original certificate transitions to `REPLACED`, sets `replaced_by_certificate_id = replacement_id`, `revoked_by_user_id = actor_id`, `revoked_at = NOW()`, and records allowlisted `revocation_reason_code` and `revocation_reason`.
   - The replacement certificate transitions to `ISSUED`, sets `replaces_certificate_id = original_id`, `issued_by_user_id = actor_id`, and `issued_at = NOW()`.
4. **Anti-Cycle & Uniqueness Constraints**:
   - `chk_certificates_no_self_replacement`: Prevents a certificate from replacing itself.
   - `chk_certificates_no_direct_cycle`: Prevents mutual replacement cycles (`A -> B -> A`).
   - `idx_certificates_replaced_by` & `idx_certificates_replaces`: Unique partial indexes guarantee strict 1-to-1 linear replacement chains without branching.
5. **Concurrency Resolution**: Concurrent replacement attempts against the same original certificate resolve with exactly one success (`200 OK`) and immediate conflict rejection (`409 Conflict`, error code `CERTIFICATE_STATE_CONFLICT`) for competing requests.

### 6. Public Certificate Verification & Privacy Masking

Public verification (`GET /api/v1/public/certificates/:public_id`) provides unauthenticated verification for employers, verification agencies, and academic institutions while strictly safeguarding student privacy:

- **Minimal Safe Projection**: Returns:
  - `public_id`
  - `status` (`ISSUED`, `REVOKED`, `REPLACED`)
  - `title`
  - `degree_type`
  - `major` (if present)
  - `graduation_date` (`YYYY-MM-DD`)
  - `issue_date` (`YYYY-MM-DD`)
  - `document_hash` (SHA-256)
  - `issuer_organization_name`
  - `issuer_organization_domain`
  - `issuer_country_code`
  - `masked_recipient_name`
  - `revocation_reason_code` (if revoked or replaced)
  - `revoked_at` (if revoked or replaced)
  - `replaced_by_public_id` (if replaced)
- **Recipient Name Masking Algorithm (`MaskRecipientName`)**:
  - Trims leading/trailing whitespace and tokenizes the name by whitespace runes.
  - For each word token, preserves the first Unicode rune and masks all subsequent runes with `*`. Single-character tokens are preserved.
  - Examples:
    - `"Jane Doe"` -> `"J*** D**"`
    - `"Alexander"` -> `"A********"`
    - `"Mary Jane Watson"` -> `"M*** J*** W*****"`
    - `""` -> `"***"`
- **Zero Sensitive Data Leaks**: Student email address, student ID number, internal database UUIDs (`id`, `recipient_user_id`, `organization_id`), object storage keys, and original file names are **never** included in public verification responses.
- **Anti-Enumeration 404**: Queries for nonexistent public IDs or unissued `DRAFT` certificates return a uniform `404 Not Found` (`CERTIFICATE_NOT_FOUND`).
- **Public Rate Limiting**: Enforces a strict ceiling of **60 requests per minute per client IP** via sliding-window rate limiting. Requests exceeding this threshold receive `429 Too Many Requests` with an integer `Retry-After` header.

### 7. Student Career Trust Passport

Authenticated students manage their credentials through dedicated passport endpoints:
- **List Credentials** (`GET /api/v1/certificates/mine`): Returns all finalized certificates (`ISSUED`, `REVOKED`, `REPLACED`) belonging to the authenticated student. Unissued `DRAFT` records are completely excluded. Supports pagination (`?page=1&limit=20`) and optional status filtering (`?status=ISSUED`).
- **Credential Details** (`GET /api/v1/certificates/mine/:certificate_id`): Returns complete credential details for a specific certificate owned by the student, including issuing institution profile, document hash, and replacement lineage. Requests for non-owned or draft certificates return `404 Not Found`.

---

## API Endpoints Reference

### Public & Health Endpoints

| Method | Path | Audience | Auth Required | CSRF Required | Rate Limit | Description |
|---|---|---|---|---|---|---|
| `GET` | `/health` | Public / Ops | No | No | Standard | Liveness probe (always returns 200 OK) |
| `GET` | `/ready` | Public / Ops | No | No | Standard | Readiness probe (verifies database pool connectivity) |
| `GET` | `/api/v1/public/verified-organizations` | Public | No | No | 60 req/min/IP | List verified organizations with minimal safe projection |
| `GET` | `/api/v1/public/organizations/:organization_id` | Public | No | No | 60 req/min/IP | Lookup single verified organization (uniform 404 for non-verified) |
| `GET` | `/api/v1/public/certificates/:public_id` | Public | No | No | 60 req/min/IP | Verify certificate with masked recipient name (uniform 404 for drafts) |

### Authentication Endpoints (Phase 4A)

| Method | Path | Audience | Auth Required | CSRF Required | Rate Limit | Description |
|---|---|---|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Public Users | No | Origin + JSON | 10 req/hour/IP | Register new user account (generic anti-enumeration 200 OK) |
| `POST` | `/api/v1/auth/login` | Registered Users | No | Origin + JSON | 5 req/15m/acct + 20/IP | Authenticate; sets Host-Only session cookie |
| `GET` | `/api/v1/auth/csrf` | Authenticated | Cookie Session | No | Standard | Retrieve session-bound HMAC CSRF token |
| `POST` | `/api/v1/auth/logout` | Authenticated | Cookie Session | Yes (`X-CSRF-Token`) | Standard | Revoke active session and clear cookie |
| `GET` | `/api/v1/auth/me` | Authenticated | Cookie Session | No | Standard | Return user profile and active memberships |

### Organization Onboarding & Tenant Endpoints (Phase 4B)

| Method | Path | Audience | Auth Required | CSRF Required | Roles / Verification | Description |
|---|---|---|---|---|---|---|
| `POST` | `/api/v1/organizations` | Applicants | Cookie Session | Yes (`X-CSRF-Token`) | Non-Superadmin | Submit onboarding application; creates PENDING org and inactive admin |
| `GET` | `/api/v1/organizations/mine` | Authenticated | Cookie Session | No | Authenticated User | List organizations applicant belongs to (includes PENDING & REJECTED) |
| `GET` | `/api/v1/organizations/:organization_id` | Tenant Members | Cookie Session | No | Active Member + VERIFIED | Retrieve verified organization tenant profile |
| `PATCH` | `/api/v1/organizations/:organization_id` | Tenant Admins | Cookie Session | Yes (`X-CSRF-Token`) | Admin + VERIFIED | Update mutable profile fields (`trade_name` only) |
| `GET` | `/api/v1/organizations/:organization_id/members` | Tenant Admins | Cookie Session | No | Admin + VERIFIED | List organization members with role filter and pagination |

### Superadmin Review & Dossier Endpoints (Phase 4B)

| Method | Path | Audience | Auth Required | CSRF Required | Roles / Verification | Description |
|---|---|---|---|---|---|---|
| `GET` | `/api/v1/admin/organizations` | Superadmins | Cookie Session | No | Superadmin Portal | List organization onboarding applications with status and applicant details |
| `GET` | `/api/v1/admin/organizations/:organization_id` | Superadmins | Cookie Session | No | Superadmin Portal | Retrieve detailed application dossier (excluding credential hashes) |
| `POST` | `/api/v1/admin/organizations/:organization_id/approve` | Superadmins | Cookie Session | Yes (`X-CSRF-Token`) | Superadmin (Anti-Self) | Approve application; sets VERIFIED and activates applicant membership |
| `POST` | `/api/v1/admin/organizations/:organization_id/reject` | Superadmins | Cookie Session | Yes (`X-CSRF-Token`) | Superadmin (Anti-Self) | Reject application; sets REJECTED and records allowlisted reason code |

### Academic Certificate Management Endpoints (University Issuers - Phase 5A)

| Method | Path | Audience | Auth Required | CSRF Required | Roles / Verification | Description |
|---|---|---|---|---|---|---|
| `POST` | `/api/v1/organizations/:organization_id/certificates` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Create unissued certificate draft |
| `PATCH` | `/api/v1/organizations/:organization_id/certificates/:certificate_id` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Update unissued certificate draft attributes |
| `POST` | `/api/v1/organizations/:organization_id/certificates/:certificate_id/file` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Upload certificate PDF (multipart, 10 MiB limit, SHA-256) |
| `POST` | `/api/v1/organizations/:organization_id/certificates/:certificate_id/issue` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Issue draft certificate (requires attached PDF, enforces hash uniqueness) |
| `GET` | `/api/v1/organizations/:organization_id/certificates` | University Issuers | Cookie Session | No | University Admin/Issuer + VERIFIED | List university certificates (paginated, status/email filters) |
| `GET` | `/api/v1/organizations/:organization_id/certificates/:certificate_id` | University Issuers | Cookie Session | No | University Admin/Issuer + VERIFIED | Retrieve complete university certificate details |
| `DELETE` | `/api/v1/organizations/:organization_id/certificates/:certificate_id` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Soft-delete draft certificate and clean up attached R2 object |
| `POST` | `/api/v1/organizations/:organization_id/certificates/:certificate_id/revoke` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Revoke issued certificate with reason code |
| `POST` | `/api/v1/organizations/:organization_id/certificates/:certificate_id/replace` | University Issuers | Cookie Session | Yes (`X-CSRF-Token`) | University Admin/Issuer + VERIFIED | Atomically replace issued certificate with replacement draft |

### Student Career Trust Passport & Download Endpoints (Phase 5A)

| Method | Path | Audience | Auth Required | CSRF Required | Roles / Verification | Description |
|---|---|---|---|---|---|---|
| `GET` | `/api/v1/certificates/mine` | Students | Cookie Session | No | Authenticated User | List finalized certificates issued to student (excludes drafts) |
| `GET` | `/api/v1/certificates/mine/:certificate_id` | Students | Cookie Session | No | Authenticated User | Retrieve details for student-owned certificate |
| `GET` | `/api/v1/certificates/:certificate_id/download` | Students / Issuers | Cookie Session | No | Recipient OR Tenant Issuer | Download certificate PDF (presigned URL or 410 Gone status metadata) |

---

## Running Locally

### Prerequisites

- Go `1.22+` (detected: `go1.26.1`)
- PostgreSQL 16+ or Neon Serverless PostgreSQL instance
- Cloudflare R2 bucket with S3 API credentials (or test configuration)

### Run the API Server

```bash
# Set pooled connection string (PgBouncer), R2 storage variables, and start server
$env:DATABASE_URL="postgres://user:password@ep-sample-pooler.example.neon.tech/neondb?sslmode=require"
$env:R2_ACCOUNT_ID="your-cloudflare-account-id"
$env:R2_ACCESS_KEY_ID="your-r2-access-key-id"
$env:R2_SECRET_ACCESS_KEY="your-r2-secret-access-key"
$env:R2_BUCKET_NAME="trustdocs-certificates"
go run ./cmd/api
```

### Run Migrations

```bash
# Set direct compute connection string and run migration CLI
$env:DATABASE_DIRECT_URL="postgres://user:password@ep-sample.example.neon.tech/neondb?sslmode=require"

# Apply pending migrations (000001 and 000002)
go run ./cmd/migrate up
```

---

## Testing & Verification

### Unit & Mock Verification Suite

Execute the local unit test suite without database or external network dependencies:

```bash
# Run all unit tests across all modules
go test -count=1 ./...

# Verify code formatting
gofmt -l .

# Run static analysis
go vet ./...
go vet -tags=integration ./...

# Verify compilation
go build ./...

# Verify git whitespace
git diff --check
```

### Compile-Only Integration Verification

Verify that guarded integration tests compile cleanly without running or connecting to any database:

```bash
# Compile-only check for organization integration suite
go test -tags=integration -count=1 -run '^$' ./internal/modules/organizations

# Compile-only check for certificate integration suite
go test -tags=integration -count=1 -run '^$' ./internal/modules/certificates
```

### Manual Database Integration Test Suite

The integration test suites verify database operations against an isolated test database.

> [!CAUTION]
> **Database Isolation Boundary & Safety Guards**:
> - Integration tests must **strictly target an isolated test database named `trustdocs_schema_test`**.
> - `TEST_DATABASE_DIRECT_URL` must point directly to the isolated test database compute instance.
> - `DB_TARGET_ENV` must be explicitly set to `test`.
> - `DATABASE_URL` and `DATABASE_DIRECT_URL` must be absent or empty; integration suites abort immediately if either is set.
> - Conservative connection pooling (`MaxConns = 5`, `MinConns = 1`) is enforced.
> - Integration tests execute `SELECT current_database()` upon connection and immediately abort if the database name is not `trustdocs_schema_test`.
> - Integration tests verify required migration tables (`certificates`, `audit_logs`, `organizations`, `users`) before executing test scenarios.
> - Integration tests use in-memory `MockStorage` for object storage operations (zero external network calls to Cloudflare R2).
> - Integration tests clean up exclusively by exact tracked primary-key UUIDs in reverse foreign-key dependency order inside a single atomic transaction, followed by post-cleanup assertion verification queries.
> - Connection strings, credentials, hostnames, and secrets are never logged or exposed.

```bash
# 1. Set isolated test database credentials
$env:TEST_DATABASE_DIRECT_URL="postgres://user:password@ep-sample.example.neon.tech/trustdocs_schema_test?sslmode=require"
$env:DB_TARGET_ENV="test"

# 2. Ensure application connection variables are absent
$env:DATABASE_URL=""
$env:DATABASE_DIRECT_URL=""

# 3. Run Phase 4A authentication integration tests
go test -tags=integration -v -count=1 ./internal/modules/auth -run "TestIntegration_"

# 4. Run Phase 4B organization integration tests
go test -tags=integration -v -count=1 ./internal/modules/organizations -run "TestIntegration_"

# 5. Run Phase 5A certificate integration tests
go test -tags=integration -v -count=1 ./internal/modules/certificates -run "TestIntegration_"
```

### Phase 4B Integration Test Scenarios

The Phase 4B integration suite (`internal/modules/organizations/organizations_integration_test.go`) exercises 13 comprehensive end-to-end database scenarios:

1. **`TestIntegration_OrganizationApplication_AtomicCreation`**: Verifies atomic creation of PENDING organization, inactive initial administrator membership with correct type-specific role, and submission audit trail for both universities and companies.
2. **`TestIntegration_OrganizationApplication_ConflictAndRollback`**: Verifies 409 conflict handling on duplicate domain/registration and confirms complete transactional rollback with zero orphaned rows or leaked applicant data.
3. **`TestIntegration_Mine_IncludesInactivePendingApplication`**: Verifies `GET /api/v1/organizations/mine` displays the applicant's pending organization with inactive membership status and nil decision reason.
4. **`TestIntegration_AdminApplicationDossier`**: Verifies superadmin application listing (`GET /api/v1/admin/organizations`) and detailed dossier retrieval (`GET /api/v1/admin/organizations/:organization_id`), absence of security credential hashes, and 403 enforcement for non-superadmins.
5. **`TestIntegration_OrgReview_InTransactionLocking`**: Verifies `SELECT ... FOR UPDATE` row locking under concurrent approval and rejection review attempts, ensuring exactly one 200 decision and one 409 conflict.
6. **`TestIntegration_OrganizationApproval_ActivatesExactMembership`**: Verifies approval transitions status to VERIFIED, sets reviewer ID and timestamp, activates only the exact applicant admin membership, and leaves unrelated memberships inactive.
7. **`TestIntegration_OrganizationRejection`**: Verifies rejection transitions status to REJECTED, stores decision reason, keeps membership inactive, logs allowlisted reason code in audit while redacting free-text reasons, returns 400 on invalid codes, and returns 409 on subsequent decisions.
8. **`TestIntegration_OrganizationSelfReviewProhibited`**: Verifies a superadmin cannot approve or reject their own organization application; returns 403 `ORGANIZATION_SELF_REVIEW_PROHIBITED` and preserves state.
9. **`TestIntegration_TenantOperations_RequireVerified`**: Verifies tenant operations return 403 for PENDING, REJECTED, and SUSPENDED organizations, non-leaking 403 for missing organizations, and permit access only when VERIFIED and active membership coincide.
10. **`TestIntegration_VerifiedProfileUpdate`**: Verifies verified admin can update `trade_name`, confirms immutable fields cannot be modified, and confirms cross-org updates are rejected.
11. **`TestIntegration_OrganizationMemberListing`**: Verifies verified admin can list members with `Cache-Control: no-store`, enforce default and maximum pagination limits, filter by allowlisted roles, reject invalid roles with 400, and deny cross-org access.
12. **`TestIntegration_PublicVerifiedOrganizationDiscovery`**: Verifies public directory exposes only VERIFIED, non-deleted organizations with minimal safe projection; returns uniform 404 for missing, pending, rejected, and suspended organizations; and verifies the 60 req/min/IP rate limiter and Retry-After header.
13. **`TestIntegration_OrganizationRegression`**: Verifies `/health` is 200, `/ready` reports PostgreSQL UP on the test database, and Phase 4A auth lifecycle (register -> login -> CSRF -> /auth/me -> logout -> revoked session) functions reliably.

### Phase 5A Integration Test Scenarios

The Phase 5A integration suite (`internal/modules/certificates/certificates_integration_test.go`) exercises 42 exhaustive end-to-end database scenarios across 8 test suites:

1. **`TestIntegration_CertificateDraft_CreationAndValidation`**:
   - Creates valid certificate drafts with canonical attribute sanitization and recipient snapshot persistence.
   - Enforces academic date consistency (`issue_date >= graduation_date`) via check constraint and service validation.
   - Rejects future issue dates beyond calendar limits with `400 Bad Request`.
   - Rejects unverified organization tenancies and non-issuer roles with `403 Forbidden`.
2. **`TestIntegration_CertificateFile_UploadValidation`**:
   - Streams valid PDF uploads to object storage and persists exact lowercase SHA-256 hex hashes in database.
   - Rejects oversized files (> 10 MiB) with `413 Request Entity Too Large`.
   - Inspects file streams and rejects non-PDF payloads lacking `%PDF-` magic bytes with `400 Bad Request`.
   - Validates upload compensation (deletes newly uploaded R2 object if database attach transaction fails).
3. **`TestIntegration_Certificate_IssuanceAndConflicts`**:
   - Transitions draft certificates with attached PDF files to `ISSUED` status.
   - Enforces immutability: re-issuing an already finalized certificate returns `409 Conflict` (`CERTIFICATE_ALREADY_ISSUED`).
   - Validates cryptographic hash uniqueness via `idx_certificates_document_hash_finalized`: uploading or issuing identical document bytes on a second certificate triggers `409 Conflict` (`DUPLICATE_DOCUMENT_HASH`).
   - Verifies soft deletion (`DELETE .../:certificate_id`) is permitted only for drafts, and asynchronously purges storage blobs.
4. **`TestIntegration_StudentPassport_AndDownloadPolicies`**:
   - Lists finalized certificates (`ISSUED`, `REVOKED`, `REPLACED`) in student Career Trust Passport (`GET /api/v1/certificates/mine`) while strictly excluding `DRAFT` records.
   - Student downloading `ISSUED` certificate returns `200 OK` with short-lived presigned download URL.
   - Student downloading `REVOKED` certificate returns `410 Gone` with `X-Certificate-Status: REVOKED` and revocation metadata.
   - Student downloading `REPLACED` certificate returns `410 Gone` with `X-Certificate-Status: REPLACED`, revocation metadata, and `replaced_by_public_id`.
   - University issuer auditing `REVOKED` or `REPLACED` certificate returns `200 OK` with presigned download URL and audit headers (`X-Certificate-Status`, `X-Replaced-By`).
5. **`TestIntegration_Certificate_ReplacementLineage`**:
   - Atomically transitions original `ISSUED` certificate to `REPLACED` and replacement `DRAFT` to `ISSUED`.
   - Establishes bidirectional foreign-key lineage (`replaced_by_certificate_id` and `replaces_certificate_id`).
   - Enforces check constraints preventing self-replacement (`chk_certificates_no_self_replacement`) and direct cycles (`chk_certificates_no_direct_cycle`).
   - Validates row-level locking concurrency: racing replacement attempts result in exactly one successful replacement and `409 Conflict` for competing requests.
6. **`TestIntegration_Certificate_ReplacementLineage_Cleanup`**:
   - Tests test-isolation teardown mechanics: neutralizes bidirectional replacement lineage cycles (REPLACED -> ISSUED) without violating `chk_certificates_status_consistency`.
   - Confirms that both original and replacement certificate rows are completely and cleanly deleted from the test database.
7. **`TestIntegration_PublicVerification_PrivacyAndRateLimit`**:
   - Verifies public verification returns safe projection with masked recipient name (`Jane Elizabeth Doe` -> `J*** E******** D**`).
   - Asserts complete omission of student emails, user UUIDs, R2 storage keys, and internal filenames.
   - Returns uniform `404 Not Found` for nonexistent public IDs and unissued draft certificates.
   - Verifies 60 req/min/IP public rate limit and validates positive integer `Retry-After` header.
8. **`TestIntegration_Phase4_Regressions_AndHealth`**:
   - Verifies `/health` (200 OK) and `/ready` probe (PostgreSQL UP).
   - Verifies Phase 4A authentication lifecycle regression (register -> login -> CSRF -> /auth/me -> logout).
   - Verifies Phase 4B organization verification status regression.

---

## Current Phase Limitations & Deferred Work

- **Cryptographic Merkle Tree Batch Anchoring (Phase 5B)**: Phase 5A implements SHA-256 document hashing and finalized document uniqueness in PostgreSQL and R2. Merkle tree batch generation, batch root publication, and public ledger anchoring are deferred to Phase 5B.
- **Scoped Consent-Based QR Verification (Phase 6)**: Dynamic QR code generation, expiring scoped verification tokens, employer verification audit logs, and student-controlled attribute disclosure remain scheduled for Phase 6.
- **Continuous Identity Chain & Employment Verifications (Phase 7+)**: Company employment credentials, role verification, milestone achievements, and cross-organization continuous identity chaining will be implemented in subsequent phases.
- **Member Invitations & Mutations**: Tenant member invitation workflows, role transitions, and member removals remain deferred.
- **Distributed Rate Limiting**: Rate limiting operates via an in-memory sliding-window store; Redis-backed distributed rate limiting for multi-instance deployments is deferred.
- **Email Dispatch & Monitoring**: External integrations for Resend email dispatch and Sentry error monitoring remain deferred to subsequent deployment phases.