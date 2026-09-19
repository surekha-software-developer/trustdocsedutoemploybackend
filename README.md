# TrustDocs Education to Employment - Backend

The core REST API backend service for the TrustDocs education-to-employment verification platform.

---

## Overview

TrustDocs connects verified university education with verified employment. This backend service powers tamper-evident digital certificate verification, scoped consent-based QR verification, and the Continuous Identity Chain across hiring milestones.

---

## Current Status: Phase 3A (Neon PostgreSQL Infrastructure Foundation)

- **Language / Runtime**: Go `1.26.1`
- **Module Path**: `github.com/surekha-software-developer/trustdocsedutoemploybackend`
- **HTTP Web Framework**: Gin (`v1.12.0`)
- **Database Driver & Pooling**: `pgx/v5` (`github.com/jackc/pgx/v5` & `github.com/jackc/pgx/v5/pgxpool`)
- **Migration Engine**: `golang-migrate` (`github.com/golang-migrate/migrate/v4`) using `pgx/v5` driver
- **Code Generator Configuration**: `sqlc.yaml` targeting PostgreSQL `pgx/v5` (code generation deferred to Phase 3B)
- **Structured Logging**: Native `log/slog` JSON output (sanitized without leaking credentials, connection strings, or raw SQL driver errors)
- **Tracing**: RFC 4122 UUID v4 Request ID middleware
- **CORS**: Restricted cross-origin protection with preflight `OPTIONS` support
- **Reliability & Probes**: Independent liveness probe (`/health`), dependency-aware readiness probe (`/ready`), safe panic recovery with sanitized JSON 500 responses, and graceful server shutdown with pool draining

---

## Architecture

The backend follows a scalable, **modular-monolith** architecture. Each domain module encapsulates its own business logic, HTTP handlers, routes, and data access layers.

### Current Directory Structure

```
trustdocsedutoemploybackend/
├── cmd/
│   ├── api/
│   │   └── main.go                  # API entry point, pgxpool lifecycle & graceful shutdown
│   └── migrate/
│       ├── main.go                  # Dedicated migration runner CLI (requires DATABASE_DIRECT_URL)
│       └── main_test.go             # Migration argument & safety unit tests
├── db/
│   ├── migrations/
│   │   └── .gitkeep                 # Tracked empty migration directory (no artificial migrations in Phase 3A)
│   ├── queries/
│   │   └── .gitkeep                 # SQL queries placeholder for Phase 3B
│   └── sqlc/
│       └── .gitkeep                 # Generated Go models placeholder for Phase 3B
├── internal/
│   ├── config/
│   │   ├── config.go                # Environment variable loader & pool configuration
│   │   └── config_test.go           # Configuration & pool validation tests
│   ├── core/
│   │   ├── errors.go                # Standard error codes & AppError types
│   │   ├── logger.go                # Structured slog JSON logger
│   │   ├── response.go              # Standard Success/Error JSON responders
│   │   └── response_test.go         # Response helper tests
│   ├── database/
│   │   └── postgres.go              # pgxpool factory with compile-time health.Pinger assertion
│   ├── middleware/
│   │   ├── cors.go                  # Restricted development CORS
│   │   ├── logging.go               # Request logging excluding secrets
│   │   ├── recovery.go              # Safe panic recovery
│   │   ├── request_id.go            # Request ID tracing middleware
│   │   └── request_id_test.go       # Request ID tests
│   ├── modules/
│   │   └── health/
│   │       ├── handler.go           # /health and dynamic /ready HTTP handlers
│   │       ├── routes.go            # Health route registration
│   │       ├── service.go           # Health & readiness domain service (Ping(ctx) with timeout)
│   │       └── handler_test.go      # Health unit tests (200, 503, timeout, recovery, sanitization)
│   ├── router/
│   │   ├── router.go                # Gin engine setup, middleware chain & dependency injection
│   │   └── router_test.go           # 404, 405, CORS, and recovery tests
│   └── server/
│       └── server.go                # HTTP server with safe timeouts
├── sqlc.yaml                        # sqlc configuration for pgx/v5
├── .env.example                     # Environment variable reference template
├── .gitignore                       # Git ignore rules
├── go.mod                           # Go module declaration
├── go.sum                           # Dependency checksums
└── README.md                        # Documentation
```

---

## Configuration & Environment Variables

> [!IMPORTANT]
> **Configuration Source**: Third-party environment loaders (like `godotenv`) are deliberately excluded. Configuration is read strictly from **process environment variables** or safe default fallbacks. The application does **not** automatically parse a `.env` file at runtime.
>
> Use `.env.example` as a variable reference when deploying or configuring local shell environments.

| Variable | Description | Default | Supported Values |
|---|---|---|---|
| `APP_ENV` | Application environment | `development` | `development`, `production`, `test` |
| `PORT` | HTTP server listening port | `8080` | `1024`–`65535` |
| `FRONTEND_URL` | Allowed origin for CORS | `http://localhost:3000` | Full URL (e.g. `http://localhost:3000`) |
| `LOG_LEVEL` | Logging verbosity | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | Neon pooled connection string (PgBouncer) | `""` | `postgres://` or `postgresql://` URL (Required for `cmd/api`) |
| `DATABASE_DIRECT_URL` | Neon direct compute connection string | `""` | `postgres://` or `postgresql://` URL (Required for `cmd/migrate`) |
| `DB_MAX_CONNS` | Maximum open connections in pgxpool | `5` | Integer `>= 1` |
| `DB_MIN_CONNS` | Minimum idle connections in pgxpool | `0` | Integer `>= 0` and `<= DB_MAX_CONNS` |
| `DB_MAX_CONN_LIFETIME` | Maximum lifetime of a pooled connection | `30m` | Go duration string (e.g. `30m`, `1h`) |
| `DB_MAX_CONN_IDLE_TIME` | Maximum idle time before recycling | `5m` | Go duration string (e.g. `5m`, `10m`) |
| `DB_HEALTH_TIMEOUT` | Database readiness probe timeout | `2s` | Go duration string (e.g. `2s`, `5s`) |

### Connection Separation: Pooled API vs. Direct Migrations

- **API Service (`cmd/api`)**: Uses `DATABASE_URL` to connect to Neon through PgBouncer (transaction pooling mode). `DATABASE_DIRECT_URL` is **not** required for `cmd/api`.
- **Migration Runner (`cmd/migrate`)**: Requires `DATABASE_DIRECT_URL` to connect directly to the PostgreSQL compute instance. `cmd/migrate` **never** falls back to `DATABASE_URL`. If `DATABASE_DIRECT_URL` is absent, `cmd/migrate` aborts immediately.
- **Secrecy**: Connection strings and credentials are never logged, printed, or exposed in errors or HTTP responses.

---

## Migration Conventions & Transaction Rules

`golang-migrate` does not automatically wrap migration SQL in a transaction for all DDL operations. For future Phase 3B migrations, the following conventions must be observed:

### 1. Transactional Migrations
For standard schema changes (tables, columns, foreign keys, views):
```sql
BEGIN;

-- transactional PostgreSQL statements
CREATE TABLE example (...);

COMMIT;
```

### 2. Non-Transactional Migrations
Operations that cannot execute inside a PostgreSQL transaction block (such as `CREATE INDEX CONCURRENTLY` or certain extension/type alterations) must be isolated in their own dedicated migration file **without** `BEGIN` or `COMMIT`.

---

## Running the Application

### Prerequisites

- Go `1.22+` (detected: `go1.26.1`)

### Run the API Server

```bash
# Set DATABASE_URL (pooled) and start server
$env:DATABASE_URL="postgres://user:password@ep-sample-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
go run ./cmd/api
```

### Run Migrations

```bash
# Set DATABASE_DIRECT_URL (direct compute) and run migration CLI
$env:DATABASE_DIRECT_URL="postgres://user:password@ep-sample.us-east-2.aws.neon.tech/neondb?sslmode=require"

# Apply all pending migrations
go run ./cmd/migrate up

# Roll back the single most recent migration
go run ./cmd/migrate down 1

# Inspect current schema version and dirty state
go run ./cmd/migrate version
```

---

## Testing & Verification

Run the verification suite:

```bash
# Run all unit and mock tests
go test ./...

# Run tests with race detection (when supported)
go test -race ./...

# Verify code formatting
gofmt -l .

# Run static analysis
go vet ./...

# Verify compilation without creating binary artifacts in the repo
go build ./...

# Verify git whitespace
git diff --check
```

---

## API Endpoints (Phase 3A Foundation)

### 1. `GET /health`
Liveness probe verifying that the API HTTP process and Go runtime are alive. Strictly independent of PostgreSQL.

* **Response** (`200 OK`):
  ```json
  {
    "success": true,
    "data": {
      "status": "ok",
      "service": "trustdocs-api"
    }
  }
  ```

### 2. `GET /ready`
Readiness probe verifying database connectivity via `pinger.Ping(timeoutCtx)`.

* **Database Available** (`200 OK`):
  ```json
  {
    "success": true,
    "data": {
      "status": "ready",
      "dependencies": [
        { "name": "postgres", "status": "up" }
      ]
    }
  }
  ```

* **Database Unavailable / Timeout** (`503 Service Unavailable`):
  ```json
  {
    "success": false,
    "error": {
      "code": "DEPENDENCY_UNAVAILABLE",
      "message": "One or more required dependencies are unavailable"
    },
    "data": {
      "status": "not_ready",
      "dependencies": [
        { "name": "postgres", "status": "down" }
      ]
    }
  }
  ```

---

## Current Phase Limitations & Deferred Work

- **Business Schema**: The 8-table business domain schema (universities, companies, students, certificates, consent tokens, verification logs, continuous identity chain, audit logs) is deferred to Phase 3B.
- **Authentication**: JWT signing, Argon2id hashing, and RBAC guards are deferred to Phase 4.
- **External Services**: Cloudflare R2 object storage, Resend email notifications, and Sentry monitoring are deferred to subsequent feature phases.