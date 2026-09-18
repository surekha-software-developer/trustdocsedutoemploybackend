# TrustDocs Education to Employment - Backend

The core REST API backend service for the TrustDocs education-to-employment verification platform.

---

## Overview

TrustDocs connects verified university education with verified employment. This backend service powers tamper-evident digital certificate verification, scoped consent-based QR verification, and the Continuous Identity Chain across hiring milestones.

---

## Current Status: Phase 2 (Go Backend Foundation)

- **Language / Runtime**: Go `1.26.1`
- **Module Path**: `github.com/surekha-software-developer/trustdocsedutoemploybackend`
- **HTTP Web Framework**: Gin (`v1.12.0`)
- **Structured Logging**: Native `log/slog` JSON output
- **Tracing**: RFC 4122 UUID v4 Request ID middleware
- **CORS**: Restricted cross-origin protection with preflight `OPTIONS` support
- **Reliability**: Panic recovery middleware with sanitized JSON 500 responses and graceful server shutdown

---

## Architecture

The backend follows a scalable, **modular-monolith** architecture. Each domain module encapsulates its own business logic, HTTP handlers, routes, and data access layers.

### Current Directory Structure

```
trustdocsedutoemploybackend/
├── cmd/
│   └── api/
│       └── main.go                  # API entry point & graceful shutdown
├── internal/
│   ├── config/
│   │   ├── config.go                # Process environment variable loader
│   │   └── config_test.go           # Configuration validation tests
│   ├── core/
│   │   ├── errors.go                # Standard error codes & AppError types
│   │   ├── logger.go                # Structured slog JSON logger
│   │   ├── response.go              # Standard Success/Error JSON responders
│   │   └── response_test.go         # Response helper tests
│   ├── middleware/
│   │   ├── cors.go                  # Restricted development CORS
│   │   ├── logging.go               # Request logging excluding secrets
│   │   ├── recovery.go              # Safe panic recovery
│   │   ├── request_id.go            # Request ID tracing middleware
│   │   └── request_id_test.go       # Request ID tests
│   ├── modules/
│   │   └── health/
│   │       ├── handler.go           # /health and /ready HTTP handlers
│   │       ├── routes.go            # Health route registration
│   │       ├── service.go           # Health check domain service
│   │       └── handler_test.go      # Health unit tests
│   ├── router/
│   │   ├── router.go                # Gin engine setup, middleware chain & routes
│   │   └── router_test.go           # 404, 405, CORS, and recovery tests
│   └── server/
│       └── server.go                # HTTP server with safe timeouts
├── .env.example                     # Environment variable reference template
├── .gitignore                       # Git ignore rules
├── go.mod                           # Go module declaration
├── go.sum                           # Dependency checksums
└── README.md                        # Documentation
```

### Module Conventions & Structure

Domain modules adhere to a uniform structure containing only the layers they genuinely need:

```
<module>/
├── handler.go       # HTTP request binding and response presentation
├── service.go       # Business logic and domain validation
├── repository.go    # Database access (added in subsequent phases)
├── routes.go        # Module route registration
├── dto.go           # Request and response structures
└── errors.go        # Module-specific domain errors
```

### Planned Future Modules (Deferred to Subsequent Phases)

The following domain modules are planned and will be introduced as their respective phases commence:

```
internal/modules/
├── admin/           # Organization approval and administrative auditing
├── auth/            # Password authentication, session lifecycle, and OAuth
├── organizations/   # University and company profile records
├── users/           # User accounts and profile management
├── certificates/    # Certificate issuance, SHA-256 hashing, and revocation
├── consent/         # Company-bound expiring QR generation and validation
├── verification/    # Multi-point credential and live presenter verification
├── identitychain/   # Continuous Identity Chain tracking across hiring stages
└── audit/           # Immutable compliance audit log recording
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

---

## Running the Application

### Prerequisites

- Go `1.22+` (detected: `go1.26.1`)

### Run Locally

```bash
# Run with default development configuration
go run ./cmd/api

# Or with custom process environment variables:
PORT=8080 FRONTEND_URL=http://localhost:3000 go run ./cmd/api
```

---

## Testing & Verification

Run the test suite:

```bash
# Run unit and integration tests
go test ./...

# Run tests with race detection (when supported)
go test -race ./...

# Verify code formatting
gofmt -l .

# Run static analysis
go vet ./...

# Verify compilation without creating binary artifacts in the repo
go build ./...
```

---

## API Endpoints (Phase 2 Foundation)

### 1. `GET /health`
Liveness check for container orchestrators and monitoring probes.

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
Readiness check verifying service dependency readiness.

* **Response** (`200 OK`):
  ```json
  {
    "success": true,
    "data": {
      "status": "ready",
      "dependencies": []
    }
  }
  ```

### 3. Unknown Route Handling
Requests to undefined routes return HTTP 404:

* **Response** (`404 Not Found`):
  ```json
  {
    "success": false,
    "error": {
      "code": "NOT_FOUND",
      "message": "The requested resource was not found"
    }
  }
  ```

### 4. Unsupported Method Handling
Requests with unsupported HTTP methods return HTTP 405:

* **Response** (`405 Method Not Allowed`):
  ```json
  {
    "success": false,
    "error": {
      "code": "METHOD_NOT_ALLOWED",
      "message": "The HTTP method is not allowed"
    }
  }
  ```

---

## Current Phase Limitations & Deferred Work

- **Database**: Neon PostgreSQL connection pool, `pgx`, `sqlc`, models, and migrations are deferred to Phase 3.
- **Authentication**: JWT generation, Argon2id password hashing, and RBAC guards are deferred to Phase 4.
- **Storage & External Services**: Cloudflare R2, Resend email notifications, and Sentry monitoring are deferred to subsequent feature phases.