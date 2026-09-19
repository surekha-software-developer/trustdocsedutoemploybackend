package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestMigrate_ArgumentParsing_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string { return "" }

	code := Run([]string{}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 when no args provided, got %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("expected usage instructions in stderr, got: %s", stderr.String())
	}
}

func TestMigrate_ArgumentParsing_UnsupportedCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string { return "" }

	code := Run([]string{"unsupported_cmd"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unsupported command, got %d", code)
	}
	if !strings.Contains(stderr.String(), "ERROR: unsupported command 'unsupported_cmd'") {
		t.Errorf("expected unsupported command error, got: %s", stderr.String())
	}
}

func TestMigrate_RejectionWhenRawURLPassedInArgv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string { return "" }

	code := Run([]string{"up", "postgres://user:secret@localhost:5432/db"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 when raw URL passed in args, got %d", code)
	}
	if !strings.Contains(stderr.String(), "connection URLs must not be passed as command-line arguments") {
		t.Errorf("expected raw URL rejection error, got: %s", stderr.String())
	}
}

func TestMigrate_UnauthorizedURLEnvVar(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string { return "postgres://user:secret@localhost:5432/db" }

	code := Run([]string{"up", "--database-url-env", "CUSTOM_SECRET_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unauthorized env var name, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unauthorized database url environment variable") {
		t.Errorf("expected unauthorized env var error, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_MissingTestFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "DATABASE_DIRECT_URL":
			return "postgres://user:pass@localhost:5432/devdb"
		default:
			return ""
		}
	}

	// Attempting down on default DATABASE_DIRECT_URL must be rejected
	code := Run([]string{"down"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 for down on default database, got %d", code)
	}
	if !strings.Contains(stderr.String(), "destructive down migrations are prohibited on the primary database") {
		t.Errorf("expected primary database down rejection, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_MissingTargetEnv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "TEST_DATABASE_DIRECT_URL":
			return "postgres://user:pass@localhost:5432/trustdocs_schema_test"
		case "ALLOW_DESTRUCTIVE_MIGRATIONS":
			return "true"
		default:
			return ""
		}
	}

	code := Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 when DB_TARGET_ENV is missing, got %d", code)
	}
	if !strings.Contains(stderr.String(), "DB_TARGET_ENV=test is required") {
		t.Errorf("expected DB_TARGET_ENV required error, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_MissingAllowDestructiveFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "TEST_DATABASE_DIRECT_URL":
			return "postgres://user:pass@localhost:5432/trustdocs_schema_test"
		case "DB_TARGET_ENV":
			return "test"
		default:
			return ""
		}
	}

	code := Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 when ALLOW_DESTRUCTIVE_MIGRATIONS is missing, got %d", code)
	}
	if !strings.Contains(stderr.String(), "ALLOW_DESTRUCTIVE_MIGRATIONS=true is required") {
		t.Errorf("expected ALLOW_DESTRUCTIVE_MIGRATIONS required error, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_TestURLEqualsProductionURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	testURL := "postgres://user:secret@localhost:5432/trustdocs_schema_test"
	mockEnv := func(key string) string {
		switch key {
		case "DATABASE_DIRECT_URL":
			return testURL
		case "TEST_DATABASE_DIRECT_URL":
			return testURL // Accidental copy-paste of same URL
		case "DB_TARGET_ENV":
			return "test"
		case "ALLOW_DESTRUCTIVE_MIGRATIONS":
			return "true"
		default:
			return ""
		}
	}

	code := Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 when TEST_DATABASE_DIRECT_URL equals DATABASE_DIRECT_URL, got %d", code)
	}
	if !strings.Contains(stderr.String(), "TEST_DATABASE_DIRECT_URL must not equal DATABASE_DIRECT_URL") {
		t.Errorf("expected URL equality rejection error, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_IncorrectDatabaseName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "DATABASE_DIRECT_URL":
			return "postgres://user:secret@dev-host:5432/neondb"
		case "TEST_DATABASE_DIRECT_URL":
			return "postgres://user:secret@test-host:5432/neondb" // Wrong DB name (neondb instead of trustdocs_schema_test)
		case "DB_TARGET_ENV":
			return "test"
		case "ALLOW_DESTRUCTIVE_MIGRATIONS":
			return "true"
		default:
			return ""
		}
	}

	mockDBQuerier := func(connURL string) (string, error) {
		return "neondb", nil // Connected to wrong DB
	}

	code := Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, mockDBQuerier)
	if code != 1 {
		t.Fatalf("expected exit code 1 when connected database is not trustdocs_schema_test, got %d", code)
	}
	if !strings.Contains(stderr.String(), "connected database is 'neondb', expected 'trustdocs_schema_test'") {
		t.Errorf("expected wrong DB name rejection, got: %s", stderr.String())
	}
}

func TestMigrate_DestructiveDown_QueryDBFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "DATABASE_DIRECT_URL":
			return "postgres://user:secret@dev-host:5432/devdb"
		case "TEST_DATABASE_DIRECT_URL":
			return "postgres://user:secret@test-host:5432/trustdocs_schema_test"
		case "DB_TARGET_ENV":
			return "test"
		case "ALLOW_DESTRUCTIVE_MIGRATIONS":
			return "true"
		default:
			return ""
		}
	}

	mockDBQuerier := func(connURL string) (string, error) {
		return "", errors.New("network timeout")
	}

	code := Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, mockDBQuerier)
	if code != 1 {
		t.Fatalf("expected exit code 1 when DB name query fails, got %d", code)
	}
	if !strings.Contains(stderr.String(), "failed to verify target database name") {
		t.Errorf("expected failure to verify DB name error, got: %s", stderr.String())
	}
}

func TestMigrate_SecretsAreNeverPrinted(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secretPassword := "SuperSecretPassword123!"
	testURL := "postgres://admin:" + secretPassword + "@ep-test-host.aws.neon.tech/trustdocs_schema_test?sslmode=require"

	mockEnv := func(key string) string {
		switch key {
		case "DATABASE_DIRECT_URL":
			return "postgres://admin:DevPass@ep-dev-host.aws.neon.tech/neondb"
		case "TEST_DATABASE_DIRECT_URL":
			return testURL
		case "DB_TARGET_ENV":
			return "test"
		case "ALLOW_DESTRUCTIVE_MIGRATIONS":
			return "true"
		default:
			return ""
		}
	}

	mockDBQuerier := func(connURL string) (string, error) {
		return "trustdocs_schema_test", nil
	}

	// This run will proceed to migrate.New which will fail locally because test-host isn't reachable
	_ = Run([]string{"down", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, mockDBQuerier)

	allOutput := stdout.String() + stderr.String()
	if strings.Contains(allOutput, secretPassword) {
		t.Errorf("CRITICAL SECURITY VIOLATION: password was printed in output: %s", allOutput)
	}
	if strings.Contains(allOutput, "admin:") {
		t.Errorf("CRITICAL SECURITY VIOLATION: credentials were printed in output: %s", allOutput)
	}
}

func TestConvertToMigrateURL_PostgresqlScheme(t *testing.T) {
	input := "postgresql://app_user:pass123@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"
	expected := "pgx5://app_user:pass123@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"

	got, err := ConvertToMigrateURL(input)
	if err != nil {
		t.Fatalf("unexpected error converting postgresql URL: %v", err)
	}
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestConvertToMigrateURL_PostgresScheme(t *testing.T) {
	input := "postgres://app_user:pass123@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"
	expected := "pgx5://app_user:pass123@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"

	got, err := ConvertToMigrateURL(input)
	if err != nil {
		t.Fatalf("unexpected error converting postgres URL: %v", err)
	}
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestConvertToMigrateURL_UnsupportedSchemesRejected(t *testing.T) {
	invalidURLs := []string{
		"mysql://user:pass@localhost:3306/db",
		"sqlite3://local.db",
		"http://localhost:8080",
		"ftp://files.example.com",
		"",
		"not_a_valid_url",
	}

	for _, raw := range invalidURLs {
		got, err := ConvertToMigrateURL(raw)
		if err == nil {
			t.Errorf("expected error for unsupported URL '%s', got: %s", raw, got)
		}
		if err != nil && err.Error() != "unsupported database URL scheme" {
			t.Errorf("expected 'unsupported database URL scheme' error for '%s', got: %v", raw, err)
		}
	}
}

func TestConvertToMigrateURL_PercentEncodedCredentialsPreserved(t *testing.T) {
	input := "postgresql://app_user:p%40ss%3Aword%23@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"
	got, err := ConvertToMigrateURL(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(got, "pgx5://") {
		t.Errorf("expected pgx5:// prefix, got: %s", got)
	}
	if !strings.Contains(got, "app_user:p%40ss%3Aword") {
		t.Errorf("expected percent-encoded credentials preserved, got: %s", got)
	}
	if !strings.Contains(got, "/trustdocs_schema_test?sslmode=require") {
		t.Errorf("expected database path and query params preserved, got: %s", got)
	}
}

func TestConvertToMigrateURL_OriginalInputNotModified(t *testing.T) {
	original := "postgresql://app_user:pass123@ep-test.neon.tech:5432/trustdocs_schema_test?sslmode=require"
	originalCopy := original

	_, err := ConvertToMigrateURL(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if original != originalCopy {
		t.Errorf("original string was modified: before=%s, after=%s", originalCopy, original)
	}
}

func TestClassifyInitError_SafeCategories(t *testing.T) {
	cases := []struct {
		name     string
		inputErr error
		expected string
	}{
		{
			name:     "nil error",
			inputErr: nil,
			expected: "",
		},
		{
			name:     "migration source failure",
			inputErr: errors.New("file: db/migrations does not exist"),
			expected: "migration source initialization failure",
		},
		{
			name:     "unknown database driver",
			inputErr: errors.New("database driver: unknown driver postgres (forgotten import?)"),
			expected: "database driver initialization failure",
		},
		{
			name:     "unsupported scheme",
			inputErr: errors.New("unsupported scheme: sqlite"),
			expected: "unsupported database URL scheme",
		},
		{
			name:     "connectivity or authentication failure with sensitive string",
			inputErr: errors.New("failed to connect to user=admin password=SecretPassword123 host=ep-test: connection refused"),
			expected: "connectivity/authentication/database failure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyInitError(tc.inputErr)
			if got != tc.expected {
				t.Errorf("expected '%s', got '%s'", tc.expected, got)
			}
			// Security check: raw error strings must not leak into category
			if tc.inputErr != nil && strings.Contains(got, "SecretPassword123") {
				t.Errorf("security violation: raw secret leaked in category '%s'", got)
			}
		})
	}
}

func TestMigrate_Run_UnsupportedSchemeRejectedSafely(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		switch key {
		case "TEST_DATABASE_DIRECT_URL":
			return "mysql://admin:secretPass@localhost:3306/trustdocs_schema_test"
		default:
			return ""
		}
	}

	code := Run([]string{"up", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unsupported scheme, got %d", code)
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "ERROR: unsupported database URL scheme") {
		t.Errorf("expected 'ERROR: unsupported database URL scheme', got: %s", errOutput)
	}

	// Verify no secrets or URLs were exposed
	if strings.Contains(errOutput, "secretPass") || strings.Contains(errOutput, "mysql://") || strings.Contains(errOutput, "admin") {
		t.Errorf("security violation: credentials or raw URL exposed in error: %s", errOutput)
	}
}

func TestMigrate_Run_InitFailureDoesNotExposeSecrets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secretPassword := "VerySecretPassword999!"
	mockEnv := func(key string) string {
		switch key {
		case "TEST_DATABASE_DIRECT_URL":
			return "postgresql://db_user:" + secretPassword + "@invalid-unreachable-neon-host.tech:5432/trustdocs_schema_test?sslmode=require"
		default:
			return ""
		}
	}

	code := Run([]string{"up", "--database-url-env", "TEST_DATABASE_DIRECT_URL"}, mockEnv, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unreachable host, got %d", code)
	}

	allOutput := stdout.String() + stderr.String()
	if strings.Contains(allOutput, secretPassword) {
		t.Errorf("security violation: password exposed in output: %s", allOutput)
	}
	if strings.Contains(allOutput, "db_user:") {
		t.Errorf("security violation: username exposed in output: %s", allOutput)
	}
	if strings.Contains(allOutput, "invalid-unreachable-neon-host") {
		t.Errorf("security violation: host exposed in error output: %s", allOutput)
	}
	if !strings.Contains(stderr.String(), "ERROR: connectivity/authentication/database failure") {
		t.Errorf("expected safe category error, got: %s", stderr.String())
	}
}
