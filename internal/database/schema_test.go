//go:build integration

package database

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSchema_IntegrationSuite(t *testing.T) {
	testURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_DIRECT_URL"))
	if testURL == "" {
		t.Fatal("TEST_DATABASE_DIRECT_URL environment variable is required when running integration tests")
	}

	if os.Getenv("DB_TARGET_ENV") != "test" {
		t.Fatal("DB_TARGET_ENV=test environment variable is required for integration tests")
	}

	if os.Getenv("ALLOW_DESTRUCTIVE_MIGRATIONS") != "true" {
		t.Fatal("ALLOW_DESTRUCTIVE_MIGRATIONS=true is required for integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer conn.Close(ctx)

	// Verify connected database is exactly trustdocs_schema_test
	var dbName string
	err = conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName)
	if err != nil {
		t.Fatalf("failed to query current_database(): %v", err)
	}

	if dbName != "trustdocs_schema_test" {
		t.Fatalf("SAFETY VIOLATION: integration tests must only run on 'trustdocs_schema_test', got: '%s'", dbName)
	}

	// Verify required tables exist
	requiredTables := []string{
		"users",
		"auth_identities",
		"auth_sessions",
		"organizations",
		"organization_memberships",
		"audit_logs",
	}

	for _, table := range requiredTables {
		var exists bool
		err := conn.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("failed to check table existence for %s: %v", table, err)
		}
		if !exists {
			t.Errorf("expected table %s to exist in trustdocs_schema_test", table)
		}
	}
}
