package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMigrate_ArgumentParsing_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string { return "" }

	code := Run([]string{}, mockEnv, &stdout, &stderr)
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

	code := Run([]string{"unsupported_cmd"}, mockEnv, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unsupported command, got %d", code)
	}
	if !strings.Contains(stderr.String(), "ERROR: unsupported command 'unsupported_cmd'") {
		t.Errorf("expected unsupported command error, got: %s", stderr.String())
	}
}

func TestMigrate_RejectionWhenDirectURLAbsent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Environment where DATABASE_DIRECT_URL is absent
	mockEnv := func(key string) string {
		return ""
	}

	code := Run([]string{"up"}, mockEnv, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when DATABASE_DIRECT_URL is absent, got %d", code)
	}
	if !strings.Contains(stderr.String(), "DATABASE_DIRECT_URL environment variable is required") {
		t.Errorf("expected missing direct URL error message, got: %s", stderr.String())
	}
}

func TestMigrate_ConfirmationDatabaseURLNeverUsedAsFallback(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Environment where DATABASE_URL is set (pooled), but DATABASE_DIRECT_URL is NOT set
	mockEnv := func(key string) string {
		if key == "DATABASE_URL" {
			return "postgres://user:secret@localhost:5432/pooled_db"
		}
		return ""
	}

	code := Run([]string{"up"}, mockEnv, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 even when DATABASE_URL is set, got %d", code)
	}
	// Must still fail with DATABASE_DIRECT_URL required error
	if !strings.Contains(stderr.String(), "DATABASE_DIRECT_URL environment variable is required") {
		t.Errorf("expected rejection because DATABASE_URL must not be used as fallback, got: %s", stderr.String())
	}
	// Verify that secret credentials from DATABASE_URL are NEVER printed
	if strings.Contains(stderr.String(), "secret") || strings.Contains(stdout.String(), "secret") {
		t.Errorf("output must NEVER leak credentials from DATABASE_URL")
	}
}

func TestMigrate_InvalidDownStepsParameter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mockEnv := func(key string) string {
		if key == "DATABASE_DIRECT_URL" {
			return "postgres://user:secret@localhost:5432/direct_db"
		}
		return ""
	}

	code := Run([]string{"down", "invalid_number"}, mockEnv, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for invalid down steps, got %d", code)
	}
	if !strings.Contains(stderr.String(), "invalid steps parameter") {
		t.Errorf("expected invalid steps error message, got: %s", stderr.String())
	}
}
