package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
)

// DBNameQuerier abstracts the SELECT current_database() check for testing and production.
type DBNameQuerier func(connURL string) (string, error)

func defaultDBNameQuerier(connURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, connURL)
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)

	var dbName string
	err = conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName)
	if err != nil {
		return "", err
	}
	return dbName, nil
}

// findMigrationsSource locates the db/migrations directory relative to current working directory.
func findMigrationsSource() string {
	candidates := []string{
		"db/migrations",
		"../db/migrations",
		"../../db/migrations",
	}
	for _, candidate := range candidates {
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return "file://" + candidate
		}
	}
	return "file://db/migrations"
}

// ConvertToMigrateURL validates that the input URL has a supported postgres or postgresql scheme,
// and returns an internal copy with the scheme changed to "pgx5" for consumption by
// golang-migrate's pgx/v5 database driver.
// The original rawURL string is not modified.
// Username, percent-encoded password, hostname, database path, and query parameters are preserved.
func ConvertToMigrateURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("unsupported database URL scheme")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "postgres" && scheme != "postgresql" {
		return "", errors.New("unsupported database URL scheme")
	}

	// Create a separate internal URL copy
	internalURL := *parsed
	internalURL.Scheme = "pgx5"

	return internalURL.String(), nil
}

// ClassifyInitError maps migration initialization errors into safe, categorized messages.
// It ensures credentials, raw URLs, and sensitive connection parameters are never exposed.
func ClassifyInitError(err error) string {
	if err == nil {
		return ""
	}
	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "source") || strings.Contains(errStr, "file:"):
		return "migration source initialization failure"
	case strings.Contains(errStr, "scheme") || strings.Contains(errStr, "unsupported scheme"):
		return "unsupported database URL scheme"
	case strings.Contains(errStr, "unknown driver") || strings.Contains(errStr, "database driver"):
		return "database driver initialization failure"
	default:
		return "connectivity/authentication/database failure"
	}
}

// Run executes the migration runner with strict environment-variable contracts and destructive guards.
func Run(args []string, getEnv func(string) string, stdout, stderr io.Writer, queryDB DBNameQuerier) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	envVarName := "DATABASE_DIRECT_URL"
	filteredArgs := make([]string, 0, len(args))

	// Parse flags and ensure no raw connection URLs were passed in argv
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.Contains(arg, "://") {
			fmt.Fprintln(stderr, "ERROR: connection URLs must not be passed as command-line arguments")
			return 1
		}

		if arg == "--database-url-env" {
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "ERROR: --database-url-env requires an environment variable name")
				return 1
			}
			envVarName = strings.TrimSpace(args[i+1])
			i++
			continue
		} else if strings.HasPrefix(arg, "--database-url-env=") {
			envVarName = strings.TrimSpace(strings.TrimPrefix(arg, "--database-url-env="))
			continue
		}

		filteredArgs = append(filteredArgs, arg)
	}

	// Validate environment variable whitelist
	switch envVarName {
	case "DATABASE_DIRECT_URL", "TEST_DATABASE_DIRECT_URL":
		// authorized
	default:
		fmt.Fprintf(stderr, "ERROR: unauthorized database url environment variable '%s'; only DATABASE_DIRECT_URL or TEST_DATABASE_DIRECT_URL are permitted\n", envVarName)
		return 1
	}

	if len(filteredArgs) == 0 {
		printUsage(stderr)
		return 1
	}

	command := strings.ToLower(strings.TrimSpace(filteredArgs[0]))
	downSteps := 1
	switch command {
	case "up", "version":
		// valid commands
	case "down":
		if len(filteredArgs) > 1 {
			parsedSteps, parseErr := strconv.Atoi(filteredArgs[1])
			if parseErr != nil || parsedSteps < 1 {
				fmt.Fprintln(stderr, "ERROR: invalid steps parameter for down command, must be a positive integer")
				return 1
			}
			downSteps = parsedSteps
		}
	default:
		fmt.Fprintf(stderr, "ERROR: unsupported command '%s'\n", command)
		printUsage(stderr)
		return 1
	}

	directURL := getEnv(envVarName)
	if strings.TrimSpace(directURL) == "" {
		fmt.Fprintf(stderr, "ERROR: %s environment variable is required for migrations.\n", envVarName)
		fmt.Fprintln(stderr, "Do NOT run migrations through a transaction pooler (PgBouncer).")
		return 1
	}

	// Validate input scheme and obtain internal pgx5 URL for golang-migrate
	migrateURL, convErr := ConvertToMigrateURL(directURL)
	if convErr != nil {
		fmt.Fprintf(stderr, "ERROR: %s\n", convErr.Error())
		return 1
	}

	// Multi-factor safety guards for destructive down migrations
	if command == "down" {
		if envVarName != "TEST_DATABASE_DIRECT_URL" {
			fmt.Fprintln(stderr, "ERROR: destructive down migrations are prohibited on the primary database; specify --database-url-env TEST_DATABASE_DIRECT_URL")
			return 1
		}

		if getEnv("DB_TARGET_ENV") != "test" {
			fmt.Fprintln(stderr, "ERROR: DB_TARGET_ENV=test is required for destructive migrations")
			return 1
		}

		if getEnv("ALLOW_DESTRUCTIVE_MIGRATIONS") != "true" {
			fmt.Fprintln(stderr, "ERROR: ALLOW_DESTRUCTIVE_MIGRATIONS=true is required for destructive migrations")
			return 1
		}

		primaryURL := getEnv("DATABASE_DIRECT_URL")
		if primaryURL != "" && strings.TrimSpace(directURL) == strings.TrimSpace(primaryURL) {
			fmt.Fprintln(stderr, "ERROR: TEST_DATABASE_DIRECT_URL must not equal DATABASE_DIRECT_URL")
			return 1
		}

		if queryDB == nil {
			queryDB = defaultDBNameQuerier
		}

		dbName, err := queryDB(directURL)
		if err != nil {
			fmt.Fprintln(stderr, "ERROR: failed to verify target database name")
			return 1
		}

		if dbName != "trustdocs_schema_test" {
			fmt.Fprintf(stderr, "ERROR: destructive down migration refused: connected database is '%s', expected 'trustdocs_schema_test'\n", dbName)
			return 1
		}

		// Log safe target info (sanitized hostname and verified database name)
		if parsedURL, parseErr := url.Parse(directURL); parseErr == nil {
			fmt.Fprintf(stdout, "Target: host=%s, database=%s (destructive test authorized)\n", parsedURL.Host, dbName)
		}
	}

	// Initialize golang-migrate instance using file source and internal pgx5 URL
	m, err := migrate.New(findMigrationsSource(), migrateURL)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %s\n", ClassifyInitError(err))
		return 1
	}
	defer func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil || dbErr != nil {
			// Clean close
		}
	}()

	switch command {
	case "up":
		err = m.Up()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fmt.Fprintln(stderr, "ERROR: migration up failed")
			return 1
		}
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Fprintln(stdout, "Database schema is already up to date (no change).")
		} else {
			fmt.Fprintln(stdout, "Migrations applied successfully.")
		}
		return 0

	case "down":
		err = m.Steps(-downSteps)
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fmt.Fprintln(stderr, "ERROR: migration down failed")
			return 1
		}
		fmt.Fprintf(stdout, "Rolled back %d migration(s) successfully.\n", downSteps)
		return 0

	case "version":
		v, dirty, vErr := m.Version()
		if vErr != nil {
			if errors.Is(vErr, migrate.ErrNilVersion) {
				fmt.Fprintln(stdout, "Database schema version: unversioned (0), dirty: false")
				return 0
			}
			fmt.Fprintln(stderr, "ERROR: failed to retrieve schema version")
			return 1
		}
		fmt.Fprintf(stdout, "Database schema version: %d, dirty: %v\n", v, dirty)
		return 0
	}

	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "TrustDocs Migration Runner")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  go run ./cmd/migrate up [--database-url-env NAME]       # Apply pending migrations")
	fmt.Fprintln(w, "  go run ./cmd/migrate down [n] [--database-url-env NAME] # Roll back n migrations (test DB only)")
	fmt.Fprintln(w, "  go run ./cmd/migrate version [--database-url-env NAME]  # Print current schema version")
}

func main() {
	exitCode := Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, defaultDBNameQuerier)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
