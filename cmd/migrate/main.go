package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Run executes the migration command with given arguments and environment lookup.
// It returns an exit code (0 for success, 1 for failure).
// This is designed for complete testability without printing secrets or invoking os.Exit in unit tests.
func Run(args []string, getEnv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	command := strings.ToLower(strings.TrimSpace(args[0]))
	downSteps := 1
	switch command {
	case "up", "version":
		// valid commands
	case "down":
		if len(args) > 1 {
			parsedSteps, parseErr := strconv.Atoi(args[1])
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

	// Strictly require DATABASE_DIRECT_URL. NEVER inspect or fall back to DATABASE_URL.
	directURL := getEnv("DATABASE_DIRECT_URL")
	if strings.TrimSpace(directURL) == "" {
		fmt.Fprintln(stderr, "ERROR: DATABASE_DIRECT_URL environment variable is required for migrations.")
		fmt.Fprintln(stderr, "Do NOT run migrations through a transaction pooler (PgBouncer).")
		return 1
	}

	// Initialize golang-migrate instance using file source and pgx/v5 driver
	m, err := migrate.New("file://db/migrations", directURL)
	if err != nil {
		fmt.Fprintln(stderr, "ERROR: failed to initialize migration engine")
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
	fmt.Fprintln(w, "  go run ./cmd/migrate up         # Apply all pending migrations")
	fmt.Fprintln(w, "  go run ./cmd/migrate down [n]   # Roll back n migrations (default: 1)")
	fmt.Fprintln(w, "  go run ./cmd/migrate version    # Print current schema version and dirty state")
}

func main() {
	exitCode := Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
