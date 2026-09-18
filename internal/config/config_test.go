package config

import (
	"os"
	"testing"
)

func TestConfig_Defaults(t *testing.T) {
	// Clear any existing env vars for this test
	os.Unsetenv("APP_ENV")
	os.Unsetenv("PORT")
	os.Unsetenv("FRONTEND_URL")
	os.Unsetenv("LOG_LEVEL")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error loading defaults, got: %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Errorf("expected default AppEnv 'development', got '%s'", cfg.AppEnv)
	}
	if cfg.Port != "8080" {
		t.Errorf("expected default Port '8080', got '%s'", cfg.Port)
	}
	if cfg.FrontendURL != "http://localhost:3000" {
		t.Errorf("expected default FrontendURL 'http://localhost:3000', got '%s'", cfg.FrontendURL)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got '%s'", cfg.LogLevel)
	}
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		expectError bool
	}{
		{
			name: "valid configuration",
			cfg: Config{
				AppEnv:      "production",
				Port:        "9000",
				FrontendURL: "https://trustdocs.example.com",
				LogLevel:    "warn",
			},
			expectError: false,
		},
		{
			name: "invalid environment",
			cfg: Config{
				AppEnv:      "staging_invalid",
				Port:        "8080",
				FrontendURL: "http://localhost:3000",
				LogLevel:    "info",
			},
			expectError: true,
		},
		{
			name: "invalid non-numeric port",
			cfg: Config{
				AppEnv:      "development",
				Port:        "abc",
				FrontendURL: "http://localhost:3000",
				LogLevel:    "info",
			},
			expectError: true,
		},
		{
			name: "invalid out-of-range port",
			cfg: Config{
				AppEnv:      "development",
				Port:        "70000",
				FrontendURL: "http://localhost:3000",
				LogLevel:    "info",
			},
			expectError: true,
		},
		{
			name: "empty frontend url",
			cfg: Config{
				AppEnv:      "development",
				Port:        "8080",
				FrontendURL: "   ",
				LogLevel:    "info",
			},
			expectError: true,
		},
		{
			name: "invalid log level",
			cfg: Config{
				AppEnv:      "development",
				Port:        "8080",
				FrontendURL: "http://localhost:3000",
				LogLevel:    "verbose",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Errorf("expected validation error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no validation error, got: %v", err)
			}
		})
	}
}
