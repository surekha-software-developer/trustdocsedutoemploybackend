package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MinPasswordRunes defines the minimum password length in Unicode code points (NIST/OWASP-aligned).
	MinPasswordRunes = 15

	// MaxPasswordBytes defines the maximum password length in UTF-8 bytes as an explicit resource-control limit.
	MaxPasswordBytes = 256

	argon2Version = argon2.Version
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordRunes)
	ErrPasswordTooLong  = fmt.Errorf("password exceeds maximum length of %d bytes", MaxPasswordBytes)
	ErrInvalidHash      = errors.New("invalid or malformed argon2id hash")
)

// Argon2Params defines tunable parameters for Argon2id key derivation.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params provides conservative, OWASP-compliant defaults (64MB, 3 iterations, 2 parallelism).
var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// GenerateDummyHash computes an Argon2id PHC string using the supplied Argon2Params
// and a synthetic non-credential string. Pre-computed once per service initialization
// so that verifying non-existent users incurs identical cost without dynamic allocation or obsolete parameters.
func GenerateDummyHash(params Argon2Params) string {
	salt := make([]byte, params.SaltLength)
	// Deterministic zero salt for synthetic dummy initialization
	key := argon2.IDKey(
		[]byte("trustdocs-timing-equalization-dummy-synthetic-credential"),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// Default static dummy hash computed once with DefaultArgon2Params.
var defaultDummyArgon2Hash = GenerateDummyHash(DefaultArgon2Params)

// ValidatePasswordPolicy checks that the candidate password satisfies NIST/OWASP length boundaries.
// Spaces, Unicode code points, emojis, and password-manager passphrases are fully supported.
// Never silently truncates.
func ValidatePasswordPolicy(password string) error {
	byteLen := len([]byte(password))
	if byteLen > MaxPasswordBytes {
		return ErrPasswordTooLong
	}

	runeCount := utf8.RuneCountInString(password)
	if runeCount < MinPasswordRunes {
		return ErrPasswordTooShort
	}

	return nil
}

// HashPassword hashes a password using Argon2id with a cryptographically secure random salt.
// Returns a standard PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func HashPassword(password string, params Argon2Params) (string, error) {
	if err := ValidatePasswordPolicy(password); err != nil {
		return "", err
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate secure salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// VerifyPassword verifies a plaintext password against an encoded Argon2id PHC string.
// Uses subtle.ConstantTimeCompare to resist timing attacks.
// Safely handles malformed strings without panics.
func VerifyPassword(password string, encodedHash string) (bool, error) {
	if len([]byte(password)) > MaxPasswordBytes {
		return false, nil
	}

	parts := strings.Split(encodedHash, "$")
	// Expected parts: ["", "argon2id", "v=19", "m=65536,t=3,p=2", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2Version {
		return false, ErrInvalidHash
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, ErrInvalidHash
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expectedHash) == 0 {
		return false, ErrInvalidHash
	}

	candidateHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)

	if subtle.ConstantTimeCompare(candidateHash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}

// DummyVerify performs a constant-time verification against the default dummy hash.
// Used as a fallback when a specific configured service dummy hash is not supplied.
func DummyVerify(password string) {
	_, _ = VerifyPassword(password, defaultDummyArgon2Hash)
}
