package auth

import (
	"strings"
	"testing"
)

func TestPassword_PolicyLengthMinimum(t *testing.T) {
	// 14 characters -> too short
	short := "ShortPass1234!"
	if err := ValidatePasswordPolicy(short); err == nil {
		t.Errorf("expected error for 14-char password, got nil")
	}

	// Exactly 15 characters -> valid
	exact15 := "Exact15CharsOK!"
	if err := ValidatePasswordPolicy(exact15); err != nil {
		t.Errorf("expected 15-char password to be valid, got: %v", err)
	}
}

func TestPassword_PolicyLengthMaximum(t *testing.T) {
	// Exactly 256 ASCII bytes -> valid
	maxValid := strings.Repeat("A", 256)
	if err := ValidatePasswordPolicy(maxValid); err != nil {
		t.Errorf("expected 256-byte password to be valid, got: %v", err)
	}

	// 257 ASCII bytes -> too long
	tooLong := strings.Repeat("A", 257)
	if err := ValidatePasswordPolicy(tooLong); err == nil {
		t.Errorf("expected error for 257-byte password, got nil")
	}
}

func TestPassword_UnicodeSpacesAndEmojis(t *testing.T) {
	// Passphrase with spaces: 26 runes
	passphrase := "correct horse battery staple"
	if err := ValidatePasswordPolicy(passphrase); err != nil {
		t.Errorf("expected passphrase with spaces to be valid, got: %v", err)
	}

	// Multibyte Unicode + Emojis (each emoji is 4 bytes, 1 rune): 15 runes total
	// 11 ASCII characters + 4 emojis = 15 runes
	unicodePass := "SecurePass!🔑🛡️🔐"
	// Check rune count
	if err := ValidatePasswordPolicy(unicodePass); err != nil {
		t.Errorf("expected unicode/emoji password to be valid, got: %v", err)
	}

	// Hash and verify the unicode/emoji password
	fastParams := Argon2Params{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	encoded, err := HashPassword(unicodePass, fastParams)
	if err != nil {
		t.Fatalf("failed to hash unicode password: %v", err)
	}

	match, err := VerifyPassword(unicodePass, encoded)
	if err != nil || !match {
		t.Errorf("expected unicode password to verify successfully, match=%v, err=%v", match, err)
	}
}

func TestPassword_Argon2idHashingAndVerification(t *testing.T) {
	pass := "StrongSecretPassword123!"
	fastParams := Argon2Params{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash1, err := HashPassword(pass, fastParams)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	hash2, err := HashPassword(pass, fastParams)
	if err != nil {
		t.Fatalf("failed to hash password second time: %v", err)
	}

	// Salt uniqueness check: identical passwords must generate distinct hashes
	if hash1 == hash2 {
		t.Errorf("expected distinct hashes due to random salt, got identical: %s", hash1)
	}

	// PHC Format validation
	if !strings.HasPrefix(hash1, "$argon2id$v=19$m=16384,t=1,p=1$") {
		t.Errorf("unexpected PHC format: %s", hash1)
	}

	// Correct password matches
	match, err := VerifyPassword(pass, hash1)
	if err != nil || !match {
		t.Errorf("expected correct password to match, got match=%v, err=%v", match, err)
	}

	// Wrong password fails cleanly
	wrongMatch, err := VerifyPassword("WrongPassword123!", hash1)
	if err != nil {
		t.Errorf("unexpected error on wrong password verification: %v", err)
	}
	if wrongMatch {
		t.Errorf("expected wrong password to fail verification")
	}
}

func TestPassword_MalformedPHCFailsSafely(t *testing.T) {
	malformedInputs := []string{
		"",
		"not_a_hash",
		"$argon2id$v=99$m=65536,t=3,p=2$salt$hash",
		"$bcrypt$v=19$m=65536,t=3,p=2$salt$hash",
		"$argon2id$v=19$invalid_params$salt$hash",
		"$argon2id$v=19$m=65536,t=3,p=2$invalid_b64!$hash",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$invalid_b64!",
	}

	for _, malformed := range malformedInputs {
		match, err := VerifyPassword("SomeValidPassword123!", malformed)
		if err == nil {
			t.Errorf("expected error for malformed hash '%s', got nil", malformed)
		}
		if match {
			t.Errorf("expected match=false for malformed hash '%s'", malformed)
		}
	}
}

func TestPassword_DummyVerify(t *testing.T) {
	// Must execute safely without panic
	DummyVerify("AnyPasswordAttempt123!")
}

func TestPassword_GenerateDummyHash_ParameterParity(t *testing.T) {
	customParams := Argon2Params{
		Memory:      24576,
		Iterations:  2,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

	dummyHash := GenerateDummyHash(customParams)

	// Ensure the encoded PHC header reflects the custom parameters exactly
	expectedPrefix := "$argon2id$v=19$m=24576,t=2,p=4$"
	if !strings.HasPrefix(dummyHash, expectedPrefix) {
		t.Errorf("expected dummy hash prefix %s, got %s", expectedPrefix, dummyHash)
	}

	// Verify that the generated dummy hash does not panic and behaves consistently
	match, err := VerifyPassword("arbitrary-guess", dummyHash)
	if err != nil {
		t.Errorf("expected no error verifying against dummy hash, got: %v", err)
	}
	if match {
		t.Errorf("arbitrary guess should never match synthetic dummy credential")
	}
}
