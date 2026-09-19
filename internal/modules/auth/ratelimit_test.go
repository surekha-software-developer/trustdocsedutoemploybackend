package auth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type mockClock struct {
	mu  sync.Mutex
	now time.Time
}

func (m *mockClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *mockClock) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
}

func TestMemoryRateLimiter_BasicAndWindowExpiry(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := &mockClock{now: start}
	limiter := NewMemoryRateLimiter(100, clock)

	key := "test-key"
	limit := 3
	window := 10 * time.Second

	// 3 requests allowed
	for i := 1; i <= 3; i++ {
		allowed, retryAfter := limiter.Allow(key, limit, window)
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
		if retryAfter != 0 {
			t.Errorf("expected retryAfter 0, got %v", retryAfter)
		}
		clock.Advance(1 * time.Second)
	}

	// 4th request rejected
	allowed, retryAfter := limiter.Allow(key, limit, window)
	if allowed {
		t.Fatalf("request 4 should be rejected")
	}
	if retryAfter < 1*time.Second {
		t.Errorf("expected positive retryAfter >= 1s, got %v", retryAfter)
	}

	// Advance clock past window
	clock.Advance(15 * time.Second)

	// Next request should be allowed again
	allowed, retryAfter = limiter.Allow(key, limit, window)
	if !allowed {
		t.Fatalf("request after window expiry should be allowed")
	}
	if retryAfter != 0 {
		t.Errorf("expected retryAfter 0, got %v", retryAfter)
	}
}

func TestMemoryRateLimiter_BoundedMemory(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := &mockClock{now: start}
	maxCapacity := 10
	limiter := NewMemoryRateLimiter(maxCapacity, clock)

	// Insert 50 distinct keys
	for i := 0; i < 50; i++ {
		key := "key-" + string(rune('A'+i))
		limiter.Allow(key, 5, 1*time.Minute)
		clock.Advance(100 * time.Millisecond)
	}

	// Lock and check size
	limiter.mu.Lock()
	currentSize := len(limiter.buckets)
	limiter.mu.Unlock()

	if currentSize > maxCapacity {
		t.Errorf("rate limiter exceeded bounded capacity: %d > %d", currentSize, maxCapacity)
	}
}

func TestDeriveAccountRateLimitKey(t *testing.T) {
	secret := "rate-limiting-secret-key-32-chars-long!"
	rawEmail := "User.Name@Example.COM "

	derived1 := DeriveAccountRateLimitKey(secret, rawEmail)
	derived2 := DeriveAccountRateLimitKey(secret, "user.name@example.com")

	if derived1 != derived2 {
		t.Errorf("DeriveAccountRateLimitKey should normalize email canonical lowercase: %s != %s", derived1, derived2)
	}

	if strings.Contains(derived1, "user") || strings.Contains(derived1, "example.com") {
		t.Errorf("derived key must not contain plaintext email components: %s", derived1)
	}

	if !strings.HasPrefix(derived1, "acc:") {
		t.Errorf("expected 'acc:' prefix, got %s", derived1)
	}
}

func TestDeriveAccountIPRateLimitKey(t *testing.T) {
	secret := "rate-limiting-secret-key-32-chars-long!"
	rawEmail := "User.Name@Example.COM "
	ip := "  192.0.2.1 "

	key1 := DeriveAccountIPRateLimitKey(secret, rawEmail, ip)
	key2 := DeriveAccountIPRateLimitKey(secret, "user.name@example.com", "192.0.2.1")

	if key1 != key2 {
		t.Errorf("expected canonical lowercase email and trimmed ip to produce identical keys: %s != %s", key1, key2)
	}

	if strings.Contains(key1, "user") || strings.Contains(key1, "example.com") {
		t.Errorf("derived key must not contain plaintext email: %s", key1)
	}

	if !strings.HasPrefix(key1, "acc:") {
		t.Errorf("expected key to start with 'acc:', got %s", key1)
	}

	if !strings.Contains(key1, ":ip:192.0.2.1") {
		t.Errorf("expected key to contain ':ip:192.0.2.1', got %s", key1)
	}
}
