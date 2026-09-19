package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Clock defines a time provider interface for deterministic testing.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// RateLimiter defines the interface for rate limiting actions.
// Documented limitation: this is an in-memory, per-process rate limiter.
// In a distributed multi-instance deployment, a centralized store (e.g. Redis) is required.
type RateLimiter interface {
	Allow(key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration)
}

// MemoryRateLimiter implements an in-memory sliding-window rate limiter with:
// - bounded memory capacity
// - opportunistic cleanup of expired entries
// - oldest-entry eviction under capacity saturation
// - zero background goroutine requirement to avoid test leaks
type MemoryRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string][]time.Time
	lastAccess map[string]time.Time
	maxEntries int
	clock      Clock
}

// NewMemoryRateLimiter creates a thread-safe in-memory rate limiter with bounded memory.
func NewMemoryRateLimiter(maxEntries int, clock Clock) *MemoryRateLimiter {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if clock == nil {
		clock = realClock{}
	}
	return &MemoryRateLimiter{
		buckets:    make(map[string][]time.Time),
		lastAccess: make(map[string]time.Time),
		maxEntries: maxEntries,
		clock:      clock,
	}
}

// Allow checks if the given key is permitted within the sliding window.
// If allowed, it records the current timestamp and returns allowed=true, retryAfter=0.
// If rate limited, it returns allowed=false and the duration until the oldest request expires.
func (r *MemoryRateLimiter) Allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock.Now()
	cutoff := now.Add(-window)

	// Opportunistic prune if map is approaching limit
	if len(r.buckets) >= r.maxEntries {
		r.pruneExpiredLocked(now, window)
		// If still at capacity and key does not exist, evict the least recently used key
		if len(r.buckets) >= r.maxEntries {
			if _, exists := r.buckets[key]; !exists {
				r.evictOldestLocked()
			}
		}
	}

	timestamps := r.buckets[key]
	// Filter timestamps within sliding window
	validTimestamps := make([]time.Time, 0, len(timestamps))
	for _, t := range timestamps {
		if t.After(cutoff) {
			validTimestamps = append(validTimestamps, t)
		}
	}

	if len(validTimestamps) < limit {
		validTimestamps = append(validTimestamps, now)
		r.buckets[key] = validTimestamps
		r.lastAccess[key] = now
		return true, 0
	}

	// Update valid timestamps even when rejecting
	r.buckets[key] = validTimestamps
	r.lastAccess[key] = now

	// Calculate retryAfter based on the oldest timestamp in the active window
	oldest := validTimestamps[0]
	retryAfter := oldest.Add(window).Sub(now)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}

	return false, retryAfter
}

// pruneExpiredLocked removes all expired keys from the in-memory store.
func (r *MemoryRateLimiter) pruneExpiredLocked(now time.Time, defaultWindow time.Duration) {
	for k, timestamps := range r.buckets {
		var active []time.Time
		for _, t := range timestamps {
			if now.Sub(t) <= defaultWindow {
				active = append(active, t)
			}
		}
		if len(active) == 0 {
			delete(r.buckets, k)
			delete(r.lastAccess, k)
		} else {
			r.buckets[k] = active
		}
	}
}

// evictOldestLocked removes the least recently accessed key to enforce bounded memory under attack.
func (r *MemoryRateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, t := range r.lastAccess {
		if first || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
			first = false
		}
	}

	if oldestKey != "" {
		delete(r.buckets, oldestKey)
		delete(r.lastAccess, oldestKey)
	}
}

const rateLimitDomainPrefix = "rate-limit:v1:"

// DeriveAccountRateLimitKey computes an opaque HMAC digest for an account key with explicit domain separation
// ("rate-limit:v1:") to prevent cross-protocol collision with CSRF tokens or other HMAC usage and avoid storing
// or logging plaintext email addresses in memory.
func DeriveAccountRateLimitKey(secret string, email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(rateLimitDomainPrefix + normalized))
	return "acc:" + hex.EncodeToString(mac.Sum(nil))
}

// DeriveIPRateLimitKey formats an IP address key.
func DeriveIPRateLimitKey(ip string) string {
	return "ip:" + strings.TrimSpace(ip)
}

// DeriveAccountIPRateLimitKey computes an opaque compound key for per-account-per-IP login rate limiting.
// Combines the domain-separated HMAC digest of the canonical email with the client IP to protect against
// brute-force attacks without enabling denial-of-service lockout against legitimate users from other IPs.
func DeriveAccountIPRateLimitKey(secret string, email string, ip string) string {
	return DeriveAccountRateLimitKey(secret, email) + ":" + DeriveIPRateLimitKey(ip)
}
