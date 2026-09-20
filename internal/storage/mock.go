package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// MockStorage is an in-memory, thread-safe implementation of ObjectStorage intended ONLY for tests.
// It must never be used in production or as an automatic fallback.
type MockStorage struct {
	mu      sync.RWMutex
	objects map[string][]byte

	// Configurable failure hooks for simulating transient failures in unit tests
	FailPut     error
	FailGet     error
	FailDelete  error
	FailPresign error

	// Call counters for assertion
	PutCount     int
	GetCount     int
	DeleteCount  int
	PresignCount int
}

// NewMockStorage constructs an empty, concurrency-safe in-memory MockStorage.
func NewMockStorage() *MockStorage {
	return &MockStorage{
		objects: make(map[string][]byte),
	}
}

// PutObject stores the stream in memory.
func (m *MockStorage) PutObject(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PutCount++

	if m.FailPut != nil {
		return m.FailPut
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("%w: failed to read body", ErrInvalidStorageInput)
	}

	m.objects[key] = data
	return nil
}

// GetObject returns an in-memory ReadCloser for the object data.
func (m *MockStorage) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.GetCount++

	if m.FailGet != nil {
		return nil, m.FailGet
	}

	data, ok := m.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

// DeleteObject removes the key from the in-memory map idempotently.
func (m *MockStorage) DeleteObject(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeleteCount++

	if m.FailDelete != nil {
		return m.FailDelete
	}

	delete(m.objects, key)
	return nil
}

// GeneratePresignedURL returns a deterministic simulated presigned URL for testing.
func (m *MockStorage) GeneratePresignedURL(ctx context.Context, key string, lifetime time.Duration) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.PresignCount++

	if m.FailPresign != nil {
		return "", m.FailPresign
	}

	if _, ok := m.objects[key]; !ok {
		return "", ErrObjectNotFound
	}

	return fmt.Sprintf("https://mock-r2.local/download/%s?expires=%d", key, time.Now().Add(lifetime).Unix()), nil
}

// HasObject helper for test assertions.
func (m *MockStorage) HasObject(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.objects[key]
	return ok
}

// GetObjectBytes helper for test assertions.
func (m *MockStorage) GetObjectBytes(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.objects[key]
	return data, ok
}
