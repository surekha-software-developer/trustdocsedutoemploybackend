package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	// ErrObjectNotFound is returned when the specified key does not exist in object storage.
	ErrObjectNotFound = errors.New("storage object not found")
	// ErrStorageUnavailable indicates a network or connectivity issue communicating with object storage.
	ErrStorageUnavailable = errors.New("object storage service unavailable")
	// ErrInvalidStorageInput indicates malformed or illegal input provided to storage operations.
	ErrInvalidStorageInput = errors.New("invalid storage input")
)

// ObjectStorage defines the unified abstraction for document and certificate blob storage.
type ObjectStorage interface {
	// PutObject streams an object to storage with bounded size and content type.
	PutObject(ctx context.Context, key string, body io.Reader, size int64, contentType string) error

	// GetObject fetches an object stream. Caller is responsible for closing ReadCloser.
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)

	// DeleteObject deletes an object. Idempotent: must not return error if object does not exist.
	DeleteObject(ctx context.Context, key string) error

	// GeneratePresignedURL creates a short-lived presigned GET URL (maximum 5 minutes).
	GeneratePresignedURL(ctx context.Context, key string, lifetime time.Duration) (string, error)
}
