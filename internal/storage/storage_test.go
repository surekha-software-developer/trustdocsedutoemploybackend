package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestMockStorage_BasicOperations(t *testing.T) {
	ctx := context.Background()
	mock := NewMockStorage()

	key := "test/sample.pdf"
	content := []byte("%PDF-1.4 sample test bytes")

	// 1. PutObject
	err := mock.PutObject(ctx, key, bytes.NewReader(content), int64(len(content)), "application/pdf")
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	if !mock.HasObject(key) {
		t.Fatalf("expected object to exist in mock storage")
	}

	// 2. GetObject
	rc, err := mock.GetObject(ctx, key)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer rc.Close()

	readData, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading body failed: %v", err)
	}
	if !bytes.Equal(readData, content) {
		t.Fatalf("content mismatch: got %q, want %q", readData, content)
	}

	// 3. GeneratePresignedURL
	url, err := mock.GeneratePresignedURL(ctx, key, 5*time.Minute)
	if err != nil {
		t.Fatalf("GeneratePresignedURL failed: %v", err)
	}
	if url == "" {
		t.Fatalf("expected non-empty presigned URL")
	}

	// 4. DeleteObject
	err = mock.DeleteObject(ctx, key)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if mock.HasObject(key) {
		t.Fatalf("expected object to be deleted")
	}

	// 5. Idempotent delete for already deleted object
	err = mock.DeleteObject(ctx, key)
	if err != nil {
		t.Fatalf("idempotent DeleteObject returned error: %v", err)
	}

	// 6. Get non-existent object
	_, err = mock.GetObject(ctx, key)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestMockStorage_Concurrency(t *testing.T) {
	ctx := context.Background()
	mock := NewMockStorage()

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("tenant/worker-%d/doc-%d.pdf", workerID, i)
				payload := []byte(fmt.Sprintf("content from worker %d iteration %d", workerID, i))

				// Put
				if err := mock.PutObject(ctx, key, bytes.NewReader(payload), int64(len(payload)), "application/pdf"); err != nil {
					t.Errorf("worker %d PutObject failed: %v", workerID, err)
					return
				}

				// Get
				rc, err := mock.GetObject(ctx, key)
				if err != nil {
					t.Errorf("worker %d GetObject failed: %v", workerID, err)
					return
				}
				data, _ := io.ReadAll(rc)
				rc.Close()
				if !bytes.Equal(data, payload) {
					t.Errorf("worker %d content mismatch", workerID)
					return
				}

				// Presign
				_, err = mock.GeneratePresignedURL(ctx, key, 2*time.Minute)
				if err != nil {
					t.Errorf("worker %d presign failed: %v", workerID, err)
					return
				}

				// Delete
				if err := mock.DeleteObject(ctx, key); err != nil {
					t.Errorf("worker %d delete failed: %v", workerID, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()
}

func TestR2Storage_ConstructorValidation(t *testing.T) {
	// 1. Missing bucket
	_, err := NewR2Storage(R2Config{
		AccountID:       "acc123",
		AccessKeyID:     "key123",
		SecretAccessKey: "sec123",
	})
	if err == nil {
		t.Fatalf("expected error for missing bucket name, got nil")
	}

	// 2. Missing credentials
	_, err = NewR2Storage(R2Config{
		BucketName: "cert-bucket",
		AccountID:  "acc123",
	})
	if err == nil {
		t.Fatalf("expected error for missing credentials, got nil")
	}

	// 3. Missing endpoint and account ID
	_, err = NewR2Storage(R2Config{
		BucketName:      "cert-bucket",
		AccessKeyID:     "key123",
		SecretAccessKey: "sec123",
	})
	if err == nil {
		t.Fatalf("expected error for missing endpoint/account ID, got nil")
	}

	// 4. Non-HTTPS endpoint
	_, err = NewR2Storage(R2Config{
		BucketName:       "cert-bucket",
		AccessKeyID:      "key123",
		SecretAccessKey:  "sec123",
		ExplicitEndpoint: "http://insecure-endpoint.local",
	})
	if err == nil {
		t.Fatalf("expected error for HTTP endpoint, got nil")
	}

	// 5. Valid config constructs client with zero network call
	storageClient, err := NewR2Storage(R2Config{
		BucketName:      "cert-bucket",
		AccessKeyID:     "key123",
		SecretAccessKey: "sec123",
		AccountID:       "0123456789abcdef0123456789abcdef",
		PresignTTL:      3 * time.Minute,
	})
	if err != nil {
		t.Fatalf("expected valid construction without network call, got: %v", err)
	}
	if storageClient == nil {
		t.Fatalf("expected non-nil storage client")
	}
}
