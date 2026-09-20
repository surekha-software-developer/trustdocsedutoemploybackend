package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	// MaxPresignTTL defines the maximum allowed lifetime for a presigned download URL (5 minutes).
	MaxPresignTTL = 5 * time.Minute
)

// R2Storage implements ObjectStorage using AWS SDK v2 targeting Cloudflare R2.
type R2Storage struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	bucketName    string
	defaultTTL    time.Duration
}

// R2Config contains constructor parameters for R2Storage.
type R2Config struct {
	AccountID        string
	AccessKeyID      string
	SecretAccessKey  string
	BucketName       string
	ExplicitEndpoint string
	PresignTTL       time.Duration
}

// NewR2Storage constructs an R2Storage adapter without executing any network calls.
func NewR2Storage(cfg R2Config) (*R2Storage, error) {
	if strings.TrimSpace(cfg.BucketName) == "" {
		return nil, fmt.Errorf("%w: bucket name is required", ErrInvalidStorageInput)
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, fmt.Errorf("%w: storage credentials are required", ErrInvalidStorageInput)
	}

	var endpoint string
	if strings.TrimSpace(cfg.ExplicitEndpoint) != "" {
		endpoint = strings.TrimSpace(cfg.ExplicitEndpoint)
	} else if strings.TrimSpace(cfg.AccountID) != "" {
		endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", strings.TrimSpace(cfg.AccountID))
	} else {
		return nil, fmt.Errorf("%w: either account_id or explicit endpoint is required", ErrInvalidStorageInput)
	}

	if !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("%w: storage endpoint must use HTTPS", ErrInvalidStorageInput)
	}

	ttl := cfg.PresignTTL
	if ttl <= 0 || ttl > MaxPresignTTL {
		ttl = MaxPresignTTL
	}

	s3Client := s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       "auto",
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
	})

	presignClient := s3.NewPresignClient(s3Client)

	return &R2Storage{
		client:        s3Client,
		presignClient: presignClient,
		bucketName:    cfg.BucketName,
		defaultTTL:    ttl,
	}, nil
}

// PutObject streams a payload to Cloudflare R2 with content type and content length.
func (r *R2Storage) PutObject(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("%w: key is required", ErrInvalidStorageInput)
	}

	input := &s3.PutObjectInput{
		Bucket:        aws.String(r.bucketName),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	}

	_, err := r.client.PutObject(ctx, input)
	if err != nil {
		return r.classifyError(err)
	}
	return nil
}

// GetObject retrieves an object stream from Cloudflare R2. Caller must close the returned ReadCloser.
func (r *R2Storage) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("%w: key is required", ErrInvalidStorageInput)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(r.bucketName),
		Key:    aws.String(key),
	}

	resp, err := r.client.GetObject(ctx, input)
	if err != nil {
		return nil, r.classifyError(err)
	}

	return resp.Body, nil
}

// DeleteObject deletes an object idempotently. Missing objects are treated as success.
func (r *R2Storage) DeleteObject(ctx context.Context, key string) error {
	if strings.TrimSpace(key) == "" {
		return nil // idempotent no-op on empty key
	}

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(r.bucketName),
		Key:    aws.String(key),
	}

	_, err := r.client.DeleteObject(ctx, input)
	if err != nil {
		classified := r.classifyError(err)
		if errors.Is(classified, ErrObjectNotFound) {
			return nil
		}
		return classified
	}
	return nil
}

// GeneratePresignedURL creates a presigned GET URL valid up to 5 minutes.
func (r *R2Storage) GeneratePresignedURL(ctx context.Context, key string, lifetime time.Duration) (string, error) {
	if strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("%w: key is required", ErrInvalidStorageInput)
	}

	if lifetime <= 0 || lifetime > MaxPresignTTL {
		lifetime = r.defaultTTL
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(r.bucketName),
		Key:    aws.String(key),
	}

	presignedReq, err := r.presignClient.PresignGetObject(ctx, input, s3.WithPresignExpires(lifetime))
	if err != nil {
		return "", r.classifyError(err)
	}

	return presignedReq.URL, nil
}

func (r *R2Storage) classifyError(err error) error {
	if err == nil {
		return nil
	}

	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return ErrObjectNotFound
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return ErrObjectNotFound
		}
	}

	// Mask underlying driver/connection error
	return ErrStorageUnavailable
}
