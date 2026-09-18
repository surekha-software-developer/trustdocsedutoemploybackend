package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSendSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	testData := map[string]string{"key": "value"}
	SendSuccess(c, http.StatusOK, testData)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp SuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success to be true, got false")
	}

	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok || dataMap["key"] != "value" {
		t.Errorf("unexpected data content: %v", resp.Data)
	}
}

func TestSendError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	SendError(c, http.StatusBadRequest, ErrCodeBadRequest, "Invalid input data")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success to be false, got true")
	}
	if resp.Error == nil {
		t.Fatalf("expected Error object, got nil")
	}
	if resp.Error.Code != ErrCodeBadRequest {
		t.Errorf("expected code '%s', got '%s'", ErrCodeBadRequest, resp.Error.Code)
	}
	if resp.Error.Message != "Invalid input data" {
		t.Errorf("expected message 'Invalid input data', got '%s'", resp.Error.Message)
	}
}
