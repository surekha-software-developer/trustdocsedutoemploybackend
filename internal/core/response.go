package core

import (
	"github.com/gin-gonic/gin"
)

// SuccessResponse defines the standard structure for successful API responses.
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

// ErrorResponse defines the standard structure for error API responses.
type ErrorResponse struct {
	Success bool      `json:"success"`
	Error   *AppError `json:"error"`
}

// SendSuccess formats and sends a standard JSON success response.
func SendSuccess(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, SuccessResponse{
		Success: true,
		Data:    data,
	})
}

// SendError formats and sends a standard JSON error response.
func SendError(c *gin.Context, statusCode int, code, message string, details ...interface{}) {
	err := NewAppError(code, message, details...)
	c.JSON(statusCode, ErrorResponse{
		Success: false,
		Error:   err,
	})
}
