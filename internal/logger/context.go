package logger

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDKey = "request_id"

// GetRequestID 컨텍스트에서 Request ID 가져오기
func GetRequestID(c *gin.Context) string {
	if reqID, exists := c.Get(RequestIDKey); exists {
		return reqID.(string)
	}
	return ""
}

// SetRequestID Request ID 설정
func SetRequestID(c *gin.Context) string {
	reqID := uuid.New().String()
	c.Set(RequestIDKey, reqID)
	return reqID
}
