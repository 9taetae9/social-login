package logger

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Middleware 요청 로깅 미들웨어
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Request ID 생성
		requestID := SetRequestID(c)

		// 시작 시간
		start := time.Now()

		// 요청 정보 로깅
		slog.Info("Incoming request",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		)

		// 다음 핸들러 실행
		c.Next()

		// 응답 정보 로깅
		duration := time.Since(start)
		statusCode := c.Writer.Status()

		logAttrs := []any{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status_code", statusCode,
			"duration_ms", duration.Milliseconds(),
			"client_ip", c.ClientIP(),
		}

		// 상태 코드에 따라 로그 레벨 조정
		if statusCode >= 500 {
			slog.Error("Request completed with server error", logAttrs...)
		} else if statusCode >= 400 {
			slog.Warn("Request completed with client error", logAttrs...)
		} else {
			slog.Info("Request completed", logAttrs...)
		}
	}
}
