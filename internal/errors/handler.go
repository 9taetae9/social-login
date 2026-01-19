package errors

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse HTTP 에러 응답 구조
type ErrorResponse struct {
	Error string `json:"error"`          // 사용자 메시지
	Code  string `json:"code,omitempty"` // 에러 코드
}

// HandleError 에러를 HTTP 응답으로 변환
func HandleError(c *gin.Context, err error) {
	// AppError로 캐스팅 시도
	if appErr, ok := err.(*AppError); ok {
		// 구조화된 로깅
		logger := slog.With(
			"error_code", appErr.Code,
			"status_code", appErr.StatusCode,
		)

		// Request ID가 있으면 추가
		if reqID, exists := c.Get("request_id"); exists {
			logger = logger.With("request_id", reqID)
		}

		// 5xx 에러는 ERROR 레벨, 4xx는 WARN 레벨
		if appErr.StatusCode >= 500 {
			logger.Error(appErr.Message, "error", appErr.Err)
		} else {
			logger.Warn(appErr.Message, "error", appErr.Err)
		}

		c.JSON(appErr.StatusCode, ErrorResponse{
			Error: appErr.Message,
			Code:  appErr.Code,
		})
		return
	}

	// 일반 에러는 Internal Server Error로 처리
	slog.Error("Unhandled error", "error", err)
	c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error: "Internal server error",
		Code:  ErrCodeInternal,
	})
}

// HandleSuccess 성공 응답 헬퍼
func HandleSuccess(c *gin.Context, statusCode int, message string, data interface{}) {
	response := gin.H{
		"message": message,
	}
	if data != nil {
		response["data"] = data
	}
	c.JSON(statusCode, response)
}
