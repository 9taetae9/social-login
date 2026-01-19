package errors

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse HTTP 에러 응답 구조
type ErrorResponse struct {
	Error       string `json:"error"`                  // 사용자 메시지
	Code        string `json:"code,omitempty"`         // 에러 코드
	LinkToken   string `json:"link_token,omitempty"`   // 소셜 연동 토큰
	Email       string `json:"email,omitempty"`        // 이메일 (소셜 연동 검증용)
	Provider    string `json:"provider,omitempty"`     // 소셜 제공자
	EmailSent   *bool  `json:"email_sent,omitempty"`   // 이메일 발송 여부
	HasPassword *bool  `json:"has_password,omitempty"` // 비밀번호 존재 여부
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

		response := ErrorResponse{
			Error: appErr.Message,
			Code:  appErr.Code,
		}

		// Data 필드가 있으면 응답에 포함
		if appErr.Data != nil {
			if linkToken, ok := appErr.Data["link_token"].(string); ok {
				response.LinkToken = linkToken
			}
			if email, ok := appErr.Data["email"].(string); ok {
				response.Email = email
			}
			if provider, ok := appErr.Data["provider"].(string); ok {
				response.Provider = provider
			}
			if emailSent, ok := appErr.Data["email_sent"].(bool); ok {
				response.EmailSent = &emailSent
			}
			if hasPassword, ok := appErr.Data["has_password"].(bool); ok {
				response.HasPassword = &hasPassword
			}
		}

		c.JSON(appErr.StatusCode, response)
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
