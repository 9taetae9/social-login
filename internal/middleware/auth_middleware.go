package middleware

import (
	"log/slog"
	"strings"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/errors"
	"github.com/9taetae9/social-login/internal/logger"
	"github.com/9taetae9/social-login/internal/utils"
	"github.com/gin-gonic/gin"
)

// JWT 인증 미들웨어
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := logger.GetRequestID(c)

		// Authorization 헤더 가져오기
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			slog.Warn("Missing authorization header", "request_id", requestID)
			errors.HandleError(c, errors.NewAuthError(errors.ErrCodeAuthFailed,
				"Authorization header is required"))
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			slog.Warn("Invalid authorization header format", "request_id", requestID)
			errors.HandleError(c, errors.NewAuthError(errors.ErrCodeAuthFailed,
				"Invalid authorization header format"))
			c.Abort()
			return
		}

		token := parts[1]

		// 토큰 검증
		claims, err := utils.ValidateToken(token, cfg.JWT.Secret)
		if err != nil {
			slog.Warn("Invalid or expired token",
				"request_id", requestID,
				"error", err,
			)
			errors.HandleError(c, errors.NewAuthError(errors.ErrCodeInvalidToken,
				"Invalid or expired token"))
			c.Abort()
			return
		}

		slog.Debug("Token validated",
			"request_id", requestID,
			"user_id", claims.UserID,
		)

		// 컨텍스트에 사용자 정보 저장
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)

		c.Next()
	}
}
