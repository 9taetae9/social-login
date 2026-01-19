package logger

import (
	"log/slog"
	"os"
)

// InitLogger slog 초기화
func InitLogger(level string, format string) {
	var logLevel slog.Level

	// 로그 레벨 파싱
	switch level {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler

	// 포맷에 따라 핸들러 선택
	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // 파일명과 라인 번호 추가
	}

	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		// Console (개발용)
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// SanitizeEmail 이메일 마스킹 (민감 정보 보호)
func SanitizeEmail(email string) string {
	if len(email) == 0 {
		return ""
	}

	at := 0
	for i, c := range email {
		if c == '@' {
			at = i
			break
		}
	}

	if at == 0 {
		return "***"
	}

	// example@domain.com -> ex***@domain.com
	if at > 2 {
		return email[:2] + "***" + email[at:]
	}
	return "***" + email[at:]
}

// SanitizePhone 전화번호 마스킹
func SanitizePhone(phone string) string {
	if len(phone) < 4 {
		return "***"
	}
	// 010-1234-5678 -> 010-****-5678
	// 01012345678 -> 010****5678
	if len(phone) <= 7 {
		return "***"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
