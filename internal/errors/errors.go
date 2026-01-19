package errors

import (
	"fmt"
)

// AppError 애플리케이션 에러의 기본 구조
type AppError struct {
	Code       string // 에러 코드 (AUTH_EMAIL_EXISTS 등)
	Message    string // 사용자에게 보여줄 메시지
	Err        error  // 원본 에러 (wrapping)
	StatusCode int    // HTTP 상태 코드
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// New 새로운 AppError 생성
func New(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// Wrap 기존 에러를 AppError로 래핑
func Wrap(err error, code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		StatusCode: statusCode,
	}
}

// NewValidationError 유효성 검증 에러
func NewValidationError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeValidation,
		Message:    message,
		StatusCode: 400,
	}
}

// NewAuthError 인증 에러
func NewAuthError(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: 401,
	}
}

// NewNotFoundError 리소스 없음 에러
func NewNotFoundError(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: 404,
	}
}

// NewConflictError 충돌 에러 (중복 등)
func NewConflictError(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: 409,
	}
}

// NewInternalError 내부 서버 에러
func NewInternalError(code, message string, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		StatusCode: 500,
	}
}
