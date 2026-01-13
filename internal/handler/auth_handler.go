package handler

import (
	"net/http"

	"github.com/9taetae9/social-login/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// 인증 핸들러
type AuthHandler struct {
	authService service.AuthService
	validate    *validator.Validate
}

// 핸들러 생성자
func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validate:    validator.New(),
	}
}

// 회원가입 요청 구조체
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// 로그인 요청 구조체
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// 토큰 갱신 요청 구조체
type RefreshTokenReqeust struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// 로그아웃 요청 구조체
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// 인증 이메일 재발송 요청 구조체
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ErrorResponse 에러 응답 구조체
type ErrorResponse struct {
	Error string `json:"error"`
}

// 성공 응답 구조체
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 회원가입 핸들러
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	//유효성 검증
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// 회원가입 처리
	response, err := h.authService.Register(req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// RegisterResponse 그대로 반환
	c.JSON(http.StatusCreated, response)
}

// 로그인 핸들러
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// 로그인 처리
	response, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data:    response,
	})
}

// 토큰 갱신 핸들러
func (h *AuthHandler) RefreshToken(c *gin.Context){
	var req RefreshTokenReqeust
	if err := c.ShouldBindJSON(&req); err != nil{
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil{
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil{
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Token refresed successfully",
		Data: response,
	})
}

// 로그아웃 핸들러
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// 로그아웃 처리
	if err := h.authService.Logout(req.RefreshToken); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Logout successful",
	})
}

// VerifyEmail 이메일 인증 핸들러
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Verification token is required"})
		return
	}

	// 이메일 인증 처리
	if err := h.authService.VerifyEmail(token); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Email verified successfully",
	})
}

func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// 인증 이메일 재발송 처리
	if err := h.authService.ResendVerificationEmail(req.Email); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Verification email sent successfully",
	})
}
