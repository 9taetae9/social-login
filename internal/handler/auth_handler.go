package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// 인증 핸들러
type AuthHandler struct {
	authService service.AuthService
	validate    *validator.Validate
	cfg			*config.Config // 설정을 직접 저장
}

// 핸들러 생성자
func NewAuthHandler(authService service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validate:    validator.New(),
		cfg:		 cfg, //주입받은 설정을 저장
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

// 구글 유저 정보 파싱용 구조체
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
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

// Google 로그인 페이지로 리다이렉트
func (h *AuthHandler) GoogleLogin(c *gin.Context){
	googleOauthConfig := &oauth2.Config{
		ClientID: h.cfg.Oauth.GoogleClientID,
		ClientSecret: h.cfg.Oauth.GoogleClientSecret,
		RedirectURL: h.cfg.Oauth.GoogleRedirectURL,
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint: google.Endpoint,
	}

	//CSRF 방지용 State 값 (실무에서는 랜덤 문자열 생성)
	state := "random-state-string"

	// 구글 로그인 URL 생성
	url := googleOauthConfig.AuthCodeURL(state)

	// 사용자를 구글로 리다이렉트
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Google 콜백 처리
func (h *AuthHandler) GoogleCallback(c *gin.Context){
	// 구글에서 보내준 code 받기
	code := c.Query("code")
	if code == ""{
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Authorization code not found"})
		return
	}

	// OAuth 설정 구성
	googleOauthConfig := &oauth2.Config{
		ClientID: h.cfg.Oauth.GoogleClientID,
		ClientSecret: h.cfg.Oauth.GoogleClientSecret,
		RedirectURL: h.cfg.Oauth.GoogleRedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	// Code -> Google Token 교환
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil{
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}

	// Google Token으로 유저 정보 조회
	client := googleOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil{
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to get user info from Google"})
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil{
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to read response body"})
		return
	}

	var googleUser GoogleUserInfo
	if err := json.Unmarshal(data, &googleUser); err != nil{
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to parse user info"})
		return
	}

	// Service 계층의 SocialLogin 호출
	authResponse, err := h.authService.SocialLogin(googleUser.Email, "google", googleUser.ID)
	if err != nil{
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}	

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Google login successful",
		Data: authResponse,
	})
}


// 토큰 갱신 핸들러
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenReqeust
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Token refresed successfully",
		Data:    response,
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
