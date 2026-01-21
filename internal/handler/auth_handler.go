package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/errors"
	"github.com/9taetae9/social-login/internal/logger"
	"github.com/9taetae9/social-login/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// 인증 핸들러
type AuthHandler struct {
	authService service.AuthService
	validate    *validator.Validate
	cfg         *config.Config // 설정을 직접 저장
}

// 핸들러 생성자
func NewAuthHandler(authService service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validate:    validator.New(),
		cfg:         cfg, //주입받은 설정을 저장
	}
}

// 회원가입 요청 구조체
type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	UserType    string `json:"user_type" validate:"required,oneof=KOREAN FOREIGNER"`
	PhoneNumber string `json:"phone_number"` // 한국인의 경우 필수
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

// 소셜 연동 확인 요청 구조체
type ConfirmSocialLinkRequest struct {
	LinkToken string `json:"link_token" validate:"required"`
	Password  string `json:"password" validate:"required"`
}

// 일반 회원 전환 요청 구조체
type ConvertToEmailRequest struct {
	Provider    string `json:"provider" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
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

// OpenID Connect ID Token Claims 구조체 (Google/Naver/Kakao 공통)
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // bool 또는 string일 수 있음
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Nickname      string `json:"nickname"` // Kakao용
}

// parseIDToken JWT id_token을 파싱하여 claims 반환 (서명 검증 없이)
// 참고: HTTPS를 통한 token exchange에서 직접 받은 토큰이므로 서명 검증 생략 가능
func parseIDToken(idToken string) (*IDTokenClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(idToken, &IDTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse id_token: %w", err)
	}

	claims, ok := token.Claims.(*IDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid id_token claims")
	}

	return claims, nil
}

// 구글 유저 정보 파싱용 구조체 (fallback용)
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// 네이버 유저 정보 파싱용 구조체
type NaverUserInfo struct {
	ResultCode string `json:"resultcode"`
	Message    string `json:"message"`
	Response   struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"response"`
}

// 카카오 유저 정보 파싱용 구조체
type KakaoUserInfo struct {
	ID           int64 `json:"id"`
	KakaoAccount struct {
		Email   string `json:"email"`
		Profile struct {
			Nickname string `json:"nickname"`
		} `json:"profile"`
	} `json:"kakao_account"`
}

// 회원가입 핸들러
func (h *AuthHandler) Register(c *gin.Context) {
	requestID := logger.GetRequestID(c)

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Warn("Invalid request body",
			"request_id", requestID,
			"error", err,
		)
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	//유효성 검증
	if err := h.validate.Struct(req); err != nil {
		slog.Warn("Validation failed",
			"request_id", requestID,
			"error", err,
		)
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	if req.UserType == "KOREAN" && req.PhoneNumber == "" {
		errors.HandleError(c, errors.New(errors.ErrCodePhoneRequired,
			"Phone number is required for Korean users", 400))
		return
	}

	// 회원가입 처리
	response, err := h.authService.Register(req.Email, req.Password, req.UserType, req.PhoneNumber)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	// RegisterResponse 그대로 반환
	c.JSON(http.StatusCreated, response)
}

// 로그인 핸들러
func (h *AuthHandler) Login(c *gin.Context) {
	requestID := logger.GetRequestID(c)

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Warn("Invalid request body",
			"request_id", requestID,
			"error", err,
		)
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		slog.Warn("Validation failed",
			"request_id", requestID,
			"error", err,
		)
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	// 로그인 처리
	response, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data:    response,
	})
}

// Google 로그인 페이지로 리다이렉트
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	googleOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.GoogleClientID,
		ClientSecret: h.cfg.Oauth.GoogleClientSecret,
		RedirectURL:  h.cfg.Oauth.GoogleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// CSRF 방지용 랜덤 State 값 생성
	state, err := generateRandomState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate state"})
		return
	}

	// State를 쿠키에 저장 (CSRF 공격 방지)
	c.SetCookie(
		"oauth_state", // name
		state,         // value
		300,           // maxAge (5분)
		"/",           // path
		"",            // domain
		false,         // secure (production에서는 true)
		true,          // httpOnly
	)

	// 구글 로그인 URL 생성
	url := googleOauthConfig.AuthCodeURL(state)

	// 사용자를 구글로 리다이렉트
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Google 콜백 처리
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	// State 파라미터 검증 (CSRF 방지)
	state := c.Query("state")
	savedState, err := c.Cookie("oauth_state")
	if err != nil || state == "" || state != savedState {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid state parameter"})
		return
	}

	// State 쿠키 삭제 (일회용)
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// 구글에서 보내준 code 받기
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Authorization code not found"})
		return
	}

	// OAuth 설정 구성
	googleOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.GoogleClientID,
		ClientSecret: h.cfg.Oauth.GoogleClientSecret,
		RedirectURL:  h.cfg.Oauth.GoogleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// Code -> Google Token 교환 (id_token 포함)
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}

	// id_token에서 유저 정보 추출 (추가 API 호출 불필요)
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "id_token not found in response"})
		return
	}

	claims, err := parseIDToken(idTokenRaw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to parse id_token"})
		return
	}

	// sub (subject)가 Google 유저 고유 ID
	googleID := claims.Subject

	// Service 계층의 SocialLogin 호출
	authResponse, err := h.authService.SocialLogin(claims.Email, "google", googleID)
	if err != nil {
		h.sendSocialCallbackResponse(c, "google", nil, err)
		return
	}

	h.sendSocialCallbackResponse(c, "google", authResponse, nil)
}

// Naver 로그인 페이지로 리다이렉트
func (h *AuthHandler) NaverLogin(c *gin.Context) {
	// 네이버 OAuth2 Endpoint 정의
	naverEndpoint := oauth2.Endpoint{
		AuthURL:  "https://nid.naver.com/oauth2.0/authorize",
		TokenURL: "https://nid.naver.com/oauth2.0/token",
	}

	naverOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.NaverClientID,
		ClientSecret: h.cfg.Oauth.NaverClientSecret,
		RedirectURL:  h.cfg.Oauth.NaverRedirectURL,
		Endpoint:     naverEndpoint,
	}

	// CSRF 방지용 랜덤 State 값 생성
	state, err := generateRandomState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate state"})
		return
	}

	// State를 쿠키에 저장 (CSRF 공격 방지)
	c.SetCookie(
		"oauth_state",
		state,
		300,
		"/",
		"",
		false,
		true,
	)

	// 네이버 로그인 URL 생성
	url := naverOauthConfig.AuthCodeURL(state)

	// 사용자를 네이버로 리다이렉트
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Naver 콜백 처리
func (h *AuthHandler) NaverCallback(c *gin.Context) {
	// State 파라미터 검증 (CSRF 방지)
	state := c.Query("state")
	savedState, err := c.Cookie("oauth_state")
	if err != nil || state == "" || state != savedState {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid state parameter"})
		return
	}

	// State 쿠키 삭제 (일회용)
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// 네이버에서 보내준 code 받기
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Authorization code not found"})
		return
	}

	// 네이버 OAuth2 Endpoint 정의
	naverEndpoint := oauth2.Endpoint{
		AuthURL:  "https://nid.naver.com/oauth2.0/authorize",
		TokenURL: "https://nid.naver.com/oauth2.0/token",
	}

	naverOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.NaverClientID,
		ClientSecret: h.cfg.Oauth.NaverClientSecret,
		RedirectURL:  h.cfg.Oauth.NaverRedirectURL,
		Endpoint:     naverEndpoint,
	}

	// Code -> Naver Token 교환
	token, err := naverOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}

	// Naver Token으로 유저 정보 조회
	client := naverOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://openapi.naver.com/v1/nid/me")
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to get user info from Naver"})
		return
	}
	defer resp.Body.Close()

	var naverUser NaverUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&naverUser); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to parse user info"})
		return
	}

	// 네이버 API 응답 성공 여부 확인
	if naverUser.ResultCode != "00" {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to get user info from Naver"})
		return
	}

	// Service 계층의 SocialLogin 호출
	authResponse, err := h.authService.SocialLogin(naverUser.Response.Email, "naver", naverUser.Response.ID)
	if err != nil {
		h.sendSocialCallbackResponse(c, "naver", nil, err)
		return
	}

	h.sendSocialCallbackResponse(c, "naver", authResponse, nil)
}

// Kakao 로그인 페이지로 리다이렉트
func (h *AuthHandler) KakaoLogin(c *gin.Context) {
	// 카카오 OAuth2 Endpoint 정의
	kakaoEndpoint := oauth2.Endpoint{
		AuthURL:  "https://kauth.kakao.com/oauth/authorize",
		TokenURL: "https://kauth.kakao.com/oauth/token",
	}

	kakaoOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.KakaoClientID,
		ClientSecret: h.cfg.Oauth.KakaoClientSecret,
		RedirectURL:  h.cfg.Oauth.KakaoRedirectURL,
		Scopes:       []string{"openid", "account_email"},
		Endpoint:     kakaoEndpoint,
	}

	// CSRF 방지용 랜덤 State 값 생성
	state, err := generateRandomState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate state"})
		return
	}

	// State를 쿠키에 저장 (CSRF 공격 방지)
	c.SetCookie(
		"oauth_state",
		state,
		300,
		"/",
		"",
		false,
		true,
	)

	// 카카오 로그인 URL 생성
	url := kakaoOauthConfig.AuthCodeURL(state)

	// 사용자를 카카오로 리다이렉트
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Kakao 콜백 처리
func (h *AuthHandler) KakaoCallback(c *gin.Context) {
	// State 파라미터 검증 (CSRF 방지)
	state := c.Query("state")
	savedState, err := c.Cookie("oauth_state")
	if err != nil || state == "" || state != savedState {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid state parameter"})
		return
	}

	// State 쿠키 삭제 (일회용)
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// 카카오에서 보내준 code 받기
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Authorization code not found"})
		return
	}

	// 카카오 OAuth2 Endpoint 정의
	kakaoEndpoint := oauth2.Endpoint{
		AuthURL:  "https://kauth.kakao.com/oauth/authorize",
		TokenURL: "https://kauth.kakao.com/oauth/token",
	}

	kakaoOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.Oauth.KakaoClientID,
		ClientSecret: h.cfg.Oauth.KakaoClientSecret,
		RedirectURL:  h.cfg.Oauth.KakaoRedirectURL,
		Scopes:       []string{"openid", "account_email"},
		Endpoint:     kakaoEndpoint,
	}

	// Code -> Kakao Token 교환 (id_token 포함)
	token, err := kakaoOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}

	// id_token에서 유저 정보 추출 (추가 API 호출 불필요)
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "id_token not found in response"})
		return
	}

	claims, err := parseIDToken(idTokenRaw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to parse id_token"})
		return
	}

	// sub (subject)가 Kakao 유저 고유 ID
	kakaoID := claims.Subject

	// Service 계층의 SocialLogin 호출
	authResponse, err := h.authService.SocialLogin(claims.Email, "kakao", kakaoID)
	if err != nil {
		h.sendSocialCallbackResponse(c, "kakao", nil, err)
		return
	}

	h.sendSocialCallbackResponse(c, "kakao", authResponse, nil)
}

// sendSocialCallbackResponse 소셜 로그인 콜백 응답을 HTML로 반환 (postMessage 사용)
func (h *AuthHandler) sendSocialCallbackResponse(c *gin.Context, provider string, authResponse interface{}, err error) {
	var jsonData string
	var statusCode int

	if err != nil {
		// 에러 응답 생성
		statusCode = http.StatusOK // HTML 페이지는 항상 200으로 반환

		// AppError인 경우 상세 데이터 포함
		if appErr, ok := err.(*errors.AppError); ok {
			if appErr.Data != nil {
				// 소셜 연동 필요 응답 (409) - code 필드 포함
				responseData := make(map[string]interface{})
				for k, v := range appErr.Data {
					responseData[k] = v
				}
				responseData["code"] = appErr.Code
				responseData["message"] = appErr.Message
				dataBytes, _ := json.Marshal(responseData)
				jsonData = string(dataBytes)
			} else {
				errResp := map[string]interface{}{
					"error":  appErr.Message,
					"code":   appErr.Code,
					"status": appErr.StatusCode,
				}
				dataBytes, _ := json.Marshal(errResp)
				jsonData = string(dataBytes)
			}
		} else {
			errResp := map[string]interface{}{
				"error": err.Error(),
			}
			dataBytes, _ := json.Marshal(errResp)
			jsonData = string(dataBytes)
		}
	} else {
		// 성공 응답 생성
		statusCode = http.StatusOK
		successResp := SuccessResponse{
			Message: fmt.Sprintf("%s login successful", provider),
			Data:    authResponse,
		}
		dataBytes, _ := json.Marshal(successResp)
		jsonData = string(dataBytes)
	}

	var html string

	if err != nil {
		// 에러/연동 필요 응답용 HTML
		html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>계정 연동 필요</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
        }
        .container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 420px;
        }
        .warning-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #f57c00 0%%, #ff9800 100%%);
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            color: white;
            font-size: 30px;
        }
        h2 { color: #f57c00; margin-bottom: 10px; }
        p { color: #666; margin-bottom: 15px; line-height: 1.6; }
        .info-box {
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px;
            text-align: left;
            border-radius: 8px;
            margin: 20px 0;
        }
        .info-box p { margin: 5px 0; font-size: 0.9em; }
        .btn {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 10px;
            font-size: 1em;
            cursor: pointer;
            margin-top: 10px;
        }
        .btn:hover { opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon">!</div>
        <h2>계정 연동이 필요합니다</h2>
        <p>이 이메일로 가입된 계정이 이미 존재합니다.</p>
        <div class="info-box">
            <p><strong>이메일 인증</strong> 또는 <strong>비밀번호 확인</strong>으로<br>기존 계정과 연동할 수 있습니다.</p>
        </div>
        <p>원래 페이지로 돌아가서 연동을 진행해주세요.</p>
        <button class="btn" onclick="window.close()">이 창 닫기</button>
    </div>
    <script>
        (function() {
            var data = %s;
            var provider = '%s';

			// 데이터 전송 객체 생성
            var result = {
                type: 'SOCIAL_LOGIN_CALLBACK',
                provider: provider,
                data: data,
                timestamp: Date.now()
            };

            console.log('Sending message to parent:', result);

            // 부모 창(window.opener)에 메시지 전송
            if (window.opener) {
                // '*'는 모든 도메인 허용 (개발 환경용)
                // 실제 배포 시에는 'http://localhost:5500' 처럼 프론트 주소를 지정
                window.opener.postMessage(result, '*');
            } else {
                console.error('No parent window found.');
            }

            // 메시지 전송 후 잠시 대기 후 닫기
            setTimeout(function() {
                window.close();
            }, 2000);
        })();
    </script>
</body>
</html>`, jsonData, provider)
	} else {
		// 성공 응답용 HTML
		html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>로그인 완료</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
        }
        .container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
        }
        .success-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #43a047 0%%, #66bb6a 100%%);
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            color: white;
            font-size: 30px;
        }
        h2 { color: #333; margin-bottom: 10px; }
        p { color: #666; margin-bottom: 20px; }
        .close-hint {
            font-size: 0.9em;
            color: #999;
            margin-top: 15px;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 10px;
            font-size: 1em;
            cursor: pointer;
            margin-top: 10px;
        }
        .btn:hover { opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h2>로그인 완료!</h2>
        <p>원래 페이지로 돌아가면 자동으로 로그인됩니다.</p>
        <button class="btn" onclick="window.close()">이 창 닫기</button>
        <p class="close-hint">창이 닫히지 않으면 수동으로 닫아주세요.</p>
    </div>
    <script>
        (function() {
            var data = %s;
            var provider = '%s';

			var result = {
                type: 'SOCIAL_LOGIN_CALLBACK',
                provider: provider,
                data: data,
                timestamp: Date.now()
            };

            console.log('Sending success message to parent:', result);

            // 부모 창(window.opener)에 메시지 전송
            if (window.opener) {
                window.opener.postMessage(result, '*');
            } else {
                console.error('No parent window found.');
            }

            // 메시지 전송 후 닫기
            setTimeout(function() {
                window.close();
            }, 2000);
        })();
    </script>
</body>
</html>`, jsonData, provider)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(statusCode, html)
}

// 토큰 갱신 핸들러
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenReqeust
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Token refreshed successfully",
		Data:    response,
	})
}

// 로그아웃 핸들러
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	// 로그아웃 처리
	if err := h.authService.Logout(req.RefreshToken); err != nil {
		errors.HandleError(c, err)
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
		errors.HandleError(c, errors.NewValidationError("Verification token is required"))
		return
	}

	// 이메일 인증 처리
	if err := h.authService.VerifyEmail(token); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Email verified successfully",
	})
}

func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	// 인증 이메일 재발송 처리
	if err := h.authService.ResendVerificationEmail(req.Email); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Verification email sent successfully",
	})
}

// ConfirmSocialLinkByPassword 비밀번호로 소셜 연동 확인 핸들러
func (h *AuthHandler) ConfirmSocialLinkByPassword(c *gin.Context) {
	var req ConfirmSocialLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	// 유효성 검증
	if err := h.validate.Struct(req); err != nil {
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	// 소셜 연동 확인 처리
	response, err := h.authService.ConfirmSocialLinkByPassword(req.LinkToken, req.Password)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Social account linked successfully",
		Data:    response,
	})
}

// ConfirmSocialLinkByEmailToken 이메일 토큰으로 소셜 연동 확인 핸들러
func (h *AuthHandler) ConfirmSocialLinkByEmailToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		errors.HandleError(c, errors.NewValidationError("Email token is required"))
		return
	}

	// 소셜 연동 확인 처리
	response, err := h.authService.ConfirmSocialLinkByEmailToken(token)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Social account linked successfully",
		Data:    response,
	})
}

// generateRandomState CSRF 방지용 랜덤 state 생성
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetLinkedSocialAccounts 연동된 소셜 계정 조회 핸들러
func (h *AuthHandler) GetLinkedSocialAccounts(c *gin.Context) {
	userID := c.GetUint("user_id")
	if userID == 0 {
		errors.HandleError(c, errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid user ID"))
		return
	}

	response, err := h.authService.GetLinkedSocialAccounts(userID)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Linked social accounts retrieved successfully",
		Data:    response,
	})
}

// UnlinkSocialAccount 소셜 계정 연동 해제 핸들러
func (h *AuthHandler) UnlinkSocialAccount(c *gin.Context) {
	userID := c.GetUint("user_id")
	if userID == 0 {
		errors.HandleError(c, errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid user ID"))
		return
	}

	provider := c.Param("provider")
	if provider == "" {
		errors.HandleError(c, errors.NewValidationError("Provider is required"))
		return
	}

	response, err := h.authService.UnlinkSocialAccount(userID, provider)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	if response.Success {
		c.JSON(http.StatusOK, SuccessResponse{
			Message: "Social account unlinked successfully",
			Data:    response,
		})
	} else {
		// 마지막 인증 수단인 경우 - 클라이언트가 모달 처리할 수 있도록 정보 반환
		c.JSON(http.StatusOK, SuccessResponse{
			Message: "Cannot unlink: this is your only authentication method",
			Data:    response,
		})
	}
}

// ConvertToEmailAccount 일반 회원 전환 핸들러 (비밀번호 설정 후 소셜 연동 해제)
func (h *AuthHandler) ConvertToEmailAccount(c *gin.Context) {
	userID := c.GetUint("user_id")
	if userID == 0 {
		errors.HandleError(c, errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid user ID"))
		return
	}

	var req ConvertToEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.HandleError(c, errors.NewValidationError("Invalid request body"))
		return
	}

	if err := h.validate.Struct(req); err != nil {
		errors.HandleError(c, errors.NewValidationError(err.Error()))
		return
	}

	if err := h.authService.ConvertToEmailAccount(userID, req.Provider, req.NewPassword); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Account converted to email successfully. Social account unlinked.",
	})
}

// DeleteAccount 회원 탈퇴 핸들러
func (h *AuthHandler) DeleteAccount(c *gin.Context) {
	userID := c.GetUint("user_id")
	if userID == 0 {
		errors.HandleError(c, errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid user ID"))
		return
	}

	if err := h.authService.DeleteAccount(userID); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Account deleted successfully",
	})
}
