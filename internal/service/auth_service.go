package service

import (
	"errors"
	"log"
	"time"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/models"
	"github.com/9taetae9/social-login/internal/repository"
	"github.com/9taetae9/social-login/internal/utils"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthService interface {
	Register(email, password string) (*AuthResponse, error)
	Login(email, password string) (*AuthResponse, error)
}

type authService struct {
	userRepo repository.UserRepository
	cfg      *config.Config
}

type AuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

func NewAuthService(userRepo repository.UserRepository, cfg *config.Config) AuthService {
	return &authService{
		userRepo: userRepo,
		cfg:      cfg,
	}
}

// 회원가입
func (s *authService) Register(email, password string) (*AuthResponse, error) {
	// 이메일 중복 확인
	existingUser, err := s.userRepo.FindByEmail(email)
	if err == nil && existingUser != nil {
		return nil, errors.New("email already exists")
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	user := &models.User{
		Email:         email,
		PasswordHash:  hashedPassword,
		EmailVerified: false,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("failed to creater user")
	}

	verificationToken := uuid.New().String()
	emailVerification := &models.EmailVerification{
		UserID:    user.ID,
		Token:     verificationToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Verified:  false,
	}

	if err := s.userRepo.CreateEmailVerification(emailVerification); err != nil {
		return nil, errors.New("failed to create email verification")
	}

	// 인증 이메일 발송
	emailCfg := utils.EmailConfig{
		SMTPHost:     s.cfg.Email.SMTPHost,
		SMTPPort:     s.cfg.Email.SMTPPort,
		SMTPUsername: s.cfg.Email.SMTPUsername,
		SMTPPassword: s.cfg.Email.SMTPPassword,
		FromEmail:    s.cfg.Email.FromEmail,
	}

	if err := utils.SendVerificationEmail(email, verificationToken, s.cfg.App.URL, emailCfg); err != nil {
		// 이메일 발송 실패는 로그만 남기고 계속 진행
		log.Printf("Failed to send verification email: %v", err)
	}

	// JWT 토큰 생성
	accessToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	refreshToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.RefreshTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	// 리프레시 토큰 저장
	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.RefreshTokenExpiry),
	}
	if err := s.userRepo.CreateRefreshToken(refreshTokenModel); err != nil {
		return nil, errors.New("failed to save refresh token")
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

// 로그인
func (s *authService) Login(email, password string) (*AuthResponse, error) {
	// 사용자 조회
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid email or password")
		}
		return nil, errors.New("failed to find user")
	}

	// 비밀번호 검증
	if err := utils.CheckPassword(user.PasswordHash, password); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// JWT 토큰 생성
	accessToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	refreshToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.RefreshTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.RefreshTokenExpiry),
	}

	if err := s.userRepo.CreateRefreshToken(refreshTokenModel); err != nil {
		return nil, errors.New("failed to save refresh token")
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}
