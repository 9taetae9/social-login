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

type RegisterResponse struct {
	Message string       `json:"message"`
	User    *models.User `json:"user"`
}

type AuthService interface {
	Register(email, password string) (*RegisterResponse, error)
	Login(email, password string) (*AuthResponse, error)
	SocialLogin(email, provider, socialID string) (*AuthResponse, error)
	RefreshToken(refreshToken string) (*AuthResponse, error)
	Logout(refreshToken string) error
	VerifyEmail(token string) error
	ResendVerificationEmail(email string) error
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
func (s *authService) Register(email, password string) (*RegisterResponse, error) {
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
		PasswordHash:  &hashedPassword,
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

	return &RegisterResponse{
		Message: "Registration successful. Please check your email to verify your account before logging in.",
		User:    user,
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

	if user.PasswordHash == nil{
		return nil, errors.New("this account uses social login. please login in with social account")
	}

	// 비밀번호 검증
	if err := utils.CheckPassword(*user.PasswordHash, password); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// 이메일 인증 확인
	if !user.EmailVerified {
		return nil, errors.New("email not verified. please check your email and verify your account before logging in")
	}

	return s.generateTokens(user)
}

// 소셜 로그인
func (s *authService) SocialLogin(email, provider, socialID string) (*AuthResponse, error){
	// 이미 소셜로 연동된 계정이 있는지 확인
	socialAccount, err := s.userRepo.FindSocialAccount(provider, socialID)

	if err == nil{
		// [case 1] 이미 가입된 소셜 유저 -> 로그인 성공
		//GORM Preload를 사용 안했으면 별도 조회 필요
		user, err := s.userRepo.FindByID(socialAccount.UserID)
		if err != nil{
			return nil, errors.New("linked user not found")
		}
		return s.generateTokens(user)
	}

	// 소셜 계정이 없다면, 이메일로 기존 가입자가 있는지 확인
	user, err := s.userRepo.FindByEmail(email)
	if err == nil{
		// [case 2] 기존 이메일 가입자 존재 -> 계정 통합 (Update)
		// ** 보안 정책에 따라 비밀번호 확인을 요구할 수도 있음 (현재는 편의상 통합)
		newSocialAccount := &models.SocialAccount{
			UserID: user.ID,
			Provider: provider,
			SocialID: socialID,
			Email: email,
		}

		if err := s.userRepo.CreateSocialAccount(newSocialAccount); err != nil{
			return nil, errors.New("failed to link social account")
		}

		// if err := s.userRepo.UpdateSocialInfo(user.ID, provider, socialID); err != nil{
		// 	return nil, errors.New("failed to link social account")
		// }
		// 정보가 업데이트되었음으로 다시 조회하거나 객체 업데이트
		if !user.EmailVerified{
			_ = s.userRepo.UpdateEmailVerified(user.ID)
			user.EmailVerified = true
		}

		return s.generateTokens(user)
	}

	// [case 3] 최초 가입자 -> User 생성 + SocialAccount 생성
	// 트랜잭션 처리 구간
	// 3-1. User 본체 생성
	newUser := &models.User{
		Email: email,
		PasswordHash: nil,
		EmailVerified: true,
	}

	if err := s.userRepo.Create(newUser); err != nil{
		return nil, errors.New("failed to create social user")
	}

	// 3-2. SocialAccount 연결 생성
	newSocialAccount := &models.SocialAccount{
		UserID: newUser.ID,
		Provider: provider,
		SocialID: socialID,
		Email: email,
	}

	if err := s.userRepo.CreateSocialAccount(newSocialAccount); err != nil{
		//TODO: 롤백 로직이 없으므로 Transaction 사용 권장
		return nil, errors.New("failed to create social account linkage")
	}
	
	return s.generateTokens(newUser)
}

// JWT 토큰 생성 핼퍼 메서드
func (s *authService) generateTokens(user *models.User) (*AuthResponse, error){
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

// RefreshToken 갱신
func (s *authService) RefreshToken(refreshToken string) (*AuthResponse, error) {
	claims, err := utils.ValidateToken(refreshToken, s.cfg.JWT.Secret)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	_, err = s.userRepo.FindRefreshTokenByToken(refreshToken)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found")
		}
		return nil, errors.New("failed to find refresh token")
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	newAccessToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	// 새로운 리프레시 토큰 생성
	newRefreshToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	// 기존 리프레시 토큰 삭제
	if err := s.userRepo.DeleteRefreshToken(refreshToken); err != nil {
		return nil, errors.New("failed to delete old refresh token")
	}

	// 새 리프레시 토큰 저장
	newTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.AccessTokenExpiry),
	}

	if err := s.userRepo.CreateRefreshToken(newTokenModel); err != nil {
		return nil, errors.New("failed to save refresh token")
	}

	return &AuthResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		User:         user,
	}, nil
}

// 로그아웃
func (s *authService) Logout(refreshToken string) error {
	// 리프레시 토큰 검증
	_, err := utils.ValidateToken(refreshToken, s.cfg.JWT.Secret)
	if err != nil {
		return errors.New("invalid refresh token")
	}

	// 리프레시 토큰 삭제
	if err := s.userRepo.DeleteRefreshToken(refreshToken); err != nil {
		return errors.New("failed to delete refresh token")
	}

	return nil
}

// 이메일 인증
func (s *authService) VerifyEmail(token string) error {
	// 이메일 인증 토큰 조회
	verification, err := s.userRepo.FindEmailVerificationByToken(token)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("invalid or expire verification token")
		}
		return errors.New("failed to find verification token")
	}

	// 토큰 만료 확인
	if time.Now().After(verification.ExpiresAt) {
		return errors.New("verification token has expired")
	}

	// 이미 인증된 토큰인지 확인
	if verification.Verified {
		return errors.New("email already verified")
	}

	// users 테이블의 email_verified를 true로 업데이트
	if err := s.userRepo.UpdateEmailVerified(verification.UserID); err != nil {
		return errors.New("failed to update email verificatin status")
	}

	// 인증 토큰을 인증됨으로 표시
	if err := s.userRepo.MarkEmailVerificationAsUsed(verification.ID); err != nil {
		return errors.New("failed to mark verification as used")
	}

	return nil
}

// 인증 이메일 재발송
func (s *authService) ResendVerificationEmail(email string) error {
	// 사용자 조회
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		return errors.New("failed to find user")
	}

	// 이미 인증된 사용자인지 확인
	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// 새로운 인증 토큰 생성
	verificationToken := uuid.New().String()
	emailVerification := &models.EmailVerification{
		UserID:    user.ID,
		Token:     verificationToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Verified:  false,
	}

	if err := s.userRepo.CreateEmailVerification(emailVerification); err != nil {
		return errors.New("failed to create email verification")
	}

	emailCfg := utils.EmailConfig{
		SMTPHost:     s.cfg.Email.SMTPHost,
		SMTPPort:     s.cfg.Email.SMTPPort,
		SMTPUsername: s.cfg.Email.SMTPUsername,
		SMTPPassword: s.cfg.Email.SMTPPassword,
		FromEmail:    s.cfg.Email.FromEmail,
	}

	if err := utils.SendVerificationEmail(user.Email, verificationToken, s.cfg.App.URL, emailCfg); err != nil {
		return errors.New("failed to send verification email")
	}

	return nil
}
