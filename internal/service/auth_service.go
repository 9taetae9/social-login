package service

import (
	"log/slog"
	"time"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/errors"
	"github.com/9taetae9/social-login/internal/logger"
	"github.com/9taetae9/social-login/internal/models"
	"github.com/9taetae9/social-login/internal/repository"
	"github.com/9taetae9/social-login/internal/utils"
	"github.com/google/uuid"
)

type RegisterResponse struct {
	Message string       `json:"message"`
	User    *models.User `json:"user"`
}

// SocialLoginTokens OAuth 토큰 정보 (소셜 로그인 시 전달)
type SocialLoginTokens struct {
	AccessToken  *string
	RefreshToken *string
	TokenExpiry  *int64
}

type AuthService interface {
	Register(email, password, userType, phoneNumber string) (*RegisterResponse, error)
	Login(email, password string) (*AuthResponse, error)
	SocialLogin(email, provider, socialID string, tokens *SocialLoginTokens) (*AuthResponse, error)
	RefreshToken(refreshToken string) (*AuthResponse, error)
	Logout(refreshToken string) error
	VerifyEmail(token string) error
	ResendVerificationEmail(email string) error
	ConfirmSocialLinkByPassword(linkToken, password string) (*AuthResponse, error)
	ConfirmSocialLinkByEmailToken(emailToken string) (*AuthResponse, error)
	SendSocialLinkEmail(linkToken string) error // 소셜 연동 이메일 발송 요청
	GetLinkedSocialAccounts(userID uint) (*LinkedAccountsResponse, error)
	UnlinkSocialAccount(userID uint, provider string) (*UnlinkResponse, error)
	ConvertToEmailAccount(userID uint, provider, newPassword string) error
	DeleteAccount(userID uint) error
	// OAuth 토큰 관련
	SaveSocialAccountTokens(userID uint, provider string, accessToken, refreshToken *string, tokenExpiry *int64) error
}

type UnlinkResponse struct {
	Success        bool `json:"success"`
	IsLastAuth     bool `json:"is_last_auth"`
	HasPassword    bool `json:"has_password"`
	SocialAccounts int  `json:"social_accounts_count"`
}

type authService struct {
	userRepo           repository.UserRepository
	cfg                *config.Config
	oauthRevokeService OAuthRevokeService
}

type AuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

type SocialAccountInfo struct {
	Provider  string `json:"provider"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

type LinkedAccountsResponse struct {
	User           *models.User        `json:"user"`
	SocialAccounts []SocialAccountInfo `json:"social_accounts"`
}

func NewAuthService(userRepo repository.UserRepository, cfg *config.Config) AuthService {
	return &authService{
		userRepo:           userRepo,
		cfg:                cfg,
		oauthRevokeService: NewOAuthRevokeService(cfg),
	}
}

// 회원가입
func (s *authService) Register(email, password, userType, phoneNumber string) (*RegisterResponse, error) {
	slog.Info("Registration attempt",
		"email", logger.SanitizeEmail(email),
		"user_type", userType,
	)

	// 이메일 중복 확인
	existingUser, err := s.userRepo.FindByEmail(email)
	if err == nil && existingUser != nil {
		slog.Warn("Registration failed: email already exists",
			"email", logger.SanitizeEmail(email),
		)
		return nil, errors.NewConflictError(errors.ErrCodeEmailExists, "Email already exists")
	}

	// 404가 아닌 다른 에러면 그대로 반환
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr.Code != errors.ErrCodeUserNotFound {
			return nil, err
		}
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return nil, errors.NewInternalError(errors.ErrCodeHashPassword, "Failed to hash password", err)
	}

	uType := models.UserType(userType)

	user := &models.User{
		Email:        email,
		PasswordHash: &hashedPassword,
		UserType:     &uType,
	}

	if models.UserType(userType) == models.UserTypeKorean {
		existingPhone, err := s.userRepo.FindByPhoneNumber(phoneNumber)
		if err == nil && existingPhone != nil {
			slog.Warn("Registration failed: phone already exists",
				"phone", logger.SanitizePhone(phoneNumber),
			)
			return nil, errors.NewConflictError(errors.ErrCodePhoneExists, "Phone number already in use")
		}

		// 404가 아닌 다른 에러면 그대로 반환
		if err != nil {
			if appErr, ok := err.(*errors.AppError); ok && appErr.Code != errors.ErrCodeUserNotFound {
				return nil, err
			}
		}

		user.PhoneNumber = &phoneNumber
		user.EmailVerified = true // 한국인은 인증된 것으로 간주
		user.CountryCode = "KR"

		slog.Info("Korean user registration", "email", logger.SanitizeEmail(email))
	} else {
		user.PhoneNumber = nil     // 외국인은 전화번호 없음
		user.EmailVerified = false // 이메일 인증 필요
		//user.CountryCode 외국인은 가입시 null 처리
		fType := models.UserTypeForeigner
		user.UserType = &fType

		slog.Info("Foreigner user registration", "email", logger.SanitizeEmail(email))
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	if *user.UserType == models.UserTypeForeigner { // 외국인인 경우에만 인증 이메일 발송
		verificationToken := uuid.New().String()
		emailVerification := &models.EmailVerification{
			UserID:    user.ID,
			Token:     verificationToken,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Verified:  false,
		}

		if err := s.userRepo.CreateEmailVerification(emailVerification); err != nil {
			return nil, err
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
			// 이메일 발송 실패는 경고만 (계속 진행)
			slog.Warn("Failed to send verification email",
				"error", err,
				"email", logger.SanitizeEmail(email),
			)
		} else {
			slog.Info("Verification email sent", "email", logger.SanitizeEmail(email))
		}

		return &RegisterResponse{
			Message: "Registration successful. Please check your email to verify your account before logging in.",
			User:    user,
		}, nil
	}

	slog.Info("Registration successful",
		"user_id", user.ID,
		"email", logger.SanitizeEmail(email),
	)

	return &RegisterResponse{
		Message: "Registration successful. You can login immediately.",
		User:    user,
	}, nil
}

// 로그인
func (s *authService) Login(email, password string) (*AuthResponse, error) {
	slog.Info("Login attempt", "email", logger.SanitizeEmail(email))

	// 사용자 조회
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Repository에서 UserNotFound 에러가 왔다면 인증 실패로 변환
		if appErr, ok := err.(*errors.AppError); ok && appErr.Code == errors.ErrCodeUserNotFound {
			slog.Warn("Login failed: user not found", "email", logger.SanitizeEmail(email))
			return nil, errors.NewAuthError(errors.ErrCodeInvalidCredentials, "Invalid email or password")
		}
		return nil, err
	}

	if user.PasswordHash == nil {
		slog.Warn("Login failed: social login account",
			"email", logger.SanitizeEmail(email),
			"user_id", user.ID,
		)
		return nil, errors.NewAuthError(errors.ErrCodeSocialLoginRequired,
			"This account uses social login. Please login with social account")
	}

	// 비밀번호 검증
	if err := utils.CheckPassword(*user.PasswordHash, password); err != nil {
		slog.Warn("Login failed: invalid password", "email", logger.SanitizeEmail(email))
		return nil, errors.NewAuthError(errors.ErrCodeInvalidCredentials, "Invalid email or password")
	}

	// 이메일 인증 확인
	if !user.EmailVerified {
		slog.Warn("Login failed: email not verified",
			"email", logger.SanitizeEmail(email),
			"user_id", user.ID,
		)
		return nil, errors.NewAuthError(errors.ErrCodeEmailNotVerified,
			"Email not verified. Please check your email and verify your account before logging in")
	}

	slog.Info("Login successful",
		"user_id", user.ID,
		"email", logger.SanitizeEmail(email),
	)

	return s.generateTokens(user)
}

// 소셜 로그인
func (s *authService) SocialLogin(email, provider, socialID string, tokens *SocialLoginTokens) (*AuthResponse, error) {
	slog.Info("Social login attempt",
		"email", logger.SanitizeEmail(email),
		"provider", provider,
	)

	// 이미 소셜로 연동된 계정이 있는지 확인
	socialAccount, err := s.userRepo.FindSocialAccount(provider, socialID)

	if err == nil {
		// [case 1] 이미 가입된 소셜 유저 -> 로그인 성공
		slog.Info("Social login: existing social account found",
			"provider", provider,
			"user_id", socialAccount.UserID,
		)
		//GORM Preload를 사용 안했으면 별도 조회 필요
		user, err := s.userRepo.FindByID(socialAccount.UserID)
		if err != nil {
			slog.Error("Failed to find linked user", "error", err, "user_id", socialAccount.UserID)
			return nil, errors.NewInternalError(errors.ErrCodeUserNotFound, "Linked user not found", err)
		}
		slog.Info("Social login successful", "user_id", user.ID, "provider", provider)
		return s.generateTokens(user)
	}

	// SocialAccount를 찾지 못한 경우가 아닌 다른 에러면 반환
	if appErr, ok := err.(*errors.AppError); ok && appErr.Code != errors.ErrCodeSocialNotFound {
		return nil, err
	}

	// 소셜 계정이 없다면, 이메일로 기존 가입자가 있는지 확인
	user, err := s.userRepo.FindByEmail(email)
	if err == nil {
		// [case 2] 기존 이메일 가입자 존재 -> 검증 후 계정 통합
		slog.Info("Social login: verification required for existing email account",
			"email", logger.SanitizeEmail(email),
			"provider", provider,
			"user_id", user.ID,
		)

		// 기존 pending link가 있으면 삭제
		_ = s.userRepo.DeletePendingSocialLinksByUserID(user.ID)

		// PendingSocialLink 생성 (link_token + email_token 둘 다 생성)
		linkToken := uuid.New().String()
		emailToken := uuid.New().String()
		pendingLink := &models.PendingSocialLink{
			UserID:     user.ID,
			Provider:   provider,
			SocialID:   socialID,
			Email:      email,
			LinkToken:  linkToken,
			EmailToken: &emailToken,
			ExpiresAt:  time.Now().Add(15 * time.Minute), // 15분 유효
		}

		// OAuth 토큰 정보 저장 (연동 완료 시 SocialAccount로 복사됨)
		if tokens != nil {
			pendingLink.AccessToken = tokens.AccessToken
			pendingLink.RefreshToken = tokens.RefreshToken
			pendingLink.TokenExpiry = tokens.TokenExpiry
		}

		if err := s.userRepo.CreatePendingSocialLink(pendingLink); err != nil {
			slog.Error("Failed to create pending social link", "error", err, "provider", provider)
			return nil, errors.NewInternalError(errors.ErrCodeSocialLinkFailed, "Failed to initiate social link verification", err)
		}

		slog.Info("Pending social link created, verification required",
			"user_id", user.ID,
			"provider", provider,
		)

		// 검증 필요 응답 반환 (이메일은 사용자가 요청 시에만 발송)
		return nil, errors.NewConflictErrorWithData(
			errors.ErrCodeSocialLinkVerificationRequired,
			"Account verification required to link social account",
			map[string]interface{}{
				"link_token":   linkToken,
				"email":        email,
				"provider":     provider,
				"has_password": user.PasswordHash != nil,
			},
		)
	}

	// UserNotFound가 아닌 다른 에러면 반환
	if appErr, ok := err.(*errors.AppError); ok && appErr.Code != errors.ErrCodeUserNotFound {
		return nil, err
	}

	// [case 3] 최초 가입자 -> User 생성 + SocialAccount 생성
	slog.Info("Social login: creating new user account",
		"email", logger.SanitizeEmail(email),
		"provider", provider,
	)

	newUser := &models.User{
		Email:         email,
		PasswordHash:  nil,
		EmailVerified: true,
	}

	err = s.userRepo.WithTrx(func(txRepo repository.UserRepository) error {
		// 3-1. User 본체 생성
		if err := txRepo.Create(newUser); err != nil {
			return err
		}

		// 3-2. SocialAccount 연결 생성
		newSocialAccount := &models.SocialAccount{
			UserID:   newUser.ID,
			Provider: provider,
			SocialID: socialID,
			Email:    email,
		}
		if err := txRepo.CreateSocialAccount(newSocialAccount); err != nil {
			return err
		}
		return nil // Commit
	})

	if err != nil {
		slog.Error("Failed to create social user", "error", err, "provider", provider)
		return nil, errors.NewInternalError(errors.ErrCodeSocialCreateFailed, "Failed to create social user", err)
	}

	slog.Info("New social user created successfully", "user_id", newUser.ID, "provider", provider)
	return s.generateTokens(newUser)
}

// JWT 토큰 생성 핼퍼 메서드
func (s *authService) generateTokens(user *models.User) (*AuthResponse, error) {
	accessToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		slog.Error("Failed to generate access token", "error", err, "user_id", user.ID)
		return nil, errors.NewInternalError(errors.ErrCodeGenerateToken, "Failed to generate access token", err)
	}

	refreshToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.RefreshTokenExpiry,
	)
	if err != nil {
		slog.Error("Failed to generate refresh token", "error", err, "user_id", user.ID)
		return nil, errors.NewInternalError(errors.ErrCodeGenerateToken, "Failed to generate refresh token", err)
	}

	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.RefreshTokenExpiry),
	}

	if err := s.userRepo.CreateRefreshToken(refreshTokenModel); err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	slog.Debug("Tokens generated successfully", "user_id", user.ID)

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

// RefreshToken 갱신
func (s *authService) RefreshToken(refreshToken string) (*AuthResponse, error) {
	slog.Info("Token refresh attempt")

	claims, err := utils.ValidateToken(refreshToken, s.cfg.JWT.Secret)
	if err != nil {
		slog.Warn("Invalid refresh token", "error", err)
		return nil, errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid refresh token")
	}

	_, err = s.userRepo.FindRefreshTokenByToken(refreshToken)
	if err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	newAccessToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.AccessTokenExpiry,
	)
	if err != nil {
		slog.Error("Failed to generate access token", "error", err)
		return nil, errors.NewInternalError(errors.ErrCodeGenerateToken, "Failed to generate access token", err)
	}

	// 새로운 리프레시 토큰 생성
	newRefreshToken, err := utils.GenerateAccessToken(
		user.ID,
		user.Email,
		s.cfg.JWT.Secret,
		s.cfg.JWT.RefreshTokenExpiry,
	)
	if err != nil {
		slog.Error("Failed to generate refresh token", "error", err)
		return nil, errors.NewInternalError(errors.ErrCodeGenerateToken, "Failed to generate refresh token", err)
	}

	// 기존 리프레시 토큰 삭제
	if err := s.userRepo.DeleteRefreshToken(refreshToken); err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	// 새 리프레시 토큰 저장
	newTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.RefreshTokenExpiry),
	}

	if err := s.userRepo.CreateRefreshToken(newTokenModel); err != nil {
		return nil, err // Repository에서 이미 AppError로 변환됨
	}

	slog.Info("Token refreshed successfully", "user_id", user.ID)

	return &AuthResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		User:         user,
	}, nil
}

// 로그아웃
func (s *authService) Logout(refreshToken string) error {
	slog.Info("Logout attempt")

	// 리프레시 토큰 검증
	_, err := utils.ValidateToken(refreshToken, s.cfg.JWT.Secret)
	if err != nil {
		slog.Warn("Invalid refresh token for logout", "error", err)
		return errors.NewAuthError(errors.ErrCodeInvalidToken, "Invalid refresh token")
	}

	// 리프레시 토큰 삭제
	if err := s.userRepo.DeleteRefreshToken(refreshToken); err != nil {
		return err // Repository에서 이미 AppError로 변환됨
	}

	slog.Info("Logout successful")
	return nil
}

// 이메일 인증
func (s *authService) VerifyEmail(token string) error {
	slog.Info("Email verification attempt")

	// 이메일 인증 토큰 조회
	verification, err := s.userRepo.FindEmailVerificationByToken(token)
	if err != nil {
		return err // Repository에서 이미 AppError로 변환됨
	}

	// 토큰 만료 확인
	if time.Now().After(verification.ExpiresAt) {
		slog.Warn("Verification token expired")
		return errors.NewAuthError(errors.ErrCodeVerificationExpired, "Verification token has expired")
	}

	// 이미 인증된 토큰인지 확인
	if verification.Verified {
		slog.Warn("Email already verified", "user_id", verification.UserID)
		return errors.New(errors.ErrCodeEmailAlreadyVerified, "Email already verified", 400)
	}

	// users 테이블의 email_verified를 true로 업데이트
	if err := s.userRepo.UpdateEmailVerified(verification.UserID); err != nil {
		return err // Repository에서 이미 AppError로 변환됨
	}

	// 인증 토큰을 인증됨으로 표시
	if err := s.userRepo.MarkEmailVerificationAsUsed(verification.ID); err != nil {
		return err // Repository에서 이미 AppError로 변환됨
	}

	slog.Info("Email verified successfully", "user_id", verification.UserID)
	return nil
}

// ConfirmSocialLinkByPassword 비밀번호로 소셜 연동 확인
func (s *authService) ConfirmSocialLinkByPassword(linkToken, password string) (*AuthResponse, error) {
	slog.Info("Social link confirmation by password attempt")

	// PendingSocialLink 조회
	pendingLink, err := s.userRepo.FindPendingSocialLinkByToken(linkToken)
	if err != nil {
		return nil, err
	}

	// 만료 확인
	if time.Now().After(pendingLink.ExpiresAt) {
		_ = s.userRepo.DeletePendingSocialLink(pendingLink.ID)
		slog.Warn("Social link token expired", "link_id", pendingLink.ID)
		return nil, errors.New(errors.ErrCodeSocialLinkExpired, "Social link token has expired", 400)
	}

	// 유저 조회
	user, err := s.userRepo.FindByID(pendingLink.UserID)
	if err != nil {
		return nil, err
	}

	// 비밀번호 검증 (소셜 전용 계정인 경우 비밀번호 없음)
	if user.PasswordHash == nil {
		slog.Warn("Social link failed: user has no password", "user_id", user.ID)
		return nil, errors.New(errors.ErrCodeSocialLinkInvalidPassword,
			"This account has no password. Please use email verification.", 400)
	}

	if err := utils.CheckPassword(*user.PasswordHash, password); err != nil {
		slog.Warn("Social link failed: invalid password", "user_id", user.ID)
		return nil, errors.New(errors.ErrCodeSocialLinkInvalidPassword, "Invalid password", 401)
	}

	// 소셜 계정 연동 및 pending link 삭제
	err = s.userRepo.WithTrx(func(txRepo repository.UserRepository) error {
		newSocialAccount := &models.SocialAccount{
			UserID:       user.ID,
			Provider:     pendingLink.Provider,
			SocialID:     pendingLink.SocialID,
			Email:        pendingLink.Email,
			AccessToken:  pendingLink.AccessToken,  // OAuth 토큰 복사
			RefreshToken: pendingLink.RefreshToken, // OAuth 토큰 복사
			TokenExpiry:  pendingLink.TokenExpiry,  // OAuth 토큰 복사
		}

		if err := txRepo.CreateSocialAccount(newSocialAccount); err != nil {
			return err
		}

		if !user.EmailVerified {
			if err := txRepo.UpdateEmailVerified(user.ID); err != nil {
				return err
			}
			user.EmailVerified = true
		}

		if err := txRepo.DeletePendingSocialLink(pendingLink.ID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		slog.Error("Failed to confirm social link", "error", err)
		return nil, errors.NewInternalError(errors.ErrCodeSocialLinkFailed, "Failed to link social account", err)
	}

	slog.Info("Social account linked successfully via password",
		"user_id", user.ID,
		"provider", pendingLink.Provider,
		"has_tokens", pendingLink.AccessToken != nil,
	)

	return s.generateTokens(user)
}

// ConfirmSocialLinkByEmailToken 이메일 토큰으로 소셜 연동 확인
func (s *authService) ConfirmSocialLinkByEmailToken(emailToken string) (*AuthResponse, error) {
	slog.Info("Social link confirmation by email token attempt")

	// PendingSocialLink 조회
	pendingLink, err := s.userRepo.FindPendingSocialLinkByEmailToken(emailToken)
	if err != nil {
		return nil, err
	}

	// 만료 확인
	if time.Now().After(pendingLink.ExpiresAt) {
		_ = s.userRepo.DeletePendingSocialLink(pendingLink.ID)
		slog.Warn("Social link email token expired", "link_id", pendingLink.ID)
		return nil, errors.New(errors.ErrCodeSocialLinkExpired, "Social link token has expired", 400)
	}

	// 유저 조회
	user, err := s.userRepo.FindByID(pendingLink.UserID)
	if err != nil {
		return nil, err
	}

	// 소셜 계정 연동 및 pending link 삭제
	err = s.userRepo.WithTrx(func(txRepo repository.UserRepository) error {
		newSocialAccount := &models.SocialAccount{
			UserID:       user.ID,
			Provider:     pendingLink.Provider,
			SocialID:     pendingLink.SocialID,
			Email:        pendingLink.Email,
			AccessToken:  pendingLink.AccessToken,  // OAuth 토큰 복사
			RefreshToken: pendingLink.RefreshToken, // OAuth 토큰 복사
			TokenExpiry:  pendingLink.TokenExpiry,  // OAuth 토큰 복사
		}

		if err := txRepo.CreateSocialAccount(newSocialAccount); err != nil {
			return err
		}

		if !user.EmailVerified {
			if err := txRepo.UpdateEmailVerified(user.ID); err != nil {
				return err
			}
			user.EmailVerified = true
		}

		if err := txRepo.DeletePendingSocialLink(pendingLink.ID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		slog.Error("Failed to confirm social link via email", "error", err)
		return nil, errors.NewInternalError(errors.ErrCodeSocialLinkFailed, "Failed to link social account", err)
	}

	slog.Info("Social account linked successfully via email token",
		"user_id", user.ID,
		"provider", pendingLink.Provider,
		"has_tokens", pendingLink.AccessToken != nil,
	)

	return s.generateTokens(user)
}

// 인증 이메일 재발송
func (s *authService) ResendVerificationEmail(email string) error {
	slog.Info("Resend verification email attempt", "email", logger.SanitizeEmail(email))

	// 사용자 조회
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return err // Repository에서 이미 AppError로 변환됨
	}

	// 이미 인증된 사용자인지 확인
	if user.EmailVerified {
		slog.Warn("Email already verified", "user_id", user.ID)
		return errors.New(errors.ErrCodeEmailAlreadyVerified, "Email already verified", 400)
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
		return err // Repository에서 이미 AppError로 변환됨
	}

	emailCfg := utils.EmailConfig{
		SMTPHost:     s.cfg.Email.SMTPHost,
		SMTPPort:     s.cfg.Email.SMTPPort,
		SMTPUsername: s.cfg.Email.SMTPUsername,
		SMTPPassword: s.cfg.Email.SMTPPassword,
		FromEmail:    s.cfg.Email.FromEmail,
	}

	if err := utils.SendVerificationEmail(user.Email, verificationToken, s.cfg.App.URL, emailCfg); err != nil {
		slog.Error("Failed to send verification email", "error", err, "email", logger.SanitizeEmail(email))
		return errors.NewInternalError(errors.ErrCodeEmailSendFailed, "Failed to send verification email", err)
	}

	slog.Info("Verification email resent successfully", "email", logger.SanitizeEmail(email))
	return nil
}

// SendSocialLinkEmail 소셜 연동 이메일 발송 (사용자 요청 시에만)
func (s *authService) SendSocialLinkEmail(linkToken string) error {
	slog.Info("Send social link email attempt")

	// PendingSocialLink 조회
	pendingLink, err := s.userRepo.FindPendingSocialLinkByToken(linkToken)
	if err != nil {
		return err
	}

	// 만료 확인
	if time.Now().After(pendingLink.ExpiresAt) {
		_ = s.userRepo.DeletePendingSocialLink(pendingLink.ID)
		slog.Warn("Social link token expired", "link_id", pendingLink.ID)
		return errors.New(errors.ErrCodeSocialLinkExpired, "Social link token has expired", 400)
	}

	// email_token이 없으면 에러
	if pendingLink.EmailToken == nil || *pendingLink.EmailToken == "" {
		slog.Error("No email token found for pending link", "link_id", pendingLink.ID)
		return errors.NewInternalError(errors.ErrCodeSocialLinkFailed, "Email token not found", nil)
	}

	// 이메일 발송
	emailCfg := utils.EmailConfig{
		SMTPHost:     s.cfg.Email.SMTPHost,
		SMTPPort:     s.cfg.Email.SMTPPort,
		SMTPUsername: s.cfg.Email.SMTPUsername,
		SMTPPassword: s.cfg.Email.SMTPPassword,
		FromEmail:    s.cfg.Email.FromEmail,
	}

	if err := utils.SendSocialLinkVerificationEmail(pendingLink.Email, *pendingLink.EmailToken, pendingLink.Provider, s.cfg.App.URL, emailCfg); err != nil {
		slog.Error("Failed to send social link verification email",
			"error", err,
			"email", logger.SanitizeEmail(pendingLink.Email),
		)
		return errors.NewInternalError(errors.ErrCodeEmailSendFailed, "Failed to send verification email", err)
	}

	slog.Info("Social link verification email sent",
		"email", logger.SanitizeEmail(pendingLink.Email),
		"provider", pendingLink.Provider,
	)

	return nil
}

// 연동된 소셜 계정 목록 조회
func (s *authService) GetLinkedSocialAccounts(userID uint) (*LinkedAccountsResponse, error) {
	slog.Info("Get linked social accounts", "user_id", userID)

	// 사용자 조회
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	// 연동된 소셜 계정 조회
	socialAccounts, err := s.userRepo.FindSocialAccountsByUserID(userID)
	if err != nil {
		return nil, err
	}

	// 응답 변환
	accountInfos := make([]SocialAccountInfo, len(socialAccounts))
	for i, account := range socialAccounts {
		accountInfos[i] = SocialAccountInfo{
			Provider:  account.Provider,
			Email:     account.Email,
			CreatedAt: account.CreatedAt.Format("2006-01-02 15:04:05"),
		}
	}

	slog.Info("Linked social accounts retrieved", "user_id", userID, "count", len(accountInfos))

	return &LinkedAccountsResponse{
		User:           user,
		SocialAccounts: accountInfos,
	}, nil
}

// UnlinkSocialAccount 소셜 계정 연동 해제
func (s *authService) UnlinkSocialAccount(userID uint, provider string) (*UnlinkResponse, error) {
	slog.Info("Unlink social account attempt", "user_id", userID, "provider", provider)

	// 사용자 조회
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	// 해당 소셜 계정이 연동되어 있는지 확인
	socialAccount, err := s.userRepo.FindSocialAccountByUserIDAndProvider(userID, provider)
	if err != nil {
		return nil, err
	}

	// 연동된 소셜 계정 목록 조회
	socialAccounts, err := s.userRepo.FindSocialAccountsByUserID(userID)
	if err != nil {
		return nil, err
	}

	hasPassword := user.PasswordHash != nil
	socialAccountCount := len(socialAccounts)

	// 다른 인증 수단이 있는지 확인
	// Case 1: 비밀번호가 있거나, 다른 소셜 계정이 있으면 즉시 연동 해제
	if hasPassword || socialAccountCount > 1 {
		// 외부 OAuth 제공자에 토큰 revoke 요청 (Best effort)
		if socialAccount.AccessToken != nil && *socialAccount.AccessToken != "" {
			if err := s.oauthRevokeService.RevokeToken(provider, *socialAccount.AccessToken, socialAccount.RefreshToken); err != nil {
				// 외부 API 호출 실패는 경고만 남기고 계속 진행
				slog.Warn("Failed to revoke external OAuth token (continuing with unlink)",
					"error", err,
					"user_id", userID,
					"provider", provider,
				)
			} else {
				slog.Info("External OAuth token revoked successfully",
					"user_id", userID,
					"provider", provider,
				)
			}
		} else {
			slog.Warn("No access token stored for social account, skipping external revoke",
				"user_id", userID,
				"provider", provider,
			)
		}

		// DB에서 소셜 계정 삭제
		if err := s.userRepo.DeleteSocialAccount(userID, provider); err != nil {
			slog.Error("Failed to unlink social account", "error", err, "user_id", userID, "provider", provider)
			return nil, errors.NewInternalError(errors.ErrCodeSocialUnlinkFailed, "Failed to unlink social account", err)
		}

		slog.Info("Social account unlinked successfully", "user_id", userID, "provider", provider)
		return &UnlinkResponse{
			Success:        true,
			IsLastAuth:     false,
			HasPassword:    hasPassword,
			SocialAccounts: socialAccountCount - 1,
		}, nil
	}

	// Case 2: 이 소셜 계정이 유일한 인증 수단
	slog.Warn("Cannot unlink: last authentication method", "user_id", userID, "provider", provider)
	return &UnlinkResponse{
		Success:        false,
		IsLastAuth:     true,
		HasPassword:    false,
		SocialAccounts: socialAccountCount,
	}, nil
}

// ConvertToEmailAccount 비밀번호 설정 후 소셜 연동 해제 (일반 회원 전환)
func (s *authService) ConvertToEmailAccount(userID uint, provider, newPassword string) error {
	slog.Info("Convert to email account attempt", "user_id", userID, "provider", provider)

	// 사용자 조회
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	// 해당 소셜 계정이 연동되어 있는지 확인
	socialAccount, err := s.userRepo.FindSocialAccountByUserIDAndProvider(userID, provider)
	if err != nil {
		return err
	}

	// 비밀번호 해시
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return errors.NewInternalError(errors.ErrCodeHashPassword, "Failed to hash password", err)
	}

	// 외부 OAuth 제공자에 토큰 revoke 요청 (Best effort)
	if socialAccount.AccessToken != nil && *socialAccount.AccessToken != "" {
		if err := s.oauthRevokeService.RevokeToken(provider, *socialAccount.AccessToken, socialAccount.RefreshToken); err != nil {
			slog.Warn("Failed to revoke external OAuth token (continuing with conversion)",
				"error", err,
				"user_id", userID,
				"provider", provider,
			)
		} else {
			slog.Info("External OAuth token revoked successfully",
				"user_id", userID,
				"provider", provider,
			)
		}
	}

	// 트랜잭션: 비밀번호 설정 + 소셜 계정 삭제
	err = s.userRepo.WithTrx(func(txRepo repository.UserRepository) error {
		// 비밀번호 설정
		if err := txRepo.UpdatePassword(userID, hashedPassword); err != nil {
			return err
		}

		// 소셜 계정 삭제
		if err := txRepo.DeleteSocialAccount(userID, provider); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		slog.Error("Failed to convert to email account", "error", err, "user_id", userID)
		return errors.NewInternalError(errors.ErrCodeSocialUnlinkFailed, "Failed to convert to email account", err)
	}

	slog.Info("Account converted to email successfully",
		"user_id", userID,
		"email", logger.SanitizeEmail(user.Email),
	)
	return nil
}

// DeleteAccount 회원 탈퇴
func (s *authService) DeleteAccount(userID uint) error {
	slog.Info("Delete account attempt", "user_id", userID)

	// 사용자 조회 (존재 확인)
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	// 연동된 소셜 계정들의 외부 OAuth 토큰 revoke (Best effort)
	socialAccounts, err := s.userRepo.FindSocialAccountsByUserID(userID)
	if err == nil && len(socialAccounts) > 0 {
		for _, sa := range socialAccounts {
			if sa.AccessToken != nil && *sa.AccessToken != "" {
				if err := s.oauthRevokeService.RevokeToken(sa.Provider, *sa.AccessToken, sa.RefreshToken); err != nil {
					slog.Warn("Failed to revoke external OAuth token during account deletion",
						"error", err,
						"user_id", userID,
						"provider", sa.Provider,
					)
				} else {
					slog.Info("External OAuth token revoked during account deletion",
						"user_id", userID,
						"provider", sa.Provider,
					)
				}
			}
		}
	}

	// 트랜잭션: 관련 데이터 삭제 (CASCADE가 설정되어 있지만 명시적으로 처리)
	err = s.userRepo.WithTrx(func(txRepo repository.UserRepository) error {
		// pending social links 삭제
		_ = txRepo.DeletePendingSocialLinksByUserID(userID)

		// 유저 삭제 (CASCADE로 social_accounts, refresh_tokens 등 자동 삭제)
		if err := txRepo.DeleteUser(userID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		slog.Error("Failed to delete account", "error", err, "user_id", userID)
		return errors.NewInternalError(errors.ErrCodeAccountDeleteFailed, "Failed to delete account", err)
	}

	slog.Info("Account deleted successfully",
		"user_id", userID,
		"email", logger.SanitizeEmail(user.Email),
	)
	return nil
}

// SaveSocialAccountTokens OAuth 토큰을 소셜 계정에 저장
func (s *authService) SaveSocialAccountTokens(userID uint, provider string, accessToken, refreshToken *string, tokenExpiry *int64) error {
	slog.Debug("Saving social account tokens",
		"user_id", userID,
		"provider", provider,
		"has_access_token", accessToken != nil,
		"has_refresh_token", refreshToken != nil,
	)

	if refreshToken == nil || *refreshToken == "" {
		existingAccount, err := s.userRepo.FindSocialAccountByUserIDAndProvider(userID, provider)
		if err == nil && existingAccount.RefreshToken != nil && *existingAccount.RefreshToken != "" {
			slog.Debug("Preserving existing refresh token", "user_id", userID, "provider", provider)
			refreshToken = existingAccount.RefreshToken
		}
	}

	if err := s.userRepo.UpdateSocialAccountTokens(userID, provider, accessToken, refreshToken, tokenExpiry); err != nil {
		slog.Error("Failed to save social account tokens",
			"error", err,
			"user_id", userID,
			"provider", provider,
		)
		return err
	}

	slog.Info("Social account tokens saved successfully",
		"user_id", userID,
		"provider", provider,
	)
	return nil
}
