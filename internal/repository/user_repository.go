package repository

import (
	"log/slog"
	"time"

	"github.com/9taetae9/social-login/internal/errors"
	"github.com/9taetae9/social-login/internal/models"
	"gorm.io/gorm"
)

// 사용자 레포지토리 인터페이스
type UserRepository interface {
	Create(user *models.User) error
	FindByEmail(email string) (*models.User, error)
	FindByPhoneNumber(phone string) (*models.User, error)
	FindByID(id uint) (*models.User, error)
	UpdateEmailVerified(userId uint) error
	UpdatePassword(userID uint, passwordHash string) error
	DeleteUser(userID uint) error

	// 소셜 로그인 관련
	// 제공자와 식별자로 유저 조회
	FindSocialAccount(provider, socialID string) (*models.SocialAccount, error)
	FindSocialAccountsByUserID(userID uint) ([]models.SocialAccount, error)
	FindSocialAccountByUserIDAndProvider(userID uint, provider string) (*models.SocialAccount, error)
	CreateSocialAccount(socialAccount *models.SocialAccount) error
	UpdateSocialAccountTokens(userID uint, provider string, accessToken, refreshToken *string, tokenExpiry *int64) error
	DeleteSocialAccount(userID uint, provider string) error

	// 기존 계정에 소셜 정보 연동 (계정 통합)
	UpdateSocialInfo(userID uint, provider, socialID string) error

	// 이메일 인증 관련
	CreateEmailVerification(verification *models.EmailVerification) error
	FindEmailVerificationByToken(token string) (*models.EmailVerification, error)
	MarkEmailVerificationAsUsed(id uint) error

	// 리프레시 토큰 관련
	CreateRefreshToken(token *models.RefreshToken) error
	FindRefreshTokenByToken(token string) (*models.RefreshToken, error)
	DeleteRefreshToken(token string) error
	DeleteExpiredTokens() error

	// 트랜잭션 헬퍼 메서드 - 트랜잭션이 적용된 Repo를 인자로 넘겨줌
	WithTrx(fn func(txRepo UserRepository) error) error

	// PendingSocialLink 관련
	CreatePendingSocialLink(link *models.PendingSocialLink) error
	FindPendingSocialLinkByToken(linkToken string) (*models.PendingSocialLink, error)
	FindPendingSocialLinkByEmailToken(emailToken string) (*models.PendingSocialLink, error)
	DeletePendingSocialLink(id uint) error
	DeletePendingSocialLinksByUserID(userID uint) error

	// 비밀번호 재설정 토큰 관련
	CreatePasswordResetToken(token *models.PasswordResetToken) error
	FindPasswordResetTokenByToken(token string) (*models.PasswordResetToken, error)
	MarkPasswordResetTokenAsUsed(id uint) error
	DeleteExpiredPasswordResetTokens() error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *models.User) error {
	err := r.db.Create(user).Error
	if err != nil {
		slog.Error("Failed to create user", "error", err)
		return errors.Wrap(err, errors.ErrCodeUserCreate, "Failed to create user", 500)
	}
	slog.Debug("User created successfully", "user_id", user.ID)
	return nil
}

func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Not found는 에러가 아님 (정상 케이스)
			return nil, errors.New(errors.ErrCodeUserNotFound, "User not found", 404)
		}
		slog.Error("Database error finding user by email", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find user", 500)
	}
	return &user, nil
}

func (r *userRepository) FindByPhoneNumber(phone string) (*models.User, error) {
	var user models.User
	err := r.db.Where("phone_number = ?", phone).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeUserNotFound, "User not found", 404)
		}
		slog.Error("Database error finding user by phone", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find user", 500)
	}
	return &user, nil
}

func (r *userRepository) FindByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeUserNotFound, "User not found", 404)
		}
		slog.Error("Database error finding user by ID", "error", err, "user_id", id)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find user", 500)
	}
	return &user, nil
}

// 소셜 계정 조회
func (r *userRepository) FindSocialAccount(provider, socialID string) (*models.SocialAccount, error) {
	var socialAccount models.SocialAccount
	// social_accounts 테이블에서 조회
	err := r.db.Where("provider = ? AND social_id = ?", provider, socialID).First(&socialAccount).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeSocialNotFound, "Social account not found", 404)
		}
		slog.Error("Database error finding social account", "error", err, "provider", provider)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find social account", 500)
	}
	return &socialAccount, nil
}

// 소셜 계정 생성 (연동)
func (r *userRepository) CreateSocialAccount(socialAccount *models.SocialAccount) error {
	err := r.db.Create(socialAccount).Error
	if err != nil {
		slog.Error("Failed to create social account", "error", err, "provider", socialAccount.Provider)
		return errors.Wrap(err, errors.ErrCodeSocialCreateFailed, "Failed to create social account", 500)
	}
	slog.Debug("Social account created successfully", "social_account_id", socialAccount.ID, "provider", socialAccount.Provider)
	return nil
}

// 유저의 연동된 소셜 계정 목록 조회
func (r *userRepository) FindSocialAccountsByUserID(userID uint) ([]models.SocialAccount, error) {
	var socialAccounts []models.SocialAccount
	err := r.db.Where("user_id = ?", userID).Find(&socialAccounts).Error
	if err != nil {
		slog.Error("Failed to find social accounts by user ID", "error", err, "user_id", userID)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find social accounts", 500)
	}
	slog.Debug("Social accounts found", "user_id", userID, "count", len(socialAccounts))
	return socialAccounts, nil
}

// 기존 유저에게 소셜 정보 업데이트(계정 통합용)
func (r *userRepository) UpdateSocialInfo(userID uint, provider, socialID string) error {
	updates := map[string]interface{}{
		"provider":       provider,
		"social_id":      socialID,
		"email_verified": true,
	}
	err := r.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error
	if err != nil {
		slog.Error("Failed to update social info", "error", err, "user_id", userID)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to update social info", 500)
	}
	slog.Debug("Social info updated successfully", "user_id", userID, "provider", provider)
	return nil
}

func (r *userRepository) UpdateEmailVerified(userID uint) error {
	err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified", true).Error
	if err != nil {
		slog.Error("Failed to update email verified status", "error", err, "user_id", userID)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to update email verified status", 500)
	}
	slog.Debug("Email verified status updated", "user_id", userID)
	return nil
}

func (r *userRepository) CreateEmailVerification(verification *models.EmailVerification) error {
	err := r.db.Create(verification).Error
	if err != nil {
		slog.Error("Failed to create email verification", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to create email verification", 500)
	}
	slog.Debug("Email verification created", "verification_id", verification.ID)
	return nil
}

func (r *userRepository) FindEmailVerificationByToken(token string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	err := r.db.Where("token  = ? AND verified = ? AND expires_at > ?",
		token, false, time.Now()).First(&verification).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeVerificationInvalid, "Invalid or expired verification token", 400)
		}
		slog.Error("Database error finding email verification", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find email verification", 500)
	}
	return &verification, nil
}

// 이메일 인증을 인증됨으로 표시
func (r *userRepository) MarkEmailVerificationAsUsed(id uint) error {
	err := r.db.Model(&models.EmailVerification{}).Where("id = ?", id).Update("verified", true).Error
	if err != nil {
		slog.Error("Failed to mark email verification as used", "error", err, "verification_id", id)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to mark verification as used", 500)
	}
	slog.Debug("Email verification marked as used", "verification_id", id)
	return nil
}

// 리프레시 토큰 생성
func (r *userRepository) CreateRefreshToken(token *models.RefreshToken) error {
	err := r.db.Create(token).Error
	if err != nil {
		slog.Error("Failed to create refresh token", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to create refresh token", 500)
	}
	slog.Debug("Refresh token created", "user_id", token.UserID)
	return nil
}

// 토큰으로 리프레시 토큰 조회
func (r *userRepository) FindRefreshTokenByToken(token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&refreshToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeTokenNotFound, "Invalid or expired refresh token", 401)
		}
		slog.Error("Database error finding refresh token", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find refresh token", 500)
	}
	return &refreshToken, nil
}

// 리프레시 토큰 삭제
func (r *userRepository) DeleteRefreshToken(token string) error {
	err := r.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error
	if err != nil {
		slog.Error("Failed to delete refresh token", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete refresh token", 500)
	}
	slog.Debug("Refresh token deleted")
	return nil
}

// 만료된 토큰 삭제
func (r *userRepository) DeleteExpiredTokens() error {
	// 만료된 리프레시 토큰 삭제
	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error; err != nil {
		slog.Error("Failed to delete expired refresh tokens", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete expired tokens", 500)
	}

	// 만료된 이메일 인증 토큰 삭제
	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&models.EmailVerification{}).Error; err != nil {
		slog.Error("Failed to delete expired email verifications", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete expired verifications", 500)
	}

	slog.Debug("Expired tokens deleted")
	return nil
}

func (r *userRepository) WithTrx(fn func(txRepo UserRepository) error) error {
	// GORM Transaction 시작
	return r.db.Transaction(func(tx *gorm.DB) error {
		// 트랜잭션이 시작된 DB 객체(tx)를 가진 새로운 Repository 생성
		txRepo := NewUserRepository(tx)
		// 비지니스 로직 실행 (여기서 에러 반환 시 자동 Rollback)
		return fn(txRepo)
	})
}

// PendingSocialLink 생성
func (r *userRepository) CreatePendingSocialLink(link *models.PendingSocialLink) error {
	err := r.db.Create(link).Error
	if err != nil {
		slog.Error("Failed to create pending social link", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to create pending social link", 500)
	}
	slog.Debug("Pending social link created", "link_id", link.ID, "user_id", link.UserID)
	return nil
}

// LinkToken으로 PendingSocialLink 조회
func (r *userRepository) FindPendingSocialLinkByToken(linkToken string) (*models.PendingSocialLink, error) {
	var link models.PendingSocialLink
	err := r.db.Where("link_token = ?", linkToken).First(&link).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeSocialLinkNotFound, "Social link not found", 404)
		}
		slog.Error("Database error finding pending social link", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find pending social link", 500)
	}
	return &link, nil
}

// EmailToken으로 PendingSocialLink 조회
func (r *userRepository) FindPendingSocialLinkByEmailToken(emailToken string) (*models.PendingSocialLink, error) {
	var link models.PendingSocialLink
	err := r.db.Where("email_token = ?", emailToken).First(&link).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeSocialLinkNotFound, "Social link not found", 404)
		}
		slog.Error("Database error finding pending social link by email token", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find pending social link", 500)
	}
	return &link, nil
}

// PendingSocialLink 삭제
func (r *userRepository) DeletePendingSocialLink(id uint) error {
	err := r.db.Delete(&models.PendingSocialLink{}, id).Error
	if err != nil {
		slog.Error("Failed to delete pending social link", "error", err, "link_id", id)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete pending social link", 500)
	}
	slog.Debug("Pending social link deleted", "link_id", id)
	return nil
}

// 유저의 모든 PendingSocialLink 삭제
func (r *userRepository) DeletePendingSocialLinksByUserID(userID uint) error {
	err := r.db.Where("user_id = ?", userID).Delete(&models.PendingSocialLink{}).Error
	if err != nil {
		slog.Error("Failed to delete pending social links by user", "error", err, "user_id", userID)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete pending social links", 500)
	}
	slog.Debug("Pending social links deleted for user", "user_id", userID)
	return nil
}

// 유저의 특정 소셜 계정 조회
func (r *userRepository) FindSocialAccountByUserIDAndProvider(userID uint, provider string) (*models.SocialAccount, error) {
	var socialAccount models.SocialAccount
	err := r.db.Where("user_id = ? AND provider = ?", userID, provider).First(&socialAccount).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeSocialNotLinked, "Social account not linked", 404)
		}
		slog.Error("Database error finding social account by user and provider", "error", err, "user_id", userID, "provider", provider)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find social account", 500)
	}
	return &socialAccount, nil
}

// 유저의 특정 소셜 계정 삭제
func (r *userRepository) DeleteSocialAccount(userID uint, provider string) error {
	result := r.db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&models.SocialAccount{})
	if result.Error != nil {
		slog.Error("Failed to delete social account", "error", result.Error, "user_id", userID, "provider", provider)
		return errors.Wrap(result.Error, errors.ErrCodeDBQuery, "Failed to delete social account", 500)
	}
	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeSocialNotLinked, "Social account not linked", 404)
	}
	slog.Debug("Social account deleted", "user_id", userID, "provider", provider)
	return nil
}

// 소셜 계정 토큰 업데이트
func (r *userRepository) UpdateSocialAccountTokens(userID uint, provider string, accessToken, refreshToken *string, tokenExpiry *int64) error {
	updates := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_expiry":  tokenExpiry,
	}
	result := r.db.Model(&models.SocialAccount{}).Where("user_id = ? AND provider = ?", userID, provider).Updates(updates)
	if result.Error != nil {
		slog.Error("Failed to update social account tokens", "error", result.Error, "user_id", userID, "provider", provider)
		return errors.Wrap(result.Error, errors.ErrCodeDBQuery, "Failed to update social account tokens", 500)
	}
	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeSocialNotLinked, "Social account not linked", 404)
	}
	slog.Debug("Social account tokens updated", "user_id", userID, "provider", provider)
	return nil
}

// 유저 비밀번호 업데이트
func (r *userRepository) UpdatePassword(userID uint, passwordHash string) error {
	err := r.db.Model(&models.User{}).Where("id = ?", userID).Update("password_hash", passwordHash).Error
	if err != nil {
		slog.Error("Failed to update password", "error", err, "user_id", userID)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to update password", 500)
	}
	slog.Debug("Password updated successfully", "user_id", userID)
	return nil
}

// 비밀번호 재설정 토큰 생성
func (r *userRepository) CreatePasswordResetToken(token *models.PasswordResetToken) error {
	err := r.db.Create(token).Error
	if err != nil {
		slog.Error("Failed to create password reset token", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to create password reset token", 500)
	}
	slog.Debug("Password reset token created", "token_id", token.ID, "user_id", token.UserID)
	return nil
}

// 토큰으로 비밀번호 재설정 토큰 조회
func (r *userRepository) FindPasswordResetTokenByToken(token string) (*models.PasswordResetToken, error) {
	var resetToken models.PasswordResetToken
	err := r.db.Where("token = ?", token).First(&resetToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodePasswordResetTokenInvalid, "Invalid password reset token", 400)
		}
		slog.Error("Database error finding password reset token", "error", err)
		return nil, errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to find password reset token", 500)
	}
	return &resetToken, nil
}

// 비밀번호 재설정 토큰을 사용됨으로 표시
func (r *userRepository) MarkPasswordResetTokenAsUsed(id uint) error {
	err := r.db.Model(&models.PasswordResetToken{}).Where("id = ?", id).Update("used", true).Error
	if err != nil {
		slog.Error("Failed to mark password reset token as used", "error", err, "token_id", id)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to mark password reset token as used", 500)
	}
	slog.Debug("Password reset token marked as used", "token_id", id)
	return nil
}

// 만료된 비밀번호 재설정 토큰 삭제
func (r *userRepository) DeleteExpiredPasswordResetTokens() error {
	err := r.db.Where("expires_at < ? OR used = ?", time.Now(), true).Delete(&models.PasswordResetToken{}).Error
	if err != nil {
		slog.Error("Failed to delete expired password reset tokens", "error", err)
		return errors.Wrap(err, errors.ErrCodeDBQuery, "Failed to delete expired password reset tokens", 500)
	}
	slog.Debug("Expired password reset tokens deleted")
	return nil
}

// 유저 삭제
func (r *userRepository) DeleteUser(userID uint) error {
	result := r.db.Delete(&models.User{}, userID)
	if result.Error != nil {
		slog.Error("Failed to delete user", "error", result.Error, "user_id", userID)
		return errors.Wrap(result.Error, errors.ErrCodeDBQuery, "Failed to delete user", 500)
	}
	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeUserNotFound, "User not found", 404)
	}
	slog.Debug("User deleted successfully", "user_id", userID)
	return nil
}
