package repository

import (
	"time"

	"github.com/9taetae9/social-login/internal/models"
	"gorm.io/gorm"
)

// 사용자 레포지토리 인터페이스
type UserRepository interface {
	Create(user *models.User) error
	FindByEmail(email string) (*models.User, error)
	FindByID(id uint) (*models.User, error)
	UpdateEmailVerified(userId uint) error

	// 소셜 로그인 관련
	// 제공자와 식별자로 유저 조회
	FindByProviderAndSocialID(provider, socialID string) (*models.User, error)

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
}

type userRepository struct {
    db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// 소셜 제공자와 식별자로 유저 조회
func (r *userRepository) FindByProviderAndSocialID(provider, socialID string) (*models.User, error){
	var user models.User
	err := r.db.Where("provider = ? AND social_id = ?", provider, socialID).First(&user).Error
	if err != nil{
		return nil, err
	}
	return &user, nil
}

// 기존 유저에게 소셜 정보 업데이트(계정 통합용)
func (r *userRepository) UpdateSocialInfo(userID uint, provider, socialID string) error{
	updates := map[string]interface{}{
		"provider": provider,
		"social_id": socialID,
		"email_verified": true,
	}
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error
}

func (r *userRepository) UpdateEmailVerified(userID uint) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified", true).Error
}

func (r *userRepository) CreateEmailVerification(verification *models.EmailVerification) error {
	return r.db.Create(verification).Error
}

func (r *userRepository) FindEmailVerificationByToken(token string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	err := r.db.Where("token  = ? AND verified = ? AND expires_at > ?",
		token, false, time.Now()).First(&verification).Error
	if err != nil {
		return nil, err
	}
	return &verification, nil
}

// 이메일 인증을 인증됨으로 표시
func (r *userRepository) MarkEmailVerificationAsUsed(id uint) error {
	return r.db.Model(&models.EmailVerification{}).Where("id = ?", id).Update("verified", true).Error
}

// 리프레시 토큰 생성
func (r *userRepository) CreateRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

// 토큰으로 리프레시 토큰 조회
func (r *userRepository) FindRefreshTokenByToken(token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&refreshToken).Error
	if err != nil {
		return nil, err
	}
	return &refreshToken, nil
}

// 리프레시 토큰 삭제
func (r *userRepository) DeleteRefreshToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error
}

// 만료된 토큰 삭제
func (r *userRepository) DeleteExpiredTokens() error {
	// 만료된 리프레시 토큰 삭제
	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error; err != nil {
		return err
	}

	// 만료된 이메일 인증 토큰 삭제
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.EmailVerification{}).Error
}
