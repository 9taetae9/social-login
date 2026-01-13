package models

import "time"

type User struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Email         string    `gorm:"uniqueIndex;not null;size:255" json:"email"`
	//PasswordHash *string: not null -> null 허용 변경(소셜 로그인 유저 비번 X)
	/*
	(Pointer 사용 이유): Go 언어에서 string 타입의 제로값은 "" (빈 문자열)입니다. 
	하지만 DB에서는 NULL과 ""은 다릅니다. 
	string (포인터)를 사용해야 nil일 때 DB에 진짜 NULL이 들어갑니다.
	*/
	PasswordHash *string    `gorm:"size:255" json:"-"` // json:"-"는 JSON 응답에서 제외, 
	Provider string `gorm:"not null;default:'email',size:20;index:idx_provider_social_id" json:"provider"`
	SocialID string `gorm:"size:255;index:idx_provider_social_id" json:"social_id"`
	EmailVerified bool      `gorm:"default:false" json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}


func(User) TableName() string{
	return "users"
}

type EmailVerification struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    UserID    uint      `gorm:"not null;index" json:"user_id"`
    Token     string    `gorm:"uniqueIndex;not null;size:255" json:"token"`
    ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
    Verified  bool      `gorm:"default:false" json:"verified"`
    CreatedAt time.Time `json:"created_at"`
    User      User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (EmailVerification) TableName() string{
	return "email_verifications"
}

type RefreshToken struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    UserID    uint      `gorm:"not null;index" json:"user_id"`
    Token     string    `gorm:"uniqueIndex;not null;size:255" json:"token"`
    ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
    CreatedAt time.Time `json:"created_at"`
    User      User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (RefreshToken) TableName() string{
	return "refresh_tokens"
}