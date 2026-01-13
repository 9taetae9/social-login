package models

import "time"

type User struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Email         string    `gorm:"uniqueIndex;not null;size:255" json:"email"`
	PasswordHash  string    `gorm:"not null;size:255" json:"-"` // json:"-"는 JSON 응답에서 제외
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