package models

import "time"

type UserType string

const (
	UserTypeKorean    UserType = "KOREAN"
	UserTypeForeigner UserType = "FOREIGNER"
)

type User struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Email string `gorm:"uniqueIndex;not null;size:255" json:"email"`
	//PasswordHash *string: not null -> null 허용 변경(소셜 로그인 유저 비번 X)
	PasswordHash *string `gorm:"size:255" json:"-"` // json:"-"는 JSON 응답에서 제외,

	UserType    *UserType `gorm:"type:varchar(20); " json:"user_type"`     // KOREAN or FOREIGNER
	PhoneNumber *string   `gorm:"uniqueIndex;size:20" json:"phone_number"` // 한국인 필수, 유니크 (NULL 허용)
	CountryCode string    `gorm:"size:5;" json:"country_code"`             // 국가 코드

	EmailVerified  bool            `gorm:"default:false" json:"email_verified"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	SocialAccounts []SocialAccount `gorm:"foreignKey:UserID" json:"social_accounts,omitempty"`
}

func (User) TableName() string {
	return "users"
}

type SocialAccount struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"not null;index" json:"user_id"`
	Provider  string    `gorm:"not null;size:20" json:"provider"`
	SocialID  string    `gorm:"not null;size:255" json:"social_id"`
	Email     string    `gorm:"size:255" json:"email"` // 소셜 이메일
	CreatedAt time.Time `json:"created_at"`
}

func (SocialAccount) TableName() string {
	return "social_accounts"
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

func (EmailVerification) TableName() string {
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

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

type PendingSocialLink struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	UserID     uint      `gorm:"not null;index" json:"user_id"`
	Provider   string    `gorm:"not null;size:20" json:"provider"`
	SocialID   string    `gorm:"not null;size:255" json:"social_id"`
	Email      string    `gorm:"not null;size:255" json:"email"`
	LinkToken  string    `gorm:"uniqueIndex;not null;size:255" json:"link_token"`
	EmailToken *string   `gorm:"uniqueIndex;size:255" json:"email_token"`
	ExpiresAt  time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	User       User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (PendingSocialLink) TableName() string {
	return "pending_social_links"
}
