package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
	Oauth	 OAuthConfig
	App      AppConfig
}

type ServerConfig struct {
	Port    string
	GinMode string
}

type DatabaseConfig struct {
	Host      string
	Port      string
	User      string
	Password  string
	DBName    string
	Charset   string
	ParseTime string
	Loc       string
}

type JWTConfig struct {
	Secret             string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
}

type OAuthConfig struct{
	GoogleClientID string
	GoogleClientSecret string
	GoogleRedirectURL string
	NaverClientID string
	NaverClientSecret string
	NaverRedirectURL string
}

type AppConfig struct {
	URL         string
	FrontendURL string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not fount")
	}

	//JWT 토큰 만료 시간 파싱
	accessTokenExpiry, _ := time.ParseDuration(getEnv("JWT_ACCESS_TOKEN_EXPIRY", "15m"))
	refreshTokenExpiry, _ := time.ParseDuration(getEnv("JWT_REFRESH_TOKEN_EXPIRY", "168h"))

	return &Config{
		Server: ServerConfig{
			Port:    getEnv("SERVER_PORT", "8080"),
			GinMode: getEnv("GIN_MODE", "debug"),
		},
		Database: DatabaseConfig{
			Host:      getEnv("DB_HOST", "localhost"),
			Port:      getEnv("DB_PORT", "3306"),
			User:      getEnv("DB_USER", "auth_user"),
			Password:  getEnv("DB_PASSWORD", ""),
			DBName:    getEnv("DB_NAME", "auth_service"),
			Charset:   getEnv("DB_CHARSET", "utf8mb4"),
			ParseTime: getEnv("DB_PARSE_TIME", "True"),
			Loc:       getEnv("DB_LOC", "Local"),
		},
		JWT: JWTConfig{
			Secret:             getEnv("JWT_SECRET", "your-secret-key"),
			AccessTokenExpiry:  accessTokenExpiry,
			RefreshTokenExpiry: refreshTokenExpiry,
		},
		Email: EmailConfig{
			SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:     getEnv("SMTP_PORT", "587"),
			SMTPUsername: getEnv("SMTP_USERNAME", ""),
			SMTPPassword: getEnv("SMTP_PASSWORD", ""),
			FromEmail:    getEnv("EMAIL_FROM", "noreply@yourapp.com"),
		},
		Oauth: OAuthConfig{
			GoogleClientID: getEnv("GOOGLE_CLIENT_ID", ""),
			GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
			GoogleRedirectURL: getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
			NaverClientID: getEnv("NAVER_CLIENT_ID", ""),
			NaverClientSecret: getEnv("NAVER_CLIENT_SECRET", ""),
			NaverRedirectURL: getEnv("NAVER_REDIRECT_URL", "http://localhost:8080/api/v1/auth/naver/callback"),
		},
		App: AppConfig{
			URL:         getEnv("APP_URL", "http://localhost:8080"),
			FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
