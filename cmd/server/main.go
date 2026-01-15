package main

import (
	"log"

	"github.com/9taetae9/social-login/internal/config"
	"github.com/9taetae9/social-login/internal/database"
	"github.com/9taetae9/social-login/internal/handler"
	"github.com/9taetae9/social-login/internal/middleware"
	"github.com/9taetae9/social-login/internal/repository"
	"github.com/9taetae9/social-login/internal/service"
	"github.com/gin-gonic/gin"
)

func main() {
	// 설정 로드
	cfg := config.Load()

	// MariaDB 연결
	if err := database.Connect(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Gin 모드 설정
	gin.SetMode(cfg.Server.GinMode)

	// 의존성 주입
	userRepo := repository.NewUserRepository(database.GetDB())
	authService := service.NewAuthService(userRepo, cfg)
	authHandler := handler.NewAuthHandler(authService, cfg)

	// Gin 라우터 설정
	router := gin.Default()

	//CORS 미들웨어
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// API 라우트 그룹
	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			// 인증 불필요 엔드포인트
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.GET("/verify/:token", authHandler.VerifyEmail)
			auth.POST("/resend-verify", authHandler.ResendVerificationEmail)

			// 인증 필요 엔드포인트
			auth.POST("/logout", authHandler.Logout)

			// 소셜 로그인 엔드포인트
			auth.GET("/google/login", authHandler.GoogleLogin)
			auth.GET("/google/callback", authHandler.GoogleCallback)
			auth.GET("/naver/login", authHandler.NaverLogin)
			auth.GET("/naver/callback", authHandler.NaverCallback)
			auth.GET("/kakao/login", authHandler.KakaoLogin)
			auth.GET("/kakao/callback", authHandler.KakaoCallback)
		}

		protected := v1.Group("/protected")
		protected.Use(middleware.AuthMiddleware(cfg))
		{
			protected.GET("/profile", func(c *gin.Context) {
				userID := c.GetUint("user_id")
				email := c.GetString("email")

				c.JSON(200, gin.H{
					"user_id": userID,
					"email":   email,
					"message": "This is a protected route",
				})
			})
		}
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":   "ok",
			"database": "connected",
		})
	})

	addr := ":" + cfg.Server.Port
	log.Printf("Server starting on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
