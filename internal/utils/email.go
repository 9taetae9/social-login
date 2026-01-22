package utils

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

// 이메일 설정
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
}

// 인증 이메일 발송 (외국인 회원가입용)
func SendVerificationEmail(to, token, appURL string, cfg EmailConfig) error {
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.FromEmail)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "[Account Verification] Please verify your email address")

	verificationURL := fmt.Sprintf("%s/api/v1/auth/verify/%s", appURL, token)

	body := fmt.Sprintf(`
	<div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
		<div style="text-align: center; margin-bottom: 30px;">
			<h1 style="color: #667eea; margin: 0;">Welcome!</h1>
			<p style="color: #888; font-size: 14px;">Thank you for signing up</p>
		</div>

		<h2 style="color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px;">Verify Your Email Address</h2>

		<p style="color: #555; line-height: 1.6;">Hello,</p>
		<p style="color: #555; line-height: 1.6;">Please click the button below to verify your email address and complete your registration:</p>

		<p style="margin: 30px 0; text-align: center;">
			<a href="%s" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 14px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Verify Email Address</a>
		</p>

		<p style="color: #555; line-height: 1.6;">Or copy and paste this URL into your browser:</p>
		<p style="background: #f5f5f5; padding: 12px; border-radius: 4px; word-break: break-all; font-size: 13px; color: #667eea;">%s</p>

		<div style="background: linear-gradient(135deg, #fff3cd 0%%, #ffeeba 100%%); border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
			<p style="color: #856404; margin: 0;"><strong>⏰ This link will expire in 24 hours.</strong></p>
		</div>

		<hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

		<p style="color: #888; font-size: 12px; line-height: 1.6;">
			If you didn't create an account, you can safely ignore this email.<br>
			This is an automated message, please do not reply.
		</p>
	</div>
    `, verificationURL, verificationURL)

	m.SetBody("text/html", body)

	//SMTP 포트를 정수로 변환
	port := 587
	if cfg.SMTPPort != "" {
		fmt.Sscanf(cfg.SMTPPort, "%d", &port)
	}

	d := gomail.NewDialer(cfg.SMTPHost, port, cfg.SMTPUsername, cfg.SMTPPassword)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// 소셜 계정 연동 인증 이메일 발송
func SendSocialLinkVerificationEmail(to, emailToken, provider, appURL string, cfg EmailConfig) error {
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.FromEmail)
	m.SetHeader("To", to)
	m.SetHeader("Subject", fmt.Sprintf("[계정 연동] %s 소셜 계정 연동 확인", provider))

	verificationURL := fmt.Sprintf("%s/api/v1/auth/confirm-social-link/%s", appURL, emailToken)

	body := fmt.Sprintf(`
	<div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
		<h2 style="color: #667eea;">소셜 계정 연동 확인</h2>
		<p>안녕하세요,</p>
		<p><strong>%s</strong> 소셜 계정을 기존 계정에 연동하려는 요청이 있었습니다.</p>
		<p>본인이 요청한 경우, 아래 버튼을 클릭하여 연동을 완료해주세요:</p>
		<p style="margin: 30px 0;">
			<a href="%s" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">소셜 계정 연동하기</a>
		</p>
		<p>또는 다음 URL을 브라우저에 복사하세요:</p>
		<p style="background: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">%s</p>
		<p style="color: #e74c3c;"><strong>이 링크는 15분 동안 유효합니다.</strong></p>
		<hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
		<p style="color: #888; font-size: 12px;">본인이 요청하지 않은 경우, 이 이메일을 무시해주세요.</p>
	</div>
    `, provider, verificationURL, verificationURL)

	m.SetBody("text/html", body)

	port := 587
	if cfg.SMTPPort != "" {
		fmt.Sscanf(cfg.SMTPPort, "%d", &port)
	}

	d := gomail.NewDialer(cfg.SMTPHost, port, cfg.SMTPUsername, cfg.SMTPPassword)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send social link verification email: %w", err)
	}

	return nil
}
