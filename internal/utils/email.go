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

// 인증 이메일 발송
func SendVerificationEmail(to, token, appURL string, cfg EmailConfig) error {
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.FromEmail)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "이메일 인증")

	verificationURL := fmt.Sprintf("%s/api/v1/auth/verify/%s", appURL, token)

	body := fmt.Sprintf(`
	<h2>이메일 인증</h2>
        <p>안녕하세요,</p>
        <p>아래 링크를 클릭하여 이메일 인증을 완료해주세요:</p>
        <p><a href="%s">이메일 인증하기</a></p>
        <p>또는 다음 URL을 브라우저에 복사하세요:</p>
        <p>%s</p>
        <p>이 링크는 24시간 동안 유효합니다.</p>
        <br>
        <p>감사합니다.</p>
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
