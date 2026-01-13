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
