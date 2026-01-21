package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/9taetae9/social-login/internal/config"
)

// OAuthRevokeService 외부 OAuth 제공자와의 연결 해제를 담당하는 서비스
type OAuthRevokeService interface {
	RevokeToken(provider string, accessToken string, refreshToken *string) error
}

type oauthRevokeService struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewOAuthRevokeService(cfg *config.Config) OAuthRevokeService {
	return &oauthRevokeService{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RevokeToken 제공자별로 토큰 revoke 수행
func (s *oauthRevokeService) RevokeToken(provider string, accessToken string, refreshToken *string) error {
	switch provider {
	case "google":
		return s.revokeGoogleToken(accessToken, refreshToken)
	case "naver":
		return s.revokeNaverToken(accessToken, refreshToken)
	case "kakao":
		return s.revokeKakaoToken(accessToken, refreshToken)
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}
}

// --------------------------------------------------------------------------
// 1. Google
// 전략: Refresh Token으로 해제 시도 -> 실패 시 Access Token으로 해제 시도
// --------------------------------------------------------------------------
func (s *oauthRevokeService) revokeGoogleToken(accessToken string, refreshToken *string) error {
	// 1. Refresh Token이 있다면 우선 시도 (더 강력한 권한 취소)
	if refreshToken != nil && *refreshToken != "" {
		err := s.sendGoogleRevokeRequest(*refreshToken)
		if err == nil {
			slog.Info("Google token revoked successfully using Refresh Token")
			return nil
		}
		slog.Warn("Failed to revoke using Refresh Token, falling back to Access Token", "error", err)
	}

	// 2. Refresh Token이 없거나 실패했다면 Access Token으로 시도
	err := s.sendGoogleRevokeRequest(accessToken)
	if err != nil {
		// 최종 실패 시 로그만 남기고 에러는 무시 (Best Effort)
		slog.Warn("Failed to revoke Google token (Access Token)", "error", err)
		return nil
	}

	slog.Info("Google token revoked successfully using Access Token")
	return nil
}

func (s *oauthRevokeService) sendGoogleRevokeRequest(token string) error {
	revokeURL := "https://oauth2.googleapis.com/revoke"
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequest("POST", revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// --------------------------------------------------------------------------
// 2. Naver
// 전략: Access Token으로 해제 시도 -> (401 등) 실패 시 토큰 갱신 -> 재시도
// --------------------------------------------------------------------------
func (s *oauthRevokeService) revokeNaverToken(accessToken string, refreshToken *string) error {
	// 1. 첫 시도
	err := s.sendNaverRevokeRequest(accessToken)
	if err == nil {
		slog.Info("Naver token revoked successfully")
		return nil
	}
	slog.Info("First attempt to revoke Naver token failed", "error", err)

	// 2. 실패했고 Refresh Token이 있다면 갱신 시도
	if refreshToken != nil && *refreshToken != "" {
		slog.Info("Trying to refresh Naver token for revoke")

		newAccessToken, refreshErr := s.refreshNaverAccessToken(*refreshToken)
		if refreshErr != nil {
			slog.Warn("Failed to refresh Naver token", "error", refreshErr)
			return nil // 갱신 실패는 무시
		}

		// 3. 갱신된 토큰으로 재시도
		if retryErr := s.sendNaverRevokeRequest(newAccessToken); retryErr != nil {
			slog.Warn("Naver revoke failed even after refresh", "error", retryErr)
		} else {
			slog.Info("Naver token revoked successfully after refresh")
		}
		return nil
	}

	slog.Warn("Naver revoke failed and no refresh token available")
	return nil
}

// sendNaverRevokeRequest: 실패 시 반드시 error를 반환해야 함
func (s *oauthRevokeService) sendNaverRevokeRequest(accessToken string) error {
	revokeURL := "https://nid.naver.com/oauth2.0/token"
	params := url.Values{}
	params.Set("grant_type", "delete")
	params.Set("client_id", s.cfg.Oauth.NaverClientID)
	params.Set("client_secret", s.cfg.Oauth.NaverClientSecret)
	params.Set("access_token", accessToken)

	// 네이버 문서는 GET/POST 모두 지원하지만, 파라미터를 Query String에 포함하는 방식은 GET이 안전
	fullURL := revokeURL + "?" + params.Encode()

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 200 OK가 아니면 에러 반환
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	// 네이버는 200 OK 안에도 error 필드가 있을 수 있음
	if strings.Contains(string(body), "\"error\"") {
		return fmt.Errorf("api error response: %s", string(body))
	}

	return nil
}

func (s *oauthRevokeService) refreshNaverAccessToken(refreshToken string) (string, error) {
	tokenURL := "https://nid.naver.com/oauth2.0/token"
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", s.cfg.Oauth.NaverClientID)
	params.Set("client_secret", s.cfg.Oauth.NaverClientSecret)
	params.Set("refresh_token", refreshToken)

	fullURL := tokenURL + "?" + params.Encode()
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access token received")
	}
	return result.AccessToken, nil
}

// --------------------------------------------------------------------------
// 3. Kakao
// 전략: Access Token으로 해제 시도 -> 실패 시 토큰 갱신 -> 재시도
// --------------------------------------------------------------------------
func (s *oauthRevokeService) revokeKakaoToken(accessToken string, refreshToken *string) error {
	// 1. 첫 시도
	err := s.sendKakaoUnlinkRequest(accessToken)
	if err == nil {
		slog.Info("Kakao unlink successful")
		return nil
	}
	slog.Info("First attempt to unlink Kakao failed", "error", err)

	// 2. 실패했고 Refresh Token이 있다면 갱신 시도
	if refreshToken != nil && *refreshToken != "" {
		slog.Info("Trying to refresh Kakao token for unlink")

		newAccessToken, refreshErr := s.refreshKakaoAccessToken(*refreshToken)
		if refreshErr != nil {
			slog.Warn("Failed to refresh Kakao token", "error", refreshErr)
			return nil
		}

		// 3. 갱신된 토큰으로 재시도
		if retryErr := s.sendKakaoUnlinkRequest(newAccessToken); retryErr != nil {
			slog.Warn("Kakao unlink failed even after refresh", "error", retryErr)
		} else {
			slog.Info("Kakao unlink successful after refresh")
		}
		return nil
	}

	slog.Warn("Kakao unlink failed and no refresh token available")
	return nil
}

// sendKakaoUnlinkRequest: 실패 시 반드시 error를 반환해야 함
func (s *oauthRevokeService) sendKakaoUnlinkRequest(accessToken string) error {
	unlinkURL := "https://kapi.kakao.com/v1/user/unlink"

	req, err := http.NewRequest("POST", unlinkURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 200 OK가 아니면 에러 반환
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (s *oauthRevokeService) refreshKakaoAccessToken(refreshToken string) (string, error) {
	tokenURL := "https://kauth.kakao.com/oauth/token"
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", s.cfg.Oauth.KakaoClientID)
	data.Set("client_secret", s.cfg.Oauth.KakaoClientSecret)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

// package service

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log/slog"
// 	"net/http"
// 	"net/url"
// 	"strings"
// 	"time"

// 	"github.com/9taetae9/social-login/internal/config"
// )

// // OAuthRevokeService 외부 OAuth 제공자와의 연결 해제를 담당하는 서비스
// type OAuthRevokeService interface {
// 	// RevokeToken 제공자별로 토큰을 revoke하여 연결 해제
// 	RevokeToken(provider string, accessToken string, refreshToken *string) error
// }

// type oauthRevokeService struct {
// 	cfg        *config.Config
// 	httpClient *http.Client
// }

// // NewOAuthRevokeService OAuthRevokeService 생성자
// func NewOAuthRevokeService(cfg *config.Config) OAuthRevokeService {
// 	return &oauthRevokeService{
// 		cfg: cfg,
// 		httpClient: &http.Client{
// 			Timeout: 10 * time.Second,
// 		},
// 	}
// }

// // RevokeToken 제공자별로 토큰 revoke 수행
// func (s *oauthRevokeService) RevokeToken(provider string, accessToken string, refreshToken *string) error {
// 	switch provider {
// 	case "google":
// 		return s.revokeGoogleToken(accessToken, refreshToken)
// 	case "naver":
// 		return s.revokeNaverToken(accessToken, refreshToken)
// 	case "kakao":
// 		return s.revokeKakaoToken(accessToken, refreshToken)
// 	default:
// 		return fmt.Errorf("unsupported provider: %s", provider)
// 	}
// }

// // revokeGoogleToken Google OAuth 토큰 revoke
// // API: POST https://oauth2.googleapis.com/revoke?token={token}
// // Content-Type: application/x-www-form-urlencoded
// // 성공: 200, 실패: 400
// func (s *oauthRevokeService) revokeGoogleToken(accessToken string, refreshToken *string) error {
// 	revokeURL := "https://oauth2.googleapis.com/revoke"

// 	tokenToSend := accessToken
// 	if refreshToken != nil && *refreshToken != "" {
// 		tokenToSend = *refreshToken
// 	}

// 	// Form 데이터 생성
// 	data := url.Values{}
// 	data.Set("token", tokenToSend)

// 	req, err := http.NewRequest("POST", revokeURL, strings.NewReader(data.Encode()))
// 	if err != nil {
// 		slog.Error("Failed to create Google revoke request", "error", err)
// 		return fmt.Errorf("failed to create revoke request: %w", err)
// 	}

// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// 	resp, err := s.httpClient.Do(req)
// 	if err != nil {
// 		slog.Error("Failed to send Google revoke request", "error", err)
// 		return fmt.Errorf("failed to send revoke request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	// 응답 본문 읽기 (디버깅용)
// 	body, _ := io.ReadAll(resp.Body)

// 	if resp.StatusCode != http.StatusOK {
// 		// Google은 이미 revoke된 토큰이나 유효하지 않은 토큰에 대해 400을 반환
// 		// 이 경우에도 연동 해제 자체는 진행할 수 있음
// 		slog.Warn("Google token revoke returned non-200",
// 			"status", resp.StatusCode,
// 			"body", string(body),
// 		)
// 		// 에러로 처리하지 않고 경고만 남김 (Best effort)
// 		return nil
// 	}

// 	slog.Info("Google token revoked successfully")
// 	return nil
// }

// // revokeNaverToken Naver OAuth 연동 해제
// // API: GET/POST https://nid.naver.com/oauth2.0/token
// // 파라미터: grant_type=delete, client_id, client_secret, access_token
// // 주의: 유효한 access_token 필요 (만료된 토큰 불가)
// func (s *oauthRevokeService) revokeNaverToken(accessToken string, refreshToken *string) error {
// 	// 1. 첫 시도
// 	err := s.sendNaverRevokeRequest(accessToken)
// 	if err == nil {
// 		return nil
// 	}

// 	// 2. 실패 && Refresh Token이 존재한다면 갱신 시도
// 	if refreshToken != nil && *refreshToken != "" {
// 		slog.Info("Naver revoke failed, trying to refresh token and retry")

// 		newAccessToken, refreshErr := s.refreshNaverAccessToken(*refreshToken)
// 		if refreshErr != nil {
// 			slog.Warn("Failed to refresh Naver token for revoke", "error", refreshErr)
// 			return nil
// 		}

// 		// 3. 갱신된 토큰으로 재시도
// 		if retryErr := s.sendNaverRevokeRequest(newAccessToken); retryErr != nil {
// 			slog.Warn("Naver revoke failed even after refresh", "error", retryErr)
// 		}
// 		return nil
// 	}

// 	slog.Warn("Naver revoke failed and no refresh token avilable", "error", err)
// 	return nil
// }

// func (s *oauthRevokeService) sendNaverRevokeRequest(accessToken string) error {
// 	revokeURL := "https://nid.naver.com/oauth2.0/token"

// 	// Query 파라미터 생성
// 	params := url.Values{}
// 	params.Set("grant_type", "delete")
// 	params.Set("client_id", s.cfg.Oauth.NaverClientID)
// 	params.Set("client_secret", s.cfg.Oauth.NaverClientSecret)
// 	params.Set("access_token", accessToken)

// 	fullURL := revokeURL + "?" + params.Encode()

// 	req, err := http.NewRequest("GET", fullURL, nil)
// 	if err != nil {
// 		slog.Error("Failed to create Naver revoke request", "error", err)
// 		return fmt.Errorf("failed to create revoke request: %w", err)
// 	}

// 	resp, err := s.httpClient.Do(req)
// 	if err != nil {
// 		slog.Error("Failed to send Naver revoke request", "error", err)
// 		return fmt.Errorf("failed to send revoke request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	// 응답 본문 읽기
// 	body, _ := io.ReadAll(resp.Body)

// 	if resp.StatusCode != http.StatusOK {
// 		slog.Warn("Naver token revoke returned non-200",
// 			"status", resp.StatusCode,
// 			"body", string(body),
// 		)
// 		// Best effort - 에러로 처리하지 않음
// 		return nil
// 	}

// 	slog.Info("Naver token revoked successfully", "response", string(body))
// 	return nil
// }

// func (s *oauthRevokeService) refreshNaverAccessToken(refreshToken string) (string, error) {
// 	tokenURL := "https://nid.naver.com/oauth2.0/token"
// 	params := url.Values{}
// 	params.Set("grant_type", "refresh_token")
// 	params.Set("client_id", s.cfg.Oauth.NaverClientID)
// 	params.Set("client_secret", s.cfg.Oauth.NaverClientSecret)
// 	params.Set("refresh_token", refreshToken)

// 	fullURL := tokenURL + "?" + params.Encode()
// 	req, err := http.NewRequest("GET", fullURL, nil)
// 	if err != nil {
// 		return "", err
// 	}

// 	resp, err := s.httpClient.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return "", fmt.Errorf("status %d", resp.StatusCode)
// 	}

// 	var result struct {
// 		AccessToken string `json:"access_token"`
// 	}
// 	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
// 		return "", err
// 	}
// 	if result.AccessToken == "" {
// 		return "", fmt.Errorf("no access token in response")
// 	}
// 	return result.AccessToken, nil

// }

// // revokeKakaoToken Kakao OAuth 연결 끊기
// // API: POST https://kapi.kakao.com/v1/user/unlink
// // Header: Authorization: Bearer {access_token}
// // Content-Type: application/x-www-form-urlencoded;charset=utf-8
// func (s *oauthRevokeService) revokeKakaoToken(accessToken string, refreshToken *string) error {
// 	// 1. 첫 시도
// 	err := s.sendKakaoUnlinkRequest(accessToken)
// 	if err == nil {
// 		return nil
// 	}

// 	// 2. 실패했고 Refresh Token이 있다면 갱신 시도
// 	if refreshToken != nil && *refreshToken != "" {
// 		slog.Info("Kakao unlink failed, trying to refresh token and retry")

// 		newAccessToken, refreshErr := s.refreshKakaoAccessToken(*refreshToken)
// 		if refreshErr != nil {
// 			slog.Warn("Failed to refresh Kakao token for unlink", "error", refreshErr)
// 			return nil
// 		}

// 		// 3. 갱신된 토큰으로 재시도
// 		if retryErr := s.sendKakaoUnlinkRequest(newAccessToken); retryErr != nil {
// 			slog.Warn("Kakao unlink failed even after refresh", "error", retryErr)
// 		}
// 		return nil
// 	}

// 	slog.Warn("Kakao unlink failed and no refresh token available", "error", err)
// 	return nil
// }

// func (s *oauthRevokeService) sendKakaoUnlinkRequest(accessToken string) error {
// 	unlinkURL := "https://kapi.kakao.com/v1/user/unlink"

// 	req, err := http.NewRequest("POST", unlinkURL, nil)
// 	if err != nil {
// 		return err
// 	}
// 	req.Header.Set("Authorization", "Bearer "+accessToken)
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

// 	resp, err := s.httpClient.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	body, _ := io.ReadAll(resp.Body)
// 	if resp.StatusCode != http.StatusOK {
// 		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
// 	}

// 	slog.Info("Kakao unlink successful")
// 	return nil
// }

// func (s *oauthRevokeService) refreshKakaoAccessToken(refreshToken string) (string, error) {
// 	tokenURL := "https://kauth.kakao.com/oauth/token"
// 	data := url.Values{}
// 	data.Set("grant_type", "refresh_token")
// 	data.Set("client_id", s.cfg.Oauth.KakaoClientID)
// 	data.Set("client_secret", s.cfg.Oauth.KakaoClientSecret)
// 	data.Set("refresh_token", refreshToken)

// 	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
// 	if err != nil {
// 		return "", err
// 	}
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

// 	resp, err := s.httpClient.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
// 	}

// 	var result struct {
// 		AccessToken string `json:"access_token"`
// 	}
// 	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
// 		return "", err
// 	}
// 	return result.AccessToken, nil
// }

// // func (s *oauthRevokeService) revokeKakaoToken(accessToken string) error {
// // 	unlinkURL := "https://kapi.kakao.com/v1/user/unlink"

// // 	req, err := http.NewRequest("POST", unlinkURL, nil)
// // 	if err != nil {
// // 		slog.Error("Failed to create Kakao unlink request", "error", err)
// // 		return fmt.Errorf("failed to create unlink request: %w", err)
// // 	}

// // 	req.Header.Set("Authorization", "Bearer "+accessToken)
// // 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

// // 	resp, err := s.httpClient.Do(req)
// // 	if err != nil {
// // 		slog.Error("Failed to send Kakao unlink request", "error", err)
// // 		return fmt.Errorf("failed to send unlink request: %w", err)
// // 	}
// // 	defer resp.Body.Close()

// // 	// 응답 본문 읽기
// // 	body, _ := io.ReadAll(resp.Body)

// // 	if resp.StatusCode != http.StatusOK {
// // 		slog.Warn("Kakao unlink returned non-200",
// // 			"status", resp.StatusCode,
// // 			"body", string(body),
// // 		)
// // 		// Best effort - 에러로 처리하지 않음
// // 		return nil
// // 	}

// // 	slog.Info("Kakao unlink successful", "response", string(body))
// // 	return nil
// // }
