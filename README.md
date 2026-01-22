# 🔐 Social Login Service

Go 언어 기반의 이메일 및 소셜 로그인(Google, Naver, Kakao) 인증 서비스입니다.

## 📋 목차

- [프로젝트 개요](#-프로젝트-개요)
- [주요 기능](#-주요-기능)
- [기술 스택](#-기술-스택)
- [아키텍처](#-아키텍처)
- [데이터베이스 스키마](#-데이터베이스-스키마)
- [API 엔드포인트](#-api-엔드포인트)
- [설치 및 실행](#-설치-및-실행)
- [환경 변수 설정](#-환경-변수-설정)
- [디렉토리 구조](#-디렉토리-구조)
- [테스트 방법](#-테스트-방법)
- [보안 특성](#-보안-특성)
- [향후 개선 사항](#-향후-개선-사항)

## 🎯 프로젝트 개요

이메일 기반 회원가입/로그인과 소셜 로그인(Google, Naver, Kakao)을 지원하는 RESTful API 인증 서비스입니다. JWT 기반 토큰 인증을 사용하며, 소셜 계정 자동 통합 기능을 제공합니다. 내국인과 외국인을 구분하여 회원가입을 처리하며, 한국인의 경우 전화번호 인증을 필수로 합니다.

### 핵심 기능 하이라이트

- **다중 소셜 로그인 지원**: 한 계정에 여러 소셜 계정 연동 가능 (Google, Naver, Kakao)
- **검증 기반 계정 통합**: 동일 이메일로 소셜 로그인 시 비밀번호 또는 이메일 인증 후 계정 연동 (보안 강화)
- **내국인/외국인 구분**: 회원 유형에 따른 차별화된 회원가입 (전화번호 필수 여부)
- **트랜잭션 보장**: GORM 트랜잭션으로 데이터 일관성 보장
- **CSRF 방지**: OAuth2 State 파라미터 암호화 검증

## ✨ 주요 기능

### 1. 이메일 인증 시스템
- 회원가입 시 이메일 인증 토큰 발송
- 24시간 유효한 UUID 토큰
- SMTP를 통한 이메일 발송 (Mailtrap 샌드박스)
- 인증 메일 재발송 기능
- **반응형 이메일 템플릿**: 그라데이션 버튼, 깔끔한 레이아웃의 HTML 이메일

### 2. JWT 기반 인증
- **Access Token**: 15분 유효 (API 요청 인증)
- **Refresh Token**: 7일 유효 (Access Token 갱신)
- HMAC-SHA256 서명
- Refresh Token DB 저장 및 무효화

### 3. 소셜 로그인
- **Google**: OpenID Connect (id_token 활용)
- **Naver**: OAuth2 + Profile API (OIDC id_token에 email 미포함)
- **Kakao**: OpenID Connect (id_token 활용)
- **성능 최적화**: Google/Kakao는 id_token JWT 파싱으로 추가 API 호출 제거
- 3가지 시나리오 자동 처리:
  1. 기존 소셜 계정 로그인
  2. 기존 이메일 계정에 소셜 연동 (검증 후 통합)
  3. 신규 소셜 회원가입

### 4. 소셜 계정 연동 검증
- 기존 이메일 가입자가 소셜 로그인 시도 시 **검증 필요**
- **비밀번호 검증**: 기존 계정의 비밀번호로 본인 확인 (즉시 연동)
- **이메일 토큰 검증**: 인증 이메일 링크 클릭으로 본인 확인
  - **온디맨드 이메일 발송**: 사용자가 이메일 인증을 선택한 경우에만 발송 (비용 최적화)
- `pending_social_links` 테이블로 대기 상태 관리
- 15분 유효 토큰으로 보안 강화

### 5. 내국인/외국인 회원 구분
- **회원 유형**: KOREAN (내국인), FOREIGNER (외국인)
- **전화번호 인증**: 한국인 회원가입 시 필수
- **국가 코드 지원**: 다국적 사용자 지원

### 6. 비밀번호 보안
- bcrypt 해싱 (cost 10)
- 최소 8자 이상 검증

### 7. 계정 관리
- **연동된 소셜 계정 조회**: 현재 계정에 연동된 모든 소셜 계정 목록 확인
- **소셜 계정 연동 해제**: 연동된 소셜 계정을 개별적으로 해제
  - 마지막 인증 수단 보호: 비밀번호 없이 유일한 소셜 계정 해제 시 경고
  - **OAuth 토큰 Revoke**: 연동 해제 시 외부 OAuth 제공자에 토큰 무효화 요청 (Google, Naver, Kakao)
- **일반 회원 전환**: 소셜 전용 계정에 비밀번호를 설정하여 이메일 로그인 가능하게 전환
- **회원 탈퇴**: 계정 및 관련 데이터 완전 삭제 (CASCADE)

### 8. 클라이언트 통신
- **postMessage API**: 소셜 로그인 콜백 결과를 부모 창에 안전하게 전달
- **팝업 기반 로그인**: 메인 페이지 이동 없이 팝업에서 소셜 로그인 처리

## 🛠 기술 스택

### Backend
- **언어**: Go 1.24+
- **프레임워크**: Gin (HTTP 웹 프레임워크)
- **ORM**: GORM
- **데이터베이스**: MariaDB 10.3+

### 주요 라이브러리
| 라이브러리 | 용도 |
|-----------|------|
| `gin-gonic/gin` | HTTP 서버 및 라우팅 |
| `gorm.io/gorm` | ORM 및 데이터베이스 접근 |
| `golang-jwt/jwt` | JWT 토큰 생성/검증 |
| `golang.org/x/oauth2` | OAuth2 클라이언트 |
| `golang.org/x/crypto/bcrypt` | 비밀번호 해싱 |
| `go-playground/validator` | 요청 데이터 검증 |
| `gopkg.in/gomail.v2` | SMTP 이메일 발송 |
| `joho/godotenv` | 환경 변수 관리 |

## 🏗 아키텍처

### 계층 구조 (Layered Architecture)

```
┌─────────────────────────────────────────┐
│   Handler Layer (HTTP 요청/응답 처리)    │
├─────────────────────────────────────────┤
│   Service Layer (비즈니스 로직)          │
├─────────────────────────────────────────┤
│   Repository Layer (데이터 접근)         │
├─────────────────────────────────────────┤
│   GORM + MariaDB (데이터 저장소)         │
└─────────────────────────────────────────┘
```

### 의존성 주입 (Dependency Injection)

```go
// main.go
userRepo := repository.NewUserRepository(db)
authService := service.NewAuthService(userRepo, cfg)
authHandler := handler.NewAuthHandler(authService, cfg)
```

### 인증 플로우

#### 일반 로그인 플로우
```
회원가입 (POST /register)
   ↓
이메일 인증 토큰 발송
   ↓
이메일 인증 (GET /verify/:token)
   ↓
로그인 (POST /login)
   ↓
JWT 토큰 발급 (Access + Refresh)
   ↓
보호된 API 접근 (Authorization: Bearer {token})
```

#### 소셜 로그인 플로우 (OpenID Connect)
```
소셜 로그인 시작 (GET /google|naver|kakao/login)
   ↓
OAuth2 제공자로 리다이렉트 (scope: openid 포함)
   ↓
사용자 인증 및 동의
   ↓
콜백 처리 (GET /google|naver|kakao/callback)
   ↓
State 파라미터 검증 (CSRF 방지)
   ↓
Authorization Code → Token 교환 (access_token + id_token 반환)
   ↓
id_token (JWT) 파싱 → 유저 정보 추출 (추가 API 호출 불필요)
   ↓
SocialLogin 서비스 호출
   ├─ [Case 1] 기존 소셜 계정 → JWT 토큰 발급
   ├─ [Case 2] 기존 이메일 계정 → 연동 검증 필요 (아래 플로우)
   └─ [Case 3] 신규 회원 → 계정 생성 → JWT 토큰 발급
```

> **성능 최적화**: 기존 OAuth2 방식에서는 Token 교환 후 별도 UserInfo API를 호출했으나,
> OpenID Connect의 id_token을 활용하여 네트워크 왕복을 1회 줄였습니다. (약 100~300ms 개선)

#### 소셜 계정 연동 검증 플로우 (Case 2)
```
기존 이메일 계정 발견
   ↓
PendingSocialLink 생성 (link_token + email_token)
   ↓
클라이언트에 검증 필요 응답 (409 Conflict)
   ├─ link_token, email, provider, has_password 반환
   ↓
사용자 검증 방법 선택
   ├─ [방법 1] 비밀번호 입력 (POST /confirm-social-link)
   │     └─ 비밀번호 검증 → 소셜 계정 연동 → JWT 발급
   └─ [방법 2] 이메일 인증 선택
         ├─ 이메일 발송 요청 (POST /send-social-link-email)
         ├─ 인증 이메일 발송
         └─ 이메일 링크 클릭 (GET /confirm-social-link/:token)
               └─ 토큰 검증 → 소셜 계정 연동 → JWT 발급
```

> **비용 최적화**: 이메일은 사용자가 이메일 인증을 선택한 경우에만 발송됩니다.
> 비밀번호로 바로 인증하는 사용자에게는 불필요한 이메일이 발송되지 않습니다.

## 🗃 데이터베이스 스키마

### ERD 개요

```
┌─────────────────────────┐
│        users            │
│  - id (PK)              │
│  - email (UNIQUE)       │
│  - password_hash        │
│  - user_type            │ (KOREAN/FOREIGNER)
│  - phone_number         │ (한국인 필수)
│  - country_code         │
│  - email_verified       │
└─────────────────────────┘
      │
      │ (1:N)
      ├─────────────►┌────────────────────────┐
      │              │  social_accounts       │
      │              │  - id (PK)             │
      │              │  - user_id (FK)        │
      │              │  - provider            │
      │              │  - social_id           │
      │              │  - email               │
      │              └────────────────────────┘
      │
      │ (1:N)
      ├─────────────►┌────────────────────────┐
      │              │  email_verifications   │
      │              └────────────────────────┘
      │
      │ (1:N)
      ├─────────────►┌────────────────────────┐
      │              │    refresh_tokens      │
      │              └────────────────────────┘
      │
      ├─────────────►┌────────────────────────┐
      │              │  sms_verifications     │
      │              │  (전화번호 인증)        │
      │              └────────────────────────┘
      │
      └─────────────►┌────────────────────────┐
                     │  pending_social_links  │
                     │  (소셜 연동 대기)       │
                     └────────────────────────┘
```

### 테이블 상세

#### users 테이블
| 컬럼 | 타입 | 제약 | 설명 |
|------|------|------|------|
| id | INT | PK, AUTO_INCREMENT | 사용자 고유 ID |
| email | VARCHAR(255) | UNIQUE, NOT NULL | 이메일 |
| password_hash | VARCHAR(255) | NULL | 비밀번호 해시 (소셜 로그인 시 NULL) |
| user_type | VARCHAR(20) | NULL | KOREAN/FOREIGNER |
| phone_number | VARCHAR(20) | UNIQUE, NULL | 전화번호 (한국인 필수) |
| country_code | VARCHAR(5) | NULL | 국가 코드 |
| email_verified | BOOLEAN | DEFAULT FALSE | 이메일 인증 여부 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 생성 시각 |
| updated_at | TIMESTAMP | ON UPDATE CURRENT_TIMESTAMP | 수정 시각 |

#### social_accounts 테이블
| 컬럼 | 타입 | 제약 | 설명 |
|------|------|------|------|
| id | INT | PK, AUTO_INCREMENT | 고유 ID |
| user_id | INT | FK, NOT NULL | users.id |
| provider | VARCHAR(20) | NOT NULL | google/naver/kakao |
| social_id | VARCHAR(255) | NOT NULL | 소셜 플랫폼 고유 ID |
| email | VARCHAR(255) | NULL | 소셜 계정 이메일 |
| access_token | VARCHAR(2048) | NULL | OAuth Access Token (연동 해제 시 revoke용) |
| refresh_token | VARCHAR(2048) | NULL | OAuth Refresh Token |
| token_expiry | BIGINT | NULL | 토큰 만료 시간 (Unix timestamp) |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 생성 시각 |
| updated_at | TIMESTAMP | ON UPDATE CURRENT_TIMESTAMP | 수정 시각 |

**제약 조건:**
- UNIQUE INDEX: (provider, social_id) - 동일 제공자 내 중복 방지
- UNIQUE INDEX: (user_id, provider) - 한 유저가 같은 제공자를 중복 연동 불가

#### sms_verifications 테이블
| 컬럼 | 타입 | 제약 | 설명 |
|------|------|------|------|
| id | INT | PK, AUTO_INCREMENT | 고유 ID |
| phone_number | VARCHAR(20) | NOT NULL | 전화번호 |
| code | VARCHAR(6) | NOT NULL | 인증 코드 (6자리) |
| verified | BOOLEAN | DEFAULT FALSE | 인증 완료 여부 |
| expires_at | TIMESTAMP | NOT NULL | 만료 시각 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 생성 시각 |

## 🌐 API 엔드포인트

### Base URL
```
http://localhost:8080/api/v1
```

### 인증 관련 API

#### 회원가입 및 로그인
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| POST | `/auth/register` | 이메일 회원가입 | ❌ |
| POST | `/auth/login` | 이메일 로그인 | ❌ |
| GET | `/auth/verify/:token` | 이메일 인증 | ❌ |
| POST | `/auth/resend-verify` | 인증 메일 재발송 | ❌ |

#### 소셜 계정 연동
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| POST | `/auth/confirm-social-link` | 비밀번호로 소셜 연동 확인 | ❌ |
| GET | `/auth/confirm-social-link/:token` | 이메일 토큰으로 소셜 연동 확인 | ❌ |
| POST | `/auth/send-social-link-email` | 소셜 연동 인증 이메일 발송 요청 | ❌ |

#### 토큰 관리
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| POST | `/auth/refresh` | Access Token 갱신 | ❌ |
| POST | `/auth/logout` | 로그아웃 (토큰 무효화) | ❌ |

#### Google 소셜 로그인
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| GET | `/auth/google/login` | Google 로그인 시작 | ❌ |
| GET | `/auth/google/callback` | Google 콜백 처리 | ❌ |

#### Naver 소셜 로그인
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| GET | `/auth/naver/login` | Naver 로그인 시작 | ❌ |
| GET | `/auth/naver/callback` | Naver 콜백 처리 | ❌ |

#### Kakao 소셜 로그인
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| GET | `/auth/kakao/login` | Kakao 로그인 시작 | ❌ |
| GET | `/auth/kakao/callback` | Kakao 콜백 처리 | ❌ |

#### 보호된 라우트
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| GET | `/protected/profile` | 사용자 프로필 조회 | ✅ |

#### 계정 관리
| Method | Endpoint | 설명 | 인증 필요 |
|--------|----------|------|----------|
| GET | `/protected/social-accounts` | 연동된 소셜 계정 목록 조회 | ✅ |
| DELETE | `/protected/social-accounts/:provider` | 소셜 계정 연동 해제 | ✅ |
| POST | `/protected/convert-to-email` | 일반 회원 전환 (비밀번호 설정) | ✅ |
| DELETE | `/protected/account` | 회원 탈퇴 | ✅ |

### 요청/응답 예시

#### 회원가입 (내국인)
```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "user_type": "KOREAN",
  "phone_number": "01012345678"
}
```

#### 회원가입 (외국인)
```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "foreigner@example.com",
  "password": "password123",
  "user_type": "FOREIGNER"
}
```

**응답 (201 Created)**
```json
{
  "message": "Registration successful. Please check your email to verify your account before logging in.",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "user_type": "KOREAN",
    "phone_number": "01012345678",
    "country_code": "KR",
    "email_verified": false,
    "created_at": "2024-01-14T10:00:00Z"
  }
}
```

#### 로그인
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**응답 (200 OK)**
```json
{
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "user_type": "KOREAN",
      "phone_number": "01012345678",
      "country_code": "KR",
      "email_verified": true,
      "social_accounts": []
    }
  }
}
```

#### 보호된 API 호출
```bash
GET /api/v1/protected/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**응답 (200 OK)**
```json
{
  "user_id": 1,
  "email": "user@example.com",
  "user_type": "KOREAN",
  "phone_number": "01012345678",
  "country_code": "KR",
  "message": "This is a protected route"
}
```

#### 연동된 소셜 계정 조회
```bash
GET /api/v1/protected/social-accounts
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**응답 (200 OK)**
```json
{
  "message": "Linked social accounts retrieved successfully",
  "data": {
    "email": "user@example.com",
    "has_password": true,
    "social_accounts": [
      {
        "provider": "google",
        "email": "user@gmail.com",
        "linked_at": "2024-01-14T10:00:00Z"
      },
      {
        "provider": "kakao",
        "email": "user@kakao.com",
        "linked_at": "2024-01-15T15:30:00Z"
      }
    ]
  }
}
```

#### 소셜 계정 연동 해제
```bash
DELETE /api/v1/protected/social-accounts/google
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**응답 (200 OK) - 연동 해제 성공**
```json
{
  "message": "Social account unlinked successfully",
  "data": {
    "success": true,
    "is_last_auth": false,
    "has_password": true,
    "social_accounts_count": 1
  }
}
```

**응답 (200 OK) - 마지막 인증 수단 경고**
```json
{
  "message": "Cannot unlink: this is your only authentication method",
  "data": {
    "success": false,
    "is_last_auth": true,
    "has_password": false,
    "social_accounts_count": 1
  }
}
```

#### 일반 회원 전환 (비밀번호 설정 후 소셜 연동 해제)
```bash
POST /api/v1/protected/convert-to-email
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "provider": "google",
  "new_password": "newPassword123"
}
```

**응답 (200 OK)**
```json
{
  "message": "Account converted to email successfully. Social account unlinked."
}
```

#### 회원 탈퇴
```bash
DELETE /api/v1/protected/account
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**응답 (200 OK)**
```json
{
  "message": "Account deleted successfully"
}
```

#### 소셜 연동 인증 이메일 발송 요청
```bash
POST /api/v1/auth/send-social-link-email
Content-Type: application/json

{
  "link_token": "550e8400-e29b-41d4-a716-446655440000"
}
```

**응답 (200 OK)**
```json
{
  "message": "Verification email sent successfully"
}
```

## 🚀 설치 및 실행

### 필수 요구사항

- Go 1.24 이상
- MariaDB 10.3 이상
- Git

### 1. 프로젝트 클론

```bash
git clone <repository-url>
cd social-login
```

### 2. Go 모듈 설치

```bash
go mod download
```

### 3. 데이터베이스 설정

```bash
# MariaDB 접속
mysql -u root -p

# 데이터베이스 및 유저 생성
CREATE DATABASE auth_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'auth1234';
GRANT ALL PRIVILEGES ON auth_service.* TO 'auth_user'@'localhost';
FLUSH PRIVILEGES;

# 스키마 생성
USE auth_service;
SOURCE database/schema.sql;
```
### 4. 소셜 로그인 설정

#### Google OAuth2
1. [Google Cloud Console](https://console.cloud.google.com/) 접속
2. 프로젝트 생성
3. "API 및 서비스" → "OAuth 동의 화면" 설정
4. "사용자 인증 정보" → "OAuth 2.0 클라이언트 ID" 생성
   - 애플리케이션 유형: 웹 애플리케이션
   - 승인된 리디렉션 URI: `http://localhost:8080/api/v1/auth/google/callback`
5. 클라이언트 ID와 Secret을 `.env`에 입력

#### Naver Login
1. [네이버 개발자센터](https://developers.naver.com/apps) 접속
2. 애플리케이션 등록
   - 애플리케이션 이름: 원하는 이름
   - 사용 API: 네이버 로그인
   - 서비스 URL: `http://localhost:8080`
   - Callback URL: `http://localhost:8080/api/v1/auth/naver/callback`
3. 제공 정보: 이메일, 이름 선택
4. 클라이언트 ID와 Secret을 `.env`에 입력

#### Kakao Login
1. [카카오 개발자센터](https://developers.kakao.com/) 접속
2. 애플리케이션 추가
   - 앱 이름: 원하는 이름
3. 앱 설정
   - "카카오 로그인" 활성화
   - Redirect URI: `http://localhost:8080/api/v1/auth/kakao/callback`
   - 동의 항목: 이메일 (필수)
4. REST API 키를 `.env`에 입력

### 5. 서버 실행

```bash
go run cmd/server/main.go
```

서버가 정상적으로 시작되면:
```
Server starting on :8080
```


## ⚙️ 환경 변수 설정

### 필수 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `SERVER_PORT` | 서버 포트 | `8080` |
| `DB_HOST` | 데이터베이스 호스트 | `localhost` |
| `DB_PORT` | 데이터베이스 포트 | `3306` |
| `DB_USER` | 데이터베이스 유저 | `auth_user` |
| `DB_PASSWORD` | 데이터베이스 비밀번호 | - |
| `DB_NAME` | 데이터베이스 이름 | `auth_service` |
| `JWT_SECRET` | JWT 서명 키 | - |

### 선택 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `GIN_MODE` | Gin 실행 모드 | `debug` |
| `JWT_ACCESS_TOKEN_EXPIRY` | Access Token 유효기간 | `15m` |
| `JWT_REFRESH_TOKEN_EXPIRY` | Refresh Token 유효기간 | `168h` |

### 소셜 로그인 환경 변수

소셜 로그인을 사용하지 않는 경우 해당 변수는 생략 가능합니다.

| 변수명 | 설명 |
|--------|------|
| `GOOGLE_CLIENT_ID` | Google OAuth2 클라이언트 ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 클라이언트 Secret |
| `GOOGLE_REDIRECT_URL` | Google 콜백 URL |
| `NAVER_CLIENT_ID` | Naver 애플리케이션 클라이언트 ID |
| `NAVER_CLIENT_SECRET` | Naver 애플리케이션 클라이언트 Secret |
| `NAVER_REDIRECT_URL` | Naver 콜백 URL |
| `KAKAO_CLIENT_ID` | Kakao REST API 키 |
| `KAKAO_CLIENT_SECRET` | Kakao 클라이언트 Secret (선택) |
| `KAKAO_REDIRECT_URL` | Kakao 콜백 URL |

## 📁 디렉토리 구조

```
social-login/
├── cmd/
│   └── server/
│       └── main.go                 # 애플리케이션 진입점
├── internal/
│   ├── config/
│   │   └── config.go               # 환경 설정 관리
│   ├── database/
│   │   └── mariadb.go              # MariaDB 연결 관리
│   ├── handler/
│   │   └── auth_handler.go         # HTTP 요청 핸들러
│   ├── middleware/
│   │   └── auth_middleware.go      # JWT 인증 미들웨어
│   ├── models/
│   │   └── user.go                 # 데이터 모델 정의
│   ├── repository/
│   │   └── user_repository.go      # 데이터 접근 계층
│   ├── service/
│   │   └── auth_service.go         # 비즈니스 로직 계층
│   └── utils/
│       ├── email.go                # 이메일 발송
│       ├── jwt.go                  # JWT 토큰 생성/검증
│       └── password.go             # 비밀번호 암호화/검증
├── database/
│   └── schema.sql                  # 데이터베이스 스키마
├── test/
│   └── index.html                  # 웹 테스트 UI
├── .env                            # 환경 변수 파일
├── go.mod                          # Go 모듈 정의
├── go.sum                          # 의존성 체크섬
└── README.md                       # 프로젝트 문서
```

### 주요 파일 설명

- **`cmd/server/main.go`**: 서버 시작점, 라우터 설정, 의존성 주입
- **`internal/handler/auth_handler.go`**: HTTP 요청 처리 및 응답 (Google, Naver, Kakao 콜백 포함)
- **`internal/service/auth_service.go`**: 비즈니스 로직 (회원가입, 로그인, 소셜 로그인)
- **`internal/repository/user_repository.go`**: 데이터베이스 CRUD 작업
- **`internal/middleware/auth_middleware.go`**: JWT 토큰 검증 미들웨어
- **`internal/models/user.go`**: User, SocialAccount, EmailVerification, RefreshToken 모델 정의
- **`database/schema.sql`**: 데이터베이스 테이블 생성 SQL

## 🧪 테스트 방법

### 1. 웹 UI 테스트

프로젝트에는 통합 테스트를 위한 웹 UI가 포함되어 있습니다.

```bash
# 서버 실행
go run cmd/server/main.go

# 브라우저에서 test/index.html 파일 열기
```

웹 UI에서 다음 기능을 테스트할 수 있습니다:
- ✅ Health Check
- ✅ 이메일 회원가입 (내국인/외국인)
- ✅ 이메일 인증
- ✅ 로그인
- ✅ Google 소셜 로그인
- ✅ Naver 소셜 로그인
- ✅ Kakao 소셜 로그인
- ✅ 토큰 갱신
- ✅ 로그아웃
- ✅ 보호된 라우트 접근

### 2. cURL 테스트

#### 회원가입 (내국인)
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email":"korean@example.com",
    "password":"password123",
    "user_type":"KOREAN",
    "phone_number":"01012345678"
  }'
```

#### 회원가입 (외국인)
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email":"foreigner@example.com",
    "password":"password123",
    "user_type":"FOREIGNER"
  }'
```

#### 로그인
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

#### 보호된 API 호출
```bash
curl -X GET http://localhost:8080/api/v1/protected/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3. Postman 테스트

Postman 컬렉션을 사용하여 모든 API를 테스트할 수 있습니다.

1. Postman 실행
2. 새 컬렉션 생성
3. 위의 API 엔드포인트 표를 참고하여 요청 추가
4. 환경 변수 설정:
   - `base_url`: `http://localhost:8080`
   - `access_token`: 로그인 후 받은 토큰

## 🔒 보안 특성

### 1. 비밀번호 보안
- **bcrypt 해싱**: cost factor 10
- **최소 길이 검증**: 8자 이상
- **솔트 자동 생성**: bcrypt 내장 기능

### 2. JWT 토큰
- **HMAC-SHA256 서명**: 변조 방지
- **짧은 만료 시간**: Access Token 15분
- **Refresh Token 분리**: 7일 유효
- **Refresh Token DB 저장**: 무효화 가능

### 3. OAuth2 CSRF 방지
- **랜덤 State 생성**: 32바이트 암호학적 난수
- **State 쿠키 검증**: 일회용, 5분 유효
- **HttpOnly 쿠키**: XSS 공격 방지

### 4. 이메일 인증
- **UUID 토큰**: 예측 불가능
- **만료 시간**: 24시간
- **일회용 토큰**: 사용 후 무효화

### 5. 데이터베이스
- **SQL Injection 방지**: GORM 파라미터화 쿼리
- **외래키 제약**: 데이터 무결성 보장
- **CASCADE DELETE**: 관련 데이터 자동 삭제

### 6. CORS 설정
- **Origin 제한**: 프로덕션에서 설정 필요
- **메서드 제한**: GET, POST, PUT, DELETE
- **헤더 제한**: Content-Type, Authorization

### 보안 체크리스트 (프로덕션 배포 전)

- [ ] `.env` 파일을 `.gitignore`에 추가
- [ ] JWT_SECRET을 강력한 랜덤 문자열로 변경
- [ ] HTTPS 사용 (OAuth2 쿠키 Secure 플래그)
- [ ] CORS Origin을 실제 도메인으로 제한
- [ ] Rate Limiting 추가
- [ ] 로그 마스킹 (비밀번호, 토큰)
- [ ] SQL Injection 추가 테스트
- [ ] XSS, CSRF 취약점 점검

## 🔧 향후 개선 사항

### 기능 추가
- [ ] **SMS 인증 구현**: 전화번호 인증 기능
- [ ] **비밀번호 찾기/재설정** 기능
- [x] **회원 탈퇴** 기능 ✅
- [ ] **프로필 이미지 업로드**
- [ ] **이메일 변경** 기능
- [x] **소셜 계정 연동 해제** ✅
- [x] **일반 회원 전환**: 소셜 전용 계정에 비밀번호 설정 ✅
- [x] **OAuth 토큰 Revoke**: 연동 해제 시 외부 제공자에 토큰 무효화 요청 ✅
- [ ] **Apple 소셜 로그인** 추가

### 보안 강화
- [ ] **Rate Limiting**: 로그인 시도 횟수 제한
- [ ] **2FA (Two-Factor Authentication)**: TOTP 기반 2단계 인증
- [ ] **블랙리스트**: 탈취된 토큰 무효화
- [ ] **IP 기반 접근 제어**
- [ ] **로그인 이력 추적**

### 최적화
- [x] **이메일 발송 최적화**: 소셜 연동 시 사용자 요청 시에만 이메일 발송 ✅