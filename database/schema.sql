-- /database/schema.sql
-- users 테이블
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_email (email)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- email_verifications 테이블 (이메일 인증용)
CREATE TABLE email_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_email_verifications_token (token),
    INDEX idx_email_verifications_user_id (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- refresh_tokens 테이블 (JWT 리프레시 토큰)
CREATE TABLE refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_refresh_tokens_token (token),
    INDEX idx_refresh_tokens_user_id (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

ALTER TABLE users
ADD COLUMN provider VARCHAR(20) NOT NULL DEFAULT 'email' AFTER email,
ADD COLUMN social_id VARCHAR(255) NULL AFTER provider,
MODIFY COLUMN password_hash VARCHAR(255) NULL;

-- 복합 인덱스 생성 (동일 제공자 내 중복 ID 방지)
-- ex: 구글에서 ID(12345)가 두 번 가입되는 것을 막음
CREATE UNIQUE INDEX idx_users_provider_social_id ON users (provider, social_id);

CREATE TABLE social_accounts (
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT NOT NULL,
	provider VARCHAR(20) NOT NULL, -- 'google', 'kakako', 'naver'
	social_id VARCHAR(255) NOT NULL, -- 소셜 플랫폼의 고유 식별자 (sub)
	email VARCHAR(255), -- 소셜 계정의 이메일 (users의 대표 이메일과 다를 수 있음)
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

-- 유저 삭제 시 소셜 연동 정보도 삭제
FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,

-- 인덱스: 특정 제공자 내에서 식별자는 유일해야 함
UNIQUE INDEX idx_provider_social_id (provider, social_id),
	auth_serviceauth_service-- 인덱스: 한 유저가 같은 제공자를 중복 연동할 수 없음
	UNIQUE INDEX idx_user_provider (user_id, provider)
) ENGINE=INNODB DEFAULT CHARSET=UTF8MB4 COLLATE=UTF8MB4_UNICODE_CI;

ALTER TABLE users DROP COLUMN provider, DROP COLUMN social_id;

ALTER TABLE users
ADD COLUMN phone_number VARCHAR(20) NULL UNIQUE AFTER email, -- 한국인은 필수
ADD COLUMN country_code VARCHAR(10) DEFAULT 'KR' AFTER phone_number, -- 국가 코드
ADD COLUMN user_type ENUM('KOREAN', 'FOREIGNER') NOT NULL DEFAULT 'KOREAN' AFTER country_code;

CREATE TABLE sms_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone_number VARCHAR(20) NOT NULL,
    code VARCHAR(6) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_phone (phone_number)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

ALTER TABLE users MODIFY COLUMN country_code VARCHAR(10) NULL;

ALTER TABLE users
MODIFY COLUMN user_type ENUM('KOREAN', 'FOREIGNER') NULL;