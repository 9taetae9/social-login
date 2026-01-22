package errors

const (
	// Validation Errors (VALIDATION_XXX)
	ErrCodeValidation        = "VALIDATION_ERROR"
	ErrCodeInvalidRequest    = "VALIDATION_INVALID_REQUEST"
	ErrCodeInvalidEmail      = "VALIDATION_INVALID_EMAIL"
	ErrCodeInvalidPassword   = "VALIDATION_INVALID_PASSWORD"
	ErrCodePhoneRequired     = "VALIDATION_PHONE_REQUIRED"

	// Authentication Errors (AUTH_XXX)
	ErrCodeAuthFailed           = "AUTH_FAILED"
	ErrCodeEmailExists          = "AUTH_EMAIL_EXISTS"
	ErrCodePhoneExists          = "AUTH_PHONE_EXISTS"
	ErrCodeInvalidCredentials   = "AUTH_INVALID_CREDENTIALS"
	ErrCodeEmailNotVerified     = "AUTH_EMAIL_NOT_VERIFIED"
	ErrCodeInvalidToken         = "AUTH_INVALID_TOKEN"
	ErrCodeTokenExpired         = "AUTH_TOKEN_EXPIRED"
	ErrCodeTokenNotFound        = "AUTH_TOKEN_NOT_FOUND"
	ErrCodeSocialLoginRequired  = "AUTH_SOCIAL_LOGIN_REQUIRED"
	ErrCodeHashPassword         = "AUTH_HASH_PASSWORD_FAILED"
	ErrCodeGenerateToken        = "AUTH_GENERATE_TOKEN_FAILED"

	// Email Verification Errors (EMAIL_XXX)
	ErrCodeEmailAlreadyVerified = "EMAIL_ALREADY_VERIFIED"
	ErrCodeEmailSendFailed      = "EMAIL_SEND_FAILED"
	ErrCodeVerificationInvalid  = "EMAIL_VERIFICATION_INVALID"
	ErrCodeVerificationExpired  = "EMAIL_VERIFICATION_EXPIRED"

	// User Errors (USER_XXX)
	ErrCodeUserNotFound = "USER_NOT_FOUND"
	ErrCodeUserCreate   = "USER_CREATE_FAILED"

	// Database Errors (DB_XXX)
	ErrCodeDBConnection  = "DB_CONNECTION_ERROR"
	ErrCodeDBQuery       = "DB_QUERY_ERROR"
	ErrCodeDBTransaction = "DB_TRANSACTION_ERROR"

	// Social Login Errors (SOCIAL_XXX)
	ErrCodeSocialLinkFailed               = "SOCIAL_LINK_FAILED"
	ErrCodeSocialCreateFailed             = "SOCIAL_CREATE_FAILED"
	ErrCodeSocialNotFound                 = "SOCIAL_NOT_FOUND"
	ErrCodeSocialLinkVerificationRequired = "SOCIAL_LINK_VERIFICATION_REQUIRED"
	ErrCodeSocialLinkNotFound             = "SOCIAL_LINK_NOT_FOUND"
	ErrCodeSocialLinkExpired              = "SOCIAL_LINK_EXPIRED"
	ErrCodeSocialLinkInvalidPassword      = "SOCIAL_LINK_INVALID_PASSWORD"
	ErrCodeSocialNotLinked                = "SOCIAL_NOT_LINKED"
	ErrCodeSocialUnlinkFailed             = "SOCIAL_UNLINK_FAILED"
	ErrCodeLastAuthMethod                 = "LAST_AUTH_METHOD"

	// Account Errors (ACCOUNT_XXX)
	ErrCodeAccountDeleteFailed = "ACCOUNT_DELETE_FAILED"

	// Password Reset Errors (PASSWORD_XXX)
	ErrCodePasswordResetTokenInvalid  = "PASSWORD_RESET_TOKEN_INVALID"
	ErrCodePasswordResetTokenExpired  = "PASSWORD_RESET_TOKEN_EXPIRED"
	ErrCodePasswordResetTokenUsed     = "PASSWORD_RESET_TOKEN_USED"
	ErrCodePasswordResetFailed        = "PASSWORD_RESET_FAILED"
	ErrCodePasswordChangeFailed       = "PASSWORD_CHANGE_FAILED"
	ErrCodePasswordCurrentInvalid     = "PASSWORD_CURRENT_INVALID"
	ErrCodePasswordSameAsOld          = "PASSWORD_SAME_AS_OLD"
	ErrCodePasswordNotSet             = "PASSWORD_NOT_SET"

	// Internal Errors (INTERNAL_XXX)
	ErrCodeInternal = "INTERNAL_ERROR"
)
