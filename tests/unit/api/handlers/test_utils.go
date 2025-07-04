package handlers

import (
	"context"
	"time"

	"github.com/bete7512/goauth/internal/api/handlers"
	"github.com/bete7512/goauth/internal/hooks"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
	models "github.com/bete7512/goauth/pkg/models"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/mock"
)

// TestAuth represents the auth structure for testing
type TestAuth struct {
	Config           config.Config
	Repository       interfaces.RepositoryFactory
	TokenManager     interfaces.TokenManagerInterface
	HookManager      hooks.HookManager
	RateLimiter      interfaces.RateLimiter
	RecaptchaManager interfaces.CaptchaVerifier
	Logger           interface{}
}

// MockUserRepository struct
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) UpsertUserByEmail(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	args := m.Called(ctx, phoneNumber)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetAllUsers(ctx context.Context, filter interfaces.Filter) ([]*models.User, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

// MockTokenRepository struct
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) SaveToken(ctx context.Context, userID, token string, tokenType models.TokenType, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, tokenType, expiry)
	return args.Error(0)
}

func (m *MockTokenRepository) SaveTokenWithDeviceId(ctx context.Context, userID, token, deviceId string, tokenType models.TokenType, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, deviceId, tokenType, expiry)
	return args.Error(0)
}

func (m *MockTokenRepository) GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType models.TokenType) (*models.Token, error) {
	args := m.Called(ctx, userID, tokenType)
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) GetActiveTokenByUserIdTypeAndDeviceId(ctx context.Context, userID string, tokenType models.TokenType, deviceID string) (*models.Token, error) {
	args := m.Called(ctx, userID, tokenType, deviceID)
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) RevokeToken(ctx context.Context, tokenId string) error {
	args := m.Called(ctx, tokenId)
	return args.Error(0)
}

func (m *MockTokenRepository) RevokeAllTokens(ctx context.Context, userID string, tokenType models.TokenType) error {
	args := m.Called(ctx, userID, tokenType)
	return args.Error(0)
}

func (m *MockTokenRepository) CleanExpiredTokens(ctx context.Context, tokenType models.TokenType) error {
	args := m.Called(ctx, tokenType)
	return args.Error(0)
}

// MockRepositoryFactory struct
type MockRepositoryFactory struct {
	mock.Mock
}

func (m *MockRepositoryFactory) GetUserRepository() interfaces.UserRepository {
	args := m.Called()
	return args.Get(0).(interfaces.UserRepository)
}

func (m *MockRepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
	args := m.Called()
	return args.Get(0).(interfaces.TokenRepository)
}

func (m *MockRepositoryFactory) GetAuditLogRepository() interfaces.AuditLogRepository {
	args := m.Called()
	return args.Get(0).(interfaces.AuditLogRepository)
}

func (m *MockRepositoryFactory) GetTotpSecretRepository() interfaces.TotpSecretRepository {
	args := m.Called()
	return args.Get(0).(interfaces.TotpSecretRepository)
}

func (m *MockRepositoryFactory) GetOauthAccountRepository() interfaces.OauthAccountRepository {
	args := m.Called()
	return args.Get(0).(interfaces.OauthAccountRepository)
}

func (m *MockRepositoryFactory) GetBackupCodeRepository() interfaces.BackupCodeRepository {
	args := m.Called()
	return args.Get(0).(interfaces.BackupCodeRepository)
}

func (m *MockRepositoryFactory) GetSessionRepository() interfaces.SessionRepository {
	args := m.Called()
	return args.Get(0).(interfaces.SessionRepository)
}

// MockTokenManager struct
type MockTokenManager struct {
	mock.Mock
}

func (m *MockTokenManager) GenerateAccessToken(user models.User, duration time.Duration, secretKey string) (string, error) {
	args := m.Called(user, duration, secretKey)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) ValidatePassword(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

func (m *MockTokenManager) GenerateTokens(user *models.User) (string, string, error) {
	args := m.Called(user)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockTokenManager) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockTokenManager) GenerateRandomToken(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) GenerateBase64Token(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) GenerateNumericOTP(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) HashToken(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) ValidateHashedToken(hashedToken, token string) error {
	args := m.Called(hashedToken, token)
	return args.Error(0)
}

func (m *MockTokenManager) ValidateJWTToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockTokenManager) Decrypt(encrypted string) (string, error) {
	args := m.Called(encrypted)
	return args.String(0), args.Error(1)
}

func (m *MockTokenManager) Encrypt(plain string) (string, error) {
	args := m.Called(plain)
	return args.String(0), args.Error(1)
}

// MockEmailSender struct
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) SendVerification(ctx context.Context, user models.User, redirectUrl string) error {
	args := m.Called(ctx, user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendWelcome(ctx context.Context, user models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockEmailSender) SendPasswordReset(ctx context.Context, user models.User, redirectUrl string) error {
	args := m.Called(ctx, user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendTwoFactorCode(ctx context.Context, user models.User, code string) error {
	args := m.Called(ctx, user, code)
	return args.Error(0)
}

func (m *MockEmailSender) SendMagicLink(ctx context.Context, user models.User, redirectUrl string) error {
	args := m.Called(ctx, user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendMagicLinkEmail(ctx context.Context, user models.User, redirectUrl string) error {
	args := m.Called(ctx, user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendForgetPasswordEmail(ctx context.Context, user models.User, redirectUrl string) error {
	args := m.Called(ctx, user, redirectUrl)
	return args.Error(0)
}

// MockSMSSender struct
type MockSMSSender struct {
	mock.Mock
}

func (m *MockSMSSender) SendMagicLink(ctx context.Context, user models.User, redirectURL string) error {
	args := m.Called(ctx, user, redirectURL)
	return args.Error(0)
}

func (m *MockSMSSender) SendVerificationCode(ctx context.Context, user models.User, code string) error {
	args := m.Called(ctx, user, code)
	return args.Error(0)
}

func (m *MockSMSSender) SendWelcome(ctx context.Context, user models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockSMSSender) SendTwoFactorCode(ctx context.Context, user models.User, code string) error {
	args := m.Called(ctx, user, code)
	return args.Error(0)
}

func (m *MockSMSSender) SendTwoFactorSMS(ctx context.Context, user models.User, code string) error {
	args := m.Called(ctx, user, code)
	return args.Error(0)
}

func (m *MockSMSSender) SendVerificationSMS(ctx context.Context, user models.User, code string) error {
	args := m.Called(ctx, user, code)
	return args.Error(0)
}

// MockCaptchaVerifier struct
type MockCaptchaVerifier struct {
	mock.Mock
}

func (m *MockCaptchaVerifier) Verify(ctx context.Context, token string, remoteIP string) (bool, error) {
	args := m.Called(ctx, token, remoteIP)
	return args.Bool(0), args.Error(1)
}

// MockAuditLogRepository struct
type MockAuditLogRepository struct {
	mock.Mock
}

func (m *MockAuditLogRepository) SaveAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockAuditLogRepository) GetAuditLogs(ctx context.Context, filter interfaces.Filter) ([]*models.AuditLog, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*models.AuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuditLogRepository) GetAuditLogByID(ctx context.Context, id string) (*models.AuditLog, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) DeleteAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

// MockTotpSecretRepository struct
type MockTotpSecretRepository struct {
	mock.Mock
}

func (m *MockTotpSecretRepository) GetTOTPSecretByUserID(ctx context.Context, userID string) (*models.TotpSecret, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*models.TotpSecret), args.Error(1)
}

func (m *MockTotpSecretRepository) CreateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockTotpSecretRepository) UpdateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockTotpSecretRepository) DeleteTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

// MockOauthAccountRepository struct
type MockOauthAccountRepository struct {
	mock.Mock
}

func (m *MockOauthAccountRepository) GetOauthAccountByUserID(ctx context.Context, userID string) (*models.OauthAccount, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*models.OauthAccount), args.Error(1)
}

func (m *MockOauthAccountRepository) CreateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockOauthAccountRepository) UpdateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

func (m *MockOauthAccountRepository) DeleteOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	args := m.Called(ctx, account)
	return args.Error(0)
}

// MockBackupCodeRepository struct
type MockBackupCodeRepository struct {
	mock.Mock
}

func (m *MockBackupCodeRepository) GetBackupCodeByUserID(ctx context.Context, userID string) (*models.BackupCode, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*models.BackupCode), args.Error(1)
}

func (m *MockBackupCodeRepository) CreateBackupCodes(ctx context.Context, codes []*models.BackupCode) error {
	args := m.Called(ctx, codes)
	return args.Error(0)
}

func (m *MockBackupCodeRepository) UpdateBackupCode(ctx context.Context, code *models.BackupCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *MockBackupCodeRepository) DeleteBackupCode(ctx context.Context, code *models.BackupCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

// MockSessionRepository struct
type MockSessionRepository struct {
	mock.Mock
}

// Helper function to create test config
func CreateTestConfig() config.Config {
	return config.Config{
		App: config.AppConfig{
			BasePath:    "/api",
			Domain:      "localhost",
			FrontendURL: "http://localhost:3000",
			Swagger: config.SwaggerConfig{
				Enable:      false,
				Title:       "Test API",
				Version:     "1.0.0",
				Description: "Test API Documentation",
				DocPath:     "/docs",
				Host:        "localhost:8080",
			},
		},
		Features: config.FeaturesConfig{
			EnableRateLimiter:   false,
			EnableRecaptcha:     false,
			EnableCustomJWT:     false,
			EnableCustomStorage: false,
		},
		Database: config.DatabaseConfig{
			Type:        "postgres",
			URL:         "postgres://test:test@localhost:5432/test",
			AutoMigrate: true,
		},
		Security: config.SecurityConfig{
			RateLimiter: config.RateLimiterConfig{
				Enabled: false,
				Type:    "memory",
				Routes:  make(map[string]config.LimiterConfig),
			},
			Recaptcha: config.RecaptchaConfig{
				Enabled:   false,
				SecretKey: "",
				SiteKey:   "",
				Provider:  "google",
				APIURL:    "",
				Routes:    make(map[string]bool),
			},
		},
		AuthConfig: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:             "test-secret-key",
				AccessTokenTTL:     3600 * time.Second,
				RefreshTokenTTL:    86400 * time.Second,
				EnableCustomClaims: false,
				ClaimsProvider:     nil,
			},
			Tokens: config.TokenConfig{
				HashSaltLength:       16,
				PhoneVerificationTTL: 10 * time.Minute,
				EmailVerificationTTL: 1 * time.Hour,
				PasswordResetTTL:     10 * time.Minute,
				TwoFactorTTL:         10 * time.Minute,
				MagicLinkTTL:         10 * time.Minute,
			},
			Methods: config.AuthMethodsConfig{
				Type:               "email",
				EnableTwoFactor:    false,
				EnableMultiSession: false,
				EnableMagicLink:    false,
				TwoFactorMethod:    "",
				EmailVerification: config.EmailVerificationConfig{
					EnableOnSignup:   false,
					VerificationURL:  "http://localhost:3000/verify",
					SendWelcomeEmail: false,
				},
				PhoneVerification: config.PhoneVerificationConfig{
					EnableOnSignup:      false,
					UniquePhoneNumber:   false,
					PhoneColumnRequired: false,
					PhoneRequired:       false,
				},
			},
			PasswordPolicy: config.PasswordPolicy{
				HashSaltLength: 16,
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			Cookie: config.CookieConfig{
				Name:     "auth_token",
				Secure:   false,
				HttpOnly: true,
				Domain:   "",
				Path:     "/",
				MaxAge:   86400,
				SameSite: 1, // http.SameSiteLaxMode
			},
		},
		Email: config.EmailConfig{
			SenderType: config.SendGrid,
			Branding: config.BrandingConfig{
				LogoURL:      "",
				CompanyName:  "Test Company",
				PrimaryColor: "#007bff",
			},
			SendGrid: config.SendGridConfig{
				APIKey: "",
			},
			SES: config.SESConfig{
				Region:          "",
				AccessKeyID:     "",
				SecretAccessKey: "",
			},
		},
		SMS: config.SMSConfig{
			Twilio: config.TwilioConfig{
				AccountSID: "",
				AuthToken:  "",
				FromNumber: "",
			},
			Branding: config.BrandingConfig{
				CompanyName: "Test Company",
			},
			CustomSender: nil,
		},
		Providers: config.ProvidersConfig{
			Enabled:   []config.AuthProvider{},
			Google:    config.ProviderConfig{},
			GitHub:    config.ProviderConfig{},
			Facebook:  config.ProviderConfig{},
			Microsoft: config.ProviderConfig{},
			Apple:     config.ProviderConfig{},
			Twitter:   config.ProviderConfig{},
			LinkedIn:  config.ProviderConfig{},
			Discord:   config.ProviderConfig{},
			Spotify:   config.ProviderConfig{},
			Slack:     config.ProviderConfig{},
		},
	}
}

// Helper function to create test auth handler
func CreateTestAuthHandler(conf config.Config) *handlers.AuthHandler {
	mockUserRepo := &MockUserRepository{}
	mockTokenRepo := &MockTokenRepository{}
	mockAuditLogRepo := &MockAuditLogRepository{}
	mockTotpSecretRepo := &MockTotpSecretRepository{}
	mockOauthAccountRepo := &MockOauthAccountRepository{}
	mockBackupCodeRepo := &MockBackupCodeRepository{}
	mockRepoFactory := &MockRepositoryFactory{}
	mockTokenManager := &MockTokenManager{}
	mockCaptchaVerifier := &MockCaptchaVerifier{}
	mockSessionRepo := &MockSessionRepository{}

	mockRepoFactory.On("GetUserRepository").Return(mockUserRepo)
	mockRepoFactory.On("GetTokenRepository").Return(mockTokenRepo)
	mockRepoFactory.On("GetAuditLogRepository").Return(mockAuditLogRepo)
	mockRepoFactory.On("GetTotpSecretRepository").Return(mockTotpSecretRepo)
	mockRepoFactory.On("GetOauthAccountRepository").Return(mockOauthAccountRepo)
	mockRepoFactory.On("GetBackupCodeRepository").Return(mockBackupCodeRepo)
	mockRepoFactory.On("GetSessionRepository").Return(mockSessionRepo)

	// Create auth structure using TestAuth
	auth := &config.Auth{
		Config:           &conf,
		Repository:       mockRepoFactory,
		TokenManager:     mockTokenManager,
		HookManager:      hooks.NewHookManager(),
		RecaptchaManager: mockCaptchaVerifier,
	}

	// Set email and SMS senders in config
	conf.Email.CustomSender = nil
	conf.SMS.CustomSender = nil

	return &handlers.AuthHandler{Auth: auth}
}

// Helper function to create a test user
func CreateTestUser() *models.User {
	active := true
	emailVerified := true
	twoFactorEnabled := false
	return &models.User{
		ID:               "test-user-id",
		FirstName:        "John",
		LastName:         "Doe",
		Email:            "test@example.com",
		Password:         "hashed_password",
		EmailVerified:    &emailVerified,
		Active:           &active,
		TwoFactorEnabled: &twoFactorEnabled,
		SignedUpVia:      "email",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// Helper function to create JWT claims
func CreateTestJWTClaims(userID string) jwt.MapClaims {
	return jwt.MapClaims{
		"user_id": userID,
		"email":   "test@example.com",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
}
