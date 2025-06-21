package routes

import (
	"time"

	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository for testing
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) UpsertUserByEmail(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}


func (m *MockUserRepository) GetUserByPhoneNumber(phoneNumber string) (*models.User, error) {
	args := m.Called(phoneNumber)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByID(id string) (*models.User, error) {
	args := m.Called(id)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetAllUsers(filter interfaces.Filter) ([]*models.User, int64, error) {
	args := m.Called(filter)
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

// MockTokenRepository for testing
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) SaveToken(userID, token string, tokenType models.TokenType, ttl time.Duration) error {
	args := m.Called(userID, token, tokenType, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) ValidateToken(token string, tokenType models.TokenType) (bool, *string, error) {
	args := m.Called(token, tokenType)
	userID := args.Get(1)
	if userID == nil {
		return args.Bool(0), nil, args.Error(2)
	}
	return args.Bool(0), userID.(*string), args.Error(2)
}

func (m *MockTokenRepository) ValidateTokenWithUserID(userID, token string, tokenType models.TokenType) (bool, error) {
	args := m.Called(userID, token, tokenType)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenRepository) InvalidateToken(userID, token string, tokenType models.TokenType) error {
	args := m.Called(userID, token, tokenType)
	return args.Error(0)
}

func (m *MockTokenRepository) InvalidateAllTokens(userID string, tokenType models.TokenType) error {
	args := m.Called(userID, tokenType)
	return args.Error(0)
}

func (m *MockTokenRepository) GetToken(token string) (*models.Token, error) {
	args := m.Called(token)
	tokenObj := args.Get(0)
	if tokenObj == nil {
		return nil, args.Error(1)
	}
	return tokenObj.(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) DeleteToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

// MockRepositoryFactory for testing
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

// MockTokenManager for testing
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
	claims := args.Get(0)
	if claims == nil {
		return nil, args.Error(1)
	}

	// Handle the case where claims is map[string]interface{} instead of jwt.MapClaims
	if mapClaims, ok := claims.(map[string]interface{}); ok {
		return jwt.MapClaims(mapClaims), args.Error(1)
	}

	return claims.(jwt.MapClaims), args.Error(1)
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
	claims := args.Get(0)
	if claims == nil {
		return nil, args.Error(1)
	}

	// Handle the case where claims is map[string]interface{} instead of jwt.MapClaims
	if mapClaims, ok := claims.(map[string]interface{}); ok {
		return jwt.MapClaims(mapClaims), args.Error(1)
	}

	return claims.(jwt.MapClaims), args.Error(1)
}

// MockEmailSender for testing
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) SendVerification(user models.User, redirectUrl string) error {
	args := m.Called(user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendPasswordReset(user models.User, redirectUrl string) error {
	args := m.Called(user, redirectUrl)
	return args.Error(0)
}

func (m *MockEmailSender) SendTwoFactorCode(user models.User, code string) error {
	args := m.Called(user, code)
	return args.Error(0)
}

func (m *MockEmailSender) SendMagicLink(user models.User, redirectUrl string) error {
	args := m.Called(user, redirectUrl)
	return args.Error(0)
}

// MockSMSSender for testing
type MockSMSSender struct {
	mock.Mock
}

// SendMagicLink implements types.SMSSenderInterface.
func (m *MockSMSSender) SendMagicLink(user models.User, redirectURL string) error {
	args := m.Called(user, redirectURL)
	return args.Error(0)
}

// SendVerificationCode implements types.SMSSenderInterface.
func (m *MockSMSSender) SendVerificationCode(user models.User, code string) error {
	args := m.Called(user, code)
	return args.Error(0)
}

// SendWelcome implements types.SMSSenderInterface.
func (m *MockSMSSender) SendWelcome(user models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockSMSSender) SendTwoFactorCode(user models.User, code string) error {
	args := m.Called(user, code)
	return args.Error(0)
}

// Helper function to create test config
func CreateTestConfig() types.Config {
	return types.Config{
		JWTSecret: "test-secret-key",
		AuthConfig: types.AuthConfig{
			Cookie: types.CookieConfig{
				Name:            "auth_token",
				AccessTokenTTL:  3600,
				RefreshTokenTTL: 86400,
				Path:            "/",
				MaxAge:          86400,
			},
			EnableEmailVerificationOnSignup: false,
			EmailVerificationURL:    "http://localhost:3000/verify",
			PasswordResetURL:        "http://localhost:3000/reset-password",
			EnableBearerAuth:        true,
		},
		PasswordPolicy: types.PasswordPolicy{
			HashSaltLength: 16,
			MinLength:      8,
			RequireUpper:   true,
			RequireLower:   true,
			RequireNumber:  true,
			RequireSpecial: false,
		},
	}
}

// Helper function to create test auth handler
func CreateTestAuthHandler(config types.Config) *AuthHandler {
	mockUserRepo := &MockUserRepository{}
	mockTokenRepo := &MockTokenRepository{}
	mockRepoFactory := &MockRepositoryFactory{}
	mockTokenManager := &MockTokenManager{}
	mockEmailSender := &MockEmailSender{}
	mockSMSSender := &MockSMSSender{}

	mockRepoFactory.On("GetUserRepository").Return(mockUserRepo)
	mockRepoFactory.On("GetTokenRepository").Return(mockTokenRepo)

	auth := &types.Auth{
		Config:       config,
		Repository:   mockRepoFactory,
		TokenManager: mockTokenManager,
		HookManager:  hooks.NewHookManager(),
	}

	// Set email and SMS senders in config
	auth.Config.EmailSender = mockEmailSender
	auth.Config.SMSSender = mockSMSSender

	return &AuthHandler{Auth: auth}
}

// Helper function to create a test user
func CreateTestUser() *models.User {
	return &models.User{
		ID:               "test-user-id",
		FirstName:        "John",
		LastName:         "Doe",
		Email:            "test@example.com",
		Password:         "hashed_password",
		EmailVerified:    true,
		Active:           true,
		TwoFactorEnabled: false,
		SignedUpVia:        "email",
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
