package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/twofactor/handlers"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type TwoFactorHandlerSuite struct {
	suite.Suite
}

func TestTwoFactorHandlerSuite(t *testing.T) {
	suite.Run(t, new(TwoFactorHandlerSuite))
}

func (s *TwoFactorHandlerSuite) setupHandler() (*handlers.TwoFactorHandler, *mocks.MockTwoFactorService, *mocks.MockEventBus, *mocks.MockSessionStorage, *mocks.MockCoreStorage) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockTwoFactorService(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockStorage := mocks.NewMockStorage(ctrl)
	mockSessionStorage := mocks.NewMockSessionStorage(ctrl)
	mockCoreStorage := mocks.NewMockCoreStorage(ctrl)
	mockSecurityManager := testutil.TestSecurityManager()

	// Allow any logger calls
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Error(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config:          testutil.TestConfig(),
		Events:          mockEvents,
		Logger:          mockLogger,
		Storage:         mockStorage,
		SecurityManager: mockSecurityManager,
	}

	// Setup storage mocks to return session storage (for token issuance tests)
	mockStorage.EXPECT().Session().Return(mockSessionStorage).AnyTimes()
	mockStorage.EXPECT().Stateless().Return(nil).AnyTimes()
	mockStorage.EXPECT().Core().Return(mockCoreStorage).AnyTimes()

	handler := handlers.NewTwoFactorHandler(deps, mockService)
	return handler, mockService, mockEvents, mockSessionStorage, mockCoreStorage
}

// ---------------------------------------------------------------------------
// Setup Handler Tests
// ---------------------------------------------------------------------------

func (s *TwoFactorHandlerSuite) TestSetupHandler_Success() {
	handler, mockService, _, _, _ := s.setupHandler()

	// Mock service expectations
	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(nil, types.NewTwoFactorNotFoundError()) // No existing 2FA

	mockService.EXPECT().
		GetUser(gomock.Any(), "user-123").
		Return(&models.User{
			ID:    "user-123",
			Email: "test@example.com",
		}, nil)

	mockService.EXPECT().
		GenerateSecret(gomock.Any(), "test@example.com").
		Return("SECRET123", "otpauth://totp/...", nil)

	mockService.EXPECT().
		GenerateBackupCodes(gomock.Any(), "user-123").
		Return([]string{"AAAA-AAAA", "BBBB-BBBB"}, nil)

	mockService.EXPECT().
		SaveTwoFactorConfig(gomock.Any(), gomock.Any()).
		Return(nil)

	mockService.EXPECT().
		SaveBackupCodes(gomock.Any(), "user-123", gomock.Any()).
		Return(nil)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/2fa/setup", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	// Execute
	handler.SetupHandler(w, req)

	// Assert
	s.Equal(http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	s.NoError(err)

	data := response["data"].(map[string]interface{})
	s.Equal("SECRET123", data["secret"])
	s.Equal("otpauth://totp/...", data["qr_url"])
	s.NotNil(data["backup_codes"])
}

func (s *TwoFactorHandlerSuite) TestSetupHandler_AlreadyEnabled() {
	handler, mockService, _, _, _ := s.setupHandler()

	// Mock: 2FA already enabled
	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(&models.TwoFactor{
			UserID:  "user-123",
			Enabled: true,
		}, nil)

	req := httptest.NewRequest(http.MethodPost, "/2fa/setup", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	handler.SetupHandler(w, req)

	s.Equal(http.StatusBadRequest, w.Code) // TwoFactorAlreadyEnabledError returns 400
}

func (s *TwoFactorHandlerSuite) TestSetupHandler_Unauthorized() {
	handler, _, _, _, _ := s.setupHandler()

	// No user ID in context
	req := httptest.NewRequest(http.MethodPost, "/2fa/setup", nil)
	w := httptest.NewRecorder()

	handler.SetupHandler(w, req)

	s.Equal(http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Verify Handler Tests (Setup Verification)
// ---------------------------------------------------------------------------

func (s *TwoFactorHandlerSuite) TestVerifyHandler_Success() {
	handler, mockService, mockEvents, _, _ := s.setupHandler()

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	// Mock expectations
	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(&models.TwoFactor{
			UserID:  "user-123",
			Secret:  "SECRET123",
			Enabled: false, // Not enabled yet
		}, nil)

	mockService.EXPECT().
		VerifyCodeManual(gomock.Any(), "SECRET123", "123456").
		Return(nil)

	mockService.EXPECT().
		EnableTwoFactor(gomock.Any(), "user-123").
		Return(nil)

	mockEvents.EXPECT().
		EmitAsync(gomock.Any(), types.EventAuth2FAEnabled, gomock.Any()).
		Return(nil)

	handler.VerifyHandler(w, req)

	s.Equal(http.StatusOK, w.Code)
}

func (s *TwoFactorHandlerSuite) TestVerifyHandler_InvalidCode() {
	handler, mockService, _, _, _ := s.setupHandler()

	body := `{"code":"000000"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(&models.TwoFactor{
			UserID: "user-123",
			Secret: "SECRET123",
		}, nil)

	mockService.EXPECT().
		VerifyCodeManual(gomock.Any(), "SECRET123", "000000").
		Return(types.NewTwoFactorInvalidError())

	handler.VerifyHandler(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Disable Handler Tests
// ---------------------------------------------------------------------------

func (s *TwoFactorHandlerSuite) TestDisableHandler_Success() {
	handler, mockService, mockEvents, _, _ := s.setupHandler()

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/disable", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		VerifyCode(gomock.Any(), "user-123", "123456").
		Return(nil)

	mockService.EXPECT().
		DisableTwoFactor(gomock.Any(), "user-123").
		Return(nil)

	mockEvents.EXPECT().
		EmitAsync(gomock.Any(), types.EventAuth2FADisabled, gomock.Any()).
		Return(nil)

	handler.DisableHandler(w, req)

	s.Equal(http.StatusOK, w.Code)
}

func (s *TwoFactorHandlerSuite) TestDisableHandler_InvalidCode() {
	handler, mockService, _, _, _ := s.setupHandler()

	body := `{"code":"000000"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/disable", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		VerifyCode(gomock.Any(), "user-123", "000000").
		Return(types.NewTwoFactorInvalidError())

	handler.DisableHandler(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Status Handler Tests
// ---------------------------------------------------------------------------

func (s *TwoFactorHandlerSuite) TestStatusHandler_Enabled() {
	handler, mockService, _, _, _ := s.setupHandler()

	req := httptest.NewRequest(http.MethodGet, "/2fa/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(&models.TwoFactor{
			UserID:  "user-123",
			Enabled: true,
			Method:  "totp",
		}, nil)

	handler.StatusHandler(w, req)

	s.Equal(http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	s.True(data["enabled"].(bool))
	s.Equal("totp", data["method"])
}

func (s *TwoFactorHandlerSuite) TestStatusHandler_Disabled() {
	handler, mockService, _, _, _ := s.setupHandler()

	req := httptest.NewRequest(http.MethodGet, "/2fa/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "user-123"))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		GetTwoFactorConfig(gomock.Any(), "user-123").
		Return(nil, types.NewTwoFactorNotFoundError())

	handler.StatusHandler(w, req)

	s.Equal(http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	s.False(data["enabled"].(bool))
}

// ---------------------------------------------------------------------------
// Verify Login Handler Tests (2FA Login Flow)
// ---------------------------------------------------------------------------

func (s *TwoFactorHandlerSuite) TestVerifyLoginHandler_Success_WithTempToken() {
	handler, mockService, mockEvents, _, _ := s.setupHandler()

	// Generate a valid temp token
	tempToken := testutil.GenerateTempToken("user-123")

	body := `{"temp_token":"` + tempToken + `","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify-login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	mockService.EXPECT().
		VerifyCodeOrBackup(gomock.Any(), "user-123", "123456").
		Return(nil)

	mockService.EXPECT().
		GetUser(gomock.Any(), "user-123").
		Return(user, nil)

	mockEvents.EXPECT().
		EmitAsync(gomock.Any(), types.EventAuth2FAVerified, gomock.Any()).
		Return(nil)

	// Mock token issuance (service handles all repository access)
	mockService.EXPECT().
		IssueAuthTokenAfter2FA(gomock.Any(), user, gomock.Any()).
		Return(map[string]any{
			"access_token":  "token_abc",
			"refresh_token": "token_xyz",
			"user": map[string]any{
				"id":    "user-123",
				"email": "test@example.com",
			},
		}, nil)

	handler.VerifyLoginHandler(w, req)

	s.Equal(http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	s.NotNil(data["access_token"])
	s.NotNil(data["refresh_token"])
	s.NotNil(data["user"])
}

func (s *TwoFactorHandlerSuite) TestVerifyLoginHandler_InvalidCode() {
	handler, mockService, _, _, _ := s.setupHandler()

	tempToken := testutil.GenerateTempToken("user-123")
	body := `{"temp_token":"` + tempToken + `","code":"000000"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify-login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	mockService.EXPECT().
		VerifyCodeOrBackup(gomock.Any(), "user-123", "000000").
		Return(types.NewTwoFactorInvalidError())

	handler.VerifyLoginHandler(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
}

func (s *TwoFactorHandlerSuite) TestVerifyLoginHandler_InvalidTempToken() {
	handler, _, _, _, _ := s.setupHandler()

	body := `{"temp_token":"invalid.token.here","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify-login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.VerifyLoginHandler(w, req)

	s.Equal(http.StatusUnauthorized, w.Code)
}

func (s *TwoFactorHandlerSuite) TestVerifyLoginHandler_ExpiredTempToken() {
	handler, _, _, _, _ := s.setupHandler()

	// Generate token that expired 10 minutes ago
	expiredToken := testutil.GenerateExpiredTempToken("user-123", -10*time.Minute)

	body := `{"temp_token":"` + expiredToken + `","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify-login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.VerifyLoginHandler(w, req)

	s.Equal(http.StatusUnauthorized, w.Code)
}

func (s *TwoFactorHandlerSuite) TestVerifyLoginHandler_BackupCode() {
	handler, mockService, mockEvents, _, _ := s.setupHandler()

	tempToken := testutil.GenerateTempToken("user-123")
	body := `{"temp_token":"` + tempToken + `","code":"AAAA-BBBB"}`
	req := httptest.NewRequest(http.MethodPost, "/2fa/verify-login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	mockService.EXPECT().
		VerifyCodeOrBackup(gomock.Any(), "user-123", "AAAA-BBBB").
		Return(nil)

	mockService.EXPECT().
		GetUser(gomock.Any(), "user-123").
		Return(user, nil)

	mockEvents.EXPECT().
		EmitAsync(gomock.Any(), types.EventAuth2FAVerified, gomock.Any()).
		Return(nil)

	// Mock token issuance (service handles all repository access)
	mockService.EXPECT().
		IssueAuthTokenAfter2FA(gomock.Any(), user, gomock.Any()).
		Return(map[string]any{
			"access_token":  "token_abc",
			"refresh_token": "token_xyz",
		}, nil)

	handler.VerifyLoginHandler(w, req)

	s.Equal(http.StatusOK, w.Code)
}
