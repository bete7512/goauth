package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleRefreshToken_Success(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()

	// Mock token validation
	// mockTokenRepo.On("ValidateToken", "valid_refresh_token", models.RefreshToken).Return(true, &testUser.ID, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Mock new token generation
	mockTokenManager.On("GenerateTokens", testUser).Return("new_access_token", "new_refresh_token", nil)

	// Mock new token saving
	// mockTokenRepo.On("SaveToken", testUser.ID, "new_refresh_token", models.RefreshToken, time.Duration(86400)).Return(nil)

	// Mock old token invalidation
	// mockTokenRepo.On("InvalidateToken", testUser.ID, "valid_refresh_token", models.RefreshToken).Return(nil)

	// Create request with valid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_refresh_token_auth_token",
		Value: "valid_refresh_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Tokens refreshed successfully", response["message"])

	// Verify mocks
	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleRefreshToken_NoToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Create request without refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "no refresh token provided", response["error"])
}

func TestHandleRefreshToken_InvalidToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)

	// Mock token validation failure
	// mockTokenRepo.On("ValidateToken", "invalid_refresh_token", models.RefreshToken).Return(false, nil, assert.AnError)

	// Create request with invalid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_refresh_token_auth_token",
		Value: "invalid_refresh_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid refresh token", response["error"])

	mockTokenRepo.AssertExpectations(t)
}

func TestHandleRefreshToken_UserNotFound(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()

	// Mock token validation
	// mockTokenRepo.On("ValidateToken", "valid_refresh_token", models.RefreshToken).Return(true, &testUser.ID, nil)

	// Mock user not found
	mockUserRepo.On("GetUserByID", testUser.ID).Return(nil, assert.AnError)

	// Create request with valid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_refresh_token_auth_token",
		Value: "valid_refresh_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user not found", response["error"])

	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleRefreshToken_TokenGenerationError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()

	// Mock token validation
	// mockTokenRepo.On("ValidateToken", "valid_refresh_token", models.RefreshToken).Return(true, &testUser.ID, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Mock token generation error
	mockTokenManager.On("GenerateTokens", testUser).Return("", "", assert.AnError)

	// Create request with valid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_refresh_token_auth_token",
		Value: "valid_refresh_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Failed to generate new tokens")

	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleRefreshToken_TokenSavingError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()

	// Mock token validation
	// mockTokenRepo.On("ValidateToken", "valid_refresh_token", models.RefreshToken).Return(true, &testUser.ID, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Mock new token generation
	mockTokenManager.On("GenerateTokens", testUser).Return("new_access_token", "new_refresh_token", nil)

	// Mock new token saving error
	// mockTokenRepo.On("SaveToken", testUser.ID, "new_refresh_token", models.RefreshToken, time.Duration(86400)).Return(assert.AnError)

	// Create request with valid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_refresh_token_auth_token",
		Value: "valid_refresh_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Failed to save new refresh token")

	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleRefreshToken_MethodNotAllowed(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	req := httptest.NewRequest(http.MethodGet, "/refresh-token", nil)
	w := httptest.NewRecorder()

	handler.HandleRefreshToken(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Method not allowed", response["error"])
}

func TestHandleRefreshToken_WithBearerToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()

	// Mock token validation
	// mockTokenRepo.On("ValidateToken", "bearer_refresh_token", models.RefreshToken).Return(true, &testUser.ID, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Mock new token generation
	mockTokenManager.On("GenerateTokens", testUser).Return("new_access_token", "new_refresh_token", nil)

	// Mock new token saving
	// mockTokenRepo.On("SaveToken", testUser.ID, "new_refresh_token", models.RefreshToken, time.Duration(86400)).Return(nil)

	// Mock old token invalidation
	// mockTokenRepo.On("InvalidateToken", testUser.ID, "bearer_refresh_token", models.RefreshToken).Return(nil)

	// Create request with bearer refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh-token", nil)
	req.Header.Set("Authorization", "Bearer bearer_refresh_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRefreshToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Tokens refreshed successfully", response["message"])

	// Verify mocks
	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}
