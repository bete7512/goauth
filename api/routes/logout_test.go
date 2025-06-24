package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/models"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestHandleLogout_Success(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Create test user
	testUser := CreateTestUser()
	testClaims := CreateTestJWTClaims(testUser.ID)

	// Mock token validation
	mockTokenManager.On("ValidateToken", "valid_token").Return(testClaims, nil)

	// Mock token invalidation
	mockTokenRepo.On("InvalidateAllTokens", testUser.ID, models.RefreshToken).Return(nil)

	// Create request with valid token
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogout(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Successfully logged out", response["message"])

	// Verify mocks
	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogout_NoToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Create request without token
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogout(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "no authentication token provided", response["message"])
}

func TestHandleLogout_InvalidToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock token validation failure
	mockTokenManager.On("ValidateToken", "invalid_token").Return(nil, assert.AnError)

	// Create request with invalid token
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogout(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["message"], "Unauthorized:")

	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogout_InvalidTokenClaims(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock token validation with invalid claims (use jwt.MapClaims to avoid panic)
	invalidClaims := make(jwt.MapClaims)
	invalidClaims["email"] = "test@example.com" // Missing user_id
	mockTokenManager.On("ValidateToken", "valid_token").Return(invalidClaims, nil)

	// Create request with valid token but invalid claims
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogout(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Unauthorized: invalid token claims", response["message"])

	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogout_TokenInvalidationError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Create test user
	testUser := CreateTestUser()
	testClaims := CreateTestJWTClaims(testUser.ID)

	// Mock token validation
	mockTokenManager.On("ValidateToken", "valid_token").Return(testClaims, nil)

	// Mock token invalidation error
	mockTokenRepo.On("InvalidateAllTokens", testUser.ID, models.RefreshToken).Return(assert.AnError)

	// Create request with valid token
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogout(w, req)

	// Assertions
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["message"], "Failed to invalidate tokens")

	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogout_MethodNotAllowed(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	w := httptest.NewRecorder()

	handler.HandleLogout(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Method not allowed", response["message"])
}
