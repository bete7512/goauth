package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleGetUser_Success(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()
	testClaims := CreateTestJWTClaims(testUser.ID)

	// Mock token validation
	mockTokenManager.On("ValidateToken", "valid_token").Return(testClaims, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Create request with valid token
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "John", response["first_name"])
	assert.Equal(t, "Doe", response["last_name"])

	// Verify mocks
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleGetUser_NoToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Create request without token
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Unauthorized: no authentication token provided", response["message"])
}

func TestHandleGetUser_InvalidToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock token validation failure - return nil claims and error
	mockTokenManager.On("ValidateToken", "invalid_token").Return(nil, assert.AnError)

	// Create request with invalid token
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["message"], "Unauthorized:")

	mockTokenManager.AssertExpectations(t)
}

func TestHandleGetUser_InvalidTokenClaims(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock token validation with invalid claims
	invalidClaims := map[string]interface{}{
		"email": "test@example.com",
		// Missing user_id
	}
	mockTokenManager.On("ValidateToken", "valid_token").Return(invalidClaims, nil)

	// Create request with valid token but invalid claims
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Unauthorized: invalid token claims", response["message"])

	mockTokenManager.AssertExpectations(t)
}

func TestHandleGetUser_UserNotFound(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()
	testClaims := CreateTestJWTClaims(testUser.ID)

	// Mock token validation
	mockTokenManager.On("ValidateToken", "valid_token").Return(testClaims, nil)

	// Mock user not found
	mockUserRepo.On("GetUserByID", testUser.ID).Return(nil, assert.AnError)

	// Create request with valid token
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "User not found", response["message"])

	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestHandleGetUser_MethodNotAllowed(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	req := httptest.NewRequest(http.MethodPost, "/me", nil)
	w := httptest.NewRecorder()

	handler.HandleGetUser(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Method not allowed", response["message"])
}

func TestHandleGetUser_WithCookieToken(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create test user
	testUser := CreateTestUser()
	testClaims := CreateTestJWTClaims(testUser.ID)

	// Mock token validation
	mockTokenManager.On("ValidateToken", "cookie_token").Return(testClaims, nil)

	// Mock user retrieval
	mockUserRepo.On("GetUserByID", testUser.ID).Return(testUser, nil)

	// Create request with cookie token
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{
		Name:  "___goauth_access_token_auth_token",
		Value: "cookie_token",
	})
	w := httptest.NewRecorder()

	// Execute
	handler.HandleGetUser(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "John", response["first_name"])
	assert.Equal(t, "Doe", response["last_name"])

	// Verify mocks
	mockTokenManager.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}
