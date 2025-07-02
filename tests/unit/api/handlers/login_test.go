package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/schemas"
	models "github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestHandleLogin_Success(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Create test user
	testUser := CreateTestUser()
	testUser.Password = "hashed_password"

	// Mock user retrieval
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return(testUser, nil)

	// Mock password validation
	mockTokenManager.On("ValidatePassword", "hashed_password", "password123").Return(nil)

	// Mock token generation
	mockTokenManager.On("GenerateTokens", testUser).Return("access_token", "refresh_token", nil)

	// Mock token saving
	mockTokenRepo.On("SaveToken", testUser.ID, "refresh_token", models.RefreshToken, time.Duration(86400)).Return(nil)

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check that user data is in the response
	userData, exists := response["user"].(map[string]interface{})
	assert.True(t, exists)
	assert.Equal(t, "test@example.com", userData["email"])
	assert.Equal(t, "John", userData["first_name"])
	assert.Equal(t, "Doe", userData["last_name"])

	// Check that tokens are in the response
	assert.Contains(t, response, "access_token")
	assert.Contains(t, response, "refresh_token")

	// Verify mocks
	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogin_UserNotFound(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Mock user not found
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return((*models.User)(nil), errors.New("user not found"))

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user not found", response["message"])

	mockUserRepo.AssertExpectations(t)
}

func TestHandleLogin_InvalidPassword(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Create test user
	testUser := CreateTestUser()
	testUser.Password = "hashed_password"

	// Mock user retrieval
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return(testUser, nil)

	// Mock password validation failure
	mockTokenManager.On("ValidatePassword", "hashed_password", "wrongpassword").Return(errors.New("invalid password"))

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid email or password", response["message"])

	mockUserRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}

func TestHandleLogin_UserInactive(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Create inactive test user
	testUser := CreateTestUser()
	active := false
	testUser.Active = &active

	// Mock user retrieval
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return(testUser, nil)

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "account is deactivated", response["message"])

	mockUserRepo.AssertExpectations(t)
}

func TestHandleLogin_EmailNotVerified(t *testing.T) {
	config := CreateTestConfig()
	config.AuthConfig.Methods.EmailVerification.EnableOnSignup = true
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)

	// Create unverified test user
	testUser := CreateTestUser()
	emailVerified := false
	testUser.EmailVerified = &emailVerified

	// Mock user retrieval
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return(testUser, nil)

	// Mock password validation success
	mockTokenManager.On("ValidatePassword", "hashed_password", "password123").Return(nil)

	// Mock token generation
	mockTokenManager.On("GenerateTokens", testUser).Return("access_token", "refresh_token", nil)

	// Mock token saving
	mockTokenRepo.On("SaveToken", testUser.ID, "refresh_token", models.RefreshToken, time.Duration(86400)).Return(nil)

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions - login should succeed even with unverified email
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotNil(t, response["user"])
	assert.NotNil(t, response["access_token"])
	assert.NotNil(t, response["refresh_token"])

	mockUserRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "method not allowed", response["message"])
}

func TestHandleLogin_InvalidJSON(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["message"], "invalid request body")
}

func TestHandleLogin_DatabaseError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Mock database error
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return((*models.User)(nil), errors.New("database connection failed"))

	// Create request
	reqBody := schemas.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLogin(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid email or password", response["message"])

	mockUserRepo.AssertExpectations(t)
}
