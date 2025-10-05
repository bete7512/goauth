# Core Module Services

## Architecture Overview

The service layer contains **all business logic** separated from HTTP concerns. Handlers are thin and only deal with HTTP request/response, while services contain the actual business logic.

## Service Files

### 1. **auth.go** - Authentication Services
- `Signup()` - User registration with validation, password hashing, and session creation
- `Login()` - User authentication with credential verification and session management
- `Logout()` - Session invalidation
- `GetCurrentUser()` - Retrieve user from session token

### 2. **verification.go** - Email & Phone Verification Services
- `SendVerificationEmail()` - Generate and send email verification token
- `VerifyEmail()` - Verify email with token
- `ResendVerificationEmail()` - Resend verification email
- `SendVerificationPhone()` - Generate and send SMS verification code
- `VerifyPhone()` - Verify phone with 6-digit code
- `ResendVerificationPhone()` - Resend verification SMS

### 3. **password.go** - Password Management Services
- `ForgotPassword()` - Initiate password reset (email/SMS)
- `ResetPassword()` - Reset password using token/code
- `ChangePassword()` - Change password (requires old password)

### 4. **profile.go** - Profile Management Services
- `GetProfile()` - Retrieve user profile
- `UpdateProfile()` - Update user profile information

### 5. **utility.go** - Utility Services
- `CheckAvailability()` - Check if email/username/phone is available

## Key Features

### ✅ **Complete Business Logic Separation**
- Handlers only parse requests and format responses
- Services contain all business logic
- Easy to test services independently
- Can reuse services in different contexts (HTTP, gRPC, CLI, etc.)

### ✅ **Security Best Practices**
- Password hashing with bcrypt
- Secure token generation using crypto/rand
- Session expiration handling
- Account status checking
- Duplicate checking for email/username/phone

### ✅ **Event-Driven**
- Emits events for important actions (signup, login, password change, etc.)
- Notification module can listen to these events
- Async event handling for non-blocking operations

### ✅ **Error Handling**
- Clear error messages
- Proper error wrapping
- Security-conscious (doesn't reveal if user exists in forgot password)

## Usage Example

### In Handlers

```go
func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // 1. Parse request
    var req dto.SignupRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.jsonError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // 2. Validate request
    if err := req.Validate(); err != nil {
        h.jsonError(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 3. Emit before:signup event (for checks, rate limiting, etc.)
    signupData := map[string]interface{}{
        "email":    req.Email,
        "username": req.Username,
    }
    if err := h.deps.Events.EmitSync(ctx, "before:signup", signupData); err != nil {
        h.jsonError(w, "Signup blocked: "+err.Error(), http.StatusForbidden)
        return
    }

    // 4. Call service - ALL business logic here
    response, err := h.CoreService.Signup(ctx, &req)
    if err != nil {
        h.jsonError(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 5. Set session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_token",
        Value:    response.Token,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        Path:     "/",
        MaxAge:   86400, // 24 hours
    })

    // 6. Return response
    h.jsonSuccess(w, response)
}
```

### Service Implementation

```go
func (s *CoreService) Signup(ctx context.Context, req *dto.SignupRequest) (*dto.AuthResponse, error) {
    // 1. Check if user exists
    if req.Email != "" {
        existing, _ := s.UserRepository.FindByEmail(ctx, req.Email)
        if existing != nil {
            return nil, errors.New("user with this email already exists")
        }
    }

    // 2. Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }

    // 3. Create user
    user := &models.User{
        ID:           uuid.New().String(),
        Email:        req.Email,
        Username:     req.Username,
        PasswordHash: string(hashedPassword),
        Name:         req.Name,
        Phone:        req.Phone,
        Active:       true,
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
    }

    if err := s.UserRepository.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    // 4. Create session
    sessionToken, _ := generateSecureToken(32)
    session := &models.Session{
        ID:        uuid.New().String(),
        UserID:    user.ID,
        Token:     sessionToken,
        ExpiresAt: time.Now().Add(24 * time.Hour),
        CreatedAt: time.Now(),
    }

    if err := s.SessionRepository.Create(ctx, session); err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    // 5. Emit event
    s.deps.Events.Emit(ctx, "after:signup", map[string]interface{}{
        "user_id": user.ID,
        "email":   user.Email,
    })

    // 6. Return response
    return &dto.AuthResponse{
        Token: sessionToken,
        User:  toUserDTO(user),
        ExpiresIn: 86400,
        Message: "Signup successful",
    }, nil
}
```

## Handler Responsibilities

✅ **DO** in Handlers:
- Parse HTTP request body
- Validate request DTOs
- Emit `before:*` events for rate limiting, fraud detection
- Call service methods
- Set HTTP headers and cookies
- Format HTTP responses
- Handle HTTP status codes

❌ **DON'T** in Handlers:
- Business logic
- Database queries
- Password hashing
- Token generation
- Complex validations

## Service Responsibilities

✅ **DO** in Services:
- All business logic
- Database operations via repositories
- Password hashing and verification
- Token/code generation
- Duplicate checking
- Data transformations
- Emit `after:*` events for notifications, analytics
- Error handling with meaningful messages

❌ **DON'T** in Services:
- HTTP concerns (headers, status codes, cookies)
- Parse HTTP requests
- Format HTTP responses

## Events Emitted

### Auth Events
- `after:signup` - After successful user registration
- `after:login` - After successful login
- `after:logout` - After logout

### Verification Events
- `email:verification:sent` - Email verification link sent
- `email:verified` - Email successfully verified
- `phone:verification:sent` - SMS verification code sent
- `phone:verified` - Phone successfully verified

### Password Events
- `password:reset:request` - Password reset requested (email)
- `password:reset:sms` - Password reset requested (SMS)
- `password:changed` - Password changed/reset

### Profile Events
- `profile:updated` - User profile updated

## Testing

Services are easy to unit test without HTTP concerns:

```go
func TestSignup(t *testing.T) {
    // Mock repositories
    mockUserRepo := &MockUserRepository{}
    mockSessionRepo := &MockSessionRepository{}
    
    // Create service
    service := NewCoreService(deps, mockUserRepo, mockSessionRepo, tokenRepo)
    
    // Test
    req := &dto.SignupRequest{
        Email:    "test@example.com",
        Password: "securePassword123",
    }
    
    response, err := service.Signup(context.Background(), req)
    
    assert.NoError(t, err)
    assert.NotNil(t, response)
    assert.Equal(t, "test@example.com", response.User.Email)
}
```

## Migration Notes

To migrate existing handlers:

1. **Move business logic** from handler to service method
2. **Keep only HTTP concerns** in handler
3. **Service returns DTOs**, not HTTP responses
4. **Handler formats** the DTO into HTTP response
5. **Emit events** from services, not handlers (except `before:*` events)

## Benefits

✅ **Testability** - Easy to unit test services  
✅ **Reusability** - Services can be used in different contexts  
✅ **Maintainability** - Clear separation of concerns  
✅ **Scalability** - Easy to add new features  
✅ **Security** - Centralized security logic  
✅ **Consistency** - Consistent error handling and responses  

