# GoAuth Core & Notification Modules - Task Breakdown

## 🎯 Goal
Get the **Core Module** and **Notification Module** working with comprehensive test coverage for all endpoints.

## 📊 Current Status Analysis

### ✅ What's Already Implemented
- **Core Module**: Complete handlers for auth, profile, availability checks
- **Notification Module**: Complete handlers for verification, password reset
- **Example Setup**: Working `main.go` with both modules configured
- **Database Models**: User, Session, Token, VerificationToken models
- **Service Layer**: Business logic separated from HTTP handlers

### ❌ What's Missing
- **No Tests**: Empty test directories (`tests/unit/`, `tests/integration/`, `tests/e2e/`)
- **Test Infrastructure**: No test setup, mocks, or test utilities
- **Endpoint Validation**: No verification that endpoints work correctly
- **Integration Testing**: No tests for module interactions

## 🚀 Task Breakdown

### Phase 1: Test Infrastructure Setup (Priority: HIGH)

#### 1.1 Create Test Utilities
- [ ] **File**: `tests/testutils/setup.go`
  - Database test setup/teardown
  - Mock storage implementations
  - Test configuration helpers
  - Common test data fixtures

- [ ] **File**: `tests/testutils/mocks.go`
  - Mock email sender
  - Mock SMS sender
  - Mock event bus
  - Mock repositories

- [ ] **File**: `tests/testutils/helpers.go`
  - HTTP request helpers
  - Response assertion helpers
  - Test user creation helpers
  - Token generation helpers

#### 1.2 Test Configuration
- [ ] **File**: `tests/config/test_config.go`
  - Test database configuration
  - Test security keys
  - Test notification settings
  - Environment-specific configs

### Phase 2: Core Module Testing (Priority: HIGH)

#### 2.1 Authentication Endpoints
- [ ] **File**: `tests/unit/core_auth_test.go`
  - `POST /signup` - User registration
    - ✅ Valid signup
    - ❌ Duplicate email
    - ❌ Invalid email format
    - ❌ Weak password
    - ❌ Missing required fields
  - `POST /login` - User authentication
    - ✅ Valid login with email
    - ✅ Valid login with username
    - ❌ Invalid credentials
    - ❌ Non-existent user
    - ❌ Account locked/disabled
  - `POST /logout` - Session termination
    - ✅ Valid logout
    - ❌ Invalid token
    - ❌ Expired token

#### 2.2 Profile Management Endpoints
- [ ] **File**: `tests/unit/core_profile_test.go`
  - `GET /profile` - Get user profile
    - ✅ Authenticated user
    - ❌ Unauthenticated request
    - ❌ Invalid token
  - `PUT /profile` - Update profile
    - ✅ Valid update
    - ❌ Invalid data
    - ❌ Unauthorized access
  - `PUT /change-password` - Change password
    - ✅ Valid password change
    - ❌ Wrong old password
    - ❌ Weak new password

#### 2.3 Availability Check Endpoints
- [ ] **File**: `tests/unit/core_availability_test.go`
  - `POST /availability/email` - Check email availability
  - `POST /availability/username` - Check username availability
  - `POST /availability/phone` - Check phone availability

#### 2.4 User Management Endpoints
- [ ] **File**: `tests/unit/core_user_test.go`
  - `GET /me` - Get current user info
    - ✅ Authenticated user
    - ❌ Unauthenticated request

### Phase 3: Notification Module Testing (Priority: HIGH)

#### 3.1 Email Verification Endpoints
- [ ] **File**: `tests/unit/notification_email_test.go`
  - `POST /send-verification-email` - Send verification email
    - ✅ Valid email
    - ❌ Invalid email format
    - ❌ Non-existent user
    - ❌ Already verified email
  - `POST /resend-verification-email` - Resend verification
  - `POST /verify-email` - Verify email with token
    - ✅ Valid token
    - ❌ Invalid token
    - ❌ Expired token

#### 3.2 Phone Verification Endpoints
- [ ] **File**: `tests/unit/notification_phone_test.go`
  - `POST /send-verification-phone` - Send verification SMS
  - `POST /resend-verification-phone` - Resend verification SMS
  - `POST /verify-phone` - Verify phone with code

#### 3.3 Password Recovery Endpoints
- [ ] **File**: `tests/unit/notification_password_test.go`
  - `POST /forgot-password` - Initiate password reset
    - ✅ Valid email
    - ❌ Invalid email
    - ❌ Non-existent user

### Phase 4: Integration Testing (Priority: MEDIUM)

#### 4.1 Module Integration Tests
- [ ] **File**: `tests/integration/module_integration_test.go`
  - Core + Notification module interaction
  - Signup flow with email verification
  - Login flow with 2FA
  - Password reset flow

#### 4.2 Database Integration Tests
- [ ] **File**: `tests/integration/database_test.go`
  - User creation and retrieval
  - Session management
  - Token storage and validation
  - Verification token lifecycle

#### 4.3 Event System Tests
- [ ] **File**: `tests/integration/events_test.go`
  - Event emission and handling
  - Custom event hooks
  - Event-driven workflows

### Phase 5: End-to-End Testing (Priority: MEDIUM)

#### 5.1 Complete User Flows
- [ ] **File**: `tests/e2e/user_registration_flow_test.go`
  - Complete signup → email verification → login flow
  - Profile update flow
  - Password change flow

- [ ] **File**: `tests/e2e/password_recovery_flow_test.go`
  - Forgot password → email → reset → login flow

- [ ] **File**: `tests/e2e/phone_verification_flow_test.go`
  - Phone verification flow

### Phase 6: Performance & Security Testing (Priority: LOW)

#### 6.1 Performance Tests
- [ ] **File**: `tests/performance/load_test.go`
  - Concurrent user signup
  - High-frequency login attempts
  - Database performance under load

#### 6.2 Security Tests
- [ ] **File**: `tests/security/security_test.go`
  - SQL injection attempts
  - XSS prevention
  - CSRF protection
  - Rate limiting

## 🛠️ Implementation Strategy

### Step 1: Start with Test Infrastructure
```bash
# Create test utilities first
mkdir -p tests/testutils
mkdir -p tests/config
```

### Step 2: Core Module Tests (Start Here)
```bash
# Begin with authentication endpoints
touch tests/unit/core_auth_test.go
```

### Step 3: Notification Module Tests
```bash
# Add notification tests
touch tests/unit/notification_email_test.go
```

### Step 4: Integration Tests
```bash
# Test module interactions
touch tests/integration/module_integration_test.go
```

## 📋 Testing Checklist

### For Each Endpoint Test:
- [ ] **Happy Path**: Valid request → Success response
- [ ] **Error Cases**: Invalid input → Proper error response
- [ ] **Authentication**: Protected endpoints require valid auth
- [ ] **Authorization**: Users can only access their own data
- [ ] **Validation**: Input validation works correctly
- [ ] **Database**: Data is stored/retrieved correctly
- [ ] **Events**: Appropriate events are emitted
- [ ] **Response Format**: Consistent response structure

### For Each Module:
- [ ] **All Endpoints Covered**: Every route has tests
- [ ] **Service Layer**: Business logic is tested
- [ ] **Error Handling**: All error cases covered
- [ ] **Integration**: Module works with dependencies
- [ ] **Configuration**: Different configs work correctly

## 🎯 Success Criteria

### Minimum Viable Testing:
1. **Core Module**: All 9 endpoints tested (signup, login, logout, profile, etc.)
2. **Notification Module**: All 7 endpoints tested (verification, password reset)
3. **Integration**: Modules work together correctly
4. **E2E**: Complete user flows work end-to-end

### Test Coverage Goals:
- **Unit Tests**: 80%+ coverage for handlers and services
- **Integration Tests**: All module interactions covered
- **E2E Tests**: Complete user journeys tested

## 🚀 Getting Started

### Quick Start Commands:
```bash
# 1. Set up test infrastructure
mkdir -p tests/{testutils,config,unit,integration,e2e}

# 2. Start with core auth tests
touch tests/unit/core_auth_test.go

# 3. Run tests
go test ./tests/unit/...

# 4. Add notification tests
touch tests/unit/notification_email_test.go

# 5. Run all tests
go test ./tests/...
```

### Test Database Setup:
```bash
# Use test database
export DB_DSN="host=localhost user=postgres password=password dbname=authdb_test port=5432 sslmode=disable"
```

## 📝 Notes

- **Start Small**: Begin with one endpoint, get it working, then expand
- **Mock External Services**: Use mocks for email/SMS to avoid external dependencies
- **Test Data**: Use consistent test data across all tests
- **Cleanup**: Always clean up test data after tests
- **Documentation**: Document any test-specific setup requirements

---

**Next Steps**: Start with Phase 1 (Test Infrastructure) and work through each phase systematically. Focus on getting Core Module tests working first, then add Notification Module tests.
