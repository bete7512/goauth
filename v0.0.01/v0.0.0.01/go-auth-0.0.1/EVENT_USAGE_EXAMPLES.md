# Event System Usage Examples

## Overview

The Event Bus is now **actively used** throughout the system. Here's how events flow through the authentication process.

## Event Flow Diagram

```
User Action → Core Module → Event Emitted → Multiple Modules Listen
     ↓
  Signup Request
     ↓
Core Module:
  1. Emit "before:signup" (SYNC) ────→ Validation modules can block
  2. Create user
  3. Emit "after:signup" (ASYNC) ───→ Email, Analytics, etc.
     ↓
  Response to user
```

## Currently Implemented Events

### 1. Signup Events

**Location**: `modules/core/handlers/signup.go`

```go
// BEFORE signup - synchronous, can block signup
h.deps.Events.EmitSync(ctx, "before:signup", map[string]interface{}{
    "email": email,
})

// AFTER signup - asynchronous, won't delay response
h.deps.Events.Emit(ctx, "after:signup", user)
```

**Who listens?**
- **Two-Factor Module**: If required, prompts user to set up 2FA
- **Email Module** (when created): Sends welcome email
- **Analytics Module** (when created): Tracks signup

### 2. Login Events

**Location**: `modules/core/handlers/login.go`

```go
// BEFORE login - synchronous, can block login
h.deps.Events.EmitSync(ctx, "before:login", loginData)

// AFTER login - asynchronous
h.deps.Events.Emit(ctx, "after:login", map[string]interface{}{
    "user":       user,
    "ip_address": ipAddress,
    "timestamp":  timestamp,
})
```

**Who listens?**
- **Two-Factor Module**: Checks if 2FA verification is needed
- **Fraud Detection** (when created): Blocks suspicious logins
- **Analytics Module** (when created): Tracks login events
- **Audit Log** (when created): Records login attempts

## Active Event Subscriptions

### Two-Factor Module

**Location**: `modules/twofactor/module.go`

```go
func (m *TwoFactorModule) RegisterHooks(events config.EventBus) error {
    // Listen to after:login
    events.Subscribe("after:login", func(ctx context.Context, event interface{}) error {
        // Check if 2FA is enabled for this user
        // If yes, verify they've completed 2FA challenge
        return nil
    })
    
    // If 2FA is required, listen to after:signup
    if m.config.Required {
        events.Subscribe("after:signup", func(ctx context.Context, event interface{}) error {
            // Prompt user to set up 2FA
            return nil
        })
    }
    
    return nil
}
```

## Creating Your Own Event Listeners

### Example 1: Email Notification Module

```go
package email

type EmailModule struct {
    deps    config.ModuleDependencies
    service *EmailService
}

func (m *EmailModule) RegisterHooks(events config.EventBus) error {
    // Send welcome email after signup
    events.Subscribe("after:signup", func(ctx context.Context, event interface{}) error {
        user := event.(map[string]interface{})
        email := user["email"].(string)
        
        return m.service.SendWelcomeEmail(email)
    })
    
    // Send password reset email
    events.Subscribe("password:reset:request", func(ctx context.Context, event interface{}) error {
        data := event.(map[string]interface{})
        email := data["email"].(string)
        token := data["token"].(string)
        
        return m.service.SendPasswordResetEmail(email, token)
    })
    
    return nil
}

// Register the module
auth.Use(email.New())
```

### Example 2: Analytics Module

```go
package analytics

type AnalyticsModule struct {
    deps    config.ModuleDependencies
    tracker *AnalyticsTracker
}

func (m *AnalyticsModule) RegisterHooks(events config.EventBus) error {
    // Track signup conversions
    events.Subscribe("after:signup", func(ctx context.Context, event interface{}) error {
        user := event.(map[string]interface{})
        return m.tracker.Track("signup", user["id"].(string))
    })
    
    // Track login events
    events.Subscribe("after:login", func(ctx context.Context, event interface{}) error {
        data := event.(map[string]interface{})
        user := data["user"].(map[string]interface{})
        return m.tracker.Track("login", user["id"].(string))
    })
    
    // Track 2FA adoption
    events.Subscribe("2fa:enabled", func(ctx context.Context, event interface{}) error {
        userID := event.(string)
        return m.tracker.Track("2fa_enabled", userID)
    })
    
    return nil
}
```

### Example 3: Fraud Detection Module

```go
package fraud

type FraudModule struct {
    deps     config.ModuleDependencies
    detector *FraudDetector
}

func (m *FraudModule) RegisterHooks(events config.EventBus) error {
    // Check BEFORE login (synchronous - can block login)
    events.Subscribe("before:login", func(ctx context.Context, event interface{}) error {
        data := event.(map[string]interface{})
        ipAddress := data["ip_address"].(string)
        
        if m.detector.IsSuspicious(ipAddress) {
            // This error will prevent the login!
            return fmt.Errorf("suspicious activity detected")
        }
        return nil
    })
    
    return nil
}
```

### Example 4: Audit Log Module

```go
package audit

type AuditModule struct {
    deps   config.ModuleDependencies
    logger *AuditLogger
}

func (m *AuditModule) RegisterHooks(events config.EventBus) error {
    // Log all authentication events
    events.Subscribe("after:login", func(ctx context.Context, event interface{}) error {
        data := event.(map[string]interface{})
        return m.logger.Log("LOGIN", data)
    })
    
    events.Subscribe("after:logout", func(ctx context.Context, event interface{}) error {
        return m.logger.Log("LOGOUT", event)
    })
    
    events.Subscribe("password:changed", func(ctx context.Context, event interface{}) error {
        return m.logger.Log("PASSWORD_CHANGED", event)
    })
    
    events.Subscribe("2fa:enabled", func(ctx context.Context, event interface{}) error {
        return m.logger.Log("2FA_ENABLED", event)
    })
    
    return nil
}
```

## Available Event Types

### User Events
- `before:signup` - Before user creation (can block)
- `after:signup` - After user created
- `before:login` - Before login (can block)
- `after:login` - After successful login
- `before:logout` - Before logout
- `after:logout` - After logout

### Security Events
- `password:changed` - Password updated
- `password:reset:request` - Password reset requested
- `password:reset` - Password reset completed
- `2fa:enabled` - 2FA enabled for user
- `2fa:disabled` - 2FA disabled
- `2fa:verified` - 2FA challenge passed

### Session Events
- `session:created` - New session created
- `session:expired` - Session expired
- `session:revoked` - Session manually revoked

## Synchronous vs Asynchronous Events

### EmitSync - Synchronous (Blocks)
```go
// Use for validation that should block the action
if err := events.EmitSync(ctx, "before:login", data); err != nil {
    // Login is blocked!
    return err
}
```

**Use cases:**
- Validation
- Fraud detection
- Rate limiting checks
- Required 2FA verification

### Emit - Asynchronous (Non-blocking)
```go
// Use for notifications and logging
events.Emit(ctx, "after:signup", user)
// Continues immediately, don't wait for email to send
```

**Use cases:**
- Sending emails
- Analytics tracking
- Audit logging
- Webhooks
- Slack notifications

## Complete Integration Example

```go
package main

func main() {
    // 1. Create auth instance
    auth, _ := auth.New(&config.Config{
        // ... config
    })
    
    // 2. Register modules (they auto-register their event listeners)
    auth.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Required: true, // Will subscribe to "after:signup"
    }))
    
    auth.Use(email.New()) // Subscribes to signup/login events
    auth.Use(analytics.New()) // Subscribes to all events
    auth.Use(fraud.New()) // Subscribes to "before:login"
    auth.Use(audit.New()) // Subscribes to all security events
    
    // 3. Initialize (calls RegisterHooks on all modules)
    auth.Initialize(context.Background())
    
    // Now when user signs up:
    // 1. Core emits "before:signup" → fraud module validates
    // 2. Core creates user
    // 3. Core emits "after:signup" → email, analytics, 2FA, audit all react
}
```

## Testing Event Handlers

```go
func TestEmailModule(t *testing.T) {
    // Create mock event bus
    mockEvents := &MockEventBus{}
    
    // Create module
    emailModule := email.New()
    emailModule.RegisterHooks(mockEvents)
    
    // Trigger event
    mockEvents.Emit(context.Background(), "after:signup", map[string]interface{}{
        "email": "test@example.com",
    })
    
    // Verify email was sent
    assert.True(t, mockEvents.EmailSent("test@example.com"))
}
```

## Why This Approach Works

✅ **Core stays simple** - Just emits events, doesn't know about email/analytics
✅ **Easy to extend** - Add new modules without modifying existing code
✅ **Testable** - Test modules independently
✅ **Optional features** - Don't register modules you don't need
✅ **Async operations** - Emails/logging don't slow down responses
✅ **Blocking when needed** - Fraud detection can prevent malicious logins

## What's Next?

You can now:
1. Create custom modules that listen to these events
2. Add more event types as needed
3. Use events to decouple your features
4. Build a plugin system around the event bus

The Event Bus is the **backbone** that makes this modular architecture work! 🎯 