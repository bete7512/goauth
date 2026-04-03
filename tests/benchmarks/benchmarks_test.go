package benchmarks

import (
	"testing"

	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/types"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// 1. BenchmarkPasswordHash -- bcrypt hash with default cost
// ---------------------------------------------------------------------------

func BenchmarkPasswordHash(b *testing.B) {
	password := []byte("SuperSecretP@ssw0rd!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. BenchmarkJWTGeneration -- Generate access token
// ---------------------------------------------------------------------------

func BenchmarkJWTGeneration(b *testing.B) {
	sm := testutil.TestSecurityManager()
	user := *testutil.TestUser()
	claims := map[string]interface{}{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm.GenerateAccessToken(user, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. BenchmarkJWTValidation -- Validate a pre-generated token (parallel)
// ---------------------------------------------------------------------------

func BenchmarkJWTValidation(b *testing.B) {
	sm := testutil.TestSecurityManager()
	user := *testutil.TestUser()
	token, err := sm.GenerateAccessToken(user, map[string]interface{}{})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, vErr := sm.ValidateJWTToken(token)
			if vErr != nil {
				b.Fatal(vErr)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. BenchmarkTokenPairGeneration -- Generate access + refresh token pair
// ---------------------------------------------------------------------------

func BenchmarkTokenPairGeneration(b *testing.B) {
	sm := testutil.TestSecurityManager()
	user := testutil.TestUser()
	claims := map[string]interface{}{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := sm.GenerateTokens(user, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. BenchmarkEncryptDecrypt -- AES-256-GCM round-trip
// ---------------------------------------------------------------------------

func BenchmarkEncryptDecrypt(b *testing.B) {
	sm := testutil.TestSecurityManager()
	plaintext := "sensitive-user-data-that-needs-encryption"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := sm.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
		_, err = sm.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. BenchmarkRandomTokenGeneration -- Generate 32-byte random token
// ---------------------------------------------------------------------------

func BenchmarkRandomTokenGeneration(b *testing.B) {
	sm := testutil.TestSecurityManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm.GenerateRandomToken(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. BenchmarkHashRefreshToken -- SHA-256 token hashing (parallel)
// ---------------------------------------------------------------------------

func BenchmarkHashRefreshToken(b *testing.B) {
	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = security.HashRefreshToken(token)
		}
	})
}

// ---------------------------------------------------------------------------
// 9. BenchmarkNumericOTP -- Generate 6-digit numeric OTP
// ---------------------------------------------------------------------------

func BenchmarkNumericOTP(b *testing.B) {
	sm := testutil.TestSecurityManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm.GenerateNumericOTP(6)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// noopLogger satisfies types.Logger for benchmarks where log output is irrelevant.
type noopLogger struct{}

var _ types.Logger = (*noopLogger)(nil)

func (l *noopLogger) Info(string, ...interface{})                    {}
func (l *noopLogger) Error(string, ...interface{})                   {}
func (l *noopLogger) Warn(string, ...interface{})                    {}
func (l *noopLogger) Debug(string, ...interface{})                   {}
func (l *noopLogger) Trace(string, ...interface{})                   {}
func (l *noopLogger) Infof(string, ...interface{})                   {}
func (l *noopLogger) Errorf(string, ...interface{})                  {}
func (l *noopLogger) Debugf(string, ...interface{})                  {}
func (l *noopLogger) Warnf(string, ...interface{})                   {}
func (l *noopLogger) Tracef(string, ...interface{})                  {}
func (l *noopLogger) Fatalf(string, ...interface{})                  {}
func (l *noopLogger) WithFields(map[string]interface{}) types.Logger { return l }
