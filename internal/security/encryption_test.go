package security

import (
	"testing"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encryptionManager() *SecurityManager {
	return NewSecurityManager(types.SecurityConfig{
		EncryptionKey: "test-encryption-key-for-tests!",
	})
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	mgr := encryptionManager()
	plaintext := "sensitive-oauth-token-xyz123"

	encrypted, err := mgr.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted, "encrypted output must differ from plaintext")

	decrypted, err := mgr.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	mgr := encryptionManager()

	encrypted, err := mgr.Encrypt("")
	require.NoError(t, err)

	decrypted, err := mgr.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "", decrypted)
}

func TestEncryptDecrypt_LongData(t *testing.T) {
	mgr := encryptionManager()
	plaintext := string(make([]byte, 10000))

	encrypted, err := mgr.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := mgr.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_DifferentOutputEachCall(t *testing.T) {
	mgr := encryptionManager()
	plaintext := "same input"

	enc1, err := mgr.Encrypt(plaintext)
	require.NoError(t, err)

	enc2, err := mgr.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "different nonces should produce different ciphertexts")
}

func TestEncrypt_FailsWithoutKey(t *testing.T) {
	mgr := NewSecurityManager(types.SecurityConfig{EncryptionKey: ""})

	_, err := mgr.Encrypt("data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key not configured")
}

func TestDecrypt_FailsWithoutKey(t *testing.T) {
	mgr := NewSecurityManager(types.SecurityConfig{EncryptionKey: ""})

	_, err := mgr.Decrypt("data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key not configured")
}

func TestDecrypt_FailsWithWrongKey(t *testing.T) {
	mgr1 := encryptionManager()
	mgr2 := NewSecurityManager(types.SecurityConfig{EncryptionKey: "different-key"})

	encrypted, err := mgr1.Encrypt("secret")
	require.NoError(t, err)

	_, err = mgr2.Decrypt(encrypted)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestDecrypt_FailsWithCorruptedData(t *testing.T) {
	mgr := encryptionManager()

	_, err := mgr.Decrypt("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecrypt_FailsWithTruncatedCiphertext(t *testing.T) {
	mgr := encryptionManager()

	encrypted, err := mgr.Encrypt("test data")
	require.NoError(t, err)

	// Truncate the ciphertext
	_, err = mgr.Decrypt(encrypted[:8])
	assert.Error(t, err)
}

func TestDeriveKey_Deterministic(t *testing.T) {
	k1 := deriveKey("my-passphrase")
	k2 := deriveKey("my-passphrase")
	assert.Equal(t, k1, k2)
	assert.Len(t, k1, 32, "AES-256 key must be 32 bytes")
}

func TestDeriveKey_DifferentInputsDifferentKeys(t *testing.T) {
	k1 := deriveKey("key-a")
	k2 := deriveKey("key-b")
	assert.NotEqual(t, k1, k2)
}
