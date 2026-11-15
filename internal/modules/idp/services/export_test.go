package services

// Internals the mock-based tests in services_test need. The mocks package
// imports this one, so those tests cannot live inside it.

// TokenData is the stored state behind an access or refresh token.
type TokenData = tokenData

// CredentialBinding identifies a user's password.
var CredentialBinding = credentialBinding

// ClientSecretDigest is the stored form of a client secret.
var ClientSecretDigest = clientSecretDigest
