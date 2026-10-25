package types

import "context"

// StorageSet adapts independently implemented feature stores to the legacy
// aggregate Storage contract. Applications fill only the capabilities they use.
// Stores are borrowed unless CloseFunc explicitly transfers cleanup ownership.
type StorageSet struct {
	CoreStore         CoreStorage
	SessionStore      SessionStorage
	StatelessStore    StatelessStorage
	OAuthStore        OAuthStorage
	TwoFactorStore    TwoFactorStorage
	PasskeyStore      PasskeyStorage
	AuditStore        AuditLogStorage
	InvitationStore   InvitationStorage
	OrganizationStore OrganizationStorage
	CloseFunc         func() error
}

// Core returns CoreStore.
func (s *StorageSet) Core() CoreStorage { return s.CoreStore }

// Session returns SessionStore.
func (s *StorageSet) Session() SessionStorage { return s.SessionStore }

// Stateless returns StatelessStore.
func (s *StorageSet) Stateless() StatelessStorage { return s.StatelessStore }

// Admin returns nil: a StorageSet has no administrative store.
func (s *StorageSet) Admin() AdminStorage { return nil }

// OAuth returns OAuthStore.
func (s *StorageSet) OAuth() OAuthStorage { return s.OAuthStore }

// TwoFactorAuth returns TwoFactorStore.
func (s *StorageSet) TwoFactorAuth() TwoFactorStorage { return s.TwoFactorStore }

// Passkeys returns PasskeyStore.
func (s *StorageSet) Passkeys() PasskeyStorage { return s.PasskeyStore }

// AuditLog returns AuditStore.
func (s *StorageSet) AuditLog() AuditLogStorage { return s.AuditStore }

// Invitation returns InvitationStore.
func (s *StorageSet) Invitation() InvitationStorage { return s.InvitationStore }

// Organization returns OrganizationStore.
func (s *StorageSet) Organization() OrganizationStorage { return s.OrganizationStore }

// DB returns nil: a StorageSet has no single underlying database handle.
func (s *StorageSet) DB() interface{} { return nil }

// Close calls CloseFunc when it is set.
func (s *StorageSet) Close() error {
	if s.CloseFunc != nil {
		return s.CloseFunc()
	}
	return nil
}

// TransactionalStorage binds every feature store in the callback to the same
// transaction. Separate custom stores must not be mixed into this callback.
type TransactionalStorage interface {
	WithTransaction(context.Context, func(Storage) error) error
}
