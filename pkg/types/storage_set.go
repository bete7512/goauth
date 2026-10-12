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

func (s *StorageSet) Core() CoreStorage                 { return s.CoreStore }
func (s *StorageSet) Session() SessionStorage           { return s.SessionStore }
func (s *StorageSet) Stateless() StatelessStorage       { return s.StatelessStore }
func (s *StorageSet) Admin() AdminStorage               { return nil }
func (s *StorageSet) OAuth() OAuthStorage               { return s.OAuthStore }
func (s *StorageSet) TwoFactorAuth() TwoFactorStorage   { return s.TwoFactorStore }
func (s *StorageSet) Passkeys() PasskeyStorage          { return s.PasskeyStore }
func (s *StorageSet) AuditLog() AuditLogStorage         { return s.AuditStore }
func (s *StorageSet) Invitation() InvitationStorage     { return s.InvitationStore }
func (s *StorageSet) Organization() OrganizationStorage { return s.OrganizationStore }
func (s *StorageSet) DB() interface{}                   { return nil }
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
