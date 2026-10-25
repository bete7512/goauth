package config

import "fmt"

// ConfigErr is a configuration error; detect it with IsConfigErr.
type ConfigErr struct {
	Message string
}

// Error returns the message.
func (e *ConfigErr) Error() string {
	return e.Message
}

// ErrConfig returns a configuration error with message.
func ErrConfig(message string) error {
	return &ConfigErr{Message: message}
}

// IsConfigErr reports whether err was created by ErrConfig.
func IsConfigErr(err error) bool {
	_, ok := err.(*ConfigErr)
	return ok
}

// Storage related errors

// ErrRepositoryNotFound returns an error naming a repository that is missing.
func ErrRepositoryNotFound(name string) error {
	return fmt.Errorf("repository %s not found", name)
}

// ErrRepositoryTypeMismatch returns an error naming a repository of an
// unexpected type.
func ErrRepositoryTypeMismatch(name string) error {
	return fmt.Errorf("repository %s is not of expected type", name)
}
