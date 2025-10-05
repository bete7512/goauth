package config

import "fmt"

type ConfigErr struct {
	Message string
}

func (e *ConfigErr) Error() string {
	return e.Message
}

func ErrConfig(message string) error {
	return &ConfigErr{Message: message}
}

func IsConfigErr(err error) bool {
	_, ok := err.(*ConfigErr)
	return ok
}

// Storage related errors
func ErrRepositoryNotFound(name string) error {
	return fmt.Errorf("repository %s not found", name)
}

func ErrRepositoryTypeMismatch(name string) error {
	return fmt.Errorf("repository %s is not of expected type", name)
}
