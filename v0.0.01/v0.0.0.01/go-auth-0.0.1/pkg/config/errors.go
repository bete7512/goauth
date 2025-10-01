package config

type ConfigErr struct {
	Message string
}

func (e *ConfigErr) Error() string {
	return e.Message
}

func NewConfigErr(message string) error {
	return &ConfigErr{Message: message}
}

func IsConfigErr(err error) bool {
	_, ok := err.(*ConfigErr)
	return ok
}
