package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"slices"
)

// StringList is a list of strings stored as a JSON array in a text column.
type StringList []string

// Value encodes the list as a JSON array. A nil list is stored as "[]".
func (l StringList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	encoded, err := json.Marshal([]string(l))
	if err != nil {
		return nil, err
	}
	return string(encoded), nil
}

// Scan decodes a JSON array read from the database.
func (l *StringList) Scan(src interface{}) error {
	return scanJSONColumn(src, (*[]string)(l))
}

// GormDataType reports the column type used by GORM.
func (StringList) GormDataType() string { return "text" }

// Contains reports whether value is in the list.
func (l StringList) Contains(value string) bool {
	return slices.Contains(l, value)
}

// scanJSONColumn decodes a text or blob column holding JSON into target.
// NULL and the empty string leave target at its zero value.
func scanJSONColumn[T any](src interface{}, target *T) error {
	var raw []byte
	switch value := src.(type) {
	case nil:
	case string:
		raw = []byte(value)
	case []byte:
		raw = value
	default:
		return fmt.Errorf("unsupported JSON column type %T", src)
	}
	var zero T
	*target = zero
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, target)
}
