package types

// APIResponse is the JSON envelope of the built-in endpoints. The payload, or
// the GoAuthError of a failed request, is under "data", with an optional message.
type APIResponse[T any] struct {
	Data    T            `json:"data,omitempty"`
	Error   *GoAuthError `json:"error,omitempty"`
	Message *string      `json:"message,omitempty"`
}

// ListResponse is the standard shape for all listing endpoints.
type ListResponse[T any] struct {
	List      []T    `json:"list"`
	SortField string `json:"sort_field"`
	SortDir   string `json:"sort_dir"`
	Total     int64  `json:"total"`
}
