package types

// Standard API response wrapper
type APIResponse[T any] struct {
	Data    T            `json:"data,omitempty"`
	Error   *GoAuthError `json:"error,omitempty"`
	Message *string      `json:"message,omitempty"`
}

// Pagination metadata
type PaginationMeta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// Paginated response
type PaginatedResponse[T any] struct {
	Data       []T            `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}
