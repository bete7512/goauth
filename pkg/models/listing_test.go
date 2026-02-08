package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultListingOpts(t *testing.T) {
	opts := DefaultListingOpts()
	assert.Equal(t, 0, opts.Offset)
	assert.Equal(t, 20, opts.Limit)
	assert.Equal(t, "created_at", opts.SortField)
	assert.Equal(t, "desc", opts.SortDir)
}

func TestListingOpts_Normalize(t *testing.T) {
	allowed := map[string]bool{"created_at": true, "email": true}

	tests := []struct {
		name     string
		opts     ListingOpts
		maxLimit int
		want     ListingOpts
	}{
		{
			name:     "defaults for zero values",
			opts:     ListingOpts{},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 20, SortField: "created_at", SortDir: "desc"},
		},
		{
			name:     "clamps limit to max",
			opts:     ListingOpts{Limit: 500},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 100, SortField: "created_at", SortDir: "desc"},
		},
		{
			name:     "negative offset becomes zero",
			opts:     ListingOpts{Offset: -5, Limit: 10},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 10, SortField: "created_at", SortDir: "desc"},
		},
		{
			name:     "invalid sort dir defaults to desc",
			opts:     ListingOpts{Limit: 10, SortDir: "invalid"},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 10, SortField: "created_at", SortDir: "desc"},
		},
		{
			name:     "asc sort dir preserved",
			opts:     ListingOpts{Limit: 10, SortDir: "asc", SortField: "email"},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 10, SortField: "email", SortDir: "asc"},
		},
		{
			name:     "disallowed sort field falls back to created_at",
			opts:     ListingOpts{Limit: 10, SortField: "password"},
			maxLimit: 100,
			want:     ListingOpts{Offset: 0, Limit: 10, SortField: "created_at", SortDir: "desc"},
		},
		{
			name:     "maxLimit zero means no cap",
			opts:     ListingOpts{Limit: 9999},
			maxLimit: 0,
			want:     ListingOpts{Offset: 0, Limit: 9999, SortField: "created_at", SortDir: "desc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Normalize(tt.maxLimit, allowed)
			assert.Equal(t, tt.want, tt.opts)
		})
	}
}

func TestUserListOpts_Normalize(t *testing.T) {
	opts := UserListOpts{
		ListingOpts: ListingOpts{Limit: 200, SortField: "email"},
		Query:       "  alice  ",
	}
	opts.Normalize(100)

	assert.Equal(t, 100, opts.Limit)
	assert.Equal(t, "email", opts.SortField)
	assert.Equal(t, "alice", opts.Query)
}

func TestUserListOpts_Normalize_DisallowedSortField(t *testing.T) {
	opts := UserListOpts{
		ListingOpts: ListingOpts{Limit: 10, SortField: "password"},
	}
	opts.Normalize(100)
	assert.Equal(t, "created_at", opts.SortField)
}

func TestSessionListOpts_Normalize(t *testing.T) {
	opts := SessionListOpts{
		ListingOpts: ListingOpts{Limit: 200, SortField: "expires_at", SortDir: "asc"},
	}
	opts.Normalize(50)

	assert.Equal(t, 50, opts.Limit)
	assert.Equal(t, "expires_at", opts.SortField)
	assert.Equal(t, "asc", opts.SortDir)
}

func TestSessionListOpts_Normalize_DisallowedSortField(t *testing.T) {
	opts := SessionListOpts{
		ListingOpts: ListingOpts{Limit: 10, SortField: "refresh_token"},
	}
	opts.Normalize(100)
	assert.Equal(t, "created_at", opts.SortField)
}

func TestAuditLogListOpts_Normalize(t *testing.T) {
	opts := AuditLogListOpts{
		ListingOpts: ListingOpts{Limit: 300, SortField: "severity"},
	}
	opts.Normalize(100)

	assert.Equal(t, 100, opts.Limit)
	assert.Equal(t, "severity", opts.SortField)
}

func TestAuditLogListOpts_Normalize_DisallowedSortField(t *testing.T) {
	opts := AuditLogListOpts{
		ListingOpts: ListingOpts{Limit: 10, SortField: "ip_address"},
	}
	opts.Normalize(100)
	assert.Equal(t, "created_at", opts.SortField)
}
