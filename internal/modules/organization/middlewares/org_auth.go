package middlewares

import (
	"context"
	"net/http"
	"strings"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type OrgAuthMiddleware struct {
	orgRepo    models.OrganizationRepository
	memberRepo models.OrganizationMemberRepository
	logger     types.Logger
}

func NewOrgAuthMiddleware(orgRepo models.OrganizationRepository, memberRepo models.OrganizationMemberRepository, logger types.Logger) *OrgAuthMiddleware {
	return &OrgAuthMiddleware{
		orgRepo:    orgRepo,
		memberRepo: memberRepo,
		logger:     logger,
	}
}

// Middleware returns the org context extraction middleware.
// It reads the org ID from the URL path parameter (extracted by the router as part of the path).
// Since stdlib http doesn't have path params, org routes use the pattern /org/{orgId}/...
// The middleware extracts orgId from the URL path.
func (m *OrgAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get user ID from context (set by auth middleware)
		userID, ok := ctx.Value(types.UserIDKey).(string)
		if !ok || userID == "" {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Authentication required")
			return
		}

		// Extract org ID from URL path
		// Routes are like: /org/{orgId}/members, /org/{orgId}/invite
		orgID := extractOrgIDFromPath(r.URL.Path)
		if orgID == "" {
			// Try X-Organization-ID header as fallback
			orgID = r.Header.Get("X-Organization-ID")
		}
		if orgID == "" {
			http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrOrgNotFound), "Organization ID is required")
			return
		}

		// Validate org exists and is active
		org, err := m.orgRepo.FindByID(ctx, orgID)
		if err != nil || org == nil {
			http_utils.RespondError(w, http.StatusNotFound, string(types.ErrOrgNotFound), "Organization not found")
			return
		}
		if !org.Active {
			http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgNotFound), "Organization is not active")
			return
		}

		// Validate user is member
		member, err := m.memberRepo.FindByOrgAndUser(ctx, orgID, userID)
		if err != nil || member == nil {
			http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgNotMember), "You are not a member of this organization")
			return
		}

		// Set org context
		ctx = context.WithValue(ctx, types.OrgIDKey, org.ID)
		ctx = context.WithValue(ctx, types.OrgRoleKey, member.Role)
		ctx = context.WithValue(ctx, types.OrgKey, org)
		ctx = context.WithValue(ctx, types.OrgMemberKey, member)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractOrgIDFromPath extracts the org ID from URL paths like /auth/org/{orgId}/...
// It looks for the segment after "/org/" that is not a known sub-route.
func extractOrgIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "org" && i+1 < len(parts) {
			next := parts[i+1]
			// Skip known non-ID segments
			switch next {
			case "my", "switch", "invitations", "":
				return ""
			default:
				return next
			}
		}
	}
	return ""
}
