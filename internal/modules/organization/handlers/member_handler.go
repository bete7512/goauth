package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/organization/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type MemberHandler struct {
	deps          config.ModuleDependencies
	memberService services.MemberService
}

func NewMemberHandler(deps config.ModuleDependencies, memberService services.MemberService) *MemberHandler {
	return &MemberHandler{deps: deps, memberService: memberService}
}

func (h *MemberHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	orgID, _ := r.Context().Value(types.OrgIDKey).(string)

	opts := models.MemberListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Role:        r.URL.Query().Get("role"),
	}
	opts.Normalize(100)

	members, total, authErr := h.memberService.ListMembers(r.Context(), orgID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, members, total, opts.SortField, opts.SortDir)
}

func (h *MemberHandler) GetMember(w http.ResponseWriter, r *http.Request) {
	orgID, _ := r.Context().Value(types.OrgIDKey).(string)
	userID := extractLastPathSegment(r.URL.Path)

	member, authErr := h.memberService.GetMember(r.Context(), orgID, userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, member, nil)
}

func (h *MemberHandler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)
	actorID, _ := r.Context().Value(types.UserIDKey).(string)
	targetUserID := extractLastPathSegment(r.URL.Path)

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}

	if authErr := h.memberService.UpdateRole(r.Context(), orgID, targetUserID, types.OrgRole(req.Role), actorID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *MemberHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)
	actorID, _ := r.Context().Value(types.UserIDKey).(string)
	targetUserID := extractLastPathSegment(r.URL.Path)

	if authErr := h.memberService.RemoveMember(r.Context(), orgID, targetUserID, actorID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

// extractLastPathSegment returns the last non-empty segment of a URL path
func extractLastPathSegment(path string) string {
	parts := strings.Split(strings.TrimRight(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
