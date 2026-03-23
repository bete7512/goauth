package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

type CreateOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

type UpdateOrgRequest struct {
	Name     *string `json:"name,omitempty"`
	LogoURL  *string `json:"logo_url,omitempty"`
	Metadata *string `json:"metadata,omitempty"`
}

type OrgService interface {
	Create(ctx context.Context, userID string, req *CreateOrgRequest) (*models.Organization, *types.GoAuthError)
	Get(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError)
	Update(ctx context.Context, orgID string, req *UpdateOrgRequest) (*models.Organization, *types.GoAuthError)
	Delete(ctx context.Context, orgID string) *types.GoAuthError
	ListByUser(ctx context.Context, userID string) ([]*models.Organization, *types.GoAuthError)
	SwitchOrg(ctx context.Context, user *models.User, targetOrgID string) (string, string, *types.GoAuthError)
}

type orgService struct {
	deps       config.ModuleDependencies
	orgRepo    models.OrganizationRepository
	memberRepo models.OrganizationMemberRepository
	userRepo   models.UserRepository
}

func NewOrgService(deps config.ModuleDependencies, orgRepo models.OrganizationRepository, memberRepo models.OrganizationMemberRepository, userRepo models.UserRepository) *orgService {
	return &orgService{deps: deps, orgRepo: orgRepo, memberRepo: memberRepo, userRepo: userRepo}
}

func (s *orgService) Create(ctx context.Context, userID string, req *CreateOrgRequest) (*models.Organization, *types.GoAuthError) {
	if req.Name == "" {
		return nil, types.NewMissingFieldsError("name")
	}

	slug := req.Slug
	if slug == "" {
		slug = generateSlug(req.Name)
	}

	available, err := s.orgRepo.IsSlugAvailable(ctx, slug)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to check slug availability: %v", err))
	}
	if !available {
		return nil, types.NewOrgSlugTakenError()
	}

	now := time.Now()
	org := &models.Organization{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Slug:      slug,
		OwnerID:   userID,
		Active:    true,
		CreatedAt: now,
	}

	if err := s.orgRepo.Create(ctx, org); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create organization: %v", err))
	}

	// Add creator as owner
	member := &models.OrganizationMember{
		ID:       uuid.New().String(),
		OrgID:    org.ID,
		UserID:   userID,
		Role:     string(types.OrgRoleOwner),
		JoinedAt: now,
	}
	if err := s.memberRepo.Create(ctx, member); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to add owner membership: %v", err))
	}

	// Emit events
	s.deps.Events.EmitAsync(ctx, types.EventOrgCreated, &types.OrgEventData{
		Organization: org,
		ActorID:      userID,
	})
	s.deps.Events.EmitAsync(ctx, types.EventOrgMemberAdded, &types.OrgMemberEventData{
		OrgID: org.ID, OrgName: org.Name, UserID: userID, Role: string(types.OrgRoleOwner), ActorID: userID,
	})

	return org, nil
}

func (s *orgService) Get(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError) {
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, types.NewOrgNotFoundError()
	}
	return org, nil
}

func (s *orgService) Update(ctx context.Context, orgID string, req *UpdateOrgRequest) (*models.Organization, *types.GoAuthError) {
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, types.NewOrgNotFoundError()
	}

	if req.Name != nil {
		org.Name = *req.Name
	}
	if req.LogoURL != nil {
		org.LogoURL = *req.LogoURL
	}
	if req.Metadata != nil {
		org.Metadata = *req.Metadata
	}
	now := time.Now()
	org.UpdatedAt = &now

	if err := s.orgRepo.Update(ctx, org); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update organization: %v", err))
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgUpdated, &types.OrgEventData{Organization: org})

	return org, nil
}

func (s *orgService) Delete(ctx context.Context, orgID string) *types.GoAuthError {
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil || org == nil {
		return types.NewOrgNotFoundError()
	}

	if err := s.orgRepo.Delete(ctx, orgID); err != nil {
		return types.NewInternalError(fmt.Sprintf("failed to delete organization: %v", err))
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgDeleted, &types.OrgEventData{Organization: org})

	return nil
}

func (s *orgService) ListByUser(ctx context.Context, userID string) ([]*models.Organization, *types.GoAuthError) {
	memberships, err := s.memberRepo.ListByUser(ctx, userID)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to list memberships: %v", err))
	}

	if len(memberships) == 0 {
		return []*models.Organization{}, nil
	}

	var orgs []*models.Organization
	for _, m := range memberships {
		org, err := s.orgRepo.FindByID(ctx, m.OrgID)
		if err != nil || org == nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

func (s *orgService) SwitchOrg(ctx context.Context, user *models.User, targetOrgID string) (string, string, *types.GoAuthError) {
	// Validate membership
	member, err := s.memberRepo.FindByOrgAndUser(ctx, targetOrgID, user.ID)
	if err != nil || member == nil {
		return "", "", types.NewOrgNotMemberError()
	}

	// Run interceptors for resume phase to get base claims (e.g. other module enrichments)
	interceptClaims, _, interceptErr := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase: types.PhaseResume,
		User:  user,
	})
	if interceptErr != nil {
		return "", "", types.NewInternalError(fmt.Sprintf("auth interceptor failed: %v", interceptErr))
	}

	// Override org-specific claims with the target org (not the default from interceptor)
	interceptClaims["active_org_id"] = targetOrgID
	interceptClaims["org_role"] = member.Role

	accessToken, refreshToken, tokenErr := s.deps.SecurityManager.GenerateTokens(user, interceptClaims)
	if tokenErr != nil {
		return "", "", types.NewInternalError(fmt.Sprintf("failed to generate tokens: %v", tokenErr))
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgSwitched, &types.OrgSwitchEventData{
		UserID:  user.ID,
		ToOrgID: targetOrgID,
	})

	return accessToken, refreshToken, nil
}

var nonAlphanumRegex = regexp.MustCompile(`[^a-z0-9-]+`)

func generateSlug(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = nonAlphanumRegex.ReplaceAllString(slug, "")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = uuid.New().String()[:8]
	}
	return slug
}
