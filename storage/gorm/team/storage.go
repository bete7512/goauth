// Package team implements types.TeamStorage with GORM.
package team

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	_ types.TeamStorage           = (*GormTeamStorage)(nil)
	_ models.TeamRepository       = (*TeamRepo)(nil)
	_ models.TeamMemberRepository = (*MemberRepo)(nil)
)

// GormTeamStorage implements types.TeamStorage using GORM.
type GormTeamStorage struct {
	db      *gorm.DB
	teams   *TeamRepo
	members *MemberRepo
}

// NewTeamStorage creates a GormTeamStorage.
func NewTeamStorage(db *gorm.DB) *GormTeamStorage {
	return &GormTeamStorage{db: db, teams: &TeamRepo{db: db}, members: &MemberRepo{db: db}}
}

// Teams returns the team repository.
func (s *GormTeamStorage) Teams() models.TeamRepository { return s.teams }

// Members returns the team member repository.
func (s *GormTeamStorage) Members() models.TeamMemberRepository { return s.members }

// WithTransaction runs fn in a database transaction.
func (s *GormTeamStorage) WithTransaction(ctx context.Context, fn func(tx types.TeamStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return fn(NewTeamStorage(tx)) })
}

// TeamRepo implements models.TeamRepository.
type TeamRepo struct {
	db *gorm.DB
}

// Create stores a team. A slug already used in the organization is
// ErrConflict.
func (r *TeamRepo) Create(ctx context.Context, team *models.Team) error {
	if team.ID == "" {
		team.ID = uuid.Must(uuid.NewV7()).String()
	}
	if team.CreatedAt.IsZero() {
		team.CreatedAt = time.Now()
	}
	if team.Path == "" {
		return fmt.Errorf("team_repository.Create: path is required")
	}
	if err := r.db.WithContext(ctx).Create(team).Error; err != nil {
		var count int64
		if r.db.WithContext(ctx).Model(&models.Team{}).Where("org_id = ? AND slug = ?", team.OrgID, team.Slug).Count(&count).Error == nil && count > 0 {
			return fmt.Errorf("team_repository.Create: %w", models.ErrConflict)
		}
		return fmt.Errorf("team_repository.Create: %w", err)
	}
	return nil
}

// FindByID returns a team, or ErrNotFound.
func (r *TeamRepo) FindByID(ctx context.Context, id string) (*models.Team, error) {
	var team models.Team
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&team).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("team_repository.FindByID: %w", err)
	}
	return &team, nil
}

// FindByIDs returns the teams that exist among ids.
func (r *TeamRepo) FindByIDs(ctx context.Context, ids []string) ([]*models.Team, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var teams []*models.Team
	if err := r.db.WithContext(ctx).Where("id IN ?", ids).Find(&teams).Error; err != nil {
		return nil, fmt.Errorf("team_repository.FindByIDs: %w", err)
	}
	return teams, nil
}

// List lists an organization's teams.
func (r *TeamRepo) List(ctx context.Context, orgID string, opts models.TeamListOpts) ([]*models.Team, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.Team{}).Where("org_id = ?", orgID)
	switch {
	case opts.ParentID != "":
		query = query.Where("parent_id = ?", opts.ParentID)
	case opts.Top:
		query = query.Where("parent_id = ''")
	}
	if opts.Query != "" {
		search := helpers.ContainsPattern(opts.Query)
		query = query.Where("(LOWER(name) LIKE ? ESCAPE '!' OR LOWER(slug) LIKE ? ESCAPE '!')", search, search)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("team_repository.List: %w", err)
	}
	var teams []*models.Team
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Order("id asc").Find(&teams).Error; err != nil {
		return nil, 0, fmt.Errorf("team_repository.List: %w", err)
	}
	return teams, total, nil
}

// Subtree returns a team and every team beneath it.
func (r *TeamRepo) Subtree(ctx context.Context, orgID, path string) ([]*models.Team, error) {
	if path == "" {
		return nil, nil
	}
	var teams []*models.Team
	err := r.db.WithContext(ctx).Where("org_id = ? AND path LIKE ? ESCAPE '!'", orgID, prefixPattern(path)).
		Order("depth asc, name asc, id asc").Find(&teams).Error
	if err != nil {
		return nil, fmt.Errorf("team_repository.Subtree: %w", err)
	}
	// Compared again here: a LIKE prefix is only a filter.
	out := teams[:0]
	for _, team := range teams {
		if team.OrgID == orgID && strings.HasPrefix(team.Path, path) {
			out = append(out, team)
		}
	}
	return out, nil
}

// CountChildren counts the teams directly beneath a team.
func (r *TeamRepo) CountChildren(ctx context.Context, teamID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.Team{}).Where("parent_id = ?", teamID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("team_repository.CountChildren: %w", err)
	}
	return count, nil
}

// Update saves a team's name, slug and description.
func (r *TeamRepo) Update(ctx context.Context, team *models.Team) error {
	now := time.Now()
	team.UpdatedAt = &now
	result := r.db.WithContext(ctx).Model(&models.Team{}).Where("id = ?", team.ID).
		Updates(map[string]interface{}{"name": team.Name, "slug": team.Slug, "description": team.Description, "updated_at": now})
	if result.Error != nil {
		var count int64
		if r.db.WithContext(ctx).Model(&models.Team{}).Where("org_id = ? AND slug = ? AND id <> ?", team.OrgID, team.Slug, team.ID).Count(&count).Error == nil && count > 0 {
			return fmt.Errorf("team_repository.Update: %w", models.ErrConflict)
		}
		return fmt.Errorf("team_repository.Update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return models.ErrNotFound
	}
	return nil
}

// Move gives a team a new parent, path and depth, and rewrites everything
// beneath it, in one transaction.
func (r *TeamRepo) Move(ctx context.Context, team *models.Team, oldPath string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var below []*models.Team
		if err := tx.Where("org_id = ? AND path LIKE ? ESCAPE '!' AND id <> ?", team.OrgID, prefixPattern(oldPath), team.ID).Find(&below).Error; err != nil {
			return fmt.Errorf("team_repository.Move: %w", err)
		}
		now := time.Now()
		team.UpdatedAt = &now
		result := tx.Model(&models.Team{}).Where("id = ? AND path = ?", team.ID, oldPath).
			Updates(map[string]interface{}{"parent_id": team.ParentID, "path": team.Path, "depth": team.Depth, "updated_at": now})
		if result.Error != nil {
			return fmt.Errorf("team_repository.Move: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			// The team moved or disappeared since it was read.
			return fmt.Errorf("team_repository.Move: %w", models.ErrConflict)
		}
		for _, child := range below {
			if !strings.HasPrefix(child.Path, oldPath) {
				continue
			}
			path := team.Path + strings.TrimPrefix(child.Path, oldPath)
			depth := strings.Count(path, "/") - 2
			if err := tx.Model(&models.Team{}).Where("id = ?", child.ID).
				Updates(map[string]interface{}{"path": path, "depth": depth, "updated_at": now}).Error; err != nil {
				return fmt.Errorf("team_repository.Move: %w", err)
			}
		}
		return nil
	})
}

// Delete removes a team and its memberships, refusing a team that still has
// teams beneath it.
func (r *TeamRepo) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var children int64
		if err := tx.Model(&models.Team{}).Where("parent_id = ?", id).Count(&children).Error; err != nil {
			return fmt.Errorf("team_repository.Delete: %w", err)
		}
		if children > 0 {
			return fmt.Errorf("team_repository.Delete: %w", models.ErrConflict)
		}
		if err := tx.Where("team_id = ?", id).Delete(&models.TeamMember{}).Error; err != nil {
			return fmt.Errorf("team_repository.Delete: %w", err)
		}
		result := tx.Where("id = ?", id).Delete(&models.Team{})
		if result.Error != nil {
			return fmt.Errorf("team_repository.Delete: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return models.ErrNotFound
		}
		return nil
	})
}

// DeleteByOrg removes every team of an organization and its memberships.
func (r *TeamRepo) DeleteByOrg(ctx context.Context, orgID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("org_id = ?", orgID).Delete(&models.TeamMember{}).Error; err != nil {
			return fmt.Errorf("team_repository.DeleteByOrg: %w", err)
		}
		if err := tx.Where("org_id = ?", orgID).Delete(&models.Team{}).Error; err != nil {
			return fmt.Errorf("team_repository.DeleteByOrg: %w", err)
		}
		return nil
	})
}

// prefixPattern matches every path that starts with path. Paths hold only
// IDs and slashes, but LIKE wildcards are escaped all the same.
func prefixPattern(path string) string {
	return strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(path) + "%"
}

// MemberRepo implements models.TeamMemberRepository.
type MemberRepo struct {
	db *gorm.DB
}

// Create adds a member; one already in the team is ErrConflict.
func (r *MemberRepo) Create(ctx context.Context, member *models.TeamMember) error {
	if member.ID == "" {
		member.ID = uuid.Must(uuid.NewV7()).String()
	}
	if member.CreatedAt.IsZero() {
		member.CreatedAt = time.Now()
	}
	if err := r.db.WithContext(ctx).Create(member).Error; err != nil {
		var count int64
		if r.db.WithContext(ctx).Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ?", member.TeamID, member.UserID).Count(&count).Error == nil && count > 0 {
			return fmt.Errorf("team_member_repository.Create: %w", models.ErrConflict)
		}
		return fmt.Errorf("team_member_repository.Create: %w", err)
	}
	return nil
}

// FindByTeamAndUser returns a membership, or ErrNotFound.
func (r *MemberRepo) FindByTeamAndUser(ctx context.Context, teamID, userID string) (*models.TeamMember, error) {
	var member models.TeamMember
	if err := r.db.WithContext(ctx).Where("team_id = ? AND user_id = ?", teamID, userID).First(&member).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("team_member_repository.FindByTeamAndUser: %w", err)
	}
	return &member, nil
}

// ListByTeam lists a team's members.
func (r *MemberRepo) ListByTeam(ctx context.Context, teamID string, opts models.TeamMemberListOpts) ([]*models.TeamMember, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.TeamMember{}).Where("team_id = ?", teamID)
	if opts.Role != "" {
		query = query.Where("role = ?", opts.Role)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("team_member_repository.ListByTeam: %w", err)
	}
	var members []*models.TeamMember
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Order("id asc").Find(&members).Error; err != nil {
		return nil, 0, fmt.Errorf("team_member_repository.ListByTeam: %w", err)
	}
	return members, total, nil
}

// ListByUser returns the user's memberships in an organization's teams.
func (r *MemberRepo) ListByUser(ctx context.Context, orgID, userID string) ([]*models.TeamMember, error) {
	var members []*models.TeamMember
	if err := r.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).Order("created_at asc, id asc").Find(&members).Error; err != nil {
		return nil, fmt.Errorf("team_member_repository.ListByUser: %w", err)
	}
	return members, nil
}

// ListByTeams returns the user's memberships among the given teams.
func (r *MemberRepo) ListByTeams(ctx context.Context, userID string, teamIDs []string) ([]*models.TeamMember, error) {
	if len(teamIDs) == 0 {
		return nil, nil
	}
	var members []*models.TeamMember
	if err := r.db.WithContext(ctx).Where("user_id = ? AND team_id IN ?", userID, teamIDs).Find(&members).Error; err != nil {
		return nil, fmt.Errorf("team_member_repository.ListByTeams: %w", err)
	}
	return members, nil
}

// Update saves a member's role.
func (r *MemberRepo) Update(ctx context.Context, member *models.TeamMember) error {
	now := time.Now()
	member.UpdatedAt = &now
	result := r.db.WithContext(ctx).Model(&models.TeamMember{}).Where("id = ?", member.ID).
		Updates(map[string]interface{}{"role": member.Role, "updated_at": now})
	if result.Error != nil {
		return fmt.Errorf("team_member_repository.Update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return models.ErrNotFound
	}
	return nil
}

// Delete removes a user from a team.
func (r *MemberRepo) Delete(ctx context.Context, teamID, userID string) error {
	if err := r.db.WithContext(ctx).Where("team_id = ? AND user_id = ?", teamID, userID).Delete(&models.TeamMember{}).Error; err != nil {
		return fmt.Errorf("team_member_repository.Delete: %w", err)
	}
	return nil
}

// DeleteByOrgAndUser removes a user from every team of an organization.
func (r *MemberRepo) DeleteByOrgAndUser(ctx context.Context, orgID, userID string) error {
	if err := r.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).Delete(&models.TeamMember{}).Error; err != nil {
		return fmt.Errorf("team_member_repository.DeleteByOrgAndUser: %w", err)
	}
	return nil
}

// DeleteByUser removes a user from every team.
func (r *MemberRepo) DeleteByUser(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.TeamMember{}).Error; err != nil {
		return fmt.Errorf("team_member_repository.DeleteByUser: %w", err)
	}
	return nil
}
