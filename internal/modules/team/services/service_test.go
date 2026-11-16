package services_test

import (
	"testing"

	"github.com/bete7512/goauth/internal/modules/team/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/suite"
)

type TeamHelpersSuite struct {
	suite.Suite
}

func TestTeamHelpersSuite(t *testing.T) {
	suite.Run(t, new(TeamHelpersSuite))
}

func (s *TeamHelpersSuite) TestSlugify() {
	for name, want := range map[string]string{
		"Engineering":         "engineering",
		"  Back-end & Data! ": "back-end-data",
		"Ünïcode Team 2":      "n-code-team-2",
		"---":                 "",
	} {
		s.Equal(want, services.Slugify(name), name)
	}
}

func (s *TeamHelpersSuite) TestTreeOrderPutsChildrenAfterParents() {
	root := &models.Team{ID: "r", Name: "Root"}
	alpha := &models.Team{ID: "a", ParentID: "r", Name: "alpha"}
	beta := &models.Team{ID: "b", ParentID: "r", Name: "Beta"}
	leaf := &models.Team{ID: "l", ParentID: "b", Name: "Leaf"}
	other := &models.Team{ID: "o", Name: "Other"}
	orphan := &models.Team{ID: "x", ParentID: "missing", Name: "Orphan"}
	got := services.TreeOrder([]*models.Team{leaf, other, beta, orphan, alpha, root})
	var ids []string
	for _, team := range got {
		ids = append(ids, team.ID)
	}
	s.Equal([]string{"x", "o", "r", "a", "b", "l"}, ids)
}

func (s *TeamHelpersSuite) TestPaths() {
	team := &models.Team{ID: "c", Path: models.TeamPath(models.TeamPath("", "a")+"b/", "c")}
	s.Equal("/a/b/c/", team.Path)
	s.Equal([]string{"a", "b", "c"}, team.AncestorIDs())
}
