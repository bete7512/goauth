package rbac_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/rbac"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

const (
	testUser = "user-1"
	testOrg  = "org-1"
	otherOrg = "org-2"
)

type ModuleSuite struct {
	suite.Suite
}

func TestModuleSuite(t *testing.T) {
	suite.Run(t, new(ModuleSuite))
}

// fixture is a module initialized against mocked storage.
type fixture struct {
	module      *rbac.RBACModule
	users       *mocks.MockUserRepository
	members     *mocks.MockOrganizationMemberRepository
	orgs        *mocks.MockOrganizationRepository
	roles       *mocks.MockRoleRepository
	assignments *mocks.MockRoleAssignmentRepository
	events      *mocks.MockEventBus
	deps        config.ModuleDependencies
}

func (s *ModuleSuite) build(cfg *rbac.Config) *fixture {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)
	f := &fixture{
		module:      rbac.New(cfg),
		users:       mocks.NewMockUserRepository(ctrl),
		members:     mocks.NewMockOrganizationMemberRepository(ctrl),
		orgs:        mocks.NewMockOrganizationRepository(ctrl),
		roles:       mocks.NewMockRoleRepository(ctrl),
		assignments: mocks.NewMockRoleAssignmentRepository(ctrl),
		events:      mocks.NewMockEventBus(ctrl),
	}

	logger := mocks.NewMockLogger(ctrl)
	logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()

	rbacStore := mocks.NewMockRBACStorage(ctrl)
	rbacStore.EXPECT().Roles().Return(f.roles).AnyTimes()
	rbacStore.EXPECT().Assignments().Return(f.assignments).AnyTimes()
	rbacStore.EXPECT().WithTransaction(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, fn func(types.RBACStorage) error) error { return fn(rbacStore) }).AnyTimes()
	core := mocks.NewMockCoreStorage(ctrl)
	core.EXPECT().Users().Return(f.users).AnyTimes()
	orgStore := mocks.NewMockOrganizationStorage(ctrl)
	orgStore.EXPECT().Organizations().Return(f.orgs).AnyTimes()
	orgStore.EXPECT().Members().Return(f.members).AnyTimes()
	store := mocks.NewMockStorage(ctrl)
	store.EXPECT().RBAC().Return(rbacStore).AnyTimes()
	store.EXPECT().Core().Return(core).AnyTimes()
	store.EXPECT().Organization().Return(orgStore).AnyTimes()

	f.deps = config.ModuleDependencies{Storage: store, Events: f.events, Logger: logger, AuthInterceptors: interceptor.NewRegistry()}
	return f
}

func (s *ModuleSuite) setup(cfg *rbac.Config) *fixture {
	f := s.build(cfg)
	s.Require().NoError(f.module.Init(context.Background(), f.deps))
	return f
}

// holds makes testUser an active user with the given roles assigned
// application-wide.
func (f *fixture) holds(roleKeys ...string) {
	f.users.EXPECT().FindByID(gomock.Any(), testUser).Return(&models.User{ID: testUser, Active: true}, nil).AnyTimes()
	rows := make([]*models.RoleAssignment, 0, len(roleKeys))
	for _, key := range roleKeys {
		rows = append(rows, &models.RoleAssignment{UserID: testUser, ScopeType: models.RoleScopeGlobal, RoleKey: key})
	}
	f.assignments.EXPECT().ListByUser(gomock.Any(), testUser, gomock.Any()).Return(rows, nil).AnyTimes()
}

// memberOf makes testUser a member of an organization with a base role.
func (f *fixture) memberOf(orgID, role string) {
	f.members.EXPECT().FindByOrgAndUser(gomock.Any(), orgID, testUser).
		Return(&models.OrganizationMember{ID: "m-" + orgID, OrgID: orgID, UserID: testUser, Role: role}, nil).AnyTimes()
	f.orgs.EXPECT().FindByID(gomock.Any(), orgID).Return(&models.Organization{ID: orgID, Active: true}, nil).AnyTimes()
}

func signedIn(orgID string) context.Context {
	return types.WithPrincipal(context.Background(), types.Principal{UserID: testUser, OrganizationID: orgID})
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func serve(handler http.Handler, method, path string, ctx context.Context) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil).WithContext(ctx))
	return recorder
}

var viewerAndEditor = []rbac.Role{
	{Key: "viewer", Grants: []string{"*:read"}},
	{Key: "editor", Grants: []string{"*:read", "*:create", "*:update"}},
}

// --- module contract ---

func (s *ModuleSuite) TestModuleContract() {
	var module config.Module = rbac.New(nil)
	s.Equal(string(types.RBACModule), module.Name())
	s.Equal([]string{string(types.CoreModule)}, module.Dependencies())
	s.Nil(module.Middlewares())
	s.NotEmpty(module.OpenAPISpecs())
	s.NoError(module.RegisterHooks(nil))

	migrations := module.Migrations()
	for _, dialect := range []types.DialectType{types.DialectTypePostgres, types.DialectTypeMysql, types.DialectTypeSqlite} {
		s.NotEmpty(migrations[dialect], "migrations for %s", dialect)
	}

	withOrgs := rbac.New(&rbac.Config{Organizations: true})
	s.Equal([]string{string(types.CoreModule), string(types.OrganizationModule)}, withOrgs.Dependencies(),
		"organization roles need the organization module, and a missing one fails at startup")
}

func (s *ModuleSuite) TestRoutes() {
	names := func(routes []config.RouteInfo) map[string]bool {
		seen := map[string]bool{}
		for _, route := range routes {
			s.False(seen[route.Name], "duplicate route name %s", route.Name)
			seen[route.Name] = true
			s.Equal([]types.MiddlewareName{types.MiddlewareAuth}, route.Middlewares, route.Name)
			s.NotNil(route.Handler, route.Name)
		}
		return seen
	}

	global := names(s.setup(nil).module.Routes())
	s.Len(global, 10)
	s.True(global[string(types.RouteRBACMyPermissions)])
	s.False(global[string(types.RouteRBACOrgListRoles)], "organization routes exist only with Organizations")

	withOrgs := names(s.setup(&rbac.Config{Organizations: true}).module.Routes())
	s.Len(withOrgs, 18)
	s.True(withOrgs[string(types.RouteRBACOrgSetMemberRoles)])
}

func (s *ModuleSuite) TestInit_ReportsConfigurationMistakes() {
	cases := map[string]*rbac.Config{
		"malformed role key":            {Roles: []rbac.Role{{Key: "Billing Manager"}}},
		"reserved role key":             {Roles: []rbac.Role{{Key: "super_admin", Grants: []string{"*"}}}},
		"malformed grant":               {Roles: []rbac.Role{{Key: "billing", Grants: []string{"invoice"}}}},
		"duplicate role":                {Roles: []rbac.Role{{Key: "billing"}, {Key: "billing"}}},
		"duplicate across scopes":       {Organizations: true, Roles: []rbac.Role{{Key: "billing"}, {Key: "billing", Scope: rbac.ScopeOrg}}},
		"org role without orgs":         {Roles: []rbac.Role{{Key: "billing", Scope: rbac.ScopeOrg}}},
		"unknown scope":                 {Roles: []rbac.Role{{Key: "billing", Scope: "team"}}},
		"malformed listed permission":   {Permissions: rbac.Permissions{"Invoice": {"read"}}},
		"reserved listed permission":    {Permissions: rbac.Permissions{"goauth.roles": {"write"}}},
		"wildcard in listed permission": {Permissions: rbac.Permissions{"invoice": {"*"}}},
	}
	for name, cfg := range cases {
		f := s.build(cfg)
		err := f.module.Init(context.Background(), f.deps)
		s.Error(err, name)
		s.True(config.IsConfigErr(err), name)
		s.True(strings.HasPrefix(err.Error(), "rbac: "), name)
	}

	// The same key may be defined once per scope.
	f := s.build(&rbac.Config{Organizations: true, Roles: []rbac.Role{
		{Key: "admin", Scope: rbac.ScopeGlobal, Grants: []string{"*"}},
		{Key: "admin", Scope: rbac.ScopeOrg, Grants: []string{"invoice:*"}},
	}})
	s.NoError(f.module.Init(context.Background(), f.deps))
}

func (s *ModuleSuite) TestInit_NeedsStorage() {
	ctrl := gomock.NewController(s.T())
	logger := mocks.NewMockLogger(ctrl)
	logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	core := mocks.NewMockCoreStorage(ctrl)
	core.EXPECT().Users().Return(mocks.NewMockUserRepository(ctrl)).AnyTimes()

	without := mocks.NewMockStorage(ctrl)
	without.EXPECT().RBAC().Return(nil)
	err := rbac.New(nil).Init(context.Background(), config.ModuleDependencies{Storage: without, Logger: logger})
	s.Error(err)
	s.Contains(err.Error(), "storage is not available")

	withoutOrgs := mocks.NewMockStorage(ctrl)
	withoutOrgs.EXPECT().RBAC().Return(mocks.NewMockRBACStorage(ctrl))
	withoutOrgs.EXPECT().Core().Return(core)
	withoutOrgs.EXPECT().Organization().Return(nil)
	err = rbac.New(&rbac.Config{Organizations: true}).Init(context.Background(), config.ModuleDependencies{Storage: withoutOrgs, Logger: logger})
	s.Error(err)
	s.Contains(err.Error(), "organization storage")

	// A store passed in the configuration is used instead of the backend's.
	custom := mocks.NewMockStorage(ctrl)
	custom.EXPECT().Core().Return(core)
	module := rbac.New(&rbac.Config{Storage: mocks.NewMockRBACStorage(ctrl)})
	s.NoError(module.Init(context.Background(), config.ModuleDependencies{Storage: custom, Logger: logger}))
}

// --- declaring permissions ---

func (s *ModuleSuite) TestPermissionsAreDeclaredByBeingUsed() {
	module := rbac.New(nil)
	module.Require("invoice:approve")
	module.Resource("project")
	s.Equal("report:export", module.Define("report:export", "Export reports as CSV"))
	module.Define("report:export") // declaring again keeps the description

	var declared []string
	descriptions := map[string]string{}
	for _, entry := range module.Catalog() {
		declared = append(declared, entry.Permission)
		descriptions[entry.Permission] = entry.Description
	}
	s.Equal([]string{
		"goauth.assignments:read", "goauth.assignments:write", "goauth.roles:read", "goauth.roles:write",
		"invoice:approve", "project:create", "project:delete", "project:read", "project:update", "report:export",
	}, declared)
	s.Equal("Export reports as CSV", descriptions["report:export"])
	s.NotEmpty(descriptions["goauth.roles:write"])
}

func (s *ModuleSuite) TestMalformedPermissionsPanicWhenRoutesAreWired() {
	module := rbac.New(nil)
	for _, permission := range []string{"", "invoice", "Invoice:read", "invoice:*", "*", "invoice:read:all", "goauth.roles:write", "goauth:read"} {
		s.Panics(func() { module.Require(permission) }, "Require(%q)", permission)
		s.Panics(func() { module.Define(permission) }, "Define(%q)", permission)
	}
	for _, resource := range []string{"", "Invoice", "invoice:read", "*", "goauth", "goauth.roles"} {
		s.Panics(func() { module.Resource(resource) }, "Resource(%q)", resource)
	}
}

func (s *ModuleSuite) TestStrictModeFixesTheCatalog() {
	f := s.setup(&rbac.Config{
		Strict:      true,
		Permissions: rbac.Permissions{"invoice": {"read", "approve"}},
		Roles:       []rbac.Role{{Key: "everything", Grants: []string{"*"}}},
	})
	f.holds("everything")

	s.NotPanics(func() { f.module.Require("invoice:approve") })
	s.Panics(func() { f.module.Require("invoice:aprove") }, "a typo is caught when the route is wired")
	s.Panics(func() { f.module.Resource("invoice") }, "create, update and delete are not listed")
	s.Panics(func() { f.module.Define("project:read") })

	ctx := signedIn("")
	s.True(f.module.Can(ctx, "invoice:read"))
	s.False(f.module.Can(ctx, "invoice:aprove"), "an unlisted permission is refused even for a role that holds everything")
	var authErr *types.GoAuthError
	s.ErrorAs(f.module.Check(ctx, "invoice:aprove"), &authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- guarding routes ---

func (s *ModuleSuite) TestRequire() {
	f := s.setup(&rbac.Config{Roles: viewerAndEditor})
	f.holds("viewer")
	read := f.module.Require("invoice:read")(ok)
	approve := f.module.Require("invoice:approve")(ok)

	s.Equal(http.StatusOK, serve(read, http.MethodGet, "/", signedIn("")).Code)

	denied := serve(approve, http.MethodPost, "/", signedIn(""))
	s.Equal(http.StatusForbidden, denied.Code)
	s.Contains(denied.Body.String(), string(types.ErrRBACPermissionDenied))
	s.Contains(denied.Body.String(), "Missing permission: invoice:approve")

	anonymous := serve(read, http.MethodGet, "/", context.Background())
	s.Equal(http.StatusUnauthorized, anonymous.Code, "Require does not authenticate; it needs RequireAuth before it")
}

func (s *ModuleSuite) TestRequire_BeforeInitializeAnswers503() {
	module := rbac.New(nil)
	guarded := module.Require("invoice:read")(ok)
	s.Equal(http.StatusServiceUnavailable, serve(guarded, http.MethodGet, "/", signedIn("")).Code)
	s.False(module.Can(signedIn(""), "invoice:read"))
	s.Error(module.Assign(context.Background(), testUser, "viewer"))
	_, err := module.Permissions(signedIn(""))
	s.Error(err)
}

// A lookup that fails is an outage, not a refusal: the client sees a 500 and
// the request never reaches the handler.
func (s *ModuleSuite) TestRequire_StorageFailureIsNotADenial() {
	f := s.setup(nil)
	f.users.EXPECT().FindByID(gomock.Any(), testUser).Return(nil, errors.New("db down")).AnyTimes()
	guarded := f.module.Require("invoice:read")(ok)

	s.Equal(http.StatusInternalServerError, serve(guarded, http.MethodGet, "/", signedIn("")).Code)
	s.False(f.module.Can(signedIn(""), "invoice:read"))
	var authErr *types.GoAuthError
	s.ErrorAs(f.module.Check(signedIn(""), "invoice:read"), &authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

func (s *ModuleSuite) TestResource_PicksThePermissionFromTheMethod() {
	f := s.setup(&rbac.Config{Roles: viewerAndEditor})
	f.holds("editor")
	guarded := f.module.Resource("invoice")(ok)

	expect := map[string]int{
		http.MethodGet:     http.StatusOK,
		http.MethodHead:    http.StatusOK,
		http.MethodPost:    http.StatusOK,
		http.MethodPut:     http.StatusOK,
		http.MethodPatch:   http.StatusOK,
		http.MethodDelete:  http.StatusForbidden,
		http.MethodOptions: http.StatusOK,
		http.MethodTrace:   http.StatusMethodNotAllowed,
	}
	for method, status := range expect {
		s.Equal(status, serve(guarded, method, "/invoices/1", signedIn("")).Code, method)
	}
	s.Equal(http.StatusOK, serve(guarded, http.MethodOptions, "/invoices/1", context.Background()).Code, "a preflight request carries no credentials")
	s.NotEmpty(serve(guarded, http.MethodTrace, "/invoices/1", signedIn("")).Header().Get("Allow"))
}

func (s *ModuleSuite) TestOnDeny() {
	var seen rbac.Check
	f := s.setup(&rbac.Config{OnDeny: func(w http.ResponseWriter, _ *http.Request, c rbac.Check) {
		seen = c
		http.Error(w, "ask your admin for "+c.Permission, http.StatusPaymentRequired)
	}})
	f.holds()
	response := serve(f.module.Require("invoice:approve")(ok), http.MethodPost, "/", signedIn(""))
	s.Equal(http.StatusPaymentRequired, response.Code)
	s.Contains(response.Body.String(), "ask your admin for invoice:approve")
	s.Equal(testUser, seen.UserID)
	s.Equal(rbac.ScopeGlobal, seen.Scope)
	s.NotNil(seen.Request)

	panicking := s.setup(&rbac.Config{OnDeny: func(http.ResponseWriter, *http.Request, rbac.Check) { panic("boom") }})
	panicking.holds()
	response = serve(panicking.module.Require("invoice:approve")(ok), http.MethodPost, "/", signedIn(""))
	s.Equal(http.StatusForbidden, response.Code, "a callback that panics falls back to the default answer")
}

// --- where a check runs ---

func (s *ModuleSuite) TestScope_DefaultsToTheOrganizationTheCallerIsSignedInTo() {
	f := s.setup(&rbac.Config{Organizations: true})
	f.holds()
	f.memberOf(testOrg, "owner")
	f.memberOf(otherOrg, "member")

	s.True(f.module.Can(signedIn(testOrg), "invoice:approve"), "owner of the active organization")
	s.False(f.module.Can(signedIn(otherOrg), "invoice:approve"), "plain member of the other one")
	s.False(f.module.Can(signedIn(""), "invoice:approve"), "no organization: application-wide roles only")

	s.False(f.module.Can(signedIn(testOrg), "invoice:approve", rbac.Global()), "Global ignores the active organization")
	s.True(f.module.Can(signedIn(otherOrg), "invoice:approve", rbac.InOrg(testOrg)), "InOrg names another one")
	s.False(f.module.Can(signedIn(testOrg), "invoice:approve", rbac.InOrg("")))

	granted, err := f.module.Permissions(signedIn(testOrg))
	s.NoError(err)
	s.Equal([]string{"*", "goauth.*:*"}, granted)
	granted, err = f.module.Permissions(signedIn(testOrg), rbac.Global())
	s.NoError(err)
	s.Empty(granted)
}

// Without Organizations the active organization of a token means nothing to
// the module: every check is application-wide.
func (s *ModuleSuite) TestScope_OrganizationsOff() {
	f := s.setup(&rbac.Config{Roles: viewerAndEditor})
	f.holds("viewer")
	s.True(f.module.Can(signedIn(testOrg), "invoice:read"))

	s.False(f.module.Can(signedIn(""), "invoice:read", rbac.InOrg(testOrg)))
	var authErr *types.GoAuthError
	s.ErrorAs(f.module.Check(signedIn(""), "invoice:read", rbac.InOrg(testOrg)), &authErr)
	s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)
	s.ErrorAs(f.module.Assign(context.Background(), testUser, "viewer", rbac.InOrg(testOrg)), &authErr)
	s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)
}

func (s *ModuleSuite) TestScope_FromTheRequest() {
	f := s.setup(&rbac.Config{Organizations: true})
	f.holds()
	f.memberOf(testOrg, "owner")
	f.memberOf(otherOrg, "member")

	mux := http.NewServeMux()
	mux.Handle("GET /orgs/{orgId}/invoices", f.module.Require("invoice:read", rbac.OrgParam("orgId"))(ok))
	mux.Handle("GET /invoices/{id}", f.module.Require("invoice:read", rbac.OrgFrom(func(r *http.Request) (string, error) {
		switch r.PathValue("id") {
		case "mine":
			return testOrg, nil
		case "theirs":
			return otherOrg, nil
		case "gone":
			return "", &types.GoAuthError{Code: types.ErrCustom, Message: "no such invoice", StatusCode: http.StatusNotFound}
		case "statusless":
			return "", types.NewCustomError("an error that carries no HTTP status")
		default:
			return "", errors.New("lookup failed")
		}
	}))(ok))

	// The caller is signed in to the other organization throughout.
	ctx := signedIn(otherOrg)
	s.Equal(http.StatusOK, serve(mux, http.MethodGet, "/orgs/"+testOrg+"/invoices", ctx).Code)
	s.Equal(http.StatusForbidden, serve(mux, http.MethodGet, "/orgs/"+otherOrg+"/invoices", ctx).Code)
	s.Equal(http.StatusOK, serve(mux, http.MethodGet, "/invoices/mine", ctx).Code)
	s.Equal(http.StatusForbidden, serve(mux, http.MethodGet, "/invoices/theirs", ctx).Code)
	s.Equal(http.StatusNotFound, serve(mux, http.MethodGet, "/invoices/gone", ctx).Code, "the resolver's typed error is the answer")
	s.Equal(http.StatusForbidden, serve(mux, http.MethodGet, "/invoices/unknown", ctx).Code, "any other resolver error refuses")
	s.Equal(http.StatusForbidden, serve(mux, http.MethodGet, "/invoices/statusless", ctx).Code, "a typed error without a status refuses too")

	// Both options need a request.
	for _, option := range []rbac.Option{rbac.OrgParam("orgId"), rbac.OrgFrom(func(*http.Request) (string, error) { return testOrg, nil })} {
		s.False(f.module.Can(ctx, "invoice:read", option))
		var authErr *types.GoAuthError
		s.ErrorAs(f.module.Check(ctx, "invoice:read", option), &authErr)
		s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)
	}
}

// --- deciding in code ---

func (s *ModuleSuite) TestCanAndCheck() {
	f := s.setup(&rbac.Config{Roles: viewerAndEditor})
	f.holds("viewer")
	ctx := signedIn("")

	s.True(f.module.Can(ctx, "invoice:read"))
	s.NoError(f.module.Check(ctx, "invoice:read"))
	s.False(f.module.Can(ctx, "invoice:delete"))

	var authErr *types.GoAuthError
	s.ErrorAs(f.module.Check(ctx, "invoice:delete"), &authErr)
	s.Equal(types.ErrRBACPermissionDenied, authErr.Code)
	s.Equal(http.StatusForbidden, authErr.StatusCode)

	s.False(f.module.Can(context.Background(), "invoice:read"), "nobody is signed in")
	s.ErrorAs(f.module.Check(context.Background(), "invoice:read"), &authErr)
	s.Equal(types.ErrUnauthorized, authErr.Code)

	s.False(f.module.Can(ctx, "not a permission"))
	s.ErrorAs(f.module.Check(ctx, "not a permission"), &authErr)
	s.Equal(types.ErrInternalError, authErr.Code)

	s.True(f.module.Can(ctx, "invoice:delete", rbac.AllowIf(func(_ context.Context, c rbac.Check) bool { return c.Request == nil })))
	s.False(f.module.Can(ctx, "invoice:read", rbac.OnlyIf(func(context.Context, rbac.Check) bool { return false })))
	s.True(f.module.Can(ctx, "invoice:read", nil), "a nil option is ignored")
}

func (s *ModuleSuite) TestFor_DecidesForANamedUser() {
	f := s.setup(&rbac.Config{Organizations: true, Roles: viewerAndEditor})
	f.holds("viewer")
	f.memberOf(testOrg, "owner")
	subject := f.module.For(testUser)

	// The context carries someone else, signed in to the organization; the
	// decision is still about the named user, application-wide.
	other := types.WithPrincipal(context.Background(), types.Principal{UserID: "someone-else", OrganizationID: testOrg})
	s.True(subject.Can(other, "invoice:read"))
	s.False(subject.Can(other, "invoice:delete"), "application-wide unless InOrg says otherwise")
	s.True(subject.Can(other, "invoice:delete", rbac.InOrg(testOrg)))
	s.NoError(subject.Check(context.Background(), "invoice:read"))

	granted, err := subject.Permissions(context.Background())
	s.NoError(err)
	s.Equal([]string{"*:read"}, granted)

	// An empty user never falls back to the caller in the context.
	nobody := f.module.For("")
	s.False(nobody.Can(signedIn(testOrg), "invoice:read"))
	var authErr *types.GoAuthError
	s.ErrorAs(nobody.Check(signedIn(testOrg), "invoice:read"), &authErr)
	s.Equal(types.ErrUnauthorized, authErr.Code)
	_, err = nobody.Permissions(signedIn(testOrg))
	s.Error(err)
}

func (s *ModuleSuite) TestDecideSeesEveryCheck() {
	var seen []string
	f := s.setup(&rbac.Config{
		Roles: viewerAndEditor,
		Decide: func(_ context.Context, c rbac.Check) rbac.Decision {
			seen = append(seen, c.Permission)
			if c.Permission == "report:export" {
				return rbac.Deny("Exports need the Pro plan")
			}
			if c.Permission == "beta:use" {
				return rbac.Allow()
			}
			return rbac.Keep
		},
	})
	f.holds("viewer")
	ctx := signedIn("")

	s.True(f.module.Can(ctx, "invoice:read"))
	s.True(f.module.Can(ctx, "beta:use"))
	var authErr *types.GoAuthError
	s.ErrorAs(f.module.Check(ctx, "report:export"), &authErr)
	s.Equal("Exports need the Pro plan", authErr.Message)
	s.Equal([]string{"invoice:read", "beta:use", "report:export"}, seen)
}

func (s *ModuleSuite) TestAssignAndRevokeFromCode() {
	f := s.setup(&rbac.Config{Roles: viewerAndEditor})
	f.holds()
	gomock.InOrder(
		f.events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeRBACRoleAssign, gomock.Any()).Return(nil),
		f.assignments.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, row *models.RoleAssignment) error {
			s.Equal(testUser, row.UserID)
			s.Equal("viewer", row.RoleKey)
			s.Equal(models.RoleScopeGlobal, row.ScopeType)
			return nil
		}),
		f.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleAssigned, gomock.Any()).Return(nil),
	)
	s.NoError(f.module.Assign(context.Background(), testUser, "viewer"))

	// Both return a plain nil on success, not a typed nil pointer.
	s.NoError(f.module.Revoke(context.Background(), testUser, "viewer"))

	var authErr *types.GoAuthError
	f.roles.EXPECT().FindByKey(gomock.Any(), "", "no-such-role").Return(nil, models.ErrNotFound)
	s.ErrorAs(f.module.Assign(context.Background(), testUser, "no-such-role"), &authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code)
}

func (s *ModuleSuite) TestFixed() {
	authorizer := rbac.Fixed("invoice:*", "project:read")
	ctx := context.Background()
	s.True(authorizer.Can(ctx, "invoice:approve"))
	s.True(authorizer.Can(ctx, "project:read", rbac.InOrg("anything")))
	s.False(authorizer.Can(ctx, "project:delete"))
	s.NoError(authorizer.Check(ctx, "invoice:read"))

	var authErr *types.GoAuthError
	s.ErrorAs(authorizer.Check(ctx, "project:delete"), &authErr)
	s.Equal(types.ErrRBACPermissionDenied, authErr.Code)

	s.False(rbac.Fixed().Can(ctx, "invoice:read"), "no grants: nothing is allowed")
	s.Panics(func() { rbac.Fixed("not a grant") })
}

// --- housekeeping ---

func (s *ModuleSuite) TestHooks_RemoveAssignmentsThatCanNoLongerApply() {
	f := s.setup(&rbac.Config{Organizations: true})
	handlers := map[types.EventType]types.EventHandler{}
	f.events.EXPECT().Subscribe(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(event types.EventType, handler types.EventHandler, _ ...interface{}) { handlers[event] = handler }).Times(3)
	s.NoError(f.module.RegisterHooks(f.events))
	ctx := context.Background()

	f.assignments.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(nil)
	s.NoError(handlers[types.EventAdminUserDeleted](ctx, &types.Event{Data: map[string]interface{}{"target_id": testUser}}))

	f.assignments.EXPECT().DeleteByUserAndScope(gomock.Any(), testUser, models.RoleScopeOrg, testOrg).Return(errors.New("db down"))
	s.NoError(handlers[types.EventOrgMemberRemoved](ctx, &types.Event{Data: &types.OrgMemberEventData{OrgID: testOrg, UserID: testUser}}),
		"a failed cleanup is logged, never returned to the event bus")

	gomock.InOrder(
		f.assignments.EXPECT().DeleteByScope(gomock.Any(), models.RoleScopeOrg, testOrg).Return(nil),
		f.roles.EXPECT().DeleteByOrg(gomock.Any(), testOrg).Return(nil),
	)
	s.NoError(handlers[types.EventOrgDeleted](ctx, &types.Event{Data: &types.OrgEventData{Organization: &models.Organization{ID: testOrg}}}))

	// Events with unexpected payloads are ignored.
	for _, handler := range handlers {
		s.NoError(handler(ctx, &types.Event{Data: 42}))
	}
	s.NoError(handlers[types.EventOrgDeleted](ctx, &types.Event{Data: &types.OrgEventData{}}))

	// Without Organizations only the user event is subscribed to.
	global := s.setup(nil)
	global.events.EXPECT().Subscribe(types.EventAdminUserDeleted, gomock.Any(), gomock.Any()).Times(1)
	s.NoError(global.module.RegisterHooks(global.events))
}

// The configuration is copied: changing it after New has no effect.
func (s *ModuleSuite) TestNewCopiesTheConfiguration() {
	cfg := &rbac.Config{Roles: []rbac.Role{{Key: "viewer", Grants: []string{"*:read"}}}}
	f := s.build(cfg)
	cfg.Roles[0].Grants[0] = "*"
	cfg.Roles = append(cfg.Roles, rbac.Role{Key: "BAD KEY"})
	cfg.Organizations = true
	s.Require().NoError(f.module.Init(context.Background(), f.deps))
	s.Equal([]string{string(types.CoreModule)}, f.module.Dependencies())
	f.holds("viewer")
	s.False(f.module.Can(signedIn(""), "invoice:delete"))
	s.True(f.module.Can(signedIn(""), "invoice:read"))
}
