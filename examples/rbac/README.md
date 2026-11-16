# RBAC example: Acme Tracker

A small project tracker, built the way a real Go service would be, that shows every way GoAuth's `rbac` module can guard a route: application-wide roles, organization roles, nested team roles, ownership lookups, the application's own rules, and checks made in code.

```sh
cd examples
go run ./rbac               # http://localhost:8080, admin console at /admin
./rbac/walkthrough.sh       # in another terminal; needs curl and jq
go test ./rbac/...          # the same scenarios as a Go test
```

Everything lives in memory, and the demo data is created at start.

## Layout

| Path | What it holds |
|---|---|
| `main.go` | Wiring: settings, GoAuth, the API, the seed, the HTTP server. |
| `internal/platform` | GoAuth setup. `platform.go` registers organization, team, rbac, audit and the admin console. `roles.go` defines the roles in code. |
| `internal/tracker` | The application's own domain: projects owned by teams, tasks inside projects, invoices owned by organizations. It knows nothing about GoAuth. |
| `internal/api` | The JSON API. `router.go` is the only place authorization is declared; `owners.go` answers "who owns this resource". The handlers in the other files just do their job. |
| `internal/seed` | Demo users, two organizations, a team tree and some data. |
| `scenarios_test.go` | Signs every demo user in and checks every guard. |

## The cast

Every user's password is `Tracker-demo-1`.

```
Acme Corp (organization, owner alice)
├── Engineering        lead: dave
│   ├── Backend        erin holds the "developer" role here
│   └── Mobile         frank is a plain member; a task is assigned to him
└── Design
Globex (organization, owner gina) ─ Platform
```

| User | Holds | Shows |
|---|---|---|
| `sam@tracker.test` | the super admin flag | everything, everywhere; can open `/admin` |
| `sue@tracker.test` | `support`, application-wide | reads every organization, exports reports |
| `alice@tracker.test` | owner of Acme | everything inside Acme, nothing in Globex |
| `bob@tracker.test` | admin of Acme | everything inside Acme, but cannot approve his own invoice |
| `carol@tracker.test` | `accountant` in Acme | reads and approves invoices |
| `hank@tracker.test` | `billing` in Acme | creates invoices, cannot approve them |
| `dave@tracker.test` | lead of Engineering | everything in Engineering, Backend and Mobile; nothing in Design |
| `erin@tracker.test` | `developer` on Backend | Backend's projects and tasks only |
| `frank@tracker.test` | plain member of Mobile | nothing, except completing the task assigned to him |
| `gina@tracker.test` | owner of Globex | nothing inside Acme |

## The guards

Every route is in `internal/api/router.go`:

| # | Route | Guard | Where the check runs |
|---|---|---|---|
| 1 | `GET /api/reports/usage` | `Require("report:export", rbac.Global())` | application-wide roles only |
| 2 | `GET, POST /api/invoices` | `Resource("invoice")` | the organization the token is signed in to |
| 3 | `POST /api/invoices/{id}/approve` | `Require("invoice:approve", rbac.OrgFrom(invoiceOrg), rbac.OnlyIf(notInvoiceCreator))` | the invoice's organization, plus a four-eyes rule |
| 4 | `GET /api/orgs/{orgId}/billing` | `Require("invoice:read", rbac.OrgParam("orgId"))` | the organization in the path |
| 5 | `GET, POST /api/teams/{teamId}/projects` | `Resource("project", rbac.TeamParam("teamId"))` | the team in the path |
| 6 | `GET, PATCH /api/projects/{id}` | `Resource("project", rbac.TeamFrom(projectTeam))` | the team that owns the project |
| 7 | `GET /api/projects` | handler calls `authz.TeamsWhere` | every team where the caller may read projects |
| 8 | `POST /api/projects/{id}/archive` | handler calls `authz.Check(ctx, "project:archive", rbac.InTeam(p.TeamID))` | decided in code, after loading the project |
| 9 | `POST /api/tasks/{id}/complete` | `Require("task:update", rbac.TeamFrom(taskTeam), rbac.AllowIf(isAssignee))` | the task's team, or its assignee |

### Rules worth noticing

- **Roles flow down the team tree.** Dave leads Engineering, so he manages Backend and Mobile as well. Erin's `developer` role is on Backend, so it doesn't reach Mobile.
- **Organization roles apply in every team.** Alice and Bob can do anything in any Acme team.
- **Nothing leaks between organizations.** Bob is an Acme admin and gets 403 on a Globex project. Carol gets 403 on a Globex invoice.
- **The token decides the organization for plain routes.** Sign in, then `POST /auth/org/switch` with `{"org_id": "…"}` to get a token for that organization. Routes with `OrgParam`, `OrgFrom`, `TeamParam` or `TeamFrom` don't depend on it.
- **Your own rules sit next to the roles.**
  - `OnlyIf` can refuse what the roles allow: Bob may approve invoices, but not his own.
  - `AllowIf` can allow what they refuse: Frank completes his own task without `task:update`.
- **A missing resource is a 404, not a 403.** The ownership lookups in `owners.go` return `types.NewNotFoundError`, and `rbac` sends it as is.

## Try it by hand

```sh
TOKEN=$(curl -s localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"carol@tracker.test","password":"Tracker-demo-1"}' | jq -r .data.access_token)
ACME=$(curl -s localhost:8080/demo/cast | jq -r .acme)
TOKEN=$(curl -s localhost:8080/auth/org/switch -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{\"org_id\":\"$ACME\"}" | jq -r .data.access_token)

curl -s localhost:8080/api/invoices -H "Authorization: Bearer $TOKEN" | jq
curl -s localhost:8080/auth/me/permissions -H "Authorization: Bearer $TOKEN" | jq
```

`/demo/cast` exists only in this example, so the walkthrough can find the seeded IDs.

In the admin console (`/admin`, sign in as `sam@tracker.test`) you can see and change all of this: roles under **Roles**, the team tree under **Teams**, and each member's team roles on their team page. Changes take effect on the next request.
