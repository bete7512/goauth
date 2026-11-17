---
id: team
title: Team Module
seoTitle: "Nested teams inside organizations in Go"
description: "Nested teams for Go apps with GoAuth: teams inside organizations up to five levels deep, team leads and members, moving sub-trees, and team-scoped RBAC roles."
keywords: ["golang teams", "go nested groups", "team management saas go", "hierarchical teams"]
sidebar_label: Team
sidebar_position: 19
---

# Team Module

The team module adds nested teams inside organizations to your Go application. A team belongs to one organization, may sit beneath another team of the same organization (up to five levels), and holds members of that organization as **leads** or **members**. Leads manage their team and every team beneath it.

It is **experimental**. It needs the [organization module](./organization). Permission checks for your own resources inside a team belong to [rbac](./rbac) with `Config.Teams`.

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/organization"
    "github.com/bete7512/goauth/pkg/modules/rbac"
    "github.com/bete7512/goauth/pkg/modules/team"
)

if err := a.Use(organization.New(nil)); err != nil {
    return err
}
if err := a.Use(team.New(nil)); err != nil {
    return err
}
// Optional: roles inside teams.
authz := rbac.New(&rbac.Config{Organizations: true, Teams: true})
if err := a.Use(authz); err != nil {
    return err
}
```

The module creates the `teams` and `team_members` tables through its migrations.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `MaxTeams` | `500` (`team.DefaultMaxTeams`) | Most teams one organization may have. |
| `Storage` | `Storage.Team()` | A custom `types.TeamStorage` instead of the backend's. |

## Endpoints

All routes need a signed-in user (`core.auth`). The service decides who may do what.

| Method | Path | Route name | What it does |
|---|---|---|---|
| GET | `/org/{orgId}/teams` | `team.list` | List teams. `tree=true` returns every team, each after its parent; `parent_id=` lists one team's children; `top=true` the top level; `q=` searches. |
| POST | `/org/{orgId}/teams` | `team.create` | Create a team (`name`, optional `slug`, `description`, `parent_id`). |
| GET | `/org/{orgId}/teams/{teamId}` | `team.get` | One team, with `depth` and `ancestors`. |
| PUT | `/org/{orgId}/teams/{teamId}` | `team.update` | Change name, slug or description. |
| POST | `/org/{orgId}/teams/{teamId}/move` | `team.move` | Move the team, with everything beneath it, under another team or to the top (`parent_id: ""`). |
| DELETE | `/org/{orgId}/teams/{teamId}` | `team.delete` | Delete a team that has no teams beneath it. |
| GET | `/org/{orgId}/teams/{teamId}/members` | `team.members.list` | List members (`role=` filter). |
| POST | `/org/{orgId}/teams/{teamId}/members` | `team.members.add` | Add an organization member (`user_id`, `role`: `lead` or `member`). |
| PUT | `/org/{orgId}/teams/{teamId}/members/{userId}` | `team.members.update` | Change a member's role. |
| DELETE | `/org/{orgId}/teams/{teamId}/members/{userId}` | `team.members.remove` | Remove a member; members may remove themselves. |

## Who manages what

- Any member of the organization may read its teams and their members. Anyone else gets `ORG_NOT_FOUND`.
- The organization's **owner and admins** manage every team, and are the only ones who create top-level teams.
- A team's **leads** manage that team and every team beneath it: rename it, add and remove members, change roles and create teams under it. A lead of a parent team is a lead everywhere beneath.
- **Deleting or moving** a team needs the right to manage where it sits: its parent, or the organization for a top-level team. A lead cannot delete the team they lead unless they also lead the team above it.
- Super admins manage every team (the admin console uses this).

These are ranks, like the organization module's member roles. They are not rbac permissions.

## Flow

1. An owner or admin creates top-level teams; leads create teams beneath theirs.
2. Members of the organization are added to teams as `lead` or `member`. Only organization members can be added.
3. A team membership records the organization membership it was made for. If the user leaves the organization and joins again, their old team memberships do not count.
4. Moving a team rewrites the stored path of everything beneath it in one transaction. A team cannot move beneath itself or a team beneath it.
5. When a member leaves an organization, the organization is deleted, or the user is deleted, the module removes the matching team rows (housekeeping; nothing relies on it).

## Roles inside teams (rbac)

With `rbac.Config{Organizations: true, Teams: true}`:

- **Roles flow down.** A role held on a team applies to that team and every team beneath it, never above or beside.
- **Organization roles apply in teams.** An organization owner or admin holds what they hold in the organization in all its teams, and so do application-wide roles.
- **Implied team roles.** A lead of the team, or of any team above it, holds the built-in `lead` role there: every permission of the application's own (`*`), like an organization admin. A plain member of the team itself holds `member`, which grants nothing. Define roles with those keys and `Scope: rbac.ScopeTeam` to change what they grant.
- **Teams use the organization's roles.** Roles are created per organization; they can be assigned in its teams. Roles defined in code with no scope (or `ScopeTeam`) can be assigned in teams too.
- **Assignments end with the membership.** A team role assignment is tied to the user's organization membership, like organization roles.

Guard routes and code with the team options:

```go
mux.Handle("DELETE /teams/{teamId}/projects/{id}",
    a.RequireAuth(authz.Require("project:delete", rbac.TeamParam("teamId"))(deleteProject)))

err := authz.Check(ctx, "project:update", rbac.InTeam(project.TeamID))

// For a route that lists team resources: which teams may the caller see?
ids, all, err := authz.TeamsWhere(ctx, orgID, "project:read")
// all == true: every team of the organization; otherwise only ids.
```

`rbac.TeamFrom(fn)` runs the check in the team a function returns, for example the team that owns the resource. See [rbac](./rbac) for the role endpoints in a team.

## Events and Errors

Events carry `*types.TeamEventData` (`OrgID`, `TeamID`, `TeamName`, `ParentID`, `UserID`, `Role`, `ActorID`):

| Event | When |
|---|---|
| `team.created` | A team was created. |
| `team.updated` | Name, slug or description changed. |
| `team.moved` | A team moved; `ParentID` is the new parent. |
| `team.deleted` | A team was deleted. |
| `team.member.added` | A member was added. |
| `team.member.removed` | A member was removed or left. |
| `team.member.role.changed` | A member's role changed. |

| Code | Status | Meaning |
|---|---|---|
| `TEAM_NOT_FOUND` | 404 | No such team in this organization. |
| `TEAM_SLUG_TAKEN` | 409 | Another team of the organization uses the slug. |
| `TEAM_TOO_DEEP` | 400 | The team would be nested more than five levels deep. |
| `TEAM_HAS_SUBTEAMS` | 409 | Delete or move the teams beneath it first. |
| `TEAM_INVALID_PARENT` | 400 | The parent is not in the organization, or is the team itself or one beneath it. |
| `TEAM_MEMBER_NOT_FOUND` | 404 | The user is not in the team. |
| `TEAM_MEMBER_EXISTS` | 409 | The user is already in the team. |
| `TEAM_FORBIDDEN` | 403 | The caller cannot manage this team. |
| `ORG_MEMBER_NOT_FOUND` | 404 | The user to add is not a member of the organization. |

## Admin console

With the [ui module](./ui), teams appear as an organization tab and under **Teams** in the sidebar: tree view, create, rename, move, delete, members and their roles, and per-member team roles when rbac has `Teams` on.

## Limitations

- Teams nest at most five levels (`models.MaxTeamDepth`).
- An organization has at most `MaxTeams` teams (default 500).
- `TeamsWhere` looks at no more than 1,000 teams of an organization.
- Teams have no custom roles of their own; they use the organization's roles and roles defined in code.
- Team management uses ranks (owner, admin, lead), not rbac permissions.
