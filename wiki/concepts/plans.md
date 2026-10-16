---
type: concept
title: 'Plans limit what a tenant may create, never who may sign in'
tags: [architecture, contract, config, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-15
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:monthly-active-users
      source: oauth-server-codebase
      evidence: 'The soft cap reads the figure already recorded per project for the current month; plans add no counting'
      confidence: high
      status: current
    - predicate: depends_on
      object: concept:team-ownership
      source: oauth-server-codebase
      evidence: 'The per-administrator limits count the teams in which the administrator holds the owner role'
      confidence: high
      status: current
---

# Plans limit what a tenant may create, never who may sign in

Since spec 102 (2026-10-15) a project (stored as a bucket) is on a **plan**: a named set of limits and features in a
catalogue a super administrator edits. The public instance needs it because anyone may register as an
administrator there; a self-hosted instance leaves it off. Nothing here charges money.

The switch is `plans.enabled`, off by default (`lib/configs/application.ts:402`). While it is off nothing is
checked and a tenant sees nothing of plans; a super administrator still sees and edits them, so the catalogue can be
prepared before it is turned on.

## The project carries the plan, and records it

The plan lives on the project because the project is the only container (spec 099): it holds the end users, the
applications and the APIs, it is what moves between teams, and it is what monthly active users are counted on
([[monthly-active-users]]).

The plan is **recorded**, never implied: `UserBucket.planId` (`lib/adapters/types.ts:1926`). A new project gets the
catalogue's current default when it is created, whether or not plans are enforced. The migration
`2026-10-18-projects-record-plan` (`lib/consts/migrations.ts:1486`) gave every project that predates plans the one
plan there was, Free. A project leaving the System team gets the default at the move.

The reason is an owner decision (spec 102, clarification Q3): making another plan the default must affect only new
projects. With "absent means the default" — the first draft — changing the default would have silently moved every
existing project, including onto smaller limits. To change every project's terms at once, edit the plan itself.

A System project (the Default and the Administrators project) carries no plan and is never limited: `planOf`
answers null for the System team (`lib/plans/catalogue.ts:38`). A `planId` that names no plan cannot arise — a plan
is not removed while a project names it — and if it ever did, `planOf` falls back to the default. The fallback goes
towards a limit, never towards none.

The catalogue is one document in the shared settings area, absent until a super administrator first edits it. An
absent document reads as the built-in catalogue (`lib/consts/plans.ts:87`), so nothing is seeded and nothing an
operator stored is ever overwritten.

## Checked in the route, before the audit write

Every limit is checked by the admin route, after its authorization and before `recordAdminAudit`. A refused request
leaves no audit entry and no write. The console and an agent are limited alike, because an agent's tool dispatches
into the same route ([[admin-mcp-control-plane]]). A check is never in a store: a store has no caller to exempt, and
it runs after the audit entry.

The checks live in `lib/plans/enforce.ts`. Each is a no-op while plans are off and for a super administrator
(`exempt`, `:36`). The check points are project create, move, restore and address change; team create; becoming a
team owner by member add, role change and invitation acceptance; application create; API declare; and federation
provider create and change. Since spec 103 a member add is a super administrator's alone, so it never limits, and an
owner invitation is not judged when it is sent — a refusal there told the inviter whether the address belongs to an
administrator who owns projects.

**Limits gate only new creations.** A project already over a limit keeps working, is editable, and signs everyone
in. Nothing is deleted, disabled, moved or hidden because a plan allows less than it holds.

**Count, then create, without a lock** (`lib/plans/enforce.ts:26`). Two creations racing at one below a limit may
both succeed. Accepted: the limit is commercial and soft, and preventing the race would need a transaction around
every creation on both backends.

## The refusal is a 409 with a code

A refusal is `409` with `code: 'plan_limit'` and a `limit` naming the limit, the plan and, where the caller may see
them, the count and the maximum (`lib/admin/auth/rbac.ts:109`; [[admin-plane-error-shape]]). Not 403: on MCP that
maps to `forbidden`, which tells an agent it lacks a permission — the wrong lesson. Not 402: nothing is billed, and a
self-hosted operator's plan is not a payment.

A refusal about another owner of a team says only that an owner of that team is at the limit. It never names them,
and never gives their count (`assertProjectRoom`, `lib/plans/enforce.ts:152`).

## Per administrator: counted over the teams they own

"Projects per administrator" counts, for each plan, the live projects in every team in which the administrator holds
the owner role ([[team-ownership]]). A project moving between two teams of the same owner is left out of their
existing count, so the move changes nothing. A project scheduled for deletion does not count until it is restored,
which is why a restore is a check point. Becoming an owner — added as one, promoted, or by an invitation — takes on
the team and every project in it. An invitation is judged only when it is accepted (spec 103), before the single-use
claim, so a refusal leaves it usable once the invitee has room (`assertMayBecomeOwner`, `:207`).

"Regular teams per administrator" is an instance setting, not a plan limit (`plans.regularTeamsPerAdministrator`):
a team has no plan of its own. A personal team never counts.

## Address names on Free are generated

On a plan without `customSlug` a tenant's new project is given a slug of eight random lowercase letters and digits
(`drawSlug`, `lib/admin/buckets/routes.ts:256`). It is random rather than derived from the project's name, so the
issuer URL does not carry the tenant's name. The generated slug is judged by every rule a named one is — reserved,
taken, a colliding subdomain — and drawn again if one refuses it.

The address form is still the tenant's choice among those `projects.addressForms` offers
([[subdomain-project-addresses]]); the plan never decides the form. On Free, naming a slug is refused, at creation
and by an address change to a different name. Moving between path and subdomain under the same name is allowed.

With plans off a slug is required as before. Plans on and a super administrator: a slug is named as before.

## Enterprise sign-in is a paid feature

A provider is social when it is a recognised provider — Google, Apple, GitHub — or Microsoft open to more than one
organisation (`common`, `organizations`, `consumers`). A generic OpenID Connect provider, or Microsoft bound to one
organisation's directory, is **enterprise sign-in** (`classifyProvider`, `lib/plans/provider.ts:24`). Microsoft for
one company is that company's single sign-on under a familiar name, so it is not free (clarification Q2). Only
creating a provider, or changing its issuer or directory, is judged; an existing provider stays editable in every
other respect.

SCIM provisioning is not a plan matter (clarification Q1). The shared instance keeps `scim.enabled` off; corporate
customers get SCIM on an instance of their own.

## The active-user cap pauses sign-ups, never sign-ins

At or over its plan's monthly-active-user cap a project stops creating accounts for people who sign themselves up:
self-registration, and a federated first sign-in that would create an account (`signUpsPaused`,
`lib/plans/signups.ts:30`; called at `lib/interactions/index.ts:1835`, `:1863` and `lib/federation/resolve.ts:285`).
Nothing else is refused — no sign-in of an existing account, no token renewal, no linking, no user an administrator
creates or invites, no directory provisioning.

Both doors answer the existing "not accepting new accounts" page, which names no plan and no figure. The federated
door does not use the provisioning-closed page: that page tells the person to ask an administrator for an account,
which is not what a paused project needs (`lib/federation/routes.ts:265`).

The figure is re-read at most every five minutes per project per process (`REREAD_MS`, `:20`). The cache is keyed by
the plan, its cap and the month, so a plan change, a new cap or a new month is seen at the next check with nothing to
invalidate. The check **fails open**: a figure that cannot be read leaves sign-ups open, because an internal fault
must not lock new people out. It is logged, not recorded as a fault — the error store's capture sites are fixed
([[error-store-capture-sites]]).

## What a caller reads before trying

The project summary carries the plan, what the project uses of each limit, and a warning at 80% (`near`) and at 100%
(`reached`) (`lib/plans/view.ts`); the Usage page rows carry the plan and the warnings. `me.can` adds `nameSlug`,
`projects` and `teams` (`lib/plans/rights.ts`), so the console says before a form is filled in that a limit is
reached, and an agent knows to leave `slug` out. These predict the routes; the routes decide.

## Related

- [[monthly-active-users]] — the figure the cap reads.
- [[team-ownership]] — the owner role the per-administrator limits count.
- [[subdomain-project-addresses]] — the address forms a generated slug is used in.
- [[admin-plane-error-shape]] — the `plan_limit` refusal.
- [[admin-mcp-control-plane]] — the plan tools and their confirmation.
