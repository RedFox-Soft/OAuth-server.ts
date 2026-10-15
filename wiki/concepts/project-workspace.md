---
type: concept
title: "The project workspace: an Overview that says what needs attention, a Settings tab with a Danger zone"
tags: [architecture, admin, console, contract]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-15
---

# The project workspace

A project is stored as a bucket (`UserBucket`, area `userBuckets`); the code, its page components
(`BucketOverview.tsx`, `BucketDetail.tsx`) and its route keys (`bucket.overview`, …) keep that name. A team
is stored as an administrator group (`Group`), and a project's group of end users as a bucket group
(`BucketGroup`). Spec 100 renamed them where people read them: the console's `/admin/projects/…` (the old
`/admin/buckets/…` addresses redirect) and the API's `/admin/api/projects/…`.

Phase 2 of the console redesign (spec 081). A project opens on an **Overview** and keeps its own properties
on a **Settings** tab, with the two acts that break things at its foot. The tabs, in order
(`lib/admin/ui/pages/BucketDetail.tsx:59-75`): Overview, Applications, APIs, Users, Groups, Sign-in,
Identity providers, Provisioning, Signing keys, Activity, Settings — each its own address, the bare
`/admin/projects/:id` being the Overview (`lib/admin/ui/frame/routes.ts:77-82`). The Groups tab was called
User groups, at `/admin/buckets/:id/user-groups`, until spec 100. The administrators' project lives on the
Administrators page since spec 083, and sign-in policy is the Sign-in tab, not a dialog
([[project-sign-in-policy]]). The Users tab and each person's page are
[[project-users-workspace]] (spec 082). Since spec 084, Groups, Identity providers and Provisioning list
and create only; each group, provider and connection has a page of its own
([[provider-connection-group-pages]]).

## The Overview reads, it never edits

`lib/admin/ui/pages/BucketOverview.tsx` shows what the project read and the summary already say:

- **Needs attention**, most urgent first: a provisioning connection holding a mass deprovisioning (its button
  opens the held connection's page since spec 084); a static token within 14 days of its expiry, or expired
  (since spec 088, [[scim-credential-overlap]]); a host no
  request has reached; email verification required while the server cannot send mail; an authenticator
  required while password sign-in is off; a project owned by the System team (super administrators only); a
  project no application signs in to yet (no retired project used it, until spec 099;
  `BucketOverview.tsx:207-222`); a project with no address of its own. Each item links to where it is fixed.
  With none, nothing is drawn: an "all good" card is one people learn to ignore.
- **Connection details**: the issuer and discovery addresses, copyable. The server sends them
  (`issuer`, `discoveryUrl` on `GET /admin/api/projects/:id`) because the browser bundle may not know the
  server's own address (`lib/configs/issuer.ts`). Unaddressed projects get `null`, not an issuer that 404s.
- **Sign-in at a glance**, read-only, with one link to change it, and the numbers.
- Since spec 099 the project's details say what it **holds**: its applications and APIs, counted, each count a
  link to its tab (`BucketOverview.tsx:327-345`). **Applications** and **APIs** are tabs of the project
  (`BucketDetail.tsx:61-62`), reusing the client and resource pages against `/admin/api/projects/:id`
  ([[project-is-the-only-container]]). Spec 085's **Used by** (the old Project entity, removed in spec 099
  and now called a retired project, with **Use in a project…**) and **Protected resources** (the namespace's
  declarations with the retired project that made each) went with those projects.
- Since spec 085:
  - **Recent changes** shows the project's five latest audit entries (`project=<id>`, `BucketOverview.tsx:438-443`;
    `bucket=<id>` until spec 100; [[admin-audit-trail]]). It is shown only to editors and super
    administrators: a users-only caller would see a partial history that looks complete.

The counts come from `GET /admin/api/projects/:id/summary` (`lib/admin/buckets/routes.ts:856`), which uses one
new adapter read, `UserStoreInstance.tally()` (`lib/adapters/types.ts:477`): total, unverified, without an
authenticator, without any linked identity — counted the same way on every backend (absent and empty
`federated` both count as unlinked) and verified on real MongoDB and PostgreSQL. Spec 083 added two counts
the sign-in preview confirms against — without a link to an *enabled* provider, and password users without an
authenticator — and, on the Default project, the applications signing in there (`applications`; `projects`,
counting retired projects, until spec 099) ([[project-sign-in-policy]]). Users active this month
appear only to a caller who may read the project's activity, and are absent, not zero, before counting began.

## Rights that depend on the project's state

Two owner decisions made two rights state-aware (`bucketCan`, `lib/admin/auth/can.ts:195`; `mayChangeBucketAddress`, `:158`):

- **`changeAddress`**: a super administrator, or an owner of the project's team while the project is served at a
  path, at a subdomain of the instance (since spec 101, `ownerMayReaddress`, `lib/admin/auth/can.ts:126`) or
  has no address, and nothing depends on it — no application in it, a self-registered one included
  (`dependentsOf`, `lib/admin/buckets/routes.ts:528`; a retired project, until spec 099), no identity
  provider, no provisioning connection. The target form is checked in the route, because `can` is per project,
  not per target: a host target is super-administrator only, and an owner may move only into a form
  `GET /admin/api/me`'s `can.addressForms` lists (`assertMayChooseForm`, `lib/admin/buckets/routes.ts:198`).
  That list replaced the boolean `can.createHost` in spec 101. It is ordered, its first entry is the form the
  console preselects, and for a team it follows the `projects.addressForms` setting
  ([[subdomain-project-addresses]]).
- **`delete`**: as before, plus: a project that still holds accounts only for an owner of its team or a super
  administrator.

This keeps 079's definition of a flag — would the route accept this caller for this project as it is now — and
the rights matrix (`test/admin/can_routes.spec.ts`) proves it with two new project kinds, "unused" and "holding
accounts". The facts are read only for callers they can change: dependency counts for an owner who is not a
super administrator, the account count for a member who is not an owner. A super administrator's list costs
nothing new. `blockers.dependents` and `blockers.accounts` carry the facts so the console can state the reason.

## The Danger zone

- **Change address…** previews by name (applications, connections, providers with their new callback address,
  resources — `applications: {clientId, name}[]` and `resources: {identifier, name}[]` since spec 099, which
  dropped the retired project beside each application) and commits only with the preview's counts (`expect`). A change in between
  is refused with a fresh preview — never applied silently. The audit entry now carries the owning team, so an
  owner sees their own change in their trail.
- **Delete project…** reads the account count when the dialog opens (`DeleteBucketDialog.tsx`, shared with the
  list menu); a count that moved before confirming is refused by the server and the dialog starts over with the
  new number. The delete entry also carries the owning team now. Since spec 090 it schedules the project's
  destruction 30 days out instead of destroying it. A scheduled project's Danger zone, banner and list menu offer
  Restore and Delete now, and every area turns read-only ([[project-soft-delete]]).

## Fixed along the way

- `setAddress` cleared nothing, so a project moved from one host to another read as "reached" from the old
  host's traffic; it now clears both arrival fields in all three adapters.
- The list's `held` flag came from one read, `ProvisioningConnectionStore.bucketsHolding()`; the MongoDB version
  uses an aggregation because `distinct` is refused under the strict Stable API. Since spec 088 the list reads
  `listHeld()` (`lib/adapters/types.ts:1563`) instead, the same hold test returning the connections, so a row also
  carries `heldConnectionId` and its On hold mark links to the connection. The list's project set is
  `visibleBuckets` (`lib/admin/buckets/visible.ts:15`), shared with the console-wide held-connections badge
  ([[scim-provisioning]]).
- The Audit page reads its filters from its address, so the Overview can link to a project's entries. Since spec
  085 it also writes them back and shows each as a removable chip ([[admin-audit-trail]]).

## Related

- [[admin-console-frame]] — addresses, rights, the confirmation ladder this builds on
- [[team-ownership]] — the two exceptions to "a member equals an owner"
- [[project-is-an-issuer]] — what an address change does to issued tokens
