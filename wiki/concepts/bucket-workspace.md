---
type: concept
title: "The bucket workspace: an Overview that says what needs attention, a Settings tab with a Danger zone"
tags: [architecture, admin, console, contract]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-11
---

# The bucket workspace

Phase 2 of the console redesign (spec 081). A bucket opens on an **Overview** and keeps its own properties
on a **Settings** tab, with the two acts that break things at its foot. The tabs, in order: Overview, Users,
User groups, Sign-in, Identity providers, Provisioning, Signing keys, Activity, Settings — each its own address, the
bare `/admin/buckets/:id` being the Overview (`lib/admin/ui/frame/routes.ts`). The administrators' bucket
lives on the Administrators page since spec 083, and sign-in policy is the Sign-in tab, not a dialog
([[bucket-sign-in-policy]]). The Users tab and each person's page are
[[bucket-users-workspace]] (spec 082). Since spec 084, User groups, Identity providers and Provisioning list
and create only; each group, provider and connection has a page of its own
([[provider-connection-group-pages]]).

## The Overview reads, it never edits

`lib/admin/ui/pages/BucketOverview.tsx` shows what the bucket read and the summary already say:

- **Needs attention**, most urgent first: a provisioning connection holding a mass deprovisioning (its button
  opens the held connection's page since spec 084); a host no
  request has reached; email verification required while the server cannot send mail; an authenticator
  required while password sign-in is off; a bucket owned by the System group (super administrators only); a
  bucket no project uses; a bucket with no address of its own. Each item links to where it is fixed. With
  none, nothing is drawn: an "all good" card is one people learn to ignore.
- **Connection details**: the issuer and discovery addresses, copyable. The server sends them
  (`issuer`, `discoveryUrl` on `GET /admin/api/buckets/:id`) because the browser bundle may not know the
  server's own address (`lib/configs/issuer.ts`). Unaddressed buckets get `null`, not an issuer that 404s.
- **Sign-in at a glance**, read-only, with one link to change it, and the numbers.
- Since spec 085:
  - **Used by** lists the projects read-only. **Use in a project…** picks a project of the same group and opens
    that project's Bucket card with this bucket chosen. The project owns the field, so the change and its
    preview happen there ([[container-ownership-transfer]]).
  - **Protected resources** lists every resource declared in the bucket's namespace, with the project that
    declared it (`GET /admin/api/buckets/:id/resources`, [[mcp-server-authorization]]).
  - **Recent changes** shows the bucket's five latest audit entries (`bucket=<id>`, [[admin-audit-trail]]). It
    is shown only to editors and super administrators: a users-only caller would see a partial history that
    looks complete.

The counts come from `GET /admin/api/buckets/:id/summary` (`lib/admin/buckets/routes.ts:777`), which uses one
new adapter read, `UserStoreInstance.tally()` (`lib/adapters/types.ts:477`): total, unverified, without an
authenticator, without any linked identity — counted the same way on every backend (absent and empty
`federated` both count as unlinked) and verified on real MongoDB and PostgreSQL. Spec 083 added two counts
the sign-in preview confirms against — without a link to an *enabled* provider, and password users without an
authenticator — and, on the default bucket, the projects signing in there ([[bucket-sign-in-policy]]). Users active this month
appear only to a caller who may read the bucket's activity, and are absent, not zero, before counting began.

## Rights that depend on the bucket's state

Two owner decisions made two rights state-aware (`lib/admin/auth/can.ts:205`):

- **`changeAddress`**: a super administrator, or an owner of the bucket's group while the bucket is served at a
  path (or has no address) and nothing depends on it — no project (counted across the instance, not only the
  ones the caller sees), no identity provider, no provisioning connection. A host target is super-administrator
  only, checked in the route because `can` is per bucket, not per target.
- **`delete`**: as before, plus: a bucket that still holds accounts only for an owner of its group or a super
  administrator.

This keeps 079's definition of a flag — would the route accept this caller for this bucket as it is now — and
the rights matrix (`test/admin/can_routes.spec.ts`) proves it with two new bucket kinds, "unused" and "holding
accounts". The facts are read only for callers they can change: dependency counts for an owner who is not a
super administrator, the account count for a member who is not an owner. A super administrator's list costs
nothing new. `blockers.dependents` and `blockers.accounts` carry the facts so the console can state the reason.

## The Danger zone

- **Change address…** previews by name (applications with their projects, connections, providers with their
  new callback address, resources) and commits only with the preview's counts (`expect`). A change in between
  is refused with a fresh preview — never applied silently. The audit entry now carries the owning group, so an
  owner sees their own change in their trail.
- **Delete bucket…** reads the account count when the dialog opens (`DeleteBucketDialog.tsx`, shared with the
  list menu); a count that moved before confirming is refused by the server and the dialog starts over with the
  new number. The delete entry also carries the owning group now.

## Fixed along the way

- `setAddress` cleared nothing, so a bucket moved from one host to another read as "reached" from the old
  host's traffic; it now clears both arrival fields in all three adapters.
- The list's `held` flag comes from one read, `ProvisioningConnectionStore.bucketsHolding()`
  (`lib/adapters/types.ts:1360`); the MongoDB version uses an aggregation because `distinct` is refused under the
  strict Stable API.
- The Audit page reads its filters from its address, so the Overview can link to a bucket's entries. Since spec
  085 it also writes them back and shows each as a removable chip ([[admin-audit-trail]]).

## Related

- [[admin-console-frame]] — addresses, rights, the confirmation ladder this builds on
- [[group-ownership]] — the two exceptions to "a member equals an owner"
- [[bucket-is-an-issuer]] — what an address change does to issued tokens
