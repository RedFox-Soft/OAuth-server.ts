---
type: concept
title: "Federation into the console: who can become an administrator, and never locking the door"
tags: [architecture, security, admin, federation]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-15
---

# Federation into the console

Since spec 080 the administrators' project takes upstream identity providers like any project, so
administrators can sign in to the console with their organisation's provider. The sign-in itself needed
nothing new: the federation flow carries the project in its pending state and never tested for the reserved
project, so a provider stored on project `admin` already appeared on the console's sign-in page and worked.
(A project is stored as a bucket, `UserBucket`; the code below keeps that name.)
What the feature adds is who may configure those providers, what a first sign-in may create or link, and a
guarantee that the console cannot shut itself.

## Only super administrators configure them

Whoever configures a provider of this project decides who can reach the console. The five provider routes use
`loadBucketForProviders` (`lib/admin/buckets/access.ts:94`), which has `loadBucketForSettings`'s rule: the
administrators' project for a super administrator only, every other project as before. In the rights guard the
reads are declared under `read` and the writes under `editSettings`, which on an ordinary project answer as
`manageUsers` and `edit` do, so nothing changed there. `assertMayConfigure` (`lib/admin/federation/service.ts:330`)
is a second lock in the service. The users' identities routes stay refused for this project: an
administrator's links are not managed from the project page, which also closes one way to unlink the last
reachable super administrator.

A provider created here defaults to `existing_only`.

## Becoming an administrator through a provider

- **Linking always needs the password proof** (`lib/federation/resolve.ts:264` since spec 088's split of the ladder). Ordinary projects link
  without it once the account holds an identity, or when the project has no password door. Here the account
  behind the address may be a super administrator, so any provider trusted for the address — a second one, or
  any one once passwords are off — would otherwise sign its holder in as them. With passwords off, no new
  identity can be linked at all; the password-off question names who that leaves out.
- **A closed sign-up closes creation** (`resolve.ts:277`), before the provider's own setting. Ordinary projects
  keep "the provider's own knob decides" (research question 9.4 of the console redesign).
- **A created administrator** gets a personal team and an `admin.register` audit entry
  (`lib/federation/routes.ts:269`, `registeredAdministrator`), and never the instance privilege: only its own
  grant routes change that membership. The refusal page says "You have no console account".
- **The second factor** stays the provider's (owner decision): the project's authenticator requirement applies
  to password sign-in only, as in every project ([[totp-second-factor]]).
- **A locked administrator** is refused at `/admin/callback` too, which now asks `canSignIn` rather than
  `active` alone.

## Never locking the console

Two rules.

1. **Password sign-in goes off only for someone who just came in through a provider.** The console session
   records `signedInWith`, the provider of the administrators' project its sign-in came through
   (`lib/admin/auth/login.ts:38`, read from the provider session's `upstream`, the codebase's one reading of
   "came in through a provider"). `assertMayTurnPasswordsOff` (`lib/admin/buckets/admin_bucket.ts:59`)
   requires that provider to be enabled and the actor linked there. An agent has no console session, so it
   never qualifies; this is a guard on the request, not a right, so `can` stays independent of the channel.
2. **While passwords are off, some super administrator must stay reachable.** `consoleStaysReachable`
   (`lib/admin/federation/reachability.ts:67`): an active, unlocked super administrator linked at an enabled
   provider that still admits their address. Every change that could break it computes its after-state and
   asks the one predicate — turning passwords off, disabling, narrowing or deleting a provider
   (`assertConsoleKeepsADoor`, `service.ts:344`), deactivating an administrator, withdrawing the privilege,
   changing an address.

If every provider fails upstream with passwords off, `bun run admin:password-sign-in`
(`database/admin_password_sign_in.ts`, `restorePasswordSignIn` in `lib/admin/password_sign_in.ts:13`) turns
password sign-in back on from the server and records `admin.passwordsignin.restore` with the bootstrap actor.
`db:setup` never rewrites an existing project, so it could not do this.

The console reads `GET /admin/api/admins/sign-in-readiness` (`lib/admin/users/routes.ts:130`) before the
switch: how this session signed in, how many super administrators could still get in, and who could not.

## Agents

An agent may configure the console's providers, as the console does, but each write there is
high-consequence: `McpTool.highWhen` (`lib/mcp/catalogue.ts:1401,1415,1442`) gates `federation_provider_create`,
`federation_provider_update` and, since spec 088, `federation_provider_move` (the sign-in button order) on the
administrators' project only, through the ordinary two-call confirmation. The token binds the target, so a confirmation for this project changes nothing on another.
Ordinary projects take one call. Turning password sign-in off is refused to an agent by rule 1.

## Related

- [[admin-project-settings]] — the project's other settings and their guards
- [[upstream-federation]] — the account-resolution ladder these rules modify
- [[admin-console-signin]] — the console's relying-party sign-in, which now records `signedInWith`
- [[admin-mcp-control-plane]] — the confirmation gate `highWhen` extends
