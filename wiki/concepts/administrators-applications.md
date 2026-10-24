---
type: concept
title: "Applications in the Administrators project: internal tools that sign administrators in"
tags: [architecture, contract, security, oauth]
sources: [oauth-server-codebase]
created: 2026-10-21
updated: 2026-10-21
graph:
  node_type: concept
---

# Applications in the Administrators project

Spec 109. A super administrator registers an ordinary sign-in application in the Administrators project so one of
the owner's own internal tools (foxtrust's admin panel was the first) admits exactly the people who administer this
instance, by the teams they are in — instead of a separate project with a second account per person. The tool
changes configuration only: issuer (the root), client id and secret, and the group it requires.

## What it is, and what it may never be

"An administrators' application" is a client whose stored `bucketId` is the administrators' bucket and whose id is
neither `admin-panel` nor `admin-mcp` (`isAdministratorsApplication`, `lib/admin/administrators_application.ts`).
The two seeded clients live in the same bucket and are not such applications.

- **Sign-in only, confidential only.** The routes write `authorization_code` (+ `refresh_token`) and nothing else;
  their bodies are closed objects, so no grant, response type, resource or project can be named
  (`lib/admin/administrator-applications/schema.ts`). The stored grant list is then the token endpoint's gate.
- **No resource at all.** `getResourceServerInfo` refuses every indicator from such a client first, before the SCIM,
  MCP and declared-resource arms (`lib/addon/resources.ts:86`). Without it the MCP arm minted it an
  administrative-audience token that only `/mcp`'s `assertClientPermitted` refused — and, the administrators' bucket
  being served at the root, the declared-resource lookup handed it **the default project's root APIs** (found by the
  boundary test, 200 before the fix). `error_description` must be ASCII (RFC 6749 §5.2): a typographic apostrophe in
  the message arrived as a space.
- **Nothing reaches the control plane.** The console API takes a bearer only on a dispatched request and only with
  the MCP audience; SCIM tokens are minted only for a connection's synthesized client; a console session comes only
  from the console's own callback. Held by `test/administrator_applications/boundary.spec.ts`.

## Routes of their own, writes withheld from agents

`/admin/api/administrators/applications[/:clientId[/secret]]`, super administrators only, audit-first
(`admin.application.*`), no plan consulted. Not the project application routes, which keep refusing the reserved
bucket: what an agent may do is decided per route in the MCP catalogue, so the reads are published
(`administrator_application_list/get`) and the four writes are `withheld` — registering one decides which outside
service may sign the instance's administrators in, the same class as permitting another client identity
(`lib/mcp/catalogue.ts:2134`). Mounted as a statement after the `adminApiRoutes` chain, not a link in it: the chain is
at TypeScript's instantiation limit (TS2589), as `lib/index.ts` already records for SCIM (`lib/admin/routes.ts:135`).
The console shows them as the Administrators page's Applications tab.

## `groups` names an administrator's teams

For an account of the administrators' bucket, `groups` is the names of the teams they are a member of, personal team
excluded, sorted, with the same 200-entry reference rule as a project's groups (`administratorTeamsClaimFor`,
`lib/bucket_groups/claim.ts:61`, chosen in `lib/addon/account.ts:128`). Keyed on the account's bucket, not the client:
the console and `admin-mcp` would get the same answer, and neither asks for the scope. This widens what `groups` means
— until now only end-user groups — without undoing spec 071's separation: it is a read of names into a signed
response; teams are still changed only by the team routes and SCIM never reaches them ([[project-groups]]).

## `groups` is now always in the ID token

Found while proving the goal against production settings: `conformIdTokenClaims` is on and userinfo is enabled, so
in the code flow the ID token carried no scope claims — `groups` included — and the internal tool, which reads
`groups` from the ID token, would have admitted nobody, with this feature or with its old separate project. Owner's
decision (2026-10-21): `conformedIdTokenScope` keeps `groups` in the masked ID token scope whenever it was granted,
for every project (`lib/consts/groups_claim.ts:76`, used by the four grants that mask). OIDC Core §5.4 moves the claims
of profile, email, address and phone to userinfo; `groups` is this server's own scope, outside that rule, and is where
Okta and Entra put it. Other scope claims stay masked.

## Signing out of the tool

Found the same way: `/logout` at the root refused every administrators'-bucket client ("client is not authorized at
this address"), because the address names the default project's cookie and the administrators' sign-in lives under
its own. The tool's sign-out redirect would have shown an error page. Now `/logout` resolves the client **before**
reading the session, and an administrators'-bucket client at the root reads and ends the administrators' sign-in —
the rule `checkBucket` applies at `/auth` (`lib/actions/end_session.ts:202`). The second leg, `POST /logout/confirm`,
carries no client: the page the first leg rendered puts `?administrators` on the confirmation's address, and the
confirmation then reads that session; its xsrf secret is that session's own, so naming the wrong one only fails the
check (`:367`). The console keeps its own BFF session: signing out of the tool ends the administrators' provider
sign-in, not the console page already open. This corrects what [[cookie-path-scoping]] said could not be done.

## Deactivation revokes

Administrator deactivation now runs `revokeAccountAccess` (`lib/admin/users/routes.ts:333`). It used to set
`active: false` only; the console and `/mcp` re-read it per request and `findAccount` refuses refresh and userinfo,
but tokens already issued to such an application lived out their lifetime. The test proves removal from storage, the
one thing only revocation does.

## Related

- [[project-groups]] — the `groups` claim, teams vs groups.
- [[team-ownership]] — teams, Super administrators.
- [[admin-mcp-control-plane]] — the withheld list.
- [[cookie-path-scoping]] — which session a sign-in and a sign-out read.
- [[admin-console-signin]] — the console's own sign-in and sign-out.
