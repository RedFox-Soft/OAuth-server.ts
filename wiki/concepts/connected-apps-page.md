---
type: concept
title: 'The connected-applications page: an end user sees and removes the access they gave'
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-10-13
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:end-user-support
    - predicate: depends_on
      object: concept:consent-screen-decisions
    - predicate: relates_to
      object: concept:cookie-path-scoping
    - predicate: relates_to
      object: concept:project-is-an-issuer
    - predicate: relates_to
      object: concept:admin-audit-trail
    - predicate: relates_to
      object: concept:interaction-page-families
---

# The connected-applications page

Since spec 095, every project has `/account/apps` at its own address. It lists the applications
holding access to the signed-in person and lets them remove one. It is the first end-user page outside a
sign-in interaction (`/ui/:uid/*`). Before it, only an administrator could end a person's access to one
application ([[end-user-support]]).

The routes are mounted bare and beneath `/:bucket` (the project's path segment), like every
project-scoped surface (`lib/index.ts:253`). They are classified always-available: no switch may hide the one place consent can be
withdrawn. The routes are `GET /account/apps`, `POST /account/apps` and `GET /account/apps/callback`
(`lib/account_page/routes.ts:213`).

## The person comes from the project's own session, not from a token

The server is the authorization server, so it already knows who is signed in. The page reads the addressed
project's session cookie and the session record (`usablePerson`, `lib/account_page/session.ts:44`). It mints
nothing. It never calls `setCookies()`, because a save renews the whole sign-in, and looking at one's
applications is no reason for a sign-in to last longer.

At the root, the Default project and every project with no address share `_session_default`, so the session's
`bucketId` names the person's project. That project must still share this address's cookie: the same comparison
sign-out makes (`session.ts:65`). Otherwise a project given an address after the sign-in would stay readable at
an address it no longer has. A person who may not sign in (`canSignIn`) gets nothing (`session.ts:76`).

## The built-in client can only bring the person back

With no usable session, the page starts an ordinary sign-in in the project through `account.<bucketId>`. That
client is synthesized from the project on every resolution and never stored, like the SCIM client
(`lib/account_page/client.ts:57`, resolved after the stored read and the SCIM client at
`lib/models/client/validate.ts:127`).

How it is limited:
- **No code, no token.** It has `response_type=none` and no grant type (`client.ts:67`). The page needs
  nothing back except that the session now exists.
- **One project.** `resolveBucketForRequest` maps the id to its project (`lib/admin/auth/resolveBucket.ts:59`),
  so `checkBucket` refuses it at any other address.
- **Not for every project.** It does not exist for the administrators' project, for a project scheduled for
  deletion, or for an unknown one: `invalid_client`.
- **No look-alikes.** `.` is outside nanoid's alphabet, so no generated id can collide with it. A registration
  is refused the prefix even through a deployment's own `idFactory` (`lib/models/client/register.ts:38`).
- **No consent page.** It belongs to no stored project record (no `bucketId`; until spec 099, no old
  Project entity either — a retired project) and
  has `consent.require: false`, so consent is waived.
  `redirectUrisVouchedFor` answers true for it (`lib/models/client/provenance.ts:30`). Otherwise a cancelled
  sign-in would show the RFC 9700 "untrusted redirect" page instead of coming back.

Every authorization leaves a trusted Grant and a session entry, and this one does too. Both are filtered out of
every per-application listing, the administrator's view included (`grantsByClient`,
`lib/end_users/sessions.ts:101`).

A project with no address of its own serves its page at the root (`accountPageBase`, `client.ts:48`),
because `issuerFor` names it `ISSUER/<id>`, which routes nothing. A sign-in started from that root page uses
the Default project's client. People of such a project therefore reach their list with the session an
application gave them, not by signing in from the page.

## A GET never removes anything

The callback checks `state` against a short-lived `_account_apps` cookie. The cookie is pathed to the page and
named the same on set and clear ([[cookie-path-scoping]]). Then the callback re-reads the session. It never
acts on what the pending sign-in asked for (`routes.ts:345`):
- A re-authentication for a removal returns to that application's confirmation, and the person confirms again
  with the fresh sign-in.
- If a different person finished the sign-in, the intent is dropped.
- A sign-in that is still not fresh shows the failure page rather than starting another round. This avoids a
  loop.

## Removing needs a recent sign-in and a form this page served

`POST /account/apps` checks, in order:
1. `Sec-Fetch-Site` and `Origin` say the page itself sent it (`fromThisOrigin`, `session.ts:113`).
   `Origin: null` is not a refusal. Every page here carries `Referrer-Policy: no-referrer`, and under that
   policy a browser serializes even a same-origin form's origin as `null`. Refusing it refused the page's own
   form in Chrome while every in-process test passed. Only the browser walk found it.
2. The session is usable.
3. The per-session anti-forgery value matches. It is a declared session field, `accountPageXsrf`
   (`lib/models/session.ts:50`), not `state`, which sign-out and the device flow overwrite wholesale. It is
   created once and saved with the session's remaining lifetime (`session.ts:81`).
4. The sign-in is no older than `ACCOUNT_REAUTHENTICATION_SECONDS` = 900 (`lib/consts/account_page.ts:21`).
   Otherwise the person signs in again with `prompt=login`.

An unknown application, another person's application and the page's own client all get the same "no longer
has access" answer (`routes.ts:286`). Removal is the administrator's `endApplicationAccess`, unchanged. It ends
the grants, every token under them and the session entries, and sends back-channel logout. So the application
asks for consent again next time. A consent-waived application signs the person in again silently, and the
confirmation says so.

The form `action` is the page's origin-relative path, never `${issuer}/…`. At a host-addressed project an
issuer URL would count as a foreign form target in `csp.ts`, and the page would lose `frame-ancestors`.

## What a row says

What a row says is decided purely in `applicationRow` (`lib/account_page/view.ts:91`):
- **Permissions:** the grant's effective permissions, sorted and worded by the consent page's own code
  (`describeGranted`, `lib/interactions/consentView.ts:403`). The grant getters have already removed what the
  person declined.
- **Hosts:** from the client's redirect URIs, because a grant stores none.
- **Logo:** only for this organization's own applications (spec 094).
- **"Keeps access after you sign out":** only when a live refresh token exists (`view.ts:135`). `offline_access`
  merely granted outlasts nothing.
- **Dates:** "Last given a token", never "last used", because a self-contained access token is never stored.
- **Consent-waived grants:** such a grant records no permissions, and the row says the application gets what
  it asks for.

## The record

Each removal is one audit entry under the administrator's action, `enduser.application.signout`. The actor is
the sentinel `enduser:<bucketId>:<accountId>` (`lib/consts/admin_audit_routes.ts:820`,
`recordEndUserAudit`, `lib/admin/audit/record.ts:222`), `viaSurface: 'self-service'`. It carries the project's
`ownerGroupId` (its owning team; `ownerTeamId` when presented), so the team's administrators read it. The
read resolves the person's address as `actorName`.
Following the bootstrap convention (a `:` and no `@`), no reader mistakes the person for an administrator.

## Grants record their project

Since spec 095 every new Grant carries `bucketId` (`lib/actions/authorization/load_grant.ts:31`,
`lib/addon/account.ts:169`, `lib/interactions/index.ts:494`). An administrator may choose an account id, so two
projects can share one. Before, `grantsIn` counted every grant as every project's, and one project's page or
console would have listed the other's access. Older grants still read as before until they expire.

## Related

- [[consent-screen-decisions]]: the "remove this access later" line on the consent page links here
  (`lib/interactions/index.ts:855`).
- [[interaction-page-families]]: the page is plain and script-free, so every step works without JavaScript.
- [[end-user-support]]: the administrator's per-application view and sign-out it reuses.
