---
type: concept
title: 'Connected services: a person connects accounts at other services'
tags: [architecture, security, storage, decision, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-02
updated: 2026-11-02
---

# Connected services

Spec 117, the floor of the token vault (spec 116 sealed stored secrets; 118 issues the stored tokens to agents by
token exchange, below; 119 adds the agent's connect link). A project declares **connected services**
(Google, GitHub, Slack, Microsoft, an OpenID Connect issuer, or a plain OAuth 2.0 provider) with its own
registration at each provider. A person **connects** their account at one from their account page, and the
provider's tokens are stored sealed. Since spec 118 an agent the administrator and the person both allowed obtains
them by token exchange.

Words: a *connected service* is the project's registration at a provider; a *connected account* is one person's
account at one service. The account page's older list is *connected applications* (specs/095), the opposite
direction.

## Where things live

- **A service is embedded on the project record**, beside `federation`: `UserBucket.connectedServices`
  (`lib/adapters/types.ts:2214`). Owned by the project for life, deleted with it, sealed by the project store's
  decorator (`lib/sealing/decorators.ts`, `services()`), at most a handful per project (a plan limit, Free 10).
  Its provider and client id never change: the accounts' tokens belong to that registration.
- **An account is a row of the `connectedAccounts` store** (`lib/consts/storage_inventory.ts:685`), three
  backends, `_id` derived from (project, service, person, upstream account)
  (`lib/connected_services/accounts.ts:59`), so a reconnect of the same upstream account replaces the row by its
  primary key on every backend and no second unique index exists.
- **A connect flow in flight is a `ConnectState` model record** (`storage_inventory.ts:423`), keyed by
  sha256(state), ten minutes, account-owned.

## Why connected accounts are deliberately not account-owned

"Owned by an account" in the inventory means "swept by `sweepAccountOwned`", which every lock, deactivation and
end of access runs (`lib/end_users/revoke_access.ts`). The owner decided a lock **keeps** connected accounts: it is
reversible, and an unlock must not make a person connect everything again; the lock already destroys the grants,
and 118's exchange checks the person can sign in. So the store declares `unowned(...)` with that reason, and the
three deletions that must remove accounts do so by hand:

- the person deleted: `removeEndUser` (`lib/end_users/service.ts:331`), which the admin route, bulk delete and SCIM
  all go through;
- the service deleted: its admin route, accounts first while the service is still on the record their revocation
  reads;
- the project destroyed: `destroyClaimed` (`lib/admin/buckets/destroy.ts:226`).

`ConnectState`, by contrast, *is* account-owned: a lock should end a connect that has not come back.

**Gotcha:** a new path that deletes a person or a service must call `destroyConnectedAccountsOf` /
`destroyServiceAccounts` itself. No sweep will.

## The connect flow and what binds it

Started only by a same-origin POST from `/account/services` with the page's anti-forgery value and a sign-in no
older than fifteen minutes (`lib/account_page/services_routes.ts`). The callback (`services_routes.ts:375`) spends
the state first, then refuses unless the addressed project is the flow's, the browser's session digest
(`services_routes.ts:405`) and account are the ones that started it, the person can still sign in, the service
still exists and a keyring is in use. Then `iss` (RFC 9207, where the provider advertises it), then the code with
the flow's PKCE verifier.

**Gotcha:** the flow never sends `response_mode` and never inherits the sign-in catalogue's `returnMode`. The
binding rests on the person's session cookie, which is `SameSite=Lax` and reaches the callback only on a top-level
GET; a provider posting back (`form_post`, as Apple does for sign-in) would arrive without it and every connect
would be refused.

**Gotcha, found only in a browser:** `form-action` governs a form's whole redirect chain, so the connect
confirmation, which posts to itself and is answered with a redirect to the provider, must name the provider's
authorization origin (`handOffTo`, `lib/account_page/html.ts`, through `page()` in
`lib/interactions/plainPage.tsx`). With `'self'` alone Chrome blocks the person's own Continue and reports the
same-origin action as the violation, while every `elysia.handle` test passes. A spec now pins the policy.

## Provider differences are data

`lib/consts/connected_service_catalogue.ts` states each one as a field, never a branch: Google needs
`access_type=offline` and `prompt=consent` for a refresh token; Slack hands the person's token back under
`authed_user`, takes scopes in `user_scope` joined by commas, and **never** gets a code challenge (enabling PKCE
on a Slack app makes it public, one-way, with refresh tokens capped at 30 days); GitHub answers with comma-separated
scopes and is identified through `/user` `id`; Microsoft is keyed `tid:oid` because `sub` is pairwise per
application, and has no revocation at all. A plain OAuth 2.0 service must declare where its account id is (an
identity endpoint or the token answer), because without a key a second account cannot be told from a reconnect.

## Tokens are never plaintext

Unlike every 116 field, the connected-account store **throws** `KeyringRequired` on a write while no keyring is in
use (`lib/sealing/decorators.ts:705`, `:744`); the service layer refuses earlier with a message, and declaring or
editing a service is refused with 409 `keyring_required`. After a lost key the account reads as
`needs_reconnection`, is counted in the keyring status with its person, and a reconnect replaces it; the service's
own secret was lost too, so an administrator re-enters it first.

## Revocation: local first, provider best-effort

Every removal deletes the row, then asks the provider (`lib/connected_services/revoke.ts`): Google's revoke form
with the refresh token, GitHub's grant deletion with Basic client auth, Slack's `auth.revoke` with the user token,
RFC 7009 for a generic provider that has an endpoint, nothing for Microsoft (the person is linked to its consent
page). Four seconds per request, so a person's own disconnect answers within five; every cascade revokes in the
background, four at a time, never holding the request.

Since spec 118, GitHub's and Slack's revocations, which authenticate with the access token, refresh an expired one
first (`revocableTokens`, `lib/connected_services/accounts.ts`): without a lease, because the record is already
deleted, and within one second for the person's own disconnect so the whole stays under five.

## Handing the tokens to agents (spec 118)

An agent exchanges a person's access token at `/token` by RFC 8693 with
`requested_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience=<service id>` and, when the person
allowed several accounts there, `login_hint=<account label>` (Auth0 Token Vault's parameter for the same choice). The
answer is the stored upstream access token, never the refresh token. Everything is in
`lib/connected_services/upstream_exchange.ts:134`; the grant only routes there by token type
(`lib/actions/grants/token_exchange.ts`).

**Two consents, both checked on every exchange.** The administrator's: `ConnectedService.applications`, the
applications that may obtain that service's tokens, edited through the service's own PATCH. The person's: a
`connected` map on their Grant to the agent, keyed `account:<id>` (or `service:<id>` before they have an account
there), so it goes wherever the grant goes (`lib/connected_services/consent.ts`). Nobody among ten vendors asks the
person per agent; this is deliberate.

**Who may exchange.** The agent itself when it is confidential, or the application an administrator linked to an API
the agent's token was issued for (`ProtectedResource.exchangedBy`, the MCP server case, Auth0's "Custom API Client").
`whyCannotExchange` (`lib/connected_services/eligibility.ts:14`) is the one test for both and for the exchange: an
application of this project, created by an administrator, that authenticates and holds the token exchange grant.

**Gotcha: a JWT access token is not stored.** `BaseModel.save` writes only when the format yields a payload, and the
JWT format yields the value alone, so a JWT subject (an MCP server's, by default) has no record and names no grant.
`exchangeSubject` (`lib/connected_services/subject.ts:123`) verifies it as its API would (keys, issuer, `at+jwt`,
lifetime), takes the person from `sub` (refused for a pairwise agent) and reads the consent from the person's live
grants to the agent: removing the application's access leaves none, so the token is refused although it cannot itself
be revoked.

**Refusals carry a `reason`** beside RFC 6749's `error` (`UpstreamTokenRefused`, `lib/helpers/errors.ts`):
`not_permitted`, `consent_required`, `connect_required`, `account_selection_required`, `reconnect_required`,
`temporarily_unavailable`. A bad subject token is plain `invalid_grant` with none, so no answer says anything about the
person's accounts.

**The grant is always advertised.** `supportedGrantTypes` lists token exchange whatever `tokenExchange.enabled` says
(`lib/configs/discoverySupport.ts:92`); the setting now gates only ID-JAGs, and an ID-JAG request while it is off is
`invalid_request`, never `unsupported_grant_type`, because an advertised grant is never refused as unsupported (see
[[enterprise-managed-authorization]]).

## One refresh at a time

GitHub (expiring user tokens) and Slack (token rotation) spend a refresh token on use, so two concurrent refreshes
lose the account. `freshAccount` (`lib/connected_services/refresh.ts:59`) shares one in-process promise per account and
takes a 20-second lease written on the record itself (`claimRefresh` / `finishRefresh` / `releaseRefresh`, all three
backends); a waiter polls the record for at most 12 seconds; a holder that died is taken over when its lease runs out.
The new tokens are stored before anyone receives them; a refresh whose result could not be stored breaks the account
(`refresh_unsaved`), because the provider has already spent the old refresh token.

**Gotcha (found by the real-PostgreSQL verify):** dropping keys with `doc - ${array}::text[]` fails at runtime, since
Bun binds a bare JS array as comma-joined text. Use `handle.array(keys, 'text')`, as every other store does.

**Slack's refreshed user token** sits where the documentation does not say: its rotation guide shows the user case
only as a fragment with the `authed_user` members. The catalogue's `refreshTokenPath: 'authed_user'` tries there, then
the top level; the code exchange never falls back to the top level, where Slack puts the bot's token.

## Keep-alive and mail

An hourly pass (`lib/connected_services/keep_alive.ts:31`, started in `lib/index.ts`) refreshes, under the same lease,
every account with a refresh token that an agent may use and did use within twelve months, when it was not refreshed
for thirty days or its refresh token expires within a week. Thirty days sits inside Google's six idle months,
Microsoft's ninety days and GitHub's six months, with no per-provider table to keep right. A token nobody uses is left
to lapse.

A break (`markBroken`, atomic, `first` true once) mails the person once; a reconnect writes a record without `broken`,
which re-arms it. An administrator's disconnect and a service deletion mail too; the person's own disconnect and a
person's or project's deletion do not (`lib/connected_services/mail.ts`). Only to a verified address, only with mail
configured, in a background queue, never naming a token or an identifier.
